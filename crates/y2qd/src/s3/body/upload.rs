//! Upload-side body adapters: `aws-chunked` decoding, whole-body
//! payload/checksum verification, and the session-leashed upload stream.
//!
//! `aws-chunked` bodies (CRLF after every line; sizes are lowercase hex):
//!
//! ```text
//! STREAMING-AWS4-HMAC-SHA256-PAYLOAD
//!   { <size>;chunk-signature=<sig> CRLF <data> CRLF }*  0;chunk-signature=<sig> CRLF CRLF
//! STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER
//!   { …same… }*  0;chunk-signature=<sig> CRLF  { <name>:<value> CRLF }*
//!   x-amz-trailer-signature:<sig> CRLF  CRLF
//! STREAMING-UNSIGNED-PAYLOAD-TRAILER
//!   { <size> CRLF <data> CRLF }*  0 CRLF  { <name>:<value> CRLF }*  CRLF
//! ```

use actix_web::http::header::HeaderMap;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use sha2::{Digest, Sha256};

use crate::error::AppError;
use crate::s3::auth::{ChunkSigning, S3Authenticated, SessionLeash};
use crate::s3::error::S3Error;
use crate::s3::sigv4::{self, PayloadHash};

use super::{AppByteStream, ErrorSideband, sideband_abort};

/// Digest accumulated over a whole upload body and checked at end of
/// stream — after every byte has been forwarded downstream, but before the
/// caller's `commit`, so a mismatched body is never persisted.
trait EofVerifier {
    fn update(&mut self, chunk: &[u8]);
    fn finish(self) -> Result<(), S3Error>;
}

/// `x-amz-content-sha256`'s declared value, verified against a running
/// SHA-256 of the whole body.
struct PayloadSha256 {
    hasher: Sha256,
    expected_hex: String,
}

impl EofVerifier for PayloadSha256 {
    fn update(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
    }

    fn finish(self) -> Result<(), S3Error> {
        let digest = sigv4::hex_encode(&self.hasher.finalize());
        if digest != self.expected_hex {
            Err(S3Error::x_amz_content_sha256_mismatch())
        } else {
            Ok(())
        }
    }
}

/// A plain (not `aws-chunked`-trailer) `x-amz-checksum-<algo>` header
/// value, verified against a running digest of the whole body.
struct ChecksumHeader {
    hasher: ChecksumHasher,
    expected_b64: String,
}

impl EofVerifier for ChecksumHeader {
    fn update(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
    }

    fn finish(self) -> Result<(), S3Error> {
        let actual = self.hasher.finish_b64();
        if actual != self.expected_b64 {
            Err(S3Error::invalid_request(format!(
                "checksum mismatch: computed {actual}, declared {}",
                self.expected_b64
            )))
        } else {
            Ok(())
        }
    }
}

/// Verify `verifier` against every byte of `inner`, failing at end-of-stream
/// on mismatch — after every byte has already been forwarded downstream,
/// but before the caller's `session.finish()`/`commit()` ever runs, so a
/// mismatched body is never actually persisted. Replaces two formerly
/// hand-duplicated adapters (`x-amz-content-sha256` and a plain
/// `x-amz-checksum-<algo>` header); [`PayloadSha256`] and [`ChecksumHeader`]
/// are the two [`EofVerifier`] impls.
fn verify_at_eof<S, V>(
    inner: S,
    verifier: V,
    sideband: ErrorSideband,
    bucket: String,
) -> impl Stream<Item = Result<Bytes, AppError>> + Unpin
where
    S: Stream<Item = Result<Bytes, AppError>> + Unpin,
    V: EofVerifier + 'static,
{
    struct St<S, V> {
        inner: S,
        verifier: Option<V>,
        sideband: ErrorSideband,
        bucket: String,
        done: bool,
    }
    let state = St {
        inner,
        verifier: Some(verifier),
        sideband,
        bucket,
        done: false,
    };
    Box::pin(futures_util::stream::try_unfold(
        state,
        |mut st| async move {
            if st.done {
                return Ok(None);
            }
            match st.inner.next().await {
                Some(Ok(chunk)) => {
                    if let Some(v) = st.verifier.as_mut() {
                        v.update(&chunk);
                    }
                    Ok(Some((chunk, st)))
                }
                Some(Err(e)) => Err(e),
                None => {
                    st.done = true;
                    let verifier = st.verifier.take().expect("verifier present until finish");
                    if let Err(e) = verifier.finish() {
                        st.sideband.set(e);
                        return Err(sideband_abort(&st.bucket));
                    }
                    Ok(None)
                }
            }
        },
    ))
}

/// Which whole-body checksum algorithm a client declared via
/// `x-amz-checksum-*` (header form) or an `aws-chunked` trailer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChecksumAlgo {
    Crc32,
    Sha256,
}

/// What an `x-amz-checksum-<name>` header or trailer name means here.
enum ChecksumDecl {
    Supported(ChecksumAlgo),
    /// crc32c / crc64nvme / sha1: recognized, deliberately unimplemented.
    Unsupported,
    NotAChecksum,
}

impl ChecksumAlgo {
    /// Classify the `x-amz-sdk-checksum-algorithm` value or an
    /// `x-amz-checksum-<algo>` header/trailer name suffix.
    fn classify(name: &str) -> ChecksumDecl {
        match name.to_ascii_lowercase().as_str() {
            "crc32" => ChecksumDecl::Supported(Self::Crc32),
            "sha256" => ChecksumDecl::Supported(Self::Sha256),
            "crc32c" | "crc64nvme" | "sha1" => ChecksumDecl::Unsupported,
            _ => ChecksumDecl::NotAChecksum,
        }
    }
}

enum ChecksumHasher {
    Crc32(crc32fast::Hasher),
    Sha256(Box<Sha256>),
}

impl ChecksumHasher {
    fn new(algo: ChecksumAlgo) -> Self {
        match algo {
            ChecksumAlgo::Crc32 => Self::Crc32(crc32fast::Hasher::new()),
            ChecksumAlgo::Sha256 => Self::Sha256(Box::new(Sha256::new())),
        }
    }
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Crc32(h) => h.update(data),
            Self::Sha256(h) => h.update(data),
        }
    }
    fn finish_b64(self) -> String {
        match self {
            Self::Crc32(h) => BASE64_STANDARD.encode(h.finalize().to_be_bytes()),
            Self::Sha256(h) => BASE64_STANDARD.encode(h.finalize()),
        }
    }
}

/// Re-validates the session as upload bytes arrive. Mirrors
/// [`super::LeashedDownload`]; the item type stays `AppError` (not
/// `S3Error`) because it feeds `cipher::stream_encrypt_for_put` directly —
/// the real reason is recorded in `sideband` before the generic abort is
/// yielded.
pub fn leashed_upload<S>(
    inner: S,
    leash: SessionLeash,
    sideband: ErrorSideband,
    bucket: String,
) -> impl Stream<Item = Result<Bytes, AppError>> + Unpin
where
    S: Stream<Item = Result<Bytes, AppError>> + Unpin,
{
    struct St<S> {
        inner: S,
        leash: SessionLeash,
        sideband: ErrorSideband,
        bucket: String,
    }
    let state = St {
        inner,
        leash,
        sideband,
        bucket,
    };
    Box::pin(futures_util::stream::try_unfold(
        state,
        |mut st| async move {
            match st.inner.next().await {
                Some(Ok(chunk)) => match st.leash.note(chunk.len() as u64) {
                    Ok(()) => Ok(Some((chunk, st))),
                    Err(e) => {
                        tracing::warn!(
                            reason = %e,
                            "aborting S3 upload: session leash tripped mid-transfer"
                        );
                        st.sideband.set(e);
                        Err(sideband_abort(&st.bucket))
                    }
                },
                Some(Err(e)) => Err(e),
                None => Ok(None),
            }
        },
    ))
}

const MAX_CHUNK_HEADER_LINE_BYTES: usize = 1024;

/// Per-request signing material threaded through the `aws-chunked` decoder;
/// `prev_signature` advances with every frame (including the terminal `0`
/// frame and, for a signed trailer, the trailer itself).
struct ChunkSigningState {
    signing_key: [u8; 32],
    scope: String,
    amz_date: String,
    prev_signature: String,
}

/// Bundled parameters for [`decode_aws_chunked`]: everything but the
/// generic `inner` stream itself.
pub(crate) struct ChunkedOptions {
    pub chunk_signing: Option<ChunkSigning>,
    pub trailer_checksum: Option<ChecksumAlgo>,
    pub max_frame_bytes: u64,
    pub sideband: ErrorSideband,
    /// `true` for the two `…-TRAILER` modes; `false` for plain
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, where the terminal chunk is
    /// followed only by its blank line.
    pub expect_trailer: bool,
    pub bucket: String,
}

struct ChunkedState<S> {
    inner: S,
    buf: bytes::BytesMut,
    inner_done: bool,
    signing: Option<ChunkSigningState>,
    /// `false` only for `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`: no trailer
    /// block follows the terminal chunk.
    expect_trailer: bool,
    max_frame_bytes: u64,
    trailer_checksum: Option<ChecksumAlgo>,
    checksum_hasher: Option<ChecksumHasher>,
    sideband: ErrorSideband,
    bucket: String,
    finished: bool,
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn framing_abort<S>(state: &ChunkedState<S>, err: S3Error) -> AppError {
    state.sideband.set(err);
    sideband_abort(&state.bucket)
}

async fn read_line<S>(state: &mut ChunkedState<S>) -> Result<String, AppError>
where
    S: Stream<Item = Result<Bytes, AppError>> + Unpin,
{
    loop {
        if let Some(pos) = find_crlf(&state.buf) {
            let line = state.buf.split_to(pos);
            let _ = state.buf.split_to(2); // discard "\r\n"
            return String::from_utf8(line.to_vec()).map_err(|_| {
                framing_abort(
                    state,
                    S3Error::invalid_argument("malformed aws-chunked framing"),
                )
            });
        }
        if state.buf.len() > MAX_CHUNK_HEADER_LINE_BYTES {
            return Err(framing_abort(
                state,
                S3Error::invalid_argument("aws-chunked frame header too long"),
            ));
        }
        if state.inner_done {
            return Err(framing_abort(
                state,
                S3Error::invalid_argument("truncated aws-chunked body"),
            ));
        }
        match state.inner.next().await {
            Some(Ok(chunk)) => state.buf.extend_from_slice(&chunk),
            Some(Err(e)) => return Err(e),
            None => state.inner_done = true,
        }
    }
}

async fn read_exact<S>(state: &mut ChunkedState<S>, n: usize) -> Result<Bytes, AppError>
where
    S: Stream<Item = Result<Bytes, AppError>> + Unpin,
{
    while state.buf.len() < n {
        if state.inner_done {
            return Err(framing_abort(
                state,
                S3Error::invalid_argument("truncated aws-chunked body"),
            ));
        }
        match state.inner.next().await {
            Some(Ok(chunk)) => state.buf.extend_from_slice(&chunk),
            Some(Err(e)) => return Err(e),
            None => state.inner_done = true,
        }
    }
    Ok(state.buf.split_to(n).freeze())
}

/// Verify one chunk-signature-bearing frame (data frame or the terminal `0`
/// frame) against the running signature chain, advancing it on success.
fn verify_chunk_signature<S>(
    state: &mut ChunkedState<S>,
    declared_sig: Option<String>,
    payload_sha256_hex: &str,
) -> Result<(), AppError> {
    let Some(signing) = state.signing.as_mut() else {
        return Ok(());
    };
    let Some(declared) = declared_sig else {
        state.sideband.set(S3Error::signature_does_not_match());
        return Err(sideband_abort(&state.bucket));
    };
    let sts = sigv4::chunk_string_to_sign(
        &signing.amz_date,
        &signing.scope,
        &signing.prev_signature,
        payload_sha256_hex,
    );
    let computed = sigv4::hex_hmac_sha256(&signing.signing_key, sts.as_bytes());
    if !sigv4::signatures_match(&computed, &declared) {
        state.sideband.set(S3Error::signature_does_not_match());
        return Err(sideband_abort(&state.bucket));
    }
    signing.prev_signature = declared;
    Ok(())
}

/// Read and validate the trailer block following the terminal `0` frame:
/// zero or more `name:value\r\n` lines, then a blank `\r\n`. For a signed
/// payload mode, the last trailer line must be
/// `x-amz-trailer-signature:<hex>\r\n`, verified via
/// [`sigv4::trailer_string_to_sign`] over the SHA-256 of every preceding
/// trailer line concatenated. Returns the parsed (non-signature) trailer
/// name/value pairs, lowercase-named.
async fn read_trailer<S>(
    state: &mut ChunkedState<S>,
) -> Result<std::collections::HashMap<String, String>, AppError>
where
    S: Stream<Item = Result<Bytes, AppError>> + Unpin,
{
    let mut content = String::new();
    let mut trailer_sig: Option<String> = None;
    let mut values = std::collections::HashMap::new();
    loop {
        let line = read_line(state).await?;
        if line.is_empty() {
            break;
        }
        if let Some(sig) = line
            .to_ascii_lowercase()
            .strip_prefix("x-amz-trailer-signature:")
        {
            trailer_sig = Some(sig.trim().to_owned());
            continue;
        }
        content.push_str(&line);
        content.push('\n');
        if let Some((name, value)) = line.split_once(':') {
            values.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    if let Some(signing) = state.signing.as_mut() {
        let Some(sig) = trailer_sig else {
            return Err(framing_abort(state, S3Error::signature_does_not_match()));
        };
        let trailer_hash = sigv4::sha256_hex(content.as_bytes());
        let sts = sigv4::trailer_string_to_sign(
            &signing.amz_date,
            &signing.scope,
            &signing.prev_signature,
            &trailer_hash,
        );
        let computed = sigv4::hex_hmac_sha256(&signing.signing_key, sts.as_bytes());
        if !sigv4::signatures_match(&computed, &sig) {
            return Err(framing_abort(state, S3Error::signature_does_not_match()));
        }
        signing.prev_signature = sig;
    }
    Ok(values)
}

async fn next_chunked_frame<S>(
    mut state: ChunkedState<S>,
) -> Result<Option<(Bytes, ChunkedState<S>)>, AppError>
where
    S: Stream<Item = Result<Bytes, AppError>> + Unpin,
{
    if state.finished {
        return Ok(None);
    }

    let header_line = read_line(&mut state).await?;
    let (size_hex, declared_sig) = match header_line.split_once(';') {
        Some((s, rest)) => (
            s,
            rest.trim()
                .strip_prefix("chunk-signature=")
                .map(|s| s.to_owned()),
        ),
        None => (header_line.as_str(), None),
    };
    let frame_size = u64::from_str_radix(size_hex.trim(), 16).map_err(|_| {
        framing_abort(
            &state,
            S3Error::invalid_argument("malformed aws-chunked frame size"),
        )
    })?;
    if frame_size > state.max_frame_bytes {
        return Err(framing_abort(
            &state,
            S3Error::invalid_request("chunk exceeds the configured max_part_bytes"),
        ));
    }

    if frame_size == 0 {
        verify_chunk_signature(&mut state, declared_sig, sigv4::EMPTY_PAYLOAD_SHA256)?;
        let trailer_values = if state.expect_trailer {
            read_trailer(&mut state).await?
        } else {
            // Still consume the mandatory terminating blank line even when
            // no trailer fields were declared.
            let blank = read_line(&mut state).await?;
            if !blank.is_empty() {
                return Err(framing_abort(
                    &state,
                    S3Error::invalid_argument("expected blank line after terminal chunk"),
                ));
            }
            std::collections::HashMap::new()
        };
        if let Some(algo) = state.trailer_checksum {
            let name = match algo {
                ChecksumAlgo::Crc32 => "x-amz-checksum-crc32",
                ChecksumAlgo::Sha256 => "x-amz-checksum-sha256",
            };
            let declared = trailer_values.get(name).cloned();
            let actual = state.checksum_hasher.take().map(ChecksumHasher::finish_b64);
            match (declared, actual) {
                (Some(d), Some(a)) if d == a => {}
                _ => {
                    return Err(framing_abort(
                        &state,
                        S3Error::invalid_request("trailer checksum mismatch or missing"),
                    ));
                }
            }
        }
        state.finished = true;
        return Ok(None);
    }

    let data = read_exact(&mut state, frame_size as usize).await?;
    let trailing = read_exact(&mut state, 2).await?;
    if &trailing[..] != b"\r\n" {
        return Err(framing_abort(
            &state,
            S3Error::invalid_argument("malformed aws-chunked frame terminator"),
        ));
    }
    verify_chunk_signature(&mut state, declared_sig, &sigv4::sha256_hex(&data))?;
    if let Some(h) = state.checksum_hasher.as_mut() {
        h.update(&data);
    }
    Ok(Some((data, state)))
}

/// Decode `aws-chunked` framing (see the module docs' grammar) into plain
/// payload bytes, verifying the per-chunk and trailer signature chain when
/// `options.chunk_signing` is present. `options.trailer_checksum`, when
/// set, is verified against a running digest of the decoded payload once
/// the trailer block (read only when `expect_trailer`) is read.
fn decode_aws_chunked<S>(
    inner: S,
    options: ChunkedOptions,
) -> impl Stream<Item = Result<Bytes, AppError>> + Unpin
where
    S: Stream<Item = Result<Bytes, AppError>> + Unpin,
{
    let signing = options.chunk_signing.map(|c| ChunkSigningState {
        signing_key: *c.signing_key,
        scope: c.scope,
        amz_date: c.amz_date,
        prev_signature: c.seed_signature,
    });
    let checksum_hasher = options.trailer_checksum.map(ChecksumHasher::new);
    let state = ChunkedState {
        inner,
        buf: bytes::BytesMut::new(),
        inner_done: false,
        signing,
        expect_trailer: options.expect_trailer,
        max_frame_bytes: options.max_frame_bytes,
        trailer_checksum: options.trailer_checksum,
        checksum_hasher,
        sideband: options.sideband,
        bucket: options.bucket,
        finished: false,
    };
    Box::pin(futures_util::stream::try_unfold(state, next_chunked_frame))
}

/// Compose the adapters a `PutObject`/`UploadPart` body needs, given the
/// request's already-verified SigV4 payload declaration. Consumes `auth` to
/// take ownership of its `leash` (not `Clone`) alongside the read-only
/// `payload`/`chunk_signing` fields. Returns a stream ready for
/// `cipher::stream_encrypt_for_put`; any adapter that rejects the body
/// records the precise reason in `sideband` before aborting the stream with
/// a generic `AppError` — callers must check `sideband.take()` after a
/// stream error and prefer it over `S3Error::from(app_error)`.
pub fn upload_stream(
    payload: actix_web::web::Payload,
    auth: S3Authenticated,
    headers: &HeaderMap,
    max_frame_bytes: u64,
    sideband: ErrorSideband,
    bucket: String,
    key: String,
) -> Result<AppByteStream, S3Error> {
    let bucket_for_err = bucket.clone();
    let key_for_err = key;
    let base = futures_util::TryStreamExt::map_err(payload, move |e| {
        AppError(y2q_core::Error::InternalError {
            bucket: bucket_for_err.clone(),
            key: key_for_err.clone(),
            operation: "read body".to_owned(),
            message: e.to_string(),
        })
    });
    let base: AppByteStream = Box::pin(base);

    // Reject an unsupported checksum algorithm before touching the body.
    let mut header_checksum: Option<(ChecksumAlgo, String)> = None;
    for (header_name, algo_name) in [
        ("x-amz-checksum-crc32", "crc32"),
        ("x-amz-checksum-sha256", "sha256"),
        ("x-amz-checksum-crc32c", "crc32c"),
        ("x-amz-checksum-crc64nvme", "crc64nvme"),
        ("x-amz-checksum-sha1", "sha1"),
    ] {
        if let Some(v) = headers.get(header_name).and_then(|v| v.to_str().ok()) {
            match ChecksumAlgo::classify(algo_name) {
                ChecksumDecl::Supported(algo) => header_checksum = Some((algo, v.to_owned())),
                ChecksumDecl::Unsupported | ChecksumDecl::NotAChecksum => {
                    return Err(S3Error::invalid_request(format!(
                        "unsupported checksum algorithm {algo_name}; y2q supports CRC32 and SHA256"
                    )));
                }
            }
        }
    }
    // A trailer-declared checksum (`x-amz-trailer: x-amz-checksum-crc32`)
    // only applies to the two `…-TRAILER` streaming payload modes. An
    // unsupported algorithm named here must reject the request outright —
    // silently treating it as "no checksum declared" would let the client
    // believe it negotiated integrity verification that never ran.
    let mut trailer_checksum: Option<ChecksumAlgo> = None;
    if let Some(v) = headers.get("x-amz-trailer").and_then(|v| v.to_str().ok()) {
        for name in v.split(',') {
            let name = name.trim().to_ascii_lowercase();
            let Some(algo_name) = name.strip_prefix("x-amz-checksum-") else {
                continue;
            };
            match ChecksumAlgo::classify(algo_name) {
                ChecksumDecl::Supported(algo) => {
                    trailer_checksum = Some(algo);
                    break;
                }
                ChecksumDecl::Unsupported => {
                    return Err(S3Error::invalid_request(format!(
                        "unsupported checksum algorithm: {algo_name}"
                    )));
                }
                ChecksumDecl::NotAChecksum => {}
            }
        }
    }

    let decoded: AppByteStream = match &auth.payload {
        PayloadHash::Exact(hex) => Box::pin(verify_at_eof(
            base,
            PayloadSha256 {
                hasher: Sha256::new(),
                expected_hex: hex.clone(),
            },
            sideband.clone(),
            bucket.clone(),
        )),
        PayloadHash::Unsigned => base,
        PayloadHash::StreamingSigned { .. } | PayloadHash::StreamingUnsigned => {
            Box::pin(decode_aws_chunked(
                base,
                ChunkedOptions {
                    chunk_signing: auth.chunk_signing.clone(),
                    trailer_checksum,
                    expect_trailer: auth.payload.has_trailer(),
                    max_frame_bytes,
                    sideband: sideband.clone(),
                    bucket: bucket.clone(),
                },
            ))
        }
    };

    let checksummed: AppByteStream = match header_checksum {
        Some((algo, expected)) => Box::pin(verify_at_eof(
            decoded,
            ChecksumHeader {
                hasher: ChecksumHasher::new(algo),
                expected_b64: expected,
            },
            sideband.clone(),
            bucket.clone(),
        )),
        None => decoded,
    };

    Ok(Box::pin(leashed_upload(
        checksummed,
        auth.leash,
        sideband,
        bucket,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    const AWS_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const AWS_DATE: &str = "20130524T000000Z";
    const AWS_SCOPE: &str = "20130524/us-east-1/s3/aws4_request";

    const PLAIN_SEED: &str = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
    const PLAIN_SIGS: [&str; 3] = [
        "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648",
        "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497",
        "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9",
    ];
    const TRAILER_SEED: &str = "106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e";
    const TRAILER_SIGS: [&str; 3] = [
        "b474d8862b1487a5145d686f57f013e54db672cee1c953b3010fb58501ef5aa2",
        "1c1344b170168f8e65b41376b44b20fe354e373826ccbbe2c1d40a8cae51e5c7",
        "2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992",
    ];
    const TRAILER_SIG: &str = "d81f82fc3505edab99d459891051a732e8730629a2e4a59689829ca17fe2e435";

    fn signing(seed: &str) -> ChunkSigning {
        ChunkSigning {
            signing_key: Zeroizing::new(sigv4::signing_key(
                AWS_SECRET.as_bytes(),
                "20130524",
                "us-east-1",
                "s3",
            )),
            scope: AWS_SCOPE.to_owned(),
            amz_date: AWS_DATE.to_owned(),
            seed_signature: seed.to_owned(),
        }
    }

    /// 65536 + 1024 `a` bytes in AWS's two frames, then
    /// `0;chunk-signature=<sigs[2]>\r\n` + `tail`.
    fn aws_body(sigs: &[&str; 3], tail: &str) -> Vec<u8> {
        let mut w = Vec::new();
        for (size_hex, len, sig) in [("10000", 65_536usize, sigs[0]), ("400", 1_024, sigs[1])] {
            w.extend_from_slice(format!("{size_hex};chunk-signature={sig}\r\n").as_bytes());
            w.resize(w.len() + len, b'a');
            w.extend_from_slice(b"\r\n");
        }
        w.extend_from_slice(format!("0;chunk-signature={}\r\n", sigs[2]).as_bytes());
        w.extend_from_slice(tail.as_bytes());
        w
    }

    /// One signed data frame carrying a non-empty `body`, then the signed
    /// terminal frame, chained from `PLAIN_SEED`, then `tail`. Uses the
    /// production primitives, so it checks framing only; the AWS vectors
    /// check conformance.
    fn signed_wire(body: &[u8], tail: &str) -> Vec<u8> {
        let key = sigv4::signing_key(AWS_SECRET.as_bytes(), "20130524", "us-east-1", "s3");
        let sign = |prev: &str, data: &[u8]| {
            let sts =
                sigv4::chunk_string_to_sign(AWS_DATE, AWS_SCOPE, prev, &sigv4::sha256_hex(data));
            sigv4::hex_hmac_sha256(&key, sts.as_bytes())
        };
        let data_sig = sign(PLAIN_SEED, body);
        let final_sig = sign(&data_sig, b"");
        let mut w = Vec::new();
        w.extend_from_slice(format!("{:x};chunk-signature={data_sig}\r\n", body.len()).as_bytes());
        w.extend_from_slice(body);
        w.extend_from_slice(b"\r\n");
        w.extend_from_slice(format!("0;chunk-signature={final_sig}\r\n").as_bytes());
        w.extend_from_slice(tail.as_bytes());
        w
    }

    /// Feed `wire` in pieces of at most `piece` bytes; return decoded bytes,
    /// or the S3 error `code` recorded in the sideband when the stream aborts.
    async fn decode(
        wire: &[u8],
        piece: usize,
        signing: Option<ChunkSigning>,
        expect_trailer: bool,
        trailer_checksum: Option<ChecksumAlgo>,
    ) -> Result<Vec<u8>, &'static str> {
        let sideband = ErrorSideband::new();
        let pieces: Vec<Result<Bytes, AppError>> = wire
            .chunks(piece)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        let mut out = decode_aws_chunked(
            futures_util::stream::iter(pieces),
            ChunkedOptions {
                chunk_signing: signing,
                trailer_checksum,
                expect_trailer,
                max_frame_bytes: 1 << 20,
                sideband: sideband.clone(),
                bucket: "bkt".to_owned(),
            },
        );
        let mut body = Vec::new();
        while let Some(item) = out.next().await {
            match item {
                Ok(b) => body.extend_from_slice(&b),
                Err(_) => return Err(sideband.take().map_or("no sideband error", |e| e.code)),
            }
        }
        Ok(body)
    }

    #[tokio::test]
    async fn plain_signed_streaming_accepts_aws_vector() {
        let wire = aws_body(&PLAIN_SIGS, "\r\n");
        let expected = vec![b'a'; 66_560];
        for piece in [wire.len(), 4099] {
            let got = decode(&wire, piece, Some(signing(PLAIN_SEED)), false, None).await;
            assert_eq!(got.map(|b| b == expected), Ok(true), "piece {piece}");
        }
    }

    #[tokio::test]
    async fn plain_signed_streaming_one_chunk_final_crlf_arrives_alone() {
        let wire = signed_wire(b"hello", "\r\n");
        let got = decode(&wire, 1, Some(signing(PLAIN_SEED)), false, None).await;
        assert_eq!(got, Ok(b"hello".to_vec()));
    }

    #[tokio::test]
    async fn plain_signed_streaming_rejects_forged_terminal_signature() {
        let mut wire = signed_wire(b"hello", "\r\n");
        let i = wire.len() - 5;
        wire[i] = if wire[i] == b'0' { b'1' } else { b'0' };
        let got = decode(&wire, wire.len(), Some(signing(PLAIN_SEED)), false, None).await;
        assert_eq!(got, Err("SignatureDoesNotMatch"));
    }

    #[tokio::test]
    async fn plain_signed_streaming_rejects_tampered_data() {
        let mut wire = signed_wire(b"hello", "\r\n");
        let i = wire
            .windows(5)
            .position(|w| w == b"hello")
            .expect("data present");
        wire[i] = b'j';
        let got = decode(&wire, wire.len(), Some(signing(PLAIN_SEED)), false, None).await;
        assert_eq!(got, Err("SignatureDoesNotMatch"));
    }

    #[tokio::test]
    async fn plain_signed_streaming_rejects_a_trailer_block() {
        let wire = signed_wire(b"hello", "x-amz-checksum-crc32:NhCmhg==\r\n\r\n");
        let got = decode(&wire, wire.len(), Some(signing(PLAIN_SEED)), false, None).await;
        assert_eq!(got, Err("InvalidArgument"));
    }

    #[tokio::test]
    async fn signed_trailer_streaming_accepts_aws_vector() {
        let wire = aws_body(
            &TRAILER_SIGS,
            &format!(
                "x-amz-checksum-crc32c:sOO8/Q==\r\nx-amz-trailer-signature:{TRAILER_SIG}\r\n\r\n"
            ),
        );
        let expected = vec![b'a'; 66_560];
        let got = decode(&wire, 4099, Some(signing(TRAILER_SEED)), true, None).await;
        assert_eq!(got.map(|b| b == expected), Ok(true));
    }

    #[tokio::test]
    async fn signed_trailer_streaming_still_requires_trailer_signature() {
        let wire = aws_body(&TRAILER_SIGS, "x-amz-checksum-crc32c:sOO8/Q==\r\n\r\n");
        let got = decode(&wire, wire.len(), Some(signing(TRAILER_SEED)), true, None).await;
        assert_eq!(got, Err("SignatureDoesNotMatch"));
    }

    #[tokio::test]
    async fn unsigned_trailer_streaming_reads_trailer_block() {
        let with = b"5\r\nhello\r\n0\r\nx-amz-checksum-crc32:NhCmhg==\r\n\r\n";
        let got = decode(with, with.len(), None, true, Some(ChecksumAlgo::Crc32)).await;
        assert_eq!(got, Ok(b"hello".to_vec()));
        let empty = b"5\r\nhello\r\n0\r\n\r\n";
        let got = decode(empty, empty.len(), None, true, None).await;
        assert_eq!(got, Ok(b"hello".to_vec()));
    }
}
