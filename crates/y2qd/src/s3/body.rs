//! Streaming body adapters shared by the S3 gateway's read and write paths.
//!
//! [`LeashedDownload`] is the download half: it wraps a plaintext stream and
//! re-validates the owning session as bytes flow, so a session that expires,
//! is revoked, or is duress-switched mid-download aborts the transfer
//! instead of silently completing under authority that's gone. The upload
//! half (`aws-chunked` decoding, payload/checksum verification,
//! `LeashedUpload`) is added alongside `PutObject` support.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::Stream;

use crate::error::AppError;
use crate::s3::auth::SessionLeash;
use crate::s3::error::S3Error;

/// Boxed, type-erased byte stream feeding `cipher::stream_encrypt_for_put`
/// or `cipher::plaintext_stream`'s consumers. Named to avoid repeating (and
/// `clippy::type_complexity`-tripping on) the full `Pin<Box<dyn Stream<...>>>`
/// spelling at every upload/copy/multipart-assembly call site.
pub(crate) type AppByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, AppError>>>>;

/// Wraps a plaintext stream and re-validates the session as bytes flow.
/// Yields [`S3Error`] (not [`AppError`]) so a mid-transfer session death is
/// distinguishable in logs from a storage fault.
pub struct LeashedDownload<S> {
    inner: S,
    leash: SessionLeash,
}

impl<S> LeashedDownload<S> {
    pub fn new(inner: S, leash: SessionLeash) -> Self {
        Self { inner, leash }
    }
}

impl<S> Stream for LeashedDownload<S>
where
    S: Stream<Item = Result<Bytes, AppError>> + Unpin,
{
    type Item = Result<Bytes, S3Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => match self.leash.note(chunk.len() as u64) {
                Ok(()) => Poll::Ready(Some(Ok(chunk))),
                Err(e) => {
                    tracing::warn!(
                        reason = %e,
                        "aborting S3 download: session leash tripped mid-transfer"
                    );
                    Poll::Ready(Some(Err(e)))
                }
            },
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(S3Error::from(e)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A body that declares a real size but carries no bytes to poll.
///
/// `HttpResponse::finish()` attaches a genuinely-zero-length body, and
/// actix's h1 encoder writes `Content-Length` from the body's *actual*
/// `BodySize` — overriding any `Content-Length` header the handler
/// inserted manually — so a `HeadObject` response built with `.finish()`
/// always reports `Content-Length: 0` regardless of the object's real
/// size. Attaching this body instead reports the true size; actix's HEAD
/// handling already skips writing body bytes to the wire for any body
/// type, so `poll_next` is never actually reached for a HEAD request.
pub struct SizedEmptyBody(pub u64);

impl actix_web::body::MessageBody for SizedEmptyBody {
    type Error = std::convert::Infallible;

    fn size(&self) -> actix_web::body::BodySize {
        actix_web::body::BodySize::Sized(self.0)
    }

    fn poll_next(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, Self::Error>>> {
        Poll::Ready(None)
    }
}

// ---------------------------------------------------------------------------
// Upload path: aws-chunked decoding, payload/checksum verification, leash.
// ---------------------------------------------------------------------------

use std::sync::{Arc, Mutex};

use actix_web::http::header::HeaderMap;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};

use crate::s3::auth::{ChunkSigning, S3Authenticated};
use crate::s3::sigv4::{self, PayloadHash};

/// Shared slot an upload-stream adapter uses to smuggle the precise
/// [`S3Error`] a generic [`AppError`] abort actually represents.
/// `cipher::stream_encrypt_for_put` is generic over `AppError` (shared with
/// the plain REST PUT path) and cannot carry S3-specific error codes
/// itself, so an adapter that rejects a request (bad signature, checksum
/// mismatch, malformed framing) records the real error here before
/// yielding a throwaway `AppError` to unwind the stream. The PUT/CopyObject
/// handlers call [`ErrorSideband::take`] after a stream error and fall back
/// to `S3Error::from(app_error)` only when it's empty (a genuine
/// storage/crypto fault, not an upload-adapter rejection).
#[derive(Clone, Default)]
pub struct ErrorSideband(Arc<Mutex<Option<S3Error>>>);

impl ErrorSideband {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn set(&self, err: S3Error) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(err);
    }

    pub fn take(&self) -> Option<S3Error> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

/// Generic placeholder abort used once the real reason has been recorded in
/// an [`ErrorSideband`]. `key` isn't part of `Error::Forbidden` but is
/// accepted for symmetry with every other error-construction call site
/// here, all of which need both address components.
fn sideband_abort(bucket: &str, _key: &str) -> AppError {
    AppError(y2q_core::Error::Forbidden {
        bucket: bucket.to_owned(),
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Verify the running SHA-256 of a stream against `expected_hex`
/// (`x-amz-content-sha256`'s declared value), failing at end-of-stream on
/// mismatch — after every byte has already been forwarded downstream, but
/// before the caller's `session.finish()`/`commit()` ever runs, so a
/// mismatched body is never actually persisted.
pub fn verify_payload_sha256<S>(
    inner: S,
    expected_hex: String,
    sideband: ErrorSideband,
    bucket: String,
    key: String,
) -> impl Stream<Item = Result<Bytes, AppError>> + Unpin
where
    S: Stream<Item = Result<Bytes, AppError>> + Unpin,
{
    struct St<S> {
        inner: S,
        hasher: Sha256,
        expected_hex: String,
        sideband: ErrorSideband,
        bucket: String,
        key: String,
        done: bool,
    }
    let state = St {
        inner,
        hasher: Sha256::new(),
        expected_hex,
        sideband,
        bucket,
        key,
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
                    st.hasher.update(&chunk);
                    Ok(Some((chunk, st)))
                }
                Some(Err(e)) => Err(e),
                None => {
                    st.done = true;
                    let digest = hex_encode(&st.hasher.clone().finalize());
                    if digest != st.expected_hex {
                        st.sideband.set(S3Error::x_amz_content_sha256_mismatch());
                        return Err(sideband_abort(&st.bucket, &st.key));
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
pub enum ChecksumAlgo {
    Crc32,
    Sha256,
}

impl ChecksumAlgo {
    /// Parse the `x-amz-sdk-checksum-algorithm` value or an
    /// `x-amz-checksum-<algo>` header name suffix. `None` means present but
    /// unsupported (crc32c, crc64nvme, sha1) — callers must reject the
    /// request rather than silently skip verification.
    fn from_name(name: &str) -> Option<Option<Self>> {
        match name.to_ascii_lowercase().as_str() {
            "crc32" => Some(Some(Self::Crc32)),
            "sha256" => Some(Some(Self::Sha256)),
            "crc32c" | "crc64nvme" | "sha1" => Some(None),
            _ => None,
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

/// Verify a whole-body `x-amz-checksum-<algo>` header value, failing at
/// end-of-stream on mismatch (same "already forwarded, never committed"
/// property as [`verify_payload_sha256`]). Used only for the plain (not
/// `aws-chunked`-trailer) declaration form.
pub fn verify_checksum_header<S>(
    inner: S,
    algo: ChecksumAlgo,
    expected_b64: String,
    sideband: ErrorSideband,
    bucket: String,
    key: String,
) -> impl Stream<Item = Result<Bytes, AppError>> + Unpin
where
    S: Stream<Item = Result<Bytes, AppError>> + Unpin,
{
    struct St<S> {
        inner: S,
        hasher: Option<ChecksumHasher>,
        expected_b64: String,
        sideband: ErrorSideband,
        bucket: String,
        key: String,
        done: bool,
    }
    let state = St {
        inner,
        hasher: Some(ChecksumHasher::new(algo)),
        expected_b64,
        sideband,
        bucket,
        key,
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
                    if let Some(h) = st.hasher.as_mut() {
                        h.update(&chunk);
                    }
                    Ok(Some((chunk, st)))
                }
                Some(Err(e)) => Err(e),
                None => {
                    st.done = true;
                    let actual = st
                        .hasher
                        .take()
                        .expect("hasher present until finish")
                        .finish_b64();
                    if actual != st.expected_b64 {
                        st.sideband.set(S3Error::invalid_request(format!(
                            "checksum mismatch: computed {actual}, declared {}",
                            st.expected_b64
                        )));
                        return Err(sideband_abort(&st.bucket, &st.key));
                    }
                    Ok(None)
                }
            }
        },
    ))
}

/// Re-validates the session as upload bytes arrive. Mirrors
/// [`LeashedDownload`]; the item type stays `AppError` (not `S3Error`)
/// because it feeds `cipher::stream_encrypt_for_put` directly — the real
/// reason is recorded in `sideband` before the generic abort is yielded.
pub fn leashed_upload<S>(
    inner: S,
    leash: SessionLeash,
    sideband: ErrorSideband,
    bucket: String,
    key: String,
) -> impl Stream<Item = Result<Bytes, AppError>> + Unpin
where
    S: Stream<Item = Result<Bytes, AppError>> + Unpin,
{
    struct St<S> {
        inner: S,
        leash: SessionLeash,
        sideband: ErrorSideband,
        bucket: String,
        key: String,
    }
    let state = St {
        inner,
        leash,
        sideband,
        bucket,
        key,
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
                        Err(sideband_abort(&st.bucket, &st.key))
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

struct ChunkedState<S> {
    inner: S,
    buf: bytes::BytesMut,
    inner_done: bool,
    signing: Option<ChunkSigningState>,
    /// `true` for both `…-TRAILER` payload modes; a trailer block (possibly
    /// empty) is always read, signed or not.
    expect_trailer: bool,
    max_frame_bytes: u64,
    trailer_checksum: Option<ChecksumAlgo>,
    checksum_hasher: Option<ChecksumHasher>,
    sideband: ErrorSideband,
    bucket: String,
    key: String,
    finished: bool,
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn framing_abort<S>(state: &ChunkedState<S>, err: S3Error) -> AppError {
    state.sideband.set(err);
    sideband_abort(&state.bucket, &state.key)
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
        return Err(sideband_abort(&state.bucket, &state.key));
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
        return Err(sideband_abort(&state.bucket, &state.key));
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
        let trailer_hash = sigv4::sha256_hex_of(content.as_bytes());
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
        verify_chunk_signature(&mut state, declared_sig, &sigv4::empty_payload_hash())?;
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
    verify_chunk_signature(&mut state, declared_sig, &sigv4::sha256_hex_of(&data))?;
    if let Some(h) = state.checksum_hasher.as_mut() {
        h.update(&data);
    }
    Ok(Some((data, state)))
}

/// Decode `aws-chunked` framing (see the module docs' grammar) into plain
/// payload bytes, verifying the per-chunk and trailer signature chain when
/// `chunk_signing` is present. `trailer_checksum`, when set, is verified
/// against a running digest of the decoded payload once the trailer block
/// (parsed regardless of signing mode) is read.
#[allow(clippy::too_many_arguments)]
pub fn decode_aws_chunked<S>(
    inner: S,
    chunk_signing: Option<ChunkSigning>,
    trailer_checksum: Option<ChecksumAlgo>,
    max_frame_bytes: u64,
    sideband: ErrorSideband,
    bucket: String,
    key: String,
) -> impl Stream<Item = Result<Bytes, AppError>> + Unpin
where
    S: Stream<Item = Result<Bytes, AppError>> + Unpin,
{
    let signing = chunk_signing.map(|c| ChunkSigningState {
        signing_key: c.signing_key,
        scope: c.scope,
        amz_date: c.amz_date,
        prev_signature: c.seed_signature,
    });
    let checksum_hasher = trailer_checksum.map(ChecksumHasher::new);
    let state = ChunkedState {
        inner,
        buf: bytes::BytesMut::new(),
        inner_done: false,
        signing,
        expect_trailer: true,
        max_frame_bytes,
        trailer_checksum,
        checksum_hasher,
        sideband,
        bucket,
        key,
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
    let key_for_err = key.clone();
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
            match ChecksumAlgo::from_name(algo_name) {
                Some(Some(algo)) => header_checksum = Some((algo, v.to_owned())),
                _ => {
                    return Err(S3Error::invalid_request(format!(
                        "unsupported checksum algorithm {algo_name}; y2q supports CRC32 and SHA256"
                    )));
                }
            }
        }
    }
    // A trailer-declared checksum (`x-amz-trailer: x-amz-checksum-crc32`)
    // only applies to the two `…-TRAILER` streaming payload modes.
    let trailer_checksum = headers
        .get("x-amz-trailer")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split(',').find_map(|name| {
                let name = name.trim().to_ascii_lowercase();
                name.strip_prefix("x-amz-checksum-")
                    .and_then(ChecksumAlgo::from_name)
                    .flatten()
            })
        });

    let decoded: AppByteStream = match &auth.payload {
        PayloadHash::Exact(hex) => Box::pin(verify_payload_sha256(
            base,
            hex.clone(),
            sideband.clone(),
            bucket.clone(),
            key.clone(),
        )),
        PayloadHash::Unsigned => base,
        PayloadHash::StreamingSigned { .. } | PayloadHash::StreamingUnsigned => {
            Box::pin(decode_aws_chunked(
                base,
                auth.chunk_signing.clone(),
                trailer_checksum,
                max_frame_bytes,
                sideband.clone(),
                bucket.clone(),
                key.clone(),
            ))
        }
    };

    let checksummed: AppByteStream = match header_checksum {
        Some((algo, expected)) => Box::pin(verify_checksum_header(
            decoded,
            algo,
            expected,
            sideband.clone(),
            bucket.clone(),
            key.clone(),
        )),
        None => decoded,
    };

    Ok(Box::pin(leashed_upload(
        checksummed,
        auth.leash,
        sideband,
        bucket,
        key,
    )))
}
