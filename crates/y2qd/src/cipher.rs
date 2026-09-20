//! Daemon-side encryption adapter.
//!
//! Sits between handlers and the storage backend: PUT plaintext goes through
//! [`encrypt_for_put`] and the resulting envelope is what the backend sees,
//! while GET ciphertext goes through [`decrypt_after_get`] before returning
//! to the client.
//!
//! Plaintext-derived metrics (size + checksums) are computed here so the
//! `Metadata` sidecar reflects what users see, not the encrypted bytes the
//! backend stores.

use bytes::{Bytes, BytesMut};
use y2q_core::crypto::envelope;
use y2q_core::storage::streaming_sink::StreamingSink;
use y2q_core::{CipherMetadata, PlaintextMetrics, StreamChecksum};

use crate::error::AppError;

/// Decrypt a GET body.
///
/// Takes an owned [`BytesMut`] so the AEAD open can run in-place on the
/// input allocation, avoiding a full ciphertext-sized copy that the older
/// `&[u8]` variant required.
///
/// `expected_size` is the object's authenticated plaintext size from its
/// sealed metadata sidecar. The envelope layer requires it because the
/// envelope header's own length field is not covered by the chunk AAD; see
/// [`envelope::decrypt`].
pub fn decrypt_after_get(
    deployment_sk: &[u8],
    bucket: &str,
    key: &str,
    bytes: BytesMut,
    expected_size: u64,
) -> Result<Bytes, AppError> {
    match envelope::decrypt_owned(deployment_sk, bytes, bucket, key, expected_size) {
        Ok(pt) => Ok(pt),
        Err(y2q_core::crypto::CryptoError::UnsupportedVersion(v)) => {
            Err(AppError(y2q_core::Error::UnsupportedEnvelopeVersion {
                version: v,
            }))
        }
        Err(y2q_core::crypto::CryptoError::Envelope(reason)) => {
            Err(AppError(y2q_core::Error::EnvelopeMalformed {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                reason: reason.to_owned(),
            }))
        }
        Err(_) => Err(AppError(y2q_core::Error::DecryptionFailed {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
        })),
    }
}

/// Decrypt a contiguous run of v3 chunks for a ranged GET.
///
/// `preamble` is the first [`envelope::v3_preamble_len`] bytes of the object,
/// `chunks_ct` the ciphertext window starting at chunk `first_chunk_idx`.
/// Returns the plaintext of those whole chunks; the caller trims to the exact
/// requested byte range. Maps crypto errors to the same [`AppError`] variants
/// as [`decrypt_after_get`].
pub fn decrypt_v3_chunks(
    bucket_sk: &[u8],
    bucket: &str,
    key: &str,
    preamble: &[u8],
    chunks_ct: &[u8],
    first_chunk_idx: u64,
) -> Result<Vec<u8>, AppError> {
    envelope::decrypt_v3_chunks(bucket_sk, preamble, chunks_ct, first_chunk_idx, bucket, key)
        .map_err(|e| match e {
            y2q_core::crypto::CryptoError::UnsupportedVersion(v) => {
                AppError(y2q_core::Error::UnsupportedEnvelopeVersion { version: v })
            }
            y2q_core::crypto::CryptoError::Envelope(reason) => {
                AppError(y2q_core::Error::EnvelopeMalformed {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    reason: reason.to_owned(),
                })
            }
            _ => AppError(y2q_core::Error::DecryptionFailed {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
            }),
        })
}

/// Decrypt a contiguous run of v4 chunks for a ranged GET. Same contract as
/// [`decrypt_v3_chunks`] plus `total_chunks` — the object's true total chunk
/// count, required so the v4 final-chunk AAD marker (see
/// `y2q_core::crypto::envelope`'s module docs) is applied to the right
/// chunk. See [`decrypt_v4_chunks`] in `envelope` for how callers compute it.
#[allow(clippy::too_many_arguments)]
pub fn decrypt_v4_chunks(
    bucket_sk: &[u8],
    bucket: &str,
    key: &str,
    preamble: &[u8],
    chunks_ct: &[u8],
    first_chunk_idx: u64,
    total_chunks: u64,
) -> Result<Vec<u8>, AppError> {
    envelope::decrypt_v4_chunks(
        bucket_sk,
        preamble,
        chunks_ct,
        first_chunk_idx,
        total_chunks,
        bucket,
        key,
    )
    .map_err(|e| match e {
        y2q_core::crypto::CryptoError::UnsupportedVersion(v) => {
            AppError(y2q_core::Error::UnsupportedEnvelopeVersion { version: v })
        }
        y2q_core::crypto::CryptoError::Envelope(reason) => {
            AppError(y2q_core::Error::EnvelopeMalformed {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                reason: reason.to_owned(),
            })
        }
        _ => AppError(y2q_core::Error::DecryptionFailed {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
        }),
    })
}

/// Stream-encrypt a PUT payload directly to `file` using the v3 chunked
/// envelope format, computing plaintext checksums along the way.
///
/// Consumes chunks from `stream` — an `actix_web::web::Payload` for a plain
/// PUT, or an S3 upload adapter chain (`aws-chunked` decoding, checksum
/// verification, session-leash re-checks) for the S3 gateway — feeds them
/// through AES-256-GCM in `chunk_size`-byte plaintext chunks, and writes each
/// encrypted chunk to `file`. Returns the file handle (for the caller to pass to
/// [`AnyStreamingPutGuard::commit`]), plus the plaintext metrics and cipher
/// metadata for the metadata sidecar.
///
/// `write_offset` is the byte offset within `file` at which the v3 envelope
/// starts. Pass the value returned by
/// [`AnyStorage::begin_streaming_put`]: `0` for the filesystem backend, `64`
/// for the uring backend.
///
/// `bucket_pk`/`key_epoch` are the *current* bucket key epoch's public key
/// and epoch number (resolved by the caller from the bucket's
/// [`BucketConfig::keys`](y2q_core::BucketKeyVersion) before calling). Only
/// the public half is needed (ML-KEM encapsulation).
///
/// `max_bytes`, when set, aborts the stream as soon as the running plaintext
/// byte count exceeds it — enforced here (not just via a `Content-Length`
/// pre-check) because chunked transfer encoding carries no `Content-Length`
/// at all, and a pre-check alone would let such a request bypass any size
/// cap entirely.
#[allow(clippy::too_many_arguments)]
pub async fn stream_encrypt_for_put(
    bucket_pk: &[u8],
    key_epoch: u32,
    mut stream: impl futures_util::Stream<Item = Result<Bytes, AppError>> + Unpin,
    sink: StreamingSink,
    bucket: &str,
    key: &str,
    write_offset: u64,
    chunk_size: usize,
    max_bytes: Option<u64>,
) -> Result<(StreamingSink, PlaintextMetrics, CipherMetadata), AppError> {
    use futures_util::StreamExt;

    let mut session = envelope::EncryptSession::new(
        sink,
        bucket_pk,
        key_epoch,
        bucket,
        key,
        write_offset,
        chunk_size,
    )
    .await
    .map_err(|_| {
        AppError(y2q_core::Error::EncryptionFailed {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
        })
    })?;

    let mut hasher = StreamChecksum::new();
    let mut plaintext_size: u64 = 0;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        hasher.update(&chunk);
        plaintext_size += chunk.len() as u64;
        if let Some(limit) = max_bytes
            && plaintext_size > limit
        {
            return Err(AppError(y2q_core::Error::BodyTooLarge {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                limit,
            }));
        }
        session.feed(&chunk).await.map_err(|_| {
            AppError(y2q_core::Error::EncryptionFailed {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
            })
        })?;
    }

    let (sink, info) = session.finish().await.map_err(|_| {
        AppError(y2q_core::Error::EncryptionFailed {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
        })
    })?;

    let cipher_size = info.cipher_size;
    // Both checksums are non-cryptographic XXH3-64, for corruption/divergence
    // detection only — tamper resistance is the per-chunk AEAD tag's job, not
    // either checksum's. The plaintext one is computed here from the stream;
    // the ciphertext one was computed incrementally inside `EncryptSession`
    // as each chunk was written, so no read-back was needed for either.
    let plaintext_metrics = PlaintextMetrics {
        size: plaintext_size,
        checksum_gxhash_b64: hasher.finish_b64(),
    };
    let cipher_metadata = CipherMetadata {
        cipher_size,
        cipher_checksum_b64: info.cipher_checksum_b64,
        kem_alg: info.kem_alg.to_owned(),
        aead_alg: info.aead_alg.to_owned(),
        envelope_version: info.envelope_version,
        key_epoch: info.key_epoch,
    };

    Ok((sink, plaintext_metrics, cipher_metadata))
}

/// Encrypt an already-in-memory plaintext buffer directly to `sink` using the
/// v3 chunked envelope format. The non-streaming counterpart to
/// [`stream_encrypt_for_put`], used by the rekey job: unlike an HTTP PUT, the
/// plaintext there comes from decrypting an existing object rather than a
/// client's request body, so there is no [`actix_web::web::Payload`] to
/// consume from.
#[allow(clippy::too_many_arguments)]
pub async fn encrypt_bytes_for_put(
    bucket_pk: &[u8],
    key_epoch: u32,
    plaintext: &[u8],
    sink: StreamingSink,
    bucket: &str,
    key: &str,
    write_offset: u64,
    chunk_size: usize,
) -> Result<(StreamingSink, PlaintextMetrics, CipherMetadata), AppError> {
    let mut session = envelope::EncryptSession::new(
        sink,
        bucket_pk,
        key_epoch,
        bucket,
        key,
        write_offset,
        chunk_size,
    )
    .await
    .map_err(|_| {
        AppError(y2q_core::Error::EncryptionFailed {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
        })
    })?;

    session.feed(plaintext).await.map_err(|_| {
        AppError(y2q_core::Error::EncryptionFailed {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
        })
    })?;

    let (sink, info) = session.finish().await.map_err(|_| {
        AppError(y2q_core::Error::EncryptionFailed {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
        })
    })?;

    let mut hasher = StreamChecksum::new();
    hasher.update(plaintext);
    let plaintext_metrics = PlaintextMetrics {
        size: plaintext.len() as u64,
        checksum_gxhash_b64: hasher.finish_b64(),
    };
    let cipher_metadata = CipherMetadata {
        cipher_size: info.cipher_size,
        cipher_checksum_b64: info.cipher_checksum_b64,
        kem_alg: info.kem_alg.to_owned(),
        aead_alg: info.aead_alg.to_owned(),
        envelope_version: info.envelope_version,
        key_epoch: info.key_epoch,
    };

    Ok((sink, plaintext_metrics, cipher_metadata))
}

/// AES-256-GCM authentication tag length appended to each v3/v4 chunk on disk.
const CHUNK_TAG_LEN: u64 = 16;

/// Geometry parsed from an object's envelope preamble, shared by every chunk
/// [`plaintext_stream`] fetches.
struct StreamGeometry {
    preamble: Bytes,
    chunk_size: u64,
    /// `Some(total_chunks)` for a v4 envelope (needed for the final-chunk AAD
    /// marker), `None` for legacy v3.
    v4_total_chunks: Option<u64>,
}

/// State machine driving [`plaintext_stream`]'s [`futures_util::stream::try_unfold`].
struct StreamState {
    storage: std::sync::Arc<y2q_core::AnyStorage>,
    bucket: String,
    key: String,
    md: y2q_core::Metadata,
    bucket_sk: y2q_core::secmem::SecretVec,
    start: u64,
    end: u64,
    /// `None` until the preamble has been fetched and geometry parsed.
    geometry: Option<StreamGeometry>,
    /// Next chunk index to fetch. Meaningless until `geometry` is `Some`.
    cur: u64,
}

/// Stream the plaintext of `[start, end]` (inclusive, plaintext byte offsets)
/// of an object, decrypting one envelope chunk at a time so peak memory is
/// one chunk rather than the whole object.
///
/// `md` must be the object's trusted metadata (it supplies the authenticated
/// plaintext size and `cipher_size`); `bucket_sk` must already be resolved
/// for `md.key_epoch`. Callers must validate `start <= end < md.size`
/// themselves (e.g. as `handlers::get::handle` already does) — this function
/// does not re-derive the 416 Range Not Satisfiable decision.
///
/// Handles v4 (current) and v3 (legacy, read-only) envelopes with the same
/// chunk arithmetic `handlers::get` uses; any other version yields
/// [`y2q_core::Error::UnsupportedEnvelopeVersion`].
pub fn plaintext_stream(
    storage: std::sync::Arc<y2q_core::AnyStorage>,
    bucket: String,
    key: String,
    md: y2q_core::Metadata,
    bucket_sk: y2q_core::secmem::SecretVec,
    start: u64,
    end: u64,
) -> impl futures_util::Stream<Item = Result<Bytes, AppError>> + Unpin {
    use y2q_core::Storage;

    let state = StreamState {
        storage,
        bucket,
        key,
        md,
        bucket_sk,
        start,
        end,
        geometry: None,
        cur: 0,
    };
    Box::pin(futures_util::stream::try_unfold(
        state,
        move |mut state| async move {
            // Lazily fetch the preamble and parse geometry on the first poll.
            if state.geometry.is_none() {
                let preamble_len = envelope::v3_preamble_len() as u64;
                let preamble = state
                    .storage
                    .get_range(&state.bucket, &state.key, (0..=preamble_len - 1).into())
                    .await
                    .map_err(AppError::from)?;
                let (chunk_size, v4_total_chunks) = match state.md.envelope_version {
                    Some(3) => {
                        let (_epoch, chunk_size_u32, _) = envelope::parse_v3_geometry(&preamble)
                            .map_err(|_| {
                                AppError(y2q_core::Error::EnvelopeMalformed {
                                    bucket: state.bucket.clone(),
                                    key: state.key.clone(),
                                    reason: "bad v3 header".to_owned(),
                                })
                            })?;
                        (chunk_size_u32 as u64, None)
                    }
                    Some(4) => {
                        let (_epoch, chunk_size_u32, _) = envelope::parse_v4_geometry(&preamble)
                            .map_err(|_| {
                                AppError(y2q_core::Error::EnvelopeMalformed {
                                    bucket: state.bucket.clone(),
                                    key: state.key.clone(),
                                    reason: "bad v4 header".to_owned(),
                                })
                            })?;
                        let chunk_size = chunk_size_u32 as u64;
                        let total_chunks = envelope::padme_len(state.md.size).div_ceil(chunk_size);
                        (chunk_size, Some(total_chunks))
                    }
                    other => {
                        return Err(AppError(y2q_core::Error::UnsupportedEnvelopeVersion {
                            version: other.unwrap_or(0),
                        }));
                    }
                };
                state.cur = state.start / chunk_size;
                state.geometry = Some(StreamGeometry {
                    preamble,
                    chunk_size,
                    v4_total_chunks,
                });
            }

            let geometry = state.geometry.as_ref().expect("just initialized above");
            let chunk_size = geometry.chunk_size;
            let last = state.end / chunk_size;
            if state.cur > last {
                return Ok(None);
            }

            let preamble_len = geometry.preamble.len() as u64;
            let stride = chunk_size + CHUNK_TAG_LEN;
            let cipher_start = preamble_len + state.cur * stride;
            let cipher_end_calc = preamble_len + (state.cur + 1) * stride - 1;
            let cipher_end = match state.md.cipher_size {
                Some(cs) => cipher_end_calc.min(cs - 1),
                None => cipher_end_calc,
            };
            let window = state
                .storage
                .get_range(
                    &state.bucket,
                    &state.key,
                    (cipher_start..=cipher_end).into(),
                )
                .await
                .map_err(AppError::from)?;
            // The backend must return exactly the requested range; a short read
            // means the on-disk object is smaller than the trusted metadata says
            // it should be (truncated after the fact) — never surface that as a
            // silently short body.
            if window.len() as u64 != cipher_end - cipher_start + 1 {
                return Err(AppError(y2q_core::Error::EnvelopeMalformed {
                    bucket: state.bucket.clone(),
                    key: state.key.clone(),
                    reason: "on-disk object shorter than recorded metadata".to_owned(),
                }));
            }

            let chunk_pt = match geometry.v4_total_chunks {
                Some(total_chunks) => decrypt_v4_chunks(
                    &state.bucket_sk,
                    &state.bucket,
                    &state.key,
                    &geometry.preamble,
                    &window,
                    state.cur,
                    total_chunks,
                )?,
                None => decrypt_v3_chunks(
                    &state.bucket_sk,
                    &state.bucket,
                    &state.key,
                    &geometry.preamble,
                    &window,
                    state.cur,
                )?,
            };

            let chunk_pt_start_abs = state.cur * chunk_size;
            let trim_front = state.start.saturating_sub(chunk_pt_start_abs) as usize;
            let last_valid_idx = chunk_pt.len().saturating_sub(1);
            let trim_back_idx = if state.cur == last {
                ((state.end - chunk_pt_start_abs) as usize).min(last_valid_idx)
            } else {
                last_valid_idx
            };
            let out = Bytes::from(chunk_pt).slice(trim_front..=trim_back_idx);

            state.cur += 1;
            Ok(Some((out, state)))
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, HttpResponse, test, web};
    use y2q_core::crypto::kem;

    async fn tempfile_sink() -> StreamingSink {
        let path = std::env::temp_dir().join(format!(
            "y2qd_cipher_test_{}.env",
            std::process::id() as u64 * 1_000_003 + rand_u64()
        ));
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .await
            .unwrap();
        StreamingSink::Tokio(file)
    }

    fn rand_u64() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos() as u64
    }

    /// Handler under test: a thin actix wrapper so `web::Payload` (which has
    /// no public constructor outside the extractor machinery) can be driven
    /// through real actix request handling.
    async fn put_probe(
        payload: web::Payload,
        pk: web::Data<Vec<u8>>,
    ) -> Result<HttpResponse, AppError> {
        let sink = tempfile_sink().await;
        let mapped = futures_util::TryStreamExt::map_err(payload, |e| {
            AppError(y2q_core::Error::InternalError {
                bucket: "bucket".to_owned(),
                key: "key".to_owned(),
                operation: "read body".to_owned(),
                message: e.to_string(),
            })
        });
        let (_, _, _) = stream_encrypt_for_put(
            &pk,
            0,
            mapped,
            sink,
            "bucket",
            "key",
            0,
            y2q_core::crypto::envelope::DEFAULT_CHUNK_SIZE_BYTES,
            Some(16),
        )
        .await?;
        Ok(HttpResponse::Ok().finish())
    }

    #[actix_web::test]
    async fn mid_stream_cap_rejects_oversized_body_with_no_content_length_reliance() {
        let (pk, _sk) = kem::keypair();
        let pk_bytes = pk.to_bytes().to_vec();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pk_bytes))
                .route("/put", web::post().to(put_probe)),
        )
        .await;

        // Within the 16-byte cap: succeeds.
        let req = test::TestRequest::post()
            .uri("/put")
            .set_payload(vec![0u8; 10])
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        // Past the cap: the mid-stream check must reject it with 413, purely
        // from the running byte count `stream_encrypt_for_put` tracks as it
        // consumes the body — not from any `Content-Length` pre-check (there
        // is none in this handler at all).
        let req = test::TestRequest::post()
            .uri("/put")
            .set_payload(vec![0u8; 1024])
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 413);
    }
}
