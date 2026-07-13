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
use y2q_core::crypto::{DecryptedKeystore, envelope};
use y2q_core::storage::streaming_sink::StreamingSink;
use y2q_core::{CipherMetadata, PlaintextMetrics, StreamChecksum};

use crate::error::AppError;

/// Decrypt a GET body.
///
/// Takes an owned [`BytesMut`] so the AEAD open can run in-place on the
/// input allocation, avoiding a full ciphertext-sized copy that the older
/// `&[u8]` variant required.
pub fn decrypt_after_get(
    keystore: &DecryptedKeystore,
    bucket: &str,
    key: &str,
    bytes: BytesMut,
) -> Result<Bytes, AppError> {
    match envelope::decrypt_owned(&keystore.secret_key, bytes, bucket, key) {
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

/// Decrypt a contiguous run of v2 chunks for a ranged GET.
///
/// `preamble` is the first [`envelope::v2_preamble_len`] bytes of the object,
/// `chunks_ct` the ciphertext window starting at chunk `first_chunk_idx`.
/// Returns the plaintext of those whole chunks; the caller trims to the exact
/// requested byte range. Maps crypto errors to the same [`AppError`] variants
/// as [`decrypt_after_get`].
pub fn decrypt_v2_chunks(
    keystore: &DecryptedKeystore,
    bucket: &str,
    key: &str,
    preamble: &[u8],
    chunks_ct: &[u8],
    first_chunk_idx: u64,
) -> Result<Vec<u8>, AppError> {
    envelope::decrypt_v2_chunks(
        &keystore.secret_key,
        preamble,
        chunks_ct,
        first_chunk_idx,
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

/// Stream-encrypt a PUT payload directly to `file` using the v2 chunked
/// envelope format, computing plaintext checksums along the way.
///
/// Consumes chunks from `stream` (an `actix_web::web::Payload`), feeds them
/// through AES-256-GCM in `chunk_size`-byte plaintext chunks, and writes each
/// encrypted chunk to `file`. Returns the file handle (for the caller to pass to
/// [`AnyStreamingPutGuard::commit`]), plus the plaintext metrics and cipher
/// metadata for the metadata sidecar.
///
/// `write_offset` is the byte offset within `file` at which the v2 envelope
/// starts. Pass the value returned by
/// [`AnyStorage::begin_streaming_put`]: `0` for the filesystem backend, `64`
/// for the uring backend.
///
/// Only the deployment **public** key is needed (ML-KEM encapsulation), so this
/// works both on the client PUT path (from the logged-in keystore) and on the
/// cluster HEAD path (from the provisioned public keystore, no login).
///
/// `max_bytes`, when set, aborts the stream as soon as the running plaintext
/// byte count exceeds it — enforced here (not just via a `Content-Length`
/// pre-check) because chunked transfer encoding carries no `Content-Length`
/// at all, and a pre-check alone would let such a request bypass any size
/// cap entirely.
#[allow(clippy::too_many_arguments)]
pub async fn stream_encrypt_for_put(
    public_key: &[u8],
    mut stream: actix_web::web::Payload,
    sink: StreamingSink,
    bucket: &str,
    key: &str,
    write_offset: u64,
    chunk_size: usize,
    max_bytes: Option<u64>,
) -> Result<(StreamingSink, PlaintextMetrics, CipherMetadata), AppError> {
    use futures::StreamExt;

    let mut session =
        envelope::EncryptSession::new(sink, public_key, bucket, key, write_offset, chunk_size)
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
        let chunk = chunk.map_err(|e| {
            AppError(y2q_core::Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "read body".to_owned(),
                message: e.to_string(),
            })
        })?;
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
    };

    Ok((sink, plaintext_metrics, cipher_metadata))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, HttpResponse, test, web};
    use pqcrypto::kem::mlkem768;
    use pqcrypto_traits::kem::PublicKey as _;

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
        let (_, _, _) = stream_encrypt_for_put(
            &pk,
            payload,
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
        let (pk, _sk) = mlkem768::keypair();
        let pk_bytes = pk.as_bytes().to_vec();

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
