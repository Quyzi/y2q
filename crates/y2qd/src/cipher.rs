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

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use bytes::{Bytes, BytesMut};
use gxhash::GxHasher;
use std::hash::Hasher;
use y2q_core::crypto::{DecryptedKeystore, envelope};
use y2q_core::storage::streaming_sink::StreamingSink;
use y2q_core::{CipherMetadata, PlaintextMetrics};

use crate::error::AppError;

/// Decrypt a GET body. If `bytes` is not a recognized y2q envelope (i.e.
/// a legacy plaintext object written before encryption was wired in), return
/// it as-is.
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
    if !envelope::looks_encrypted(&bytes) {
        return Ok(bytes.freeze());
    }
    match envelope::decrypt_owned(&keystore.secret_key, bytes) {
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
    envelope::decrypt_v2_chunks(&keystore.secret_key, preamble, chunks_ct, first_chunk_idx).map_err(
        |e| match e {
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
        },
    )
}

/// True if the bytes on disk are a y2q envelope. Used by GET to decide
/// whether a `Range` request can be answered (it cannot for encrypted
/// objects — whole-object AEAD).
pub fn is_encrypted_envelope(bytes: &[u8]) -> bool {
    envelope::looks_encrypted(bytes)
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
pub async fn stream_encrypt_for_put(
    keystore: &DecryptedKeystore,
    mut stream: actix_web::web::Payload,
    sink: StreamingSink,
    bucket: &str,
    key: &str,
    write_offset: u64,
    chunk_size: usize,
) -> Result<(StreamingSink, PlaintextMetrics, CipherMetadata), AppError> {
    use futures::StreamExt;

    let mut session =
        envelope::EncryptSession::new(sink, &keystore.public.public_key, write_offset, chunk_size)
            .await
            .map_err(|_| {
                AppError(y2q_core::Error::EncryptionFailed {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                })
            })?;

    let mut hasher = GxHasher::with_seed(0);
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
        hasher.write(&chunk);
        plaintext_size += chunk.len() as u64;
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

    let digest = hasher.finish().to_le_bytes();

    let cipher_size = info.cipher_size;
    // SHA-256 of the on-disk envelope would require a read-back; omit
    // cipher_sha256 here (set to empty string). The plaintext checksum
    // is a non-cryptographic gxhash64 for fast corruption detection.
    let plaintext_metrics = PlaintextMetrics {
        size: plaintext_size,
        checksum_gxhash_b64: B64.encode(digest),
    };
    let cipher_metadata = CipherMetadata {
        cipher_size,
        cipher_sha256_b64: String::new(),
        kem_alg: info.kem_alg.to_owned(),
        aead_alg: info.aead_alg.to_owned(),
        envelope_version: info.envelope_version,
    };

    Ok((sink, plaintext_metrics, cipher_metadata))
}
