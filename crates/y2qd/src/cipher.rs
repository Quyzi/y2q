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
use bytes::Bytes;
use md5::Md5;
use sha2::{Digest, Sha256};
use y2q_core::crypto::{DecryptedKeystore, envelope};
use y2q_core::{CipherMetadata, PlaintextMetrics};

use crate::error::AppError;


/// Decrypt a GET body. If `bytes` is not a recognized y2q envelope (i.e.
/// a legacy plaintext object written before encryption was wired in), return
/// it as-is.
pub fn decrypt_after_get(
    keystore: &DecryptedKeystore,
    bucket: &str,
    key: &str,
    bytes: &[u8],
) -> Result<Bytes, AppError> {
    if !envelope::looks_encrypted(bytes) {
        return Ok(Bytes::copy_from_slice(bytes));
    }
    match envelope::decrypt(&keystore.secret_key, bytes) {
        Ok(pt) => Ok(Bytes::from(pt)),
        Err(y2q_core::crypto::CryptoError::UnsupportedVersion(v)) => Err(AppError(
            y2q_core::Error::UnsupportedEnvelopeVersion { version: v },
        )),
        Err(y2q_core::crypto::CryptoError::Envelope(reason)) => Err(AppError(
            y2q_core::Error::EnvelopeMalformed {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                reason: reason.to_owned(),
            },
        )),
        Err(_) => Err(AppError(y2q_core::Error::DecryptionFailed {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
        })),
    }
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
/// through AES-256-GCM 1 MiB chunks, and writes each encrypted chunk to
/// `file`. Returns the file handle (for the caller to pass to
/// [`StreamingPutGuard::commit`]), plus the plaintext metrics and cipher
/// metadata for the metadata sidecar.
pub async fn stream_encrypt_for_put(
    keystore: &DecryptedKeystore,
    mut stream: actix_web::web::Payload,
    file: tokio::fs::File,
    bucket: &str,
    key: &str,
) -> Result<(tokio::fs::File, PlaintextMetrics, CipherMetadata), AppError> {
    use futures::StreamExt;

    let mut session = envelope::EncryptSession::new(file, &keystore.public.public_key)
        .await
        .map_err(|_| AppError(y2q_core::Error::EncryptionFailed {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
        }))?;

    let mut md5_hasher = Md5::new();
    let mut sha_hasher = Sha256::new();
    let mut plaintext_size: u64 = 0;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| AppError(y2q_core::Error::InternalError {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            operation: "read body".to_owned(),
            message: e.to_string(),
        }))?;
        md5_hasher.update(&chunk);
        sha_hasher.update(&chunk);
        plaintext_size += chunk.len() as u64;
        session.feed(&chunk).await.map_err(|_| AppError(y2q_core::Error::EncryptionFailed {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
        }))?;
    }

    let (file, info) = session.finish().await.map_err(|_| AppError(y2q_core::Error::EncryptionFailed {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
    }))?;

    let md5_digest = md5_hasher.finalize();
    let sha_digest = sha_hasher.finalize();

    let cipher_size = info.cipher_size;
    // Compute SHA-256 of the on-disk envelope by reading it back would be
    // expensive; omit cipher_sha256 for streaming puts (set to empty string).
    // The plaintext checksums remain authoritative for integrity.
    let plaintext_metrics = PlaintextMetrics {
        size: plaintext_size,
        checksum_md5_b64: B64.encode(md5_digest),
        checksum_sha256_b64: B64.encode(sha_digest),
    };
    let cipher_metadata = CipherMetadata {
        cipher_size,
        cipher_sha256_b64: String::new(),
        kem_alg: info.kem_alg.to_owned(),
        aead_alg: info.aead_alg.to_owned(),
        envelope_version: info.envelope_version,
    };

    Ok((file, plaintext_metrics, cipher_metadata))
}
