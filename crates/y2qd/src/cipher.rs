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

/// Bundle returned from [`encrypt_for_put`] — the encrypted envelope bytes
/// the backend should write, plus the metadata fields the sidecar should
/// record.
pub struct EncryptedPut {
    pub envelope: Bytes,
    pub plaintext_metrics: PlaintextMetrics,
    pub cipher_metadata: CipherMetadata,
}

/// Encrypt a PUT body. Computes plaintext checksums + size up-front so the
/// metadata sidecar can record values the user expects to see.
pub fn encrypt_for_put(
    keystore: &DecryptedKeystore,
    bucket: &str,
    key: &str,
    plaintext: &[u8],
) -> Result<EncryptedPut, AppError> {
    let md5_digest = Md5::digest(plaintext);
    let sha_digest = Sha256::digest(plaintext);

    let (envelope_bytes, info) = envelope::encrypt(&keystore.public.public_key, plaintext)
        .map_err(|_| AppError(y2q_core::Error::EncryptionFailed {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
        }))?;

    let cipher_sha = Sha256::digest(&envelope_bytes);

    let plaintext_metrics = PlaintextMetrics {
        size: plaintext.len() as u64,
        checksum_md5_b64: B64.encode(md5_digest),
        checksum_sha256_b64: B64.encode(sha_digest),
    };
    let cipher_metadata = CipherMetadata {
        cipher_size: info.cipher_size,
        cipher_sha256_b64: B64.encode(cipher_sha),
        kem_alg: info.kem_alg.to_owned(),
        aead_alg: info.aead_alg.to_owned(),
        envelope_version: info.envelope_version,
    };
    Ok(EncryptedPut {
        envelope: Bytes::from(envelope_bytes),
        plaintext_metrics,
        cipher_metadata,
    })
}

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
