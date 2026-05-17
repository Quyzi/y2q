//! Metadata Encryption Key (MEK) derivation and encrypt/decrypt helpers.
//!
//! The MEK is derived from the deployment public key alone:
//!     MEK = SHA-256(pk_bytes || "y2q-metadata-encryption-key-v1")
//!
//! This means anyone with the public-key file (in `keystore_dir`) can derive
//! the MEK without a user login. An attacker who has only the storage
//! directory cannot, because the public key lives elsewhere.
//!
//! Encrypted metadata wire format:
//!     [0x01 | 12-byte random nonce | AES-256-GCM(meta_json)]
//!
//! Legacy metadata (written before encryption was enabled) begins with any
//! byte other than 0x01 and is passed through as plain JSON for backward
//! compatibility.

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

use super::CryptoError;

type HmacSha256 = Hmac<Sha256>;

const DERIVATION_LABEL: &[u8] = b"y2q-metadata-encryption-key-v1";
const INDEX_KEY_LABEL: &[u8] = b"y2q-index-key-v1";
const VERSION_BYTE: u8 = 0x01;
const NONCE_LEN: usize = 12;
/// Minimum blob size for an encrypted blob: version + nonce + GCM tag.
const MIN_ENCRYPTED_LEN: usize = 1 + NONCE_LEN + 16;

/// HMAC-SHA256 keyed PRF: `HMAC(key, data) → [u8; 32]`.
///
/// Used both to derive sub-keys and to blind index key fields.
pub fn prf(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Derive the Index Key (IK) from the MEK.
///
/// `IK = HMAC-SHA256(MEK, "y2q-index-key-v1")`
///
/// IK is used exclusively for HMAC-blinding redb index keys; the MEK is used
/// for AES-256-GCM value encryption. Keeping them separate ensures that
/// compromise of one operation does not directly expose the other.
pub fn derive_index_key(mek: &[u8; 32]) -> [u8; 32] {
    prf(mek, INDEX_KEY_LABEL)
}

/// Derive the Metadata Encryption Key from the raw bytes of the deployment
/// public key.
pub fn derive_mek(pk_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(pk_bytes);
    h.update(DERIVATION_LABEL);
    h.finalize().into()
}

/// Encrypt `json` with AES-256-GCM under `mek`.
///
/// Returns `[0x01 | 12-byte nonce | ciphertext]`.
pub fn encrypt_meta(mek: &[u8; 32], json: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(mek.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, json)
        .map_err(|_| CryptoError::Aead("metadata encrypt"))?;
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(VERSION_BYTE);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt or pass through a metadata blob.
///
/// - First byte `0x01` → AES-256-GCM encrypted; decrypt and return the JSON.
/// - Any other first byte → legacy plaintext JSON; return as-is.
pub fn decrypt_meta(mek: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.is_empty() || blob[0] != VERSION_BYTE {
        return Ok(blob.to_vec());
    }
    if blob.len() < MIN_ENCRYPTED_LEN {
        return Err(CryptoError::Envelope(
            "metadata blob too short for decryption",
        ));
    }
    let nonce = aes_gcm::Nonce::from_slice(&blob[1..1 + NONCE_LEN]);
    let ct = &blob[1 + NONCE_LEN..];
    let cipher = Aes256Gcm::new(mek.into());
    cipher
        .decrypt(nonce, ct)
        .map_err(|_| CryptoError::AuthFailed)
}
