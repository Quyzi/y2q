//! Metadata Encryption Key (MEK) derivation and encrypt/decrypt helpers.
//!
//! The MEK is derived from the deployment *secret* key:
//!     MEK = SHA-256(sk_bytes || "y2q-metadata-encryption-key-v2")
//!
//! The secret key is wrapped per-user under an Argon2id-derived KEK and is only
//! unwrapped in memory after a successful login, so the MEK is unavailable until
//! someone authenticates. An attacker holding only the on-disk files - the
//! storage directory and the keystore directory (which contains just the public
//! key plus password-wrapped secret keys) - cannot derive the MEK without a
//! user password. This gives metadata the same confidentiality boundary as
//! object bodies, which already require the secret key to decrypt.
//!
//! Encrypted metadata wire format:
//!     [0x01 | 12-byte random nonce | AES-256-GCM(meta_json)]
//!
//! Legacy metadata (written before encryption was enabled) begins with any
//! byte other than 0x01 and is passed through as plain JSON for backward
//! compatibility.

use std::sync::RwLock;

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::CryptoError;

type HmacSha256 = Hmac<Sha256>;

const DERIVATION_LABEL: &[u8] = b"y2q-metadata-encryption-key-v2";
const INDEX_KEY_LABEL: &[u8] = b"y2q-index-key-v1";
const INDEX_FILE_KEY_LABEL: &[u8] = b"y2q-index-file-key-v1";
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

/// Derive the whole-file encryption key for the metadata index redb file.
///
/// `FK = HMAC-SHA256(MEK, "y2q-index-file-key-v1")`
///
/// Used by [`crate::storage::EncryptedFileBackend`] to encrypt every block of
/// the `_y2q_index.redb` file at rest. Domain-separated from the MEK (object
/// sidecar encryption) and the Index Key. Deterministic from the MEK, so the
/// same file key is recovered on every restart + login - the existing
/// encrypted index file reopens without any rewrapping.
pub fn derive_index_file_key(mek: &[u8; 32]) -> [u8; 32] {
    prf(mek, INDEX_FILE_KEY_LABEL)
}

/// Derive the Metadata Encryption Key from the raw bytes of the deployment
/// *secret* key.
///
/// The secret key is only available in memory after a login unwraps it, so the
/// returned MEK inherits that confidentiality: it cannot be computed from the
/// on-disk public key or storage directory alone.
pub fn derive_mek(sk_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(sk_bytes);
    h.update(DERIVATION_LABEL);
    h.finalize().into()
}

/// Live, clearable holder for the Metadata Encryption Key and its derived
/// Index Key.
///
/// Installed at login from the deployment secret key (see [`derive_mek`]) and
/// zeroized via [`MekSlot::clear`] when the daemon goes idle, mirroring the
/// secret-key drop. Neither key lingers in memory while no session is active.
/// The MEK is deterministic from the secret key, so re-installing after an idle
/// clear restores the same keys. Shared (behind an `Arc`) by the storage
/// backend and its metadata index so a single install/clear covers both.
#[derive(Default)]
pub struct MekSlot {
    inner: RwLock<Option<MekKeys>>,
}

struct MekKeys {
    mek: Zeroizing<[u8; 32]>,
    ik: Zeroizing<[u8; 32]>,
}

impl MekSlot {
    /// An empty slot.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(None),
        }
    }

    /// Install the MEK, deriving and storing the Index Key alongside it.
    /// Replaces any prior value.
    pub fn install(&self, mek: [u8; 32]) {
        let ik = derive_index_key(&mek);
        *self.inner.write().expect("MekSlot poisoned") = Some(MekKeys {
            mek: Zeroizing::new(mek),
            ik: Zeroizing::new(ik),
        });
    }

    /// Zeroize and drop the stored keys. Returns `true` if a key was present.
    pub fn clear(&self) -> bool {
        self.inner
            .write()
            .expect("MekSlot poisoned")
            .take()
            .is_some()
    }

    /// A copy of the MEK, if installed.
    pub fn mek(&self) -> Option<[u8; 32]> {
        self.inner
            .read()
            .expect("MekSlot poisoned")
            .as_ref()
            .map(|k| *k.mek)
    }

    /// Copies of the MEK and Index Key, if installed.
    pub fn mek_ik(&self) -> (Option<[u8; 32]>, Option<[u8; 32]>) {
        match self.inner.read().expect("MekSlot poisoned").as_ref() {
            Some(k) => (Some(*k.mek), Some(*k.ik)),
            None => (None, None),
        }
    }

    /// Whether a key is currently installed.
    pub fn is_set(&self) -> bool {
        self.inner.read().expect("MekSlot poisoned").is_some()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mek_is_deterministic_per_secret_key() {
        let sk = b"deployment-secret-key-bytes";
        assert_eq!(derive_mek(sk), derive_mek(sk));
    }

    #[test]
    fn mek_differs_across_secret_keys() {
        assert_ne!(derive_mek(b"sk-one"), derive_mek(b"sk-two"));
    }

    #[test]
    fn mek_uses_v2_label() {
        // Guard against accidentally reverting to the legacy public-key label.
        // The v2 MEK must match an explicit SHA-256(sk || v2-label) computation
        // and must differ from what the old v1 label would have produced.
        let sk = b"some-secret-key";
        let mut h = Sha256::new();
        h.update(sk);
        h.update(b"y2q-metadata-encryption-key-v2");
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(derive_mek(sk), expected);

        let mut h1 = Sha256::new();
        h1.update(sk);
        h1.update(b"y2q-metadata-encryption-key-v1");
        let v1: [u8; 32] = h1.finalize().into();
        assert_ne!(derive_mek(sk), v1);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mek = derive_mek(b"sk");
        let blob = encrypt_meta(&mek, b"{\"hello\":\"world\"}").unwrap();
        assert_eq!(blob[0], VERSION_BYTE);
        assert_eq!(decrypt_meta(&mek, &blob).unwrap(), b"{\"hello\":\"world\"}");
    }

    #[test]
    fn wrong_mek_fails_to_decrypt() {
        let blob = encrypt_meta(&derive_mek(b"sk-a"), b"secret").unwrap();
        assert!(matches!(
            decrypt_meta(&derive_mek(b"sk-b"), &blob),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn mek_slot_install_clear_reinstall() {
        let slot = MekSlot::new();
        assert!(!slot.is_set());
        assert_eq!(slot.mek(), None);
        assert_eq!(slot.mek_ik(), (None, None));

        let mek = derive_mek(b"sk");
        slot.install(mek);
        assert!(slot.is_set());
        assert_eq!(slot.mek(), Some(mek));
        let (m, ik) = slot.mek_ik();
        assert_eq!(m, Some(mek));
        assert_eq!(ik, Some(derive_index_key(&mek)));

        // Clearing zeroizes and drops; reports that a key was present.
        assert!(slot.clear());
        assert!(!slot.is_set());
        assert_eq!(slot.mek(), None);
        // Clearing an empty slot reports nothing was present.
        assert!(!slot.clear());

        // Deterministic re-install restores the same keys (idle drop -> relogin).
        slot.install(derive_mek(b"sk"));
        assert_eq!(slot.mek(), Some(mek));
    }

    #[test]
    fn legacy_plaintext_passes_through() {
        // Any blob not starting with VERSION_BYTE is treated as legacy plaintext.
        let plain = b"{\"legacy\":true}";
        assert_eq!(decrypt_meta(&derive_mek(b"sk"), plain).unwrap(), plain);
    }
}
