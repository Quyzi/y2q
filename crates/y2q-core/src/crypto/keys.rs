//! In-memory holders for the deployment keypair.
//!
//! - [`Keystore`] holds just the public key — always available, never secret.
//! - [`DecryptedKeystore`] adds the unwrapped secret key. The SK bytes are
//!   zeroized on drop so a routine `Arc` deref-count drop scrubs them from
//!   process memory.

use std::sync::Arc;

use zeroize::Zeroizing;

/// Public-only view of the deployment keypair.
///
/// Loaded from `pubkey.json` at startup; safe to share freely.
#[derive(Debug, Clone)]
pub struct Keystore {
    /// Raw ML-KEM-768 public key bytes (1184 bytes for ML-KEM-768).
    pub public_key: Arc<Vec<u8>>,
    /// `kem_alg` string — currently always `"ml-kem-768"`.
    pub kem_alg: String,
    /// SHA-256 fingerprint of `public_key`, lowercase hex.
    pub fingerprint: String,
}

/// Public + secret-key view of the deployment keypair.
///
/// Constructed only after a successful login that unwraps the SK from a user
/// record. The secret key bytes live behind a [`Zeroizing`] buffer so they
/// are cleared from memory as soon as the last `Arc` referencing them is
/// dropped.
pub struct DecryptedKeystore {
    /// Public-key half (cloneable, non-secret).
    pub public: Keystore,
    /// Raw ML-KEM-768 secret key bytes (zeroized on drop).
    pub secret_key: Zeroizing<Vec<u8>>,
}

// `Zeroizing` only scrubs on drop — it forwards `Debug` to the inner type, so
// a derived impl here would print the raw secret key. Redact it explicitly.
impl std::fmt::Debug for DecryptedKeystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedKeystore")
            .field("public", &self.public)
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

impl DecryptedKeystore {
    /// Construct a new decrypted keystore from a public-key view and the
    /// freshly-unwrapped secret key bytes.
    pub fn new(public: Keystore, secret_key: Vec<u8>) -> Self {
        Self {
            public,
            secret_key: Zeroizing::new(secret_key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_secret_key() {
        let public = Keystore {
            public_key: Arc::new(vec![1, 2, 3]),
            kem_alg: "ml-kem-768".to_owned(),
            fingerprint: "deadbeef".to_owned(),
        };
        // A distinctive byte pattern that must never appear in the Debug output.
        let secret_key = vec![0x13u8, 0x37, 0x42, 0x99, 0xAB, 0xCD];
        let ks = DecryptedKeystore::new(public, secret_key.clone());

        let formatted = format!("{ks:?}");
        assert!(formatted.contains("<redacted>"));
        assert!(!formatted.contains(&format!("{secret_key:?}")));
    }
}
