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
#[derive(Debug)]
pub struct DecryptedKeystore {
    /// Public-key half (cloneable, non-secret).
    pub public: Keystore,
    /// Raw ML-KEM-768 secret key bytes (zeroized on drop).
    pub secret_key: Zeroizing<Vec<u8>>,
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
