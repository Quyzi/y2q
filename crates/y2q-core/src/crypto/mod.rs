//! Post-quantum encryption layer for stored objects.
//!
//! Every PUT runs a fresh ML-KEM-768 encapsulation against the deployment's
//! single public key; the resulting shared secret is fed through HKDF-SHA256
//! to derive an AES-256-GCM content key that encrypts the whole object body.
//! Range reads on encrypted objects are not supported.
//!
//! Submodules:
//! - [`envelope`] — on-disk format and whole-object AEAD.
//! - [`kdf`] — Argon2id wrap/unwrap of the deployment secret key under a user
//!   password.
//! - [`keystore`] — public-key file (`pubkey.json`) plus first-run generation.
//! - [`user_store`] — redb-backed table of user records (each carrying its own
//!   wrapped copy of the secret key).
//! - [`keys`] — in-memory holders for the live keypair, with zeroize on drop.

pub mod envelope;
pub mod kdf;
pub mod keys;
pub mod keystore;
pub mod metadata_key;
pub mod user_store;

pub use envelope::{ENVELOPE_HEADER_FIXED_LEN, EnvelopeInfo};
pub use kdf::{Argon2Params, WrappedSk, default_argon2_params};
pub use keys::{DecryptedKeystore, Keystore};
pub use keystore::{KeystoreFiles, PubkeyFile};
pub use metadata_key::{decrypt_meta, derive_index_key, derive_mek, encrypt_meta, prf};
pub use user_store::{UserRecord, UserStore, UserSummary};

use crate::Error;

/// Errors raised by the crypto layer before they're attached to a bucket/key
/// and surfaced as [`crate::Error`].
#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    /// A symmetric AEAD operation (encrypt/decrypt or wrap/unwrap) failed.
    #[error("aead failure: {0}")]
    Aead(&'static str),

    /// Argon2id key derivation failed for an unexpected reason.
    #[error("kdf failure: {0}")]
    Kdf(String),

    /// A `pqcrypto` key, ciphertext, or shared-secret blob could not be
    /// decoded back into its typed representation.
    #[error("kem decode: {0}")]
    KemDecode(&'static str),

    /// An on-disk envelope header (magic, version, algorithm tags) did not
    /// match the values this build understands.
    #[error("malformed envelope: {0}")]
    Envelope(&'static str),

    /// The envelope advertised a `format_ver` newer than this build supports.
    #[error("unsupported envelope version: {0}")]
    UnsupportedVersion(u16),

    /// AEAD tag did not verify — ciphertext was tampered with, the wrong key
    /// was used, or the AAD differed.
    #[error("authentication failed")]
    AuthFailed,

    /// I/O against the keystore directory or files failed.
    #[error("keystore io: {0}")]
    KeystoreIo(String),

    /// `pubkey.json` is missing — caller should run first-run setup.
    #[error("keystore not found at {0}")]
    KeystoreMissing(String),

    /// `pubkey.json` exists but could not be parsed.
    #[error("keystore corrupt at {path}: {reason}")]
    KeystoreCorrupt {
        /// Filesystem path of the corrupt keystore.
        path: String,
        /// Short description of the corruption detected.
        reason: String,
    },

    /// User-store (redb) operation failed.
    #[error("user store: {0}")]
    UserStore(String),
}

impl CryptoError {
    /// Convert into the [`Error`] surfaced by [`crate::Storage`] operations,
    /// attaching `bucket`/`key` context where the variant supports it.
    pub fn into_storage_error(self, bucket: &str, key: &str) -> Error {
        match self {
            CryptoError::AuthFailed | CryptoError::Aead(_) | CryptoError::KemDecode(_) => {
                Error::DecryptionFailed {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                }
            }
            CryptoError::Envelope(reason) => Error::EnvelopeMalformed {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                reason: reason.to_owned(),
            },
            CryptoError::UnsupportedVersion(v) => Error::UnsupportedEnvelopeVersion { version: v },
            CryptoError::Kdf(reason) => Error::KdfFailed { reason },
            CryptoError::KeystoreIo(msg) => Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "keystore-io".to_owned(),
                message: msg,
            },
            CryptoError::KeystoreMissing(path) => Error::KeystoreNotFound { path },
            CryptoError::KeystoreCorrupt { path, reason } => {
                Error::KeystoreCorrupt { path, reason }
            }
            CryptoError::UserStore(msg) => Error::Index { message: msg },
        }
    }
}
