//! Post-quantum encryption layer for stored objects.
//!
//! Every PUT runs a fresh ML-KEM-768 encapsulation against the deployment's
//! single public key (transitional through phases 1-2 — phase 3 replaces it
//! with per-bucket keys); the resulting shared secret is fed through
//! HKDF-SHA256 to derive an AES-256-GCM content key that encrypts the
//! object body in fixed-size chunks, supporting ranged reads.
//!
//! Submodules:
//! - [`envelope`] — on-disk format and whole-object AEAD.
//! - [`kdf`] — Argon2id wrap/unwrap of credential-slot payloads.
//! - [`keystore`] — keystore manifest (`keystore.json`) plus first-run
//!   generation.
//! - [`node_key`] — resolves the operator-supplied node key at boot.
//! - [`node_keys`] — derives every server-structural key from the node key.
//! - [`seal`] — ML-KEM-768 public-key sealing (wrap under a recipient's
//!   public key rather than a password).
//! - [`user_store`] — redb-backed table of user records, each carrying
//!   [`user_store::CREDENTIAL_SLOTS`] credential slots.

pub mod envelope;
pub mod kdf;
pub mod keystore;
pub mod node_key;
pub mod node_keys;
pub mod seal;
pub mod user_store;

pub use envelope::EnvelopeInfo;
pub use kdf::{Argon2Params, WrappedSk, default_argon2_params, unwrap_with_key, wrap_with_key};
pub use keystore::KeystoreFiles;
pub use node_key::load_node_key;
pub use node_keys::{
    NodeKeySlot, decrypt_meta, derive_bucket_config_key, derive_control_store_key,
    derive_index_file_key, derive_index_key, derive_node_key_verifier, derive_object_metadata_key,
    derive_path_key, encrypt_meta, prf,
};
pub use seal::{
    SealedKey, bucket_grant_aad, bucket_sk_wrap_aad, open_sealed, seal_to, seal_to_slots,
};
pub use user_store::{
    CREDENTIAL_SLOTS, CredentialSlot, Role, SlotPayload, UserRecord, UserStore, UserSummary,
};

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

    /// `keystore.json` is missing - caller should run first-run setup.
    #[error("keystore not found at {0}")]
    KeystoreMissing(String),

    /// `keystore.json` exists but could not be parsed.
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

    /// Neither `Y2QD_NODE_KEY` nor `[crypto] node_key_file` supplied a node
    /// key at boot.
    #[error("node key not supplied: set Y2QD_NODE_KEY or [crypto] node_key_file")]
    NodeKeyMissing,

    /// The supplied node key material failed to decode or was too short.
    #[error("node key malformed: {0}")]
    NodeKeyMalformed(String),

    /// The supplied node key's verifier does not match the one stored in
    /// `keystore.json` — wrong key, or a keystore from another deployment.
    #[error(
        "node key does not match this keystore (wrong key, or keystore from another deployment)"
    )]
    NodeKeyMismatch,

    /// The keystore directory still holds a pre-hierarchy `pubkey.json`.
    /// There is no conversion path — re-initialize the deployment.
    #[error(
        "keystore at {0} predates the per-bucket key hierarchy; re-initialize the deployment (this build cannot read it)"
    )]
    LegacyKeystore(String),
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
            CryptoError::NodeKeyMissing => Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "node-key".to_owned(),
                message: "node key not supplied".to_owned(),
            },
            CryptoError::NodeKeyMalformed(reason) => Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "node-key".to_owned(),
                message: reason,
            },
            CryptoError::NodeKeyMismatch => Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "node-key".to_owned(),
                message: "node key does not match this keystore".to_owned(),
            },
            CryptoError::LegacyKeystore(path) => Error::KeystoreCorrupt {
                path,
                reason: "legacy pre-hierarchy keystore; re-initialize the deployment".to_owned(),
            },
        }
    }
}

#[cfg(test)]
mod into_storage_error_tests {
    use super::*;
    use crate::Error;

    #[test]
    fn maps_each_variant() {
        assert!(matches!(
            CryptoError::AuthFailed.into_storage_error("b", "k"),
            Error::DecryptionFailed { .. }
        ));
        assert!(matches!(
            CryptoError::Aead("x").into_storage_error("b", "k"),
            Error::DecryptionFailed { .. }
        ));
        assert!(matches!(
            CryptoError::KemDecode("x").into_storage_error("b", "k"),
            Error::DecryptionFailed { .. }
        ));
        assert!(matches!(
            CryptoError::Envelope("x").into_storage_error("b", "k"),
            Error::EnvelopeMalformed { .. }
        ));
        assert!(matches!(
            CryptoError::UnsupportedVersion(9).into_storage_error("b", "k"),
            Error::UnsupportedEnvelopeVersion { version: 9 }
        ));
        assert!(matches!(
            CryptoError::Kdf("x".into()).into_storage_error("b", "k"),
            Error::KdfFailed { .. }
        ));
        assert!(matches!(
            CryptoError::KeystoreIo("x".into()).into_storage_error("b", "k"),
            Error::InternalError { .. }
        ));
        assert!(matches!(
            CryptoError::KeystoreMissing("p".into()).into_storage_error("b", "k"),
            Error::KeystoreNotFound { .. }
        ));
        assert!(matches!(
            CryptoError::KeystoreCorrupt {
                path: "p".into(),
                reason: "r".into()
            }
            .into_storage_error("b", "k"),
            Error::KeystoreCorrupt { .. }
        ));
        assert!(matches!(
            CryptoError::UserStore("x".into()).into_storage_error("b", "k"),
            Error::Index { .. }
        ));
        assert!(matches!(
            CryptoError::NodeKeyMissing.into_storage_error("b", "k"),
            Error::InternalError { .. }
        ));
        assert!(matches!(
            CryptoError::NodeKeyMalformed("x".into()).into_storage_error("b", "k"),
            Error::InternalError { .. }
        ));
        assert!(matches!(
            CryptoError::NodeKeyMismatch.into_storage_error("b", "k"),
            Error::InternalError { .. }
        ));
        assert!(matches!(
            CryptoError::LegacyKeystore("p".into()).into_storage_error("b", "k"),
            Error::KeystoreCorrupt { .. }
        ));
    }
}
