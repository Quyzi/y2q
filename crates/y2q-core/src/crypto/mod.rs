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
//! - [`kem`] — ML-KEM-768 keypair, encapsulate, decapsulate over RustCrypto
//!   `ml-kem`, plus the legacy 2400-byte expanded secret-key encoding every
//!   on-disk keystore and bucket-key blob uses.
//! - [`keystore`] — keystore manifest (`keystore.json`) plus first-run
//!   generation.
//! - [`node_key`] — resolves the node key at boot: operator-supplied, or
//!   unlocked from a registered device registry ([`devices`]).
//! - [`node_keys`] — derives every server-structural key from the node key.
//! - [`seal`] — ML-KEM-768 public-key sealing (wrap under a recipient's
//!   public key rather than a password).
//! - [`user_store`] — redb-backed table of user records, each carrying
//!   [`user_store::CREDENTIAL_SLOTS`] credential slots.

pub mod devices;
pub mod envelope;
pub mod kdf;
pub mod kem;
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
    NodeKeySlot, decrypt_meta, derive_bucket_config_key, derive_container_header_key,
    derive_index_file_key, derive_index_key, derive_node_key_verifier, derive_object_metadata_key,
    derive_path_key, derive_user_store_file_key, encrypt_meta, prf,
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

    /// A KEM key, ciphertext, or shared-secret blob could not be decoded
    /// back into its typed representation.
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

    /// The node key file is accessible to group or other. Any local user
    /// who can read it holds the node key.
    #[error(
        "{path} has mode {mode:04o}: group/other access is not allowed; run `chmod 0400 {path}`; \
         if the key may have been exposed, rotate it (`y2qd --rotate-node-key`)"
    )]
    NodeKeyFilePermissions { path: String, mode: u32 },

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

    /// A guarded-memory allocation or protection operation failed.
    #[error(transparent)]
    SecMem(#[from] crate::secmem::SecMemError),

    /// `devices.json` could not be read or written.
    #[error("device registry io: {0}")]
    DeviceRegistryIo(String),

    /// `devices.json` does not exist.
    #[error("device registry not found at {0}")]
    DeviceRegistryMissing(String),

    /// `devices.json` exists but is structurally invalid.
    #[error("device registry corrupt at {path}: {reason}")]
    DeviceRegistryCorrupt {
        /// Filesystem path of the registry.
        path: String,
        /// Short description of the corruption detected.
        reason: String,
    },

    /// `device init` found an existing registry.
    #[error(
        "device registry already exists at {0}; the emergency codes are printed once at init and there is no regeneration command — a new set requires a new registry (new RMK), and over an existing dataset only with --adopt-existing-node-key and the raw node key in hand"
    )]
    DeviceRegistryExists(String),

    /// `devices.json` carries a `format_version` this build does not understand.
    #[error(
        "device registry at {path} has format_version {found}, this build understands {expected}"
    )]
    DeviceRegistryVersion {
        /// Filesystem path of the registry.
        path: String,
        /// Version found in the file.
        found: u16,
        /// Version this build understands.
        expected: u16,
    },

    /// A removal would leave no device record.
    #[error(
        "refusing to remove the last registered device: at least one device must remain able to unlock this node; add another device first"
    )]
    DeviceRegistryLastDevice,

    /// A removal would drop the last home device while away devices remain.
    #[error(
        "refusing to remove the last home device '{label}' while FIDO2 devices remain; add another home device first (this needs a home unlock)"
    )]
    DeviceLastHomeRemovalRefused {
        /// Label of the record whose removal was refused.
        label: String,
    },

    /// `--permanent-away` and the first device's kind disagree.
    #[error(
        "--permanent-away must be given exactly when the first device is FIDO2; the first device here is {kind:?}"
    )]
    DevicePermanentAwayMismatch {
        /// Kind of the first device.
        kind: devices::DeviceKind,
    },

    /// A registry is present but this binary was built without device support.
    #[error(
        "device registry at {0} requires a Linux build with the `devices` feature; this binary has no TPM 2.0 or FIDO2 support"
    )]
    DeviceSupportNotCompiled(String),

    /// The registry state MAC did not verify.
    #[error(
        "device registry state does not authenticate: grants, signature counters, burn records, or the grant period were modified outside y2q"
    )]
    DeviceStateTampered,

    /// `repair-state` was run on a registry whose MAC already verifies.
    #[error(
        "device registry state already authenticates; there is nothing to repair — `repair-state` applies only when the state MAC does not verify"
    )]
    DeviceStateIntact,

    /// `repair-state` was run without acknowledging the inventory.
    #[error(
        "refusing to repair without acknowledgement: review the printed inventory (record labels, ids, timestamps, PCR selections and uv flags are re-signed as found), then re-run with --accept-current-inventory"
    )]
    DeviceRepairNotAccepted,

    /// The authority that unlocked the registry may not perform the operation.
    #[error("operation '{operation}' requires {required}; attempted by {by}")]
    DeviceAuthorityInsufficient {
        /// Operation attempted.
        operation: String,
        /// Minimum authority required.
        required: String,
        /// Authority that attempted it.
        by: String,
    },

    /// A device wrap did not open.
    #[error(
        "device wrap did not open: wrong device secret, a tampered registry, or a registry from another deployment"
    )]
    DeviceUnwrapFailed,

    /// An away grant has passed its deadline.
    #[error(
        "away device '{label}' had access until {not_after_unix}; attested time is {attested_now}, so the grant has been erased — unlock on a home device to issue a new one (an emergency code does not issue grants); the authenticator stays registered"
    )]
    DeviceGrantExpired {
        /// Device label.
        label: String,
        /// Grant deadline (unix seconds).
        not_after_unix: u64,
        /// Attested time at the check (unix seconds).
        attested_now: u64,
    },

    /// An away device has no live grant.
    #[error("away device '{label}' has no live grant; unlock on a home device to issue one")]
    DeviceGrantAbsent {
        /// Device label.
        label: String,
    },

    /// The away grant period is out of bounds.
    #[error("away grant period {seconds}s is outside the allowed range 60 .. 2592000")]
    DeviceGrantPeriodInvalid {
        /// Offending value.
        seconds: u32,
    },

    /// The authenticator's signature counter did not advance.
    #[error(
        "away device '{label}' reported signature counter {asserted}, not above the last recorded {last}; replay, clone, or a rolled-back authenticator"
    )]
    DeviceSignCountRollback {
        /// Device label.
        label: String,
        /// Counter just asserted.
        asserted: u32,
        /// Highest counter previously accepted.
        last: u32,
    },

    /// No attested time could be obtained.
    #[error(
        "could not attest the current time from any configured Roughtime server: {0}; an away device cannot unlock without attested time (a home device or an emergency code still works)"
    )]
    AttestedTimeUnavailable(String),

    /// Roughtime servers disagree.
    #[error(
        "configured Roughtime servers disagree: the highest lower bound {low} exceeds the lowest upper bound {high}; at least one server is lying or badly skewed, refusing to pick a winner"
    )]
    AttestedTimeInconsistent {
        /// Highest lower bound across responses.
        low: u64,
        /// Lowest upper bound across responses.
        high: u64,
    },

    /// No Roughtime servers are configured.
    #[error(
        "no Roughtime servers are configured; set [crypto.devices.roughtime] servers (or pass --roughtime-server) — away-device unlock has no host-clock fallback by design"
    )]
    RoughtimeNotConfigured,

    /// A device produced a secret of the wrong length.
    #[error("device '{label}' produced a {len}-byte secret; expected exactly 32")]
    DeviceSecretLength {
        /// Device label.
        label: String,
        /// Length produced.
        len: usize,
    },

    /// No device matches the selector.
    #[error("no registered device with id or label '{0}'")]
    DeviceNotFound(String),

    /// A device label is already registered.
    #[error("a device labelled '{0}' is already registered; labels must be unique")]
    DeviceLabelInUse(String),

    /// A device label is not acceptable.
    #[error("device label invalid: {0}")]
    DeviceLabelInvalid(String),

    /// A Fido2 record is still referenced as a home device's second factor.
    #[error(
        "device '{label}' is the second factor of a home device; change the home device's factor before removing it"
    )]
    DeviceFactorInUse {
        /// Label of the record the caller tried to remove.
        label: String,
    },

    /// A home-device second factor is not acceptable.
    #[error("home device factor invalid: {0}")]
    DeviceFactorInvalid(String),

    /// No registered device could unlock the node key.
    #[error(
        "no registered device could unlock the node key: {0}; set Y2QD_EMERGENCY_KEY to one of the ten codes printed at `y2q admin device init`"
    )]
    DeviceUnlockUnavailable(String),

    /// A hardware backend (FIDO2) failed.
    #[error("device backend: {0}")]
    DeviceBackend(String),

    /// The TPM could not be reached.
    #[error("tpm unavailable: {0}")]
    TpmUnavailable(String),

    /// A TPM operation failed.
    #[error("tpm error: {0}")]
    Tpm(String),

    /// The TPM PCR policy refused to unseal.
    #[error(
        "tpm policy check failed: PCR values changed (kernel, firmware, or Secure Boot update); re-seal with: y2q admin device reseal-tpm <id>"
    )]
    TpmPcrMismatch,

    /// An emergency code is not decodable.
    #[error("emergency code malformed: {0}")]
    EmergencyCodeMalformed(String),

    /// No unused emergency slot opens with the supplied code.
    #[error(
        "emergency code rejected: no unused emergency slot opens with it (already used, or not from this registry)"
    )]
    EmergencyCodeRejected,

    /// Every emergency slot has been burned.
    #[error(
        "all 10 emergency codes have been used; emergency access is permanently exhausted for this registry"
    )]
    EmergencyCodesExhausted,
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
            CryptoError::NodeKeyFilePermissions { .. } => Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "node-key".to_owned(),
                message: "node key file permissions too broad".to_owned(),
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
            CryptoError::SecMem(e) => Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "secmem".to_owned(),
                message: e.to_string(),
            },
            CryptoError::DeviceRegistryIo(_)
            | CryptoError::DeviceRegistryMissing(_)
            | CryptoError::DeviceRegistryCorrupt { .. }
            | CryptoError::DeviceRegistryExists(_)
            | CryptoError::DeviceRegistryVersion { .. }
            | CryptoError::DeviceRegistryLastDevice
            | CryptoError::DeviceLastHomeRemovalRefused { .. }
            | CryptoError::DevicePermanentAwayMismatch { .. }
            | CryptoError::DeviceSupportNotCompiled(_)
            | CryptoError::DeviceStateTampered
            | CryptoError::DeviceStateIntact
            | CryptoError::DeviceRepairNotAccepted
            | CryptoError::DeviceAuthorityInsufficient { .. }
            | CryptoError::DeviceUnwrapFailed
            | CryptoError::DeviceGrantExpired { .. }
            | CryptoError::DeviceGrantAbsent { .. }
            | CryptoError::DeviceGrantPeriodInvalid { .. }
            | CryptoError::DeviceSignCountRollback { .. }
            | CryptoError::AttestedTimeUnavailable(_)
            | CryptoError::AttestedTimeInconsistent { .. }
            | CryptoError::RoughtimeNotConfigured
            | CryptoError::DeviceSecretLength { .. }
            | CryptoError::DeviceNotFound(_)
            | CryptoError::DeviceLabelInUse(_)
            | CryptoError::DeviceFactorInUse { .. }
            | CryptoError::DeviceFactorInvalid(_)
            | CryptoError::DeviceLabelInvalid(_)
            | CryptoError::DeviceUnlockUnavailable(_)
            | CryptoError::DeviceBackend(_)
            | CryptoError::TpmUnavailable(_)
            | CryptoError::Tpm(_)
            | CryptoError::TpmPcrMismatch
            | CryptoError::EmergencyCodeMalformed(_)
            | CryptoError::EmergencyCodeRejected
            | CryptoError::EmergencyCodesExhausted => Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "device-unlock".to_owned(),
                message: self.to_string(),
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
