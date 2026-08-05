//! Node Key (NK) derivation and encrypt/decrypt helpers for every
//! server-structural key the daemon needs before anyone logs in.
//!
//! The node key is supplied by the operator (`[crypto] node_key_file` or
//! `Y2QD_NODE_KEY` — see [`super::node_key`]), never derived from a user's
//! password or the deployment secret key. It is installed once at boot and
//! lives for the process lifetime: unlike the old MEK, there is nothing to
//! clear, because the daemon cannot serve anything without it.
//!
//! Everything below is domain-separated with `prf` (`HMAC-SHA256`) under a
//! distinct `y2q/v3/*` label, so compromise of one derived key says nothing
//! about the others:
//!
//! | Key | Label | Protects |
//! |---|---|---|
//! | `IFK` | `index-file-key` | whole-file AES-GCM of `_y2q_index.redb` |
//! | `IK` | `index-key` | HMAC-blinding of redb index keys |
//! | `PATHK` | `path-key` | bucket dir + object filename blinding |
//! | `OMK` | `object-metadata-key` | object metadata sidecars |
//! | `BCK` | `bucket-config-key` | the `.y2q-bucket.json` sidecar |
//! | `NKV` | `node-key-verifier` | wrong-NK detection |
//!
//! An attacker holding only the on-disk files — the storage directory and
//! the keystore directory — cannot derive any of these without the node
//! key. That gives object metadata the same confidentiality boundary as
//! before, but now anchored to an operator secret instead of a
//! user-recoverable one; see the crate-level exposure model in the design
//! plan for what a node-key-holding attacker gains and, critically, does
//! not gain (object plaintext).
//!
//! Encrypted metadata wire format (unchanged from the MEK era):
//!     [0x01 | 12-byte random nonce | AES-256-GCM(meta_json)]
//!
//! A blob not beginning with `0x01` is rejected outright — there is no
//! unauthenticated plaintext passthrough for legacy/pre-encryption metadata.
//!
//! The AEAD is bound to the object's opaque on-disk id via AAD (see
//! [`encrypt_meta`]/[`decrypt_meta`]), the same identity-binding principle
//! used for object envelopes ([`super::envelope`]). `OMK` is one fixed key
//! for the whole deployment rather than per-object, so without this binding
//! an attacker with filesystem write access could copy one object's
//! encrypted metadata blob onto another object's location and have it
//! decrypt successfully every time, splicing one object's
//! labels/timestamps/checksums onto another.
//!
//! Binding is keyed to the opaque object id (the `.obj` filename stem — see
//! `storage::filesystem::encode_object_id`) rather than the plaintext
//! `(bucket, key)` strings directly. The id is recoverable from a file's own
//! path with no decryption needed, which the index-rebuild scan depends on:
//! it discovers each object's `(bucket, key)` only by decrypting its
//! metadata, so binding to bucket/key strings would make that first decrypt
//! impossible. Binding to the id instead gives the identical guarantee (a
//! blob only opens at the exact path it was sealed for) without that
//! chicken-and-egg problem.

use std::sync::RwLock;

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use hmac::{Hmac, Mac};
use rand::Rng;
use zeroize::Zeroizing;

use super::CryptoError;

type HmacSha256 = Hmac<Sha256>;
use sha2::Sha256;

const INDEX_FILE_KEY_LABEL: &[u8] = b"y2q/v3/index-file-key";
const INDEX_KEY_LABEL: &[u8] = b"y2q/v3/index-key";
const PATH_KEY_LABEL: &[u8] = b"y2q/v3/path-key";
const OBJECT_METADATA_KEY_LABEL: &[u8] = b"y2q/v3/object-metadata-key";
const BUCKET_CONFIG_KEY_LABEL: &[u8] = b"y2q/v3/bucket-config-key";
const NODE_KEY_VERIFIER_LABEL: &[u8] = b"y2q/v3/node-key-verifier";

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

/// Derive the Index File Key (IFK): `prf(NK, "y2q/v3/index-file-key")`.
///
/// Used by [`crate::storage::EncryptedFileBackend`] to encrypt every block of
/// the `_y2q_index.redb` file at rest.
pub fn derive_index_file_key(nk: &[u8; 32]) -> [u8; 32] {
    prf(nk, INDEX_FILE_KEY_LABEL)
}

/// Derive the Index Key (IK): `prf(NK, "y2q/v3/index-key")`.
///
/// Used exclusively for HMAC-blinding redb index keys.
pub fn derive_index_key(nk: &[u8; 32]) -> [u8; 32] {
    prf(nk, INDEX_KEY_LABEL)
}

/// Derive the Path Key (PATHK): `prf(NK, "y2q/v3/path-key")`.
///
/// Used to keyed-hash bucket directory names and object filenames on disk so
/// that the storage tree reveals neither bucket names nor object-key
/// existence to anyone without the node key.
pub fn derive_path_key(nk: &[u8; 32]) -> [u8; 32] {
    prf(nk, PATH_KEY_LABEL)
}

/// Derive the Object Metadata Key (OMK): `prf(NK, "y2q/v3/object-metadata-key")`.
///
/// Used by [`encrypt_meta`]/[`decrypt_meta`] to seal each object's metadata
/// sidecar.
pub fn derive_object_metadata_key(nk: &[u8; 32]) -> [u8; 32] {
    prf(nk, OBJECT_METADATA_KEY_LABEL)
}

/// Derive the Bucket Config Key (BCK): `prf(NK, "y2q/v3/bucket-config-key")`.
///
/// Used to seal the `.y2q-bucket.json` sidecar (owner + ACL + bucket key
/// material).
pub fn derive_bucket_config_key(nk: &[u8; 32]) -> [u8; 32] {
    prf(nk, BUCKET_CONFIG_KEY_LABEL)
}

/// Derive the Node Key Verifier (NKV): `prf(NK, "y2q/v3/node-key-verifier")`.
///
/// Stored in `keystore.json` to detect a wrong node key at boot.
pub fn derive_node_key_verifier(nk: &[u8; 32]) -> [u8; 32] {
    prf(nk, NODE_KEY_VERIFIER_LABEL)
}

/// Live holder for the four "hot" node-derived keys used on every request:
/// the Index Key, Path Key, Object Metadata Key, and Bucket Config Key.
///
/// Installed once at boot from the operator-supplied node key (see
/// [`super::node_key::load_node_key`]) and never cleared — the daemon cannot
/// serve anything without these, so unlike the old `MekSlot` (retired) there is no
/// idle-drop path. Shared (behind an `Arc`) by the storage backend and its
/// metadata index so a single install covers both.
#[derive(Default)]
pub struct NodeKeySlot {
    inner: RwLock<Option<NodeKeys>>,
}

struct NodeKeys {
    index_key: Zeroizing<[u8; 32]>,
    path_key: Zeroizing<[u8; 32]>,
    object_metadata_key: Zeroizing<[u8; 32]>,
    bucket_config_key: Zeroizing<[u8; 32]>,
}

impl NodeKeySlot {
    /// An empty slot.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(None),
        }
    }

    /// Install the node key, deriving and storing the four hot keys.
    /// Replaces any prior value. Called exactly once, at boot.
    pub fn install(&self, nk: [u8; 32]) {
        *self.inner.write().expect("NodeKeySlot poisoned") = Some(NodeKeys {
            index_key: Zeroizing::new(derive_index_key(&nk)),
            path_key: Zeroizing::new(derive_path_key(&nk)),
            object_metadata_key: Zeroizing::new(derive_object_metadata_key(&nk)),
            bucket_config_key: Zeroizing::new(derive_bucket_config_key(&nk)),
        });
    }

    /// A copy of the Index Key, if installed.
    pub fn index_key(&self) -> Option<[u8; 32]> {
        self.inner
            .read()
            .expect("NodeKeySlot poisoned")
            .as_ref()
            .map(|k| *k.index_key)
    }

    /// A copy of the Path Key, if installed. Used to keyed-hash on-disk
    /// bucket and object names.
    pub fn path_key(&self) -> Option<[u8; 32]> {
        self.inner
            .read()
            .expect("NodeKeySlot poisoned")
            .as_ref()
            .map(|k| *k.path_key)
    }

    /// A copy of the Object Metadata Key, if installed.
    pub fn object_metadata_key(&self) -> Option<[u8; 32]> {
        self.inner
            .read()
            .expect("NodeKeySlot poisoned")
            .as_ref()
            .map(|k| *k.object_metadata_key)
    }

    /// A copy of the Bucket Config Key, if installed.
    pub fn bucket_config_key(&self) -> Option<[u8; 32]> {
        self.inner
            .read()
            .expect("NodeKeySlot poisoned")
            .as_ref()
            .map(|k| *k.bucket_config_key)
    }

    /// Whether the node key has been installed.
    pub fn is_set(&self) -> bool {
        self.inner.read().expect("NodeKeySlot poisoned").is_some()
    }
}

/// Encrypt `json` with AES-256-GCM under `omk`, bound to `object_id` (the
/// object's opaque on-disk id — see `storage::filesystem::encode_object_id`).
///
/// Returns `[0x01 | 12-byte nonce | ciphertext]`. The blob only decrypts
/// successfully for the same `object_id` it was encrypted for — copying it
/// to a different object's storage location fails AEAD verification.
pub fn encrypt_meta(omk: &[u8; 32], json: &[u8], object_id: &str) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(omk.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = &aes_gcm::Nonce::from(nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: json,
                aad: object_id.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::Aead("metadata encrypt"))?;
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(VERSION_BYTE);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a metadata blob, requiring it to have been sealed for the same
/// `object_id`.
///
/// The first byte must be `0x01`; anything else (including legacy
/// pre-encryption plaintext) is rejected rather than passed through
/// unauthenticated. A blob relocated from a different object's storage
/// location fails with [`CryptoError::AuthFailed`], the same as a corrupted
/// or tampered blob.
pub fn decrypt_meta(omk: &[u8; 32], blob: &[u8], object_id: &str) -> Result<Vec<u8>, CryptoError> {
    if blob.is_empty() || blob[0] != VERSION_BYTE {
        return Err(CryptoError::Envelope("unrecognized metadata format"));
    }
    if blob.len() < MIN_ENCRYPTED_LEN {
        return Err(CryptoError::Envelope(
            "metadata blob too short for decryption",
        ));
    }
    let nonce = &aes_gcm::Nonce::try_from(&blob[1..1 + NONCE_LEN])
        .expect("length checked against MIN_ENCRYPTED_LEN above");
    let ct = &blob[1 + NONCE_LEN..];
    let cipher = Aes256Gcm::new(omk.into());
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct,
                aad: object_id.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nk(seed: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k.fill(seed);
        k
    }

    #[test]
    fn derivations_are_deterministic_and_domain_separated() {
        let k = nk(1);
        assert_eq!(derive_index_file_key(&k), derive_index_file_key(&k));
        let derived = [
            derive_index_file_key(&k),
            derive_index_key(&k),
            derive_path_key(&k),
            derive_object_metadata_key(&k),
            derive_bucket_config_key(&k),
            derive_node_key_verifier(&k),
        ];
        for i in 0..derived.len() {
            for j in (i + 1)..derived.len() {
                assert_ne!(derived[i], derived[j], "labels {i} and {j} collided");
            }
        }
    }

    #[test]
    fn derivations_differ_across_node_keys() {
        assert_ne!(
            derive_object_metadata_key(&nk(1)),
            derive_object_metadata_key(&nk(2))
        );
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let omk = derive_object_metadata_key(&nk(1));
        let blob = encrypt_meta(&omk, b"{\"hello\":\"world\"}", "obj-id-a").unwrap();
        assert_eq!(blob[0], VERSION_BYTE);
        assert_eq!(
            decrypt_meta(&omk, &blob, "obj-id-a").unwrap(),
            b"{\"hello\":\"world\"}"
        );
    }

    #[test]
    fn wrong_omk_fails_to_decrypt() {
        let blob =
            encrypt_meta(&derive_object_metadata_key(&nk(1)), b"secret", "obj-id-a").unwrap();
        assert!(matches!(
            decrypt_meta(&derive_object_metadata_key(&nk(2)), &blob, "obj-id-a"),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn meta_blob_cannot_be_relocated_to_a_different_object() {
        let omk = derive_object_metadata_key(&nk(1));
        let blob = encrypt_meta(&omk, b"{\"secret\":true}", "obj-id-a").unwrap();

        // Same blob, different object id (as if copied to another object's path).
        assert!(matches!(
            decrypt_meta(&omk, &blob, "obj-id-b"),
            Err(CryptoError::AuthFailed)
        ));
        // Genuine address still opens it.
        assert_eq!(
            decrypt_meta(&omk, &blob, "obj-id-a").unwrap(),
            b"{\"secret\":true}"
        );
    }

    #[test]
    fn node_key_slot_install_and_read() {
        let slot = NodeKeySlot::new();
        assert!(!slot.is_set());
        assert_eq!(slot.index_key(), None);

        let k = nk(1);
        slot.install(k);
        assert!(slot.is_set());
        assert_eq!(slot.index_key(), Some(derive_index_key(&k)));
        assert_eq!(slot.path_key(), Some(derive_path_key(&k)));
        assert_eq!(
            slot.object_metadata_key(),
            Some(derive_object_metadata_key(&k))
        );
        assert_eq!(slot.bucket_config_key(), Some(derive_bucket_config_key(&k)));
    }

    #[test]
    fn legacy_plaintext_is_rejected() {
        // Any blob not starting with VERSION_BYTE is rejected, not passed through.
        let plain = b"{\"legacy\":true}";
        assert!(matches!(
            decrypt_meta(&derive_object_metadata_key(&nk(1)), plain, "obj-id-a"),
            Err(CryptoError::Envelope(_))
        ));
    }

    #[test]
    fn empty_blob_is_rejected() {
        assert!(matches!(
            decrypt_meta(&derive_object_metadata_key(&nk(1)), b"", "obj-id-a"),
            Err(CryptoError::Envelope(_))
        ));
    }
}
