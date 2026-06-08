//! Wire types for the CRAQ data plane.
//!
//! A PREPARE carries the **ciphertext envelope** in the HTTP body (streamed) and
//! everything a downstream replica needs to write a byte-identical `.obj` in a
//! single JSON sidecar, [`PrepareMeta`], sent in the [`PREPARE_META_HEADER`]
//! request header. Encryption happens once at the HEAD; downstream nodes write
//! the received bytes verbatim (never re-encrypting) and stamp the metadata the
//! HEAD computed, so every replica's plaintext metrics and cipher metadata match.

use serde::{Deserialize, Serialize};

use y2q_core::{CipherMetadata, PlaintextMetrics, PutOptions, SyncLevel};

/// Request header carrying the JSON-encoded [`PrepareMeta`].
pub const PREPARE_META_HEADER: &str = "X-Y2Q-Prepare";

/// Metadata accompanying a PREPARE: addressing, fencing, and the plaintext/cipher
/// fields the receiving node persists alongside the verbatim envelope bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepareMeta {
    /// Target bucket.
    pub bucket: String,
    /// Target key.
    pub key: String,
    /// Consistent-hash chain id (recomputed locally, carried for diagnostics).
    pub chain_id: u64,
    /// Epoch the write is fenced under; a node rejects a PREPARE older than its
    /// committed epoch.
    pub epoch: u64,
    /// CRAQ object version assigned by the HEAD. Every replica persists this
    /// exact value in [`Metadata::version`](y2q_core::Metadata::version) so all
    /// copies of a version agree; the TAIL's committed value is what a version
    /// query returns.
    pub version: u64,
    /// The v2 header `plaintext_len` (padded length) the HEAD patched locally.
    /// The Tee does not forward the patch, so the receiver backfills it from
    /// here to keep its envelope byte-identical to the HEAD's.
    pub plaintext_len: u64,
    /// True plaintext size in bytes (stored in `Metadata::size`).
    pub plaintext_size: u64,
    /// gxhash64 of the plaintext, standard base64 (stored in `Metadata`).
    pub checksum_gxhash_b64: String,
    /// On-disk envelope size in bytes.
    pub cipher_size: u64,
    /// SHA-256 of the envelope, standard base64 (empty when the HEAD did not
    /// compute it — matches the single-node streaming PUT path).
    pub cipher_sha256_b64: String,
    /// Symbolic KEM algorithm name.
    pub kem_alg: String,
    /// Symbolic AEAD algorithm name.
    pub aead_alg: String,
    /// Envelope format version.
    pub envelope_version: u16,
    /// Whether the write must be durable (`fdatasync`) before acking.
    pub sync_durable: bool,
    /// User labels to persist with the object.
    pub labels: Vec<(String, String)>,
}

impl PrepareMeta {
    /// The durability level encoded by [`Self::sync_durable`].
    pub fn sync_level(&self) -> SyncLevel {
        if self.sync_durable {
            SyncLevel::Durable
        } else {
            SyncLevel::BestEffort
        }
    }

    /// Reconstruct the [`PutOptions`] a replica uses when committing. Carries the
    /// HEAD-assigned version so the replica stamps the identical
    /// [`Metadata::version`](y2q_core::Metadata::version).
    pub fn put_options(&self) -> PutOptions {
        PutOptions {
            labels: self.labels.iter().cloned().collect(),
            sync: self.sync_level(),
            version: Some(self.version),
            ..Default::default()
        }
    }

    /// The plaintext metrics a replica persists.
    pub fn plaintext_metrics(&self) -> PlaintextMetrics {
        PlaintextMetrics {
            size: self.plaintext_size,
            checksum_gxhash_b64: self.checksum_gxhash_b64.clone(),
        }
    }

    /// The cipher metadata a replica persists.
    pub fn cipher_metadata(&self) -> CipherMetadata {
        CipherMetadata {
            cipher_size: self.cipher_size,
            cipher_sha256_b64: self.cipher_sha256_b64.clone(),
            kem_alg: self.kem_alg.clone(),
            aead_alg: self.aead_alg.clone(),
            envelope_version: self.envelope_version,
        }
    }
}

/// Response to a PREPARE once the (sub)chain rooted at the receiver has committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepareResp {
    /// Whether an existing object was replaced at the TAIL (the commit point).
    pub overwrite: bool,
}

/// How a label edit combines the supplied labels with an object's current set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LabelMode {
    /// Add the supplied labels to the existing set.
    Set,
    /// Remove every value of each supplied label name (or clear all if empty).
    Remove,
    /// Replace the entire set with the supplied labels.
    Replace,
}

impl LabelMode {
    /// Resolve an edit against `current` into the final label set. Inputs and
    /// output are deduplicated and ordered (collected through a `BTreeSet`) so
    /// every chain member that applies the resolved set ends up identical.
    pub fn resolve(
        self,
        current: Vec<(String, String)>,
        incoming: Vec<(String, String)>,
    ) -> Vec<(String, String)> {
        use std::collections::BTreeSet;
        match self {
            LabelMode::Set => {
                let mut merged: BTreeSet<(String, String)> = current.into_iter().collect();
                merged.extend(incoming);
                merged.into_iter().collect()
            }
            LabelMode::Remove => {
                if incoming.is_empty() {
                    return Vec::new();
                }
                let names: BTreeSet<&String> = incoming.iter().map(|(n, _)| n).collect();
                let kept: BTreeSet<(String, String)> = current
                    .into_iter()
                    .filter(|(n, _)| !names.contains(n))
                    .collect();
                kept.into_iter().collect()
            }
            LabelMode::Replace => {
                let set: BTreeSet<(String, String)> = incoming.into_iter().collect();
                set.into_iter().collect()
            }
        }
    }
}

/// Request header carrying the JSON-encoded [`BackfillObjectMeta`] on a
/// backfill object fetch response.
pub const BACKFILL_META_HEADER: &str = "X-Y2Q-Backfill";

/// One entry in a backfill manifest: an object a peer holds, with the version
/// and ciphertext digest a recovering node diffs against its own copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackfillEntry {
    /// Bucket.
    pub bucket: String,
    /// Key.
    pub key: String,
    /// Committed CRAQ version (`None` for legacy/unversioned objects).
    pub version: Option<u64>,
    /// Standard-base64 SHA-256 of the on-disk envelope (`None` if not recorded).
    pub cipher_sha256: Option<String>,
}

/// A backfill manifest page: the objects a peer holds locally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackfillManifest {
    /// Objects held by the answering node.
    pub entries: Vec<BackfillEntry>,
}

/// Metadata accompanying a backfill object fetch: everything a recovering node
/// needs to commit a byte-identical replica at the same version. Mirrors the
/// commit-relevant subset of [`PrepareMeta`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackfillObjectMeta {
    /// CRAQ version to stamp into the replica.
    pub version: u64,
    /// The v2 header `plaintext_len` (padded length) at envelope offset 20.
    pub plaintext_len: u64,
    /// True plaintext size.
    pub plaintext_size: u64,
    /// gxhash64 of the plaintext, standard base64.
    pub checksum_gxhash_b64: String,
    /// On-disk envelope size in bytes.
    pub cipher_size: u64,
    /// SHA-256 of the envelope, standard base64 (empty when unknown).
    pub cipher_sha256_b64: String,
    /// Symbolic KEM algorithm name.
    pub kem_alg: String,
    /// Symbolic AEAD algorithm name.
    pub aead_alg: String,
    /// Envelope format version.
    pub envelope_version: u16,
    /// User labels to persist with the object.
    pub labels: Vec<(String, String)>,
}

impl BackfillObjectMeta {
    /// Build the [`PrepareMeta`] used to stage and commit this object locally
    /// (TAIL/solo path: no forwarding). `epoch` is the recovering node's current
    /// committed epoch; the write is durable so it survives a crash mid-backfill.
    pub fn to_prepare(&self, bucket: &str, key: &str, chain_id: u64, epoch: u64) -> PrepareMeta {
        PrepareMeta {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            chain_id,
            epoch,
            version: self.version,
            plaintext_len: self.plaintext_len,
            plaintext_size: self.plaintext_size,
            checksum_gxhash_b64: self.checksum_gxhash_b64.clone(),
            cipher_size: self.cipher_size,
            cipher_sha256_b64: self.cipher_sha256_b64.clone(),
            kem_alg: self.kem_alg.clone(),
            aead_alg: self.aead_alg.clone(),
            envelope_version: self.envelope_version,
            sync_durable: true,
            labels: self.labels.clone(),
        }
    }
}

/// Response to a version query (`GET /internal/v1/version`): the committed CRAQ
/// version the answering node holds for `(bucket, key)`. `None` means the node
/// has no committed copy, or holds a legacy/single-node object without a version.
/// The chain TAIL is the authoritative answerer (the CRAQ commit point).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionResp {
    /// The committed object version, or `None` if absent/unversioned.
    pub version: Option<u64>,
}

/// A non-PUT mutation routed down the chain (no bulk body): DELETE, or a label
/// edit. For labels the HEAD resolves the edit against its committed copy into a
/// final set ([`MutateOp::SetLabels`]) and relays that set verbatim, so every
/// member applies identical labels regardless of which node was contacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutateOp {
    /// Delete the object at every chain member.
    Delete,
    /// An unresolved label edit. Only the HEAD receives this; it resolves the
    /// edit against its local copy and relays the resulting [`Self::SetLabels`].
    EditLabels {
        /// How the incoming labels combine with the current set.
        mode: LabelMode,
        /// The labels supplied by the client request.
        incoming: Vec<(String, String)>,
    },
    /// A resolved label set, applied verbatim at every member (what downstream
    /// members receive after the HEAD resolves an [`Self::EditLabels`]).
    SetLabels {
        /// The full label set to apply.
        labels: Vec<(String, String)>,
    },
}

/// Addressing + fencing for a [`MutateOp`] relayed through the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutateMeta {
    /// Target bucket.
    pub bucket: String,
    /// Target key.
    pub key: String,
    /// Consistent-hash chain id (diagnostics).
    pub chain_id: u64,
    /// Epoch the mutation is fenced under.
    pub epoch: u64,
    /// The mutation to apply at each member.
    pub op: MutateOp,
}

/// Response from a chain mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutateResp {
    /// Whether the object existed at the node that originated the chain apply
    /// (the HEAD). For DELETE this distinguishes 204 from 404.
    pub existed: bool,
    /// The resolved label set the HEAD applied (empty for DELETE). Returned so
    /// the contact node can render it in the HTTP response without re-reading.
    pub labels: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PrepareMeta {
        PrepareMeta {
            bucket: "b".into(),
            key: "k".into(),
            chain_id: 42,
            epoch: 7,
            version: 3,
            plaintext_len: 4096,
            plaintext_size: 4000,
            checksum_gxhash_b64: "Y2hrc3VtAAA=".into(),
            cipher_size: 5200,
            cipher_sha256_b64: String::new(),
            kem_alg: "ml-kem-768".into(),
            aead_alg: "aes-256-gcm".into(),
            envelope_version: 2,
            sync_durable: true,
            labels: vec![("env".into(), "prod".into())],
        }
    }

    #[test]
    fn round_trips_through_json() {
        let m = sample();
        let bytes = serde_json::to_vec(&m).unwrap();
        let back: PrepareMeta = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn mutate_meta_round_trips() {
        for op in [
            MutateOp::Delete,
            MutateOp::EditLabels {
                mode: LabelMode::Set,
                incoming: vec![("env".into(), "prod".into())],
            },
            MutateOp::SetLabels {
                labels: vec![
                    ("env".into(), "prod".into()),
                    ("team".into(), "core".into()),
                ],
            },
        ] {
            let m = MutateMeta {
                bucket: "b".into(),
                key: "k".into(),
                chain_id: 11,
                epoch: 3,
                op,
            };
            let bytes = serde_json::to_vec(&m).unwrap();
            let back: MutateMeta = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(m, back);
        }
        let r = MutateResp {
            existed: true,
            labels: vec![("env".into(), "prod".into())],
        };
        let back: MutateResp = serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn label_mode_resolves() {
        let current = vec![("a".to_string(), "1".to_string())];
        let incoming = vec![("b".to_string(), "2".to_string())];
        // set merges
        assert_eq!(
            LabelMode::Set.resolve(current.clone(), incoming.clone()),
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string())
            ]
        );
        // replace drops current
        assert_eq!(
            LabelMode::Replace.resolve(current.clone(), incoming.clone()),
            vec![("b".to_string(), "2".to_string())]
        );
        // remove by name; empty incoming clears all
        let two = vec![
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string()),
        ];
        assert_eq!(
            LabelMode::Remove.resolve(two.clone(), vec![("a".to_string(), "x".to_string())]),
            vec![("b".to_string(), "2".to_string())]
        );
        assert!(LabelMode::Remove.resolve(two, vec![]).is_empty());
    }

    #[test]
    fn derives_put_options_and_metrics() {
        let m = sample();
        assert_eq!(m.sync_level(), SyncLevel::Durable);
        let opts = m.put_options();
        assert_eq!(opts.sync, SyncLevel::Durable);
        assert_eq!(opts.version, Some(3));
        assert!(opts.labels.contains(&("env".into(), "prod".into())));
        assert_eq!(m.plaintext_metrics().size, 4000);
        assert_eq!(m.cipher_metadata().cipher_size, 5200);
    }
}
