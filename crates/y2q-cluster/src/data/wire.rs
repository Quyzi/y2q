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

    /// Reconstruct the [`PutOptions`] a replica uses when committing.
    pub fn put_options(&self) -> PutOptions {
        PutOptions {
            labels: self.labels.iter().cloned().collect(),
            sync: self.sync_level(),
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

/// A non-PUT mutation routed down the chain (no bulk body): DELETE, or a label
/// set. The final state is computed once (at the contact node for labels) and
/// applied verbatim at every member so replicas stay identical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutateOp {
    /// Delete the object at every chain member.
    Delete,
    /// Replace the object's label set at every member with these pairs.
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
        let r = MutateResp { existed: true };
        let back: MutateResp = serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn derives_put_options_and_metrics() {
        let m = sample();
        assert_eq!(m.sync_level(), SyncLevel::Durable);
        let opts = m.put_options();
        assert_eq!(opts.sync, SyncLevel::Durable);
        assert!(opts.labels.contains(&("env".into(), "prod".into())));
        assert_eq!(m.plaintext_metrics().size, 4000);
        assert_eq!(m.cipher_metadata().cipher_size, 5200);
    }
}
