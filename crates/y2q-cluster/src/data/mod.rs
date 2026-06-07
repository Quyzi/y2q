//! CRAQ data plane: chain-replicated writes over the internal transport.
//!
//! Object data never enters raft. A write is replicated down the chain computed
//! from the committed control state ([`route`]): the HEAD encrypts once and tees
//! the ciphertext to its successor (the y2qd PUT handler drives that, using
//! [`StreamingSink::Tee`](y2q_core::storage::streaming_sink::StreamingSink::Tee));
//! each downstream node ([`DistributedStorage::accept_prepare`]) writes the bytes
//! verbatim, relays them to its own successor, and commits **after** the
//! downstream sub-chain commits, so the TAIL is the commit point exactly as CRAQ
//! prescribes. Reads, DELETE/label routing, and apportioned/versioned reads land
//! in later phases; this module is the replicated write path and its primitives.
//!
//! `DistributedStorage` wraps a local [`AnyStorage`] rather than being an
//! `AnyStorage` variant: `AnyStorage` lives in `y2q-core`, which cannot depend on
//! this crate (the dependency runs the other way), so the daemon selects the
//! distributed path at the handler layer instead of inside the storage enum.

pub mod pending;
pub mod route;
pub mod wire;

use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::mpsc;

use y2q_core::crypto::envelope;
use y2q_core::storage::streaming_sink::StreamingSink;
use y2q_core::{AnyStorage, AnyStreamingPutGuard};

use crate::control::Controller;
use crate::control::types::ControlState;
use crate::hashing::chain::Role;
use crate::identity::NodeId;
use crate::transport::InternalClient;
use crate::transport::TransportError;

pub use pending::{Pending, PendingGuard, PendingWrites};
pub use route::{ChainRoute, resolve_route};
pub use wire::{PREPARE_META_HEADER, PrepareMeta, PrepareResp};

/// Bounded depth of the per-hop forward channel. A few in-flight chunks gives
/// pipelining without letting a slow downstream make an upstream node buffer the
/// whole object (the backpressure invariant for multi-GiB PUTs).
const FORWARD_BOUND: usize = 8;

/// Errors from the data plane.
#[derive(thiserror::Error, Debug)]
pub enum DataError {
    /// A local storage operation failed.
    #[error("local storage: {0}")]
    Storage(#[from] y2q_core::Error),
    /// Writing the envelope to the local sink failed.
    #[error("write envelope: {0}")]
    Io(String),
    /// The downstream forward channel closed before the write finished.
    #[error("downstream replication failed (forward channel closed)")]
    ForwardClosed,
    /// A peer RPC failed.
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    /// No chain (or no reachable successor) exists for the address.
    #[error("no chain for {bucket}/{key}")]
    NoChain {
        /// Bucket component.
        bucket: String,
        /// Key component.
        key: String,
    },
    /// This node is not a member of the chain it was asked to replicate to.
    #[error("not a chain member for {bucket}/{key}")]
    NotMember {
        /// Bucket component.
        bucket: String,
        /// Key component.
        key: String,
    },
}

/// The distributed storage handle: a local backend plus the cluster control and
/// transport needed to replicate writes across a chain.
pub struct DistributedStorage {
    local: Arc<AnyStorage>,
    controller: Arc<Controller>,
    client: Arc<InternalClient>,
    node_id: NodeId,
    replication_factor: usize,
    virtual_nodes_per_node: u32,
    pending: PendingWrites,
}

impl DistributedStorage {
    /// Construct a distributed storage handle.
    pub fn new(
        local: Arc<AnyStorage>,
        controller: Arc<Controller>,
        client: Arc<InternalClient>,
        node_id: NodeId,
        replication_factor: usize,
        virtual_nodes_per_node: u32,
    ) -> Self {
        Self {
            local,
            controller,
            client,
            node_id,
            replication_factor,
            virtual_nodes_per_node,
            pending: PendingWrites::new(),
        }
    }

    /// This node's id.
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// The wrapped local backend (used by the read path and handlers).
    pub fn local(&self) -> &Arc<AnyStorage> {
        &self.local
    }

    /// The in-flight write tracker.
    pub fn pending(&self) -> &PendingWrites {
        &self.pending
    }

    /// Resolve the chain for `(bucket, key)` from the current control state.
    pub async fn route(&self, bucket: &str, key: &str) -> ChainRoute {
        let state = self.controller.control_state().await;
        resolve_route(
            &state,
            bucket,
            key,
            self.replication_factor,
            self.virtual_nodes_per_node,
        )
    }

    /// A peer's base URL from the control state (the full `addr` it advertised).
    fn peer_base_url(&self, state: &ControlState, id: NodeId) -> Option<String> {
        state.nodes.get(&id).map(|meta| meta.addr.clone())
    }

    /// Receive a PREPARE: write the ciphertext envelope verbatim to the local
    /// backend, relay it to the next chain member (if any), and commit once the
    /// downstream sub-chain has committed. Returns the TAIL's overwrite verdict.
    ///
    /// `body` yields the envelope bytes in order (the actix handler drains the
    /// request body into it). The key is marked dirty for the duration.
    pub async fn accept_prepare(
        &self,
        meta: PrepareMeta,
        body: mpsc::Receiver<Bytes>,
    ) -> Result<PrepareResp, DataError> {
        let _pending = self.pending.begin(&meta.bucket, &meta.key, meta.epoch);
        let state = self.controller.control_state().await;
        let route = resolve_route(
            &state,
            &meta.bucket,
            &meta.key,
            self.replication_factor,
            self.virtual_nodes_per_node,
        );
        if matches!(route.role(self.node_id), Role::NotInChain) {
            return Err(DataError::NotMember {
                bucket: meta.bucket,
                key: meta.key,
            });
        }

        match route.next_after(self.node_id) {
            // Interior node: stage locally while relaying to the successor, await
            // the downstream commit, then commit locally (HEAD..TAIL ordering).
            Some(next_id) => {
                let next_url =
                    self.peer_base_url(&state, next_id)
                        .ok_or_else(|| DataError::NoChain {
                            bucket: meta.bucket.clone(),
                            key: meta.key.clone(),
                        })?;
                let (fwd_tx, fwd_rx) = mpsc::channel::<Bytes>(FORWARD_BOUND);
                let client = Arc::clone(&self.client);
                let fmeta = meta.clone();
                let fwd_task = tokio::spawn(async move {
                    forward_prepare(&client, &next_url, &fmeta, fwd_rx).await
                });

                let (guard, sink) = stage_envelope(&self.local, &meta, body, Some(fwd_tx)).await?;
                // fwd_tx was dropped by stage_envelope, ending the relay body.
                let down = fwd_task
                    .await
                    .map_err(|e| DataError::Io(format!("forward task join: {e}")))??;
                commit_staged(guard, sink, &meta).await?;
                Ok(PrepareResp {
                    overwrite: down.overwrite,
                })
            }
            // TAIL / Solo: the commit point.
            None => {
                let (guard, sink) = stage_envelope(&self.local, &meta, body, None).await?;
                let overwrite = commit_staged(guard, sink, &meta).await?;
                Ok(PrepareResp { overwrite })
            }
        }
    }
}

/// Stream the envelope `body` into a fresh local `.tmp`, optionally relaying each
/// chunk to `forward`, and backfill the v2 `plaintext_len` patch. Returns the
/// uncommitted guard and its sink so the caller can commit after the downstream
/// sub-chain has committed. On return, `forward` (if any) is dropped, signalling
/// end-of-stream to the relay task.
async fn stage_envelope(
    local: &AnyStorage,
    meta: &PrepareMeta,
    mut body: mpsc::Receiver<Bytes>,
    forward: Option<mpsc::Sender<Bytes>>,
) -> Result<(AnyStreamingPutGuard, StreamingSink), DataError> {
    let (guard, mut sink, write_offset) =
        local.begin_streaming_put(&meta.bucket, &meta.key).await?;

    while let Some(chunk) = body.recv().await {
        sink.write_all(&chunk)
            .await
            .map_err(|e| DataError::Io(e.to_string()))?;
        if let Some(f) = &forward {
            f.send(chunk).await.map_err(|_| DataError::ForwardClosed)?;
        }
    }

    // The Tee at the HEAD does not forward the positioned plaintext_len patch, so
    // backfill it here to keep this replica's envelope byte-identical.
    sink.write_all_at(
        &meta.plaintext_len.to_be_bytes(),
        write_offset + envelope::V2_PLAINTEXT_LEN_OFFSET,
    )
    .await
    .map_err(|e| DataError::Io(e.to_string()))?;
    sink.seek_to_end()
        .await
        .map_err(|e| DataError::Io(e.to_string()))?;

    Ok((guard, sink))
}

/// Commit a staged replica write using the HEAD-computed metrics.
async fn commit_staged(
    guard: AnyStreamingPutGuard,
    sink: StreamingSink,
    meta: &PrepareMeta,
) -> Result<bool, DataError> {
    guard
        .commit(
            sink,
            meta.put_options(),
            meta.plaintext_metrics(),
            meta.cipher_metadata(),
        )
        .await
        .map_err(DataError::from)
}

/// Relay a PREPARE to the next chain member: stream `rx`'s chunks as the request
/// body and return the downstream commit response.
async fn forward_prepare(
    client: &InternalClient,
    base_url: &str,
    meta: &PrepareMeta,
    rx: mpsc::Receiver<Bytes>,
) -> Result<PrepareResp, DataError> {
    let url = format!("{base_url}/internal/v1/prepare");
    let meta_json = serde_json::to_string(meta).map_err(|e| DataError::Io(e.to_string()))?;
    let stream = futures::stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|b| (Ok::<Bytes, std::io::Error>(b), rx))
    });
    let body = reqwest::Body::wrap_stream(stream);
    let resp: PrepareResp = client
        .post_stream(&url, &[(PREPARE_META_HEADER, meta_json)], body)
        .await?;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use y2q_core::FilesystemStorage;
    use y2q_core::Storage;

    /// Build a tempdir-backed local AnyStorage with a MEK installed.
    fn local_storage(dir: &std::path::Path) -> Arc<AnyStorage> {
        let fs = FilesystemStorage::new(dir.join("data"), dir.join("index.redb")).unwrap();
        fs.install_mek([7u8; 32]);
        Arc::new(AnyStorage::Filesystem(fs))
    }

    /// Feed bytes through a channel as if they were a streamed PREPARE body.
    fn body_of(bytes: &[u8]) -> mpsc::Receiver<Bytes> {
        let (tx, rx) = mpsc::channel(8);
        let owned = Bytes::copy_from_slice(bytes);
        tokio::spawn(async move {
            let _ = tx.send(owned).await;
        });
        rx
    }

    /// The TAIL/Solo path writes the envelope verbatim and applies the
    /// plaintext_len patch, so a read-back returns byte-identical data.
    #[tokio::test]
    async fn stage_and_commit_writes_verbatim_with_patch() {
        let dir = tempfile::tempdir().unwrap();
        let local = local_storage(dir.path());

        // 64-byte stand-in "envelope"; the patch lands at offset 20.
        let mut env = vec![0u8; 64];
        for (i, b) in env.iter_mut().enumerate() {
            *b = i as u8;
        }
        let plaintext_len: u64 = 0x0102_0304_0506_0708;

        let meta = PrepareMeta {
            bucket: "bkt".into(),
            key: "obj".into(),
            chain_id: 1,
            epoch: 0,
            plaintext_len,
            plaintext_size: 50,
            checksum_gxhash_b64: "AAAAAAAAAAA=".into(),
            cipher_size: env.len() as u64,
            cipher_sha256_b64: String::new(),
            kem_alg: "ml-kem-768".into(),
            aead_alg: "aes-256-gcm".into(),
            envelope_version: 2,
            sync_durable: false,
            labels: vec![],
        };

        let (guard, sink) = stage_envelope(&local, &meta, body_of(&env), None)
            .await
            .unwrap();
        let overwrite = commit_staged(guard, sink, &meta).await.unwrap();
        assert!(!overwrite, "first write is not an overwrite");

        let got = local.get("bkt", "obj").await.unwrap();
        let mut expected = env.clone();
        expected[20..28].copy_from_slice(&plaintext_len.to_be_bytes());
        assert_eq!(&got[..], &expected[..]);

        // Re-writing the same key reports an overwrite.
        let (g2, s2) = stage_envelope(&local, &meta, body_of(&env), None)
            .await
            .unwrap();
        assert!(commit_staged(g2, s2, &meta).await.unwrap());
    }
}
