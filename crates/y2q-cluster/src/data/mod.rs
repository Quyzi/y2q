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
use y2q_core::{
    AnyStorage, AnyStreamingPutGuard, DEFAULT_LIST_LIMIT, LabelQuery, ListOptions, ListPage,
    Listing, MAX_LIST_LIMIT, Metadata, Storage,
};

use crate::control::Controller;
use crate::control::types::{ControlState, NodeStatus};
use crate::hashing::chain::Role;
use crate::hashing::ring::{Ring, chain_id};
use crate::identity::NodeId;
use crate::transport::InternalClient;
use crate::transport::TransportError;

pub use pending::{Pending, PendingGuard, PendingWrites};
pub use route::{ChainRoute, resolve_route};
pub use wire::{
    BACKFILL_META_HEADER, BackfillEntry, BackfillManifest, BackfillObjectMeta, LabelMode,
    MigrateReport, MutateMeta, MutateOp, MutateResp, PREPARE_META_HEADER, PrepareMeta, PrepareResp,
    VersionResp,
};

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
    /// The streamed envelope was shorter than the HEAD-committed size (a
    /// truncated or aborted relay). The replica is not committed.
    #[error("short envelope for {bucket}/{key}: got {got} bytes, expected {expected}")]
    ShortEnvelope {
        /// Bucket component.
        bucket: String,
        /// Key component.
        key: String,
        /// Envelope size the HEAD committed and advertised in the PREPARE.
        expected: u64,
        /// Bytes actually received before the body channel closed.
        got: u64,
    },
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

/// Read consistency requested for an apportioned read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadConsistency {
    /// Linearizable: a dirty chain member version-queries the TAIL (the commit
    /// point) and fetches the committed version if its local copy is behind.
    Strong,
    /// Serve the local committed copy if this node is a chain member, even if a
    /// newer write is in flight. Cheapest; may return a slightly stale version.
    Eventual,
    /// Serve the local committed copy if it is clean, or if it last committed
    /// within `bound_ms`; otherwise fall back to the strong version-query path.
    EventualBounded {
        /// Freshness window in milliseconds.
        bound_ms: u64,
    },
}

/// Outcome of the pure read decision before any I/O: serve the local copy,
/// fetch from the TAIL, or run a version query to decide between the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServeDecision {
    /// Serve this node's local committed copy.
    Local,
    /// Fetch the committed envelope from the TAIL.
    Remote,
    /// Dirty key under a linearizable mode: compare local vs TAIL version.
    VersionQuery,
}

/// Decide, from already-resolved inputs, how a node should serve a read.
///
/// `is_member` is whether this node is in the object's chain; `pending` whether a
/// write is in flight locally; `fresh` whether the local copy is within the
/// `eventual-bounded` window (only meaningful when `pending`).
fn serve_decision(
    consistency: ReadConsistency,
    is_member: bool,
    pending: bool,
    fresh: bool,
) -> ServeDecision {
    if !is_member {
        // A non-member holds no copy; it must fetch the committed envelope.
        return ServeDecision::Remote;
    }
    match consistency {
        // Always serve the local copy, even if a newer write is in flight.
        ReadConsistency::Eventual => ServeDecision::Local,
        // Clean copies serve locally; dirty copies serve locally only while fresh,
        // else fall back to the linearizable version query.
        ReadConsistency::EventualBounded { .. } => {
            if !pending || fresh {
                ServeDecision::Local
            } else {
                ServeDecision::VersionQuery
            }
        }
        // Clean copies are the latest committed (fast path); dirty copies require a
        // version query against the TAIL (the commit point).
        ReadConsistency::Strong => {
            if pending {
                ServeDecision::VersionQuery
            } else {
                ServeDecision::Local
            }
        }
    }
}

/// Where an apportioned read should source its bytes.
pub enum ReadPlan {
    /// Serve from this node's local committed copy (the GET handler's normal
    /// local path, range-capable).
    Local,
    /// Serve the committed ciphertext envelope fetched from the chain TAIL,
    /// along with the true plaintext size for padding trim.
    Remote {
        /// The committed envelope bytes (ciphertext), to be decrypted locally.
        envelope: Bytes,
        /// True plaintext size, for trimming Padmé padding after decryption.
        size: u64,
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

    /// Public lookup of a node's advertised base URL (used to proxy a client PUT
    /// to the chain HEAD).
    pub async fn peer_url(&self, id: NodeId) -> Option<String> {
        let state = self.controller.control_state().await;
        self.peer_base_url(&state, id)
    }

    /// This node's locally-committed CRAQ version for `(bucket, key)`, or `None`
    /// when absent or unversioned (legacy/single-node object).
    pub async fn local_committed_version(&self, bucket: &str, key: &str) -> Option<u64> {
        self.local
            .describe(bucket, key)
            .await
            .ok()
            .and_then(|m| m.version)
    }

    /// The committed version of `(bucket, key)` as known to the chain TAIL — the
    /// CRAQ commit point, so its answer is the authoritative committed version.
    /// Answered locally when this node is the TAIL, otherwise via a version query
    /// to the TAIL's `/internal/v1/version`.
    pub async fn tail_committed_version(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<u64>, DataError> {
        let state = self.controller.control_state().await;
        let route = resolve_route(
            &state,
            bucket,
            key,
            self.replication_factor,
            self.virtual_nodes_per_node,
        );
        match route.tail() {
            Some(tail) if tail == self.node_id => {
                Ok(self.local_committed_version(bucket, key).await)
            }
            Some(tail) => {
                let url = self
                    .peer_base_url(&state, tail)
                    .ok_or_else(|| DataError::NoChain {
                        bucket: bucket.to_owned(),
                        key: key.to_owned(),
                    })?;
                let resp: VersionResp = self
                    .client
                    .get_json_query(
                        &format!("{url}/internal/v1/version"),
                        &[("bucket", bucket), ("key", key)],
                    )
                    .await?;
                Ok(resp.version)
            }
            None => Err(DataError::NoChain {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
            }),
        }
    }

    /// Decide how to serve a read of `(bucket, key)` under `consistency`
    /// (CRAQ apportioned read). Returns [`ReadPlan::Local`] when this node may
    /// serve its own committed copy, or [`ReadPlan::Remote`] carrying the
    /// committed envelope fetched from the chain TAIL when the local copy is
    /// absent or behind.
    pub async fn plan_read(
        &self,
        bucket: &str,
        key: &str,
        consistency: ReadConsistency,
    ) -> Result<ReadPlan, DataError> {
        let state = self.controller.control_state().await;
        let route = resolve_route(
            &state,
            bucket,
            key,
            self.replication_factor,
            self.virtual_nodes_per_node,
        );

        // No chain yet (empty cluster / unrouted): best-effort local copy.
        if route.members.is_empty() {
            return Ok(ReadPlan::Local);
        }

        let is_member = route.contains(self.node_id);
        let pending = self.pending.is_pending(bucket, key);
        let fresh = match consistency {
            // Only `eventual-bounded` consults committed_at, and only when dirty.
            ReadConsistency::EventualBounded { bound_ms } if pending => {
                self.local_fresh_within(bucket, key, bound_ms).await
            }
            _ => false,
        };

        let serve_local = match serve_decision(consistency, is_member, pending, fresh) {
            ServeDecision::Local => true,
            ServeDecision::Remote => false,
            // Dirty under strong/bounded: the local committed copy is current only
            // if it matches the TAIL's committed version.
            ServeDecision::VersionQuery => {
                let local_v = self.local_committed_version(bucket, key).await;
                let tail_v = self.tail_committed_version(bucket, key).await?;
                local_v == tail_v
            }
        };

        if serve_local {
            return Ok(ReadPlan::Local);
        }

        // The authoritative committed copy lives at the TAIL. If this node *is*
        // the TAIL, its local copy is authoritative — serve it.
        match route.tail() {
            Some(tail) if tail == self.node_id => Ok(ReadPlan::Local),
            Some(tail) => {
                let url = self
                    .peer_base_url(&state, tail)
                    .ok_or_else(|| DataError::NoChain {
                        bucket: bucket.to_owned(),
                        key: key.to_owned(),
                    })?;
                let (envelope, size) = self
                    .client
                    .fetch_object(
                        &format!("{url}/internal/v1/read"),
                        &[("bucket", bucket), ("key", key)],
                    )
                    .await
                    .map_err(map_fetch_err)?;
                Ok(ReadPlan::Remote { envelope, size })
            }
            None => Err(DataError::NoChain {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
            }),
        }
    }

    /// Whether this node's local committed copy of `(bucket, key)` was committed
    /// within `bound_ms` of now (used by `eventual-bounded`).
    async fn local_fresh_within(&self, bucket: &str, key: &str, bound_ms: u64) -> bool {
        let Some(committed_at) = self
            .local
            .describe(bucket, key)
            .await
            .ok()
            .and_then(|m| m.committed_at)
        else {
            return false;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        now.saturating_sub(committed_at) <= bound_ms.saturating_mul(1_000_000)
    }

    /// List every object this node holds locally, for a peer's backfill diff.
    /// Unpaged (one response); paging is a future refinement for large stores.
    pub async fn local_manifest(&self) -> Result<BackfillManifest, DataError> {
        let buckets = self.local.list_buckets().await?;
        let mut entries = Vec::new();
        for bucket in buckets {
            let mut after: Option<String> = None;
            loop {
                let page = self
                    .local
                    .list_objects(
                        &bucket,
                        ListOptions {
                            after: after.clone(),
                            limit: Some(MAX_LIST_LIMIT),
                            ..Default::default()
                        },
                    )
                    .await?;
                for md in &page.items {
                    entries.push(BackfillEntry {
                        bucket: md.bucket.clone(),
                        key: md.key.clone(),
                        version: md.version,
                        cipher_sha256: md.cipher_sha256.clone(),
                    });
                }
                match page.next {
                    Some(n) => after = Some(n),
                    None => break,
                }
            }
        }
        Ok(BackfillManifest { entries })
    }

    /// Fan a list (or label search) across every Active node, k-way merge the
    /// per-node pages, dedup by `(bucket, key)` keeping the highest committed
    /// `version`, and return one merged page honoring `limit`.
    ///
    /// `bucket` is `Some` for a single-bucket list/search and `None` for a
    /// cross-bucket search; `query` is the raw label-query string for a search
    /// (`None` for a plain list). Each node returns up to `limit` of its lowest
    /// keys `> after`; the global first `limit` distinct keys are a subset of the
    /// union of those per-node pages, so merging the lowest `limit` distinct is
    /// complete. Unreachable peers are skipped (their objects still surface from a
    /// live replica) — CRAQ's "reads continue elsewhere" availability.
    pub async fn scatter_list(
        &self,
        bucket: Option<&str>,
        query: Option<&str>,
        opts: &ListOptions,
    ) -> Result<ListPage, DataError> {
        let limit = opts
            .limit
            .filter(|n| *n > 0)
            .map(|n| n.min(MAX_LIST_LIMIT))
            .unwrap_or(DEFAULT_LIST_LIMIT);
        let state = self.controller.control_state().await;

        let mut pages: Vec<ListPage> = Vec::new();
        pages.push(self.local_list_page(bucket, query, opts).await?);

        for (id, meta) in state.nodes.iter() {
            if *id == self.node_id || meta.status != NodeStatus::Active {
                continue;
            }
            match self
                .fetch_remote_list(&meta.addr, bucket, query, opts)
                .await
            {
                Ok(page) => pages.push(page),
                Err(e) => tracing::warn!(
                    peer = %meta.addr,
                    error = %e,
                    "scatter list: peer unreachable, skipping"
                ),
            }
        }

        Ok(merge_list_pages(pages, bucket.is_some(), limit))
    }

    /// Compute this node's own list/search page for a scatter-gather.
    async fn local_list_page(
        &self,
        bucket: Option<&str>,
        query: Option<&str>,
        opts: &ListOptions,
    ) -> Result<ListPage, DataError> {
        match (bucket, query) {
            (Some(b), None) => Ok(self.local.list_objects(b, opts.clone()).await?),
            (b, Some(q)) => {
                let parsed = LabelQuery::parse(q)
                    .map_err(|e| DataError::Io(format!("bad label query: {e}")))?;
                Ok(self.local.search_objects(&parsed, b, opts.clone()).await?)
            }
            (None, None) => Err(DataError::Io(
                "scatter list requires a bucket or a label query".into(),
            )),
        }
    }

    /// Fetch one peer's local list/search page from its `/internal/v1/list`.
    async fn fetch_remote_list(
        &self,
        peer_url: &str,
        bucket: Option<&str>,
        query: Option<&str>,
        opts: &ListOptions,
    ) -> Result<ListPage, DataError> {
        let mut params: Vec<(&str, &str)> = Vec::new();
        if let Some(b) = bucket {
            params.push(("bucket", b));
        }
        if let Some(q) = query {
            params.push(("q", q));
        }
        if let Some(p) = opts.prefix.as_deref() {
            params.push(("prefix", p));
        }
        if let Some(a) = opts.after.as_deref() {
            params.push(("after", a));
        }
        let limit_s = opts.limit.map(|n| n.to_string());
        if let Some(l) = limit_s.as_deref() {
            params.push(("limit", l));
        }
        let url = format!("{peer_url}/internal/v1/list");
        self.client
            .get_json_query(&url, &params)
            .await
            .map_err(DataError::from)
    }

    /// Whether this node *would* hold `(bucket, key)` once Active, computed from
    /// the ring over the active membership **plus this node** (so a Recovering
    /// node — excluded from the active ring — still discovers what to pull).
    fn prospective_holds(&self, state: &ControlState, bucket: &str, key: &str) -> bool {
        let mut members = state.active_nodes();
        if !members.contains(&self.node_id) {
            members.push(self.node_id);
            members.sort_unstable();
        }
        let ring = Ring::new(&members, self.virtual_nodes_per_node);
        ring.chain_for_id(chain_id(bucket, key), self.replication_factor)
            .contains(&self.node_id)
    }

    /// Pull a single object's committed envelope from `peer_url` and commit a
    /// byte-identical replica at the carried version (TAIL/solo commit path).
    async fn backfill_object(
        &self,
        peer_url: &str,
        bucket: &str,
        key: &str,
        epoch: u64,
    ) -> Result<(), DataError> {
        let (envelope, header) = self
            .client
            .get_bytes_and_header(
                &format!("{peer_url}/internal/v1/backfill/object"),
                &[("bucket", bucket), ("key", key)],
                wire::BACKFILL_META_HEADER,
            )
            .await
            .map_err(map_fetch_err)?;
        let header =
            header.ok_or_else(|| DataError::Io("backfill object missing meta header".into()))?;
        let meta: BackfillObjectMeta =
            serde_json::from_str(&header).map_err(|e| DataError::Io(e.to_string()))?;
        let pmeta = meta.to_prepare(bucket, key, chain_id(bucket, key), epoch);

        let (tx, rx) = mpsc::channel::<Bytes>(4);
        tokio::spawn(async move {
            let _ = tx.send(envelope).await;
        });
        let (guard, sink) = stage_envelope(&self.local, &pmeta, rx, None).await?;
        commit_staged(guard, sink, &pmeta).await?;
        Ok(())
    }

    /// Run one backfill sweep: for every object an Active peer holds that this
    /// node should hold (prospectively) and is missing or behind on, pull and
    /// commit it. Returns the number of objects fetched (0 ⇒ nothing was
    /// missing this sweep — i.e. caught up).
    #[tracing::instrument(skip_all, name = "cluster.backfill")]
    pub async fn backfill_pass(&self) -> Result<usize, DataError> {
        let state = self.controller.control_state().await;
        let epoch = state.epoch;
        let peers: Vec<String> = state
            .nodes
            .iter()
            .filter(|(id, meta)| **id != self.node_id && meta.status == NodeStatus::Active)
            .map(|(_, meta)| meta.addr.clone())
            .collect();

        let mut fetched = 0usize;
        for url in peers {
            let manifest: BackfillManifest = match self
                .client
                .get_json(&format!("{url}/internal/v1/backfill/manifest"))
                .await
            {
                Ok(m) => m,
                Err(_) => continue, // peer unreachable this sweep; try the rest
            };
            for entry in manifest.entries {
                if !self.prospective_holds(&state, &entry.bucket, &entry.key) {
                    continue;
                }
                let local = self
                    .local
                    .describe(&entry.bucket, &entry.key)
                    .await
                    .ok()
                    .map(|m| (m.version, m.cipher_sha256));
                if !need_backfill(local, entry.version, &entry.cipher_sha256) {
                    continue;
                }
                if self
                    .backfill_object(&url, &entry.bucket, &entry.key, epoch)
                    .await
                    .is_ok()
                {
                    fetched += 1;
                }
            }
        }
        Ok(fetched)
    }

    /// Distribute this node's local objects across the cluster (single-node →
    /// cluster import). For each local object, resolve its chain and — unless
    /// every chain member already holds a byte-identical copy — push the verbatim
    /// envelope to the chain HEAD, which replicates it down the chain. Idempotent
    /// and resumable: objects already replicated are skipped. With `prune`, an
    /// object whose chain excludes this node is deleted locally after it has been
    /// safely replicated (never before, and never on a transfer error).
    pub async fn migrate_distribute(&self, prune: bool) -> Result<MigrateReport, DataError> {
        use std::collections::HashMap;

        let state = self.controller.control_state().await;
        let manifest = self.local_manifest().await?;
        // Per-member manifest cache: member id → {(bucket,key) → cipher_sha256}.
        let mut member_objs: HashMap<NodeId, HashMap<(String, String), Option<String>>> =
            HashMap::new();
        let mut report = MigrateReport::default();

        for entry in manifest.entries {
            report.scanned += 1;
            let route = resolve_route(
                &state,
                &entry.bucket,
                &entry.key,
                self.replication_factor,
                self.virtual_nodes_per_node,
            );
            if route.members.is_empty() {
                report
                    .errors
                    .push(format!("{}/{}: no chain", entry.bucket, entry.key));
                continue;
            }

            if self
                .chain_fully_holds(&state, &route, &entry, &mut member_objs)
                .await
            {
                report.skipped += 1;
            } else {
                match self
                    .push_object(&state, &route, &entry.bucket, &entry.key)
                    .await
                {
                    Ok(()) => report.transferred += 1,
                    Err(e) => {
                        report
                            .errors
                            .push(format!("{}/{}: {e}", entry.bucket, entry.key));
                        continue; // do not prune an object we failed to replicate
                    }
                }
            }

            if prune
                && !route.contains(self.node_id)
                && self.local.delete(&entry.bucket, &entry.key).await.is_ok()
            {
                report.pruned += 1;
            }
        }
        Ok(report)
    }

    /// Whether every chain member other than this node already holds a copy of
    /// `entry` with a matching ciphertext digest (so a distribute can skip it).
    /// Lazily fetches and caches each member's backfill manifest; an unreachable
    /// member or an unknown digest counts as "does not hold" (forcing a push).
    async fn chain_fully_holds(
        &self,
        state: &ControlState,
        route: &ChainRoute,
        entry: &BackfillEntry,
        cache: &mut std::collections::HashMap<
            NodeId,
            std::collections::HashMap<(String, String), Option<String>>,
        >,
    ) -> bool {
        use std::collections::HashMap;
        let Some(want) = entry.cipher_sha256.clone() else {
            return false;
        };
        for &m in &route.members {
            if m == self.node_id {
                continue;
            }
            // Lazily fetch and cache the member's manifest. The await happens
            // inside the vacant arm, which is the sole borrow of `cache`.
            if let std::collections::hash_map::Entry::Vacant(slot) = cache.entry(m) {
                let mut map: HashMap<(String, String), Option<String>> = HashMap::new();
                if let Some(url) = self.peer_base_url(state, m)
                    && let Ok(man) = self
                        .client
                        .get_json::<BackfillManifest>(&format!(
                            "{url}/internal/v1/backfill/manifest"
                        ))
                        .await
                {
                    for e in man.entries {
                        map.insert((e.bucket, e.key), e.cipher_sha256);
                    }
                }
                slot.insert(map);
            }
            let held = cache
                .get(&m)
                .and_then(|map| map.get(&(entry.bucket.clone(), entry.key.clone())).cloned())
                .flatten();
            if held.as_deref() != Some(want.as_str()) {
                return false;
            }
        }
        true
    }

    /// Push one local object's verbatim envelope onto its chain. If this node is
    /// the chain HEAD it replicates straight down the chain; otherwise it sends a
    /// PREPARE to the remote HEAD, which writes the bytes verbatim and relays them
    /// through the rest of the chain (including back through this node when it is a
    /// non-head member — an idempotent verbatim overwrite).
    async fn push_object(
        &self,
        state: &ControlState,
        route: &ChainRoute,
        bucket: &str,
        key: &str,
    ) -> Result<(), DataError> {
        let md = self.local.describe(bucket, key).await?;
        let bmeta = BackfillObjectMeta {
            version: md.version.unwrap_or(0),
            plaintext_len: envelope::padme_len(md.size),
            plaintext_size: md.size,
            checksum_gxhash_b64: md.checksum_gxhash.clone(),
            cipher_size: md.cipher_size.unwrap_or(0),
            cipher_sha256_b64: md.cipher_sha256.clone().unwrap_or_default(),
            kem_alg: md.kem_alg.clone().unwrap_or_default(),
            aead_alg: md.aead_alg.clone().unwrap_or_default(),
            envelope_version: md.envelope_version.unwrap_or(2),
            labels: md.labels.iter().cloned().collect(),
        };
        let pmeta = bmeta.to_prepare(bucket, key, chain_id(bucket, key), route.epoch);
        let envelope = self.local.get(bucket, key).await?.into_inner();

        let (tx, rx) = mpsc::channel::<Bytes>(4);
        tokio::spawn(async move {
            let _ = tx.send(envelope).await;
        });

        match route.head() {
            Some(h) if h == self.node_id => {
                self.forward_to_next(&pmeta, rx).await?;
            }
            Some(h) => {
                let url = self
                    .peer_base_url(state, h)
                    .ok_or_else(|| DataError::NoChain {
                        bucket: bucket.to_owned(),
                        key: key.to_owned(),
                    })?;
                forward_prepare(&self.client, &url, &pmeta, rx).await?;
            }
            None => {
                return Err(DataError::NoChain {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Collect every object in the cluster onto this node (cluster → single-node
    /// export). Pulls the full object set from every Active peer regardless of
    /// chain ownership, so afterwards this node holds a complete copy and can run
    /// standalone (`cluster.enabled = false`). Idempotent: objects already present
    /// with a matching digest are skipped.
    pub async fn migrate_collect(&self) -> Result<MigrateReport, DataError> {
        let state = self.controller.control_state().await;
        let epoch = state.epoch;
        let peers: Vec<String> = state
            .nodes
            .iter()
            .filter(|(id, meta)| **id != self.node_id && meta.status == NodeStatus::Active)
            .map(|(_, meta)| meta.addr.clone())
            .collect();

        let mut report = MigrateReport::default();
        for url in peers {
            let manifest: BackfillManifest = match self
                .client
                .get_json(&format!("{url}/internal/v1/backfill/manifest"))
                .await
            {
                Ok(m) => m,
                Err(e) => {
                    report.errors.push(format!("manifest {url}: {e}"));
                    continue;
                }
            };
            for entry in manifest.entries {
                report.scanned += 1;
                let local = self
                    .local
                    .describe(&entry.bucket, &entry.key)
                    .await
                    .ok()
                    .map(|m| (m.version, m.cipher_sha256));
                if !need_backfill(local, entry.version, &entry.cipher_sha256) {
                    report.skipped += 1;
                    continue;
                }
                match self
                    .backfill_object(&url, &entry.bucket, &entry.key, epoch)
                    .await
                {
                    Ok(()) => report.transferred += 1,
                    Err(e) => report
                        .errors
                        .push(format!("{}/{}: {e}", entry.bucket, entry.key)),
                }
            }
        }
        Ok(report)
    }

    /// Apply a non-PUT mutation (DELETE / label edit) locally and relay it to the
    /// next chain member. Called on each member as the mutation walks the chain.
    ///
    /// A label edit ([`MutateOp::EditLabels`]) is resolved here against this
    /// node's committed copy into a concrete set, which is what gets applied and
    /// relayed downstream — so every member ends up with identical labels even
    /// though only the HEAD reads the prior set. Returns the HEAD's `existed`
    /// verdict and the resolved label set. Marks the key dirty for the duration.
    pub async fn accept_mutate(&self, meta: MutateMeta) -> Result<MutateResp, DataError> {
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

        // Resolve a label edit against the local copy before applying/relaying,
        // so downstream members receive the already-resolved set.
        let resolved = self.resolve_op(&meta).await?;
        let labels = match &resolved.op {
            MutateOp::SetLabels { labels } => labels.clone(),
            _ => Vec::new(),
        };

        let existed = self.apply_mutate(&resolved).await?;

        if let Some(next_id) = route.next_after(self.node_id) {
            let url = self
                .peer_base_url(&state, next_id)
                .ok_or_else(|| DataError::NoChain {
                    bucket: resolved.bucket.clone(),
                    key: resolved.key.clone(),
                })?;
            let _down: MutateResp = self
                .client
                .post_json(&format!("{url}/internal/v1/mutate"), &resolved)
                .await?;
        }
        Ok(MutateResp { existed, labels })
    }

    /// Resolve a label edit against this node's committed copy. Delete and an
    /// already-resolved `SetLabels` pass through unchanged.
    async fn resolve_op(&self, meta: &MutateMeta) -> Result<MutateMeta, DataError> {
        match &meta.op {
            MutateOp::EditLabels { mode, incoming } => {
                let current: Vec<(String, String)> = self
                    .local
                    .describe(&meta.bucket, &meta.key)
                    .await?
                    .labels
                    .into_iter()
                    .collect();
                let labels = mode.resolve(current, incoming.clone());
                Ok(MutateMeta {
                    op: MutateOp::SetLabels { labels },
                    ..meta.clone()
                })
            }
            _ => Ok(meta.clone()),
        }
    }

    /// Apply a (resolved) mutation to the local backend.
    async fn apply_mutate(&self, meta: &MutateMeta) -> Result<bool, DataError> {
        match &meta.op {
            MutateOp::Delete => match self.local.delete(&meta.bucket, &meta.key).await {
                Ok(_) => Ok(true),
                Err(y2q_core::Error::NotFound { .. }) => Ok(false),
                Err(e) => Err(e.into()),
            },
            MutateOp::SetLabels { labels } => {
                self.local
                    .set_labels(&meta.bucket, &meta.key, labels.iter().cloned().collect())
                    .await?;
                Ok(true)
            }
            // Resolved by `resolve_op` before reaching here; never relayed raw.
            MutateOp::EditLabels { .. } => Err(DataError::Io(
                "unresolved label edit reached apply_mutate".to_owned(),
            )),
        }
    }

    /// Send a mutation to a peer's `/internal/v1/mutate` (used when the contact
    /// node is not the HEAD: it forwards to the HEAD, which walks the chain).
    pub async fn send_mutate(
        &self,
        base_url: &str,
        meta: &MutateMeta,
    ) -> Result<MutateResp, DataError> {
        let resp = self
            .client
            .post_json(&format!("{base_url}/internal/v1/mutate"), meta)
            .await?;
        Ok(resp)
    }

    /// Forward an already-committed envelope from this node (the HEAD) to the next
    /// chain member, which relays it through the rest of the chain. `body` yields
    /// the verbatim envelope bytes. Returns the downstream commit response, or
    /// `None` when this node has no successor (a solo chain — nothing to do).
    pub async fn forward_to_next(
        &self,
        meta: &PrepareMeta,
        body: mpsc::Receiver<Bytes>,
    ) -> Result<Option<PrepareResp>, DataError> {
        let state = self.controller.control_state().await;
        let route = resolve_route(
            &state,
            &meta.bucket,
            &meta.key,
            self.replication_factor,
            self.virtual_nodes_per_node,
        );
        match route.next_after(self.node_id) {
            Some(next_id) => {
                let url =
                    self.peer_base_url(&state, next_id)
                        .ok_or_else(|| DataError::NoChain {
                            bucket: meta.bucket.clone(),
                            key: meta.key.clone(),
                        })?;
                let resp = forward_prepare(&self.client, &url, meta, body).await?;
                Ok(Some(resp))
            }
            None => Ok(None),
        }
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

                // On a local staging failure, cancel the relay so the successor
                // does not see a clean EOF and commit a partial copy.
                let (guard, sink) =
                    match stage_envelope(&self.local, &meta, body, Some(fwd_tx)).await {
                        Ok(staged) => staged,
                        Err(e) => {
                            fwd_task.abort();
                            return Err(e);
                        }
                    };
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

/// Whether a recovering node must pull `(version, sha)` from a peer, given its
/// own copy (`local`, `None` ⇒ object absent locally). Pulls when missing,
/// behind, or same-version with a divergent ciphertext digest.
fn need_backfill(
    local: Option<(Option<u64>, Option<String>)>,
    entry_version: Option<u64>,
    entry_sha: &Option<String>,
) -> bool {
    let Some((lv, lsha)) = local else {
        return true; // absent locally
    };
    let lv = lv.unwrap_or(0);
    let ev = entry_version.unwrap_or(0);
    if lv < ev {
        return true; // behind
    }
    if lv == ev {
        // Same version: refetch only if both digests are known and differ.
        if let (Some(a), Some(b)) = (&lsha, entry_sha) {
            return a != b;
        }
        return false;
    }
    false // local is ahead
}

/// K-way merge per-node list pages: dedup by `(bucket, key)` keeping the highest
/// committed `version` (legacy `None` treated as v0), sort ascending by
/// `(bucket, key)`, and cap at `limit`. `single_bucket` selects the cursor
/// format: a bare `key` for a single-bucket list/search, or the `bucket\0key`
/// composite the core index uses for cross-bucket pagination.
///
/// `next` is `Some(last cursor)` whenever more may remain — either the merge
/// overflowed `limit`, or some node still had a continuation — and `None` only
/// when every node's page was exhausted and the merge fit within `limit`.
fn merge_list_pages(pages: Vec<ListPage>, single_bucket: bool, limit: usize) -> ListPage {
    use std::collections::HashMap;

    let any_more = pages.iter().any(|p| p.next.is_some());
    let mut best: HashMap<(String, String), Metadata> = HashMap::new();
    for page in pages {
        for md in page.items {
            let id = (md.bucket.clone(), md.key.clone());
            match best.get(&id) {
                Some(existing) if existing.version.unwrap_or(0) >= md.version.unwrap_or(0) => {}
                _ => {
                    best.insert(id, md);
                }
            }
        }
    }

    let mut items: Vec<Metadata> = best.into_values().collect();
    items.sort_by(|a, b| a.bucket.cmp(&b.bucket).then_with(|| a.key.cmp(&b.key)));
    let overflow = items.len() > limit;
    items.truncate(limit);

    let next = if overflow || any_more {
        items.last().map(|m| {
            if single_bucket {
                m.key.clone()
            } else {
                format!("{}\u{0}{}", m.bucket, m.key)
            }
        })
    } else {
        None
    };

    ListPage { items, next }
}

/// Map a peer object-fetch transport error: a `404` from the TAIL becomes a
/// typed not-found (so the read surfaces as 404, not 500); other errors pass
/// through as transport failures.
fn map_fetch_err(e: TransportError) -> DataError {
    match e {
        TransportError::Status { status: 404, .. } => {
            DataError::Storage(y2q_core::Error::NotFound {
                bucket: String::new(),
                key: String::new(),
            })
        }
        other => DataError::Transport(other),
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

    let mut received: u64 = 0;
    while let Some(chunk) = body.recv().await {
        received += chunk.len() as u64;
        sink.write_all(&chunk)
            .await
            .map_err(|e| DataError::Io(e.to_string()))?;
        if let Some(f) = &forward {
            f.send(chunk).await.map_err(|_| DataError::ForwardClosed)?;
        }
    }

    // A closed body channel is indistinguishable from a complete one, so a cut or
    // aborted relay would otherwise commit a short, undecryptable replica. Reject
    // anything that does not match the exact envelope the HEAD committed.
    if received != meta.cipher_size {
        return Err(DataError::ShortEnvelope {
            bucket: meta.bucket.clone(),
            key: meta.key.clone(),
            expected: meta.cipher_size,
            got: received,
        });
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

    /// The pure backfill decision covers absent / behind / same-version /
    /// digest-mismatch / ahead cases.
    #[test]
    fn need_backfill_matrix() {
        // Absent locally -> always pull.
        assert!(need_backfill(None, Some(3), &Some("x".into())));
        // Behind -> pull.
        assert!(need_backfill(
            Some((Some(2), Some("a".into()))),
            Some(3),
            &Some("b".into())
        ));
        // Same version, matching digest -> skip.
        assert!(!need_backfill(
            Some((Some(3), Some("a".into()))),
            Some(3),
            &Some("a".into())
        ));
        // Same version, divergent digest -> pull.
        assert!(need_backfill(
            Some((Some(3), Some("a".into()))),
            Some(3),
            &Some("b".into())
        ));
        // Same version, digest unknown on a side -> skip (cannot tell).
        assert!(!need_backfill(
            Some((Some(3), None)),
            Some(3),
            &Some("a".into())
        ));
        // Local ahead -> skip.
        assert!(!need_backfill(
            Some((Some(5), Some("a".into()))),
            Some(3),
            &Some("b".into())
        ));
    }

    /// The pure read decision covers every consistency mode against the
    /// member/pending/fresh inputs.
    #[test]
    fn serve_decision_matrix() {
        use ReadConsistency::*;
        // Non-members always fetch from the TAIL, regardless of mode.
        for c in [Strong, Eventual, EventualBounded { bound_ms: 100 }] {
            assert_eq!(
                serve_decision(c, false, false, false),
                ServeDecision::Remote
            );
        }
        // Strong: clean member serves local; dirty member version-queries.
        assert_eq!(
            serve_decision(Strong, true, false, false),
            ServeDecision::Local
        );
        assert_eq!(
            serve_decision(Strong, true, true, false),
            ServeDecision::VersionQuery
        );
        // Eventual: members always serve local, even when dirty.
        assert_eq!(
            serve_decision(Eventual, true, true, false),
            ServeDecision::Local
        );
        // Eventual-bounded: dirty + fresh serves local; dirty + stale falls back.
        let b = EventualBounded { bound_ms: 100 };
        assert_eq!(serve_decision(b, true, false, false), ServeDecision::Local);
        assert_eq!(serve_decision(b, true, true, true), ServeDecision::Local);
        assert_eq!(
            serve_decision(b, true, true, false),
            ServeDecision::VersionQuery
        );
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
            version: 1,
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

    /// A relay that delivers fewer bytes than the HEAD committed is rejected
    /// (not committed as a truncated replica).
    #[tokio::test]
    async fn stage_rejects_short_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let local = local_storage(dir.path());

        let env = vec![0u8; 32];
        let meta = PrepareMeta {
            bucket: "bkt".into(),
            key: "obj".into(),
            chain_id: 1,
            epoch: 0,
            version: 1,
            plaintext_len: 16,
            plaintext_size: 16,
            checksum_gxhash_b64: "AAAAAAAAAAA=".into(),
            // Claim a larger envelope than the body will deliver.
            cipher_size: 64,
            cipher_sha256_b64: String::new(),
            kem_alg: "ml-kem-768".into(),
            aead_alg: "aes-256-gcm".into(),
            envelope_version: 2,
            sync_durable: false,
            labels: vec![],
        };

        let Err(err) = stage_envelope(&local, &meta, body_of(&env), None).await else {
            panic!("expected a ShortEnvelope error");
        };
        assert!(matches!(
            err,
            DataError::ShortEnvelope {
                expected: 64,
                got: 32,
                ..
            }
        ));
        // Nothing was committed.
        assert!(local.get("bkt", "obj").await.is_err());
    }

    /// Build a minimal `Metadata` for merge tests.
    fn md(bucket: &str, key: &str, version: Option<u64>) -> Metadata {
        Metadata {
            created: 0,
            modified: 0,
            size: 0,
            checksum_gxhash: String::new(),
            bucket: bucket.into(),
            key: key.into(),
            disk_path: std::path::PathBuf::new(),
            url_path: format!("{bucket}/{key}"),
            labels: Default::default(),
            cipher_size: None,
            cipher_sha256: None,
            kem_alg: None,
            aead_alg: None,
            envelope_version: None,
            version,
            committed_at: None,
        }
    }

    fn page(items: Vec<Metadata>, next: Option<&str>) -> ListPage {
        ListPage {
            items,
            next: next.map(|s| s.to_string()),
        }
    }

    /// Replicas of the same key collapse to one entry (highest version wins),
    /// results sort by key, and the cursor is a bare key for a single bucket.
    #[test]
    fn merge_dedups_by_highest_version_single_bucket() {
        let pages = vec![
            page(vec![md("b", "a", Some(2)), md("b", "c", Some(1))], None),
            page(vec![md("b", "a", Some(3)), md("b", "b", Some(1))], None),
        ];
        let merged = merge_list_pages(pages, true, 10);
        let keys: Vec<_> = merged.items.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(keys, ["a", "b", "c"]);
        // The surviving "a" is the higher-version replica.
        assert_eq!(merged.items[0].version, Some(3));
        // Exhausted within limit -> no cursor.
        assert_eq!(merged.next, None);
    }

    /// Overflowing `limit` truncates and emits the last key as the cursor.
    #[test]
    fn merge_truncates_and_emits_cursor() {
        let pages = vec![
            page(vec![md("b", "a", None), md("b", "c", None)], None),
            page(vec![md("b", "b", None), md("b", "d", None)], None),
        ];
        let merged = merge_list_pages(pages, true, 2);
        let keys: Vec<_> = merged.items.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(keys, ["a", "b"]);
        assert_eq!(merged.next.as_deref(), Some("b"));
    }

    /// A continuation from any node propagates even when the merge fits `limit`.
    #[test]
    fn merge_propagates_peer_continuation() {
        let pages = vec![
            page(vec![md("b", "a", None)], Some("a")),
            page(vec![md("b", "b", None)], None),
        ];
        let merged = merge_list_pages(pages, true, 10);
        assert_eq!(merged.items.len(), 2);
        // A peer still had more, so a cursor is emitted at the last key.
        assert_eq!(merged.next.as_deref(), Some("b"));
    }

    /// Cross-bucket merges sort by `(bucket, key)` and emit the `bucket\0key`
    /// composite cursor the core index uses.
    #[test]
    fn merge_cross_bucket_composite_cursor() {
        let pages = vec![
            page(vec![md("z", "k", None), md("a", "k", None)], None),
            page(vec![md("a", "j", None)], None),
        ];
        let merged = merge_list_pages(pages, false, 2);
        let ids: Vec<_> = merged
            .items
            .iter()
            .map(|m| (m.bucket.as_str(), m.key.as_str()))
            .collect();
        assert_eq!(ids, [("a", "j"), ("a", "k")]);
        assert_eq!(merged.next.as_deref(), Some("a\u{0}k"));
    }
}
