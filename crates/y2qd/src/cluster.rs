//! Cluster control-plane integration for the daemon.
//!
//! Builds the [`ClusterRuntime`] (provisioned MEK unlock, node identity, the
//! embedded raft [`Controller`] over the HTTP transport), the [`ClusterPeer`]
//! extractor that authenticates peer requests, and the actix handlers serving
//! the `/internal/v1` raft RPCs plus the admin `/api/v1/cluster` endpoints.
//!
//! Everything here is reached only when `[cluster] enabled = true`; the
//! single-node path never constructs a runtime or registers these routes.

use std::collections::{BTreeMap, BTreeSet};
use std::future::{Ready, ready};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use actix_web::{
    FromRequest, HttpRequest, HttpResponse,
    dev::Payload,
    error::{ErrorBadGateway, ErrorBadRequest, ErrorUnauthorized},
    web,
};
use bytes::Bytes;
use openraft::BasicNode;
use openraft::raft::{AppendEntriesRequest, InstallSnapshotRequest, VoteRequest};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use y2q_cluster::control::raft_impl::TypeConfig;
use y2q_cluster::transport::internal_client::CLUSTER_AUTH_HEADER;
use y2q_cluster::{
    BACKFILL_META_HEADER, BackfillObjectMeta, ChainRoute, ControlCmd, Controller, ControllerConfig,
    DistributedStorage, HttpRaftNetworkFactory, InternalClient, InternalTlsOptions, LabelMode,
    MutateMeta, MutateOp, MutateResp, NodeStatus, PREPARE_META_HEADER, PrepareMeta,
    ReadConsistency, ReadPlan, Role, VersionResp, chain_id, resolve_node_id,
};
use y2q_core::crypto::{envelope, kdf};
use y2q_core::{
    AnyStorage, AnyStreamingPutGuard, LabelSet, ListOptions, Listing, MAX_LIST_LIMIT, PutOptions,
    Storage, SyncLevel,
};

use crate::auth::{AdminAuthenticated, AuthState};
use crate::cipher;
use crate::config::{ClusterAuth, ClusterConsistency, Config};
use crate::error::AppError;

/// Long-lived cluster runtime, shared with handlers via `web::Data`.
pub struct ClusterRuntime {
    /// The embedded raft controller.
    pub controller: Arc<Controller>,
    /// The CRAQ data-plane handle (chain routing + replicated writes).
    pub distributed: Arc<DistributedStorage>,
    /// Internal HTTP client for peer RPC (used to attest a candidate's identity
    /// on admission).
    client: Arc<InternalClient>,
    /// This node's deployment public-key fingerprint. The leader admits a peer
    /// only if it attests the same fingerprint (the shared-MEK invariant).
    fingerprint: String,
    /// Deployment public key, used to encrypt at the HEAD without a login (the
    /// MEK is provisioned at boot; encryption only needs the public key).
    public_key: Arc<Vec<u8>>,
    /// This node's id.
    pub node_id: u64,
    /// Shared secret used to authenticate peer requests (when `auth_mode` is
    /// `shared-secret`).
    shared_secret: Option<Zeroizing<String>>,
    /// Peer authentication mode in effect.
    auth_mode: ClusterAuth,
    /// Read consistency applied to apportioned GETs.
    pub read_consistency: ReadConsistency,
    /// Set true once this node has completed a clean back-fill sweep while in
    /// `Recovering`; reported in health so the leader can promote it to `Active`.
    /// Reset whenever the node observes itself `Down` (it has lost currency).
    backfill_caught_up: Arc<AtomicBool>,
}

impl ClusterRuntime {
    /// Validate a peer request's credentials.
    fn peer_authorized(&self, req: &HttpRequest) -> bool {
        match self.auth_mode {
            // mTLS: the rustls layer already verified the client certificate
            // against the configured cluster CA at handshake time.
            ClusterAuth::Mtls => true,
            ClusterAuth::SharedSecret => {
                let provided = req
                    .headers()
                    .get(CLUSTER_AUTH_HEADER)
                    .and_then(|v| v.to_str().ok());
                match (provided, self.shared_secret.as_deref()) {
                    (Some(p), Some(expected)) => {
                        bool::from(p.as_bytes().ct_eq(expected.as_bytes()))
                    }
                    _ => false,
                }
            }
        }
    }
}

/// Extractor that admits only authenticated cluster peers. Used to gate the
/// `/internal/v1` endpoints; rejects with 401 otherwise.
pub struct ClusterPeer;

impl FromRequest for ClusterPeer {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let ok = req
            .app_data::<web::Data<ClusterRuntime>>()
            .is_some_and(|rt| rt.peer_authorized(req));
        ready(if ok {
            Ok(ClusterPeer)
        } else {
            Err(ErrorUnauthorized("cluster peer authentication failed"))
        })
    }
}

/// Build the cluster runtime: provision the MEK, resolve identity, start the
/// raft controller over HTTP, and (on the bootstrap node) initialize the cluster
/// and schedule peer joins.
pub async fn build_runtime(
    cfg: &Config,
    auth_state: &AuthState,
    storage: Arc<AnyStorage>,
) -> std::io::Result<ClusterRuntime> {
    provision_mek(auth_state, cfg)?;

    let raft_dir = raft_dir(cfg);
    std::fs::create_dir_all(&raft_dir).map_err(|e| {
        std::io::Error::other(format!("create raft dir {}: {e}", raft_dir.display()))
    })?;

    let configured_id = {
        let raw = cfg.cluster.node_id.trim();
        if raw.is_empty() {
            None
        } else {
            Some(
                raw.parse::<u64>()
                    .map_err(|_| std::io::Error::other("cluster.node_id must be a u64"))?,
            )
        }
    };
    let node_id = resolve_node_id(&raft_dir, configured_id)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let shared_secret = cluster_shared_secret(cfg);
    let tls = internal_tls_options(cfg)?;
    let client = Arc::new(
        InternalClient::new(&tls, shared_secret.clone())
            .map_err(|e| std::io::Error::other(format!("internal client: {e}")))?,
    );

    let factory = HttpRaftNetworkFactory::new(Arc::clone(&client));
    let ccfg = ControllerConfig {
        heartbeat_interval_ms: cfg.cluster.raft.heartbeat_interval_ms,
        election_timeout_min_ms: cfg.cluster.raft.election_timeout_min_ms,
        election_timeout_max_ms: cfg.cluster.raft.election_timeout_max_ms,
        replication_factor: cfg.cluster.replication_factor,
        virtual_nodes_per_node: cfg.cluster.virtual_nodes_per_node,
    };
    let controller = Arc::new(
        Controller::start(node_id, &raft_dir, factory, ccfg)
            .await
            .map_err(|e| std::io::Error::other(format!("start controller: {e}")))?,
    );

    tracing::info!(node_id, raft_dir = %raft_dir.display(), "cluster controller started");

    let distributed = Arc::new(DistributedStorage::new(
        storage,
        Arc::clone(&controller),
        Arc::clone(&client),
        node_id,
        cfg.cluster.replication_factor,
        cfg.cluster.virtual_nodes_per_node,
    ));

    let fingerprint = auth_state.public_keystore.fingerprint.clone();
    let public_key = Arc::clone(&auth_state.public_keystore.public_key);

    if cfg.cluster.raft.bootstrap {
        bootstrap(&controller, &client, cfg, node_id, fingerprint.clone()).await;
    }

    Ok(ClusterRuntime {
        controller,
        distributed,
        client,
        fingerprint,
        public_key,
        node_id,
        shared_secret: shared_secret.map(Zeroizing::new),
        auth_mode: cfg.cluster.auth,
        read_consistency: read_consistency(cfg),
        backfill_caught_up: Arc::new(AtomicBool::new(false)),
    })
}

/// Map the configured consistency mode to the data-plane [`ReadConsistency`].
fn read_consistency(cfg: &Config) -> ReadConsistency {
    match cfg.cluster.consistency {
        ClusterConsistency::Strong => ReadConsistency::Strong,
        ClusterConsistency::Eventual => ReadConsistency::Eventual,
        ClusterConsistency::EventualBounded => ReadConsistency::EventualBounded {
            bound_ms: cfg.cluster.eventual_bound_ms,
        },
    }
}

/// Spawn the cluster maintenance loop. Every node runs it, but the roles differ:
///
/// - **Self-recovery (any node):** when this node observes itself `Recovering`,
///   it runs back-fill sweeps (pulling objects it should hold from Active peers)
///   until a sweep finds nothing missing, then advertises `caught_up` in health
///   so the leader can promote it. Observing itself `Down` resets `caught_up`.
/// - **Leader (controller authority):** each tick it re-splices (pinning
///   membership deltas and bumping the epoch the fence enforces) and probes every
///   other node, driving the liveness state machine:
///   `Active` → `Down` after `fail_threshold` failed probes; `Down` → `Recovering`
///   once reachable again; `Recovering` → `Active` once the peer reports
///   `caught_up`. Each transition re-splices so chains follow membership.
pub fn spawn_maintenance(rt: web::Data<ClusterRuntime>, interval_ms: u64, fail_threshold: u32) {
    let interval = Duration::from_millis(interval_ms.max(100));
    let threshold = fail_threshold.max(1);
    tokio::spawn(async move {
        let mut failures: BTreeMap<u64, u32> = BTreeMap::new();
        loop {
            tokio::time::sleep(interval).await;
            let state = rt.controller.control_state().await;

            // Refresh the cluster gauges every tick on every node so `/metrics`
            // tracks raft term/leadership/epoch and chain health continuously.
            record_cluster_gauges(&rt, &state).await;

            // Self-recovery runs on every node regardless of leadership.
            run_self_recovery(&rt, &state).await;

            // Only the leader drives the cluster-wide liveness state machine.
            if !rt.controller.is_leader().await {
                failures.clear();
                continue;
            }

            // Pin chains + bump epoch for any membership delta (no-op in steady
            // state, so this does not churn the epoch).
            if let Err(e) = rt.controller.resplice_now().await {
                tracing::warn!(error = %e, "cluster maintenance: resplice tick failed");
            }

            for (id, meta) in state.nodes.iter() {
                if *id == rt.node_id {
                    continue;
                }
                let url = format!("{}/internal/v1/health", meta.addr);
                let probe = rt.client.get_json::<HealthResp>(&url).await;
                drive_peer_liveness(&rt, *id, meta.status, probe, &mut failures, threshold).await;
            }
        }
    });
}

/// If this node sees itself `Recovering`, run a back-fill sweep and flag
/// `caught_up` when a sweep pulls nothing (everything it should hold is present).
/// Seeing itself `Down` clears the flag (it has lost currency since last caught up).
///
/// LIMITATION: a recovering node is excluded from chains until promoted, so it
/// does not receive writes during recovery. Writes to its prospective chains in
/// the window between `caught_up` and promotion can be missed until a later
/// recovery. Converging under concurrent writes (the recovering node joining the
/// write chain while catching up) is a Phase F hardening; today back-fill is
/// correct when writes to the recovering chains quiesce during the window.
async fn run_self_recovery(rt: &ClusterRuntime, state: &y2q_cluster::ControlState) {
    let my_status = state.nodes.get(&rt.node_id).map(|m| m.status);
    match my_status {
        Some(NodeStatus::Down) => {
            rt.backfill_caught_up.store(false, Ordering::Relaxed);
        }
        Some(NodeStatus::Recovering) if !rt.backfill_caught_up.load(Ordering::Relaxed) => {
            match rt.distributed.backfill_pass().await {
                Ok(0) => {
                    rt.backfill_caught_up.store(true, Ordering::Relaxed);
                    tracing::info!("cluster maintenance: back-fill caught up; awaiting promotion");
                }
                Ok(n) => {
                    metrics::counter!(crate::observability::CLUSTER_BACKFILL_OBJECTS)
                        .increment(n as u64);
                    tracing::info!(fetched = n, "cluster maintenance: back-fill sweep");
                }
                Err(e) => tracing::warn!(error = %e, "cluster maintenance: back-fill sweep failed"),
            }
        }
        _ => {}
    }
}

/// Refresh the cluster gauges from this node's raft + control state. Called every
/// maintenance tick on every node so `/metrics` always reflects current topology.
async fn record_cluster_gauges(rt: &ClusterRuntime, state: &y2q_cluster::ControlState) {
    let raft_metrics = rt.controller.raft().metrics().borrow().clone();
    let term = raft_metrics.current_term;
    let last_applied = raft_metrics.last_applied.map(|l| l.index).unwrap_or(0);
    let is_leader = rt.controller.is_leader().await;
    metrics::gauge!(crate::observability::CLUSTER_RAFT_TERM).set(term as f64);
    metrics::gauge!(crate::observability::CLUSTER_RAFT_LAST_APPLIED).set(last_applied as f64);
    metrics::gauge!(crate::observability::CLUSTER_IS_LEADER).set(if is_leader { 1.0 } else { 0.0 });
    metrics::gauge!(crate::observability::CLUSTER_EPOCH).set(state.epoch as f64);
    metrics::gauge!(crate::observability::CLUSTER_ACTIVE_NODES)
        .set(state.active_nodes().len() as f64);
}

/// Drive one peer through the liveness state machine from a probe result. The
/// leader proposes the transition and re-splices on success.
async fn drive_peer_liveness(
    rt: &ClusterRuntime,
    id: u64,
    status: NodeStatus,
    probe: Result<HealthResp, y2q_cluster::TransportError>,
    failures: &mut BTreeMap<u64, u32>,
    threshold: u32,
) {
    match (status, probe) {
        // Reachable Active peer: clear its failure count.
        (NodeStatus::Active, Ok(_)) => {
            failures.remove(&id);
        }
        // Unreachable Active/Recovering peer: count toward marking it Down.
        (NodeStatus::Active | NodeStatus::Recovering, Err(_)) => {
            let n = failures.entry(id).or_insert(0);
            *n += 1;
            if *n >= threshold && set_status_resplice(rt, id, NodeStatus::Down).await {
                failures.remove(&id);
            }
        }
        // A Down peer that answers again starts recovering.
        (NodeStatus::Down, Ok(_)) => {
            failures.remove(&id);
            set_status_resplice(rt, id, NodeStatus::Recovering).await;
        }
        // A Recovering peer that reports it has caught up is promoted to Active.
        (NodeStatus::Recovering, Ok(h)) if h.caught_up => {
            set_status_resplice(rt, id, NodeStatus::Active).await;
        }
        _ => {}
    }
}

/// Propose `SetNodeStatus(id, status)` and re-splice on success. Returns whether
/// the proposal applied.
async fn set_status_resplice(rt: &ClusterRuntime, id: u64, status: NodeStatus) -> bool {
    tracing::info!(peer = id, ?status, "cluster maintenance: status transition");
    match rt
        .controller
        .propose(ControlCmd::SetNodeStatus {
            node_id: id,
            status,
        })
        .await
    {
        Ok(_) => {
            if let Err(e) = rt.controller.resplice_now().await {
                tracing::warn!(error = %e, "cluster maintenance: resplice after status change failed");
            }
            true
        }
        Err(e) => {
            tracing::warn!(error = %e, peer = id, ?status, "cluster maintenance: SetNodeStatus failed");
            false
        }
    }
}

/// Unwrap the deployment SK from the configured `unlock_user`'s record using the
/// provisioned secret, derive the MEK, and install it for the process lifetime.
fn provision_mek(auth_state: &AuthState, cfg: &Config) -> std::io::Result<()> {
    let secret = read_unlock_secret(cfg)?;
    let record = auth_state
        .user_store
        .get(&cfg.cluster.unlock_user)
        .map_err(|e| std::io::Error::other(format!("read unlock user: {e}")))?
        .ok_or_else(|| {
            std::io::Error::other(format!(
                "cluster.unlock_user {:?} not found in the user store",
                cfg.cluster.unlock_user
            ))
        })?;

    let sk = Zeroizing::new(
        kdf::unwrap_sk(&record.wrapped_sk, secret.as_bytes(), &record.kdf).map_err(|_| {
            std::io::Error::other(
                "cluster provisioned unlock failed: wrong secret for cluster.unlock_user",
            )
        })?,
    );
    auth_state.install_mek_from_sk(sk.as_slice());
    tracing::info!(
        user = %cfg.cluster.unlock_user,
        "cluster: MEK provisioned at boot (idle-drop disabled while clustered)"
    );
    Ok(())
}

/// Read the provisioned unlock secret from the env var (preferred) or the file.
fn read_unlock_secret(cfg: &Config) -> std::io::Result<Zeroizing<String>> {
    if let Ok(s) = std::env::var("Y2QD_CLUSTER__UNLOCK_SECRET") {
        return Ok(Zeroizing::new(s));
    }
    let path = cfg.cluster.unlock_secret_file.trim();
    if path.is_empty() {
        return Err(std::io::Error::other(
            "cluster provisioned unlock requires Y2QD_CLUSTER__UNLOCK_SECRET or cluster.unlock_secret_file",
        ));
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| std::io::Error::other(format!("read unlock_secret_file {path}: {e}")))?;
    Ok(Zeroizing::new(
        raw.trim_end_matches(['\n', '\r']).to_string(),
    ))
}

/// Initialize a single-node cluster on the bootstrap node, then spawn a task
/// that registers this node, admits the configured peers (verifying each one's
/// deployment-key fingerprint), and promotes the voter set.
async fn bootstrap(
    controller: &Arc<Controller>,
    client: &Arc<InternalClient>,
    cfg: &Config,
    node_id: u64,
    fingerprint: String,
) {
    let self_url = node_base_url(cfg);
    match controller
        .initialize(BTreeMap::from([(
            node_id,
            BasicNode::new(self_url.clone()),
        )]))
        .await
    {
        Ok(()) => tracing::info!(node_id, "cluster initialized (single-node)"),
        // Already-initialized is fine on restart.
        Err(e) => tracing::info!(error = %e, "cluster initialize skipped (already initialized?)"),
    }

    let controller = Arc::clone(controller);
    let client = Arc::clone(client);
    let peers = cfg.cluster.peers.clone();
    let voter_seeds: BTreeSet<u64> = cfg.cluster.raft.voter_seeds.iter().copied().collect();
    tokio::spawn(async move {
        // Register self in the control state so routing sees this node and its
        // fingerprint. Retry until this node has won leadership (propose only
        // succeeds on the leader).
        loop {
            match controller
                .propose(ControlCmd::AddNode {
                    node_id,
                    addr: self_url.clone(),
                    fingerprint: fingerprint.clone(),
                })
                .await
            {
                Ok(_) => {
                    tracing::info!(node_id, "registered self in cluster control state");
                    break;
                }
                Err(e) => {
                    tracing::debug!(error = %e, "self AddNode not yet applied (awaiting leadership)");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }

        // Admit each peer: verify its attested fingerprint, then add it as a
        // learner and record it in the control state. Retry until reachable.
        for peer in &peers {
            loop {
                match verify_and_admit(&controller, &client, &fingerprint, peer.id, &peer.url).await
                {
                    Ok(()) => {
                        tracing::info!(peer = peer.id, url = %peer.url, "admitted cluster peer");
                        break;
                    }
                    Err(AdmitError::Fingerprint { expected, actual }) => {
                        // A keystore mismatch is not transient: refuse and stop
                        // retrying this peer (it would silently diverge).
                        tracing::error!(
                            peer = peer.id, url = %peer.url, %expected, %actual,
                            "REFUSING cluster peer: deployment-key fingerprint mismatch"
                        );
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(peer = peer.id, error = %e, "admit failed; retrying");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }

        // Promote the voting quorum (always including self when a set is given).
        if !voter_seeds.is_empty() {
            let mut voters = voter_seeds.clone();
            voters.insert(node_id);
            match controller.change_membership(voters).await {
                Ok(()) => tracing::info!("cluster voting membership applied"),
                Err(e) => tracing::warn!(error = %e, "change_membership failed"),
            }
        }
    });
}

/// Failure reasons when the leader tries to admit a candidate node.
#[derive(thiserror::Error, Debug)]
enum AdmitError {
    /// The candidate could not be probed for its identity.
    #[error("probe {url}: {error}")]
    Probe {
        /// Candidate base URL.
        url: String,
        /// Underlying transport error.
        error: String,
    },
    /// The candidate attested a different deployment-key fingerprint, so it does
    /// not share the cluster's key hierarchy (the shared-MEK invariant). Admitting
    /// it would make it store data no one else can read and serve reads no one
    /// else wrote.
    #[error("fingerprint mismatch (expected {expected}, got {actual})")]
    Fingerprint {
        /// This cluster's deployment-key fingerprint.
        expected: String,
        /// The fingerprint the candidate attested.
        actual: String,
    },
    /// The raft membership change failed.
    #[error("raft: {0}")]
    Raft(String),
}

/// Admit a candidate into the cluster: probe its `/internal/v1/health` over the
/// authenticated peer channel, reject it unless it attests this cluster's
/// deployment-key fingerprint, then add it as a learner and record it (with its
/// fingerprint and URL) in the replicated control state.
///
/// The fingerprint is attested by the candidate over the shared-secret/mTLS
/// channel; it primarily catches an operator pointing a node at the wrong
/// keystore. It is not a substitute for the peer-auth credential, and a peer that
/// already holds the credential could attest a fingerprint it does not truly
/// possess — but without the matching secret key it still cannot decrypt or
/// commit, so it self-excludes functionally.
async fn verify_and_admit(
    controller: &Controller,
    client: &InternalClient,
    expected_fp: &str,
    id: u64,
    url: &str,
) -> Result<(), AdmitError> {
    let health: HealthResp = client
        .get_json(&format!("{url}/internal/v1/health"))
        .await
        .map_err(|e| AdmitError::Probe {
            url: url.to_string(),
            error: e.to_string(),
        })?;

    if health.fingerprint != expected_fp {
        return Err(AdmitError::Fingerprint {
            expected: expected_fp.to_string(),
            actual: health.fingerprint,
        });
    }

    controller
        .add_learner(id, BasicNode::new(url.to_string()))
        .await
        .map_err(|e| AdmitError::Raft(e.to_string()))?;
    controller
        .propose(ControlCmd::AddNode {
            node_id: id,
            addr: url.to_string(),
            fingerprint: health.fingerprint,
        })
        .await
        .map_err(|e| AdmitError::Raft(e.to_string()))?;
    Ok(())
}

/// The base URL this node advertises (`scheme://advertise_addr`).
fn node_base_url(cfg: &Config) -> String {
    let scheme = if cfg.server.tls.enabled {
        "https"
    } else {
        "http"
    };
    format!("{scheme}://{}", cfg.cluster.advertise_addr)
}

/// Directory for the raft log + persisted node id.
fn raft_dir(cfg: &Config) -> PathBuf {
    let configured = cfg.cluster.raft.log_dir.trim();
    if configured.is_empty() {
        PathBuf::from(format!("{}/_y2q_raft", cfg.storage.base_path))
    } else {
        PathBuf::from(configured)
    }
}

/// The shared secret (env preferred), or `None` when using mTLS.
fn cluster_shared_secret(cfg: &Config) -> Option<String> {
    if cfg.cluster.auth != ClusterAuth::SharedSecret {
        return None;
    }
    std::env::var("Y2QD_CLUSTER__SHARED_SECRET")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let s = cfg.cluster.shared_secret.trim();
            (!s.is_empty()).then(|| s.to_string())
        })
}

/// Build the internal client's TLS options from the server TLS config: trust the
/// cluster CA when provided, present the server cert/key as the client identity
/// under mTLS, and fall back to insecure verification for plaintext/dev setups.
fn internal_tls_options(cfg: &Config) -> std::io::Result<InternalTlsOptions> {
    let tls = &cfg.server.tls;
    let ca_cert_pem = match tls.client_ca_path.as_deref() {
        Some(p) => Some(
            std::fs::read(p)
                .map_err(|e| std::io::Error::other(format!("read cluster CA {p}: {e}")))?,
        ),
        None => None,
    };

    let client_identity_pem = if cfg.cluster.auth == ClusterAuth::Mtls {
        match (tls.cert_path.as_deref(), tls.key_path.as_deref()) {
            (Some(cert), Some(key)) => {
                let mut pem = std::fs::read(cert)
                    .map_err(|e| std::io::Error::other(format!("read cert {cert}: {e}")))?;
                let mut key_pem = std::fs::read(key)
                    .map_err(|e| std::io::Error::other(format!("read key {key}: {e}")))?;
                pem.push(b'\n');
                pem.append(&mut key_pem);
                Some(Zeroizing::new(pem))
            }
            _ => {
                return Err(std::io::Error::other(
                    "cluster.auth = mtls requires server.tls.cert_path and key_path for the client identity",
                ));
            }
        }
    } else {
        None
    };

    Ok(InternalTlsOptions {
        // Without a CA to anchor trust (and not mTLS), accept the peer cert so a
        // TLS-enabled cluster works out of the box; set client_ca_path to verify.
        insecure: ca_cert_pem.is_none() && cfg.cluster.auth != ClusterAuth::Mtls,
        ca_cert_pem,
        client_identity_pem,
    })
}

// ---------------------------------------------------------------------------
// Distributed write path
// ---------------------------------------------------------------------------

/// Window size for streaming a committed envelope to the next chain member.
const REPLICATE_WINDOW: u64 = 4 << 20;

/// Run the CRAQ HEAD write, timing the full-chain commit. Returns whether an
/// existing object was overwritten. The HEAD is where the whole chain's commit
/// latency is observable, so it records [`CLUSTER_COMMIT_DURATION`].
///
/// [`CLUSTER_COMMIT_DURATION`]: crate::observability::CLUSTER_COMMIT_DURATION
pub async fn head_write(
    rt: &ClusterRuntime,
    bucket: &str,
    key: &str,
    payload: web::Payload,
    labels: LabelSet,
    sync: SyncLevel,
    chunk_size: usize,
) -> Result<bool, AppError> {
    let started = std::time::Instant::now();
    let res = head_write_inner(rt, bucket, key, payload, labels, sync, chunk_size).await;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;
    let result = if res.is_ok() { "ok" } else { "err" };
    metrics::histogram!(crate::observability::CLUSTER_COMMIT_DURATION, "result" => result)
        .record(elapsed_ms);
    res
}

/// The CRAQ HEAD write: encrypt the plaintext once into a local `.tmp`,
/// replicate the staged envelope down the chain, and commit locally **only
/// after** the downstream sub-chain has committed.
///
/// TAIL-first ordering: the TAIL is the commit point. The key is marked dirty
/// for the whole replicate-then-commit window so a concurrent strong read here
/// version-queries the TAIL rather than serving the still-old `.obj`; and a
/// downstream failure aborts the write (the `.tmp` is dropped, nothing renamed)
/// instead of committing an under-replicated copy — no torn or dirty reads.
#[tracing::instrument(skip_all, name = "cluster.commit", fields(bucket = %bucket, key = %key))]
async fn head_write_inner(
    rt: &ClusterRuntime,
    bucket: &str,
    key: &str,
    payload: web::Payload,
    labels: LabelSet,
    sync: SyncLevel,
    chunk_size: usize,
) -> Result<bool, AppError> {
    let local = rt.distributed.local();

    // Assign the next CRAQ version from this HEAD's committed copy (clean v0 when
    // the key is new or predates versioning). The chain order, not this counter,
    // is what makes CRAQ correct; the counter lets reads compare copies.
    let prior_version = local
        .describe(bucket, key)
        .await
        .ok()
        .and_then(|m| m.version)
        .unwrap_or(0);
    let version = prior_version + 1;

    let (guard, sink, write_offset) = local
        .begin_streaming_put(bucket, key)
        .await
        .map_err(AppError::from)?;
    let (sink, pm, cm) = cipher::stream_encrypt_for_put(
        &rt.public_key,
        payload,
        sink,
        bucket,
        key,
        write_offset,
        chunk_size,
    )
    .await?;

    // Metadata the replicas persist. The padded v2 `plaintext_len` at envelope
    // offset 20 is `padme_len(plaintext_size)` (what `EncryptSession::finish`
    // patched), so derive it directly instead of reading the staged bytes back.
    let label_vec: Vec<(String, String)> = labels.iter().cloned().collect();
    let plaintext_size = pm.size;
    let cipher_size = cm.cipher_size;
    let plaintext_len = envelope::padme_len(plaintext_size);

    let route = rt.distributed.route(bucket, key).await;
    let meta = PrepareMeta {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        chain_id: chain_id(bucket, key),
        epoch: route.epoch,
        version,
        plaintext_len,
        plaintext_size,
        checksum_gxhash_b64: pm.checksum_gxhash_b64.clone(),
        cipher_size,
        cipher_sha256_b64: cm.cipher_sha256_b64.clone(),
        kem_alg: cm.kem_alg.clone(),
        aead_alg: cm.aead_alg.clone(),
        envelope_version: cm.envelope_version,
        sync_durable: sync == SyncLevel::Durable,
        labels: label_vec,
    };

    // Mark dirty for the tail-first window: until the local commit below, the
    // committed `.obj` still holds the prior version, so a concurrent strong read
    // must version-query the TAIL rather than serve it.
    let _pending = rt.distributed.pending().begin(bucket, key, route.epoch);

    // Replicate the STAGED envelope to the rest of the chain and await the full
    // downstream commit (no-op `Ok(None)` for a solo chain). Stream it in bounded
    // windows read from the uncommitted `.tmp` so large objects do not buffer
    // whole.
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(8);
    let feeder = stream_staged_windows(&guard, write_offset, cipher_size, tx);
    let forward = rt.distributed.forward_to_next(&meta, rx);
    let (feed_res, fwd_res) = tokio::join!(feeder, forward);
    feed_res?;
    fwd_res.map_err(|e| {
        AppError(y2q_core::Error::InternalError {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            operation: "replicate".to_owned(),
            message: e.to_string(),
        })
    })?;

    // Downstream committed: now promote this HEAD's copy (the commit point has
    // already passed at the TAIL, so the HEAD is last, as CRAQ prescribes).
    let overwrite = guard
        .commit(
            sink,
            PutOptions {
                labels,
                sync,
                version: Some(version),
                ..Default::default()
            },
            pm,
            cm,
        )
        .await
        .map_err(AppError::from)?;

    Ok(overwrite)
}

/// Stream a staged (uncommitted) object's envelope to `tx` in bounded windows,
/// read from the HEAD's `.tmp` before commit. `write_offset` is the file offset
/// at which the envelope begins (the 64-byte container header precedes it).
async fn stream_staged_windows(
    guard: &AnyStreamingPutGuard,
    write_offset: u64,
    cipher_size: u64,
    tx: tokio::sync::mpsc::Sender<Bytes>,
) -> Result<(), AppError> {
    let mut off = 0u64;
    while off < cipher_size {
        let len = REPLICATE_WINDOW.min(cipher_size - off);
        let window = guard
            .read_staged_range(write_offset + off, len)
            .await
            .map_err(AppError::from)?;
        off += len;
        if tx.send(window).await.is_err() {
            break; // forward task ended (downstream error)
        }
    }
    Ok(())
}

/// Header carrying the JSON [`InternalPutMeta`] on a contact-node → HEAD plaintext
/// forward.
const CLUSTER_PUT_HEADER: &str = "X-Y2Q-Cluster-Put";

/// Metadata for a peer-forwarded plaintext PUT (contact node is not the HEAD).
#[derive(Debug, Serialize, Deserialize)]
struct InternalPutMeta {
    bucket: String,
    key: String,
    labels: Vec<(String, String)>,
    sync_durable: bool,
}

/// Response body of the internal plaintext PUT.
#[derive(Debug, Serialize, Deserialize)]
struct PutResp {
    overwrite: bool,
}

/// Proxy a client PUT's plaintext to the chain HEAD over the authenticated peer
/// channel (used when the contact node is not the HEAD). The HEAD encrypts,
/// commits, and replicates; this returns its overwrite verdict.
pub async fn proxy_put_to_head(
    rt: &ClusterRuntime,
    head_url: &str,
    bucket: &str,
    key: &str,
    mut payload: web::Payload,
    labels: &LabelSet,
    sync: SyncLevel,
) -> Result<bool, AppError> {
    let meta = InternalPutMeta {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        labels: labels.iter().cloned().collect(),
        sync_durable: sync == SyncLevel::Durable,
    };
    let meta_json = serde_json::to_string(&meta).map_err(|e| internal_err(bucket, key, e))?;

    // Drain the client body into a channel so the cluster transport (which owns
    // the reqwest dependency) can stream it to the HEAD without buffering.
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(8);
    let feeder = async {
        use futures::StreamExt as _;
        let mut result = Ok::<(), AppError>(());
        while let Some(chunk) = payload.next().await {
            match chunk {
                Ok(chunk) => {
                    if tx.send(chunk).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    result = Err(internal_err(bucket, key, e));
                    break;
                }
            }
        }
        // See the matching note in `prepare`: drop the sender so the relayed body
        // reaches EOF; `tokio::join!` otherwise keeps `tx` alive until the joined
        // send future finishes, which deadlocks against the HEAD awaiting the body.
        drop(tx);
        result
    };
    let url = format!("{head_url}/internal/v1/put");
    let headers = [(CLUSTER_PUT_HEADER, meta_json)];
    let send = rt.client.post_stream_rx::<PutResp>(&url, &headers, rx);
    let (feed_res, send_res) = tokio::join!(feeder, send);
    feed_res?;
    let resp = send_res.map_err(|e| internal_err(bucket, key, e))?;
    Ok(resp.overwrite)
}

/// Build a generic 500 `AppError` for a cluster write failure.
fn internal_err(bucket: &str, key: &str, e: impl std::fmt::Display) -> AppError {
    AppError(y2q_core::Error::InternalError {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        operation: "cluster put".to_owned(),
        message: e.to_string(),
    })
}

/// Map a data-plane error to an `AppError`, preserving a wrapped core error
/// (so e.g. `NotFound` from a label set on a missing object still becomes 404).
fn map_data_err(bucket: &str, key: &str, e: y2q_cluster::DataError) -> AppError {
    match e {
        y2q_cluster::DataError::Storage(core) => AppError(core),
        other => internal_err(bucket, key, other),
    }
}

/// Dispatch a chain mutation: apply+relay locally when this node is the HEAD,
/// otherwise forward it to the HEAD (which walks the chain).
async fn dispatch_mutate(
    rt: &ClusterRuntime,
    route: &ChainRoute,
    meta: MutateMeta,
) -> Result<MutateResp, AppError> {
    let bucket = meta.bucket.clone();
    let key = meta.key.clone();
    match route.role(rt.node_id) {
        Role::Head | Role::Solo => rt
            .distributed
            .accept_mutate(meta)
            .await
            .map_err(|e| map_data_err(&bucket, &key, e)),
        Role::Middle | Role::Tail | Role::NotInChain => {
            let head_id = route.head().ok_or_else(|| {
                internal_err(
                    &bucket,
                    &key,
                    "no chain head (cluster has no active members)",
                )
            })?;
            let head_url = rt.distributed.peer_url(head_id).await.ok_or_else(|| {
                internal_err(
                    &bucket,
                    &key,
                    format!("head node {head_id} has no known address"),
                )
            })?;
            rt.distributed
                .send_mutate(&head_url, &meta)
                .await
                .map_err(|e| map_data_err(&bucket, &key, e))
        }
    }
}

/// Route a DELETE through the chain. Returns whether the object existed.
pub async fn chain_delete(rt: &ClusterRuntime, bucket: &str, key: &str) -> Result<bool, AppError> {
    let route = rt.distributed.route(bucket, key).await;
    let meta = MutateMeta {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        chain_id: chain_id(bucket, key),
        epoch: route.epoch,
        op: MutateOp::Delete,
    };
    Ok(dispatch_mutate(rt, &route, meta).await?.existed)
}

/// Decide how to serve an apportioned read of `(bucket, key)` under the
/// configured consistency mode: serve the local committed copy, or fetch the
/// committed envelope from the chain TAIL ([`ReadPlan::Remote`]).
pub async fn plan_read(rt: &ClusterRuntime, bucket: &str, key: &str) -> Result<ReadPlan, AppError> {
    rt.distributed
        .plan_read(bucket, key, rt.read_consistency)
        .await
        .map_err(|e| map_data_err(bucket, key, e))
}

/// Scatter-gather a list (`query = None`) or label search across every Active
/// node, returning the merged, deduped page. `bucket` is `Some` for a
/// single-bucket list/search and `None` for a cross-bucket search.
pub async fn scatter_list(
    rt: &ClusterRuntime,
    bucket: Option<&str>,
    query: Option<&str>,
    opts: &y2q_core::ListOptions,
) -> Result<y2q_core::ListPage, AppError> {
    rt.distributed
        .scatter_list(bucket, query, opts)
        .await
        .map_err(|e| match e {
            y2q_cluster::DataError::Storage(core) => AppError(core),
            other => internal_err(bucket.unwrap_or(""), "", other),
        })
}

/// Route a label edit through the chain. The HEAD resolves `mode`/`incoming`
/// against its committed copy and applies the resolved set verbatim at every
/// member; the resolved set is returned for the HTTP response.
pub async fn chain_edit_labels(
    rt: &ClusterRuntime,
    bucket: &str,
    key: &str,
    mode: LabelMode,
    incoming: Vec<(String, String)>,
) -> Result<LabelSet, AppError> {
    let route = rt.distributed.route(bucket, key).await;
    let meta = MutateMeta {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        chain_id: chain_id(bucket, key),
        epoch: route.epoch,
        op: MutateOp::EditLabels { mode, incoming },
    };
    let resp = dispatch_mutate(rt, &route, meta).await?;
    Ok(resp.labels.into_iter().collect())
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

/// Register the cluster routes. Must be configured BEFORE `handlers::configure`
/// so the specific paths win over the greedy `/{bucket}/{tail}*` route.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/internal/v1/raft/append").route(web::post().to(raft_append)));
    cfg.service(web::resource("/internal/v1/raft/vote").route(web::post().to(raft_vote)));
    cfg.service(web::resource("/internal/v1/raft/snapshot").route(web::post().to(raft_snapshot)));
    cfg.service(web::resource("/internal/v1/prepare").route(web::post().to(prepare)));
    cfg.service(web::resource("/internal/v1/put").route(web::post().to(internal_put)));
    cfg.service(web::resource("/internal/v1/mutate").route(web::post().to(mutate)));
    cfg.service(web::resource("/internal/v1/version").route(web::get().to(version)));
    cfg.service(web::resource("/internal/v1/read").route(web::get().to(internal_read)));
    cfg.service(web::resource("/internal/v1/list").route(web::get().to(internal_list)));
    cfg.service(
        web::resource("/internal/v1/backfill/manifest").route(web::get().to(backfill_manifest)),
    );
    cfg.service(
        web::resource("/internal/v1/backfill/object").route(web::get().to(backfill_object)),
    );
    cfg.service(web::resource("/internal/v1/health").route(web::get().to(health)));
    cfg.service(web::resource("/api/v1/cluster/status").route(web::get().to(status)));
    cfg.service(web::resource("/api/v1/cluster/join").route(web::post().to(join)));
}

async fn raft_append(
    rt: web::Data<ClusterRuntime>,
    _peer: ClusterPeer,
    body: web::Json<AppendEntriesRequest<TypeConfig>>,
) -> HttpResponse {
    let res = rt.controller.raft().append_entries(body.into_inner()).await;
    HttpResponse::Ok().json(res)
}

async fn raft_vote(
    rt: web::Data<ClusterRuntime>,
    _peer: ClusterPeer,
    body: web::Json<VoteRequest<u64>>,
) -> HttpResponse {
    let res = rt.controller.raft().vote(body.into_inner()).await;
    HttpResponse::Ok().json(res)
}

async fn raft_snapshot(
    rt: web::Data<ClusterRuntime>,
    _peer: ClusterPeer,
    body: web::Json<InstallSnapshotRequest<TypeConfig>>,
) -> HttpResponse {
    let res = rt
        .controller
        .raft()
        .install_snapshot(body.into_inner())
        .await;
    HttpResponse::Ok().json(res)
}

/// Whether a message stamped with `msg_epoch` is stale relative to the
/// receiver's `committed` epoch. Strictly-older messages were routed under a
/// superseded topology and must be rejected; equal or newer are accepted (a
/// newer epoch means this node is merely lagging the raft log).
fn epoch_is_stale(msg_epoch: u64, committed: u64) -> bool {
    msg_epoch < committed
}

/// Reject a peer write whose epoch predates this node's committed epoch (the
/// stale-topology fence). Returns `409 STALE_EPOCH` and bumps the rejection
/// metric; the sender should re-resolve the route and retry.
async fn fence_epoch(rt: &ClusterRuntime, msg_epoch: u64) -> Result<(), actix_web::Error> {
    let committed = rt.controller.control_state().await.epoch;
    if epoch_is_stale(msg_epoch, committed) {
        metrics::counter!(crate::observability::CLUSTER_STALE_EPOCH_REJECTIONS).increment(1);
        return Err(actix_web::error::ErrorConflict(format!(
            "STALE_EPOCH: message epoch {msg_epoch} < committed {committed}"
        )));
    }
    Ok(())
}

/// Receive a CRAQ PREPARE: stream the ciphertext envelope from the request body
/// into the data plane, which writes it locally, relays it down-chain, and
/// commits once the downstream sub-chain commits. The `X-Y2Q-Prepare` header
/// carries the [`PrepareMeta`] the replica persists alongside the bytes.
#[tracing::instrument(skip_all, name = "cluster.prepare")]
async fn prepare(
    rt: web::Data<ClusterRuntime>,
    _peer: ClusterPeer,
    req: HttpRequest,
    mut payload: web::Payload,
) -> Result<HttpResponse, actix_web::Error> {
    let meta_raw = req
        .headers()
        .get(PREPARE_META_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ErrorBadRequest("missing X-Y2Q-Prepare header"))?;
    let meta: PrepareMeta = serde_json::from_str(meta_raw)
        .map_err(|e| ErrorBadRequest(format!("bad prepare meta: {e}")))?;

    // Epoch fence: reject a PREPARE routed under a superseded topology before
    // staging anything locally.
    fence_epoch(&rt, meta.epoch).await?;

    // Drain the request body into a bounded channel the data plane consumes, so
    // the envelope streams through without being buffered whole.
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(8);
    let feeder = async {
        use futures::StreamExt as _;
        let mut result = Ok::<(), actix_web::Error>(());
        while let Some(chunk) = payload.next().await {
            match chunk {
                Ok(chunk) => {
                    if tx.send(chunk).await.is_err() {
                        break; // receiver gone (accept_prepare returned early)
                    }
                }
                Err(e) => {
                    result = Err(ErrorBadRequest(format!("read body: {e}")));
                    break;
                }
            }
        }
        // Drop the sender so the data plane's body channel reaches end-of-stream.
        // `tokio::join!` keeps this (completed) future — and thus its captured
        // `tx` — alive until the joined `accept` future also finishes, so without
        // this explicit drop the receiver would block forever waiting for a close
        // that only happens when the whole handler returns. That is a deadlock:
        // `accept` cannot finish because it is still awaiting the body.
        drop(tx);
        result
    };
    let accept = rt.distributed.accept_prepare(meta, rx);

    let started = std::time::Instant::now();
    let (feed_res, accept_res) = tokio::join!(feeder, accept);
    let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;
    let result = if feed_res.is_ok() && accept_res.is_ok() {
        "ok"
    } else {
        "err"
    };
    metrics::histogram!(crate::observability::CLUSTER_PREPARE_HOP_DURATION, "result" => result)
        .record(elapsed_ms);
    feed_res?;
    let resp = accept_res.map_err(|e| ErrorBadGateway(format!("prepare: {e}")))?;
    Ok(HttpResponse::Ok().json(resp))
}

/// Receive a peer-forwarded plaintext PUT (the contact node was not the HEAD).
/// This node is the HEAD: encrypt, commit, and replicate down the chain.
async fn internal_put(
    rt: web::Data<ClusterRuntime>,
    _peer: ClusterPeer,
    req: HttpRequest,
    payload: web::Payload,
    encryption: web::Data<crate::config::EncryptionParams>,
) -> Result<HttpResponse, actix_web::Error> {
    let raw = req
        .headers()
        .get(CLUSTER_PUT_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ErrorBadRequest("missing X-Y2Q-Cluster-Put header"))?;
    let m: InternalPutMeta =
        serde_json::from_str(raw).map_err(|e| ErrorBadRequest(format!("bad put meta: {e}")))?;
    let labels: LabelSet = m.labels.into_iter().collect();
    let sync = if m.sync_durable {
        SyncLevel::Durable
    } else {
        SyncLevel::BestEffort
    };
    let overwrite = head_write(
        &rt,
        &m.bucket,
        &m.key,
        payload,
        labels,
        sync,
        encryption.chunk_size_bytes,
    )
    .await?;
    Ok(HttpResponse::Ok().json(PutResp { overwrite }))
}

/// Receive a chain mutation (DELETE / set-labels): apply it locally and relay it
/// to the next chain member.
async fn mutate(
    rt: web::Data<ClusterRuntime>,
    _peer: ClusterPeer,
    body: web::Json<MutateMeta>,
) -> Result<HttpResponse, actix_web::Error> {
    let meta = body.into_inner();
    // Epoch fence: reject a mutation routed under a superseded topology.
    fence_epoch(&rt, meta.epoch).await?;
    let resp = rt
        .distributed
        .accept_mutate(meta)
        .await
        .map_err(|e| ErrorBadGateway(format!("mutate: {e}")))?;
    Ok(HttpResponse::Ok().json(resp))
}

/// Query params for [`version`].
#[derive(Debug, Deserialize)]
struct VersionParams {
    /// Target bucket.
    bucket: String,
    /// Target key.
    key: String,
}

/// Answer a CRAQ version query with this node's locally-committed version for
/// `(bucket, key)`. The data-plane read path directs these at the chain TAIL,
/// whose committed version is authoritative (the CRAQ commit point).
#[tracing::instrument(skip_all, name = "cluster.version_query")]
async fn version(
    rt: web::Data<ClusterRuntime>,
    _peer: ClusterPeer,
    q: web::Query<VersionParams>,
) -> HttpResponse {
    metrics::counter!(crate::observability::CLUSTER_VERSION_QUERIES).increment(1);
    let version = rt
        .distributed
        .local_committed_version(&q.bucket, &q.key)
        .await;
    HttpResponse::Ok().json(VersionResp { version })
}

/// Serve this node's committed ciphertext envelope for `(bucket, key)` to a peer
/// (the apportioned read fetch). The envelope is returned verbatim — the peer
/// decrypts it with the user keystore (this node dropped the deployment SK after
/// deriving the MEK). The `X-Y2Q-Size` header carries the true plaintext size
/// for the caller's padding trim.
async fn internal_read(
    rt: web::Data<ClusterRuntime>,
    _peer: ClusterPeer,
    q: web::Query<VersionParams>,
) -> Result<HttpResponse, actix_web::Error> {
    let local = rt.distributed.local();
    let object = local.get(&q.bucket, &q.key).await.map_err(|e| match e {
        y2q_core::Error::NotFound { .. } => actix_web::error::ErrorNotFound(e.to_string()),
        other => actix_web::error::ErrorBadGateway(other.to_string()),
    })?;
    let size = local
        .describe(&q.bucket, &q.key)
        .await
        .map(|m| m.size)
        .unwrap_or(0);
    Ok(HttpResponse::Ok()
        .insert_header(("X-Y2Q-Size", size.to_string()))
        .content_type("application/octet-stream")
        .body(object.into_inner()))
}

/// Query params for the internal scatter-gather list/search endpoint.
#[derive(Debug, Deserialize)]
struct InternalListParams {
    /// Bucket to list/search; omit for a cross-bucket search.
    bucket: Option<String>,
    /// Raw label-query expression; omit for a plain prefix list.
    #[serde(rename = "q")]
    query: Option<String>,
    /// Key prefix filter.
    prefix: Option<String>,
    /// Continuation cursor (key, or `bucket\0key` composite cross-bucket).
    after: Option<String>,
    /// Page size cap.
    limit: Option<usize>,
}

/// Serve this node's *local* list/search page for a scatter-gather. The contact
/// node merges these per-node pages, dedups by `(bucket, key)`, and enforces user
/// authorization; this endpoint trusts the peer and returns raw local metadata.
async fn internal_list(
    rt: web::Data<ClusterRuntime>,
    _peer: ClusterPeer,
    q: web::Query<InternalListParams>,
) -> Result<HttpResponse, actix_web::Error> {
    let q = q.into_inner();
    let opts = ListOptions {
        prefix: q.prefix,
        after: q.after,
        limit: q.limit.map(|n| n.min(MAX_LIST_LIMIT)),
    };
    let local = rt.distributed.local();
    let page = match (q.bucket.as_deref(), q.query.as_deref()) {
        (Some(b), None) => local.list_objects(b, opts).await,
        (b, Some(qstr)) => {
            let parsed =
                y2q_core::LabelQuery::parse(qstr).map_err(|e| ErrorBadRequest(e.to_string()))?;
            local.search_objects(&parsed, b, opts).await
        }
        (None, None) => {
            return Err(ErrorBadRequest("list requires a bucket or a label query"));
        }
    }
    .map_err(|e| ErrorBadGateway(e.to_string()))?;
    Ok(HttpResponse::Ok().json(page))
}

/// Serve this node's backfill manifest (every object it holds) to a recovering
/// peer, which diffs it against its own copies.
async fn backfill_manifest(
    rt: web::Data<ClusterRuntime>,
    _peer: ClusterPeer,
) -> Result<HttpResponse, actix_web::Error> {
    let manifest = rt
        .distributed
        .local_manifest()
        .await
        .map_err(|e| ErrorBadGateway(format!("manifest: {e}")))?;
    Ok(HttpResponse::Ok().json(manifest))
}

/// Serve a single committed envelope to a recovering peer, with the
/// [`BackfillObjectMeta`] needed to commit a byte-identical replica carried in
/// the `X-Y2Q-Backfill` header.
async fn backfill_object(
    rt: web::Data<ClusterRuntime>,
    _peer: ClusterPeer,
    q: web::Query<VersionParams>,
) -> Result<HttpResponse, actix_web::Error> {
    let local = rt.distributed.local();
    let md = local
        .describe(&q.bucket, &q.key)
        .await
        .map_err(|e| match e {
            y2q_core::Error::NotFound { .. } => actix_web::error::ErrorNotFound(e.to_string()),
            other => ErrorBadGateway(other.to_string()),
        })?;
    let object = local
        .get(&q.bucket, &q.key)
        .await
        .map_err(|e| ErrorBadGateway(e.to_string()))?;
    let meta = BackfillObjectMeta {
        version: md.version.unwrap_or(0),
        plaintext_len: envelope::padme_len(md.size),
        plaintext_size: md.size,
        checksum_gxhash_b64: md.checksum_gxhash,
        cipher_size: md.cipher_size.unwrap_or(0),
        cipher_sha256_b64: md.cipher_sha256.unwrap_or_default(),
        kem_alg: md.kem_alg.unwrap_or_default(),
        aead_alg: md.aead_alg.unwrap_or_default(),
        envelope_version: md.envelope_version.unwrap_or(2),
        labels: md.labels.into_iter().collect(),
    };
    let meta_json =
        serde_json::to_string(&meta).map_err(|e| ErrorBadGateway(format!("encode meta: {e}")))?;
    let envelope = object.into_inner();
    metrics::counter!(crate::observability::CLUSTER_BACKFILL_BYTES_SERVED)
        .increment(envelope.len() as u64);
    Ok(HttpResponse::Ok()
        .insert_header((BACKFILL_META_HEADER, meta_json))
        .content_type("application/octet-stream")
        .body(envelope))
}

/// Liveness + identity returned from `/internal/v1/health`. The `fingerprint`
/// lets the leader attest a candidate's deployment key before admitting it.
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResp {
    /// This node's id.
    pub node_id: u64,
    /// Committed global epoch.
    pub epoch: u64,
    /// Whether this node currently believes it is the leader.
    pub is_leader: bool,
    /// This node's deployment public-key fingerprint (SHA-256 hex).
    pub fingerprint: String,
    /// Whether this node has completed a clean back-fill sweep while
    /// `Recovering` (so the leader may promote it to `Active`). Always `false`
    /// for nodes that are not recovering.
    #[serde(default)]
    pub caught_up: bool,
}

/// Peer liveness + identity (used for admission fingerprint attestation, and by
/// the leader's maintenance loop to drive recovery promotion).
async fn health(rt: web::Data<ClusterRuntime>, _peer: ClusterPeer) -> HttpResponse {
    let epoch = rt.controller.control_state().await.epoch;
    let is_leader = rt.controller.is_leader().await;
    HttpResponse::Ok().json(HealthResp {
        node_id: rt.node_id,
        epoch,
        is_leader,
        fingerprint: rt.fingerprint.clone(),
        caught_up: rt.backfill_caught_up.load(Ordering::Relaxed),
    })
}

/// Operator-facing cluster status (admin).
async fn status(rt: web::Data<ClusterRuntime>, _auth: AdminAuthenticated) -> HttpResponse {
    let state = rt.controller.control_state().await;
    let is_leader = rt.controller.is_leader().await;
    HttpResponse::Ok().json(serde_json::json!({
        "node_id": rt.node_id,
        "is_leader": is_leader,
        "epoch": state.epoch,
        "nodes": state.nodes,
        "chains": state.chains.len(),
    }))
}

/// Request body for [`join`].
#[derive(Debug, Deserialize)]
pub struct JoinRequest {
    /// The joining node's id.
    pub id: u64,
    /// The joining node's base URL.
    pub url: String,
    /// Whether to promote it into the voting quorum.
    #[serde(default)]
    pub voter: bool,
}

/// Response body for [`join`].
#[derive(Debug, Serialize)]
pub struct JoinResponse {
    /// Whether the node was promoted to a voter.
    pub voter: bool,
}

/// Add a node to the cluster (admin). Runs on the leader: verifies the
/// candidate's deployment-key fingerprint, adds it as a learner, records it in
/// the control state, and (if `voter`) promotes it into the voting membership.
///
/// A fingerprint mismatch is rejected with 403 (the candidate does not share the
/// cluster's key hierarchy); transient probe/raft failures return 502.
async fn join(
    rt: web::Data<ClusterRuntime>,
    _auth: AdminAuthenticated,
    body: web::Json<JoinRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    let req = body.into_inner();
    verify_and_admit(
        &rt.controller,
        &rt.client,
        &rt.fingerprint,
        req.id,
        &req.url,
    )
    .await
    .map_err(|e| match e {
        AdmitError::Fingerprint { .. } => actix_web::error::ErrorForbidden(e.to_string()),
        _ => actix_web::error::ErrorBadGateway(e.to_string()),
    })?;

    if req.voter {
        // Extend the *current* voting quorum with the joiner rather than
        // promoting every active node, so the voter set stays bounded (the
        // voter/learner split). The leader is already a voter.
        let mut voters = rt.controller.current_voters();
        voters.insert(rt.node_id);
        voters.insert(req.id);
        rt.controller
            .change_membership(voters)
            .await
            .map_err(|e| actix_web::error::ErrorBadGateway(format!("change_membership: {e}")))?;
    }
    Ok(HttpResponse::Ok().json(JoinResponse { voter: req.voter }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stand-in mirroring `ClusterRuntime`'s auth fields, so the constant-time
    /// comparison is testable without constructing a live controller.
    struct AuthOnly {
        shared_secret: Option<Zeroizing<String>>,
        auth_mode: ClusterAuth,
    }
    impl AuthOnly {
        fn check(&self, provided: Option<&str>) -> bool {
            match self.auth_mode {
                ClusterAuth::Mtls => true,
                ClusterAuth::SharedSecret => match (provided, self.shared_secret.as_deref()) {
                    (Some(p), Some(expected)) => {
                        bool::from(p.as_bytes().ct_eq(expected.as_bytes()))
                    }
                    _ => false,
                },
            }
        }
    }

    #[test]
    fn shared_secret_matches_only_when_equal() {
        let a = AuthOnly {
            shared_secret: Some(Zeroizing::new("s3cret".to_string())),
            auth_mode: ClusterAuth::SharedSecret,
        };
        assert!(a.check(Some("s3cret")));
        assert!(!a.check(Some("wrong")));
        assert!(!a.check(None));
    }

    #[test]
    fn mtls_mode_trusts_connection() {
        let a = AuthOnly {
            shared_secret: None,
            auth_mode: ClusterAuth::Mtls,
        };
        assert!(a.check(None));
    }

    /// The health response (the admission attestation channel) round-trips so the
    /// leader can decode a candidate's fingerprint.
    #[test]
    fn health_resp_round_trips_with_fingerprint() {
        let h = HealthResp {
            node_id: 5,
            epoch: 9,
            is_leader: true,
            fingerprint: "deadbeef".to_string(),
            caught_up: false,
        };
        let bytes = serde_json::to_vec(&h).unwrap();
        let back: HealthResp = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.fingerprint, "deadbeef");
        assert_eq!(back.node_id, 5);
        assert!(back.is_leader);
    }

    /// Epoch fencing rejects strictly-older messages; equal or newer pass.
    #[test]
    fn epoch_fence_rejects_only_older() {
        assert!(epoch_is_stale(4, 5)); // stale: routed under an old topology
        assert!(!epoch_is_stale(5, 5)); // current
        assert!(!epoch_is_stale(6, 5)); // newer: this node is merely lagging
        assert!(!epoch_is_stale(0, 0));
    }

    /// A fingerprint mismatch renders an unambiguous, non-transient error so the
    /// admit path rejects (403) rather than retrying forever.
    #[test]
    fn fingerprint_mismatch_is_distinct_error() {
        let e = AdmitError::Fingerprint {
            expected: "aaaa".to_string(),
            actual: "bbbb".to_string(),
        };
        assert!(matches!(e, AdmitError::Fingerprint { .. }));
        assert!(e.to_string().contains("expected aaaa"));
        assert!(e.to_string().contains("got bbbb"));
    }
}
