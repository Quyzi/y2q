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
    ControlCmd, Controller, ControllerConfig, DistributedStorage, HttpRaftNetworkFactory,
    InternalClient, InternalTlsOptions, PREPARE_META_HEADER, PrepareMeta, resolve_node_id,
};
use y2q_core::AnyStorage;
use y2q_core::crypto::kdf;

use crate::auth::{AdminAuthenticated, AuthState};
use crate::config::{ClusterAuth, Config};

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
    /// This node's id.
    pub node_id: u64,
    /// Shared secret used to authenticate peer requests (when `auth_mode` is
    /// `shared-secret`).
    shared_secret: Option<Zeroizing<String>>,
    /// Peer authentication mode in effect.
    auth_mode: ClusterAuth,
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

    if cfg.cluster.raft.bootstrap {
        bootstrap(&controller, &client, cfg, node_id, fingerprint.clone()).await;
    }

    Ok(ClusterRuntime {
        controller,
        distributed,
        client,
        fingerprint,
        node_id,
        shared_secret: shared_secret.map(Zeroizing::new),
        auth_mode: cfg.cluster.auth,
    })
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
// HTTP handlers
// ---------------------------------------------------------------------------

/// Register the cluster routes. Must be configured BEFORE `handlers::configure`
/// so the specific paths win over the greedy `/{bucket}/{tail}*` route.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/internal/v1/raft/append").route(web::post().to(raft_append)));
    cfg.service(web::resource("/internal/v1/raft/vote").route(web::post().to(raft_vote)));
    cfg.service(web::resource("/internal/v1/raft/snapshot").route(web::post().to(raft_snapshot)));
    cfg.service(web::resource("/internal/v1/prepare").route(web::post().to(prepare)));
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

/// Receive a CRAQ PREPARE: stream the ciphertext envelope from the request body
/// into the data plane, which writes it locally, relays it down-chain, and
/// commits once the downstream sub-chain commits. The `X-Y2Q-Prepare` header
/// carries the [`PrepareMeta`] the replica persists alongside the bytes.
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

    // Drain the request body into a bounded channel the data plane consumes, so
    // the envelope streams through without being buffered whole.
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(8);
    let feeder = async {
        use futures::StreamExt as _;
        while let Some(chunk) = payload.next().await {
            let chunk = chunk.map_err(|e| ErrorBadRequest(format!("read body: {e}")))?;
            if tx.send(chunk).await.is_err() {
                break; // receiver gone (accept_prepare returned early with an error)
            }
        }
        Ok::<(), actix_web::Error>(())
    };
    let accept = rt.distributed.accept_prepare(meta, rx);

    let (feed_res, accept_res) = tokio::join!(feeder, accept);
    feed_res?;
    let resp = accept_res.map_err(|e| ErrorBadGateway(format!("prepare: {e}")))?;
    Ok(HttpResponse::Ok().json(resp))
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
}

/// Peer liveness + identity (used for admission fingerprint attestation).
async fn health(rt: web::Data<ClusterRuntime>, _peer: ClusterPeer) -> HttpResponse {
    let epoch = rt.controller.control_state().await.epoch;
    let is_leader = rt.controller.is_leader().await;
    HttpResponse::Ok().json(HealthResp {
        node_id: rt.node_id,
        epoch,
        is_leader,
        fingerprint: rt.fingerprint.clone(),
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
        let mut voters: BTreeSet<u64> = rt
            .controller
            .control_state()
            .await
            .active_nodes()
            .into_iter()
            .collect();
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
        };
        let bytes = serde_json::to_vec(&h).unwrap();
        let back: HealthResp = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.fingerprint, "deadbeef");
        assert_eq!(back.node_id, 5);
        assert!(back.is_leader);
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
