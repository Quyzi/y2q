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
    FromRequest, HttpRequest, HttpResponse, dev::Payload, error::ErrorUnauthorized, web,
};
use openraft::BasicNode;
use openraft::raft::{AppendEntriesRequest, InstallSnapshotRequest, VoteRequest};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use y2q_cluster::control::raft_impl::TypeConfig;
use y2q_cluster::transport::internal_client::CLUSTER_AUTH_HEADER;
use y2q_cluster::{
    Controller, ControllerConfig, HttpRaftNetworkFactory, InternalClient, InternalTlsOptions,
    resolve_node_id,
};
use y2q_core::crypto::kdf;

use crate::auth::{AdminAuthenticated, AuthState};
use crate::config::{ClusterAuth, Config};

/// Long-lived cluster runtime, shared with handlers via `web::Data`.
pub struct ClusterRuntime {
    /// The embedded raft controller.
    pub controller: Arc<Controller>,
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

    let factory = HttpRaftNetworkFactory::new(client);
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

    if cfg.cluster.raft.bootstrap {
        bootstrap(&controller, cfg, node_id).await;
    }

    Ok(ClusterRuntime {
        controller,
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
/// that adds the configured peers as learners and promotes the voter set.
async fn bootstrap(controller: &Arc<Controller>, cfg: &Config, node_id: u64) {
    let self_url = node_base_url(cfg);
    match controller
        .initialize(BTreeMap::from([(node_id, BasicNode::new(self_url))]))
        .await
    {
        Ok(()) => tracing::info!(node_id, "cluster initialized (single-node)"),
        // Already-initialized is fine on restart.
        Err(e) => tracing::info!(error = %e, "cluster initialize skipped (already initialized?)"),
    }

    let controller = Arc::clone(controller);
    let peers = cfg.cluster.peers.clone();
    let voter_seeds: BTreeSet<u64> = cfg.cluster.raft.voter_seeds.iter().copied().collect();
    tokio::spawn(async move {
        // Add each peer as a learner, retrying until it is reachable.
        for peer in &peers {
            loop {
                match controller
                    .add_learner(peer.id, BasicNode::new(peer.url.clone()))
                    .await
                {
                    Ok(()) => {
                        tracing::info!(peer = peer.id, url = %peer.url, "added cluster learner");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(peer = peer.id, error = %e, "add_learner failed; retrying");
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

/// Peer liveness + basic status.
async fn health(rt: web::Data<ClusterRuntime>, _peer: ClusterPeer) -> HttpResponse {
    let epoch = rt.controller.control_state().await.epoch;
    let is_leader = rt.controller.is_leader().await;
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "node_id": rt.node_id,
        "epoch": epoch,
        "is_leader": is_leader,
    }))
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

/// Add a node to the cluster (admin). Runs on the leader: adds the node as a
/// learner and, if `voter`, promotes it into the voting membership.
async fn join(
    rt: web::Data<ClusterRuntime>,
    _auth: AdminAuthenticated,
    body: web::Json<JoinRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    let req = body.into_inner();
    rt.controller
        .add_learner(req.id, BasicNode::new(req.url.clone()))
        .await
        .map_err(|e| actix_web::error::ErrorBadGateway(format!("add_learner: {e}")))?;

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
}
