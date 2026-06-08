//! The control-plane controller: a thin runtime wrapper around the openraft
//! [`Raft`] handle plus the [`StateMachineStore`].
//!
//! It owns the raft instance, exposes the operations the daemon needs
//! (bootstrap, join, propose a [`ControlCmd`], read the live [`ControlState`]),
//! and implements the leader's re-splice step. The raft network is injected so
//! the same controller works with the in-process test router and, later, the
//! HTTP transport.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use openraft::network::RaftNetworkFactory;
use openraft::{BasicNode, Config};

use crate::control::raft_impl::{Raft, TypeConfig};
use crate::control::store::{self, StateMachineStore};
use crate::control::types::{ControlCmd, ControlResp, ControlState, compute_resplice};
use crate::identity::NodeId;

/// Errors from controller operations.
#[derive(thiserror::Error, Debug)]
pub enum ControllerError {
    /// Underlying raft storage failed to open.
    #[error("raft storage: {0}")]
    Storage(String),
    /// A raft operation failed (construction, membership, or client write).
    #[error("raft: {0}")]
    Raft(String),
}

/// Tuning for the controller and its embedded raft.
#[derive(Debug, Clone)]
pub struct ControllerConfig {
    /// Leader heartbeat interval (ms).
    pub heartbeat_interval_ms: u64,
    /// Lower bound of the randomized election timeout (ms).
    pub election_timeout_min_ms: u64,
    /// Upper bound of the randomized election timeout (ms).
    pub election_timeout_max_ms: u64,
    /// Chain length `R` used when re-splicing.
    pub replication_factor: usize,
    /// Virtual nodes per node on the ring.
    pub virtual_nodes_per_node: u32,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_ms: 250,
            election_timeout_min_ms: 1000,
            election_timeout_max_ms: 1500,
            replication_factor: 3,
            virtual_nodes_per_node: 256,
        }
    }
}

/// The control plane for one node.
pub struct Controller {
    raft: Raft,
    sm: StateMachineStore,
    node_id: NodeId,
    replication_factor: usize,
    virtual_nodes_per_node: u32,
}

impl Controller {
    /// Construct a controller: open the redb raft store at `raft_dir/raft.redb`
    /// and start the raft engine with the given `network`.
    pub async fn start<NF>(
        node_id: NodeId,
        raft_dir: &Path,
        network: NF,
        cfg: ControllerConfig,
    ) -> Result<Self, ControllerError>
    where
        NF: RaftNetworkFactory<TypeConfig>,
    {
        let (log_store, sm) = store::open(&raft_dir.join("raft.redb"))
            .map_err(|e| ControllerError::Storage(e.to_string()))?;

        let raft_config = Config {
            cluster_name: "y2q".to_string(),
            heartbeat_interval: cfg.heartbeat_interval_ms,
            election_timeout_min: cfg.election_timeout_min_ms,
            election_timeout_max: cfg.election_timeout_max_ms,
            ..Default::default()
        }
        .validate()
        .map_err(|e| ControllerError::Raft(e.to_string()))?;

        let raft = Raft::new(
            node_id,
            Arc::new(raft_config),
            network,
            log_store,
            sm.clone(),
        )
        .await
        .map_err(|e| ControllerError::Raft(e.to_string()))?;

        Ok(Self {
            raft,
            sm,
            node_id,
            replication_factor: cfg.replication_factor,
            virtual_nodes_per_node: cfg.virtual_nodes_per_node,
        })
    }

    /// This node's id.
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// The raft handle (used by the network handlers to serve incoming RPCs).
    pub fn raft(&self) -> &Raft {
        &self.raft
    }

    /// Subscribe to control-state updates published on every applied entry.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<Arc<ControlState>> {
        self.sm.subscribe()
    }

    /// A snapshot of the current applied control state.
    pub async fn control_state(&self) -> ControlState {
        self.sm.control_state().await
    }

    /// Whether this node currently believes itself to be the leader.
    pub async fn is_leader(&self) -> bool {
        self.raft.current_leader().await == Some(self.node_id)
    }

    /// Initialize a brand-new single-node cluster consisting of `members`
    /// (typically just this node). Call on exactly one node, once.
    pub async fn initialize(
        &self,
        members: BTreeMap<NodeId, BasicNode>,
    ) -> Result<(), ControllerError> {
        self.raft
            .initialize(members)
            .await
            .map_err(|e| ControllerError::Raft(e.to_string()))
    }

    /// Add a node as a non-voting learner (the common path for joins).
    pub async fn add_learner(&self, id: NodeId, node: BasicNode) -> Result<(), ControllerError> {
        self.raft
            .add_learner(id, node, true)
            .await
            .map(|_| ())
            .map_err(|e| ControllerError::Raft(e.to_string()))
    }

    /// The current voting membership as known to this node's raft.
    pub fn current_voters(&self) -> BTreeSet<NodeId> {
        self.raft
            .metrics()
            .borrow()
            .membership_config
            .voter_ids()
            .collect()
    }

    /// Change the voting membership to `voters` (promoting learners as needed).
    pub async fn change_membership(&self, voters: BTreeSet<NodeId>) -> Result<(), ControllerError> {
        self.raft
            .change_membership(voters, false)
            .await
            .map(|_| ())
            .map_err(|e| ControllerError::Raft(e.to_string()))
    }

    /// Propose a control command through raft, returning the applied response.
    /// Only succeeds on the leader.
    pub async fn propose(&self, cmd: ControlCmd) -> Result<ControlResp, ControllerError> {
        self.raft
            .client_write(cmd)
            .await
            .map(|r| r.data)
            .map_err(|e| ControllerError::Raft(e.to_string()))
    }

    /// Recompute pinned chains from the current membership and commit the
    /// changed ones plus a single epoch bump. Returns the number of commands
    /// proposed (0 in the steady state). Only meaningful on the leader.
    pub async fn resplice_now(&self) -> Result<usize, ControllerError> {
        let state = self.control_state().await;
        let ring = state.ring(self.virtual_nodes_per_node);
        let cmds = compute_resplice(&state, &ring, self.replication_factor);
        let n = cmds.len();
        for cmd in cmds {
            self.propose(cmd).await?;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Duration;

    use openraft::error::{RPCError, RemoteError, Unreachable};
    use openraft::network::{RPCOption, RaftNetwork};
    use openraft::raft::{
        AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest,
        InstallSnapshotResponse, VoteRequest, VoteResponse,
    };

    /// Shared registry mapping node id -> its raft handle, so an in-process
    /// network can dispatch RPCs directly to the target engine.
    type Registry = Arc<Mutex<HashMap<NodeId, Raft>>>;

    #[derive(Clone)]
    struct RouterFactory {
        registry: Registry,
    }

    struct RouterNetwork {
        registry: Registry,
        target: NodeId,
    }

    /// Build an `Unreachable` RPC error for a target not in the registry.
    fn unreachable<E: std::error::Error + 'static>(
        target: NodeId,
    ) -> RPCError<NodeId, BasicNode, E> {
        RPCError::Unreachable(Unreachable::new(&std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("node {target} not registered"),
        )))
    }

    impl RouterNetwork {
        fn target_raft(&self) -> Option<Raft> {
            self.registry.lock().unwrap().get(&self.target).cloned()
        }
    }

    impl RaftNetworkFactory<TypeConfig> for RouterFactory {
        type Network = RouterNetwork;

        async fn new_client(&mut self, target: NodeId, _node: &BasicNode) -> RouterNetwork {
            RouterNetwork {
                registry: self.registry.clone(),
                target,
            }
        }
    }

    impl RaftNetwork<TypeConfig> for RouterNetwork {
        async fn append_entries(
            &mut self,
            rpc: AppendEntriesRequest<TypeConfig>,
            _option: RPCOption,
        ) -> Result<
            AppendEntriesResponse<NodeId>,
            RPCError<NodeId, BasicNode, openraft::error::RaftError<NodeId>>,
        > {
            let raft = self.target_raft().ok_or_else(|| unreachable(self.target))?;
            raft.append_entries(rpc)
                .await
                .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
        }

        async fn vote(
            &mut self,
            rpc: VoteRequest<NodeId>,
            _option: RPCOption,
        ) -> Result<
            VoteResponse<NodeId>,
            RPCError<NodeId, BasicNode, openraft::error::RaftError<NodeId>>,
        > {
            let raft = self.target_raft().ok_or_else(|| unreachable(self.target))?;
            raft.vote(rpc)
                .await
                .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
        }

        async fn install_snapshot(
            &mut self,
            rpc: InstallSnapshotRequest<TypeConfig>,
            _option: RPCOption,
        ) -> Result<
            InstallSnapshotResponse<NodeId>,
            RPCError<
                NodeId,
                BasicNode,
                openraft::error::RaftError<NodeId, openraft::error::InstallSnapshotError>,
            >,
        > {
            let raft = self.target_raft().ok_or_else(|| unreachable(self.target))?;
            raft.install_snapshot(rpc)
                .await
                .map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
        }
    }

    fn fast_cfg() -> ControllerConfig {
        // Fast timers so the in-process election settles in well under a second.
        ControllerConfig {
            heartbeat_interval_ms: 50,
            election_timeout_min_ms: 150,
            election_timeout_max_ms: 300,
            replication_factor: 3,
            virtual_nodes_per_node: 64,
        }
    }

    /// Poll an async condition until true or a generous deadline elapses.
    async fn wait_until<F, Fut>(label: &str, cond: F)
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        for _ in 0..200 {
            if cond().await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("timed out waiting for: {label}");
    }

    async fn build_cluster(n: usize) -> (Registry, Vec<tempfile::TempDir>, Vec<Controller>) {
        let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
        let dirs: Vec<_> = (0..n).map(|_| tempfile::tempdir().unwrap()).collect();
        let mut controllers = Vec::new();
        for (i, dir) in dirs.iter().enumerate() {
            let id = (i + 1) as NodeId;
            let factory = RouterFactory {
                registry: registry.clone(),
            };
            let c = Controller::start(id, dir.path(), factory, fast_cfg())
                .await
                .unwrap();
            registry.lock().unwrap().insert(id, c.raft().clone());
            controllers.push(c);
        }
        (registry, dirs, controllers)
    }

    #[tokio::test]
    async fn three_nodes_elect_leader_and_converge() {
        let (_registry, _dirs, controllers) = build_cluster(3).await;

        // Bootstrap node 1, then grow to a 3-voter cluster.
        controllers[0]
            .initialize(BTreeMap::from([(1, BasicNode::new("1"))]))
            .await
            .unwrap();
        controllers[0]
            .add_learner(2, BasicNode::new("2"))
            .await
            .unwrap();
        controllers[0]
            .add_learner(3, BasicNode::new("3"))
            .await
            .unwrap();
        controllers[0]
            .change_membership(BTreeSet::from([1, 2, 3]))
            .await
            .unwrap();

        // Node 1 should be the leader and every node should agree on it.
        wait_until("node 1 leads", || async {
            controllers[0].raft().metrics().borrow().current_leader == Some(1)
        })
        .await;
        for c in &controllers {
            let leader = c.raft().metrics().borrow().current_leader;
            assert_eq!(leader, Some(1), "node {} disagrees on leader", c.node_id());
        }

        // A control command proposed at the leader replicates to followers.
        controllers[0]
            .propose(ControlCmd::AddNode {
                node_id: 42,
                addr: "42".to_string(),
                fingerprint: "fp".to_string(),
            })
            .await
            .unwrap();
        for c in &controllers {
            let cid = c.node_id();
            wait_until(&format!("node {cid} sees AddNode(42)"), || async {
                c.control_state().await.nodes.contains_key(&42)
            })
            .await;
        }

        // Epoch is monotonic: a BumpEpoch raises it everywhere.
        let before = controllers[0].control_state().await.epoch;
        controllers[0].propose(ControlCmd::BumpEpoch).await.unwrap();
        wait_until("epoch advanced on follower 2", || async {
            controllers[1].control_state().await.epoch == before + 1
        })
        .await;
    }

    #[tokio::test]
    async fn learner_receives_log_without_voting() {
        let (_registry, _dirs, controllers) = build_cluster(2).await;

        controllers[0]
            .initialize(BTreeMap::from([(1, BasicNode::new("1"))]))
            .await
            .unwrap();
        wait_until("node 1 leads", || async {
            controllers[0].raft().metrics().borrow().current_leader == Some(1)
        })
        .await;

        // Node 2 joins as a learner only (never promoted to voter).
        controllers[0]
            .add_learner(2, BasicNode::new("2"))
            .await
            .unwrap();
        controllers[0]
            .propose(ControlCmd::AddNode {
                node_id: 7,
                addr: "7".to_string(),
                fingerprint: "fp".to_string(),
            })
            .await
            .unwrap();

        // The learner receives the replicated log...
        wait_until("learner sees AddNode(7)", || async {
            controllers[1].control_state().await.nodes.contains_key(&7)
        })
        .await;
        // ...but is not a voter and is not the leader.
        let m = controllers[1].raft().metrics().borrow().clone();
        assert_eq!(m.current_leader, Some(1));
        let voter_ids: Vec<NodeId> = m.membership_config.voter_ids().collect();
        assert_eq!(voter_ids, vec![1], "learner must not be a voter");
    }
}
