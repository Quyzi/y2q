//! Control-plane domain types: the commands replicated through raft and the
//! state they apply to.
//!
//! These are the ONLY things the raft log carries: cluster topology (and, in a
//! later phase, auth/bucket metadata). Object data and per-object metadata never
//! enter the log. The apply logic and re-splice computation here are pure and
//! independently unit-tested; the openraft state-machine adapter (later) simply
//! drives [`ControlState::apply`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::hashing::chain::ChainTable;
use crate::hashing::ring::Ring;
use crate::identity::NodeId;

/// Liveness/role status of a node, tracked by the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    /// Fully participating: serves reads/writes and is eligible for chains.
    Active,
    /// Health probes failing; a candidate for removal from chains.
    Suspect,
    /// Confirmed down; excluded from chains.
    Down,
    /// Back-filling state after (re)joining; accepts writes, reads redirected
    /// elsewhere until caught up.
    Recovering,
}

/// Per-node metadata replicated through raft.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeMeta {
    /// Full base URL (`scheme://host:port`) other nodes dial for the internal
    /// API; the data plane appends the endpoint path to it.
    pub addr: String,
    /// Deployment public-key fingerprint (SHA-256 hex). The controller refuses to
    /// admit a node whose fingerprint differs, guarding the shared-MEK invariant.
    pub fingerprint: String,
    /// Current liveness/role status.
    pub status: NodeStatus,
}

/// Commands replicated through the raft log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlCmd {
    /// Admit a node into the cluster (initially [`NodeStatus::Active`]).
    AddNode {
        /// Node id being admitted.
        node_id: NodeId,
        /// Its advertised `host:port`.
        addr: String,
        /// Its deployment-key fingerprint.
        fingerprint: String,
    },
    /// Remove a node from the cluster entirely.
    RemoveNode {
        /// Node id being removed.
        node_id: NodeId,
    },
    /// Change a node's liveness/role status.
    SetNodeStatus {
        /// Affected node id.
        node_id: NodeId,
        /// New status.
        status: NodeStatus,
    },
    /// Pin or replace a chain's ordered members under an epoch.
    UpdateChain {
        /// Chain identifier.
        chain_id: u64,
        /// Ordered members, HEAD first and TAIL last.
        members: Vec<NodeId>,
        /// Epoch the chain is committed under.
        epoch: u64,
    },
    /// Monotonically increment the global epoch (the fencing token).
    BumpEpoch,
}

/// Response from applying a [`ControlCmd`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlResp {
    /// The global epoch after the command was applied.
    pub epoch: u64,
}

/// The replicated control-plane state — the applied form of the raft log.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlState {
    /// Known nodes and their metadata.
    pub nodes: BTreeMap<NodeId, NodeMeta>,
    /// Committed chain table.
    pub chains: ChainTable,
    /// Global epoch (fencing token); bumped on every reconfiguration.
    pub epoch: u64,
}

impl ControlState {
    /// Apply one command, mutating the state, and return the resulting epoch.
    ///
    /// This is the single source of truth for how the log shapes the state, used
    /// both by the openraft state-machine adapter and by unit tests.
    pub fn apply(&mut self, cmd: &ControlCmd) -> ControlResp {
        match cmd {
            ControlCmd::AddNode {
                node_id,
                addr,
                fingerprint,
            } => {
                self.nodes.insert(
                    *node_id,
                    NodeMeta {
                        addr: addr.clone(),
                        fingerprint: fingerprint.clone(),
                        status: NodeStatus::Active,
                    },
                );
            }
            ControlCmd::RemoveNode { node_id } => {
                self.nodes.remove(node_id);
            }
            ControlCmd::SetNodeStatus { node_id, status } => {
                if let Some(meta) = self.nodes.get_mut(node_id) {
                    meta.status = *status;
                }
            }
            ControlCmd::UpdateChain {
                chain_id,
                members,
                epoch,
            } => {
                self.chains.upsert(*chain_id, members.clone(), *epoch);
            }
            ControlCmd::BumpEpoch => {
                self.epoch += 1;
            }
        }
        ControlResp { epoch: self.epoch }
    }

    /// Ids of nodes currently [`NodeStatus::Active`], ascending.
    pub fn active_nodes(&self) -> Vec<NodeId> {
        self.nodes
            .iter()
            .filter(|(_, meta)| meta.status == NodeStatus::Active)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Build a consistent-hash ring from the current active membership.
    pub fn ring(&self, vnodes_per_node: u32) -> Ring {
        Ring::new(&self.active_nodes(), vnodes_per_node)
    }
}

/// Compute the chain-table updates needed to bring the pinned chains in line
/// with `ring` at `replication_factor`.
///
/// Run by the controller leader after a membership change: for each already
/// pinned chain whose computed membership differs from what's committed, emit an
/// [`ControlCmd::UpdateChain`] stamped with `state.epoch + 1`, and append a
/// single [`ControlCmd::BumpEpoch`]. Returns an empty vec when nothing moved, so
/// the leader commits nothing in the steady state.
///
/// Only already-pinned chains are recomputed; an unpinned `chain_id` is resolved
/// lazily from the ring on first write (data plane) rather than enumerated here.
pub fn compute_resplice(
    state: &ControlState,
    ring: &Ring,
    replication_factor: usize,
) -> Vec<ControlCmd> {
    let new_epoch = state.epoch + 1;
    let mut cmds = Vec::new();
    for (chain_id, entry) in state.chains.iter() {
        let members = ring.chain_for_id(chain_id, replication_factor);
        if members != entry.members {
            cmds.push(ControlCmd::UpdateChain {
                chain_id,
                members,
                epoch: new_epoch,
            });
        }
    }
    if !cmds.is_empty() {
        cmds.push(ControlCmd::BumpEpoch);
    }
    cmds
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add(state: &mut ControlState, id: NodeId) {
        state.apply(&ControlCmd::AddNode {
            node_id: id,
            addr: format!("10.0.0.{id}:8443"),
            fingerprint: "fp".to_string(),
        });
    }

    #[test]
    fn add_remove_and_status() {
        let mut s = ControlState::default();
        add(&mut s, 1);
        add(&mut s, 2);
        assert_eq!(s.active_nodes(), vec![1, 2]);
        assert_eq!(s.nodes[&1].status, NodeStatus::Active);

        s.apply(&ControlCmd::SetNodeStatus {
            node_id: 1,
            status: NodeStatus::Down,
        });
        assert_eq!(s.active_nodes(), vec![2]);

        s.apply(&ControlCmd::RemoveNode { node_id: 2 });
        assert!(s.active_nodes().is_empty());
        // Status change on an unknown node is a no-op, not a panic.
        s.apply(&ControlCmd::SetNodeStatus {
            node_id: 99,
            status: NodeStatus::Active,
        });
        assert!(!s.nodes.contains_key(&99));
    }

    #[test]
    fn bump_epoch_is_monotonic() {
        let mut s = ControlState::default();
        assert_eq!(s.epoch, 0);
        assert_eq!(s.apply(&ControlCmd::BumpEpoch).epoch, 1);
        assert_eq!(s.apply(&ControlCmd::BumpEpoch).epoch, 2);
    }

    #[test]
    fn update_chain_records_members_and_epoch() {
        let mut s = ControlState::default();
        s.apply(&ControlCmd::UpdateChain {
            chain_id: 7,
            members: vec![1, 2, 3],
            epoch: 4,
        });
        let entry = s.chains.get(7).unwrap();
        assert_eq!(entry.members, vec![1, 2, 3]);
        assert_eq!(entry.epoch, 4);
    }

    #[test]
    fn resplice_is_empty_when_membership_unchanged() {
        let mut s = ControlState::default();
        for id in [1, 2, 3] {
            add(&mut s, id);
        }
        // Pin chains exactly as the ring would compute them.
        let ring = s.ring(256);
        for chain_id in [10u64, 20, 30, 40] {
            let members = ring.chain_for_id(chain_id, 3);
            s.apply(&ControlCmd::UpdateChain {
                chain_id,
                members,
                epoch: s.epoch,
            });
        }
        // No membership change => no updates.
        assert!(compute_resplice(&s, &ring, 3).is_empty());
    }

    #[test]
    fn resplice_emits_updates_and_bump_after_membership_change() {
        let mut s = ControlState::default();
        for id in [1, 2, 3] {
            add(&mut s, id);
        }
        let ring_before = s.ring(256);
        // Pin many chains spread across the whole u64 ring (small sequential ids
        // would all land in one tiny region). With this spread the joining node
        // is certain to enter some chain's top-R, forcing a re-splice.
        for i in 0..256u64 {
            let chain_id = i.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            let members = ring_before.chain_for_id(chain_id, 3);
            s.apply(&ControlCmd::UpdateChain {
                chain_id,
                members,
                epoch: s.epoch,
            });
        }
        // A node joins: the ring changes, so some chains must be re-spliced.
        add(&mut s, 4);
        let ring_after = s.ring(256);
        let cmds = compute_resplice(&s, &ring_after, 3);
        assert!(!cmds.is_empty(), "expected re-splice after a node joined");
        // Exactly one BumpEpoch, and it is the last command.
        assert!(matches!(cmds.last(), Some(ControlCmd::BumpEpoch)));
        let bumps = cmds
            .iter()
            .filter(|c| matches!(c, ControlCmd::BumpEpoch))
            .count();
        assert_eq!(bumps, 1);
        // Every UpdateChain carries the bumped epoch and a genuinely changed set.
        for cmd in &cmds {
            if let ControlCmd::UpdateChain {
                chain_id,
                members,
                epoch,
            } = cmd
            {
                assert_eq!(*epoch, s.epoch + 1);
                assert_ne!(*members, s.chains.get(*chain_id).unwrap().members);
            }
        }
    }

    #[test]
    fn control_cmd_round_trips_through_serde() {
        let cmd = ControlCmd::AddNode {
            node_id: 42,
            addr: "host:1".to_string(),
            fingerprint: "abc".to_string(),
        };
        let bytes = serde_json::to_vec(&cmd).unwrap();
        let back: ControlCmd = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(cmd, back);

        let mut s = ControlState::default();
        s.apply(&cmd);
        s.apply(&ControlCmd::UpdateChain {
            chain_id: 1,
            members: vec![42],
            epoch: 1,
        });
        let bytes = serde_json::to_vec(&s).unwrap();
        let back: ControlState = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(s, back);
    }
}
