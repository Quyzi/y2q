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
use y2q_core::BucketConfig;
use y2q_core::crypto::{Role, UserRecord};

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
    /// Register a bucket cluster-wide, creating a default config entry if the
    /// bucket is not yet known. Idempotent: an existing entry is left untouched.
    RegisterBucket {
        /// Bucket name.
        bucket: String,
    },
    /// Replace a bucket's full configuration (quota, CORS, owner, ACL). Used by
    /// the config and ACL admin endpoints, which read-modify-write the whole
    /// config under an admin check before proposing it.
    SetBucketConfig {
        /// Bucket name.
        bucket: String,
        /// The complete configuration to store for the bucket.
        config: BucketConfig,
    },
    /// Claim a bucket's owner if it has none yet (race-safe at the apply point:
    /// the first claim through raft wins, later claims are no-ops). Ensures the
    /// bucket entry exists. Mirrors the single-node `claim_ownership` semantics.
    ClaimBucketOwner {
        /// Bucket name.
        bucket: String,
        /// Username to record as owner when the bucket currently has none.
        owner: String,
    },
    /// Remove a bucket's cluster-wide registry/config entry.
    UnregisterBucket {
        /// Bucket name.
        bucket: String,
    },
    /// Insert or replace a user's durable record cluster-wide (create, or
    /// password change which re-wraps the SK). The wrapped SK in the record is
    /// the same ciphertext-at-rest already stored on disk; the daemon projects
    /// the record into each node's local user store on apply.
    UpsertUser {
        /// The complete user record to store (keyed by its username).
        record: UserRecord,
    },
    /// Remove a user's record cluster-wide.
    DeleteUser {
        /// Username to remove.
        username: String,
    },
    /// Change a user's global role cluster-wide (idempotent; no-op if the user
    /// is unknown). Kept distinct from [`Self::UpsertUser`] so a role change does
    /// not resend the wrapped SK and so it applies atomically at the leader.
    SetUserRole {
        /// Affected username.
        username: String,
        /// New global role.
        role: Role,
    },
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
    /// Cluster-wide bucket registry and config (owner, ACL, quota, CORS),
    /// replicated so every node shares one authoritative view. Each node
    /// projects this into its local bucket sidecars on apply.
    #[serde(default)]
    pub buckets: BTreeMap<String, BucketConfig>,
    /// Cluster-wide user records (durable auth state: wrapped SK, KDF params,
    /// role), replicated so a joined node inherits every user. Each node projects
    /// this into its local user store on apply, preserving the node-local
    /// `last_login`. Sessions stay node-local and are not replicated.
    #[serde(default)]
    pub users: BTreeMap<String, UserRecord>,
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
            ControlCmd::RegisterBucket { bucket } => {
                self.buckets.entry(bucket.clone()).or_default();
            }
            ControlCmd::SetBucketConfig { bucket, config } => {
                self.buckets.insert(bucket.clone(), config.clone());
            }
            ControlCmd::ClaimBucketOwner { bucket, owner } => {
                let cfg = self.buckets.entry(bucket.clone()).or_default();
                if cfg.owner.is_none() {
                    cfg.owner = Some(owner.clone());
                }
            }
            ControlCmd::UnregisterBucket { bucket } => {
                self.buckets.remove(bucket);
            }
            ControlCmd::UpsertUser { record } => {
                self.users.insert(record.username.clone(), record.clone());
            }
            ControlCmd::DeleteUser { username } => {
                self.users.remove(username);
            }
            ControlCmd::SetUserRole { username, role } => {
                if let Some(rec) = self.users.get_mut(username) {
                    rec.role = *role;
                }
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
    fn bucket_registry_apply() {
        use y2q_core::BucketPermission;

        let mut s = ControlState::default();

        // Register creates a default entry; re-register is a no-op.
        s.apply(&ControlCmd::RegisterBucket {
            bucket: "photos".into(),
        });
        assert!(s.buckets.contains_key("photos"));
        assert_eq!(s.buckets["photos"], BucketConfig::default());
        s.apply(&ControlCmd::SetBucketConfig {
            bucket: "photos".into(),
            config: BucketConfig {
                owner: Some("alice".into()),
                quota_bytes: Some(1024),
                ..Default::default()
            },
        });
        s.apply(&ControlCmd::RegisterBucket {
            bucket: "photos".into(),
        });
        // Re-register did not clobber the existing config.
        assert_eq!(s.buckets["photos"].owner.as_deref(), Some("alice"));
        assert_eq!(s.buckets["photos"].quota_bytes, Some(1024));

        // Claim is first-writer-wins and idempotent.
        s.apply(&ControlCmd::RegisterBucket {
            bucket: "docs".into(),
        });
        s.apply(&ControlCmd::ClaimBucketOwner {
            bucket: "docs".into(),
            owner: "bob".into(),
        });
        s.apply(&ControlCmd::ClaimBucketOwner {
            bucket: "docs".into(),
            owner: "carol".into(),
        });
        assert_eq!(s.buckets["docs"].owner.as_deref(), Some("bob"));
        // Claim on an unknown bucket creates it owned.
        s.apply(&ControlCmd::ClaimBucketOwner {
            bucket: "fresh".into(),
            owner: "dave".into(),
        });
        assert_eq!(s.buckets["fresh"].owner.as_deref(), Some("dave"));

        // ACL flows through a full SetBucketConfig.
        let mut acl = BTreeMap::new();
        acl.insert("eve".to_string(), BucketPermission::Read);
        s.apply(&ControlCmd::SetBucketConfig {
            bucket: "docs".into(),
            config: BucketConfig {
                owner: Some("bob".into()),
                acl,
                ..Default::default()
            },
        });
        assert_eq!(
            s.buckets["docs"].acl.get("eve"),
            Some(&BucketPermission::Read)
        );

        // Unregister removes the entry; unregistering an absent bucket is a no-op.
        s.apply(&ControlCmd::UnregisterBucket {
            bucket: "photos".into(),
        });
        assert!(!s.buckets.contains_key("photos"));
        s.apply(&ControlCmd::UnregisterBucket {
            bucket: "nope".into(),
        });
    }

    #[test]
    fn bucket_cmd_round_trips_through_serde() {
        let cmd = ControlCmd::SetBucketConfig {
            bucket: "b".into(),
            config: BucketConfig {
                owner: Some("alice".into()),
                quota_bytes: Some(42),
                ..Default::default()
            },
        };
        let bytes = serde_json::to_vec(&cmd).unwrap();
        let back: ControlCmd = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(cmd, back);

        // ControlState with buckets round-trips, and a legacy state with no
        // `buckets` field deserializes to an empty map (serde default).
        let mut s = ControlState::default();
        s.apply(&cmd);
        let bytes = serde_json::to_vec(&s).unwrap();
        let back: ControlState = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(s, back);
        let legacy: ControlState =
            serde_json::from_str(r#"{"nodes":{},"chains":{"chains":{}},"epoch":0}"#).unwrap();
        assert!(legacy.buckets.is_empty());
    }

    fn user_record(name: &str, role: Role) -> UserRecord {
        let params = y2q_core::crypto::default_argon2_params();
        let wrapped = y2q_core::crypto::kdf::wrap_sk(b"sk-bytes", b"pw", &params).unwrap();
        UserRecord {
            username: name.to_owned(),
            created_at: 1,
            last_login: None,
            kdf: params,
            wrapped_sk: wrapped,
            role,
        }
    }

    #[test]
    fn user_registry_apply() {
        let mut s = ControlState::default();

        s.apply(&ControlCmd::UpsertUser {
            record: user_record("alice", Role::User),
        });
        assert_eq!(s.users["alice"].role, Role::User);

        // SetUserRole changes only the role.
        s.apply(&ControlCmd::SetUserRole {
            username: "alice".into(),
            role: Role::Admin,
        });
        assert_eq!(s.users["alice"].role, Role::Admin);
        // SetUserRole on an unknown user is a no-op (no panic, no insert).
        s.apply(&ControlCmd::SetUserRole {
            username: "ghost".into(),
            role: Role::Admin,
        });
        assert!(!s.users.contains_key("ghost"));

        // Upsert replaces the whole record (e.g. password change re-wraps the SK).
        let mut rotated = user_record("alice", Role::Admin);
        rotated.last_login = Some(42);
        s.apply(&ControlCmd::UpsertUser {
            record: rotated.clone(),
        });
        assert_eq!(s.users["alice"].last_login, Some(42));

        // Delete removes; deleting an absent user is a no-op.
        s.apply(&ControlCmd::DeleteUser {
            username: "alice".into(),
        });
        assert!(!s.users.contains_key("alice"));
        s.apply(&ControlCmd::DeleteUser {
            username: "alice".into(),
        });
    }

    #[test]
    fn user_cmd_round_trips_through_serde() {
        let cmd = ControlCmd::UpsertUser {
            record: user_record("bob", Role::Admin),
        };
        let bytes = serde_json::to_vec(&cmd).unwrap();
        let back: ControlCmd = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(cmd, back);

        // A legacy state with neither `buckets` nor `users` deserializes to empty.
        let legacy: ControlState =
            serde_json::from_str(r#"{"nodes":{},"chains":{"chains":{}},"epoch":0}"#).unwrap();
        assert!(legacy.users.is_empty());
        assert!(legacy.buckets.is_empty());
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
