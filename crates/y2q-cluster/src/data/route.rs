//! Resolve an object's chain from the committed control state.
//!
//! Every node maps `(bucket, key)` to the same chain because the mapping is a
//! pure function of the replicated membership (see [`crate::hashing::ring`]). A
//! chain may be **pinned** in the committed [`ChainTable`] (the controller leader
//! re-splices pinned chains on membership change) or, for a key never written
//! before, resolved **lazily** from the live ring at the current epoch. Either
//! way the result is deterministic across nodes given the same control state, so
//! any contact node can route a request without a central lookup.

use crate::control::types::ControlState;
use crate::hashing::chain::{self, Role};
use crate::hashing::ring::chain_id;
use crate::identity::NodeId;

/// The resolved chain for one object: ordered members (HEAD first, TAIL last),
/// the `chain_id`, and the epoch the routing was computed under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainRoute {
    /// Consistent-hash identifier of the chain.
    pub chain_id: u64,
    /// Ordered chain members, HEAD first and TAIL last. Empty if the cluster has
    /// no active members yet.
    pub members: Vec<NodeId>,
    /// Epoch the route was resolved under (the pinned entry's epoch, or the
    /// current global epoch for a lazily-resolved chain).
    pub epoch: u64,
    /// Whether the chain came from the committed table (`true`) rather than a
    /// lazy ring computation (`false`).
    pub pinned: bool,
}

impl ChainRoute {
    /// This node's [`Role`] in the chain.
    pub fn role(&self, me: NodeId) -> Role {
        chain::role(me, &self.members)
    }

    /// The chain HEAD, if any.
    pub fn head(&self) -> Option<NodeId> {
        chain::head(&self.members)
    }

    /// The chain TAIL, if any.
    pub fn tail(&self) -> Option<NodeId> {
        chain::tail(&self.members)
    }

    /// The member immediately downstream of `me`, if any (`None` at the TAIL or
    /// when `me` is not in the chain).
    pub fn next_after(&self, me: NodeId) -> Option<NodeId> {
        chain::next_in_chain(me, &self.members)
    }

    /// Whether `me` participates in this chain at all.
    pub fn contains(&self, me: NodeId) -> bool {
        self.members.contains(&me)
    }
}

/// Resolve the chain for `(bucket, key)` from `state`.
///
/// Uses the committed [`ChainTable`] entry when the chain is pinned; otherwise
/// computes the chain from the live ring built over the currently-active
/// membership at `replication_factor`, stamped with the current epoch.
pub fn resolve_route(
    state: &ControlState,
    bucket: &str,
    key: &str,
    replication_factor: usize,
    vnodes_per_node: u32,
) -> ChainRoute {
    let id = chain_id(bucket, key);
    if let Some(entry) = state.chains.get(id) {
        return ChainRoute {
            chain_id: id,
            members: entry.members.clone(),
            epoch: entry.epoch,
            pinned: true,
        };
    }
    let ring = state.ring(vnodes_per_node);
    let members = ring.chain_for_id(id, replication_factor);
    ChainRoute {
        chain_id: id,
        members,
        epoch: state.epoch,
        pinned: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::types::ControlCmd;

    fn state_with(ids: &[NodeId]) -> ControlState {
        let mut s = ControlState::default();
        for &id in ids {
            s.apply(&ControlCmd::AddNode {
                node_id: id,
                addr: format!("10.0.0.{id}:8443"),
                fingerprint: "fp".to_string(),
            });
        }
        s
    }

    #[test]
    fn lazy_route_is_deterministic_and_sized() {
        let s = state_with(&[1, 2, 3, 4, 5]);
        let a = resolve_route(&s, "bkt", "obj", 3, 64);
        let b = resolve_route(&s, "bkt", "obj", 3, 64);
        assert_eq!(a, b);
        assert!(!a.pinned);
        assert_eq!(a.members.len(), 3);
        assert_eq!(a.epoch, s.epoch);
        // HEAD/TAIL/next consistency.
        let head = a.head().unwrap();
        assert_eq!(a.role(head), Role::Head);
        assert_eq!(a.role(a.tail().unwrap()), Role::Tail);
        assert_eq!(a.next_after(head), Some(a.members[1]));
    }

    #[test]
    fn pinned_route_wins_over_ring() {
        let mut s = state_with(&[1, 2, 3]);
        let id = chain_id("b", "k");
        s.apply(&ControlCmd::UpdateChain {
            chain_id: id,
            members: vec![3, 1, 2],
            epoch: 9,
        });
        let r = resolve_route(&s, "b", "k", 3, 64);
        assert!(r.pinned);
        assert_eq!(r.members, vec![3, 1, 2]);
        assert_eq!(r.epoch, 9);
        assert_eq!(r.head(), Some(3));
        assert_eq!(r.tail(), Some(2));
    }

    #[test]
    fn empty_cluster_yields_empty_chain() {
        let s = ControlState::default();
        let r = resolve_route(&s, "b", "k", 3, 64);
        assert!(r.members.is_empty());
        assert_eq!(r.role(1), Role::NotInChain);
        assert_eq!(r.head(), None);
    }

    #[test]
    fn solo_chain_when_single_node() {
        let s = state_with(&[7]);
        let r = resolve_route(&s, "b", "k", 3, 64);
        assert_eq!(r.members, vec![7]);
        assert_eq!(r.role(7), Role::Solo);
        assert_eq!(r.next_after(7), None);
    }
}
