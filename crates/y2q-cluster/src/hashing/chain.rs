//! Committed chain table and per-node role logic.
//!
//! The controller leader computes chains from the ring and commits them through
//! raft as a [`ChainTable`], each entry stamped with the epoch it was committed
//! under (used for fencing stale views). Nodes serve requests from this
//! committed table. [`Role`] and the navigation helpers tell a node where it
//! sits in a chain so it can act as HEAD, forward to its successor, or answer
//! version queries at the TAIL.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::identity::NodeId;

/// A node's position within a specific chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// First node in a chain of length >= 2: assigns versions, starts PREPARE.
    Head,
    /// Interior node: forwards PREPARE downstream.
    Middle,
    /// Last node in a chain of length >= 2: commit authority, answers version
    /// queries.
    Tail,
    /// The only node in a length-1 chain: simultaneously HEAD and TAIL.
    Solo,
    /// This node is not a member of the chain.
    NotInChain,
}

/// One committed chain: the ordered member list (HEAD first, TAIL last) and the
/// epoch it was committed under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEntry {
    /// Ordered chain members, HEAD first and TAIL last.
    pub members: Vec<NodeId>,
    /// Epoch the entry was committed under; messages older than a node's current
    /// epoch are fenced out.
    pub epoch: u64,
}

/// The committed mapping from `chain_id` to its members, as replicated by raft.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainTable {
    chains: BTreeMap<u64, ChainEntry>,
}

impl ChainTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a committed chain by id.
    pub fn get(&self, chain_id: u64) -> Option<&ChainEntry> {
        self.chains.get(&chain_id)
    }

    /// Insert or replace a chain entry.
    pub fn upsert(&mut self, chain_id: u64, members: Vec<NodeId>, epoch: u64) {
        self.chains.insert(chain_id, ChainEntry { members, epoch });
    }

    /// Number of pinned chains.
    pub fn len(&self) -> usize {
        self.chains.len()
    }

    /// Whether any chain is pinned.
    pub fn is_empty(&self) -> bool {
        self.chains.is_empty()
    }
}

/// Determine `this` node's [`Role`] in `chain` (ordered HEAD..TAIL).
pub fn role(this: NodeId, chain: &[NodeId]) -> Role {
    match chain {
        [] => Role::NotInChain,
        [only] => {
            if *only == this {
                Role::Solo
            } else {
                Role::NotInChain
            }
        }
        [first, .., last] => {
            if *first == this {
                Role::Head
            } else if *last == this {
                Role::Tail
            } else if chain.contains(&this) {
                Role::Middle
            } else {
                Role::NotInChain
            }
        }
    }
}

/// The node immediately downstream of `this` in `chain`, if any (`None` at the
/// TAIL or when `this` is not a member).
pub fn next_in_chain(this: NodeId, chain: &[NodeId]) -> Option<NodeId> {
    let pos = chain.iter().position(|&n| n == this)?;
    chain.get(pos + 1).copied()
}

/// The chain HEAD, if the chain is non-empty.
pub fn head(chain: &[NodeId]) -> Option<NodeId> {
    chain.first().copied()
}

/// The chain TAIL, if the chain is non-empty.
pub fn tail(chain: &[NodeId]) -> Option<NodeId> {
    chain.last().copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_in_a_long_chain() {
        let chain = [1u64, 2, 3, 4];
        assert_eq!(role(1, &chain), Role::Head);
        assert_eq!(role(2, &chain), Role::Middle);
        assert_eq!(role(3, &chain), Role::Middle);
        assert_eq!(role(4, &chain), Role::Tail);
        assert_eq!(role(99, &chain), Role::NotInChain);
    }

    #[test]
    fn solo_and_empty_chains() {
        assert_eq!(role(7, &[7]), Role::Solo);
        assert_eq!(role(7, &[8]), Role::NotInChain);
        assert_eq!(role(7, &[]), Role::NotInChain);
    }

    #[test]
    fn two_node_chain_has_head_and_tail_only() {
        let chain = [5u64, 6];
        assert_eq!(role(5, &chain), Role::Head);
        assert_eq!(role(6, &chain), Role::Tail);
    }

    #[test]
    fn navigation_helpers() {
        let chain = [1u64, 2, 3];
        assert_eq!(next_in_chain(1, &chain), Some(2));
        assert_eq!(next_in_chain(2, &chain), Some(3));
        assert_eq!(next_in_chain(3, &chain), None);
        assert_eq!(next_in_chain(99, &chain), None);
        assert_eq!(head(&chain), Some(1));
        assert_eq!(tail(&chain), Some(3));
        assert_eq!(head(&[]), None);
        assert_eq!(tail(&[]), None);
    }

    #[test]
    fn chain_table_upsert_and_lookup() {
        let mut table = ChainTable::new();
        assert!(table.is_empty());
        table.upsert(42, vec![1, 2, 3], 7);
        assert_eq!(table.len(), 1);
        let entry = table.get(42).unwrap();
        assert_eq!(entry.members, vec![1, 2, 3]);
        assert_eq!(entry.epoch, 7);
        // Upsert replaces.
        table.upsert(42, vec![4, 5], 8);
        assert_eq!(table.get(42).unwrap().members, vec![4, 5]);
        assert_eq!(table.len(), 1);
        assert!(table.get(0).is_none());
    }
}
