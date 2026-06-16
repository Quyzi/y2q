//! Consistent-hash ring with virtual nodes.
//!
//! The ring maps an object's `(bucket, key)` to a point on a `u64` ring, and
//! maps each node to `vnodes_per_node` points. The chain for an object is the
//! next `R` *distinct* nodes walking clockwise from the object's point. This is
//! deterministic on every node given the same membership, so any node can route
//! a request without a lookup table, and adding/removing a node only reshuffles
//! the key ranges adjacent to its tokens.
//!
//! The controller leader uses [`Ring::chain_for_id`] to *compute* the chain
//! table it commits through raft; nodes then serve from the committed,
//! epoch-stamped table rather than the live ring (see [`super::chain`]).

use xxhash_rust::xxh3::xxh3_64_with_seed;

use crate::identity::NodeId;

/// Seed for all ring hashing. This is a pinned wire constant: changing it
/// reshuffles every object's chain assignment, so it must never change without a
/// data migration.
const RING_SEED: u64 = 0x7932_7100_0000_0001;

/// Hash an object `(bucket, key)` to its point on the ring.
///
/// Length-prefixing each component makes the mapping unambiguous (so
/// `("a", "bc")` and `("ab", "c")` never collide by construction) and identical
/// on every node.
pub fn chain_id(bucket: &str, key: &str) -> u64 {
    let mut buf = Vec::with_capacity(16 + bucket.len() + key.len());
    buf.extend_from_slice(&(bucket.len() as u64).to_le_bytes());
    buf.extend_from_slice(bucket.as_bytes());
    buf.extend_from_slice(&(key.len() as u64).to_le_bytes());
    buf.extend_from_slice(key.as_bytes());
    hash(&buf)
}

/// Hash a node's virtual-node token point.
fn token(node: NodeId, vnode: u32) -> u64 {
    let mut buf = [0u8; 12];
    buf[..8].copy_from_slice(&node.to_le_bytes());
    buf[8..].copy_from_slice(&vnode.to_le_bytes());
    hash(&buf)
}

/// Single-shot XXH3-64 of a buffer with the pinned ring seed.
fn hash(bytes: &[u8]) -> u64 {
    xxh3_64_with_seed(bytes, RING_SEED)
}

/// A consistent-hash ring over the current active membership.
///
/// Cheap to rebuild; reconstruct it whenever membership changes.
#[derive(Debug, Clone)]
pub struct Ring {
    /// `(token, node)` pairs sorted ascending by token, then by node id to make
    /// the order fully deterministic even on a (vanishingly unlikely) token tie.
    tokens: Vec<(u64, NodeId)>,
}

impl Ring {
    /// Build a ring placing `vnodes_per_node` virtual points for each node.
    ///
    /// Duplicate node ids in `nodes` are ignored. `vnodes_per_node` should be at
    /// least 1; higher values smooth the key distribution.
    pub fn new(nodes: &[NodeId], vnodes_per_node: u32) -> Self {
        let mut seen = Vec::new();
        let mut tokens = Vec::with_capacity(nodes.len() * vnodes_per_node.max(1) as usize);
        for &node in nodes {
            if seen.contains(&node) {
                continue;
            }
            seen.push(node);
            for vnode in 0..vnodes_per_node {
                tokens.push((token(node, vnode), node));
            }
        }
        tokens.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        Self { tokens }
    }

    /// Number of distinct nodes on the ring.
    pub fn node_count(&self) -> usize {
        let mut nodes: Vec<NodeId> = self.tokens.iter().map(|&(_, n)| n).collect();
        nodes.sort_unstable();
        nodes.dedup();
        nodes.len()
    }

    /// Whether the ring has no nodes.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Ordered chain (HEAD first, TAIL last) of up to `r` distinct nodes that
    /// own `id`, walking clockwise from `id`'s point.
    ///
    /// The result is clamped to the number of distinct nodes on the ring, so an
    /// `r` larger than the membership yields a shorter chain rather than
    /// repeating a node. Returns empty if the ring is empty or `r == 0`.
    pub fn chain_for_id(&self, id: u64, r: usize) -> Vec<NodeId> {
        if self.tokens.is_empty() || r == 0 {
            return Vec::new();
        }
        let n = self.tokens.len();
        let start = self.tokens.partition_point(|&(t, _)| t < id);
        let mut chain = Vec::with_capacity(r);
        for i in 0..n {
            if chain.len() == r {
                break;
            }
            let (_, node) = self.tokens[(start + i) % n];
            if !chain.contains(&node) {
                chain.push(node);
            }
        }
        chain
    }

    /// Convenience: the chain for an object `(bucket, key)`.
    pub fn chain_for(&self, bucket: &str, key: &str, r: usize) -> Vec<NodeId> {
        self.chain_for_id(chain_id(bucket, key), r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn chain_id_is_deterministic_and_length_unambiguous() {
        assert_eq!(chain_id("bucket", "key"), chain_id("bucket", "key"));
        // Length-prefixing prevents the boundary collision.
        assert_ne!(chain_id("a", "bc"), chain_id("ab", "c"));
    }

    #[test]
    fn ring_construction_is_deterministic() {
        let nodes = [1u64, 2, 3, 4, 5];
        let a = Ring::new(&nodes, 64);
        let b = Ring::new(&nodes, 64);
        for key in ["one", "two", "three", "alpha/beta", ""] {
            assert_eq!(a.chain_for("b", key, 3), b.chain_for("b", key, 3));
        }
    }

    #[test]
    fn chain_members_are_distinct_and_clamped() {
        let nodes = [10u64, 20, 30];
        let ring = Ring::new(&nodes, 128);
        for i in 0..1000u64 {
            let chain = ring.chain_for_id(i.wrapping_mul(0x9E37_79B9_7F4A_7C15), 5);
            // Clamped to distinct membership (3 nodes), never repeats.
            assert_eq!(chain.len(), 3);
            let set: HashSet<_> = chain.iter().copied().collect();
            assert_eq!(set.len(), chain.len(), "chain repeated a node: {chain:?}");
            for n in &chain {
                assert!(nodes.contains(n));
            }
        }
    }

    #[test]
    fn replication_factor_is_honored_when_below_membership() {
        let nodes = [1u64, 2, 3, 4, 5, 6, 7];
        let ring = Ring::new(&nodes, 64);
        let chain = ring.chain_for("bkt", "obj", 3);
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn empty_ring_and_zero_r_yield_empty_chains() {
        let empty = Ring::new(&[], 64);
        assert!(empty.is_empty());
        assert!(empty.chain_for("b", "k", 3).is_empty());

        let ring = Ring::new(&[1, 2, 3], 64);
        assert!(ring.chain_for_id(0, 0).is_empty());
    }

    #[test]
    fn distribution_is_roughly_balanced() {
        let nodes = [1u64, 2, 3, 4];
        let ring = Ring::new(&nodes, 256);
        let mut counts = std::collections::HashMap::new();
        let total = 20_000u64;
        for i in 0..total {
            let head = ring.chain_for_id(i.wrapping_mul(0x9E37_79B9_7F4A_7C15), 1)[0];
            *counts.entry(head).or_insert(0u64) += 1;
        }
        // Every node should own a meaningful share; assert each is within 2x of
        // an even split (a loose bound that still catches gross imbalance).
        let even = total / nodes.len() as u64;
        for &node in &nodes {
            let c = *counts.get(&node).unwrap_or(&0);
            assert!(c > even / 2, "node {node} underweight: {c} (even {even})");
            assert!(c < even * 2, "node {node} overweight: {c} (even {even})");
        }
    }

    #[test]
    fn adding_a_node_reshuffles_only_a_fraction() {
        let before = Ring::new(&[1u64, 2, 3, 4], 256);
        let after = Ring::new(&[1u64, 2, 3, 4, 5], 256);
        let total = 10_000u64;
        let mut moved = 0u64;
        for i in 0..total {
            let id = i.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            if before.chain_for_id(id, 1)[0] != after.chain_for_id(id, 1)[0] {
                moved += 1;
            }
        }
        // With 5 nodes, ~1/5 of keys should move; assert well under half.
        assert!(moved < total / 2, "too many keys moved: {moved}/{total}");
    }
}
