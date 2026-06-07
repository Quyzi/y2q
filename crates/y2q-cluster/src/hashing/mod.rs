//! Consistent-hash chain mapping.
//!
//! [`ring`] maps an object's `(bucket, key)` to a `chain_id` and computes the
//! ordered list of nodes that own a chain. [`chain`] holds the committed chain
//! table and the role logic a node uses to find its position within a chain.

pub mod chain;
pub mod ring;
