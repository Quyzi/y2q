//! y2q distributed-storage cluster.
//!
//! This crate implements clustering for `y2q`: a CRAQ data plane (chain
//! replication with apportioned queries) over an embedded raft control plane.
//! It depends on `y2q-core` for the storage trait, metadata, and crypto, and is
//! consumed by `y2qd`. Object data and per-object metadata never flow through
//! raft — only cluster topology (membership, chain table, epoch) is replicated.
//!
//! Phase A scope (this commit): persistent node identity ([`identity`]) and the
//! consistent-hash chain mapping ([`hashing`]). Later phases add the raft
//! control plane, the CRAQ data plane, and the internal HTTP transport.

pub mod hashing;
pub mod identity;

pub use hashing::chain::{ChainEntry, ChainTable, Role};
pub use hashing::ring::{Ring, chain_id};
pub use identity::{IdentityError, NodeId, resolve_node_id};

/// Top-level cluster error.
#[derive(thiserror::Error, Debug)]
pub enum ClusterError {
    /// Node identity could not be resolved or persisted.
    #[error(transparent)]
    Identity(#[from] IdentityError),
}
