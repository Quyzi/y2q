//! Control plane: the embedded raft group that replicates cluster topology.
//!
//! Raft replicates only [`ControlCmd`]s into a [`ControlState`] (membership,
//! chain table, epoch). The controller leader recomputes chains from the ring
//! and commits the resulting updates via [`compute_resplice`]. Object data never
//! enters the log.
//!
//! Phase B1 (this module so far): the pure domain types and apply/re-splice
//! logic. The redb-backed openraft storage, the raft network, and the
//! [`Controller`] runtime land in subsequent steps.

pub mod types;

pub use types::{ControlCmd, ControlResp, ControlState, NodeMeta, NodeStatus, compute_resplice};
