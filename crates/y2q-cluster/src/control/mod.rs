//! Control plane: the embedded raft group that replicates cluster topology.
//!
//! Raft replicates only [`ControlCmd`]s into a [`ControlState`] (membership,
//! chain table, epoch). The controller leader recomputes chains from the ring
//! and commits the resulting updates via [`compute_resplice`]. Object data never
//! enters the log.
//!
//! The redb-backed openraft storage ([`store`]) and the [`raft_impl`] type
//! configuration are implemented. The raft network and the `Controller` runtime
//! land in subsequent steps.

pub mod controller;
pub mod raft_impl;
pub mod store;
pub mod types;

pub use controller::{Controller, ControllerConfig, ControllerError};
pub use raft_impl::{Raft, TypeConfig};
pub use store::{LogStore, StateMachineStore, open};
pub use types::{ControlCmd, ControlResp, ControlState, NodeMeta, NodeStatus, compute_resplice};
