//! openraft type configuration for the control plane.
//!
//! Binds the generic openraft engine to our concrete types: [`ControlCmd`] as
//! the application request, [`ControlResp`] as the response, `u64` node ids, and
//! [`BasicNode`](openraft::BasicNode) (which carries a peer's advertised address)
//! as the node payload. The log entry, snapshot data, async runtime, and
//! responder use openraft's defaults.

use crate::control::types::{ControlCmd, ControlResp};

openraft::declare_raft_types!(
    /// The control-plane raft type configuration.
    pub TypeConfig:
        D = ControlCmd,
        R = ControlResp,
        NodeId = u64,
        Node = openraft::BasicNode,
        Entry = openraft::Entry<TypeConfig>,
        SnapshotData = std::io::Cursor<Vec<u8>>,
);

/// The concrete control-plane raft handle.
pub type Raft = openraft::Raft<TypeConfig>;
