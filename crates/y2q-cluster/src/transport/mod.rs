//! Node-to-node transport over HTTP.
//!
//! [`internal_client`] is a thin reqwest wrapper (PQ-TLS, optional mTLS, shared-
//! secret header) used for all peer RPC. [`raft_network`] implements openraft's
//! network traits on top of it, posting raft RPCs to a peer's `/internal/v1/raft`
//! endpoints. The actix handlers that receive these RPCs live in `y2qd`.

pub mod internal_client;
pub mod raft_network;

pub use internal_client::{InternalClient, InternalTlsOptions, TransportError};
pub use raft_network::HttpRaftNetworkFactory;
