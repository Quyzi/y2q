//! openraft network over HTTP.
//!
//! Forwards raft RPCs to a peer's `/internal/v1/raft/{append,vote,snapshot}`
//! endpoints via the [`InternalClient`]. Each peer's base URL is carried in its
//! [`BasicNode`] (set when the node joins). The receiving side (actix handlers
//! in `y2qd`) calls the local `Raft` and serializes the `Result<Resp, RaftError>`
//! back, which this client maps into the openraft `RPCError` shape.

use std::sync::Arc;

use openraft::BasicNode;
use openraft::error::{InstallSnapshotError, NetworkError, RPCError, RaftError, RemoteError};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};

use crate::control::raft_impl::TypeConfig;
use crate::identity::NodeId;
use crate::transport::internal_client::InternalClient;

/// Build the URL for a raft RPC `method` on a peer's base URL.
fn raft_url(base: &str, method: &str) -> String {
    format!("{}/internal/v1/raft/{}", base.trim_end_matches('/'), method)
}

/// Factory creating an [`HttpRaftNetwork`] per target node.
#[derive(Clone)]
pub struct HttpRaftNetworkFactory {
    client: Arc<InternalClient>,
}

impl HttpRaftNetworkFactory {
    /// Create a factory sharing one HTTP client across all peer connections.
    pub fn new(client: Arc<InternalClient>) -> Self {
        Self { client }
    }
}

impl RaftNetworkFactory<TypeConfig> for HttpRaftNetworkFactory {
    type Network = HttpRaftNetwork;

    async fn new_client(&mut self, target: NodeId, node: &BasicNode) -> HttpRaftNetwork {
        HttpRaftNetwork {
            client: self.client.clone(),
            target,
            base_url: node.addr.clone(),
        }
    }
}

/// A network handle sending raft RPCs to a single target node.
pub struct HttpRaftNetwork {
    client: Arc<InternalClient>,
    target: NodeId,
    base_url: String,
}

impl RaftNetwork<TypeConfig> for HttpRaftNetwork {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let url = raft_url(&self.base_url, "append");
        let wire: Result<AppendEntriesResponse<NodeId>, RaftError<NodeId>> = self
            .client
            .post_json(&url, &rpc)
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        wire.map_err(|raft_err| RPCError::RemoteError(RemoteError::new(self.target, raft_err)))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let url = raft_url(&self.base_url, "vote");
        let wire: Result<VoteResponse<NodeId>, RaftError<NodeId>> = self
            .client
            .post_json(&url, &rpc)
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        wire.map_err(|raft_err| RPCError::RemoteError(RemoteError::new(self.target, raft_err)))
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        let url = raft_url(&self.base_url, "snapshot");
        let wire: Result<InstallSnapshotResponse<NodeId>, RaftError<NodeId, InstallSnapshotError>> =
            self.client
                .post_json(&url, &rpc)
                .await
                .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        wire.map_err(|raft_err| RPCError::RemoteError(RemoteError::new(self.target, raft_err)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raft_url_joins_cleanly() {
        assert_eq!(
            raft_url("https://10.0.0.2:8443", "append"),
            "https://10.0.0.2:8443/internal/v1/raft/append"
        );
        // Trailing slash on the base is tolerated.
        assert_eq!(
            raft_url("https://10.0.0.2:8443/", "vote"),
            "https://10.0.0.2:8443/internal/v1/raft/vote"
        );
    }
}
