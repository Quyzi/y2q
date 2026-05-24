//! Admin operations shared by the CLI and the TUI: index rebuild, stale-lock
//! management, user administration, and metrics.

use y2q_client::{ClientError, RebuildStatus, StaleLockEntry, UserView, Y2qClient};

/// Start a metadata index rebuild.
pub async fn rebuild_start(client: &Y2qClient) -> Result<(), ClientError> {
    client.rebuild_start().await
}

/// Fetch the current rebuild status.
pub async fn rebuild_status(client: &Y2qClient) -> Result<RebuildStatus, ClientError> {
    client.rebuild_status().await
}

/// List stale write locks older than `older_than` (e.g. `5m`, `1h`).
pub async fn locks_list(
    client: &Y2qClient,
    older_than: &str,
) -> Result<Vec<StaleLockEntry>, ClientError> {
    client.locks_list(older_than).await
}

/// Clear stale write locks older than `older_than`. Returns the count removed.
pub async fn locks_clear(client: &Y2qClient, older_than: &str) -> Result<u64, ClientError> {
    client.locks_clear(older_than).await
}

/// Add a user.
pub async fn add_user(
    client: &Y2qClient,
    username: &str,
    password: &str,
) -> Result<(), ClientError> {
    client.add_user(username, password).await
}

/// List users.
pub async fn list_users(client: &Y2qClient) -> Result<Vec<UserView>, ClientError> {
    client.list_users().await
}

/// Delete a user.
pub async fn delete_user(client: &Y2qClient, username: &str) -> Result<(), ClientError> {
    client.delete_user(username).await
}

/// Fetch the raw Prometheus scrape body.
pub async fn prometheus_metrics(client: &Y2qClient) -> Result<String, ClientError> {
    client.prometheus_metrics().await
}
