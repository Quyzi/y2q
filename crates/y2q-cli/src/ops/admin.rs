//! Admin operations shared by the CLI and the TUI: index rebuild, stale-lock
//! management, user administration, and metrics.

use y2q_client::{AclBody, ClientError, RebuildStatus, StaleLockEntry, UserView, Y2qClient};

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

/// Add a user. `role` is `"admin"`, `"user"`, or `None` for the server default.
pub async fn add_user(
    client: &Y2qClient,
    username: &str,
    password: &str,
    role: Option<&str>,
) -> Result<(), ClientError> {
    client.add_user(username, password, role).await
}

/// List users.
pub async fn list_users(client: &Y2qClient) -> Result<Vec<UserView>, ClientError> {
    client.list_users().await
}

/// Delete a user.
pub async fn delete_user(client: &Y2qClient, username: &str) -> Result<(), ClientError> {
    client.delete_user(username).await
}

/// Change a user's global role.
pub async fn set_user_role(
    client: &Y2qClient,
    username: &str,
    role: &str,
) -> Result<(), ClientError> {
    client.set_user_role(username, role).await
}

/// Fetch a bucket's owner and ACL.
pub async fn acl_show(client: &Y2qClient, bucket: &str) -> Result<AclBody, ClientError> {
    client.get_bucket_acl(bucket).await
}

/// Grant `username` permission `perm` (`read`/`write`/`admin`) on `bucket`.
pub async fn acl_grant(
    client: &Y2qClient,
    bucket: &str,
    username: &str,
    perm: &str,
) -> Result<AclBody, ClientError> {
    let mut acl = client.get_bucket_acl(bucket).await?;
    acl.grants.insert(username.to_owned(), perm.to_owned());
    client.set_bucket_acl(bucket, &acl).await
}

/// Revoke any grant `username` holds on `bucket`.
pub async fn acl_revoke(
    client: &Y2qClient,
    bucket: &str,
    username: &str,
) -> Result<AclBody, ClientError> {
    let mut acl = client.get_bucket_acl(bucket).await?;
    acl.grants.remove(username);
    client.set_bucket_acl(bucket, &acl).await
}

/// Transfer ownership of `bucket` to `new_owner`.
pub async fn acl_chown(
    client: &Y2qClient,
    bucket: &str,
    new_owner: &str,
) -> Result<AclBody, ClientError> {
    let mut acl = client.get_bucket_acl(bucket).await?;
    acl.owner = Some(new_owner.to_owned());
    client.set_bucket_acl(bucket, &acl).await
}

/// Fetch the raw Prometheus scrape body.
pub async fn prometheus_metrics(client: &Y2qClient) -> Result<String, ClientError> {
    client.prometheus_metrics().await
}
