//! Authentication operations shared by the CLI and the TUI.
//!
//! Token persistence (`TokenStore`) stays with the caller; these functions only
//! perform the network exchange.

use y2q_client::{ClientError, TokenResponse, Y2qClient};

/// Log in and obtain a session token. `ttl` is an optional lifetime in seconds.
pub async fn login(
    client: &Y2qClient,
    username: &str,
    password: &str,
    ttl: Option<u64>,
) -> Result<TokenResponse, ClientError> {
    client.login(username, password, ttl).await
}

/// Revoke the current session token server-side.
pub async fn logout(client: &Y2qClient) -> Result<(), ClientError> {
    client.logout().await
}

/// Change the authenticated user's password.
pub async fn change_password(
    client: &Y2qClient,
    current: &str,
    new: &str,
) -> Result<(), ClientError> {
    client.change_password(current, new).await
}
