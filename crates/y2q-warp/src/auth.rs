use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;
use tracing::warn;
use y2q_client::{ClientConfig, Y2qClient};
use y2q_config::{TokenEntry, TokenStore, default_tokens_path};
use zeroize::Zeroizing;

use crate::error::WarpError;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Resolve the initial token for `alias`:
/// 1. Use stored valid token if available.
/// 2. Fall back to `password` → login → store token.
pub async fn resolve_token(
    client: &Y2qClient,
    alias: &str,
    username: &str,
    password: Option<&str>,
) -> Result<(Zeroizing<String>, u64), WarpError> {
    let tokens_path = default_tokens_path()?;
    let store = TokenStore::load(&tokens_path)?;

    if let Some(tok) = store.token_for(alias) {
        let expires_at = store.get_valid(alias).unwrap().expires_at;
        return Ok((tok, expires_at));
    }

    let pw = password.ok_or_else(|| {
        WarpError::Other(format!(
            "no valid session for alias `{alias}` — run `y2q login {alias}` first or pass --password"
        ))
    })?;

    let resp = client.login(username, pw, Some(86400)).await?;
    let expires_at = resp.expires_at;

    let mut store = TokenStore::load(&tokens_path)?;
    store.set(
        alias,
        TokenEntry {
            token: resp.token.clone(),
            expires_at,
            username: username.to_owned(),
        },
    );
    store.save(&tokens_path)?;

    Ok((Zeroizing::new(resp.token), expires_at))
}

/// Spawn a background task that refreshes the token 5 minutes before expiry.
/// Sends updated tokens on `tx` and writes them back to tokens.toml.
pub fn spawn_refresh_task(
    client: Y2qClient,
    alias: String,
    username: String,
    expires_at: u64,
    tx: watch::Sender<Zeroizing<String>>,
) {
    tokio::spawn(async move {
        let mut expires_at = expires_at;
        loop {
            let now = now_secs();
            let refresh_at = expires_at.saturating_sub(300);
            if now < refresh_at {
                tokio::time::sleep(Duration::from_secs(refresh_at - now)).await;
            }

            match client.refresh().await {
                Ok(resp) => {
                    expires_at = resp.expires_at;
                    let tok = Zeroizing::new(resp.token.clone());
                    let _ = tx.send(tok);

                    if let Ok(tokens_path) = default_tokens_path() {
                        if let Ok(mut store) = TokenStore::load(&tokens_path) {
                            store.set(
                                &alias,
                                TokenEntry {
                                    token: resp.token,
                                    expires_at: resp.expires_at,
                                    username: username.clone(),
                                },
                            );
                            let _ = store.save(&tokens_path);
                        }
                    }
                }
                Err(e) => {
                    warn!("token refresh failed: {e}");
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            }
        }
    });
}

/// Build a Y2qClient for an alias, using the given token.
pub fn build_client(base_url: &str, token: &Zeroizing<String>) -> Result<Y2qClient, WarpError> {
    let client = Y2qClient::new(ClientConfig {
        base_url: base_url.to_owned(),
        token: Some(token.clone()),
    })?;
    Ok(client)
}
