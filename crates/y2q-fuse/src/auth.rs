use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use y2q_client::{ClientConfig, TlsOptions, Y2qClient};
use y2q_config::{Alias, CliConfig, TokenStore, default_config_path, default_tokens_path};
use zeroize::Zeroizing;

use crate::error::FuseError;

/// Load config + token store, build a ready client and return it alongside
/// the token's expiry timestamp (unix seconds).
pub fn resolve_client(
    config_override: Option<&Path>,
    alias_name: &str,
) -> Result<(Arc<RwLock<Y2qClient>>, u64), FuseError> {
    let config_path: PathBuf = match config_override {
        Some(p) => p.to_owned(),
        None => default_config_path()?,
    };
    let config = CliConfig::load(&config_path)?;
    let alias = config.get_alias(alias_name)?;

    let tokens_path = default_tokens_path()?;
    let store = TokenStore::load(&tokens_path)?;
    let entry = store
        .get_valid(alias_name)
        .ok_or_else(|| FuseError::NotLoggedIn(alias_name.to_owned()))?;

    let expires_at = entry.expires_at;
    let token = Zeroizing::new(entry.token.clone());

    let client = build_client(alias, Some(token))?;
    Ok((Arc::new(RwLock::new(client)), expires_at))
}

pub fn build_client(
    alias: &Alias,
    token: Option<Zeroizing<String>>,
) -> Result<Y2qClient, FuseError> {
    let mut tls = TlsOptions {
        insecure: alias.insecure,
        ..TlsOptions::default()
    };
    if let Some(path) = &alias.ca_cert_path {
        tls.ca_cert_pem = Some(read_pem(path, "CA certificate")?);
    }
    match (&alias.client_cert_path, &alias.client_key_path) {
        (Some(cert), Some(key)) => {
            let mut bundle = read_pem(cert, "client certificate")?;
            bundle.push(b'\n');
            bundle.extend_from_slice(&read_pem(key, "client key")?);
            tls.client_identity_pem = Some(Zeroizing::new(bundle));
        }
        (None, None) => {}
        _ => {
            return Err(FuseError::Other(
                "client_cert_path and client_key_path must both be set or both unset".into(),
            ));
        }
    }
    Y2qClient::new(ClientConfig {
        base_url: alias.url.clone(),
        token,
        tls,
    })
    .map_err(FuseError::from)
}

fn read_pem(path: &str, label: &str) -> Result<Vec<u8>, FuseError> {
    fs::read(Path::new(path))
        .map_err(|e| FuseError::Other(format!("read {label} from {path}: {e}")))
}

/// Spawn a background task that refreshes the token ~60 seconds before expiry.
/// On success the new token is installed into the shared client.
pub fn spawn_token_refresh(
    rt: tokio::runtime::Handle,
    client: Arc<RwLock<Y2qClient>>,
    expires_at: u64,
) {
    rt.spawn(async move {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let refresh_at = expires_at.saturating_sub(60);
        if refresh_at > now {
            tokio::time::sleep(std::time::Duration::from_secs(refresh_at - now)).await;
        }
        let snapshot = { client.read().unwrap().clone() };
        match snapshot.refresh().await {
            Ok(resp) => {
                client.write().unwrap().set_token(resp.token);
                tracing::info!(expires_at = resp.expires_at, "token refreshed");
                // Schedule another refresh for the new expiry.
                spawn_token_refresh(tokio::runtime::Handle::current(), client, resp.expires_at);
            }
            Err(e) => tracing::warn!("token refresh failed: {e}"),
        }
    });
}
