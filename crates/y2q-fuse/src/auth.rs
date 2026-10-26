use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use y2q_client::{ClientConfig, TlsOptions, TokenResponse, Y2qClient};
use y2q_config::{Alias, CliConfig, TokenEntry, TokenStore, default_config_path};
use zeroize::Zeroizing;

use crate::error::FuseError;

/// Paths + identity needed to write refreshed tokens back to the store that
/// `resolve_client` loaded from (sibling of the active config file).
#[derive(Clone)]
struct TokenTarget {
    tokens_path: PathBuf,
    alias: String,
    url: String,
    username: String,
}

/// Load config + token store, build a ready client and return it alongside
/// the token's expiry timestamp (unix seconds) and the resolved config path
/// (so refresh write-back uses the same sibling `tokens.toml`).
pub fn resolve_client(
    config_override: Option<&Path>,
    alias_name: &str,
) -> Result<(Arc<RwLock<Y2qClient>>, u64, PathBuf), FuseError> {
    let config_path: PathBuf = match config_override {
        Some(p) => p.to_owned(),
        None => default_config_path()?,
    };
    let config = CliConfig::load(&config_path)?;
    let alias = config.get_alias(alias_name)?;

    // Sibling of the active config so `--config other.toml` cannot reuse the
    // default profile's cached bearer against a different URL.
    let tokens_path = config_path.with_file_name("tokens.toml");
    let store = TokenStore::load(&tokens_path)?;
    let entry = store
        .get_bound(alias_name, &alias.url, &alias.username)
        .ok_or_else(|| FuseError::NotLoggedIn(alias_name.to_owned()))?;

    let expires_at = entry.expires_at;
    let token = Zeroizing::new(entry.token.clone());

    let client = build_client(alias, Some(token))?;
    Ok((Arc::new(RwLock::new(client)), expires_at, config_path))
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

fn persist_refreshed_token(target: &TokenTarget, resp: &TokenResponse) -> Result<(), FuseError> {
    TokenStore::update(&target.tokens_path, |store| {
        store.set(
            &target.alias,
            TokenEntry {
                token: resp.token.clone(),
                expires_at: resp.expires_at,
                username: resp.username.clone(),
                url: target.url.clone(),
            },
        );
        Ok(())
    })
    .map_err(FuseError::from)
}

/// If `tokens.toml` has a still-valid, URL-bound token for `target` that
/// differs from the one currently installed in `client`, install it and
/// return its expiry.
fn reload_token_from_store(
    target: &TokenTarget,
    client: &Arc<RwLock<Y2qClient>>,
) -> Result<Option<u64>, FuseError> {
    let store = TokenStore::load(&target.tokens_path)?;
    let Some(entry) = store.get_bound(&target.alias, &target.url, &target.username) else {
        return Ok(None);
    };
    let current = client.read().unwrap().token_snapshot();
    if current.as_deref() == Some(entry.token.as_str()) {
        return Ok(None);
    }
    client.write().unwrap().set_token(entry.token.clone());
    Ok(Some(entry.expires_at))
}

fn build_target(alias_name: &str, config_path: &Path) -> Result<TokenTarget, FuseError> {
    let config = CliConfig::load(config_path)?;
    let alias = config.get_alias(alias_name)?;
    Ok(TokenTarget {
        tokens_path: config_path.with_file_name("tokens.toml"),
        alias: alias_name.to_owned(),
        url: alias.url.clone(),
        username: alias.username.clone(),
    })
}

/// Spawn a background task that refreshes the token ~60 seconds before expiry.
/// On success the new token is installed into the shared client **and** written
/// back to the config-sibling `tokens.toml` so the CLI / `y2q logout` share the
/// live credential. On failure, re-read that store once (pick up a fresh
/// `y2q login`); if nothing usable is there, log at ERROR and stop scheduling.
pub fn spawn_token_refresh(
    rt: tokio::runtime::Handle,
    client: Arc<RwLock<Y2qClient>>,
    expires_at: u64,
    alias: String,
    config_path: PathBuf,
) {
    rt.spawn(async move {
        let target = match build_target(&alias, &config_path) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(alias = %alias, "token refresh: resolve token store: {e}");
                return;
            }
        };

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
                if let Err(e) = persist_refreshed_token(&target, &resp) {
                    tracing::error!(
                        alias = %target.alias,
                        "token refreshed in memory but failed to write tokens.toml: {e}"
                    );
                }
                client.write().unwrap().set_token(resp.token);
                tracing::info!(expires_at = resp.expires_at, "token refreshed");
                spawn_token_refresh(
                    tokio::runtime::Handle::current(),
                    client,
                    resp.expires_at,
                    target.alias,
                    config_path,
                );
            }
            Err(e) => {
                tracing::warn!(alias = %target.alias, "token refresh failed: {e}");
                match reload_token_from_store(&target, &client) {
                    Ok(Some(new_exp)) => {
                        tracing::info!(
                            alias = %target.alias,
                            expires_at = new_exp,
                            "loaded replacement token from tokens.toml after refresh failure"
                        );
                        spawn_token_refresh(
                            tokio::runtime::Handle::current(),
                            client,
                            new_exp,
                            target.alias,
                            config_path,
                        );
                    }
                    Ok(None) => {
                        tracing::error!(
                            alias = %target.alias,
                            "token refresh failed and tokens.toml has no usable replacement; \
                             remount after `y2q login {}`",
                            target.alias
                        );
                    }
                    Err(err) => {
                        tracing::error!(
                            alias = %target.alias,
                            "token refresh failed and re-reading tokens.toml failed: {err}"
                        );
                    }
                }
            }
        }
    });
}
