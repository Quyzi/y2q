use zeroize::Zeroizing;

use crate::client_builder::{client_from_alias, resolve_config_path, resolve_tokens_path};
use crate::config::CliConfig;
use crate::error::CliError;
use crate::output::{OutputMode, print_json};
use crate::token::{TokenEntry, TokenStore};

pub(crate) fn prompt_password(prompt: &str) -> Result<Zeroizing<String>, CliError> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(CliError::Io)
}

/// A password on the command line is visible to any local user via `ps`/
/// `/proc/<pid>/cmdline`, and typically persists in shell history. Omit the
/// flag to use the interactive (non-echoing) prompt instead. Written with
/// `eprintln!`, not `tracing`, so `-q`/`RUST_LOG` cannot suppress it.
pub(crate) fn warn_password_on_cli_flag() {
    eprintln!(
        "warning: a password was passed on the command line; it is visible to other local \
         users (via `ps`/`/proc`) and may be saved in shell history. Omit the flag to be \
         prompted interactively instead."
    );
}

pub async fn login(
    alias: &str,
    user: Option<String>,
    password: Option<String>,
    ttl: Option<u64>,
    mode: OutputMode,
) -> Result<(), CliError> {
    let config_path = resolve_config_path()?;
    let tokens_path = resolve_tokens_path()?;
    let config = CliConfig::load(&config_path)?;
    let entry = config.get_alias(alias)?;

    let username = user
        .or_else(|| Some(entry.username.clone()))
        .unwrap_or_default();

    let pw = if let Some(p) = password {
        warn_password_on_cli_flag();
        Zeroizing::new(p)
    } else if let Some(ref p) = entry.password {
        Zeroizing::new(p.clone())
    } else {
        prompt_password(&format!("Password for {username}@{alias}: "))?
    };

    let client = client_from_alias(entry, None)?;
    let token_resp = crate::ops::auth::login(&client, &username, pw.as_str(), ttl).await?;

    let token_entry = TokenEntry {
        token: token_resp.token,
        expires_at: token_resp.expires_at,
        username: token_resp.username.clone(),
        url: entry.url.clone(),
    };
    TokenStore::update(&tokens_path, |store| {
        store.set(alias, token_entry.clone());
        Ok(())
    })?;

    if mode == OutputMode::Json {
        print_json(&serde_json::json!({
            "alias": alias,
            "username": token_entry.username,
            "expires_at": token_entry.expires_at,
        }));
    } else {
        let secs_left = token_entry.expires_at.saturating_sub(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        println!(
            "Logged in as {} (token expires in {}s)",
            token_entry.username, secs_left
        );
    }
    Ok(())
}

pub async fn logout(alias: &str, mode: OutputMode) -> Result<(), CliError> {
    let config_path = resolve_config_path()?;
    let tokens_path = resolve_tokens_path()?;
    let config = CliConfig::load(&config_path)?;
    let entry = config.get_alias(alias)?;

    let mut revoke_failed: Option<String> = None;
    // Snapshot under the lock, attempt revoke outside it, then clear under
    // the lock so a concurrent login cannot resurrect a just-cleared token.
    let cached = {
        let store = TokenStore::load(&tokens_path)?;
        store
            .get_bound(alias, &entry.url, &entry.username)
            .or_else(|| store.get_valid(alias))
            .map(|t| t.token.clone())
    };
    if let Some(tok) = cached {
        // Best effort: an alias whose URL/TLS config is unusable must still be
        // able to drop its cached token locally.
        match client_from_alias(entry, Some(Zeroizing::new(tok))) {
            Ok(client) => {
                if let Err(e) = crate::ops::auth::logout(&client).await {
                    revoke_failed = Some(e.to_string());
                }
            }
            Err(e) => {
                revoke_failed = Some(format!("cannot reach `{alias}` ({e})"));
            }
        }
    }
    TokenStore::update(&tokens_path, |store| {
        store.clear(alias);
        Ok(())
    })?;

    if let Some(reason) = revoke_failed.as_ref() {
        eprintln!(
            "warning: {reason}; removed the local token but the server session may still be live"
        );
    }

    if mode == OutputMode::Json {
        print_json(&serde_json::json!({
            "alias": alias,
            "logged_out": true,
            "server_revoke_ok": revoke_failed.is_none(),
        }));
    } else {
        println!("Logged out of `{alias}`");
    }
    Ok(())
}

pub async fn passwd(
    alias: &str,
    current: Option<String>,
    new: Option<String>,
    mode: OutputMode,
) -> Result<(), CliError> {
    let config_path = resolve_config_path()?;
    let tokens_path = resolve_tokens_path()?;
    let config = CliConfig::load(&config_path)?;
    let entry = config.get_alias(alias)?;
    let store = TokenStore::load(&tokens_path)?;

    let token = store
        .token_for_bound(alias, &entry.url, &entry.username)
        .ok_or_else(|| CliError::Client(y2q_client::ClientError::Unauthenticated))?;

    let current_pw = if let Some(p) = current {
        warn_password_on_cli_flag();
        Zeroizing::new(p)
    } else {
        prompt_password("Current password: ")?
    };
    let new_pw = if let Some(p) = new {
        warn_password_on_cli_flag();
        Zeroizing::new(p)
    } else {
        prompt_password("New password: ")?
    };

    let client = client_from_alias(entry, Some(token))?;
    crate::ops::auth::change_password(&client, current_pw.as_str(), new_pw.as_str()).await?;

    if mode == OutputMode::Json {
        print_json(&serde_json::json!({ "alias": alias, "changed": true }));
    } else {
        println!("Password changed for `{alias}`");
    }
    Ok(())
}
