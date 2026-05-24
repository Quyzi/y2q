use zeroize::Zeroizing;

use crate::client_builder::{client_from_alias, resolve_config_path};
use crate::config::{CliConfig, default_tokens_path};
use crate::error::CliError;
use crate::output::{OutputMode, print_json};
use crate::token::{TokenEntry, TokenStore};

fn prompt_password(prompt: &str) -> Result<Zeroizing<String>, CliError> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(CliError::Io)
}

pub async fn login(
    alias: &str,
    user: Option<String>,
    password: Option<String>,
    ttl: Option<u64>,
    mode: OutputMode,
) -> Result<(), CliError> {
    let config_path = resolve_config_path()?;
    let tokens_path = default_tokens_path()?;
    let config = CliConfig::load(&config_path)?;
    let entry = config.get_alias(alias)?;

    let username = user
        .or_else(|| Some(entry.username.clone()))
        .unwrap_or_default();

    let pw = if let Some(p) = password {
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
    };
    let mut store = TokenStore::load(&tokens_path)?;
    store.set(alias, token_entry.clone());
    store.save(&tokens_path)?;

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
    let tokens_path = default_tokens_path()?;
    let config = CliConfig::load(&config_path)?;
    let entry = config.get_alias(alias)?;

    let mut store = TokenStore::load(&tokens_path)?;
    if let Some(tok) = store.get_valid(alias) {
        let client = client_from_alias(entry, Some(Zeroizing::new(tok.token.clone())))?;
        let _ = crate::ops::auth::logout(&client).await;
    }
    store.clear(alias);
    store.save(&tokens_path)?;

    if mode == OutputMode::Json {
        print_json(&serde_json::json!({ "alias": alias, "logged_out": true }));
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
    let tokens_path = default_tokens_path()?;
    let config = CliConfig::load(&config_path)?;
    let entry = config.get_alias(alias)?;
    let store = TokenStore::load(&tokens_path)?;

    let token = store
        .token_for(alias)
        .ok_or_else(|| CliError::Client(y2q_client::ClientError::Unauthenticated))?;

    let current_pw = if let Some(p) = current {
        Zeroizing::new(p)
    } else {
        prompt_password("Current password: ")?
    };
    let new_pw = if let Some(p) = new {
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
