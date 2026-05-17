use y2q_client::{ClientConfig, Y2qClient};
use zeroize::Zeroizing;

use crate::config::{CliConfig, default_config_path, default_tokens_path};
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
    let config_path = default_config_path()?;
    let tokens_path = default_tokens_path()?;
    let config = CliConfig::load(&config_path)?;
    let profile = config.get_profile(alias)?;

    let username = user
        .or_else(|| Some(profile.username.clone()))
        .unwrap_or_default();

    let pw = if let Some(p) = password {
        Zeroizing::new(p)
    } else if let Some(ref p) = profile.password {
        Zeroizing::new(p.clone())
    } else {
        prompt_password(&format!("Password for {username}@{alias}: "))?
    };

    let client = Y2qClient::new(ClientConfig {
        base_url: profile.url.clone(),
        token: None,
    })?;
    let token_resp = client.login(&username, pw.as_str(), ttl).await?;

    let entry = TokenEntry {
        token: token_resp.token,
        expires_at: token_resp.expires_at,
        username: token_resp.username.clone(),
    };
    let mut store = TokenStore::load(&tokens_path)?;
    store.set(alias, entry.clone());
    store.save(&tokens_path)?;

    if mode == OutputMode::Json {
        print_json(&serde_json::json!({
            "alias": alias,
            "username": entry.username,
            "expires_at": entry.expires_at,
        }));
    } else {
        let secs_left = entry.expires_at.saturating_sub(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        println!(
            "Logged in as {} (token expires in {}s)",
            entry.username, secs_left
        );
    }
    Ok(())
}

pub async fn logout(alias: &str, mode: OutputMode) -> Result<(), CliError> {
    let config_path = default_config_path()?;
    let tokens_path = default_tokens_path()?;
    let config = CliConfig::load(&config_path)?;
    let profile = config.get_profile(alias)?;

    let mut store = TokenStore::load(&tokens_path)?;
    if let Some(entry) = store.get_valid(alias) {
        let client = Y2qClient::new(ClientConfig {
            base_url: profile.url.clone(),
            token: Some(zeroize::Zeroizing::new(entry.token.clone())),
        })?;
        let _ = client.logout().await;
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
    let config_path = default_config_path()?;
    let tokens_path = default_tokens_path()?;
    let config = CliConfig::load(&config_path)?;
    let profile = config.get_profile(alias)?;
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

    let client = Y2qClient::new(ClientConfig {
        base_url: profile.url.clone(),
        token: Some(token),
    })?;
    client
        .change_password(current_pw.as_str(), new_pw.as_str())
        .await?;

    if mode == OutputMode::Json {
        print_json(&serde_json::json!({ "alias": alias, "changed": true }));
    } else {
        println!("Password changed for `{alias}`");
    }
    Ok(())
}
