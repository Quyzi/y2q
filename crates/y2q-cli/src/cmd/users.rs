use y2q_client::{ClientConfig, Y2qClient};
use zeroize::Zeroizing;

use crate::cli::UserCmd;
use crate::config::{CliConfig, default_config_path, default_tokens_path};
use crate::error::CliError;
use crate::output::{OutputMode, fmt_ns, print_json, print_table};
use crate::token::TokenStore;

pub async fn run(cmd: UserCmd, mode: OutputMode) -> Result<(), CliError> {
    match cmd {
        UserCmd::Add { alias, username, password } => {
            let pw = if let Some(p) = password {
                Zeroizing::new(p)
            } else {
                Zeroizing::new(
                    rpassword::prompt_password(format!("Password for {username}: "))
                        .map_err(CliError::Io)?,
                )
            };
            let client = make_client(&alias).await?;
            client.add_user(&username, pw.as_str()).await?;
            if mode == OutputMode::Json {
                print_json(&serde_json::json!({ "created": username }));
            } else {
                println!("Created user `{username}`");
            }
        }

        UserCmd::Ls { alias } => {
            let client = make_client(&alias).await?;
            let users = client.list_users().await?;
            if mode == OutputMode::Json {
                print_json(&users);
            } else {
                let rows: Vec<Vec<String>> = users
                    .iter()
                    .map(|u| {
                        vec![
                            u.username.clone(),
                            fmt_ns(u.created_at),
                            u.last_login.map(fmt_ns).unwrap_or_else(|| "never".into()),
                        ]
                    })
                    .collect();
                print_table(&["USERNAME", "CREATED", "LAST_LOGIN"], &rows);
            }
        }

        UserCmd::Rm { alias, username } => {
            let client = make_client(&alias).await?;
            client.delete_user(&username).await?;
            if mode == OutputMode::Json {
                print_json(&serde_json::json!({ "deleted": username }));
            } else {
                println!("Deleted user `{username}`");
            }
        }
    }
    Ok(())
}

async fn make_client(alias: &str) -> Result<Y2qClient, CliError> {
    let config = CliConfig::load(&default_config_path()?)?;
    let profile = config.get_profile(alias)?;
    let store = TokenStore::load(&default_tokens_path()?)?;
    let token = store
        .token_for(alias)
        .ok_or(CliError::Client(y2q_client::ClientError::Unauthenticated))?;
    Ok(Y2qClient::new(ClientConfig { base_url: profile.url.clone(), token: Some(token) })?)
}
