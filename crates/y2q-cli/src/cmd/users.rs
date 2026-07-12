use y2q_client::Y2qClient;
use zeroize::Zeroizing;

use crate::cli::UserCmd;
use crate::client_builder::{client_from_alias, resolve_config_path};
use crate::config::{CliConfig, default_tokens_path};
use crate::error::CliError;
use crate::output::{OutputMode, fmt_ns, print_json, print_table};
use crate::token::TokenStore;

pub async fn run(cmd: UserCmd, mode: OutputMode) -> Result<(), CliError> {
    match cmd {
        UserCmd::Add {
            alias,
            username,
            password,
            role,
        } => {
            let pw = if let Some(p) = password {
                crate::cmd::auth::warn_password_on_cli_flag();
                Zeroizing::new(p)
            } else {
                Zeroizing::new(
                    rpassword::prompt_password(format!("Password for {username}: "))
                        .map_err(CliError::Io)?,
                )
            };
            let client = make_client(&alias).await?;
            crate::ops::admin::add_user(&client, &username, pw.as_str(), Some(&role)).await?;
            if mode == OutputMode::Json {
                print_json(&serde_json::json!({ "created": username, "role": role }));
            } else {
                println!("Created user `{username}` ({role})");
            }
        }

        UserCmd::List { alias } => {
            let client = make_client(&alias).await?;
            let users = crate::ops::admin::list_users(&client).await?;
            if mode == OutputMode::Json {
                print_json(&users);
            } else {
                let rows: Vec<Vec<String>> = users
                    .iter()
                    .map(|u| {
                        vec![
                            u.username.clone(),
                            if u.role.is_empty() {
                                "-".into()
                            } else {
                                u.role.clone()
                            },
                            fmt_ns(u.created_at),
                            u.last_login.map(fmt_ns).unwrap_or_else(|| "never".into()),
                        ]
                    })
                    .collect();
                print_table(&["USERNAME", "ROLE", "CREATED", "LAST_LOGIN"], &rows);
            }
        }

        UserCmd::Remove { alias, username } => {
            let client = make_client(&alias).await?;
            crate::ops::admin::delete_user(&client, &username).await?;
            if mode == OutputMode::Json {
                print_json(&serde_json::json!({ "deleted": username }));
            } else {
                println!("Deleted user `{username}`");
            }
        }

        UserCmd::Role {
            alias,
            username,
            role,
        } => {
            let client = make_client(&alias).await?;
            crate::ops::admin::set_user_role(&client, &username, &role).await?;
            if mode == OutputMode::Json {
                print_json(&serde_json::json!({ "user": username, "role": role }));
            } else {
                println!("Set role of `{username}` to {role}");
            }
        }
    }
    Ok(())
}

async fn make_client(alias: &str) -> Result<Y2qClient, CliError> {
    let config = CliConfig::load(&resolve_config_path()?)?;
    let entry = config.get_alias(alias)?;
    let store = TokenStore::load(&default_tokens_path()?)?;
    let token = store
        .token_for(alias)
        .ok_or(CliError::Client(y2q_client::ClientError::Unauthenticated))?;
    client_from_alias(entry, Some(token))
}
