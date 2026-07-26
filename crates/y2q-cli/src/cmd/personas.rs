use y2q_client::Y2qClient;

use crate::cli::PersonaCmd;
use crate::client_builder::{client_from_alias, resolve_config_path};
use crate::cmd::auth::prompt_password;
use crate::config::{CliConfig, default_tokens_path};
use crate::error::CliError;
use crate::output::{OutputMode, print_json};
use crate::token::TokenStore;

pub async fn run(cmd: PersonaCmd, mode: OutputMode) -> Result<(), CliError> {
    match cmd {
        PersonaCmd::Add {
            alias,
            slot,
            role,
            duress,
        } => {
            // Always prompted, never accepted as an argument - a duress
            // password is exactly the kind of secret that must not end up
            // in shell history or `ps`/`/proc/<pid>/cmdline`.
            let pw = prompt_password(&format!("New password for persona slot {slot}: "))?;
            let client = make_client(&alias).await?;
            let resp = crate::ops::personas::add(&client, slot, pw.as_str(), role.as_deref(), duress).await?;
            if mode == OutputMode::Json {
                print_json(&serde_json::json!({ "slot": slot, "warning": resp.warning }));
            } else {
                println!("Persona slot {slot} written. {}", resp.warning);
            }
        }

        PersonaCmd::Rm { alias, slot } => {
            let client = make_client(&alias).await?;
            crate::ops::personas::remove(&client, slot).await?;
            if mode == OutputMode::Json {
                print_json(&serde_json::json!({ "removed_slot": slot }));
            } else {
                println!("Persona slot {slot} overwritten with a decoy.");
            }
        }

        PersonaCmd::Whoami { alias } => {
            let client = make_client(&alias).await?;
            let view = crate::ops::personas::whoami(&client).await?;
            if mode == OutputMode::Json {
                print_json(&view);
            } else {
                println!(
                    "slot: {}\nrole: {}\nrevoke_other_sessions: {}",
                    view.slot, view.role, view.revoke_other_sessions
                );
            }
        }

        PersonaCmd::Grant {
            alias,
            slot,
            buckets,
        } => {
            let client = make_client(&alias).await?;
            crate::ops::personas::grant(&client, slot, &buckets).await?;
            if mode == OutputMode::Json {
                print_json(&serde_json::json!({ "granted_slot": slot, "buckets": buckets }));
            } else {
                println!("Shared {} bucket(s) with persona slot {slot}.", buckets.len());
            }
        }

        PersonaCmd::Revoke {
            alias,
            slot,
            buckets,
        } => {
            let client = make_client(&alias).await?;
            crate::ops::personas::revoke(&client, slot, &buckets).await?;
            if mode == OutputMode::Json {
                print_json(&serde_json::json!({ "revoked_slot": slot, "buckets": buckets }));
            } else {
                println!("Revoked {} bucket(s) from persona slot {slot}.", buckets.len());
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
