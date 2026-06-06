//! `y2q admin acl …` — inspect and edit per-bucket ownership and grants.

use y2q_client::{AclBody, Y2qClient};

use crate::cli::AclCmd;
use crate::client_builder::{client_from_alias, resolve_config_path};
use crate::config::{CliConfig, default_tokens_path};
use crate::error::CliError;
use crate::output::{OutputMode, print_json, print_table};
use crate::token::TokenStore;

pub async fn run(cmd: AclCmd, mode: OutputMode) -> Result<(), CliError> {
    match cmd {
        AclCmd::Get { alias, bucket } => {
            let client = make_client(&alias).await?;
            let acl = crate::ops::admin::acl_show(&client, &bucket).await?;
            output(&acl, mode);
        }
        AclCmd::Grant {
            alias,
            bucket,
            username,
            permission,
        } => {
            let client = make_client(&alias).await?;
            let acl =
                crate::ops::admin::acl_grant(&client, &bucket, &username, &permission).await?;
            output(&acl, mode);
        }
        AclCmd::Revoke {
            alias,
            bucket,
            username,
        } => {
            let client = make_client(&alias).await?;
            let acl = crate::ops::admin::acl_revoke(&client, &bucket, &username).await?;
            output(&acl, mode);
        }
        AclCmd::Chown {
            alias,
            bucket,
            username,
        } => {
            let client = make_client(&alias).await?;
            let acl = crate::ops::admin::acl_chown(&client, &bucket, &username).await?;
            output(&acl, mode);
        }
    }
    Ok(())
}

fn output(acl: &AclBody, mode: OutputMode) {
    if mode == OutputMode::Json {
        print_json(acl);
        return;
    }
    println!("owner: {}", acl.owner.as_deref().unwrap_or("(none)"));
    if acl.grants.is_empty() {
        println!("grants: (none)");
    } else {
        let rows: Vec<Vec<String>> = acl
            .grants
            .iter()
            .map(|(u, p)| vec![u.clone(), p.clone()])
            .collect();
        print_table(&["USER", "PERMISSION"], &rows);
    }
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
