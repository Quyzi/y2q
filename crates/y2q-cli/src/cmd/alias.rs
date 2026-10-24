use std::io::Read;

use y2q_client::ClientError;

use crate::cli::AliasCmd;
use crate::client_builder::{resolve_config_path, resolve_tokens_path};
use crate::config::{Alias, CliConfig};
use crate::error::CliError;
use crate::output::{OutputMode, print_json, print_table};
use crate::token::TokenStore;

pub async fn run(cmd: AliasCmd, mode: OutputMode) -> Result<(), CliError> {
    let config_path = resolve_config_path()?;
    let mut config = CliConfig::load(&config_path)?;

    match cmd {
        AliasCmd::Set {
            alias,
            url,
            user,
            insecure,
            ca_cert,
            client_cert,
            client_key,
        } => {
            // Before the username prompt: a bad URL must fail without asking anything.
            y2q_client::validate_base_url(&url)?;
            let username = match user {
                Some(u) => u,
                None => {
                    eprint!("Username: ");
                    let mut buf = String::new();
                    std::io::stdin().read_line(&mut buf)?;
                    buf.trim().to_owned()
                }
            };
            let entry = Alias {
                url: url.clone(),
                username: username.clone(),
                password: None,
                insecure,
                ca_cert_path: ca_cert.map(|p| p.to_string_lossy().into_owned()),
                client_cert_path: client_cert.map(|p| p.to_string_lossy().into_owned()),
                client_key_path: client_key.map(|p| p.to_string_lossy().into_owned()),
            };
            // Any change to url/username (or a fresh alias) must drop a cached
            // bearer keyed by this name — otherwise the next command would send
            // the old session to the new URL.
            let previous = config.aliases.get(&alias).cloned();
            let rebound = previous
                .as_ref()
                .is_none_or(|p| p.url != entry.url || p.username != entry.username);
            config.add_alias(alias.clone(), entry);
            config.save(&config_path)?;
            if rebound {
                let tokens_path = resolve_tokens_path()?;
                let _ = TokenStore::update(&tokens_path, |store| {
                    store.clear(&alias);
                    Ok(())
                });
            }
            if mode == OutputMode::Json {
                print_json(
                    &serde_json::json!({ "alias": alias, "url": url, "username": username }),
                );
            } else {
                println!("Added alias `{alias}`  ->  {url}  (user: {username})");
                println!("Tip: to log in, run: y2q login {alias}");
            }
        }

        AliasCmd::List => {
            if mode == OutputMode::Json {
                let v: Vec<_> = config
                    .aliases
                    .iter()
                    .map(|(alias, p)| {
                        serde_json::json!({ "alias": alias, "url": p.url, "username": p.username })
                    })
                    .collect();
                print_json(&v);
            } else if config.aliases.is_empty() {
                println!("No aliases configured. Add one with: y2q alias set <alias> <url>");
            } else {
                let rows: Vec<Vec<String>> = config
                    .aliases
                    .iter()
                    .map(|(alias, p)| vec![alias.clone(), p.url.clone(), p.username.clone()])
                    .collect();
                print_table(&["ALIAS", "URL", "USERNAME"], &rows);
            }
        }

        AliasCmd::Remove { alias } => {
            if config.remove_alias(&alias) {
                config.save(&config_path)?;
                let tokens_path = resolve_tokens_path()?;
                let _ = TokenStore::update(&tokens_path, |store| {
                    store.clear(&alias);
                    Ok(())
                });
                if mode == OutputMode::Json {
                    print_json(&serde_json::json!({ "removed": alias }));
                } else {
                    println!("Removed alias `{alias}`");
                }
            } else if mode == OutputMode::Json {
                print_json(&serde_json::json!({ "error": format!("unknown alias `{alias}`") }));
            } else {
                eprintln!("Unknown alias `{alias}`");
            }
        }

        AliasCmd::Export => {
            let text = toml::to_string_pretty(&config)
                .map_err(|e| CliError::Other(format!("export serialize: {e}")))?;
            print!("{text}");
        }

        AliasCmd::Import { merge } => {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            #[derive(serde::Deserialize)]
            struct Imported {
                #[serde(default)]
                aliases: indexmap::IndexMap<String, Alias>,
                #[serde(default)]
                profiles: indexmap::IndexMap<String, Alias>,
            }
            let imported: Imported =
                toml::from_str(&buf).map_err(|e| CliError::Other(format!("import parse: {e}")))?;
            let incoming: Vec<_> = imported
                .aliases
                .into_iter()
                .chain(imported.profiles)
                .collect();
            // All-or-nothing: every entry in the file must be valid, including
            // ones the non-`--merge` path would skip because the name already
            // exists, before anything is written to disk.
            for (name, entry) in &incoming {
                if let Err(ClientError::BadRequest { message }) =
                    y2q_client::validate_base_url(&entry.url)
                {
                    return Err(ClientError::BadRequest {
                        message: format!("alias `{name}`: {message}; nothing was imported"),
                    }
                    .into());
                }
            }
            let mut added = 0usize;
            let mut cleared: Vec<String> = Vec::new();
            for (name, entry) in incoming {
                if !merge && config.aliases.contains_key(&name) {
                    continue;
                }
                let rebound = config
                    .aliases
                    .get(&name)
                    .is_none_or(|p| p.url != entry.url || p.username != entry.username);
                if rebound {
                    cleared.push(name.clone());
                }
                config.aliases.insert(name, entry);
                added += 1;
            }
            config.save(&config_path)?;
            if !cleared.is_empty() {
                let tokens_path = resolve_tokens_path()?;
                let _ = TokenStore::update(&tokens_path, |store| {
                    for name in &cleared {
                        store.clear(name);
                    }
                    Ok(())
                });
            }
            if mode == OutputMode::Json {
                print_json(&serde_json::json!({ "imported": added }));
            } else {
                let suffix = if added == 1 { "y" } else { "ies" };
                println!("Imported {added} alias entr{suffix}");
            }
        }
    }
    Ok(())
}
