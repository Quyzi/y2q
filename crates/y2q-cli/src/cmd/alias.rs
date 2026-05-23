use std::io::Read;

use crate::cli::AliasCmd;
use crate::client_builder::resolve_config_path;
use crate::config::{Alias, CliConfig};
use crate::error::CliError;
use crate::output::{OutputMode, print_json, print_table};

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
            config.add_alias(alias.clone(), entry);
            config.save(&config_path)?;
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
            let incoming = imported.aliases.into_iter().chain(imported.profiles);
            let mut added = 0usize;
            for (name, entry) in incoming {
                if !merge && config.aliases.contains_key(&name) {
                    continue;
                }
                config.aliases.insert(name, entry);
                added += 1;
            }
            config.save(&config_path)?;
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
