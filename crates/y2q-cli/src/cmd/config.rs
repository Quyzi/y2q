use crate::cli::ConfigCmd;
use crate::config::{CliConfig, Profile, default_config_path};
use crate::error::CliError;
use crate::output::{OutputMode, print_json, print_table};

pub async fn run(cmd: ConfigCmd, mode: OutputMode) -> Result<(), CliError> {
    let config_path = default_config_path()?;
    let mut config = CliConfig::load(&config_path)?;

    match cmd {
        ConfigCmd::Add {
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
            let profile = Profile {
                url: url.clone(),
                username: username.clone(),
                password: None,
                insecure,
                ca_cert_path: ca_cert.map(|p| p.to_string_lossy().into_owned()),
                client_cert_path: client_cert.map(|p| p.to_string_lossy().into_owned()),
                client_key_path: client_key.map(|p| p.to_string_lossy().into_owned()),
            };
            config.add_profile(alias.clone(), profile);
            config.save(&config_path)?;
            if mode == OutputMode::Json {
                print_json(
                    &serde_json::json!({ "alias": alias, "url": url, "username": username }),
                );
            } else {
                println!("Added profile `{alias}`  →  {url}  (user: {username})");
                println!("Tip: to log in, run: y2q login {alias}");
            }
        }

        ConfigCmd::Ls => {
            if mode == OutputMode::Json {
                let v: Vec<_> = config
                    .profiles
                    .iter()
                    .map(|(alias, p)| {
                        serde_json::json!({ "alias": alias, "url": p.url, "username": p.username })
                    })
                    .collect();
                print_json(&v);
            } else if config.profiles.is_empty() {
                println!("No profiles configured. Add one with: y2q config add <alias> <url>");
            } else {
                let rows: Vec<Vec<String>> = config
                    .profiles
                    .iter()
                    .map(|(alias, p)| vec![alias.clone(), p.url.clone(), p.username.clone()])
                    .collect();
                print_table(&["ALIAS", "URL", "USERNAME"], &rows);
            }
        }

        ConfigCmd::Rm { alias } => {
            if config.remove_profile(&alias) {
                config.save(&config_path)?;
                if mode == OutputMode::Json {
                    print_json(&serde_json::json!({ "removed": alias }));
                } else {
                    println!("Removed profile `{alias}`");
                }
            } else if mode == OutputMode::Json {
                print_json(&serde_json::json!({ "error": format!("unknown alias `{alias}`") }));
            } else {
                eprintln!("Unknown alias `{alias}`");
            }
        }
    }
    Ok(())
}
