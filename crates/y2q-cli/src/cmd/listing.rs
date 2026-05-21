use serde_json::json;
use y2q_client::ListOptions;

use crate::client_builder::client_from_alias;
use crate::config::{CliConfig, default_config_path, default_tokens_path};
use crate::error::CliError;
use crate::output::{OutputMode, fmt_bytes, fmt_ns, print_json, print_table};
use crate::path::RemotePath;
use crate::token::TokenStore;

pub async fn run(
    path: Option<String>,
    limit: Option<u32>,
    after: Option<String>,
    all: bool,
    mode: OutputMode,
) -> Result<(), CliError> {
    let config_path = default_config_path()?;
    let tokens_path = default_tokens_path()?;
    let config = CliConfig::load(&config_path)?;
    let store = TokenStore::load(&tokens_path)?;

    match path {
        None => {
            // No path: list all known aliases and note they need to be browsed individually
            if mode == OutputMode::Json {
                let names: Vec<_> = config.aliases.keys().collect();
                print_json(&names);
            } else {
                println!("Configured aliases:");
                for alias in config.aliases.keys() {
                    println!("  {alias}/");
                }
                println!("\nTo list buckets: y2q ls <alias>/");
            }
        }
        Some(ref p) => {
            let remote = RemotePath::parse(p)?;
            let entry = config.get_alias(&remote.alias)?;
            let token = store
                .token_for(&remote.alias)
                .ok_or(CliError::Client(y2q_client::ClientError::Unauthenticated))?;
            let client = client_from_alias(entry, Some(token))?;

            if remote.bucket.is_none() {
                // list buckets for this alias
                let buckets = client.list_buckets().await?;
                if mode == OutputMode::Json {
                    print_json(&buckets);
                } else {
                    for b in &buckets {
                        println!("{}/{b}/", remote.alias);
                    }
                }
            } else {
                let bucket = remote.bucket.as_deref().unwrap();
                let prefix = remote.key.clone();
                let opts = ListOptions {
                    prefix,
                    after,
                    limit,
                };

                if all {
                    let mut cursor = None;
                    let mut all_items = vec![];
                    loop {
                        let opts_page = ListOptions {
                            prefix: opts.prefix.clone(),
                            after: cursor,
                            limit,
                        };
                        let page = client.list_objects(bucket, &opts_page).await?;
                        all_items.extend(page.items);
                        cursor = page.next;
                        if cursor.is_none() {
                            break;
                        }
                    }
                    if mode == OutputMode::Json {
                        print_json(&all_items);
                    } else {
                        let rows: Vec<Vec<String>> = all_items
                            .iter()
                            .map(|m| {
                                vec![
                                    m.key.clone(),
                                    fmt_bytes(m.size),
                                    fmt_ns(m.modified),
                                    m.checksum_gxhash.clone(),
                                ]
                            })
                            .collect();
                        print_table(&["KEY", "SIZE", "MODIFIED", "GXHASH"], &rows);
                    }
                } else {
                    let page = client.list_objects(bucket, &opts).await?;
                    if mode == OutputMode::Json {
                        print_json(&json!({ "items": page.items, "next": page.next }));
                    } else {
                        let rows: Vec<Vec<String>> = page
                            .items
                            .iter()
                            .map(|m| {
                                vec![
                                    m.key.clone(),
                                    fmt_bytes(m.size),
                                    fmt_ns(m.modified),
                                    m.checksum_gxhash.clone(),
                                ]
                            })
                            .collect();
                        print_table(&["KEY", "SIZE", "MODIFIED", "GXHASH"], &rows);
                        if let Some(ref next) = page.next {
                            println!("\n(next: {next})");
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
