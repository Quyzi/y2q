use futures::StreamExt;
use y2q_client::{ClientConfig, Y2qClient};

use crate::cli::{LocksCmd, RebuildCmd};
use crate::config::{CliConfig, default_config_path, default_tokens_path};
use crate::error::CliError;
use crate::output::{OutputMode, fmt_bytes, print_json, print_table};
use crate::token::TokenStore;

pub async fn rebuild(cmd: RebuildCmd, mode: OutputMode) -> Result<(), CliError> {
    match cmd {
        RebuildCmd::Start { alias } => {
            let client = make_client(&alias).await?;
            client.rebuild_start().await?;
            if mode == OutputMode::Json {
                print_json(&serde_json::json!({ "status": "running" }));
            } else {
                println!("Rebuild started on `{alias}`");
            }
        }
        RebuildCmd::Status { alias } => {
            let client = make_client(&alias).await?;
            let status = client.rebuild_status().await?;
            if mode == OutputMode::Json {
                print_json(&serde_json::json!({
                    "state": status.state,
                    "percent": status.percent,
                    "reason": status.reason,
                }));
            } else {
                let desc = match status.state.as_str() {
                    "running" => format!("running ({}%)", status.percent.unwrap_or(0)),
                    "failed" => {
                        format!("failed: {}", status.reason.as_deref().unwrap_or("unknown"))
                    }
                    s => s.to_owned(),
                };
                println!("Rebuild [{alias}]: {desc}");
            }
        }
    }
    Ok(())
}

pub async fn locks(cmd: LocksCmd, mode: OutputMode) -> Result<(), CliError> {
    match cmd {
        LocksCmd::Ls { alias, older_than } => {
            let client = make_client(&alias).await?;
            let locks = client.locks_list(&older_than).await?;
            if mode == OutputMode::Json {
                print_json(&locks);
            } else if locks.is_empty() {
                println!("No stale locks found");
            } else {
                let rows: Vec<Vec<String>> = locks
                    .iter()
                    .map(|l| {
                        vec![
                            l.bucket.clone(),
                            l.uuid[..8.min(l.uuid.len())].to_owned(),
                            format!("{}s", l.age_seconds),
                        ]
                    })
                    .collect();
                print_table(&["BUCKET", "UUID", "AGE"], &rows);
            }
        }
        LocksCmd::Clear { alias, older_than } => {
            let client = make_client(&alias).await?;
            let removed = client.locks_clear(&older_than).await?;
            if mode == OutputMode::Json {
                print_json(&serde_json::json!({ "removed": removed }));
            } else {
                println!("Cleared {removed} stale lock(s) on `{alias}`");
            }
        }
    }
    Ok(())
}

pub async fn trace(alias: &str, errors_only: bool) -> Result<(), CliError> {
    let client = make_client(alias).await?;
    let mut stream = client.connect_trace().await?;
    eprintln!("Streaming trace from `{alias}` — Ctrl-C to stop");
    while let Some(event) = stream.next().await {
        if errors_only && event.status < 400 {
            continue;
        }
        let ts = format_trace_ts(event.timestamp_ns);
        let (color, reset) = ansi_status(event.status);
        let rb = event.req_bytes.map(fmt_bytes).unwrap_or_else(|| "—".into());
        let db = event
            .resp_bytes
            .map(fmt_bytes)
            .unwrap_or_else(|| "—".into());
        println!(
            "{ts}  {m:<7}  {p:<40}  {color}{s:>3}{reset}  {lat:>8.1}ms  {rb:>9}\u{2191}  {db:>9}\u{2193}",
            m = event.method,
            p = event.path,
            s = event.status,
            lat = event.latency_ms,
        );
    }
    Ok(())
}

fn format_trace_ts(ns: u64) -> String {
    use chrono::{DateTime, Utc};
    DateTime::<Utc>::from_timestamp_nanos(ns as i64)
        .format("%H:%M:%S%.3f")
        .to_string()
}

fn ansi_status(status: u16) -> (&'static str, &'static str) {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        return ("", "");
    }
    match status {
        200..=299 => ("\x1b[32m", "\x1b[0m"),
        300..=399 => ("\x1b[36m", "\x1b[0m"),
        400..=499 => ("\x1b[33m", "\x1b[0m"),
        _ => ("\x1b[31m", "\x1b[0m"),
    }
}

async fn make_client(alias: &str) -> Result<Y2qClient, CliError> {
    let config = CliConfig::load(&default_config_path()?)?;
    let profile = config.get_profile(alias)?;
    let store = TokenStore::load(&default_tokens_path()?)?;
    let token = store
        .token_for(alias)
        .ok_or(CliError::Client(y2q_client::ClientError::Unauthenticated))?;
    Ok(Y2qClient::new(ClientConfig {
        base_url: profile.url.clone(),
        token: Some(token),
    })?)
}
