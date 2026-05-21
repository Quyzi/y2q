//! `watch` — stream PUT/DELETE/HEAD/GET events for a target prefix.
//!
//! Reuses the existing trace SSE channel; filters client-side to the requested
//! bucket/prefix and event types.

use std::collections::HashSet;

use futures::StreamExt;

use crate::cmd::objects::make_client;
use crate::error::CliError;
use crate::output::{OutputMode, print_json};
use crate::path::RemotePath;

pub async fn run(path: String, events: Vec<String>, mode: OutputMode) -> Result<(), CliError> {
    let remote = RemotePath::parse(&path)?;
    let bucket = remote.bucket.as_deref();
    let prefix = remote.key.as_deref();

    let allowed: HashSet<String> = if events.is_empty() {
        ["PUT", "DELETE", "GET", "HEAD"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    } else {
        events.iter().map(|s| s.to_uppercase()).collect()
    };

    let path_filter = match (bucket, prefix) {
        (Some(b), Some(p)) => Some(format!("/{b}/{}", p.trim_start_matches('/'))),
        (Some(b), None) => Some(format!("/{b}/")),
        _ => None,
    };

    let client = make_client(&remote.alias).await?;
    let mut stream = client.connect_trace().await?;
    eprintln!("Watching `{path}` — Ctrl-C to stop");

    while let Some(event) = stream.next().await {
        if !allowed.contains(&event.method) {
            continue;
        }
        if let Some(ref f) = path_filter
            && !event.path.starts_with(f)
        {
            continue;
        }

        if mode == OutputMode::Json {
            print_json(&serde_json::json!({
                "timestamp_ns": event.timestamp_ns,
                "method": event.method,
                "path": event.path,
                "status": event.status,
                "latency_ms": event.latency_ms,
            }));
        } else {
            let ts = format_ts(event.timestamp_ns);
            println!(
                "{ts}  {m:<6}  {p:<60}  {s:>3}  {lat:>7.1}ms",
                m = event.method,
                p = event.path,
                s = event.status,
                lat = event.latency_ms,
            );
        }
    }
    Ok(())
}

fn format_ts(ns: u64) -> String {
    use chrono::{DateTime, Utc};
    DateTime::<Utc>::from_timestamp_nanos(ns as i64)
        .format("%H:%M:%S%.3f")
        .to_string()
}
