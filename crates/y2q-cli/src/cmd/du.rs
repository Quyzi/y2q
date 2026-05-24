//! `du` — disk usage summary across a remote prefix.
//!
//! Lists objects under the given path and prints total size + count.
//! `--depth N` groups results by the first N path segments after the prefix.

use crate::cmd::objects::make_client;
use crate::error::CliError;
use crate::output::{OutputMode, fmt_bytes, print_json, print_table};
use crate::path::RemotePath;

pub async fn run(path: String, depth: Option<u32>, mode: OutputMode) -> Result<(), CliError> {
    let remote = RemotePath::parse(&path)?;
    let client = make_client(&remote.alias).await?;

    let bucket = match remote.bucket.as_deref() {
        Some(b) => b,
        None => {
            // No bucket given: summarize every bucket on the alias.
            let summary = crate::ops::listing::du_buckets(&client).await?;
            let mut rows: Vec<Vec<String>> = Vec::new();
            let mut json_rows: Vec<serde_json::Value> = Vec::new();
            for (b, bytes, count) in &summary {
                rows.push(vec![
                    fmt_bytes(*bytes),
                    count.to_string(),
                    format!("{}/{b}/", remote.alias),
                ]);
                json_rows.push(serde_json::json!({
                    "path": format!("{}/{b}/", remote.alias),
                    "bytes": bytes,
                    "count": count,
                }));
            }
            if mode == OutputMode::Json {
                print_json(&json_rows);
            } else {
                print_table(&["SIZE", "OBJECTS", "PATH"], &rows);
            }
            return Ok(());
        }
    };

    let prefix = remote.key.as_deref();
    let (bytes, count, grouped) =
        crate::ops::listing::du(&client, bucket, prefix, depth.unwrap_or(0)).await?;

    if mode == OutputMode::Json {
        let entries: Vec<_> = grouped
            .iter()
            .map(|(group, (b, c))| {
                serde_json::json!({
                    "path": format!("{}/{bucket}/{}", remote.alias, group),
                    "bytes": b,
                    "count": c,
                })
            })
            .collect();
        print_json(&serde_json::json!({
            "path": path,
            "bytes": bytes,
            "count": count,
            "entries": entries,
        }));
    } else {
        if !grouped.is_empty() {
            let rows: Vec<Vec<String>> = grouped
                .iter()
                .map(|(group, (b, c))| {
                    vec![
                        fmt_bytes(*b),
                        c.to_string(),
                        format!("{}/{bucket}/{}", remote.alias, group),
                    ]
                })
                .collect();
            print_table(&["SIZE", "OBJECTS", "PATH"], &rows);
        }
        println!(
            "Total: {} across {count} object(s) in {path}",
            fmt_bytes(bytes)
        );
    }
    Ok(())
}
