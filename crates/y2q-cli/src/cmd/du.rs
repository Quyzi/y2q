//! `du` — disk usage summary across a remote prefix.
//!
//! Lists objects under the given path and prints total size + count.
//! `--depth N` groups results by the first N path segments after the prefix.

use std::collections::BTreeMap;

use y2q_client::ListOptions;

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
            let buckets = client.list_buckets().await?;
            let mut rows: Vec<Vec<String>> = Vec::new();
            let mut json_rows: Vec<serde_json::Value> = Vec::new();
            for b in &buckets {
                let (bytes, count) = sum_prefix(&client, b, None).await?;
                rows.push(vec![
                    fmt_bytes(bytes),
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
        sum_with_grouping(&client, bucket, prefix, depth.unwrap_or(0)).await?;

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

async fn sum_prefix(
    client: &y2q_client::Y2qClient,
    bucket: &str,
    prefix: Option<&str>,
) -> Result<(u64, u64), CliError> {
    let mut total = 0u64;
    let mut count = 0u64;
    let mut after: Option<String> = None;
    loop {
        let page = client
            .list_objects(
                bucket,
                &ListOptions {
                    prefix: prefix.map(str::to_owned),
                    after: after.clone(),
                    limit: Some(1000),
                },
            )
            .await?;
        for item in &page.items {
            total += item.size;
            count += 1;
        }
        match page.next {
            Some(c) => after = Some(c),
            None => break,
        }
    }
    Ok((total, count))
}

#[allow(clippy::type_complexity)]
async fn sum_with_grouping(
    client: &y2q_client::Y2qClient,
    bucket: &str,
    prefix: Option<&str>,
    depth: u32,
) -> Result<(u64, u64, BTreeMap<String, (u64, u64)>), CliError> {
    let mut total = 0u64;
    let mut count = 0u64;
    let mut groups: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut after: Option<String> = None;
    let prefix_trim = prefix.map(|p| p.trim_end_matches('/').to_owned());

    loop {
        let page = client
            .list_objects(
                bucket,
                &ListOptions {
                    prefix: prefix.map(str::to_owned),
                    after: after.clone(),
                    limit: Some(1000),
                },
            )
            .await?;
        for item in &page.items {
            total += item.size;
            count += 1;
            if depth > 0 {
                let relative = match &prefix_trim {
                    Some(p) if !p.is_empty() => item.key.strip_prefix(p).unwrap_or(&item.key),
                    _ => &item.key,
                };
                let relative = relative.trim_start_matches('/');
                let group = relative
                    .split('/')
                    .take(depth as usize)
                    .collect::<Vec<_>>()
                    .join("/");
                let entry = groups.entry(group).or_insert((0, 0));
                entry.0 += item.size;
                entry.1 += 1;
            }
        }
        match page.next {
            Some(c) => after = Some(c),
            None => break,
        }
    }
    Ok((total, count, groups))
}
