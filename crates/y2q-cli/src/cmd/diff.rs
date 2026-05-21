//! `diff` — compare two trees (local or remote) and report what differs.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use y2q_client::ListOptions;

use crate::cmd::objects::make_client;
use crate::error::CliError;
use crate::output::{OutputMode, fmt_bytes, print_json};
use crate::path::{CpEndpoint, RemotePath};

#[derive(Debug, Clone)]
struct Entry {
    size: u64,
    checksum: Option<String>,
}

type Entries = BTreeMap<String, Entry>;

#[derive(Debug, serde::Serialize)]
struct DiffRow {
    op: &'static str,
    key: String,
    src_size: Option<u64>,
    dst_size: Option<u64>,
}

pub async fn run(src: String, dst: String, mode: OutputMode) -> Result<(), CliError> {
    let src_ep = CpEndpoint::parse(&src);
    let dst_ep = CpEndpoint::parse(&dst);

    let src_entries = collect(&src_ep).await?;
    let dst_entries = collect(&dst_ep).await?;

    let mut rows: Vec<DiffRow> = Vec::new();
    for (key, s) in &src_entries {
        match dst_entries.get(key) {
            Some(d) if d.size != s.size => rows.push(DiffRow {
                op: "!",
                key: key.clone(),
                src_size: Some(s.size),
                dst_size: Some(d.size),
            }),
            Some(d) if s.checksum.is_some() && d.checksum.is_some() && s.checksum != d.checksum => {
                rows.push(DiffRow {
                    op: "!",
                    key: key.clone(),
                    src_size: Some(s.size),
                    dst_size: Some(d.size),
                });
            }
            Some(_) => {}
            None => rows.push(DiffRow {
                op: "<",
                key: key.clone(),
                src_size: Some(s.size),
                dst_size: None,
            }),
        }
    }
    for (key, d) in &dst_entries {
        if !src_entries.contains_key(key) {
            rows.push(DiffRow {
                op: ">",
                key: key.clone(),
                src_size: None,
                dst_size: Some(d.size),
            });
        }
    }
    rows.sort_by(|a, b| a.key.cmp(&b.key));

    if mode == OutputMode::Json {
        print_json(&serde_json::json!({
            "src": src,
            "dst": dst,
            "diffs": rows,
        }));
    } else if rows.is_empty() {
        println!("No differences.");
    } else {
        for r in &rows {
            let (s, d) = (
                r.src_size.map(fmt_bytes).unwrap_or_else(|| "-".into()),
                r.dst_size.map(fmt_bytes).unwrap_or_else(|| "-".into()),
            );
            println!("{:1}  {:>10}  {:>10}  {}", r.op, s, d, r.key);
        }
        println!(
            "\n{} difference(s) — `<` only in src, `>` only in dst, `!` differs.",
            rows.len()
        );
    }
    Ok(())
}

async fn collect(ep: &CpEndpoint) -> Result<Entries, CliError> {
    match ep {
        CpEndpoint::Local(path) => collect_local(Path::new(path)),
        CpEndpoint::Remote(remote) => collect_remote(remote).await,
    }
}

fn collect_local(root: &Path) -> Result<Entries, CliError> {
    let mut entries: Entries = BTreeMap::new();
    if !root.exists() {
        return Ok(entries);
    }
    if root.is_file() {
        let meta = std::fs::metadata(root)?;
        let key = root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        entries.insert(
            key,
            Entry {
                size: meta.len(),
                checksum: None,
            },
        );
        return Ok(entries);
    }
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let rel: PathBuf = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_owned();
        let key = rel.to_string_lossy().replace('\\', "/");
        let meta = entry
            .metadata()
            .map_err(|e| CliError::Other(format!("metadata: {e}")))?;
        entries.insert(
            key,
            Entry {
                size: meta.len(),
                checksum: None,
            },
        );
    }
    Ok(entries)
}

async fn collect_remote(remote: &RemotePath) -> Result<Entries, CliError> {
    let bucket = remote.bucket.as_deref().ok_or_else(|| {
        CliError::InvalidPath(format!("{}/", remote.alias), "missing bucket".into())
    })?;
    let client = make_client(&remote.alias).await?;
    let prefix = remote.key.clone();
    let prefix_trim = prefix
        .as_deref()
        .map(|p| p.trim_end_matches('/').to_owned());
    let mut entries: Entries = BTreeMap::new();
    let mut after: Option<String> = None;
    loop {
        let page = client
            .list_objects(
                bucket,
                &ListOptions {
                    prefix: prefix.clone(),
                    after: after.clone(),
                    limit: Some(1000),
                },
            )
            .await?;
        for item in page.items {
            let key = match &prefix_trim {
                Some(p) if !p.is_empty() => item
                    .key
                    .strip_prefix(p)
                    .map(|s| s.trim_start_matches('/').to_owned())
                    .unwrap_or(item.key.clone()),
                _ => item.key.clone(),
            };
            entries.insert(
                key,
                Entry {
                    size: item.size,
                    checksum: if item.checksum_gxhash.is_empty() {
                        None
                    } else {
                        Some(item.checksum_gxhash)
                    },
                },
            );
        }
        match page.next {
            Some(c) => after = Some(c),
            None => break,
        }
    }
    Ok(entries)
}
