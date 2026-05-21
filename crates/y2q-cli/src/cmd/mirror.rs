//! `mirror` — rsync-style one-way sync.
//!
//! Supports local↔remote and remote↔remote sources. Copies entries from
//! `src` to `dst` when missing or differing in size; with `--remove`, also
//! deletes destinations missing from source. Client-side only — no daemon
//! changes needed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use y2q_client::{ListOptions, Y2qClient};

use crate::cmd::objects::make_client;
use crate::error::CliError;
use crate::output::{OutputMode, fmt_bytes, print_json};
use crate::path::{CpEndpoint, RemotePath};

#[derive(Clone, Debug)]
struct Entry {
    size: u64,
    checksum: Option<String>,
}

type Entries = BTreeMap<String, Entry>;

#[derive(Default, Debug)]
pub struct Options {
    pub overwrite: bool,
    pub remove: bool,
    pub exclude: Vec<String>,
}

#[derive(Default, Debug, serde::Serialize)]
pub struct MirrorStats {
    pub copied: u64,
    pub updated: u64,
    pub deleted: u64,
    pub skipped: u64,
    pub bytes: u64,
}

pub async fn run(
    src: String,
    dst: String,
    opts: Options,
    mode: OutputMode,
) -> Result<(), CliError> {
    let src_ep = CpEndpoint::parse(&src);
    let dst_ep = CpEndpoint::parse(&dst);

    if matches!(&src_ep, CpEndpoint::Local(l) if l == "-")
        || matches!(&dst_ep, CpEndpoint::Local(l) if l == "-")
    {
        return Err(CliError::Other(
            "mirror does not accept stdin/stdout".into(),
        ));
    }

    let exclude_patterns: Vec<glob::Pattern> = opts
        .exclude
        .iter()
        .map(|p| {
            glob::Pattern::new(p)
                .map_err(|e| CliError::Other(format!("invalid --exclude `{p}`: {e}")))
        })
        .collect::<Result<_, _>>()?;

    let src_entries = collect(&src_ep, &exclude_patterns).await?;
    let dst_entries = collect(&dst_ep, &exclude_patterns).await?;

    let mut stats = MirrorStats::default();

    for (key, s) in &src_entries {
        let action = match dst_entries.get(key) {
            None => "copy",
            Some(d) if d.size != s.size => "update",
            Some(d)
                if opts.overwrite
                    && s.checksum.is_some()
                    && d.checksum.is_some()
                    && s.checksum != d.checksum =>
            {
                "update"
            }
            Some(_) => {
                stats.skipped += 1;
                continue;
            }
        };

        copy_one(&src_ep, &dst_ep, key, s).await?;
        stats.bytes += s.size;
        match action {
            "copy" => stats.copied += 1,
            "update" => stats.updated += 1,
            _ => {}
        }
        if mode != OutputMode::Json {
            println!("{action:<6} {key} ({})", fmt_bytes(s.size));
        }
    }

    if opts.remove {
        for key in dst_entries.keys() {
            if src_entries.contains_key(key) {
                continue;
            }
            delete_one(&dst_ep, key).await?;
            stats.deleted += 1;
            if mode != OutputMode::Json {
                println!("delete {key}");
            }
        }
    }

    if mode == OutputMode::Json {
        print_json(&serde_json::json!({
            "src": src,
            "dst": dst,
            "stats": stats,
        }));
    } else {
        println!(
            "\nMirror summary: copied={} updated={} deleted={} skipped={} bytes={}",
            stats.copied,
            stats.updated,
            stats.deleted,
            stats.skipped,
            fmt_bytes(stats.bytes),
        );
    }
    Ok(())
}

async fn collect(ep: &CpEndpoint, excludes: &[glob::Pattern]) -> Result<Entries, CliError> {
    let entries = match ep {
        CpEndpoint::Local(path) => collect_local(Path::new(path))?,
        CpEndpoint::Remote(remote) => collect_remote(remote).await?,
    };
    if excludes.is_empty() {
        return Ok(entries);
    }
    Ok(entries
        .into_iter()
        .filter(|(k, _)| !excludes.iter().any(|p| p.matches(k)))
        .collect())
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

async fn copy_one(
    src: &CpEndpoint,
    dst: &CpEndpoint,
    key: &str,
    entry: &Entry,
) -> Result<(), CliError> {
    match (src, dst) {
        (CpEndpoint::Local(src_root), CpEndpoint::Remote(dst_remote)) => {
            let dst_bucket = dst_remote.bucket.as_deref().ok_or_else(|| {
                CliError::InvalidPath(format!("{}/", dst_remote.alias), "missing bucket".into())
            })?;
            let dst_key = join_prefix(dst_remote.key.as_deref(), key);
            let path = join_local(Path::new(src_root), key);
            let file = tokio::fs::File::open(&path).await?;
            let client = make_client(&dst_remote.alias).await?;
            client
                .put_from_reader(
                    dst_bucket,
                    &dst_key,
                    file,
                    Some(entry.size),
                    &Default::default(),
                    None,
                )
                .await?;
        }
        (CpEndpoint::Remote(src_remote), CpEndpoint::Local(dst_root)) => {
            let src_bucket = src_remote.bucket.as_deref().ok_or_else(|| {
                CliError::InvalidPath(format!("{}/", src_remote.alias), "missing bucket".into())
            })?;
            let src_key = join_prefix(src_remote.key.as_deref(), key);
            let path = join_local(Path::new(dst_root), key);
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let mut file = tokio::fs::File::create(&path).await?;
            let client = make_client(&src_remote.alias).await?;
            client
                .get_to_writer(src_bucket, &src_key, &mut file)
                .await?;
        }
        (CpEndpoint::Remote(src_remote), CpEndpoint::Remote(dst_remote)) => {
            let src_bucket = src_remote.bucket.as_deref().ok_or_else(|| {
                CliError::InvalidPath(format!("{}/", src_remote.alias), "missing bucket".into())
            })?;
            let dst_bucket = dst_remote.bucket.as_deref().ok_or_else(|| {
                CliError::InvalidPath(format!("{}/", dst_remote.alias), "missing bucket".into())
            })?;
            let src_key = join_prefix(src_remote.key.as_deref(), key);
            let dst_key = join_prefix(dst_remote.key.as_deref(), key);
            let src_client = make_client(&src_remote.alias).await?;
            let dst_client = make_client(&dst_remote.alias).await?;
            tunnel_remote_to_remote(
                &src_client,
                src_bucket,
                &src_key,
                &dst_client,
                dst_bucket,
                &dst_key,
                entry.size,
            )
            .await?;
        }
        (CpEndpoint::Local(_), CpEndpoint::Local(_)) => {
            return Err(CliError::Other(
                "mirror local→local is not supported; use rsync or cp -r".into(),
            ));
        }
    }
    Ok(())
}

async fn delete_one(ep: &CpEndpoint, key: &str) -> Result<(), CliError> {
    match ep {
        CpEndpoint::Local(root) => {
            let path = join_local(Path::new(root), key);
            tokio::fs::remove_file(&path).await.map_err(CliError::Io)
        }
        CpEndpoint::Remote(remote) => {
            let bucket = remote.bucket.as_deref().ok_or_else(|| {
                CliError::InvalidPath(format!("{}/", remote.alias), "missing bucket".into())
            })?;
            let full_key = join_prefix(remote.key.as_deref(), key);
            let client = make_client(&remote.alias).await?;
            client.delete(bucket, &full_key).await?;
            Ok(())
        }
    }
}

fn join_prefix(prefix: Option<&str>, key: &str) -> String {
    match prefix {
        Some(p) if !p.is_empty() => format!("{}/{key}", p.trim_end_matches('/')),
        _ => key.to_owned(),
    }
}

fn join_local(root: &Path, key: &str) -> PathBuf {
    let mut p = root.to_path_buf();
    for part in key.split('/') {
        if !part.is_empty() {
            p.push(part);
        }
    }
    p
}

async fn tunnel_remote_to_remote(
    src: &Y2qClient,
    src_bucket: &str,
    src_key: &str,
    dst: &Y2qClient,
    dst_bucket: &str,
    dst_key: &str,
    size: u64,
) -> Result<(), CliError> {
    let (reader, mut writer) = tokio::io::duplex(64 * 1024);
    let src_clone = src.clone();
    let src_b = src_bucket.to_owned();
    let src_k = src_key.to_owned();
    let get_task =
        tokio::spawn(async move { src_clone.get_to_writer(&src_b, &src_k, &mut writer).await });
    dst.put_from_reader(
        dst_bucket,
        dst_key,
        reader,
        Some(size),
        &Default::default(),
        None,
    )
    .await?;
    let _ = get_task.await;
    Ok(())
}
