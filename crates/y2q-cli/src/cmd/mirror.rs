//! `mirror` — rsync-style one-way sync.
//!
//! Supports local↔remote and remote↔remote sources. Copies entries from
//! `src` to `dst` when missing or differing in size; with `--remove`, also
//! deletes destinations missing from source. Client-side only — no daemon
//! changes needed.

use std::path::{Path, PathBuf};

use y2q_client::Y2qClient;

use crate::cmd::objects::make_client;
use crate::error::CliError;
use crate::ops::listing::{
    DiffEntries, MirrorAction, collect_local_entries, collect_remote_entries, mirror_plan,
};
use crate::output::{OutputMode, fmt_bytes, print_json};
use crate::path::CpEndpoint;

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

    let plan = mirror_plan(&src_entries, &dst_entries, opts.overwrite);
    let mut stats = MirrorStats {
        skipped: plan.skipped,
        ..Default::default()
    };

    for (key, action) in &plan.actions {
        let size = src_entries.get(key).map(|e| e.size).unwrap_or(0);
        copy_one(&src_ep, &dst_ep, key, size).await?;
        stats.bytes += size;
        match action {
            MirrorAction::Copy => stats.copied += 1,
            MirrorAction::Update => stats.updated += 1,
        }
        if mode != OutputMode::Json {
            println!("{:<6} {key} ({})", action.label(), fmt_bytes(size));
        }
    }

    if opts.remove {
        for key in &plan.deletions {
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

async fn collect(ep: &CpEndpoint, excludes: &[glob::Pattern]) -> Result<DiffEntries, CliError> {
    let entries = match ep {
        CpEndpoint::Local(path) => {
            collect_local_entries(Path::new(path)).map_err(CliError::Other)?
        }
        CpEndpoint::Remote(remote) => {
            let bucket = remote.bucket.as_deref().ok_or_else(|| {
                CliError::InvalidPath(format!("{}/", remote.alias), "missing bucket".into())
            })?;
            let client = make_client(&remote.alias).await?;
            collect_remote_entries(&client, bucket, remote.key.as_deref()).await?
        }
    };
    if excludes.is_empty() {
        return Ok(entries);
    }
    Ok(entries
        .into_iter()
        .filter(|(k, _)| !excludes.iter().any(|p| p.matches(k)))
        .collect())
}

async fn copy_one(
    src: &CpEndpoint,
    dst: &CpEndpoint,
    key: &str,
    size: u64,
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
                    Some(size),
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
                size,
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
