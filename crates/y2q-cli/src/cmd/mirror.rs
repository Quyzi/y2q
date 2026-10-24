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
    DiffEntries, MirrorAction, MirrorPlan, collect_local_entries, collect_remote_entries,
    mirror_plan,
};
use crate::output::{OutputMode, fmt_bytes, is_quiet, print_json};
use crate::path::CpEndpoint;
use crate::staged_file::StagedFile;

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

    let mut plan = mirror_plan(&src_entries, &dst_entries, opts.overwrite);
    drop_unsafe_keys(&mut plan, mode);
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
        if mode != OutputMode::Json && !is_quiet() {
            println!("{:<6} {key} ({})", action.label(), fmt_bytes(size));
        }
    }

    if opts.remove {
        for key in &plan.deletions {
            delete_one(&dst_ep, key).await?;
            stats.deleted += 1;
            if mode != OutputMode::Json && !is_quiet() {
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
    } else if !is_quiet() {
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

/// Drop keys whose local join would escape (`.` / `..` / absolute segments).
/// Continues the rest of the plan so one poisoned key does not abort a sync.
fn drop_unsafe_keys(plan: &mut MirrorPlan, mode: OutputMode) {
    let warn = mode != OutputMode::Json && !is_quiet();
    let before_actions = plan.actions.len();
    plan.actions.retain(|(key, _)| {
        if key_is_safe_local(key) {
            true
        } else {
            if warn {
                eprintln!("warning: skipping unsafe key `{key}`");
            }
            false
        }
    });
    let before_deletions = plan.deletions.len();
    plan.deletions.retain(|key| {
        if key_is_safe_local(key) {
            true
        } else {
            if warn {
                eprintln!("warning: skipping unsafe key `{key}`");
            }
            false
        }
    });
    plan.skipped += (before_actions - plan.actions.len()) as u64;
    plan.skipped += (before_deletions - plan.deletions.len()) as u64;
}

fn key_is_safe_local(key: &str) -> bool {
    join_local(Path::new("/"), key).is_ok()
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
            let path = join_local(Path::new(src_root), key)?;
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
            let path = join_local(Path::new(dst_root), key)?;
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let mut staged = StagedFile::create(&path).await?;
            let client = make_client(&src_remote.alias).await?;
            client
                .get_to_writer(src_bucket, &src_key, staged.file_mut())
                .await?;
            staged.commit().await?;
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
            let path = join_local(Path::new(root), key)?;
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

fn join_local(root: &Path, key: &str) -> Result<PathBuf, CliError> {
    let mut p = root.to_path_buf();
    for part in key.split('/') {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." || Path::new(part).is_absolute() {
            return Err(CliError::InvalidPath(
                key.to_owned(),
                "\".\" and \"..\" path components are not allowed".into(),
            ));
        }
        p.push(part);
    }
    Ok(p)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::listing::{DiffEntry, DiffEntries, mirror_plan};
    use std::collections::BTreeMap;

    #[test]
    fn join_local_accepts_nested_key() {
        let got = join_local(Path::new("/tmp/dst"), "a/b/c").unwrap();
        assert_eq!(got, PathBuf::from("/tmp/dst/a/b/c"));
    }

    #[test]
    fn join_local_rejects_dot_and_dotdot() {
        for key in ["../outside", "a/../b", "a/./b", ".", "..", "../../evil"] {
            assert!(
                join_local(Path::new("/tmp/dst"), key).is_err(),
                "expected Err for {key:?}"
            );
        }
    }

    #[test]
    fn join_local_leading_slash_key_is_harmless_after_split() {
        // `/abs` splits to `["", "abs"]`; empty parts are skipped, so the key
        // lands under root. Absolute *segments* (Path::is_absolute) are still
        // rejected when expressible — e.g. a lone absolute component.
        let got = join_local(Path::new("/tmp/dst"), "/abs").unwrap();
        assert_eq!(got, PathBuf::from("/tmp/dst/abs"));
        assert!(Path::new("/abs").is_absolute());
    }

    #[cfg(windows)]
    #[test]
    fn join_local_rejects_absolute_windows_segment() {
        assert!(join_local(Path::new(r"C:\dst"), r"C:\outside").is_err());
    }

    #[test]
    fn drop_unsafe_keys_keeps_only_safe_actions() {
        let mut src: DiffEntries = BTreeMap::new();
        src.insert(
            "ok.txt".into(),
            DiffEntry {
                size: 1,
                checksum: None,
            },
        );
        src.insert(
            "../../evil".into(),
            DiffEntry {
                size: 1,
                checksum: None,
            },
        );
        let dst: DiffEntries = BTreeMap::new();
        let mut plan = mirror_plan(&src, &dst, false);
        assert_eq!(plan.actions.len(), 2);
        // Json mode skips the human warning path.
        drop_unsafe_keys(&mut plan, OutputMode::Json);
        let keys: Vec<&str> = plan.actions.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["ok.txt"]);
        assert!(!plan.actions.iter().any(|(k, _)| k.contains("..")));
        assert!(plan.skipped >= 1);
    }

    #[test]
    fn join_local_plus_staged_does_not_escape_root() {
        // Focused containment: rejected keys never produce a PathBuf outside root.
        let root = Path::new("/tmp/mirror-dst");
        let err = join_local(root, "prefix/../../outside.txt").unwrap_err();
        assert!(matches!(err, CliError::InvalidPath(_, _)));
        assert!(!key_is_safe_local("prefix/../../outside.txt"));
        assert!(key_is_safe_local("prefix/ok.txt"));
        let safe = join_local(root, "prefix/ok.txt").unwrap();
        assert!(safe.starts_with(root));
        assert_eq!(safe, PathBuf::from("/tmp/mirror-dst/prefix/ok.txt"));
    }
}
