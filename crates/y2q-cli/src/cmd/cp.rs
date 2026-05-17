use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use y2q_client::{ClientConfig, Y2qClient};

use crate::config::{CliConfig, default_config_path, default_tokens_path};
use crate::error::CliError;
use crate::output::{OutputMode, fmt_bytes, print_json};
use crate::path::{CpEndpoint, RemotePath};
use crate::progress::{CountingReader, make_reporter};
use crate::token::TokenStore;

fn has_glob(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

pub async fn run(
    src: String,
    dst: String,
    labels: Vec<String>,
    sync: Option<String>,
    recursive: bool,
    mode: OutputMode,
) -> Result<(), CliError> {
    let src_ep = CpEndpoint::parse(&src);
    let dst_ep = CpEndpoint::parse(&dst);

    if src_ep.is_remote() && dst_ep.is_remote() {
        return Err(CliError::RemoteToRemote);
    }

    let mut label_map: BTreeMap<String, String> = BTreeMap::new();
    for raw in &labels {
        let (k, v) = raw
            .split_once('=')
            .ok_or_else(|| CliError::InvalidPath(raw.clone(), "label must be key=value".into()))?;
        if k.is_empty() {
            return Err(CliError::InvalidPath(
                raw.clone(),
                "label key must not be empty".into(),
            ));
        }
        label_map.insert(k.to_lowercase(), v.to_owned());
    }

    match (&src_ep, &dst_ep) {
        (CpEndpoint::Local(local_path), CpEndpoint::Remote(remote)) => {
            if local_path == "-" {
                if recursive {
                    return Err(CliError::Other("-r cannot be used with stdin".into()));
                }
                upload_single(local_path, remote, label_map, sync.as_deref(), mode).await
            } else if has_glob(local_path) {
                upload_glob(
                    local_path,
                    remote,
                    label_map,
                    sync.as_deref(),
                    recursive,
                    mode,
                )
                .await
            } else if recursive {
                upload_recursive(
                    Path::new(local_path),
                    remote,
                    label_map,
                    sync.as_deref(),
                    mode,
                )
                .await
            } else {
                upload_single(local_path, remote, label_map, sync.as_deref(), mode).await
            }
        }
        (CpEndpoint::Remote(remote), CpEndpoint::Local(local_path)) => {
            if !labels.is_empty() {
                return Err(CliError::Other("--label is only valid for uploads".into()));
            }
            if recursive {
                return Err(CliError::Other("-r is only valid for uploads".into()));
            }
            download(remote, local_path, mode).await
        }
        _ => unreachable!(),
    }
}

async fn upload_single(
    local_path: &str,
    remote: &RemotePath,
    labels: BTreeMap<String, String>,
    sync: Option<&str>,
    mode: OutputMode,
) -> Result<(), CliError> {
    let bucket = remote.bucket.as_deref().ok_or_else(|| {
        CliError::InvalidPath(format!("{}/", remote.alias), "missing bucket".into())
    })?;
    let key = remote.key.as_deref().ok_or_else(|| {
        CliError::InvalidPath(format!("{}/{bucket}/", remote.alias), "missing key".into())
    })?;

    let client = make_client(&remote.alias).await?;

    let (file, content_length) = if local_path == "-" {
        (None, None)
    } else {
        let f = tokio::fs::File::open(local_path).await?;
        let meta = f.metadata().await?;
        (Some(f), Some(meta.len()))
    };

    let label = format!("{local_path} → {}/{bucket}/{key}", remote.alias);
    let reporter = if local_path != "-" {
        Some(make_reporter(&label, content_length))
    } else {
        None
    };

    let created = if let Some(file) = file {
        if let Some(reporter) = reporter {
            let reader = CountingReader::new(file, reporter);
            client
                .put_from_reader(bucket, key, reader, content_length, &labels, sync)
                .await?
        } else {
            client
                .put_from_reader(bucket, key, file, content_length, &labels, sync)
                .await?
        }
    } else {
        let stdin = tokio::io::stdin();
        client
            .put_from_reader(bucket, key, stdin, None, &labels, sync)
            .await?
    };

    let result_path = format!("{}/{bucket}/{key}", remote.alias);
    if mode == OutputMode::Json {
        print_json(&serde_json::json!({ "path": result_path, "created": created }));
    } else if created {
        println!("Stored: {result_path}");
    } else {
        println!("Updated: {result_path}");
    }
    Ok(())
}

/// Upload all files matching a local glob pattern to a remote prefix.
struct UploadCtx<'a> {
    alias: &'a str,
    bucket: &'a str,
    dst_prefix: &'a str,
    client: &'a Y2qClient,
    labels: &'a BTreeMap<String, String>,
    sync: Option<&'a str>,
    mode: OutputMode,
}

async fn upload_glob(
    pattern: &str,
    remote: &RemotePath,
    labels: BTreeMap<String, String>,
    sync: Option<&str>,
    recursive: bool,
    mode: OutputMode,
) -> Result<(), CliError> {
    let bucket = remote.bucket.as_deref().ok_or_else(|| {
        CliError::InvalidPath(format!("{}/", remote.alias), "missing bucket".into())
    })?;
    let dst_prefix = remote.key.as_deref().unwrap_or("");

    let paths: Vec<PathBuf> = glob::glob(pattern)
        .map_err(|e| CliError::Other(format!("invalid glob pattern: {e}")))?
        .filter_map(|r| r.ok())
        .collect();

    if paths.is_empty() {
        return Err(CliError::Other(format!(
            "glob pattern matched no files: {pattern}"
        )));
    }

    let client = make_client(&remote.alias).await?;
    let ctx = UploadCtx {
        alias: &remote.alias,
        bucket,
        dst_prefix,
        client: &client,
        labels: &labels,
        sync,
        mode,
    };

    for path in &paths {
        if path.is_dir() {
            if recursive {
                upload_dir_files(path, path, &ctx).await?;
            }
            continue;
        }
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let key = if dst_prefix.is_empty() {
            file_name
        } else {
            format!("{}/{}", dst_prefix.trim_end_matches('/'), file_name)
        };
        upload_file(path, &key, &ctx).await?;
    }
    Ok(())
}

/// Recursively upload all files under `src_dir` to `bucket/dst_prefix/<relative-path>`.
async fn upload_recursive(
    src_dir: &Path,
    remote: &RemotePath,
    labels: BTreeMap<String, String>,
    sync: Option<&str>,
    mode: OutputMode,
) -> Result<(), CliError> {
    if !src_dir.is_dir() {
        return Err(CliError::Other(format!(
            "-r requires a directory source, but `{}` is not a directory",
            src_dir.display()
        )));
    }

    let bucket = remote.bucket.as_deref().ok_or_else(|| {
        CliError::InvalidPath(format!("{}/", remote.alias), "missing bucket".into())
    })?;
    let dst_prefix = remote.key.as_deref().unwrap_or("");
    let client = make_client(&remote.alias).await?;
    let ctx = UploadCtx {
        alias: &remote.alias,
        bucket,
        dst_prefix,
        client: &client,
        labels: &labels,
        sync,
        mode,
    };

    upload_dir_files(src_dir, src_dir, &ctx).await
}

/// Walk `dir`, uploading each file with a key relative to `root`.
async fn upload_dir_files(root: &Path, dir: &Path, ctx: &UploadCtx<'_>) -> Result<(), CliError> {
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| match e {
            Ok(e) => Some(e),
            Err(err) => {
                eprintln!("warning: skipping unreadable entry: {err}");
                None
            }
        })
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry.path().strip_prefix(root).unwrap_or(entry.path());
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let key = if ctx.dst_prefix.is_empty() {
            rel_str.to_owned()
        } else {
            format!("{}/{}", ctx.dst_prefix.trim_end_matches('/'), rel_str)
        };
        upload_file(entry.path(), &key, ctx).await?;
    }
    Ok(())
}

async fn upload_file(path: &Path, key: &str, ctx: &UploadCtx<'_>) -> Result<(), CliError> {
    let file = tokio::fs::File::open(path).await?;
    let size = file.metadata().await?.len();
    let label_str = format!("{} → {}/{}/{key}", path.display(), ctx.alias, ctx.bucket);
    let reporter = make_reporter(&label_str, Some(size));
    let reader = CountingReader::new(file, reporter);
    let created = ctx
        .client
        .put_from_reader(ctx.bucket, key, reader, Some(size), ctx.labels, ctx.sync)
        .await?;

    let result_path = if ctx.alias.is_empty() {
        format!("{}/{key}", ctx.bucket)
    } else {
        format!("{}/{}/{key}", ctx.alias, ctx.bucket)
    };

    if ctx.mode == OutputMode::Json {
        print_json(&serde_json::json!({ "path": result_path, "created": created }));
    } else if created {
        println!("Stored: {result_path}");
    } else {
        println!("Updated: {result_path}");
    }
    Ok(())
}

async fn download(remote: &RemotePath, local_path: &str, mode: OutputMode) -> Result<(), CliError> {
    let bucket = remote.bucket.as_deref().ok_or_else(|| {
        CliError::InvalidPath(format!("{}/", remote.alias), "missing bucket".into())
    })?;
    let key = remote.key.as_deref().ok_or_else(|| {
        CliError::InvalidPath(format!("{}/{bucket}/", remote.alias), "missing key".into())
    })?;

    let client = make_client(&remote.alias).await?;

    let n = if local_path == "-" {
        let mut stdout = tokio::io::stdout();
        client.get_to_writer(bucket, key, &mut stdout).await?
    } else {
        let mut file = tokio::fs::File::create(local_path).await?;
        let n = client.get_to_writer(bucket, key, &mut file).await?;
        eprintln!(
            "Downloaded {} ← {}/{bucket}/{key}",
            fmt_bytes(n),
            remote.alias
        );
        n
    };

    if mode == OutputMode::Json && local_path != "-" {
        print_json(&serde_json::json!({
            "source": format!("{}/{bucket}/{key}", remote.alias),
            "destination": local_path,
            "bytes": n,
        }));
    }
    Ok(())
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
