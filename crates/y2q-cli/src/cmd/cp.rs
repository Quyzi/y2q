use std::collections::BTreeMap;

use y2q_client::{ClientConfig, Y2qClient};

use crate::config::{CliConfig, default_config_path, default_tokens_path};
use crate::error::CliError;
use crate::output::{OutputMode, fmt_bytes, print_json};
use crate::path::{CpEndpoint, RemotePath};
use crate::progress::{CountingReader, make_reporter};
use crate::token::TokenStore;

pub async fn run(
    src: String,
    dst: String,
    labels: Vec<String>,
    sync: Option<String>,
    mode: OutputMode,
) -> Result<(), CliError> {
    let src_ep = CpEndpoint::parse(&src);
    let dst_ep = CpEndpoint::parse(&dst);

    if src_ep.is_remote() && dst_ep.is_remote() {
        return Err(CliError::RemoteToRemote);
    }

    // Parse labels: "key=value"
    let mut label_map: BTreeMap<String, String> = BTreeMap::new();
    for raw in &labels {
        let (k, v) = raw.split_once('=').ok_or_else(|| {
            CliError::InvalidPath(raw.clone(), "label must be key=value".into())
        })?;
        if k.is_empty() {
            return Err(CliError::InvalidPath(raw.clone(), "label key must not be empty".into()));
        }
        label_map.insert(k.to_lowercase(), v.to_owned());
    }

    match (&src_ep, &dst_ep) {
        (CpEndpoint::Local(local_path), CpEndpoint::Remote(remote)) => {
            upload(local_path, remote, label_map, sync.as_deref(), mode).await
        }
        (CpEndpoint::Remote(remote), CpEndpoint::Local(local_path)) => {
            if !labels.is_empty() {
                return Err(CliError::Other("--label is only valid for uploads".into()));
            }
            download(remote, local_path, mode).await
        }
        _ => unreachable!(),
    }
}

async fn upload(
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
    let reporter = if local_path != "-" { Some(make_reporter(&label, content_length)) } else { None };

    let created = if let Some(file) = file {
        if let Some(reporter) = reporter {
            let reader = CountingReader::new(file, reporter);
            client.put_from_reader(bucket, key, reader, content_length, &labels, sync).await?
        } else {
            client.put_from_reader(bucket, key, file, content_length, &labels, sync).await?
        }
    } else {
        let stdin = tokio::io::stdin();
        client.put_from_reader(bucket, key, stdin, None, &labels, sync).await?
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
        eprintln!("Downloaded {} ← {}/{bucket}/{key}", fmt_bytes(n), remote.alias);
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
    Ok(Y2qClient::new(ClientConfig { base_url: profile.url.clone(), token: Some(token) })?)
}
