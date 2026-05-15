use y2q_client::{ClientConfig, Y2qClient};

use crate::config::{CliConfig, default_config_path, default_tokens_path};
use crate::error::CliError;
use crate::output::{OutputMode, fmt_bytes, fmt_ns, print_json};
use crate::path::RemotePath;
use crate::token::TokenStore;

fn require_bucket_key(remote: &RemotePath) -> Result<(&str, &str), CliError> {
    let bucket = remote
        .bucket
        .as_deref()
        .ok_or_else(|| CliError::InvalidPath(format!("{}/", remote.alias), "missing bucket".into()))?;
    let key = remote
        .key
        .as_deref()
        .ok_or_else(|| CliError::InvalidPath(format!("{}/{bucket}/", remote.alias), "missing key".into()))?;
    Ok((bucket, key))
}

pub async fn rm(path: String, mode: OutputMode) -> Result<(), CliError> {
    let remote = RemotePath::parse(&path)?;
    let (bucket, key) = require_bucket_key(&remote)?;

    let config = CliConfig::load(&default_config_path()?)?;
    let profile = config.get_profile(&remote.alias)?;
    let store = TokenStore::load(&default_tokens_path()?)?;
    let token = store.token_for(&remote.alias).ok_or(CliError::Client(
        y2q_client::ClientError::Unauthenticated,
    ))?;
    let client = Y2qClient::new(ClientConfig { base_url: profile.url.clone(), token: Some(token) })?;
    client.delete(bucket, key).await?;

    if mode == OutputMode::Json {
        print_json(&serde_json::json!({ "deleted": path }));
    } else {
        println!("Deleted {path}");
    }
    Ok(())
}

pub async fn stat(path: String, mode: OutputMode) -> Result<(), CliError> {
    let remote = RemotePath::parse(&path)?;
    let (bucket, key) = require_bucket_key(&remote)?;

    let config = CliConfig::load(&default_config_path()?)?;
    let profile = config.get_profile(&remote.alias)?;
    let store = TokenStore::load(&default_tokens_path()?)?;
    let token = store.token_for(&remote.alias).ok_or(CliError::Client(
        y2q_client::ClientError::Unauthenticated,
    ))?;
    let client = Y2qClient::new(ClientConfig { base_url: profile.url.clone(), token: Some(token) })?;
    let head = client.head(bucket, key).await?;

    if mode == OutputMode::Json {
        print_json(&serde_json::json!({
            "path": path,
            "size": head.size,
            "created": head.created,
            "modified": head.modified,
            "checksum_md5": head.checksum_md5,
            "checksum_sha256": head.checksum_sha256,
            "labels": head.labels,
            "cipher_size": head.cipher_size,
            "cipher_sha256": head.cipher_sha256,
            "kem_alg": head.kem_alg,
            "aead_alg": head.aead_alg,
            "envelope_version": head.envelope_version,
        }));
    } else {
        println!("Path:     {path}");
        println!("Size:     {}", fmt_bytes(head.size));
        if head.size == 0 && head.kem_alg.is_some() {
            println!("          (size recorded as 0; object was uploaded before size tracking was active — re-upload to correct)");
        }
        println!("Created:  {}", fmt_ns(head.created));
        println!("Modified: {}", fmt_ns(head.modified));
        println!("MD5:      {}", head.checksum_md5);
        println!("SHA256:   {}", head.checksum_sha256);
        if !head.labels.is_empty() {
            println!("Labels:");
            for (k, v) in &head.labels {
                println!("  {k}: {v}");
            }
        }
        if let Some(ref alg) = head.kem_alg {
            println!("KEM:      {alg}");
        }
        if let Some(ref alg) = head.aead_alg {
            println!("AEAD:     {alg}");
        }
        if let Some(sz) = head.cipher_size {
            println!("Envelope: {} on disk", fmt_bytes(sz));
        }
    }
    Ok(())
}

pub async fn cat(path: String) -> Result<(), CliError> {
    let remote = RemotePath::parse(&path)?;
    let (bucket, key) = require_bucket_key(&remote)?;

    let config = CliConfig::load(&default_config_path()?)?;
    let profile = config.get_profile(&remote.alias)?;
    let store = TokenStore::load(&default_tokens_path()?)?;
    let token = store.token_for(&remote.alias).ok_or(CliError::Client(
        y2q_client::ClientError::Unauthenticated,
    ))?;
    let client = Y2qClient::new(ClientConfig { base_url: profile.url.clone(), token: Some(token) })?;

    let mut stdout = tokio::io::stdout();
    client.get_to_writer(bucket, key, &mut stdout).await?;
    Ok(())
}
