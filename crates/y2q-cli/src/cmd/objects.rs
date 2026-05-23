use y2q_client::{ListOptions, Y2qClient};

use crate::client_builder::client_from_alias;
use crate::config::{CliConfig, default_config_path, default_tokens_path};
use crate::error::CliError;
use crate::output::{OutputMode, fmt_bytes, fmt_ns, print_json};
use crate::path::RemotePath;
use crate::token::TokenStore;

fn has_glob(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

fn require_bucket_key(remote: &RemotePath) -> Result<(&str, &str), CliError> {
    let bucket = remote.bucket.as_deref().ok_or_else(|| {
        CliError::InvalidPath(format!("{}/", remote.alias), "missing bucket".into())
    })?;
    let key = remote.key.as_deref().ok_or_else(|| {
        CliError::InvalidPath(format!("{}/{bucket}/", remote.alias), "missing key".into())
    })?;
    Ok((bucket, key))
}

pub(crate) async fn make_client(alias: &str) -> Result<Y2qClient, CliError> {
    let config = CliConfig::load(&default_config_path()?)?;
    let entry = config.get_alias(alias)?;
    let store = TokenStore::load(&default_tokens_path()?)?;
    let token = store
        .token_for(alias)
        .ok_or(CliError::Client(y2q_client::ClientError::Unauthenticated))?;
    client_from_alias(entry, Some(token))
}

pub async fn rm(path: String, force: bool, mode: OutputMode) -> Result<(), CliError> {
    let remote = RemotePath::parse(&path)?;
    let bucket = remote.bucket.as_deref().ok_or_else(|| {
        CliError::InvalidPath(format!("{}/", remote.alias), "missing bucket".into())
    })?;
    let key_pattern = remote.key.as_deref().ok_or_else(|| {
        CliError::InvalidPath(format!("{}/{bucket}/", remote.alias), "missing key".into())
    })?;

    let client = make_client(&remote.alias).await?;

    if !has_glob(key_pattern) {
        // Single object delete — original behaviour
        client.delete(bucket, key_pattern).await?;
        if mode == OutputMode::Json {
            print_json(&serde_json::json!({ "deleted": path }));
        } else {
            println!("Deleted {path}");
        }
        return Ok(());
    }

    // Glob delete: list all matching keys, confirm, then delete each
    let glob_prefix = key_pattern
        .find(['*', '?', '['])
        .map(|i| &key_pattern[..i])
        .unwrap_or("")
        .to_owned();

    let pattern = glob::Pattern::new(key_pattern)
        .map_err(|e| CliError::Other(format!("invalid glob pattern: {e}")))?;

    let mut matching_keys: Vec<String> = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let page = client
            .list_objects(
                bucket,
                &ListOptions {
                    prefix: if glob_prefix.is_empty() {
                        None
                    } else {
                        Some(glob_prefix.clone())
                    },
                    after: after.clone(),
                    limit: Some(1000),
                },
            )
            .await?;

        for item in &page.items {
            if pattern.matches(&item.key) {
                matching_keys.push(item.key.clone());
            }
        }

        match page.next {
            Some(cursor) => after = Some(cursor),
            None => break,
        }
    }

    if matching_keys.is_empty() {
        eprintln!("No objects matched: {key_pattern}");
        return Ok(());
    }

    if !force {
        eprintln!(
            "The following {} object(s) will be deleted:",
            matching_keys.len()
        );
        for k in &matching_keys {
            eprintln!("  {}/{bucket}/{k}", remote.alias);
        }
        eprint!("Confirm deletion? [y/N] ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    let mut deleted: Vec<String> = Vec::new();
    for key in &matching_keys {
        client.delete(bucket, key).await?;
        let full = format!("{}/{bucket}/{key}", remote.alias);
        if mode != OutputMode::Json {
            println!("Deleted {full}");
        }
        deleted.push(full);
    }

    if mode == OutputMode::Json {
        print_json(&serde_json::json!({ "deleted": deleted }));
    }
    Ok(())
}

pub async fn stat(path: String, mode: OutputMode) -> Result<(), CliError> {
    let remote = RemotePath::parse(&path)?;
    let (bucket, key) = require_bucket_key(&remote)?;

    let client = make_client(&remote.alias).await?;
    let head = client.head(bucket, key).await?;

    if mode == OutputMode::Json {
        print_json(&serde_json::json!({
            "path": path,
            "size": head.size,
            "created": head.created,
            "modified": head.modified,
            "checksum_gxhash": head.checksum_gxhash,
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
            println!(
                "          (size recorded as 0; object was uploaded before size tracking was active — re-upload to correct)"
            );
        }
        println!("Created:  {}", fmt_ns(head.created));
        println!("Modified: {}", fmt_ns(head.modified));
        println!("GxHash:   {}", head.checksum_gxhash);
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

pub async fn cat(path: String, range: Option<(u64, u64)>) -> Result<(), CliError> {
    let remote = RemotePath::parse(&path)?;
    let (bucket, key) = require_bucket_key(&remote)?;

    let client = make_client(&remote.alias).await?;

    let mut stdout = tokio::io::stdout();
    match range {
        Some((start, end)) => {
            client
                .get_range_to_writer(bucket, key, start, end, &mut stdout)
                .await?;
        }
        None => {
            client.get_to_writer(bucket, key, &mut stdout).await?;
        }
    }
    Ok(())
}
