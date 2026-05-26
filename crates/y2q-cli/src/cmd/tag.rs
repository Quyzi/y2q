//! `tag` and `attribute` — mutate object labels. Both map to y2q's single
//! label namespace (tags and attributes are the same store).

use std::collections::BTreeSet;

use crate::cli::{AttributeCmd, TagCmd};
use crate::cmd::objects::make_client;
use crate::error::CliError;
use crate::output::{OutputMode, print_json};
use crate::path::RemotePath;

fn split_target(target: &str) -> Result<(RemotePath, String, String), CliError> {
    let remote = RemotePath::parse(target)?;
    let bucket = remote
        .bucket
        .clone()
        .ok_or_else(|| CliError::InvalidPath(target.to_owned(), "missing bucket".into()))?;
    let key = remote
        .key
        .clone()
        .ok_or_else(|| CliError::InvalidPath(target.to_owned(), "missing key".into()))?;
    Ok((remote, bucket, key))
}

fn parse_kv(pairs: &[String]) -> Result<BTreeSet<(String, String)>, CliError> {
    let mut set = BTreeSet::new();
    for raw in pairs {
        let (k, v) = raw
            .split_once('=')
            .ok_or_else(|| CliError::Other(format!("expected key=value, got `{raw}`")))?;
        if k.is_empty() {
            return Err(CliError::Other("label key must not be empty".into()));
        }
        // A name may be given more than once with different values.
        set.insert((k.to_lowercase(), v.to_owned()));
    }
    Ok(set)
}

async fn set(target: &str, pairs: &[String], mode: OutputMode) -> Result<(), CliError> {
    let (remote, bucket, key) = split_target(target)?;
    let labels = parse_kv(pairs)?;
    let client = make_client(&remote.alias).await?;
    let result = crate::ops::objects::set_labels(&client, &bucket, &key, "set", &labels).await?;
    if mode == OutputMode::Json {
        print_json(&serde_json::json!({ "target": target, "labels": result }));
    } else {
        println!("Set {} label(s) on {target}", labels.len());
    }
    Ok(())
}

async fn list(target: &str, mode: OutputMode) -> Result<(), CliError> {
    let (remote, bucket, key) = split_target(target)?;
    let client = make_client(&remote.alias).await?;
    let head = crate::ops::objects::head(&client, &bucket, &key).await?;
    if mode == OutputMode::Json {
        print_json(&serde_json::json!({ "target": target, "labels": head.labels }));
    } else if head.labels.is_empty() {
        println!("No labels on {target}");
    } else {
        for (k, v) in &head.labels {
            println!("{k} = {v}");
        }
    }
    Ok(())
}

async fn remove(target: &str, keys: &[String], mode: OutputMode) -> Result<(), CliError> {
    let (remote, bucket, key) = split_target(target)?;
    // Empty set with op=remove clears all; named keys remove every value of
    // those names (the value carried here is ignored server-side).
    let labels: BTreeSet<(String, String)> = keys
        .iter()
        .map(|k| (k.to_lowercase(), String::new()))
        .collect();
    let client = make_client(&remote.alias).await?;
    let result = crate::ops::objects::set_labels(&client, &bucket, &key, "remove", &labels).await?;
    if mode == OutputMode::Json {
        print_json(&serde_json::json!({ "target": target, "labels": result }));
    } else if keys.is_empty() {
        println!("Cleared all labels on {target}");
    } else {
        println!("Removed {} label(s) from {target}", keys.len());
    }
    Ok(())
}

pub async fn run_tag(cmd: TagCmd, mode: OutputMode) -> Result<(), CliError> {
    match cmd {
        TagCmd::Set { target, tags } => set(&target, &tags, mode).await,
        TagCmd::List { target } => list(&target, mode).await,
        TagCmd::Remove { target } => remove(&target, &[], mode).await,
    }
}

pub async fn run_attribute(cmd: AttributeCmd, mode: OutputMode) -> Result<(), CliError> {
    match cmd {
        AttributeCmd::Set { target, attrs } => set(&target, &attrs, mode).await,
        AttributeCmd::List { target } => list(&target, mode).await,
        AttributeCmd::Remove { target } => remove(&target, &[], mode).await,
    }
}
