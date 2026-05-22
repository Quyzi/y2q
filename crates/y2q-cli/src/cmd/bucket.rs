//! `mb` (make bucket) and `rb` (remove bucket).

use crate::cmd::objects::make_client;
use crate::error::CliError;
use crate::output::{OutputMode, print_json};
use crate::path::RemotePath;

pub async fn make(target: String, ignore_existing: bool, mode: OutputMode) -> Result<(), CliError> {
    let remote = RemotePath::parse(&target)?;
    let bucket = remote
        .bucket
        .as_deref()
        .ok_or_else(|| CliError::InvalidPath(target.clone(), "expected alias/bucket".into()))?;
    if remote.key.is_some() {
        return Err(CliError::InvalidPath(
            target.clone(),
            "mb takes alias/bucket, not a key".into(),
        ));
    }

    let client = make_client(&remote.alias).await?;
    let created = client.create_bucket(bucket).await?;

    if !created && !ignore_existing {
        return Err(CliError::Other(format!("bucket already exists: {target}")));
    }

    if mode == OutputMode::Json {
        print_json(&serde_json::json!({ "bucket": target, "created": created }));
    } else if created {
        println!("Created bucket {target}");
    } else {
        println!("Bucket already exists: {target}");
    }
    Ok(())
}

pub async fn remove(target: String, force: bool, mode: OutputMode) -> Result<(), CliError> {
    let remote = RemotePath::parse(&target)?;
    let bucket = remote
        .bucket
        .as_deref()
        .ok_or_else(|| CliError::InvalidPath(target.clone(), "expected alias/bucket".into()))?;
    if remote.key.is_some() {
        return Err(CliError::InvalidPath(
            target.clone(),
            "rb takes alias/bucket, not a key".into(),
        ));
    }

    if !force {
        eprint!("Delete bucket `{target}` and ALL its objects? [y/N] ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    let client = make_client(&remote.alias).await?;
    let removed = client.delete_bucket(bucket).await?;

    if mode == OutputMode::Json {
        print_json(&serde_json::json!({ "bucket": target, "objects_removed": removed }));
    } else {
        println!("Removed bucket {target} ({removed} object(s))");
    }
    Ok(())
}
