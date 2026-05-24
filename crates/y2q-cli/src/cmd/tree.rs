//! `tree` — render a remote prefix as a directory tree.

use crate::cmd::objects::make_client;
use crate::error::CliError;
use crate::ops::listing::build_tree;
use crate::output::{OutputMode, print_json};
use crate::path::RemotePath;

pub async fn run(
    path: String,
    depth: Option<u32>,
    show_files: bool,
    mode: OutputMode,
) -> Result<(), CliError> {
    let remote = RemotePath::parse(&path)?;
    let bucket = remote.bucket.as_deref().ok_or_else(|| {
        CliError::InvalidPath(format!("{}/", remote.alias), "missing bucket".into())
    })?;

    let client = make_client(&remote.alias).await?;
    let root = build_tree(&client, bucket, remote.key.as_deref()).await?;

    if mode == OutputMode::Json {
        print_json(&root.to_json(&path));
        return Ok(());
    }

    println!("{path}");
    for line in root.render_lines(show_files, depth.unwrap_or(0)) {
        println!("{line}");
    }
    Ok(())
}
