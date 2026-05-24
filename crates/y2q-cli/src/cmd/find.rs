//! `find` — filter a remote listing by name/size/time.

use crate::cmd::objects::make_client;
use crate::error::CliError;
use crate::ops::listing::{FindFilter, find};
use crate::output::{OutputMode, fmt_bytes, fmt_ns, print_json, print_table};
use crate::path::RemotePath;

pub async fn run(
    path: String,
    name: Option<String>,
    size: Option<String>,
    older_than: Option<String>,
    newer_than: Option<String>,
    mode: OutputMode,
) -> Result<(), CliError> {
    let remote = RemotePath::parse(&path)?;
    let bucket = remote.bucket.as_deref().ok_or_else(|| {
        CliError::InvalidPath(format!("{}/", remote.alias), "missing bucket".into())
    })?;

    let filter = FindFilter::build(
        name.as_deref(),
        size.as_deref(),
        older_than.as_deref(),
        newer_than.as_deref(),
    )
    .map_err(CliError::Other)?;

    let client = make_client(&remote.alias).await?;
    let matches_meta = find(&client, bucket, remote.key.clone(), &filter).await?;

    if mode == OutputMode::Json {
        print_json(&matches_meta);
    } else if matches_meta.is_empty() {
        eprintln!("No matches.");
    } else {
        let rows: Vec<Vec<String>> = matches_meta
            .iter()
            .map(|m| {
                vec![
                    format!("{}/{bucket}/{}", remote.alias, m.key),
                    fmt_bytes(m.size),
                    fmt_ns(m.modified),
                ]
            })
            .collect();
        print_table(&["PATH", "SIZE", "MODIFIED"], &rows);
    }
    Ok(())
}
