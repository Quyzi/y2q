//! `diff` — compare two trees (local or remote) and report what differs.

use std::path::Path;

use crate::cmd::objects::make_client;
use crate::error::CliError;
use crate::ops::listing::{
    DiffEntries, collect_local_entries, collect_remote_entries, diff_entries,
};
use crate::output::{OutputMode, fmt_bytes, print_json};
use crate::path::{CpEndpoint, RemotePath};

pub async fn run(src: String, dst: String, mode: OutputMode) -> Result<(), CliError> {
    let src_ep = CpEndpoint::parse(&src);
    let dst_ep = CpEndpoint::parse(&dst);

    let src_entries = collect(&src_ep).await?;
    let dst_entries = collect(&dst_ep).await?;
    let rows = diff_entries(&src_entries, &dst_entries);

    if mode == OutputMode::Json {
        print_json(&serde_json::json!({
            "src": src,
            "dst": dst,
            "diffs": rows,
        }));
    } else if rows.is_empty() {
        println!("No differences.");
    } else {
        for r in &rows {
            let (s, d) = (
                r.src_size.map(fmt_bytes).unwrap_or_else(|| "-".into()),
                r.dst_size.map(fmt_bytes).unwrap_or_else(|| "-".into()),
            );
            println!("{:1}  {:>10}  {:>10}  {}", r.op, s, d, r.key);
        }
        println!(
            "\n{} difference(s) — `<` only in src, `>` only in dst, `!` differs.",
            rows.len()
        );
    }
    Ok(())
}

async fn collect(ep: &CpEndpoint) -> Result<DiffEntries, CliError> {
    match ep {
        CpEndpoint::Local(path) => collect_local_entries(Path::new(path)).map_err(CliError::Other),
        CpEndpoint::Remote(remote) => collect_remote(remote).await,
    }
}

async fn collect_remote(remote: &RemotePath) -> Result<DiffEntries, CliError> {
    let bucket = remote.bucket.as_deref().ok_or_else(|| {
        CliError::InvalidPath(format!("{}/", remote.alias), "missing bucket".into())
    })?;
    let client = make_client(&remote.alias).await?;
    Ok(collect_remote_entries(&client, bucket, remote.key.as_deref()).await?)
}
