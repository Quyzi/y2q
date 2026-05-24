//! `search` - find objects by a label query (server-side).

use crate::cmd::objects::make_client;
use crate::error::CliError;
use crate::output::{OutputMode, fmt_bytes, fmt_ns, print_json, print_table};
use crate::path::RemotePath;

/// Run a label search against the server an alias points to.
///
/// `path` is `alias/` (all buckets), `alias/bucket`, or `alias/bucket/prefix`.
/// `query` is a label expression, e.g. `env == prod and tier != test`.
pub async fn run(path: String, query: String, mode: OutputMode) -> Result<(), CliError> {
    let remote = RemotePath::parse(&path)?;
    let client = make_client(&remote.alias).await?;

    let hits =
        crate::ops::listing::search(&client, remote.bucket.clone(), remote.key.clone(), &query)
            .await?;

    if mode == OutputMode::Json {
        print_json(&hits);
    } else if hits.is_empty() {
        eprintln!("No matches.");
    } else {
        let rows: Vec<Vec<String>> = hits
            .iter()
            .map(|m| {
                vec![
                    format!("{}/{}/{}", remote.alias, m.bucket, m.key),
                    fmt_bytes(m.size),
                    fmt_ns(m.modified),
                ]
            })
            .collect();
        print_table(&["PATH", "SIZE", "MODIFIED"], &rows);
    }
    Ok(())
}
