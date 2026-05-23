//! `search` - find objects by a label query (server-side).

use y2q_client::{MetadataView, SearchOptions};

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

    let mut after: Option<String> = None;
    let mut hits: Vec<MetadataView> = Vec::new();

    loop {
        let page = client
            .search_labels(
                &query,
                &SearchOptions {
                    bucket: remote.bucket.clone(),
                    prefix: remote.key.clone(),
                    after: after.clone(),
                    limit: Some(1000),
                },
            )
            .await?;
        hits.extend(page.items);
        match page.next {
            Some(c) => after = Some(c),
            None => break,
        }
    }

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
