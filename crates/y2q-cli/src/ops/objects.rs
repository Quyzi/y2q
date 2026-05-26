//! Object operations shared by the CLI and the TUI: glob expansion, delete,
//! and same-server copy / rename.

use std::collections::BTreeSet;

use y2q_client::{ClientError, ListOptions, Y2qClient};

/// List every key in `bucket` matching a glob `pattern` (e.g. `logs/*.txt`).
///
/// The literal prefix before the first wildcard is used to scope the server-side
/// listing; the full pattern is then matched client-side.
pub async fn glob_keys(
    client: &Y2qClient,
    bucket: &str,
    pattern: &str,
) -> Result<Vec<String>, ClientError> {
    let glob_prefix = pattern
        .find(['*', '?', '['])
        .map(|i| &pattern[..i])
        .unwrap_or("")
        .to_owned();

    let glob = glob::Pattern::new(pattern).map_err(|e| ClientError::BadRequest {
        message: format!("invalid glob pattern: {e}"),
    })?;

    let mut keys = Vec::new();
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
            if glob.matches(&item.key) {
                keys.push(item.key.clone());
            }
        }

        match page.next {
            Some(cursor) => after = Some(cursor),
            None => break,
        }
    }
    Ok(keys)
}

/// Delete a single object.
pub async fn delete(client: &Y2qClient, bucket: &str, key: &str) -> Result<(), ClientError> {
    client.delete(bucket, key).await
}

/// Apply a label mutation to an object. `op` is `set`, `remove`, or `replace`.
/// Returns the object's full label set after the change.
pub async fn set_labels(
    client: &Y2qClient,
    bucket: &str,
    key: &str,
    op: &str,
    labels: &BTreeSet<(String, String)>,
) -> Result<BTreeSet<(String, String)>, ClientError> {
    client.set_labels(bucket, key, op, labels).await
}

/// Fetch an object's metadata (including its current labels).
pub async fn head(
    client: &Y2qClient,
    bucket: &str,
    key: &str,
) -> Result<y2q_client::ObjectHead, ClientError> {
    client.head(bucket, key).await
}

/// Copy an object to a new key within the same server, preserving its labels.
///
/// Streams the source through memory; intended for interactive single-object
/// renames, not bulk data movement.
pub async fn copy(
    client: &Y2qClient,
    bucket: &str,
    src_key: &str,
    dst_key: &str,
) -> Result<(), ClientError> {
    let head = client.head(bucket, src_key).await?;
    let mut buf: Vec<u8> = Vec::new();
    client.get_to_writer(bucket, src_key, &mut buf).await?;
    let len = buf.len() as u64;
    let labels: BTreeSet<(String, String)> = head.labels;
    client
        .put_from_reader(
            bucket,
            dst_key,
            std::io::Cursor::new(buf),
            Some(len),
            &labels,
            None,
        )
        .await?;
    Ok(())
}

/// Rename an object: copy to `dst_key` then delete `src_key`.
pub async fn rename(
    client: &Y2qClient,
    bucket: &str,
    src_key: &str,
    dst_key: &str,
) -> Result<(), ClientError> {
    copy(client, bucket, src_key, dst_key).await?;
    client.delete(bucket, src_key).await
}
