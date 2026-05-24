//! Bucket lifecycle and configuration operations shared by the CLI and the TUI.

use y2q_client::{BucketConfig, ClientError, Y2qClient};

/// Create a bucket. Returns `true` if newly created, `false` if it already existed.
pub async fn create(client: &Y2qClient, bucket: &str) -> Result<bool, ClientError> {
    client.create_bucket(bucket).await
}

/// Delete a bucket and all of its objects. Returns the number of objects removed.
pub async fn delete(client: &Y2qClient, bucket: &str) -> Result<u64, ClientError> {
    client.delete_bucket(bucket).await
}

/// Fetch a bucket's configuration (quota, default SSE).
pub async fn get_config(client: &Y2qClient, bucket: &str) -> Result<BucketConfig, ClientError> {
    client.get_bucket_config(bucket).await
}

/// Persist a bucket's configuration.
pub async fn set_config(
    client: &Y2qClient,
    bucket: &str,
    config: &BucketConfig,
) -> Result<BucketConfig, ClientError> {
    client.set_bucket_config(bucket, config).await
}

/// Parse a human size like `500m`, `2g`, `1KiB` into bytes. Decimal suffixes
/// (k/m/g/t) are powers of 1000; binary suffixes (ki/mi/gi/ti) powers of 1024.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, suffix) = s
        .find(|c: char| c.is_ascii_alphabetic())
        .map(|i| s.split_at(i))
        .unwrap_or((s, ""));
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|e| format!("invalid size `{s}`: {e}"))?;
    let mult = match suffix.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 1u64,
        "K" | "KB" => 1_000,
        "KI" | "KIB" => 1_024,
        "M" | "MB" => 1_000_000,
        "MI" | "MIB" => 1_024 * 1_024,
        "G" | "GB" => 1_000_000_000,
        "GI" | "GIB" => 1_024 * 1_024 * 1_024,
        "T" | "TB" => 1_000_000_000_000,
        "TI" | "TIB" => 1_024u64.pow(4),
        other => return Err(format!("unknown size unit `{other}`")),
    };
    Ok(n.saturating_mul(mult))
}
