//! Shared bucket-quota enforcement for every write path (plain REST `PUT`,
//! S3 `PutObject`/`CopyObject`/`UploadPart`/`CompleteMultipartUpload`).

use y2q_core::{AnyStorage, Listing, Storage};

use crate::error::AppError;

/// Effective mid-stream byte cap for a write into `bucket` that replaces
/// `key`: the server-wide `ceiling`, further reduced by the bucket quota's
/// remaining headroom after crediting the object this write will replace.
/// Only quota'd buckets pay the usage scan. Returns
/// [`y2q_core::Error::QuotaExceeded`] when that post-credit usage plus
/// `incoming` exceeds the quota.
///
/// [`Listing::bucket_usage`] sums plaintext [`y2q_core::Metadata::size`].
/// The credit is that same field from [`Storage::describe`] — a missing key
/// credits 0. Any other describe error propagates. `used` on
/// [`y2q_core::Error::QuotaExceeded`] is the post-credit usage compared
/// against the limit (space still occupied by other objects).
pub async fn write_budget(
    storage: &AnyStorage,
    cfg: &y2q_core::BucketConfig,
    bucket: &str,
    key: &str,
    incoming: u64,
    ceiling: u64,
) -> Result<u64, AppError> {
    let Some(limit) = cfg.quota_bytes else {
        return Ok(ceiling);
    };
    let used = storage.bucket_usage(bucket).await.map_err(AppError::from)?;
    let replaced = match storage.describe(bucket, key).await {
        Ok(md) => md.size,
        Err(y2q_core::Error::NotFound { .. }) => 0,
        Err(e) => return Err(AppError::from(e)),
    };
    // Same unit `bucket_usage` sums (`Metadata::size`, plaintext), not
    // `cipher_size`. A shrink that still fits must not be charged for both
    // the old object and the new one.
    let effective_used = used.saturating_sub(replaced);
    if effective_used.saturating_add(incoming) > limit {
        return Err(AppError(y2q_core::Error::QuotaExceeded {
            bucket: bucket.to_owned(),
            limit,
            used: effective_used,
            incoming,
        }));
    }
    Ok(ceiling.min(limit.saturating_sub(effective_used)))
}
