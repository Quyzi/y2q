//! Shared bucket-quota enforcement for every write path (plain REST `PUT`,
//! S3 `PutObject`/`CopyObject`/`UploadPart`/`CompleteMultipartUpload`).

use y2q_core::{AnyStorage, Listing};

use crate::error::AppError;

/// Effective mid-stream byte cap for a write into `bucket`: the server-wide
/// `ceiling`, further reduced by the bucket quota's remaining headroom.
/// Only quota'd buckets pay the usage scan. Returns
/// [`y2q_core::Error::QuotaExceeded`] when `incoming` alone already exceeds
/// the quota.
pub async fn write_budget(
    storage: &AnyStorage,
    cfg: &y2q_core::BucketConfig,
    bucket: &str,
    incoming: u64,
    ceiling: u64,
) -> Result<u64, AppError> {
    let Some(limit) = cfg.quota_bytes else {
        return Ok(ceiling);
    };
    let used = storage.bucket_usage(bucket).await.map_err(AppError::from)?;
    if used + incoming > limit {
        return Err(AppError(y2q_core::Error::QuotaExceeded {
            bucket: bucket.to_owned(),
            limit,
            used,
            incoming,
        }));
    }
    Ok(ceiling.min(limit.saturating_sub(used)))
}
