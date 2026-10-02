//! Shared bucket-quota enforcement for every write path (plain REST `PUT`,
//! S3 `PutObject`/`CopyObject`/`UploadPart`/`CompleteMultipartUpload`).

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex as StdMutex};

use tokio::sync::{Mutex, OwnedMutexGuard};
use y2q_core::{AnyStorage, Listing, Storage};

use crate::error::AppError;

/// Per-bucket locks for quota'd writes. Retained for the process lifetime so
/// a guard can outlive the lookup that minted it. The std mutex is dropped
/// before any `.await`.
static QUOTA_LOCKS: LazyLock<StdMutex<HashMap<String, Arc<Mutex<()>>>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

/// Byte cap for one write, plus the permit that keeps that check atomic
/// with the commit.
///
/// Quota'd buckets hold a per-bucket mutex from the usage check until the
/// caller drops this value (after the write commits or fails). Buckets
/// without a quota hold nothing and stay fully concurrent. Dropping the
/// permit only releases the lock — it does not add a reservation, because
/// a successful commit is already visible in [`Listing::bucket_usage`].
#[must_use = "hold until the write commits or fails; dropping releases the quota lock"]
pub struct WriteBudget {
    /// Mid-stream plaintext cap: `ceiling` tightened by remaining quota.
    pub max_bytes: u64,
    _permit: Option<OwnedMutexGuard<()>>,
}

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
///
/// Callers must keep the returned [`WriteBudget`] alive until the write
/// commits or fails, and must acquire it before `begin_streaming_put` so
/// the lock order stays quota-then-storage.
pub async fn write_budget(
    storage: &AnyStorage,
    cfg: &y2q_core::BucketConfig,
    bucket: &str,
    key: &str,
    incoming: u64,
    ceiling: u64,
) -> Result<WriteBudget, AppError> {
    let Some(limit) = cfg.quota_bytes else {
        return Ok(WriteBudget {
            max_bytes: ceiling,
            _permit: None,
        });
    };
    // Serialize quota'd writes on this bucket before reading usage, so two
    // puts cannot both observe a total neither can satisfy together.
    let permit = lock_quota_bucket(bucket).await;
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
    Ok(WriteBudget {
        max_bytes: ceiling.min(limit.saturating_sub(effective_used)),
        _permit: Some(permit),
    })
}

async fn lock_quota_bucket(bucket: &str) -> OwnedMutexGuard<()> {
    let mutex = {
        let mut map = QUOTA_LOCKS.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(bucket.to_owned())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    };
    mutex.lock_owned().await
}
