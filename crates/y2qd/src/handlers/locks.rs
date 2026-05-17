//! `GET /api/v1/locks` and `DELETE /api/v1/locks` — find and clear stale
//! `.lock` sidecar files left behind by abruptly-killed PUTs.
//!
//! Both endpoints require an `older_than` query parameter. Accepted forms:
//!
//! - A relative duration: `<n>{s|m|h|d|w}` (e.g. `1h`, `30m`, `2d`). The
//!   cutoff is computed as `now - duration`.
//! - An absolute Unix timestamp in seconds: a bare integer (e.g.
//!   `1715000000`). Interpreted as seconds since UNIX_EPOCH.
//!
//! Anything else yields 400 [`Error::InvalidStaleLockThreshold`].
//!
//! Cleaning a stale lock does not touch the metadata index. If the
//! partial PUT also corrupted the object file, run
//! `POST /api/v1/rebuild` afterward.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use actix_web::{HttpResponse, web};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use y2q_core::{AnyStorage, Error as CoreError, StaleLock, StorageExt};

use crate::auth::Authenticated;
use crate::error::{AppError, ErrorBody};

/// Query parameters for `GET` and `DELETE` on `/api/v1/locks`.
#[derive(Debug, Deserialize, IntoParams)]
pub struct LocksQuery {
    /// Required cutoff: either a relative duration (`1h`, `30m`, `45s`,
    /// `2d`, `1w`) or a bare Unix-seconds timestamp.
    pub older_than: String,
}

/// One stale lock returned by `GET /api/v1/locks`.
#[derive(Debug, Serialize, ToSchema)]
pub struct StaleLockEntry {
    /// Bucket directory the lock lives under.
    pub bucket: String,
    /// `<uuid>` portion of the `.lock` filename. Cross-reference with the
    /// metadata index to recover the original object key.
    pub uuid: String,
    /// Unix nanoseconds since epoch — the timestamp recorded inside the
    /// lock file at acquisition time.
    pub locked_since_nanos: u64,
    /// Seconds elapsed between `locked_since` and the time of the scan.
    pub age_seconds: u64,
}

/// JSON body returned by `DELETE /api/v1/locks`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ClearStaleLocksResponse {
    /// Number of `.lock` files successfully unlinked.
    pub removed: u64,
}

/// List stale `.lock` sidecars older than `older_than`.
#[utoipa::path(
    get,
    operation_id = "list_stale_locks",
    path = "/api/v1/locks",
    params(LocksQuery),
    responses(
        (status = 200, description = "Stale locks (dry-run)", body = [StaleLockEntry], content_type = "application/json"),
        (status = 400, description = "Missing or malformed `older_than`", body = ErrorBody, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "admin",
)]
pub async fn list(
    storage: web::Data<Arc<AnyStorage>>,
    query: web::Query<LocksQuery>,
    _auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let now = SystemTime::now();
    let cutoff = parse_older_than(&query.older_than, now)?;
    let locks = storage
        .list_stale_locks(cutoff)
        .await
        .map_err(AppError::from)?;
    let entries: Vec<StaleLockEntry> = locks.into_iter().map(|l| to_entry(l, now)).collect();
    Ok(HttpResponse::Ok().json(entries))
}

/// Remove every stale `.lock` sidecar older than `older_than`.
#[utoipa::path(
    delete,
    operation_id = "clear_stale_locks",
    path = "/api/v1/locks",
    params(LocksQuery),
    responses(
        (status = 200, description = "Stale locks cleared", body = ClearStaleLocksResponse, content_type = "application/json"),
        (status = 400, description = "Missing or malformed `older_than`", body = ErrorBody, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "admin",
)]
pub async fn clear(
    storage: web::Data<Arc<AnyStorage>>,
    query: web::Query<LocksQuery>,
    _auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let now = SystemTime::now();
    let cutoff = parse_older_than(&query.older_than, now)?;
    let removed = storage
        .clear_stale_locks(cutoff)
        .await
        .map_err(AppError::from)?;
    Ok(HttpResponse::Ok().json(ClearStaleLocksResponse { removed }))
}

fn to_entry(l: StaleLock, now: SystemTime) -> StaleLockEntry {
    let locked_since_nanos = l
        .locked_since
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let age_seconds = now
        .duration_since(l.locked_since)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    StaleLockEntry {
        bucket: l.bucket,
        uuid: l.uuid,
        locked_since_nanos,
        age_seconds,
    }
}

/// Parse the `older_than` query value into a `SystemTime` cutoff.
///
/// - All-digit input → Unix seconds since epoch.
/// - `<n>{s|m|h|d|w}` → relative duration; cutoff = `now - duration`.
/// - Empty input or anything else → [`CoreError::InvalidStaleLockThreshold`].
fn parse_older_than(value: &str, now: SystemTime) -> Result<SystemTime, AppError> {
    let bad = || {
        AppError(CoreError::InvalidStaleLockThreshold {
            value: value.to_owned(),
        })
    };
    if value.is_empty() {
        return Err(bad());
    }

    if value.chars().all(|c| c.is_ascii_digit()) {
        let seconds: u64 = value.parse().map_err(|_| bad())?;
        return Ok(UNIX_EPOCH + Duration::from_secs(seconds));
    }

    let last = value.chars().last().ok_or_else(bad)?;
    let unit_secs: u64 = match last {
        's' => 1,
        'm' => 60,
        'h' => 60 * 60,
        'd' => 60 * 60 * 24,
        'w' => 60 * 60 * 24 * 7,
        _ => return Err(bad()),
    };
    let n_str = &value[..value.len() - 1];
    if n_str.is_empty() || !n_str.chars().all(|c| c.is_ascii_digit()) {
        return Err(bad());
    }
    let n: u64 = n_str.parse().map_err(|_| bad())?;
    let duration = Duration::from_secs(n.checked_mul(unit_secs).ok_or_else(bad)?);
    now.checked_sub(duration).ok_or_else(bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_relative_duration_seconds() {
        let now = SystemTime::now();
        let cutoff = parse_older_than("30s", now).unwrap();
        let diff = now.duration_since(cutoff).unwrap();
        assert_eq!(diff.as_secs(), 30);
    }

    #[test]
    fn parse_relative_duration_minutes_hours_days_weeks() {
        let now = SystemTime::now();
        for (s, expected_secs) in [
            ("5m", 5 * 60),
            ("2h", 2 * 60 * 60),
            ("3d", 3 * 60 * 60 * 24),
            ("1w", 60 * 60 * 24 * 7),
        ] {
            let cutoff = parse_older_than(s, now).unwrap();
            let diff = now.duration_since(cutoff).unwrap();
            assert_eq!(diff.as_secs(), expected_secs, "input {s}");
        }
    }

    #[test]
    fn parse_unix_timestamp() {
        let now = SystemTime::now();
        let cutoff = parse_older_than("1715000000", now).unwrap();
        assert_eq!(
            cutoff.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            1_715_000_000
        );
    }

    #[test]
    fn parse_rejects_empty_garbage_and_bad_units() {
        let now = SystemTime::now();
        for bad in ["", "banana", "1y", "h", "1.5h", "-1s", "1 h", " 30s"] {
            let err = parse_older_than(bad, now).unwrap_err();
            assert!(
                matches!(err.0, CoreError::InvalidStaleLockThreshold { .. }),
                "expected InvalidStaleLockThreshold for {bad:?}",
            );
        }
    }
}
