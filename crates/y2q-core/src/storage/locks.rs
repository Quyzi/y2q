//! Stale `.lock` sidecar discovery and cleanup.
//!
//! Both backends serialize per-object writes through a sibling
//! `<uuid>.lock` file created with `O_EXCL` and containing 8 LE bytes of
//! nanoseconds-since-UNIX_EPOCH. The lock is released by
//! `LockGuard::drop` via `remove_file`, but a `SIGKILL` (or any abrupt
//! process death) mid-PUT leaves the file behind. Future writes to that
//! key then fail with [`crate::Error::Locked`] until an operator
//! intervenes.
//!
//! This module walks the on-disk tree and offers two operations against
//! that orphan set: list (dry-run) and clear. The walker is layout-aware
//! but extension-agnostic between backends — both write `.lock` at the
//! same 4-level path shape (`<base>/<bucket>/<xx>/<yy>/<uuid>.lock`).
//!
//! ## Race semantics
//!
//! Scan and unlink are not atomic across the tree. A lock acquired
//! between the scan and the corresponding `remove_file` could be
//! unlinked under a live writer. The worst case is a single retry on
//! the in-flight PUT — `acquire_lock`'s `O_EXCL` semantics mean two
//! writers can never both believe they hold the lock.
//!
//! ## Cross-node clock skew
//!
//! The stamped timestamp comes from the *writing* node's wall clock.
//! Multi-node deployments sharing the backing dir over NFS (not a
//! supported configuration today) would see "stale" relative to that
//! node, not to the clearing node.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::fs;
use tokio::io::AsyncReadExt;

/// One stale lock found on disk.
///
/// `uuid` is the lock file's stem — the deterministic UUID we derive
/// from the original object key. Recovering the human-readable key
/// requires consulting [`crate::MetadataIndex`].
#[derive(Debug, Clone)]
pub struct StaleLock {
    /// The bucket directory the lock lives under.
    pub bucket: String,
    /// `<uuid>` portion of the `.lock` filename, no extension.
    pub uuid: String,
    /// Wall-clock time the lock was acquired, recovered from the file
    /// contents.
    pub locked_since: SystemTime,
}

/// List every `.lock` file whose recorded `locked_since` is **strictly
/// earlier** than `older_than`.
///
/// Locks whose 8-byte timestamp is missing or short-read are treated as
/// "fresh" (skipped) so a half-written lock file is never reported as
/// stale on the basis of partial data.
pub(crate) async fn list_stale_locks_under(
    base_path: &Path,
    older_than: SystemTime,
) -> std::io::Result<Vec<StaleLock>> {
    let mut out = Vec::new();
    let mut paths = Vec::new();
    walk_lock_files(base_path, &mut paths).await?;
    for path in paths {
        let Some((bucket, uuid)) = split_bucket_and_uuid(base_path, &path) else {
            continue;
        };
        let Some(stamp) = read_lock_timestamp(&path).await else {
            continue;
        };
        if stamp < older_than {
            out.push(StaleLock {
                bucket,
                uuid,
                locked_since: stamp,
            });
        }
    }
    Ok(out)
}

/// Remove every `.lock` file whose recorded `locked_since` is strictly
/// earlier than `older_than`. Returns the number successfully removed.
///
/// `ENOENT` on the unlink is treated as success — another worker may
/// have legitimately released the lock between scan and unlink. Any
/// other I/O error aborts the walk.
pub(crate) async fn clear_stale_locks_under(
    base_path: &Path,
    older_than: SystemTime,
) -> std::io::Result<u64> {
    let mut paths = Vec::new();
    walk_lock_files(base_path, &mut paths).await?;
    let mut removed: u64 = 0;
    for path in paths {
        let Some(stamp) = read_lock_timestamp(&path).await else {
            continue;
        };
        if stamp >= older_than {
            continue;
        }
        match fs::remove_file(&path).await {
            Ok(()) => removed += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(removed)
}

/// Recursively gather every `*.lock` path under `<base>/<bucket>/xx/yy/`.
///
/// The walk mirrors `collect_obj_files` and `collect_sidecars` so the
/// three backend rebuild / cleanup paths stay shaped the same way.
/// Directory names are not validated here — `validate_bucket` would
/// require an [`crate::Error`] type and this helper returns
/// `std::io::Result` so it composes with callers. Anything that isn't a
/// directory is silently skipped.
async fn walk_lock_files(base_path: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let mut buckets = match fs::read_dir(base_path).await {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    while let Some(b_entry) = buckets.next_entry().await? {
        if !b_entry.file_type().await?.is_dir() {
            continue;
        }
        let bucket_path = b_entry.path();
        let mut l1 = fs::read_dir(&bucket_path).await?;
        while let Some(l1_entry) = l1.next_entry().await? {
            if !l1_entry.file_type().await?.is_dir() {
                continue;
            }
            let mut l2 = fs::read_dir(l1_entry.path()).await?;
            while let Some(l2_entry) = l2.next_entry().await? {
                if !l2_entry.file_type().await?.is_dir() {
                    continue;
                }
                let mut files = fs::read_dir(l2_entry.path()).await?;
                while let Some(f) = files.next_entry().await? {
                    let p = f.path();
                    if p.extension().is_some_and(|e| e == "lock") {
                        out.push(p);
                    }
                }
            }
        }
    }
    Ok(())
}

/// Read the 8-byte LE timestamp embedded in a `.lock` file.
///
/// Returns `None` on any I/O error or a short read — callers treat that
/// as "lock looks fresh, leave it alone." Mirrors the read pattern in
/// `filesystem::read_lock_timestamp` / `uring::ops::read_lock_timestamp`
/// but is independent so this module stays self-contained.
async fn read_lock_timestamp(path: &Path) -> Option<SystemTime> {
    let mut f = fs::File::open(path).await.ok()?;
    let mut buf = [0u8; 8];
    if f.read_exact(&mut buf).await.is_err() {
        return None;
    }
    let nanos = u64::from_le_bytes(buf);
    Some(UNIX_EPOCH + Duration::from_nanos(nanos))
}

/// Split a `<base>/<bucket>/xx/yy/<uuid>.lock` path into `(bucket, uuid)`.
///
/// Returns `None` if the path doesn't have the expected three-component
/// suffix below `base_path`, or if its stem can't be parsed as UTF-8.
fn split_bucket_and_uuid(base_path: &Path, lock_path: &Path) -> Option<(String, String)> {
    let rel = lock_path.strip_prefix(base_path).ok()?;
    let mut comps = rel.components();
    let bucket = comps.next()?.as_os_str().to_str()?.to_owned();
    // skip <xx>/<yy>/
    comps.next()?;
    comps.next()?;
    let file = comps.next()?.as_os_str().to_str()?;
    let stem = file.strip_suffix(".lock")?.to_owned();
    if comps.next().is_some() {
        return None;
    }
    Some((bucket, stem))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::TempDir;

    /// Build the canonical 4-level path and write `stamp_nanos` as 8 LE
    /// bytes into a `.lock` file at that location.
    async fn plant_lock(base: &Path, bucket: &str, uuid: &str, stamp_nanos: u64) -> PathBuf {
        let dir = base.join(bucket).join(&uuid[0..2]).join(&uuid[2..4]);
        fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join(format!("{uuid}.lock"));
        fs::write(&path, stamp_nanos.to_le_bytes()).await.unwrap();
        path
    }

    fn nanos(t: SystemTime) -> u64 {
        t.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
    }

    #[tokio::test]
    async fn list_returns_only_locks_older_than_cutoff() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let now = SystemTime::now();
        let old = now - Duration::from_secs(60);
        let young = now;
        plant_lock(base, "b1", "aabbccdd-stale", nanos(old)).await;
        plant_lock(base, "b1", "eeffgghh-fresh", nanos(young)).await;

        let cutoff = now - Duration::from_secs(30);
        let locks = list_stale_locks_under(base, cutoff).await.unwrap();
        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].bucket, "b1");
        assert_eq!(locks[0].uuid, "aabbccdd-stale");
    }

    #[tokio::test]
    async fn clear_removes_only_stale_locks() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let now = SystemTime::now();
        let stale_p = plant_lock(
            base,
            "b",
            "11223344-stale",
            nanos(now - Duration::from_secs(60)),
        )
        .await;
        let fresh_p = plant_lock(base, "b", "55667788-fresh", nanos(now)).await;

        let cutoff = now - Duration::from_secs(30);
        let removed = clear_stale_locks_under(base, cutoff).await.unwrap();
        assert_eq!(removed, 1);
        assert!(!stale_p.exists());
        assert!(fresh_p.exists());
    }

    #[tokio::test]
    async fn malformed_lock_files_are_skipped() {
        // < 8 bytes — short read — treated as fresh (not reported, not removed).
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let leaf = base.join("b").join("aa").join("bb");
        fs::create_dir_all(&leaf).await.unwrap();
        let p = leaf.join("partial.lock");
        fs::write(&p, b"abc").await.unwrap();

        let cutoff = SystemTime::now() + Duration::from_secs(60);
        let locks = list_stale_locks_under(base, cutoff).await.unwrap();
        assert!(locks.is_empty());
        let removed = clear_stale_locks_under(base, cutoff).await.unwrap();
        assert_eq!(removed, 0);
        assert!(p.exists(), "malformed lock must not be deleted");
    }

    #[tokio::test]
    async fn missing_base_dir_yields_empty_results() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does-not-exist");
        let now = SystemTime::now();
        assert!(
            list_stale_locks_under(&missing, now)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(clear_stale_locks_under(&missing, now).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn non_lock_files_are_ignored() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let leaf = base.join("b").join("aa").join("bb");
        fs::create_dir_all(&leaf).await.unwrap();
        fs::write(leaf.join("foo.obj"), b"\0").await.unwrap();
        fs::write(leaf.join("foo.meta"), b"{}").await.unwrap();

        let cutoff = SystemTime::now() + Duration::from_secs(60);
        let locks = list_stale_locks_under(base, cutoff).await.unwrap();
        assert!(locks.is_empty());
    }

    #[tokio::test]
    async fn cutoff_boundary_is_strict_less_than() {
        // A lock whose stamp equals the cutoff is NOT stale.
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let now = SystemTime::now();
        plant_lock(base, "b", "deadbeef-edge", nanos(now)).await;

        let locks = list_stale_locks_under(base, now).await.unwrap();
        assert!(locks.is_empty(), "stamp == cutoff must not be reported");
    }
}
