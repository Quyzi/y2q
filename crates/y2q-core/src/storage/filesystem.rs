use core::range::RangeInclusive;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use bytes::Bytes;
use sha2::Digest;
use uuid::Uuid;

use crate::{
    CacheRebuildStatus, DEFAULT_LIST_LIMIT, Error, ListOptions, ListPage, Listing, MAX_LIST_LIMIT,
    Metadata, MetadataIndex, Object, PutOptions, StaleLock, Storage, StorageExt,
    storage::locks::{clear_stale_locks_under, list_stale_locks_under},
};

/// UUID v5 namespace used to derive deterministic filenames from object keys.
///
/// This is the RFC 4122 URL namespace (`6ba7b811-9dad-11d1-80b4-00c04fd430c8`),
/// chosen as a stable, well-known constant so the same key always maps to the
/// same filename regardless of which process or host computes it.
const Y2Q_NAMESPACE: Uuid = Uuid::from_bytes([
    0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
]);

/// A [`Storage`] backend that persists objects on a local filesystem.
///
/// Objects are stored in a two-level hex-sharded directory tree rooted at
/// `base_path`:
///
/// ```text
/// <base_path>/<bucket>/<xx>/<yy>/<uuid>        — object data
/// <base_path>/<bucket>/<xx>/<yy>/<uuid>.meta   — JSON metadata sidecar
/// <base_path>/<bucket>/<xx>/<yy>/<uuid>.lock   — ephemeral write-lock file
/// ```
///
/// where `<xx>` and `<yy>` are the first two hex-character pairs of a UUID v5
/// derived from the object key, and `<uuid>` is the full UUID. The sharding
/// keeps directory entry counts manageable on filesystems with per-directory
/// limits (e.g. ext3 without `dir_index`).
///
/// A secondary [`MetadataIndex`] (redb-backed) is kept in sync on every
/// `put` / `delete`. The on-disk sidecar is the source of truth: index
/// failures are logged but do not fail the operation, since the index can be
/// rebuilt from a sidecar scan.
pub struct FilesystemStorage {
    base_path: PathBuf,
    index: Arc<MetadataIndex>,
    rebuild_state: Arc<tokio::sync::Mutex<CacheRebuildStatus>>,
}

impl FilesystemStorage {
    /// Create a new `FilesystemStorage` rooted at `base_path`, with a
    /// secondary metadata index file at `index_path`.
    ///
    /// `base_path` is created if it does not yet exist, then canonicalized so
    /// that `Metadata::disk_path` is consistently absolute. The parent of
    /// `index_path` is also created on demand.
    pub fn new(base_path: impl Into<PathBuf>, index_path: impl AsRef<Path>) -> Result<Self, Error> {
        let base_path = base_path.into();
        std::fs::create_dir_all(&base_path).map_err(|e| Error::InternalError {
            bucket: String::new(),
            key: String::new(),
            operation: "open".to_owned(),
            message: format!("create base_path: {e}"),
        })?;
        let base_path = std::fs::canonicalize(&base_path).map_err(|e| Error::InternalError {
            bucket: String::new(),
            key: String::new(),
            operation: "open".to_owned(),
            message: format!("canonicalize base_path: {e}"),
        })?;
        let index_path = index_path.as_ref();
        if let Some(parent) = index_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::InternalError {
                bucket: String::new(),
                key: String::new(),
                operation: "open".to_owned(),
                message: format!("create index parent: {e}"),
            })?;
        }
        let index = MetadataIndex::open(index_path)?;
        Ok(Self {
            base_path,
            index: Arc::new(index),
            rebuild_state: Arc::new(tokio::sync::Mutex::new(CacheRebuildStatus::Idle)),
        })
    }

    /// Access the underlying metadata index, e.g. for `lookup_by_label`.
    pub fn index(&self) -> &MetadataIndex {
        &self.index
    }

    /// Derive the canonical filesystem path for `(bucket, key)`.
    ///
    /// The path is deterministic: the same inputs always produce the same path.
    /// Callers can append extensions (`.meta`, `.lock`, `.tmp`) to get the
    /// paths of related sidecar files.
    fn key_path(&self, bucket: &str, key: &str) -> PathBuf {
        let id = Uuid::new_v5(&Y2Q_NAMESPACE, key.as_bytes());
        let s = id.hyphenated().to_string();
        self.base_path
            .join(bucket)
            .join(&s[0..2])
            .join(&s[2..4])
            .join(&s)
    }
}

/// Validate that `bucket` is a safe directory name.
///
/// Buckets must be non-empty and contain only alphanumeric characters, `-`, or
/// `_`. Path separators and `..` components are rejected to prevent escaping
/// the storage root.
fn validate_bucket(bucket: &str) -> Result<(), Error> {
    if bucket.is_empty()
        || bucket.contains('/')
        || bucket.contains('\\')
        || bucket.contains("..")
        || !bucket
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::InvalidBucket {
            bucket: bucket.to_owned(),
        });
    }
    Ok(())
}

/// Validate that `key` is a legal object key.
///
/// Keys must be non-empty, free of null bytes, and at most 1 024 bytes long.
fn validate_key(key: &str) -> Result<(), Error> {
    const MAX_KEY_LEN: usize = 1024;
    if key.is_empty() || key.contains('\0') || key.len() > MAX_KEY_LEN {
        return Err(Error::InvalidKey {
            key: key.to_owned(),
        });
    }
    Ok(())
}

/// Encode `metadata` as pretty-printed JSON for the on-disk sidecar.
fn encode_metadata(meta: &Metadata) -> Result<Vec<u8>, std::io::Error> {
    serde_json::to_vec_pretty(meta)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Read and parse the JSON metadata sidecar at `path`.
async fn read_metadata_sidecar(path: &Path) -> Result<Metadata, std::io::Error> {
    let bytes = tokio::fs::read(path).await?;
    serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Compute the MD5 and SHA-256 checksums of `data`, returning each as the full
/// digest encoded with standard base64 (RFC 4648 §4, padded).
fn compute_checksums(data: &[u8]) -> (String, String) {
    let md5_digest = md5::Md5::digest(data);
    let sha256_digest = sha2::Sha256::digest(data);
    let engine = base64::engine::general_purpose::STANDARD;
    (engine.encode(md5_digest), engine.encode(sha256_digest))
}

/// Return the current time as nanoseconds since the Unix epoch.
fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// RAII guard that holds a write lock on an object for the duration of a
/// [`Storage::put`] operation.
///
/// The lock is represented by a `.lock` sidecar file created with `O_EXCL`
/// (via [`tokio::fs::OpenOptions::create_new`]), which is atomic on Linux.
/// The file contains the lock acquisition time as a little-endian `u64` of
/// nanoseconds since the Unix epoch, so callers can report how long the lock
/// has been held.
///
/// The lock file is removed synchronously in [`Drop`] to ensure it is always
/// cleaned up, even if the future holding the guard is cancelled.
struct LockGuard {
    path: PathBuf,
}

impl LockGuard {
    /// Attempt to acquire the lock at `path`.
    ///
    /// Returns `Ok(guard)` on success. Returns [`Error::Locked`] if the lock
    /// file already exists, or [`Error::InternalError`] for any other I/O failure.
    async fn acquire(path: PathBuf, bucket: &str, key: &str) -> Result<Self, Error> {
        use tokio::io::AsyncWriteExt;

        let result = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await;

        match result {
            Ok(mut f) => {
                f.write_all(&now_nanos().to_le_bytes()).await.ok();
                Ok(LockGuard { path })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let since = read_lock_timestamp(&path).await;
                Err(Error::Locked {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    since,
                })
            }
            Err(e) => Err(Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "lock".to_owned(),
                message: e.to_string(),
            }),
        }
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Read the lock acquisition timestamp from `path`.
///
/// Falls back to [`SystemTime::now`] if the file cannot be read or is too short.
async fn read_lock_timestamp(path: &Path) -> SystemTime {
    if let Ok(bytes) = tokio::fs::read(path).await
        && bytes.len() >= 8
    {
        let nanos = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        return UNIX_EPOCH + std::time::Duration::from_nanos(nanos);
    }
    SystemTime::now()
}

/// Return [`Error::Locked`] if a `.lock` file exists at `lock_path`.
///
/// Called by read operations (`get`, `get_range`, `describe`, `delete`) before
/// any I/O so they never observe a partially-written object.
async fn check_not_locked(lock_path: &Path, bucket: &str, key: &str) -> Result<(), Error> {
    if tokio::fs::try_exists(lock_path).await.unwrap_or(false) {
        let since = read_lock_timestamp(lock_path).await;
        return Err(Error::Locked {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            since,
        });
    }
    Ok(())
}

/// Read the `created` timestamp from an existing JSON metadata sidecar.
///
/// Returns `None` if the file does not exist or cannot be parsed.
async fn read_created_timestamp(meta_path: &Path) -> Option<u64> {
    read_metadata_sidecar(meta_path)
        .await
        .ok()
        .map(|m| m.created)
}

impl Storage for FilesystemStorage {
    async fn get(&self, bucket: &str, key: &str) -> Result<Object, Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;

        let data_path = self.key_path(bucket, key);
        check_not_locked(&data_path.with_extension("lock"), bucket, key).await?;

        match tokio::fs::read(&data_path).await {
            Ok(bytes) => Ok(Object::new(Bytes::from(bytes))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::NotFound {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
            }),
            Err(e) => Err(Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "get".to_owned(),
                message: e.to_string(),
            }),
        }
    }

    async fn get_range(
        &self,
        bucket: &str,
        key: &str,
        range: RangeInclusive<u64>,
    ) -> Result<Bytes, Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;

        let data_path = self.key_path(bucket, key);
        check_not_locked(&data_path.with_extension("lock"), bucket, key).await?;

        let data = match tokio::fs::read(&data_path).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::NotFound {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                });
            }
            Err(e) => {
                return Err(Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "get_range".to_owned(),
                    message: e.to_string(),
                });
            }
        };

        let start = range.start as usize;
        let end = (range.last as usize).min(data.len().saturating_sub(1));

        if start >= data.len() {
            return Ok(Bytes::new());
        }
        Ok(Bytes::copy_from_slice(&data[start..=end]))
    }

    // NOTE on durability: this backend currently performs best-effort writes
    // regardless of `options.sync`. The metadata sidecar and object data are
    // written via `tokio::fs::write` (which does not fsync) and the rename is
    // atomic but unfenced. A later change may upgrade this backend to honour
    // `SyncLevel::Durable`; the field is accepted today so the API is stable.
    async fn put(
        &self,
        bucket: &str,
        key: &str,
        payload: Object,
        options: PutOptions,
    ) -> Result<bool, Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;
        let _ = &options.sync; // documented above; honoured by UringStorage

        let data_path = self.key_path(bucket, key);
        let meta_path = data_path.with_extension("meta");
        let lock_path = data_path.with_extension("lock");
        let tmp_path = data_path.with_extension("tmp");

        if let Some(parent) = data_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "put".to_owned(),
                    message: e.to_string(),
                })?;
        }

        let _guard = LockGuard::acquire(lock_path, bucket, key).await?;

        let is_overwrite = tokio::fs::try_exists(&data_path).await.unwrap_or(false);

        let data: &[u8] = &payload;
        let now = now_nanos();
        let created = if is_overwrite {
            read_created_timestamp(&meta_path).await.unwrap_or(now)
        } else {
            now
        };

        let (checksum_md5, checksum_sha256) = compute_checksums(data);
        let metadata = Metadata {
            created,
            modified: now,
            size: data.len() as u64,
            checksum_md5,
            checksum_sha256,
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            disk_path: data_path.clone(),
            url_path: format!("{bucket}/{key}"),
            labels: options.labels,
        };

        tokio::fs::write(&tmp_path, data)
            .await
            .map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "put".to_owned(),
                message: e.to_string(),
            })?;
        tokio::fs::rename(&tmp_path, &data_path)
            .await
            .map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "put".to_owned(),
                message: e.to_string(),
            })?;

        let encoded = encode_metadata(&metadata).map_err(|e| Error::InternalError {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            operation: "put".to_owned(),
            message: e.to_string(),
        })?;
        tokio::fs::write(&meta_path, &encoded)
            .await
            .map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "put".to_owned(),
                message: e.to_string(),
            })?;

        if let Err(e) = self.index.upsert(&metadata).await {
            tracing::warn!(
                bucket = bucket,
                key = key,
                error = %e,
                "metadata index upsert failed; sidecar is authoritative"
            );
        }

        Ok(is_overwrite)
    }

    async fn delete(&self, bucket: &str, key: &str) -> Result<Object, Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;

        let data_path = self.key_path(bucket, key);
        let lock_path = data_path.with_extension("lock");
        let meta_path = data_path.with_extension("meta");

        check_not_locked(&lock_path, bucket, key).await?;

        let data = match tokio::fs::read(&data_path).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::NotFound {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                });
            }
            Err(e) => {
                return Err(Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "delete".to_owned(),
                    message: e.to_string(),
                });
            }
        };

        tokio::fs::remove_file(&data_path).await.ok();
        tokio::fs::remove_file(&meta_path).await.ok();

        if let Err(e) = self.index.remove(bucket, key).await {
            tracing::warn!(
                bucket = bucket,
                key = key,
                error = %e,
                "metadata index remove failed; sidecar is authoritative"
            );
        }

        Ok(Object::new(Bytes::from(data)))
    }

    async fn describe(&self, bucket: &str, key: &str) -> Result<Metadata, Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;

        let data_path = self.key_path(bucket, key);
        let lock_path = data_path.with_extension("lock");
        let meta_path = data_path.with_extension("meta");

        check_not_locked(&lock_path, bucket, key).await?;

        if !tokio::fs::try_exists(&data_path).await.unwrap_or(false) {
            return Err(Error::NotFound {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
            });
        }

        read_metadata_sidecar(&meta_path)
            .await
            .map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "describe".to_owned(),
                message: e.to_string(),
            })
    }
}

impl Listing for FilesystemStorage {
    /// Enumerate every bucket that has at least one object, by reading the
    /// secondary index. Buckets are returned sorted ascending.
    ///
    /// The index is the source of truth here: an empty bucket directory on
    /// disk (e.g. leftover from a deleted object) does not surface, and any
    /// bucket present in the index is listed.
    async fn list_buckets(&self) -> Result<Vec<String>, Error> {
        self.index.list_buckets().await
    }

    async fn list_objects(&self, bucket: &str, options: ListOptions) -> Result<ListPage, Error> {
        validate_bucket(bucket)?;
        let limit = options
            .limit
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_LIST_LIMIT)
            .min(MAX_LIST_LIMIT);
        self.index
            .scan_objects(
                bucket,
                options.prefix.as_deref(),
                options.after.as_deref(),
                limit,
            )
            .await
    }
}

impl StorageExt for FilesystemStorage {
    /// Spawn a background task that reconciles the secondary index against the
    /// on-disk sidecar tree. Returns [`Error::RebuildAlreadyRunning`] if a
    /// rebuild is already in progress.
    async fn rebuild_cache(&self) -> Result<(), Error> {
        {
            let mut state = self.rebuild_state.lock().await;
            if matches!(*state, CacheRebuildStatus::Running(_)) {
                return Err(Error::RebuildAlreadyRunning);
            }
            *state = CacheRebuildStatus::Running(0);
        }

        let base_path = self.base_path.clone();
        let index = self.index.clone();
        let state = self.rebuild_state.clone();
        tokio::spawn(async move {
            let result = run_rebuild(base_path, index, state.clone()).await;
            let mut s = state.lock().await;
            *s = match result {
                Ok(()) => CacheRebuildStatus::Completed,
                Err(msg) => {
                    tracing::error!(error = %msg, "cache rebuild failed");
                    CacheRebuildStatus::Failed(msg)
                }
            };
        });

        Ok(())
    }

    async fn rebuild_progress(&self) -> Result<CacheRebuildStatus, Error> {
        Ok(self.rebuild_state.lock().await.clone())
    }

    async fn list_stale_locks(&self, older_than: SystemTime) -> Result<Vec<StaleLock>, Error> {
        list_stale_locks_under(&self.base_path, older_than)
            .await
            .map_err(|e| Error::InternalError {
                bucket: String::new(),
                key: String::new(),
                operation: "list_stale_locks".to_owned(),
                message: e.to_string(),
            })
    }

    async fn clear_stale_locks(&self, older_than: SystemTime) -> Result<u64, Error> {
        clear_stale_locks_under(&self.base_path, older_than)
            .await
            .map_err(|e| Error::InternalError {
                bucket: String::new(),
                key: String::new(),
                operation: "clear_stale_locks".to_owned(),
                message: e.to_string(),
            })
    }
}

/// Walk every `.meta` sidecar under `base_path`, upsert it into `index`, and
/// then drop any index rows that no longer have a sidecar on disk. Updates
/// `state` with `Running(pct)` periodically; capped at 99 until the call site
/// transitions to `Completed`.
async fn run_rebuild(
    base_path: PathBuf,
    index: Arc<MetadataIndex>,
    state: Arc<tokio::sync::Mutex<CacheRebuildStatus>>,
) -> Result<(), String> {
    let sidecars = collect_sidecars(&base_path)
        .await
        .map_err(|e| format!("enumerate sidecars: {e}"))?;
    let total = sidecars.len();

    let mut seen: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::with_capacity(total);
    let report_every = (total / 100).max(1);

    for (i, path) in sidecars.into_iter().enumerate() {
        match read_metadata_sidecar(&path).await {
            Ok(meta) => {
                if let Err(e) = index.upsert(&meta).await {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "rebuild: index upsert failed; continuing"
                    );
                }
                seen.insert((meta.bucket, meta.key));
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "rebuild: failed to read sidecar; skipping"
                );
            }
        }
        if i % report_every == 0 && total > 0 {
            let pct = (((i + 1) * 100 / total) as u8).min(99);
            *state.lock().await = CacheRebuildStatus::Running(pct);
        }
    }

    let all_keys = index
        .list_all_keys()
        .await
        .map_err(|e| format!("list index keys: {e}"))?;
    for (bucket, key) in all_keys {
        if !seen.contains(&(bucket.clone(), key.clone()))
            && let Err(e) = index.remove(&bucket, &key).await
        {
            tracing::warn!(
                bucket = %bucket,
                key = %key,
                error = %e,
                "rebuild: stale index row removal failed; continuing"
            );
        }
    }

    Ok(())
}

/// Recursively gather every `*.meta` path under `base_path/<bucket>/xx/yy/`.
///
/// Bucket directories whose name fails [`validate_bucket`] are skipped, which
/// excludes reserved files like `_y2q_index.redb`.
async fn collect_sidecars(base_path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut buckets = tokio::fs::read_dir(base_path).await?;
    while let Some(b_entry) = buckets.next_entry().await? {
        if !b_entry.file_type().await?.is_dir() {
            continue;
        }
        let bucket_name = match b_entry.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue,
        };
        if validate_bucket(&bucket_name).is_err() {
            continue;
        }
        let bucket_path = b_entry.path();
        let mut l1 = tokio::fs::read_dir(&bucket_path).await?;
        while let Some(l1_entry) = l1.next_entry().await? {
            if !l1_entry.file_type().await?.is_dir() {
                continue;
            }
            let mut l2 = tokio::fs::read_dir(l1_entry.path()).await?;
            while let Some(l2_entry) = l2.next_entry().await? {
                if !l2_entry.file_type().await?.is_dir() {
                    continue;
                }
                let mut files = tokio::fs::read_dir(l2_entry.path()).await?;
                while let Some(f) = files.next_entry().await? {
                    let p = f.path();
                    if p.extension().is_some_and(|e| e == "meta") {
                        out.push(p);
                    }
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    fn make_storage() -> (FilesystemStorage, TempDir) {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("data");
        let index = dir.path().join("index.redb");
        let storage = FilesystemStorage::new(base, index).unwrap();
        (storage, dir)
    }

    fn make_object(data: &[u8]) -> Object {
        Object::new(Bytes::copy_from_slice(data))
    }

    fn opts(labels: &[(&str, &str)]) -> PutOptions {
        let mut m = BTreeMap::new();
        for (k, v) in labels {
            m.insert((*k).to_owned(), (*v).to_owned());
        }
        PutOptions {
            labels: m,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn put_then_get_roundtrip() {
        let (s, _dir) = make_storage();
        s.put(
            "bucket1",
            "my-key",
            make_object(b"hello world"),
            PutOptions::default(),
        )
        .await
        .unwrap();
        let got = s.get("bucket1", "my-key").await.unwrap();
        assert_eq!(&got[..], b"hello world");
    }

    #[tokio::test]
    async fn put_returns_overwrite_flag() {
        let (s, _dir) = make_storage();
        let first = s
            .put("bucket1", "k", make_object(b"v1"), PutOptions::default())
            .await
            .unwrap();
        let second = s
            .put("bucket1", "k", make_object(b"v2"), PutOptions::default())
            .await
            .unwrap();
        assert!(!first);
        assert!(second);
    }

    #[tokio::test]
    async fn describe_after_put() {
        let (s, _dir) = make_storage();
        let data = b"test payload";
        s.put("b", "k", make_object(data), PutOptions::default())
            .await
            .unwrap();
        let meta = s.describe("b", "k").await.unwrap();
        assert_eq!(meta.size, data.len() as u64);
        assert!(meta.created > 0);
        assert!(meta.modified >= meta.created);
        assert_eq!(meta.bucket, "b");
        assert_eq!(meta.key, "k");
        assert_eq!(meta.url_path, "b/k");
        assert!(meta.labels.is_empty());
        assert!(meta.disk_path.is_absolute());
        // Base64 MD5 = 24 chars (16 raw + padding), SHA-256 = 44 chars.
        assert_eq!(meta.checksum_md5.len(), 24);
        assert_eq!(meta.checksum_sha256.len(), 44);
    }

    #[tokio::test]
    async fn overwrite_preserves_created() {
        let (s, _dir) = make_storage();
        s.put("b", "k", make_object(b"v1"), PutOptions::default())
            .await
            .unwrap();
        let meta1 = s.describe("b", "k").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        s.put("b", "k", make_object(b"v2"), PutOptions::default())
            .await
            .unwrap();
        let meta2 = s.describe("b", "k").await.unwrap();
        assert_eq!(meta1.created, meta2.created);
        assert!(meta2.modified >= meta2.created);
    }

    #[tokio::test]
    async fn delete_removes_files() {
        let (s, _dir) = make_storage();
        s.put("b", "k", make_object(b"data"), PutOptions::default())
            .await
            .unwrap();
        s.delete("b", "k").await.unwrap();
        let err = s.get("b", "k").await.unwrap_err();
        assert!(matches!(err, crate::Error::NotFound { .. }));
        let data_path = s.key_path("b", "k");
        assert!(!data_path.exists());
        assert!(!data_path.with_extension("meta").exists());
    }

    #[tokio::test]
    async fn locked_object_returns_error() {
        let (s, _dir) = make_storage();
        s.put("b", "k", make_object(b"x"), PutOptions::default())
            .await
            .unwrap();
        let lock_path = s.key_path("b", "k").with_extension("lock");
        tokio::fs::write(&lock_path, 1_000_000_000u64.to_le_bytes())
            .await
            .unwrap();
        let err = s.get("b", "k").await.unwrap_err();
        assert!(matches!(err, crate::Error::Locked { .. }));
        tokio::fs::remove_file(&lock_path).await.unwrap();
    }

    #[tokio::test]
    async fn get_range_returns_slice() {
        let (s, _dir) = make_storage();
        s.put("b", "k", make_object(b"abcdefgh"), PutOptions::default())
            .await
            .unwrap();
        let slice = s.get_range("b", "k", (2u64..=5u64).into()).await.unwrap();
        assert_eq!(&slice[..], b"cdef");
    }

    #[tokio::test]
    async fn invalid_bucket_error() {
        let (s, _dir) = make_storage();
        let err = s.get("bad/bucket", "k").await.unwrap_err();
        assert!(matches!(err, crate::Error::InvalidBucket { .. }));
        let err2 = s.get("../escape", "k").await.unwrap_err();
        assert!(matches!(err2, crate::Error::InvalidBucket { .. }));
    }

    #[tokio::test]
    async fn get_missing_key_returns_not_found() {
        let (s, _dir) = make_storage();
        let err = s.get("bucket", "no-such-key").await.unwrap_err();
        assert!(matches!(err, crate::Error::NotFound { .. }));
    }

    #[tokio::test]
    async fn put_with_labels_roundtrips_via_describe() {
        let (s, _dir) = make_storage();
        s.put(
            "b",
            "k",
            make_object(b"x"),
            opts(&[("env", "prod"), ("owner", "alice")]),
        )
        .await
        .unwrap();
        let meta = s.describe("b", "k").await.unwrap();
        assert_eq!(meta.labels.get("env").map(String::as_str), Some("prod"));
        assert_eq!(meta.labels.get("owner").map(String::as_str), Some("alice"));
    }

    #[tokio::test]
    async fn index_lookup_by_label() {
        let (s, _dir) = make_storage();
        s.put("b", "k1", make_object(b"a"), opts(&[("env", "prod")]))
            .await
            .unwrap();
        s.put("b", "k2", make_object(b"b"), opts(&[("env", "prod")]))
            .await
            .unwrap();
        s.put("b", "k3", make_object(b"c"), opts(&[("env", "dev")]))
            .await
            .unwrap();
        let mut prods = s.index().lookup_by_label("env", "prod").await.unwrap();
        prods.sort();
        assert_eq!(
            prods,
            vec![
                ("b".to_owned(), "k1".to_owned()),
                ("b".to_owned(), "k2".to_owned()),
            ]
        );
        let devs = s.index().lookup_by_label("env", "dev").await.unwrap();
        assert_eq!(devs, vec![("b".to_owned(), "k3".to_owned())]);
    }

    #[tokio::test]
    async fn overwrite_replaces_labels() {
        let (s, _dir) = make_storage();
        s.put("b", "k", make_object(b"v1"), opts(&[("env", "prod")]))
            .await
            .unwrap();
        s.put("b", "k", make_object(b"v2"), opts(&[("env", "dev")]))
            .await
            .unwrap();
        let prods = s.index().lookup_by_label("env", "prod").await.unwrap();
        assert!(prods.is_empty(), "old label should be removed on overwrite");
        let devs = s.index().lookup_by_label("env", "dev").await.unwrap();
        assert_eq!(devs, vec![("b".to_owned(), "k".to_owned())]);
    }

    #[tokio::test]
    async fn index_cleared_on_delete() {
        let (s, _dir) = make_storage();
        s.put("b", "k", make_object(b"v"), opts(&[("env", "prod")]))
            .await
            .unwrap();
        s.delete("b", "k").await.unwrap();
        let hits = s.index().lookup_by_label("env", "prod").await.unwrap();
        assert!(hits.is_empty());
        let row = s.index().lookup_by_key("b", "k").await.unwrap();
        assert!(row.is_none());
    }

    #[tokio::test]
    async fn index_survives_reopen() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("data");
        let index = dir.path().join("index.redb");
        {
            let s = FilesystemStorage::new(&base, &index).unwrap();
            s.put("b", "k", make_object(b"v"), opts(&[("env", "prod")]))
                .await
                .unwrap();
        }
        let s2 = FilesystemStorage::new(&base, &index).unwrap();
        let hits = s2.index().lookup_by_label("env", "prod").await.unwrap();
        assert_eq!(hits, vec![("b".to_owned(), "k".to_owned())]);
    }

    #[tokio::test]
    async fn list_buckets_empty() {
        let (s, _dir) = make_storage();
        let buckets = s.list_buckets().await.unwrap();
        assert!(buckets.is_empty());
    }

    #[tokio::test]
    async fn list_buckets_returns_sorted_unique() {
        let (s, _dir) = make_storage();
        s.put("zeta", "a", make_object(b"x"), PutOptions::default())
            .await
            .unwrap();
        s.put("alpha", "a", make_object(b"x"), PutOptions::default())
            .await
            .unwrap();
        s.put("alpha", "b", make_object(b"x"), PutOptions::default())
            .await
            .unwrap();
        s.put("mid", "a", make_object(b"x"), PutOptions::default())
            .await
            .unwrap();
        let buckets = s.list_buckets().await.unwrap();
        assert_eq!(buckets, vec!["alpha", "mid", "zeta"]);
    }

    #[tokio::test]
    async fn list_objects_empty_bucket() {
        let (s, _dir) = make_storage();
        let page = s
            .list_objects("nobody", ListOptions::default())
            .await
            .unwrap();
        assert!(page.items.is_empty());
        assert!(page.next.is_none());
    }

    #[tokio::test]
    async fn list_objects_sorted_by_string_key_not_encoded_order() {
        // Regression: redb's length-prefixed encoding puts shorter encoded
        // keys first, so "abz" (len 3) would sort before "abcd" (len 4) in
        // raw redb order. The trait must return string-sorted results.
        let (s, _dir) = make_storage();
        for k in &["abz", "abcd", "aa"] {
            s.put("b", k, make_object(b"x"), PutOptions::default())
                .await
                .unwrap();
        }
        let page = s.list_objects("b", ListOptions::default()).await.unwrap();
        let keys: Vec<_> = page.items.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(keys, vec!["aa", "abcd", "abz"]);
        assert!(page.next.is_none());
    }

    #[tokio::test]
    async fn list_objects_prefix_filter() {
        let (s, _dir) = make_storage();
        for k in &["foo/a", "foo/b", "bar/a"] {
            s.put("b", k, make_object(b"x"), PutOptions::default())
                .await
                .unwrap();
        }
        let page = s
            .list_objects(
                "b",
                ListOptions {
                    prefix: Some("foo/".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let keys: Vec<_> = page.items.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(keys, vec!["foo/a", "foo/b"]);
    }

    #[tokio::test]
    async fn list_objects_pagination_with_cursor() {
        let (s, _dir) = make_storage();
        for k in &["a", "b", "c", "d"] {
            s.put("b", k, make_object(b"x"), PutOptions::default())
                .await
                .unwrap();
        }
        let p1 = s
            .list_objects(
                "b",
                ListOptions {
                    limit: Some(2),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let keys1: Vec<_> = p1.items.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(keys1, vec!["a", "b"]);
        assert_eq!(p1.next.as_deref(), Some("b"));

        let p2 = s
            .list_objects(
                "b",
                ListOptions {
                    after: p1.next,
                    limit: Some(2),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let keys2: Vec<_> = p2.items.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(keys2, vec!["c", "d"]);
        assert!(p2.next.is_none(), "final page should not signal more");
    }

    #[tokio::test]
    async fn list_objects_does_not_leak_other_buckets() {
        let (s, _dir) = make_storage();
        s.put("b1", "a", make_object(b"x"), PutOptions::default())
            .await
            .unwrap();
        s.put("b2", "a", make_object(b"y"), PutOptions::default())
            .await
            .unwrap();
        let page = s.list_objects("b1", ListOptions::default()).await.unwrap();
        let keys: Vec<_> = page.items.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(keys, vec!["a"]);
        assert_eq!(page.items[0].bucket, "b1");
    }

    #[tokio::test]
    async fn list_objects_invalid_bucket() {
        let (s, _dir) = make_storage();
        let err = s
            .list_objects("bad/bucket", ListOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, crate::Error::InvalidBucket { .. }));
    }

    async fn wait_until_done(s: &FilesystemStorage) -> CacheRebuildStatus {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let st = s.rebuild_progress().await.unwrap();
                if matches!(
                    st,
                    CacheRebuildStatus::Completed | CacheRebuildStatus::Failed(_)
                ) {
                    return st;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("rebuild did not finish in time")
    }

    #[tokio::test]
    async fn rebuild_repopulates_empty_index() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("data");
        let index_a = dir.path().join("index_a.redb");
        let index_b = dir.path().join("index_b.redb");

        {
            let s = FilesystemStorage::new(&base, &index_a).unwrap();
            s.put("b1", "k1", make_object(b"v1"), opts(&[("env", "prod")]))
                .await
                .unwrap();
            s.put("b1", "k2", make_object(b"v2"), opts(&[("env", "dev")]))
                .await
                .unwrap();
            s.put("b2", "x", make_object(b"x"), PutOptions::default())
                .await
                .unwrap();
        }

        let s2 = FilesystemStorage::new(&base, &index_b).unwrap();
        assert!(s2.list_buckets().await.unwrap().is_empty());
        assert!(
            s2.index()
                .lookup_by_label("env", "prod")
                .await
                .unwrap()
                .is_empty()
        );

        s2.rebuild_cache().await.unwrap();
        let status = wait_until_done(&s2).await;
        assert!(matches!(status, CacheRebuildStatus::Completed));

        let mut buckets = s2.list_buckets().await.unwrap();
        buckets.sort();
        assert_eq!(buckets, vec!["b1".to_owned(), "b2".to_owned()]);
        assert_eq!(
            s2.index().lookup_by_label("env", "prod").await.unwrap(),
            vec![("b1".to_owned(), "k1".to_owned())]
        );
    }

    #[tokio::test]
    async fn rebuild_drops_stale_entries() {
        let (s, _dir) = make_storage();
        s.put("b", "alive", make_object(b"a"), PutOptions::default())
            .await
            .unwrap();
        s.put("b", "ghost", make_object(b"g"), PutOptions::default())
            .await
            .unwrap();

        let ghost_data = s.key_path("b", "ghost");
        tokio::fs::remove_file(&ghost_data).await.unwrap();
        tokio::fs::remove_file(ghost_data.with_extension("meta"))
            .await
            .unwrap();

        assert!(
            s.index()
                .lookup_by_key("b", "ghost")
                .await
                .unwrap()
                .is_some()
        );

        s.rebuild_cache().await.unwrap();
        let status = wait_until_done(&s).await;
        assert!(matches!(status, CacheRebuildStatus::Completed));

        assert!(
            s.index()
                .lookup_by_key("b", "ghost")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            s.index()
                .lookup_by_key("b", "alive")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn rebuild_progress_reaches_completed() {
        let (s, _dir) = make_storage();
        for i in 0..10 {
            s.put(
                "b",
                &format!("k{i}"),
                make_object(b"v"),
                PutOptions::default(),
            )
            .await
            .unwrap();
        }
        assert!(matches!(
            s.rebuild_progress().await.unwrap(),
            CacheRebuildStatus::Idle
        ));
        s.rebuild_cache().await.unwrap();
        let status = wait_until_done(&s).await;
        assert!(matches!(status, CacheRebuildStatus::Completed));
    }

    #[tokio::test]
    async fn rebuild_rejects_concurrent_calls() {
        let (s, _dir) = make_storage();
        for i in 0..200 {
            s.put(
                "b",
                &format!("k{i}"),
                make_object(b"v"),
                PutOptions::default(),
            )
            .await
            .unwrap();
        }
        s.rebuild_cache().await.unwrap();
        let err = s.rebuild_cache().await.unwrap_err();
        assert!(matches!(err, crate::Error::RebuildAlreadyRunning));
        let _ = wait_until_done(&s).await;
    }
}
