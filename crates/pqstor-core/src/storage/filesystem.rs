use core::range::RangeInclusive;
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use sha2::Digest;
use uuid::Uuid;

use crate::{Error, Metadata, Object, Storage};

/// UUID v5 namespace used to derive deterministic filenames from object keys.
///
/// This is the RFC 4122 URL namespace (`6ba7b811-9dad-11d1-80b4-00c04fd430c8`),
/// chosen as a stable, well-known constant so the same key always maps to the
/// same filename regardless of which process or host computes it.
const PQSTOR_NAMESPACE: Uuid = Uuid::from_bytes([
    0x6b, 0xa7, 0xb8, 0x11,
    0x9d, 0xad,
    0x11, 0xd1,
    0x80, 0xb4,
    0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
]);

/// A [`Storage`] backend that persists objects on a local filesystem.
///
/// Objects are stored in a two-level hex-sharded directory tree rooted at
/// `base_path`:
///
/// ```text
/// <base_path>/<bucket>/<xx>/<yy>/<uuid>        — object data
/// <base_path>/<bucket>/<xx>/<yy>/<uuid>.meta   — 40-byte metadata sidecar
/// <base_path>/<bucket>/<xx>/<yy>/<uuid>.lock   — ephemeral write-lock file
/// ```
///
/// where `<xx>` and `<yy>` are the first two hex-character pairs of a UUID v5
/// derived from the object key, and `<uuid>` is the full UUID. The sharding
/// keeps directory entry counts manageable on filesystems with per-directory
/// limits (e.g. ext3 without `dir_index`).
pub struct FilesystemStorage {
    base_path: PathBuf,
}

impl FilesystemStorage {
    /// Create a new `FilesystemStorage` rooted at `base_path`.
    ///
    /// The directory need not exist yet; it (and any intermediate directories)
    /// will be created on the first [`Storage::put`] call.
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self { base_path: base_path.into() }
    }

    /// Derive the canonical filesystem path for `(bucket, key)`.
    ///
    /// The path is deterministic: the same inputs always produce the same path.
    /// Callers can append extensions (`.meta`, `.lock`, `.tmp`) to get the
    /// paths of related sidecar files.
    fn key_path(&self, bucket: &str, key: &str) -> PathBuf {
        let id = Uuid::new_v5(&PQSTOR_NAMESPACE, key.as_bytes());
        let s = id.hyphenated().to_string();
        self.base_path.join(bucket).join(&s[0..2]).join(&s[2..4]).join(&s)
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
        || !bucket.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::InvalidBucket { bucket: bucket.to_owned() });
    }
    Ok(())
}

/// Validate that `key` is a legal object key.
///
/// Keys must be non-empty, free of null bytes, and at most 1 024 bytes long.
fn validate_key(key: &str) -> Result<(), Error> {
    const MAX_KEY_LEN: usize = 1024;
    if key.is_empty() || key.contains('\0') || key.len() > MAX_KEY_LEN {
        return Err(Error::InvalidKey { key: key.to_owned() });
    }
    Ok(())
}

/// Encode a [`Metadata`] value into the 40-byte on-disk format.
///
/// Layout (all fields little-endian `u64`):
///
/// | Offset | Field             |
/// |--------|-------------------|
/// | 0–7    | `created`         |
/// | 8–15   | `modified`        |
/// | 16–23  | `size`            |
/// | 24–31  | `checksum_md5`    |
/// | 32–39  | `checksum_sha256` |
fn serialize_metadata(m: &Metadata) -> [u8; 40] {
    let mut buf = [0u8; 40];
    buf[0..8].copy_from_slice(&m.created.to_le_bytes());
    buf[8..16].copy_from_slice(&m.modified.to_le_bytes());
    buf[16..24].copy_from_slice(&m.size.to_le_bytes());
    buf[24..32].copy_from_slice(&m.checksum_md5.to_le_bytes());
    buf[32..40].copy_from_slice(&m.checksum_sha256.to_le_bytes());
    buf
}

/// Decode a [`Metadata`] value from the 40-byte on-disk format produced by
/// [`serialize_metadata`].
fn deserialize_metadata(buf: &[u8; 40]) -> Metadata {
    Metadata {
        created:         u64::from_le_bytes(buf[0..8].try_into().unwrap()),
        modified:        u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        size:            u64::from_le_bytes(buf[16..24].try_into().unwrap()),
        checksum_md5:    u64::from_le_bytes(buf[24..32].try_into().unwrap()),
        checksum_sha256: u64::from_le_bytes(buf[32..40].try_into().unwrap()),
    }
}

/// Compute the MD5 and SHA-256 checksums of `data`, returning each as the
/// first 8 bytes of the digest interpreted as a little-endian `u64`.
fn compute_checksums(data: &[u8]) -> (u64, u64) {
    let md5_digest = md5::Md5::digest(data);
    let sha256_digest = sha2::Sha256::digest(data);
    let md5_u64 = u64::from_le_bytes(md5_digest[0..8].try_into().unwrap());
    let sha256_u64 = u64::from_le_bytes(sha256_digest[0..8].try_into().unwrap());
    (md5_u64, sha256_u64)
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

/// Read the `created` timestamp (first 8 bytes) from an existing `.meta` file.
///
/// Returns `None` if the file does not exist or is too short to contain a
/// valid timestamp.
async fn read_created_timestamp(meta_path: &Path) -> Option<u64> {
    let bytes = tokio::fs::read(meta_path).await.ok()?;
    if bytes.len() < 8 { return None; }
    Some(u64::from_le_bytes(bytes[0..8].try_into().unwrap()))
}

impl Storage for FilesystemStorage {
    async fn get(&self, bucket: &str, key: &str) -> Result<Object, Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;

        let data_path = self.key_path(bucket, key);
        check_not_locked(&data_path.with_extension("lock"), bucket, key).await?;

        match tokio::fs::read(&data_path).await {
            Ok(bytes) => Ok(Object::new(Bytes::from(bytes))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::NotFound { bucket: bucket.to_owned(), key: key.to_owned() })
            }
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
                return Err(Error::NotFound { bucket: bucket.to_owned(), key: key.to_owned() });
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

    async fn put(&self, bucket: &str, key: &str, payload: Object) -> Result<bool, Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;

        let data_path = self.key_path(bucket, key);
        let meta_path = data_path.with_extension("meta");
        let lock_path = data_path.with_extension("lock");
        let tmp_path = data_path.with_extension("tmp");

        if let Some(parent) = data_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| Error::InternalError {
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
        };

        tokio::fs::write(&tmp_path, data).await.map_err(|e| Error::InternalError {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            operation: "put".to_owned(),
            message: e.to_string(),
        })?;
        tokio::fs::rename(&tmp_path, &data_path).await.map_err(|e| Error::InternalError {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            operation: "put".to_owned(),
            message: e.to_string(),
        })?;
        tokio::fs::write(&meta_path, serialize_metadata(&metadata)).await.map_err(|e| {
            Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "put".to_owned(),
                message: e.to_string(),
            }
        })?;

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
                return Err(Error::NotFound { bucket: bucket.to_owned(), key: key.to_owned() });
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
            return Err(Error::NotFound { bucket: bucket.to_owned(), key: key.to_owned() });
        }

        let bytes = tokio::fs::read(&meta_path).await.map_err(|e| Error::InternalError {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            operation: "describe".to_owned(),
            message: e.to_string(),
        })?;

        if bytes.len() < 40 {
            return Err(Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "describe".to_owned(),
                message: "metadata file is truncated".to_owned(),
            });
        }

        let arr: &[u8; 40] = bytes[0..40].try_into().unwrap();
        Ok(deserialize_metadata(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_storage() -> (FilesystemStorage, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(dir.path());
        (storage, dir)
    }

    fn make_object(data: &[u8]) -> Object {
        Object::new(Bytes::copy_from_slice(data))
    }

    #[tokio::test]
    async fn put_then_get_roundtrip() {
        let (s, _dir) = make_storage();
        s.put("bucket1", "my-key", make_object(b"hello world")).await.unwrap();
        let got = s.get("bucket1", "my-key").await.unwrap();
        assert_eq!(&got[..], b"hello world");
    }

    #[tokio::test]
    async fn put_returns_overwrite_flag() {
        let (s, _dir) = make_storage();
        let first = s.put("bucket1", "k", make_object(b"v1")).await.unwrap();
        let second = s.put("bucket1", "k", make_object(b"v2")).await.unwrap();
        assert!(!first);
        assert!(second);
    }

    #[tokio::test]
    async fn describe_after_put() {
        let (s, _dir) = make_storage();
        let data = b"test payload";
        s.put("b", "k", make_object(data)).await.unwrap();
        let meta = s.describe("b", "k").await.unwrap();
        assert_eq!(meta.size, data.len() as u64);
        assert!(meta.created > 0);
        assert!(meta.modified >= meta.created);
    }

    #[tokio::test]
    async fn overwrite_preserves_created() {
        let (s, _dir) = make_storage();
        s.put("b", "k", make_object(b"v1")).await.unwrap();
        let meta1 = s.describe("b", "k").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        s.put("b", "k", make_object(b"v2")).await.unwrap();
        let meta2 = s.describe("b", "k").await.unwrap();
        assert_eq!(meta1.created, meta2.created);
        assert!(meta2.modified >= meta2.created);
    }

    #[tokio::test]
    async fn delete_removes_files() {
        let (s, _dir) = make_storage();
        s.put("b", "k", make_object(b"data")).await.unwrap();
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
        s.put("b", "k", make_object(b"x")).await.unwrap();
        let lock_path = s.key_path("b", "k").with_extension("lock");
        tokio::fs::write(&lock_path, 1_000_000_000u64.to_le_bytes()).await.unwrap();
        let err = s.get("b", "k").await.unwrap_err();
        assert!(matches!(err, crate::Error::Locked { .. }));
        tokio::fs::remove_file(&lock_path).await.unwrap();
    }

    #[tokio::test]
    async fn get_range_returns_slice() {
        let (s, _dir) = make_storage();
        s.put("b", "k", make_object(b"abcdefgh")).await.unwrap();
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
}
