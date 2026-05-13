//! The `UringStorage` backend struct and its trait implementations.
//!
//! The trait methods themselves are thin: they validate inputs, compute the
//! object's on-disk paths, build a typed [`UringOp`] envelope, dispatch it to
//! the worker pool (sharded by `(bucket, key)` hash), and await the reply.
//! All real I/O lives in [`super::ops`] inside the uring runtime.

use core::range::RangeInclusive;
use std::{path::PathBuf, sync::Arc};

use bytes::Bytes;
use uuid::Uuid;

use crate::{
    CacheRebuildStatus, DEFAULT_LIST_LIMIT, Error, ListOptions, ListPage, Listing, MAX_LIST_LIMIT,
    Metadata, MetadataIndex, Object, PutOptions, Storage, StorageExt,
};

use super::{ops::UringOp, runtime::WorkerPool};

/// UUID v5 namespace used to derive deterministic filenames from object keys.
///
/// Matches the constant used by [`crate::FilesystemStorage`].
const Y2Q_NAMESPACE: Uuid = Uuid::from_bytes([
    0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
]);

/// io_uring-backed object storage backend.
///
/// One file per object using the single-file format defined in
/// [`super::format`]: `[header | data | meta | trailer]`. PUTs are durable
/// (`fdatasync` on the data file plus directory `fsync` after rename).
///
/// All I/O is dispatched to a dedicated `tokio-uring` worker pool — see
/// [`super::runtime`] — keeping the actix-web tokio runtime unblocked.
pub struct UringStorage {
    base_path: PathBuf,
    index: Arc<MetadataIndex>,
    #[allow(dead_code)] // wired in subsequent steps (rebuild_cache)
    rebuild_state: Arc<tokio::sync::Mutex<CacheRebuildStatus>>,
    #[allow(dead_code)] // referenced in subsequent steps (O_DIRECT threshold)
    config: UringConfig,
    pool: WorkerPool,
}

/// Tunables for [`UringStorage`].
#[derive(Debug, Clone)]
pub struct UringConfig {
    /// Number of dedicated tokio-uring worker threads. Defaults to the number
    /// of logical CPUs.
    pub workers: usize,
    /// Object size at or above which writes switch to the `O_DIRECT` path
    /// with aligned buffers. Below this, buffered uring writes are used.
    pub large_object_bytes: u64,
}

impl Default for UringConfig {
    fn default() -> Self {
        Self {
            workers: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            large_object_bytes: 4 * 1024 * 1024,
        }
    }
}

impl UringStorage {
    /// Construct a new `UringStorage` rooted at `base_path`, with its secondary
    /// metadata index file at `index_path`.
    ///
    /// Spins up `config.workers` dedicated tokio-uring threads. Requires a
    /// Linux kernel with `io_uring` enabled (≥ 5.6).
    pub fn new(
        base_path: impl Into<PathBuf>,
        index_path: impl AsRef<std::path::Path>,
        config: UringConfig,
    ) -> Result<Self, Error> {
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
        let pool = WorkerPool::spawn(&config);
        Ok(Self {
            base_path,
            index: Arc::new(index),
            rebuild_state: Arc::new(tokio::sync::Mutex::new(CacheRebuildStatus::Idle)),
            config,
            pool,
        })
    }

    /// Access the underlying metadata index, e.g. for `lookup_by_label`.
    pub fn index(&self) -> &MetadataIndex {
        &self.index
    }

    /// Canonical on-disk path for the single-file object record of
    /// `(bucket, key)`: `<base>/<bucket>/<xx>/<yy>/<uuid>.obj`.
    fn obj_path(&self, bucket: &str, key: &str) -> PathBuf {
        let id = Uuid::new_v5(&Y2Q_NAMESPACE, key.as_bytes());
        let s = id.hyphenated().to_string();
        let mut p = self
            .base_path
            .join(bucket)
            .join(&s[0..2])
            .join(&s[2..4])
            .join(&s);
        p.set_extension("obj");
        p
    }

    /// Dispatch an op to the worker that owns `(bucket, key)`, then await the
    /// oneshot reply. Mapping channel/oneshot failures into [`Error`] is
    /// centralised here so the trait methods stay terse.
    async fn dispatch<R>(
        &self,
        op: UringOp,
        bucket: &str,
        key: &str,
        op_name: &'static str,
        reply_rx: tokio::sync::oneshot::Receiver<Result<R, Error>>,
    ) -> Result<R, Error> {
        self.pool
            .dispatch_for_key(bucket, key)
            .send(op)
            .await
            .map_err(|_| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: op_name.to_owned(),
                message: "uring worker pool closed".to_owned(),
            })?;
        reply_rx.await.map_err(|_| Error::InternalError {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            operation: op_name.to_owned(),
            message: "uring worker dropped reply".to_owned(),
        })?
    }
}

/// Validate that `bucket` is a safe directory name.
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
fn validate_key(key: &str) -> Result<(), Error> {
    const MAX_KEY_LEN: usize = 1024;
    if key.is_empty() || key.contains('\0') || key.len() > MAX_KEY_LEN {
        return Err(Error::InvalidKey {
            key: key.to_owned(),
        });
    }
    Ok(())
}

impl Storage for UringStorage {
    async fn get(&self, bucket: &str, key: &str) -> Result<Object, Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;
        let obj_path = self.obj_path(bucket, key);
        let lock_path = obj_path.with_extension("lock");
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        let op = UringOp::Get {
            obj_path,
            lock_path,
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            reply,
        };
        self.dispatch(op, bucket, key, "get", reply_rx).await
    }

    async fn get_range(
        &self,
        bucket: &str,
        key: &str,
        range: RangeInclusive<u64>,
    ) -> Result<Bytes, Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;
        let obj_path = self.obj_path(bucket, key);
        let lock_path = obj_path.with_extension("lock");
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        let op = UringOp::GetRange {
            obj_path,
            lock_path,
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            range,
            reply,
        };
        self.dispatch(op, bucket, key, "get_range", reply_rx).await
    }

    async fn put(
        &self,
        bucket: &str,
        key: &str,
        payload: Object,
        options: PutOptions,
    ) -> Result<bool, Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;
        let obj_path = self.obj_path(bucket, key);
        let lock_path = obj_path.with_extension("lock");
        let tmp_path = obj_path.with_extension("tmp");
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        let op = UringOp::Put {
            obj_path,
            tmp_path,
            lock_path,
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            url_path: format!("{bucket}/{key}"),
            payload: payload.into_inner(),
            labels: options.labels,
            reply,
        };
        let (is_overwrite, metadata) = self.dispatch(op, bucket, key, "put", reply_rx).await?;

        // Mirror FilesystemStorage: the on-disk record is authoritative, so a
        // failed index upsert is logged but not surfaced — the index can be
        // rebuilt from the trailer scan in `rebuild_cache`.
        if let Err(e) = self.index.upsert(&metadata).await {
            tracing::warn!(
                bucket = bucket,
                key = key,
                error = %e,
                "metadata index upsert failed; on-disk record is authoritative"
            );
        }
        Ok(is_overwrite)
    }

    async fn delete(&self, bucket: &str, key: &str) -> Result<Object, Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;
        let obj_path = self.obj_path(bucket, key);
        let lock_path = obj_path.with_extension("lock");
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        let op = UringOp::Delete {
            obj_path,
            lock_path,
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            reply,
        };
        let obj = self.dispatch(op, bucket, key, "delete", reply_rx).await?;

        if let Err(e) = self.index.remove(bucket, key).await {
            tracing::warn!(
                bucket = bucket,
                key = key,
                error = %e,
                "metadata index remove failed; on-disk record is authoritative"
            );
        }
        Ok(obj)
    }

    async fn describe(&self, bucket: &str, key: &str) -> Result<Metadata, Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;
        let obj_path = self.obj_path(bucket, key);
        let lock_path = obj_path.with_extension("lock");
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        let op = UringOp::Describe {
            obj_path,
            lock_path,
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            reply,
        };
        self.dispatch(op, bucket, key, "describe", reply_rx).await
    }
}

impl Listing for UringStorage {
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

impl StorageExt for UringStorage {
    async fn rebuild_cache(&self) -> Result<(), Error> {
        todo!("UringStorage::rebuild_cache")
    }

    async fn rebuild_progress(&self) -> Result<CacheRebuildStatus, Error> {
        todo!("UringStorage::rebuild_progress")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PutOptions;
    use bytes::Bytes;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    fn make_storage(dir: &TempDir, workers: usize) -> UringStorage {
        UringStorage::new(
            dir.path(),
            dir.path().join("idx.redb"),
            UringConfig {
                workers,
                ..UringConfig::default()
            },
        )
        .unwrap()
    }

    fn payload(bytes: &[u8]) -> Object {
        Object::new(Bytes::copy_from_slice(bytes))
    }

    #[tokio::test]
    async fn put_then_get_round_trips() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 2);
        let body = b"the quick brown fox jumps over the lazy dog".to_vec();
        let is_overwrite = storage
            .put("b", "k", payload(&body), PutOptions::default())
            .await
            .unwrap();
        assert!(!is_overwrite);
        let got = storage.get("b", "k").await.unwrap();
        assert_eq!(&got[..], body.as_slice());
    }

    #[tokio::test]
    async fn put_then_describe_returns_correct_metadata() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 1);
        let body = vec![7u8; 4096];
        let mut labels = BTreeMap::new();
        labels.insert("env".to_owned(), "prod".to_owned());
        storage
            .put("b", "k", payload(&body), PutOptions { labels })
            .await
            .unwrap();
        let meta = storage.describe("b", "k").await.unwrap();
        assert_eq!(meta.size, 4096);
        assert_eq!(meta.bucket, "b");
        assert_eq!(meta.key, "k");
        assert_eq!(meta.labels.get("env"), Some(&"prod".to_owned()));
        assert!(!meta.checksum_md5.is_empty());
        assert!(!meta.checksum_sha256.is_empty());
    }

    #[tokio::test]
    async fn overwrite_preserves_created_and_returns_true() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 1);
        storage
            .put("b", "k", payload(b"v1"), PutOptions::default())
            .await
            .unwrap();
        let first = storage.describe("b", "k").await.unwrap();
        // Sleep a touch so `modified` will move forward.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let is_overwrite = storage
            .put("b", "k", payload(b"v2_longer"), PutOptions::default())
            .await
            .unwrap();
        assert!(is_overwrite);
        let second = storage.describe("b", "k").await.unwrap();
        assert_eq!(second.created, first.created);
        assert!(second.modified >= first.modified);
        assert_eq!(second.size, b"v2_longer".len() as u64);
        let bytes = storage.get("b", "k").await.unwrap();
        assert_eq!(&bytes[..], b"v2_longer");
    }

    #[tokio::test]
    async fn get_range_returns_only_requested_slice() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 1);
        // 4 KiB payload of distinct bytes so we can locate the slice unambiguously.
        let body: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        storage
            .put("b", "k", payload(&body), PutOptions::default())
            .await
            .unwrap();

        let slice = storage
            .get_range("b", "k", RangeInclusive { start: 100, last: 199 })
            .await
            .unwrap();
        assert_eq!(slice.len(), 100);
        assert_eq!(&slice[..], &body[100..=199]);

        // Range past EOF clamps to actual length.
        let tail = storage
            .get_range("b", "k", RangeInclusive { start: 4000, last: 999_999 })
            .await
            .unwrap();
        assert_eq!(tail.len(), 96);
        assert_eq!(&tail[..], &body[4000..]);

        // Start past EOF returns empty.
        let empty = storage
            .get_range("b", "k", RangeInclusive { start: 10_000, last: 20_000 })
            .await
            .unwrap();
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn delete_returns_object_and_makes_subsequent_get_not_found() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 1);
        storage
            .put("b", "k", payload(b"bye"), PutOptions::default())
            .await
            .unwrap();
        let got = storage.delete("b", "k").await.unwrap();
        assert_eq!(&got[..], b"bye");
        let err = storage.get("b", "k").await.unwrap_err();
        assert!(matches!(err, Error::NotFound { .. }));
    }

    #[tokio::test]
    async fn put_populates_index_for_list_objects() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 1);
        storage
            .put("b", "alpha", payload(b"a"), PutOptions::default())
            .await
            .unwrap();
        storage
            .put("b", "beta", payload(b"bb"), PutOptions::default())
            .await
            .unwrap();
        let page = storage.list_objects("b", ListOptions::default()).await.unwrap();
        let keys: Vec<_> = page.items.iter().map(|m| m.key.clone()).collect();
        assert_eq!(keys, vec!["alpha".to_owned(), "beta".to_owned()]);
        let buckets = storage.list_buckets().await.unwrap();
        assert_eq!(buckets, vec!["b".to_owned()]);
    }

    #[tokio::test]
    async fn get_missing_object_returns_not_found() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 1);
        let err = storage.get("b", "nope").await.unwrap_err();
        assert!(matches!(err, Error::NotFound { .. }));
    }

    #[tokio::test]
    async fn describe_missing_object_returns_not_found() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 1);
        let err = storage.describe("b", "nope").await.unwrap_err();
        assert!(matches!(err, Error::NotFound { .. }));
    }

    #[tokio::test]
    async fn invalid_bucket_is_rejected_before_dispatch() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 1);
        let err = storage.get("../escape", "k").await.unwrap_err();
        assert!(matches!(err, Error::InvalidBucket { .. }));
    }
}
