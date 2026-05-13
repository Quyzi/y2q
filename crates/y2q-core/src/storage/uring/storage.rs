//! The `UringStorage` backend struct and its trait implementations.
//!
//! Currently in progress: [`UringStorage::describe`] is wired end-to-end
//! through the worker-pool bridge; every other method is still `todo!()`.

use core::range::RangeInclusive;
use std::{path::PathBuf, sync::Arc};

use bytes::Bytes;
use uuid::Uuid;

use crate::{
    CacheRebuildStatus, Error, ListOptions, ListPage, Listing, Metadata, MetadataIndex, Object,
    PutOptions, Storage, StorageExt,
};

use super::{ops::UringOp, runtime::WorkerPool};

/// UUID v5 namespace used to derive deterministic filenames from object keys.
///
/// Matches the constant used by [`crate::FilesystemStorage`] so the two
/// backends agree on path layout while we transition the on-disk format.
const Y2Q_NAMESPACE: Uuid = Uuid::from_bytes([
    0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
]);

/// io_uring-backed object storage backend.
///
/// One file per object using the single-file format defined in
/// [`super::format`] (landing in a subsequent step — for now the backend
/// reads metadata sidecars in the same layout as [`crate::FilesystemStorage`]).
/// PUTs are durable by default once they're implemented.
///
/// All I/O is dispatched to a dedicated `tokio-uring` worker pool — see
/// [`super::runtime`] — keeping the actix-web tokio runtime unblocked.
pub struct UringStorage {
    base_path: PathBuf,
    index: Arc<MetadataIndex>,
    #[allow(dead_code)] // wired in subsequent steps
    rebuild_state: Arc<tokio::sync::Mutex<CacheRebuildStatus>>,
    #[allow(dead_code)] // referenced in subsequent steps
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

    /// Derive the canonical on-disk path of the metadata sidecar for
    /// `(bucket, key)`. Matches the [`FilesystemStorage`](crate::FilesystemStorage)
    /// layout: `<base>/<bucket>/<xx>/<yy>/<uuid>.meta`.
    fn meta_path(&self, bucket: &str, key: &str) -> PathBuf {
        let id = Uuid::new_v5(&Y2Q_NAMESPACE, key.as_bytes());
        let s = id.hyphenated().to_string();
        let mut p = self
            .base_path
            .join(bucket)
            .join(&s[0..2])
            .join(&s[2..4])
            .join(&s);
        p.set_extension("meta");
        p
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
    async fn get(&self, _bucket: &str, _key: &str) -> Result<Object, Error> {
        todo!("UringStorage::get")
    }

    async fn get_range(
        &self,
        _bucket: &str,
        _key: &str,
        _range: RangeInclusive<u64>,
    ) -> Result<Bytes, Error> {
        todo!("UringStorage::get_range")
    }

    async fn put(
        &self,
        _bucket: &str,
        _key: &str,
        _payload: Object,
        _options: PutOptions,
    ) -> Result<bool, Error> {
        todo!("UringStorage::put")
    }

    async fn delete(&self, _bucket: &str, _key: &str) -> Result<Object, Error> {
        todo!("UringStorage::delete")
    }

    async fn describe(&self, bucket: &str, key: &str) -> Result<Metadata, Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;

        let path = self.meta_path(bucket, key);
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let op = UringOp::Describe {
            path,
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            reply: reply_tx,
        };
        self.pool
            .dispatch_for_key(bucket, key)
            .send(op)
            .await
            .map_err(|_| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "describe".to_owned(),
                message: "uring worker pool closed".to_owned(),
            })?;
        reply_rx.await.map_err(|_| Error::InternalError {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            operation: "describe".to_owned(),
            message: "uring worker dropped reply".to_owned(),
        })?
    }
}

impl Listing for UringStorage {
    async fn list_buckets(&self) -> Result<Vec<String>, Error> {
        todo!("UringStorage::list_buckets")
    }

    async fn list_objects(&self, _bucket: &str, _options: ListOptions) -> Result<ListPage, Error> {
        todo!("UringStorage::list_objects")
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
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    /// End-to-end smoke test for the worker-pool bridge:
    /// `tokio` test runtime → `async_channel` → `tokio-uring` worker → `openat`
    /// → `statx` → `read_exact_at` → JSON decode → `oneshot` reply → assertion.
    /// If any layer of the bridge is broken this test fails or hangs.
    #[tokio::test]
    async fn describe_roundtrips_via_uring_bridge() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();
        let index_path = base.join("idx.redb");
        let config = UringConfig {
            workers: 2,
            ..UringConfig::default()
        };
        let storage = UringStorage::new(&base, &index_path, config).unwrap();

        let bucket = "test";
        let key = "hello/world";
        let path = storage.meta_path(bucket, key);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let expected = Metadata {
            created: 1,
            modified: 2,
            size: 42,
            checksum_md5: "md5".to_owned(),
            checksum_sha256: "sha".to_owned(),
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            disk_path: path.clone(),
            url_path: format!("{bucket}/{key}"),
            labels: BTreeMap::new(),
        };
        std::fs::write(&path, serde_json::to_vec(&expected).unwrap()).unwrap();

        let got = storage.describe(bucket, key).await.unwrap();
        assert_eq!(got.bucket, expected.bucket);
        assert_eq!(got.key, expected.key);
        assert_eq!(got.size, 42);
        assert_eq!(got.created, 1);
    }

    #[tokio::test]
    async fn describe_returns_not_found_for_missing_object() {
        let dir = TempDir::new().unwrap();
        let storage = UringStorage::new(
            dir.path(),
            dir.path().join("idx.redb"),
            UringConfig {
                workers: 1,
                ..UringConfig::default()
            },
        )
        .unwrap();
        let err = storage.describe("test", "nope").await.unwrap_err();
        assert!(matches!(err, Error::NotFound { .. }), "got {err:?}");
    }
}
