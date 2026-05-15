//! Runtime-selectable [`Storage`] backend.
//!
//! `async fn` in traits is not dyn-compatible, so we can't store
//! `Arc<dyn Storage + ...>` directly. Rather than make every handler
//! generic, this enum wraps the concrete backends and forwards trait calls
//! to the active variant. Daemons construct an [`AnyStorage`] at startup
//! and pass it to handlers as `web::Data<Arc<AnyStorage>>`.

use core::range::RangeInclusive;
use std::time::SystemTime;

use bytes::Bytes;

use crate::{
    CacheRebuildStatus, Error, FilesystemStorage, ListOptions, ListPage, Listing, Metadata,
    Object, PutOptions, StaleLock, Storage, StorageExt, StreamingPutGuard,
};

#[cfg(all(target_os = "linux", feature = "uring"))]
use crate::UringStorage;

/// One of the available storage backends, selected at startup.
///
/// Variants are gated on platform + feature so the daemon binary on macOS
/// (or any non-Linux target) compiles cleanly with just the filesystem
/// variant; on Linux with `--features uring` the uring variant is added.
pub enum AnyStorage {
    /// Portable [`tokio::fs`]-based backend.
    Filesystem(FilesystemStorage),
    /// Linux-only `io_uring` backend.
    #[cfg(all(target_os = "linux", feature = "uring"))]
    Uring(UringStorage),
}

impl Storage for AnyStorage {
    async fn get(&self, bucket: &str, key: &str) -> Result<Object, Error> {
        match self {
            Self::Filesystem(s) => s.get(bucket, key).await,
            #[cfg(all(target_os = "linux", feature = "uring"))]
            Self::Uring(s) => s.get(bucket, key).await,
        }
    }

    async fn get_range(
        &self,
        bucket: &str,
        key: &str,
        range: RangeInclusive<u64>,
    ) -> Result<Bytes, Error> {
        match self {
            Self::Filesystem(s) => s.get_range(bucket, key, range).await,
            #[cfg(all(target_os = "linux", feature = "uring"))]
            Self::Uring(s) => s.get_range(bucket, key, range).await,
        }
    }

    async fn put(
        &self,
        bucket: &str,
        key: &str,
        payload: Object,
        options: PutOptions,
    ) -> Result<bool, Error> {
        match self {
            Self::Filesystem(s) => s.put(bucket, key, payload, options).await,
            #[cfg(all(target_os = "linux", feature = "uring"))]
            Self::Uring(s) => s.put(bucket, key, payload, options).await,
        }
    }

    async fn delete(&self, bucket: &str, key: &str) -> Result<Object, Error> {
        match self {
            Self::Filesystem(s) => s.delete(bucket, key).await,
            #[cfg(all(target_os = "linux", feature = "uring"))]
            Self::Uring(s) => s.delete(bucket, key).await,
        }
    }

    async fn describe(&self, bucket: &str, key: &str) -> Result<Metadata, Error> {
        match self {
            Self::Filesystem(s) => s.describe(bucket, key).await,
            #[cfg(all(target_os = "linux", feature = "uring"))]
            Self::Uring(s) => s.describe(bucket, key).await,
        }
    }
}

impl Listing for AnyStorage {
    async fn list_buckets(&self) -> Result<Vec<String>, Error> {
        match self {
            Self::Filesystem(s) => s.list_buckets().await,
            #[cfg(all(target_os = "linux", feature = "uring"))]
            Self::Uring(s) => s.list_buckets().await,
        }
    }

    async fn list_objects(&self, bucket: &str, options: ListOptions) -> Result<ListPage, Error> {
        match self {
            Self::Filesystem(s) => s.list_objects(bucket, options).await,
            #[cfg(all(target_os = "linux", feature = "uring"))]
            Self::Uring(s) => s.list_objects(bucket, options).await,
        }
    }
}

impl AnyStorage {
    /// Begin a streaming PUT, acquiring the object lock and opening the tmp
    /// file. See [`FilesystemStorage::begin_streaming_put`] for full semantics.
    pub async fn begin_streaming_put(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(StreamingPutGuard, tokio::fs::File), Error> {
        match self {
            Self::Filesystem(s) => s.begin_streaming_put(bucket, key).await,
            #[cfg(all(target_os = "linux", feature = "uring"))]
            Self::Uring(_) => {
                // io_uring backend doesn't support streaming PUT yet.
                Err(Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "begin_streaming_put".to_owned(),
                    message: "uring backend does not support streaming PUT".to_owned(),
                })
            }
        }
    }
}

impl StorageExt for AnyStorage {
    async fn rebuild_cache(&self) -> Result<(), Error> {
        match self {
            Self::Filesystem(s) => s.rebuild_cache().await,
            #[cfg(all(target_os = "linux", feature = "uring"))]
            Self::Uring(s) => s.rebuild_cache().await,
        }
    }

    async fn rebuild_progress(&self) -> Result<CacheRebuildStatus, Error> {
        match self {
            Self::Filesystem(s) => s.rebuild_progress().await,
            #[cfg(all(target_os = "linux", feature = "uring"))]
            Self::Uring(s) => s.rebuild_progress().await,
        }
    }

    async fn list_stale_locks(&self, older_than: SystemTime) -> Result<Vec<StaleLock>, Error> {
        match self {
            Self::Filesystem(s) => s.list_stale_locks(older_than).await,
            #[cfg(all(target_os = "linux", feature = "uring"))]
            Self::Uring(s) => s.list_stale_locks(older_than).await,
        }
    }

    async fn clear_stale_locks(&self, older_than: SystemTime) -> Result<u64, Error> {
        match self {
            Self::Filesystem(s) => s.clear_stale_locks(older_than).await,
            #[cfg(all(target_os = "linux", feature = "uring"))]
            Self::Uring(s) => s.clear_stale_locks(older_than).await,
        }
    }
}
