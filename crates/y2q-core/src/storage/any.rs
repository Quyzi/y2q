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
    CacheRebuildStatus, CipherMetadata, Error, FilesystemStorage, ListOptions, ListPage, Listing,
    Metadata, Object, PlaintextMetrics, PutOptions, StaleLock, Storage, StorageExt,
    StreamingPutGuard,
    storage::format::HEADER_SIZE,
};

#[cfg(all(target_os = "linux", feature = "uring"))]
use crate::UringStorage;
#[cfg(all(target_os = "linux", feature = "uring"))]
use crate::storage::uring::{UringStreamingPutGuard, URING_STREAMING_WRITE_OFFSET};

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

/// Backend-erased streaming PUT guard returned by
/// [`AnyStorage::begin_streaming_put`].
///
/// Call [`commit`] after feeding all data through the encrypt session.
pub enum AnyStreamingPutGuard {
    /// Guard backed by [`FilesystemStorage`].
    Filesystem(StreamingPutGuard),
    /// Guard backed by [`UringStorage`] (Linux + `uring` feature only).
    #[cfg(all(target_os = "linux", feature = "uring"))]
    Uring(UringStreamingPutGuard),
}

impl AnyStreamingPutGuard {
    /// Finalise the streaming PUT. See the backend-specific guard types for
    /// full semantics; both rename the tmp file atomically into place and
    /// update the secondary metadata index.
    pub async fn commit(
        self,
        file: tokio::fs::File,
        options: PutOptions,
        plaintext_metrics: PlaintextMetrics,
        cipher_metadata: CipherMetadata,
    ) -> Result<bool, Error> {
        match self {
            Self::Filesystem(g) => g.commit(file, options, plaintext_metrics, cipher_metadata).await,
            #[cfg(all(target_os = "linux", feature = "uring"))]
            Self::Uring(g) => g.commit(file, options, plaintext_metrics, cipher_metadata).await,
        }
    }
}

impl AnyStorage {
    /// Begin a streaming PUT, acquiring the object lock and opening the tmp
    /// file. Returns the guard, the open tmp file, and a `write_offset` that
    /// must be passed to
    /// [`crate::crypto::envelope::EncryptSession::new`].
    ///
    /// `write_offset` is `0` for the filesystem backend (the v2 envelope
    /// fills the whole file) and `64` for the uring backend (where a 64-byte
    /// `.obj` header precedes the envelope). Passing it to `EncryptSession`
    /// ensures `finish()` seeks to the right position to patch `plaintext_len`.
    pub async fn begin_streaming_put(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(AnyStreamingPutGuard, tokio::fs::File, u64), Error> {
        match self {
            Self::Filesystem(s) => {
                let (g, f) = s.begin_streaming_put(bucket, key).await?;
                Ok((AnyStreamingPutGuard::Filesystem(g), f, HEADER_SIZE as u64))
            }
            #[cfg(all(target_os = "linux", feature = "uring"))]
            Self::Uring(s) => {
                let (g, f) = s.begin_streaming_put(bucket, key).await?;
                Ok((AnyStreamingPutGuard::Uring(g), f, URING_STREAMING_WRITE_OFFSET))
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
