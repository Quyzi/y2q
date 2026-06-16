//! Runtime-selectable [`Storage`] backend.
//!
//! `async fn` in traits is not dyn-compatible, so we can't store
//! `Arc<dyn Storage + ...>` directly. Rather than make every handler
//! generic, this enum wraps the concrete backends and forwards trait calls
//! to the active variant. Daemons construct an [`AnyStorage`] at startup
//! and pass it to handlers as `web::Data<Arc<AnyStorage>>`.

use core::range::RangeInclusive;
use std::sync::Arc;
use std::time::SystemTime;

use crate::crypto::metadata_key::MekSlot;

use bytes::Bytes;

use crate::{
    CacheRebuildStatus, CipherMetadata, Error, FilesystemStorage, ListOptions, ListPage, Listing,
    Metadata, Object, PlaintextMetrics, PutOptions, StaleLock, Storage, StorageExt,
    StreamingPutGuard,
    storage::{format::HEADER_SIZE, streaming_sink::StreamingSink},
};

#[cfg(target_os = "linux")]
use crate::UringStorage;
#[cfg(target_os = "linux")]
use crate::storage::uring::{URING_STREAMING_WRITE_OFFSET, UringStreamingPutGuard};

/// One of the available storage backends, selected at startup.
///
/// The uring variant is gated on `target_os = "linux"`, so the daemon binary
/// on macOS (or any non-Linux target) compiles cleanly with just the
/// filesystem variant; on Linux the uring variant is always present.
pub enum AnyStorage {
    /// Portable [`tokio::fs`]-based backend.
    Filesystem(FilesystemStorage),
    /// Linux-only `io_uring` backend.
    #[cfg(target_os = "linux")]
    Uring(UringStorage),
}

impl Storage for AnyStorage {
    async fn get(&self, bucket: &str, key: &str) -> Result<Object, Error> {
        match self {
            Self::Filesystem(s) => s.get(bucket, key).await,
            #[cfg(target_os = "linux")]
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
            #[cfg(target_os = "linux")]
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
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.put(bucket, key, payload, options).await,
        }
    }

    async fn delete(&self, bucket: &str, key: &str) -> Result<Object, Error> {
        match self {
            Self::Filesystem(s) => s.delete(bucket, key).await,
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.delete(bucket, key).await,
        }
    }

    async fn describe(&self, bucket: &str, key: &str) -> Result<Metadata, Error> {
        match self {
            Self::Filesystem(s) => s.describe(bucket, key).await,
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.describe(bucket, key).await,
        }
    }

    async fn set_labels(
        &self,
        bucket: &str,
        key: &str,
        labels: crate::LabelSet,
    ) -> Result<(), Error> {
        match self {
            Self::Filesystem(s) => s.set_labels(bucket, key, labels).await,
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.set_labels(bucket, key, labels).await,
        }
    }
}

impl Listing for AnyStorage {
    async fn list_buckets(&self) -> Result<Vec<String>, Error> {
        match self {
            Self::Filesystem(s) => s.list_buckets().await,
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.list_buckets().await,
        }
    }

    async fn bucket_exists(&self, bucket: &str) -> Result<bool, Error> {
        match self {
            Self::Filesystem(s) => s.bucket_exists(bucket).await,
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.bucket_exists(bucket).await,
        }
    }

    async fn list_objects(&self, bucket: &str, options: ListOptions) -> Result<ListPage, Error> {
        match self {
            Self::Filesystem(s) => s.list_objects(bucket, options).await,
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.list_objects(bucket, options).await,
        }
    }

    async fn search_objects(
        &self,
        query: &crate::LabelQuery,
        bucket: Option<&str>,
        options: ListOptions,
    ) -> Result<ListPage, Error> {
        match self {
            Self::Filesystem(s) => s.search_objects(query, bucket, options).await,
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.search_objects(query, bucket, options).await,
        }
    }

    async fn create_bucket(&self, bucket: &str) -> Result<bool, Error> {
        match self {
            Self::Filesystem(s) => s.create_bucket(bucket).await,
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.create_bucket(bucket).await,
        }
    }

    async fn delete_bucket(&self, bucket: &str) -> Result<u64, Error> {
        match self {
            Self::Filesystem(s) => s.delete_bucket(bucket).await,
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.delete_bucket(bucket).await,
        }
    }

    async fn get_bucket_config(&self, bucket: &str) -> Result<crate::BucketConfig, Error> {
        match self {
            Self::Filesystem(s) => s.get_bucket_config(bucket).await,
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.get_bucket_config(bucket).await,
        }
    }

    async fn set_bucket_config(
        &self,
        bucket: &str,
        config: &crate::BucketConfig,
    ) -> Result<(), Error> {
        match self {
            Self::Filesystem(s) => s.set_bucket_config(bucket, config).await,
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.set_bucket_config(bucket, config).await,
        }
    }

    async fn bucket_usage(&self, bucket: &str) -> Result<u64, Error> {
        match self {
            Self::Filesystem(s) => s.bucket_usage(bucket).await,
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.bucket_usage(bucket).await,
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
    #[cfg(target_os = "linux")]
    Uring(UringStreamingPutGuard),
}

impl AnyStreamingPutGuard {
    /// Finalise the streaming PUT. See the backend-specific guard types for
    /// full semantics; both rename the tmp file atomically into place and
    /// update the secondary metadata index.
    pub async fn commit(
        self,
        sink: StreamingSink,
        options: PutOptions,
        plaintext_metrics: PlaintextMetrics,
        cipher_metadata: CipherMetadata,
    ) -> Result<bool, Error> {
        match (self, sink) {
            (Self::Filesystem(g), StreamingSink::Tokio(file)) => {
                g.commit(file, options, plaintext_metrics, cipher_metadata)
                    .await
            }
            #[cfg(target_os = "linux")]
            (Self::Uring(g), StreamingSink::Uring(writer)) => {
                g.commit(writer, options, plaintext_metrics, cipher_metadata)
                    .await
            }
            _ => Err(Error::InternalError {
                bucket: String::new(),
                key: String::new(),
                operation: "commit_streaming_put".to_owned(),
                message: "streaming sink backend does not match guard backend".to_owned(),
            }),
        }
    }

    /// Read `len` bytes at absolute file offset `start` from the staged (not yet
    /// committed) tmp file. Used by the cluster HEAD to stream the envelope
    /// down-chain before committing locally (CRAQ tail-first ordering).
    pub async fn read_staged_range(&self, start: u64, len: u64) -> Result<Bytes, Error> {
        match self {
            Self::Filesystem(g) => g.read_staged_range(start, len).await,
            #[cfg(target_os = "linux")]
            Self::Uring(g) => g.read_staged_range(start, len).await,
        }
    }
}

impl AnyStorage {
    /// Install the Metadata Encryption Key on the active backend. Derived from
    /// the deployment secret key when a login unwraps it; idempotent.
    pub fn install_mek(&self, mek: [u8; 32]) {
        match self {
            Self::Filesystem(s) => s.install_mek(mek),
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.install_mek(mek),
        }
    }

    /// Shared handle to the active backend's MEK slot.
    pub fn mek_slot(&self) -> Arc<MekSlot> {
        match self {
            Self::Filesystem(s) => s.mek_slot(),
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.mek_slot(),
        }
    }

    /// Zeroize and drop the installed MEK on the active backend and close the
    /// whole-file-encrypted metadata index, leaving only ciphertext on disk.
    /// Called when the daemon goes idle, in step with the secret-key drop.
    /// Returns `true` if a key was present. A later login re-installs and
    /// reopens.
    pub fn clear_mek(&self) -> bool {
        match self {
            Self::Filesystem(s) => s.clear_mek(),
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.clear_mek(),
        }
    }

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
    ) -> Result<(AnyStreamingPutGuard, StreamingSink, u64), Error> {
        match self {
            Self::Filesystem(s) => {
                let (g, f) = s.begin_streaming_put(bucket, key).await?;
                Ok((
                    AnyStreamingPutGuard::Filesystem(g),
                    StreamingSink::Tokio(f),
                    HEADER_SIZE as u64,
                ))
            }
            #[cfg(target_os = "linux")]
            Self::Uring(s) => {
                let (g, w) = s.begin_streaming_put(bucket, key).await?;
                Ok((
                    AnyStreamingPutGuard::Uring(g),
                    StreamingSink::Uring(w),
                    URING_STREAMING_WRITE_OFFSET,
                ))
            }
        }
    }
}

impl StorageExt for AnyStorage {
    async fn rebuild_cache(&self) -> Result<(), Error> {
        match self {
            Self::Filesystem(s) => s.rebuild_cache().await,
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.rebuild_cache().await,
        }
    }

    async fn rebuild_progress(&self) -> Result<CacheRebuildStatus, Error> {
        match self {
            Self::Filesystem(s) => s.rebuild_progress().await,
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.rebuild_progress().await,
        }
    }

    async fn list_stale_locks(&self, older_than: SystemTime) -> Result<Vec<StaleLock>, Error> {
        match self {
            Self::Filesystem(s) => s.list_stale_locks(older_than).await,
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.list_stale_locks(older_than).await,
        }
    }

    async fn clear_stale_locks(&self, older_than: SystemTime) -> Result<u64, Error> {
        match self {
            Self::Filesystem(s) => s.clear_stale_locks(older_than).await,
            #[cfg(target_os = "linux")]
            Self::Uring(s) => s.clear_stale_locks(older_than).await,
        }
    }
}
