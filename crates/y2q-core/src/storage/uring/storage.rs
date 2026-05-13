//! The `UringStorage` backend struct and its trait implementations.
//!
//! This file is currently a skeleton: all I/O methods are `todo!()` and the
//! type only carries enough state to round-trip configuration. The shape is
//! deliberately mirror-image of [`crate::FilesystemStorage`] so callers can
//! swap one for the other once the implementations land.

use core::range::RangeInclusive;
use std::{path::PathBuf, sync::Arc};

use bytes::Bytes;

use crate::{
    CacheRebuildStatus, Error, ListOptions, ListPage, Listing, Metadata, MetadataIndex, Object,
    PutOptions, Storage, StorageExt,
};

/// io_uring-backed object storage backend.
///
/// One file per object using the single-file format defined in
/// [`super::format`]. PUTs are durable by default (`fdatasync` on the data
/// file plus `fsync` on the parent directory).
///
/// All I/O is dispatched to a dedicated `tokio-uring` worker pool — see
/// [`super::runtime`] — keeping the actix-web tokio runtime unblocked.
pub struct UringStorage {
    #[allow(dead_code)] // wired in subsequent steps
    base_path: PathBuf,
    #[allow(dead_code)]
    index: Arc<MetadataIndex>,
    #[allow(dead_code)]
    rebuild_state: Arc<tokio::sync::Mutex<CacheRebuildStatus>>,
    #[allow(dead_code)]
    config: UringConfig,
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
    /// This currently builds the struct but does not spin up the worker pool
    /// or open any uring instances; those land with the first real I/O method.
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
        Ok(Self {
            base_path,
            index: Arc::new(index),
            rebuild_state: Arc::new(tokio::sync::Mutex::new(CacheRebuildStatus::Idle)),
            config,
        })
    }

    /// Access the underlying metadata index, e.g. for `lookup_by_label`.
    pub fn index(&self) -> &MetadataIndex {
        &self.index
    }
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

    async fn describe(&self, _bucket: &str, _key: &str) -> Result<Metadata, Error> {
        todo!("UringStorage::describe")
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
