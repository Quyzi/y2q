use core::range::RangeInclusive;
use std::{ops::Deref, time::SystemTime};
use bytes::Bytes;

pub mod storage;
pub use storage::filesystem::FilesystemStorage;

/// A stored binary object. Wraps [`bytes::Bytes`] for cheap cloning and slicing.
#[derive(Debug)]
pub struct Object(Bytes);

impl Object {
    /// Create a new `Object` from a [`bytes::Bytes`] value.
    pub fn new(bytes: Bytes) -> Self {
        Self(bytes)
    }
}

impl Deref for Object {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Descriptive information about a stored object.
///
/// Timestamps are nanoseconds since the Unix epoch. Checksums are the first
/// 8 bytes of each digest interpreted as a little-endian `u64`.
pub struct Metadata {
    /// Nanoseconds since Unix epoch when the object was first written.
    pub created: u64,
    /// Nanoseconds since Unix epoch when the object was last overwritten.
    pub modified: u64,
    /// Size of the object in bytes.
    pub size: u64,
    /// First 8 bytes of the MD5 digest as a little-endian `u64`.
    pub checksum_md5: u64,
    /// First 8 bytes of the SHA-256 digest as a little-endian `u64`.
    pub checksum_sha256: u64,
}

/// Errors returned by [`Storage`] operations.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The bucket name is empty, contains disallowed characters, or would escape
    /// the storage root (e.g. `..` components).
    #[error("invalid bucket: {bucket}")]
    InvalidBucket {
        bucket: String,
    },

    /// The key is empty, contains null bytes, or exceeds the maximum length.
    #[error("invalid key: {key}")]
    InvalidKey {
        key: String,
    },

    /// No object exists at the given `bucket`/`key` address.
    #[error("not found: {bucket}/{key}")]
    NotFound {
        bucket: String,
        key: String,
    },

    /// The object is currently being written to; `since` is when the lock was acquired.
    #[error("object {bucket}/{key} is locked since {since:?}")]
    Locked {
        bucket: String,
        key: String,
        /// Wall-clock time when the write lock was acquired.
        since: SystemTime,
    },

    /// An unexpected I/O or internal error occurred during `operation`.
    #[error("internal error in {operation} on {bucket}/{key}: {message}")]
    InternalError {
        bucket: String,
        key: String,
        /// Name of the operation that failed (e.g. `"get"`, `"put"`).
        operation: String,
        message: String,
    },
}

/// Async interface for object storage backends.
///
/// Objects are addressed by a `(bucket, key)` pair. Buckets group related
/// objects and map to a top-level directory in filesystem-backed
/// implementations. Keys are arbitrary UTF-8 strings (max 1 024 bytes).
///
/// All methods validate their inputs and return typed [`Error`] variants rather
/// than raw I/O errors.
#[allow(async_fn_in_trait)]
pub trait Storage {
    /// Retrieve an object by `bucket` and `key`.
    ///
    /// Returns [`Error::NotFound`] if no object exists at that address, or
    /// [`Error::Locked`] if a write is currently in progress.
    async fn get(&self, bucket: &str, key: &str) -> Result<Object, Error>;

    /// Retrieve a byte slice of an object.
    ///
    /// `range` is an inclusive range of byte offsets. Indices beyond the end of
    /// the object are clamped. Returns an empty [`Bytes`] if `start` is past the
    /// end of the object.
    async fn get_range(&self, bucket: &str, key: &str, range: RangeInclusive<u64>) -> Result<Bytes, Error>;

    /// Write `payload` to `bucket`/`key`.
    ///
    /// The write is atomic: readers see either the old object or the new one,
    /// never a partial write. Returns `true` if an existing object was replaced,
    /// `false` if this was a fresh insert. The original `created` timestamp is
    /// preserved on overwrite.
    async fn put(&self, bucket: &str, key: &str, payload: Object) -> Result<bool, Error>;

    /// Delete the object at `bucket`/`key` and return its contents.
    ///
    /// Returns [`Error::NotFound`] if no object exists at that address.
    async fn delete(&self, bucket: &str, key: &str) -> Result<Object, Error>;

    /// Return the [`Metadata`] for the object at `bucket`/`key`.
    ///
    /// Returns [`Error::NotFound`] if no object exists at that address.
    async fn describe(&self, bucket: &str, key: &str) -> Result<Metadata, Error>;
}
