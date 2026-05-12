use bytes::Bytes;
use core::range::RangeInclusive;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, ops::Deref, path::PathBuf, time::SystemTime};

pub mod storage;
pub use storage::filesystem::FilesystemStorage;
pub use storage::index::MetadataIndex;

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
/// Timestamps are nanoseconds since the Unix epoch. Checksums are the full
/// digest encoded as standard base64 (RFC 4648 §4, with padding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    /// Nanoseconds since Unix epoch when the object was first written.
    pub created: u64,
    /// Nanoseconds since Unix epoch when the object was last overwritten.
    pub modified: u64,
    /// Size of the object in bytes.
    pub size: u64,
    /// Full 16-byte MD5 digest as standard base64 (24 chars, padded).
    pub checksum_md5: String,
    /// Full 32-byte SHA-256 digest as standard base64 (44 chars, padded).
    pub checksum_sha256: String,
    /// Bucket the object belongs to.
    pub bucket: String,
    /// Object key within the bucket.
    pub key: String,
    /// Absolute on-disk path of the object data file.
    pub disk_path: PathBuf,
    /// Logical URL path: `"<bucket>/<key>"`.
    pub url_path: String,
    /// Arbitrary user-supplied labels (from `X-Y2Q-<label>` request headers on PUT).
    /// Names are stored lowercased.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// Options passed to [`Storage::put`].
///
/// Extensible: future fields (content-type, TTL, preconditions) can be added
/// without breaking the trait signature.
#[derive(Debug, Default, Clone)]
pub struct PutOptions {
    /// User-supplied labels to attach to the object.
    pub labels: BTreeMap<String, String>,
}

/// Errors returned by [`Storage`] operations.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The bucket name is empty, contains disallowed characters, or would escape
    /// the storage root (e.g. `..` components).
    #[error("invalid bucket: {bucket}")]
    InvalidBucket { bucket: String },

    /// The key is empty, contains null bytes, or exceeds the maximum length.
    #[error("invalid key: {key}")]
    InvalidKey { key: String },

    /// No object exists at the given `bucket`/`key` address.
    #[error("not found: {bucket}/{key}")]
    NotFound { bucket: String, key: String },

    /// The object is currently being written to; `since` is when the lock was acquired.
    #[error("object {bucket}/{key} is locked since {since:?}")]
    Locked {
        bucket: String,
        key: String,
        /// Wall-clock time when the write lock was acquired.
        since: SystemTime,
    },

    /// A label name collides with a reserved system metadata name
    /// (`created`, `modified`, `checksum-md5`, `checksum-sha256`).
    #[error("reserved label: {name}")]
    ReservedLabel { name: String },

    /// A label value was not valid UTF-8.
    #[error("invalid label value (not UTF-8): {name}")]
    InvalidLabelValue { name: String },

    /// A label name exceeded the configured maximum byte length.
    #[error("label name too long: {name}")]
    LabelNameTooLong { name: String },

    /// A label value exceeded the configured maximum byte length.
    #[error("label value too long: {name}")]
    LabelValueTooLong { name: String },

    /// More labels were supplied than the configured maximum.
    #[error("too many labels: {count}")]
    TooManyLabels { count: usize },

    /// The secondary metadata index returned an error.
    #[error("index error: {message}")]
    Index { message: String },

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
    async fn get_range(
        &self,
        bucket: &str,
        key: &str,
        range: RangeInclusive<u64>,
    ) -> Result<Bytes, Error>;

    /// Write `payload` to `bucket`/`key`.
    ///
    /// The write is atomic: readers see either the old object or the new one,
    /// never a partial write. Returns `true` if an existing object was replaced,
    /// `false` if this was a fresh insert. The original `created` timestamp is
    /// preserved on overwrite. `options.labels` are stored alongside the object
    /// and indexed for label-based queries.
    async fn put(
        &self,
        bucket: &str,
        key: &str,
        payload: Object,
        options: PutOptions,
    ) -> Result<bool, Error>;

    /// Delete the object at `bucket`/`key` and return its contents.
    ///
    /// Returns [`Error::NotFound`] if no object exists at that address.
    async fn delete(&self, bucket: &str, key: &str) -> Result<Object, Error>;

    /// Return the [`Metadata`] for the object at `bucket`/`key`.
    ///
    /// Returns [`Error::NotFound`] if no object exists at that address.
    async fn describe(&self, bucket: &str, key: &str) -> Result<Metadata, Error>;
}
