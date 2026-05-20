//! Core library for the y2q post-quantum secure object store.
//!
//! Provides the [`Storage`], [`Listing`], and [`StorageExt`] traits, concrete
//! backends ([`FilesystemStorage`], [`UringStorage`] on Linux), the
//! [`MetadataIndex`], and the [`crypto`] layer (ML-KEM-768 + AES-256-GCM
//! envelope format, Argon2id key wrapping, and the user-store database).

#[cfg(all(feature = "uring", not(target_os = "linux")))]
compile_error!("feature `uring` is only supported on Linux");

use bytes::Bytes;
use core::range::RangeInclusive;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, ops::Deref, path::PathBuf, time::SystemTime};

pub mod crypto;
/// Storage backends (filesystem and io_uring), metadata index, and lock management.
pub mod storage;
pub use storage::any::{AnyStorage, AnyStreamingPutGuard};
pub use storage::filesystem::{FilesystemStorage, StreamingPutGuard};
pub use storage::index::MetadataIndex;
pub use storage::locks::StaleLock;

#[cfg(all(target_os = "linux", feature = "uring"))]
pub use storage::uring::UringStorage;

/// Payload sent on the dirty-write channel after a best-effort PUT commit.
/// The background flusher drains these and fsyncs each path.
pub struct DirtyEntry {
    pub obj_path: PathBuf,
    pub parent_dir: PathBuf,
}

/// A stored binary object. Wraps [`bytes::Bytes`] for cheap cloning and slicing.
#[derive(Debug)]
pub struct Object(Bytes);

impl Object {
    /// Create a new `Object` from a [`bytes::Bytes`] value.
    pub fn new(bytes: Bytes) -> Self {
        Self(bytes)
    }

    /// Consume the `Object` and return its inner [`bytes::Bytes`] payload.
    ///
    /// Useful when handing the payload off to backends that need to move
    /// the buffer (e.g. a worker pool that takes ownership of the bytes).
    pub fn into_inner(self) -> Bytes {
        self.0
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
    /// Total bytes on disk for the encrypted envelope, when encryption is
    /// enabled. `None` for legacy plaintext objects written before the
    /// crypto layer was wired in.
    #[serde(default)]
    pub cipher_size: Option<u64>,
    /// Standard-base64 SHA-256 of the on-disk envelope bytes (cheap to
    /// recompute without the secret key — useful for `rebuild_cache`
    /// integrity scans). `None` for legacy plaintext objects.
    #[serde(default)]
    pub cipher_sha256: Option<String>,
    /// Symbolic KEM algorithm name (e.g. `"ml-kem-768"`) when the object is
    /// encrypted; `None` for legacy plaintext objects.
    #[serde(default)]
    pub kem_alg: Option<String>,
    /// Symbolic AEAD algorithm name (e.g. `"aes-256-gcm"`) when the object is
    /// encrypted; `None` for legacy plaintext objects.
    #[serde(default)]
    pub aead_alg: Option<String>,
    /// Envelope format version when the object is encrypted; `None` for
    /// legacy plaintext objects.
    #[serde(default)]
    pub envelope_version: Option<u16>,
}

/// Durability guarantee a PUT should provide before returning success.
///
/// Default is [`SyncLevel::Durable`]: every successful PUT must survive a
/// power loss. Callers willing to trade durability for throughput can pass
/// [`SyncLevel::BestEffort`] per request.
///
/// Backend support:
/// - [`UringStorage`](crate::storage::uring::UringStorage) (Linux): honoured.
///   `Durable` issues `fdatasync` on the object file plus `fsync` on the
///   parent directory after `rename`; `BestEffort` skips both.
/// - [`FilesystemStorage`]: honoured. Same semantics as the uring backend:
///   `Durable` issues `fdatasync` + parent dir `fsync`; `BestEffort` skips both.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SyncLevel {
    /// `fdatasync` on the object file + parent directory `fsync` before
    /// returning. Crash-safe — the object is on stable storage.
    #[default]
    Durable,
    /// No fsync. The kernel will flush eventually; an unclean shutdown can
    /// lose a recently-PUT object even though the API returned success.
    BestEffort,
}

/// Options passed to [`Storage::put`].
///
/// Extensible: future fields (content-type, TTL, preconditions) can be added
/// without breaking the trait signature.
#[derive(Debug, Default, Clone)]
pub struct PutOptions {
    /// User-supplied labels to attach to the object.
    pub labels: BTreeMap<String, String>,
    /// Durability guarantee required before the PUT returns success.
    pub sync: SyncLevel,
    /// When the daemon performs encryption ahead of the backend, the
    /// plaintext metrics that should be persisted instead of the values the
    /// backend would otherwise compute from the (encrypted) payload bytes.
    pub plaintext_metrics: Option<PlaintextMetrics>,
    /// When the daemon performs encryption ahead of the backend, the
    /// ciphertext-side fields the backend should attach to the metadata
    /// sidecar (cipher_size, kem/aead alg, envelope_version, cipher_sha256).
    pub cipher_metadata: Option<CipherMetadata>,
}

/// Plaintext-derived size and checksums supplied by the daemon when it has
/// encrypted the body before handing it to the backend. The backend should
/// store these values in [`Metadata::size`], [`Metadata::checksum_md5`], and
/// [`Metadata::checksum_sha256`] in place of values it would otherwise
/// compute from the (encrypted) bytes it sees.
#[derive(Debug, Clone)]
pub struct PlaintextMetrics {
    /// Plaintext size in bytes.
    pub size: u64,
    /// Full 16-byte MD5 of the plaintext, standard base64 (24 chars).
    pub checksum_md5_b64: String,
    /// Full 32-byte SHA-256 of the plaintext, standard base64 (44 chars).
    pub checksum_sha256_b64: String,
}

/// Ciphertext-side metadata fields supplied by the daemon for the backend to
/// attach to the metadata sidecar. These never change the bytes the backend
/// writes — they're informational fields for `HEAD` responses and the
/// integrity-scan codepath.
#[derive(Debug, Clone)]
pub struct CipherMetadata {
    /// Total on-disk envelope size in bytes.
    pub cipher_size: u64,
    /// SHA-256 of the on-disk envelope, standard base64 (44 chars).
    pub cipher_sha256_b64: String,
    /// Symbolic KEM algorithm name, e.g. `"ml-kem-768"`.
    pub kem_alg: String,
    /// Symbolic AEAD algorithm name, e.g. `"aes-256-gcm"`.
    pub aead_alg: String,
    /// Envelope format version number.
    pub envelope_version: u16,
}

/// Default page size when [`ListOptions::limit`] is `None` or `Some(0)`.
pub const DEFAULT_LIST_LIMIT: usize = 1000;

/// Hard upper bound on a single listing page.
pub const MAX_LIST_LIMIT: usize = 10_000;

/// Options passed to [`Listing::list_objects`].
#[derive(Debug, Default, Clone)]
pub struct ListOptions {
    /// If set, only keys with this prefix are returned.
    pub prefix: Option<String>,
    /// Continuation cursor: return only keys strictly greater than this.
    /// Pass back the `next` value from a previous [`ListPage`] to resume.
    pub after: Option<String>,
    /// Maximum number of items in the returned page. `None` or `Some(0)` use
    /// [`DEFAULT_LIST_LIMIT`]; values are clamped to [`MAX_LIST_LIMIT`].
    pub limit: Option<usize>,
}

/// One page of results from [`Listing::list_objects`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListPage {
    /// Object metadata, sorted ascending by key.
    pub items: Vec<Metadata>,
    /// If `Some`, more results exist; pass this value as
    /// [`ListOptions::after`] on the next call. `None` means the listing is
    /// exhausted.
    pub next: Option<String>,
}

/// Errors returned by [`Storage`] operations.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The bucket name is empty, contains disallowed characters, or would escape
    /// the storage root (e.g. `..` components).
    #[error("invalid bucket: {bucket}")]
    InvalidBucket {
        /// The rejected bucket name.
        bucket: String,
    },

    /// The key is empty, contains null bytes, or exceeds the maximum length.
    #[error("invalid key: {key}")]
    InvalidKey {
        /// The rejected key.
        key: String,
    },

    /// No object exists at the given `bucket`/`key` address.
    #[error("not found: {bucket}/{key}")]
    NotFound {
        /// Bucket component of the address.
        bucket: String,
        /// Key component of the address.
        key: String,
    },

    /// The object is currently being written to; `since` is when the lock was acquired.
    #[error("object {bucket}/{key} is locked since {since:?}")]
    Locked {
        /// Bucket component of the locked address.
        bucket: String,
        /// Key component of the locked address.
        key: String,
        /// Wall-clock time when the write lock was acquired.
        since: SystemTime,
    },

    /// A label name collides with a reserved system metadata name
    /// (`created`, `modified`, `checksum-md5`, `checksum-sha256`).
    #[error("reserved label: {name}")]
    ReservedLabel {
        /// The reserved label name that was rejected.
        name: String,
    },

    /// A label value was not valid UTF-8.
    #[error("invalid label value (not UTF-8): {name}")]
    InvalidLabelValue {
        /// Name of the label whose value was invalid.
        name: String,
    },

    /// A label name exceeded the configured maximum byte length.
    #[error("label name too long: {name}")]
    LabelNameTooLong {
        /// The oversized label name.
        name: String,
    },

    /// A label value exceeded the configured maximum byte length.
    #[error("label value too long: {name}")]
    LabelValueTooLong {
        /// Name of the label whose value was too long.
        name: String,
    },

    /// More labels were supplied than the configured maximum.
    #[error("too many labels: {count}")]
    TooManyLabels {
        /// Number of labels that were supplied.
        count: usize,
    },

    /// The secondary metadata index returned an error.
    #[error("index error: {message}")]
    Index {
        /// Error detail from the index layer.
        message: String,
    },

    /// An unexpected I/O or internal error occurred during `operation`.
    #[error("internal error in {operation} on {bucket}/{key}: {message}")]
    InternalError {
        /// Bucket component of the address being operated on.
        bucket: String,
        /// Key component of the address being operated on.
        key: String,
        /// Name of the operation that failed (e.g. `"get"`, `"put"`).
        operation: String,
        /// Human-readable error detail.
        message: String,
    },

    /// A cache rebuild was requested while one is already in progress.
    #[error("rebuild already in progress")]
    RebuildAlreadyRunning,

    /// The `older_than` parameter passed to the stale-lock admin endpoint
    /// was neither a valid duration (`1h`, `30m`, ...) nor a Unix-seconds
    /// timestamp.
    #[error("invalid stale-lock threshold: {value}")]
    InvalidStaleLockThreshold {
        /// The raw value the caller supplied.
        value: String,
    },

    /// `pubkey.json` is missing — the daemon cannot serve traffic until
    /// first-run setup completes.
    #[error("keystore not found at {path}")]
    KeystoreNotFound {
        /// Filesystem path where the keystore was expected.
        path: String,
    },

    /// `pubkey.json` exists but is unparseable, has a wrong-size key, or
    /// fingerprint mismatches.
    #[error("keystore corrupt at {path}: {reason}")]
    KeystoreCorrupt {
        /// Filesystem path of the corrupt keystore.
        path: String,
        /// Short description of the corruption detected.
        reason: String,
    },

    /// Argon2id key derivation failed (typically a bad parameter triple).
    #[error("kdf failure: {reason}")]
    KdfFailed {
        /// Short description of the KDF failure.
        reason: String,
    },

    /// Encrypting an object body failed for an unexpected reason.
    #[error("encryption failed for {bucket}/{key}")]
    EncryptionFailed {
        /// Bucket component of the address being encrypted.
        bucket: String,
        /// Key component of the address being encrypted.
        key: String,
    },

    /// Decrypting an object body failed — bad ciphertext, wrong key, or
    /// AAD mismatch. The HTTP layer must NEVER include the underlying
    /// reason in the response body to avoid side-channel leaks about disk
    /// state.
    #[error("decryption failed for {bucket}/{key}")]
    DecryptionFailed {
        /// Bucket component of the address being decrypted.
        bucket: String,
        /// Key component of the address being decrypted.
        key: String,
    },

    /// On-disk envelope header (magic / algorithm tags / lengths) failed
    /// validation.
    #[error("envelope malformed for {bucket}/{key}: {reason}")]
    EnvelopeMalformed {
        /// Bucket component of the address with the malformed envelope.
        bucket: String,
        /// Key component of the address with the malformed envelope.
        key: String,
        /// Short description of what failed validation.
        reason: String,
    },

    /// Envelope advertises a `format_ver` newer than this build supports.
    #[error("unsupported envelope version: {version}")]
    UnsupportedEnvelopeVersion {
        /// The version number found in the envelope header.
        version: u16,
    },

    /// Range read attempted against an encrypted object — the on-disk
    /// envelope is whole-object AEAD, so partial reads aren't possible.
    #[error("range reads are not supported on encrypted objects")]
    RangeReadOnEncrypted,
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

/// Enumerate buckets and the objects within them.
///
/// Listing is a paginated, sorted view: results come back ordered by key, and
/// callers resume with the `next` cursor returned in [`ListPage`].
#[allow(async_fn_in_trait)]
pub trait Listing: Storage {
    /// Return the names of every bucket that contains at least one object,
    /// sorted ascending.
    async fn list_buckets(&self) -> Result<Vec<String>, Error>;

    /// Return one page of objects in `bucket`, filtered and paginated by
    /// `options`. Results are sorted ascending by key.
    async fn list_objects(&self, bucket: &str, options: ListOptions) -> Result<ListPage, Error>;
}

/// Reported state of the secondary-index rebuild process.
///
/// Returned by [`StorageExt::rebuild_progress`]. A rebuild is fire-and-forget:
/// [`StorageExt::rebuild_cache`] spawns the work and returns immediately; the
/// caller polls progress through this enum.
#[derive(Debug, Clone)]
pub enum CacheRebuildStatus {
    /// No rebuild has been started since the process started.
    Idle,
    /// A rebuild is in progress; `u8` is percent complete (0..=100).
    Running(u8),
    /// The most recent rebuild finished successfully.
    Completed,
    /// The most recent rebuild aborted; `String` is a short human reason.
    Failed(String),
}

/// Administrative operations on a [`Storage`] backend.
///
/// Currently exposes a way to rebuild the secondary metadata cache from the
/// on-disk source of truth, and to query the progress of that rebuild.
#[allow(async_fn_in_trait)]
pub trait StorageExt: Storage {
    /// Kick off a background rebuild of the secondary metadata cache.
    ///
    /// Returns `Ok(())` as soon as the background task is spawned, or
    /// [`Error::RebuildAlreadyRunning`] if one is already in flight. Poll
    /// [`StorageExt::rebuild_progress`] to observe completion.
    async fn rebuild_cache(&self) -> Result<(), Error>;

    /// Return the current state of the background rebuild.
    async fn rebuild_progress(&self) -> Result<CacheRebuildStatus, Error>;

    /// Enumerate `.lock` sidecar files whose recorded acquisition time is
    /// strictly earlier than `older_than`.
    ///
    /// Locks are only released by their owning process under normal
    /// shutdown; a `SIGKILL` (or kernel panic) mid-PUT leaves the file
    /// behind and future writes to that key fail with [`Error::Locked`].
    /// This call is the "dry-run" counterpart to
    /// [`StorageExt::clear_stale_locks`].
    async fn list_stale_locks(&self, older_than: SystemTime) -> Result<Vec<StaleLock>, Error>;

    /// Delete every `.lock` sidecar older than `older_than`. Returns the
    /// number of files successfully removed.
    ///
    /// `ENOENT` on the unlink is treated as success — another worker may
    /// have legitimately released the lock between the scan and the
    /// unlink. The scan / unlink pair is not atomic across the tree; see
    /// [`storage::locks`] for race semantics.
    async fn clear_stale_locks(&self, older_than: SystemTime) -> Result<u64, Error>;
}
