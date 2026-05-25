//! Storage behavior: object CRUD, bucket administration, maintenance, and the
//! streaming-put guard pattern.
//!
//! Domain types are associated types so the contract is free of any concrete
//! storage crate, and async methods are dyn-compatible via [`async_trait`].

use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::time::SystemTime;

use async_trait::async_trait;
use bytes::Bytes;

/// Object-level create, read, update, and delete addressed by `(bucket, key)`.
#[async_trait]
pub trait ObjectStore: Send + Sync {
    /// Error returned by object operations.
    type Error: std::error::Error + Send + Sync + 'static;
    /// An object payload: the bytes plus any in-memory framing the backend keeps.
    type Object: Send + Sync;
    /// Metadata describing a stored object (size, timestamps, checksums, labels).
    type Metadata: Send + Sync;
    /// Options controlling a put: labels, durability level, and cipher metadata.
    type PutOptions: Send + Sync;

    /// Fetch a whole object by key.
    async fn get(&self, bucket: &str, key: &str) -> Result<Self::Object, Self::Error>;

    /// Fetch an inclusive byte range `[start, end]` of an object's payload.
    async fn get_range(
        &self,
        bucket: &str,
        key: &str,
        range: RangeInclusive<u64>,
    ) -> Result<Bytes, Self::Error>;

    /// Store `payload` at `(bucket, key)` with `options`. Returns `true` if an
    /// existing object was overwritten, `false` if this created a new one.
    async fn put(
        &self,
        bucket: &str,
        key: &str,
        payload: Self::Object,
        options: Self::PutOptions,
    ) -> Result<bool, Self::Error>;

    /// Delete an object and return its final contents.
    async fn delete(&self, bucket: &str, key: &str) -> Result<Self::Object, Self::Error>;

    /// Return an object's metadata without fetching its payload.
    async fn describe(&self, bucket: &str, key: &str) -> Result<Self::Metadata, Self::Error>;

    /// Replace an object's label set with `labels`.
    async fn set_labels(
        &self,
        bucket: &str,
        key: &str,
        labels: BTreeMap<String, String>,
    ) -> Result<(), Self::Error>;
}

/// Bucket administration plus object listing and label search.
#[async_trait]
pub trait BucketStore: Send + Sync {
    /// Error returned by bucket operations.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Per-bucket configuration: quota, default server-side encryption, CORS.
    type BucketConfig: Send + Sync;
    /// Options controlling a listing: prefix, continuation cursor, and limit.
    type ListOptions: Send + Sync;
    /// A page of results plus a cursor for the next page, if any.
    type ListPage: Send + Sync;
    /// A parsed label query used to filter a listing.
    type Query: Send + Sync;

    /// List the names of all buckets.
    async fn list_buckets(&self) -> Result<Vec<String>, Self::Error>;

    /// Create a bucket. Returns `true` if newly created, `false` if it existed.
    async fn create_bucket(&self, bucket: &str) -> Result<bool, Self::Error>;

    /// Delete a bucket and all its objects, returning the count of objects removed.
    async fn delete_bucket(&self, bucket: &str) -> Result<u64, Self::Error>;

    /// Read a bucket's configuration.
    async fn get_bucket_config(&self, bucket: &str) -> Result<Self::BucketConfig, Self::Error>;

    /// Write a bucket's configuration.
    async fn set_bucket_config(
        &self,
        bucket: &str,
        config: &Self::BucketConfig,
    ) -> Result<(), Self::Error>;

    /// Sum of stored object sizes in a bucket, in bytes. Used for quota checks.
    async fn bucket_usage(&self, bucket: &str) -> Result<u64, Self::Error>;

    /// List objects in a bucket, paginated according to `options`.
    async fn list_objects(
        &self,
        bucket: &str,
        options: Self::ListOptions,
    ) -> Result<Self::ListPage, Self::Error>;

    /// List objects matching a label `query`, either across all buckets or scoped
    /// to one when `bucket` is `Some`.
    async fn search_objects(
        &self,
        query: &Self::Query,
        bucket: Option<&str>,
        options: Self::ListOptions,
    ) -> Result<Self::ListPage, Self::Error>;
}

/// Background maintenance: rebuilding the metadata index and clearing stale locks.
#[async_trait]
pub trait MaintenanceStore: Send + Sync {
    /// Error returned by maintenance operations.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Progress or terminal state of a cache rebuild.
    type RebuildStatus: Send + Sync;
    /// A record describing a lock and when it was taken.
    type StaleLock: Send + Sync;

    /// Rebuild the metadata index by re-reading object headers from disk. Used to
    /// recover the index after corruption or an out-of-band change to storage.
    async fn rebuild_cache(&self) -> Result<(), Self::Error>;

    /// Report the progress or result of the most recent rebuild.
    async fn rebuild_progress(&self) -> Result<Self::RebuildStatus, Self::Error>;

    /// List locks taken before `older_than`, i.e. those considered stale.
    async fn list_stale_locks(
        &self,
        older_than: SystemTime,
    ) -> Result<Vec<Self::StaleLock>, Self::Error>;

    /// Release locks taken before `older_than`, returning the number cleared.
    async fn clear_stale_locks(&self, older_than: SystemTime) -> Result<u64, Self::Error>;
}

/// Opens a streaming put: a write sink the caller fills incrementally and a guard
/// that finalizes the object once the stream is complete.
///
/// Splitting open from commit lets the body be written and synced before the
/// object is atomically made visible and its metadata recorded.
#[async_trait]
pub trait StreamingPut: Send + Sync {
    /// Error returned when opening a streaming put.
    type Error: std::error::Error + Send + Sync + 'static;
    /// The write sink the caller streams ciphertext into.
    type Sink: Send;
    /// The guard that finalizes this put. Bound to share the sink, options, and
    /// metadata types declared here.
    type Guard: StreamingPutGuard<
            Error = Self::Error,
            Sink = Self::Sink,
            PutOptions = Self::PutOptions,
            PlaintextMetrics = Self::PlaintextMetrics,
            CipherMetadata = Self::CipherMetadata,
        >;
    /// Options controlling the put: labels, durability, and cipher metadata.
    type PutOptions: Send + Sync;
    /// Plaintext size and checksum, computed by the caller during streaming and
    /// recorded at commit.
    type PlaintextMetrics: Send + Sync;
    /// Ciphertext size, digest, and algorithm identifiers, recorded at commit.
    type CipherMetadata: Send + Sync;

    /// Begin a streaming put for `(bucket, key)`, returning the finalization guard
    /// and the write sink to stream the body into.
    async fn begin_streaming_put(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(Self::Guard, Self::Sink), Self::Error>;
}

/// Finalizes a streaming put: durably renames the temporary object into place and
/// records its metadata in the index.
///
/// [`commit`](Self::commit) consumes a boxed `self` so the trait stays
/// dyn-compatible; dropping the guard without committing abandons the temporary
/// object.
#[async_trait]
pub trait StreamingPutGuard: Send {
    /// Error returned when committing.
    type Error: std::error::Error + Send + Sync + 'static;
    /// The write sink handed back for finalization. Must match the opener's sink.
    type Sink: Send;
    /// Options controlling the put.
    type PutOptions: Send + Sync;
    /// Plaintext size and checksum measured during streaming.
    type PlaintextMetrics: Send + Sync;
    /// Ciphertext size, digest, and algorithm identifiers.
    type CipherMetadata: Send + Sync;

    /// Commit the streamed object: finalize `sink`, atomically publish the object,
    /// and write metadata from `options`, `plaintext`, and `cipher`. Returns `true`
    /// if an existing object was overwritten.
    async fn commit(
        self: Box<Self>,
        sink: Self::Sink,
        options: Self::PutOptions,
        plaintext: Self::PlaintextMetrics,
        cipher: Self::CipherMetadata,
    ) -> Result<bool, Self::Error>;
}
