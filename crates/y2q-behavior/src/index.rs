//! The encrypted metadata index.
//!
//! Stores per-object metadata and label postings, sealed under a metadata
//! encryption key (MEK) and blinded under a derived index key. Backs object
//! listing, key lookups, and label search. Construction is a constructor rather
//! than behavior and is left to the implementor.

use async_trait::async_trait;

/// Encrypted metadata and label-posting store.
///
/// Object metadata is encrypted before storage, and object keys and label values
/// are blinded so the on-disk index reveals neither without the active key.
#[async_trait]
pub trait MetadataIndex: Send + Sync {
    /// Error returned by index operations.
    type Error: std::error::Error + Send + Sync + 'static;
    /// Metadata describing a stored object.
    type Metadata: Send + Sync;
    /// A parsed label query used by [`search_labels`](Self::search_labels).
    type Query: Send + Sync;
    /// A page of results plus a cursor for the next page, if any.
    type ListPage: Send + Sync;
    /// Durability level applied to a write.
    type SyncLevel: Send + Sync;

    /// Install the metadata encryption key used to seal entries and derive the
    /// blinding key. Must be set before reads and writes can resolve entries.
    fn set_mek(&self, mek: [u8; 32]);

    /// Insert or replace the metadata for an object, flushed according to `sync`.
    async fn upsert(&self, m: &Self::Metadata, sync: Self::SyncLevel) -> Result<(), Self::Error>;

    /// Remove an object's metadata entry and its label postings.
    async fn remove(&self, bucket: &str, key: &str) -> Result<(), Self::Error>;

    /// Look up an object's metadata by `(bucket, key)`. Returns `None` if absent.
    async fn lookup_by_key(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<Self::Metadata>, Self::Error>;

    /// Return the `(bucket, key)` pairs carrying the label `name=value`.
    async fn lookup_by_label(
        &self,
        name: &str,
        value: &str,
    ) -> Result<Vec<(String, String)>, Self::Error>;

    /// List the names of all buckets known to the index.
    async fn list_buckets(&self) -> Result<Vec<String>, Self::Error>;

    /// Return every `(bucket, key)` pair in the index. Used for full rebuilds and
    /// administrative scans.
    async fn list_all_keys(&self) -> Result<Vec<(String, String)>, Self::Error>;

    /// Scan objects in a bucket, returning at most `limit` results after the `after`
    /// cursor and restricted to those whose key starts with `prefix` when given.
    async fn scan_objects(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Self::ListPage, Self::Error>;

    /// Search objects matching the label `query`, optionally scoped to one `bucket`
    /// and a key `prefix`, returning at most `limit` results after the `after`
    /// cursor.
    async fn search_labels(
        &self,
        query: &Self::Query,
        bucket: Option<&str>,
        prefix: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Self::ListPage, Self::Error>;
}
