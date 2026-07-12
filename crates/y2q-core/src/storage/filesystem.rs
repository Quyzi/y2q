use core::range::RangeInclusive;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::{
    CacheRebuildStatus, CipherMetadata, DEFAULT_LIST_LIMIT, Error, ListOptions, ListPage, Listing,
    MAX_LIST_LIMIT, Metadata, MetadataIndex, Object, PlaintextMetrics, PutOptions, StaleLock,
    Storage, StorageExt, SyncLevel,
    crypto::{decrypt_meta, encrypt_meta, metadata_key::MekSlot, prf},
    storage::{
        format::{self, HEADER_SIZE, Header},
        locks::LockRegistry,
    },
};

/// A [`Storage`] backend that persists objects on a local filesystem.
///
/// Objects are stored in a two-level hex-sharded directory tree rooted at
/// `base_path`, with both the bucket directory and the object filename derived
/// as keyed HMACs under the login-gated path key (so the tree leaks neither
/// bucket names nor object-key existence to anyone without a login):
///
/// ```text
/// <base_path>/<bucket_dir>/<xx>/<yy>/<id>.obj    — single-file object record
/// <base_path>/<bucket_dir>/<xx>/<yy>/<id>.lock   — ephemeral write-lock file
/// ```
///
/// Each `.obj` file uses the shared [`crate::storage::format`] layout:
/// `[header 64 B | data N B | meta M B | trailer 64 B]`. This is identical
/// to the format written by [`crate::UringStorage`], so files are
/// cross-compatible between backends.
///
/// A secondary [`MetadataIndex`] (redb-backed) is kept in sync on every
/// `put` / `delete`. The on-disk `.obj` record is the source of truth:
/// index failures are logged but do not fail the operation, and the index
/// can be rebuilt from an `.obj` scan.
pub struct FilesystemStorage {
    base_path: PathBuf,
    index: Arc<MetadataIndex>,
    rebuild_state: Arc<tokio::sync::Mutex<CacheRebuildStatus>>,
    /// Shared MEK slot, also held by `index`. Empty until a login installs the
    /// key derived from the deployment secret key; zeroized on idle; never read
    /// from disk.
    mek: Arc<MekSlot>,
    dirty_tx: Option<flume::Sender<crate::DirtyEntry>>,
    flush_notify: Option<Arc<tokio::sync::Notify>>,
    flush_limit: usize,
    locks: LockRegistry,
}

impl FilesystemStorage {
    /// Create a new `FilesystemStorage` rooted at `base_path`, with a
    /// secondary metadata index file at `index_path`.
    pub fn new(base_path: impl Into<PathBuf>, index_path: impl AsRef<Path>) -> Result<Self, Error> {
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
        let index = MetadataIndex::new(index_path);
        let mek = index.mek_slot();
        Ok(Self {
            base_path,
            index: Arc::new(index),
            rebuild_state: Arc::new(tokio::sync::Mutex::new(CacheRebuildStatus::Idle)),
            mek,
            dirty_tx: None,
            flush_notify: None,
            flush_limit: 0,
            locks: LockRegistry::new(),
        })
    }

    /// Access the underlying metadata index, e.g. for `lookup_by_label`.
    pub fn index(&self) -> &MetadataIndex {
        &self.index
    }

    /// Install the Metadata Encryption Key (derived from the deployment secret
    /// key when a login unwraps it). Object sidecar metadata is encrypted under
    /// the MEK, and the whole-file-encrypted metadata index is opened (its file
    /// key is derived from the MEK). Idempotent across re-logins.
    pub fn install_mek(&self, mek: [u8; 32]) {
        self.index.set_mek(mek);
    }

    /// Clear the MEK and close the metadata index, leaving only ciphertext on
    /// disk. Returns whether a key was present. Called on idle drop.
    pub fn clear_mek(&self) -> bool {
        let had = self.mek.clear();
        self.index.close();
        had
    }

    /// Shared handle to the MEK slot, so the daemon can install or clear the key
    /// in step with login / idle-drop.
    pub fn mek_slot(&self) -> Arc<MekSlot> {
        Arc::clone(&self.mek)
    }

    /// Attach a dirty-write channel for best-effort PUT flushing.
    /// After each non-Durable commit, the obj path is sent to `tx`.
    /// When the queue depth reaches `flush_limit`, `notify` is signalled.
    pub fn with_dirty_channel(
        mut self,
        tx: flume::Sender<crate::DirtyEntry>,
        notify: Arc<tokio::sync::Notify>,
        flush_limit: usize,
    ) -> Self {
        self.dirty_tx = Some(tx);
        self.flush_notify = Some(notify);
        self.flush_limit = flush_limit;
        self
    }

    /// Canonical on-disk path for the single-file object record of
    /// `(bucket, key)`: `<base>/<bucket_dir>/<xx>/<yy>/<id>.obj`, where
    /// `bucket_dir` and `id` are keyed HMACs under the login-gated path key.
    ///
    /// Matches the path scheme used by [`crate::UringStorage`] so both
    /// backends can read each other's files when sharing a `base_path` and the
    /// same deployment secret key. Errors if no login has installed the MEK
    /// (and hence the path key) yet.
    pub fn key_path(&self, bucket: &str, key: &str) -> Result<PathBuf, Error> {
        let path_key = require_path_key(&self.mek)?;
        Ok(obj_path_for(&self.base_path, &path_key, bucket, key))
    }
}

/// Lowercase-hex encode `bytes`.
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Read the path key from `mek`, erroring if no session has installed it.
///
/// Object and bucket on-disk locations are keyed by the login-gated path key,
/// so every path-building operation requires an active session — mirroring the
/// MEK requirement for metadata encryption.
pub(crate) fn require_path_key(mek: &MekSlot) -> Result<[u8; 32], Error> {
    mek.path_key().ok_or_else(|| Error::InternalError {
        bucket: String::new(),
        key: String::new(),
        operation: "path".to_owned(),
        message: "path operation attempted without an installed MEK".to_owned(),
    })
}

/// Keyed opaque directory name for `bucket`:
/// `hex(HMAC-SHA256(path_key, "y2q-bucket\0" || len(bucket) || bucket))`.
pub(crate) fn encode_bucket_dir(path_key: &[u8; 32], bucket: &str) -> String {
    let mut buf = Vec::with_capacity(15 + bucket.len());
    buf.extend_from_slice(b"y2q-bucket\0");
    buf.extend_from_slice(&(bucket.len() as u32).to_be_bytes());
    buf.extend_from_slice(bucket.as_bytes());
    to_hex(&prf(path_key, &buf))
}

/// Keyed opaque object id (filename stem) for `(bucket, key)`:
/// `hex(HMAC-SHA256(path_key, "y2q-object\0" || len(bucket)||bucket || len(key)||key))`.
/// Including the bucket means identical keys in different buckets map to
/// distinct ids.
pub(crate) fn encode_object_id(path_key: &[u8; 32], bucket: &str, key: &str) -> String {
    let mut buf = Vec::with_capacity(19 + bucket.len() + key.len());
    buf.extend_from_slice(b"y2q-object\0");
    for part in [bucket.as_bytes(), key.as_bytes()] {
        buf.extend_from_slice(&(part.len() as u32).to_be_bytes());
        buf.extend_from_slice(part);
    }
    to_hex(&prf(path_key, &buf))
}

/// Absolute on-disk directory for `bucket` under `base_path`.
pub(crate) fn bucket_dir_path(base_path: &Path, path_key: &[u8; 32], bucket: &str) -> PathBuf {
    base_path.join(encode_bucket_dir(path_key, bucket))
}

/// Extract the opaque per-object id (the `.obj` filename stem produced by
/// [`encode_object_id`]) from a path built by [`obj_path_for`].
///
/// Used to bind encrypted metadata to its physical storage location (see
/// [`crate::crypto::metadata_key`]) without needing to already know the
/// object's bucket/key — the index-rebuild scan discovers those only by
/// decrypting the metadata itself, so the id must be derivable from the path
/// alone.
pub(crate) fn object_id_from_path(path: &Path) -> Option<&str> {
    path.file_stem().and_then(|s| s.to_str())
}

/// Reserved bucket names that conflict with the `/api/v1/*` admin namespace.
const RESERVED_BUCKETS: &[&str] = &["api"];

pub(crate) fn validate_bucket(bucket: &str) -> Result<(), Error> {
    let lower = bucket.to_ascii_lowercase();
    if bucket.is_empty()
        || bucket.contains('/')
        || bucket.contains('\\')
        || bucket.contains("..")
        || !bucket
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        || RESERVED_BUCKETS.contains(&lower.as_str())
    {
        return Err(Error::InvalidBucket {
            bucket: bucket.to_owned(),
        });
    }
    Ok(())
}

/// Create the on-disk directory for `bucket` and register it in the encrypted
/// index. Returns `true` if it was newly created, `false` if it already
/// existed. Shared by both storage backends, which use an identical
/// `<base>/<bucket_dir>/...` layout.
pub(crate) async fn create_bucket_impl(
    base_path: &Path,
    index: &MetadataIndex,
    path_key: &[u8; 32],
    bucket: &str,
) -> Result<bool, Error> {
    validate_bucket(bucket)?;
    let dir = bucket_dir_path(base_path, path_key, bucket);
    if tokio::fs::try_exists(&dir).await.unwrap_or(false) {
        return Ok(false);
    }
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| Error::InternalError {
            bucket: bucket.to_owned(),
            key: String::new(),
            operation: "create_bucket".to_owned(),
            message: e.to_string(),
        })?;
    // Record the plaintext name in the encrypted index so empty buckets still
    // list (the on-disk dir name is an opaque, irreversible HMAC).
    index.register_bucket(bucket).await?;
    Ok(true)
}

/// Delete every object in `bucket` from the index and remove the bucket
/// directory tree from disk. Returns the number of index entries removed.
pub(crate) async fn delete_bucket_impl(
    base_path: &Path,
    index: &MetadataIndex,
    path_key: &[u8; 32],
    bucket: &str,
) -> Result<u64, Error> {
    validate_bucket(bucket)?;
    let dir = bucket_dir_path(base_path, path_key, bucket);
    let dir_exists = tokio::fs::try_exists(&dir).await.unwrap_or(false);

    let keys = index.list_all_keys().await?;
    let mut removed = 0u64;
    for (b, key) in keys {
        if b == bucket {
            index.remove(bucket, &key).await?;
            removed += 1;
        }
    }

    if !dir_exists && removed == 0 {
        return Err(Error::NotFound {
            bucket: bucket.to_owned(),
            key: String::new(),
        });
    }
    if dir_exists {
        tokio::fs::remove_dir_all(&dir)
            .await
            .map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: String::new(),
                operation: "delete_bucket".to_owned(),
                message: e.to_string(),
            })?;
    }
    index.unregister_bucket(bucket).await?;
    Ok(removed)
}

/// Union the bucket names that have objects (derived from the encrypted index)
/// with the registry of explicitly-created buckets, so that empty buckets
/// (created via `create_bucket`, no objects yet) are still reported. Result is
/// sorted and de-duplicated.
///
/// The on-disk directory names are opaque keyed HMACs and cannot be decoded
/// back to bucket names, so the encrypted index — not a `read_dir` — is the
/// source of truth for bucket names.
pub(crate) async fn list_buckets_union(index: &MetadataIndex) -> Result<Vec<String>, Error> {
    let mut buckets = index.list_buckets().await?;
    buckets.extend(index.list_registered_buckets().await?);
    buckets.sort();
    buckets.dedup();
    Ok(buckets)
}

/// Canonical `.obj` path for `(bucket, key)` rooted at `base_path`, using the
/// keyed opaque bucket directory and object id. Mirrors
/// [`FilesystemStorage::key_path`] / the uring backend so the shared bucket and
/// label helpers can locate records without a backend instance.
pub(crate) fn obj_path_for(
    base_path: &Path,
    path_key: &[u8; 32],
    bucket: &str,
    key: &str,
) -> PathBuf {
    let id = encode_object_id(path_key, bucket, key);
    let mut p = bucket_dir_path(base_path, path_key, bucket)
        .join(&id[0..2])
        .join(&id[2..4])
        .join(&id);
    p.set_extension("obj");
    p
}

/// Rewrite an object's `.obj` record, replacing only its user labels and
/// `modified` timestamp. The data section and all envelope/cipher metadata are
/// preserved byte-for-byte. Shared by both backends (identical on-disk format).
///
/// The write is atomic: a new file is written to a sibling `.tmp` path and
/// renamed into place. The secondary index is updated afterwards.
pub(crate) async fn set_labels_impl(
    base_path: &Path,
    index: &MetadataIndex,
    mek: Option<&[u8; 32]>,
    path_key: &[u8; 32],
    bucket: &str,
    key: &str,
    labels: crate::LabelSet,
) -> Result<(), Error> {
    validate_bucket(bucket)?;
    validate_key(key)?;

    let obj_path = obj_path_for(base_path, path_key, bucket, key);
    let bytes = match tokio::fs::read(&obj_path).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::NotFound {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
            });
        }
        Err(e) => {
            return Err(Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "set_labels".to_owned(),
                message: e.to_string(),
            });
        }
    };

    let internal = |message: String| Error::InternalError {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        operation: "set_labels".to_owned(),
        message,
    };

    if bytes.len() < HEADER_SIZE {
        return Err(internal("object file shorter than header".to_owned()));
    }
    let mut header_buf = [0u8; HEADER_SIZE];
    header_buf.copy_from_slice(&bytes[..HEADER_SIZE]);
    let header =
        Header::decode(&header_buf).map_err(|e| internal(format!("decode header: {e}")))?;

    let data_start = header.data_offset as usize;
    let meta_start = header.meta_offset() as usize;
    let meta_end = meta_start + header.meta_len as usize;
    if meta_end > bytes.len() {
        return Err(internal("meta block extends past end of file".to_owned()));
    }
    let data = &bytes[data_start..meta_start];
    let meta_bytes = &bytes[meta_start..meta_end];

    let object_id = object_id_from_path(&obj_path)
        .ok_or_else(|| internal("cannot derive object id from path".to_owned()))?;
    let meta_json = match mek {
        Some(k) => decrypt_meta(k, meta_bytes, object_id)
            .map_err(|e| internal(format!("decrypt meta: {e}")))?,
        None => meta_bytes.to_vec(),
    };
    let mut metadata: Metadata =
        serde_json::from_slice(&meta_json).map_err(|e| internal(format!("parse meta: {e}")))?;

    metadata.labels = labels;
    metadata.modified = now_nanos();

    let new_json =
        serde_json::to_vec(&metadata).map_err(|e| internal(format!("encode meta: {e}")))?;
    // Writes require an installed MEK; refuse rather than persisting plaintext.
    let new_meta = match mek {
        Some(k) => encrypt_meta(k, &new_json, object_id)
            .map_err(|e| internal(format!("encrypt meta: {e}")))?,
        None => {
            return Err(internal(
                "metadata write attempted without an installed MEK".to_owned(),
            ));
        }
    };

    let new_header = Header {
        data_len: header.data_len,
        meta_len: new_meta.len() as u32,
        data_offset: header.data_offset,
        flags: header.flags,
        version: header.version,
    };
    let header_enc = new_header.encode();

    let mut out = Vec::with_capacity(data_start + data.len() + new_meta.len() + HEADER_SIZE);
    out.extend_from_slice(&header_enc);
    out.resize(data_start, 0); // zero padding up to data_offset (O_DIRECT path)
    out.extend_from_slice(data);
    out.extend_from_slice(&new_meta);
    out.extend_from_slice(&header_enc); // trailer mirrors the header

    let tmp_path = obj_path.with_extension("labels.tmp");
    tokio::fs::write(&tmp_path, &out)
        .await
        .map_err(|e| internal(format!("write tmp: {e}")))?;
    tokio::fs::rename(&tmp_path, &obj_path)
        .await
        .map_err(|e| internal(format!("rename: {e}")))?;

    if let Err(e) = index.upsert(&metadata, SyncLevel::Durable).await {
        tracing::warn!(bucket, key, error = %e, "metadata index upsert failed after set_labels");
    }
    Ok(())
}

/// Filename of the per-bucket JSON config sidecar, stored at the bucket root
/// (`<base>/<bucket_dir>/.y2q-bucket.json`). It is a plain file, not a sharded
/// `.obj`, so it never appears in object listings.
const BUCKET_CONFIG_FILE: &str = ".y2q-bucket.json";

pub(crate) async fn get_bucket_config_impl(
    base_path: &Path,
    path_key: &[u8; 32],
    bucket: &str,
) -> Result<crate::BucketConfig, Error> {
    validate_bucket(bucket)?;
    let path = bucket_dir_path(base_path, path_key, bucket).join(BUCKET_CONFIG_FILE);
    match tokio::fs::read(&path).await {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| Error::InternalError {
            bucket: bucket.to_owned(),
            key: String::new(),
            operation: "get_bucket_config".to_owned(),
            message: format!("parse config: {e}"),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(crate::BucketConfig::default()),
        Err(e) => Err(Error::InternalError {
            bucket: bucket.to_owned(),
            key: String::new(),
            operation: "get_bucket_config".to_owned(),
            message: e.to_string(),
        }),
    }
}

pub(crate) async fn set_bucket_config_impl(
    base_path: &Path,
    path_key: &[u8; 32],
    bucket: &str,
    config: &crate::BucketConfig,
) -> Result<(), Error> {
    validate_bucket(bucket)?;
    let dir = bucket_dir_path(base_path, path_key, bucket);
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| Error::InternalError {
            bucket: bucket.to_owned(),
            key: String::new(),
            operation: "set_bucket_config".to_owned(),
            message: format!("create bucket dir: {e}"),
        })?;
    let json = serde_json::to_vec_pretty(config).map_err(|e| Error::InternalError {
        bucket: bucket.to_owned(),
        key: String::new(),
        operation: "set_bucket_config".to_owned(),
        message: format!("encode config: {e}"),
    })?;
    let path = dir.join(BUCKET_CONFIG_FILE);
    let tmp = dir.join(".y2q-bucket.json.tmp");
    tokio::fs::write(&tmp, &json)
        .await
        .map_err(|e| Error::InternalError {
            bucket: bucket.to_owned(),
            key: String::new(),
            operation: "set_bucket_config".to_owned(),
            message: format!("write config: {e}"),
        })?;
    tokio::fs::rename(&tmp, &path)
        .await
        .map_err(|e| Error::InternalError {
            bucket: bucket.to_owned(),
            key: String::new(),
            operation: "set_bucket_config".to_owned(),
            message: format!("rename config: {e}"),
        })?;
    Ok(())
}

pub(crate) async fn bucket_usage_impl(index: &MetadataIndex, bucket: &str) -> Result<u64, Error> {
    validate_bucket(bucket)?;
    let mut total = 0u64;
    let mut after: Option<String> = None;
    loop {
        let page = index
            .scan_objects(bucket, None, after.as_deref(), 1000)
            .await?;
        for item in &page.items {
            total += item.size;
        }
        match page.next {
            Some(c) => after = Some(c),
            None => break,
        }
    }
    Ok(total)
}

fn validate_key(key: &str) -> Result<(), Error> {
    const MAX_KEY_LEN: usize = 1024;
    if key.is_empty() || key.contains('\0') || key.len() > MAX_KEY_LEN {
        return Err(Error::InvalidKey {
            key: key.to_owned(),
        });
    }
    Ok(())
}

fn compute_checksum(data: &[u8]) -> String {
    crate::checksum::checksum_b64(data)
}

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn record_storage_op<T, E>(op: &'static str, result: &Result<T, E>, elapsed_ms: f64) {
    let result_label = if result.is_ok() { "ok" } else { "err" };
    metrics::counter!(
        "y2qd_storage_ops_total",
        "op" => op, "backend" => "filesystem", "result" => result_label
    )
    .increment(1);
    metrics::histogram!(
        "y2qd_storage_op_duration_milliseconds",
        "op" => op, "backend" => "filesystem"
    )
    .record(elapsed_ms);
}

/// Read and decode the metadata embedded in a `.obj` file at `path`.
async fn read_obj_metadata(
    path: &Path,
    mek: Option<&[u8; 32]>,
) -> Result<Metadata, std::io::Error> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut header_buf = [0u8; HEADER_SIZE];
    file.read_exact(&mut header_buf).await?;
    let header = Header::decode(&header_buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    file.seek(std::io::SeekFrom::Start(header.meta_offset()))
        .await?;
    let mut meta_buf = vec![0u8; header.meta_len as usize];
    file.read_exact(&mut meta_buf).await?;
    let json = if let Some(mek) = mek {
        let object_id = object_id_from_path(path).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "cannot derive object id from path",
            )
        })?;
        decrypt_meta(mek, &meta_buf, object_id)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?
    } else {
        meta_buf
    };
    serde_json::from_slice(&json)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Read the `created` timestamp from an existing `.obj` file, returning `None`
/// if the file cannot be read or parsed.
async fn read_obj_created(path: &Path, mek: Option<&[u8; 32]>) -> Option<u64> {
    read_obj_metadata(path, mek).await.ok().map(|m| m.created)
}

/// RAII guard returned by [`FilesystemStorage::begin_streaming_put`].
///
/// Holds the `.lock` file and tmp-file path for the duration of a streaming
/// PUT. Call [`commit`] (passing back the file handle) when encryption is
/// done; otherwise [`Drop`] removes the tmp file and releases the lock.
pub struct StreamingPutGuard {
    tmp_path: PathBuf,
    obj_path: PathBuf,
    _lock: crate::storage::locks::LockGuard,
    bucket: String,
    key: String,
    is_overwrite: bool,
    prior_created: Option<u64>,
    index: Arc<MetadataIndex>,
    mek: Arc<MekSlot>,
    dirty_tx: Option<flume::Sender<crate::DirtyEntry>>,
    flush_notify: Option<Arc<tokio::sync::Notify>>,
    flush_limit: usize,
}

impl StreamingPutGuard {
    /// Flush and close `file`, write the metadata blob and trailer, overwrite
    /// the placeholder header at offset 0 with the real header, optionally
    /// fdatasync, rename the tmp file atomically into place, and update the
    /// secondary index. Returns `true` if this was an overwrite.
    pub async fn commit(
        self,
        mut file: tokio::fs::File,
        options: PutOptions,
        plaintext_metrics: PlaintextMetrics,
        cipher_metadata: CipherMetadata,
    ) -> Result<bool, Error> {
        let bucket = self.bucket.as_str();
        let key = self.key.as_str();
        let cipher_size = cipher_metadata.cipher_size;
        let now = now_nanos();
        let created = self.prior_created.unwrap_or(now);

        let metadata = Metadata {
            created,
            modified: now,
            size: plaintext_metrics.size,
            checksum_gxhash: plaintext_metrics.checksum_gxhash_b64,
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            disk_path: self.obj_path.clone(),
            url_path: format!("{bucket}/{key}"),
            labels: options.labels,
            cipher_size: Some(cipher_size),
            cipher_checksum: Some(cipher_metadata.cipher_checksum_b64),
            kem_alg: Some(cipher_metadata.kem_alg),
            aead_alg: Some(cipher_metadata.aead_alg),
            envelope_version: Some(cipher_metadata.envelope_version),
            version: options.version,
            committed_at: options.version.map(|_| now),
        };

        let meta_json = serde_json::to_vec(&metadata).map_err(|e| Error::InternalError {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            operation: "put".to_owned(),
            message: format!("encode meta: {e}"),
        })?;
        let meta_bytes = match self.mek.mek() {
            Some(mek) => {
                let object_id =
                    object_id_from_path(&self.obj_path).ok_or_else(|| Error::InternalError {
                        bucket: bucket.to_owned(),
                        key: key.to_owned(),
                        operation: "put".to_owned(),
                        message: "cannot derive object id from path".to_owned(),
                    })?;
                encrypt_meta(&mek, &meta_json, object_id).map_err(|e| Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "put".to_owned(),
                    message: format!("encrypt meta: {e}"),
                })?
            }
            None => {
                return Err(Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "put".to_owned(),
                    message: "metadata write attempted without an installed MEK".to_owned(),
                });
            }
        };

        let mut flags = 0u16;
        if options.sync == SyncLevel::Durable {
            flags |= format::flags::DURABLE;
        }
        let header = Header {
            data_len: cipher_size,
            meta_len: meta_bytes.len() as u32,
            data_offset: Header::MIN_DATA_OFFSET,
            flags,
            version: format::VERSION,
        };

        // File is at EOF after EncryptSession. Append meta then trailer.
        file.write_all(&meta_bytes)
            .await
            .map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "put".to_owned(),
                message: format!("write meta: {e}"),
            })?;
        file.write_all(&header.encode())
            .await
            .map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "put".to_owned(),
                message: format!("write trailer: {e}"),
            })?;

        // Overwrite the placeholder header at offset 0 with the real one.
        file.seek(std::io::SeekFrom::Start(0))
            .await
            .map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "put".to_owned(),
                message: format!("seek to header: {e}"),
            })?;
        file.write_all(&header.encode())
            .await
            .map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "put".to_owned(),
                message: format!("write header: {e}"),
            })?;

        if options.sync == SyncLevel::Durable {
            file.sync_data().await.map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "put".to_owned(),
                message: format!("fdatasync: {e}"),
            })?;
        }
        drop(file);

        tokio::fs::rename(&self.tmp_path, &self.obj_path)
            .await
            .map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "put".to_owned(),
                message: format!("rename: {e}"),
            })?;

        if options.sync == SyncLevel::Durable {
            if let Some(parent) = self.obj_path.parent()
                && let Ok(dir) = tokio::fs::File::open(parent).await
            {
                let _ = dir.sync_all().await;
            }
        } else if let Some(ref tx) = self.dirty_tx
            && let Some(parent_dir) = self.obj_path.parent().map(PathBuf::from)
        {
            let entry = crate::DirtyEntry {
                obj_path: self.obj_path.clone(),
                parent_dir,
            };
            let _ = tx.send(entry);
            if tx.len() >= self.flush_limit
                && let Some(ref notify) = self.flush_notify
            {
                notify.notify_one();
            }
        }

        if let Err(e) = self.index.upsert(&metadata, options.sync).await {
            tracing::warn!(
                bucket = bucket,
                key = key,
                error = %e,
                "metadata index upsert failed; on-disk record is authoritative"
            );
        }

        Ok(self.is_overwrite)
    }

    /// Read `len` bytes at absolute file offset `start` from the staged (not yet
    /// committed) tmp file. The cluster HEAD uses this to stream the envelope
    /// down-chain before committing locally (CRAQ tail-first ordering), when the
    /// committed `.obj` does not yet exist.
    pub async fn read_staged_range(&self, start: u64, len: u64) -> Result<Bytes, Error> {
        read_staged_range_from(&self.tmp_path, &self.bucket, &self.key, start, len).await
    }
}

/// Read `len` bytes at `start` from `path` (a staging tmp file). Shared by the
/// streaming guards' `read_staged_range`.
pub(crate) async fn read_staged_range_from(
    path: &Path,
    bucket: &str,
    key: &str,
    start: u64,
    len: u64,
) -> Result<Bytes, Error> {
    let internal = |message: String| Error::InternalError {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        operation: "read_staged".to_owned(),
        message,
    };
    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|e| internal(format!("open tmp: {e}")))?;
    f.seek(std::io::SeekFrom::Start(start))
        .await
        .map_err(|e| internal(format!("seek tmp: {e}")))?;
    let mut buf = vec![0u8; len as usize];
    f.read_exact(&mut buf)
        .await
        .map_err(|e| internal(format!("read tmp: {e}")))?;
    Ok(Bytes::from(buf))
}

impl Drop for StreamingPutGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.tmp_path);
    }
}

impl FilesystemStorage {
    /// Begin a streaming PUT: validate inputs, create the directory, acquire the
    /// lock, open the tmp file, and write a 64-byte placeholder `.obj` header.
    /// Returns a [`StreamingPutGuard`] plus the open tmp file. The caller writes
    /// encrypted bytes to the file (starting at offset 64), then calls
    /// [`StreamingPutGuard::commit`] to finalise the on-disk record.
    pub async fn begin_streaming_put(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(StreamingPutGuard, tokio::fs::File), Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;

        let obj_path = self.key_path(bucket, key)?;
        let tmp_path = obj_path.with_extension("tmp");

        if let Some(parent) = obj_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "begin_streaming_put".to_owned(),
                    message: format!("create dirs: {e}"),
                })?;
        }

        let (is_overwrite, prior_created) = match tokio::fs::metadata(&obj_path).await {
            Ok(_) => {
                let created = read_obj_created(&obj_path, self.mek.mek().as_ref()).await;
                (true, created)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (false, None),
            Err(e) => {
                return Err(Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "begin_streaming_put".to_owned(),
                    message: format!("stat existing: {e}"),
                });
            }
        };

        let lock = self.locks.try_acquire(bucket, key)?;

        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .await
            .map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "begin_streaming_put".to_owned(),
                message: format!("open tmp: {e}"),
            })?;

        file.write_all(&[0u8; HEADER_SIZE])
            .await
            .map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "begin_streaming_put".to_owned(),
                message: format!("write placeholder header: {e}"),
            })?;

        let guard = StreamingPutGuard {
            tmp_path,
            obj_path,
            _lock: lock,
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            is_overwrite,
            prior_created,
            mek: Arc::clone(&self.mek),
            index: self.index.clone(),
            dirty_tx: self.dirty_tx.clone(),
            flush_notify: self.flush_notify.clone(),
            flush_limit: self.flush_limit,
        };
        Ok((guard, file))
    }
}

impl Storage for FilesystemStorage {
    async fn get(&self, bucket: &str, key: &str) -> Result<Object, Error> {
        let started = Instant::now();
        let result = async {
            validate_bucket(bucket)?;
            validate_key(key)?;

            let obj_path = self.key_path(bucket, key)?;
            self.locks.check_not_locked(bucket, key)?;

            let mut file = match tokio::fs::File::open(&obj_path).await {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(Error::NotFound {
                        bucket: bucket.to_owned(),
                        key: key.to_owned(),
                    });
                }
                Err(e) => {
                    return Err(Error::InternalError {
                        bucket: bucket.to_owned(),
                        key: key.to_owned(),
                        operation: "get".to_owned(),
                        message: e.to_string(),
                    });
                }
            };

            let mut header_buf = [0u8; HEADER_SIZE];
            file.read_exact(&mut header_buf)
                .await
                .map_err(|e| Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "get".to_owned(),
                    message: format!("read header: {e}"),
                })?;
            let header = Header::decode(&header_buf).map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "get".to_owned(),
                message: format!("decode header: {e}"),
            })?;

            file.seek(std::io::SeekFrom::Start(header.data_offset as u64))
                .await
                .map_err(|e| Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "get".to_owned(),
                    message: format!("seek data: {e}"),
                })?;

            let mut data = vec![0u8; header.data_len as usize];
            file.read_exact(&mut data)
                .await
                .map_err(|e| Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "get".to_owned(),
                    message: format!("read data: {e}"),
                })?;

            Ok(Object::new(Bytes::from(data)))
        }
        .await;
        record_storage_op("get", &result, started.elapsed().as_secs_f64() * 1_000.0);
        result
    }

    async fn get_range(
        &self,
        bucket: &str,
        key: &str,
        range: RangeInclusive<u64>,
    ) -> Result<Bytes, Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;

        let obj_path = self.key_path(bucket, key)?;
        self.locks.check_not_locked(bucket, key)?;

        let mut file = match tokio::fs::File::open(&obj_path).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::NotFound {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                });
            }
            Err(e) => {
                return Err(Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "get_range".to_owned(),
                    message: e.to_string(),
                });
            }
        };

        let mut header_buf = [0u8; HEADER_SIZE];
        file.read_exact(&mut header_buf)
            .await
            .map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "get_range".to_owned(),
                message: format!("read header: {e}"),
            })?;
        let header = Header::decode(&header_buf).map_err(|e| Error::InternalError {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            operation: "get_range".to_owned(),
            message: format!("decode header: {e}"),
        })?;

        if header.data_len == 0 || range.start >= header.data_len {
            return Ok(Bytes::new());
        }

        let start = range.start;
        let end_inclusive = range.last.min(header.data_len - 1);
        let len = (end_inclusive - start + 1) as usize;

        file.seek(std::io::SeekFrom::Start(header.data_offset as u64 + start))
            .await
            .map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "get_range".to_owned(),
                message: format!("seek: {e}"),
            })?;

        let mut data = vec![0u8; len];
        file.read_exact(&mut data)
            .await
            .map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "get_range".to_owned(),
                message: format!("read data: {e}"),
            })?;

        Ok(Bytes::from(data))
    }

    async fn put(
        &self,
        bucket: &str,
        key: &str,
        payload: Object,
        options: PutOptions,
    ) -> Result<bool, Error> {
        let started = Instant::now();
        let result = async {
            validate_bucket(bucket)?;
            validate_key(key)?;

            let obj_path = self.key_path(bucket, key)?;
            let tmp_path = obj_path.with_extension("tmp");

            if let Some(parent) = obj_path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| Error::InternalError {
                        bucket: bucket.to_owned(),
                        key: key.to_owned(),
                        operation: "put".to_owned(),
                        message: e.to_string(),
                    })?;
            }

            let _lock = self.locks.try_acquire(bucket, key)?;

            let (is_overwrite, prior_created) = match tokio::fs::metadata(&obj_path).await {
                Ok(_) => {
                    let created = read_obj_created(&obj_path, self.mek.mek().as_ref()).await;
                    (true, created)
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (false, None),
                Err(e) => {
                    return Err(Error::InternalError {
                        bucket: bucket.to_owned(),
                        key: key.to_owned(),
                        operation: "put".to_owned(),
                        message: format!("stat existing: {e}"),
                    });
                }
            };

            let data: &[u8] = &payload;
            let now = now_nanos();
            let created = prior_created.unwrap_or(now);

            let (size, checksum_gxhash) = match &options.plaintext_metrics {
                Some(p) => (p.size, p.checksum_gxhash_b64.clone()),
                None => (data.len() as u64, compute_checksum(data)),
            };
            let (cipher_size, cipher_checksum, kem_alg, aead_alg, envelope_version) =
                match &options.cipher_metadata {
                    Some(c) => (
                        Some(c.cipher_size),
                        Some(c.cipher_checksum_b64.clone()),
                        Some(c.kem_alg.clone()),
                        Some(c.aead_alg.clone()),
                        Some(c.envelope_version),
                    ),
                    None => (None, None, None, None, None),
                };

            let metadata = Metadata {
                created,
                modified: now,
                size,
                checksum_gxhash,
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                disk_path: obj_path.clone(),
                url_path: format!("{bucket}/{key}"),
                labels: options.labels,
                cipher_size,
                cipher_checksum,
                kem_alg,
                aead_alg,
                envelope_version,
                // Buffered put is not a cluster write path; CRAQ versions are
                // assigned only on the streaming commit path.
                version: None,
                committed_at: None,
            };

            let meta_json = serde_json::to_vec(&metadata).map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "put".to_owned(),
                message: e.to_string(),
            })?;
            let meta_bytes = match self.mek.mek() {
                Some(mek) => {
                    let object_id =
                        object_id_from_path(&obj_path).ok_or_else(|| Error::InternalError {
                            bucket: bucket.to_owned(),
                            key: key.to_owned(),
                            operation: "put".to_owned(),
                            message: "cannot derive object id from path".to_owned(),
                        })?;
                    encrypt_meta(&mek, &meta_json, object_id).map_err(|e| Error::InternalError {
                        bucket: bucket.to_owned(),
                        key: key.to_owned(),
                        operation: "put".to_owned(),
                        message: e.to_string(),
                    })?
                }
                None => {
                    return Err(Error::InternalError {
                        bucket: bucket.to_owned(),
                        key: key.to_owned(),
                        operation: "put".to_owned(),
                        message: "metadata write attempted without an installed MEK".to_owned(),
                    });
                }
            };

            let mut header_flags = 0u16;
            if options.sync == SyncLevel::Durable {
                header_flags |= format::flags::DURABLE;
            }
            let header = Header {
                data_len: data.len() as u64,
                meta_len: meta_bytes.len() as u32,
                data_offset: Header::MIN_DATA_OFFSET,
                flags: header_flags,
                version: format::VERSION,
            };

            let mut tmp_file = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)
                .await
                .map_err(|e| Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "put".to_owned(),
                    message: e.to_string(),
                })?;

            tmp_file
                .write_all(&header.encode())
                .await
                .map_err(|e| Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "put".to_owned(),
                    message: format!("write header: {e}"),
                })?;
            tmp_file
                .write_all(data)
                .await
                .map_err(|e| Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "put".to_owned(),
                    message: format!("write data: {e}"),
                })?;
            tmp_file
                .write_all(&meta_bytes)
                .await
                .map_err(|e| Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "put".to_owned(),
                    message: format!("write meta: {e}"),
                })?;
            tmp_file
                .write_all(&header.encode())
                .await
                .map_err(|e| Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "put".to_owned(),
                    message: format!("write trailer: {e}"),
                })?;

            if options.sync == SyncLevel::Durable {
                tmp_file
                    .sync_data()
                    .await
                    .map_err(|e| Error::InternalError {
                        bucket: bucket.to_owned(),
                        key: key.to_owned(),
                        operation: "put".to_owned(),
                        message: format!("fdatasync: {e}"),
                    })?;
            }
            drop(tmp_file);

            tokio::fs::rename(&tmp_path, &obj_path)
                .await
                .map_err(|e| Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "put".to_owned(),
                    message: format!("rename: {e}"),
                })?;

            if options.sync == SyncLevel::Durable {
                if let Some(parent) = obj_path.parent()
                    && let Ok(dir) = tokio::fs::File::open(parent).await
                {
                    let _ = dir.sync_all().await;
                }
            } else if let Some(ref tx) = self.dirty_tx
                && let Some(parent_dir) = obj_path.parent().map(PathBuf::from)
            {
                let entry = crate::DirtyEntry {
                    obj_path: obj_path.clone(),
                    parent_dir,
                };
                let _ = tx.send(entry);
                if tx.len() >= self.flush_limit
                    && let Some(ref notify) = self.flush_notify
                {
                    notify.notify_one();
                }
            }

            if let Err(e) = self.index.upsert(&metadata, options.sync).await {
                tracing::warn!(
                    bucket = bucket,
                    key = key,
                    error = %e,
                    "metadata index upsert failed; on-disk record is authoritative"
                );
            }

            Ok(is_overwrite)
        }
        .await;
        record_storage_op("put", &result, started.elapsed().as_secs_f64() * 1_000.0);
        result
    }

    async fn delete(&self, bucket: &str, key: &str) -> Result<Object, Error> {
        let started = Instant::now();
        let result = async {
            validate_bucket(bucket)?;
            validate_key(key)?;

            let obj_path = self.key_path(bucket, key)?;
            self.locks.check_not_locked(bucket, key)?;

            let mut file = match tokio::fs::File::open(&obj_path).await {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(Error::NotFound {
                        bucket: bucket.to_owned(),
                        key: key.to_owned(),
                    });
                }
                Err(e) => {
                    return Err(Error::InternalError {
                        bucket: bucket.to_owned(),
                        key: key.to_owned(),
                        operation: "delete".to_owned(),
                        message: e.to_string(),
                    });
                }
            };

            let mut header_buf = [0u8; HEADER_SIZE];
            file.read_exact(&mut header_buf)
                .await
                .map_err(|e| Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "delete".to_owned(),
                    message: format!("read header: {e}"),
                })?;
            let header = Header::decode(&header_buf).map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "delete".to_owned(),
                message: format!("decode header: {e}"),
            })?;

            file.seek(std::io::SeekFrom::Start(header.data_offset as u64))
                .await
                .map_err(|e| Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "delete".to_owned(),
                    message: format!("seek data: {e}"),
                })?;

            let mut data = vec![0u8; header.data_len as usize];
            file.read_exact(&mut data)
                .await
                .map_err(|e| Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "delete".to_owned(),
                    message: format!("read data: {e}"),
                })?;
            drop(file);

            tokio::fs::remove_file(&obj_path).await.ok();

            if let Err(e) = self.index.remove(bucket, key).await {
                tracing::warn!(
                    bucket = bucket,
                    key = key,
                    error = %e,
                    "metadata index remove failed"
                );
            }

            Ok(Object::new(Bytes::from(data)))
        }
        .await;
        record_storage_op("delete", &result, started.elapsed().as_secs_f64() * 1_000.0);
        result
    }

    async fn set_labels(
        &self,
        bucket: &str,
        key: &str,
        labels: crate::LabelSet,
    ) -> Result<(), Error> {
        let started = Instant::now();
        let result = async {
            self.locks.check_not_locked(bucket, key)?;
            let path_key = require_path_key(&self.mek)?;
            set_labels_impl(
                &self.base_path,
                &self.index,
                self.mek.mek().as_ref(),
                &path_key,
                bucket,
                key,
                labels,
            )
            .await
        }
        .await;
        record_storage_op(
            "set_labels",
            &result,
            started.elapsed().as_secs_f64() * 1_000.0,
        );
        result
    }

    async fn describe(&self, bucket: &str, key: &str) -> Result<Metadata, Error> {
        let started = Instant::now();
        let result = async {
            validate_bucket(bucket)?;
            validate_key(key)?;

            let obj_path = self.key_path(bucket, key)?;
            self.locks.check_not_locked(bucket, key)?;

            if !tokio::fs::try_exists(&obj_path).await.unwrap_or(false) {
                return Err(Error::NotFound {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                });
            }

            read_obj_metadata(&obj_path, self.mek.mek().as_ref())
                .await
                .map_err(|e| Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "describe".to_owned(),
                    message: e.to_string(),
                })
        }
        .await;
        record_storage_op(
            "describe",
            &result,
            started.elapsed().as_secs_f64() * 1_000.0,
        );
        result
    }
}

impl Listing for FilesystemStorage {
    async fn list_buckets(&self) -> Result<Vec<String>, Error> {
        list_buckets_union(&self.index).await
    }

    async fn bucket_exists(&self, bucket: &str) -> Result<bool, Error> {
        self.index.bucket_exists(bucket).await
    }

    async fn create_bucket(&self, bucket: &str) -> Result<bool, Error> {
        let path_key = require_path_key(&self.mek)?;
        create_bucket_impl(&self.base_path, &self.index, &path_key, bucket).await
    }

    async fn delete_bucket(&self, bucket: &str) -> Result<u64, Error> {
        let path_key = require_path_key(&self.mek)?;
        delete_bucket_impl(&self.base_path, &self.index, &path_key, bucket).await
    }

    async fn get_bucket_config(&self, bucket: &str) -> Result<crate::BucketConfig, Error> {
        let path_key = require_path_key(&self.mek)?;
        get_bucket_config_impl(&self.base_path, &path_key, bucket).await
    }

    async fn set_bucket_config(
        &self,
        bucket: &str,
        config: &crate::BucketConfig,
    ) -> Result<(), Error> {
        let path_key = require_path_key(&self.mek)?;
        set_bucket_config_impl(&self.base_path, &path_key, bucket, config).await
    }

    async fn bucket_usage(&self, bucket: &str) -> Result<u64, Error> {
        bucket_usage_impl(&self.index, bucket).await
    }

    async fn list_objects(&self, bucket: &str, options: ListOptions) -> Result<ListPage, Error> {
        validate_bucket(bucket)?;
        let limit = options
            .limit
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_LIST_LIMIT)
            .min(MAX_LIST_LIMIT);
        self.index
            .scan_objects(
                bucket,
                options.prefix.as_deref(),
                options.after.as_deref(),
                limit,
            )
            .await
    }

    async fn search_objects(
        &self,
        query: &crate::LabelQuery,
        bucket: Option<&str>,
        options: ListOptions,
    ) -> Result<ListPage, Error> {
        if let Some(b) = bucket {
            validate_bucket(b)?;
        }
        let limit = options
            .limit
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_LIST_LIMIT)
            .min(MAX_LIST_LIMIT);
        self.index
            .search_labels(
                query,
                bucket,
                options.prefix.as_deref(),
                options.after.as_deref(),
                limit,
            )
            .await
    }
}

impl StorageExt for FilesystemStorage {
    async fn rebuild_cache(&self) -> Result<(), Error> {
        {
            let mut state = self.rebuild_state.lock().await;
            if matches!(*state, CacheRebuildStatus::Running(_)) {
                return Err(Error::RebuildAlreadyRunning);
            }
            *state = CacheRebuildStatus::Running(0);
        }

        let base_path = self.base_path.clone();
        let index = self.index.clone();
        let state = self.rebuild_state.clone();
        let mek = self.mek.mek();
        tokio::spawn(async move {
            let result = run_rebuild(base_path, index, state.clone(), mek).await;
            let mut s = state.lock().await;
            *s = match result {
                Ok(()) => CacheRebuildStatus::Completed,
                Err(msg) => {
                    tracing::error!(error = %msg, "cache rebuild failed");
                    CacheRebuildStatus::Failed(msg)
                }
            };
        });

        Ok(())
    }

    async fn rebuild_progress(&self) -> Result<CacheRebuildStatus, Error> {
        Ok(self.rebuild_state.lock().await.clone())
    }

    async fn list_stale_locks(&self, older_than: SystemTime) -> Result<Vec<StaleLock>, Error> {
        Ok(self.locks.list_stale(older_than))
    }

    async fn clear_stale_locks(&self, older_than: SystemTime) -> Result<u64, Error> {
        let locks = self.locks.clear_stale(older_than);
        // Fold in orphan `.tmp` GC: a hard crash mid-PUT leaves a staging file
        // the guard's Drop never ran on. Count it toward the swept total.
        let tmp = clear_orphan_tmp_files(&self.base_path, older_than)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "orphan tmp sweep failed; continuing");
                0
            });
        Ok(locks + tmp)
    }
}

/// Remove every orphan `*.tmp` staging file under `base_path/<bucket>/xx/yy/`
/// whose mtime is older than `cutoff`, returning the count removed.
///
/// Orphans are left only by a hard crash mid-write (the streaming guard's
/// [`Drop`] unlinks the tmp on any clean abort). An in-flight write's tmp has a
/// fresh mtime, so a sane `cutoff` never races an active PUT. Shared by the
/// filesystem and uring backends, which use the identical on-disk layout.
pub(crate) async fn clear_orphan_tmp_files(
    base_path: &Path,
    cutoff: SystemTime,
) -> std::io::Result<u64> {
    let mut removed = 0u64;
    let mut buckets = tokio::fs::read_dir(base_path).await?;
    while let Some(b) = buckets.next_entry().await? {
        if !b.file_type().await?.is_dir() {
            continue;
        }
        let mut l1 = tokio::fs::read_dir(b.path()).await?;
        while let Some(e1) = l1.next_entry().await? {
            if !e1.file_type().await?.is_dir() {
                continue;
            }
            let mut l2 = tokio::fs::read_dir(e1.path()).await?;
            while let Some(e2) = l2.next_entry().await? {
                if !e2.file_type().await?.is_dir() {
                    continue;
                }
                let mut files = tokio::fs::read_dir(e2.path()).await?;
                while let Some(f) = files.next_entry().await? {
                    let p = f.path();
                    if p.extension().is_none_or(|x| x != "tmp") {
                        continue;
                    }
                    let stale = matches!(
                        f.metadata().await.and_then(|m| m.modified()),
                        Ok(mtime) if mtime < cutoff
                    );
                    if stale && tokio::fs::remove_file(&p).await.is_ok() {
                        removed += 1;
                    }
                }
            }
        }
    }
    Ok(removed)
}

/// Walk every `.obj` file under `base_path/<bucket>/xx/yy/`, read the embedded
/// metadata, upsert it into `index`, then drop any index rows whose `.obj`
/// file is gone. Updates `state` with `Running(pct)` periodically.
async fn run_rebuild(
    base_path: PathBuf,
    index: Arc<MetadataIndex>,
    state: Arc<tokio::sync::Mutex<CacheRebuildStatus>>,
    mek: Option<[u8; 32]>,
) -> Result<(), String> {
    let obj_files = collect_obj_files(&base_path)
        .await
        .map_err(|e| format!("enumerate obj files: {e}"))?;
    let total = obj_files.len();

    let mut seen: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::with_capacity(total);
    let report_every = (total / 100).max(1);

    for (i, path) in obj_files.into_iter().enumerate() {
        match read_obj_metadata(&path, mek.as_ref()).await {
            Ok(meta) => {
                if let Err(e) = index.upsert(&meta, SyncLevel::Durable).await {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "rebuild: index upsert failed; continuing"
                    );
                }
                seen.insert((meta.bucket, meta.key));
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "rebuild: failed to read obj metadata; skipping"
                );
            }
        }
        if i % report_every == 0 && total > 0 {
            let pct = (((i + 1) * 100 / total) as u8).min(99);
            *state.lock().await = CacheRebuildStatus::Running(pct);
        }
    }

    let all_keys = index
        .list_all_keys()
        .await
        .map_err(|e| format!("list index keys: {e}"))?;
    let mut lost: u64 = 0;
    for (bucket, key) in all_keys {
        if !seen.contains(&(bucket.clone(), key.clone())) {
            lost += 1;
            tracing::error!(
                bucket = %bucket,
                key = %key,
                "data loss detected: object in index but not on disk; removing stale entry"
            );
            if let Err(e) = index.remove(&bucket, &key).await {
                tracing::warn!(
                    bucket = %bucket,
                    key = %key,
                    error = %e,
                    "rebuild: stale index row removal failed; continuing"
                );
            }
        }
    }
    if lost > 0 {
        tracing::error!(count = lost, "rebuild complete: {lost} object(s) lost");
    } else {
        tracing::info!("rebuild complete: no data loss detected");
    }

    Ok(())
}

/// Recursively gather every `*.obj` file under `base_path/<bucket_dir>/xx/yy/`.
///
/// Bucket directory names are opaque keyed HMACs, so they cannot be filtered by
/// name; every subdirectory is walked and only `*.obj` files are collected.
/// The true `(bucket, key)` for each record is read from its (encrypted)
/// embedded metadata by the caller, not inferred from the path.
async fn collect_obj_files(base_path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut buckets = tokio::fs::read_dir(base_path).await?;
    while let Some(b_entry) = buckets.next_entry().await? {
        if !b_entry.file_type().await?.is_dir() {
            continue;
        }
        let bucket_path = b_entry.path();
        let mut l1 = tokio::fs::read_dir(&bucket_path).await?;
        while let Some(l1_entry) = l1.next_entry().await? {
            if !l1_entry.file_type().await?.is_dir() {
                continue;
            }
            let mut l2 = tokio::fs::read_dir(l1_entry.path()).await?;
            while let Some(l2_entry) = l2.next_entry().await? {
                if !l2_entry.file_type().await?.is_dir() {
                    continue;
                }
                let mut files = tokio::fs::read_dir(l2_entry.path()).await?;
                while let Some(f) = files.next_entry().await? {
                    let p = f.path();
                    if p.extension().is_some_and(|e| e == "obj") {
                        out.push(p);
                    }
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Stand-in for the login-derived MEK; metadata writes require one.
    const TEST_MEK: [u8; 32] = [7u8; 32];

    /// The path key derived from [`TEST_MEK`] — used to recompute expected
    /// opaque on-disk names in tests.
    fn test_path_key() -> [u8; 32] {
        crate::crypto::derive_path_key(&TEST_MEK)
    }

    fn make_storage() -> (FilesystemStorage, TempDir) {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("data");
        let index = dir.path().join("index.redb");
        let storage = FilesystemStorage::new(base, index).unwrap();
        storage.install_mek(TEST_MEK);
        (storage, dir)
    }

    fn make_object(data: &[u8]) -> Object {
        Object::new(Bytes::copy_from_slice(data))
    }

    fn opts(labels: &[(&str, &str)]) -> PutOptions {
        let m: crate::LabelSet = labels
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        PutOptions {
            labels: m,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn clear_stale_locks_sweeps_orphan_tmp() {
        let (s, _dir) = make_storage();
        // Write a real object so the sharded directory tree exists.
        s.put("b", "k", make_object(b"data"), PutOptions::default())
            .await
            .unwrap();
        // Plant an orphan `.tmp` next to the committed `.obj`.
        let obj = s.key_path("b", "k").unwrap();
        let tmp = obj.with_extension("tmp");
        tokio::fs::write(&tmp, b"orphan").await.unwrap();
        assert!(tmp.exists());

        // A cutoff in the past leaves the just-created orphan in place.
        let past = SystemTime::now() - std::time::Duration::from_secs(3600);
        assert_eq!(s.clear_stale_locks(past).await.unwrap(), 0);
        assert!(tmp.exists(), "fresh tmp must survive an old cutoff");

        // A cutoff in the future treats it as stale and removes it.
        let future = SystemTime::now() + std::time::Duration::from_secs(3600);
        assert_eq!(s.clear_stale_locks(future).await.unwrap(), 1);
        assert!(!tmp.exists(), "stale orphan tmp must be swept");
    }

    #[tokio::test]
    async fn put_then_get_roundtrip() {
        let (s, _dir) = make_storage();
        s.put(
            "bucket1",
            "my-key",
            make_object(b"hello world"),
            PutOptions::default(),
        )
        .await
        .unwrap();
        let got = s.get("bucket1", "my-key").await.unwrap();
        assert_eq!(&got[..], b"hello world");
    }

    #[tokio::test]
    async fn on_disk_path_is_opaque_and_keyed() {
        let (s, dir) = make_storage();
        let path = s.key_path("photos", "vacation/cliff.jpg").unwrap();

        // Neither the bucket name nor the key appears anywhere in the path.
        let as_str = path.to_string_lossy();
        assert!(!as_str.contains("photos"), "bucket name leaked: {as_str}");
        assert!(!as_str.contains("vacation"), "key leaked: {as_str}");
        assert!(!as_str.contains("cliff"), "key leaked: {as_str}");

        // The bucket directory is a 64-char lowercase-hex HMAC, not the plaintext.
        let base = std::fs::canonicalize(dir.path().join("data")).unwrap();
        let bucket_dir = path
            .strip_prefix(&base)
            .unwrap()
            .components()
            .next()
            .unwrap()
            .as_os_str()
            .to_string_lossy()
            .into_owned();
        assert_eq!(bucket_dir.len(), 64);
        assert!(bucket_dir.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(bucket_dir, encode_bucket_dir(&test_path_key(), "photos"));
    }

    #[tokio::test]
    async fn on_disk_path_changes_with_a_different_mek() {
        let (s1, _d1) = make_storage();
        let p1 = s1.key_path("b", "k").unwrap();

        let dir = TempDir::new().unwrap();
        let s2 =
            FilesystemStorage::new(dir.path().join("data"), dir.path().join("i.redb")).unwrap();
        s2.install_mek([9u8; 32]);
        let p2 = s2.key_path("b", "k").unwrap();

        // Same (bucket, key) under a different deployment key yields a different
        // opaque path: the layout is keyed, not a public function of the key.
        assert_ne!(
            p1.file_name().unwrap(),
            p2.file_name().unwrap(),
            "object id must depend on the path key"
        );
    }

    #[tokio::test]
    async fn path_ops_error_without_an_installed_mek() {
        let dir = TempDir::new().unwrap();
        let s = FilesystemStorage::new(dir.path().join("data"), dir.path().join("i.redb")).unwrap();
        // No install_mek: the path key is unavailable, so path-building errors.
        assert!(s.key_path("b", "k").is_err());
    }

    #[tokio::test]
    async fn empty_created_bucket_lists_via_registry() {
        let (s, _dir) = make_storage();
        assert!(s.create_bucket("empty-one").await.unwrap());
        // No objects, but the explicitly-created bucket still lists.
        let buckets = s.list_buckets().await.unwrap();
        assert!(buckets.contains(&"empty-one".to_owned()));
        // Deleting it removes it from the listing.
        s.delete_bucket("empty-one").await.unwrap();
        let buckets = s.list_buckets().await.unwrap();
        assert!(!buckets.contains(&"empty-one".to_owned()));
    }

    #[tokio::test]
    async fn put_returns_overwrite_flag() {
        let (s, _dir) = make_storage();
        let first = s
            .put("bucket1", "k", make_object(b"v1"), PutOptions::default())
            .await
            .unwrap();
        let second = s
            .put("bucket1", "k", make_object(b"v2"), PutOptions::default())
            .await
            .unwrap();
        assert!(!first);
        assert!(second);
    }

    #[tokio::test]
    async fn describe_after_put() {
        let (s, _dir) = make_storage();
        let data = b"test payload";
        s.put("b", "k", make_object(data), PutOptions::default())
            .await
            .unwrap();
        let meta = s.describe("b", "k").await.unwrap();
        assert_eq!(meta.size, data.len() as u64);
        assert!(meta.created > 0);
        assert!(meta.modified >= meta.created);
        assert_eq!(meta.bucket, "b");
        assert_eq!(meta.key, "k");
        assert_eq!(meta.url_path, "b/k");
        assert!(meta.labels.is_empty());
        assert!(meta.disk_path.is_absolute());
        assert_eq!(meta.checksum_gxhash.len(), 12);
    }

    #[tokio::test]
    async fn overwrite_preserves_created() {
        let (s, _dir) = make_storage();
        s.put("b", "k", make_object(b"v1"), PutOptions::default())
            .await
            .unwrap();
        let meta1 = s.describe("b", "k").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        s.put("b", "k", make_object(b"v2"), PutOptions::default())
            .await
            .unwrap();
        let meta2 = s.describe("b", "k").await.unwrap();
        assert_eq!(meta1.created, meta2.created);
        assert!(meta2.modified >= meta2.created);
    }

    #[tokio::test]
    async fn delete_removes_obj_file() {
        let (s, _dir) = make_storage();
        s.put("b", "k", make_object(b"data"), PutOptions::default())
            .await
            .unwrap();
        s.delete("b", "k").await.unwrap();
        let err = s.get("b", "k").await.unwrap_err();
        assert!(matches!(err, crate::Error::NotFound { .. }));
        assert!(!s.key_path("b", "k").unwrap().exists());
    }

    #[tokio::test]
    async fn locked_object_returns_error() {
        let (s, _dir) = make_storage();
        s.put("b", "k", make_object(b"x"), PutOptions::default())
            .await
            .unwrap();
        let _guard = s
            .locks
            .try_acquire("b", "k")
            .expect("registry free after put");
        let err = s.get("b", "k").await.unwrap_err();
        assert!(matches!(err, crate::Error::Locked { .. }));
    }

    #[tokio::test]
    async fn get_range_returns_slice() {
        let (s, _dir) = make_storage();
        s.put("b", "k", make_object(b"abcdefgh"), PutOptions::default())
            .await
            .unwrap();
        let slice = s.get_range("b", "k", (2u64..=5u64).into()).await.unwrap();
        assert_eq!(&slice[..], b"cdef");
    }

    #[tokio::test]
    async fn invalid_bucket_error() {
        let (s, _dir) = make_storage();
        let err = s.get("bad/bucket", "k").await.unwrap_err();
        assert!(matches!(err, crate::Error::InvalidBucket { .. }));
        let err2 = s.get("../escape", "k").await.unwrap_err();
        assert!(matches!(err2, crate::Error::InvalidBucket { .. }));
    }

    #[tokio::test]
    async fn get_missing_key_returns_not_found() {
        let (s, _dir) = make_storage();
        let err = s.get("bucket", "no-such-key").await.unwrap_err();
        assert!(matches!(err, crate::Error::NotFound { .. }));
    }

    #[tokio::test]
    async fn put_with_labels_roundtrips_via_describe() {
        let (s, _dir) = make_storage();
        s.put(
            "b",
            "k",
            make_object(b"x"),
            opts(&[("env", "prod"), ("owner", "alice")]),
        )
        .await
        .unwrap();
        let meta = s.describe("b", "k").await.unwrap();
        assert!(meta.labels.contains(&("env".to_owned(), "prod".to_owned())));
        assert!(
            meta.labels
                .contains(&("owner".to_owned(), "alice".to_owned()))
        );
    }

    #[tokio::test]
    async fn index_lookup_by_label() {
        let (s, _dir) = make_storage();
        s.put("b", "k1", make_object(b"a"), opts(&[("env", "prod")]))
            .await
            .unwrap();
        s.put("b", "k2", make_object(b"b"), opts(&[("env", "prod")]))
            .await
            .unwrap();
        s.put("b", "k3", make_object(b"c"), opts(&[("env", "dev")]))
            .await
            .unwrap();
        let mut prods = s.index().lookup_by_label("env", "prod").await.unwrap();
        prods.sort();
        assert_eq!(
            prods,
            vec![
                ("b".to_owned(), "k1".to_owned()),
                ("b".to_owned(), "k2".to_owned()),
            ]
        );
        let devs = s.index().lookup_by_label("env", "dev").await.unwrap();
        assert_eq!(devs, vec![("b".to_owned(), "k3".to_owned())]);
    }

    #[tokio::test]
    async fn search_objects_by_label_query() {
        let (s, _dir) = make_storage();
        s.put(
            "b1",
            "web-1",
            make_object(b"a"),
            opts(&[("env", "prod"), ("tier", "web")]),
        )
        .await
        .unwrap();
        s.put(
            "b1",
            "db-1",
            make_object(b"b"),
            opts(&[("env", "prod"), ("tier", "db")]),
        )
        .await
        .unwrap();
        s.put(
            "b2",
            "web-2",
            make_object(b"c"),
            opts(&[("env", "dev"), ("tier", "web")]),
        )
        .await
        .unwrap();

        let hits = |page: ListPage| {
            let mut v: Vec<(String, String)> =
                page.items.into_iter().map(|m| (m.bucket, m.key)).collect();
            v.sort();
            v
        };

        // Cross-bucket conjunction.
        let q = crate::LabelQuery::parse("env == prod and tier == web").unwrap();
        let page = s
            .search_objects(&q, None, ListOptions::default())
            .await
            .unwrap();
        assert_eq!(hits(page), vec![("b1".to_owned(), "web-1".to_owned())]);

        // Disjunction with prefix + regex, all buckets.
        let q = crate::LabelQuery::parse(r#"tier ^= web or env =~ "de.*""#).unwrap();
        let page = s
            .search_objects(&q, None, ListOptions::default())
            .await
            .unwrap();
        assert_eq!(
            hits(page),
            vec![
                ("b1".to_owned(), "web-1".to_owned()),
                ("b2".to_owned(), "web-2".to_owned()),
            ]
        );

        // Bucket-scoped: same query, only b1.
        let page = s
            .search_objects(&q, Some("b1"), ListOptions::default())
            .await
            .unwrap();
        assert_eq!(hits(page), vec![("b1".to_owned(), "web-1".to_owned())]);

        // Inequality matches the absent-label and differing-value rows.
        let q = crate::LabelQuery::parse("tier != web").unwrap();
        let page = s
            .search_objects(&q, None, ListOptions::default())
            .await
            .unwrap();
        assert_eq!(hits(page), vec![("b1".to_owned(), "db-1".to_owned())]);
    }

    #[tokio::test]
    async fn overwrite_replaces_labels() {
        let (s, _dir) = make_storage();
        s.put("b", "k", make_object(b"v1"), opts(&[("env", "prod")]))
            .await
            .unwrap();
        s.put("b", "k", make_object(b"v2"), opts(&[("env", "dev")]))
            .await
            .unwrap();
        let prods = s.index().lookup_by_label("env", "prod").await.unwrap();
        assert!(prods.is_empty(), "old label should be removed on overwrite");
        let devs = s.index().lookup_by_label("env", "dev").await.unwrap();
        assert_eq!(devs, vec![("b".to_owned(), "k".to_owned())]);
    }

    #[tokio::test]
    async fn index_cleared_on_delete() {
        let (s, _dir) = make_storage();
        s.put("b", "k", make_object(b"v"), opts(&[("env", "prod")]))
            .await
            .unwrap();
        s.delete("b", "k").await.unwrap();
        let hits = s.index().lookup_by_label("env", "prod").await.unwrap();
        assert!(hits.is_empty());
        let row = s.index().lookup_by_key("b", "k").await.unwrap();
        assert!(row.is_none());
    }

    #[tokio::test]
    async fn index_survives_reopen() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("data");
        let index = dir.path().join("index.redb");
        {
            let s = FilesystemStorage::new(&base, &index).unwrap();
            s.install_mek(TEST_MEK);
            s.put("b", "k", make_object(b"v"), opts(&[("env", "prod")]))
                .await
                .unwrap();
        }
        let s2 = FilesystemStorage::new(&base, &index).unwrap();
        s2.install_mek(TEST_MEK);
        let hits = s2.index().lookup_by_label("env", "prod").await.unwrap();
        assert_eq!(hits, vec![("b".to_owned(), "k".to_owned())]);
    }

    #[tokio::test]
    async fn list_buckets_empty() {
        let (s, _dir) = make_storage();
        let buckets = s.list_buckets().await.unwrap();
        assert!(buckets.is_empty());
    }

    #[tokio::test]
    async fn list_buckets_returns_sorted_unique() {
        let (s, _dir) = make_storage();
        s.put("zeta", "a", make_object(b"x"), PutOptions::default())
            .await
            .unwrap();
        s.put("alpha", "a", make_object(b"x"), PutOptions::default())
            .await
            .unwrap();
        s.put("alpha", "b", make_object(b"x"), PutOptions::default())
            .await
            .unwrap();
        s.put("mid", "a", make_object(b"x"), PutOptions::default())
            .await
            .unwrap();
        let buckets = s.list_buckets().await.unwrap();
        assert_eq!(buckets, vec!["alpha", "mid", "zeta"]);
    }

    #[tokio::test]
    async fn create_bucket_persists_empty_bucket_in_listing() {
        let (s, _dir) = make_storage();
        let created = s.create_bucket("empty").await.unwrap();
        assert!(created);
        // Empty bucket has no objects but must still appear via the dir union.
        let buckets = s.list_buckets().await.unwrap();
        assert_eq!(buckets, vec!["empty"]);
        // Idempotent: second create reports already-existed.
        assert!(!s.create_bucket("empty").await.unwrap());
    }

    #[tokio::test]
    async fn create_bucket_rejects_invalid_name() {
        let (s, _dir) = make_storage();
        assert!(s.create_bucket("bad/name").await.is_err());
        assert!(s.create_bucket("api").await.is_err());
    }

    #[tokio::test]
    async fn delete_bucket_removes_objects_and_dir() {
        let (s, _dir) = make_storage();
        s.put("doomed", "a", make_object(b"x"), PutOptions::default())
            .await
            .unwrap();
        s.put(
            "doomed",
            "nested/b",
            make_object(b"y"),
            PutOptions::default(),
        )
        .await
        .unwrap();
        s.put("keep", "a", make_object(b"z"), PutOptions::default())
            .await
            .unwrap();

        let removed = s.delete_bucket("doomed").await.unwrap();
        assert_eq!(removed, 2);

        let buckets = s.list_buckets().await.unwrap();
        assert_eq!(buckets, vec!["keep"]);
        assert!(s.get("doomed", "a").await.is_err());
    }

    #[tokio::test]
    async fn delete_bucket_missing_is_not_found() {
        let (s, _dir) = make_storage();
        assert!(s.delete_bucket("ghost").await.is_err());
    }

    #[tokio::test]
    async fn set_labels_replaces_labels_and_preserves_data() {
        let (s, _dir) = make_storage();
        s.put(
            "b",
            "k",
            make_object(b"hello world"),
            opts(&[("env", "prod")]),
        )
        .await
        .unwrap();

        let new_labels: crate::LabelSet = [
            ("env".to_owned(), "staging".to_owned()),
            ("team".to_owned(), "core".to_owned()),
        ]
        .into_iter()
        .collect();
        s.set_labels("b", "k", new_labels.clone()).await.unwrap();

        // Data unchanged.
        let obj = s.get("b", "k").await.unwrap();
        assert_eq!(&obj.into_inner()[..], b"hello world");
        // Labels replaced.
        let meta = s.describe("b", "k").await.unwrap();
        assert_eq!(meta.labels, new_labels);
        // Reverse label index reflects the change.
        let hits = s.index().lookup_by_label("team", "core").await.unwrap();
        assert_eq!(hits, vec![("b".to_owned(), "k".to_owned())]);
        assert!(
            s.index()
                .lookup_by_label("env", "prod")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn bucket_config_round_trips_and_defaults_empty() {
        let (s, _dir) = make_storage();
        // Absent sidecar → default config.
        let cfg = s.get_bucket_config("b").await.unwrap();
        assert_eq!(cfg, crate::BucketConfig::default());

        let want = crate::BucketConfig {
            quota_bytes: Some(4096),
            default_sse: Some("aes256-gcm".to_owned()),
            cors_allow_origin: None,
            ..Default::default()
        };
        s.set_bucket_config("b", &want).await.unwrap();
        assert_eq!(s.get_bucket_config("b").await.unwrap(), want);
    }

    #[tokio::test]
    async fn bucket_usage_sums_object_sizes() {
        let (s, _dir) = make_storage();
        s.put("b", "a", make_object(b"12345"), PutOptions::default())
            .await
            .unwrap();
        s.put("b", "c", make_object(b"678"), PutOptions::default())
            .await
            .unwrap();
        assert_eq!(s.bucket_usage("b").await.unwrap(), 8);
        assert_eq!(s.bucket_usage("empty").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn set_labels_missing_object_is_not_found() {
        let (s, _dir) = make_storage();
        assert!(
            s.set_labels("b", "ghost", crate::LabelSet::new())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn list_objects_empty_bucket() {
        let (s, _dir) = make_storage();
        let page = s
            .list_objects("nobody", ListOptions::default())
            .await
            .unwrap();
        assert!(page.items.is_empty());
        assert!(page.next.is_none());
    }

    #[tokio::test]
    async fn list_objects_sorted_by_string_key_not_encoded_order() {
        let (s, _dir) = make_storage();
        for k in &["abz", "abcd", "aa"] {
            s.put("b", k, make_object(b"x"), PutOptions::default())
                .await
                .unwrap();
        }
        let page = s.list_objects("b", ListOptions::default()).await.unwrap();
        let keys: Vec<_> = page.items.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(keys, vec!["aa", "abcd", "abz"]);
        assert!(page.next.is_none());
    }

    #[tokio::test]
    async fn list_objects_prefix_filter() {
        let (s, _dir) = make_storage();
        for k in &["foo/a", "foo/b", "bar/a"] {
            s.put("b", k, make_object(b"x"), PutOptions::default())
                .await
                .unwrap();
        }
        let page = s
            .list_objects(
                "b",
                ListOptions {
                    prefix: Some("foo/".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let keys: Vec<_> = page.items.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(keys, vec!["foo/a", "foo/b"]);
    }

    #[tokio::test]
    async fn list_objects_pagination_with_cursor() {
        let (s, _dir) = make_storage();
        for k in &["a", "b", "c", "d"] {
            s.put("b", k, make_object(b"x"), PutOptions::default())
                .await
                .unwrap();
        }
        let p1 = s
            .list_objects(
                "b",
                ListOptions {
                    limit: Some(2),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let keys1: Vec<_> = p1.items.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(keys1, vec!["a", "b"]);
        assert_eq!(p1.next.as_deref(), Some("b"));

        let p2 = s
            .list_objects(
                "b",
                ListOptions {
                    after: p1.next,
                    limit: Some(2),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let keys2: Vec<_> = p2.items.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(keys2, vec!["c", "d"]);
        assert!(p2.next.is_none(), "final page should not signal more");
    }

    #[tokio::test]
    async fn list_objects_does_not_leak_other_buckets() {
        let (s, _dir) = make_storage();
        s.put("b1", "a", make_object(b"x"), PutOptions::default())
            .await
            .unwrap();
        s.put("b2", "a", make_object(b"y"), PutOptions::default())
            .await
            .unwrap();
        let page = s.list_objects("b1", ListOptions::default()).await.unwrap();
        let keys: Vec<_> = page.items.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(keys, vec!["a"]);
        assert_eq!(page.items[0].bucket, "b1");
    }

    #[tokio::test]
    async fn list_objects_invalid_bucket() {
        let (s, _dir) = make_storage();
        let err = s
            .list_objects("bad/bucket", ListOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, crate::Error::InvalidBucket { .. }));
    }

    async fn wait_until_done(s: &FilesystemStorage) -> CacheRebuildStatus {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let st = s.rebuild_progress().await.unwrap();
                if matches!(
                    st,
                    CacheRebuildStatus::Completed | CacheRebuildStatus::Failed(_)
                ) {
                    return st;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("rebuild did not finish in time")
    }

    #[tokio::test]
    async fn rebuild_repopulates_empty_index() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("data");
        let index_a = dir.path().join("index_a.redb");
        let index_b = dir.path().join("index_b.redb");

        {
            let s = FilesystemStorage::new(&base, &index_a).unwrap();
            s.install_mek(TEST_MEK);
            s.put("b1", "k1", make_object(b"v1"), opts(&[("env", "prod")]))
                .await
                .unwrap();
            s.put("b1", "k2", make_object(b"v2"), opts(&[("env", "dev")]))
                .await
                .unwrap();
            s.put("b2", "x", make_object(b"x"), PutOptions::default())
                .await
                .unwrap();
        }

        let s2 = FilesystemStorage::new(&base, &index_b).unwrap();
        s2.install_mek(TEST_MEK);
        // The fresh index is empty; the label index proves it. list_buckets now
        // unions on-disk bucket directories, so it already reflects b1/b2 here
        // even before the rebuild repopulates the object/label index.
        assert!(
            s2.index()
                .lookup_by_label("env", "prod")
                .await
                .unwrap()
                .is_empty()
        );

        s2.rebuild_cache().await.unwrap();
        let status = wait_until_done(&s2).await;
        assert!(matches!(status, CacheRebuildStatus::Completed));

        let mut buckets = s2.list_buckets().await.unwrap();
        buckets.sort();
        assert_eq!(buckets, vec!["b1".to_owned(), "b2".to_owned()]);
        assert_eq!(
            s2.index().lookup_by_label("env", "prod").await.unwrap(),
            vec![("b1".to_owned(), "k1".to_owned())]
        );
    }

    #[tokio::test]
    async fn rebuild_drops_stale_entries() {
        let (s, _dir) = make_storage();
        s.put("b", "alive", make_object(b"a"), PutOptions::default())
            .await
            .unwrap();
        s.put("b", "ghost", make_object(b"g"), PutOptions::default())
            .await
            .unwrap();

        // Remove the ghost's .obj file but leave its index entry.
        tokio::fs::remove_file(s.key_path("b", "ghost").unwrap())
            .await
            .unwrap();

        assert!(
            s.index()
                .lookup_by_key("b", "ghost")
                .await
                .unwrap()
                .is_some()
        );

        s.rebuild_cache().await.unwrap();
        let status = wait_until_done(&s).await;
        assert!(matches!(status, CacheRebuildStatus::Completed));

        assert!(
            s.index()
                .lookup_by_key("b", "ghost")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            s.index()
                .lookup_by_key("b", "alive")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn rebuild_progress_reaches_completed() {
        let (s, _dir) = make_storage();
        for i in 0..10 {
            s.put(
                "b",
                &format!("k{i}"),
                make_object(b"v"),
                PutOptions::default(),
            )
            .await
            .unwrap();
        }
        assert!(matches!(
            s.rebuild_progress().await.unwrap(),
            CacheRebuildStatus::Idle
        ));
        s.rebuild_cache().await.unwrap();
        let status = wait_until_done(&s).await;
        assert!(matches!(status, CacheRebuildStatus::Completed));
    }

    #[tokio::test]
    async fn rebuild_rejects_concurrent_calls() {
        let (s, _dir) = make_storage();
        for i in 0..200 {
            s.put(
                "b",
                &format!("k{i}"),
                make_object(b"v"),
                PutOptions::default(),
            )
            .await
            .unwrap();
        }
        s.rebuild_cache().await.unwrap();
        let err = s.rebuild_cache().await.unwrap_err();
        assert!(matches!(err, crate::Error::RebuildAlreadyRunning));
        let _ = wait_until_done(&s).await;
    }

    /// Verify that the on-disk file uses the shared `.obj` format by inspecting
    /// the header magic and data_offset directly.
    #[tokio::test]
    async fn put_writes_obj_format_with_correct_header() {
        use crate::storage::format::{HEADER_SIZE, Header, MAGIC};

        let (s, _dir) = make_storage();
        let body = b"hello obj";
        s.put("b", "k", make_object(body), PutOptions::default())
            .await
            .unwrap();

        let obj_path = s.key_path("b", "k").unwrap();
        assert_eq!(obj_path.extension().and_then(|e| e.to_str()), Some("obj"));

        let bytes = std::fs::read(&obj_path).unwrap();
        assert!(bytes.len() >= HEADER_SIZE);
        assert_eq!(&bytes[..4], &MAGIC);

        let header_arr: [u8; HEADER_SIZE] = bytes[..HEADER_SIZE].try_into().unwrap();
        let header = Header::decode(&header_arr).unwrap();
        assert_eq!(header.data_len, body.len() as u64);
        assert_eq!(header.data_offset, Header::MIN_DATA_OFFSET);
        assert_eq!(
            &bytes[header.data_offset as usize..header.data_offset as usize + body.len()],
            body
        );
    }

    fn plaintext_metrics(size: u64) -> crate::PlaintextMetrics {
        crate::PlaintextMetrics {
            size,
            checksum_gxhash_b64: "AAAAAAAAAAA=".to_owned(),
        }
    }

    fn cipher_metadata(cipher_size: u64) -> crate::CipherMetadata {
        crate::CipherMetadata {
            cipher_size,
            cipher_checksum_b64: "x".to_owned(),
            kem_alg: "ml-kem-768".to_owned(),
            aead_alg: "aes-256-gcm".to_owned(),
            envelope_version: 1,
        }
    }

    #[tokio::test]
    async fn streaming_put_then_get_and_overwrite() {
        use tokio::io::AsyncWriteExt;
        let (s, _dir) = make_storage();

        let (guard, mut file) = s.begin_streaming_put("sb", "sk").await.unwrap();
        let body = b"ciphertext-ish bytes";
        file.write_all(body).await.unwrap();
        let overwrite = guard
            .commit(
                file,
                PutOptions {
                    sync: SyncLevel::Durable,
                    ..Default::default()
                },
                plaintext_metrics(body.len() as u64),
                cipher_metadata(body.len() as u64),
            )
            .await
            .unwrap();
        assert!(!overwrite);

        let got = s.get("sb", "sk").await.unwrap();
        assert_eq!(&got[..], body);
        let meta = s.describe("sb", "sk").await.unwrap();
        assert_eq!(meta.size, body.len() as u64);
        assert_eq!(meta.kem_alg.as_deref(), Some("ml-kem-768"));
        assert_eq!(meta.aead_alg.as_deref(), Some("aes-256-gcm"));

        // Second streaming PUT to the same key reports an overwrite.
        let (guard2, mut f2) = s.begin_streaming_put("sb", "sk").await.unwrap();
        f2.write_all(b"new").await.unwrap();
        let ow = guard2
            .commit(
                f2,
                PutOptions::default(),
                plaintext_metrics(3),
                cipher_metadata(3),
            )
            .await
            .unwrap();
        assert!(ow);
        assert_eq!(&s.get("sb", "sk").await.unwrap()[..], b"new");
    }

    #[tokio::test]
    async fn streaming_put_guard_drop_cleans_tmp() {
        let (s, _dir) = make_storage();
        let (guard, _file) = s.begin_streaming_put("b", "k").await.unwrap();
        drop(guard); // no commit -> tmp removed, lock released
        // The key must not exist and a fresh streaming put must succeed.
        assert!(s.get("b", "k").await.is_err());
        let (g2, _f2) = s.begin_streaming_put("b", "k").await.unwrap();
        drop(g2);
    }

    #[tokio::test]
    async fn durable_put_and_range_edges() {
        let (s, _dir) = make_storage();
        s.put(
            "b",
            "k",
            make_object(b"0123456789"),
            PutOptions {
                sync: SyncLevel::Durable,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            &s.get_range("b", "k", (0u64..=0u64).into()).await.unwrap()[..],
            b"0"
        );
        assert_eq!(
            &s.get_range("b", "k", (3u64..=6u64).into()).await.unwrap()[..],
            b"3456"
        );
        assert_eq!(
            &s.get_range("b", "k", (7u64..=9u64).into()).await.unwrap()[..],
            b"789"
        );
    }

    #[tokio::test]
    async fn delete_missing_key_errors() {
        let (s, _dir) = make_storage();
        let err = s.delete("b", "absent").await.unwrap_err();
        assert!(matches!(err, crate::Error::NotFound { .. }));
    }
}
