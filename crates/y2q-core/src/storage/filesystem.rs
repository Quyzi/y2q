use core::range::RangeInclusive;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use bytes::Bytes;
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;

use crate::{
    CacheRebuildStatus, CipherMetadata, DEFAULT_LIST_LIMIT, Error, ListOptions, ListPage, Listing,
    MAX_LIST_LIMIT, Metadata, MetadataIndex, Object, PlaintextMetrics, PutOptions, StaleLock,
    Storage, StorageExt, SyncLevel,
    crypto::{decrypt_meta, encrypt_meta},
    storage::{
        format::{self, HEADER_SIZE, Header},
        locks::{clear_stale_locks_under, list_stale_locks_under},
    },
};

/// UUID v5 namespace used to derive deterministic filenames from object keys.
///
/// This is the RFC 4122 URL namespace (`6ba7b811-9dad-11d1-80b4-00c04fd430c8`),
/// chosen as a stable, well-known constant so the same key always maps to the
/// same filename regardless of which process or host computes it.
const Y2Q_NAMESPACE: Uuid = Uuid::from_bytes([
    0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
]);

/// A [`Storage`] backend that persists objects on a local filesystem.
///
/// Objects are stored in a two-level hex-sharded directory tree rooted at
/// `base_path`:
///
/// ```text
/// <base_path>/<bucket>/<xx>/<yy>/<uuid>.obj    — single-file object record
/// <base_path>/<bucket>/<xx>/<yy>/<uuid>.lock   — ephemeral write-lock file
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
    mek: Option<[u8; 32]>,
    dirty_tx: Option<flume::Sender<crate::DirtyEntry>>,
    flush_notify: Option<Arc<tokio::sync::Notify>>,
    flush_limit: usize,
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
        let index = MetadataIndex::open(index_path)?;
        Ok(Self {
            base_path,
            index: Arc::new(index),
            rebuild_state: Arc::new(tokio::sync::Mutex::new(CacheRebuildStatus::Idle)),
            mek: None,
            dirty_tx: None,
            flush_notify: None,
            flush_limit: 0,
        })
    }

    /// Access the underlying metadata index, e.g. for `lookup_by_label`.
    pub fn index(&self) -> &MetadataIndex {
        &self.index
    }

    /// Set the Metadata Encryption Key. All subsequent metadata writes will be
    /// encrypted; reads transparently decrypt or pass through legacy plaintext.
    /// Also enables encrypted key blinding on the metadata index.
    pub fn with_mek(mut self, mek: [u8; 32]) -> Self {
        self.index.set_mek(mek);
        self.mek = Some(mek);
        self
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
    /// `(bucket, key)`: `<base>/<bucket>/<xx>/<yy>/<uuid>.obj`.
    ///
    /// Matches the path scheme used by [`crate::UringStorage`] so both
    /// backends can read each other's files when sharing a `base_path`.
    pub fn key_path(&self, bucket: &str, key: &str) -> PathBuf {
        let id = Uuid::new_v5(&Y2Q_NAMESPACE, key.as_bytes());
        let s = id.hyphenated().to_string();
        let mut p = self
            .base_path
            .join(bucket)
            .join(&s[0..2])
            .join(&s[2..4])
            .join(&s);
        p.set_extension("obj");
        p
    }
}

/// Reserved bucket names that conflict with the `/api/v1/*` admin namespace.
const RESERVED_BUCKETS: &[&str] = &["api"];

fn validate_bucket(bucket: &str) -> Result<(), Error> {
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

fn validate_key(key: &str) -> Result<(), Error> {
    const MAX_KEY_LEN: usize = 1024;
    if key.is_empty() || key.contains('\0') || key.len() > MAX_KEY_LEN {
        return Err(Error::InvalidKey {
            key: key.to_owned(),
        });
    }
    Ok(())
}

fn compute_checksums(data: &[u8]) -> (String, String) {
    let md5_digest = md5::Md5::digest(data);
    let sha256_digest = sha2::Sha256::digest(data);
    let engine = base64::engine::general_purpose::STANDARD;
    (engine.encode(md5_digest), engine.encode(sha256_digest))
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

/// RAII guard that holds a write lock on an object for the duration of a
/// [`Storage::put`] operation.
///
/// The lock is a `.lock` sidecar file created with `O_EXCL`. The file
/// contains the lock acquisition time as a little-endian `u64` of nanoseconds
/// since the Unix epoch so callers can report how long the lock has been held.
///
/// The lock file is removed synchronously in [`Drop`] so it is always cleaned
/// up even if the future holding the guard is cancelled.
struct LockGuard {
    path: PathBuf,
}

impl LockGuard {
    async fn acquire(path: PathBuf, bucket: &str, key: &str) -> Result<Self, Error> {
        let result = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await;

        match result {
            Ok(mut f) => {
                f.write_all(&now_nanos().to_le_bytes()).await.ok();
                Ok(LockGuard { path })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let since = read_lock_timestamp(&path).await;
                Err(Error::Locked {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    since,
                })
            }
            Err(e) => Err(Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "lock".to_owned(),
                message: e.to_string(),
            }),
        }
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn read_lock_timestamp(path: &Path) -> SystemTime {
    if let Ok(bytes) = tokio::fs::read(path).await
        && bytes.len() >= 8
    {
        let nanos = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        return UNIX_EPOCH + std::time::Duration::from_nanos(nanos);
    }
    SystemTime::now()
}

async fn check_not_locked(lock_path: &Path, bucket: &str, key: &str) -> Result<(), Error> {
    if tokio::fs::try_exists(lock_path).await.unwrap_or(false) {
        let since = read_lock_timestamp(lock_path).await;
        return Err(Error::Locked {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            since,
        });
    }
    Ok(())
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
        decrypt_meta(mek, &meta_buf)
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
    _lock: LockGuard,
    bucket: String,
    key: String,
    is_overwrite: bool,
    prior_created: Option<u64>,
    index: Arc<MetadataIndex>,
    mek: Option<[u8; 32]>,
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
            checksum_md5: plaintext_metrics.checksum_md5_b64,
            checksum_sha256: plaintext_metrics.checksum_sha256_b64,
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            disk_path: self.obj_path.clone(),
            url_path: format!("{bucket}/{key}"),
            labels: options.labels,
            cipher_size: Some(cipher_size),
            cipher_sha256: Some(cipher_metadata.cipher_sha256_b64),
            kem_alg: Some(cipher_metadata.kem_alg),
            aead_alg: Some(cipher_metadata.aead_alg),
            envelope_version: Some(cipher_metadata.envelope_version),
        };

        let meta_json = serde_json::to_vec(&metadata).map_err(|e| Error::InternalError {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            operation: "put".to_owned(),
            message: format!("encode meta: {e}"),
        })?;
        let meta_bytes = if let Some(ref mek) = self.mek {
            encrypt_meta(mek, &meta_json).map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "put".to_owned(),
                message: format!("encrypt meta: {e}"),
            })?
        } else {
            meta_json
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
        } else if let Some(ref tx) = self.dirty_tx {
            if let Some(parent_dir) = self.obj_path.parent().map(PathBuf::from) {
                let entry = crate::DirtyEntry {
                    obj_path: self.obj_path.clone(),
                    parent_dir,
                };
                let _ = tx.send(entry);
                if tx.len() >= self.flush_limit {
                    if let Some(ref notify) = self.flush_notify {
                        notify.notify_one();
                    }
                }
            }
        }

        if let Err(e) = self.index.upsert(&metadata).await {
            tracing::warn!(
                bucket = bucket,
                key = key,
                error = %e,
                "metadata index upsert failed; on-disk record is authoritative"
            );
        }

        Ok(self.is_overwrite)
    }
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

        let obj_path = self.key_path(bucket, key);
        let tmp_path = obj_path.with_extension("tmp");
        let lock_path = obj_path.with_extension("lock");

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
                let created = read_obj_created(&obj_path, self.mek.as_ref()).await;
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

        let lock = LockGuard::acquire(lock_path, bucket, key).await?;

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
            mek: self.mek,
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

            let obj_path = self.key_path(bucket, key);
            check_not_locked(&obj_path.with_extension("lock"), bucket, key).await?;

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

        let obj_path = self.key_path(bucket, key);
        check_not_locked(&obj_path.with_extension("lock"), bucket, key).await?;

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

            let obj_path = self.key_path(bucket, key);
            let tmp_path = obj_path.with_extension("tmp");
            let lock_path = obj_path.with_extension("lock");

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

            let _lock = LockGuard::acquire(lock_path, bucket, key).await?;

            let (is_overwrite, prior_created) = match tokio::fs::metadata(&obj_path).await {
                Ok(_) => {
                    let created = read_obj_created(&obj_path, self.mek.as_ref()).await;
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

            let (size, checksum_md5, checksum_sha256) = match &options.plaintext_metrics {
                Some(p) => (
                    p.size,
                    p.checksum_md5_b64.clone(),
                    p.checksum_sha256_b64.clone(),
                ),
                None => {
                    let (md5, sha) = compute_checksums(data);
                    (data.len() as u64, md5, sha)
                }
            };
            let (cipher_size, cipher_sha256, kem_alg, aead_alg, envelope_version) =
                match &options.cipher_metadata {
                    Some(c) => (
                        Some(c.cipher_size),
                        Some(c.cipher_sha256_b64.clone()),
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
                checksum_md5,
                checksum_sha256,
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                disk_path: obj_path.clone(),
                url_path: format!("{bucket}/{key}"),
                labels: options.labels,
                cipher_size,
                cipher_sha256,
                kem_alg,
                aead_alg,
                envelope_version,
            };

            let meta_json = serde_json::to_vec(&metadata).map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "put".to_owned(),
                message: e.to_string(),
            })?;
            let meta_bytes = if let Some(mek) = &self.mek {
                encrypt_meta(mek, &meta_json).map_err(|e| Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "put".to_owned(),
                    message: e.to_string(),
                })?
            } else {
                meta_json
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
            } else if let Some(ref tx) = self.dirty_tx {
                if let Some(parent_dir) = obj_path.parent().map(PathBuf::from) {
                    let entry = crate::DirtyEntry {
                        obj_path: obj_path.clone(),
                        parent_dir,
                    };
                    let _ = tx.send(entry);
                    if tx.len() >= self.flush_limit {
                        if let Some(ref notify) = self.flush_notify {
                            notify.notify_one();
                        }
                    }
                }
            }

            if let Err(e) = self.index.upsert(&metadata).await {
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

            let obj_path = self.key_path(bucket, key);
            check_not_locked(&obj_path.with_extension("lock"), bucket, key).await?;

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

    async fn describe(&self, bucket: &str, key: &str) -> Result<Metadata, Error> {
        let started = Instant::now();
        let result = async {
            validate_bucket(bucket)?;
            validate_key(key)?;

            let obj_path = self.key_path(bucket, key);
            check_not_locked(&obj_path.with_extension("lock"), bucket, key).await?;

            if !tokio::fs::try_exists(&obj_path).await.unwrap_or(false) {
                return Err(Error::NotFound {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                });
            }

            read_obj_metadata(&obj_path, self.mek.as_ref())
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
        self.index.list_buckets().await
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
        let mek = self.mek;
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
        list_stale_locks_under(&self.base_path, older_than)
            .await
            .map_err(|e| Error::InternalError {
                bucket: String::new(),
                key: String::new(),
                operation: "list_stale_locks".to_owned(),
                message: e.to_string(),
            })
    }

    async fn clear_stale_locks(&self, older_than: SystemTime) -> Result<u64, Error> {
        clear_stale_locks_under(&self.base_path, older_than)
            .await
            .map_err(|e| Error::InternalError {
                bucket: String::new(),
                key: String::new(),
                operation: "clear_stale_locks".to_owned(),
                message: e.to_string(),
            })
    }
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
                if let Err(e) = index.upsert(&meta).await {
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

/// Recursively gather every `*.obj` file under `base_path/<bucket>/xx/yy/`.
///
/// Bucket directories whose name fails [`validate_bucket`] are skipped, which
/// excludes reserved entries like `_y2q_index.redb`.
async fn collect_obj_files(base_path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut buckets = tokio::fs::read_dir(base_path).await?;
    while let Some(b_entry) = buckets.next_entry().await? {
        if !b_entry.file_type().await?.is_dir() {
            continue;
        }
        let bucket_name = match b_entry.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue,
        };
        if validate_bucket(&bucket_name).is_err() {
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
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    fn make_storage() -> (FilesystemStorage, TempDir) {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("data");
        let index = dir.path().join("index.redb");
        let storage = FilesystemStorage::new(base, index).unwrap();
        (storage, dir)
    }

    fn make_object(data: &[u8]) -> Object {
        Object::new(Bytes::copy_from_slice(data))
    }

    fn opts(labels: &[(&str, &str)]) -> PutOptions {
        let mut m = BTreeMap::new();
        for (k, v) in labels {
            m.insert((*k).to_owned(), (*v).to_owned());
        }
        PutOptions {
            labels: m,
            ..Default::default()
        }
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
        assert_eq!(meta.checksum_md5.len(), 24);
        assert_eq!(meta.checksum_sha256.len(), 44);
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
        assert!(!s.key_path("b", "k").exists());
    }

    #[tokio::test]
    async fn locked_object_returns_error() {
        let (s, _dir) = make_storage();
        s.put("b", "k", make_object(b"x"), PutOptions::default())
            .await
            .unwrap();
        let lock_path = s.key_path("b", "k").with_extension("lock");
        tokio::fs::write(&lock_path, 1_000_000_000u64.to_le_bytes())
            .await
            .unwrap();
        let err = s.get("b", "k").await.unwrap_err();
        assert!(matches!(err, crate::Error::Locked { .. }));
        tokio::fs::remove_file(&lock_path).await.unwrap();
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
        assert_eq!(meta.labels.get("env").map(String::as_str), Some("prod"));
        assert_eq!(meta.labels.get("owner").map(String::as_str), Some("alice"));
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
            s.put("b", "k", make_object(b"v"), opts(&[("env", "prod")]))
                .await
                .unwrap();
        }
        let s2 = FilesystemStorage::new(&base, &index).unwrap();
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
        assert!(s2.list_buckets().await.unwrap().is_empty());
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
        tokio::fs::remove_file(s.key_path("b", "ghost"))
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

        let obj_path = s.key_path("b", "k");
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
}
