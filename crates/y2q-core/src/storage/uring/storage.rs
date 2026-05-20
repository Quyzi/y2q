//! The `UringStorage` backend struct and its trait implementations.
//!
//! The trait methods themselves are thin: they validate inputs, compute the
//! object's on-disk paths, build a typed [`UringOp`] envelope, dispatch it to
//! the worker pool (sharded by `(bucket, key)` hash), and await the reply.
//! All real I/O lives in [`super::ops`] inside the uring runtime.

use core::range::RangeInclusive;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use bytes::Bytes;
use uuid::Uuid;

use std::time::{Instant, SystemTime};

use crate::{
    CacheRebuildStatus, DEFAULT_LIST_LIMIT, Error, ListOptions, ListPage, Listing, MAX_LIST_LIMIT,
    Metadata, MetadataIndex, Object, PutOptions, StaleLock, Storage, StorageExt, SyncLevel,
    storage::locks::LockRegistry,
};

use super::{ops::UringOp, runtime::WorkerPool, streaming::UringStreamingPutGuard};

/// UUID v5 namespace used to derive deterministic filenames from object keys.
///
/// Matches the constant used by [`crate::FilesystemStorage`].
const Y2Q_NAMESPACE: Uuid = Uuid::from_bytes([
    0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
]);

/// io_uring-backed object storage backend.
///
/// One file per object using the single-file format defined in
/// [`super::format`]: `[header | data | meta | trailer]`. PUTs are durable
/// (`fdatasync` on the data file plus directory `fsync` after rename).
///
/// All I/O is dispatched to a dedicated `tokio-uring` worker pool — see
/// [`super::runtime`] — keeping the actix-web tokio runtime unblocked.
pub struct UringStorage {
    base_path: PathBuf,
    index: Arc<MetadataIndex>,
    rebuild_state: Arc<tokio::sync::Mutex<CacheRebuildStatus>>,
    config: UringConfig,
    /// `Arc` so a spawned rebuild task can share dispatch without making
    /// `WorkerPool` cloneable (the `JoinHandle`s aren't).
    pool: Arc<WorkerPool>,
    locks: LockRegistry,
}

/// Tunables for [`UringStorage`].
#[derive(Clone)]
pub struct UringConfig {
    /// Number of dedicated tokio-uring worker threads. Defaults to the number
    /// of logical CPUs.
    pub workers: usize,
    /// Object size at or above which writes switch to the `O_DIRECT` path
    /// with aligned buffers. Below this, buffered uring writes are used.
    pub large_object_bytes: u64,
    /// Metadata Encryption Key. When set, all metadata blobs are encrypted
    /// with AES-256-GCM on write and decrypted on read. Legacy plaintext
    /// metadata is read transparently for backward compatibility.
    pub mek: Option<[u8; 32]>,
}

impl std::fmt::Debug for UringConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UringConfig")
            .field("workers", &self.workers)
            .field("large_object_bytes", &self.large_object_bytes)
            .field("mek", &self.mek.map(|_| "[redacted]"))
            .finish()
    }
}

impl Default for UringConfig {
    fn default() -> Self {
        Self {
            workers: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            large_object_bytes: 4 * 1024 * 1024,
            mek: None,
        }
    }
}

impl UringStorage {
    /// Construct a new `UringStorage` rooted at `base_path`, with its secondary
    /// metadata index file at `index_path`.
    ///
    /// Spins up `config.workers` dedicated tokio-uring threads. Requires a
    /// Linux kernel with `io_uring` enabled (≥ 5.6).
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
        if let Some(mek) = config.mek {
            index.set_mek(mek);
        }
        let pool = Arc::new(
            WorkerPool::spawn(&config).map_err(|msg| Error::InternalError {
                bucket: String::new(),
                key: String::new(),
                operation: "open".to_owned(),
                message: format!("uring worker pool init: {msg}"),
            })?,
        );
        Ok(Self {
            base_path,
            index: Arc::new(index),
            rebuild_state: Arc::new(tokio::sync::Mutex::new(CacheRebuildStatus::Idle)),
            config,
            pool,
            locks: LockRegistry::new(),
        })
    }

    /// Set the Metadata Encryption Key. All subsequent metadata writes will be
    /// encrypted; reads transparently decrypt or pass through legacy plaintext.
    /// Also enables encrypted key blinding on the metadata index.
    pub fn with_mek(mut self, mek: [u8; 32]) -> Self {
        self.index.set_mek(mek);
        self.config.mek = Some(mek);
        self
    }

    /// Access the underlying metadata index, e.g. for `lookup_by_label`.
    pub fn index(&self) -> &MetadataIndex {
        &self.index
    }

    /// Canonical on-disk path for the single-file object record of
    /// `(bucket, key)`: `<base>/<bucket>/<xx>/<yy>/<uuid>.obj`.
    fn obj_path(&self, bucket: &str, key: &str) -> PathBuf {
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

    /// Dispatch an op to the worker that owns `(bucket, key)`, then await the
    /// oneshot reply. Mapping channel/oneshot failures into [`Error`] is
    /// centralised here so the trait methods stay terse.
    async fn dispatch<R>(
        &self,
        op: UringOp,
        bucket: &str,
        key: &str,
        op_name: &'static str,
        reply_rx: tokio::sync::oneshot::Receiver<Result<R, Error>>,
    ) -> Result<R, Error> {
        self.pool
            .dispatch_for_key(bucket, key)
            .send(op)
            .await
            .map_err(|_| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: op_name.to_owned(),
                message: "uring worker pool closed".to_owned(),
            })?;
        reply_rx.await.map_err(|_| Error::InternalError {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            operation: op_name.to_owned(),
            message: "uring worker dropped reply".to_owned(),
        })?
    }
}

impl UringStorage {
    /// Begin a streaming PUT for `bucket`/`key`.
    ///
    /// Acquires the object write-lock, opens a tmp file, writes a 64-byte
    /// placeholder `.obj` header, and returns the guard + file. The caller
    /// passes the file to an [`crate::crypto::envelope::EncryptSession`]
    /// (with `write_offset = STREAMING_DATA_OFFSET`) to stream-encrypt the
    /// body, then calls [`UringStreamingPutGuard::commit`] to finalise and
    /// rename the object.
    pub async fn begin_streaming_put(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(UringStreamingPutGuard, tokio::fs::File), Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;

        let obj_path = self.obj_path(bucket, key);
        let tmp_path = obj_path.with_extension("tmp");

        if let Some(parent) = obj_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| Error::InternalError {
                    bucket: bucket.to_owned(),
                    key: key.to_owned(),
                    operation: "begin_streaming_put".to_owned(),
                    message: format!("mkdir: {e}"),
                })?;
        }

        // Detect overwrite before acquiring the lock (ReadObjectMeta skips
        // the lock check, so it's safe to call concurrently with readers).
        let (is_overwrite, prior_created) = match tokio::fs::metadata(&obj_path).await {
            Ok(_) => {
                let (reply, reply_rx) = tokio::sync::oneshot::channel();
                let op = UringOp::ReadObjectMeta {
                    path: obj_path.clone(),
                    mek: self.config.mek,
                    reply,
                };
                self.pool
                    .dispatch_for_key(bucket, key)
                    .send(op)
                    .await
                    .map_err(|_| Error::InternalError {
                        bucket: bucket.to_owned(),
                        key: key.to_owned(),
                        operation: "begin_streaming_put".to_owned(),
                        message: "worker pool closed".to_owned(),
                    })?;
                let prior_created = match reply_rx.await {
                    Ok(Ok(meta)) => Some(meta.created),
                    _ => None,
                };
                (true, prior_created)
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

        // Open the tmp file and write a placeholder `.obj` header so the
        // EncryptSession starts writing at data_offset (= HEADER_SIZE = 64).
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

        use tokio::io::AsyncWriteExt as _;
        let placeholder = [0u8; super::format::HEADER_SIZE];
        file.write_all(&placeholder)
            .await
            .map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "begin_streaming_put".to_owned(),
                message: format!("write placeholder header: {e}"),
            })?;

        let guard = UringStreamingPutGuard::new(
            tmp_path,
            obj_path,
            lock,
            bucket.to_owned(),
            key.to_owned(),
            is_overwrite,
            prior_created,
            self.config.mek,
            self.index.clone(),
        );

        Ok((guard, file))
    }
}

/// Reserved bucket names that conflict with the `/api/v1/*` admin namespace.
const RESERVED_BUCKETS: &[&str] = &["api"];

/// Validate that `bucket` is a safe directory name.
///
/// Names in `RESERVED_BUCKETS` are rejected case-insensitively.
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

/// Validate that `key` is a legal object key.
fn validate_key(key: &str) -> Result<(), Error> {
    const MAX_KEY_LEN: usize = 1024;
    if key.is_empty() || key.contains('\0') || key.len() > MAX_KEY_LEN {
        return Err(Error::InvalidKey {
            key: key.to_owned(),
        });
    }
    Ok(())
}

fn record_storage_op<T, E>(op: &'static str, result: &Result<T, E>, elapsed_ms: f64) {
    let result_label = if result.is_ok() { "ok" } else { "err" };
    metrics::counter!(
        "y2qd_storage_ops_total",
        "op" => op, "backend" => "uring", "result" => result_label
    )
    .increment(1);
    metrics::histogram!(
        "y2qd_storage_op_duration_milliseconds",
        "op" => op, "backend" => "uring"
    )
    .record(elapsed_ms);
}

impl Storage for UringStorage {
    async fn get(&self, bucket: &str, key: &str) -> Result<Object, Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;
        let started = Instant::now();
        let obj_path = self.obj_path(bucket, key);
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        let op = UringOp::Get {
            obj_path,
            locks: self.locks.clone(),
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            reply,
        };
        let result = self.dispatch(op, bucket, key, "get", reply_rx).await;
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
        let obj_path = self.obj_path(bucket, key);
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        let op = UringOp::GetRange {
            obj_path,
            locks: self.locks.clone(),
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            range,
            reply,
        };
        self.dispatch(op, bucket, key, "get_range", reply_rx).await
    }

    async fn put(
        &self,
        bucket: &str,
        key: &str,
        payload: Object,
        options: PutOptions,
    ) -> Result<bool, Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;
        let started = Instant::now();
        let obj_path = self.obj_path(bucket, key);
        let tmp_path = obj_path.with_extension("tmp");
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        let crypto = match (options.plaintext_metrics, options.cipher_metadata) {
            (Some(p), Some(c)) => Some(Box::new(crate::storage::uring::ops::PutCryptoFields {
                plaintext_metrics: p,
                cipher_metadata: c,
            })),
            _ => None,
        };
        let op = UringOp::Put {
            obj_path,
            tmp_path,
            locks: self.locks.clone(),
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            url_path: format!("{bucket}/{key}"),
            payload: payload.into_inner(),
            labels: options.labels,
            crypto,
            large_object_bytes: self.config.large_object_bytes,
            sync: options.sync,
            mek: self.config.mek,
            reply,
        };
        let dispatch_result = self.dispatch(op, bucket, key, "put", reply_rx).await;
        let result = dispatch_result.map(|(is_overwrite, metadata)| (is_overwrite, metadata));
        record_storage_op("put", &result, started.elapsed().as_secs_f64() * 1_000.0);
        let (is_overwrite, metadata) = result?;

        // Mirror FilesystemStorage: the on-disk record is authoritative, so a
        // failed index upsert is logged but not surfaced — the index can be
        // rebuilt from the trailer scan in `rebuild_cache`.
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

    async fn delete(&self, bucket: &str, key: &str) -> Result<Object, Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;
        let started = Instant::now();
        let obj_path = self.obj_path(bucket, key);
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        let op = UringOp::Delete {
            obj_path,
            locks: self.locks.clone(),
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            reply,
        };
        let result = self.dispatch(op, bucket, key, "delete", reply_rx).await;
        record_storage_op("delete", &result, started.elapsed().as_secs_f64() * 1_000.0);
        let obj = result?;

        if let Err(e) = self.index.remove(bucket, key).await {
            tracing::warn!(
                bucket = bucket,
                key = key,
                error = %e,
                "metadata index remove failed; on-disk record is authoritative"
            );
        }
        Ok(obj)
    }

    async fn describe(&self, bucket: &str, key: &str) -> Result<Metadata, Error> {
        validate_bucket(bucket)?;
        validate_key(key)?;
        let started = Instant::now();
        let obj_path = self.obj_path(bucket, key);
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        let op = UringOp::Describe {
            obj_path,
            locks: self.locks.clone(),
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            mek: self.config.mek,
            reply,
        };
        let result = self.dispatch(op, bucket, key, "describe", reply_rx).await;
        record_storage_op(
            "describe",
            &result,
            started.elapsed().as_secs_f64() * 1_000.0,
        );
        result
    }
}

impl Listing for UringStorage {
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

impl StorageExt for UringStorage {
    /// Spawn a background task that rebuilds the secondary index from the
    /// on-disk `.obj` files.
    ///
    /// Returns [`Error::RebuildAlreadyRunning`] if a rebuild is already in
    /// flight. Otherwise the task is scheduled on the actix-side tokio
    /// runtime; it dispatches per-file metadata reads to the uring worker
    /// pool in batches of [`REBUILD_BATCH_SIZE`] so I/O stays parallel.
    /// Progress is observable via [`Self::rebuild_progress`].
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
        let pool = Arc::clone(&self.pool);
        let mek = self.config.mek;
        tokio::spawn(async move {
            let result = run_rebuild(base_path, index, state.clone(), pool, mek).await;
            let mut s = state.lock().await;
            *s = match result {
                Ok(()) => CacheRebuildStatus::Completed,
                Err(msg) => {
                    tracing::error!(error = %msg, "uring cache rebuild failed");
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
        Ok(self.locks.clear_stale(older_than))
    }
}

/// Number of read-meta ops the rebuild walker dispatches in a single batch.
///
/// Submitted in flight together, then awaited together before the next
/// batch starts. With N workers, throughput is bounded by the slowest in
/// the batch but the worst-case memory overhead stays at
/// `BATCH_SIZE * sizeof(oneshot pair)` regardless of total object count.
const REBUILD_BATCH_SIZE: usize = 64;

/// Walk every `.obj` file under `base_path`, dispatch a read-meta op for
/// each, upsert the decoded metadata into `index`, then drop any index rows
/// whose object is no longer on disk. Updates `state` with `Running(pct)`
/// periodically; the caller transitions to `Completed` after this returns.
async fn run_rebuild(
    base_path: PathBuf,
    index: Arc<MetadataIndex>,
    state: Arc<tokio::sync::Mutex<CacheRebuildStatus>>,
    pool: Arc<WorkerPool>,
    mek: Option<[u8; 32]>,
) -> Result<(), String> {
    let obj_paths = collect_obj_files(&base_path)
        .await
        .map_err(|e| format!("enumerate .obj files: {e}"))?;
    let total = obj_paths.len();
    let report_every = (total / 100).max(1);

    let mut seen: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::with_capacity(total);

    let mut path_iter = obj_paths.into_iter();
    let mut processed = 0;
    loop {
        // Submit a batch of read-meta ops to the worker pool.
        let mut receivers = Vec::with_capacity(REBUILD_BATCH_SIZE);
        for _ in 0..REBUILD_BATCH_SIZE {
            let Some(path) = path_iter.next() else { break };
            let (reply, reply_rx) = tokio::sync::oneshot::channel();
            let sender = pool.dispatch_for_path(&path).clone();
            let op = UringOp::ReadObjectMeta { path, mek, reply };
            if let Err(e) = sender.send(op).await {
                return Err(format!("worker pool closed mid-rebuild: {e}"));
            }
            receivers.push(reply_rx);
        }
        if receivers.is_empty() {
            break;
        }

        // Drain the batch in submission order. Workers process concurrently
        // across the pool, so by the time we await later receivers their
        // results may already be in flight.
        for rx in receivers {
            match rx.await {
                Ok(Ok(meta)) => {
                    seen.insert((meta.bucket.clone(), meta.key.clone()));
                    if let Err(e) = index.upsert(&meta, SyncLevel::Durable).await {
                        tracing::warn!(
                            bucket = %meta.bucket,
                            key = %meta.key,
                            error = %e,
                            "rebuild: index upsert failed; continuing"
                        );
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "rebuild: read meta failed; skipping");
                }
                Err(_) => {
                    tracing::warn!("rebuild: worker dropped reply; skipping");
                }
            }
            processed += 1;
            if processed % report_every == 0 && total > 0 {
                let pct = ((processed * 100 / total) as u8).min(99);
                *state.lock().await = CacheRebuildStatus::Running(pct);
            }
        }
    }

    // Drop index rows whose `.obj` file is no longer on disk.
    let all_keys = index
        .list_all_keys()
        .await
        .map_err(|e| format!("list index keys: {e}"))?;
    for (bucket, key) in all_keys {
        if !seen.contains(&(bucket.clone(), key.clone()))
            && let Err(e) = index.remove(&bucket, &key).await
        {
            tracing::warn!(
                bucket = %bucket,
                key = %key,
                error = %e,
                "rebuild: stale index row removal failed; continuing"
            );
        }
    }

    Ok(())
}

/// Recursively gather every `*.obj` file under
/// `base_path/<bucket>/<xx>/<yy>/`.
///
/// Bucket directories whose name fails [`validate_bucket`] are skipped,
/// which excludes reserved files like `_y2q_index.redb` and any leftover
/// `.tmp` files at unexpected nesting levels.
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
    use crate::PutOptions;
    use bytes::Bytes;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    fn make_storage(dir: &TempDir, workers: usize) -> UringStorage {
        UringStorage::new(
            dir.path(),
            dir.path().join("idx.redb"),
            UringConfig {
                workers,
                ..UringConfig::default()
            },
        )
        .unwrap()
    }

    /// Build a UringStorage with a custom large-object threshold so tests can
    /// trigger the `O_DIRECT` path without allocating multi-MiB payloads.
    fn make_storage_with_threshold(
        dir: &TempDir,
        workers: usize,
        large_object_bytes: u64,
    ) -> UringStorage {
        UringStorage::new(
            dir.path(),
            dir.path().join("idx.redb"),
            UringConfig {
                workers,
                large_object_bytes,
                ..UringConfig::default()
            },
        )
        .unwrap()
    }

    /// A TempDir on a disk-backed filesystem so tests actually exercise
    /// `O_DIRECT` (the default `/tmp` is usually tmpfs, which returns EINVAL
    /// on O_DIRECT and would force the fallback path). The workspace's
    /// `target/` lives under `$CARGO_MANIFEST_DIR/../../target` and is btrfs
    /// or ext4 on every dev box.
    fn disk_backed_tempdir() -> TempDir {
        let parent = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("target")
            .join("uring-test-tmp");
        std::fs::create_dir_all(&parent).unwrap();
        tempfile::Builder::new()
            .prefix("y2q-uring-")
            .tempdir_in(&parent)
            .unwrap()
    }

    fn payload(bytes: &[u8]) -> Object {
        Object::new(Bytes::copy_from_slice(bytes))
    }

    #[tokio::test]
    async fn put_then_get_round_trips() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 2);
        let body = b"the quick brown fox jumps over the lazy dog".to_vec();
        let is_overwrite = storage
            .put("b", "k", payload(&body), PutOptions::default())
            .await
            .unwrap();
        assert!(!is_overwrite);
        let got = storage.get("b", "k").await.unwrap();
        assert_eq!(&got[..], body.as_slice());
    }

    #[tokio::test]
    async fn put_then_describe_returns_correct_metadata() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 1);
        let body = vec![7u8; 4096];
        let mut labels = BTreeMap::new();
        labels.insert("env".to_owned(), "prod".to_owned());
        storage
            .put(
                "b",
                "k",
                payload(&body),
                PutOptions {
                    labels,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let meta = storage.describe("b", "k").await.unwrap();
        assert_eq!(meta.size, 4096);
        assert_eq!(meta.bucket, "b");
        assert_eq!(meta.key, "k");
        assert_eq!(meta.labels.get("env"), Some(&"prod".to_owned()));
        assert!(!meta.checksum_md5.is_empty());
        assert!(!meta.checksum_sha256.is_empty());
    }

    #[tokio::test]
    async fn overwrite_preserves_created_and_returns_true() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 1);
        storage
            .put("b", "k", payload(b"v1"), PutOptions::default())
            .await
            .unwrap();
        let first = storage.describe("b", "k").await.unwrap();
        // Sleep a touch so `modified` will move forward.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let is_overwrite = storage
            .put("b", "k", payload(b"v2_longer"), PutOptions::default())
            .await
            .unwrap();
        assert!(is_overwrite);
        let second = storage.describe("b", "k").await.unwrap();
        assert_eq!(second.created, first.created);
        assert!(second.modified >= first.modified);
        assert_eq!(second.size, b"v2_longer".len() as u64);
        let bytes = storage.get("b", "k").await.unwrap();
        assert_eq!(&bytes[..], b"v2_longer");
    }

    #[tokio::test]
    async fn get_range_returns_only_requested_slice() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 1);
        // 4 KiB payload of distinct bytes so we can locate the slice unambiguously.
        let body: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        storage
            .put("b", "k", payload(&body), PutOptions::default())
            .await
            .unwrap();

        let slice = storage
            .get_range(
                "b",
                "k",
                RangeInclusive {
                    start: 100,
                    last: 199,
                },
            )
            .await
            .unwrap();
        assert_eq!(slice.len(), 100);
        assert_eq!(&slice[..], &body[100..=199]);

        // Range past EOF clamps to actual length.
        let tail = storage
            .get_range(
                "b",
                "k",
                RangeInclusive {
                    start: 4000,
                    last: 999_999,
                },
            )
            .await
            .unwrap();
        assert_eq!(tail.len(), 96);
        assert_eq!(&tail[..], &body[4000..]);

        // Start past EOF returns empty.
        let empty = storage
            .get_range(
                "b",
                "k",
                RangeInclusive {
                    start: 10_000,
                    last: 20_000,
                },
            )
            .await
            .unwrap();
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn delete_returns_object_and_makes_subsequent_get_not_found() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 1);
        storage
            .put("b", "k", payload(b"bye"), PutOptions::default())
            .await
            .unwrap();
        let got = storage.delete("b", "k").await.unwrap();
        assert_eq!(&got[..], b"bye");
        let err = storage.get("b", "k").await.unwrap_err();
        assert!(matches!(err, Error::NotFound { .. }));
    }

    #[tokio::test]
    async fn put_populates_index_for_list_objects() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 1);
        storage
            .put("b", "alpha", payload(b"a"), PutOptions::default())
            .await
            .unwrap();
        storage
            .put("b", "beta", payload(b"bb"), PutOptions::default())
            .await
            .unwrap();
        let page = storage
            .list_objects("b", ListOptions::default())
            .await
            .unwrap();
        let keys: Vec<_> = page.items.iter().map(|m| m.key.clone()).collect();
        assert_eq!(keys, vec!["alpha".to_owned(), "beta".to_owned()]);
        let buckets = storage.list_buckets().await.unwrap();
        assert_eq!(buckets, vec!["b".to_owned()]);
    }

    #[tokio::test]
    async fn get_missing_object_returns_not_found() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 1);
        let err = storage.get("b", "nope").await.unwrap_err();
        assert!(matches!(err, Error::NotFound { .. }));
    }

    #[tokio::test]
    async fn describe_missing_object_returns_not_found() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 1);
        let err = storage.describe("b", "nope").await.unwrap_err();
        assert!(matches!(err, Error::NotFound { .. }));
    }

    #[tokio::test]
    async fn invalid_bucket_is_rejected_before_dispatch() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 1);
        let err = storage.get("../escape", "k").await.unwrap_err();
        assert!(matches!(err, Error::InvalidBucket { .. }));
    }

    /// Round-trip a payload whose size is an exact multiple of the 4 KiB
    /// alignment block — the O_DIRECT bulk consumes the whole payload, no
    /// non-aligned tail. Uses a disk-backed tempdir so the O_DIRECT path
    /// actually runs (tmpfs fallback would still pass this test, but defeats
    /// the purpose).
    #[tokio::test]
    async fn put_then_get_round_trips_aligned_large_object() {
        let dir = disk_backed_tempdir();
        // Threshold of 8 KiB makes 16 KiB qualify as "large".
        let storage = make_storage_with_threshold(&dir, 2, 8 * 1024);
        // 16 KiB of distinct bytes so corruption would show up in the
        // assertion below.
        let body: Vec<u8> = (0..16 * 1024).map(|i| (i % 251) as u8).collect();
        storage
            .put("b", "k", payload(&body), PutOptions::default())
            .await
            .unwrap();
        let got = storage.get("b", "k").await.unwrap();
        assert_eq!(&got[..], body.as_slice());
        let meta = storage.describe("b", "k").await.unwrap();
        assert_eq!(meta.size, body.len() as u64);
    }

    /// Round-trip a payload whose size has a non-aligned tail. Exercises the
    /// split between the O_DIRECT aligned bulk and the buffered tail write.
    #[tokio::test]
    async fn put_then_get_round_trips_large_object_with_tail() {
        let dir = disk_backed_tempdir();
        let storage = make_storage_with_threshold(&dir, 2, 8 * 1024);
        // 18 KiB = 4 KiB-aligned bulk (16 KiB) + 2 KiB tail. The tail
        // exercises the buffered fd's write_all_at path.
        let body: Vec<u8> = (0..18 * 1024).map(|i| (i % 251) as u8).collect();
        storage
            .put("b", "k", payload(&body), PutOptions::default())
            .await
            .unwrap();
        let got = storage.get("b", "k").await.unwrap();
        assert_eq!(&got[..], body.as_slice());
    }

    /// `get_range` against an O_DIRECT-written object must work the same as
    /// for a buffered one — the read path uses `header.data_offset` so the
    /// 4 KiB pad in front of the data is invisible to callers.
    #[tokio::test]
    async fn get_range_works_on_large_object_with_tail() {
        let dir = disk_backed_tempdir();
        let storage = make_storage_with_threshold(&dir, 1, 8 * 1024);
        let body: Vec<u8> = (0..18 * 1024).map(|i| (i % 251) as u8).collect();
        storage
            .put("b", "k", payload(&body), PutOptions::default())
            .await
            .unwrap();

        // Cross the boundary between aligned bulk (16 KiB) and the 2 KiB tail
        // so we exercise both write regions in one read.
        let slice = storage
            .get_range(
                "b",
                "k",
                RangeInclusive {
                    start: 16_000,
                    last: 17_500,
                },
            )
            .await
            .unwrap();
        assert_eq!(slice.len(), 1501);
        assert_eq!(&slice[..], &body[16_000..=17_500]);
    }

    /// A payload below the threshold must take the buffered path even when
    /// large_object_bytes is configured. Use a 4 KiB body with a 64 KiB
    /// threshold and verify the header's data_offset is the buffered value
    /// (64) rather than the O_DIRECT-aligned value (4096).
    #[tokio::test]
    async fn small_object_below_threshold_uses_buffered_layout() {
        let dir = disk_backed_tempdir();
        let storage = make_storage_with_threshold(&dir, 1, 64 * 1024);
        let body = vec![9u8; 4 * 1024];
        storage
            .put("b", "k", payload(&body), PutOptions::default())
            .await
            .unwrap();

        // Inspect the on-disk header directly to confirm the buffered layout.
        let obj_path = storage.obj_path("b", "k");
        let bytes = std::fs::read(&obj_path).unwrap();
        assert!(bytes.len() >= super::super::format::HEADER_SIZE);
        let header_arr: [u8; super::super::format::HEADER_SIZE] = bytes
            [..super::super::format::HEADER_SIZE]
            .try_into()
            .unwrap();
        let header = super::super::format::Header::decode(&header_arr).unwrap();
        assert_eq!(
            header.data_offset,
            super::super::format::Header::MIN_DATA_OFFSET
        );
        assert_eq!(
            header.flags & super::super::format::flags::WRITTEN_O_DIRECT,
            0,
            "small object should not have the O_DIRECT flag"
        );
    }

    /// Pagination across prefix + after + limit must behave the same as on
    /// FilesystemStorage — both backends share `MetadataIndex::scan_objects`.
    /// This test is a smoke-test for parity rather than testing the index
    /// itself.
    #[tokio::test]
    async fn list_objects_paginates_with_prefix_and_after() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 1);
        for key in ["a/1", "a/2", "a/3", "b/1", "b/2"] {
            storage
                .put("bkt", key, payload(b"x"), PutOptions::default())
                .await
                .unwrap();
        }

        let page = storage
            .list_objects(
                "bkt",
                ListOptions {
                    prefix: Some("a/".to_owned()),
                    after: None,
                    limit: Some(2),
                },
            )
            .await
            .unwrap();
        let keys: Vec<_> = page.items.iter().map(|m| m.key.clone()).collect();
        assert_eq!(keys, vec!["a/1".to_owned(), "a/2".to_owned()]);
        assert_eq!(page.next.as_deref(), Some("a/2"));

        let page2 = storage
            .list_objects(
                "bkt",
                ListOptions {
                    prefix: Some("a/".to_owned()),
                    after: page.next,
                    limit: Some(10),
                },
            )
            .await
            .unwrap();
        let keys2: Vec<_> = page2.items.iter().map(|m| m.key.clone()).collect();
        assert_eq!(keys2, vec!["a/3".to_owned()]);
        assert!(page2.next.is_none());
    }

    /// Wait for the spawned rebuild task to reach a terminal state.
    /// Polls progress; bails out (panics) if it stays running too long.
    async fn wait_for_rebuild(storage: &UringStorage) -> super::CacheRebuildStatus {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let s = storage.rebuild_progress().await.unwrap();
            if matches!(
                s,
                super::CacheRebuildStatus::Completed | super::CacheRebuildStatus::Failed(_)
            ) {
                return s;
            }
            if std::time::Instant::now() > deadline {
                panic!("rebuild did not complete within 5s; last status: {s:?}");
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// `rebuild_cache` must repopulate the secondary index from `.obj`
    /// files on disk after the index has been wiped, so a corrupted /
    /// missing redb is fully recoverable from the source-of-truth files.
    #[tokio::test]
    async fn rebuild_repopulates_index_after_wipe() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 2);
        for (k, v) in [
            ("alpha", &b"a"[..]),
            ("beta", &b"bb"[..]),
            ("gamma", &b"ccc"[..]),
        ] {
            storage
                .put("b", k, payload(v), PutOptions::default())
                .await
                .unwrap();
        }
        // Drop the storage so the redb file is closed cleanly, then wipe it
        // and reopen. The .obj files on disk remain untouched.
        let base = storage.base_path.clone();
        drop(storage);
        let index_path = base.join("idx.redb");
        std::fs::remove_file(&index_path).unwrap();

        let storage = UringStorage::new(
            &base,
            &index_path,
            UringConfig {
                workers: 2,
                ..UringConfig::default()
            },
        )
        .unwrap();
        // Index is empty right now.
        let page = storage
            .list_objects("b", ListOptions::default())
            .await
            .unwrap();
        assert!(page.items.is_empty());

        storage.rebuild_cache().await.unwrap();
        let final_state = wait_for_rebuild(&storage).await;
        assert!(matches!(final_state, super::CacheRebuildStatus::Completed));

        let page = storage
            .list_objects("b", ListOptions::default())
            .await
            .unwrap();
        let keys: Vec<_> = page.items.iter().map(|m| m.key.clone()).collect();
        assert_eq!(
            keys,
            vec!["alpha".to_owned(), "beta".to_owned(), "gamma".to_owned()]
        );
    }

    /// If a `.obj` file is removed out-of-band, `rebuild_cache` must drop
    /// the corresponding index row so subsequent listings stay consistent.
    #[tokio::test]
    async fn rebuild_drops_stale_index_entries() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 1);
        storage
            .put("b", "ghost", payload(b"boo"), PutOptions::default())
            .await
            .unwrap();
        storage
            .put("b", "real", payload(b"yes"), PutOptions::default())
            .await
            .unwrap();

        // Yank the ghost's .obj file but leave the index entry.
        let ghost_path = storage.obj_path("b", "ghost");
        std::fs::remove_file(&ghost_path).unwrap();

        storage.rebuild_cache().await.unwrap();
        assert!(matches!(
            wait_for_rebuild(&storage).await,
            super::CacheRebuildStatus::Completed
        ));

        let page = storage
            .list_objects("b", ListOptions::default())
            .await
            .unwrap();
        let keys: Vec<_> = page.items.iter().map(|m| m.key.clone()).collect();
        assert_eq!(keys, vec!["real".to_owned()]);
    }

    /// A second `rebuild_cache` call while one is in flight must return
    /// `Error::RebuildAlreadyRunning` rather than starting a parallel
    /// rebuild that races with the first one over the index.
    #[tokio::test]
    async fn rebuild_rejects_concurrent_invocations() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir, 1);
        // Seed enough objects that the rebuild takes long enough to overlap
        // with our second call.
        for i in 0..32 {
            storage
                .put("b", &format!("k{i}"), payload(b"x"), PutOptions::default())
                .await
                .unwrap();
        }

        storage.rebuild_cache().await.unwrap();
        // Immediately try again — the first one is still going.
        match storage.rebuild_cache().await {
            Err(Error::RebuildAlreadyRunning) => { /* expected */ }
            other => panic!("expected RebuildAlreadyRunning, got {other:?}"),
        }
        let _ = wait_for_rebuild(&storage).await;
    }

    /// Regression guard for the dispatch logic: a payload that exceeds the
    /// threshold must take the O_DIRECT path, producing a header with the
    /// `WRITTEN_O_DIRECT` flag set and `data_offset = 4096`.
    ///
    /// Uses `disk_backed_tempdir()` which lives under the workspace's
    /// `target/`, so the underlying filesystem (btrfs/ext4/xfs) supports
    /// O_DIRECT on every Linux dev box. If you genuinely need to run this
    /// on tmpfs, expect a failure — that's the test's job.
    #[tokio::test]
    async fn large_object_writes_with_o_direct_flag_set() {
        let dir = disk_backed_tempdir();
        let storage = make_storage_with_threshold(&dir, 1, 8 * 1024);
        let body = vec![5u8; 16 * 1024];
        storage
            .put("b", "k", payload(&body), PutOptions::default())
            .await
            .unwrap();

        let obj_path = storage.obj_path("b", "k");
        let bytes = std::fs::read(&obj_path).unwrap();
        let header_arr: [u8; super::super::format::HEADER_SIZE] = bytes
            [..super::super::format::HEADER_SIZE]
            .try_into()
            .unwrap();
        let header = super::super::format::Header::decode(&header_arr).unwrap();
        assert_ne!(
            header.flags & super::super::format::flags::WRITTEN_O_DIRECT,
            0,
            "expected WRITTEN_O_DIRECT flag; underlying FS may not support O_DIRECT \
             (this test requires the workspace target dir on ext4/btrfs/xfs)"
        );
        assert_eq!(
            header.data_offset,
            super::super::format::MIN_DIRECT_DATA_OFFSET
        );
    }
}
