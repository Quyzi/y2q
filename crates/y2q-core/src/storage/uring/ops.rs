//! Typed operation envelopes sent from the actix-web side to the
//! `tokio-uring` worker pool, plus their worker-side handlers.
//!
//! Each variant carries the inputs needed to execute the op on the worker,
//! plus a `tokio::sync::oneshot::Sender` for the reply. The worker pulls an
//! op off its queue, runs the matching handler inside the uring runtime,
//! then signals completion through the oneshot.
//!
//! The handlers in this file are the small-object buffered-uring path. The
//! `O_DIRECT` large-object path is added in a subsequent step and dispatches
//! from inside `do_put` based on payload size.

use core::range::RangeInclusive;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use bytes::Bytes;
use sha2::Digest;
use tokio::sync::oneshot;
use tokio_uring::fs::{File, OpenOptions};

use crate::{Error, Metadata, Object};

use super::format::{self, HEADER_SIZE, Header};

/// One unit of work submitted to a uring worker.
pub(super) enum UringOp {
    /// Read the full object payload.
    Get {
        obj_path: PathBuf,
        lock_path: PathBuf,
        bucket: String,
        key: String,
        reply: oneshot::Sender<Result<Object, Error>>,
    },
    /// Read a byte range of the object payload.
    GetRange {
        obj_path: PathBuf,
        lock_path: PathBuf,
        bucket: String,
        key: String,
        range: RangeInclusive<u64>,
        reply: oneshot::Sender<Result<Bytes, Error>>,
    },
    /// Write a new object (durably) using the temp-file + atomic-rename pattern.
    Put {
        obj_path: PathBuf,
        tmp_path: PathBuf,
        lock_path: PathBuf,
        bucket: String,
        key: String,
        url_path: String,
        payload: Bytes,
        labels: BTreeMap<String, String>,
        reply: oneshot::Sender<Result<(bool, Metadata), Error>>,
    },
    /// Read the object, then unlink it. Returns the deleted bytes.
    Delete {
        obj_path: PathBuf,
        lock_path: PathBuf,
        bucket: String,
        key: String,
        reply: oneshot::Sender<Result<Object, Error>>,
    },
    /// Read and decode just the metadata blob.
    Describe {
        obj_path: PathBuf,
        lock_path: PathBuf,
        bucket: String,
        key: String,
        reply: oneshot::Sender<Result<Metadata, Error>>,
    },
}

/// Dispatch one op to its handler. Called from the worker's recv loop.
pub(super) async fn handle(op: UringOp) {
    match op {
        UringOp::Get {
            obj_path,
            lock_path,
            bucket,
            key,
            reply,
        } => {
            let _ = reply.send(do_get(obj_path, lock_path, bucket, key).await);
        }
        UringOp::GetRange {
            obj_path,
            lock_path,
            bucket,
            key,
            range,
            reply,
        } => {
            let _ = reply.send(do_get_range(obj_path, lock_path, bucket, key, range).await);
        }
        UringOp::Put {
            obj_path,
            tmp_path,
            lock_path,
            bucket,
            key,
            url_path,
            payload,
            labels,
            reply,
        } => {
            let _ = reply.send(
                do_put(
                    obj_path, tmp_path, lock_path, bucket, key, url_path, payload, labels,
                )
                .await,
            );
        }
        UringOp::Delete {
            obj_path,
            lock_path,
            bucket,
            key,
            reply,
        } => {
            let _ = reply.send(do_delete(obj_path, lock_path, bucket, key).await);
        }
        UringOp::Describe {
            obj_path,
            lock_path,
            bucket,
            key,
            reply,
        } => {
            let _ = reply.send(do_describe(obj_path, lock_path, bucket, key).await);
        }
    }
}

// ───── helpers ──────────────────────────────────────────────────────────────

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn internal(bucket: &str, key: &str, op: &str, msg: impl std::fmt::Display) -> Error {
    Error::InternalError {
        bucket: bucket.to_owned(),
        key: key.to_owned(),
        operation: op.to_owned(),
        message: msg.to_string(),
    }
}

/// Returns `Err(Error::Locked)` if a `.lock` sidecar exists for this object.
/// A best-effort timestamp is read from the lock file's first 8 bytes; if
/// unreadable, `since` falls back to `UNIX_EPOCH`.
async fn check_not_locked(lock_path: &Path, bucket: &str, key: &str) -> Result<(), Error> {
    match tokio_uring::fs::statx(lock_path).await {
        Ok(_) => {
            let since = read_lock_timestamp(lock_path).await;
            Err(Error::Locked {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                since,
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(internal(bucket, key, "lock", format!("statx: {e}"))),
    }
}

async fn read_lock_timestamp(path: &Path) -> SystemTime {
    let Ok(file) = File::open(path).await else {
        return UNIX_EPOCH;
    };
    let buf = vec![0u8; 8];
    let (res, buf) = file.read_exact_at(buf, 0).await;
    let _ = file.close().await;
    if res.is_ok()
        && let Ok(arr) = <[u8; 8]>::try_from(buf.as_slice())
    {
        return UNIX_EPOCH + Duration::from_nanos(u64::from_le_bytes(arr));
    }
    UNIX_EPOCH
}

/// RAII guard that removes a `.lock` sidecar on drop.
///
/// Removal is synchronous because async-Drop doesn't exist; this is the same
/// trick [`crate::FilesystemStorage`]'s `LockGuard` uses. The blocking call
/// here is a single `unlink(2)`, cheap even inside a uring worker thread.
struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Acquire an exclusive lock for `lock_path` via `openat(O_EXCL|O_CREAT)`.
///
/// Writes the current timestamp into the lock so subsequent
/// [`Error::Locked`] errors carry useful `since` data.
async fn acquire_lock(
    lock_path: PathBuf,
    bucket: &str,
    key: &str,
) -> Result<LockGuard, Error> {
    let file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .await
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let since = read_lock_timestamp(&lock_path).await;
            return Err(Error::Locked {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                since,
            });
        }
        Err(e) => return Err(internal(bucket, key, "lock", format!("create: {e}"))),
    };
    let stamp = now_nanos().to_le_bytes().to_vec();
    let (_, _) = file.write_all_at(stamp, 0).await;
    let _ = file.close().await;
    Ok(LockGuard { path: lock_path })
}

/// Open an object file and decode + validate its 64-byte header.
async fn open_and_read_header(
    obj_path: &Path,
    bucket: &str,
    key: &str,
    op_name: &str,
) -> Result<(File, Header), Error> {
    let file = match File::open(obj_path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::NotFound {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
            });
        }
        Err(e) => return Err(internal(bucket, key, op_name, format!("open: {e}"))),
    };
    let buf = vec![0u8; HEADER_SIZE];
    let (res, buf) = file.read_exact_at(buf, 0).await;
    if let Err(e) = res {
        let _ = file.close().await;
        return Err(internal(bucket, key, op_name, format!("read header: {e}")));
    }
    let header_bytes: [u8; HEADER_SIZE] = buf.as_slice().try_into().expect("HEADER_SIZE buffer");
    let header = match Header::decode(&header_bytes) {
        Ok(h) => h,
        Err(e) => {
            let _ = file.close().await;
            return Err(internal(bucket, key, op_name, format!("decode header: {e}")));
        }
    };
    Ok((file, header))
}

/// Read the metadata blob from an already-opened object, given its decoded
/// header.
async fn read_meta_blob(
    file: &File,
    header: &Header,
    bucket: &str,
    key: &str,
    op_name: &str,
) -> Result<Metadata, Error> {
    let buf = vec![0u8; header.meta_len as usize];
    let (res, buf) = file.read_exact_at(buf, header.meta_offset()).await;
    res.map_err(|e| internal(bucket, key, op_name, format!("read meta: {e}")))?;
    serde_json::from_slice(&buf)
        .map_err(|e| internal(bucket, key, op_name, format!("decode meta: {e}")))
}

// ───── operation handlers ────────────────────────────────────────────────────

async fn do_describe(
    obj_path: PathBuf,
    lock_path: PathBuf,
    bucket: String,
    key: String,
) -> Result<Metadata, Error> {
    check_not_locked(&lock_path, &bucket, &key).await?;
    let (file, header) = open_and_read_header(&obj_path, &bucket, &key, "describe").await?;
    let meta = read_meta_blob(&file, &header, &bucket, &key, "describe").await;
    let _ = file.close().await;
    meta
}

async fn do_get(
    obj_path: PathBuf,
    lock_path: PathBuf,
    bucket: String,
    key: String,
) -> Result<Object, Error> {
    check_not_locked(&lock_path, &bucket, &key).await?;
    let (file, header) = open_and_read_header(&obj_path, &bucket, &key, "get").await?;

    let data_len = header.data_len as usize;
    let buf = vec![0u8; data_len];
    let (res, buf) = file.read_exact_at(buf, Header::DATA_OFFSET).await;
    let _ = file.close().await;
    res.map_err(|e| internal(&bucket, &key, "get", format!("read data: {e}")))?;
    Ok(Object::new(Bytes::from(buf)))
}

async fn do_get_range(
    obj_path: PathBuf,
    lock_path: PathBuf,
    bucket: String,
    key: String,
    range: RangeInclusive<u64>,
) -> Result<Bytes, Error> {
    check_not_locked(&lock_path, &bucket, &key).await?;
    let (file, header) = open_and_read_header(&obj_path, &bucket, &key, "get_range").await?;

    if header.data_len == 0 || range.start >= header.data_len {
        let _ = file.close().await;
        return Ok(Bytes::new());
    }
    let start = range.start;
    // RangeInclusive end is `last`; clamp to data_len-1, then convert to a
    // length so it fits a single read_exact_at.
    let end_inclusive = range.last.min(header.data_len - 1);
    let len = (end_inclusive - start + 1) as usize;
    let buf = vec![0u8; len];
    let (res, buf) = file.read_exact_at(buf, Header::DATA_OFFSET + start).await;
    let _ = file.close().await;
    res.map_err(|e| internal(&bucket, &key, "get_range", format!("read data: {e}")))?;
    Ok(Bytes::from(buf))
}

async fn do_delete(
    obj_path: PathBuf,
    lock_path: PathBuf,
    bucket: String,
    key: String,
) -> Result<Object, Error> {
    check_not_locked(&lock_path, &bucket, &key).await?;
    let (file, header) = open_and_read_header(&obj_path, &bucket, &key, "delete").await?;

    let data_len = header.data_len as usize;
    let buf = vec![0u8; data_len];
    let (res, buf) = file.read_exact_at(buf, Header::DATA_OFFSET).await;
    let _ = file.close().await;
    res.map_err(|e| internal(&bucket, &key, "delete", format!("read data: {e}")))?;

    if let Err(e) = tokio_uring::fs::remove_file(&obj_path).await {
        return Err(internal(&bucket, &key, "delete", format!("unlink: {e}")));
    }
    Ok(Object::new(Bytes::from(buf)))
}

#[allow(clippy::too_many_arguments)] // small-object handler, kept flat on purpose
async fn do_put(
    obj_path: PathBuf,
    tmp_path: PathBuf,
    lock_path: PathBuf,
    bucket: String,
    key: String,
    url_path: String,
    payload: Bytes,
    labels: BTreeMap<String, String>,
) -> Result<(bool, Metadata), Error> {
    if let Some(parent) = obj_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| internal(&bucket, &key, "put", format!("mkdir: {e}")))?;
    }

    let _lock = acquire_lock(lock_path, &bucket, &key).await?;

    // Detect overwrite by looking up the existing object header, which also
    // gives us its prior `created` timestamp for preservation.
    let (is_overwrite, prior_created) = match File::open(&obj_path).await {
        Ok(file) => {
            let prior = read_existing_created(&file).await;
            let _ = file.close().await;
            (true, prior)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (false, None),
        Err(e) => return Err(internal(&bucket, &key, "put", format!("stat existing: {e}"))),
    };

    // Stream the checksums chunk-by-chunk. For the buffered small-object
    // path the payload is already resident, so the streaming pattern is here
    // mainly to mirror the large-object path (step 5) and keep the hashers
    // wired the same way regardless of size.
    const HASH_CHUNK: usize = 1024 * 1024;
    let mut md5_hasher = md5::Md5::new();
    let mut sha_hasher = sha2::Sha256::new();
    for chunk in payload.chunks(HASH_CHUNK) {
        md5_hasher.update(chunk);
        sha_hasher.update(chunk);
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let checksum_md5 = b64.encode(md5_hasher.finalize());
    let checksum_sha256 = b64.encode(sha_hasher.finalize());

    let now = now_nanos();
    let created = prior_created.unwrap_or(now);
    let metadata = Metadata {
        created,
        modified: now,
        size: payload.len() as u64,
        checksum_md5,
        checksum_sha256,
        bucket: bucket.clone(),
        key: key.clone(),
        disk_path: obj_path.clone(),
        url_path,
        labels,
    };

    let meta_bytes = serde_json::to_vec(&metadata)
        .map_err(|e| internal(&bucket, &key, "put", format!("encode meta: {e}")))?;

    let header = Header {
        data_len: payload.len() as u64,
        meta_len: meta_bytes.len() as u32,
        flags: format::flags::DURABLE,
        version: format::VERSION,
    };
    let header_bytes = header.encode().to_vec();
    let trailer_bytes = header.encode().to_vec();

    // Write [header | data | meta | trailer] as four positioned writes into
    // a freshly-truncated tmp file. Each call submits via io_uring.
    let tmp = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)
        .await
        .map_err(|e| internal(&bucket, &key, "put", format!("open tmp: {e}")))?;

    let (res, _) = tmp.write_all_at(header_bytes, 0).await;
    res.map_err(|e| internal(&bucket, &key, "put", format!("write header: {e}")))?;
    // For step 4 we copy the payload into an owned Vec; the zero-copy
    // registered-buffer path lands with the O_DIRECT step.
    let (res, _) = tmp.write_all_at(payload.to_vec(), Header::DATA_OFFSET).await;
    res.map_err(|e| internal(&bucket, &key, "put", format!("write data: {e}")))?;
    let (res, _) = tmp.write_all_at(meta_bytes, header.meta_offset()).await;
    res.map_err(|e| internal(&bucket, &key, "put", format!("write meta: {e}")))?;
    let (res, _) = tmp.write_all_at(trailer_bytes, header.trailer_offset()).await;
    res.map_err(|e| internal(&bucket, &key, "put", format!("write trailer: {e}")))?;

    tmp.sync_data()
        .await
        .map_err(|e| internal(&bucket, &key, "put", format!("fdatasync: {e}")))?;
    let _ = tmp.close().await;

    tokio_uring::fs::rename(&tmp_path, &obj_path)
        .await
        .map_err(|e| internal(&bucket, &key, "put", format!("rename: {e}")))?;

    // fsync the parent directory so the new dirent entry is durable. tokio-uring
    // can open directories but doesn't expose a directory-only sync method;
    // a synchronous fsync on a freshly opened std::fs::File is the simplest
    // portable option and runs in ~tens of microseconds on NVMe.
    if let Some(parent) = obj_path.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }

    Ok((is_overwrite, metadata))
}

/// Read the `created` timestamp from an existing object by parsing its
/// header + metadata blob. Returns `None` if anything is unreadable; the
/// caller falls back to "now" in that case.
async fn read_existing_created(file: &File) -> Option<u64> {
    let buf = vec![0u8; HEADER_SIZE];
    let (res, buf) = file.read_exact_at(buf, 0).await;
    res.ok()?;
    let header_bytes: [u8; HEADER_SIZE] = buf.as_slice().try_into().ok()?;
    let header = Header::decode(&header_bytes).ok()?;
    let meta_buf = vec![0u8; header.meta_len as usize];
    let (res, meta_buf) = file.read_exact_at(meta_buf, header.meta_offset()).await;
    res.ok()?;
    let m: Metadata = serde_json::from_slice(&meta_buf).ok()?;
    Some(m.created)
}
