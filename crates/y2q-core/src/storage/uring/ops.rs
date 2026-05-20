//! Typed operation envelopes sent from the actix-web side to the
//! `tokio-uring` worker pool, plus their worker-side handlers.
//!
//! Each variant carries the inputs needed to execute the op on the worker,
//! plus a `tokio::sync::oneshot::Sender` for the reply. The worker pulls an
//! op off its queue, runs the matching handler inside the uring runtime,
//! then signals completion through the oneshot.
//!
//! The PUT handler dispatches between a buffered path and an `O_DIRECT`
//! large-object path based on payload size; see [`do_put`] for the split.
//! Read paths (get / get_range / describe / delete) honour the decoded
//! header's `data_offset` so they work for both layouts transparently.

use core::range::RangeInclusive;
use std::{
    collections::BTreeMap,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use bytes::Bytes;
use sha2::Digest;
use tokio::sync::oneshot;
use tokio_uring::fs::{File, OpenOptions};

use crate::{
    Error, Metadata, Object, SyncLevel,
    crypto::{decrypt_meta, encrypt_meta},
    storage::locks::LockRegistry,
};

use super::{
    buffer::{AlignedBuf, DIRECT_IO_ALIGN, DIRECT_IO_CHUNK},
    format::{self, HEADER_SIZE, Header},
};

/// Bundle of encryption-side fields handed to a PUT worker, boxed so that
/// adding them to [`UringOp::Put`] doesn't blow up the enum variant size.
pub(super) struct PutCryptoFields {
    pub plaintext_metrics: crate::PlaintextMetrics,
    pub cipher_metadata: crate::CipherMetadata,
}

/// One unit of work submitted to a uring worker.
pub(super) enum UringOp {
    /// Read the full object payload.
    Get {
        obj_path: PathBuf,
        locks: LockRegistry,
        bucket: String,
        key: String,
        reply: oneshot::Sender<Result<Object, Error>>,
    },
    /// Read a byte range of the object payload.
    GetRange {
        obj_path: PathBuf,
        locks: LockRegistry,
        bucket: String,
        key: String,
        range: RangeInclusive<u64>,
        reply: oneshot::Sender<Result<Bytes, Error>>,
    },
    /// Write a new object using the temp-file + atomic-rename pattern.
    Put {
        obj_path: PathBuf,
        tmp_path: PathBuf,
        locks: LockRegistry,
        bucket: String,
        key: String,
        url_path: String,
        payload: Bytes,
        labels: BTreeMap<String, String>,
        /// Encryption-side fields supplied by the daemon when it has
        /// already encrypted the body before this PUT. Boxed to keep the
        /// enum variant size in check (clippy::large_enum_variant).
        crypto: Option<Box<PutCryptoFields>>,
        /// Threshold at or above which the worker uses the `O_DIRECT` path.
        /// `0` disables the threshold (always buffered).
        large_object_bytes: u64,
        /// Whether to fdatasync + fsync the parent dir before returning.
        sync: SyncLevel,
        /// Metadata Encryption Key. When set, the metadata JSON blob is
        /// encrypted before being written to the `.obj` file.
        mek: Option<[u8; 32]>,
        reply: oneshot::Sender<Result<(bool, Metadata), Error>>,
    },
    /// Read the object, then unlink it. Returns the deleted bytes.
    Delete {
        obj_path: PathBuf,
        locks: LockRegistry,
        bucket: String,
        key: String,
        reply: oneshot::Sender<Result<Object, Error>>,
    },
    /// Read and decode just the metadata blob.
    Describe {
        obj_path: PathBuf,
        locks: LockRegistry,
        bucket: String,
        key: String,
        /// Metadata Encryption Key for decrypting the embedded metadata blob.
        mek: Option<[u8; 32]>,
        reply: oneshot::Sender<Result<Metadata, Error>>,
    },
    /// Read the on-disk metadata for an object given its file path, without
    /// resolving a `(bucket, key)` first. Used by [`rebuild_cache`] to
    /// repopulate the secondary index from the source-of-truth `.obj` files.
    ///
    /// Unlike [`Describe`], no `.lock` check is performed: rebuild is allowed
    /// to read concurrently with PUTs because `.obj` files are always whole
    /// (writes happen to `.tmp` then rename).
    ///
    /// [`rebuild_cache`]: crate::StorageExt::rebuild_cache
    ReadObjectMeta {
        path: PathBuf,
        /// Metadata Encryption Key for decrypting the embedded metadata blob.
        mek: Option<[u8; 32]>,
        reply: oneshot::Sender<Result<Metadata, Error>>,
    },
}

/// Dispatch one op to its handler. Called from the worker's recv loop.
pub(super) async fn handle(op: UringOp) {
    match op {
        UringOp::Get {
            obj_path,
            locks,
            bucket,
            key,
            reply,
        } => {
            let _ = reply.send(do_get(obj_path, locks, bucket, key).await);
        }
        UringOp::GetRange {
            obj_path,
            locks,
            bucket,
            key,
            range,
            reply,
        } => {
            let _ = reply.send(do_get_range(obj_path, locks, bucket, key, range).await);
        }
        UringOp::Put {
            obj_path,
            tmp_path,
            locks,
            bucket,
            key,
            url_path,
            payload,
            labels,
            crypto,
            large_object_bytes,
            sync,
            mek,
            reply,
        } => {
            let (plaintext_metrics, cipher_metadata) = match crypto {
                Some(b) => (Some(b.plaintext_metrics), Some(b.cipher_metadata)),
                None => (None, None),
            };
            let _ = reply.send(
                do_put(
                    obj_path,
                    tmp_path,
                    locks,
                    bucket,
                    key,
                    url_path,
                    payload,
                    labels,
                    plaintext_metrics,
                    cipher_metadata,
                    large_object_bytes,
                    sync,
                    mek,
                )
                .await,
            );
        }
        UringOp::Delete {
            obj_path,
            locks,
            bucket,
            key,
            reply,
        } => {
            let _ = reply.send(do_delete(obj_path, locks, bucket, key).await);
        }
        UringOp::Describe {
            obj_path,
            locks,
            bucket,
            key,
            mek,
            reply,
        } => {
            let _ = reply.send(do_describe(obj_path, locks, bucket, key, mek).await);
        }
        UringOp::ReadObjectMeta { path, mek, reply } => {
            let _ = reply.send(do_read_object_meta(path, mek).await);
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
            return Err(internal(
                bucket,
                key,
                op_name,
                format!("decode header: {e}"),
            ));
        }
    };
    Ok((file, header))
}

/// Read the metadata blob from an already-opened object, given its decoded
/// header. Decrypts with `mek` if the blob carries the 0x01 version prefix.
async fn read_meta_blob(
    file: &File,
    header: &Header,
    bucket: &str,
    key: &str,
    op_name: &str,
    mek: Option<&[u8; 32]>,
) -> Result<Metadata, Error> {
    let buf = vec![0u8; header.meta_len as usize];
    let (res, buf) = file.read_exact_at(buf, header.meta_offset()).await;
    res.map_err(|e| internal(bucket, key, op_name, format!("read meta: {e}")))?;
    let json = if let Some(mek) = mek {
        decrypt_meta(mek, &buf)
            .map_err(|e| internal(bucket, key, op_name, format!("decrypt meta: {e}")))?
    } else {
        buf
    };
    serde_json::from_slice(&json)
        .map_err(|e| internal(bucket, key, op_name, format!("decode meta: {e}")))
}

// ───── operation handlers ────────────────────────────────────────────────────

async fn do_describe(
    obj_path: PathBuf,
    locks: LockRegistry,
    bucket: String,
    key: String,
    mek: Option<[u8; 32]>,
) -> Result<Metadata, Error> {
    locks.check_not_locked(&bucket, &key)?;
    let (file, header) = open_and_read_header(&obj_path, &bucket, &key, "describe").await?;
    let meta = read_meta_blob(&file, &header, &bucket, &key, "describe", mek.as_ref()).await;
    let _ = file.close().await;
    meta
}

/// Read just the metadata for the `.obj` file at `path` — no lock check, no
/// bucket/key validation. Used by the rebuild walker, which has thousands
/// of paths to process and identifies each object by the metadata embedded
/// in the file itself.
async fn do_read_object_meta(path: PathBuf, mek: Option<[u8; 32]>) -> Result<Metadata, Error> {
    let make_err = |msg: String| Error::InternalError {
        bucket: String::new(),
        key: String::new(),
        operation: "rebuild".to_owned(),
        message: format!("{}: {}", path.display(), msg),
    };

    let file = File::open(&path)
        .await
        .map_err(|e| make_err(format!("open: {e}")))?;
    let buf = vec![0u8; HEADER_SIZE];
    let (res, buf) = file.read_exact_at(buf, 0).await;
    if let Err(e) = res {
        let _ = file.close().await;
        return Err(make_err(format!("read header: {e}")));
    }
    let header_bytes: [u8; HEADER_SIZE] = buf.as_slice().try_into().expect("HEADER_SIZE buffer");
    let header = match Header::decode(&header_bytes) {
        Ok(h) => h,
        Err(e) => {
            let _ = file.close().await;
            return Err(make_err(format!("decode header: {e}")));
        }
    };
    let meta_buf = vec![0u8; header.meta_len as usize];
    let (res, meta_buf) = file.read_exact_at(meta_buf, header.meta_offset()).await;
    let _ = file.close().await;
    res.map_err(|e| make_err(format!("read meta: {e}")))?;
    let json = if let Some(ref mek) = mek {
        decrypt_meta(mek, &meta_buf).map_err(|e| make_err(format!("decrypt meta: {e}")))?
    } else {
        meta_buf
    };
    serde_json::from_slice(&json).map_err(|e| make_err(format!("decode meta: {e}")))
}

async fn do_get(
    obj_path: PathBuf,
    locks: LockRegistry,
    bucket: String,
    key: String,
) -> Result<Object, Error> {
    locks.check_not_locked(&bucket, &key)?;
    let (file, header) = open_and_read_header(&obj_path, &bucket, &key, "get").await?;

    let data_len = header.data_len as usize;
    let buf = vec![0u8; data_len];
    let (res, buf) = file.read_exact_at(buf, header.data_offset as u64).await;
    let _ = file.close().await;
    res.map_err(|e| internal(&bucket, &key, "get", format!("read data: {e}")))?;
    Ok(Object::new(Bytes::from(buf)))
}

async fn do_get_range(
    obj_path: PathBuf,
    locks: LockRegistry,
    bucket: String,
    key: String,
    range: RangeInclusive<u64>,
) -> Result<Bytes, Error> {
    locks.check_not_locked(&bucket, &key)?;
    let (file, header) = open_and_read_header(&obj_path, &bucket, &key, "get_range").await?;

    if header.data_len == 0 || range.start >= header.data_len {
        let _ = file.close().await;
        return Ok(Bytes::new());
    }
    let start = range.start;
    let end_inclusive = range.last.min(header.data_len - 1);
    let len = (end_inclusive - start + 1) as usize;
    let buf = vec![0u8; len];
    let (res, buf) = file
        .read_exact_at(buf, header.data_offset as u64 + start)
        .await;
    let _ = file.close().await;
    res.map_err(|e| internal(&bucket, &key, "get_range", format!("read data: {e}")))?;
    Ok(Bytes::from(buf))
}

async fn do_delete(
    obj_path: PathBuf,
    locks: LockRegistry,
    bucket: String,
    key: String,
) -> Result<Object, Error> {
    locks.check_not_locked(&bucket, &key)?;
    let (file, header) = open_and_read_header(&obj_path, &bucket, &key, "delete").await?;

    let data_len = header.data_len as usize;
    let buf = vec![0u8; data_len];
    let (res, buf) = file.read_exact_at(buf, header.data_offset as u64).await;
    let _ = file.close().await;
    res.map_err(|e| internal(&bucket, &key, "delete", format!("read data: {e}")))?;

    if let Err(e) = tokio_uring::fs::remove_file(&obj_path).await {
        return Err(internal(&bucket, &key, "delete", format!("unlink: {e}")));
    }
    Ok(Object::new(Bytes::from(buf)))
}

#[allow(clippy::too_many_arguments)]
async fn do_put(
    obj_path: PathBuf,
    tmp_path: PathBuf,
    locks: LockRegistry,
    bucket: String,
    key: String,
    url_path: String,
    payload: Bytes,
    labels: BTreeMap<String, String>,
    plaintext_metrics: Option<crate::PlaintextMetrics>,
    cipher_metadata: Option<crate::CipherMetadata>,
    large_object_bytes: u64,
    sync: SyncLevel,
    mek: Option<[u8; 32]>,
) -> Result<(bool, Metadata), Error> {
    if let Some(parent) = obj_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| internal(&bucket, &key, "put", format!("mkdir: {e}")))?;
    }

    let _lock = locks.try_acquire(&bucket, &key)?;

    // Detect overwrite by looking up the existing object header, which also
    // gives us its prior `created` timestamp for preservation.
    let (is_overwrite, prior_created) = match File::open(&obj_path).await {
        Ok(file) => {
            let prior = read_existing_created(&file, mek.as_ref()).await;
            let _ = file.close().await;
            (true, prior)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (false, None),
        Err(e) => {
            return Err(internal(
                &bucket,
                &key,
                "put",
                format!("stat existing: {e}"),
            ));
        }
    };

    // When the daemon supplied plaintext-derived size + checksums, persist
    // those instead of values computed from the (possibly encrypted) bytes
    // we're about to write to disk.
    let (size, checksum_md5, checksum_sha256) = match plaintext_metrics {
        Some(p) => (p.size, p.checksum_md5_b64, p.checksum_sha256_b64),
        None => {
            // Stream the checksums chunk-by-chunk. Memory is the same as a
            // single hash call (the payload is already resident here), but
            // the streaming shape mirrors how the O_DIRECT path consumes
            // the buffer in chunks.
            const HASH_CHUNK: usize = 1024 * 1024;
            let mut md5_hasher = md5::Md5::new();
            let mut sha_hasher = sha2::Sha256::new();
            for chunk in payload.chunks(HASH_CHUNK) {
                md5_hasher.update(chunk);
                sha_hasher.update(chunk);
            }
            let b64 = base64::engine::general_purpose::STANDARD;
            (
                payload.len() as u64,
                b64.encode(md5_hasher.finalize()),
                b64.encode(sha_hasher.finalize()),
            )
        }
    };
    let (cipher_size, cipher_sha256, kem_alg, aead_alg, envelope_version) = match cipher_metadata {
        Some(c) => (
            Some(c.cipher_size),
            Some(c.cipher_sha256_b64),
            Some(c.kem_alg),
            Some(c.aead_alg),
            Some(c.envelope_version),
        ),
        None => (None, None, None, None, None),
    };

    let now = now_nanos();
    let created = prior_created.unwrap_or(now);
    let mut metadata = Metadata {
        created,
        modified: now,
        size,
        checksum_md5,
        checksum_sha256,
        bucket: bucket.clone(),
        key: key.clone(),
        disk_path: obj_path.clone(),
        url_path,
        labels,
        cipher_size,
        cipher_sha256,
        kem_alg,
        aead_alg,
        envelope_version,
    };

    let meta_json = serde_json::to_vec(&metadata)
        .map_err(|e| internal(&bucket, &key, "put", format!("encode meta: {e}")))?;
    let meta_bytes = if let Some(ref mek) = mek {
        encrypt_meta(mek, &meta_json)
            .map_err(|e| internal(&bucket, &key, "put", format!("encrypt meta: {e}")))?
    } else {
        meta_json
    };

    let use_direct = large_object_bytes > 0 && payload.len() as u64 >= large_object_bytes;
    if use_direct {
        match put_via_direct(
            &obj_path,
            &tmp_path,
            &bucket,
            &key,
            &payload,
            &meta_bytes,
            sync,
        )
        .await
        {
            Ok(true) => return Ok((is_overwrite, metadata)),
            Ok(false) => {
                tracing::warn!(
                    bucket = %bucket,
                    key = %key,
                    "O_DIRECT not supported on this filesystem; falling back to buffered path"
                );
            }
            Err(e) => return Err(e),
        }
        // Mark the metadata so a future re-PUT (or `rebuild_cache`) can see
        // the fallback happened. Cheap; this branch is rare.
        metadata
            .labels
            .insert("y2q.direct_io".to_owned(), "fallback".to_owned());
    }

    put_via_buffered(
        &obj_path,
        &tmp_path,
        &bucket,
        &key,
        &payload,
        &meta_bytes,
        sync,
    )
    .await?;
    Ok((is_overwrite, metadata))
}

/// Buffered write path: one fd, four positioned writes, optional fdatasync,
/// rename, optional dir-fsync. Uses [`Header::MIN_DATA_OFFSET`], no padding.
async fn put_via_buffered(
    obj_path: &Path,
    tmp_path: &Path,
    bucket: &str,
    key: &str,
    payload: &Bytes,
    meta_bytes: &[u8],
    sync: SyncLevel,
) -> Result<(), Error> {
    let mut header_flags = 0u16;
    if sync == SyncLevel::Durable {
        header_flags |= format::flags::DURABLE;
    }
    let header = Header {
        data_len: payload.len() as u64,
        meta_len: meta_bytes.len() as u32,
        data_offset: Header::MIN_DATA_OFFSET,
        flags: header_flags,
        version: format::VERSION,
    };
    let header_bytes = header.encode().to_vec();
    let trailer_bytes = header.encode().to_vec();

    let tmp = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(tmp_path)
        .await
        .map_err(|e| internal(bucket, key, "put", format!("open tmp: {e}")))?;

    let (res, _) = tmp.write_all_at(header_bytes, 0).await;
    res.map_err(|e| internal(bucket, key, "put", format!("write header: {e}")))?;
    let (res, _) = tmp
        .write_all_at(payload.to_vec(), header.data_offset as u64)
        .await;
    res.map_err(|e| internal(bucket, key, "put", format!("write data: {e}")))?;
    let (res, _) = tmp
        .write_all_at(meta_bytes.to_vec(), header.meta_offset())
        .await;
    res.map_err(|e| internal(bucket, key, "put", format!("write meta: {e}")))?;
    let (res, _) = tmp
        .write_all_at(trailer_bytes, header.trailer_offset())
        .await;
    res.map_err(|e| internal(bucket, key, "put", format!("write trailer: {e}")))?;

    if sync == SyncLevel::Durable {
        tmp.sync_data()
            .await
            .map_err(|e| internal(bucket, key, "put", format!("fdatasync: {e}")))?;
    }
    let _ = tmp.close().await;

    finalize_rename_and_dir_fsync(tmp_path, obj_path, bucket, key, sync).await
}

/// `O_DIRECT` write path:
///   - two fds to the same tmp file (one with `O_DIRECT`, one without)
///   - 4 KiB-padded layout (`data_offset = 4096`)
///   - aligned bulk of data goes through the `O_DIRECT` fd in 1 MiB chunks
///   - header, non-aligned data tail, meta, trailer go through the
///     buffered fd
///   - single fdatasync covers both fds (same inode)
///
/// Returns `Ok(true)` if the path completed successfully, `Ok(false)` if
/// the underlying filesystem doesn't support `O_DIRECT` and the caller
/// should fall back to the buffered path. Other I/O errors propagate as
/// `Err`.
async fn put_via_direct(
    obj_path: &Path,
    tmp_path: &Path,
    bucket: &str,
    key: &str,
    payload: &Bytes,
    meta_bytes: &[u8],
    sync: SyncLevel,
) -> Result<bool, Error> {
    // Try the O_DIRECT open first so the EINVAL case has zero cleanup. If
    // it succeeds it has also created and truncated the tmp file, so the
    // buffered fd that follows just opens-without-create.
    let probe = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_DIRECT)
        .open(tmp_path)
        .await;
    let fd_direct = match probe {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => return Ok(false),
        Err(e) => return Err(internal(bucket, key, "put", format!("open O_DIRECT: {e}"))),
    };
    let fd_buffered = match OpenOptions::new().write(true).open(tmp_path).await {
        Ok(f) => f,
        Err(e) => {
            let _ = fd_direct.close().await;
            let _ = tokio_uring::fs::remove_file(tmp_path).await;
            return Err(internal(
                bucket,
                key,
                "put",
                format!("open buffered fd: {e}"),
            ));
        }
    };

    let data_offset = format::MIN_DIRECT_DATA_OFFSET;
    let mut header_flags = format::flags::WRITTEN_O_DIRECT;
    if sync == SyncLevel::Durable {
        header_flags |= format::flags::DURABLE;
    }
    let header = Header {
        data_len: payload.len() as u64,
        meta_len: meta_bytes.len() as u32,
        data_offset,
        flags: header_flags,
        version: format::VERSION,
    };
    let header_bytes = header.encode().to_vec();
    let trailer_bytes = header.encode().to_vec();

    // Header at offset 0 — buffered (the kernel will leave [64, 4096) as a
    // sparse hole; reads of that range return zero, which is what we want).
    let (res, _) = fd_buffered.write_all_at(header_bytes, 0).await;
    if let Err(e) = res {
        cleanup_direct_failure(fd_direct, fd_buffered, tmp_path).await;
        return Err(internal(bucket, key, "put", format!("write header: {e}")));
    }

    // Aligned bulk via O_DIRECT in DIRECT_IO_CHUNK-sized chunks.
    let data_len = payload.len() as u64;
    let aligned_bulk_bytes = (data_len / DIRECT_IO_ALIGN as u64) * DIRECT_IO_ALIGN as u64;
    let tail_bytes = data_len - aligned_bulk_bytes;

    let mut written: u64 = 0;
    while written < aligned_bulk_bytes {
        let remaining = aligned_bulk_bytes - written;
        let chunk_len = remaining.min(DIRECT_IO_CHUNK as u64) as usize;
        let start = written as usize;
        let buf = AlignedBuf::from_slice(&payload[start..start + chunk_len]);
        let offset = data_offset as u64 + written;
        let (res, _) = fd_direct.write_all_at(buf, offset).await;
        if let Err(e) = res {
            cleanup_direct_failure(fd_direct, fd_buffered, tmp_path).await;
            return Err(internal(
                bucket,
                key,
                "put",
                format!("write data chunk @ {offset}: {e}"),
            ));
        }
        written += chunk_len as u64;
    }

    // Tail: at most DIRECT_IO_ALIGN-1 bytes, written via the buffered fd
    // since its offset and length are not block-aligned.
    if tail_bytes > 0 {
        let start = aligned_bulk_bytes as usize;
        let tail_vec = payload[start..].to_vec();
        let tail_offset = data_offset as u64 + aligned_bulk_bytes;
        let (res, _) = fd_buffered.write_all_at(tail_vec, tail_offset).await;
        if let Err(e) = res {
            cleanup_direct_failure(fd_direct, fd_buffered, tmp_path).await;
            return Err(internal(
                bucket,
                key,
                "put",
                format!("write data tail: {e}"),
            ));
        }
    }

    // Meta + trailer via the buffered fd.
    let (res, _) = fd_buffered
        .write_all_at(meta_bytes.to_vec(), header.meta_offset())
        .await;
    if let Err(e) = res {
        cleanup_direct_failure(fd_direct, fd_buffered, tmp_path).await;
        return Err(internal(bucket, key, "put", format!("write meta: {e}")));
    }
    let (res, _) = fd_buffered
        .write_all_at(trailer_bytes, header.trailer_offset())
        .await;
    if let Err(e) = res {
        cleanup_direct_failure(fd_direct, fd_buffered, tmp_path).await;
        return Err(internal(bucket, key, "put", format!("write trailer: {e}")));
    }

    // Single fdatasync (when Durable) — both fds point at the same inode,
    // so this flushes the data and size metadata for everything written via
    // either fd plus any in-flight O_DIRECT submissions.
    if sync == SyncLevel::Durable
        && let Err(e) = fd_buffered.sync_data().await
    {
        cleanup_direct_failure(fd_direct, fd_buffered, tmp_path).await;
        return Err(internal(bucket, key, "put", format!("fdatasync: {e}")));
    }
    let _ = fd_direct.close().await;
    let _ = fd_buffered.close().await;

    finalize_rename_and_dir_fsync(tmp_path, obj_path, bucket, key, sync).await?;
    Ok(true)
}

/// Close both fds and unlink the tmp file on error so we don't leak
/// partial writes between PUT attempts.
async fn cleanup_direct_failure(fd_direct: File, fd_buffered: File, tmp_path: &Path) {
    let _ = fd_direct.close().await;
    let _ = fd_buffered.close().await;
    let _ = tokio_uring::fs::remove_file(tmp_path).await;
}

/// Atomically replace the destination object with the tmp file, then —
/// when [`SyncLevel::Durable`] — fsync the parent directory so the dirent
/// change survives a power loss.
///
/// tokio-uring can open directories but doesn't expose a directory-only
/// sync method, so we use a synchronous `fsync` on a freshly opened
/// `std::fs::File` — a single syscall, ~tens of microseconds on NVMe.
async fn finalize_rename_and_dir_fsync(
    tmp_path: &Path,
    obj_path: &Path,
    bucket: &str,
    key: &str,
    sync: SyncLevel,
) -> Result<(), Error> {
    tokio_uring::fs::rename(tmp_path, obj_path)
        .await
        .map_err(|e| internal(bucket, key, "put", format!("rename: {e}")))?;

    if sync == SyncLevel::Durable
        && let Some(parent) = obj_path.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Read the `created` timestamp from an existing object by parsing its
/// header + metadata blob. Returns `None` if anything is unreadable; the
/// caller falls back to "now" in that case.
async fn read_existing_created(file: &File, mek: Option<&[u8; 32]>) -> Option<u64> {
    let buf = vec![0u8; HEADER_SIZE];
    let (res, buf) = file.read_exact_at(buf, 0).await;
    res.ok()?;
    let header_bytes: [u8; HEADER_SIZE] = buf.as_slice().try_into().ok()?;
    let header = Header::decode(&header_bytes).ok()?;
    let meta_buf = vec![0u8; header.meta_len as usize];
    let (res, meta_buf) = file.read_exact_at(meta_buf, header.meta_offset()).await;
    res.ok()?;
    let json = if let Some(mek) = mek {
        decrypt_meta(mek, &meta_buf).ok()?
    } else {
        meta_buf
    };
    let m: Metadata = serde_json::from_slice(&json).ok()?;
    Some(m.created)
}
