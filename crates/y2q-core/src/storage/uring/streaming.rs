//! Streaming PUT guard for the io_uring backend.
//!
//! The guard is returned by [`UringStorage::begin_streaming_put`] alongside a
//! `tokio::fs::File` positioned just after the 64-byte `.obj` placeholder
//! header. The caller streams encrypted data through an
//! [`crate::crypto::envelope::EncryptSession`] (writing into that file), then
//! calls [`UringStreamingPutGuard::commit`] to finalise the on-disk record.
//!
//! The data write itself uses ordinary `tokio::fs` (no `O_DIRECT`) because
//! the v2 envelope preamble (1 120 bytes) is not 4 KiB-aligned. The atomic
//! rename and directory fsync at commit time go through the standard syscalls.

use std::{
    io,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_channel::Sender;
use bytes::Bytes;
use tokio::sync::oneshot;

use crate::storage::locks::LockGuard;

use crate::{
    CipherMetadata, Error, Metadata, MetadataIndex, PlaintextMetrics, PutOptions, SyncLevel,
    crypto::encrypt_meta,
};

use super::format::{self, HEADER_SIZE, Header};
use super::ops::UringOp;

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// RAII guard for an in-progress streaming PUT to the uring backend.
///
/// Acquired via [`UringStorage::begin_streaming_put`]. The caller passes data
/// through [`crate::crypto::envelope::EncryptSession`], which writes encrypted
/// bytes directly to the returned `tokio::fs::File` (positioned past the
/// 64-byte `.obj` placeholder header). When all data has been fed, call
/// [`commit`] to write the metadata, real header, and trailer, then rename the
/// tmp file atomically into place.
///
/// Dropping without calling `commit` removes the tmp file and releases the
/// object lock.
pub struct UringStreamingPutGuard {
    pub(super) tmp_path: PathBuf,
    pub(super) obj_path: PathBuf,
    _lock: LockGuard,
    pub(super) bucket: String,
    pub(super) key: String,
    pub(super) is_overwrite: bool,
    pub(super) prior_created: Option<u64>,
    pub(super) mek: Option<[u8; 32]>,
    pub(super) index: Arc<MetadataIndex>,
}

impl UringStreamingPutGuard {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        tmp_path: PathBuf,
        obj_path: PathBuf,
        lock: LockGuard,
        bucket: String,
        key: String,
        is_overwrite: bool,
        prior_created: Option<u64>,
        mek: Option<[u8; 32]>,
        index: Arc<MetadataIndex>,
    ) -> Self {
        Self {
            tmp_path,
            obj_path,
            _lock: lock,
            bucket,
            key,
            is_overwrite,
            prior_created,
            mek,
            index,
        }
    }

    /// Finalise the streaming PUT.
    ///
    /// `writer` must be the [`UringStreamingWriter`] returned by
    /// [`UringStorage::begin_streaming_put`], currently positioned at the end
    /// of the encrypted data (i.e. right after the last byte written by the
    /// encrypt session). This method writes the metadata blob and `.obj`
    /// trailer, overwrites the placeholder header at offset 0 with the real
    /// header, optionally fsyncs, renames the tmp file into place, and
    /// updates the secondary index — all via uring worker ops.
    pub async fn commit(
        self,
        mut writer: UringStreamingWriter,
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
        // Writes require an installed MEK; refuse rather than persisting plaintext.
        let meta_bytes = match self.mek {
            Some(ref mek) => encrypt_meta(mek, &meta_json).map_err(|e| Error::InternalError {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                operation: "put".to_owned(),
                message: format!("encrypt meta: {e}"),
            })?,
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
            // Streaming path always uses the buffered (non-O_DIRECT) layout.
            data_offset: Header::MIN_DATA_OFFSET,
            flags,
            version: format::VERSION,
        };

        let map_io = |stage: &'static str, e: io::Error| Error::InternalError {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            operation: "put".to_owned(),
            message: format!("{stage}: {e}"),
        };

        // Writer cursor is at the end of the encrypted data. Append meta then
        // trailer.
        writer
            .write_all(&meta_bytes)
            .await
            .map_err(|e| map_io("write meta", e))?;
        let trailer = header.encode();
        writer
            .write_all(&trailer)
            .await
            .map_err(|e| map_io("write trailer", e))?;

        // Overwrite the placeholder header at offset 0 with the real one.
        writer
            .write_all_at(&header.encode(), 0)
            .await
            .map_err(|e| map_io("write header", e))?;

        if options.sync == SyncLevel::Durable {
            writer
                .sync_data()
                .await
                .map_err(|e| map_io("fdatasync", e))?;
        }

        writer.rename(self.obj_path.clone(), options.sync).await?;

        if let Err(e) = self.index.upsert(&metadata, options.sync).await {
            tracing::warn!(
                bucket = %bucket,
                key = %key,
                error = %e,
                "streaming put: metadata index upsert failed; on-disk record is authoritative"
            );
        }

        Ok(self.is_overwrite)
    }

    /// Read `len` bytes at absolute file offset `start` from the staged (not yet
    /// committed) tmp file. The cluster HEAD uses this to stream the envelope
    /// down-chain before committing locally (CRAQ tail-first ordering).
    pub async fn read_staged_range(&self, start: u64, len: u64) -> Result<Bytes, Error> {
        crate::storage::filesystem::read_staged_range_from(
            &self.tmp_path,
            &self.bucket,
            &self.key,
            start,
            len,
        )
        .await
    }
}

impl Drop for UringStreamingPutGuard {
    fn drop(&mut self) {
        // No-op if commit already renamed the file; ENOENT is silently ignored.
        let _ = std::fs::remove_file(&self.tmp_path);
    }
}

/// Byte offset within the uring tmp file at which the v2 envelope starts.
///
/// Equals `HEADER_SIZE` (64): the `.obj` header occupies the first 64 bytes.
/// Passed as `write_offset` to [`crate::crypto::envelope::EncryptSession::new`]
/// so `finish()` seeks to the correct position to patch `plaintext_len`.
pub const URING_STREAMING_WRITE_OFFSET: u64 = HEADER_SIZE as u64;

/// Channel-bound writer that funnels streaming-PUT writes through the uring
/// worker thread that owns the `(bucket, key)` shard.
///
/// Each write becomes a [`UringOp::StreamWrite`] dispatched to the worker,
/// which opens the file via `tokio_uring::fs::OpenOptions`, calls
/// `write_all_at`, and closes — all on an io_uring SQE chain, bypassing the
/// tokio blocking thread pool.
///
/// The writer tracks its own `cursor` (next append offset) and `end`
/// (high-water mark) so it can answer `seek_to_end` without an `fstat`.
pub struct UringStreamingWriter {
    tx: Sender<UringOp>,
    path: PathBuf,
    cursor: u64,
    end: u64,
}

impl UringStreamingWriter {
    pub(super) fn new(tx: Sender<UringOp>, path: PathBuf, start_offset: u64) -> Self {
        Self {
            tx,
            path,
            cursor: start_offset,
            end: start_offset,
        }
    }

    /// High-water mark of any byte written so far. Equivalent to the file's
    /// data length, assuming no holes.
    pub fn end_offset(&self) -> u64 {
        self.end
    }

    /// Set the logical write cursor. Subsequent `write_all` calls begin here.
    pub fn set_offset(&mut self, offset: u64) {
        self.cursor = offset;
    }

    /// Append `bytes` at the current cursor; advance cursor by `bytes.len()`.
    pub async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        let offset = self.cursor;
        self.write_all_at(bytes, offset).await
    }

    /// Write `bytes` at `offset`. Cursor moves to `offset + bytes.len()`.
    pub async fn write_all_at(&mut self, bytes: &[u8], offset: u64) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let payload = Bytes::copy_from_slice(bytes);
        let (reply, reply_rx) = oneshot::channel();
        self.tx
            .send(UringOp::StreamWrite {
                path: self.path.clone(),
                offset,
                bytes: payload,
                reply,
            })
            .await
            .map_err(|_| io::Error::other("uring worker channel closed"))?;
        match reply_rx.await {
            Ok(Ok(())) => {
                let end = offset + bytes.len() as u64;
                self.cursor = end;
                if end > self.end {
                    self.end = end;
                }
                Ok(())
            }
            Ok(Err(e)) => Err(io::Error::other(format!("{e}"))),
            Err(_) => Err(io::Error::other("uring worker reply dropped")),
        }
    }

    /// `fdatasync` the underlying tmp file via the worker.
    pub async fn sync_data(&self) -> io::Result<()> {
        let (reply, reply_rx) = oneshot::channel();
        self.tx
            .send(UringOp::StreamSyncData {
                path: self.path.clone(),
                reply,
            })
            .await
            .map_err(|_| io::Error::other("uring worker channel closed"))?;
        match reply_rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(io::Error::other(format!("{e}"))),
            Err(_) => Err(io::Error::other("uring worker reply dropped")),
        }
    }

    /// Rename the tmp file into place via the worker. Honours `sync` for the
    /// optional parent-directory fsync.
    pub(super) async fn rename(self, target: PathBuf, sync: SyncLevel) -> Result<(), Error> {
        let (reply, reply_rx) = oneshot::channel();
        self.tx
            .send(UringOp::StreamRename {
                from: self.path.clone(),
                to: target,
                sync,
                reply,
            })
            .await
            .map_err(|_| Error::InternalError {
                bucket: String::new(),
                key: String::new(),
                operation: "stream_rename".to_owned(),
                message: "worker channel closed".to_owned(),
            })?;
        match reply_rx.await {
            Ok(r) => r,
            Err(_) => Err(Error::InternalError {
                bucket: String::new(),
                key: String::new(),
                operation: "stream_rename".to_owned(),
                message: "worker reply dropped".to_owned(),
            }),
        }
    }
}
