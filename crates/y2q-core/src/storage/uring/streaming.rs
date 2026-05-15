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
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::{
    CipherMetadata, Error, Metadata, MetadataIndex, PlaintextMetrics, PutOptions, SyncLevel,
    crypto::encrypt_meta,
};

use super::format::{self, Header, HEADER_SIZE};

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Removes a lock file synchronously on drop.
struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
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
    pub(super) fn new(
        tmp_path: PathBuf,
        obj_path: PathBuf,
        lock_path: PathBuf,
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
            _lock: LockGuard { path: lock_path },
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
    /// `file` must be the `tokio::fs::File` returned by
    /// [`UringStorage::begin_streaming_put`], currently positioned at the end
    /// of the encrypted data (i.e. right after the last byte written by the
    /// encrypt session). This method writes the metadata blob and `.obj`
    /// trailer, overwrites the placeholder header at offset 0 with the real
    /// header, optionally fsyncs, renames the tmp file into place, and
    /// updates the secondary index.
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
            // Streaming path always uses the buffered (non-O_DIRECT) layout.
            data_offset: Header::MIN_DATA_OFFSET,
            flags,
            version: format::VERSION,
        };

        // File is at EOF (after v2 envelope). Append meta then trailer.
        file.write_all(&meta_bytes).await.map_err(|e| Error::InternalError {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            operation: "put".to_owned(),
            message: format!("write meta: {e}"),
        })?;
        file.write_all(&header.encode()).await.map_err(|e| Error::InternalError {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            operation: "put".to_owned(),
            message: format!("write trailer: {e}"),
        })?;

        // Overwrite the placeholder header at offset 0 with the real one.
        file.seek(std::io::SeekFrom::Start(0)).await.map_err(|e| Error::InternalError {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            operation: "put".to_owned(),
            message: format!("seek to header: {e}"),
        })?;
        file.write_all(&header.encode()).await.map_err(|e| Error::InternalError {
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

        tokio::fs::rename(&self.tmp_path, &self.obj_path).await.map_err(|e| Error::InternalError {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            operation: "put".to_owned(),
            message: format!("rename: {e}"),
        })?;

        if options.sync == SyncLevel::Durable {
            if let Some(parent) = self.obj_path.parent()
                && let Ok(dir) = std::fs::File::open(parent)
            {
                let _ = dir.sync_all();
            }
        }

        if let Err(e) = self.index.upsert(&metadata).await {
            tracing::warn!(
                bucket = %bucket,
                key = %key,
                error = %e,
                "streaming put: metadata index upsert failed; on-disk record is authoritative"
            );
        }

        Ok(self.is_overwrite)
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
