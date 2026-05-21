//! Backend-agnostic write sink used by the streaming-PUT pipeline.
//!
//! [`crate::crypto::envelope::EncryptSession`] writes encrypted chunks through
//! a `StreamingSink` so the same encrypt path serves both backends:
//!
//! - [`StreamingSink::Tokio`] wraps a [`tokio::fs::File`]; writes route through
//!   the tokio blocking thread pool. Used by [`crate::FilesystemStorage`].
//! - [`StreamingSink::Uring`] holds an [`UringStreamingWriter`] that funnels
//!   each write through a uring worker thread, where it issues an `openat /
//!   pwrite / close` SQE chain via [`tokio_uring`]. Used by the uring backend.
//!
//! The `Uring` variant lets the streaming PUT path avoid `spawn_blocking` —
//! the dominant CPU cost in profiles before this abstraction landed.

use std::io;

#[cfg(all(target_os = "linux", feature = "uring"))]
pub use crate::storage::uring::streaming::UringStreamingWriter;

/// Sink for encrypted chunk writes during streaming PUT.
pub enum StreamingSink {
    /// Backed by a `tokio::fs::File`; writes via tokio's async fs (which uses
    /// `spawn_blocking` under the hood).
    Tokio(tokio::fs::File),
    /// Backed by io_uring via a dedicated worker thread.
    #[cfg(all(target_os = "linux", feature = "uring"))]
    Uring(UringStreamingWriter),
}

impl StreamingSink {
    /// Append `bytes` at the sink's current write cursor.
    pub async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Tokio(f) => {
                use tokio::io::AsyncWriteExt as _;
                f.write_all(bytes).await
            }
            #[cfg(all(target_os = "linux", feature = "uring"))]
            Self::Uring(w) => w.write_all(bytes).await,
        }
    }

    /// Write `bytes` at absolute file offset `offset`, leaving the sink's
    /// virtual cursor advanced to `offset + bytes.len()`.
    pub async fn write_all_at(&mut self, bytes: &[u8], offset: u64) -> io::Result<()> {
        match self {
            Self::Tokio(f) => {
                use tokio::io::{AsyncSeekExt as _, AsyncWriteExt as _};
                f.seek(io::SeekFrom::Start(offset)).await?;
                f.write_all(bytes).await?;
                Ok(())
            }
            #[cfg(all(target_os = "linux", feature = "uring"))]
            Self::Uring(w) => w.write_all_at(bytes, offset).await,
        }
    }

    /// Seek the sink's logical cursor to `offset`. Subsequent `write_all`
    /// writes begin at this position.
    pub async fn seek(&mut self, offset: u64) -> io::Result<()> {
        match self {
            Self::Tokio(f) => {
                use tokio::io::AsyncSeekExt as _;
                f.seek(io::SeekFrom::Start(offset)).await?;
                Ok(())
            }
            #[cfg(all(target_os = "linux", feature = "uring"))]
            Self::Uring(w) => {
                w.set_offset(offset);
                Ok(())
            }
        }
    }

    /// Reposition the cursor to the end of the file's current data. Required
    /// after `write_all_at` patches an earlier offset and the caller wants
    /// further appends.
    pub async fn seek_to_end(&mut self) -> io::Result<u64> {
        match self {
            Self::Tokio(f) => {
                use tokio::io::AsyncSeekExt as _;
                f.seek(io::SeekFrom::End(0)).await
            }
            #[cfg(all(target_os = "linux", feature = "uring"))]
            Self::Uring(w) => {
                let end = w.end_offset();
                w.set_offset(end);
                Ok(end)
            }
        }
    }

    /// `fdatasync` the underlying file.
    pub async fn sync_data(&mut self) -> io::Result<()> {
        match self {
            Self::Tokio(f) => f.sync_data().await,
            #[cfg(all(target_os = "linux", feature = "uring"))]
            Self::Uring(w) => w.sync_data().await,
        }
    }
}
