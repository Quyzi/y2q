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

use bytes::Bytes;

#[cfg(target_os = "linux")]
pub use crate::storage::uring::streaming::UringStreamingWriter;

/// Sink for encrypted chunk writes during streaming PUT.
pub enum StreamingSink {
    /// Backed by a `tokio::fs::File`; writes via tokio's async fs (which uses
    /// `spawn_blocking` under the hood).
    Tokio(tokio::fs::File),
    /// Backed by io_uring via a dedicated worker thread.
    #[cfg(target_os = "linux")]
    Uring(UringStreamingWriter),
    /// CRAQ fan-out: mirror every appended chunk to `local` (a real backend
    /// sink) and forward a copy to `forward`, a bounded channel drained by the
    /// chain-replication task that streams ciphertext to the next chain member.
    ///
    /// Only sequential appends ([`write_all`](StreamingSink::write_all)) are
    /// forwarded: those are exactly the v2 envelope bytes the HEAD produces, in
    /// order. Positioned patches ([`write_all_at`](StreamingSink::write_all_at),
    /// used by `EncryptSession::finish` to backfill `plaintext_len`) and cursor
    /// moves are applied to `local` only; downstream nodes reconstruct that
    /// patch from a header carried alongside the PREPARE. The channel is bounded
    /// so a slow downstream blocks the HEAD's encrypt loop rather than letting it
    /// buffer the whole object (the backpressure invariant that keeps multi-GiB
    /// PUTs from OOMing).
    Tee {
        /// The real backend sink this node writes its own copy to.
        local: Box<StreamingSink>,
        /// Bounded forward channel; each appended chunk is copied here.
        forward: tokio::sync::mpsc::Sender<Bytes>,
    },
}

impl StreamingSink {
    /// Append `bytes` at the sink's current write cursor.
    pub async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Tokio(f) => {
                use tokio::io::AsyncWriteExt as _;
                f.write_all(bytes).await
            }
            #[cfg(target_os = "linux")]
            Self::Uring(w) => w.write_all(bytes).await,
            Self::Tee { local, forward } => {
                Box::pin(local.write_all(bytes)).await?;
                // Bounded send: blocks here (and thus the encrypt loop) when the
                // downstream is slow. A closed channel means the forwarding task
                // has died, so surface it as a write failure to abort the PUT.
                forward
                    .send(Bytes::copy_from_slice(bytes))
                    .await
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "chain forward channel closed (downstream replication failed)",
                        )
                    })
            }
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
            #[cfg(target_os = "linux")]
            Self::Uring(w) => w.write_all_at(bytes, offset).await,
            // Positioned patch (e.g. plaintext_len backfill): local only. The
            // downstream applies the equivalent patch from a PREPARE header.
            Self::Tee { local, .. } => Box::pin(local.write_all_at(bytes, offset)).await,
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
            #[cfg(target_os = "linux")]
            Self::Uring(w) => {
                w.set_offset(offset);
                Ok(())
            }
            Self::Tee { local, .. } => Box::pin(local.seek(offset)).await,
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
            #[cfg(target_os = "linux")]
            Self::Uring(w) => {
                let end = w.end_offset();
                w.set_offset(end);
                Ok(end)
            }
            Self::Tee { local, .. } => Box::pin(local.seek_to_end()).await,
        }
    }

    /// `fdatasync` the underlying file.
    pub async fn sync_data(&mut self) -> io::Result<()> {
        match self {
            Self::Tokio(f) => f.sync_data().await,
            #[cfg(target_os = "linux")]
            Self::Uring(w) => w.sync_data().await,
            Self::Tee { local, .. } => Box::pin(local.sync_data()).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

    /// A Tee mirrors sequential appends to the local file and forwards a copy of
    /// each chunk down the channel, in order.
    #[tokio::test]
    async fn tee_forwards_appends_and_writes_local() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .open(tmp.path())
            .await
            .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(8);
        let mut sink = StreamingSink::Tee {
            local: Box::new(StreamingSink::Tokio(file)),
            forward: tx,
        };

        sink.write_all(b"hello ").await.unwrap();
        sink.write_all(b"world").await.unwrap();

        // Drop the sink to close the channel, then drain the forwarded copy.
        drop(sink);
        let mut forwarded = Vec::new();
        while let Some(chunk) = rx.recv().await {
            forwarded.extend_from_slice(&chunk);
        }
        assert_eq!(forwarded, b"hello world");

        let mut local = Vec::new();
        let mut f = tokio::fs::File::open(tmp.path()).await.unwrap();
        f.read_to_end(&mut local).await.unwrap();
        assert_eq!(local, b"hello world");
    }

    /// A positioned patch is applied to the local file only; it is never copied
    /// to the forward channel (downstream reconstructs it from a PREPARE header).
    #[tokio::test]
    async fn tee_does_not_forward_positioned_patch() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .open(tmp.path())
            .await
            .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(8);
        let mut sink = StreamingSink::Tee {
            local: Box::new(StreamingSink::Tokio(file)),
            forward: tx,
        };

        sink.write_all(b"AAAA").await.unwrap();
        sink.write_all_at(b"BB", 1).await.unwrap();
        drop(sink);

        let mut forwarded = Vec::new();
        while let Some(chunk) = rx.recv().await {
            forwarded.extend_from_slice(&chunk);
        }
        // Only the append was forwarded, not the patch.
        assert_eq!(forwarded, b"AAAA");

        let mut local = Vec::new();
        let mut f = tokio::fs::File::open(tmp.path()).await.unwrap();
        f.seek(io::SeekFrom::Start(0)).await.unwrap();
        f.read_to_end(&mut local).await.unwrap();
        assert_eq!(local, b"ABBA");
    }
}
