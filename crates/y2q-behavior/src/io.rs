//! Low-level async file-I/O sink.

use async_trait::async_trait;

/// Backend-agnostic async write target for object payloads.
///
/// Abstracts the write side of the streaming-put path so the encryptor and the
/// storage backend share one contract regardless of whether the underlying sink
/// is a buffered file handle or a kernel-offloaded (`io_uring`) writer. Supports
/// both sequential appends and positioned writes, since the on-disk object
/// reserves a fixed header region that is written after the body.
#[async_trait]
pub trait AsyncSink: Send {
    /// Write all of `bytes` at the current cursor, advancing the cursor past them.
    async fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()>;

    /// Write all of `bytes` starting at absolute `offset`, leaving the cursor
    /// unchanged. Used to back-fill the reserved header once the body is known.
    async fn write_all_at(&mut self, bytes: &[u8], offset: u64) -> std::io::Result<()>;

    /// Move the write cursor to absolute `offset`.
    async fn seek(&mut self, offset: u64) -> std::io::Result<()>;

    /// Move the write cursor to the end of the sink, returning the new offset.
    async fn seek_to_end(&mut self) -> std::io::Result<u64>;

    /// Flush written data to durable storage. Flushes file contents only, not
    /// directory or inode metadata.
    async fn sync_data(&mut self) -> std::io::Result<()>;
}
