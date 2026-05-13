//! Aligned-buffer pool for the `O_DIRECT` large-object write path.
//!
//! `O_DIRECT` requires that user buffers, file offsets, and transfer sizes
//! are all aligned to the underlying device's logical block size (4 KiB on
//! every NVMe device shipping today; verify with `statx` at startup). We
//! pool 1 MiB-aligned buffers and register them with the uring instance via
//! `io_uring_register_buffers` for zero-copy submission.
//!
//! Stub for now: real implementation lands with the large-object path.

#![allow(dead_code)] // populated in subsequent steps

/// Required alignment for `O_DIRECT` buffers, offsets, and lengths.
///
/// Matches the logical block size of every NVMe SSD currently sold. If we
/// ever encounter a device that requires more, [`UringStorage`](super::UringStorage)
/// should query `statx`'s `stx_dio_mem_align` field at open time and refuse
/// to enable `O_DIRECT` if it exceeds this constant.
pub const DIRECT_IO_ALIGN: usize = 4 * 1024;

/// Default size of each chunk submitted to uring on the large-object path.
pub const DIRECT_IO_CHUNK: usize = 1024 * 1024;
