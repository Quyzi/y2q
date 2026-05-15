//! io_uring-backed [`Storage`](crate::Storage) implementation.
//!
//! Linux-only fast path. Gated behind the `uring` cargo feature and
//! `#[cfg(target_os = "linux")]` at the module level, so non-Linux targets
//! never see this code.
//!
//! The backend lives alongside [`FilesystemStorage`](crate::FilesystemStorage);
//! daemons select one at startup via configuration. See the design notes in
//! `plans/how-would-i-optimize-greedy-forest.md` for the on-disk format,
//! runtime bridge, and size-tiered I/O strategy.

mod buffer;
mod format;
mod ops;
mod runtime;
mod storage;
mod streaming;

pub use storage::{UringConfig, UringStorage};
pub use streaming::{UringStreamingPutGuard, URING_STREAMING_WRITE_OFFSET};
