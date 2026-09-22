//! Storage backends, metadata index, and write-lock management.
//!
//! - [`any`] — [`AnyStorage`] dispatcher that selects the active backend at runtime.
//! - [`encrypted_backend`] — whole-file-encrypting [`redb::StorageBackend`] for the index.
//! - [`filesystem`] — portable tokio::fs-based backend.
//! - [`format`] — shared on-disk `.obj` file format (header, trailer, flags).
//! - [`index`] — redb-backed secondary metadata index for fast listing.
//! - [`locks`] — stale write-lock scan and removal utilities.
//! - [`uring`] — Linux-only io_uring fast-path backend (feature-gated).

pub mod any;
pub mod bufpool;
/// Whole-file-encrypting redb storage backend for the metadata index.
pub mod encrypted_backend;
/// Portable tokio::fs-based storage backend.
pub mod filesystem;
/// Shared on-disk `.obj` single-file format used by both storage backends.
pub mod format;
pub mod index;
pub mod locks;
/// Offline node-key rotation across the whole storage tree.
pub mod rotation;
pub mod streaming_sink;

#[cfg(target_os = "linux")]
pub mod uring;

pub use encrypted_backend::{EncryptedFileBackend, ForeignFile};

/// Record how long one phase of a write-path operation took, in milliseconds.
///
/// Complements `y2qd_storage_op_duration_milliseconds` (whole-op) by
/// splitting a PUT or DELETE into its durability barriers and its metadata
/// index commit, so a throughput regression can be attributed to the data
/// path, the filesystem, or the index without re-instrumenting the daemon.
///
/// `phase` is one of `fdatasync`, `dir_fsync`, `unlink`, `index_commit`.
/// For the uring backend `dir_fsync` covers the rename *and* the directory
/// fsync, because they are one worker round trip. Time spent encrypting and
/// streaming the body is not a phase: it is
/// `y2qd_request_duration_milliseconds` minus the phases below.
pub(crate) fn record_write_phase(phase: &'static str, backend: &'static str, elapsed_ms: f64) {
    metrics::histogram!(
        "y2qd_storage_phase_duration_milliseconds",
        "phase" => phase, "backend" => backend
    )
    .record(elapsed_ms);
}
