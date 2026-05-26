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

pub use encrypted_backend::EncryptedFileBackend;
pub mod locks;
pub mod streaming_sink;

#[cfg(target_os = "linux")]
pub mod uring;
