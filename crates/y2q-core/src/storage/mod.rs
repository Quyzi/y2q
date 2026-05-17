//! Storage backends, metadata index, and write-lock management.
//!
//! - [`any`] — [`AnyStorage`] dispatcher that selects the active backend at runtime.
//! - [`filesystem`] — portable tokio::fs-based backend.
//! - [`format`] — shared on-disk `.obj` file format (header, trailer, flags).
//! - [`index`] — redb-backed secondary metadata index for fast listing.
//! - [`locks`] — stale write-lock scan and removal utilities.
//! - [`uring`] — Linux-only io_uring fast-path backend (feature-gated).

pub mod any;
/// Portable tokio::fs-based storage backend.
pub mod filesystem;
/// Shared on-disk `.obj` single-file format used by both storage backends.
pub mod format;
pub mod index;
pub mod locks;

#[cfg(all(target_os = "linux", feature = "uring"))]
pub mod uring;
