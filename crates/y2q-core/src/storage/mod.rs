//! Storage backends, metadata index, and write-lock management.
//!
//! - [`any`] — [`AnyStorage`] dispatcher that selects the active backend at runtime.
//! - [`filesystem`] — portable tokio::fs-based backend.
//! - [`index`] — redb-backed secondary metadata index for fast listing.
//! - [`locks`] — stale write-lock scan and removal utilities.
//! - [`uring`] — Linux-only io_uring fast-path backend (feature-gated).

pub mod any;
/// Portable tokio::fs-based storage backend.
pub mod filesystem;
pub mod index;
pub mod locks;

#[cfg(all(target_os = "linux", feature = "uring"))]
pub mod uring;
