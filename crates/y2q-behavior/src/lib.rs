//! `y2q-behavior` defines the server-side behavioral contract for `y2q` as a
//! set of traits, with no implementations.
//!
//! The traits formalize the file-I/O, encryption, and metadata-index behavior
//! that currently lives as concrete types and free functions in `y2q-core`.
//! Domain types (objects, metadata, errors, options) are exposed as associated
//! types so this crate stays free of any dependency on `y2q-core`; an
//! implementor supplies the concrete types.
//!
//! Async methods use [`async_trait`] so every trait is dyn-compatible and can be
//! used behind a `Box<dyn ...>` boundary.
//!
//! # Modules
//! - [`io`] - low-level async file-I/O sink.
//! - [`crypto`] - object envelope, streaming encryptor, key derivation,
//!   metadata cipher, and in-memory key slot.
//! - [`storage`] - object store, bucket store, maintenance, and streaming put.
//! - [`index`] - the encrypted metadata index.

pub mod crypto;
pub mod index;
pub mod io;
pub mod storage;
