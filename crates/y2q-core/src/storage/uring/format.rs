//! On-disk single-file object format for [`UringStorage`](super::UringStorage).
//!
//! Each object is one file laid out as:
//!
//! ```text
//! [ header  64 B ]
//! [ data    N B  ]    where N = header.data_len (u64; no protocol cap)
//! [ meta    M B  ]    JSON-encoded [`crate::Metadata`]
//! [ trailer 64 B ]    bitwise mirror of header for torn-write recovery
//! ```
//!
//! The header and trailer both carry a CRC32 over the rest of the record so
//! we can detect torn writes after a crash and prefer the half that survived.
//! Encoding/decoding lives here; the layout will be exercised by unit tests in
//! a later step.

#![allow(dead_code)] // populated in subsequent steps

/// 4-byte magic prefix identifying this format: `b"Y2QO"` (y2q object).
pub const MAGIC: [u8; 4] = *b"Y2QO";

/// Current header version. Bump on any breaking layout change.
pub const VERSION: u16 = 1;

/// Fixed size of the header (and trailer) record, in bytes.
pub const HEADER_SIZE: usize = 64;

/// Flag bits stored in the header.
#[allow(dead_code)] // populated in subsequent steps
pub mod flags {
    /// Object was written with the `O_DIRECT` large-object path.
    pub const WRITTEN_O_DIRECT: u16 = 1 << 0;
    /// Object body was fdatasync'd before rename (durable PUT).
    pub const DURABLE: u16 = 1 << 1;
}

/// Parsed header of a single-file object record.
///
/// The on-disk encoding is little-endian for all multi-byte fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // populated in subsequent steps
pub struct Header {
    /// Length of the object payload in bytes.
    pub data_len: u64,
    /// Length of the JSON metadata blob in bytes.
    pub meta_len: u32,
    /// Header flag bits.
    pub flags: u16,
    /// Format version (matches [`VERSION`] at write time).
    pub version: u16,
}
