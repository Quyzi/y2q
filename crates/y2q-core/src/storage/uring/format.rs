//! On-disk single-file object format for [`UringStorage`](super::UringStorage).
//!
//! Each object is one file laid out as:
//!
//! ```text
//! [ header  64 B ]
//! [ data    N B  ]    where N = header.data_len (u64; no protocol cap)
//! [ meta    M B  ]    where M = header.meta_len (u32); JSON-encoded Metadata
//! [ trailer 64 B ]    bitwise mirror of header for torn-write recovery
//! ```
//!
//! Both header and trailer carry a CRC32 over the rest of their 64-byte
//! record, so a torn write that lands the head but not the tail (or vice
//! versa) is detectable and the surviving copy can be used for repair. The
//! data payload's integrity is covered by the SHA-256 stored in the JSON
//! metadata; we do not pay for a whole-object CRC at write time.
//!
//! All multi-byte fields are little-endian.

/// 4-byte magic prefix identifying this format: `b"Y2QO"` (y2q object).
pub const MAGIC: [u8; 4] = *b"Y2QO";

/// Current header version. Bump on any breaking layout change.
pub const VERSION: u16 = 1;

/// Fixed size of the header (and trailer) record, in bytes.
pub const HEADER_SIZE: usize = 64;

/// Flag bits stored in the header.
#[allow(dead_code)] // populated by the write path in subsequent steps
pub mod flags {
    /// Object was written with the `O_DIRECT` large-object path.
    pub const WRITTEN_O_DIRECT: u16 = 1 << 0;
    /// Object body was fdatasync'd before rename (durable PUT).
    pub const DURABLE: u16 = 1 << 1;
}

/// Errors returned by [`Header::decode`].
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum FormatError {
    /// The first four bytes did not match [`MAGIC`].
    #[error("invalid magic bytes")]
    Magic,
    /// The version field did not match [`VERSION`].
    #[error("unsupported format version {0}")]
    Version(u16),
    /// The recomputed CRC32 did not match the stored value.
    #[error("header CRC32 mismatch")]
    Crc,
}

/// Parsed header of a single-file object record.
///
/// On disk this is a fixed 64-byte little-endian record. See [`Header::encode`]
/// for the exact layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Length of the object payload in bytes.
    pub data_len: u64,
    /// Length of the JSON metadata blob in bytes.
    pub meta_len: u32,
    /// Header flag bits — see [`flags`].
    pub flags: u16,
    /// Format version (matches [`VERSION`] at write time).
    pub version: u16,
}

impl Header {
    /// Byte offset of the data section within the file.
    pub const DATA_OFFSET: u64 = HEADER_SIZE as u64;

    /// Byte offset at which the metadata blob starts.
    pub fn meta_offset(&self) -> u64 {
        Self::DATA_OFFSET + self.data_len
    }

    /// Byte offset at which the trailer record starts.
    pub fn trailer_offset(&self) -> u64 {
        self.meta_offset() + self.meta_len as u64
    }

    /// Total length of the on-disk file: `2*header + data + meta`.
    #[allow(dead_code)] // used by tests now; production callers land with rebuild_cache
    pub fn total_len(&self) -> u64 {
        2 * HEADER_SIZE as u64 + self.data_len + self.meta_len as u64
    }

    /// Encode the header as a fixed 64-byte record.
    ///
    /// Layout (offsets are byte positions):
    ///
    /// | range  | field                      |
    /// |--------|----------------------------|
    /// | 0..4   | magic = `b"Y2QO"`          |
    /// | 4..6   | version (u16 LE)           |
    /// | 6..8   | flags (u16 LE)             |
    /// | 8..16  | data_len (u64 LE)          |
    /// | 16..20 | meta_len (u32 LE)          |
    /// | 20..60 | reserved, zero             |
    /// | 60..64 | CRC32 of bytes 0..60 (LE)  |
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&MAGIC);
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..8].copy_from_slice(&self.flags.to_le_bytes());
        buf[8..16].copy_from_slice(&self.data_len.to_le_bytes());
        buf[16..20].copy_from_slice(&self.meta_len.to_le_bytes());
        // bytes 20..60 remain zero — reserved for future fields.
        let crc = crc32fast::hash(&buf[0..60]);
        buf[60..64].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    /// Decode and validate a 64-byte header record.
    ///
    /// Returns [`FormatError::BadMagic`] if the magic prefix doesn't match,
    /// [`FormatError::BadVersion`] if the version isn't [`VERSION`], or
    /// [`FormatError::BadCrc`] if the stored CRC32 doesn't match the
    /// recomputed value. Reserved bytes are *not* checked: future writers
    /// may populate them.
    pub fn decode(buf: &[u8; HEADER_SIZE]) -> Result<Self, FormatError> {
        if buf[0..4] != MAGIC {
            return Err(FormatError::Magic);
        }
        let version = u16::from_le_bytes(buf[4..6].try_into().unwrap());
        if version != VERSION {
            return Err(FormatError::Version(version));
        }
        let stored_crc = u32::from_le_bytes(buf[60..64].try_into().unwrap());
        let computed_crc = crc32fast::hash(&buf[0..60]);
        if stored_crc != computed_crc {
            return Err(FormatError::Crc);
        }
        let flags = u16::from_le_bytes(buf[6..8].try_into().unwrap());
        let data_len = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let meta_len = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        Ok(Self {
            data_len,
            meta_len,
            flags,
            version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Header {
        Header {
            data_len: 1_500_000_000_000, // 1.5 TB — proves >32-bit support
            meta_len: 1234,
            flags: flags::DURABLE | flags::WRITTEN_O_DIRECT,
            version: VERSION,
        }
    }

    #[test]
    fn encoded_size_is_fixed() {
        let buf = sample().encode();
        assert_eq!(buf.len(), HEADER_SIZE);
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        let original = sample();
        let decoded = Header::decode(&original.encode()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_zero_object() {
        // Empty objects must round-trip too: data_len=0, meta_len=0.
        let h = Header {
            data_len: 0,
            meta_len: 0,
            flags: 0,
            version: VERSION,
        };
        assert_eq!(Header::decode(&h.encode()).unwrap(), h);
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut buf = sample().encode();
        buf[0] ^= 0xff;
        // CRC will also fail, but the magic check should take precedence so
        // the error message is useful when someone points us at the wrong file.
        assert_eq!(Header::decode(&buf), Err(FormatError::Magic));
    }

    #[test]
    fn decode_rejects_wrong_version() {
        let mut buf = sample().encode();
        let bogus_version: u16 = VERSION.wrapping_add(7);
        buf[4..6].copy_from_slice(&bogus_version.to_le_bytes());
        // Recompute CRC so we exercise the version check, not the CRC check.
        let crc = crc32fast::hash(&buf[0..60]);
        buf[60..64].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            Header::decode(&buf),
            Err(FormatError::Version(bogus_version))
        );
    }

    #[test]
    fn decode_detects_corrupted_payload_field() {
        let mut buf = sample().encode();
        // Flip a bit in data_len. CRC should catch it.
        buf[8] ^= 0x01;
        assert_eq!(Header::decode(&buf), Err(FormatError::Crc));
    }

    #[test]
    fn decode_detects_corrupted_crc_byte() {
        let mut buf = sample().encode();
        buf[60] ^= 0x01;
        assert_eq!(Header::decode(&buf), Err(FormatError::Crc));
    }

    #[test]
    fn layout_offsets_match_encoding() {
        let h = Header {
            data_len: 1024,
            meta_len: 512,
            flags: 0,
            version: VERSION,
        };
        assert_eq!(Header::DATA_OFFSET, 64);
        assert_eq!(h.meta_offset(), 64 + 1024);
        assert_eq!(h.trailer_offset(), 64 + 1024 + 512);
        assert_eq!(h.total_len(), 64 + 1024 + 512 + 64);
    }

    #[test]
    fn trailer_round_trips_as_a_second_header() {
        // The trailer is a bitwise mirror of the header — the same encoded
        // 64-byte record. Confirm decoding either copy yields the same value.
        let h = sample();
        let head_bytes = h.encode();
        let trailer_bytes = h.encode();
        assert_eq!(head_bytes, trailer_bytes);
        assert_eq!(Header::decode(&trailer_bytes).unwrap(), h);
    }
}
