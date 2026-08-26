//! On-disk single-file object format for [`UringStorage`](super::UringStorage).
//!
//! Each object is one file laid out as:
//!
//! ```text
//! [ header   64 B ]
//! [ padding  P B  ]   P = header.data_offset - 64 (zero on the buffered path)
//! [ data     N B  ]   N = header.data_len  (u64; no protocol cap)
//! [ meta     M B  ]   M = header.meta_len  (u32); JSON-encoded Metadata
//! [ trailer  64 B ]   bitwise mirror of header for torn-write recovery
//! ```
//!
//! Both header and trailer carry a CRC32 over the rest of their 64-byte
//! record, so a torn write that lands the head but not the tail (or vice
//! versa) is detectable and the surviving copy can be used for repair. The
//! CRC is a corruption check only — it is recomputable, so it says nothing
//! about tampering. Bytes `24..56` therefore carry an HMAC-SHA256 over the
//! meaningful header fields, keyed by the node-derived Container Header Key
//! and bound to the object's on-disk id. The data payload's integrity is
//! covered by the SHA-256 stored in the JSON metadata; we do not pay for a
//! whole-object CRC at write time.
//!
//! `data_offset` lets the write path push the data section out to a 4 KiB
//! boundary so the bulk write can use `O_DIRECT` with aligned offsets. On
//! the small-object buffered path it equals [`HEADER_SIZE`] (no padding); on
//! the large-object path it equals [`MIN_DIRECT_DATA_OFFSET`] (4 KiB).
//!
//! All multi-byte fields are little-endian.
use aes_gcm::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// 4-byte magic prefix identifying this format: `b"Y2QO"` (y2q object).
pub const MAGIC: [u8; 4] = *b"Y2QO";

/// Current header version. Bump on any breaking layout change.
///
/// Version 2 added the HMAC at bytes `24..56`; version 1 left that region
/// reserved and zero.
pub const VERSION: u16 = 2;

/// Fixed size of the header (and trailer) record, in bytes.
pub const HEADER_SIZE: usize = 64;

/// `data_offset` value used by the `O_DIRECT` large-object path. Picked to
/// match the logical block size of every NVMe SSD currently sold so the
/// data section starts on a 4 KiB-aligned boundary.
pub const MIN_DIRECT_DATA_OFFSET: u32 = 4096;

/// Flag bits stored in the header.
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
    /// The recomputed CRC32 did not match the stored value. Checked before
    /// the MAC, because a CRC failure is the torn-write signal the trailer
    /// repair path depends on.
    #[error("header CRC32 mismatch")]
    Crc,
    /// The recomputed HMAC did not match the stored value: the header was
    /// altered by something without the node key, or relocated from another
    /// object.
    #[error("header MAC mismatch")]
    Mac,
    /// The header's declared total length disagrees with the actual file
    /// length, so `meta_len`/`data_len` cannot be trusted to size a read or an
    /// allocation.
    #[error("header declares total length {declared} but the file is {actual} bytes")]
    TotalLen {
        /// Total length implied by the header fields.
        declared: u64,
        /// Actual logical length of the file on disk.
        actual: u64,
    },
    /// `data_offset` was smaller than [`Header::MIN_DATA_OFFSET`], which
    /// would let the data section overlap the fixed-size header — only
    /// reachable via a corrupt or adversarial header, since every writer in
    /// this codebase always sets `data_offset` to a valid value.
    #[error("data_offset {0} is below the minimum of {min}", min = HEADER_SIZE)]
    DataOffset(u32),
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
    /// Byte offset at which the data section starts.
    ///
    /// `HEADER_SIZE` (64) on the buffered path; [`MIN_DIRECT_DATA_OFFSET`]
    /// (4096) on the `O_DIRECT` path so the data section is block-aligned.
    pub data_offset: u32,
    /// Header flag bits — see [`flags`].
    pub flags: u16,
    /// Format version (matches [`VERSION`] at write time).
    pub version: u16,
}

impl Header {
    /// Smallest legal value of `data_offset` — the buffered-path layout where
    /// the data section starts immediately after the 64-byte header.
    pub const MIN_DATA_OFFSET: u32 = HEADER_SIZE as u32;

    /// Byte offset at which the metadata blob starts.
    pub fn meta_offset(&self) -> u64 {
        self.data_offset as u64 + self.data_len
    }

    /// Byte offset at which the trailer record starts.
    pub fn trailer_offset(&self) -> u64 {
        self.meta_offset() + self.meta_len as u64
    }

    /// Total length of the on-disk file: `data_offset + data + meta + 64`,
    /// computed with checked arithmetic. Returns `None` if the fields would
    /// overflow `u64` — only reachable from a corrupt or adversarial header,
    /// since every writer in this codebase produces headers whose fields
    /// sum well within `u64`. Callers MUST treat `None` (and any `Some`
    /// value exceeding the actual file length) as invalid rather than
    /// falling back to unchecked arithmetic, which can wrap and desync a
    /// slice's start/end bounds — see `filesystem::set_labels_impl` and
    /// `rotation::migrate_object_file` for the production validation this
    /// backs.
    pub fn checked_total_len(&self) -> Option<u64> {
        (self.data_offset as u64)
            .checked_add(self.data_len)?
            .checked_add(self.meta_len as u64)?
            .checked_add(HEADER_SIZE as u64)
    }

    /// Reject a header whose declared total length disagrees with the file's
    /// actual logical length.
    ///
    /// Kept out of [`Self::decode`], which has no way to know the file size.
    /// Every write path finishes by writing the 64-byte trailer at
    /// [`Self::trailer_offset`], so the final size is exactly
    /// `trailer_offset() + 64 == checked_total_len()`. The `O_DIRECT` path is
    /// not an exception: it pads the *data section start* to 4 KiB by leaving
    /// `[64, 4096)` a sparse hole and routes the unaligned tail, metadata and
    /// trailer through a buffered fd, so no tail padding is appended.
    ///
    /// `actual` MUST come from the logical length (`std::fs::Metadata::len`),
    /// never from `blocks()`, which the sparse hole makes smaller.
    pub fn check_total_len(&self, actual: u64) -> Result<(), FormatError> {
        match self.checked_total_len() {
            Some(declared) if declared == actual => Ok(()),
            Some(declared) => Err(FormatError::TotalLen { declared, actual }),
            None => Err(FormatError::TotalLen {
                declared: u64::MAX,
                actual,
            }),
        }
    }

    /// HMAC-SHA256 over the meaningful header bytes, bound to `object_id`.
    ///
    /// Covers bytes `0..24` — magic, version, flags, `data_len`, `meta_len`,
    /// `data_offset` — which is every field that drives a read. Binding to the
    /// object id (the `.obj` filename stem, the same identity `encrypt_meta`
    /// binds to) stops a header being relocated between objects.
    fn mac(chk: &[u8; 32], buf: &[u8; HEADER_SIZE], object_id: &str) -> [u8; 32] {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac =
            <HmacSha256 as KeyInit>::new_from_slice(chk).expect("HMAC accepts any key size");
        mac.update(&buf[0..24]);
        mac.update(object_id.as_bytes());
        let out = mac.finalize().into_bytes();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&out);
        tag
    }

    /// Encode the header as a fixed 64-byte record.
    ///
    /// Layout (offsets are byte positions):
    ///
    /// | range  | field                                          |
    /// |--------|------------------------------------------------|
    /// | 0..4   | magic = `b"Y2QO"`                              |
    /// | 4..6   | version (u16 LE)                               |
    /// | 6..8   | flags (u16 LE)                                 |
    /// | 8..16  | data_len (u64 LE)                              |
    /// | 16..20 | meta_len (u32 LE)                              |
    /// | 20..24 | data_offset (u32 LE; 0 ⇒ HEADER_SIZE on read)  |
    /// | 24..56 | HMAC-SHA256(CHK, buf[0..24] ‖ object_id)       |
    /// | 56..60 | reserved, zero                                 |
    /// | 60..64 | CRC32 of bytes 0..60 (LE)                      |
    pub fn encode(&self, chk: &[u8; 32], object_id: &str) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&MAGIC);
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..8].copy_from_slice(&self.flags.to_le_bytes());
        buf[8..16].copy_from_slice(&self.data_len.to_le_bytes());
        buf[16..20].copy_from_slice(&self.meta_len.to_le_bytes());
        buf[20..24].copy_from_slice(&self.data_offset.to_le_bytes());
        let tag = Self::mac(chk, &buf, object_id);
        buf[24..56].copy_from_slice(&tag);
        // bytes 56..60 remain zero — reserved for future fields.
        let crc = crc32fast::hash(&buf[0..60]);
        buf[60..64].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    /// Decode and validate a 64-byte header record.
    ///
    /// Checks, in order: magic, version, CRC32, MAC, `data_offset`. The CRC is
    /// checked before the MAC deliberately — it is the cheap torn-write signal
    /// the trailer-repair path keys off, and a half-written header should
    /// report as corruption rather than as tampering.
    ///
    /// Returns [`FormatError::Magic`] if the magic prefix doesn't match,
    /// [`FormatError::Version`] if the version isn't [`VERSION`],
    /// [`FormatError::Crc`] if the stored CRC32 doesn't match the recomputed
    /// value, [`FormatError::Mac`] if the header was altered without the node
    /// key or copied from another object, or [`FormatError::DataOffset`] if
    /// `data_offset` is nonzero but smaller than [`Self::MIN_DATA_OFFSET`]
    /// (which would let the data section overlap the header).
    ///
    /// `data_offset == 0` is interpreted as [`Self::MIN_DATA_OFFSET`] so
    /// step-4 records (written before the field existed) decode correctly
    /// without a format-version bump.
    pub fn decode(
        buf: &[u8; HEADER_SIZE],
        chk: &[u8; 32],
        object_id: &str,
    ) -> Result<Self, FormatError> {
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
        let expected = Self::mac(chk, buf, object_id);
        if !bool::from(buf[24..56].ct_eq(&expected)) {
            return Err(FormatError::Mac);
        }
        let flags = u16::from_le_bytes(buf[6..8].try_into().unwrap());
        let data_len = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let meta_len = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        let raw_data_offset = u32::from_le_bytes(buf[20..24].try_into().unwrap());
        let data_offset = if raw_data_offset == 0 {
            Self::MIN_DATA_OFFSET
        } else {
            raw_data_offset
        };
        if data_offset < Self::MIN_DATA_OFFSET {
            return Err(FormatError::DataOffset(data_offset));
        }
        Ok(Self {
            data_len,
            meta_len,
            data_offset,
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
            data_offset: Header::MIN_DATA_OFFSET,
            flags: flags::DURABLE | flags::WRITTEN_O_DIRECT,
            version: VERSION,
        }
    }

    /// Container Header Key used throughout these tests.
    const CHK: [u8; 32] = [0x5Au8; 32];
    /// Object id the sample header is bound to.
    const OID: &str = "abc";

    #[test]
    fn encoded_size_is_fixed() {
        let buf = sample().encode(&CHK, OID);
        assert_eq!(buf.len(), HEADER_SIZE);
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        let original = sample();
        let decoded = Header::decode(&original.encode(&CHK, OID), &CHK, OID).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn round_trip_with_o_direct_alignment() {
        // O_DIRECT large-object path uses data_offset = 4096.
        let h = Header {
            data_len: 1 << 28, // 256 MiB
            meta_len: 500,
            data_offset: MIN_DIRECT_DATA_OFFSET,
            flags: flags::DURABLE | flags::WRITTEN_O_DIRECT,
            version: VERSION,
        };
        let decoded = Header::decode(&h.encode(&CHK, OID), &CHK, OID).unwrap();
        assert_eq!(decoded, h);
        assert_eq!(decoded.data_offset, 4096);
    }

    #[test]
    fn round_trip_zero_object() {
        // Empty objects must round-trip too: data_len=0, meta_len=0.
        let h = Header {
            data_len: 0,
            meta_len: 0,
            data_offset: Header::MIN_DATA_OFFSET,
            flags: 0,
            version: VERSION,
        };
        assert_eq!(Header::decode(&h.encode(&CHK, OID), &CHK, OID).unwrap(), h);
    }

    #[test]
    fn legacy_zero_data_offset_decodes_to_min() {
        // Step-4 records had bytes 20..24 = 0. Decode must map that to the
        // legacy 64-byte data offset so old records still read correctly.
        let mut h = sample();
        h.data_offset = 0;
        // Encode with the field already zero so the MAC covers what is on
        // disk; the header is otherwise identical.
        let buf = h.encode(&CHK, OID);
        let decoded = Header::decode(&buf, &CHK, OID).unwrap();
        assert_eq!(decoded.data_offset, Header::MIN_DATA_OFFSET);
        assert_eq!(decoded.data_offset, 64);
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut buf = sample().encode(&CHK, OID);
        buf[0] ^= 0xff;
        // CRC will also fail, but the magic check should take precedence so
        // the error message is useful when someone points us at the wrong file.
        assert_eq!(Header::decode(&buf, &CHK, OID), Err(FormatError::Magic));
    }

    #[test]
    fn decode_rejects_wrong_version() {
        let mut buf = sample().encode(&CHK, OID);
        let bogus_version: u16 = VERSION.wrapping_add(7);
        buf[4..6].copy_from_slice(&bogus_version.to_le_bytes());
        // Recompute CRC so we exercise the version check, not the CRC check.
        let crc = crc32fast::hash(&buf[0..60]);
        buf[60..64].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            Header::decode(&buf, &CHK, OID),
            Err(FormatError::Version(bogus_version))
        );
    }

    #[test]
    fn decode_detects_corrupted_payload_field() {
        let mut buf = sample().encode(&CHK, OID);
        // Flip a bit in data_len. CRC should catch it.
        buf[8] ^= 0x01;
        assert_eq!(Header::decode(&buf, &CHK, OID), Err(FormatError::Crc));
    }

    #[test]
    fn decode_detects_corrupted_crc_byte() {
        let mut buf = sample().encode(&CHK, OID);
        buf[60] ^= 0x01;
        assert_eq!(Header::decode(&buf, &CHK, OID), Err(FormatError::Crc));
    }

    #[test]
    fn recomputed_crc_does_not_launder_a_tampered_field() {
        // This is the exact tamper the CRC-only header accepted: flip a field,
        // recompute the CRC, and the header verifies. The MAC must catch it.
        let mut buf = sample().encode(&CHK, OID);
        buf[8] ^= 0x01;
        let crc = crc32fast::hash(&buf[0..60]);
        buf[60..64].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(Header::decode(&buf, &CHK, OID), Err(FormatError::Mac));
    }

    #[test]
    fn header_cannot_be_relocated_to_another_object() {
        let buf = sample().encode(&CHK, OID);
        // Byte-for-byte valid, but read as a different object's header.
        assert_eq!(Header::decode(&buf, &CHK, "xyz"), Err(FormatError::Mac));
        // And a different node key must not verify it either.
        assert_eq!(
            Header::decode(&buf, &[0x11u8; 32], OID),
            Err(FormatError::Mac)
        );
    }

    #[test]
    fn total_length_must_match_the_file() {
        let h = sample();
        let declared = h.checked_total_len().unwrap();
        assert_eq!(h.check_total_len(declared), Ok(()));
        assert_eq!(
            h.check_total_len(declared - 1),
            Err(FormatError::TotalLen {
                declared,
                actual: declared - 1
            })
        );
        // An oversized meta_len cannot drive an allocation past the real file.
        let mut lying = sample();
        lying.meta_len = u32::MAX;
        assert!(lying.check_total_len(declared).is_err());
    }

    #[test]
    fn layout_offsets_match_encoding_buffered() {
        let h = Header {
            data_len: 1024,
            meta_len: 512,
            data_offset: Header::MIN_DATA_OFFSET,
            flags: 0,
            version: VERSION,
        };
        assert_eq!(h.data_offset, 64);
        assert_eq!(h.meta_offset(), 64 + 1024);
        assert_eq!(h.trailer_offset(), 64 + 1024 + 512);
        assert_eq!(h.checked_total_len(), Some(64 + 1024 + 512 + 64));
    }

    #[test]
    fn layout_offsets_match_encoding_o_direct() {
        let h = Header {
            data_len: 1024 * 1024,
            meta_len: 512,
            data_offset: MIN_DIRECT_DATA_OFFSET,
            flags: flags::WRITTEN_O_DIRECT,
            version: VERSION,
        };
        assert_eq!(h.meta_offset(), 4096 + 1024 * 1024);
        assert_eq!(h.trailer_offset(), 4096 + 1024 * 1024 + 512);
        assert_eq!(h.checked_total_len(), Some(4096 + 1024 * 1024 + 512 + 64));
    }

    #[test]
    fn decode_rejects_data_offset_below_minimum() {
        // A nonzero but sub-minimum data_offset would let the data section
        // overlap the 64-byte header. `raw_data_offset == 0` is the
        // legitimate legacy sentinel (see `legacy_zero_data_offset_decodes_to_min`);
        // anything else below `MIN_DATA_OFFSET` is adversarial/corrupt.
        let mut h = sample();
        h.data_offset = 32;
        let buf = h.encode(&CHK, OID);
        assert_eq!(
            Header::decode(&buf, &CHK, OID),
            Err(FormatError::DataOffset(32))
        );
    }

    #[test]
    fn checked_total_len_none_on_overflow() {
        // data_len alone is within u64::MAX - HEADER_SIZE - meta_len, so
        // plain `+` wraps silently instead of erroring; checked arithmetic
        // must catch it.
        let h = Header {
            data_len: u64::MAX - 100,
            meta_len: 1000,
            data_offset: Header::MIN_DATA_OFFSET,
            flags: 0,
            version: VERSION,
        };
        assert_eq!(h.checked_total_len(), None);
    }

    #[test]
    fn trailer_round_trips_as_a_second_header() {
        // The trailer is a bitwise mirror of the header — the same encoded
        // 64-byte record. Confirm decoding either copy yields the same value.
        let h = sample();
        let head_bytes = h.encode(&CHK, OID);
        let trailer_bytes = h.encode(&CHK, OID);
        assert_eq!(head_bytes, trailer_bytes);
        assert_eq!(Header::decode(&trailer_bytes, &CHK, OID).unwrap(), h);
    }
}
