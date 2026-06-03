//! Boundary-independent plaintext checksum.
//!
//! The plaintext "corruption detection" checksum is a non-cryptographic
//! `gxhash64`. gxhash's streaming [`Hasher`] is **boundary-dependent**: each
//! [`Hasher::write`] call mixes one AES round over `compress_all(slice)`, with
//! no internal buffering, so `write(a); write(b) != write(ab)`. Feeding it the
//! variable network-sized chunks a PUT body arrives in therefore produced a
//! different digest every time the same content was stored, breaking dedup and
//! the checksum's stated purpose on any object larger than a single chunk.
//!
//! [`StreamChecksum`] fixes this by re-buffering arbitrary input into
//! fixed-size [`CHECKSUM_BLOCK`] blocks before each `write`, so the sequence of
//! `write` calls depends only on the content and its total length, never on how
//! the bytes were chunked on the wire. Every compute site (daemon-side
//! streaming encrypt, filesystem backend, io_uring backend) routes through this
//! type, so all backends agree on the digest for identical plaintext.
//!
//! Objects at or below `CHECKSUM_BLOCK` hash as a single `write(full)`, which
//! matches the digest the old single-shot paths produced, so checksums of
//! small objects (and the live dedup that relies on them) are unchanged.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use gxhash::GxHasher;
use std::hash::Hasher as _;

/// Block size at which buffered input is flushed into the hasher. Fixing this
/// makes the digest independent of input chunk boundaries; changing it changes
/// every digest of objects larger than one block.
pub const CHECKSUM_BLOCK: usize = 1024 * 1024;

/// Seed for the plaintext gxhash. Hardcoded (the checksum is for corruption
/// detection, not DOS resistance), and must match across every compute site.
const CHECKSUM_SEED: i64 = 0;

/// Incremental, boundary-independent gxhash of a byte stream.
///
/// Feed bytes with [`update`](Self::update) in any chunking, then take the
/// digest with [`finish`](Self::finish) or [`finish_b64`](Self::finish_b64).
pub struct StreamChecksum {
    hasher: GxHasher,
    /// Pending bytes not yet flushed; always strictly shorter than
    /// [`CHECKSUM_BLOCK`].
    buf: Vec<u8>,
}

impl StreamChecksum {
    /// Create an empty checksum accumulator.
    pub fn new() -> Self {
        Self {
            hasher: GxHasher::with_seed(CHECKSUM_SEED),
            buf: Vec::with_capacity(CHECKSUM_BLOCK),
        }
    }

    /// Feed bytes. The resulting digest is identical regardless of how the
    /// total content is split across calls.
    pub fn update(&mut self, mut data: &[u8]) {
        // Top up a partially filled block first.
        if !self.buf.is_empty() {
            let need = CHECKSUM_BLOCK - self.buf.len();
            let take = need.min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() == CHECKSUM_BLOCK {
                self.hasher.write(&self.buf);
                self.buf.clear();
            }
        }
        // Flush whole blocks straight from the input without copying.
        while data.len() >= CHECKSUM_BLOCK {
            self.hasher.write(&data[..CHECKSUM_BLOCK]);
            data = &data[CHECKSUM_BLOCK..];
        }
        // Stash the sub-block remainder for the next call / finish.
        self.buf.extend_from_slice(data);
    }

    /// Consume the accumulator and return the 64-bit digest.
    pub fn finish(mut self) -> u64 {
        if !self.buf.is_empty() {
            self.hasher.write(&self.buf);
        }
        self.hasher.finish()
    }

    /// Consume the accumulator and return the digest as standard base64 of the
    /// little-endian 8-byte value (12 chars), the on-disk encoding.
    pub fn finish_b64(self) -> String {
        B64.encode(self.finish().to_le_bytes())
    }
}

impl Default for StreamChecksum {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot boundary-independent checksum of a fully-resident buffer, base64
/// encoded. Equivalent to feeding `data` to a [`StreamChecksum`] in one call.
pub fn checksum_b64(data: &[u8]) -> String {
    let mut c = StreamChecksum::new();
    c.update(data);
    c.finish_b64()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point: identical content split at different boundaries must
    /// yield the same digest. This is what the old per-write hashing violated.
    #[test]
    fn digest_is_chunk_boundary_independent() {
        let data: Vec<u8> = (0..(CHECKSUM_BLOCK * 3 + 12345))
            .map(|i| (i * 31 + 7) as u8)
            .collect();

        // One shot.
        let whole = checksum_b64(&data);

        // Odd, irregular splits straddling block boundaries.
        let splits = [
            1usize,
            7,
            4096,
            999_983,
            CHECKSUM_BLOCK - 1,
            CHECKSUM_BLOCK + 5,
        ];
        for &step in &splits {
            let mut c = StreamChecksum::new();
            let mut off = 0;
            while off < data.len() {
                let end = (off + step).min(data.len());
                c.update(&data[off..end]);
                off = end;
            }
            assert_eq!(
                c.finish_b64(),
                whole,
                "split step {step} changed the digest"
            );
        }
    }

    /// Objects at or below one block hash as a single `write(full)`, matching
    /// the legacy single-shot digest, so small-object checksums don't move.
    #[test]
    fn small_object_matches_single_write() {
        let data: Vec<u8> = (0..79 * 1024).map(|i| (i % 251) as u8).collect();
        assert!(data.len() <= CHECKSUM_BLOCK);

        let mut legacy = GxHasher::with_seed(CHECKSUM_SEED);
        legacy.write(&data);
        let expected = B64.encode(legacy.finish().to_le_bytes());

        assert_eq!(checksum_b64(&data), expected);
    }

    /// Empty input is stable and writes nothing into the hasher.
    #[test]
    fn empty_is_stable() {
        let a = StreamChecksum::new().finish_b64();
        let mut c = StreamChecksum::new();
        c.update(&[]);
        c.update(&[]);
        assert_eq!(c.finish_b64(), a);
    }
}
