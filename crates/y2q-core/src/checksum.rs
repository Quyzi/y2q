//! Boundary-independent plaintext checksum.
//!
//! The plaintext "corruption detection" checksum is a non-cryptographic
//! XXH3-64 (via `xxhash-rust`). XXH3's streaming hasher buffers internally and
//! is boundary-independent by construction: `update(a); update(b)` always
//! yields the same digest as `update(ab)`. [`StreamChecksum`] wraps it directly
//! so every compute site (daemon-side streaming encrypt, filesystem backend,
//! io_uring backend) agrees on the digest for identical plaintext regardless of
//! how the bytes were chunked on the wire.
//!
//! XXH3 is pure Rust with no hardware-intrinsic requirement, so digests are
//! reproducible across CPU architectures - unlike the gxhash this replaced,
//! which mixed in AES-NI/NEON instructions and was not portable to riscv64 and
//! other architectures lacking those intrinsics.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use xxhash_rust::xxh3::Xxh3;

/// Block size at which buffered input is flushed into the hasher. Kept from
/// the gxhash-era implementation as the streaming chunk size; XXH3 itself does
/// not require fixed-size blocks but this avoids unbounded buffering.
pub const CHECKSUM_BLOCK: usize = 1024 * 1024;

/// Seed for the plaintext XXH3. Hardcoded (the checksum is for corruption
/// detection, not DOS resistance), and must match across every compute site.
const CHECKSUM_SEED: u64 = 0;

/// Incremental, boundary-independent XXH3-64 of a byte stream.
///
/// Feed bytes with [`update`](Self::update) in any chunking, then take the
/// digest with [`finish`](Self::finish) or [`finish_b64`](Self::finish_b64).
pub struct StreamChecksum {
    hasher: Xxh3,
}

impl StreamChecksum {
    /// Create an empty checksum accumulator.
    pub fn new() -> Self {
        Self {
            hasher: Xxh3::with_seed(CHECKSUM_SEED),
        }
    }

    /// Feed bytes. The resulting digest is identical regardless of how the
    /// total content is split across calls.
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Consume the accumulator and return the 64-bit digest.
    pub fn finish(self) -> u64 {
        self.hasher.digest()
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

    /// A small object hashed via `checksum_b64` matches a direct single-shot
    /// XXH3 digest with the same seed.
    #[test]
    fn small_object_matches_single_write() {
        let data: Vec<u8> = (0..79 * 1024).map(|i| (i % 251) as u8).collect();
        assert!(data.len() <= CHECKSUM_BLOCK);

        let mut direct = Xxh3::with_seed(CHECKSUM_SEED);
        direct.update(&data);
        let expected = B64.encode(direct.digest().to_le_bytes());

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
