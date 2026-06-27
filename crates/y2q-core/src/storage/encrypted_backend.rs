//! Whole-file-encrypting [`redb::StorageBackend`].
//!
//! redb performs random-access reads and writes at arbitrary offsets, so the
//! file cannot be encrypted as a single blob. Instead this backend encrypts the
//! file in fixed-size blocks with AES-256-GCM and transparently translates
//! redb's logical offsets to physical (on-disk) offsets. redb sees plaintext;
//! the bytes on disk are always ciphertext.
//!
//! ## On-disk layout
//!
//! ```text
//! [ header (52 bytes) ][ data block 0 ][ data block 1 ] ...
//! ```
//!
//! Header:
//! ```text
//! [ magic "Y2QIDX01" : 8 ][ nonce : 12 ][ AES-256-GCM(version u32 | block_size u32 | logical_len u64) + tag : 32 ]
//! ```
//! The magic is plaintext (so a foreign/legacy file is detected cheaply without
//! the key); the rest is sealed with the magic as AAD. `logical_len` is the file
//! length redb believes it has - it is authenticated, so truncation is detected.
//!
//! Each data block holds exactly `BLOCK_SIZE` plaintext bytes:
//! ```text
//! [ nonce : 12 ][ AES-256-GCM(BLOCK_SIZE plaintext) + tag : 16 ]
//! ```
//! A fresh random nonce is drawn on every block write (blocks are rewritten in
//! place, so a fixed nonce would be catastrophic under GCM). The block index is
//! bound as AAD, so a block cannot be relocated within the file undetected.
//!
//! ## Key
//!
//! The file key is derived from the login-gated MEK
//! ([`crate::crypto::derive_index_file_key`]); the backend therefore can only be
//! opened while a session is active. See [`crate::storage::index`] for the
//! open-on-login / close-on-idle lifecycle.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::RwLock;

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use rand::Rng;
use redb::StorageBackend;

/// Plaintext bytes per data block.
const BLOCK_SIZE: usize = 4096;
/// AES-256-GCM nonce length.
const NONCE_LEN: usize = 12;
/// AES-256-GCM authentication tag length.
const TAG_LEN: usize = 16;
/// Physical size of one encrypted data block: nonce + ciphertext + tag.
const PHYS_BLOCK: usize = NONCE_LEN + BLOCK_SIZE + TAG_LEN;

/// File magic identifying an encrypted index file (plaintext prefix).
const MAGIC: &[u8; 8] = b"Y2QIDX01";
/// Format version sealed in the header.
const FORMAT_VERSION: u32 = 1;
/// Plaintext bytes sealed in the header: version(4) + block_size(4) + logical_len(8).
const HEADER_PLAINTEXT_LEN: usize = 16;
/// Physical header size: magic + nonce + sealed(header plaintext) + tag.
const HEADER_PHYS: u64 = (8 + NONCE_LEN + HEADER_PLAINTEXT_LEN + TAG_LEN) as u64;

/// Physical byte offset of data block `idx`.
fn block_phys_offset(idx: u64) -> u64 {
    HEADER_PHYS + idx * PHYS_BLOCK as u64
}

/// A [`redb::StorageBackend`] that encrypts the whole backing file in blocks.
///
/// I/O goes through positioned reads/writes (`pread`/`pwrite`) so the backing
/// file has no shared seek cursor. That lets reads run under a shared
/// [`RwLock`] read guard - concurrent reads no longer serialize against each
/// other - while writes (redb already single-writes) take the exclusive guard.
pub struct EncryptedFileBackend {
    cipher: Aes256Gcm,
    inner: RwLock<Inner>,
}

struct Inner {
    file: File,
    /// Logical length redb believes the file has.
    logical_len: u64,
    /// Cached physical length of the backing file. Maintained on every write so
    /// the hot path never has to `stat(2)` per block.
    phys_len: u64,
}

impl fmt::Debug for EncryptedFileBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.inner.read().map(|i| i.logical_len).unwrap_or(0);
        f.debug_struct("EncryptedFileBackend")
            .field("logical_len", &len)
            .finish_non_exhaustive()
    }
}

fn invalid_data(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

impl EncryptedFileBackend {
    /// Open (or create) the encrypted file at `path` under `file_key`.
    ///
    /// If the file is empty it is initialized with a fresh header. If it carries
    /// our [`MAGIC`] the header is decrypted and validated (a wrong key or
    /// tampering yields an error). If it is non-empty but does **not** carry our
    /// magic it is treated as a stale/foreign file (e.g. a pre-encryption redb
    /// index) and recreated empty - the caller is expected to rebuild it.
    pub fn open(path: &Path, file_key: [u8; 32]) -> Result<Self, io::Error> {
        let cipher = Aes256Gcm::new((&file_key).into());
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let initial_phys = file.metadata()?.len();
        let logical_len = if initial_phys == 0 {
            // Fresh file: write an empty header.
            write_header(&cipher, &mut file, 0)?;
            0
        } else if initial_phys >= 8 && read_magic(&mut file)? == *MAGIC {
            read_header(&cipher, &mut file)?
        } else {
            // Foreign/legacy/corrupt file with no recognizable magic. Recreate.
            file.set_len(0)?;
            write_header(&cipher, &mut file, 0)?;
            0
        };
        // Re-stat: the branches above may have created or truncated the file.
        let phys_len = file.metadata()?.len();

        Ok(Self {
            cipher,
            inner: RwLock::new(Inner {
                file,
                logical_len,
                phys_len,
            }),
        })
    }

    /// Seal `BLOCK_SIZE` plaintext bytes for data block `idx` into a physical block.
    fn seal_block(&self, idx: u64, plain: &[u8; BLOCK_SIZE]) -> Result<Vec<u8>, io::Error> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        let ct = self
            .cipher
            .encrypt(
                aes_gcm::Nonce::from_slice(&nonce),
                aes_gcm::aead::Payload {
                    msg: plain.as_slice(),
                    aad: &idx.to_be_bytes(),
                },
            )
            .map_err(|_| invalid_data("index block encrypt"))?;
        let mut out = Vec::with_capacity(PHYS_BLOCK);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Read and decrypt data block `idx`. Blocks that have never been written
    /// (physical offset beyond the file end) read back as all-zero, matching the
    /// semantics redb expects from a freshly extended file.
    fn read_block(&self, inner: &Inner, idx: u64) -> Result<[u8; BLOCK_SIZE], io::Error> {
        let phys = block_phys_offset(idx);
        if phys.saturating_add(PHYS_BLOCK as u64) > inner.phys_len {
            // Not yet materialized on disk.
            return Ok([0u8; BLOCK_SIZE]);
        }
        let mut buf = vec![0u8; PHYS_BLOCK];
        inner.file.read_exact_at(&mut buf, phys)?;
        let nonce = &buf[..NONCE_LEN];
        let ct = &buf[NONCE_LEN..];
        let plain = self
            .cipher
            .decrypt(
                aes_gcm::Nonce::from_slice(nonce),
                aes_gcm::aead::Payload {
                    msg: ct,
                    aad: &idx.to_be_bytes(),
                },
            )
            .map_err(|_| invalid_data("index block decrypt/auth"))?;
        if plain.len() != BLOCK_SIZE {
            return Err(invalid_data("index block wrong plaintext length"));
        }
        let mut out = [0u8; BLOCK_SIZE];
        out.copy_from_slice(&plain);
        Ok(out)
    }

    /// Write a full plaintext block `idx`, materializing any gap blocks between
    /// the current physical end and `idx` as sealed all-zero blocks.
    fn write_block(
        &self,
        inner: &mut Inner,
        idx: u64,
        plain: &[u8; BLOCK_SIZE],
    ) -> Result<(), io::Error> {
        // First block index not yet present on disk.
        let next_missing = if inner.phys_len <= HEADER_PHYS {
            0
        } else {
            (inner.phys_len - HEADER_PHYS).div_ceil(PHYS_BLOCK as u64)
        };
        if idx > next_missing {
            // Materialize the gap as sealed all-zero blocks in a single buffer,
            // written with one positioned write instead of seek+write per block.
            let zero = [0u8; BLOCK_SIZE];
            let mut batch = Vec::with_capacity((idx - next_missing) as usize * PHYS_BLOCK);
            for gap in next_missing..idx {
                batch.extend_from_slice(&self.seal_block(gap, &zero)?);
            }
            inner
                .file
                .write_all_at(&batch, block_phys_offset(next_missing))?;
        }
        let block = self.seal_block(idx, plain)?;
        inner.file.write_all_at(&block, block_phys_offset(idx))?;
        let end_phys = block_phys_offset(idx) + PHYS_BLOCK as u64;
        if end_phys > inner.phys_len {
            inner.phys_len = end_phys;
        }
        Ok(())
    }
}

/// Read the 8-byte plaintext magic from the start of the file.
fn read_magic(file: &mut File) -> Result<[u8; 8], io::Error> {
    let mut magic = [0u8; 8];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut magic)?;
    Ok(magic)
}

/// Seal and write the header carrying `logical_len`.
fn write_header(cipher: &Aes256Gcm, file: &mut File, logical_len: u64) -> Result<(), io::Error> {
    let mut plaintext = [0u8; HEADER_PLAINTEXT_LEN];
    plaintext[0..4].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    plaintext[4..8].copy_from_slice(&(BLOCK_SIZE as u32).to_be_bytes());
    plaintext[8..16].copy_from_slice(&logical_len.to_be_bytes());

    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            aes_gcm::Nonce::from_slice(&nonce),
            aes_gcm::aead::Payload {
                msg: &plaintext,
                aad: MAGIC,
            },
        )
        .map_err(|_| invalid_data("index header encrypt"))?;

    let mut out = Vec::with_capacity(HEADER_PHYS as usize);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&out)?;
    Ok(())
}

/// Read and validate the header, returning the stored logical length.
fn read_header(cipher: &Aes256Gcm, file: &mut File) -> Result<u64, io::Error> {
    let mut buf = vec![0u8; HEADER_PHYS as usize];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut buf)?;
    let nonce = &buf[8..8 + NONCE_LEN];
    let ct = &buf[8 + NONCE_LEN..];
    let plain = cipher
        .decrypt(
            aes_gcm::Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: ct,
                aad: MAGIC,
            },
        )
        .map_err(|_| invalid_data("index header decrypt/auth (wrong key or tampered)"))?;
    if plain.len() != HEADER_PLAINTEXT_LEN {
        return Err(invalid_data("index header wrong length"));
    }
    let version = u32::from_be_bytes(plain[0..4].try_into().unwrap());
    if version != FORMAT_VERSION {
        return Err(invalid_data(format!("unsupported index format {version}")));
    }
    let block_size = u32::from_be_bytes(plain[4..8].try_into().unwrap()) as usize;
    if block_size != BLOCK_SIZE {
        return Err(invalid_data(format!(
            "index block size mismatch: file {block_size}, expected {BLOCK_SIZE}"
        )));
    }
    Ok(u64::from_be_bytes(plain[8..16].try_into().unwrap()))
}

impl StorageBackend for EncryptedFileBackend {
    fn len(&self) -> Result<u64, io::Error> {
        Ok(self.inner.read().expect("backend poisoned").logical_len)
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), io::Error> {
        let inner = self.inner.read().expect("backend poisoned");
        let mut done = 0usize;
        while done < out.len() {
            let logical_pos = offset + done as u64;
            let idx = logical_pos / BLOCK_SIZE as u64;
            let within = (logical_pos % BLOCK_SIZE as u64) as usize;
            let n = (BLOCK_SIZE - within).min(out.len() - done);
            let plain = self.read_block(&inner, idx)?;
            out[done..done + n].copy_from_slice(&plain[within..within + n]);
            done += n;
        }
        Ok(())
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), io::Error> {
        let mut inner = self.inner.write().expect("backend poisoned");
        let mut done = 0usize;
        while done < data.len() {
            let logical_pos = offset + done as u64;
            let idx = logical_pos / BLOCK_SIZE as u64;
            let within = (logical_pos % BLOCK_SIZE as u64) as usize;
            let n = (BLOCK_SIZE - within).min(data.len() - done);
            // Full-block aligned write needs no read; partial writes are RMW.
            let mut plain = if within == 0 && n == BLOCK_SIZE {
                [0u8; BLOCK_SIZE]
            } else {
                self.read_block(&inner, idx)?
            };
            plain[within..within + n].copy_from_slice(&data[done..done + n]);
            self.write_block(&mut inner, idx, &plain)?;
            done += n;
        }
        let end = offset + data.len() as u64;
        if end > inner.logical_len {
            inner.logical_len = end;
            let len = inner.logical_len;
            write_header(&self.cipher, &mut inner.file, len)?;
        }
        Ok(())
    }

    fn set_len(&self, len: u64) -> Result<(), io::Error> {
        let mut inner = self.inner.write().expect("backend poisoned");
        inner.logical_len = len;
        // Physically truncate to the matching block count when shrinking; growth
        // is materialized lazily on write (and gap-filled there).
        let needed_blocks = len.div_ceil(BLOCK_SIZE as u64);
        let needed_phys = HEADER_PHYS + needed_blocks * PHYS_BLOCK as u64;
        if inner.phys_len > needed_phys {
            inner.file.set_len(needed_phys)?;
            inner.phys_len = needed_phys;
        }
        // Match `ftruncate` semantics: bytes at or beyond `len` must read as
        // zero if the file is later regrown. The last logical block may still
        // physically hold stale bytes past the new boundary, so zero its tail.
        let rem = (len % BLOCK_SIZE as u64) as usize;
        if rem != 0 {
            let idx = len / BLOCK_SIZE as u64;
            let present = inner.phys_len >= block_phys_offset(idx + 1);
            if present {
                let mut plain = self.read_block(&inner, idx)?;
                plain[rem..].fill(0);
                self.write_block(&mut inner, idx, &plain)?;
            }
        }
        write_header(&self.cipher, &mut inner.file, len)?;
        Ok(())
    }

    fn sync_data(&self) -> Result<(), io::Error> {
        self.inner
            .read()
            .expect("backend poisoned")
            .file
            .sync_data()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngExt;

    fn backend(dir: &std::path::Path) -> EncryptedFileBackend {
        EncryptedFileBackend::open(&dir.join("t.redb"), [7u8; 32]).unwrap()
    }

    #[test]
    fn write_read_roundtrip_against_oracle() {
        let dir = tempfile::tempdir().unwrap();
        let be = backend(dir.path());
        let mut oracle: Vec<u8> = Vec::new();
        let mut rng = rand::rng();

        for _ in 0..400 {
            let len = rng.random_range(1..9000usize);
            let offset = rng.random_range(0..20_000u64);
            let end = offset as usize + len;
            if end as u64 > be.len().unwrap() {
                be.set_len(end as u64).unwrap();
            }
            if oracle.len() < end {
                oracle.resize(end, 0);
            }
            let data: Vec<u8> = (0..len).map(|_| rng.random()).collect();
            be.write(offset, &data).unwrap();
            oracle[offset as usize..end].copy_from_slice(&data);
        }

        // Full read-back must match the oracle.
        let mut got = vec![0u8; oracle.len()];
        be.read(0, &mut got).unwrap();
        assert_eq!(got, oracle);

        // Random sub-range reads must match too.
        for _ in 0..200 {
            if oracle.is_empty() {
                break;
            }
            let off = rng.random_range(0..oracle.len());
            let n = rng.random_range(0..(oracle.len() - off + 1));
            let mut buf = vec![0u8; n];
            be.read(off as u64, &mut buf).unwrap();
            assert_eq!(buf, &oracle[off..off + n]);
        }
    }

    #[test]
    fn shrink_then_grow_reads_zero() {
        let dir = tempfile::tempdir().unwrap();
        let be = backend(dir.path());
        be.set_len(10_000).unwrap();
        be.write(0, &[0xAB; 10_000]).unwrap();
        be.set_len(100).unwrap();
        be.set_len(10_000).unwrap();
        let mut buf = vec![0u8; 9_900];
        be.read(100, &mut buf).unwrap();
        assert!(
            buf.iter().all(|&b| b == 0),
            "grown region must read as zero"
        );
    }

    #[test]
    fn reopen_persists_data_and_len() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.redb");
        {
            let be = EncryptedFileBackend::open(&path, [9u8; 32]).unwrap();
            be.set_len(5000).unwrap();
            be.write(123, b"hello encrypted world").unwrap();
            be.sync_data().unwrap();
        }
        let be = EncryptedFileBackend::open(&path, [9u8; 32]).unwrap();
        assert_eq!(be.len().unwrap(), 5000);
        let mut buf = vec![0u8; 21];
        be.read(123, &mut buf).unwrap();
        assert_eq!(&buf, b"hello encrypted world");
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.redb");
        {
            let be = EncryptedFileBackend::open(&path, [1u8; 32]).unwrap();
            be.write(0, b"secret").unwrap();
            be.sync_data().unwrap();
        }
        assert!(EncryptedFileBackend::open(&path, [2u8; 32]).is_err());
    }

    #[test]
    fn plaintext_not_present_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.redb");
        let needle = b"TOPSECRETNEEDLE12345";
        {
            let be = EncryptedFileBackend::open(&path, [3u8; 32]).unwrap();
            be.write(64, needle).unwrap();
            be.sync_data().unwrap();
        }
        let mut raw = Vec::new();
        File::open(&path).unwrap().read_to_end(&mut raw).unwrap();
        assert!(
            !raw.windows(needle.len()).any(|w| w == needle),
            "plaintext leaked to disk"
        );
        // Magic is the only recognizable plaintext prefix.
        assert_eq!(&raw[..8], MAGIC);
    }

    #[test]
    fn foreign_file_is_recreated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.redb");
        std::fs::write(&path, b"redb-or-some-other-format-without-our-magic").unwrap();
        let be = EncryptedFileBackend::open(&path, [4u8; 32]).unwrap();
        assert_eq!(be.len().unwrap(), 0);
    }
}
