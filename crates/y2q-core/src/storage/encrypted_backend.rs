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
//! The file key is derived from the operator-supplied node key, installed
//! once at boot ([`crate::crypto::derive_index_file_key`]). Used by
//! [`crate::storage::index::MetadataIndex`] for `_y2q_index.redb`.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::RwLock;

#[cfg(unix)]
fn file_read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
fn file_read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut total = 0;
    while total < buf.len() {
        let n = file.seek_read(&mut buf[total..], offset + total as u64)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF during positioned read",
            ));
        }
        total += n;
    }
    Ok(())
}

#[cfg(unix)]
fn file_write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(buf, offset)
}

#[cfg(windows)]
fn file_write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut total = 0;
    while total < buf.len() {
        let n = file.seek_write(&buf[total..], offset + total as u64)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "zero-byte positioned write",
            ));
        }
        total += n;
    }
    Ok(())
}

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
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
/// Format version sealed in the header, as a single byte at plaintext offset 0.
///
/// Version 1 stored this as a big-endian `u32`, so a legacy header always has
/// `0x00` in that byte — which is not a valid version-2 tag. That makes the two
/// layouts distinguishable with no ambiguity and no extra field.
const FORMAT_VERSION: u8 = 2;
/// Legacy (version-1) files are recognized by a zero first byte.
const LEGACY_VERSION_TAG: u8 = 0x00;
/// Set in the header flags byte while a legacy re-seal is in progress; see
/// [`EncryptedFileBackend::reseal_legacy_blocks`].
const FLAG_RESEAL_PENDING: u8 = 1 << 0;
/// Plaintext bytes sealed in the header. Unchanged from version 1 so that
/// [`HEADER_PHYS`] — and therefore every block offset — stays put across the
/// version bump.
///
/// Version 2 layout: version(1) + flags(1) + logical_len(u48 BE) +
/// nonce_epoch(u48 BE) + reserved(2).
const HEADER_PLAINTEXT_LEN: usize = 16;
/// Physical header size: magic + nonce + sealed(header plaintext) + tag.
const HEADER_PHYS: u64 = (8 + NONCE_LEN + HEADER_PLAINTEXT_LEN + TAG_LEN) as u64;
/// Largest value representable in the 48-bit `logical_len`, `nonce_epoch` and
/// nonce-sequence fields.
const MAX_U48: u64 = (1 << 48) - 1;

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
    /// High half of every nonce this backend emits. Bumped once per open and
    /// persisted before the first block write, so no two runs of the process
    /// can ever share a nonce namespace — including across a hard crash.
    epoch: u64,
    /// Low half of every nonce, incremented on each seal within this epoch.
    seq: u64,
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

/// What [`EncryptedFileBackend::open`] does with a non-empty file that does not
/// carry [`MAGIC`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForeignFile {
    /// Truncate and recreate. Only correct for a rebuildable cache.
    Recreate,
    /// Refuse to open. Correct for anything whose loss is unrecoverable.
    Reject,
}

impl EncryptedFileBackend {
    /// Open (or create) the encrypted file at `path` under `file_key`.
    ///
    /// If the file is empty it is initialized with a fresh header. If it carries
    /// our [`MAGIC`] the header is decrypted and validated (a wrong key or
    /// tampering yields an error). If it is non-empty but does **not** carry our
    /// magic, `on_foreign` decides: [`ForeignFile::Recreate`] destroys and
    /// recreates it (for a rebuildable index), [`ForeignFile::Reject`] refuses.
    pub fn open(
        path: &Path,
        file_key: [u8; 32],
        on_foreign: ForeignFile,
    ) -> Result<Self, io::Error> {
        let mut open_options = OpenOptions::new();
        open_options
            .read(true)
            .write(true)
            .create(true)
            .truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open_options.mode(0o600);
        }
        let file = open_options.open(path)?;
        Self::open_file(file, file_key, on_foreign)
    }

    /// Same as [`Self::open`] for a file the caller has already opened.
    ///
    /// The handle must be readable and writable. Used by callers that need to
    /// control the create mode themselves (e.g. the user store).
    pub fn open_file(
        mut file: File,
        file_key: [u8; 32],
        on_foreign: ForeignFile,
    ) -> Result<Self, io::Error> {
        let cipher = Aes256Gcm::new((&file_key).into());

        let initial_phys = file.metadata()?.len();
        let stored = if initial_phys == 0 {
            // Fresh file.
            StoredHeader::default()
        } else if initial_phys >= 8 && read_magic(&mut file)? == *MAGIC {
            read_header(&cipher, &mut file)?
        } else if on_foreign == ForeignFile::Reject {
            return Err(invalid_data("encrypted file has no recognizable magic"));
        } else {
            // Foreign/legacy/corrupt file with no recognizable magic.
            // Recreate — but this is destructive (the prior contents are
            // gone), so make it observable in logs where it would otherwise
            // be silent.
            tracing::error!(
                phys_len = initial_phys,
                "encrypted index file has no recognizable magic; destroying and recreating it"
            );
            file.set_len(0)?;
            StoredHeader::default()
        };

        // Reserve a fresh nonce namespace for this run. Burning an epoch before
        // the first block write is what makes the scheme crash-safe: a run that
        // dies without a clean shutdown still never shares nonces with the next
        // one, because the next one reads the persisted epoch and moves past it.
        let epoch = stored
            .nonce_epoch
            .checked_add(1)
            .filter(|e| *e <= MAX_U48)
            .ok_or_else(|| invalid_data("index nonce epoch exhausted"))?;

        // Re-stat: the branches above may have truncated the file.
        let phys_len = file.metadata()?.len();

        let backend = Self {
            cipher,
            inner: RwLock::new(Inner {
                file,
                logical_len: stored.logical_len,
                phys_len,
                epoch,
                seq: 0,
            }),
        };

        {
            let mut inner = backend.inner.write().expect("backend poisoned");
            let needs_reseal = stored.legacy || stored.reseal_pending;
            // Persist the new epoch (and, for a legacy file, the in-progress
            // marker) before anything else can be written under it.
            backend.write_header(&mut inner, needs_reseal)?;
            inner.file.sync_data()?;
            if needs_reseal {
                backend.reseal_legacy_blocks(&mut inner)?;
            }
        }

        Ok(backend)
    }

    /// Next nonce in this backend's namespace: `epoch (6B BE) || seq (6B BE)`.
    ///
    /// Replaces the per-block random draw the version-1 format used. A random
    /// 96-bit nonce under one long-lived file key has a birthday bound that a
    /// busy index erodes; a strictly increasing counter has none, and costs a
    /// increment instead of an RNG call.
    fn next_nonce(inner: &mut Inner) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..6].copy_from_slice(&inner.epoch.to_be_bytes()[2..]);
        nonce[6..].copy_from_slice(&inner.seq.to_be_bytes()[2..]);
        inner.seq += 1;
        nonce
    }

    /// Roll to the next epoch when the 48-bit sequence is exhausted, persisting
    /// it before it is used.
    ///
    /// Unreachable in practice — 2^48 blocks is an exabyte of writes in one
    /// open — but the counter must not silently wrap onto nonces this run has
    /// already emitted.
    fn ensure_nonce_space(&self, inner: &mut Inner) -> Result<(), io::Error> {
        if inner.seq < MAX_U48 {
            return Ok(());
        }
        let next = inner
            .epoch
            .checked_add(1)
            .filter(|e| *e <= MAX_U48)
            .ok_or_else(|| invalid_data("index nonce epoch exhausted"))?;
        inner.epoch = next;
        inner.seq = 0;
        self.write_header(inner, false)?;
        inner.file.sync_data()?;
        Ok(())
    }

    /// Seal and write the header carrying the current logical length and epoch.
    fn write_header(&self, inner: &mut Inner, reseal_pending: bool) -> Result<(), io::Error> {
        if inner.logical_len > MAX_U48 {
            return Err(invalid_data("index logical length exceeds 48-bit field"));
        }
        let mut plaintext = [0u8; HEADER_PLAINTEXT_LEN];
        plaintext[0] = FORMAT_VERSION;
        plaintext[1] = if reseal_pending {
            FLAG_RESEAL_PENDING
        } else {
            0
        };
        plaintext[2..8].copy_from_slice(&inner.logical_len.to_be_bytes()[2..]);
        plaintext[8..14].copy_from_slice(&inner.epoch.to_be_bytes()[2..]);
        // bytes 14..16 remain zero — reserved.

        let nonce = Self::next_nonce(inner);
        let ct = self
            .cipher
            .encrypt(
                &aes_gcm::Nonce::from(nonce),
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
        file_write_all_at(&inner.file, &out, 0)?;
        if HEADER_PHYS > inner.phys_len {
            inner.phys_len = HEADER_PHYS;
        }
        Ok(())
    }

    /// Re-seal every existing block under the current (fresh) epoch.
    ///
    /// Version-1 blocks carry random nonces, which could in principle collide
    /// with a deterministic one, so a legacy file is re-sealed rather than
    /// merely re-headered. This is offset-preserving and needs no temp file:
    /// each block's nonce is stored inline, so a half-migrated file is a legal
    /// mix of old- and new-nonce blocks that still reads correctly. The
    /// in-progress marker in the header is only cleared at the end, and the
    /// epoch was already advanced and persisted before the first rewrite, so an
    /// interrupted run resumes under a genuinely fresh namespace.
    fn reseal_legacy_blocks(&self, inner: &mut Inner) -> Result<(), io::Error> {
        let blocks = inner.phys_len.saturating_sub(HEADER_PHYS) / PHYS_BLOCK as u64;
        if blocks > 0 {
            tracing::info!(
                blocks,
                "re-sealing index blocks under a deterministic nonce"
            );
        }
        for idx in 0..blocks {
            let plain = self.read_block(inner, idx)?;
            self.write_block(inner, idx, &plain)?;
        }
        self.write_header(inner, false)?;
        inner.file.sync_data()?;
        if blocks > 0 {
            tracing::info!(blocks, "index re-seal complete");
        }
        Ok(())
    }

    /// Seal `BLOCK_SIZE` plaintext bytes for data block `idx` into a physical block.
    fn seal_block(
        &self,
        inner: &mut Inner,
        idx: u64,
        plain: &[u8; BLOCK_SIZE],
    ) -> Result<Vec<u8>, io::Error> {
        let nonce = Self::next_nonce(inner);
        let ct = self
            .cipher
            .encrypt(
                &aes_gcm::Nonce::from(nonce),
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
        file_read_exact_at(&inner.file, &mut buf, phys)?;
        let nonce = &buf[..NONCE_LEN];
        let ct = &buf[NONCE_LEN..];
        let plain = self
            .cipher
            .decrypt(
                &aes_gcm::Nonce::try_from(nonce).expect("nonce slice is NONCE_LEN bytes"),
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
        self.ensure_nonce_space(inner)?;
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
                let sealed = self.seal_block(inner, gap, &zero)?;
                batch.extend_from_slice(&sealed);
            }
            file_write_all_at(&inner.file, &batch, block_phys_offset(next_missing))?;
        }
        let block = self.seal_block(inner, idx, plain)?;
        file_write_all_at(&inner.file, &block, block_phys_offset(idx))?;
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

/// What [`read_header`] recovered from an existing file.
#[derive(Debug, Default, Clone, Copy)]
struct StoredHeader {
    logical_len: u64,
    /// Highest nonce epoch the file has ever been written under. `0` for a
    /// fresh or version-1 file.
    nonce_epoch: u64,
    /// The file predates the deterministic-nonce format and its blocks carry
    /// random nonces.
    legacy: bool,
    /// A previous run started re-sealing and did not finish.
    reseal_pending: bool,
}

/// Read and validate the header.
///
/// Accepts both layouts. Version 1 is recognized by a zero first byte (it
/// stored the version as a big-endian `u32`), which is not a valid version-2
/// tag, so the two can never be confused.
fn read_header(cipher: &Aes256Gcm, file: &mut File) -> Result<StoredHeader, io::Error> {
    let mut buf = vec![0u8; HEADER_PHYS as usize];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut buf)?;
    let nonce = &buf[8..8 + NONCE_LEN];
    let ct = &buf[8 + NONCE_LEN..];
    let plain = cipher
        .decrypt(
            &aes_gcm::Nonce::try_from(nonce).expect("nonce slice is NONCE_LEN bytes"),
            aes_gcm::aead::Payload {
                msg: ct,
                aad: MAGIC,
            },
        )
        .map_err(|_| invalid_data("index header decrypt/auth (wrong key or tampered)"))?;
    if plain.len() != HEADER_PLAINTEXT_LEN {
        return Err(invalid_data("index header wrong length"));
    }

    if plain[0] == LEGACY_VERSION_TAG {
        let version = u32::from_be_bytes(plain[0..4].try_into().unwrap());
        if version != 1 {
            return Err(invalid_data(format!("unsupported index format {version}")));
        }
        let block_size = u32::from_be_bytes(plain[4..8].try_into().unwrap()) as usize;
        if block_size != BLOCK_SIZE {
            return Err(invalid_data(format!(
                "index block size mismatch: file {block_size}, expected {BLOCK_SIZE}"
            )));
        }
        return Ok(StoredHeader {
            logical_len: u64::from_be_bytes(plain[8..16].try_into().unwrap()),
            nonce_epoch: 0,
            legacy: true,
            reseal_pending: false,
        });
    }

    if plain[0] != FORMAT_VERSION {
        return Err(invalid_data(format!(
            "unsupported index format {}",
            plain[0]
        )));
    }
    Ok(StoredHeader {
        logical_len: read_u48(&plain[2..8]),
        nonce_epoch: read_u48(&plain[8..14]),
        legacy: false,
        reseal_pending: plain[1] & FLAG_RESEAL_PENDING != 0,
    })
}

/// Decode a 48-bit big-endian field.
fn read_u48(bytes: &[u8]) -> u64 {
    let mut wide = [0u8; 8];
    wide[2..].copy_from_slice(bytes);
    u64::from_be_bytes(wide)
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
            self.write_header(&mut inner, false)?;
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
        self.write_header(&mut inner, false)?;
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
        EncryptedFileBackend::open(&dir.join("t.redb"), [7u8; 32], ForeignFile::Recreate).unwrap()
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
            let be = EncryptedFileBackend::open(&path, [9u8; 32], ForeignFile::Recreate).unwrap();
            be.set_len(5000).unwrap();
            be.write(123, b"hello encrypted world").unwrap();
            be.sync_data().unwrap();
        }
        let be = EncryptedFileBackend::open(&path, [9u8; 32], ForeignFile::Recreate).unwrap();
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
            let be = EncryptedFileBackend::open(&path, [1u8; 32], ForeignFile::Recreate).unwrap();
            be.write(0, b"secret").unwrap();
            be.sync_data().unwrap();
        }
        assert!(EncryptedFileBackend::open(&path, [2u8; 32], ForeignFile::Recreate).is_err());
    }

    #[test]
    fn plaintext_not_present_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.redb");
        let needle = b"TOPSECRETNEEDLE12345";
        {
            let be = EncryptedFileBackend::open(&path, [3u8; 32], ForeignFile::Recreate).unwrap();
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
        let be = EncryptedFileBackend::open(&path, [4u8; 32], ForeignFile::Recreate).unwrap();
        assert_eq!(be.len().unwrap(), 0);
    }

    #[test]
    fn foreign_file_is_rejected_when_asked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.redb");
        std::fs::write(&path, b"redb-or-some-other-format-without-our-magic").unwrap();
        let err = EncryptedFileBackend::open(&path, [4u8; 32], ForeignFile::Reject).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // The foreign contents must survive an attempted open.
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"redb-or-some-other-format-without-our-magic"
        );
    }

    #[test]
    #[cfg(unix)]
    fn index_file_is_created_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.redb");
        let _be = EncryptedFileBackend::open(&path, [5u8; 32], ForeignFile::Recreate).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "index file must be created 0600");
    }

    /// Every block's 12-byte nonce, read straight off the physical file.
    fn block_nonces(path: &std::path::Path) -> Vec<u128> {
        let raw = std::fs::read(path).unwrap();
        let blocks = (raw.len() as u64 - HEADER_PHYS) / PHYS_BLOCK as u64;
        (0..blocks)
            .map(|i| {
                let at = block_phys_offset(i) as usize;
                let mut wide = [0u8; 16];
                wide[4..].copy_from_slice(&raw[at..at + NONCE_LEN]);
                u128::from_be_bytes(wide)
            })
            .collect()
    }

    #[test]
    fn block_nonces_are_deterministic_and_strictly_increasing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.redb");

        {
            let be = EncryptedFileBackend::open(&path, [11u8; 32], ForeignFile::Recreate).unwrap();
            be.set_len(64 * BLOCK_SIZE as u64).unwrap();
            for i in 0..64u64 {
                be.write(i * BLOCK_SIZE as u64, &[i as u8; BLOCK_SIZE])
                    .unwrap();
            }
            be.sync_data().unwrap();
        }
        let first = block_nonces(&path);
        assert_eq!(first.len(), 64);
        let mut sorted = first.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), first.len(), "nonces must all be distinct");
        assert!(
            first.windows(2).all(|w| w[0] < w[1]),
            "nonces must be strictly increasing"
        );

        // A second open must burn an epoch, so nothing it writes can collide
        // with the first run even though the counter restarts at zero.
        {
            let be = EncryptedFileBackend::open(&path, [11u8; 32], ForeignFile::Recreate).unwrap();
            for i in 0..64u64 {
                be.write(i * BLOCK_SIZE as u64, &[(i + 1) as u8; BLOCK_SIZE])
                    .unwrap();
            }
            be.sync_data().unwrap();
        }
        let second = block_nonces(&path);
        let first_max = first.iter().max().copied().unwrap();
        assert!(
            second.iter().all(|n| *n > first_max),
            "a reopened backend must not reuse the previous run's nonce space"
        );
    }

    /// Write a version-1 header: version as a big-endian u32, block size, and
    /// logical length, sealed under a random nonce exactly as the old code did.
    fn write_legacy_header(cipher: &Aes256Gcm, file: &File, logical_len: u64) {
        use rand::Rng as _;
        let mut plaintext = [0u8; HEADER_PLAINTEXT_LEN];
        plaintext[0..4].copy_from_slice(&1u32.to_be_bytes());
        plaintext[4..8].copy_from_slice(&(BLOCK_SIZE as u32).to_be_bytes());
        plaintext[8..16].copy_from_slice(&logical_len.to_be_bytes());
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(
                &aes_gcm::Nonce::from(nonce),
                aes_gcm::aead::Payload {
                    msg: &plaintext,
                    aad: MAGIC,
                },
            )
            .unwrap();
        let mut out = Vec::with_capacity(HEADER_PHYS as usize);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        file_write_all_at(file, &out, 0).unwrap();
    }

    #[test]
    fn legacy_version_one_file_is_resealed_on_open() {
        use rand::Rng as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.redb");
        let key = [13u8; 32];
        let cipher = Aes256Gcm::new((&key).into());

        // Build a version-1 file by hand: legacy header plus blocks sealed
        // under random nonces, which is exactly what the old writer produced.
        let payload: Vec<[u8; BLOCK_SIZE]> = (0..4u8).map(|i| [i + 1; BLOCK_SIZE]).collect();
        {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            write_legacy_header(&cipher, &file, 4 * BLOCK_SIZE as u64);
            for (idx, plain) in payload.iter().enumerate() {
                let mut nonce = [0u8; NONCE_LEN];
                rand::rng().fill_bytes(&mut nonce);
                let ct = cipher
                    .encrypt(
                        &aes_gcm::Nonce::from(nonce),
                        aes_gcm::aead::Payload {
                            msg: plain.as_slice(),
                            aad: &(idx as u64).to_be_bytes(),
                        },
                    )
                    .unwrap();
                let mut block = Vec::with_capacity(PHYS_BLOCK);
                block.extend_from_slice(&nonce);
                block.extend_from_slice(&ct);
                file_write_all_at(&file, &block, block_phys_offset(idx as u64)).unwrap();
            }
        }

        let legacy_nonces = block_nonces(&path);
        assert_eq!(legacy_nonces.len(), 4);

        // Opening migrates it: data survives, header flips to version 2, and
        // every block carries a deterministic nonce afterwards.
        {
            let be = EncryptedFileBackend::open(&path, key, ForeignFile::Reject).unwrap();
            assert_eq!(be.len().unwrap(), 4 * BLOCK_SIZE as u64);
            for (idx, plain) in payload.iter().enumerate() {
                let mut got = vec![0u8; BLOCK_SIZE];
                be.read(idx as u64 * BLOCK_SIZE as u64, &mut got).unwrap();
                assert_eq!(got.as_slice(), plain.as_slice(), "block {idx} lost data");
            }
            be.sync_data().unwrap();
        }

        let migrated = block_nonces(&path);
        assert!(
            migrated.windows(2).all(|w| w[0] < w[1]),
            "re-sealed blocks must carry increasing deterministic nonces"
        );
        assert!(
            migrated.iter().all(|n| !legacy_nonces.contains(n)),
            "no legacy random nonce may survive the re-seal"
        );

        // The on-disk header is now version 2, so a later open takes the
        // ordinary path rather than migrating again.
        let mut file = File::open(&path).unwrap();
        let stored = read_header(&cipher, &mut file).unwrap();
        assert!(!stored.legacy);
        assert!(!stored.reseal_pending);
        assert_eq!(stored.logical_len, 4 * BLOCK_SIZE as u64);
        assert!(stored.nonce_epoch >= 1);
    }
}
