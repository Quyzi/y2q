//! AEAD envelope formats.
//!
//! **v1** (whole-object): Each PUT runs a fresh ML-KEM-768 encapsulation,
//! derives an AES-256-GCM key via HKDF-SHA256, and encrypts the entire
//! plaintext as a single AEAD ciphertext. Simple but requires buffering the
//! whole object in memory — not suitable for multi-GiB uploads.
//!
//! **v2** (1 MiB chunked): Same KEM encapsulation (once per object) and key
//! derivation, but the plaintext is split into 1 MiB chunks each encrypted
//! with an independently derived nonce (`nonce_base XOR chunk_idx`). Supports
//! streaming writes: receive a chunk, encrypt it, write it to disk, repeat.
//!
//! ## v1 on-disk layout
//! ```text
//! magic         [u8; 4]    = b"Y2Q1"
//! format_ver    u16 BE     = 1
//! kem_alg       u8         = 1 (ML-KEM-768)
//! aead_alg      u8         = 1 (AES-256-GCM)
//! nonce         [u8; 12]
//! plaintext_len u64 BE
//! kem_ct        [u8; 1088]
//! aead_ct       [u8; N + 16]   // ciphertext || GCM tag
//! ```
//! Total fixed overhead = 28 (header) + 1088 (KEM CT) + 16 (tag) = 1132 bytes.
//! AAD = 28-byte fixed header.
//!
//! ## v2 on-disk layout
//! ```text
//! magic         [u8; 4]    = b"Y2Q2"
//! format_ver    u16 BE     = 2
//! kem_alg       u8         = 1 (ML-KEM-768)
//! aead_alg      u8         = 1 (AES-256-GCM)
//! nonce_base    [u8; 12]
//! plaintext_len u64 BE     (patched after streaming completes)
//! chunk_size    u32 BE     = 1 048 576
//! kem_ct        [u8; 1088]
//! [ aead_ct     [u8; chunk_plaintext_len + 16] ] × N chunks
//! ```
//! Fixed header = 32 bytes.  Preamble (header + KEM CT) = 1120 bytes.
//! Chunk nonce_i = nonce_base XOR (i as u64 BE in bytes [4..12]).
//! AAD for each chunk = the 32-byte v2 fixed header.

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use pqcrypto::kem::mlkem768;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertextTrait, PublicKey as KemPublicKeyTrait,
    SecretKey as KemSecretKeyTrait, SharedSecret as KemSharedSecretTrait,
};
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use zeroize::Zeroize;

use super::CryptoError;

// ── v1 constants ─────────────────────────────────────────────────────────────

/// Header bytes preceding the KEM ciphertext in a v1 envelope.
///
/// Layout: 4 magic + 2 version + 1 kem_alg + 1 aead_alg + 12 nonce + 8 plaintext_len.
pub const ENVELOPE_HEADER_FIXED_LEN: usize = 4 + 2 + 1 + 1 + 12 + 8;

const MAGIC_V1: &[u8; 4] = b"Y2Q1";
const FORMAT_VER_V1: u16 = 1;

// ── v2 constants ─────────────────────────────────────────────────────────────

/// Fixed-header length for a v2 envelope (includes the 4-byte chunk_size field).
pub const ENVELOPE_V2_HEADER_FIXED_LEN: usize = 4 + 2 + 1 + 1 + 12 + 8 + 4; // = 32

const MAGIC_V2: &[u8; 4] = b"Y2Q2";
const FORMAT_VER_V2: u16 = 2;
/// 1 MiB plaintext chunks.
const CHUNK_SIZE: usize = 1 << 20;
/// Byte offset of `plaintext_len` inside the v2 fixed header.
const V2_PLAINTEXT_LEN_OFFSET: u64 = 20;

// ── shared constants ─────────────────────────────────────────────────────────

/// `kem_alg = 1` is reserved for ML-KEM-768.
const KEM_ALG_MLKEM768: u8 = 1;
/// `aead_alg = 1` is reserved for AES-256-GCM with a 12-byte nonce and 16-byte tag.
const AEAD_ALG_AES256GCM: u8 = 1;

// Shared MAGIC / FORMAT_VER kept for backward-compat with existing call sites.
const MAGIC: &[u8; 4] = MAGIC_V1;
const FORMAT_VER: u16 = FORMAT_VER_V1;

/// HKDF info string. Bumped if the KDF derivation changes.
const HKDF_INFO: &[u8] = b"y2q/v1/content-key";

/// Identifying string written into [`crate::Metadata::kem_alg`].
pub const KEM_ALG_NAME: &str = "ml-kem-768";
/// Identifying string written into [`crate::Metadata::aead_alg`].
pub const AEAD_ALG_NAME: &str = "aes-256-gcm";

/// Summary of a successful encryption, returned alongside the ciphertext so
/// the caller can persist these fields in the object's metadata sidecar.
#[derive(Debug, Clone)]
pub struct EnvelopeInfo {
    /// `format_ver` written into the envelope header.
    pub envelope_version: u16,
    /// Symbolic name of the KEM algorithm.
    pub kem_alg: &'static str,
    /// Symbolic name of the AEAD algorithm.
    pub aead_alg: &'static str,
    /// Total bytes in the envelope (what's stored on disk).
    pub cipher_size: u64,
}

/// Encrypt `plaintext` under `pk` with a fresh per-call KEM encapsulation.
///
/// Returns the on-disk envelope bytes plus an [`EnvelopeInfo`] describing the
/// ciphertext for metadata-sidecar use.
pub fn encrypt(pk_bytes: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, EnvelopeInfo), CryptoError> {
    let pk = mlkem768::PublicKey::from_bytes(pk_bytes)
        .map_err(|_| CryptoError::KemDecode("public key"))?;

    let (ss, kem_ct) = mlkem768::encapsulate(&pk);
    let kem_ct_bytes = kem_ct.as_bytes();

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let mut header = build_header(&nonce_bytes, plaintext.len() as u64);

    let key = derive_content_key(ss.as_bytes(), kem_ct_bytes)?;
    let cipher = Aes256Gcm::new((&key).into());
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let aead_ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| CryptoError::Aead("encrypt"))?;

    let mut out =
        Vec::with_capacity(ENVELOPE_HEADER_FIXED_LEN + kem_ct_bytes.len() + aead_ct.len());
    out.append(&mut header);
    out.extend_from_slice(kem_ct_bytes);
    out.extend_from_slice(&aead_ct);

    let info = EnvelopeInfo {
        envelope_version: FORMAT_VER,
        kem_alg: KEM_ALG_NAME,
        aead_alg: AEAD_ALG_NAME,
        cipher_size: out.len() as u64,
    };
    Ok((out, info))
}

/// Decrypt a complete envelope under `sk`.
///
/// Dispatches to v1 (whole-object) or v2 (chunked) decryption based on the
/// magic bytes. Returns the recovered plaintext on success.
pub fn decrypt(sk_bytes: &[u8], envelope: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if envelope.len() < 4 {
        return Err(CryptoError::Envelope("truncated header"));
    }
    match &envelope[..4] {
        m if m == MAGIC_V1 => decrypt_v1(sk_bytes, envelope),
        m if m == MAGIC_V2 => decrypt_v2(sk_bytes, envelope),
        _ => Err(CryptoError::Envelope("bad magic")),
    }
}

fn decrypt_v1(sk_bytes: &[u8], envelope: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let header = parse_and_validate_v1_header(envelope)?;
    let kem_ct_start = ENVELOPE_HEADER_FIXED_LEN;
    let kem_ct_end = kem_ct_start + mlkem768::ciphertext_bytes();
    if envelope.len() < kem_ct_end + 16 {
        return Err(CryptoError::Envelope("truncated envelope"));
    }
    let kem_ct_bytes = &envelope[kem_ct_start..kem_ct_end];
    let aead_ct = &envelope[kem_ct_end..];

    let sk = mlkem768::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| CryptoError::KemDecode("secret key"))?;
    let kem_ct = mlkem768::Ciphertext::from_bytes(kem_ct_bytes)
        .map_err(|_| CryptoError::KemDecode("kem ciphertext"))?;
    let ss = mlkem768::decapsulate(&kem_ct, &sk);

    let mut key = derive_content_key(ss.as_bytes(), kem_ct_bytes)?;
    let cipher = Aes256Gcm::new((&key).into());
    let nonce = aes_gcm::Nonce::from_slice(&header.nonce);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: aead_ct,
                aad: &envelope[..ENVELOPE_HEADER_FIXED_LEN],
            },
        )
        .map_err(|_| CryptoError::AuthFailed);
    key.zeroize();

    let pt = plaintext?;
    if pt.len() as u64 != header.plaintext_len {
        return Err(CryptoError::Envelope("plaintext length mismatch"));
    }
    Ok(pt)
}

fn decrypt_v2(sk_bytes: &[u8], envelope: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let preamble_len = ENVELOPE_V2_HEADER_FIXED_LEN + mlkem768::ciphertext_bytes();
    if envelope.len() < preamble_len {
        return Err(CryptoError::Envelope("truncated v2 envelope"));
    }
    if envelope[6] != KEM_ALG_MLKEM768 {
        return Err(CryptoError::Envelope("unknown kem_alg"));
    }
    if envelope[7] != AEAD_ALG_AES256GCM {
        return Err(CryptoError::Envelope("unknown aead_alg"));
    }
    let mut nonce_base = [0u8; 12];
    nonce_base.copy_from_slice(&envelope[8..20]);
    let plaintext_len = u64::from_be_bytes(envelope[20..28].try_into().unwrap());
    let chunk_size = u32::from_be_bytes(envelope[28..32].try_into().unwrap()) as usize;
    if chunk_size == 0 {
        return Err(CryptoError::Envelope("zero chunk_size"));
    }

    let kem_ct_bytes = &envelope[ENVELOPE_V2_HEADER_FIXED_LEN..preamble_len];
    // AAD = first 20 bytes only (magic…nonce_base), matching EncryptSession.
    let aad = &envelope[..V2_AAD_LEN];

    let sk = mlkem768::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| CryptoError::KemDecode("secret key"))?;
    let kem_ct = mlkem768::Ciphertext::from_bytes(kem_ct_bytes)
        .map_err(|_| CryptoError::KemDecode("kem ciphertext"))?;
    let ss = mlkem768::decapsulate(&kem_ct, &sk);

    let mut key = derive_content_key(ss.as_bytes(), kem_ct_bytes)?;
    let cipher = Aes256Gcm::new((&key).into());
    key.zeroize();

    let mut plaintext = if plaintext_len > 0 {
        Vec::with_capacity(plaintext_len as usize)
    } else {
        Vec::new()
    };

    let mut pos = preamble_len;
    let mut chunk_idx: u64 = 0;
    while pos < envelope.len() {
        let ct_end = (pos + chunk_size + 16).min(envelope.len());
        let ct_chunk = &envelope[pos..ct_end];
        if ct_chunk.len() < 16 {
            return Err(CryptoError::Envelope("truncated chunk ciphertext"));
        }
        let nonce = chunk_nonce(&nonce_base, chunk_idx);
        let pt = cipher
            .decrypt(
                aes_gcm::Nonce::from_slice(&nonce),
                Payload { msg: ct_chunk, aad },
            )
            .map_err(|_| CryptoError::AuthFailed)?;
        plaintext.extend_from_slice(&pt);
        pos = ct_end;
        chunk_idx += 1;
    }

    if plaintext_len > 0 && plaintext.len() as u64 != plaintext_len {
        return Err(CryptoError::Envelope("plaintext length mismatch"));
    }
    Ok(plaintext)
}

/// Length of the stable prefix used as per-chunk AAD in v2.
///
/// This is the first 20 bytes of the v2 fixed header: magic + format_ver +
/// kem_alg + aead_alg + nonce_base. The subsequent `plaintext_len` (bytes
/// 20-27) and `chunk_size` (bytes 28-31) are excluded because `plaintext_len`
/// is only known after all chunks are written (it's patched via seek), and
/// including a zero placeholder would cause an AAD mismatch at decrypt time.
const V2_AAD_LEN: usize = 20; // up to and including nonce_base

/// Streaming AES-256-GCM v2 encryptor that writes directly to a file.
///
/// Feed plaintext in arbitrary-sized chunks via [`feed`]; call [`finish`] when
/// done to flush the last chunk and patch the `plaintext_len` field in the
/// header. The file is returned so the caller can close or rename it.
///
/// `write_offset` is the byte offset within the file at which the v2 envelope
/// starts. Pass `0` when the envelope occupies the whole file (filesystem
/// backend). Pass `64` when a 64-byte container header precedes the envelope
/// (uring backend — the caller pre-writes a placeholder header before creating
/// the session).
pub struct EncryptSession {
    file: tokio::fs::File,
    cipher: Aes256Gcm,
    nonce_base: [u8; 12],
    chunk_idx: u64,
    buf: Vec<u8>,
    plaintext_total: u64,
    /// First 20 bytes of the fixed header (magic … nonce_base), used as AAD.
    aad: [u8; V2_AAD_LEN],
    bytes_written: u64,
    /// Byte offset within the file at which the v2 envelope begins.
    write_offset: u64,
}

impl EncryptSession {
    /// Create a new encrypt session for a v2 envelope.
    ///
    /// Writes the 32-byte fixed header (with `plaintext_len = 0`) and the
    /// 1088-byte KEM ciphertext to `file`, starting at the current file
    /// position (which must equal `write_offset`). Pass `write_offset = 0`
    /// when the envelope is the entire file; pass a non-zero value when a
    /// container header precedes it.
    pub async fn new(
        mut file: tokio::fs::File,
        pk_bytes: &[u8],
        write_offset: u64,
    ) -> Result<Self, CryptoError> {
        let pk = mlkem768::PublicKey::from_bytes(pk_bytes)
            .map_err(|_| CryptoError::KemDecode("public key"))?;
        let (ss, kem_ct) = mlkem768::encapsulate(&pk);
        let kem_ct_bytes = kem_ct.as_bytes();

        let mut nonce_base = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_base);

        // Build the 32-byte v2 fixed header (plaintext_len = 0 placeholder).
        let mut header = Vec::with_capacity(ENVELOPE_V2_HEADER_FIXED_LEN);
        header.extend_from_slice(MAGIC_V2);
        header.extend_from_slice(&FORMAT_VER_V2.to_be_bytes());
        header.push(KEM_ALG_MLKEM768);
        header.push(AEAD_ALG_AES256GCM);
        header.extend_from_slice(&nonce_base);
        header.extend_from_slice(&0u64.to_be_bytes()); // plaintext_len placeholder
        header.extend_from_slice(&(CHUNK_SIZE as u32).to_be_bytes());

        file.write_all(&header)
            .await
            .map_err(|_| CryptoError::Aead("write header"))?;
        file.write_all(kem_ct_bytes)
            .await
            .map_err(|_| CryptoError::Aead("write kem ct"))?;

        let key = derive_content_key(ss.as_bytes(), kem_ct_bytes)?;
        let cipher = Aes256Gcm::new((&key).into());
        let bytes_written = (header.len() + kem_ct_bytes.len()) as u64;

        let mut aad = [0u8; V2_AAD_LEN];
        aad.copy_from_slice(&header[..V2_AAD_LEN]);

        Ok(Self {
            file,
            cipher,
            nonce_base,
            chunk_idx: 0,
            buf: Vec::with_capacity(CHUNK_SIZE),
            plaintext_total: 0,
            aad,
            bytes_written,
            write_offset,
        })
    }

    /// Buffer `data` and flush complete 1 MiB chunks to the file as encrypted.
    pub async fn feed(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let mut remaining = data;
        while !remaining.is_empty() {
            let space = CHUNK_SIZE - self.buf.len();
            let take = remaining.len().min(space);
            self.buf.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
            if self.buf.len() == CHUNK_SIZE {
                self.flush_chunk().await?;
            }
        }
        Ok(())
    }

    /// Flush remaining buffered data, seek back to patch `plaintext_len`, and
    /// return the file handle plus [`EnvelopeInfo`].
    pub async fn finish(mut self) -> Result<(tokio::fs::File, EnvelopeInfo), CryptoError> {
        if !self.buf.is_empty() {
            self.flush_chunk().await?;
        }
        let cipher_size = self.bytes_written;

        // Patch plaintext_len at its position within the v2 envelope.
        self.file
            .seek(std::io::SeekFrom::Start(self.write_offset + V2_PLAINTEXT_LEN_OFFSET))
            .await
            .map_err(|_| CryptoError::Aead("seek plaintext_len"))?;
        self.file
            .write_all(&self.plaintext_total.to_be_bytes())
            .await
            .map_err(|_| CryptoError::Aead("write plaintext_len"))?;
        // Return to end so callers can do further writes / flush / close.
        self.file
            .seek(std::io::SeekFrom::End(0))
            .await
            .map_err(|_| CryptoError::Aead("seek end"))?;

        Ok((
            self.file,
            EnvelopeInfo {
                envelope_version: FORMAT_VER_V2,
                kem_alg: KEM_ALG_NAME,
                aead_alg: AEAD_ALG_NAME,
                cipher_size,
            },
        ))
    }

    async fn flush_chunk(&mut self) -> Result<(), CryptoError> {
        let nonce = chunk_nonce(&self.nonce_base, self.chunk_idx);
        let ct = self
            .cipher
            .encrypt(
                aes_gcm::Nonce::from_slice(&nonce),
                Payload {
                    msg: &self.buf,
                    aad: &self.aad,
                },
            )
            .map_err(|_| CryptoError::Aead("encrypt chunk"))?;
        self.plaintext_total += self.buf.len() as u64;
        self.bytes_written += ct.len() as u64;
        self.file
            .write_all(&ct)
            .await
            .map_err(|_| CryptoError::Aead("write chunk"))?;
        self.buf.clear();
        self.chunk_idx += 1;
        Ok(())
    }
}

/// Derive a per-chunk nonce by XORing `chunk_idx` (as big-endian u64) into
/// bytes [4..12] of `nonce_base`.
fn chunk_nonce(base: &[u8; 12], idx: u64) -> [u8; 12] {
    let mut n = *base;
    let idx_bytes = idx.to_be_bytes();
    for i in 0..8 {
        n[4 + i] ^= idx_bytes[i];
    }
    n
}

/// Sniff the magic+version prefix to decide whether `bytes` is an encrypted
/// y2q envelope (v1 or v2). Used by GET to fall through to plaintext for
/// legacy objects written before encryption was enabled.
pub fn looks_encrypted(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    match &bytes[..4] {
        m if m == MAGIC_V1 => {
            bytes.len() >= ENVELOPE_HEADER_FIXED_LEN + mlkem768::ciphertext_bytes() + 16
        }
        m if m == MAGIC_V2 => {
            bytes.len() >= ENVELOPE_V2_HEADER_FIXED_LEN + mlkem768::ciphertext_bytes()
        }
        _ => false,
    }
}

/// Parsed view of the 28-byte v1 fixed header.
struct V1Header {
    nonce: [u8; 12],
    plaintext_len: u64,
}

fn build_header(nonce: &[u8; 12], plaintext_len: u64) -> Vec<u8> {
    let mut h = Vec::with_capacity(ENVELOPE_HEADER_FIXED_LEN);
    h.extend_from_slice(MAGIC);
    h.extend_from_slice(&FORMAT_VER.to_be_bytes());
    h.push(KEM_ALG_MLKEM768);
    h.push(AEAD_ALG_AES256GCM);
    h.extend_from_slice(nonce);
    h.extend_from_slice(&plaintext_len.to_be_bytes());
    h
}

fn parse_and_validate_v1_header(env: &[u8]) -> Result<V1Header, CryptoError> {
    if env.len() < ENVELOPE_HEADER_FIXED_LEN {
        return Err(CryptoError::Envelope("truncated header"));
    }
    if &env[0..4] != MAGIC_V1 {
        return Err(CryptoError::Envelope("bad magic"));
    }
    let ver = u16::from_be_bytes([env[4], env[5]]);
    if ver != FORMAT_VER_V1 {
        return Err(CryptoError::UnsupportedVersion(ver));
    }
    if env[6] != KEM_ALG_MLKEM768 {
        return Err(CryptoError::Envelope("unknown kem_alg"));
    }
    if env[7] != AEAD_ALG_AES256GCM {
        return Err(CryptoError::Envelope("unknown aead_alg"));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&env[8..20]);
    let plaintext_len = u64::from_be_bytes(env[20..28].try_into().unwrap());
    Ok(V1Header { nonce, plaintext_len })
}

fn derive_content_key(ss: &[u8], kem_ct: &[u8]) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(kem_ct), ss);
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .map_err(|_| CryptoError::Aead("hkdf expand"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_small() {
        let (pk, sk) = mlkem768::keypair();
        let pt = b"hello, post-quantum world";
        let (env, info) = encrypt(pk.as_bytes(), pt).unwrap();
        assert!(info.cipher_size as usize == env.len());
        assert!(env.len() > pt.len() + 1000);
        let recovered = decrypt(sk.as_bytes(), &env).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn roundtrip_empty() {
        let (pk, sk) = mlkem768::keypair();
        let (env, _) = encrypt(pk.as_bytes(), b"").unwrap();
        let pt = decrypt(sk.as_bytes(), &env).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn roundtrip_large() {
        let (pk, sk) = mlkem768::keypair();
        let pt = vec![0xAB; 1 << 20];
        let (env, _) = encrypt(pk.as_bytes(), &pt).unwrap();
        let rec = decrypt(sk.as_bytes(), &env).unwrap();
        assert_eq!(rec, pt);
    }

    #[test]
    fn fresh_kem_per_call() {
        let (pk, _sk) = mlkem768::keypair();
        let (a, _) = encrypt(pk.as_bytes(), b"x").unwrap();
        let (b, _) = encrypt(pk.as_bytes(), b"x").unwrap();
        assert_ne!(a, b, "two encrypts of same plaintext must differ");
    }

    #[test]
    fn tamper_byte_breaks_decrypt() {
        let (pk, sk) = mlkem768::keypair();
        let (mut env, _) = encrypt(pk.as_bytes(), b"some payload").unwrap();
        let last = env.len() - 1;
        env[last] ^= 1;
        assert!(matches!(
            decrypt(sk.as_bytes(), &env),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn wrong_key_breaks_decrypt() {
        let (pk1, _) = mlkem768::keypair();
        let (_, sk2) = mlkem768::keypair();
        let (env, _) = encrypt(pk1.as_bytes(), b"hi").unwrap();
        assert!(decrypt(sk2.as_bytes(), &env).is_err());
    }

    #[test]
    fn bad_magic_rejected() {
        let mut env = vec![0u8; ENVELOPE_HEADER_FIXED_LEN + 2000];
        env[0] = b'X';
        let (_, sk) = mlkem768::keypair();
        assert!(matches!(
            decrypt(sk.as_bytes(), &env),
            Err(CryptoError::Envelope("bad magic"))
        ));
    }

    #[test]
    fn unsupported_version_rejected() {
        let (pk, sk) = mlkem768::keypair();
        let (mut env, _) = encrypt(pk.as_bytes(), b"hi").unwrap();
        env[4] = 0xff;
        env[5] = 0xff;
        assert!(matches!(
            decrypt(sk.as_bytes(), &env),
            Err(CryptoError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn looks_encrypted_works() {
        let (pk, _) = mlkem768::keypair();
        let (env, _) = encrypt(pk.as_bytes(), b"hi").unwrap();
        assert!(looks_encrypted(&env));
        assert!(!looks_encrypted(b"plain bytes"));
        assert!(!looks_encrypted(b""));
    }

    // ── v2 EncryptSession tests ───────────────────────────────────────────

    #[tokio::test]
    async fn v2_roundtrip_small() {
        let (pk, sk) = mlkem768::keypair();
        let pt = b"hello chunked world";
        let file = tempfile_v2().await;
        let mut session = EncryptSession::new(file, pk.as_bytes(), 0).await.unwrap();
        session.feed(pt).await.unwrap();
        let (file, info) = session.finish().await.unwrap();
        assert_eq!(info.envelope_version, 2);
        let env = read_file(file).await;
        assert!(looks_encrypted(&env));
        let recovered = decrypt(sk.as_bytes(), &env).unwrap();
        assert_eq!(recovered, pt);
    }

    #[tokio::test]
    async fn v2_roundtrip_empty() {
        let (pk, sk) = mlkem768::keypair();
        let file = tempfile_v2().await;
        let session = EncryptSession::new(file, pk.as_bytes(), 0).await.unwrap();
        let (file, _) = session.finish().await.unwrap();
        let env = read_file(file).await;
        let recovered = decrypt(sk.as_bytes(), &env).unwrap();
        assert!(recovered.is_empty());
    }

    #[tokio::test]
    async fn v2_roundtrip_multi_chunk() {
        let (pk, sk) = mlkem768::keypair();
        // 2.5 MiB — spans three chunks
        let pt = vec![0xAB_u8; 5 * (1 << 20) / 2];
        let file = tempfile_v2().await;
        let mut session = EncryptSession::new(file, pk.as_bytes(), 0).await.unwrap();
        // Feed in small slices to exercise partial-chunk buffering.
        for chunk in pt.chunks(65536) {
            session.feed(chunk).await.unwrap();
        }
        let (file, info) = session.finish().await.unwrap();
        assert_eq!(info.cipher_size, {
            let env = read_file_clone(&file).await;
            env.len() as u64
        });
        let env = read_file(file).await;
        let recovered = decrypt(sk.as_bytes(), &env).unwrap();
        assert_eq!(recovered, pt);
    }

    #[tokio::test]
    async fn v2_tamper_breaks_decrypt() {
        let (pk, sk) = mlkem768::keypair();
        let file = tempfile_v2().await;
        let mut session = EncryptSession::new(file, pk.as_bytes(), 0).await.unwrap();
        session.feed(b"some payload").await.unwrap();
        let (file, _) = session.finish().await.unwrap();
        let mut env = read_file(file).await;
        let last = env.len() - 1;
        env[last] ^= 1;
        assert!(decrypt(sk.as_bytes(), &env).is_err());
    }

    async fn tempfile_v2() -> tokio::fs::File {
        let path = std::env::temp_dir().join(format!("y2q_test_{}.env", rand_u64()));
        tokio::fs::OpenOptions::new()
            .write(true).read(true).create(true).truncate(true)
            .open(&path).await.unwrap()
    }

    async fn read_file(file: tokio::fs::File) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let mut f = file;
        f.seek(std::io::SeekFrom::Start(0)).await.unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).await.unwrap();
        buf
    }

    async fn read_file_clone(file: &tokio::fs::File) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let mut f = file.try_clone().await.unwrap();
        f.seek(std::io::SeekFrom::Start(0)).await.unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).await.unwrap();
        buf
    }

    fn rand_u64() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as u64
    }
}
