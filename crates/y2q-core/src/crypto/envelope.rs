//! AEAD envelope formats.
//!
//! **v1** (whole-object): Each PUT runs a fresh ML-KEM-768 encapsulation,
//! derives an AES-256-GCM key via HKDF-SHA256, and encrypts the entire
//! plaintext as a single AEAD ciphertext. Simple but requires buffering the
//! whole object in memory — not suitable for multi-GiB uploads.
//!
//! **v2** (chunked): Same KEM encapsulation (once per object) and key
//! derivation, but the plaintext is split into fixed-size chunks (default 4 MiB,
//! configurable per write and recorded in the header) each encrypted with an
//! independently derived nonce (`nonce_base XOR chunk_idx`). Supports streaming
//! writes: receive a chunk, encrypt it, write it to disk, repeat. Because every
//! chunk but the last is full-size, plaintext offsets map deterministically to
//! ciphertext offsets, enabling ranged decryption.
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
//! chunk_size    u32 BE     (plaintext chunk size; default 4 MiB)
//! kem_ct        [u8; 1088]
//! [ aead_ct     [u8; chunk_plaintext_len + 16] ] × N chunks
//! ```
//! Fixed header = 32 bytes.  Preamble (header + KEM CT) = 1120 bytes.
//! Chunk nonce_i = nonce_base XOR (i as u64 BE in bytes [4..12]).
//! AAD for each chunk = the 32-byte v2 fixed header.

use aes_gcm::{Aes256Gcm, KeyInit, aead::AeadInPlace};

type Nonce = aes_gcm::aead::Nonce<Aes256Gcm>;
use bytes::{Bytes, BytesMut};
use hkdf::Hkdf;
use pqcrypto::kem::mlkem768;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertextTrait, PublicKey as KemPublicKeyTrait,
    SecretKey as KemSecretKeyTrait, SharedSecret as KemSharedSecretTrait,
};
use rand::Rng;
use sha2::Sha256;
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
/// Default v2 plaintext chunk size (4 MiB) when no config override is given.
/// The actual size used per object is recorded in the envelope header, so
/// decryption never depends on this constant.
pub const DEFAULT_CHUNK_SIZE_BYTES: usize = 4 << 20;
/// Byte offset of `plaintext_len` inside the v2 fixed header.
///
/// Public so cluster replicas can backfill this field verbatim: the CRAQ HEAD
/// patches it locally at `finish()` but does not forward the patch down-chain
/// (the [`Tee`](crate::storage::streaming_sink::StreamingSink::Tee) only mirrors
/// appends), so a downstream node applies the same patch from a PREPARE header
/// to keep its on-disk envelope byte-identical.
pub const V2_PLAINTEXT_LEN_OFFSET: u64 = 20;

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

/// AES-256-GCM authentication tag length in bytes.
const TAG_LEN: usize = 16;

/// Identifying string written into [`crate::Metadata::kem_alg`].
pub const KEM_ALG_NAME: &str = "ml-kem-768";
/// Identifying string written into [`crate::Metadata::aead_alg`].
pub const AEAD_ALG_NAME: &str = "aes-256-gcm";

/// Padmé-padded length for a plaintext of `l` bytes.
///
/// Padmé (Nikitin et al., "Reducing Metadata Leakage from Encrypted Files…",
/// PETS 2019) rounds `l` up so that the padded size leaks at most O(log log l)
/// bits about the true size, with overhead bounded below ~12%. The on-disk
/// `plaintext_len` / container `data_len` fields therefore reveal only a coarse
/// bucket, not the exact object size. The true size is kept in the encrypted
/// metadata sidecar and used to trim the decrypted plaintext on read.
pub fn padme_len(l: u64) -> u64 {
    if l < 2 {
        return l;
    }
    // e = floor(log2 l)  (>= 1 for l >= 2)
    let e: u32 = 63 - l.leading_zeros();
    // s = floor(log2 e) + 1
    let s: u32 = (31 - e.leading_zeros()) + 1;
    if e <= s {
        return l;
    }
    let last_bits = e - s;
    let mask: u64 = (1u64 << last_bits) - 1;
    l.saturating_add(mask) & !mask
}

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
    rand::rng().fill_bytes(&mut nonce_bytes);

    let header = build_header(&nonce_bytes, plaintext.len() as u64);

    let mut key_bytes = derive_content_key(ss.as_bytes(), kem_ct_bytes)?;
    let cipher = aes_key(&key_bytes);
    key_bytes.zeroize();

    // Encrypt plaintext into a buffer; aes-gcm appends the 16-byte GCM tag
    // in-place, avoiding a separate ciphertext allocation.
    let mut ct_buf: Vec<u8> = plaintext.to_vec();
    cipher
        .encrypt_in_place(&aes_nonce(&nonce_bytes), &header[..], &mut ct_buf)
        .map_err(|_| CryptoError::Aead("encrypt"))?;

    let mut out = Vec::with_capacity(ENVELOPE_HEADER_FIXED_LEN + kem_ct_bytes.len() + ct_buf.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(kem_ct_bytes);
    out.extend_from_slice(&ct_buf);

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
    if envelope.len() < kem_ct_end + TAG_LEN {
        return Err(CryptoError::Envelope("truncated envelope"));
    }
    let kem_ct_bytes = &envelope[kem_ct_start..kem_ct_end];
    let aead_ct = &envelope[kem_ct_end..];

    let sk = mlkem768::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| CryptoError::KemDecode("secret key"))?;
    let kem_ct = mlkem768::Ciphertext::from_bytes(kem_ct_bytes)
        .map_err(|_| CryptoError::KemDecode("kem ciphertext"))?;
    let ss = mlkem768::decapsulate(&kem_ct, &sk);

    let mut key_bytes = derive_content_key(ss.as_bytes(), kem_ct_bytes)?;
    let cipher = aes_key(&key_bytes);
    key_bytes.zeroize();

    // Decrypt in-place: verifies the tag and truncates the buffer to plaintext,
    // avoiding a second Vec allocation.
    let mut ct_buf = aead_ct.to_vec();
    cipher
        .decrypt_in_place(
            &aes_nonce(&header.nonce),
            &envelope[..ENVELOPE_HEADER_FIXED_LEN],
            &mut ct_buf,
        )
        .map_err(|_| CryptoError::AuthFailed)?;

    if ct_buf.len() as u64 != header.plaintext_len {
        return Err(CryptoError::Envelope("plaintext length mismatch"));
    }
    Ok(ct_buf)
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
    let aad = &envelope[..V2_AAD_LEN];

    let sk = mlkem768::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| CryptoError::KemDecode("secret key"))?;
    let kem_ct = mlkem768::Ciphertext::from_bytes(kem_ct_bytes)
        .map_err(|_| CryptoError::KemDecode("kem ciphertext"))?;
    let ss = mlkem768::decapsulate(&kem_ct, &sk);

    let mut key_bytes = derive_content_key(ss.as_bytes(), kem_ct_bytes)?;
    let cipher = aes_key(&key_bytes);
    key_bytes.zeroize();

    let mut plaintext = if plaintext_len > 0 {
        Vec::with_capacity(plaintext_len as usize)
    } else {
        Vec::new()
    };

    let mut pos = preamble_len;
    let mut chunk_idx: u64 = 0;
    while pos < envelope.len() {
        let ct_end = (pos + chunk_size + TAG_LEN).min(envelope.len());
        if ct_end - pos < TAG_LEN {
            return Err(CryptoError::Envelope("truncated chunk ciphertext"));
        }
        let chunk_nonce_bytes = chunk_nonce(&nonce_base, chunk_idx);
        let mut chunk_buf = envelope[pos..ct_end].to_vec();
        cipher
            .decrypt_in_place(&aes_nonce(&chunk_nonce_bytes), aad, &mut chunk_buf)
            .map_err(|_| CryptoError::AuthFailed)?;
        plaintext.extend_from_slice(&chunk_buf);
        pos = ct_end;
        chunk_idx += 1;
    }

    if plaintext_len > 0 && plaintext.len() as u64 != plaintext_len {
        return Err(CryptoError::Envelope("plaintext length mismatch"));
    }
    Ok(plaintext)
}

/// Decrypt a complete envelope, consuming an owned `BytesMut` buffer.
///
/// Identical semantics to [`decrypt`], but lets v1/v2 reuse the input
/// allocation for the in-place AEAD open instead of allocating a fresh
/// ciphertext buffer per call. Returns the recovered plaintext as `Bytes`
/// (zero-copy of the freed underlying allocation).
pub fn decrypt_owned(sk_bytes: &[u8], envelope: BytesMut) -> Result<Bytes, CryptoError> {
    if envelope.len() < 4 {
        return Err(CryptoError::Envelope("truncated header"));
    }
    match &envelope[..4] {
        m if m == MAGIC_V1 => decrypt_v1_owned(sk_bytes, envelope),
        m if m == MAGIC_V2 => decrypt_v2_owned(sk_bytes, envelope),
        _ => Err(CryptoError::Envelope("bad magic")),
    }
}

fn decrypt_v1_owned(sk_bytes: &[u8], mut envelope: BytesMut) -> Result<Bytes, CryptoError> {
    let header = parse_and_validate_v1_header(&envelope)?;
    let kem_ct_start = ENVELOPE_HEADER_FIXED_LEN;
    let kem_ct_end = kem_ct_start + mlkem768::ciphertext_bytes();
    if envelope.len() < kem_ct_end + TAG_LEN {
        return Err(CryptoError::Envelope("truncated envelope"));
    }
    // Small fixed-size AAD snapshot — released before we split the body off.
    let mut aad_bytes = [0u8; ENVELOPE_HEADER_FIXED_LEN];
    aad_bytes.copy_from_slice(&envelope[..ENVELOPE_HEADER_FIXED_LEN]);
    // ML-KEM ciphertext is small (1088 bytes); cheap to clone out so we can
    // free the prefix and decrypt the (potentially huge) aead_ct in place.
    let kem_ct_owned: Vec<u8> = envelope[kem_ct_start..kem_ct_end].to_vec();

    let sk = mlkem768::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| CryptoError::KemDecode("secret key"))?;
    let kem_ct = mlkem768::Ciphertext::from_bytes(&kem_ct_owned)
        .map_err(|_| CryptoError::KemDecode("kem ciphertext"))?;
    let ss = mlkem768::decapsulate(&kem_ct, &sk);

    let mut key_bytes = derive_content_key(ss.as_bytes(), &kem_ct_owned)?;
    let cipher = aes_key(&key_bytes);
    key_bytes.zeroize();

    // O(1) split: `body` owns the aead_ct region of the original allocation.
    let body = envelope.split_off(kem_ct_end);
    drop(envelope);
    let mut body_vec: Vec<u8> = body.into();
    cipher
        .decrypt_in_place(&aes_nonce(&header.nonce), &aad_bytes[..], &mut body_vec)
        .map_err(|_| CryptoError::AuthFailed)?;

    if body_vec.len() as u64 != header.plaintext_len {
        return Err(CryptoError::Envelope("plaintext length mismatch"));
    }
    Ok(Bytes::from(body_vec))
}

fn decrypt_v2_owned(sk_bytes: &[u8], mut envelope: BytesMut) -> Result<Bytes, CryptoError> {
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
    let mut aad = [0u8; V2_AAD_LEN];
    aad.copy_from_slice(&envelope[..V2_AAD_LEN]);
    let kem_ct_owned: Vec<u8> = envelope[ENVELOPE_V2_HEADER_FIXED_LEN..preamble_len].to_vec();

    let sk = mlkem768::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| CryptoError::KemDecode("secret key"))?;
    let kem_ct = mlkem768::Ciphertext::from_bytes(&kem_ct_owned)
        .map_err(|_| CryptoError::KemDecode("kem ciphertext"))?;
    let ss = mlkem768::decapsulate(&kem_ct, &sk);

    let mut key_bytes = derive_content_key(ss.as_bytes(), &kem_ct_owned)?;
    let cipher = aes_key(&key_bytes);
    key_bytes.zeroize();

    // Drop the preamble; `body` retains the chunked ciphertext region.
    let mut body = envelope.split_off(preamble_len);
    drop(envelope);

    let mut plaintext = if plaintext_len > 0 {
        BytesMut::with_capacity(plaintext_len as usize)
    } else {
        BytesMut::new()
    };

    let mut chunk_idx: u64 = 0;
    while !body.is_empty() {
        let take = (chunk_size + TAG_LEN).min(body.len());
        if take < TAG_LEN {
            return Err(CryptoError::Envelope("truncated chunk ciphertext"));
        }
        let chunk_nonce_bytes = chunk_nonce(&nonce_base, chunk_idx);
        // O(1) split: `chunk_buf` owns this chunk's ciphertext region.
        let chunk_buf = body.split_to(take);
        let mut chunk_vec: Vec<u8> = chunk_buf.into();
        cipher
            .decrypt_in_place(&aes_nonce(&chunk_nonce_bytes), &aad[..], &mut chunk_vec)
            .map_err(|_| CryptoError::AuthFailed)?;
        plaintext.extend_from_slice(&chunk_vec);
        chunk_idx += 1;
    }

    if plaintext_len > 0 && plaintext.len() as u64 != plaintext_len {
        return Err(CryptoError::Envelope("plaintext length mismatch"));
    }
    Ok(plaintext.freeze())
}

/// Number of bytes before the first chunk in a v2 envelope: the 32-byte fixed
/// header plus the 1088-byte ML-KEM-768 ciphertext. A ranged read must fetch at
/// least this prefix to recover the content key and chunk geometry.
pub fn v2_preamble_len() -> usize {
    ENVELOPE_V2_HEADER_FIXED_LEN + mlkem768::ciphertext_bytes()
}

/// Parse `(chunk_size, plaintext_len)` from the fixed portion of a v2 header.
///
/// `header` must be at least [`ENVELOPE_V2_HEADER_FIXED_LEN`] bytes. Validates
/// the v2 magic, version, and algorithm IDs.
pub fn parse_v2_geometry(header: &[u8]) -> Result<(u32, u64), CryptoError> {
    if header.len() < ENVELOPE_V2_HEADER_FIXED_LEN {
        return Err(CryptoError::Envelope("truncated v2 header"));
    }
    if &header[0..4] != MAGIC_V2 {
        return Err(CryptoError::Envelope("bad magic"));
    }
    let ver = u16::from_be_bytes([header[4], header[5]]);
    if ver != FORMAT_VER_V2 {
        return Err(CryptoError::UnsupportedVersion(ver));
    }
    if header[6] != KEM_ALG_MLKEM768 {
        return Err(CryptoError::Envelope("unknown kem_alg"));
    }
    if header[7] != AEAD_ALG_AES256GCM {
        return Err(CryptoError::Envelope("unknown aead_alg"));
    }
    let plaintext_len = u64::from_be_bytes(header[20..28].try_into().unwrap());
    let chunk_size = u32::from_be_bytes(header[28..32].try_into().unwrap());
    if chunk_size == 0 {
        return Err(CryptoError::Envelope("zero chunk_size"));
    }
    Ok((chunk_size, plaintext_len))
}

/// Decrypt a contiguous run of whole v2 chunks beginning at `first_chunk_idx`.
///
/// `preamble` must be the first [`v2_preamble_len`] bytes of the envelope (used
/// to recover the content key, chunk geometry, and AAD). `chunks_ct` holds the
/// ciphertext for chunks `[first_chunk_idx ..]`, aligned to a chunk boundary
/// (i.e. it must start exactly at the on-disk offset of `first_chunk_idx`).
///
/// Returns the concatenated plaintext of the decrypted whole chunks; the caller
/// trims to the exact requested byte range. Used by ranged GET; the per-chunk
/// AEAD nonce and AAD match [`decrypt_v2`].
pub fn decrypt_v2_chunks(
    sk_bytes: &[u8],
    preamble: &[u8],
    chunks_ct: &[u8],
    first_chunk_idx: u64,
) -> Result<Vec<u8>, CryptoError> {
    let preamble_len = v2_preamble_len();
    if preamble.len() < preamble_len {
        return Err(CryptoError::Envelope("truncated v2 preamble"));
    }
    let (chunk_size_u32, _plaintext_len) =
        parse_v2_geometry(&preamble[..ENVELOPE_V2_HEADER_FIXED_LEN])?;
    let chunk_size = chunk_size_u32 as usize;

    let mut nonce_base = [0u8; 12];
    nonce_base.copy_from_slice(&preamble[8..20]);
    let aad = &preamble[..V2_AAD_LEN];

    let kem_ct_bytes = &preamble[ENVELOPE_V2_HEADER_FIXED_LEN..preamble_len];

    let sk = mlkem768::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| CryptoError::KemDecode("secret key"))?;
    let kem_ct = mlkem768::Ciphertext::from_bytes(kem_ct_bytes)
        .map_err(|_| CryptoError::KemDecode("kem ciphertext"))?;
    let ss = mlkem768::decapsulate(&kem_ct, &sk);

    let mut key_bytes = derive_content_key(ss.as_bytes(), kem_ct_bytes)?;
    let cipher = aes_key(&key_bytes);
    key_bytes.zeroize();

    let mut plaintext = Vec::with_capacity(chunks_ct.len());
    let mut pos = 0usize;
    let mut chunk_idx = first_chunk_idx;
    while pos < chunks_ct.len() {
        let ct_end = (pos + chunk_size + TAG_LEN).min(chunks_ct.len());
        if ct_end - pos < TAG_LEN {
            return Err(CryptoError::Envelope("truncated chunk ciphertext"));
        }
        let chunk_nonce_bytes = chunk_nonce(&nonce_base, chunk_idx);
        let mut chunk_buf = chunks_ct[pos..ct_end].to_vec();
        cipher
            .decrypt_in_place(&aes_nonce(&chunk_nonce_bytes), aad, &mut chunk_buf)
            .map_err(|_| CryptoError::AuthFailed)?;
        plaintext.extend_from_slice(&chunk_buf);
        pos = ct_end;
        chunk_idx += 1;
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
    sink: crate::storage::streaming_sink::StreamingSink,
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
    /// Plaintext chunk size used for this session (recorded in the header).
    chunk_size: usize,
}

impl EncryptSession {
    /// Create a new encrypt session for a v2 envelope.
    ///
    /// Writes the 32-byte fixed header (with `plaintext_len = 0`) and the
    /// 1088-byte KEM ciphertext to `sink`, starting at the sink's current
    /// cursor (which must equal `write_offset`). Pass `write_offset = 0`
    /// when the envelope is the entire file; pass a non-zero value when a
    /// container header precedes it.
    pub async fn new(
        mut sink: crate::storage::streaming_sink::StreamingSink,
        pk_bytes: &[u8],
        write_offset: u64,
        chunk_size: usize,
    ) -> Result<Self, CryptoError> {
        if chunk_size == 0 || chunk_size > u32::MAX as usize {
            return Err(CryptoError::Envelope("invalid chunk_size"));
        }
        let pk = mlkem768::PublicKey::from_bytes(pk_bytes)
            .map_err(|_| CryptoError::KemDecode("public key"))?;
        let (ss, kem_ct) = mlkem768::encapsulate(&pk);
        let kem_ct_bytes = kem_ct.as_bytes();

        let mut nonce_base = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_base);

        // Build the 32-byte v2 fixed header (plaintext_len = 0 placeholder).
        let mut header = Vec::with_capacity(ENVELOPE_V2_HEADER_FIXED_LEN);
        header.extend_from_slice(MAGIC_V2);
        header.extend_from_slice(&FORMAT_VER_V2.to_be_bytes());
        header.push(KEM_ALG_MLKEM768);
        header.push(AEAD_ALG_AES256GCM);
        header.extend_from_slice(&nonce_base);
        header.extend_from_slice(&0u64.to_be_bytes()); // plaintext_len placeholder
        header.extend_from_slice(&(chunk_size as u32).to_be_bytes());

        sink.write_all(&header)
            .await
            .map_err(|_| CryptoError::Aead("write header"))?;
        sink.write_all(kem_ct_bytes)
            .await
            .map_err(|_| CryptoError::Aead("write kem ct"))?;

        let mut key_bytes = derive_content_key(ss.as_bytes(), kem_ct_bytes)?;
        let cipher = aes_key(&key_bytes);
        key_bytes.zeroize();

        let bytes_written = (header.len() + kem_ct_bytes.len()) as u64;

        let mut aad = [0u8; V2_AAD_LEN];
        aad.copy_from_slice(&header[..V2_AAD_LEN]);

        Ok(Self {
            sink,
            cipher,
            nonce_base,
            chunk_idx: 0,
            buf: Vec::with_capacity(chunk_size),
            plaintext_total: 0,
            aad,
            bytes_written,
            write_offset,
            chunk_size,
        })
    }

    /// Buffer `data` and flush complete chunks to the sink as encrypted.
    pub async fn feed(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let mut remaining = data;
        while !remaining.is_empty() {
            let space = self.chunk_size - self.buf.len();
            let take = remaining.len().min(space);
            self.buf.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
            if self.buf.len() == self.chunk_size {
                self.flush_chunk().await?;
            }
        }
        Ok(())
    }

    /// Flush remaining buffered data, patch `plaintext_len` at its v2 header
    /// position, and return the sink (now positioned at end-of-data) plus
    /// [`EnvelopeInfo`].
    pub async fn finish(
        mut self,
    ) -> Result<(crate::storage::streaming_sink::StreamingSink, EnvelopeInfo), CryptoError> {
        // Zero-pad up to the Padmé boundary to hide the exact object size. The
        // padding is appended to the still-unflushed tail buffer (and beyond),
        // flushing full chunks as it fills so that — as the chunk format
        // requires — only the final chunk is shorter than `chunk_size`. The
        // cleartext `plaintext_len` therefore becomes the padded length; the
        // true size lives only in the encrypted metadata sidecar and trims the
        // plaintext on read.
        let real_total = self.plaintext_total + self.buf.len() as u64;
        let target = padme_len(real_total);
        let mut pad_remaining = target - real_total;
        while pad_remaining > 0 {
            let space = self.chunk_size - self.buf.len();
            let take = (space as u64).min(pad_remaining) as usize;
            self.buf.resize(self.buf.len() + take, 0);
            pad_remaining -= take as u64;
            if self.buf.len() == self.chunk_size {
                self.flush_chunk().await?;
            }
        }
        // Flush the final (possibly partial) chunk of real tail + padding.
        if !self.buf.is_empty() {
            self.flush_chunk().await?;
        }

        let cipher_size = self.bytes_written;

        // Patch plaintext_len at its position within the v2 envelope.
        self.sink
            .write_all_at(
                &self.plaintext_total.to_be_bytes(),
                self.write_offset + V2_PLAINTEXT_LEN_OFFSET,
            )
            .await
            .map_err(|_| CryptoError::Aead("write plaintext_len"))?;
        // Return to end so callers can do further writes / flush / close.
        self.sink
            .seek_to_end()
            .await
            .map_err(|_| CryptoError::Aead("seek end"))?;

        Ok((
            self.sink,
            EnvelopeInfo {
                envelope_version: FORMAT_VER_V2,
                kem_alg: KEM_ALG_NAME,
                aead_alg: AEAD_ALG_NAME,
                cipher_size,
            },
        ))
    }

    async fn flush_chunk(&mut self) -> Result<(), CryptoError> {
        let chunk_nonce_bytes = chunk_nonce(&self.nonce_base, self.chunk_idx);
        let plaintext_len = self.buf.len();

        // Encrypt self.buf in-place; aes-gcm appends the 16-byte tag, so
        // self.buf becomes [ciphertext || tag] with no separate ct allocation.
        self.cipher
            .encrypt_in_place(&aes_nonce(&chunk_nonce_bytes), &self.aad[..], &mut self.buf)
            .map_err(|_| CryptoError::Aead("encrypt chunk"))?;

        self.plaintext_total += plaintext_len as u64;
        self.bytes_written += self.buf.len() as u64;
        self.sink
            .write_all(&self.buf)
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

/// Build an [`Aes256Gcm`] cipher from a 32-byte AES-256 key.
fn aes_key(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(key.into())
}

/// Wrap a 12-byte array into an AES-GCM [`Nonce`].
fn aes_nonce(bytes: &[u8; 12]) -> Nonce {
    Nonce::clone_from_slice(bytes)
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
            bytes.len() >= ENVELOPE_HEADER_FIXED_LEN + mlkem768::ciphertext_bytes() + TAG_LEN
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
    Ok(V1Header {
        nonce,
        plaintext_len,
    })
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
    fn decrypt_owned_v1_roundtrip() {
        let (pk, sk) = mlkem768::keypair();
        let pt = vec![0xCD; 4096];
        let (env, _) = encrypt(pk.as_bytes(), &pt).unwrap();
        let rec = decrypt_owned(sk.as_bytes(), BytesMut::from(env.as_slice())).unwrap();
        assert_eq!(rec.as_ref(), pt.as_slice());
    }

    #[test]
    fn decrypt_owned_v1_tamper() {
        let (pk, sk) = mlkem768::keypair();
        let (mut env, _) = encrypt(pk.as_bytes(), b"abc").unwrap();
        let last = env.len() - 1;
        env[last] ^= 1;
        assert!(matches!(
            decrypt_owned(sk.as_bytes(), BytesMut::from(env.as_slice())),
            Err(CryptoError::AuthFailed)
        ));
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
        let mut session = EncryptSession::new(file, pk.as_bytes(), 0, DEFAULT_CHUNK_SIZE_BYTES)
            .await
            .unwrap();
        session.feed(pt).await.unwrap();
        let (file, info) = session.finish().await.unwrap();
        assert_eq!(info.envelope_version, 2);
        let env = read_file(file).await;
        assert!(looks_encrypted(&env));
        let recovered = decrypt(sk.as_bytes(), &env).unwrap();
        // The envelope zero-pads to a Padmé boundary to hide the exact size; the
        // higher layer trims to the true size from metadata. The recovered
        // plaintext therefore carries the original bytes followed by zero pad.
        assert_eq!(recovered.len() as u64, padme_len(pt.len() as u64));
        assert_eq!(&recovered[..pt.len()], pt);
        assert!(recovered[pt.len()..].iter().all(|&b| b == 0));
    }

    #[test]
    fn padme_len_never_shrinks_and_is_bounded() {
        for l in [0u64, 1, 2, 3, 19, 1000, 1 << 20, (1 << 20) + 1, 12_345_678] {
            let p = padme_len(l);
            assert!(p >= l, "padme({l}) = {p} shrank");
            // Padmé overhead is bounded well under ~12%.
            if l > 0 {
                assert!(
                    p <= l + l / 8 + 1,
                    "padme({l}) = {p} exceeds the ~12% overhead bound"
                );
            }
        }
        // Powers of two and their multiples by the bucket size are unchanged.
        assert_eq!(padme_len(0), 0);
        assert_eq!(padme_len(1), 1);
        assert_eq!(padme_len(1 << 20), 1 << 20);
    }

    #[tokio::test]
    async fn v2_quantizes_size_and_trims_back() {
        let (pk, sk) = mlkem768::keypair();
        // Two plaintexts of slightly different size that share a Padmé bucket.
        let a = vec![0x11u8; 1000];
        let b = vec![0x22u8; 1001];
        assert_eq!(
            padme_len(a.len() as u64),
            padme_len(b.len() as u64),
            "test inputs must share a Padmé bucket"
        );

        let mut sizes = Vec::new();
        for pt in [&a, &b] {
            let file = tempfile_v2().await;
            let mut session = EncryptSession::new(file, pk.as_bytes(), 0, DEFAULT_CHUNK_SIZE_BYTES)
                .await
                .unwrap();
            session.feed(pt).await.unwrap();
            let (file, info) = session.finish().await.unwrap();
            sizes.push(info.cipher_size);
            // The decrypted plaintext is padded; trimming to the true size (as
            // the GET handler does from metadata) recovers the original bytes.
            let env = read_file(file).await;
            let recovered = decrypt(sk.as_bytes(), &env).unwrap();
            assert_eq!(&recovered[..pt.len()], pt.as_slice());
        }
        // The on-disk envelope size is identical for both, so it leaks only the
        // bucket, not which of the two objects was stored.
        assert_eq!(sizes[0], sizes[1], "cipher size must be quantized");
    }

    #[tokio::test]
    async fn v2_roundtrip_empty() {
        let (pk, sk) = mlkem768::keypair();
        let file = tempfile_v2().await;
        let session = EncryptSession::new(file, pk.as_bytes(), 0, DEFAULT_CHUNK_SIZE_BYTES)
            .await
            .unwrap();
        let (file, _) = session.finish().await.unwrap();
        let env = read_file(file).await;
        let recovered = decrypt(sk.as_bytes(), &env).unwrap();
        assert!(recovered.is_empty());
    }

    #[tokio::test]
    async fn v2_roundtrip_multi_chunk() {
        let (pk, sk) = mlkem768::keypair();
        // 2.5 chunks — spans three chunks (last is partial)
        let pt = vec![0xAB_u8; 5 * DEFAULT_CHUNK_SIZE_BYTES / 2];
        let file = tempfile_v2().await;
        let mut session = EncryptSession::new(file, pk.as_bytes(), 0, DEFAULT_CHUNK_SIZE_BYTES)
            .await
            .unwrap();
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
    async fn decrypt_owned_v2_multi_chunk() {
        let (pk, sk) = mlkem768::keypair();
        let pt = vec![0x37_u8; 5 * DEFAULT_CHUNK_SIZE_BYTES / 2];
        let file = tempfile_v2().await;
        let mut session = EncryptSession::new(file, pk.as_bytes(), 0, DEFAULT_CHUNK_SIZE_BYTES)
            .await
            .unwrap();
        for chunk in pt.chunks(65536) {
            session.feed(chunk).await.unwrap();
        }
        let (file, _) = session.finish().await.unwrap();
        let env = read_file(file).await;
        let rec = decrypt_owned(sk.as_bytes(), BytesMut::from(env.as_slice())).unwrap();
        assert_eq!(rec.as_ref(), pt.as_slice());
    }

    #[tokio::test]
    async fn v2_ranged_decrypt_matches_full() {
        let (pk, sk) = mlkem768::keypair();
        // Use a small chunk size so the test stays cheap but still multi-chunk.
        let chunk_size = 4096usize;
        let pt: Vec<u8> = (0..(chunk_size * 5 / 2)).map(|i| (i % 251) as u8).collect();
        let file = tempfile_v2().await;
        let mut session = EncryptSession::new(file, pk.as_bytes(), 0, chunk_size)
            .await
            .unwrap();
        for c in pt.chunks(777) {
            session.feed(c).await.unwrap();
        }
        let (file, info) = session.finish().await.unwrap();
        let env = read_file(file).await;
        let cipher_size = info.cipher_size;
        let preamble_len = v2_preamble_len();
        let stride = chunk_size + TAG_LEN;

        // Exercise several ranges: within one chunk, across a boundary, into the
        // final partial chunk, a single byte, and the whole object.
        let ranges = [
            (0u64, 9u64),
            (chunk_size as u64 - 5, chunk_size as u64 + 5),
            (chunk_size as u64, 2 * chunk_size as u64 - 1),
            (2 * chunk_size as u64, pt.len() as u64 - 1),
            (chunk_size as u64 + 100, chunk_size as u64 + 100),
            (0, pt.len() as u64 - 1),
        ];
        for (start, end) in ranges {
            let first = start / chunk_size as u64;
            let last = end / chunk_size as u64;
            let cipher_start = preamble_len as u64 + first * stride as u64;
            let cipher_end =
                (preamble_len as u64 + (last + 1) * stride as u64 - 1).min(cipher_size - 1);
            let preamble = &env[..preamble_len];
            let window = &env[cipher_start as usize..=cipher_end as usize];
            let chunks_pt = decrypt_v2_chunks(sk.as_bytes(), preamble, window, first).unwrap();
            let trim_front = (start - first * chunk_size as u64) as usize;
            let take = (end - start + 1) as usize;
            let got = &chunks_pt[trim_front..trim_front + take];
            assert_eq!(
                got,
                &pt[start as usize..=end as usize],
                "range {start}-{end}"
            );
        }
    }

    #[tokio::test]
    async fn v2_tamper_breaks_decrypt() {
        let (pk, sk) = mlkem768::keypair();
        let file = tempfile_v2().await;
        let mut session = EncryptSession::new(file, pk.as_bytes(), 0, DEFAULT_CHUNK_SIZE_BYTES)
            .await
            .unwrap();
        session.feed(b"some payload").await.unwrap();
        let (file, _) = session.finish().await.unwrap();
        let mut env = read_file(file).await;
        let last = env.len() - 1;
        env[last] ^= 1;
        assert!(decrypt(sk.as_bytes(), &env).is_err());
    }

    async fn tempfile_v2() -> crate::storage::streaming_sink::StreamingSink {
        let path = std::env::temp_dir().join(format!("y2q_test_{}.env", rand_u64()));
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .await
            .unwrap();
        crate::storage::streaming_sink::StreamingSink::Tokio(file)
    }

    fn into_file(sink: crate::storage::streaming_sink::StreamingSink) -> tokio::fs::File {
        match sink {
            crate::storage::streaming_sink::StreamingSink::Tokio(f) => f,
            #[cfg(target_os = "linux")]
            _ => panic!("envelope tests expect a Tokio sink"),
        }
    }

    async fn read_file(sink: crate::storage::streaming_sink::StreamingSink) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let mut f = into_file(sink);
        f.seek(std::io::SeekFrom::Start(0)).await.unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).await.unwrap();
        buf
    }

    async fn read_file_clone(sink: &crate::storage::streaming_sink::StreamingSink) -> Vec<u8> {
        let f = match sink {
            crate::storage::streaming_sink::StreamingSink::Tokio(f) => f,
            #[cfg(target_os = "linux")]
            _ => panic!("envelope tests expect a Tokio sink"),
        };
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let mut f = f.try_clone().await.unwrap();
        f.seek(std::io::SeekFrom::Start(0)).await.unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).await.unwrap();
        buf
    }

    fn rand_u64() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos() as u64
    }
}
