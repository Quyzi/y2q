//! AEAD envelope format (v3, chunked).
//!
//! Each PUT runs a fresh ML-KEM-768 encapsulation (once per object) and
//! derives an AES-256-GCM key via HKDF-SHA256, bound to the object's
//! `(bucket, key)` address (see [`derive_content_key`]) so a ciphertext
//! valid for one object cannot be relocated onto another object's storage
//! location and decrypt there. The plaintext is split into fixed-size chunks
//! (default 4 MiB, configurable per write and recorded in the header) each
//! encrypted with an independently derived nonce (`nonce_base XOR
//! chunk_idx`). Supports streaming writes: receive a chunk, encrypt it,
//! write it to disk, repeat. Because every chunk but the last is full-size,
//! plaintext offsets map deterministically to ciphertext offsets, enabling
//! ranged decryption.
//!
//! ## on-disk layout
//! ```text
//! magic         [u8; 4]    = b"Y2Q3"
//! format_ver    u16 BE     = 3 (legacy, read-only) or 4 (current)
//! kem_alg       u8         = 1 (ML-KEM-768)
//! aead_alg      u8         = 1 (AES-256-GCM)
//! key_epoch     u32 BE     (which bucket key epoch's public key sealed kem_ct)
//! nonce_base    [u8; 12]
//! plaintext_len u64 BE     (patched after streaming completes)
//! chunk_size    u32 BE     (plaintext chunk size; default 4 MiB)
//! kem_ct        [u8; 1088]
//! [ aead_ct     [u8; chunk_plaintext_len + 16] ] × N chunks
//! ```
//! Fixed header = 36 bytes. Preamble (header + KEM CT) = 1124 bytes.
//! Chunk nonce_i = nonce_base XOR (i as u64 BE in bytes [4..12]).
//! AAD for each chunk = magic/format_ver/kem_alg/aead_alg/key_epoch/nonce_base
//! plus chunk_size (see [`build_v3_aad`]) — everything in the fixed header except
//! `plaintext_len`, which is only known after all chunks are written. Format
//! v4 additionally appends a 1-byte `is_final` flag (1 for the object's true
//! last chunk, 0 otherwise) to every chunk's AAD — see the v4 note below.
//! `key_epoch` is therefore authenticated the same way as every other
//! structural field: a caller who supplies the wrong bucket-epoch secret key
//! derives the wrong content key and every chunk fails to open, but an
//! on-path tamperer flipping `key_epoch` to point at a *different*, correct
//! secret key is caught by the AAD mismatch instead of silently succeeding.
//!
//! `key_epoch` records which epoch of the *bucket's* ML-KEM-768 keypair
//! `kem_ct` was encapsulated against — callers resolve the matching secret
//! key (via the bucket's key-version list) before calling [`decrypt`] et al.;
//! this module has no notion of buckets or grants, only that the same epoch
//! used to encrypt must be used to decrypt.
//!
//! Envelopes without the recognized magic (including the retired v1
//! whole-object format and the retired v2 chunked format, which lacked
//! `key_epoch`) are rejected outright — there is no unauthenticated
//! passthrough for unrecognized or legacy data.
//!
//! ## v4: authenticated final-chunk marker
//!
//! v3's AAD covers every fixed-header field except `plaintext_len` (see
//! above), which means `plaintext_len` — and by extension the object's
//! apparent length — is not authenticated. A filesystem-write attacker can
//! drop trailing whole chunks from an on-disk v3 envelope and patch
//! `plaintext_len` down to match the truncated ciphertext: every surviving
//! chunk still authenticates under its unchanged nonce/AAD, and the
//! post-loop `plaintext.len() == plaintext_len` check trivially passes
//! because both sides were forged together. v4 closes this by appending a
//! 1-byte `is_final` flag to the per-chunk AAD (see [`build_v4_aad`]): the
//! object's true last chunk is sealed with `is_final = 1`, every other
//! chunk with `is_final = 0`. [`EncryptSession`] defers writing each chunk
//! by one position (see its `pending` field) so it always knows, at write
//! time, whether the chunk it's about to seal is genuinely the last one.
//! On decrypt, the last chunk *presented* is always checked against
//! `is_final = 1`; if the true final chunk was truncated away, the new
//! (shorter) last chunk was originally sealed with `is_final = 0` and fails
//! to authenticate. v3 envelopes already on disk remain readable
//! (`decrypt_v3`/`decrypt_v3_owned`/`decrypt_v3_chunks`), but every new
//! write produces v4; there is no way to opt back into writing v3.

use aes_gcm::{Aes256Gcm, KeyInit, aead::AeadInOut};

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

// ── v3 constants ─────────────────────────────────────────────────────────────

/// Fixed-header length for a v3 envelope (includes the 4-byte `key_epoch`
/// field and the 4-byte `chunk_size` field).
pub const ENVELOPE_V3_HEADER_FIXED_LEN: usize = 4 + 2 + 1 + 1 + 4 + 12 + 8 + 4; // = 36

const MAGIC_V3: &[u8; 4] = b"Y2Q3";
const FORMAT_VER_V3: u16 = 3;
/// Current write format: identical wire layout to v3, but every chunk's AAD
/// additionally covers a 1-byte final-chunk marker (see the module docs'
/// "v4: authenticated final-chunk marker" section). `decrypt`/`decrypt_owned`
/// still read v3 for existing on-disk data; every new write is v4.
const FORMAT_VER_V4: u16 = 4;
/// Default v3 plaintext chunk size (4 MiB) when no config override is given.
/// The actual size used per object is recorded in the envelope header, so
/// decryption never depends on this constant.
pub const DEFAULT_CHUNK_SIZE_BYTES: usize = 4 << 20;
/// Byte offset of `plaintext_len` inside the v3 fixed header.
///
/// `EncryptSession::finish` patches this field in place once the true
/// plaintext length is known, after the rest of the header has already been
/// written.
pub const V3_PLAINTEXT_LEN_OFFSET: u64 = 24;

// ── shared constants ─────────────────────────────────────────────────────────

/// `kem_alg = 1` is reserved for ML-KEM-768.
const KEM_ALG_MLKEM768: u8 = 1;
/// `aead_alg = 1` is reserved for AES-256-GCM with a 12-byte nonce and 16-byte tag.
const AEAD_ALG_AES256GCM: u8 = 1;

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
    /// Boundary-independent XXH3-64 checksum (base64) of the complete
    /// on-disk envelope (header + KEM ciphertext + every chunk's ciphertext
    /// and tag), computed incrementally as bytes are written — no read-back.
    /// Non-cryptographic, same as the plaintext `checksum_gxhash`: it's for
    /// detecting accidental corruption/divergence between replicas, not
    /// tamper detection (that's what the per-chunk AEAD tag is for).
    pub cipher_checksum_b64: String,
    /// The bucket key epoch this envelope's `kem_ct` was encapsulated
    /// against, mirrored here so the caller can persist it in
    /// [`crate::Metadata::key_epoch`] without a separate header parse.
    pub key_epoch: u32,
}

/// Decrypt a complete envelope under `sk`, addressed to `bucket`/`key`.
///
/// `sk` must be the secret key for the epoch the envelope was encrypted
/// under (its `key_epoch` header field, itself authenticated via the AAD —
/// see the module docs). Callers resolve the matching epoch's secret key
/// (typically from [`crate::Metadata::key_epoch`], populated at encrypt time
/// from [`EnvelopeInfo::key_epoch`]) before calling this function; supplying
/// the wrong epoch's key derives the wrong content key and every chunk fails
/// to authenticate.
///
/// `bucket`/`key` must be the address the caller actually requested — they're
/// folded into the content-key derivation (see [`derive_content_key`]), so
/// decrypting under any other address derives the wrong key and fails. This
/// means an envelope that's byte-for-byte valid for one object cannot be
/// copied onto a different object's storage location and decrypt there: the
/// ciphertext itself carries no identity, so without this binding a
/// filesystem-write attacker could substitute one object's envelope for
/// another's and have it decrypt successfully under the wrong address.
///
/// Returns the recovered plaintext on success, or an error if the magic bytes
/// are unrecognized (including any pre-v3 or otherwise legacy data — there is
/// no unauthenticated passthrough).
pub fn decrypt(
    sk_bytes: &[u8],
    envelope: &[u8],
    bucket: &str,
    key: &str,
) -> Result<Vec<u8>, CryptoError> {
    if envelope.len() < 4 {
        return Err(CryptoError::Envelope("truncated header"));
    }
    if &envelope[..4] != MAGIC_V3 {
        return Err(CryptoError::Envelope("bad magic"));
    }
    if envelope.len() < 6 {
        return Err(CryptoError::Envelope("truncated header"));
    }
    match u16::from_be_bytes([envelope[4], envelope[5]]) {
        FORMAT_VER_V3 => decrypt_v3(sk_bytes, envelope, bucket, key),
        FORMAT_VER_V4 => decrypt_v4(sk_bytes, envelope, bucket, key),
        other => Err(CryptoError::UnsupportedVersion(other)),
    }
}

fn decrypt_v3(
    sk_bytes: &[u8],
    envelope: &[u8],
    bucket: &str,
    key: &str,
) -> Result<Vec<u8>, CryptoError> {
    let preamble_len = ENVELOPE_V3_HEADER_FIXED_LEN + mlkem768::ciphertext_bytes();
    if envelope.len() < preamble_len {
        return Err(CryptoError::Envelope("truncated v3 envelope"));
    }
    let ver = u16::from_be_bytes([envelope[4], envelope[5]]);
    if ver != FORMAT_VER_V3 {
        return Err(CryptoError::UnsupportedVersion(ver));
    }
    if envelope[6] != KEM_ALG_MLKEM768 {
        return Err(CryptoError::Envelope("unknown kem_alg"));
    }
    if envelope[7] != AEAD_ALG_AES256GCM {
        return Err(CryptoError::Envelope("unknown aead_alg"));
    }
    let mut nonce_base = [0u8; 12];
    nonce_base.copy_from_slice(&envelope[12..24]);
    let plaintext_len = u64::from_be_bytes(envelope[24..32].try_into().unwrap());
    let chunk_size = u32::from_be_bytes(envelope[32..36].try_into().unwrap()) as usize;
    if chunk_size == 0 {
        return Err(CryptoError::Envelope("zero chunk_size"));
    }

    let kem_ct_bytes = &envelope[ENVELOPE_V3_HEADER_FIXED_LEN..preamble_len];
    let aad = build_v3_aad(&envelope[..ENVELOPE_V3_HEADER_FIXED_LEN]);

    let sk = mlkem768::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| CryptoError::KemDecode("secret key"))?;
    let kem_ct = mlkem768::Ciphertext::from_bytes(kem_ct_bytes)
        .map_err(|_| CryptoError::KemDecode("kem ciphertext"))?;
    let ss = mlkem768::decapsulate(&kem_ct, &sk);

    let mut key_bytes = derive_content_key(ss.as_bytes(), kem_ct_bytes, bucket, key)?;
    let cipher = aes_key(&key_bytes);
    key_bytes.zeroize();

    // `plaintext_len` is read from the header before any AEAD chunk has been
    // verified, so it isn't trustworthy yet — cap the pre-allocation at the
    // received envelope's length (a real upper bound on achievable plaintext
    // regardless of what the header claims) instead of trusting it outright.
    let cap = plaintext_len.min(envelope.len() as u64) as usize;
    let mut plaintext = Vec::with_capacity(cap);

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
            .decrypt_in_place(&aes_nonce(&chunk_nonce_bytes), &aad, &mut chunk_buf)
            .map_err(|_| CryptoError::AuthFailed)?;
        plaintext.extend_from_slice(&chunk_buf);
        pos = ct_end;
        chunk_idx += 1;
    }

    if plaintext.len() as u64 != plaintext_len {
        return Err(CryptoError::Envelope("plaintext length mismatch"));
    }
    Ok(plaintext)
}

fn decrypt_v4(
    sk_bytes: &[u8],
    envelope: &[u8],
    bucket: &str,
    key: &str,
) -> Result<Vec<u8>, CryptoError> {
    let preamble_len = ENVELOPE_V3_HEADER_FIXED_LEN + mlkem768::ciphertext_bytes();
    if envelope.len() < preamble_len {
        return Err(CryptoError::Envelope("truncated v4 envelope"));
    }
    let ver = u16::from_be_bytes([envelope[4], envelope[5]]);
    if ver != FORMAT_VER_V4 {
        return Err(CryptoError::UnsupportedVersion(ver));
    }
    if envelope[6] != KEM_ALG_MLKEM768 {
        return Err(CryptoError::Envelope("unknown kem_alg"));
    }
    if envelope[7] != AEAD_ALG_AES256GCM {
        return Err(CryptoError::Envelope("unknown aead_alg"));
    }
    let mut nonce_base = [0u8; 12];
    nonce_base.copy_from_slice(&envelope[12..24]);
    let plaintext_len = u64::from_be_bytes(envelope[24..32].try_into().unwrap());
    let chunk_size = u32::from_be_bytes(envelope[32..36].try_into().unwrap()) as usize;
    if chunk_size == 0 {
        return Err(CryptoError::Envelope("zero chunk_size"));
    }

    let kem_ct_bytes = &envelope[ENVELOPE_V3_HEADER_FIXED_LEN..preamble_len];
    let aad_base = build_v3_aad(&envelope[..ENVELOPE_V3_HEADER_FIXED_LEN]);

    let sk = mlkem768::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| CryptoError::KemDecode("secret key"))?;
    let kem_ct = mlkem768::Ciphertext::from_bytes(kem_ct_bytes)
        .map_err(|_| CryptoError::KemDecode("kem ciphertext"))?;
    let ss = mlkem768::decapsulate(&kem_ct, &sk);

    let mut key_bytes = derive_content_key(ss.as_bytes(), kem_ct_bytes, bucket, key)?;
    let cipher = aes_key(&key_bytes);
    key_bytes.zeroize();

    // `plaintext_len` is read from the header before any AEAD chunk has been
    // verified, so it isn't trustworthy yet — cap the pre-allocation at the
    // received envelope's length (a real upper bound on achievable plaintext
    // regardless of what the header claims) instead of trusting it outright.
    let cap = plaintext_len.min(envelope.len() as u64) as usize;
    let mut plaintext = Vec::with_capacity(cap);

    let mut pos = preamble_len;
    let mut chunk_idx: u64 = 0;
    while pos < envelope.len() {
        let ct_end = (pos + chunk_size + TAG_LEN).min(envelope.len());
        if ct_end - pos < TAG_LEN {
            return Err(CryptoError::Envelope("truncated chunk ciphertext"));
        }
        // The last chunk PRESENT in this envelope must carry the
        // is_final=1 AAD tag; every earlier one must carry is_final=0 — see
        // the module docs' "v4: authenticated final-chunk marker" section.
        // A truncated envelope's new (shorter) last chunk was originally
        // sealed with is_final=0 and fails to authenticate here.
        let is_final = ct_end == envelope.len();
        let aad = build_v4_aad(&aad_base, is_final);
        let chunk_nonce_bytes = chunk_nonce(&nonce_base, chunk_idx);
        let mut chunk_buf = envelope[pos..ct_end].to_vec();
        cipher
            .decrypt_in_place(&aes_nonce(&chunk_nonce_bytes), &aad, &mut chunk_buf)
            .map_err(|_| CryptoError::AuthFailed)?;
        plaintext.extend_from_slice(&chunk_buf);
        pos = ct_end;
        chunk_idx += 1;
    }

    if plaintext.len() as u64 != plaintext_len {
        return Err(CryptoError::Envelope("plaintext length mismatch"));
    }
    Ok(plaintext)
}

/// Decrypt a complete envelope, consuming an owned `BytesMut` buffer.
///
/// Identical semantics to [`decrypt`] (including the `bucket`/`key` identity
/// binding and the epoch-selection contract on `sk_bytes` — see its doc
/// comment), but reuses the input allocation for the in-place AEAD open
/// instead of allocating a fresh ciphertext buffer per call. Returns the
/// recovered plaintext as `Bytes` (zero-copy of the freed underlying
/// allocation).
pub fn decrypt_owned(
    sk_bytes: &[u8],
    envelope: BytesMut,
    bucket: &str,
    key: &str,
) -> Result<Bytes, CryptoError> {
    if envelope.len() < 4 {
        return Err(CryptoError::Envelope("truncated header"));
    }
    if &envelope[..4] != MAGIC_V3 {
        return Err(CryptoError::Envelope("bad magic"));
    }
    if envelope.len() < 6 {
        return Err(CryptoError::Envelope("truncated header"));
    }
    match u16::from_be_bytes([envelope[4], envelope[5]]) {
        FORMAT_VER_V3 => decrypt_v3_owned(sk_bytes, envelope, bucket, key),
        FORMAT_VER_V4 => decrypt_v4_owned(sk_bytes, envelope, bucket, key),
        other => Err(CryptoError::UnsupportedVersion(other)),
    }
}

fn decrypt_v3_owned(
    sk_bytes: &[u8],
    mut envelope: BytesMut,
    bucket: &str,
    key: &str,
) -> Result<Bytes, CryptoError> {
    let preamble_len = ENVELOPE_V3_HEADER_FIXED_LEN + mlkem768::ciphertext_bytes();
    if envelope.len() < preamble_len {
        return Err(CryptoError::Envelope("truncated v3 envelope"));
    }
    let ver = u16::from_be_bytes([envelope[4], envelope[5]]);
    if ver != FORMAT_VER_V3 {
        return Err(CryptoError::UnsupportedVersion(ver));
    }
    if envelope[6] != KEM_ALG_MLKEM768 {
        return Err(CryptoError::Envelope("unknown kem_alg"));
    }
    if envelope[7] != AEAD_ALG_AES256GCM {
        return Err(CryptoError::Envelope("unknown aead_alg"));
    }
    let mut nonce_base = [0u8; 12];
    nonce_base.copy_from_slice(&envelope[12..24]);
    let plaintext_len = u64::from_be_bytes(envelope[24..32].try_into().unwrap());
    let chunk_size = u32::from_be_bytes(envelope[32..36].try_into().unwrap()) as usize;
    if chunk_size == 0 {
        return Err(CryptoError::Envelope("zero chunk_size"));
    }
    let aad = build_v3_aad(&envelope[..ENVELOPE_V3_HEADER_FIXED_LEN]);
    let kem_ct_owned: Vec<u8> = envelope[ENVELOPE_V3_HEADER_FIXED_LEN..preamble_len].to_vec();

    let sk = mlkem768::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| CryptoError::KemDecode("secret key"))?;
    let kem_ct = mlkem768::Ciphertext::from_bytes(&kem_ct_owned)
        .map_err(|_| CryptoError::KemDecode("kem ciphertext"))?;
    let ss = mlkem768::decapsulate(&kem_ct, &sk);

    let mut key_bytes = derive_content_key(ss.as_bytes(), &kem_ct_owned, bucket, key)?;
    let cipher = aes_key(&key_bytes);
    key_bytes.zeroize();

    // Drop the preamble; `body` retains the chunked ciphertext region.
    let mut body = envelope.split_off(preamble_len);
    drop(envelope);

    // See the matching comment in `decrypt_v3` — `plaintext_len` isn't
    // trustworthy until the chunks are verified, so the pre-allocation is
    // capped by the received body length instead of the raw header value.
    let cap = plaintext_len.min(body.len() as u64) as usize;
    let mut plaintext = BytesMut::with_capacity(cap);

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

    if plaintext.len() as u64 != plaintext_len {
        return Err(CryptoError::Envelope("plaintext length mismatch"));
    }
    Ok(plaintext.freeze())
}

fn decrypt_v4_owned(
    sk_bytes: &[u8],
    mut envelope: BytesMut,
    bucket: &str,
    key: &str,
) -> Result<Bytes, CryptoError> {
    let preamble_len = ENVELOPE_V3_HEADER_FIXED_LEN + mlkem768::ciphertext_bytes();
    if envelope.len() < preamble_len {
        return Err(CryptoError::Envelope("truncated v4 envelope"));
    }
    let ver = u16::from_be_bytes([envelope[4], envelope[5]]);
    if ver != FORMAT_VER_V4 {
        return Err(CryptoError::UnsupportedVersion(ver));
    }
    if envelope[6] != KEM_ALG_MLKEM768 {
        return Err(CryptoError::Envelope("unknown kem_alg"));
    }
    if envelope[7] != AEAD_ALG_AES256GCM {
        return Err(CryptoError::Envelope("unknown aead_alg"));
    }
    let mut nonce_base = [0u8; 12];
    nonce_base.copy_from_slice(&envelope[12..24]);
    let plaintext_len = u64::from_be_bytes(envelope[24..32].try_into().unwrap());
    let chunk_size = u32::from_be_bytes(envelope[32..36].try_into().unwrap()) as usize;
    if chunk_size == 0 {
        return Err(CryptoError::Envelope("zero chunk_size"));
    }
    let aad_base = build_v3_aad(&envelope[..ENVELOPE_V3_HEADER_FIXED_LEN]);
    let kem_ct_owned: Vec<u8> = envelope[ENVELOPE_V3_HEADER_FIXED_LEN..preamble_len].to_vec();

    let sk = mlkem768::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| CryptoError::KemDecode("secret key"))?;
    let kem_ct = mlkem768::Ciphertext::from_bytes(&kem_ct_owned)
        .map_err(|_| CryptoError::KemDecode("kem ciphertext"))?;
    let ss = mlkem768::decapsulate(&kem_ct, &sk);

    let mut key_bytes = derive_content_key(ss.as_bytes(), &kem_ct_owned, bucket, key)?;
    let cipher = aes_key(&key_bytes);
    key_bytes.zeroize();

    // Total envelope length known up front (unlike streaming feed), so the
    // final chunk's on-disk end offset can be determined before the loop.
    let total_len = envelope.len();

    // Drop the preamble; `body` retains the chunked ciphertext region.
    let mut body = envelope.split_off(preamble_len);
    drop(envelope);

    // See the matching comment in `decrypt_v4` — `plaintext_len` isn't
    // trustworthy until the chunks are verified, so the pre-allocation is
    // capped by the received body length instead of the raw header value.
    let cap = plaintext_len.min(body.len() as u64) as usize;
    let mut plaintext = BytesMut::with_capacity(cap);

    let mut chunk_idx: u64 = 0;
    let mut consumed = preamble_len;
    while !body.is_empty() {
        let take = (chunk_size + TAG_LEN).min(body.len());
        if take < TAG_LEN {
            return Err(CryptoError::Envelope("truncated chunk ciphertext"));
        }
        consumed += take;
        let is_final = consumed == total_len;
        let aad = build_v4_aad(&aad_base, is_final);
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

    if plaintext.len() as u64 != plaintext_len {
        return Err(CryptoError::Envelope("plaintext length mismatch"));
    }
    Ok(plaintext.freeze())
}

/// Number of bytes before the first chunk in a v3 envelope: the 36-byte fixed
/// header plus the 1088-byte ML-KEM-768 ciphertext. A ranged read must fetch at
/// least this prefix to recover the content key and chunk geometry.
pub fn v3_preamble_len() -> usize {
    ENVELOPE_V3_HEADER_FIXED_LEN + mlkem768::ciphertext_bytes()
}

/// Parse `(key_epoch, chunk_size, plaintext_len)` from the fixed portion of a
/// v3 header.
///
/// `header` must be at least [`ENVELOPE_V3_HEADER_FIXED_LEN`] bytes. Validates
/// the v3 magic, version, and algorithm IDs. `key_epoch` is cleartext (it must
/// be, since it's needed to select the secret key before anything can be
/// decrypted) but is still authenticated as part of the AAD on every chunk —
/// see the module docs.
pub fn parse_v3_geometry(header: &[u8]) -> Result<(u32, u32, u64), CryptoError> {
    if header.len() < ENVELOPE_V3_HEADER_FIXED_LEN {
        return Err(CryptoError::Envelope("truncated v3 header"));
    }
    if &header[0..4] != MAGIC_V3 {
        return Err(CryptoError::Envelope("bad magic"));
    }
    let ver = u16::from_be_bytes([header[4], header[5]]);
    if ver != FORMAT_VER_V3 {
        return Err(CryptoError::UnsupportedVersion(ver));
    }
    if header[6] != KEM_ALG_MLKEM768 {
        return Err(CryptoError::Envelope("unknown kem_alg"));
    }
    if header[7] != AEAD_ALG_AES256GCM {
        return Err(CryptoError::Envelope("unknown aead_alg"));
    }
    let key_epoch = u32::from_be_bytes(header[8..12].try_into().unwrap());
    let plaintext_len = u64::from_be_bytes(header[24..32].try_into().unwrap());
    let chunk_size = u32::from_be_bytes(header[32..36].try_into().unwrap());
    if chunk_size == 0 {
        return Err(CryptoError::Envelope("zero chunk_size"));
    }
    Ok((key_epoch, chunk_size, plaintext_len))
}

/// Same as [`parse_v3_geometry`] but for a v4 header (see the module docs'
/// "v4: authenticated final-chunk marker" section) — identical fixed-header
/// layout, only the accepted `format_ver` value differs.
pub fn parse_v4_geometry(header: &[u8]) -> Result<(u32, u32, u64), CryptoError> {
    if header.len() < ENVELOPE_V3_HEADER_FIXED_LEN {
        return Err(CryptoError::Envelope("truncated v4 header"));
    }
    if &header[0..4] != MAGIC_V3 {
        return Err(CryptoError::Envelope("bad magic"));
    }
    let ver = u16::from_be_bytes([header[4], header[5]]);
    if ver != FORMAT_VER_V4 {
        return Err(CryptoError::UnsupportedVersion(ver));
    }
    if header[6] != KEM_ALG_MLKEM768 {
        return Err(CryptoError::Envelope("unknown kem_alg"));
    }
    if header[7] != AEAD_ALG_AES256GCM {
        return Err(CryptoError::Envelope("unknown aead_alg"));
    }
    let key_epoch = u32::from_be_bytes(header[8..12].try_into().unwrap());
    let plaintext_len = u64::from_be_bytes(header[24..32].try_into().unwrap());
    let chunk_size = u32::from_be_bytes(header[32..36].try_into().unwrap());
    if chunk_size == 0 {
        return Err(CryptoError::Envelope("zero chunk_size"));
    }
    Ok((key_epoch, chunk_size, plaintext_len))
}

/// Decrypt a contiguous run of whole v3 chunks beginning at `first_chunk_idx`.
///
/// `preamble` must be the first [`v3_preamble_len`] bytes of the envelope (used
/// to recover the content key, chunk geometry, and AAD). `chunks_ct` holds the
/// ciphertext for chunks `[first_chunk_idx ..]`, aligned to a chunk boundary
/// (i.e. it must start exactly at the on-disk offset of `first_chunk_idx`).
///
/// Returns the concatenated plaintext of the decrypted whole chunks; the caller
/// trims to the exact requested byte range. Used by ranged GET; the per-chunk
/// AEAD nonce and AAD match [`decrypt_v3`]. `bucket`/`key` must be the address
/// the caller requested, and `sk_bytes` the epoch-matching secret key — see
/// the identity/epoch-binding notes on [`decrypt`].
pub fn decrypt_v3_chunks(
    sk_bytes: &[u8],
    preamble: &[u8],
    chunks_ct: &[u8],
    first_chunk_idx: u64,
    bucket: &str,
    key: &str,
) -> Result<Vec<u8>, CryptoError> {
    let preamble_len = v3_preamble_len();
    if preamble.len() < preamble_len {
        return Err(CryptoError::Envelope("truncated v3 preamble"));
    }
    let (_key_epoch, chunk_size_u32, _plaintext_len) =
        parse_v3_geometry(&preamble[..ENVELOPE_V3_HEADER_FIXED_LEN])?;
    let chunk_size = chunk_size_u32 as usize;

    let mut nonce_base = [0u8; 12];
    nonce_base.copy_from_slice(&preamble[12..24]);
    let aad = build_v3_aad(&preamble[..ENVELOPE_V3_HEADER_FIXED_LEN]);

    let kem_ct_bytes = &preamble[ENVELOPE_V3_HEADER_FIXED_LEN..preamble_len];

    let sk = mlkem768::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| CryptoError::KemDecode("secret key"))?;
    let kem_ct = mlkem768::Ciphertext::from_bytes(kem_ct_bytes)
        .map_err(|_| CryptoError::KemDecode("kem ciphertext"))?;
    let ss = mlkem768::decapsulate(&kem_ct, &sk);

    let mut key_bytes = derive_content_key(ss.as_bytes(), kem_ct_bytes, bucket, key)?;
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
            .decrypt_in_place(&aes_nonce(&chunk_nonce_bytes), &aad, &mut chunk_buf)
            .map_err(|_| CryptoError::AuthFailed)?;
        plaintext.extend_from_slice(&chunk_buf);
        pos = ct_end;
        chunk_idx += 1;
    }
    Ok(plaintext)
}

/// Decrypt a contiguous run of whole v4 chunks beginning at `first_chunk_idx`.
///
/// Identical contract to [`decrypt_v3_chunks`] with one addition:
/// `total_chunks` must be the object's TRUE total chunk count, computed by
/// the caller from an authenticated plaintext size (e.g.
/// `padme_len(trusted_size).div_ceil(chunk_size)`, where `chunk_size` is the
/// value returned by [`parse_v4_geometry`] on this same preamble — safe to
/// trust for this computation because a wrong `chunk_size` fails every
/// chunk's AEAD tag regardless). This is what lets the final-chunk AAD
/// marker (see the module docs) be applied correctly on a ranged read: only
/// the chunk at index `total_chunks - 1` is checked against `is_final = 1`,
/// never merely because it happens to be the last chunk in the requested
/// window.
pub fn decrypt_v4_chunks(
    sk_bytes: &[u8],
    preamble: &[u8],
    chunks_ct: &[u8],
    first_chunk_idx: u64,
    total_chunks: u64,
    bucket: &str,
    key: &str,
) -> Result<Vec<u8>, CryptoError> {
    let preamble_len = v3_preamble_len();
    if preamble.len() < preamble_len {
        return Err(CryptoError::Envelope("truncated v4 preamble"));
    }
    let (_key_epoch, chunk_size_u32, _plaintext_len) =
        parse_v4_geometry(&preamble[..ENVELOPE_V3_HEADER_FIXED_LEN])?;
    let chunk_size = chunk_size_u32 as usize;

    let mut nonce_base = [0u8; 12];
    nonce_base.copy_from_slice(&preamble[12..24]);
    let aad_base = build_v3_aad(&preamble[..ENVELOPE_V3_HEADER_FIXED_LEN]);

    let kem_ct_bytes = &preamble[ENVELOPE_V3_HEADER_FIXED_LEN..preamble_len];

    let sk = mlkem768::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| CryptoError::KemDecode("secret key"))?;
    let kem_ct = mlkem768::Ciphertext::from_bytes(kem_ct_bytes)
        .map_err(|_| CryptoError::KemDecode("kem ciphertext"))?;
    let ss = mlkem768::decapsulate(&kem_ct, &sk);

    let mut key_bytes = derive_content_key(ss.as_bytes(), kem_ct_bytes, bucket, key)?;
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
        let is_final = chunk_idx + 1 == total_chunks;
        let aad = build_v4_aad(&aad_base, is_final);
        let chunk_nonce_bytes = chunk_nonce(&nonce_base, chunk_idx);
        let mut chunk_buf = chunks_ct[pos..ct_end].to_vec();
        cipher
            .decrypt_in_place(&aes_nonce(&chunk_nonce_bytes), &aad, &mut chunk_buf)
            .map_err(|_| CryptoError::AuthFailed)?;
        plaintext.extend_from_slice(&chunk_buf);
        pos = ct_end;
        chunk_idx += 1;
    }
    Ok(plaintext)
}

/// Length of the header prefix (magic + format_ver + kem_alg + aead_alg +
/// key_epoch + nonce_base) that forms the first part of the v3 per-chunk AAD.
const V3_AAD_PREFIX_LEN: usize = 24; // up to and including nonce_base

/// Total length of the v3 per-chunk AAD: the header prefix plus `chunk_size`
/// (bytes 32-35). `plaintext_len` (bytes 24-31) is the only fixed-header
/// field excluded — it's only known after all chunks are written (patched in
/// via a seek in [`EncryptSession::finish`]), so a placeholder value bound at
/// encrypt time would never match what's read back at decrypt time.
/// `chunk_size` has no such excuse: it's fixed before the first byte is
/// written, so it's authenticated like every other header field.
const V3_AAD_LEN: usize = V3_AAD_PREFIX_LEN + 4;

/// Build the v3 per-chunk AAD from a (at least) 36-byte fixed header: the
/// magic/version/alg/key_epoch/nonce_base prefix concatenated with
/// `chunk_size`, skipping the not-yet-known `plaintext_len` bytes in between.
fn build_v3_aad(header: &[u8]) -> [u8; V3_AAD_LEN] {
    let mut aad = [0u8; V3_AAD_LEN];
    aad[..V3_AAD_PREFIX_LEN].copy_from_slice(&header[..V3_AAD_PREFIX_LEN]);
    aad[V3_AAD_PREFIX_LEN..].copy_from_slice(&header[32..36]);
    aad
}

/// Total length of the v4 per-chunk AAD: the v3 prefix+chunk_size (28 bytes,
/// [`V3_AAD_LEN`]) plus a 1-byte final-chunk marker — see the module docs'
/// "v4: authenticated final-chunk marker" section.
const V4_AAD_LEN: usize = V3_AAD_LEN + 1;

/// Build the v4 per-chunk AAD from the shared 28-byte prefix (see
/// [`build_v3_aad`]) plus a 1-byte `is_final` marker: `1` for the object's
/// true last chunk, `0` for every other chunk.
fn build_v4_aad(aad_base: &[u8; V3_AAD_LEN], is_final: bool) -> [u8; V4_AAD_LEN] {
    let mut aad = [0u8; V4_AAD_LEN];
    aad[..V3_AAD_LEN].copy_from_slice(aad_base);
    aad[V3_AAD_LEN] = is_final as u8;
    aad
}

/// Streaming AES-256-GCM v3 encryptor that writes directly to a file.
///
/// Feed plaintext in arbitrary-sized chunks via [`feed`]; call [`finish`] when
/// done to flush the last chunk and patch the `plaintext_len` field in the
/// header. The file is returned so the caller can close or rename it.
///
/// `write_offset` is the byte offset within the file at which the v3 envelope
/// starts. Pass `0` when the envelope occupies the whole file (filesystem
/// backend). Pass `64` when a 64-byte container header precedes the envelope
/// (uring backend — the caller pre-writes a placeholder header before creating
/// the session).
pub struct EncryptSession {
    sink: crate::storage::streaming_sink::StreamingSink,
    cipher: Aes256Gcm,
    nonce_base: [u8; 12],
    chunk_idx: u64,
    /// Plaintext currently accumulating toward the next full chunk
    /// (`< chunk_size`).
    staging: Vec<u8>,
    /// One already-completed `chunk_size`-plaintext chunk, held back one
    /// write so its final-chunk AAD marker can be set correctly once it's
    /// known whether more data (or `finish`) follows — see the module docs'
    /// "v4: authenticated final-chunk marker" section.
    pending: Option<Vec<u8>>,
    plaintext_total: u64,
    /// This session's 28-byte AAD prefix: the header prefix concatenated
    /// with `chunk_size` (see [`build_v3_aad`]). The final-chunk marker byte
    /// is appended per write in [`flush_raw`](Self::flush_raw).
    aad_base: [u8; V3_AAD_LEN],
    bytes_written: u64,
    /// Byte offset within the file at which the v4 envelope begins.
    write_offset: u64,
    /// Plaintext chunk size used for this session (recorded in the header).
    chunk_size: usize,
    /// Bucket key epoch this session encapsulated `pk_bytes` from, mirrored
    /// into [`EnvelopeInfo::key_epoch`] on [`finish`](Self::finish).
    key_epoch: u32,
    /// Running checksum of every byte written (header, KEM ciphertext, and
    /// each chunk's ciphertext+tag), fed incrementally as it's written so no
    /// read-back is needed. See [`EnvelopeInfo::cipher_checksum_b64`].
    cipher_hasher: crate::checksum::StreamChecksum,
}

impl EncryptSession {
    /// Create a new encrypt session for a v4 envelope.
    ///
    /// Writes the 36-byte fixed header (with `plaintext_len = 0`) and the
    /// 1088-byte KEM ciphertext to `sink`, starting at the sink's current
    /// cursor (which must equal `write_offset`). Pass `write_offset = 0`
    /// when the envelope is the entire file; pass a non-zero value when a
    /// container header precedes it.
    ///
    /// `pk_bytes` is the public key of the bucket key epoch `key_epoch`
    /// identifies; the two must correspond to the same epoch, since
    /// `key_epoch` is written into the header (and folded into every
    /// chunk's AAD) so a future reader knows which secret key decrypts this
    /// envelope. `bucket`/`key` are the address this object is being
    /// written to. They're folded into the content-key derivation so the
    /// resulting envelope only decrypts when later read back under this same
    /// address — see the identity-binding note on [`decrypt`].
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        mut sink: crate::storage::streaming_sink::StreamingSink,
        pk_bytes: &[u8],
        key_epoch: u32,
        bucket: &str,
        key: &str,
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

        // Build the 36-byte v4 fixed header (plaintext_len = 0 placeholder).
        let mut header = Vec::with_capacity(ENVELOPE_V3_HEADER_FIXED_LEN);
        header.extend_from_slice(MAGIC_V3);
        header.extend_from_slice(&FORMAT_VER_V4.to_be_bytes());
        header.push(KEM_ALG_MLKEM768);
        header.push(AEAD_ALG_AES256GCM);
        header.extend_from_slice(&key_epoch.to_be_bytes());
        header.extend_from_slice(&nonce_base);
        header.extend_from_slice(&0u64.to_be_bytes()); // plaintext_len placeholder
        header.extend_from_slice(&(chunk_size as u32).to_be_bytes());

        sink.write_all(&header)
            .await
            .map_err(|_| CryptoError::Aead("write header"))?;
        sink.write_all(kem_ct_bytes)
            .await
            .map_err(|_| CryptoError::Aead("write kem ct"))?;

        let mut key_bytes = derive_content_key(ss.as_bytes(), kem_ct_bytes, bucket, key)?;
        let cipher = aes_key(&key_bytes);
        key_bytes.zeroize();

        let bytes_written = (header.len() + kem_ct_bytes.len()) as u64;

        let aad_base = build_v3_aad(&header);

        let mut cipher_hasher = crate::checksum::StreamChecksum::new();
        cipher_hasher.update(&header);
        cipher_hasher.update(kem_ct_bytes);

        Ok(Self {
            sink,
            cipher,
            nonce_base,
            chunk_idx: 0,
            staging: Vec::with_capacity(chunk_size),
            pending: None,
            plaintext_total: 0,
            aad_base,
            bytes_written,
            write_offset,
            chunk_size,
            key_epoch,
            cipher_hasher,
        })
    }

    /// Buffer `data` and promote complete chunks toward the sink.
    pub async fn feed(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        let mut remaining = data;
        while !remaining.is_empty() {
            let space = self.chunk_size - self.staging.len();
            let take = remaining.len().min(space);
            self.staging.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
            if self.staging.len() == self.chunk_size {
                self.promote_staging().await?;
            }
        }
        Ok(())
    }

    /// `staging` just reached a full chunk: flush whatever was previously
    /// `pending` (now known to NOT be the final chunk, since more data
    /// followed it) and hold the newly-completed chunk as the new
    /// `pending`, deferred until [`finish`](Self::finish) or a later call
    /// here settles whether *it* turns out to be final.
    async fn promote_staging(&mut self) -> Result<(), CryptoError> {
        if let Some(prev) = self.pending.take() {
            self.flush_raw(prev, false).await?;
        }
        self.pending = Some(std::mem::replace(
            &mut self.staging,
            Vec::with_capacity(self.chunk_size),
        ));
        Ok(())
    }

    /// Flush remaining buffered data, patch `plaintext_len` at its v4 header
    /// position, and return the sink (now positioned at end-of-data) plus
    /// [`EnvelopeInfo`].
    pub async fn finish(
        mut self,
    ) -> Result<(crate::storage::streaming_sink::StreamingSink, EnvelopeInfo), CryptoError> {
        // Zero-pad up to the Padmé boundary to hide the exact object size.
        // `plaintext_total` only reflects chunks already flushed to disk
        // (deferred by one — see `pending`), so the real running total also
        // includes whatever's held in `pending` and `staging`.
        let already_absorbed = self.plaintext_total
            + self.pending.as_ref().map_or(0, |p| p.len() as u64)
            + self.staging.len() as u64;
        let target = padme_len(already_absorbed);
        let mut pad_remaining = target - already_absorbed;
        while pad_remaining > 0 {
            let space = self.chunk_size - self.staging.len();
            let take = (space as u64).min(pad_remaining) as usize;
            self.staging.resize(self.staging.len() + take, 0);
            pad_remaining -= take as u64;
            if self.staging.len() == self.chunk_size {
                self.promote_staging().await?;
            }
        }

        // Whatever's left in `staging` is the true tail (real bytes and/or
        // padding, always `< chunk_size` unless the object is empty). If
        // it's non-empty, it — not `pending` — is the final chunk. If it's
        // empty, the total was an exact multiple of `chunk_size` and
        // `pending` (if any) is the final chunk instead.
        if !self.staging.is_empty() {
            if let Some(prev) = self.pending.take() {
                self.flush_raw(prev, false).await?;
            }
            let tail = std::mem::take(&mut self.staging);
            self.flush_raw(tail, true).await?;
        } else if let Some(prev) = self.pending.take() {
            self.flush_raw(prev, true).await?;
        }
        // else: nothing was ever fed and `padme_len(0) == 0` — a genuinely
        // empty object; zero chunks written.

        let cipher_size = self.bytes_written;

        // Patch plaintext_len at its position within the v4 envelope.
        self.sink
            .write_all_at(
                &self.plaintext_total.to_be_bytes(),
                self.write_offset + V3_PLAINTEXT_LEN_OFFSET,
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
                envelope_version: FORMAT_VER_V4,
                kem_alg: KEM_ALG_NAME,
                aead_alg: AEAD_ALG_NAME,
                cipher_size,
                cipher_checksum_b64: self.cipher_hasher.finish_b64(),
                key_epoch: self.key_epoch,
            },
        ))
    }

    /// Encrypt and write one chunk of already-finalized plaintext, tagging
    /// its AAD with `is_final` (see [`build_v4_aad`]).
    async fn flush_raw(&mut self, mut data: Vec<u8>, is_final: bool) -> Result<(), CryptoError> {
        let chunk_nonce_bytes = chunk_nonce(&self.nonce_base, self.chunk_idx);
        let plaintext_len = data.len();
        let aad = build_v4_aad(&self.aad_base, is_final);

        // Encrypt `data` in-place; aes-gcm appends the 16-byte tag, so
        // `data` becomes [ciphertext || tag] with no separate ct allocation.
        self.cipher
            .encrypt_in_place(&aes_nonce(&chunk_nonce_bytes), &aad, &mut data)
            .map_err(|_| CryptoError::Aead("encrypt chunk"))?;

        self.plaintext_total += plaintext_len as u64;
        self.bytes_written += data.len() as u64;
        self.cipher_hasher.update(&data);
        self.sink
            .write_all(&data)
            .await
            .map_err(|_| CryptoError::Aead("write chunk"))?;
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
    Nonce::from(*bytes)
}

/// Derive the per-object AES-256 content key, bound to `bucket`/`key`.
///
/// The HKDF `info` parameter doesn't need to be secret — it's supplied by
/// the caller at both encrypt and decrypt time, never transmitted or stored
/// — so folding the object's address into it costs nothing and doesn't leak
/// bucket/key names anywhere (unlike putting them in the AAD, which travels
/// in cleartext alongside the ciphertext). It does mean a ciphertext
/// encrypted for one `(bucket, key)` derives a different key, and therefore
/// fails to decrypt, if presented under a different address: copying one
/// object's on-disk envelope onto another object's storage location no
/// longer grants access to it. Length-prefixed (matching
/// `filesystem::encode_object_id`'s scheme) so there's no ambiguity between
/// different bucket/key splits of the same concatenated bytes.
fn derive_content_key(
    ss: &[u8],
    kem_ct: &[u8],
    bucket: &str,
    key: &str,
) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(kem_ct), ss);
    let mut info = Vec::with_capacity(HKDF_INFO.len() + 8 + bucket.len() + key.len());
    info.extend_from_slice(HKDF_INFO);
    for part in [bucket.as_bytes(), key.as_bytes()] {
        info.extend_from_slice(&(part.len() as u32).to_be_bytes());
        info.extend_from_slice(part);
    }
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .map_err(|_| CryptoError::Aead("hkdf expand"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPOCH: u32 = 0;

    #[test]
    fn bad_magic_rejected() {
        let env = vec![0u8; ENVELOPE_V3_HEADER_FIXED_LEN + 2000];
        let (_, sk) = mlkem768::keypair();
        assert!(matches!(
            decrypt(sk.as_bytes(), &env, "bucket", "key"),
            Err(CryptoError::Envelope("bad magic"))
        ));
        assert!(matches!(
            decrypt_owned(
                sk.as_bytes(),
                BytesMut::from(env.as_slice()),
                "bucket",
                "key"
            ),
            Err(CryptoError::Envelope("bad magic"))
        ));
    }

    #[tokio::test]
    async fn unsupported_version_rejected() {
        let (pk, sk) = mlkem768::keypair();
        let file = tempfile_v3().await;
        let session = EncryptSession::new(
            file,
            pk.as_bytes(),
            EPOCH,
            "bucket",
            "key",
            0,
            DEFAULT_CHUNK_SIZE_BYTES,
        )
        .await
        .unwrap();
        let (file, _) = session.finish().await.unwrap();
        let mut env = read_file(file).await;
        env[4] = 0xff;
        env[5] = 0xff;
        assert!(matches!(
            decrypt(sk.as_bytes(), &env, "bucket", "key"),
            Err(CryptoError::UnsupportedVersion(_))
        ));
    }

    #[tokio::test]
    async fn v3_wrong_key_breaks_decrypt() {
        let (pk1, _) = mlkem768::keypair();
        let (_, sk2) = mlkem768::keypair();
        let file = tempfile_v3().await;
        let mut session = EncryptSession::new(
            file,
            pk1.as_bytes(),
            EPOCH,
            "bucket",
            "key",
            0,
            DEFAULT_CHUNK_SIZE_BYTES,
        )
        .await
        .unwrap();
        session.feed(b"hi").await.unwrap();
        let (file, _) = session.finish().await.unwrap();
        let env = read_file(file).await;
        assert!(decrypt(sk2.as_bytes(), &env, "bucket", "key").is_err());
    }

    #[tokio::test]
    async fn v3_fresh_kem_per_call() {
        let (pk, _sk) = mlkem768::keypair();
        let mut envs = Vec::new();
        for _ in 0..2 {
            let file = tempfile_v3().await;
            let mut session = EncryptSession::new(
                file,
                pk.as_bytes(),
                EPOCH,
                "bucket",
                "key",
                0,
                DEFAULT_CHUNK_SIZE_BYTES,
            )
            .await
            .unwrap();
            session.feed(b"x").await.unwrap();
            let (file, _) = session.finish().await.unwrap();
            envs.push(read_file(file).await);
        }
        assert_ne!(
            envs[0], envs[1],
            "two encrypts of same plaintext must differ"
        );
    }

    // ── v3 EncryptSession tests ───────────────────────────────────────────

    #[tokio::test]
    async fn v3_roundtrip_small() {
        let (pk, sk) = mlkem768::keypair();
        let pt = b"hello chunked world";
        let file = tempfile_v3().await;
        let mut session = EncryptSession::new(
            file,
            pk.as_bytes(),
            EPOCH,
            "bucket",
            "key",
            0,
            DEFAULT_CHUNK_SIZE_BYTES,
        )
        .await
        .unwrap();
        session.feed(pt).await.unwrap();
        let (file, info) = session.finish().await.unwrap();
        assert_eq!(info.envelope_version, 4);
        assert_eq!(info.key_epoch, EPOCH);
        let env = read_file(file).await;
        let recovered = decrypt(sk.as_bytes(), &env, "bucket", "key").unwrap();
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
    async fn v3_quantizes_size_and_trims_back() {
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
            let file = tempfile_v3().await;
            let mut session = EncryptSession::new(
                file,
                pk.as_bytes(),
                EPOCH,
                "bucket",
                "key",
                0,
                DEFAULT_CHUNK_SIZE_BYTES,
            )
            .await
            .unwrap();
            session.feed(pt).await.unwrap();
            let (file, info) = session.finish().await.unwrap();
            sizes.push(info.cipher_size);
            // The decrypted plaintext is padded; trimming to the true size (as
            // the GET handler does from metadata) recovers the original bytes.
            let env = read_file(file).await;
            let recovered = decrypt(sk.as_bytes(), &env, "bucket", "key").unwrap();
            assert_eq!(&recovered[..pt.len()], pt.as_slice());
        }
        // The on-disk envelope size is identical for both, so it leaks only the
        // bucket, not which of the two objects was stored.
        assert_eq!(sizes[0], sizes[1], "cipher size must be quantized");
    }

    #[tokio::test]
    async fn v3_roundtrip_empty() {
        let (pk, sk) = mlkem768::keypair();
        let file = tempfile_v3().await;
        let session = EncryptSession::new(
            file,
            pk.as_bytes(),
            EPOCH,
            "bucket",
            "key",
            0,
            DEFAULT_CHUNK_SIZE_BYTES,
        )
        .await
        .unwrap();
        let (file, _) = session.finish().await.unwrap();
        let env = read_file(file).await;
        let recovered = decrypt(sk.as_bytes(), &env, "bucket", "key").unwrap();
        assert!(recovered.is_empty());
    }

    #[tokio::test]
    async fn v3_roundtrip_multi_chunk() {
        let (pk, sk) = mlkem768::keypair();
        // 2.5 chunks — spans three chunks (last is partial)
        let pt = vec![0xAB_u8; 5 * DEFAULT_CHUNK_SIZE_BYTES / 2];
        let file = tempfile_v3().await;
        let mut session = EncryptSession::new(
            file,
            pk.as_bytes(),
            EPOCH,
            "bucket",
            "key",
            0,
            DEFAULT_CHUNK_SIZE_BYTES,
        )
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
        let recovered = decrypt(sk.as_bytes(), &env, "bucket", "key").unwrap();
        assert_eq!(recovered, pt);
    }

    #[tokio::test]
    async fn decrypt_owned_v3_multi_chunk() {
        let (pk, sk) = mlkem768::keypair();
        let pt = vec![0x37_u8; 5 * DEFAULT_CHUNK_SIZE_BYTES / 2];
        let file = tempfile_v3().await;
        let mut session = EncryptSession::new(
            file,
            pk.as_bytes(),
            EPOCH,
            "bucket",
            "key",
            0,
            DEFAULT_CHUNK_SIZE_BYTES,
        )
        .await
        .unwrap();
        for chunk in pt.chunks(65536) {
            session.feed(chunk).await.unwrap();
        }
        let (file, _) = session.finish().await.unwrap();
        let env = read_file(file).await;
        let rec = decrypt_owned(
            sk.as_bytes(),
            BytesMut::from(env.as_slice()),
            "bucket",
            "key",
        )
        .unwrap();
        assert_eq!(rec.as_ref(), pt.as_slice());
    }

    #[tokio::test]
    async fn v3_ranged_decrypt_matches_full() {
        let (pk, sk) = mlkem768::keypair();
        // Use a small chunk size so the test stays cheap but still multi-chunk.
        let chunk_size = 4096usize;
        let pt: Vec<u8> = (0..(chunk_size * 5 / 2)).map(|i| (i % 251) as u8).collect();
        let file = tempfile_v3().await;
        let mut session =
            EncryptSession::new(file, pk.as_bytes(), EPOCH, "bucket", "key", 0, chunk_size)
                .await
                .unwrap();
        for c in pt.chunks(777) {
            session.feed(c).await.unwrap();
        }
        let (file, info) = session.finish().await.unwrap();
        let env = read_file(file).await;
        let cipher_size = info.cipher_size;
        let preamble_len = v3_preamble_len();
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
        let total_chunks = padme_len(pt.len() as u64).div_ceil(chunk_size as u64);
        for (start, end) in ranges {
            let first = start / chunk_size as u64;
            let last = end / chunk_size as u64;
            let cipher_start = preamble_len as u64 + first * stride as u64;
            let cipher_end =
                (preamble_len as u64 + (last + 1) * stride as u64 - 1).min(cipher_size - 1);
            let preamble = &env[..preamble_len];
            let window = &env[cipher_start as usize..=cipher_end as usize];
            let chunks_pt = decrypt_v4_chunks(
                sk.as_bytes(),
                preamble,
                window,
                first,
                total_chunks,
                "bucket",
                "key",
            )
            .unwrap();
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
    async fn v3_tamper_breaks_decrypt() {
        let (pk, sk) = mlkem768::keypair();
        let file = tempfile_v3().await;
        let mut session = EncryptSession::new(
            file,
            pk.as_bytes(),
            EPOCH,
            "bucket",
            "key",
            0,
            DEFAULT_CHUNK_SIZE_BYTES,
        )
        .await
        .unwrap();
        session.feed(b"some payload").await.unwrap();
        let (file, _) = session.finish().await.unwrap();
        let mut env = read_file(file).await;
        let last = env.len() - 1;
        env[last] ^= 1;
        assert!(decrypt(sk.as_bytes(), &env, "bucket", "key").is_err());
    }

    #[tokio::test]
    async fn v3_chunk_size_tampering_is_authenticated() {
        // Before chunk_size was included in the AAD, substituting a different
        // (still-oversized-relative-to-the-ciphertext) chunk_size value went
        // completely undetected on a single-chunk object: any value large
        // enough to clamp the decrypt window to the same bytes produced the
        // exact same ciphertext window and AAD, so the tag check couldn't
        // tell the difference. It's now part of the AAD, so this must fail.
        let (pk, sk) = mlkem768::keypair();
        let file = tempfile_v3().await;
        let mut session = EncryptSession::new(
            file,
            pk.as_bytes(),
            EPOCH,
            "bucket",
            "key",
            0,
            DEFAULT_CHUNK_SIZE_BYTES,
        )
        .await
        .unwrap();
        session.feed(b"some payload").await.unwrap();
        let (file, _) = session.finish().await.unwrap();
        let mut env = read_file(file).await;

        // chunk_size lives at header bytes [32..36].
        let tampered = (DEFAULT_CHUNK_SIZE_BYTES as u32) / 2;
        env[32..36].copy_from_slice(&tampered.to_be_bytes());

        assert!(matches!(
            decrypt(sk.as_bytes(), &env, "bucket", "key"),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[tokio::test]
    async fn v3_key_epoch_tampering_is_authenticated() {
        // key_epoch must be cleartext (a reader needs it before it can pick a
        // secret key), but flipping it to point at a *different, still-valid*
        // epoch must not silently decrypt as if nothing changed — it's part
        // of the AAD, so tampering with it invalidates every chunk's tag.
        let (pk, sk) = mlkem768::keypair();
        let file = tempfile_v3().await;
        let mut session = EncryptSession::new(
            file,
            pk.as_bytes(),
            EPOCH,
            "bucket",
            "key",
            0,
            DEFAULT_CHUNK_SIZE_BYTES,
        )
        .await
        .unwrap();
        session.feed(b"some payload").await.unwrap();
        let (file, _) = session.finish().await.unwrap();
        let mut env = read_file(file).await;

        // key_epoch lives at header bytes [8..12].
        env[8..12].copy_from_slice(&99u32.to_be_bytes());

        assert!(matches!(
            decrypt(sk.as_bytes(), &env, "bucket", "key"),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[tokio::test]
    async fn v3_envelope_cannot_be_relocated_to_a_different_object() {
        // The ciphertext itself carries no identity — a filesystem-write
        // attacker who copies object A's on-disk envelope onto object B's
        // storage location must not be able to have it decrypt successfully
        // "as B". The content key is bound to (bucket, key), so the exact
        // same bytes, decrypted under a different address, must fail.
        let (pk, sk) = mlkem768::keypair();
        let file = tempfile_v3().await;
        let mut session = EncryptSession::new(
            file,
            pk.as_bytes(),
            EPOCH,
            "bucket-a",
            "secret-object",
            0,
            DEFAULT_CHUNK_SIZE_BYTES,
        )
        .await
        .unwrap();
        session
            .feed(b"object A's confidential payload")
            .await
            .unwrap();
        let (file, _) = session.finish().await.unwrap();
        let env = read_file(file).await;

        // Byte-for-byte identical ciphertext, decrypted for its real address:
        // must succeed.
        assert!(decrypt(sk.as_bytes(), &env, "bucket-a", "secret-object").is_ok());

        // The exact same bytes, relocated to a different bucket/key (as if
        // an attacker had copied the raw file onto another object's on-disk
        // path): must fail, not silently return object A's plaintext under
        // object B's identity.
        assert!(matches!(
            decrypt(sk.as_bytes(), &env, "bucket-b", "other-object"),
            Err(CryptoError::AuthFailed)
        ));
        // Same bucket, different key.
        assert!(matches!(
            decrypt(sk.as_bytes(), &env, "bucket-a", "other-object"),
            Err(CryptoError::AuthFailed)
        ));
        // Different bucket, same key.
        assert!(matches!(
            decrypt(sk.as_bytes(), &env, "bucket-b", "secret-object"),
            Err(CryptoError::AuthFailed)
        ));

        // The owned and chunked decrypt paths derive the key the same way —
        // relocation must fail there too.
        assert!(matches!(
            decrypt_owned(
                sk.as_bytes(),
                BytesMut::from(env.as_slice()),
                "bucket-b",
                "other-object"
            ),
            Err(CryptoError::AuthFailed)
        ));
        let preamble_len = v3_preamble_len();
        let total_chunks = 1u64;
        assert!(matches!(
            decrypt_v4_chunks(
                sk.as_bytes(),
                &env[..preamble_len],
                &env[preamble_len..],
                0,
                total_chunks,
                "bucket-b",
                "other-object",
            ),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[tokio::test]
    async fn v3_lying_plaintext_len_does_not_drive_unbounded_allocation() {
        // plaintext_len isn't authenticated (it's patched in after all chunks
        // are written, so it can't be bound at encrypt time). Before the fix
        // its raw value was trusted directly as a Vec/BytesMut pre-allocation
        // size. A tiny, otherwise-legitimate envelope claiming a multi-exabyte
        // plaintext_len must not attempt that allocation — the real chunks
        // still decrypt fine, and the lie is caught by the trailing
        // length-consistency check instead of an AEAD failure.
        let (pk, sk) = mlkem768::keypair();
        let file = tempfile_v3().await;
        let mut session = EncryptSession::new(
            file,
            pk.as_bytes(),
            EPOCH,
            "bucket",
            "key",
            0,
            DEFAULT_CHUNK_SIZE_BYTES,
        )
        .await
        .unwrap();
        session.feed(b"tiny").await.unwrap();
        let (file, _) = session.finish().await.unwrap();
        let mut env = read_file(file).await;

        // plaintext_len lives at header bytes [24..32].
        env[24..32].copy_from_slice(&u64::MAX.to_be_bytes());

        assert!(matches!(
            decrypt(sk.as_bytes(), &env, "bucket", "key"),
            Err(CryptoError::Envelope("plaintext length mismatch"))
        ));
        assert!(matches!(
            decrypt_owned(
                sk.as_bytes(),
                BytesMut::from(env.as_slice()),
                "bucket",
                "key"
            ),
            Err(CryptoError::Envelope("plaintext length mismatch"))
        ));
    }

    #[tokio::test]
    async fn v4_tail_truncation_is_detected() {
        // Regression test for the v3 gap this format version closes: with
        // `plaintext_len` unauthenticated, an attacker could drop trailing
        // whole chunks and patch `plaintext_len` down to match, and every
        // surviving chunk still authenticated. v4's final-chunk AAD marker
        // means the new (shorter) last chunk was originally sealed
        // `is_final = 0` and fails to authenticate as the presented final
        // chunk.
        let (pk, sk) = mlkem768::keypair();
        let chunk_size = 4096usize;
        // Exactly 4 full chunks, so truncation lands on a chunk boundary.
        let pt: Vec<u8> = (0..(chunk_size * 4)).map(|i| (i % 251) as u8).collect();
        assert_eq!(padme_len(pt.len() as u64), pt.len() as u64, "no padding");

        let file = tempfile_v3().await;
        let mut session =
            EncryptSession::new(file, pk.as_bytes(), EPOCH, "bucket", "key", 0, chunk_size)
                .await
                .unwrap();
        session.feed(&pt).await.unwrap();
        let (file, _) = session.finish().await.unwrap();
        let env = read_file(file).await;

        let preamble_len = v3_preamble_len();
        let stride = chunk_size + TAG_LEN;
        let kept_chunks = 2usize;
        let mut forged = env[..preamble_len + kept_chunks * stride].to_vec();
        let forged_len = (kept_chunks * chunk_size) as u64;
        forged[V3_PLAINTEXT_LEN_OFFSET as usize..V3_PLAINTEXT_LEN_OFFSET as usize + 8]
            .copy_from_slice(&forged_len.to_be_bytes());

        assert!(
            matches!(
                decrypt(sk.as_bytes(), &forged, "bucket", "key"),
                Err(CryptoError::AuthFailed)
            ),
            "truncated v4 envelope must fail authentication, not decrypt cleanly"
        );
        assert!(matches!(
            decrypt_owned(
                sk.as_bytes(),
                BytesMut::from(forged.as_slice()),
                "bucket",
                "key"
            ),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[tokio::test]
    async fn v4_ranged_decrypt_rejects_wrong_total_chunks() {
        // `decrypt_v4_chunks` only sees the ciphertext window it's handed —
        // it cannot itself detect that a *shorter-than-requested* window
        // was returned by a truncated backend (that's the caller's job:
        // verify the returned window length against the requested range,
        // computed from a trusted size — see `get.rs`). What it CAN and
        // must enforce is that the `is_final` marker matches reality: if
        // the caller supplies the wrong `total_chunks` (so a non-final
        // chunk gets checked against `is_final = 1`, or the true final
        // chunk against `is_final = 0`), authentication fails rather than
        // silently returning plaintext under the wrong marker.
        let (pk, sk) = mlkem768::keypair();
        let chunk_size = 4096usize;
        let pt: Vec<u8> = (0..(chunk_size * 4)).map(|i| (i % 251) as u8).collect();
        let file = tempfile_v3().await;
        let mut session =
            EncryptSession::new(file, pk.as_bytes(), EPOCH, "bucket", "key", 0, chunk_size)
                .await
                .unwrap();
        session.feed(&pt).await.unwrap();
        let (file, _) = session.finish().await.unwrap();
        let env = read_file(file).await;

        let preamble_len = v3_preamble_len();
        let stride = chunk_size + TAG_LEN;
        let true_total_chunks = padme_len(pt.len() as u64).div_ceil(chunk_size as u64);
        assert_eq!(true_total_chunks, 4);
        let preamble = &env[..preamble_len];

        // Correct total_chunks: the whole object decrypts.
        let whole_window = &env[preamble_len..];
        assert!(
            decrypt_v4_chunks(
                sk.as_bytes(),
                preamble,
                whole_window,
                0,
                true_total_chunks,
                "bucket",
                "key",
            )
            .is_ok()
        );

        // Wrong total_chunks (claims one more chunk exists than really
        // does): the true last chunk (index 3) is now checked against
        // `is_final = 0` instead of the `is_final = 1` it was sealed with.
        assert!(matches!(
            decrypt_v4_chunks(
                sk.as_bytes(),
                preamble,
                whole_window,
                0,
                true_total_chunks + 1,
                "bucket",
                "key",
            ),
            Err(CryptoError::AuthFailed)
        ));

        // Wrong total_chunks (claims fewer chunks than really exist): chunk
        // index 2 (genuinely non-final) is now checked against
        // `is_final = 1` instead of the `is_final = 0` it was sealed with.
        let three_chunk_window = &env[preamble_len..preamble_len + 3 * stride];
        assert!(matches!(
            decrypt_v4_chunks(
                sk.as_bytes(),
                preamble,
                three_chunk_window,
                0,
                3,
                "bucket",
                "key",
            ),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[tokio::test]
    async fn v4_encrypt_session_multi_chunk_final_marker_is_correct() {
        // Directly exercises the lookahead-buffer bookkeeping in
        // `EncryptSession` across several chunk-alignment edge cases:
        // exactly one full chunk, an exact multiple of chunk_size, and a
        // partial trailing chunk. Each must round-trip and each object's
        // true last on-disk chunk must be the one carrying `is_final = 1`
        // (implicitly verified by `decrypt` succeeding at all, since a
        // wrong marker on any chunk fails that chunk's AEAD tag).
        let (pk, sk) = mlkem768::keypair();
        let chunk_size = 1024usize;
        for total_bytes in [chunk_size, chunk_size * 3, chunk_size * 2 + 100, 1] {
            let pt: Vec<u8> = (0..total_bytes).map(|i| (i % 251) as u8).collect();
            let file = tempfile_v3().await;
            let mut session =
                EncryptSession::new(file, pk.as_bytes(), EPOCH, "bucket", "key", 0, chunk_size)
                    .await
                    .unwrap();
            // Feed in small slices to exercise the staging/pending handoff
            // repeatedly rather than in one exact-chunk-sized call.
            for c in pt.chunks(333) {
                session.feed(c).await.unwrap();
            }
            let (file, info) = session.finish().await.unwrap();
            assert_eq!(info.envelope_version, 4);
            let env = read_file(file).await;
            let recovered = decrypt(sk.as_bytes(), &env, "bucket", "key").unwrap();
            assert_eq!(
                &recovered[..pt.len()],
                pt.as_slice(),
                "round trip failed for total_bytes={total_bytes}"
            );
        }
    }

    async fn tempfile_v3() -> crate::storage::streaming_sink::StreamingSink {
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
