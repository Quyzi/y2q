//! Whole-object AEAD envelope.
//!
//! Each PUT runs a fresh ML-KEM-768 encapsulation against the deployment's
//! public key, derives an AES-256-GCM key from the resulting shared secret via
//! HKDF-SHA256, and writes the encrypted body together with the encapsulation
//! ciphertext into a self-describing envelope.
//!
//! The on-disk layout, in order:
//!
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
//!
//! Total fixed overhead = 28 (header) + 1088 (KEM ciphertext) + 16 (tag) = 1132 bytes.
//!
//! AAD bound to each AEAD operation = the 28-byte fixed header.
//! `kem_ct` is implicitly bound because the content key is derived from it.

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
use zeroize::Zeroize;

use super::CryptoError;

/// Header bytes preceding the KEM ciphertext.
///
/// Layout: 4 magic + 2 version + 1 kem_alg + 1 aead_alg + 12 nonce + 8 plaintext_len.
pub const ENVELOPE_HEADER_FIXED_LEN: usize = 4 + 2 + 1 + 1 + 12 + 8;

/// 4-byte file-format magic.
const MAGIC: &[u8; 4] = b"Y2Q1";
/// Bumped only when the on-disk format changes incompatibly.
const FORMAT_VER: u16 = 1;
/// `kem_alg = 1` is reserved for ML-KEM-768.
const KEM_ALG_MLKEM768: u8 = 1;
/// `aead_alg = 1` is reserved for AES-256-GCM with a 12-byte nonce and 16-byte tag.
const AEAD_ALG_AES256GCM: u8 = 1;

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
/// Returns the recovered plaintext on success. Any malformed header,
/// unsupported version, KEM-decode failure, or AEAD-tag mismatch surfaces as a
/// distinct [`CryptoError`] variant — except the AEAD-tag case, which the
/// caller should always present as a generic decryption failure to avoid
/// leaking ciphertext-state side channels.
pub fn decrypt(sk_bytes: &[u8], envelope: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let header = parse_and_validate_header(envelope)?;
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

/// Sniff the magic+version prefix to decide whether `bytes` is an encrypted
/// y2q envelope. Used by GET to fall through to plaintext for legacy objects
/// written before encryption was enabled.
pub fn looks_encrypted(bytes: &[u8]) -> bool {
    bytes.len() >= ENVELOPE_HEADER_FIXED_LEN + mlkem768::ciphertext_bytes() + 16
        && &bytes[..4] == MAGIC
}

/// Parsed view of the 28-byte fixed header.
struct Header {
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

fn parse_and_validate_header(env: &[u8]) -> Result<Header, CryptoError> {
    if env.len() < ENVELOPE_HEADER_FIXED_LEN {
        return Err(CryptoError::Envelope("truncated header"));
    }
    if &env[0..4] != MAGIC {
        return Err(CryptoError::Envelope("bad magic"));
    }
    let ver = u16::from_be_bytes([env[4], env[5]]);
    if ver != FORMAT_VER {
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
    Ok(Header {
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
}
