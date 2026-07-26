//! ML-KEM-768 encapsulation + AES-256-GCM seal of a secret to a recipient
//! public key.
//!
//! [`kdf`](super::kdf) wraps a secret under a *password* (Argon2id). This
//! module wraps a secret under a *public key*: any holder of the recipient's
//! public key can seal a value for them with no interaction, and only the
//! matching secret key can open it. Used to grant a symmetric key (a bucket
//! wrap key) to a specific ML-KEM-768 identity without ever needing that
//! identity's password.
//!
//! Derivation mirrors [`super::envelope::derive_content_key`]: the KEM shared
//! secret and ciphertext feed HKDF-SHA256 (`salt = kem_ct`, `info =
//! b"y2q/v3/seal"`) to produce the AES-256-GCM key, so the same
//! algorithm-agility posture applies here. Callers supply `aad` to bind a
//! sealed blob to its purpose/position (e.g. a bucket/epoch/user/slot tuple)
//! so ciphertext cannot be relocated across sealed values it wasn't produced
//! for.

use aes_gcm::{Aes256Gcm, KeyInit, aead::AeadInOut};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use pqcrypto::kem::mlkem768;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertextTrait, PublicKey as KemPublicKeyTrait,
    SecretKey as KemSecretKeyTrait, SharedSecret as KemSharedSecretTrait,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use super::CryptoError;

type Nonce = aes_gcm::aead::Nonce<Aes256Gcm>;

/// HKDF info string for the seal key derivation. Bumped if the derivation
/// changes.
const SEAL_HKDF_INFO: &[u8] = b"y2q/v3/seal";

/// Build the AAD binding a sealed bucket-wrap-key grant to its bucket,
/// epoch, grantee, and credential slot:
/// `b"y2q/v3/bucket-grant" || u32_be(bucket.len()) || bucket || u32_be(epoch)
/// || u32_be(user.len()) || user || u32_be(slot)`.
///
/// Binding the slot stops a sealed blob being relocated to a different
/// persona of the same user (mirrors [`super::kdf::slot_wrap_aad`]'s
/// slot-position binding); binding `(bucket, epoch)` stops it being
/// relocated to a different bucket or a stale/future epoch.
pub fn bucket_grant_aad(bucket: &str, epoch: u32, user: &str, slot: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(20 + 8 + bucket.len() + user.len());
    aad.extend_from_slice(b"y2q/v3/bucket-grant");
    aad.extend_from_slice(&(bucket.len() as u32).to_be_bytes());
    aad.extend_from_slice(bucket.as_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&(user.len() as u32).to_be_bytes());
    aad.extend_from_slice(user.as_bytes());
    aad.extend_from_slice(&(slot as u32).to_be_bytes());
    aad
}

/// Build the AAD binding a bucket epoch's ML-KEM-768 secret key to its wrap
/// under the bucket wrap key (BWK): `b"y2q/v3/bucket-sk" ||
/// u32_be(bucket.len()) || bucket || u32_be(epoch)`.
pub fn bucket_sk_wrap_aad(bucket: &str, epoch: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 4 + bucket.len());
    aad.extend_from_slice(b"y2q/v3/bucket-sk");
    aad.extend_from_slice(&(bucket.len() as u32).to_be_bytes());
    aad.extend_from_slice(bucket.as_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

/// Seal `secret` once per identity in `slot_identity_pks_b64`: a real seal
/// at `real_idx`, and a seal of `secret.len()` freshly-generated random
/// bytes to every other entry, all under `aad`.
///
/// The padding is sized to match `secret`, not a fixed width: `SealedKey`'s
/// ciphertext length is `plaintext.len() + 16` (the GCM tag), so padding of
/// the wrong length would leak which entry is real via ciphertext length
/// alone, even though every entry stays individually unreadable. Callers
/// that only ever seal fixed-width secrets (e.g. a 32-byte bucket wrap key)
/// get this for free automatically; callers sealing a variable-width secret
/// still get it because the padding width always tracks `secret.len()`.
pub fn seal_to_slots(
    secret: &[u8],
    slot_identity_pks_b64: &[String],
    real_idx: usize,
    aad: &[u8],
) -> Result<Vec<SealedKey>, CryptoError> {
    let mut out = Vec::with_capacity(slot_identity_pks_b64.len());
    for (i, pk_b64) in slot_identity_pks_b64.iter().enumerate() {
        let pk_bytes = STANDARD
            .decode(pk_b64)
            .map_err(|_| CryptoError::KemDecode("slot identity public key"))?;
        let sealed = if i == real_idx {
            seal_to(&pk_bytes, secret, aad)?
        } else {
            let mut padding = vec![0u8; secret.len()];
            rand::rng().fill_bytes(&mut padding);
            seal_to(&pk_bytes, &padding, aad)?
        };
        out.push(sealed);
    }
    Ok(out)
}

/// ML-KEM-768 encapsulation + AES-256-GCM seal of a secret to a recipient
/// public key. All three fields are standard-base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedKey {
    pub kem_ct_b64: String,
    pub nonce_b64: String,
    pub ct_b64: String,
}

/// Seal `plaintext` to `recipient_pk`, binding it to `aad`.
///
/// Runs a fresh ML-KEM-768 encapsulation against `recipient_pk` (so every
/// call produces an independent ciphertext even for the same plaintext/key),
/// derives an AES-256-GCM key from the shared secret, and encrypts
/// `plaintext` under a fresh random 12-byte nonce with `aad` as AEAD
/// associated data.
pub fn seal_to(
    recipient_pk: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<SealedKey, CryptoError> {
    let pk = mlkem768::PublicKey::from_bytes(recipient_pk)
        .map_err(|_| CryptoError::KemDecode("public key"))?;
    let (ss, kem_ct) = mlkem768::encapsulate(&pk);
    let kem_ct_bytes = kem_ct.as_bytes();

    let mut key_bytes = derive_seal_key(ss.as_bytes(), kem_ct_bytes)?;
    let cipher = Aes256Gcm::new((&key_bytes).into());
    key_bytes.zeroize();
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let mut buf = plaintext.to_vec();
    cipher
        .encrypt_in_place(&Nonce::from(nonce_bytes), aad, &mut buf)
        .map_err(|_| CryptoError::Aead("seal encrypt"))?;

    Ok(SealedKey {
        kem_ct_b64: STANDARD.encode(kem_ct_bytes),
        nonce_b64: STANDARD.encode(nonce_bytes),
        ct_b64: STANDARD.encode(buf),
    })
}

/// Open a value sealed with [`seal_to`], requiring the same `aad` it was
/// sealed with.
///
/// Returns [`CryptoError::AuthFailed`] if the AEAD tag does not verify
/// (wrong secret key, tampered ciphertext, or mismatched `aad`), and
/// [`CryptoError::KemDecode`] if any field fails to base64-decode or the
/// secret key or KEM ciphertext is malformed.
pub fn open_sealed(
    recipient_sk: &[u8],
    sealed: &SealedKey,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let kem_ct_bytes = STANDARD
        .decode(&sealed.kem_ct_b64)
        .map_err(|_| CryptoError::KemDecode("kem ciphertext"))?;
    let nonce_bytes = STANDARD
        .decode(&sealed.nonce_b64)
        .map_err(|_| CryptoError::KemDecode("nonce"))?;
    let ct_bytes = STANDARD
        .decode(&sealed.ct_b64)
        .map_err(|_| CryptoError::KemDecode("ciphertext"))?;
    let nonce_bytes: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| CryptoError::KemDecode("nonce"))?;

    let sk = mlkem768::SecretKey::from_bytes(recipient_sk)
        .map_err(|_| CryptoError::KemDecode("secret key"))?;
    let kem_ct = mlkem768::Ciphertext::from_bytes(&kem_ct_bytes)
        .map_err(|_| CryptoError::KemDecode("kem ciphertext"))?;
    let ss = mlkem768::decapsulate(&kem_ct, &sk);

    let mut key_bytes = derive_seal_key(ss.as_bytes(), &kem_ct_bytes)?;
    let cipher = Aes256Gcm::new((&key_bytes).into());
    key_bytes.zeroize();

    let mut buf = ct_bytes;
    cipher
        .decrypt_in_place(&Nonce::from(nonce_bytes), aad, &mut buf)
        .map_err(|_| CryptoError::AuthFailed)?;
    Ok(Zeroizing::new(buf))
}

fn derive_seal_key(ss: &[u8], kem_ct: &[u8]) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(kem_ct), ss);
    let mut out = [0u8; 32];
    hk.expand(SEAL_HKDF_INFO, &mut out)
        .map_err(|_| CryptoError::Aead("hkdf expand"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let (pk, sk) = mlkem768::keypair();
        let aad = b"y2q/v3/bucket-grant test";
        let secret = b"a 32 byte bucket wrap key value";
        let sealed = seal_to(pk.as_bytes(), secret, aad).unwrap();
        let opened = open_sealed(sk.as_bytes(), &sealed, aad).unwrap();
        assert_eq!(&opened[..], secret);
    }

    #[test]
    fn wrong_aad_fails() {
        let (pk, sk) = mlkem768::keypair();
        let sealed = seal_to(pk.as_bytes(), b"secret", b"aad-a").unwrap();
        let err = open_sealed(sk.as_bytes(), &sealed, b"aad-b").unwrap_err();
        assert!(matches!(err, CryptoError::AuthFailed));
    }

    #[test]
    fn wrong_secret_key_fails() {
        let (pk, _sk1) = mlkem768::keypair();
        let (_pk2, sk2) = mlkem768::keypair();
        let sealed = seal_to(pk.as_bytes(), b"secret", b"aad").unwrap();
        let err = open_sealed(sk2.as_bytes(), &sealed, b"aad").unwrap_err();
        assert!(matches!(err, CryptoError::AuthFailed));
    }

    #[test]
    fn fresh_kem_per_call() {
        let (pk, _sk) = mlkem768::keypair();
        let a = seal_to(pk.as_bytes(), b"secret", b"aad").unwrap();
        let b = seal_to(pk.as_bytes(), b"secret", b"aad").unwrap();
        assert_ne!(a.kem_ct_b64, b.kem_ct_b64);
        assert_ne!(a.ct_b64, b.ct_b64);
    }

    #[test]
    fn malformed_pk_is_kem_decode() {
        let err = seal_to(&[0u8; 4], b"secret", b"aad").unwrap_err();
        assert!(matches!(err, CryptoError::KemDecode("public key")));
    }

    #[test]
    fn seal_to_slots_pads_ciphertext_to_the_same_length_as_the_real_secret() {
        // A variable-width secret (unlike a fixed 32-byte bucket wrap key)
        // must still get length-matched padding, or the real slot would be
        // identifiable by its ciphertext length alone.
        let keypairs: Vec<_> = (0..4).map(|_| mlkem768::keypair()).collect();
        let pks: Vec<String> = keypairs
            .iter()
            .map(|(pk, _)| STANDARD.encode(pk.as_bytes()))
            .collect();
        let secret = vec![0xABu8; 2400]; // variable-width, e.g. an ML-KEM-768 secret key
        let real_idx = 1;
        let grants = seal_to_slots(&secret, &pks, real_idx, b"aad").unwrap();
        assert_eq!(grants.len(), 4);
        let lens: Vec<usize> = grants.iter().map(|g| g.ct_b64.len()).collect();
        assert!(
            lens.iter().all(|&l| l == lens[0]),
            "every grant's ciphertext must be the same length regardless of which slot is real"
        );

        // Only the real slot's secret key recovers the genuine secret.
        let opened =
            open_sealed(keypairs[real_idx].1.as_bytes(), &grants[real_idx], b"aad").unwrap();
        assert_eq!(&opened[..], &secret[..]);

        // A padding slot's own secret key opens to random bytes of the same
        // length, never the real secret.
        let padding_opened = open_sealed(keypairs[0].1.as_bytes(), &grants[0], b"aad").unwrap();
        assert_ne!(&padding_opened[..], &secret[..]);
        assert_eq!(padding_opened.len(), secret.len());
    }
}
