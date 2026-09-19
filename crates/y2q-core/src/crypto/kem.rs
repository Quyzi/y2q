//! ML-KEM-768 over RustCrypto `ml-kem`.
//!
//! Secret keys are serialized in the legacy 2400-byte expanded form, not the
//! 64-byte seed: every keystore and bucket-key blob written by earlier
//! releases stores the expanded form, and `SlotPayload`'s fixed-width
//! deniability padding is sized to it.
#![allow(deprecated)] // `ExpandedKeyEncoding` — required for on-disk compatibility, see above.

use ml_kem::array::Array;
use ml_kem::ml_kem_768::{
    Ciphertext as MlCiphertext, DecapsulationKey as Dk, EncapsulationKey as Ek,
    ExpandedDecapsulationKey,
};
use ml_kem::{
    Decapsulate, Encapsulate, ExpandedKeyEncoding, Generate, KeyExport, SharedKey, TryKeyInit,
};
use zeroize::Zeroizing;

use super::CryptoError;

/// Encoded ML-KEM-768 encapsulation (public) key length, in bytes.
pub const PUBLIC_KEY_BYTES: usize = 1184;
/// Encoded ML-KEM-768 decapsulation (secret) key length, in bytes (legacy
/// expanded form — see the module docs).
pub const SECRET_KEY_BYTES: usize = 2400;
/// Encoded ML-KEM-768 ciphertext length, in bytes.
pub const CIPHERTEXT_BYTES: usize = 1088;
/// Shared-secret length, in bytes.
pub const SHARED_SECRET_BYTES: usize = 32;

/// KEM ciphertext (encapsulated shared secret).
pub type Ciphertext = MlCiphertext;
/// KEM shared secret produced by encapsulation/decapsulation.
pub type SharedSecret = SharedKey;

/// ML-KEM-768 encapsulation (public) key.
#[derive(Clone)]
pub struct PublicKey(Ek);

/// ML-KEM-768 decapsulation (secret) key. Zeroized on drop.
pub struct SecretKey(Dk);

/// Generate a fresh ML-KEM-768 keypair.
pub fn keypair() -> (PublicKey, SecretKey) {
    let sk = Dk::generate_from_rng(&mut rand::rng());
    let pk = PublicKey(sk.encapsulation_key().clone());
    (pk, SecretKey(sk))
}

/// Encapsulate a fresh shared secret against `pk`. Every call produces an
/// independent ciphertext/shared-secret pair even for the same key.
pub fn encapsulate(pk: &PublicKey) -> (SharedSecret, Ciphertext) {
    let (ct, ss) = pk.0.encapsulate_with_rng(&mut rand::rng());
    (ss, ct)
}

/// Recover the shared secret encapsulated in `ct` under `sk`'s matching
/// public key. Infallible (implicit rejection): a mismatched ciphertext
/// yields an unusable but well-formed shared secret rather than an error,
/// matching the KEM's standard anti-Bleichenbacher construction.
pub fn decapsulate(ct: &Ciphertext, sk: &SecretKey) -> SharedSecret {
    sk.0.decapsulate(ct)
}

impl PublicKey {
    /// Decode a public key from its `PUBLIC_KEY_BYTES`-length encoding.
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        if b.len() != PUBLIC_KEY_BYTES {
            return Err(CryptoError::KemDecode("public key"));
        }
        Ek::new_from_slice(b)
            .map(PublicKey)
            .map_err(|_| CryptoError::KemDecode("public key"))
    }

    /// Encode this public key to its `PUBLIC_KEY_BYTES`-length form.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.0.to_bytes().into()
    }
}

impl SecretKey {
    /// Decode a secret key from its `SECRET_KEY_BYTES`-length legacy
    /// expanded encoding (the on-disk format used by every keystore and
    /// bucket-key blob).
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        if b.len() != SECRET_KEY_BYTES {
            return Err(CryptoError::KemDecode("secret key"));
        }
        let expanded: ExpandedDecapsulationKey =
            Array::try_from(b).map_err(|_| CryptoError::KemDecode("secret key"))?;
        Dk::from_expanded_bytes(&expanded)
            .map(SecretKey)
            .map_err(|_| CryptoError::KemDecode("secret key"))
    }

    /// Encode this secret key to its `SECRET_KEY_BYTES`-length legacy
    /// expanded form.
    pub fn to_bytes(&self) -> Zeroizing<[u8; SECRET_KEY_BYTES]> {
        Zeroizing::new(self.0.to_expanded_bytes().into())
    }
}

/// Decode a KEM ciphertext from its `CIPHERTEXT_BYTES`-length encoding.
pub fn ciphertext_from_bytes(b: &[u8]) -> Result<Ciphertext, CryptoError> {
    if b.len() != CIPHERTEXT_BYTES {
        return Err(CryptoError::KemDecode("ciphertext"));
    }
    Ciphertext::try_from(b).map_err(|_| CryptoError::KemDecode("ciphertext"))
}
