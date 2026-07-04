//! Argon2id wrap/unwrap of the deployment ML-KEM-768 secret key.
//!
//! Each user record stores the SK encrypted under a key derived from that
//! user's password via Argon2id. KDF parameters are stored alongside the
//! wrapped SK so the operator can raise them later without invalidating
//! existing accounts.
//!
//! Wrap envelope: AES-256-GCM with the user's KEK as the key, a fresh random
//! 12-byte nonce, and a stable AAD `b"y2q/v1/sk-wrap"` that binds the
//! ciphertext to its purpose (wrapping a deployment secret key).

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::CryptoError;

/// Stable AAD bound to every wrapped-SK ciphertext.
const WRAP_AAD: &[u8] = b"y2q/v1/sk-wrap";

/// Argon2id parameters, persisted per user record.
///
/// Defaults follow OWASP's "second-tier" recommendation (m=64 MiB, t=3,
/// p=4) — slow enough on commodity hardware that a single login takes
/// hundreds of milliseconds, which acts as natural brute-force friction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB. Argon2's `m_cost`.
    pub m_cost_kib: u32,
    /// Time cost (iteration count). Argon2's `t_cost`.
    pub t_cost: u32,
    /// Parallelism (lanes). Argon2's `p_cost`.
    pub p_cost: u32,
    /// 16-byte salt, stored alongside the wrapped key.
    #[serde(with = "salt_b64")]
    pub salt: [u8; 16],
}

/// AES-256-GCM ciphertext (with 16-byte tag appended) of the deployment SK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedSk {
    /// 12-byte AEAD nonce.
    #[serde(with = "nonce_b64")]
    pub nonce: [u8; 12],
    /// Ciphertext + 16-byte GCM tag.
    #[serde(with = "ct_b64")]
    pub ciphertext: Vec<u8>,
}

/// Default Argon2id parameters used for newly added users.
pub fn default_argon2_params() -> Argon2Params {
    Argon2Params::with_random_salt(64 * 1024, 3, 4)
}

impl Argon2Params {
    /// Build a params struct with `m`/`t`/`p` and a freshly generated
    /// random salt.
    pub fn with_random_salt(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Self {
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        Self {
            m_cost_kib,
            t_cost,
            p_cost,
            salt,
        }
    }

    fn argon2(&self) -> Result<Argon2<'static>, CryptoError> {
        let params = Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(32))
            .map_err(|e| CryptoError::Kdf(format!("invalid params: {e}")))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    /// Run Argon2id over `password` to derive a 32-byte KEK.
    ///
    /// The returned buffer is the *raw* derived key — keep its lifetime
    /// short and zeroize when done.
    pub fn derive_kek(&self, password: &[u8]) -> Result<[u8; 32], CryptoError> {
        let argon2 = self.argon2()?;
        let mut kek = [0u8; 32];
        argon2
            .hash_password_into(password, &self.salt, &mut kek)
            .map_err(|e| CryptoError::Kdf(format!("hash: {e}")))?;
        Ok(kek)
    }
}

/// Wrap `sk_bytes` (raw ML-KEM-768 secret key bytes) under a key derived from
/// `password` with the supplied Argon2 parameters.
pub fn wrap_sk(
    sk_bytes: &[u8],
    password: &[u8],
    params: &Argon2Params,
) -> Result<WrappedSk, CryptoError> {
    let mut kek = params.derive_kek(password)?;
    let result = wrap_with_kek(sk_bytes, &kek);
    kek.zeroize();
    result
}

/// Unwrap a previously wrapped SK using `password` + the same params used
/// when wrapping.
pub fn unwrap_sk(
    wrapped: &WrappedSk,
    password: &[u8],
    params: &Argon2Params,
) -> Result<Vec<u8>, CryptoError> {
    let mut kek = params.derive_kek(password)?;
    let result = unwrap_with_kek(wrapped, &kek);
    kek.zeroize();
    result
}

fn wrap_with_kek(sk_bytes: &[u8], kek: &[u8; 32]) -> Result<WrappedSk, CryptoError> {
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new(kek.into());
    let ct = cipher
        .encrypt(
            &aes_gcm::Nonce::from(nonce_bytes),
            Payload {
                msg: sk_bytes,
                aad: WRAP_AAD,
            },
        )
        .map_err(|_| CryptoError::Aead("wrap encrypt"))?;
    Ok(WrappedSk {
        nonce: nonce_bytes,
        ciphertext: ct,
    })
}

fn unwrap_with_kek(wrapped: &WrappedSk, kek: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(kek.into());
    cipher
        .decrypt(
            &aes_gcm::Nonce::from(wrapped.nonce),
            Payload {
                msg: &wrapped.ciphertext,
                aad: WRAP_AAD,
            },
        )
        .map_err(|_| CryptoError::AuthFailed)
}

mod salt_b64 {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(d)?;
        let v = STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != 16 {
            return Err(serde::de::Error::custom("salt must be 16 bytes"));
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

mod nonce_b64 {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 12], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 12], D::Error> {
        let s = String::deserialize(d)?;
        let v = STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != 12 {
            return Err(serde::de::Error::custom("nonce must be 12 bytes"));
        }
        let mut out = [0u8; 12];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

mod ct_b64 {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_params() -> Argon2Params {
        Argon2Params::with_random_salt(8 * 1024, 1, 1)
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let sk = vec![0xCD; 2400];
        let params = fast_params();
        let wrapped = wrap_sk(&sk, b"correct horse battery staple", &params).unwrap();
        let recovered = unwrap_sk(&wrapped, b"correct horse battery staple", &params).unwrap();
        assert_eq!(recovered, sk);
    }

    #[test]
    fn wrong_password_fails() {
        let params = fast_params();
        let wrapped = wrap_sk(b"some-secret", b"right", &params).unwrap();
        assert!(matches!(
            unwrap_sk(&wrapped, b"wrong", &params),
            Err(CryptoError::AuthFailed)
        ));
    }

    #[test]
    fn nonce_changes_each_wrap() {
        let params = fast_params();
        let a = wrap_sk(b"x", b"pw", &params).unwrap();
        let b = wrap_sk(b"x", b"pw", &params).unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn params_serialize_roundtrip() {
        let params = fast_params();
        let wrapped = wrap_sk(b"sk", b"pw", &params).unwrap();
        let json = serde_json::to_string(&(&params, &wrapped)).unwrap();
        let (params2, wrapped2): (Argon2Params, WrappedSk) = serde_json::from_str(&json).unwrap();
        let recovered = unwrap_sk(&wrapped2, b"pw", &params2).unwrap();
        assert_eq!(recovered, b"sk");
    }
}
