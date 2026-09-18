//! Process-ephemeral wrapping key for session secrets.
//!
//! One [`SessionKeyring`] is shared (via `Arc`) by every row in a
//! [`super::session::SessionStore`]. It wraps each session's identity secret
//! key and cached bucket keys as AES-256-GCM ciphertext under a single
//! [`MemoryKey`] that itself lives in guarded memory (see
//! [`y2q_core::secmem`]), so a session row at rest holds no plaintext key
//! material — only [`SealedSecret`] ciphertext.
//!
//! Every seal/open is bound (via AAD) to the session's token hash. A sealed
//! blob moved to a different session row therefore fails to open: an
//! attacker with memory *write* access cannot graft one session's sealed
//! identity key onto another session's row.

use y2q_core::secmem::{MemoryKey, SealedSecret, SecretVec};

use super::error::AuthError;

/// HKDF-free AAD-bound wrapping key for session key material. See the
/// module docs.
pub struct SessionKeyring {
    key: MemoryKey,
}

impl SessionKeyring {
    /// Generate a fresh process-ephemeral wrapping key.
    pub fn new() -> Result<Self, AuthError> {
        Ok(Self {
            key: MemoryKey::generate().map_err(|e| AuthError::Backend(e.to_string()))?,
        })
    }

    /// Seal a persona's identity secret key for storage in a session row.
    pub fn seal_identity(
        &self,
        token_hash: &[u8; 32],
        username: &str,
        persona: u8,
        sk: &[u8],
    ) -> Result<SealedSecret, AuthError> {
        self.key
            .seal(sk, &identity_aad(token_hash, username, persona))
            .map_err(|e| AuthError::Backend(e.to_string()))
    }

    /// Open a session row's sealed identity secret key.
    pub fn open_identity(
        &self,
        token_hash: &[u8; 32],
        username: &str,
        persona: u8,
        sealed: &SealedSecret,
    ) -> Result<SecretVec, AuthError> {
        self.key
            .open(sealed, &identity_aad(token_hash, username, persona))
            .map_err(|e| AuthError::Backend(e.to_string()))
    }

    /// Seal a resolved bucket secret key for a session's bucket-key cache.
    pub fn seal_bucket_key(
        &self,
        token_hash: &[u8; 32],
        bucket: &str,
        epoch: u32,
        sk: &[u8],
    ) -> Result<SealedSecret, AuthError> {
        self.key
            .seal(sk, &bucket_key_aad(token_hash, bucket, epoch))
            .map_err(|e| AuthError::Backend(e.to_string()))
    }

    /// Open a cached sealed bucket secret key.
    pub fn open_bucket_key(
        &self,
        token_hash: &[u8; 32],
        bucket: &str,
        epoch: u32,
        sealed: &SealedSecret,
    ) -> Result<SecretVec, AuthError> {
        self.key
            .open(sealed, &bucket_key_aad(token_hash, bucket, epoch))
            .map_err(|e| AuthError::Backend(e.to_string()))
    }
}

/// Build the AAD binding a sealed identity secret key to the session token
/// that holds it, plus the username/persona it belongs to:
/// `b"y2q/v1/session-sk" || token_hash || [persona] || u32_be(username.len()) || username`.
fn identity_aad(token_hash: &[u8; 32], username: &str, persona: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(18 + 32 + 1 + 4 + username.len());
    aad.extend_from_slice(b"y2q/v1/session-sk");
    aad.extend_from_slice(token_hash);
    aad.push(persona);
    aad.extend_from_slice(&(username.len() as u32).to_be_bytes());
    aad.extend_from_slice(username.as_bytes());
    aad
}

/// Build the AAD binding a session's cached bucket key to the session token
/// that holds it, plus the bucket/epoch it was resolved for:
/// `b"y2q/v1/session-bk" || token_hash || u32_be(epoch) || u32_be(bucket.len()) || bucket`.
fn bucket_key_aad(token_hash: &[u8; 32], bucket: &str, epoch: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(18 + 32 + 4 + 4 + bucket.len());
    aad.extend_from_slice(b"y2q/v1/session-bk");
    aad.extend_from_slice(token_hash);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&(bucket.len() as u32).to_be_bytes());
    aad.extend_from_slice(bucket.as_bytes());
    aad
}
