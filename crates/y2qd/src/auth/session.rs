//! In-memory session store keyed by SHA-256(token).
//!
//! Tokens themselves are 32 random bytes encoded with URL-safe base64
//! (no padding) — a 43-character ASCII string. We store only the hash so a
//! memory dump of the daemon doesn't leak replay-able credentials.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use dashmap::DashMap;
use rand::RngCore;
use sha2::{Digest, Sha256};

use super::error::AuthError;

/// Bearer token issued to a client. The wire form is `URL_SAFE_NO_PAD(b)`
/// where `b` is 32 random bytes from the OS CSPRNG.
#[derive(Debug, Clone)]
pub struct SessionToken(pub String);

impl SessionToken {
    /// Mint a fresh random token.
    pub fn random() -> Self {
        let mut buf = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        SessionToken(URL_SAFE_NO_PAD.encode(buf))
    }

    /// SHA-256 of the wire form, used as the lookup key in the store.
    pub fn hash(&self) -> [u8; 32] {
        hash_token(&self.0)
    }
}

/// SHA-256 of `token` as the canonical session-store key.
pub fn hash_token(token: &str) -> [u8; 32] {
    let d = Sha256::digest(token.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Per-session state held in the [`SessionStore`] map.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub username: String,
    /// When the session was issued (informational; not used for expiry).
    #[allow(dead_code)]
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}

impl SessionInfo {
    pub fn is_expired(&self, now: SystemTime) -> bool {
        now >= self.expires_at
    }
}

/// In-memory map of session-token-hash → session info.
///
/// Cheap to clone (`Arc` inside).
#[derive(Default, Clone)]
pub struct SessionStore {
    inner: Arc<DashMap<[u8; 32], Arc<SessionInfo>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a fresh session, returning the wire-form token to hand to
    /// the client.
    pub fn insert(&self, info: SessionInfo) -> SessionToken {
        let token = SessionToken::random();
        self.inner.insert(token.hash(), Arc::new(info));
        token
    }

    /// Look up a session by token-hash, validating expiry.
    ///
    /// Returns [`AuthError::TokenInvalid`] for an unknown hash and
    /// [`AuthError::TokenExpired`] for an expired one (and removes the
    /// expired row as a side effect).
    pub fn get_active(&self, token_hash: &[u8; 32]) -> Result<Arc<SessionInfo>, AuthError> {
        let info = self
            .inner
            .get(token_hash)
            .map(|r| r.value().clone())
            .ok_or(AuthError::TokenInvalid)?;
        if info.is_expired(SystemTime::now()) {
            self.inner.remove(token_hash);
            return Err(AuthError::TokenExpired);
        }
        Ok(info)
    }

    /// Drop the session for `token_hash`, returning whether one existed.
    pub fn revoke(&self, token_hash: &[u8; 32]) -> bool {
        self.inner.remove(token_hash).is_some()
    }

    /// Total number of (possibly expired) entries — used to decide when to
    /// drop the in-memory SK.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Iterate and drop every expired session. Returns the count removed.
    /// Called periodically from a background task.
    pub fn sweep(&self) -> usize {
        let now = SystemTime::now();
        let stale: Vec<[u8; 32]> = self
            .inner
            .iter()
            .filter_map(|r| r.value().is_expired(now).then_some(*r.key()))
            .collect();
        let n = stale.len();
        for k in stale {
            self.inner.remove(&k);
        }
        n
    }
}

/// Decide how long a new session should live.
///
/// `requested_seconds`: caller's `ttl_seconds` field on the login request.
/// `default_ttl`: from `[auth] default_ttl_seconds`.
/// `max_ttl`: from `[auth] max_ttl_seconds`.
pub fn compute_expiry(
    requested_seconds: Option<u64>,
    default_ttl: u64,
    max_ttl: u64,
) -> Result<SystemTime, AuthError> {
    let ttl = requested_seconds.unwrap_or(default_ttl);
    if ttl == 0 || ttl > max_ttl {
        return Err(AuthError::TtlOutOfRange { max: max_ttl });
    }
    Ok(SystemTime::now() + Duration::from_secs(ttl))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_lookup_revoke() {
        let s = SessionStore::new();
        let info = SessionInfo {
            username: "alice".into(),
            created_at: SystemTime::now(),
            expires_at: SystemTime::now() + Duration::from_secs(60),
        };
        let token = s.insert(info);
        let hash = token.hash();
        let found = s.get_active(&hash).unwrap();
        assert_eq!(found.username, "alice");
        assert!(s.revoke(&hash));
        assert!(matches!(s.get_active(&hash), Err(AuthError::TokenInvalid)));
    }

    #[test]
    fn expired_session_returns_expired() {
        let s = SessionStore::new();
        let info = SessionInfo {
            username: "alice".into(),
            created_at: SystemTime::now() - Duration::from_secs(120),
            expires_at: SystemTime::now() - Duration::from_secs(1),
        };
        let token = s.insert(info);
        assert!(matches!(
            s.get_active(&token.hash()),
            Err(AuthError::TokenExpired)
        ));
        // Expired session is removed on access.
        assert!(matches!(
            s.get_active(&token.hash()),
            Err(AuthError::TokenInvalid)
        ));
    }

    #[test]
    fn sweep_removes_expired() {
        let s = SessionStore::new();
        let now = SystemTime::now();
        s.insert(SessionInfo {
            username: "a".into(),
            created_at: now,
            expires_at: now + Duration::from_secs(60),
        });
        s.insert(SessionInfo {
            username: "b".into(),
            created_at: now - Duration::from_secs(120),
            expires_at: now - Duration::from_secs(1),
        });
        assert_eq!(s.sweep(), 1);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn ttl_validation() {
        assert!(compute_expiry(Some(0), 3600, 86400).is_err());
        assert!(compute_expiry(Some(100_000), 3600, 86400).is_err());
        assert!(compute_expiry(Some(3600), 3600, 86400).is_ok());
        assert!(compute_expiry(None, 3600, 86400).is_ok());
    }
}
