//! In-memory session store keyed by SHA-256(token).
//!
//! Tokens themselves are 32 random bytes encoded with URL-safe base64
//! (no padding) — a 43-character ASCII string. We store only the hash so a
//! memory dump of the daemon doesn't leak replay-able credentials.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use dashmap::DashMap;
use rand::Rng;
use sha2::{Digest, Sha256};
use y2q_core::crypto::Role;
use zeroize::Zeroizing;

use super::error::AuthError;

/// Bearer token issued to a client. The wire form is `URL_SAFE_NO_PAD(b)`
/// where `b` is 32 random bytes from the OS CSPRNG.
#[derive(Debug, Clone)]
pub struct SessionToken(pub String);

impl SessionToken {
    /// Mint a fresh random token.
    pub fn random() -> Self {
        let mut buf = [0u8; 32];
        rand::rng().fill_bytes(&mut buf);
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

/// Bucket keys already opened by a session, keyed by `(bucket, epoch)`.
/// FIFO-evicted at [`MAX_SESSION_BUCKET_KEYS`] entries so a session touching
/// many buckets can't grow this cache unbounded. Keying by epoch (not just
/// bucket) means a rotation can never serve a stale key from the cache — the
/// new epoch simply misses and gets opened fresh.
///
/// Wired up by `bucket_keys.rs`'s `resolve_read_key`/`is_visible`.
#[derive(Default)]
struct BucketKeyCache {
    entries: HashMap<(String, u32), Arc<Zeroizing<Vec<u8>>>>,
    order: VecDeque<(String, u32)>,
}

/// FIFO eviction width for [`BucketKeyCache`].
const MAX_SESSION_BUCKET_KEYS: usize = 32;

impl BucketKeyCache {
    fn get(&self, bucket: &str, epoch: u32) -> Option<Arc<Zeroizing<Vec<u8>>>> {
        self.entries.get(&(bucket.to_owned(), epoch)).cloned()
    }

    fn insert(&mut self, bucket: String, epoch: u32, key: Arc<Zeroizing<Vec<u8>>>) {
        let id = (bucket, epoch);
        if !self.entries.contains_key(&id) {
            self.order.push_back(id.clone());
            if self.order.len() > MAX_SESSION_BUCKET_KEYS
                && let Some(oldest) = self.order.pop_front()
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(id, key);
    }
}

/// Per-session state held in the [`SessionStore`] map.
pub struct SessionInfo {
    pub username: String,
    /// Global role captured at login, used to authorize admin endpoints and
    /// grant implicit access to every bucket. Cached here so authorization does
    /// no user-store lookup on the request hot path; a role change therefore
    /// only takes effect on the user's next login (sessions are short-lived).
    pub role: Role,
    /// When the session was issued (informational; not used for expiry).
    #[allow(dead_code)]
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    /// Which credential slot opened this session. Needed so a duress login
    /// (phase 5) can revoke only *other* personas' sessions, and so bucket
    /// grants (phase 3) resolve per persona rather than per username.
    pub persona: u8,
    /// This persona's duress flag, captured at login. Reported verbatim by
    /// `GET /api/v1/personas/me` — there is no other way to recover it
    /// post-login, since it lives only in the encrypted `SlotPayload`, not
    /// on the user record's cleartext fields.
    pub revoke_other_sessions: bool,
    /// The unwrapped identity secret key of the persona this session logged
    /// in as. Lives exactly as long as the session; zeroized when the entry
    /// is dropped from the store.
    pub identity_sk: Zeroizing<Vec<u8>>,
    /// Bucket keys already opened by this session. See [`BucketKeyCache`].
    bucket_keys: Mutex<BucketKeyCache>,
}

// `Zeroizing` only scrubs on drop — it forwards `Debug` to the inner type, so
// a derived impl here would print the raw secret key. Redact it explicitly.
impl std::fmt::Debug for SessionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionInfo")
            .field("username", &self.username)
            .field("role", &self.role)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("persona", &self.persona)
            .field("revoke_other_sessions", &self.revoke_other_sessions)
            .field("identity_sk", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl SessionInfo {
    /// Build a fresh session for `persona`'s `identity_sk`. The bucket-key
    /// cache starts empty.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        username: String,
        role: Role,
        created_at: SystemTime,
        expires_at: SystemTime,
        persona: u8,
        revoke_other_sessions: bool,
        identity_sk: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self {
            username,
            role,
            created_at,
            expires_at,
            persona,
            revoke_other_sessions,
            identity_sk,
            bucket_keys: Mutex::new(BucketKeyCache::default()),
        }
    }

    pub fn is_expired(&self, now: SystemTime) -> bool {
        now >= self.expires_at
    }

    /// A cached bucket key for `(bucket, epoch)`, if this session has
    /// already opened it.
    pub fn cached_bucket_key(&self, bucket: &str, epoch: u32) -> Option<Arc<Zeroizing<Vec<u8>>>> {
        self.bucket_keys
            .lock()
            .expect("bucket key cache poisoned")
            .get(bucket, epoch)
    }

    /// Cache a newly-opened bucket key for `(bucket, epoch)`.
    pub fn cache_bucket_key(&self, bucket: String, epoch: u32, key: Arc<Zeroizing<Vec<u8>>>) {
        self.bucket_keys
            .lock()
            .expect("bucket key cache poisoned")
            .insert(bucket, epoch, key);
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

    /// Revoke every session belonging to `username`. Returns the count removed.
    /// Used when a user's role changes (or they are disabled) so the change
    /// takes effect immediately rather than at the next session expiry.
    pub fn revoke_user(&self, username: &str) -> usize {
        let victims: Vec<[u8; 32]> = self
            .inner
            .iter()
            .filter_map(|r| (r.value().username == username).then_some(*r.key()))
            .collect();
        let n = victims.len();
        for k in victims {
            self.inner.remove(&k);
        }
        n
    }

    /// Revoke every session belonging to `username` *except* those opened
    /// through `keep_persona`. Used by a duress-flagged login
    /// (`revoke_other_sessions`) to drop the real persona's live sessions
    /// without touching its own. Returns the count removed.
    pub fn revoke_user_except(&self, username: &str, keep_persona: u8) -> usize {
        let victims: Vec<[u8; 32]> = self
            .inner
            .iter()
            .filter_map(|r| {
                let info = r.value();
                (info.username == username && info.persona != keep_persona).then_some(*r.key())
            })
            .collect();
        let n = victims.len();
        for k in victims {
            self.inner.remove(&k);
        }
        n
    }

    /// Revoke every session belonging to `username` opened through exactly
    /// `persona`. Used by `DELETE /api/v1/personas/{slot}` so overwriting a
    /// slot with a fresh decoy immediately kills any live session still
    /// carrying the old identity secret key. Returns the count removed.
    pub fn revoke_user_persona(&self, username: &str, persona: u8) -> usize {
        let victims: Vec<[u8; 32]> = self
            .inner
            .iter()
            .filter_map(|r| {
                let info = r.value();
                (info.username == username && info.persona == persona).then_some(*r.key())
            })
            .collect();
        let n = victims.len();
        for k in victims {
            self.inner.remove(&k);
        }
        n
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

    fn test_session(username: &str, persona: u8, expires_at: SystemTime) -> SessionInfo {
        SessionInfo::new(
            username.to_owned(),
            Role::User,
            SystemTime::now(),
            expires_at,
            persona,
            false,
            Zeroizing::new(vec![0u8; 8]),
        )
    }

    #[test]
    fn insert_lookup_revoke() {
        let s = SessionStore::new();
        let info = test_session("alice", 0, SystemTime::now() + Duration::from_secs(60));
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
        let info = test_session("alice", 0, SystemTime::now() - Duration::from_secs(1));
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
        s.insert(test_session("a", 0, now + Duration::from_secs(60)));
        s.insert(test_session("b", 0, now - Duration::from_secs(1)));
        assert_eq!(s.sweep(), 1);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn revoke_user_except_keeps_only_the_named_persona() {
        let s = SessionStore::new();
        let future = SystemTime::now() + Duration::from_secs(60);
        let tok_a = s.insert(test_session("alice", 0, future));
        let tok_b = s.insert(test_session("alice", 1, future));
        let tok_c = s.insert(test_session("bob", 0, future));

        assert_eq!(s.revoke_user_except("alice", 1), 1);
        assert!(matches!(
            s.get_active(&tok_a.hash()),
            Err(AuthError::TokenInvalid)
        ));
        assert!(s.get_active(&tok_b.hash()).is_ok());
        assert!(s.get_active(&tok_c.hash()).is_ok());
    }

    #[test]
    fn bucket_key_cache_evicts_oldest_past_the_limit() {
        let info = test_session("alice", 0, SystemTime::now() + Duration::from_secs(60));
        for epoch in 0..(MAX_SESSION_BUCKET_KEYS as u32 + 1) {
            info.cache_bucket_key(
                "b".to_owned(),
                epoch,
                Arc::new(Zeroizing::new(vec![epoch as u8])),
            );
        }
        // The oldest entry (epoch 0) was evicted; the newest survives.
        assert!(info.cached_bucket_key("b", 0).is_none());
        assert!(info.cached_bucket_key("b", MAX_SESSION_BUCKET_KEYS as u32).is_some());
    }

    #[test]
    fn ttl_validation() {
        assert!(compute_expiry(Some(0), 3600, 86400).is_err());
        assert!(compute_expiry(Some(100_000), 3600, 86400).is_err());
        assert!(compute_expiry(Some(3600), 3600, 86400).is_ok());
        assert!(compute_expiry(None, 3600, 86400).is_ok());
    }

    #[test]
    fn revoke_user_persona_only_removes_that_slot() {
        let s = SessionStore::new();
        let future = SystemTime::now() + Duration::from_secs(60);
        let tok_a = s.insert(test_session("alice", 0, future));
        let tok_b = s.insert(test_session("alice", 1, future));
        let tok_c = s.insert(test_session("bob", 1, future));

        assert_eq!(s.revoke_user_persona("alice", 1), 1);
        assert!(s.get_active(&tok_a.hash()).is_ok());
        assert!(matches!(
            s.get_active(&tok_b.hash()),
            Err(AuthError::TokenInvalid)
        ));
        // A different user's session at the same persona index is untouched.
        assert!(s.get_active(&tok_c.hash()).is_ok());
    }
}
