//! In-memory session store keyed by SHA-256(token).
//!
//! Tokens themselves are 32 random bytes encoded with URL-safe base64
//! (no padding) — a 43-character ASCII string. We store only the hash so a
//! memory dump of the daemon doesn't leak replay-able credentials.
//!
//! Every session's identity secret key, and every bucket key it has opened,
//! is held as [`SealedSecret`] ciphertext under the store's
//! [`SessionKeyring`] — never as plaintext. See the `keyring` module docs
//! for the wrapping scheme.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use dashmap::DashMap;
use rand::Rng;
use sha2::{Digest, Sha256};
use y2q_core::crypto::Role;
use y2q_core::secmem::{SealedSecret, SecretString, SecretVec};

use super::error::AuthError;
use super::keyring::SessionKeyring;

/// Bearer token issued to a client. The wire form is `URL_SAFE_NO_PAD(b)`
/// where `b` is 32 random bytes from the OS CSPRNG. Held as a
/// [`SecretString`], not a plain `String`: it's bearer-equivalent to the
/// session's identity secret key for as long as it's live.
pub struct SessionToken(pub SecretString);

// `SecretString` is neither `Debug` (redacted separately below) nor
// `Clone` — no caller clones a token.
impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl SessionToken {
    /// Mint a fresh random token: 32 random bytes, URL-safe-base64 encoded
    /// with no padding, entirely inside guarded memory.
    pub fn random() -> Self {
        let mut raw = SecretVec::zeroed(32).expect("guarded allocation for a session token");
        rand::rng().fill_bytes(raw.as_mut_slice());
        let mut encoded = SecretVec::zeroed(43).expect("guarded allocation for a session token");
        URL_SAFE_NO_PAD
            .encode_slice(&raw[..], encoded.as_mut_slice())
            .expect("43 bytes exactly fits URL_SAFE_NO_PAD(32 random bytes)");
        let token = encoded
            .as_str()
            .expect("base64 URL_SAFE_NO_PAD output is ASCII");
        SessionToken(SecretString::from_str(token).expect("guarded allocation for a session token"))
    }

    /// SHA-256 of the wire form, used as the lookup key in the store.
    pub fn hash(&self) -> [u8; 32] {
        hash_token(self.0.expose())
    }
}

/// SHA-256 of `token` as the canonical session-store key.
pub fn hash_token(token: &str) -> [u8; 32] {
    let d = Sha256::digest(token.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Bucket keys already opened by a session, keyed by `(bucket, epoch)`, held
/// as [`SealedSecret`] ciphertext. FIFO-evicted at
/// [`MAX_SESSION_BUCKET_KEYS`] entries so a session touching many buckets
/// can't grow this cache unbounded. Keying by epoch (not just bucket) means
/// a rotation can never serve a stale key from the cache — the new epoch
/// simply misses and gets opened fresh.
///
/// Wired up by `bucket_keys.rs`'s `resolve_read_key`/`is_visible`.
#[derive(Default)]
struct BucketKeyCache {
    entries: HashMap<(String, u32), SealedSecret>,
    order: VecDeque<(String, u32)>,
}

/// FIFO eviction width for [`BucketKeyCache`].
const MAX_SESSION_BUCKET_KEYS: usize = 32;

impl BucketKeyCache {
    fn get(&self, bucket: &str, epoch: u32) -> Option<SealedSecret> {
        self.entries.get(&(bucket.to_owned(), epoch)).cloned()
    }

    fn insert(&mut self, bucket: String, epoch: u32, key: SealedSecret) {
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

/// Everything needed to mint a fresh session, before it's sealed and
/// inserted into a [`SessionStore`].
pub struct NewSession {
    pub username: String,
    pub role: Role,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    /// Which credential slot this session logged in as.
    pub persona: u8,
    pub revoke_other_sessions: bool,
    /// The unwrapped identity secret key of the persona this session logged
    /// in as. Consumed (and scrubbed) by [`SessionStore::insert`], which
    /// seals it before the session row is ever visible to another thread.
    pub identity_sk: SecretVec,
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
    /// (phase 5) can switch only *other* personas' live sessions over to
    /// itself, and so bucket grants (phase 3) resolve per persona rather
    /// than per username.
    pub persona: u8,
    /// This persona's duress flag, captured at login. Server-internal only:
    /// never returned by any API response (including `GET
    /// /api/v1/personas/me`) — exposing it, even just for the caller's own
    /// session, would hand a technical coercer who queries the endpoint
    /// directly a definitive signal that this is a duress persona.
    pub revoke_other_sessions: bool,
    /// The identity secret key of the persona this session logged in as,
    /// sealed under `keyring` and bound to `token_hash`. Never plaintext at
    /// rest; see [`SessionInfo::with_identity_sk`].
    identity_sk: SealedSecret,
    /// SHA-256 of this session's bearer token. Part of the AAD binding
    /// `identity_sk` (and every entry in `bucket_keys`) to this exact row —
    /// a sealed blob copied onto a different session's row fails to open.
    token_hash: [u8; 32],
    /// Process-ephemeral wrapping key shared by every session in the store.
    keyring: Arc<SessionKeyring>,
    /// Bucket keys already opened by this session. See [`BucketKeyCache`].
    bucket_keys: Mutex<BucketKeyCache>,
}

// A derived `Debug` would be fine today (every field's own `Debug` already
// redacts), but written out explicitly so a future field addition doesn't
// silently start printing secret material.
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
    pub fn is_expired(&self, now: SystemTime) -> bool {
        now >= self.expires_at
    }

    /// Open this session's identity secret key into a guarded buffer for
    /// the duration of `f`, then drop (and scrub) it. The plaintext key
    /// never outlives this call.
    pub fn with_identity_sk<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R, AuthError> {
        let sk = self.open_identity_sk()?;
        Ok(f(&sk))
    }

    fn open_identity_sk(&self) -> Result<SecretVec, AuthError> {
        self.keyring.open_identity(
            &self.token_hash,
            &self.username,
            self.persona,
            &self.identity_sk,
        )
    }

    /// A cached bucket key for `(bucket, epoch)`, if this session has
    /// already opened it. Decrypts the cached ciphertext on every call —
    /// cheap relative to the AEAD-open-through-ML-KEM path it's saving a
    /// repeat of.
    pub fn cached_bucket_key(
        &self,
        bucket: &str,
        epoch: u32,
    ) -> Option<Result<SecretVec, AuthError>> {
        let sealed = self
            .bucket_keys
            .lock()
            .expect("bucket key cache poisoned")
            .get(bucket, epoch)?;
        Some(
            self.keyring
                .open_bucket_key(&self.token_hash, bucket, epoch, &sealed),
        )
    }

    /// Seal and cache a newly-opened bucket key for `(bucket, epoch)`.
    pub fn cache_bucket_key(&self, bucket: String, epoch: u32, sk: &[u8]) -> Result<(), AuthError> {
        let sealed = self
            .keyring
            .seal_bucket_key(&self.token_hash, &bucket, epoch, sk)?;
        self.bucket_keys
            .lock()
            .expect("bucket key cache poisoned")
            .insert(bucket, epoch, sealed);
        Ok(())
    }
}

/// In-memory map of session-token-hash → session info.
///
/// Cheap to clone (`Arc` inside).
#[derive(Clone)]
pub struct SessionStore {
    inner: Arc<DashMap<[u8; 32], Arc<SessionInfo>>>,
    keyring: Arc<SessionKeyring>,
}

impl SessionStore {
    /// Allocate a fresh store with its own process-ephemeral wrapping key.
    pub fn new() -> Result<Self, AuthError> {
        Ok(Self {
            inner: Arc::new(DashMap::new()),
            keyring: Arc::new(SessionKeyring::new()?),
        })
    }

    /// The store's process-ephemeral wrapping key, shared with the S3
    /// credential store so an S3 secret is sealed under the same key as the
    /// session's identity key.
    pub fn keyring(&self) -> Arc<SessionKeyring> {
        Arc::clone(&self.keyring)
    }

    /// Seal `s`'s identity secret key and insert a fresh session, returning
    /// the wire-form token to hand to the client.
    pub fn insert(&self, s: NewSession) -> Result<SessionToken, AuthError> {
        let token = SessionToken::random();
        let token_hash = token.hash();
        let identity_sk =
            self.keyring
                .seal_identity(&token_hash, &s.username, s.persona, &s.identity_sk)?;
        let info = SessionInfo {
            username: s.username,
            role: s.role,
            created_at: s.created_at,
            expires_at: s.expires_at,
            persona: s.persona,
            revoke_other_sessions: s.revoke_other_sessions,
            identity_sk,
            token_hash,
            keyring: Arc::clone(&self.keyring),
            bucket_keys: Mutex::new(BucketKeyCache::default()),
        };
        self.inner.insert(token_hash, Arc::new(info));
        Ok(token)
    }

    /// Mint a fresh token for the session at `old_hash`, carrying its
    /// identity key (re-sealed under the new token hash) and role/persona
    /// forward, with a new `expires_at`. Revokes the old token. Never
    /// materializes the identity key outside guarded memory.
    pub fn reissue(
        &self,
        old_hash: &[u8; 32],
        expires_at: SystemTime,
    ) -> Result<SessionToken, AuthError> {
        let old = self
            .inner
            .get(old_hash)
            .map(|r| r.value().clone())
            .ok_or(AuthError::TokenInvalid)?;
        let sk = old.open_identity_sk()?;

        let token = SessionToken::random();
        let new_hash = token.hash();
        let identity_sk = self
            .keyring
            .seal_identity(&new_hash, &old.username, old.persona, &sk)?;
        let info = SessionInfo {
            username: old.username.clone(),
            role: old.role,
            created_at: old.created_at,
            expires_at,
            persona: old.persona,
            revoke_other_sessions: old.revoke_other_sessions,
            identity_sk,
            token_hash: new_hash,
            keyring: Arc::clone(&self.keyring),
            bucket_keys: Mutex::new(BucketKeyCache::default()),
        };
        self.inner.insert(new_hash, Arc::new(info));
        self.inner.remove(old_hash);
        Ok(token)
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

    /// Silently convert every OTHER live session belonging to `username` to
    /// `new_persona`'s identity, in place — same token, same expiry, no
    /// re-issued credential, no observable interruption. Used by a
    /// duress-flagged login (`revoke_other_sessions`): rather than revoking
    /// a coerced session (a visible logout is itself a tell that something
    /// happened), any other live session for this account is transparently
    /// downgraded to the duress persona's access on its very next request.
    /// Whoever holds one of those tokens keeps working exactly as before,
    /// just scoped to whatever the duress persona was granted. Returns the
    /// count switched.
    pub fn switch_user_to_persona(
        &self,
        username: &str,
        new_persona: u8,
        new_role: Role,
        new_revoke_other_sessions: bool,
        identity_sk: &SecretVec,
    ) -> usize {
        let victims: Vec<[u8; 32]> = self
            .inner
            .iter()
            .filter_map(|r| {
                let info = r.value();
                (info.username == username && info.persona != new_persona).then_some(*r.key())
            })
            .collect();
        let n = victims.len();
        for k in victims {
            let Some(old) = self.inner.get(&k).map(|r| r.value().clone()) else {
                continue;
            };
            let sealed = match self
                .keyring
                .seal_identity(&k, username, new_persona, identity_sk)
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "failed to reseal identity key while switching a session to the duress persona"
                    );
                    continue;
                }
            };
            let switched = SessionInfo {
                username: old.username.clone(),
                role: new_role,
                created_at: old.created_at,
                expires_at: old.expires_at,
                persona: new_persona,
                revoke_other_sessions: new_revoke_other_sessions,
                identity_sk: sealed,
                token_hash: k,
                keyring: Arc::clone(&self.keyring),
                bucket_keys: Mutex::new(BucketKeyCache::default()),
            };
            self.inner.insert(k, Arc::new(switched));
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

    /// Total number of (possibly expired) entries currently in the store.
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

    fn new_session(username: &str, persona: u8, expires_at: SystemTime, sk: &[u8]) -> NewSession {
        NewSession {
            username: username.to_owned(),
            role: Role::User,
            created_at: SystemTime::now(),
            expires_at,
            persona,
            revoke_other_sessions: false,
            identity_sk: SecretVec::from_slice(sk).unwrap(),
        }
    }

    #[test]
    fn insert_lookup_revoke() {
        let s = SessionStore::new().unwrap();
        let token = s
            .insert(new_session(
                "alice",
                0,
                SystemTime::now() + Duration::from_secs(60),
                &[0u8; 8],
            ))
            .unwrap();
        let hash = token.hash();
        let found = s.get_active(&hash).unwrap();
        assert_eq!(found.username, "alice");
        assert!(s.revoke(&hash));
        assert!(matches!(s.get_active(&hash), Err(AuthError::TokenInvalid)));
    }

    #[test]
    fn expired_session_returns_expired() {
        let s = SessionStore::new().unwrap();
        let token = s
            .insert(new_session(
                "alice",
                0,
                SystemTime::now() - Duration::from_secs(1),
                &[0u8; 8],
            ))
            .unwrap();
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
        let s = SessionStore::new().unwrap();
        let now = SystemTime::now();
        s.insert(new_session(
            "a",
            0,
            now + Duration::from_secs(60),
            &[0u8; 8],
        ))
        .unwrap();
        s.insert(new_session("b", 0, now - Duration::from_secs(1), &[0u8; 8]))
            .unwrap();
        assert_eq!(s.sweep(), 1);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn duress_login_switches_other_sessions_to_the_duress_persona_in_place() {
        let s = SessionStore::new().unwrap();
        let future = SystemTime::now() + Duration::from_secs(60);
        // alice's real-persona session, plus a second live one from another
        // device — both must switch, not die.
        let tok_a = s
            .insert(new_session("alice", 0, future, &[0u8; 8]))
            .unwrap();
        let tok_a2 = s
            .insert(new_session("alice", 0, future, &[0u8; 8]))
            .unwrap();
        // bob must never be touched by alice's duress login.
        let tok_bob = s.insert(new_session("bob", 0, future, &[0u8; 8])).unwrap();

        let duress_sk = SecretVec::from_slice(&[9u8; 8]).unwrap();
        let n = s.switch_user_to_persona("alice", 1, Role::ReadOnly, true, &duress_sk);
        assert_eq!(n, 2);

        // Same tokens still authenticate - nothing was revoked - but now
        // carry the duress persona's identity/role.
        let a = s.get_active(&tok_a.hash()).unwrap();
        let a2 = s.get_active(&tok_a2.hash()).unwrap();
        assert_eq!(a.persona, 1);
        assert_eq!(a2.persona, 1);
        assert_eq!(a.role, Role::ReadOnly);
        assert_eq!(
            a.with_identity_sk(|sk| sk.to_vec()).unwrap(),
            &duress_sk[..]
        );

        let bob = s.get_active(&tok_bob.hash()).unwrap();
        assert_eq!(bob.persona, 0);
    }

    #[test]
    fn switch_user_to_persona_leaves_that_persona_s_own_session_untouched() {
        let s = SessionStore::new().unwrap();
        let future = SystemTime::now() + Duration::from_secs(60);
        let tok_duress = s
            .insert(new_session("alice", 1, future, &[0u8; 8]))
            .unwrap();

        let duress_sk = SecretVec::from_slice(&[9u8; 8]).unwrap();
        // Already persona 1 - the just-inserted session that logged in as
        // the duress persona itself must not be touched by its own login.
        assert_eq!(
            s.switch_user_to_persona("alice", 1, Role::ReadOnly, true, &duress_sk),
            0
        );
        assert_eq!(s.get_active(&tok_duress.hash()).unwrap().persona, 1);
    }

    #[test]
    fn bucket_key_cache_evicts_oldest_past_the_limit() {
        let s = SessionStore::new().unwrap();
        let token = s
            .insert(new_session(
                "alice",
                0,
                SystemTime::now() + Duration::from_secs(60),
                &[0u8; 8],
            ))
            .unwrap();
        let info = s.get_active(&token.hash()).unwrap();
        for epoch in 0..(MAX_SESSION_BUCKET_KEYS as u32 + 1) {
            info.cache_bucket_key("b".to_owned(), epoch, &[epoch as u8])
                .unwrap();
        }
        // The oldest entry (epoch 0) was evicted; the newest survives.
        assert!(info.cached_bucket_key("b", 0).is_none());
        assert!(
            info.cached_bucket_key("b", MAX_SESSION_BUCKET_KEYS as u32)
                .is_some()
        );
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
        let s = SessionStore::new().unwrap();
        let future = SystemTime::now() + Duration::from_secs(60);
        let tok_a = s
            .insert(new_session("alice", 0, future, &[0u8; 8]))
            .unwrap();
        let tok_b = s
            .insert(new_session("alice", 1, future, &[0u8; 8]))
            .unwrap();
        let tok_c = s.insert(new_session("bob", 1, future, &[0u8; 8])).unwrap();

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
