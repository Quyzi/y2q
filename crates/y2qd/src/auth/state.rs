//! Shared state passed via `actix_web::web::Data<AuthState>`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use y2q_core::AnyStorage;
use y2q_core::crypto::{Argon2Params, Keystore, UserRecord, UserStore, kdf};

use super::keystore::KeystoreSlot;
use super::session::SessionStore;
use crate::config::{Argon2Config, AuthConfig};

/// Bag of long-lived auth state shared across requests.
pub struct AuthState {
    /// The deployment public key + algorithm fingerprint (always available).
    pub public_keystore: Keystore,
    /// User-records database (redb). Reads happen on every login; writes on
    /// add/delete/password-change.
    pub user_store: UserStore,
    /// In-memory session map.
    pub sessions: SessionStore,
    /// Slot for the unwrapped SK after the first successful login.
    pub keystore: KeystoreSlot,
    /// Per-username failed-login counter for lockout enforcement.
    pub login_attempts: Arc<Mutex<LoginAttempts>>,
    /// Snapshot of `[auth]` config at startup.
    pub config: AuthConfig,
    /// Snapshot of `[crypto.argon2]` config used to derive new user-record
    /// KDF params (each new record gets a fresh random salt + these costs).
    pub argon2_config: Argon2Config,
    /// Active storage backend, so a login can install the MEK (and the derived
    /// index key) the moment it unwraps the deployment secret key.
    pub storage: Arc<AnyStorage>,
    /// Fired once, the first time the MEK is installed, to release the deferred
    /// startup index rebuild.
    pub mek_ready: Arc<tokio::sync::Notify>,
    /// Set once the deferred startup rebuild has been triggered, so later
    /// idle-clear / re-login cycles don't fire it again.
    rebuild_triggered: AtomicBool,
    /// A throwaway user record whose Argon2id unwrap is run on the login path
    /// for usernames that don't exist, so a missing user costs the same KDF
    /// work as a wrong password and login can't be used as an
    /// existence-timing oracle. Its params mirror the current config.
    pub dummy_record: UserRecord,
}

impl AuthState {
    pub fn new(
        public_keystore: Keystore,
        user_store: UserStore,
        config: AuthConfig,
        argon2_config: Argon2Config,
        storage: Arc<AnyStorage>,
        mek_ready: Arc<tokio::sync::Notify>,
    ) -> Self {
        let dummy_record = Self::build_dummy_record(&argon2_config);
        Self {
            public_keystore,
            user_store,
            sessions: SessionStore::new(),
            keystore: KeystoreSlot::new(config.keystore_idle_drop_seconds),
            login_attempts: Arc::new(Mutex::new(LoginAttempts::default())),
            config,
            argon2_config,
            storage,
            mek_ready,
            rebuild_triggered: AtomicBool::new(false),
            dummy_record,
        }
    }

    /// Build the throwaway record used to equalize login timing for unknown
    /// usernames. Wraps a fixed dummy SK under a fixed password with current
    /// Argon2 costs and a random salt; only the KDF cost matters, never the
    /// recoverability (its unwrap with an attacker password is expected to
    /// fail). Computed once at startup.
    fn build_dummy_record(argon2_config: &Argon2Config) -> UserRecord {
        let params = Argon2Params::with_random_salt(
            argon2_config.m_cost_kib,
            argon2_config.t_cost,
            argon2_config.p_cost,
        );
        // A 2400-byte placeholder roughly the size of an ML-KEM-768 secret key,
        // so the wrap/unwrap moves a representative amount of data.
        let dummy_sk = [0u8; 2400];
        let wrapped_sk = kdf::wrap_sk(&dummy_sk, b"y2q-dummy-password", &params)
            .expect("wrap dummy SK for login-timing record");
        UserRecord {
            username: String::new(),
            created_at: 0,
            last_login: None,
            kdf: params,
            wrapped_sk,
        }
    }

    /// Derive the MEK from the just-unwrapped deployment secret key and install
    /// it (plus the derived index key) into the storage backend. Re-derives the
    /// same deterministic value on every login, so it also restores the MEK
    /// after an idle clear. The deferred startup index rebuild is released
    /// exactly once, on the first install of the daemon's lifetime.
    pub fn install_mek_from_sk(&self, sk_bytes: &[u8]) {
        let mek = y2q_core::crypto::derive_mek(sk_bytes);
        self.storage.install_mek(mek);
        if !self.rebuild_triggered.swap(true, Ordering::Relaxed) {
            self.mek_ready.notify_one();
        }
    }

    /// Build a fresh `Argon2Params` for a new user record using the
    /// configured costs and a random salt.
    pub fn new_argon2_params(&self) -> Argon2Params {
        Argon2Params::with_random_salt(
            self.argon2_config.m_cost_kib,
            self.argon2_config.t_cost,
            self.argon2_config.p_cost,
        )
    }
}

/// Per-username failed-login counter and lockout-until timestamp.
///
/// Reset to zero on a successful login. Trivial in-memory map; not persisted
/// across restarts (a restart effectively resets all lockouts, which is
/// acceptable since restarts also drop the SK).
#[derive(Default)]
pub struct LoginAttempts {
    inner: HashMap<String, AttemptState>,
}

#[derive(Default)]
struct AttemptState {
    failed_count: u32,
    locked_until: Option<Instant>,
}

impl LoginAttempts {
    /// Returns `Err(until)` if the account is currently locked out.
    pub fn check_lockout(&mut self, username: &str) -> Result<(), Instant> {
        if let Some(s) = self.inner.get_mut(username)
            && let Some(until) = s.locked_until
        {
            if Instant::now() < until {
                return Err(until);
            }
            // Lockout expired; reset.
            s.failed_count = 0;
            s.locked_until = None;
        }
        Ok(())
    }

    /// Record a failed attempt; if the count reaches `max_failed`, set a
    /// lockout for `lockout_duration`.
    pub fn record_failure(&mut self, username: &str, max_failed: u32, lockout_duration: Duration) {
        if max_failed == 0 {
            return;
        }
        let s = self.inner.entry(username.to_owned()).or_default();
        s.failed_count = s.failed_count.saturating_add(1);
        if s.failed_count >= max_failed {
            s.locked_until = Some(Instant::now() + lockout_duration);
        }
    }

    /// Clear failure count for a user (call on successful login).
    pub fn record_success(&mut self, username: &str) {
        if let Some(s) = self.inner.get_mut(username) {
            s.failed_count = 0;
            s.locked_until = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_record_does_real_argon2_work() {
        // Cheap costs keep the test fast; the point is that the dummy record is
        // a genuine wrapped SK so its unwrap exercises Argon2id — the same work
        // the not-found login branch must perform to avoid a timing oracle.
        let cfg = Argon2Config {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let rec = AuthState::build_dummy_record(&cfg);
        // The correct dummy password unwraps; any other fails — proving the
        // record wraps real material and the unwrap runs the full KDF + AEAD.
        assert!(kdf::unwrap_sk(&rec.wrapped_sk, b"y2q-dummy-password", &rec.kdf).is_ok());
        assert!(kdf::unwrap_sk(&rec.wrapped_sk, b"not-the-password", &rec.kdf).is_err());
    }
}
