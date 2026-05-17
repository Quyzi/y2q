//! Shared state passed via `actix_web::web::Data<AuthState>`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use y2q_core::crypto::{Argon2Params, Keystore, UserStore};

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
}

impl AuthState {
    pub fn new(
        public_keystore: Keystore,
        user_store: UserStore,
        config: AuthConfig,
        argon2_config: Argon2Config,
    ) -> Self {
        Self {
            public_keystore,
            user_store,
            sessions: SessionStore::new(),
            keystore: KeystoreSlot::new(config.keystore_idle_drop_seconds),
            login_attempts: Arc::new(Mutex::new(LoginAttempts::default())),
            config,
            argon2_config,
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
