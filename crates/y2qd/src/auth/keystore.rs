//! Process-wide slot for the unwrapped deployment secret key.
//!
//! Empty at startup. Populated on the first successful login (which decrypts
//! the SK from the user's wrapped record). Cleared when the last session
//! expires, after `keystore_idle_drop_seconds` seconds of grace.

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot_compat::RwLock;
use y2q_core::crypto::DecryptedKeystore;

use super::session::SessionStore;

/// Holds the optional in-memory `Arc<DecryptedKeystore>` plus a timestamp of
/// when the last session was last seen to be present.
pub struct KeystoreSlot {
    inner: RwLock<State>,
    idle_drop: Duration,
}

struct State {
    keystore: Option<Arc<DecryptedKeystore>>,
    /// When sessions hit zero we record the moment so a periodic sweep can
    /// drop the SK after `idle_drop` has elapsed.
    empty_since: Option<Instant>,
}

impl KeystoreSlot {
    /// Empty slot. `idle_drop_seconds` controls how long after the last
    /// session expires the SK is retained in memory; `0` = drop immediately
    /// on the next sweep.
    pub fn new(idle_drop_seconds: u64) -> Self {
        Self {
            inner: RwLock::new(State {
                keystore: None,
                empty_since: None,
            }),
            idle_drop: Duration::from_secs(idle_drop_seconds),
        }
    }

    /// Install (or replace) the decrypted keystore. Called after a
    /// successful login.
    pub fn install(&self, ks: Arc<DecryptedKeystore>) {
        let mut s = self.inner.write();
        s.keystore = Some(ks);
        s.empty_since = None;
    }

    /// Cheap clone of the current `Arc<DecryptedKeystore>`, if any.
    pub fn current(&self) -> Option<Arc<DecryptedKeystore>> {
        self.inner.read().keystore.clone()
    }

    /// Reconcile against the live session count. Should be called from the
    /// session sweeper periodically. If sessions == 0 and the grace period
    /// has elapsed, the SK is dropped.
    ///
    /// Returns `true` exactly on the sweep that drops the SK, so the caller can
    /// zeroize the MEK in the same step.
    pub fn reconcile(&self, sessions: &SessionStore) -> bool {
        let active = sessions.len();
        let mut s = self.inner.write();
        if active == 0 {
            match s.empty_since {
                None => {
                    s.empty_since = Some(Instant::now());
                }
                Some(t) if t.elapsed() >= self.idle_drop => {
                    let dropped = s.keystore.take().is_some();
                    s.empty_since = None;
                    return dropped;
                }
                _ => {}
            }
        } else {
            s.empty_since = None;
        }
        false
    }
}

/// Tiny shim over `std::sync::RwLock` so we don't pull in `parking_lot` just
/// for this — but we still want the simple `read() -> guard` ergonomics.
mod parking_lot_compat {
    use std::sync::{RwLock as StdRwLock, RwLockReadGuard, RwLockWriteGuard};

    pub struct RwLock<T>(StdRwLock<T>);

    impl<T> RwLock<T> {
        pub fn new(t: T) -> Self {
            Self(StdRwLock::new(t))
        }
        pub fn read(&self) -> RwLockReadGuard<'_, T> {
            self.0.read().unwrap()
        }
        pub fn write(&self) -> RwLockWriteGuard<'_, T> {
            self.0.write().unwrap()
        }
    }
}
