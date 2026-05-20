//! In-memory per-object write-lock registry.
//!
//! Replaces the on-disk `.lock` sidecar approach. Since only one `y2qd`
//! process accesses the data directory, disk files add I/O overhead and
//! create orphan-lock risk on `SIGKILL`. With an in-memory registry, all
//! locks vanish on process exit — no orphan recovery needed.
//!
//! Mutual exclusion is provided by [`papaya::HashMap::try_insert`], which is
//! atomic across concurrent callers. Each entry maps
//! `(bucket, key) -> SystemTime` (acquisition time).

use std::sync::Arc;
use std::time::SystemTime;

use papaya::HashMap;

use crate::Error;

/// RAII guard that removes the registry entry on drop, releasing the lock.
pub(crate) struct LockGuard {
    map: Arc<HashMap<(String, String), SystemTime>>,
    key: (String, String),
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        self.map.pin().remove(&self.key);
    }
}

/// In-memory registry of active per-object write locks.
///
/// Cheaply cloneable — the underlying map is reference-counted.
#[derive(Clone)]
pub(crate) struct LockRegistry {
    inner: Arc<HashMap<(String, String), SystemTime>>,
}

impl LockRegistry {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(HashMap::new()),
        }
    }

    /// Acquire an exclusive write lock for `(bucket, key)`.
    ///
    /// Returns [`Error::Locked`] if a lock for this object is already held.
    pub(crate) fn try_acquire(&self, bucket: &str, key: &str) -> Result<LockGuard, Error> {
        let k = (bucket.to_owned(), key.to_owned());
        let now = SystemTime::now();
        match self.inner.pin().try_insert(k.clone(), now) {
            Ok(_) => Ok(LockGuard {
                map: Arc::clone(&self.inner),
                key: k,
            }),
            Err(e) => Err(Error::Locked {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                since: *e.current,
            }),
        }
    }

    /// Return [`Error::Locked`] if `(bucket, key)` is currently locked.
    pub(crate) fn check_not_locked(&self, bucket: &str, key: &str) -> Result<(), Error> {
        let k = (bucket.to_owned(), key.to_owned());
        if let Some(&since) = self.inner.pin().get(&k) {
            return Err(Error::Locked {
                bucket: bucket.to_owned(),
                key: key.to_owned(),
                since,
            });
        }
        Ok(())
    }

    /// List all locks acquired before `older_than` (stuck in-flight PUTs).
    pub(crate) fn list_stale(&self, older_than: SystemTime) -> Vec<StaleLock> {
        let guard = self.inner.pin();
        guard
            .iter()
            .filter(|(_, since)| **since < older_than)
            .map(|(k, since)| StaleLock {
                bucket: k.0.clone(),
                key: k.1.clone(),
                locked_since: *since,
            })
            .collect()
    }

    /// Remove all locks acquired before `older_than`. Returns count removed.
    ///
    /// Forcibly evicts registry entries for stuck in-flight PUTs. The
    /// in-flight operation is not cancelled, but subsequent readers and writers
    /// will no longer see the lock.
    pub(crate) fn clear_stale(&self, older_than: SystemTime) -> u64 {
        let guard = self.inner.pin();
        let stale: Vec<(String, String)> = guard
            .iter()
            .filter(|(_, since)| **since < older_than)
            .map(|(k, _)| k.clone())
            .collect();
        let mut removed = 0u64;
        for k in stale {
            if guard.remove(&k).is_some() {
                removed += 1;
            }
        }
        removed
    }
}

/// One active write lock returned by `GET /api/v1/locks`.
///
/// Unlike the previous disk-based implementation, this always represents a
/// live in-flight PUT (not an orphaned sidecar file). All locks disappear on
/// process restart.
#[derive(Debug, Clone)]
pub struct StaleLock {
    /// The bucket the locked object belongs to.
    pub bucket: String,
    /// The original object key.
    pub key: String,
    /// Wall-clock time the lock was acquired.
    pub locked_since: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn acquire_and_release() {
        let reg = LockRegistry::new();
        let guard = reg.try_acquire("b", "k").expect("first acquire ok");
        assert!(matches!(
            reg.try_acquire("b", "k"),
            Err(crate::Error::Locked { .. })
        ));
        drop(guard);
        assert!(reg.try_acquire("b", "k").is_ok());
    }

    #[test]
    fn check_not_locked_reflects_state() {
        let reg = LockRegistry::new();
        assert!(reg.check_not_locked("b", "k").is_ok());
        let _guard = reg.try_acquire("b", "k").unwrap();
        assert!(matches!(
            reg.check_not_locked("b", "k"),
            Err(crate::Error::Locked { .. })
        ));
    }

    #[test]
    fn different_keys_are_independent() {
        let reg = LockRegistry::new();
        let _g1 = reg.try_acquire("b", "k1").unwrap();
        let _g2 = reg.try_acquire("b", "k2").unwrap();
        let _g3 = reg.try_acquire("b2", "k1").unwrap();
    }

    #[test]
    fn list_and_clear_stale() {
        let reg = LockRegistry::new();
        let now = SystemTime::now();
        let old_time = now - Duration::from_secs(60);
        reg.inner
            .pin()
            .insert(("b".to_owned(), "old".to_owned()), old_time);
        reg.inner
            .pin()
            .insert(("b".to_owned(), "fresh".to_owned()), now);

        let cutoff = now - Duration::from_secs(30);
        let stale = reg.list_stale(cutoff);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].key, "old");

        let removed = reg.clear_stale(cutoff);
        assert_eq!(removed, 1);
        assert!(
            reg.inner
                .pin()
                .get(&("b".to_owned(), "old".to_owned()))
                .is_none()
        );
        assert!(
            reg.inner
                .pin()
                .get(&("b".to_owned(), "fresh".to_owned()))
                .is_some()
        );
    }

    #[test]
    fn cutoff_boundary_is_strict_less_than() {
        let reg = LockRegistry::new();
        let now = SystemTime::now();
        reg.inner
            .pin()
            .insert(("b".to_owned(), "k".to_owned()), now);
        let stale = reg.list_stale(now);
        assert!(stale.is_empty(), "stamp == cutoff must not be reported");
    }
}
