//! In-flight write tracking for the CRAQ data plane.
//!
//! A write is **dirty** on a node from the moment it begins staging a new
//! version (`.tmp`) until that version commits (`.tmp` → `.obj`). [`PendingWrites`]
//! records the dirty `(bucket, key)` addresses so the read path can tell, without
//! touching disk, whether a key has an in-flight write and must therefore
//! version-query the TAIL before serving (the apportioned-read fast/slow path
//! lands in Phase D; this phase only tracks presence and cleans up on commit or
//! abort).
//!
//! Cleanup is RAII: [`PendingWrites::begin`] returns a [`PendingGuard`] that
//! removes the entry on drop, so an aborted or panicking write never leaves a
//! key wedged as permanently dirty.

use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;

/// Record of one in-flight write on this node.
#[derive(Debug, Clone)]
pub struct Pending {
    /// Epoch the write was admitted under (for fencing diagnostics).
    pub epoch: u64,
    /// When the write began staging (for stale-pending diagnostics / GC).
    pub started: Instant,
}

/// Concurrent set of in-flight (dirty) writes keyed by `(bucket, key)`.
#[derive(Clone, Default)]
pub struct PendingWrites {
    map: Arc<DashMap<(String, String), Pending>>,
}

impl PendingWrites {
    /// An empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark `(bucket, key)` as dirty and return a guard that clears it on drop.
    pub fn begin(&self, bucket: &str, key: &str, epoch: u64) -> PendingGuard {
        let k = (bucket.to_owned(), key.to_owned());
        self.map.insert(
            k.clone(),
            Pending {
                epoch,
                started: Instant::now(),
            },
        );
        PendingGuard {
            map: Arc::clone(&self.map),
            key: k,
        }
    }

    /// Whether `(bucket, key)` currently has an in-flight write.
    pub fn is_pending(&self, bucket: &str, key: &str) -> bool {
        self.map.contains_key(&(bucket.to_owned(), key.to_owned()))
    }

    /// Number of in-flight writes.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether there are no in-flight writes.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// RAII handle that keeps a `(bucket, key)` marked dirty until dropped.
pub struct PendingGuard {
    map: Arc<DashMap<(String, String), Pending>>,
    key: (String, String),
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.map.remove(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn begin_marks_pending_and_guard_clears_on_drop() {
        let pw = PendingWrites::new();
        assert!(!pw.is_pending("b", "k"));
        {
            let _g = pw.begin("b", "k", 3);
            assert!(pw.is_pending("b", "k"));
            assert_eq!(pw.len(), 1);
        }
        // Guard dropped => entry removed.
        assert!(!pw.is_pending("b", "k"));
        assert!(pw.is_empty());
    }

    #[test]
    fn distinct_keys_are_independent() {
        let pw = PendingWrites::new();
        let g1 = pw.begin("b", "k1", 1);
        let _g2 = pw.begin("b", "k2", 1);
        assert_eq!(pw.len(), 2);
        drop(g1);
        assert!(!pw.is_pending("b", "k1"));
        assert!(pw.is_pending("b", "k2"));
    }
}
