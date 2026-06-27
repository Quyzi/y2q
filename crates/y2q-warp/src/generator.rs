use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use tokio::io::AsyncRead;
use tokio::io::ReadBuf;
use tokio::sync::Mutex;

/// AsyncRead that yields synthetic pseudo-random bytes up to `remain` total.
/// Uses a fixed 64 KiB buffer cycled indefinitely — O(1) memory.
pub struct BoundedRepeatReader {
    buf: Box<[u8; 65536]>,
    pos: usize,
    remain: u64,
}

impl BoundedRepeatReader {
    pub fn new(size: u64) -> Self {
        let mut buf = Box::new([0u8; 65536]);
        StdRng::seed_from_u64(0).fill(&mut buf[..]);
        Self {
            buf,
            pos: 0,
            remain: size,
        }
    }
}

impl AsyncRead for BoundedRepeatReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.remain == 0 {
            return Poll::Ready(Ok(()));
        }
        let avail = dst.remaining();
        let from_buf = self.buf.len() - self.pos;
        let can_read = avail.min(from_buf).min(self.remain as usize);
        dst.put_slice(&self.buf[self.pos..self.pos + can_read]);
        self.pos = (self.pos + can_read) % self.buf.len();
        self.remain -= can_read as u64;
        Poll::Ready(Ok(()))
    }
}

struct PoolInner {
    /// Keys currently considered live (server-side object exists).
    keys: Vec<String>,
    /// In-flight read reservations per key (GET/STAT). A key with a non-zero
    /// count is leased to a reader and must not be deleted out from under it.
    readers: HashMap<String, u32>,
}

/// Shared pool of object keys for the mixed workload.
/// - GET/STAT reserve a random live key (read lease, see [`Self::pick_for_get`])
/// - DELETE removes a key, but never one with an active read lease
/// - PUT generates new keys and appends on success
///
/// Read leases close the self-inflicted race where a DELETE could remove and
/// delete a key that a concurrent GET/STAT had already selected, producing a
/// spurious 404. Every successful [`Self::pick_for_get`] must be paired with a
/// [`Self::release_read`] once the read completes.
#[allow(dead_code)]
pub struct ObjectPool {
    inner: Mutex<PoolInner>,
    next_seq: AtomicU64,
    run_id: String,
    cap: usize,
}

impl ObjectPool {
    pub fn new(run_id: String, initial_keys: Vec<String>, objects: u32) -> Arc<Self> {
        let cap = ((objects as usize) * 2).max(10_000);
        Arc::new(Self {
            inner: Mutex::new(PoolInner {
                keys: initial_keys,
                readers: HashMap::new(),
            }),
            next_seq: AtomicU64::new(objects as u64),
            run_id,
            cap,
        })
    }

    /// Reserve a random live key for reading. Increments its read-lease count so
    /// a concurrent DELETE will skip it. Caller must [`Self::release_read`] when
    /// done. Returns `None` if the pool is empty.
    pub async fn pick_for_get(&self) -> Option<String> {
        let mut inner = self.inner.lock().await;
        if inner.keys.is_empty() {
            return None;
        }
        let idx = rand::rng().random_range(0..inner.keys.len());
        let key = inner.keys[idx].clone();
        *inner.readers.entry(key.clone()).or_insert(0) += 1;
        Some(key)
    }

    /// Release a read lease taken by [`Self::pick_for_get`].
    pub async fn release_read(&self, key: &str) {
        let mut inner = self.inner.lock().await;
        if let Some(count) = inner.readers.get_mut(key) {
            *count -= 1;
            if *count == 0 {
                inner.readers.remove(key);
            }
        }
    }

    /// Take a random live key that has no active read lease, removing it from the
    /// pool. Returns `None` if the pool is empty or every key is currently leased
    /// to a reader.
    pub async fn take_for_delete(&self) -> Option<String> {
        let mut inner = self.inner.lock().await;
        let len = inner.keys.len();
        if len == 0 {
            return None;
        }
        let start = rand::rng().random_range(0..len);
        // Probe from a random offset for the first unleased key so deletes still
        // make progress under read contention instead of bailing out.
        for offset in 0..len {
            let idx = (start + offset) % inner.keys.len();
            if !inner.readers.contains_key(&inner.keys[idx]) {
                return Some(inner.keys.swap_remove(idx));
            }
        }
        None
    }

    pub async fn return_key(&self, key: String) {
        let mut inner = self.inner.lock().await;
        if inner.keys.len() < self.cap {
            inner.keys.push(key);
        }
    }

    #[allow(dead_code)]
    pub fn next_put_key(&self) -> String {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        format!("warp/{}/{seq:08}", self.run_id)
    }

    pub async fn on_put_success(&self, key: String) {
        let mut inner = self.inner.lock().await;
        if inner.keys.len() < self.cap {
            inner.keys.push(key);
        }
    }

    #[allow(dead_code)]
    pub async fn len(&self) -> usize {
        self.inner.lock().await.keys.len()
    }
}
