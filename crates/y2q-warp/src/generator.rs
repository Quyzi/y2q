use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tokio::io::AsyncRead;
use tokio::io::ReadBuf;
use tokio::sync::RwLock;

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

/// Shared pool of object keys for the mixed workload.
/// - GET picks a random live key (non-destructive)
/// - DELETE removes a key optimistically (re-inserts on error)
/// - PUT generates new keys and appends on success
#[allow(dead_code)]
pub struct ObjectPool {
    live_keys: RwLock<Vec<String>>,
    next_seq: AtomicU64,
    run_id: String,
    cap: usize,
}

impl ObjectPool {
    pub fn new(run_id: String, initial_keys: Vec<String>, objects: u32) -> Arc<Self> {
        let cap = ((objects as usize) * 2).max(10_000);
        Arc::new(Self {
            live_keys: RwLock::new(initial_keys),
            next_seq: AtomicU64::new(objects as u64),
            run_id,
            cap,
        })
    }

    pub async fn pick_for_get(&self) -> Option<String> {
        let keys = self.live_keys.read().await;
        if keys.is_empty() {
            return None;
        }
        let idx = rand::thread_rng().gen_range(0..keys.len());
        Some(keys[idx].clone())
    }

    pub async fn take_for_delete(&self) -> Option<String> {
        let mut keys = self.live_keys.write().await;
        if keys.is_empty() {
            return None;
        }
        let idx = rand::thread_rng().gen_range(0..keys.len());
        Some(keys.swap_remove(idx))
    }

    pub async fn return_key(&self, key: String) {
        let mut keys = self.live_keys.write().await;
        if keys.len() < self.cap {
            keys.push(key);
        }
    }

    #[allow(dead_code)]
    pub fn next_put_key(&self) -> String {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        format!("warp/{}/{seq:08}", self.run_id)
    }

    pub async fn on_put_success(&self, key: String) {
        let mut keys = self.live_keys.write().await;
        if keys.len() < self.cap {
            keys.push(key);
        }
    }

    #[allow(dead_code)]
    pub async fn len(&self) -> usize {
        self.live_keys.read().await.len()
    }
}
