//! Runtime bridge between the actix-web tokio runtime and a dedicated pool of
//! `tokio-uring` worker threads.
//!
//! The pool is constructed once at backend startup. Each worker owns its own
//! `tokio_uring::start` runtime on a dedicated OS thread and consumes one
//! [`async_channel`] of typed [`UringOp`] values. Callers on the actix side
//! pick a worker via [`WorkerPool::dispatch_for_key`], `send().await` an op,
//! and `await` a [`tokio::sync::oneshot`] reply.
//!
//! Workers are picked by a stable hash of `(bucket, key)` so concurrent ops
//! on the same object serialize on the same worker. This keeps per-object
//! ordering coherent without any cross-worker locking.
//!
//! Shutdown is implicit: when the pool drops, every channel sender drops,
//! every worker's `recv()` returns `Err`, the future completes, and the
//! thread exits. Drop joins the threads so callers don't leak workers.

use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    path::Path,
    sync::Mutex,
    thread::JoinHandle,
};

use async_channel::{Receiver, Sender};

use super::{ops::UringOp, storage::UringConfig};

/// A pool of dedicated `tokio-uring` worker threads.
pub(super) struct WorkerPool {
    /// One sender per worker. Each is the *unique* sender for its channel
    /// (we never clone these), so dropping the `Vec` closes every channel.
    senders: Vec<Sender<UringOp>>,
    handles: Mutex<Vec<JoinHandle<()>>>,
}

impl WorkerPool {
    /// Spawn `config.workers` (≥1) dedicated uring worker threads.
    ///
    /// Each thread runs an io_uring probe before entering the work loop. If
    /// io_uring is unavailable (kernel too old, seccomp blocking the syscall,
    /// or missing permissions) this returns `Err` immediately rather than
    /// failing silently on the first dispatched op.
    pub fn spawn(config: &UringConfig) -> Result<Self, String> {
        let n = config.workers.max(1);
        let mut senders = Vec::with_capacity(n);
        let mut handles = Vec::with_capacity(n);
        for i in 0..n {
            let (tx, rx) = async_channel::unbounded::<UringOp>();
            let (probe_tx, probe_rx) = std::sync::mpsc::channel::<Result<(), String>>();
            senders.push(tx);
            let handle = std::thread::Builder::new()
                .name(format!("y2q-uring-worker-{i}"))
                .spawn(move || {
                    let ok = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        tokio_uring::start(async {})
                    })) {
                        Ok(()) => {
                            let _ = probe_tx.send(Ok(()));
                            true
                        }
                        Err(payload) => {
                            let msg = payload
                                .downcast_ref::<String>()
                                .cloned()
                                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                                .unwrap_or_else(|| "io_uring runtime panic".to_owned());
                            let _ = probe_tx.send(Err(msg));
                            false
                        }
                    };
                    if ok {
                        worker_main(rx);
                    }
                })
                .expect("spawn uring worker thread");
            handles.push(handle);

            match probe_rx.recv() {
                Ok(Ok(())) => {}
                Ok(Err(msg)) => {
                    return Err(format!("worker {i}: io_uring setup failed: {msg}"));
                }
                Err(_) => {
                    return Err(format!("worker {i}: thread died during io_uring probe"));
                }
            }
        }
        Ok(Self {
            senders,
            handles: Mutex::new(handles),
        })
    }

    /// Pick the worker that owns `(bucket, key)`.
    ///
    /// The hash is process-local and non-cryptographic; ordering is stable
    /// within a single process run, which is all we need for per-object
    /// serialization.
    pub fn dispatch_for_key(&self, bucket: &str, key: &str) -> &Sender<UringOp> {
        let mut h = DefaultHasher::new();
        bucket.hash(&mut h);
        key.hash(&mut h);
        let idx = (h.finish() as usize) % self.senders.len();
        &self.senders[idx]
    }

    /// Pick a worker by hashing `path`. Used by the rebuild walker, which
    /// has paths but not yet the corresponding `(bucket, key)` pair.
    pub fn dispatch_for_path(&self, path: &Path) -> &Sender<UringOp> {
        let mut h = DefaultHasher::new();
        path.hash(&mut h);
        let idx = (h.finish() as usize) % self.senders.len();
        &self.senders[idx]
    }
}

impl Drop for WorkerPool {
    fn drop(&mut self) {
        // Closing each sender wakes the worker's `recv().await` with an Err,
        // which causes the worker future to return and tokio_uring::start to
        // exit. Then we join to make sure the OS threads have actually gone.
        for s in self.senders.iter() {
            s.close();
        }
        if let Ok(mut h) = self.handles.lock() {
            for handle in std::mem::take(&mut *h) {
                let _ = handle.join();
            }
        }
    }
}

/// Worker thread entry point.
///
/// Blocks the OS thread via `recv_blocking` (futex) when idle, so the thread
/// parks at zero CPU cost rather than spinning inside `tokio_uring::start`.
/// The `tokio-uring` runtime is entered only when there is real work to do;
/// one `io_uring` ring is created and torn down per op. The loop exits when
/// the matching `Sender` is dropped or closed.
///
/// Background: `tokio_uring::start` parks by calling `io_uring_enter` with
/// `IORING_ENTER_GETEVENTS`. When the submission ring is empty that syscall
/// returns immediately, producing a tight spin loop even on an idle worker.
/// Keeping the blocking wait outside the uring runtime avoids this entirely.
fn worker_main(rx: Receiver<UringOp>) {
    while let Ok(op) = rx.recv_blocking() {
        tokio_uring::start(super::ops::handle(op));
    }
}
