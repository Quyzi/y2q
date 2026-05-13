//! Runtime bridge between the actix-web tokio runtime and a dedicated pool of
//! `tokio-uring` worker threads.
//!
//! The pool is constructed once at backend startup. Each worker owns its own
//! `tokio_uring::start` runtime and consumes a single [`async_channel`] queue
//! of typed [`super::ops::UringOp`] values. Callers on the actix side submit
//! an op and await a `tokio::sync::oneshot` reply.
//!
//! This module is currently a stub: the types are defined so other modules
//! can reference them, but [`WorkerPool::spawn`] is `todo!()` until the first
//! real op lands.

#![allow(dead_code)] // populated in subsequent steps

use super::storage::UringConfig;

/// Handle to a pool of `tokio-uring` worker threads.
///
/// Cloning the handle is cheap; the underlying workers and channels are
/// shared via `Arc` internally.
#[derive(Clone)]
pub struct WorkerPool {
    // Future fields: Arc<[async_channel::Sender<UringOp>]> sharded by key hash,
    // plus a shutdown signal.
}

impl WorkerPool {
    /// Spawn `config.workers` dedicated uring worker threads.
    pub fn spawn(_config: &UringConfig) -> Self {
        todo!("WorkerPool::spawn")
    }
}
