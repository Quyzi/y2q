//! Typed operation envelopes sent from the actix-web side to the
//! `tokio-uring` worker pool.
//!
//! Each variant carries its arguments plus a `tokio::sync::oneshot::Sender`
//! for the reply. The worker pulls an op off its queue, executes it inside
//! the uring runtime, and signals completion through the oneshot.
//!
//! This module is currently a stub: the enum is empty and will gain variants
//! as the corresponding `UringStorage` methods are filled in.

#![allow(dead_code)] // populated in subsequent steps

/// One unit of work submitted to a uring worker.
pub enum UringOp {
    // Variants land here as ops are implemented:
    //   Put { bucket, key, payload, options, reply }
    //   Get { bucket, key, reply }
    //   GetRange { bucket, key, range, reply }
    //   Delete { bucket, key, reply }
    //   Describe { bucket, key, reply }
}
