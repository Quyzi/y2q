//! Typed operation envelopes sent from the actix-web side to the
//! `tokio-uring` worker pool, plus their worker-side handlers.
//!
//! Each variant carries the inputs needed to execute the op on the worker,
//! plus a `tokio::sync::oneshot::Sender` for the reply. The worker pulls an
//! op off its queue, runs the matching handler inside the uring runtime,
//! then signals completion through the oneshot.
//!
//! Variants are added one per `UringStorage` method as they're implemented.
//! Currently: [`UringOp::Describe`] only.

use std::path::PathBuf;

use tokio::sync::oneshot;

use crate::{Error, Metadata};

/// One unit of work submitted to a uring worker.
pub(super) enum UringOp {
    /// Read and decode the metadata sidecar for `(bucket, key)`.
    ///
    /// `path` is the absolute on-disk location pre-computed by the caller;
    /// the worker does not re-resolve it. `bucket` and `key` are passed
    /// through so error messages name the object instead of its UUID path.
    Describe {
        path: PathBuf,
        bucket: String,
        key: String,
        reply: oneshot::Sender<Result<Metadata, Error>>,
    },
}

/// Dispatch one op to its handler. Called from the worker's recv loop.
pub(super) async fn handle(op: UringOp) {
    match op {
        UringOp::Describe {
            path,
            bucket,
            key,
            reply,
        } => {
            let result = do_describe(path, bucket, key).await;
            // The receiver may have dropped (caller cancelled). That's fine —
            // we still want the I/O to have completed cleanly, which it did
            // by the time we get here.
            let _ = reply.send(result);
        }
    }
}

/// Read the metadata sidecar at `path` using uring's `openat` + `read_exact_at`.
///
/// Returns [`Error::NotFound`] if the file is absent, [`Error::InternalError`]
/// for any other I/O or decode failure.
async fn do_describe(path: PathBuf, bucket: String, key: String) -> Result<Metadata, Error> {
    use tokio_uring::fs::File;

    let file = match File::open(&path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::NotFound { bucket, key });
        }
        Err(e) => {
            return Err(Error::InternalError {
                bucket,
                key,
                operation: "describe".to_owned(),
                message: format!("open: {e}"),
            });
        }
    };

    let stat = match file.statx().await {
        Ok(s) => s,
        Err(e) => {
            let _ = file.close().await;
            return Err(Error::InternalError {
                bucket,
                key,
                operation: "describe".to_owned(),
                message: format!("statx: {e}"),
            });
        }
    };
    let size = stat.stx_size as usize;

    let buf = vec![0u8; size];
    let (read_res, buf) = file.read_exact_at(buf, 0).await;
    if let Err(e) = read_res {
        let _ = file.close().await;
        return Err(Error::InternalError {
            bucket,
            key,
            operation: "describe".to_owned(),
            message: format!("read: {e}"),
        });
    }
    let _ = file.close().await;

    serde_json::from_slice(&buf).map_err(|e| Error::InternalError {
        bucket,
        key,
        operation: "describe".to_owned(),
        message: format!("decode: {e}"),
    })
}
