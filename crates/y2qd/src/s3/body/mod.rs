//! Streaming body adapters shared by the S3 gateway's read and write paths.
//!
//! [`download`] is the download half: [`LeashedDownload`] wraps a plaintext
//! stream and re-validates the owning session as bytes flow, so a session
//! that expires, is revoked, or is duress-switched mid-download aborts the
//! transfer instead of silently completing under authority that's gone.
//! [`upload`] is the upload half: `aws-chunked` decoding, payload/checksum
//! verification, and the leashed-upload adapter that gives an in-flight
//! `PutObject`/`UploadPart`/`CopyObject` the same mid-transfer session
//! guarantee.

use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures_util::Stream;

use crate::error::AppError;
use crate::s3::error::S3Error;

mod download;
mod upload;

pub use download::{LeashedDownload, SizedEmptyBody};
pub use upload::{leashed_upload, upload_stream};

/// Boxed, type-erased byte stream feeding `cipher::stream_encrypt_for_put`
/// or `cipher::plaintext_stream`'s consumers. Named to avoid repeating (and
/// `clippy::type_complexity`-tripping on) the full `Pin<Box<dyn Stream<...>>>`
/// spelling at every upload/copy/multipart-assembly call site.
pub(crate) type AppByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, AppError>>>>;

/// Shared slot an upload-stream adapter uses to smuggle the precise
/// [`S3Error`] a generic [`AppError`] abort actually represents.
/// `cipher::stream_encrypt_for_put` is generic over `AppError` (shared with
/// the plain REST PUT path) and cannot carry S3-specific error codes
/// itself, so an adapter that rejects a request (bad signature, checksum
/// mismatch, malformed framing) records the real error here before
/// yielding a throwaway `AppError` to unwind the stream. The PUT/CopyObject
/// handlers call [`ErrorSideband::take`] after a stream error and fall back
/// to `S3Error::from(app_error)` only when it's empty (a genuine
/// storage/crypto fault, not an upload-adapter rejection).
#[derive(Clone, Default)]
pub struct ErrorSideband(Arc<Mutex<Option<S3Error>>>);

impl ErrorSideband {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn set(&self, err: S3Error) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(err);
    }

    pub fn take(&self) -> Option<S3Error> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

/// Generic placeholder abort used once the real reason has been recorded in
/// an [`ErrorSideband`]. `y2q_core::Error::Forbidden` carries only a
/// bucket, never a key, so there is nothing address-specific for this
/// function to accept beyond `bucket`.
pub(crate) fn sideband_abort(bucket: &str) -> AppError {
    AppError(y2q_core::Error::Forbidden {
        bucket: bucket.to_owned(),
    })
}
