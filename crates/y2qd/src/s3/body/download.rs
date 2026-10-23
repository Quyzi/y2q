//! Download-side body adapter: session-leashed plaintext streaming.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::Stream;

use crate::error::AppError;
use crate::s3::auth::SessionLeash;
use crate::s3::error::S3Error;

/// Wraps a plaintext stream and re-validates the session as bytes flow.
/// Yields [`S3Error`] (not [`AppError`]) so a mid-transfer session death is
/// distinguishable in logs from a storage fault.
pub struct LeashedDownload<S> {
    inner: S,
    leash: SessionLeash,
}

impl<S> LeashedDownload<S> {
    pub fn new(inner: S, leash: SessionLeash) -> Self {
        Self { inner, leash }
    }
}

impl<S> Stream for LeashedDownload<S>
where
    S: Stream<Item = Result<Bytes, AppError>> + Unpin,
{
    type Item = Result<Bytes, S3Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => match self.leash.note(chunk.len() as u64) {
                Ok(()) => Poll::Ready(Some(Ok(chunk))),
                Err(e) => {
                    tracing::warn!(
                        reason = %e,
                        "aborting S3 download: session leash tripped mid-transfer"
                    );
                    Poll::Ready(Some(Err(e)))
                }
            },
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(S3Error::from(e)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
