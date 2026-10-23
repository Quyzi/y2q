//! Body type that declares a size but carries no bytes (HEAD responses).

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use actix_web::body::{BodySize, MessageBody};
use bytes::Bytes;

/// A body that declares a real size but carries no bytes to poll.
///
/// `HttpResponse::finish()` attaches a genuinely-zero-length body, and
/// actix's h1 and h2 encoders derive `Content-Length` from the body's
/// *actual* `BodySize`, overriding any `Content-Length` header the handler
/// inserted manually, so a HEAD response built with `.finish()` always
/// reports `Content-Length: 0` regardless of the object's real size.
/// Attaching this body instead reports the true size. For HEAD, h1 polls
/// the body once and gets `None`; h2 never polls it; neither writes body
/// bytes to the wire.
pub(crate) struct SizedEmptyBody(pub u64);

impl MessageBody for SizedEmptyBody {
    type Error = Infallible;

    fn size(&self) -> BodySize {
        BodySize::Sized(self.0)
    }

    fn poll_next(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, Self::Error>>> {
        Poll::Ready(None)
    }
}
