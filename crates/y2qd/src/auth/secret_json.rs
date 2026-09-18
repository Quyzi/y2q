//! `SecretJson<T>` — like `actix_web::web::Json<T>`, but the request body is
//! aggregated into guarded memory instead of an ordinary heap buffer, and
//! deserialized directly out of it.
//!
//! Used in place of `web::Json` on every endpoint whose body carries a
//! password: `web::Json`'s aggregator (and `serde_json::from_slice` over an
//! ordinary `Bytes`/`Vec<u8>`) would otherwise leave the plaintext password
//! sitting in swappable, dumpable heap for the life of the request.

use std::ops::Deref;
use std::pin::Pin;

use actix_web::{FromRequest, HttpRequest, dev::Payload, http::header};
use futures::StreamExt;
use serde::de::DeserializeOwned;
use y2q_core::secmem::SecretVec;

use super::error::AuthError;

/// Hard cap on a `SecretJson` body. Every current payload (a username, one
/// or two passwords, and a handful of small fields) fits comfortably;
/// anything larger is rejected outright rather than grown into — a growing
/// buffer would leave plaintext copies behind at every reallocation.
const MAX_SECRET_BODY_BYTES: usize = 8 * 1024;

/// JSON body extractor that aggregates into a [`SecretVec`] rather than an
/// ordinary heap buffer.
pub struct SecretJson<T>(pub T);

impl<T> Deref for SecretJson<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: DeserializeOwned + 'static> FromRequest for SecretJson<T> {
    type Error = AuthError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, AuthError>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        // A present `Content-Length` sizes the buffer exactly (clamped to
        // the hard cap); a missing one allocates the cap outright — either
        // way the buffer never grows, so no reallocation ever leaves a
        // stale plaintext copy behind in ordinary heap.
        let cap = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .map(|n| n.min(MAX_SECRET_BODY_BYTES))
            .unwrap_or(MAX_SECRET_BODY_BYTES);
        let mut stream = payload.take();

        Box::pin(async move {
            let mut buf = SecretVec::with_capacity(cap.max(1))
                .map_err(|e| AuthError::Backend(e.to_string()))?;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| AuthError::InvalidBody {
                    reason: e.to_string(),
                })?;
                // A chunk that would exceed the buffer's fixed capacity —
                // whether because `Content-Length` understated the body or
                // was absent — fails immediately rather than buffering
                // further.
                buf.push_slice(&chunk).map_err(|_| AuthError::InvalidBody {
                    reason: "request body too large".to_owned(),
                })?;
            }
            let value: T = serde_json::from_slice(&buf).map_err(|e| AuthError::InvalidBody {
                reason: e.to_string(),
            })?;
            Ok(SecretJson(value))
        })
    }
}
