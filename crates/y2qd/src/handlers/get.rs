//! `GET /{bucket}/{key}` — retrieve a stored object.
//!
//! Range requests on encrypted objects return **501 Not Implemented**.
//! Encryption uses whole-object AEAD, so a partial read would require
//! decrypting and discarding the rest, which the project deliberately
//! doesn't support — clients should fetch the full object instead.

use std::sync::Arc;

use actix_web::http::header;
use actix_web::{HttpRequest, HttpResponse, web};
use bytes::BytesMut;
use y2q_core::{AnyStorage, Storage};

use crate::auth::Authenticated;
use crate::cipher;
use crate::error::{AppError, ErrorBody};

/// Retrieve a stored object.
///
/// If a `Range: bytes=N-M` header is present and the object is plaintext
/// (legacy, pre-encryption), returns 206 Partial Content with a
/// `Content-Range` header. For encrypted objects (the default), `Range`
/// returns 501. Otherwise returns 200 OK with the full plaintext body.
/// Requires a valid Bearer token.
#[utoipa::path(
    get,
    operation_id = "get_object",
    path = "/{bucket}/{key}",
    params(
        ("bucket" = String, Path, description = "Bucket name (alphanumeric, `-`, `_`)"),
        ("key" = String, Path, description = "Object key; may contain `/` to represent nested paths"),
        ("Range" = Option<String>, Header, description = "Byte range to retrieve, e.g. `bytes=0-1023`. Returns 206 for plaintext objects, 501 for encrypted objects."),
    ),
    responses(
        (status = 200, description = "Full object body", content_type = "application/octet-stream"),
        (status = 206, description = "Partial content (Range request, plaintext objects only)", content_type = "application/octet-stream"),
        (status = 400, description = "Invalid bucket or key", body = ErrorBody, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 404, description = "Object not found", body = ErrorBody, content_type = "application/json"),
        (status = 409, description = "Object is locked (write in progress)", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
        (status = 501, description = "Range read attempted on an encrypted object", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "objects",
)]
pub async fn handle(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    storage: web::Data<Arc<AnyStorage>>,
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let (bucket, key) = path.into_inner();
    let range_header = req
        .headers()
        .get(header::RANGE)
        .and_then(|h| h.to_str().ok())
        .and_then(parse_byte_range);

    // Always fetch the full stored bytes — even for a Range request we need
    // to determine if the object is encrypted (in which case Range fails).
    let object = storage.get(&bucket, &key).await.map_err(AppError::from)?;
    let stored = object.into_inner();

    if cipher::is_encrypted_envelope(&stored) {
        if range_header.is_some() {
            return Err(AppError(y2q_core::Error::RangeReadOnEncrypted));
        }
        // Try to consume the storage allocation directly so the AEAD open
        // happens in place; fall back to a copy if the buffer is shared.
        let buf = stored
            .try_into_mut()
            .unwrap_or_else(|b| BytesMut::from(b.as_ref()));
        let plaintext = cipher::decrypt_after_get(&auth.keystore, &bucket, &key, buf)?;
        return Ok(HttpResponse::Ok()
            .content_type("application/octet-stream")
            .body(plaintext));
    }

    // Plaintext object (legacy, pre-encryption). Honour Range as before.
    if let Some((start, end)) = range_header {
        let total = stored.len() as u64;
        let start_u = start as usize;
        let end_u = (end as usize).min(stored.len().saturating_sub(1));
        let body = if start_u >= stored.len() {
            actix_web::web::Bytes::new()
        } else {
            stored.slice(start_u..=end_u)
        };
        return Ok(HttpResponse::PartialContent()
            .insert_header((header::CONTENT_TYPE, "application/octet-stream"))
            .insert_header((
                header::CONTENT_RANGE,
                format!("bytes {}-{}/{}", start, end_u, total),
            ))
            .body(body));
    }

    Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .body(stored))
}

/// Parse a `bytes=N-M` range string into `(start, end)`.
///
/// Returns `None` for open-ended forms (`bytes=N-`, `bytes=-M`) and for
/// inverted ranges where `start > end`.
fn parse_byte_range(s: &str) -> Option<(u64, u64)> {
    let s = s.trim().strip_prefix("bytes=")?;
    let (start_s, end_s) = s.split_once('-')?;
    let start = start_s.trim().parse::<u64>().ok()?;
    let end = end_s.trim().parse::<u64>().ok()?;
    if start <= end {
        Some((start, end))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::parse_byte_range;

    #[test]
    fn parses_valid_ranges() {
        assert_eq!(parse_byte_range("bytes=0-99"), Some((0, 99)));
        assert_eq!(parse_byte_range("  bytes=10-10 "), Some((10, 10)));
    }

    #[test]
    fn rejects_bad_ranges() {
        assert_eq!(parse_byte_range("0-99"), None); // no bytes= prefix
        assert_eq!(parse_byte_range("bytes=99-0"), None); // start > end
        assert_eq!(parse_byte_range("bytes=abc-1"), None);
        assert_eq!(parse_byte_range("bytes=5"), None); // no dash
    }
}
