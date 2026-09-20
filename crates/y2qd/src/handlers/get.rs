//! `GET /{bucket}/{key}` — retrieve a stored object.
//!
//! Range requests are served from the chunk-addressable v3 envelope: only the
//! ciphertext chunks covering the requested plaintext bytes are read from
//! storage and decrypted (206 Partial Content). Every object is always
//! encrypted; there is no unauthenticated plaintext passthrough.

use std::sync::Arc;

use actix_web::http::header;
use actix_web::{HttpRequest, HttpResponse, web};
use bytes::{Bytes, BytesMut};
use y2q_core::{AnyStorage, BucketPermission, Listing, Storage};

use crate::auth::{AuthState, Authenticated};
use crate::authz::authorize_bucket;
use crate::bucket_keys;
use crate::cipher;
use crate::error::{AppError, ErrorBody};

/// Retrieve a stored object.
///
/// If a `Range: bytes=N-M` header is present, returns 206 Partial Content with
/// a `Content-Range` header: only the covering ciphertext chunks are read and
/// decrypted. A malformed or out-of-bounds range returns 416. Without a
/// `Range` header, returns 200 OK with the full body. Requires a valid Bearer
/// token.
#[utoipa::path(
    get,
    operation_id = "get_object",
    path = "/{bucket}/{key}",
    params(
        ("bucket" = String, Path, description = "Bucket name (alphanumeric, `-`, `_`)"),
        ("key" = String, Path, description = "Object key; may contain `/` to represent nested paths"),
        ("Range" = Option<String>, Header, description = "Byte range to retrieve, e.g. `bytes=0-1023`. Returns 206, or 416 if out of bounds."),
    ),
    responses(
        (status = 200, description = "Full object body", content_type = "application/octet-stream"),
        (status = 206, description = "Partial content (Range request)", content_type = "application/octet-stream"),
        (status = 400, description = "Invalid bucket or key", body = ErrorBody, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 404, description = "Object not found", body = ErrorBody, content_type = "application/json"),
        (status = 409, description = "Object is locked (write in progress)", body = ErrorBody, content_type = "application/json"),
        (status = 416, description = "Requested range not satisfiable (inverted or out of bounds)", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "objects",
)]
pub async fn handle(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    storage: web::Data<Arc<AnyStorage>>,
    _state: web::Data<AuthState>,
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let (bucket, key) = path.into_inner();
    authorize_bucket(&auth, &storage, &bucket, BucketPermission::Read).await?;
    let range_header = req
        .headers()
        .get(header::RANGE)
        .and_then(|h| h.to_str().ok())
        .and_then(parse_byte_range);

    let cfg = storage
        .get_bucket_config(&bucket)
        .await
        .map_err(AppError::from)?;

    // Consult metadata (index lookup, no whole-file read) up front: every path
    // below needs the plaintext size and the bucket key epoch this object was
    // encrypted under before it can resolve the right secret key.
    let md = storage
        .describe(&bucket, &key)
        .await
        .map_err(AppError::from)?;
    let epoch = md.key_epoch.ok_or_else(|| {
        AppError(y2q_core::Error::EnvelopeMalformed {
            bucket: bucket.clone(),
            key: key.clone(),
            reason: "object metadata has no key_epoch".to_owned(),
        })
    })?;
    let bucket_sk =
        bucket_keys::resolve_read_key(&auth.session, &cfg, &bucket, epoch).map_err(AppError)?;

    // No Range header: return the full object, decrypted in place.
    let Some((start, end)) = range_header else {
        let object = storage.get(&bucket, &key).await.map_err(AppError::from)?;
        let stored = object.into_inner();
        // Consume the storage allocation so the AEAD open happens in place;
        // fall back to a copy if the buffer is shared.
        let buf = stored
            .try_into_mut()
            .unwrap_or_else(|b| BytesMut::from(b.as_ref()));
        // v3/v4 envelopes are zero-padded to a Padmé boundary to hide the exact
        // object size, so the decrypted plaintext carries trailing pad bytes.
        // The envelope layer trims to the authenticated size and rejects
        // anything shorter — a truncated envelope with a patched length field
        // must not surface as a 200 with a short body.
        let plaintext = cipher::decrypt_after_get(&bucket_sk, &bucket, &key, buf, md.size)?;
        return Ok(HttpResponse::Ok()
            .content_type("application/octet-stream")
            .body(plaintext));
    };

    let size = md.size;

    // A range must be well-formed and lie entirely within the object.
    if start > end || start >= size || end >= size {
        return Ok(range_not_satisfiable(size));
    }

    let storage_arc = Arc::clone(storage.get_ref());
    match md.envelope_version {
        Some(3) | Some(4) => {
            let mut stream = cipher::plaintext_stream(
                storage_arc,
                bucket.clone(),
                key.clone(),
                md.clone(),
                bucket_sk,
                start,
                end,
            );
            let mut body = BytesMut::new();
            while let Some(chunk) = futures_util::StreamExt::next(&mut stream).await {
                body.extend_from_slice(&chunk?);
            }
            Ok(partial_content(start, end, size, body.freeze()))
        }
        // Any other (unknown, or pre-v3/legacy) envelope version is rejected —
        // there is no unauthenticated plaintext passthrough to fall back to.
        other => Err(AppError(y2q_core::Error::UnsupportedEnvelopeVersion {
            version: other.unwrap_or(0),
        })),
    }
}

/// Build a 206 Partial Content response for `[start, end]` of a `total`-byte object.
fn partial_content(start: u64, end: u64, total: u64, body: Bytes) -> HttpResponse {
    HttpResponse::PartialContent()
        .insert_header((header::CONTENT_TYPE, "application/octet-stream"))
        .insert_header((
            header::CONTENT_RANGE,
            format!("bytes {start}-{end}/{total}"),
        ))
        .body(body)
}

/// Build a 416 Range Not Satisfiable response with `Content-Range: bytes */total`.
fn range_not_satisfiable(total: u64) -> HttpResponse {
    HttpResponse::RangeNotSatisfiable()
        .insert_header((header::CONTENT_RANGE, format!("bytes */{total}")))
        .finish()
}

/// Parse a `bytes=N-M` range string into `(start, end)`.
///
/// Returns `None` for open-ended forms (`bytes=N-`, `bytes=-M`) and unparseable
/// input. Inverted ranges (`start > end`) ARE returned so the handler can reject
/// them with 416 rather than silently falling through to a full response.
fn parse_byte_range(s: &str) -> Option<(u64, u64)> {
    let s = s.trim().strip_prefix("bytes=")?;
    let (start_s, end_s) = s.split_once('-')?;
    let start = start_s.trim().parse::<u64>().ok()?;
    let end = end_s.trim().parse::<u64>().ok()?;
    Some((start, end))
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
        assert_eq!(parse_byte_range("bytes=abc-1"), None);
        assert_eq!(parse_byte_range("bytes=5"), None); // no dash
    }

    #[test]
    fn surfaces_inverted_range() {
        // Inverted ranges are returned so the handler can reject them with 416.
        assert_eq!(parse_byte_range("bytes=99-0"), Some((99, 0)));
    }
}
