//! `GET /{bucket}/{key}` — retrieve a stored object.
//!
//! Supports partial content via the `Range` header. Only the `bytes=N-M` form
//! (two explicit offsets) is implemented; open-ended ranges fall back to a
//! full 200 response.

use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, web};
use actix_web::http::header;
use y2q_core::{FilesystemStorage, Storage};

use crate::error::{AppError, ErrorBody};

/// Retrieve a stored object.
///
/// If a `Range: bytes=N-M` header is present, returns 206 Partial Content
/// with a `Content-Range` header and only the requested byte slice.
/// Otherwise returns 200 OK with the full object body.
#[utoipa::path(
    get,
    operation_id = "get_object",
    path = "/{bucket}/{key}",
    params(
        ("bucket" = String, Path, description = "Bucket name (alphanumeric, `-`, `_`)"),
        ("key" = String, Path, description = "Object key; may contain `/` to represent nested paths"),
        ("Range" = Option<String>, Header, description = "Byte range to retrieve, e.g. `bytes=0-1023`. Returns 206 when present."),
    ),
    responses(
        (status = 200, description = "Full object body", content_type = "application/octet-stream"),
        (status = 206, description = "Partial content (Range request)", content_type = "application/octet-stream"),
        (status = 400, description = "Invalid bucket or key", body = ErrorBody, content_type = "application/json"),
        (status = 404, description = "Object not found", body = ErrorBody, content_type = "application/json"),
        (status = 409, description = "Object is locked (write in progress)", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    tag = "objects",
)]
pub async fn handle(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    storage: web::Data<Arc<FilesystemStorage>>,
) -> Result<HttpResponse, AppError> {
    let (bucket, key) = path.into_inner();

    if let Some(range_header) = req.headers().get(header::RANGE) {
        if let Ok(range_str) = range_header.to_str() {
            if let Some((start, end)) = parse_byte_range(range_str) {
                let data = storage
                    .get_range(&bucket, &key, (start..=end).into())
                    .await
                    .map_err(AppError::from)?;
                // describe() is called after get_range() to include the total
                // size in the Content-Range header, as required by RFC 7233.
                let meta = storage
                    .describe(&bucket, &key)
                    .await
                    .map_err(AppError::from)?;

                return Ok(HttpResponse::PartialContent()
                    .insert_header((header::CONTENT_TYPE, "application/octet-stream"))
                    .insert_header((
                        header::CONTENT_RANGE,
                        format!("bytes {}-{}/{}", start, end, meta.size),
                    ))
                    .body(data));
            }
        }
    }

    let object = storage.get(&bucket, &key).await.map_err(AppError::from)?;
    Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .body((*object).clone()))
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
    if start <= end { Some((start, end)) } else { None }
}
