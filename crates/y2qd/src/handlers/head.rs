//! `HEAD /{bucket}/{key}` — retrieve object metadata without a body.

use std::sync::Arc;

use actix_web::{HttpResponse, web};
use y2q_core::{FilesystemStorage, Storage};

use crate::error::{AppError, ErrorBody};

/// Retrieve object metadata without transferring the body.
///
/// Returns 200 OK with no body. Object metadata is exposed as response headers:
///
/// | Header | Value |
/// |--------|-------|
/// | `Content-Length` | Object size in bytes |
/// | `Content-Type` | `application/octet-stream` |
/// | `X-Y2Q-Created` | Nanoseconds since Unix epoch when first written |
/// | `X-Y2Q-Modified` | Nanoseconds since Unix epoch when last overwritten |
/// | `X-Y2Q-Checksum-MD5` | Full 16-byte MD5 digest as standard base64 (24 chars) |
/// | `X-Y2Q-Checksum-SHA256` | Full 32-byte SHA-256 digest as standard base64 (44 chars) |
/// | `X-Y2Q-<label>` | Any custom label attached to the object on PUT |
///
/// Custom label names are echoed back lowercased.
/// Returns 404 if the object does not exist.
#[utoipa::path(
    head,
    operation_id = "head_object",
    path = "/{bucket}/{key}",
    params(
        ("bucket" = String, Path, description = "Bucket name (alphanumeric, `-`, `_`)"),
        ("key" = String, Path, description = "Object key; may contain `/` to represent nested paths"),
    ),
    responses(
        (status = 200, description = "Object exists. Metadata is returned in response headers: \
            `X-Y2Q-Created` (ns since epoch), `X-Y2Q-Modified` (ns since epoch), \
            `X-Y2Q-Checksum-MD5` (base64, 24 chars), `X-Y2Q-Checksum-SHA256` (base64, 44 chars), \
            plus any `X-Y2Q-<label>` headers attached on PUT."),
        (status = 400, description = "Invalid bucket or key", body = ErrorBody, content_type = "application/json"),
        (status = 404, description = "Object not found", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    tag = "objects",
)]
pub async fn handle(
    path: web::Path<(String, String)>,
    storage: web::Data<Arc<FilesystemStorage>>,
) -> Result<HttpResponse, AppError> {
    let (bucket, key) = path.into_inner();
    let meta = storage
        .describe(&bucket, &key)
        .await
        .map_err(AppError::from)?;

    let mut builder = HttpResponse::Ok();
    builder
        .insert_header(("Content-Length", meta.size.to_string()))
        .insert_header(("Content-Type", "application/octet-stream"))
        .insert_header(("X-Y2Q-Created", meta.created.to_string()))
        .insert_header(("X-Y2Q-Modified", meta.modified.to_string()))
        .insert_header(("X-Y2Q-Checksum-MD5", meta.checksum_md5.clone()))
        .insert_header(("X-Y2Q-Checksum-SHA256", meta.checksum_sha256.clone()));

    for (name, value) in &meta.labels {
        builder.insert_header((format!("X-Y2Q-{}", name), value.clone()));
    }

    Ok(builder.finish())
}
