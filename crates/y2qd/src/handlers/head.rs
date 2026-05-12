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
/// | `X-Y2Q-Checksum-MD5` | First 8 bytes of the MD5 digest as 16 lowercase hex chars |
/// | `X-Y2Q-Checksum-SHA256` | First 8 bytes of the SHA-256 digest as 16 lowercase hex chars |
///
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
            `X-Y2Q-Checksum-MD5` (16 hex chars), `X-Y2Q-Checksum-SHA256` (16 hex chars)."),
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
    let meta = storage.describe(&bucket, &key).await.map_err(AppError::from)?;

    Ok(HttpResponse::Ok()
        .insert_header(("Content-Length", meta.size.to_string()))
        .insert_header(("Content-Type", "application/octet-stream"))
        .insert_header(("X-Y2Q-Created", meta.created.to_string()))
        .insert_header(("X-Y2Q-Modified", meta.modified.to_string()))
        .insert_header(("X-Y2Q-Checksum-MD5", format!("{:016x}", meta.checksum_md5)))
        .insert_header(("X-Y2Q-Checksum-SHA256", format!("{:016x}", meta.checksum_sha256)))
        .finish())
}
