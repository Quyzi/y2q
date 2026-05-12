//! `PUT /{bucket}/{key}` — write or overwrite a stored object.

use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, web};
use y2q_core::{FilesystemStorage, Object, PutOptions, Storage};

use crate::config::LabelLimits;
use crate::error::{AppError, ErrorBody};
use crate::handlers::labels::extract_labels;

/// Write or overwrite a stored object.
///
/// The raw request body is stored as a new object at `bucket`/`key`.
/// Writes are atomic: readers see either the old object or the new one.
///
/// Any request header matching `X-Y2Q-<label>` (case-insensitive) is captured
/// as a custom label and persisted with the object. The label name is
/// lowercased on storage. The reserved names `X-Y2Q-Created`,
/// `X-Y2Q-Modified`, `X-Y2Q-Checksum-MD5`, and `X-Y2Q-Checksum-SHA256` are
/// emitted by the server on `HEAD` and may not be supplied by clients;
/// supplying any reserved name returns 400. When the same label is sent
/// multiple times, the last value wins.
///
/// Returns 201 Created if the key did not previously exist, or 200 OK if an
/// existing object was replaced.
#[utoipa::path(
    put,
    operation_id = "put_object",
    path = "/{bucket}/{key}",
    params(
        ("bucket" = String, Path, description = "Bucket name (alphanumeric, `-`, `_`)"),
        ("key" = String, Path, description = "Object key; may contain `/` to represent nested paths"),
    ),
    request_body(
        content = Vec<u8>,
        content_type = "application/octet-stream",
        description = "Raw object bytes to store. Custom labels may be attached via `X-Y2Q-<label>` request headers; \
            the reserved names `Created`, `Modified`, `Checksum-MD5`, `Checksum-SHA256` are rejected.",
    ),
    responses(
        (status = 201, description = "Object created"),
        (status = 200, description = "Object replaced (key already existed)"),
        (status = 400, description = "Invalid bucket, key, or label", body = ErrorBody, content_type = "application/json"),
        (status = 409, description = "Object is locked (write in progress)", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    tag = "objects",
)]
pub async fn handle(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    body: web::Bytes,
    storage: web::Data<Arc<FilesystemStorage>>,
    limits: web::Data<LabelLimits>,
) -> Result<HttpResponse, AppError> {
    let (bucket, key) = path.into_inner();
    let labels = extract_labels(&req, limits.get_ref())?;
    let payload = Object::new(body);
    let was_overwrite = storage
        .put(&bucket, &key, payload, PutOptions { labels })
        .await
        .map_err(AppError::from)?;

    if was_overwrite {
        Ok(HttpResponse::Ok().finish())
    } else {
        Ok(HttpResponse::Created().finish())
    }
}
