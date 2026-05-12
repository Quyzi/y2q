//! `PUT /{bucket}/{key}` — write or overwrite a stored object.

use std::sync::Arc;

use actix_web::{HttpResponse, web};
use y2q_core::{FilesystemStorage, Object, Storage};

use crate::error::{AppError, ErrorBody};

/// Write or overwrite a stored object.
///
/// The raw request body is stored as a new object at `bucket`/`key`.
/// Writes are atomic: readers see either the old object or the new one.
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
        description = "Raw object bytes to store",
    ),
    responses(
        (status = 201, description = "Object created"),
        (status = 200, description = "Object replaced (key already existed)"),
        (status = 400, description = "Invalid bucket or key", body = ErrorBody, content_type = "application/json"),
        (status = 409, description = "Object is locked (write in progress)", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    tag = "objects",
)]
pub async fn handle(
    path: web::Path<(String, String)>,
    body: web::Bytes,
    storage: web::Data<Arc<FilesystemStorage>>,
) -> Result<HttpResponse, AppError> {
    let (bucket, key) = path.into_inner();
    let payload = Object::new(body.into());
    let was_overwrite = storage
        .put(&bucket, &key, payload)
        .await
        .map_err(AppError::from)?;

    if was_overwrite {
        Ok(HttpResponse::Ok().finish())
    } else {
        Ok(HttpResponse::Created().finish())
    }
}
