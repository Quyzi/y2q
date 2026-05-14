//! `DELETE /{bucket}/{key}` — remove a stored object.

use std::sync::Arc;

use actix_web::{HttpResponse, web};
use y2q_core::{AnyStorage, Storage};

use crate::error::{AppError, ErrorBody};

/// Remove a stored object.
///
/// Returns 204 No Content on success, or 404 if the object does not exist.
#[utoipa::path(
    delete,
    operation_id = "delete_object",
    path = "/{bucket}/{key}",
    params(
        ("bucket" = String, Path, description = "Bucket name (alphanumeric, `-`, `_`)"),
        ("key" = String, Path, description = "Object key; may contain `/` to represent nested paths"),
    ),
    responses(
        (status = 204, description = "Object deleted"),
        (status = 400, description = "Invalid bucket or key", body = ErrorBody, content_type = "application/json"),
        (status = 404, description = "Object not found", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    tag = "objects",
)]
pub async fn handle(
    path: web::Path<(String, String)>,
    storage: web::Data<Arc<AnyStorage>>,
) -> Result<HttpResponse, AppError> {
    let (bucket, key) = path.into_inner();
    storage
        .delete(&bucket, &key)
        .await
        .map_err(AppError::from)?;
    Ok(HttpResponse::NoContent().finish())
}
