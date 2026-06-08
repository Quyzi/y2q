//! `DELETE /{bucket}/{key}` — remove a stored object.

use std::sync::Arc;

use actix_web::{HttpResponse, web};
use y2q_core::{AnyStorage, BucketPermission, Storage};

use crate::auth::Authenticated;
use crate::authz::authorize_bucket;
use crate::cluster::{self, ClusterRuntime};
use crate::error::{AppError, ErrorBody};

/// Remove a stored object. Requires a valid Bearer token.
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
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 404, description = "Object not found", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "objects",
)]
pub async fn handle(
    path: web::Path<(String, String)>,
    storage: web::Data<Arc<AnyStorage>>,
    cluster: Option<web::Data<ClusterRuntime>>,
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let (bucket, key) = path.into_inner();
    authorize_bucket(&auth, &storage, &bucket, BucketPermission::Write).await?;

    // Clustered: delete across the chain. 404 if no member held the object.
    if let Some(rt) = cluster.as_ref() {
        if cluster::chain_delete(rt, &bucket, &key).await? {
            return Ok(HttpResponse::NoContent().finish());
        }
        return Err(AppError(y2q_core::Error::NotFound { bucket, key }));
    }

    storage
        .delete(&bucket, &key)
        .await
        .map_err(AppError::from)?;
    Ok(HttpResponse::NoContent().finish())
}
