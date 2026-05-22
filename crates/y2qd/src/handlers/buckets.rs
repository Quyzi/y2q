//! `PUT /{bucket}/` and `DELETE /{bucket}/` — explicit bucket lifecycle.
//!
//! Buckets are otherwise implicit (created on first object PUT). These routes
//! let clients create an empty bucket up front and delete a bucket along with
//! all of its objects.

use std::sync::Arc;

use actix_web::{HttpResponse, web};
use serde::Serialize;
use utoipa::ToSchema;
use y2q_core::{AnyStorage, Listing};

use crate::auth::Authenticated;
use crate::error::{AppError, ErrorBody};

/// Response body for `PUT /{bucket}/`.
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateBucketResponse {
    pub bucket: String,
    /// `true` if the bucket was newly created, `false` if it already existed.
    pub created: bool,
}

/// Response body for `DELETE /{bucket}/`.
#[derive(Debug, Serialize, ToSchema)]
pub struct DeleteBucketResponse {
    pub bucket: String,
    /// Number of objects removed along with the bucket.
    pub objects_removed: u64,
}

/// Create a bucket. Idempotent: returns 200 whether or not it already existed.
#[utoipa::path(
    put,
    operation_id = "create_bucket",
    path = "/{bucket}/",
    params(("bucket" = String, Path, description = "Bucket name (alphanumeric, `-`, `_`)")),
    responses(
        (status = 200, description = "Bucket created or already present", body = CreateBucketResponse, content_type = "application/json"),
        (status = 400, description = "Invalid bucket name", body = ErrorBody, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "buckets",
)]
pub async fn create(
    path: web::Path<String>,
    storage: web::Data<Arc<AnyStorage>>,
    _auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let bucket = path.into_inner();
    let created = storage
        .create_bucket(&bucket)
        .await
        .map_err(AppError::from)?;
    Ok(HttpResponse::Ok().json(CreateBucketResponse { bucket, created }))
}

/// Delete a bucket and all of its objects.
#[utoipa::path(
    delete,
    operation_id = "delete_bucket",
    path = "/{bucket}/",
    params(("bucket" = String, Path, description = "Bucket name (alphanumeric, `-`, `_`)")),
    responses(
        (status = 200, description = "Bucket deleted", body = DeleteBucketResponse, content_type = "application/json"),
        (status = 400, description = "Invalid bucket name", body = ErrorBody, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 404, description = "Bucket not found", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "buckets",
)]
pub async fn remove(
    path: web::Path<String>,
    storage: web::Data<Arc<AnyStorage>>,
    _auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let bucket = path.into_inner();
    let objects_removed = storage
        .delete_bucket(&bucket)
        .await
        .map_err(AppError::from)?;
    Ok(HttpResponse::Ok().json(DeleteBucketResponse {
        bucket,
        objects_removed,
    }))
}
