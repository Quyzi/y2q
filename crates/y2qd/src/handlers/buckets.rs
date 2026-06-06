//! `PUT /{bucket}/` and `DELETE /{bucket}/` — explicit bucket lifecycle.
//!
//! Buckets are otherwise implicit (created on first object PUT). These routes
//! let clients create an empty bucket up front and delete a bucket along with
//! all of its objects.

use std::sync::Arc;

use actix_web::{HttpResponse, web};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use y2q_core::{AnyStorage, BucketConfig, BucketPermission, Listing};

use crate::auth::Authenticated;
use crate::authz::{Decision, authorize_bucket, claim_ownership};
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
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let bucket = path.into_inner();
    let decision = authorize_bucket(&auth, &storage, &bucket, BucketPermission::Write).await?;
    let created = storage
        .create_bucket(&bucket)
        .await
        .map_err(AppError::from)?;
    // Explicitly creating a brand-new bucket makes the caller its owner.
    if matches!(decision, Decision::ClaimOwnership) {
        claim_ownership(&storage, &bucket, &auth.username).await?;
    }
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
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let bucket = path.into_inner();
    authorize_bucket(&auth, &storage, &bucket, BucketPermission::Admin).await?;
    let objects_removed = storage
        .delete_bucket(&bucket)
        .await
        .map_err(AppError::from)?;
    Ok(HttpResponse::Ok().json(DeleteBucketResponse {
        bucket,
        objects_removed,
    }))
}

/// Bucket configuration body for `GET`/`PUT /api/v1/buckets/{bucket}/config`.
/// Mirrors [`BucketConfig`] with a utoipa schema; backs the `quota`, `encrypt`,
/// and `cors` CLI commands via read-modify-write.
#[derive(Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct BucketConfigBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_sse: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cors_allow_origin: Option<String>,
}

impl From<BucketConfig> for BucketConfigBody {
    fn from(c: BucketConfig) -> Self {
        Self {
            quota_bytes: c.quota_bytes,
            default_sse: c.default_sse,
            cors_allow_origin: c.cors_allow_origin,
        }
    }
}

// Note: there is deliberately no `From<BucketConfigBody> for BucketConfig`. The
// config endpoint must read-modify-write so it preserves `owner`/`acl`; a blanket
// conversion would zero those fields and silently drop ownership. `set_config`
// merges the body into the existing config instead.

/// Read a bucket's configuration.
#[utoipa::path(
    get,
    operation_id = "get_bucket_config",
    path = "/api/v1/buckets/{bucket}/config",
    params(("bucket" = String, Path, description = "Bucket name")),
    responses(
        (status = 200, description = "Bucket configuration", body = BucketConfigBody, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "buckets",
)]
pub async fn get_config(
    path: web::Path<String>,
    storage: web::Data<Arc<AnyStorage>>,
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let bucket = path.into_inner();
    authorize_bucket(&auth, &storage, &bucket, BucketPermission::Read).await?;
    let cfg = storage
        .get_bucket_config(&bucket)
        .await
        .map_err(AppError::from)?;
    Ok(HttpResponse::Ok().json(BucketConfigBody::from(cfg)))
}

/// Replace a bucket's configuration.
#[utoipa::path(
    put,
    operation_id = "set_bucket_config",
    path = "/api/v1/buckets/{bucket}/config",
    params(("bucket" = String, Path, description = "Bucket name")),
    request_body(content = BucketConfigBody, content_type = "application/json"),
    responses(
        (status = 200, description = "Configuration stored", body = BucketConfigBody, content_type = "application/json"),
        (status = 400, description = "Invalid bucket name", body = ErrorBody, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "buckets",
)]
pub async fn set_config(
    path: web::Path<String>,
    body: web::Json<BucketConfigBody>,
    storage: web::Data<Arc<AnyStorage>>,
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let bucket = path.into_inner();
    authorize_bucket(&auth, &storage, &bucket, BucketPermission::Admin).await?;
    let body = body.into_inner();
    // Read-modify-write: this endpoint only edits the quota/SSE/CORS fields and
    // must preserve the bucket's owner and ACL (which are managed separately via
    // the ACL endpoints, never through this public config body).
    let mut cfg = storage
        .get_bucket_config(&bucket)
        .await
        .map_err(AppError::from)?;
    cfg.quota_bytes = body.quota_bytes;
    cfg.default_sse = body.default_sse;
    cfg.cors_allow_origin = body.cors_allow_origin;
    storage
        .set_bucket_config(&bucket, &cfg)
        .await
        .map_err(AppError::from)?;
    Ok(HttpResponse::Ok().json(BucketConfigBody::from(cfg)))
}
