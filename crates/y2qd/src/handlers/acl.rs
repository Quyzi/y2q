//! `GET`/`PUT /api/v1/buckets/{bucket}/acl` — read and replace a bucket's
//! owner and access-control list.
//!
//! Ownership and ACL are deliberately kept out of the generic bucket-config
//! body (`/api/v1/buckets/{bucket}/config`) so that the config endpoint cannot
//! be used to escalate privileges. They are managed only here, behind a bucket
//! `Admin` (owner) or global-admin check. Transferring ownership additionally
//! requires being the current owner or a global admin.

use std::collections::BTreeMap;
use std::sync::Arc;

use actix_web::{HttpResponse, web};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use y2q_core::{AnyStorage, BucketPermission, Listing};

use crate::auth::{AuthState, Authenticated};
use crate::authz::authorize_bucket;
use crate::error::{AppError, ErrorBody};

/// Owner + grants view returned by `GET` and accepted by `PUT`.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AclBody {
    /// Bucket owner (full control). `null` only for unclaimed legacy buckets,
    /// which are admin-only until an admin assigns an owner here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Per-user grants. Keys are usernames; values are `"read"`, `"write"`, or
    /// `"admin"`. The owner is never listed (they have implicit full control).
    #[serde(default)]
    #[schema(value_type = std::collections::HashMap<String, String>)]
    pub grants: BTreeMap<String, BucketPermission>,
}

/// Read a bucket's owner and ACL. Requires bucket `Admin` (owner) or global admin.
#[utoipa::path(
    get,
    operation_id = "get_bucket_acl",
    path = "/api/v1/buckets/{bucket}/acl",
    params(("bucket" = String, Path, description = "Bucket name")),
    responses(
        (status = 200, description = "Bucket owner and ACL", body = AclBody, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 403, description = "Caller is not the owner / a global admin", body = ErrorBody, content_type = "application/json"),
        (status = 404, description = "Bucket not found (or not visible to the caller)", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "buckets",
)]
pub async fn get_acl(
    path: web::Path<String>,
    storage: web::Data<Arc<AnyStorage>>,
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let bucket = path.into_inner();
    // Global admins and auditors may view any bucket's ACL; otherwise the
    // caller must be the bucket's owner or a bucket-admin grantee.
    if !auth.is_admin_or_auditor() {
        authorize_bucket(&auth, &storage, &bucket, BucketPermission::Admin).await?;
    }
    if !storage
        .bucket_exists(&bucket)
        .await
        .map_err(AppError::from)?
    {
        return Err(not_found(&bucket));
    }
    let cfg = storage
        .get_bucket_config(&bucket)
        .await
        .map_err(AppError::from)?;
    Ok(HttpResponse::Ok().json(AclBody {
        owner: cfg.owner,
        grants: cfg.acl,
    }))
}

/// Replace a bucket's ACL (and optionally transfer ownership). Requires bucket
/// `Admin` (owner) or global admin; assigning a new `owner` additionally
/// requires being the current owner or a global admin.
#[utoipa::path(
    put,
    operation_id = "set_bucket_acl",
    path = "/api/v1/buckets/{bucket}/acl",
    params(("bucket" = String, Path, description = "Bucket name")),
    request_body(content = AclBody, content_type = "application/json"),
    responses(
        (status = 200, description = "Updated owner and ACL", body = AclBody, content_type = "application/json"),
        (status = 400, description = "Unknown grantee, empty username, or redundant owner grant", body = ErrorBody, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 403, description = "Caller may not manage this ACL or transfer ownership", body = ErrorBody, content_type = "application/json"),
        (status = 404, description = "Bucket not found (or not visible to the caller)", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "buckets",
)]
pub async fn set_acl(
    path: web::Path<String>,
    body: web::Json<AclBody>,
    storage: web::Data<Arc<AnyStorage>>,
    state: web::Data<AuthState>,
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let bucket = path.into_inner();
    authorize_bucket(&auth, &storage, &bucket, BucketPermission::Admin).await?;
    if !storage
        .bucket_exists(&bucket)
        .await
        .map_err(AppError::from)?
    {
        return Err(not_found(&bucket));
    }

    let body = body.into_inner();
    let mut cfg = storage
        .get_bucket_config(&bucket)
        .await
        .map_err(AppError::from)?;

    // Ownership transfer / assignment: only the current owner or a global admin
    // may change the owner (a mere bucket-`Admin` grantee may not).
    if let Some(new_owner) = body.owner {
        let is_current_owner = cfg.owner.as_deref() == Some(auth.username.as_str());
        if !auth.is_admin() && !is_current_owner {
            return Err(AppError(y2q_core::Error::Forbidden {
                bucket: bucket.clone(),
            }));
        }
        ensure_user_exists(&state, &new_owner)?;
        cfg.owner = Some(new_owner);
    }

    // Validate the proposed grants before applying. Grantee existence is NOT
    // checked: a grant to an unknown username is inert (it can never match a
    // real login), and validating it would turn this endpoint into a
    // username-enumeration oracle for any bucket owner. Owner *transfer* is
    // still validated above — but probing it costs the prober their bucket, so
    // it is not a usable enumeration vector.
    for user in body.grants.keys() {
        if user.trim().is_empty() {
            return Err(invalid_acl("grant username must not be empty"));
        }
        if cfg.owner.as_deref() == Some(user.as_str()) {
            return Err(invalid_acl(&format!(
                "user `{user}` is the bucket owner and already has full access"
            )));
        }
    }
    cfg.acl = body.grants;

    storage
        .set_bucket_config(&bucket, &cfg)
        .await
        .map_err(AppError::from)?;
    Ok(HttpResponse::Ok().json(AclBody {
        owner: cfg.owner,
        grants: cfg.acl,
    }))
}

/// Reject the request if `username` is not a known user.
fn ensure_user_exists(state: &AuthState, username: &str) -> Result<(), AppError> {
    let exists = state
        .user_store
        .get(username)
        .map_err(|e| {
            AppError(y2q_core::Error::Index {
                message: e.to_string(),
            })
        })?
        .is_some();
    if exists {
        Ok(())
    } else {
        Err(invalid_acl(&format!("unknown user `{username}`")))
    }
}

fn invalid_acl(reason: &str) -> AppError {
    AppError(y2q_core::Error::InvalidAcl {
        reason: reason.to_owned(),
    })
}

fn not_found(bucket: &str) -> AppError {
    AppError(y2q_core::Error::NotFound {
        bucket: bucket.to_owned(),
        key: String::new(),
    })
}
