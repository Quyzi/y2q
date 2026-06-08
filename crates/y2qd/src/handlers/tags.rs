//! `PATCH /{bucket}/{key}` — mutate an object's labels (a.k.a. tags /
//! attributes) without re-uploading its body.
//!
//! The operation is selected with the `?op=` query parameter:
//! - `set` (default): add the supplied `X-Y2Q-<label>` pairs to the existing
//!   label set. A name may end up with several values; exact duplicates
//!   collapse. To replace a name's values, use `remove` then `set`, or
//!   `replace`.
//! - `remove`: delete every value of each supplied label name; with no labels
//!   supplied, clears every label.
//! - `replace`: replace the entire label set with the supplied labels.

use std::collections::BTreeSet;
use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, web};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use y2q_cluster::LabelMode;
use y2q_core::{AnyStorage, BucketPermission, Storage};

use super::labels::extract_labels;
use crate::auth::Authenticated;
use crate::authz::authorize_bucket;
use crate::cluster::{self, ClusterRuntime};
use crate::config::LabelLimits;
use crate::error::{AppError, ErrorBody};

#[derive(Debug, Deserialize)]
pub struct TagQuery {
    #[serde(default)]
    op: Option<String>,
}

/// Response body for `PATCH /{bucket}/{key}`.
#[derive(Debug, Serialize, ToSchema)]
pub struct SetTagsResponse {
    pub bucket: String,
    pub key: String,
    /// The full label set after the operation, as `(name, value)` pairs.
    pub labels: BTreeSet<(String, String)>,
}

/// Mutate an object's labels. Requires a valid Bearer token.
#[utoipa::path(
    patch,
    operation_id = "set_tags",
    path = "/{bucket}/{key}",
    params(
        ("bucket" = String, Path, description = "Bucket name"),
        ("key" = String, Path, description = "Object key"),
        ("op" = Option<String>, Query, description = "set (default) | remove | replace"),
    ),
    responses(
        (status = 200, description = "Updated label set", body = SetTagsResponse, content_type = "application/json"),
        (status = 400, description = "Invalid bucket/key/label or unknown op", body = ErrorBody, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 404, description = "Object not found", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "tags",
)]
pub async fn handle(
    path: web::Path<(String, String)>,
    query: web::Query<TagQuery>,
    req: HttpRequest,
    storage: web::Data<Arc<AnyStorage>>,
    limits: web::Data<LabelLimits>,
    cluster: Option<web::Data<ClusterRuntime>>,
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let (bucket, key) = path.into_inner();
    authorize_bucket(&auth, &storage, &bucket, BucketPermission::Write).await?;
    let incoming = extract_labels(&req, limits.get_ref())?;
    let op = query.op.as_deref().unwrap_or("set");
    let mode = match op {
        "set" => LabelMode::Set,
        "remove" => LabelMode::Remove,
        "replace" => LabelMode::Replace,
        other => {
            return Err(AppError(y2q_core::Error::InvalidLabelValue {
                name: format!("op={other} (expected set|remove|replace)"),
            }));
        }
    };

    // Clustered: the edit is resolved at the chain HEAD against its committed
    // copy and applied verbatim across the chain. The contact node may not hold
    // the object, so it must not read the current set locally. Single-node:
    // read-modify-write against the local copy.
    let final_labels: BTreeSet<(String, String)> = if let Some(rt) = cluster.as_ref() {
        cluster::chain_edit_labels(rt, &bucket, &key, mode, incoming.into_iter().collect()).await?
    } else {
        let current: Vec<(String, String)> = storage
            .describe(&bucket, &key)
            .await
            .map_err(AppError::from)?
            .labels
            .into_iter()
            .collect();
        let resolved: BTreeSet<(String, String)> = mode
            .resolve(current, incoming.into_iter().collect())
            .into_iter()
            .collect();
        storage
            .set_labels(&bucket, &key, resolved.clone())
            .await
            .map_err(AppError::from)?;
        resolved
    };

    Ok(HttpResponse::Ok().json(SetTagsResponse {
        bucket,
        key,
        labels: final_labels,
    }))
}
