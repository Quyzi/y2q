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

    let current = storage
        .describe(&bucket, &key)
        .await
        .map_err(AppError::from)?
        .labels;

    let final_labels = match op {
        "set" => {
            let mut merged = current;
            merged.extend(incoming);
            merged
        }
        "remove" => {
            if incoming.is_empty() {
                BTreeSet::new()
            } else {
                let names: BTreeSet<&String> = incoming.iter().map(|(n, _)| n).collect();
                current
                    .into_iter()
                    .filter(|(n, _)| !names.contains(n))
                    .collect()
            }
        }
        "replace" => incoming,
        other => {
            return Err(AppError(y2q_core::Error::InvalidLabelValue {
                name: format!("op={other} (expected set|remove|replace)"),
            }));
        }
    };

    // Clustered: apply the final label set across the chain. Otherwise write
    // locally. The final set is computed once here and applied verbatim at every
    // replica so they stay identical.
    if let Some(rt) = cluster.as_ref() {
        cluster::chain_set_labels(rt, &bucket, &key, &final_labels).await?;
    } else {
        storage
            .set_labels(&bucket, &key, final_labels.clone())
            .await
            .map_err(AppError::from)?;
    }

    Ok(HttpResponse::Ok().json(SetTagsResponse {
        bucket,
        key,
        labels: final_labels,
    }))
}
