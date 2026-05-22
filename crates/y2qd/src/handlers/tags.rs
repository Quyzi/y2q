//! `PATCH /{bucket}/{key}` — mutate an object's labels (a.k.a. tags /
//! attributes) without re-uploading its body.
//!
//! The operation is selected with the `?op=` query parameter:
//! - `set` (default): merge the supplied `X-Y2Q-<label>` headers into the
//!   existing label set (overwriting same-named labels).
//! - `remove`: delete the supplied label names; with no labels supplied,
//!   clears every label.
//! - `replace`: replace the entire label set with the supplied labels.

use std::collections::BTreeMap;
use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, web};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use y2q_core::{AnyStorage, Storage};

use super::labels::extract_labels;
use crate::auth::Authenticated;
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
    /// The full label set after the operation.
    pub labels: BTreeMap<String, String>,
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
    _auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let (bucket, key) = path.into_inner();
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
                BTreeMap::new()
            } else {
                let mut remaining = current;
                for name in incoming.keys() {
                    remaining.remove(name);
                }
                remaining
            }
        }
        "replace" => incoming,
        other => {
            return Err(AppError(y2q_core::Error::InvalidLabelValue {
                name: format!("op={other} (expected set|remove|replace)"),
            }));
        }
    };

    storage
        .set_labels(&bucket, &key, final_labels.clone())
        .await
        .map_err(AppError::from)?;

    Ok(HttpResponse::Ok().json(SetTagsResponse {
        bucket,
        key,
        labels: final_labels,
    }))
}
