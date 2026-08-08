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
use crate::config::LabelLimits;
use crate::error::{AppError, ErrorBody};

#[derive(Debug, Deserialize)]
pub struct TagQuery {
    #[serde(default)]
    op: Option<String>,
}

/// How a `PATCH` label edit combines with the object's existing labels.
#[derive(Debug, Clone, Copy)]
enum LabelMode {
    /// Add the supplied labels to the existing set.
    Set,
    /// Remove every value of each supplied label name (or clear all if empty).
    Remove,
    /// Replace the entire set with the supplied labels.
    Replace,
}

impl LabelMode {
    /// Resolve an edit against `current` into the final label set. Inputs and
    /// output are deduplicated and ordered (collected through a `BTreeSet`).
    fn resolve(
        self,
        current: Vec<(String, String)>,
        incoming: Vec<(String, String)>,
    ) -> Vec<(String, String)> {
        match self {
            LabelMode::Set => {
                let mut merged: BTreeSet<(String, String)> = current.into_iter().collect();
                merged.extend(incoming);
                merged.into_iter().collect()
            }
            LabelMode::Remove => {
                if incoming.is_empty() {
                    return Vec::new();
                }
                let names: BTreeSet<&String> = incoming.iter().map(|(n, _)| n).collect();
                let kept: BTreeSet<(String, String)> = current
                    .into_iter()
                    .filter(|(n, _)| !names.contains(n))
                    .collect();
                kept.into_iter().collect()
            }
            LabelMode::Replace => {
                let set: BTreeSet<(String, String)> = incoming.into_iter().collect();
                set.into_iter().collect()
            }
        }
    }
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
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let (bucket, key) = path.into_inner();
    authorize_bucket(&auth, &storage, &bucket, BucketPermission::Write).await?;
    // A `WriteOnly` drop-box grantee never gets a real cryptographic grant
    // and must never learn an object's pre-existing labels — but `Write`
    // gates this handler, and `Write`'s grant level also implies `Read`
    // (see `authz::grant_caps`), so a second, explicit `Read` check is the
    // only way to tell a genuine write-only caller apart from one who can
    // also read. Gates the RESPONSE only; the label mutation itself still
    // succeeds either way — that's the drop-box's whole point.
    let can_read = authorize_bucket(&auth, &storage, &bucket, BucketPermission::Read)
        .await
        .is_ok();
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

    // Read-modify-write against the local copy.
    let current: Vec<(String, String)> = storage
        .describe(&bucket, &key)
        .await
        .map_err(AppError::from)?
        .labels
        .into_iter()
        .collect();
    let incoming_set: BTreeSet<(String, String)> = incoming.into_iter().collect();
    let final_labels: BTreeSet<(String, String)> = mode
        .resolve(current, incoming_set.iter().cloned().collect())
        .into_iter()
        .collect();
    storage
        .set_labels(&bucket, &key, final_labels.clone())
        .await
        .map_err(AppError::from)?;

    // Without read access, echo back only what the caller itself just
    // submitted (which it already knows), never the merged result — that
    // would reveal labels attached before this call, or by someone else.
    let response_labels = if can_read { final_labels } else { incoming_set };

    Ok(HttpResponse::Ok().json(SetTagsResponse {
        bucket,
        key,
        labels: response_labels,
    }))
}
