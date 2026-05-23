//! `GET /api/v1/search` - find objects whose labels satisfy a boolean query.
//!
//! The `q` parameter is a label query (see [`y2q_core::LabelQuery`]): leaf
//! conditions `name OP value` with `OP` in `== != =~ ^= $=`, combined with
//! `and`/`&&`, `or`/`||`, `not`/`!`, and parentheses. When `bucket` is omitted
//! the search spans every bucket.

use std::sync::Arc;

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use y2q_core::{AnyStorage, LabelQuery, ListOptions, Listing, MAX_LIST_LIMIT};

use super::list_objects::{ListObjectsResponse, MetadataView};
use crate::auth::Authenticated;
use crate::error::{AppError, ErrorBody};

/// Query-string parameters for `GET /api/v1/search`.
#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    /// Label query expression, e.g. `env == prod and tier != test`.
    pub q: String,
    /// Restrict the search to a single bucket. Omit to search all buckets.
    pub bucket: Option<String>,
    /// Return only keys with this prefix.
    pub prefix: Option<String>,
    /// Continuation cursor: opaque value from a previous response's `next`.
    pub after: Option<String>,
    /// Maximum number of items in the response page.
    pub limit: Option<usize>,
}

/// Search objects by label query.
///
/// Results are sorted by `(bucket, key)` and capped at `limit` (default 1000,
/// max 10000). When more results exist, `next` carries an opaque continuation
/// cursor; pass it back as `after` to fetch the following page.
#[utoipa::path(
    get,
    operation_id = "search_objects",
    path = "/api/v1/search",
    params(
        ("q" = String, Query, description = "Label query, e.g. `env == prod and tier != test`"),
        ("bucket" = Option<String>, Query, description = "Restrict to a single bucket (default: all)"),
        ("prefix" = Option<String>, Query, description = "Return only keys with this prefix"),
        ("after" = Option<String>, Query, description = "Continuation cursor from a previous response"),
        ("limit" = Option<usize>, Query, description = "Maximum items per page (default 1000, max 10000)"),
    ),
    responses(
        (status = 200, description = "Sorted page of matching object metadata", body = ListObjectsResponse, content_type = "application/json"),
        (status = 400, description = "Invalid query or bucket", body = ErrorBody, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "listing",
)]
pub async fn handle(
    query: web::Query<SearchQuery>,
    storage: web::Data<Arc<AnyStorage>>,
    _auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let q = query.into_inner();
    let parsed = LabelQuery::parse(&q.q).map_err(AppError::from)?;
    let options = ListOptions {
        prefix: q.prefix,
        after: q.after,
        limit: q.limit.map(|n| n.min(MAX_LIST_LIMIT)),
    };
    let page = storage
        .search_objects(&parsed, q.bucket.as_deref(), options)
        .await
        .map_err(AppError::from)?;

    let response = ListObjectsResponse {
        items: page.items.into_iter().map(MetadataView::from).collect(),
        next: page.next,
    };
    Ok(HttpResponse::Ok().json(response))
}
