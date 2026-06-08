//! `GET /api/v1/search` - find objects whose labels satisfy a boolean query.
//!
//! The `q` parameter is a label query (see [`y2q_core::LabelQuery`]): leaf
//! conditions `name OP value` with `OP` in `== != =~ ^= $=`, combined with
//! `and`/`&&`, `or`/`||`, `not`/`!`, and parentheses. When `bucket` is omitted
//! the search spans every bucket.

use std::collections::HashMap;
use std::sync::Arc;

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use y2q_core::{
    AnyStorage, BucketPermission, DEFAULT_LIST_LIMIT, LabelQuery, ListOptions, Listing,
    MAX_LIST_LIMIT, Metadata,
};

use super::list_objects::{ListObjectsResponse, MetadataView};
use crate::auth::Authenticated;
use crate::authz::{authorize_bucket, bucket_readable};
use crate::cluster::{self, ClusterRuntime};
use crate::error::{AppError, ErrorBody};

/// Continuation cursor for cross-bucket search, mirroring the core index's
/// `bucket\0key` composite. Built only from items the caller can read so the
/// cursor never names a hidden bucket.
fn cursor_of(m: &Metadata) -> String {
    format!("{}\u{0}{}", m.bucket, m.key)
}

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
    cluster: Option<web::Data<ClusterRuntime>>,
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let q = query.into_inner();
    let parsed = LabelQuery::parse(&q.q).map_err(AppError::from)?;
    let user_limit = q.limit.map(|n| n.min(MAX_LIST_LIMIT));

    // Single-bucket search: authorize that one bucket (404 hides a bucket the
    // caller cannot read), then return its page directly. Every item is
    // readable and the cursor stays within a bucket the caller can see.
    if let Some(b) = q.bucket.as_deref() {
        authorize_bucket(&auth, &storage, b, BucketPermission::Read).await?;
        let opts = ListOptions {
            prefix: q.prefix,
            after: q.after,
            limit: user_limit,
        };
        let page = if let Some(rt) = cluster.as_ref() {
            cluster::scatter_list(rt, Some(b), Some(&q.q), &opts).await?
        } else {
            storage
                .search_objects(&parsed, Some(b), opts)
                .await
                .map_err(AppError::from)?
        };
        return Ok(HttpResponse::Ok().json(ListObjectsResponse {
            items: page.items.into_iter().map(MetadataView::from).collect(),
            next: page.next,
        }));
    }

    // Cross-bucket search. Admins and auditors can read every bucket, so the
    // core cursor is safe to expose and no filtering is required.
    if auth.is_admin_or_auditor() {
        let opts = ListOptions {
            prefix: q.prefix,
            after: q.after,
            limit: user_limit,
        };
        let page = if let Some(rt) = cluster.as_ref() {
            cluster::scatter_list(rt, None, Some(&q.q), &opts).await?
        } else {
            storage
                .search_objects(&parsed, None, opts)
                .await
                .map_err(AppError::from)?
        };
        return Ok(HttpResponse::Ok().json(ListObjectsResponse {
            items: page.items.into_iter().map(MetadataView::from).collect(),
            next: page.next,
        }));
    }

    // Cross-bucket search by a non-global role. Fetch a wide window, drop
    // matches in buckets the caller cannot read, then paginate over the visible
    // results in the daemon. The continuation cursor is built only from a
    // visible item, so it never leaks a hidden bucket name or object key.
    let lim = user_limit.unwrap_or(DEFAULT_LIST_LIMIT);
    let wide = ListOptions {
        prefix: q.prefix,
        after: q.after,
        limit: Some(MAX_LIST_LIMIT),
    };
    let raw = if let Some(rt) = cluster.as_ref() {
        cluster::scatter_list(rt, None, Some(&q.q), &wide).await?
    } else {
        storage
            .search_objects(&parsed, None, wide)
            .await
            .map_err(AppError::from)?
    };
    let more_raw = raw.next.is_some();

    let mut readable: HashMap<String, bool> = HashMap::new();
    let mut visible: Vec<Metadata> = Vec::new();
    for m in raw.items {
        let ok = match readable.get(&m.bucket) {
            Some(v) => *v,
            None => {
                let v = bucket_readable(&auth, &storage, &m.bucket).await?;
                readable.insert(m.bucket.clone(), v);
                v
            }
        };
        if ok {
            visible.push(m);
        }
    }

    let truncated = visible.len() > lim;
    visible.truncate(lim);
    // Emit a cursor (from the last *visible* item) whenever more results may
    // remain; `None` only when the visible result set is exhausted.
    let next = if truncated || more_raw {
        visible.last().map(cursor_of)
    } else {
        None
    };

    Ok(HttpResponse::Ok().json(ListObjectsResponse {
        items: visible.into_iter().map(MetadataView::from).collect(),
        next,
    }))
}
