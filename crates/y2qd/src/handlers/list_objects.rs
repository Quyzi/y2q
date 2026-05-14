//! `GET /{bucket}/` — enumerate objects in a bucket with optional prefix
//! filter and cursor-based pagination.

use std::collections::BTreeMap;
use std::sync::Arc;

use actix_web::{HttpResponse, web};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use y2q_core::{AnyStorage, ListOptions, Listing, MAX_LIST_LIMIT, Metadata};

use crate::error::{AppError, ErrorBody};

/// Query-string parameters for `GET /{bucket}/`.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Return only keys with this prefix.
    pub prefix: Option<String>,
    /// Continuation cursor: return only keys strictly greater than this.
    pub after: Option<String>,
    /// Maximum number of items in the response page.
    pub limit: Option<usize>,
}

/// Mirror of [`y2q_core::Metadata`] for OpenAPI schema generation.
///
/// Defined in y2qd (not in core) so that core does not need a `utoipa`
/// dependency. Wire format is identical to the core type.
#[derive(Debug, Serialize, ToSchema)]
pub struct MetadataView {
    /// Nanoseconds since Unix epoch when the object was first written.
    pub created: u64,
    /// Nanoseconds since Unix epoch when the object was last overwritten.
    pub modified: u64,
    /// Size of the object in bytes.
    pub size: u64,
    /// Full 16-byte MD5 digest as standard base64 (24 chars, padded).
    pub checksum_md5: String,
    /// Full 32-byte SHA-256 digest as standard base64 (44 chars, padded).
    pub checksum_sha256: String,
    /// Bucket the object belongs to.
    pub bucket: String,
    /// Object key within the bucket.
    pub key: String,
    /// Absolute on-disk path of the object data file.
    pub disk_path: String,
    /// Logical URL path: `"<bucket>/<key>"`.
    pub url_path: String,
    /// User-supplied labels attached to the object.
    pub labels: BTreeMap<String, String>,
}

impl From<Metadata> for MetadataView {
    fn from(m: Metadata) -> Self {
        Self {
            created: m.created,
            modified: m.modified,
            size: m.size,
            checksum_md5: m.checksum_md5,
            checksum_sha256: m.checksum_sha256,
            bucket: m.bucket,
            key: m.key,
            disk_path: m.disk_path.to_string_lossy().into_owned(),
            url_path: m.url_path,
            labels: m.labels,
        }
    }
}

/// Response body for `GET /{bucket}/`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListObjectsResponse {
    /// Object metadata, sorted ascending by key.
    pub items: Vec<MetadataView>,
    /// Continuation cursor: pass back as `after` to fetch the next page,
    /// or `null` if no more results remain.
    pub next: Option<String>,
}

/// List one page of objects in a bucket.
///
/// Results are sorted ascending by key. The response is capped at `limit`
/// items (default 1000, max 10000). When more results exist, `next` contains
/// the last key returned; pass it back as the `after` parameter on a
/// subsequent request to fetch the next page.
#[utoipa::path(
    get,
    operation_id = "list_objects",
    path = "/{bucket}/",
    params(
        ("bucket" = String, Path, description = "Bucket name (alphanumeric, `-`, `_`)"),
        ("prefix" = Option<String>, Query, description = "Return only keys with this prefix"),
        ("after" = Option<String>, Query, description = "Continuation cursor: return only keys strictly greater than this"),
        ("limit" = Option<usize>, Query, description = "Maximum items per page (default 1000, max 10000)"),
    ),
    responses(
        (status = 200, description = "Sorted page of object metadata", body = ListObjectsResponse, content_type = "application/json"),
        (status = 400, description = "Invalid bucket", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    tag = "listing",
)]
pub async fn handle(
    path: web::Path<String>,
    query: web::Query<ListQuery>,
    storage: web::Data<Arc<AnyStorage>>,
) -> Result<HttpResponse, AppError> {
    let bucket = path.into_inner();
    let q = query.into_inner();
    let options = ListOptions {
        prefix: q.prefix,
        after: q.after,
        limit: q.limit.map(|n| n.min(MAX_LIST_LIMIT)),
    };
    let page = storage
        .list_objects(&bucket, options)
        .await
        .map_err(AppError::from)?;

    let response = ListObjectsResponse {
        items: page.items.into_iter().map(MetadataView::from).collect(),
        next: page.next,
    };
    Ok(HttpResponse::Ok().json(response))
}
