//! `GET /{bucket}/` — enumerate objects in a bucket with optional prefix
//! filter and cursor-based pagination.

use std::sync::Arc;

use actix_web::{HttpResponse, web};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use y2q_core::{AnyStorage, ListOptions, Listing, MAX_LIST_LIMIT, Metadata};

use crate::auth::Authenticated;
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
    /// 8-byte gxhash64 digest as standard base64 (12 chars, padded).
    pub checksum_gxhash: String,
    /// Bucket the object belongs to.
    pub bucket: String,
    /// Object key within the bucket.
    pub key: String,
    /// Absolute on-disk path of the object data file.
    pub disk_path: String,
    /// Logical URL path: `"<bucket>/<key>"`.
    pub url_path: String,
    /// User-supplied labels attached to the object, as `(name, value)` pairs.
    /// A name may appear more than once with different values.
    #[schema(value_type = Vec<Vec<String>>)]
    pub labels: Vec<(String, String)>,
    /// Total bytes on disk (encrypted envelope), if encryption is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_size: Option<u64>,
    /// Standard-base64 SHA-256 of the on-disk envelope bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_sha256: Option<String>,
    /// Symbolic KEM algorithm name (e.g. `"ml-kem-768"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kem_alg: Option<String>,
    /// Symbolic AEAD algorithm name (e.g. `"aes-256-gcm"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aead_alg: Option<String>,
    /// Envelope format version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope_version: Option<u16>,
}

impl From<Metadata> for MetadataView {
    fn from(m: Metadata) -> Self {
        Self {
            created: m.created,
            modified: m.modified,
            size: m.size,
            checksum_gxhash: m.checksum_gxhash,
            bucket: m.bucket,
            key: m.key,
            disk_path: m.disk_path.to_string_lossy().into_owned(),
            url_path: m.url_path,
            labels: m.labels.into_iter().collect(),
            cipher_size: m.cipher_size,
            cipher_sha256: m.cipher_sha256,
            kem_alg: m.kem_alg,
            aead_alg: m.aead_alg,
            envelope_version: m.envelope_version,
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
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "listing",
)]
pub async fn handle(
    path: web::Path<String>,
    query: web::Query<ListQuery>,
    storage: web::Data<Arc<AnyStorage>>,
    _auth: Authenticated,
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
