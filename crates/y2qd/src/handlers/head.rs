//! `HEAD /{bucket}/{key}` — retrieve object metadata without a body.

use std::sync::Arc;

use actix_web::{HttpResponse, web};
use y2q_core::{AnyStorage, Storage};

use crate::auth::Authenticated;
use crate::error::{AppError, ErrorBody};

/// Retrieve object metadata without transferring the body.
///
/// Returns 200 OK with no body. Object metadata is exposed as response headers:
///
/// | Header | Value |
/// |--------|-------|
/// | `Content-Length` | Object size in bytes |
/// | `Content-Type` | `application/octet-stream` |
/// | `X-Y2Q-Created` | Nanoseconds since Unix epoch when first written |
/// | `X-Y2Q-Modified` | Nanoseconds since Unix epoch when last overwritten |
/// | `X-Y2Q-Checksum-GxHash` | 8-byte gxhash64 digest as standard base64 (12 chars) |
/// | `X-Y2Q-<label>` | Any custom label attached to the object on PUT |
///
/// Custom label names are echoed back lowercased.
/// Returns 404 if the object does not exist.
#[utoipa::path(
    head,
    operation_id = "head_object",
    path = "/{bucket}/{key}",
    params(
        ("bucket" = String, Path, description = "Bucket name (alphanumeric, `-`, `_`)"),
        ("key" = String, Path, description = "Object key; may contain `/` to represent nested paths"),
    ),
    responses(
        (status = 200, description = "Object exists. Metadata is returned in response headers: \
            `X-Y2Q-Created` (ns since epoch), `X-Y2Q-Modified` (ns since epoch), \
            `X-Y2Q-Checksum-GxHash` (base64, 12 chars), \
            plus any `X-Y2Q-<label>` headers attached on PUT. \
            Encrypted objects also expose `X-Y2Q-Cipher-Size`, `X-Y2Q-Cipher-SHA256`, \
            `X-Y2Q-Kem-Alg`, `X-Y2Q-Aead-Alg`, and `X-Y2Q-Envelope-Version`."),
        (status = 400, description = "Invalid bucket or key", body = ErrorBody, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 404, description = "Object not found", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "objects",
)]
pub async fn handle(
    path: web::Path<(String, String)>,
    storage: web::Data<Arc<AnyStorage>>,
    _auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let (bucket, key) = path.into_inner();
    let meta = storage
        .describe(&bucket, &key)
        .await
        .map_err(AppError::from)?;

    let mut builder = HttpResponse::Ok();
    builder
        .insert_header(("Content-Length", meta.size.to_string()))
        .insert_header(("X-Y2Q-Size", meta.size.to_string()))
        .insert_header(("Content-Type", "application/octet-stream"))
        .insert_header(("X-Y2Q-Created", meta.created.to_string()))
        .insert_header(("X-Y2Q-Modified", meta.modified.to_string()))
        .insert_header(("X-Y2Q-Checksum-GxHash", meta.checksum_gxhash.clone()));

    if let Some(v) = meta.cipher_size {
        builder.insert_header(("X-Y2Q-Cipher-Size", v.to_string()));
    }
    if let Some(ref v) = meta.cipher_sha256 {
        builder.insert_header(("X-Y2Q-Cipher-SHA256", v.clone()));
    }
    if let Some(ref v) = meta.kem_alg {
        builder.insert_header(("X-Y2Q-Kem-Alg", v.clone()));
    }
    if let Some(ref v) = meta.aead_alg {
        builder.insert_header(("X-Y2Q-Aead-Alg", v.clone()));
    }
    if let Some(v) = meta.envelope_version {
        builder.insert_header(("X-Y2Q-Envelope-Version", v.to_string()));
    }

    for (name, value) in &meta.labels {
        builder.insert_header((format!("X-Y2Q-{}", name), value.clone()));
    }

    Ok(builder.finish())
}
