//! `PUT /{bucket}/{key}` — write or overwrite a stored object.

use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, web};
use y2q_core::{AnyStorage, PutOptions, SyncLevel};

use crate::auth::Authenticated;
use crate::cipher;
use crate::config::LabelLimits;
use crate::error::{AppError, ErrorBody};
use crate::handlers::labels::extract_labels;

/// Write or overwrite a stored object.
///
/// The raw request body is encrypted under the deployment public key and the
/// resulting envelope is stored at `bucket`/`key`. Writes are atomic: readers
/// see either the old object or the new one. Requires a valid Bearer token.
///
/// Any request header matching `X-Y2Q-<label>` (case-insensitive) is captured
/// as a custom label and persisted with the object. The label name is
/// lowercased on storage. The reserved names `X-Y2Q-Created`,
/// `X-Y2Q-Modified`, `X-Y2Q-Checksum-MD5`, and `X-Y2Q-Checksum-SHA256` are
/// emitted by the server on `HEAD` and may not be supplied by clients;
/// supplying any reserved name returns 400. When the same label is sent
/// multiple times, the last value wins.
///
/// Returns 201 Created if the key did not previously exist, or 200 OK if an
/// existing object was replaced.
#[utoipa::path(
    put,
    operation_id = "put_object",
    path = "/{bucket}/{key}",
    params(
        ("bucket" = String, Path, description = "Bucket name (alphanumeric, `-`, `_`)"),
        ("key" = String, Path, description = "Object key; may contain `/` to represent nested paths"),
    ),
    request_body(
        content = Vec<u8>,
        content_type = "application/octet-stream",
        description = "Raw object bytes to store. Custom labels may be attached via `X-Y2Q-<label>` request headers; \
            the reserved names `Created`, `Modified`, `Checksum-MD5`, `Checksum-SHA256` are rejected.",
    ),
    responses(
        (status = 201, description = "Object created"),
        (status = 200, description = "Object replaced (key already existed)"),
        (status = 400, description = "Invalid bucket, key, or label", body = ErrorBody, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 409, description = "Object is locked (write in progress)", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "objects",
)]
pub async fn handle(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    payload: web::Payload,
    storage: web::Data<Arc<AnyStorage>>,
    limits: web::Data<LabelLimits>,
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let (bucket, key) = path.into_inner();
    let labels = extract_labels(&req, limits.get_ref())?;
    let sync = parse_sync_header(&req)?;

    let (guard, file, write_offset) = storage
        .begin_streaming_put(&bucket, &key)
        .await
        .map_err(AppError::from)?;

    let (file, plaintext_metrics, cipher_metadata) =
        cipher::stream_encrypt_for_put(&auth.keystore, payload, file, &bucket, &key, write_offset)
            .await?;

    let was_overwrite = guard
        .commit(
            file,
            PutOptions {
                labels,
                sync,
                ..Default::default()
            },
            plaintext_metrics,
            cipher_metadata,
        )
        .await
        .map_err(AppError::from)?;

    if was_overwrite {
        Ok(HttpResponse::Ok().finish())
    } else {
        Ok(HttpResponse::Created().finish())
    }
}

/// Parse the optional `X-Y2Q-Sync` request header into a [`SyncLevel`].
///
/// Accepts `durable` (default; same as omitting the header) or `best-effort`.
/// Any other value returns a 400 via the existing `InvalidLabelValue` shape
/// since `sync` lives in the same header namespace as user labels.
fn parse_sync_header(req: &HttpRequest) -> Result<SyncLevel, AppError> {
    let Some(raw) = req.headers().get("x-y2q-sync") else {
        return Ok(SyncLevel::default());
    };
    let value = raw.to_str().map_err(|_| {
        AppError(y2q_core::Error::InvalidLabelValue {
            name: "sync".to_owned(),
        })
    })?;
    match value.trim().to_ascii_lowercase().as_str() {
        "durable" => Ok(SyncLevel::Durable),
        "best-effort" | "besteffort" => Ok(SyncLevel::BestEffort),
        _ => Err(AppError(y2q_core::Error::InvalidLabelValue {
            name: "sync".to_owned(),
        })),
    }
}
