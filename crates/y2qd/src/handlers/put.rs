//! `PUT /{bucket}/{key}` — write or overwrite a stored object.

use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, web};
use y2q_cluster::Role;
use y2q_core::{AnyStorage, BucketPermission, Listing, PutOptions, SyncLevel};

use crate::auth::Authenticated;
use crate::authz::{Decision, authorize_bucket, claim_ownership};
use crate::cipher;
use crate::cluster::{self, ClusterRuntime};
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
/// `X-Y2Q-Modified`, and `X-Y2Q-Checksum-GxHash` are emitted by the server
/// on `HEAD` and may not be supplied by clients; supplying any reserved name
/// returns 400. When the same label is sent multiple times, the last value
/// wins.
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
            the reserved names `Created`, `Modified`, `Checksum-GxHash` are rejected.",
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
// Args are actix extractors (one per injected dependency), not a refactorable
// signature; the count is dictated by the framework.
#[allow(clippy::too_many_arguments)]
pub async fn handle(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    payload: web::Payload,
    storage: web::Data<Arc<AnyStorage>>,
    limits: web::Data<LabelLimits>,
    default_sync: web::Data<SyncLevel>,
    encryption: web::Data<crate::config::EncryptionParams>,
    cluster: Option<web::Data<ClusterRuntime>>,
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let (bucket, key) = path.into_inner();
    let decision = authorize_bucket(&auth, &storage, &bucket, BucketPermission::Write).await?;
    let labels = extract_labels(&req, limits.get_ref())?;
    let sync = parse_sync_header(&req, *default_sync.get_ref())?;

    // Quota enforcement: only buckets that actually set a quota pay the usage
    // scan cost. The Content-Length-based check below is a fast-reject
    // optimization only (skipped by chunked transfer encoding, which has no
    // Content-Length) — `max_bytes`, enforced mid-stream in
    // `stream_encrypt_for_put`, is what actually bounds both the server-wide
    // cap and any bucket quota regardless of how the body is transferred.
    let cfg = storage
        .get_bucket_config(&bucket)
        .await
        .map_err(AppError::from)?;
    let mut max_bytes = encryption.max_body_bytes;
    if let Some(limit) = cfg.quota_bytes {
        let incoming = req
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let used = storage
            .bucket_usage(&bucket)
            .await
            .map_err(AppError::from)?;
        if used + incoming > limit {
            return Err(AppError(y2q_core::Error::QuotaExceeded {
                bucket: bucket.clone(),
                limit,
                used,
                incoming,
            }));
        }
        max_bytes = max_bytes.min(limit.saturating_sub(used));
    }

    // Clustered: route the write through the chain instead of writing locally.
    // The contact node either is the HEAD (encrypt + replicate here) or proxies
    // the plaintext to the HEAD. Reads still come from the local copy (works at
    // replication_factor == node count; apportioned reads land in a later phase).
    if let Some(rt) = cluster.as_ref() {
        let route = rt.distributed.route(&bucket, &key).await;
        let was_overwrite = match route.role(rt.node_id) {
            // This node owns the HEAD: encrypt once and replicate down-chain.
            Role::Head | Role::Solo => {
                cluster::head_write(
                    rt,
                    &bucket,
                    &key,
                    payload,
                    labels,
                    sync,
                    encryption.chunk_size_bytes,
                )
                .await?
            }
            // Not the HEAD: forward the plaintext to the HEAD over the peer channel.
            Role::Middle | Role::Tail | Role::NotInChain => {
                let head_id = route.head().ok_or_else(|| {
                    AppError(y2q_core::Error::InternalError {
                        bucket: bucket.clone(),
                        key: key.clone(),
                        operation: "cluster put".to_owned(),
                        message: "no chain head (cluster has no active members)".to_owned(),
                    })
                })?;
                let head_url = rt.distributed.peer_url(head_id).await.ok_or_else(|| {
                    AppError(y2q_core::Error::InternalError {
                        bucket: bucket.clone(),
                        key: key.clone(),
                        operation: "cluster put".to_owned(),
                        message: format!("head node {head_id} has no known address"),
                    })
                })?;
                cluster::proxy_put_to_head(rt, &head_url, &bucket, &key, payload, &labels, sync)
                    .await?
            }
        };

        if matches!(decision, Decision::ClaimOwnership) {
            cluster::cluster_claim_owner(rt, &bucket, &auth.username).await?;
        }
        return Ok(if was_overwrite {
            HttpResponse::Ok().finish()
        } else {
            HttpResponse::Created().finish()
        });
    }

    let (guard, sink, write_offset) = storage
        .begin_streaming_put(&bucket, &key)
        .await
        .map_err(AppError::from)?;

    let (sink, plaintext_metrics, cipher_metadata) = cipher::stream_encrypt_for_put(
        &auth.keystore.public.public_key,
        payload,
        sink,
        &bucket,
        &key,
        write_offset,
        encryption.chunk_size_bytes,
        Some(max_bytes),
    )
    .await?;

    let was_overwrite = guard
        .commit(
            sink,
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

    // A PUT to a brand-new bucket implicitly creates it; record the writer as
    // its owner so subsequent access is governed by ownership/ACL.
    if matches!(decision, Decision::ClaimOwnership) {
        claim_ownership(&storage, &bucket, &auth.username).await?;
    }

    if was_overwrite {
        Ok(HttpResponse::Ok().finish())
    } else {
        Ok(HttpResponse::Created().finish())
    }
}

/// Parse the optional `X-Y2Q-Sync` request header into a [`SyncLevel`].
///
/// Falls back to `default` when the header is absent. Accepts `durable` or
/// `best-effort`. Any other value returns 400.
fn parse_sync_header(req: &HttpRequest, default: SyncLevel) -> Result<SyncLevel, AppError> {
    let Some(raw) = req.headers().get("x-y2q-sync") else {
        return Ok(default);
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
