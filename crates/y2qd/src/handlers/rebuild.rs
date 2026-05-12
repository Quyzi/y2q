//! `POST /_admin/rebuild` and `GET /_admin/rebuild` — kick off and poll a
//! secondary-index rebuild.
//!
//! Rebuild is fire-and-forget. `POST` returns 202 once the background task is
//! spawned; concurrent kick-offs while one is running return 409. `GET` returns
//! the current state.

use std::sync::Arc;

use actix_web::{HttpResponse, web};
use serde::Serialize;
use utoipa::ToSchema;
use y2q_core::{CacheRebuildStatus, FilesystemStorage, StorageExt};

use crate::error::{AppError, ErrorBody};

/// JSON body for `GET /_admin/rebuild`.
///
/// `state` is one of `idle`, `running`, `completed`, or `failed`. `percent` is
/// present when `state == "running"`. `reason` is present when
/// `state == "failed"`.
#[derive(Debug, Serialize, ToSchema)]
pub struct RebuildStatusResponse {
    /// Current rebuild state: `idle`, `running`, `completed`, or `failed`.
    pub state: &'static str,
    /// Percent complete (0..=100). Only present while running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent: Option<u8>,
    /// Short human description of the failure. Only present after a failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl From<CacheRebuildStatus> for RebuildStatusResponse {
    fn from(status: CacheRebuildStatus) -> Self {
        match status {
            CacheRebuildStatus::Idle => Self {
                state: "idle",
                percent: None,
                reason: None,
            },
            CacheRebuildStatus::Running(p) => Self {
                state: "running",
                percent: Some(p),
                reason: None,
            },
            CacheRebuildStatus::Completed => Self {
                state: "completed",
                percent: None,
                reason: None,
            },
            CacheRebuildStatus::Failed(r) => Self {
                state: "failed",
                percent: None,
                reason: Some(r),
            },
        }
    }
}

/// Body returned by `POST /_admin/rebuild` when a rebuild is successfully
/// kicked off.
#[derive(Debug, Serialize, ToSchema)]
pub struct RebuildStartResponse {
    /// Always `"running"`.
    pub status: &'static str,
}

/// Start a secondary-index rebuild in the background.
#[utoipa::path(
    post,
    operation_id = "start_rebuild",
    path = "/_admin/rebuild",
    responses(
        (status = 202, description = "Rebuild started", body = RebuildStartResponse, content_type = "application/json"),
        (status = 409, description = "Rebuild already in progress", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    tag = "admin",
)]
pub async fn start(storage: web::Data<Arc<FilesystemStorage>>) -> Result<HttpResponse, AppError> {
    storage.rebuild_cache().await.map_err(AppError::from)?;
    Ok(HttpResponse::Accepted().json(RebuildStartResponse { status: "running" }))
}

/// Query the current state of the secondary-index rebuild.
#[utoipa::path(
    get,
    operation_id = "rebuild_status",
    path = "/_admin/rebuild",
    responses(
        (status = 200, description = "Current rebuild state", body = RebuildStatusResponse, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    tag = "admin",
)]
pub async fn status(storage: web::Data<Arc<FilesystemStorage>>) -> Result<HttpResponse, AppError> {
    let s = storage.rebuild_progress().await.map_err(AppError::from)?;
    Ok(HttpResponse::Ok().json(RebuildStatusResponse::from(s)))
}
