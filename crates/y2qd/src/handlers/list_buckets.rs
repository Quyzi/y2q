//! `GET /` — enumerate every bucket that contains at least one object.

use std::sync::Arc;

use actix_web::{HttpResponse, web};
use serde::Serialize;
use utoipa::ToSchema;
use y2q_core::{AnyStorage, Listing};

use crate::error::{AppError, ErrorBody};

/// Response body for `GET /`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListBucketsResponse {
    /// All bucket names, sorted ascending.
    pub buckets: Vec<String>,
}

/// List all buckets that contain at least one object.
#[utoipa::path(
    get,
    operation_id = "list_buckets",
    path = "/",
    responses(
        (status = 200, description = "Sorted list of bucket names", body = ListBucketsResponse, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    tag = "listing",
)]
pub async fn handle(storage: web::Data<Arc<AnyStorage>>) -> Result<HttpResponse, AppError> {
    let buckets = storage.list_buckets().await.map_err(AppError::from)?;
    Ok(HttpResponse::Ok().json(ListBucketsResponse { buckets }))
}
