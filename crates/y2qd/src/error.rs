//! HTTP error mapping for [`y2q_core::Error`].

use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde::Serialize;
use utoipa::ToSchema;
use y2q_core::Error as CoreError;

/// JSON body returned for all error responses: `{"error": "<message>"}`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    /// Human-readable description of the error.
    pub error: String,
}

/// Newtype wrapper around [`y2q_core::Error`] that implements actix-web's
/// [`ResponseError`], mapping each core error variant to an appropriate HTTP
/// status code and a JSON body of the form `{"error": "<message>"}`.
///
/// | Core error variant      | HTTP status |
/// |-------------------------|-------------|
/// | `NotFound`              | 404         |
/// | `InvalidBucket`         | 400         |
/// | `InvalidKey`            | 400         |
/// | `ReservedLabel`         | 400         |
/// | `InvalidLabelValue`     | 400         |
/// | `LabelNameTooLong`      | 400         |
/// | `LabelValueTooLong`     | 400         |
/// | `TooManyLabels`             | 400         |
/// | `InvalidStaleLockThreshold` | 400         |
/// | `Locked`                    | 409         |
/// | `RebuildAlreadyRunning`     | 409         |
/// | `Index`                     | 500         |
/// | `InternalError`             | 500         |
#[derive(Debug)]
pub struct AppError(pub CoreError);

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<CoreError> for AppError {
    fn from(e: CoreError) -> Self {
        AppError(e)
    }
}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match &self.0 {
            CoreError::NotFound { .. } => StatusCode::NOT_FOUND,
            CoreError::InvalidBucket { .. }
            | CoreError::InvalidKey { .. }
            | CoreError::ReservedLabel { .. }
            | CoreError::InvalidLabelValue { .. }
            | CoreError::LabelNameTooLong { .. }
            | CoreError::LabelValueTooLong { .. }
            | CoreError::TooManyLabels { .. }
            | CoreError::InvalidStaleLockThreshold { .. } => StatusCode::BAD_REQUEST,
            CoreError::Locked { .. } | CoreError::RebuildAlreadyRunning => StatusCode::CONFLICT,
            CoreError::Index { .. } | CoreError::InternalError { .. } => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        HttpResponse::build(status).json(ErrorBody {
            error: self.to_string(),
        })
    }
}
