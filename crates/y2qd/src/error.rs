//! HTTP error mapping for [`y2q_core::Error`] and [`crate::auth::AuthError`].

use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde::Serialize;
use utoipa::ToSchema;
use y2q_core::Error as CoreError;

use crate::auth::AuthError;

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
/// | Core error variant            | HTTP status |
/// |-------------------------------|-------------|
/// | `NotFound`                    | 404         |
/// | `InvalidBucket`               | 400         |
/// | `InvalidKey`                  | 400         |
/// | `ReservedLabel`               | 400         |
/// | `InvalidLabelValue`           | 400         |
/// | `LabelNameTooLong`            | 400         |
/// | `LabelValueTooLong`           | 400         |
/// | `TooManyLabels`               | 400         |
/// | `InvalidStaleLockThreshold`   | 400         |
/// | `Locked`                      | 409         |
/// | `RebuildAlreadyRunning`       | 409         |
/// | `Index`                       | 500         |
/// | `InternalError`               | 500         |
/// | `KdfFailed`                   | 500         |
/// | `EncryptionFailed`            | 500         |
/// | `DecryptionFailed`            | 500 (generic body) |
/// | `EnvelopeMalformed`           | 500 (generic body) |
/// | `UnsupportedEnvelopeVersion`  | 500         |
/// | `KeystoreNotFound`            | 503         |
/// | `KeystoreCorrupt`             | 500         |
/// | `RangeReadOnEncrypted`        | 501         |
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

impl From<AuthError> for AppError {
    fn from(_: AuthError) -> Self {
        // AuthError is normally returned directly by handlers/extractors —
        // this conversion exists only so handlers that use `?` against a
        // mixed result type compile. The real surface is AuthError's own
        // ResponseError impl below.
        AppError(CoreError::InternalError {
            bucket: String::new(),
            key: String::new(),
            operation: "auth".to_owned(),
            message: "auth error".to_owned(),
        })
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
            CoreError::Index { .. }
            | CoreError::InternalError { .. }
            | CoreError::KdfFailed { .. }
            | CoreError::EncryptionFailed { .. }
            | CoreError::DecryptionFailed { .. }
            | CoreError::EnvelopeMalformed { .. }
            | CoreError::UnsupportedEnvelopeVersion { .. }
            | CoreError::KeystoreCorrupt { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            CoreError::KeystoreNotFound { .. } => StatusCode::SERVICE_UNAVAILABLE,
            CoreError::RangeReadOnEncrypted => StatusCode::NOT_IMPLEMENTED,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        // For decryption / envelope errors we deliberately return a generic
        // message — the underlying `reason` may distinguish a tag mismatch
        // from a malformed header, which is a side channel about disk state.
        let body = match &self.0 {
            CoreError::DecryptionFailed { .. } => ErrorBody {
                error: "decryption failed".to_owned(),
            },
            CoreError::EnvelopeMalformed { .. } => ErrorBody {
                error: "object format error".to_owned(),
            },
            _ => ErrorBody {
                error: self.to_string(),
            },
        };
        HttpResponse::build(status).json(body)
    }
}
