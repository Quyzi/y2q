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
/// | `Forbidden`                   | 403         |
/// | `InvalidAcl`                  | 400         |
/// | `Index`                       | 500 (generic body) |
/// | `InternalError`               | 500 (generic body) |
/// | `KdfFailed`                   | 500 (generic body) |
/// | `EncryptionFailed`            | 500         |
/// | `DecryptionFailed`            | 500 (generic body) |
/// | `EnvelopeMalformed`           | 500 (generic body) |
/// | `UnsupportedEnvelopeVersion`  | 500         |
/// | `KeystoreNotFound`            | 503         |
/// | `KeystoreCorrupt`             | 500 (generic body) |
/// | `Query`                       | 400         |
/// | `BodyTooLarge`                | 413         |
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
            | CoreError::Query { .. }
            | CoreError::InvalidAcl { .. }
            | CoreError::InvalidStaleLockThreshold { .. } => StatusCode::BAD_REQUEST,
            CoreError::Locked { .. } | CoreError::RebuildAlreadyRunning => StatusCode::CONFLICT,
            CoreError::Forbidden { .. } => StatusCode::FORBIDDEN,
            CoreError::QuotaExceeded { .. } | CoreError::BodyTooLarge { .. } => {
                StatusCode::PAYLOAD_TOO_LARGE
            }
            CoreError::Index { .. }
            | CoreError::InternalError { .. }
            | CoreError::KdfFailed { .. }
            | CoreError::EncryptionFailed { .. }
            | CoreError::DecryptionFailed { .. }
            | CoreError::EnvelopeMalformed { .. }
            | CoreError::UnsupportedEnvelopeVersion { .. }
            | CoreError::KeystoreCorrupt { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            CoreError::KeystoreNotFound { .. } => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        // For decryption / envelope errors we deliberately return a generic
        // message — the underlying `reason` may distinguish a tag mismatch
        // from a malformed header, which is a side channel about disk state.
        // Internal/backend errors carry raw OS or storage-backend detail
        // (filesystem paths, redb error text) that's useful for an operator
        // but not for a client — log it server-side and return a generic
        // body instead of echoing it back.
        let body = match &self.0 {
            CoreError::DecryptionFailed { .. } => ErrorBody {
                error: "decryption failed".to_owned(),
            },
            CoreError::EnvelopeMalformed { .. } => ErrorBody {
                error: "object format error".to_owned(),
            },
            CoreError::Index { .. }
            | CoreError::InternalError { .. }
            | CoreError::KdfFailed { .. }
            | CoreError::KeystoreCorrupt { .. } => {
                tracing::error!(error = %self.0, "internal error");
                ErrorBody {
                    error: "internal error".to_owned(),
                }
            }
            _ => ErrorBody {
                error: self.to_string(),
            },
        };
        HttpResponse::build(status).json(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body_text(err: &AppError) -> String {
        let resp = err.error_response();
        let bytes =
            futures::executor::block_on(actix_web::body::to_bytes(resp.into_body())).unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn internal_error_body_does_not_leak_raw_detail() {
        let err = AppError(CoreError::InternalError {
            bucket: "b".to_owned(),
            key: "k".to_owned(),
            operation: "open".to_owned(),
            message: "/var/lib/y2q/secret/path: permission denied".to_owned(),
        });
        let text = body_text(&err);
        assert!(!text.contains("/var/lib/y2q"));
        assert!(text.contains("internal error"));
    }

    #[test]
    fn keystore_corrupt_body_does_not_leak_raw_path() {
        let err = AppError(CoreError::KeystoreCorrupt {
            path: "/var/lib/y2q/keystore/pubkey.json".to_owned(),
            reason: "bad length".to_owned(),
        });
        let text = body_text(&err);
        assert!(!text.contains("/var/lib/y2q"));
        assert!(text.contains("internal error"));
    }

    #[test]
    fn not_found_body_is_still_specific() {
        // Only internal/backend-detail variants get genericized — everything
        // else keeps its normal, already-safe message.
        let err = AppError(CoreError::NotFound {
            bucket: "b".to_owned(),
            key: "k".to_owned(),
        });
        let text = body_text(&err);
        assert!(text.contains("b") && text.contains("k"));
    }
}
