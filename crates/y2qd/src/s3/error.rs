//! S3 REST error type: wire `Code`, HTTP status, and XML body.
//!
//! Mirrors the security posture of `crate::error::AppError`: internal/backend
//! detail is logged server-side and collapsed to a generic message on the
//! wire (requirement 13 of the S3 gateway security contract — see the S3
//! gateway plan), and decryption/envelope failures never distinguish "wrong
//! key" from "corrupt data" in the response body.

use actix_web::http::StatusCode;
use actix_web::{HttpMessage, HttpRequest, HttpResponse, ResponseError};
use y2q_core::Error as CoreError;

use crate::auth::AuthError;
use crate::error::AppError;
use crate::request_id::RequestIdExt;
use crate::s3::sigv4::SigV4Error;
use crate::s3::xml;

/// An S3 REST error: wire `Code`, HTTP status, message, and the resource
/// path the error concerns (S3 convention: `/bucket/key`).
#[derive(Debug, Clone)]
pub struct S3Error {
    pub code: &'static str,
    pub status: StatusCode,
    pub message: String,
    pub resource: String,
    pub request_id: String,
}

impl S3Error {
    pub fn new(code: &'static str, status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            code,
            status,
            message: message.into(),
            resource: String::new(),
            request_id: generate_request_id(),
        }
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = request_id.into();
        self
    }

    /// Read the daemon's own per-request id (set by
    /// `request_id::request_id_middleware`, shared with the REST listener)
    /// off `req`'s extensions, falling back to a fresh one if absent.
    pub fn request_id_from(req: &HttpRequest) -> String {
        req.extensions()
            .get::<RequestIdExt>()
            .map(|r| r.0.clone())
            .unwrap_or_else(generate_request_id)
    }

    pub fn no_such_bucket() -> Self {
        Self::new(
            "NoSuchBucket",
            StatusCode::NOT_FOUND,
            "The specified bucket does not exist.",
        )
    }

    pub fn no_such_key() -> Self {
        Self::new(
            "NoSuchKey",
            StatusCode::NOT_FOUND,
            "The specified key does not exist.",
        )
    }

    pub fn no_such_upload() -> Self {
        Self::new(
            "NoSuchUpload",
            StatusCode::NOT_FOUND,
            "The specified multipart upload does not exist.",
        )
    }

    pub fn access_denied(message: impl Into<String>) -> Self {
        Self::new("AccessDenied", StatusCode::FORBIDDEN, message)
    }

    pub fn invalid_access_key_id() -> Self {
        Self::new(
            "InvalidAccessKeyId",
            StatusCode::FORBIDDEN,
            "The access key id you provided does not exist.",
        )
    }

    pub fn expired_token(message: impl Into<String>) -> Self {
        Self::new("ExpiredToken", StatusCode::BAD_REQUEST, message)
    }

    pub fn signature_does_not_match() -> Self {
        Self::new(
            "SignatureDoesNotMatch",
            StatusCode::FORBIDDEN,
            "The request signature we calculated does not match the signature you provided.",
        )
    }

    pub fn authorization_header_malformed(message: impl Into<String>) -> Self {
        Self::new(
            "AuthorizationHeaderMalformed",
            StatusCode::BAD_REQUEST,
            message,
        )
    }

    pub fn request_time_too_skewed() -> Self {
        Self::new(
            "RequestTimeTooSkewed",
            StatusCode::FORBIDDEN,
            "The difference between the request time and the current time is too large.",
        )
    }

    pub fn x_amz_content_sha256_mismatch() -> Self {
        Self::new(
            "XAmzContentSHA256Mismatch",
            StatusCode::BAD_REQUEST,
            "The provided 'x-amz-content-sha256' header does not match what was computed.",
        )
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new("InvalidArgument", StatusCode::BAD_REQUEST, message)
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new("InvalidRequest", StatusCode::BAD_REQUEST, message)
    }

    pub fn malformed_xml(message: impl Into<String>) -> Self {
        Self::new("MalformedXML", StatusCode::BAD_REQUEST, message)
    }

    pub fn not_implemented(message: impl Into<String>) -> Self {
        Self::new("NotImplemented", StatusCode::NOT_IMPLEMENTED, message)
    }

    pub fn internal_error() -> Self {
        Self::new(
            "InternalError",
            StatusCode::INTERNAL_SERVER_ERROR,
            "We encountered an internal error. Please try again.",
        )
    }
}

/// 32-character lowercase-hex id, matching
/// `request_id::request_id_middleware`'s own fallback shape.
fn generate_request_id() -> String {
    use rand::RngExt;
    format!("{:032x}", rand::rng().random::<u128>())
}

impl std::fmt::Display for S3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for S3Error {}

impl ResponseError for S3Error {
    fn status_code(&self) -> StatusCode {
        self.status
    }

    fn error_response(&self) -> HttpResponse {
        let mut body = String::with_capacity(160 + self.message.len() + self.resource.len());
        xml::header(&mut body);
        body.push_str("<Error>");
        xml::tag(&mut body, "Code", self.code);
        xml::tag(&mut body, "Message", &self.message);
        xml::tag(&mut body, "Resource", &self.resource);
        xml::tag(&mut body, "RequestId", &self.request_id);
        body.push_str("</Error>");
        HttpResponse::build(self.status)
            .content_type("application/xml")
            .insert_header(("x-amz-request-id", self.request_id.clone()))
            .body(body)
    }
}

/// Maps a core storage/crypto error onto its S3 wire equivalent.
///
/// Every 500-mapped variant collapses to the fixed `InternalError` message
/// and logs the real detail server-side — mirroring `AppError`'s own
/// suppression — so a probe cannot distinguish corruption from a wrong key
/// from a filesystem fault.
/// Convenience so a bare `y2q_core::Error` (from `storage.describe`,
/// `bucket_keys::resolve_read_key`, etc.) can `?`-convert straight to
/// `S3Error` without an intermediate `AppError::from` at every call site.
/// Goes through the same mapping table as `From<AppError>`.
impl From<CoreError> for S3Error {
    fn from(err: CoreError) -> Self {
        AppError(err).into()
    }
}

impl From<AppError> for S3Error {
    fn from(err: AppError) -> Self {
        match err.0 {
            CoreError::NotFound { key, .. } if key.is_empty() => S3Error::no_such_bucket(),
            CoreError::NotFound { .. } => S3Error::no_such_key(),
            CoreError::Forbidden { .. } => {
                S3Error::new("AccessDenied", StatusCode::FORBIDDEN, "Access Denied")
            }
            CoreError::InvalidBucket { bucket } => S3Error::new(
                "InvalidBucketName",
                StatusCode::BAD_REQUEST,
                format!("The specified bucket is not valid: {bucket}"),
            ),
            CoreError::InvalidKey { .. } => {
                S3Error::invalid_argument("The specified key is not valid.")
            }
            CoreError::ReservedLabel { .. }
            | CoreError::InvalidLabelValue { .. }
            | CoreError::LabelNameTooLong { .. }
            | CoreError::LabelValueTooLong { .. }
            | CoreError::TooManyLabels { .. } => {
                S3Error::new("InvalidTag", StatusCode::BAD_REQUEST, err.0.to_string())
            }
            CoreError::Locked { .. } => S3Error::new(
                "OperationAborted",
                StatusCode::CONFLICT,
                "A conflicting write is already in progress for this object.",
            ),
            CoreError::QuotaExceeded { .. } => S3Error::new(
                "QuotaExceeded",
                StatusCode::PAYLOAD_TOO_LARGE,
                "The bucket quota would be exceeded by this request.",
            ),
            CoreError::BodyTooLarge { limit, .. } => S3Error::new(
                "EntityTooLarge",
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("Your proposed upload exceeds the maximum allowed size ({limit} bytes)."),
            ),
            CoreError::InvalidAcl { reason }
            | CoreError::InvalidPersonaRequest { reason }
            | CoreError::Query { message: reason }
            | CoreError::InvalidStaleLockThreshold { value: reason } => {
                S3Error::invalid_request(reason)
            }
            CoreError::TooManyBucketKeyEpochs { .. } | CoreError::RekeyAlreadyRunning { .. } => {
                S3Error::new(
                    "OperationAborted",
                    StatusCode::CONFLICT,
                    "A conflicting operation is already in progress for this bucket.",
                )
            }
            CoreError::RebuildAlreadyRunning => S3Error::new(
                "OperationAborted",
                StatusCode::CONFLICT,
                "A conflicting administrative operation is already in progress.",
            ),
            CoreError::KeystoreNotFound { .. } => S3Error::new(
                "ServiceUnavailable",
                StatusCode::SERVICE_UNAVAILABLE,
                "Please reduce your request rate.",
            ),
            other @ (CoreError::Index { .. }
            | CoreError::InternalError { .. }
            | CoreError::KdfFailed { .. }
            | CoreError::EncryptionFailed { .. }
            | CoreError::DecryptionFailed { .. }
            | CoreError::EnvelopeMalformed { .. }
            | CoreError::UnsupportedEnvelopeVersion { .. }
            | CoreError::KeystoreCorrupt { .. }) => {
                tracing::error!(error = %other, "internal error");
                S3Error::internal_error()
            }
        }
    }
}

/// Maps a session/credential error onto its S3 wire equivalent. See the S3
/// gateway plan's security contract: every variant here either kills the
/// credential (expiry/revocation) or refuses the signature outright, never
/// silently downgrading to a weaker check.
impl From<AuthError> for S3Error {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::TokenExpired | AuthError::TokenInvalid => {
                S3Error::expired_token("The provided token has expired.")
            }
            AuthError::TokenMissing => S3Error::access_denied("Access Denied"),
            AuthError::Forbidden | AuthError::AccountDisabled => {
                S3Error::access_denied("Access Denied")
            }
            AuthError::S3CredentialUnknown => S3Error::invalid_access_key_id(),
            other => {
                tracing::error!(error = %other, "internal auth error on S3 gateway");
                S3Error::internal_error()
            }
        }
    }
}

impl From<SigV4Error> for S3Error {
    fn from(err: SigV4Error) -> Self {
        match err {
            SigV4Error::NoCredentials => S3Error::access_denied("Access Denied"),
            SigV4Error::MalformedHeader
            | SigV4Error::MalformedScope
            | SigV4Error::MissingHostHeader => {
                S3Error::authorization_header_malformed(err.to_string())
            }
            SigV4Error::UnsupportedAlgorithm => {
                S3Error::authorization_header_malformed("Unsupported signing algorithm.")
            }
            SigV4Error::MalformedDate | SigV4Error::MalformedExpires => {
                S3Error::authorization_header_malformed(err.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_with_empty_key_maps_to_no_such_bucket() {
        let e: S3Error = AppError(CoreError::NotFound {
            bucket: "b".to_owned(),
            key: String::new(),
        })
        .into();
        assert_eq!(e.code, "NoSuchBucket");
        assert_eq!(e.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn not_found_with_key_maps_to_no_such_key() {
        let e: S3Error = AppError(CoreError::NotFound {
            bucket: "b".to_owned(),
            key: "k".to_owned(),
        })
        .into();
        assert_eq!(e.code, "NoSuchKey");
    }

    #[test]
    fn internal_errors_collapse_to_generic_message() {
        let e: S3Error = AppError(CoreError::DecryptionFailed {
            bucket: "b".to_owned(),
            key: "k".to_owned(),
        })
        .into();
        assert_eq!(e.code, "InternalError");
        assert_eq!(e.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!e.message.contains("b/k"));
    }

    #[test]
    fn forbidden_maps_to_access_denied_403() {
        let e: S3Error = AppError(CoreError::Forbidden {
            bucket: "b".to_owned(),
        })
        .into();
        assert_eq!(e.code, "AccessDenied");
        assert_eq!(e.status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn error_response_body_is_well_formed_xml_with_all_fields() {
        let e = S3Error::no_such_key().with_request_id("test-request-id");
        let resp = e.error_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
