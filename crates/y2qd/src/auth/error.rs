//! Authentication error type with HTTP status mapping.
//!
//! `InvalidCredentials` is deliberately generic — the HTTP body never says
//! whether the username was unknown or the password was wrong. Both forms
//! return 401 with the same message.

use actix_web::{HttpResponse, ResponseError, http::StatusCode, http::header};
use std::time::SystemTime;

use crate::error::ErrorBody;

/// Errors returned by the auth layer.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Username doesn't exist or password is wrong. Generic on purpose.
    #[error("invalid credentials")]
    InvalidCredentials,

    /// `Authorization` header was absent.
    #[error("authentication required")]
    TokenMissing,

    /// Header was present but not a recognizable `Bearer <token>` value.
    #[error("invalid authentication token")]
    TokenInvalid,

    /// Token was found but its expiry has passed.
    #[error("authentication token expired")]
    TokenExpired,

    /// Caller is authenticated but lacks the global admin role required for
    /// this endpoint.
    #[error("administrator privileges required")]
    Forbidden,

    /// The account has been disabled by an administrator.
    #[error("account disabled")]
    AccountDisabled,

    /// Caller requested a session lifetime greater than `auth.max_ttl_seconds`.
    #[error("ttl_seconds out of range (max {max})")]
    TtlOutOfRange { max: u64 },

    /// Account has too many recent failed logins; locked until `until`.
    #[error("account locked until {until:?}")]
    LockedOut { until: SystemTime },

    /// `PUT /api/v1/users/add` for a username that already exists.
    #[error("user already exists: {username}")]
    UserExists { username: String },

    /// Admin endpoint targeting a user that isn't in the store.
    #[error("user not found: {username}")]
    UserNotFound { username: String },

    /// `DELETE /api/v1/users/{user}` for the sole remaining user.
    #[error("cannot delete last remaining user")]
    CannotDeleteLastUser,

    /// `DELETE /api/v1/users/{user}` would remove the only administrator,
    /// locking everyone out of admin endpoints.
    #[error("cannot delete the last remaining administrator")]
    CannotDeleteLastAdmin,

    /// A role change would demote the only administrator, locking everyone out
    /// of admin endpoints.
    #[error("cannot demote the last remaining administrator")]
    CannotDemoteLastAdmin,

    /// A role string was not one of the recognized roles.
    #[error("invalid role: {role}")]
    InvalidRole { role: String },

    /// Caller hit a protected endpoint before any user has logged in
    /// since the daemon started, so the SK isn't available in memory.
    #[error("keystore unavailable: no active session has unlocked it")]
    KeystoreUnavailable,

    /// Username failed validation (empty, too long, illegal chars).
    #[error("invalid username: {reason}")]
    InvalidUsername { reason: &'static str },

    /// Body could not be parsed as JSON or fields missing.
    #[error("invalid request body: {reason}")]
    InvalidBody { reason: String },

    /// Wrapped y2q-core error from the underlying user store / crypto.
    #[error("auth backend error: {0}")]
    Backend(String),

    /// `web::Data<AuthState>` was not registered. Programmer error.
    #[error("internal: auth state not configured")]
    InternalState,
}

impl ResponseError for AuthError {
    fn status_code(&self) -> StatusCode {
        match self {
            AuthError::InvalidCredentials
            | AuthError::TokenMissing
            | AuthError::TokenInvalid
            | AuthError::TokenExpired => StatusCode::UNAUTHORIZED,
            AuthError::Forbidden | AuthError::AccountDisabled => StatusCode::FORBIDDEN,
            AuthError::LockedOut { .. } => StatusCode::TOO_MANY_REQUESTS,
            AuthError::TtlOutOfRange { .. }
            | AuthError::InvalidUsername { .. }
            | AuthError::InvalidRole { .. }
            | AuthError::InvalidBody { .. } => StatusCode::BAD_REQUEST,
            AuthError::UserExists { .. }
            | AuthError::CannotDeleteLastUser
            | AuthError::CannotDeleteLastAdmin
            | AuthError::CannotDemoteLastAdmin => StatusCode::CONFLICT,
            AuthError::UserNotFound { .. } => StatusCode::NOT_FOUND,
            AuthError::KeystoreUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            AuthError::Backend(_) | AuthError::InternalState => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let mut builder = HttpResponse::build(self.status_code());
        match self {
            AuthError::TokenMissing | AuthError::TokenInvalid | AuthError::TokenExpired => {
                builder.insert_header((header::WWW_AUTHENTICATE, "Bearer realm=\"y2qd\""));
            }
            AuthError::LockedOut { until } => {
                if let Ok(d) = until.duration_since(SystemTime::now()) {
                    builder.insert_header((header::RETRY_AFTER, d.as_secs().to_string()));
                }
            }
            _ => {}
        }
        // `Backend` wraps raw underlying-store error text (reachable even
        // pre-auth, via login) — log it server-side and return a generic
        // message instead of the raw detail.
        let message = match self {
            AuthError::Backend(detail) => {
                tracing::error!(error = %detail, "auth backend error");
                "internal error".to_owned()
            }
            other => other.to_string(),
        };
        builder.json(ErrorBody { error: message })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_code_mapping() {
        use StatusCode as S;
        let cases: Vec<(AuthError, S)> = vec![
            (AuthError::InvalidCredentials, S::UNAUTHORIZED),
            (AuthError::TokenMissing, S::UNAUTHORIZED),
            (AuthError::TokenInvalid, S::UNAUTHORIZED),
            (AuthError::TokenExpired, S::UNAUTHORIZED),
            (AuthError::Forbidden, S::FORBIDDEN),
            (AuthError::AccountDisabled, S::FORBIDDEN),
            (AuthError::CannotDemoteLastAdmin, S::CONFLICT),
            (AuthError::InvalidRole { role: "x".into() }, S::BAD_REQUEST),
            (
                AuthError::LockedOut {
                    until: SystemTime::now(),
                },
                S::TOO_MANY_REQUESTS,
            ),
            (AuthError::TtlOutOfRange { max: 10 }, S::BAD_REQUEST),
            (AuthError::InvalidUsername { reason: "bad" }, S::BAD_REQUEST),
            (
                AuthError::InvalidBody { reason: "x".into() },
                S::BAD_REQUEST,
            ),
            (
                AuthError::UserExists {
                    username: "u".into(),
                },
                S::CONFLICT,
            ),
            (AuthError::CannotDeleteLastUser, S::CONFLICT),
            (AuthError::CannotDeleteLastAdmin, S::CONFLICT),
            (
                AuthError::UserNotFound {
                    username: "u".into(),
                },
                S::NOT_FOUND,
            ),
            (AuthError::KeystoreUnavailable, S::SERVICE_UNAVAILABLE),
            (AuthError::Backend("e".into()), S::INTERNAL_SERVER_ERROR),
            (AuthError::InternalState, S::INTERNAL_SERVER_ERROR),
        ];
        for (err, code) in cases {
            assert_eq!(err.status_code(), code, "{err:?}");
        }
    }

    #[test]
    fn backend_error_body_does_not_leak_raw_detail() {
        let err = AuthError::Backend("open /var/lib/y2q/users.redb: permission denied".into());
        let resp = err.error_response();
        let body = actix_web::body::to_bytes(resp.into_body());
        let body = futures::executor::block_on(body).unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(!text.contains("/var/lib/y2q"));
        assert!(text.contains("internal error"));
    }
}
