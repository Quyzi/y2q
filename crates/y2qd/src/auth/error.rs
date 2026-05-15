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
            AuthError::LockedOut { .. } => StatusCode::TOO_MANY_REQUESTS,
            AuthError::TtlOutOfRange { .. }
            | AuthError::InvalidUsername { .. }
            | AuthError::InvalidBody { .. } => StatusCode::BAD_REQUEST,
            AuthError::UserExists { .. } | AuthError::CannotDeleteLastUser => StatusCode::CONFLICT,
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
        builder.json(ErrorBody {
            error: self.to_string(),
        })
    }
}
