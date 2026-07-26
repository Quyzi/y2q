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

    /// `DELETE /api/v1/users/{user}` for a user who is the sole grantee
    /// (real or decoy — any username present as a key at all) of one or
    /// more buckets' newest key epoch: deleting them would strand those
    /// buckets — their identity (and any real bucket-key grant sealed to
    /// it) becomes unrecoverable, so nobody could ever grant new access
    /// again, even though existing objects stay readable to whoever
    /// already holds a live grant. Pass `?force=true` to delete anyway.
    #[error("user is the only key holder for bucket(s): {}", buckets.join(", "))]
    CannotDeleteSoleGrantee { buckets: Vec<String> },

    /// A role change would demote the only administrator, locking everyone out
    /// of admin endpoints.
    #[error("cannot demote the last remaining administrator")]
    CannotDemoteLastAdmin,

    /// A role string was not one of the recognized roles.
    #[error("invalid role: {role}")]
    InvalidRole { role: String },

    /// Username failed validation (empty, too long, illegal chars).
    #[error("invalid username: {reason}")]
    InvalidUsername { reason: &'static str },

    /// Body could not be parsed as JSON or fields missing.
    #[error("invalid request body: {reason}")]
    InvalidBody { reason: String },

    /// `POST /api/v1/personas` for a slot outside `1..=3`, or
    /// `DELETE /api/v1/personas/{slot}` for slot 0.
    #[error("invalid persona slot: {reason}")]
    InvalidPersonaSlot { reason: &'static str },

    /// `POST /api/v1/personas` with a role exceeding the account's own
    /// global role.
    #[error("persona role must not exceed the account's global role")]
    RoleExceedsAccount,

    /// `POST /api/v1/personas` with a password that already opens one of
    /// the caller's four credential slots.
    #[error("that password already opens one of your credential slots")]
    PasswordReused,

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
            | AuthError::InvalidPersonaSlot { .. }
            | AuthError::RoleExceedsAccount
            | AuthError::InvalidBody { .. } => StatusCode::BAD_REQUEST,
            AuthError::UserExists { .. }
            | AuthError::CannotDeleteLastUser
            | AuthError::CannotDeleteLastAdmin
            | AuthError::CannotDemoteLastAdmin
            | AuthError::CannotDeleteSoleGrantee { .. }
            | AuthError::PasswordReused => StatusCode::CONFLICT,
            AuthError::UserNotFound { .. } => StatusCode::NOT_FOUND,
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
                AuthError::CannotDeleteSoleGrantee {
                    buckets: vec!["b".into()],
                },
                S::CONFLICT,
            ),
            (
                AuthError::UserNotFound {
                    username: "u".into(),
                },
                S::NOT_FOUND,
            ),
            (AuthError::Backend("e".into()), S::INTERNAL_SERVER_ERROR),
            (AuthError::InternalState, S::INTERNAL_SERVER_ERROR),
            (
                AuthError::InvalidPersonaSlot { reason: "bad" },
                S::BAD_REQUEST,
            ),
            (AuthError::RoleExceedsAccount, S::BAD_REQUEST),
            (AuthError::PasswordReused, S::CONFLICT),
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
