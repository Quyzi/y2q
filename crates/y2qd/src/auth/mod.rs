//! User authentication, session storage, and the `Authenticated` extractor.
//!
//! Sessions live entirely in memory ([`SessionStore`]) and are forgotten on
//! restart. The deployment secret key is held in a process-wide
//! [`KeystoreSlot`] that the first successful login populates and that empties
//! again when the last session expires (with an optional grace period).
//!
//! Every protected handler takes an [`Authenticated`] extractor parameter;
//! the extractor parses the `Authorization: Bearer <token>` header, looks up
//! the token's SHA-256 hash in the session store, validates expiry, and
//! attaches the user identity + decrypted keystore to the request.

pub mod error;
pub mod handlers;
pub mod keystore;
pub mod session;
pub mod state;
pub mod users;

pub use error::AuthError;
pub use state::AuthState;

use actix_web::{FromRequest, HttpRequest, dev::Payload, http::header};
use std::future::{Ready, ready};
use std::sync::Arc;

use y2q_core::crypto::{DecryptedKeystore, Role};

/// Identity attached to a successfully-authenticated request.
///
/// Acquired via the [`actix_web::FromRequest`] impl: handlers that require
/// auth simply add an `Authenticated` parameter and the framework calls into
/// the extractor for them. Handlers that intentionally don't require auth
/// (login, refresh-with-token, the metrics dashboard when
/// `unauthenticated_metrics = true`) just leave the parameter out.
#[derive(Clone)]
pub struct Authenticated {
    /// Username from the user record this session was minted under.
    pub username: String,
    /// Global role captured at login. Admins bypass per-bucket ACLs and may
    /// call admin endpoints.
    pub role: Role,
    /// Hashed token id (used to look up / revoke this session).
    pub token_hash: [u8; 32],
    /// Decrypted keypair held in process memory. Cheap to clone — `Arc`.
    pub keystore: Arc<DecryptedKeystore>,
    /// Whether bucket ownership/ACL and the admin role are enforced
    /// (`[auth] enforce_authorization`). When `false`, [`crate::authz`] and
    /// [`AdminAuthenticated`] short-circuit to allow.
    pub authz_enforced: bool,
}

impl Authenticated {
    /// Whether this caller holds the global admin role (and authorization is
    /// being enforced — when it is not, every caller is effectively admin).
    pub fn is_admin(&self) -> bool {
        !self.authz_enforced || self.role == Role::Admin
    }

    /// Whether this caller may use admin *read* endpoints (user list, rebuild
    /// status, lock list, trace): a full admin or an auditor (or anyone when
    /// authorization is not enforced).
    pub fn is_admin_or_auditor(&self) -> bool {
        !self.authz_enforced || matches!(self.role, Role::Admin | Role::Auditor)
    }
}

impl FromRequest for Authenticated {
    type Error = AuthError;
    type Future = Ready<Result<Self, AuthError>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(extract_authenticated(req))
    }
}

/// Like [`Authenticated`] but the extractor rejects non-admin callers with
/// 403 (unless `[auth] enforce_authorization = false`). Declared by handlers
/// that must be restricted to global administrators.
#[derive(Clone)]
pub struct AdminAuthenticated(pub Authenticated);

impl FromRequest for AdminAuthenticated {
    type Error = AuthError;
    type Future = Ready<Result<Self, AuthError>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(extract_authenticated(req).and_then(|auth| {
            if auth.is_admin() {
                Ok(AdminAuthenticated(auth))
            } else {
                Err(AuthError::Forbidden)
            }
        }))
    }
}

/// Guard extractor for admin *read* endpoints: admits full administrators and
/// auditors (or anyone when authorization is not enforced). Used purely to gate
/// access — it carries no identity, unlike [`AdminAuthenticated`]. The mutating
/// admin endpoints use [`AdminAuthenticated`] instead.
pub struct AdminReadAuthenticated;

impl FromRequest for AdminReadAuthenticated {
    type Error = AuthError;
    type Future = Ready<Result<Self, AuthError>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(extract_authenticated(req).and_then(|auth| {
            if auth.is_admin_or_auditor() {
                Ok(AdminReadAuthenticated)
            } else {
                Err(AuthError::Forbidden)
            }
        }))
    }
}

fn extract_authenticated(req: &HttpRequest) -> Result<Authenticated, AuthError> {
    let state = req
        .app_data::<actix_web::web::Data<AuthState>>()
        .ok_or(AuthError::InternalState)?;

    let token = parse_bearer(req)?;
    let token_hash = session::hash_token(&token);
    let session = state.sessions.get_active(&token_hash)?;
    // A user disabled mid-session is rejected immediately (a role change also
    // revokes their sessions, so this is belt-and-suspenders).
    if state.config.enforce_authorization && session.role == Role::Disabled {
        return Err(AuthError::AccountDisabled);
    }
    let keystore = state
        .keystore
        .current()
        .ok_or(AuthError::KeystoreUnavailable)?;
    Ok(Authenticated {
        username: session.username.clone(),
        role: session.role,
        token_hash,
        keystore,
        authz_enforced: state.config.enforce_authorization,
    })
}

fn parse_bearer(req: &HttpRequest) -> Result<String, AuthError> {
    let header = req
        .headers()
        .get(header::AUTHORIZATION)
        .ok_or(AuthError::TokenMissing)?;
    let raw = header.to_str().map_err(|_| AuthError::TokenInvalid)?;
    let trimmed = raw.trim();
    let (scheme, token) = trimmed.split_once(' ').ok_or(AuthError::TokenInvalid)?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(AuthError::TokenInvalid);
    }
    let token = token.trim();
    if token.is_empty() {
        return Err(AuthError::TokenMissing);
    }
    Ok(token.to_owned())
}
