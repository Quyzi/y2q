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

use y2q_core::crypto::DecryptedKeystore;

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
    /// Hashed token id (used to look up / revoke this session).
    pub token_hash: [u8; 32],
    /// Decrypted keypair held in process memory. Cheap to clone — `Arc`.
    pub keystore: Arc<DecryptedKeystore>,
}

impl FromRequest for Authenticated {
    type Error = AuthError;
    type Future = Ready<Result<Self, AuthError>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(extract_authenticated(req))
    }
}

fn extract_authenticated(req: &HttpRequest) -> Result<Authenticated, AuthError> {
    let state = req
        .app_data::<actix_web::web::Data<AuthState>>()
        .ok_or(AuthError::InternalState)?;

    let token = parse_bearer(req)?;
    let token_hash = session::hash_token(&token);
    let session = state.sessions.get_active(&token_hash)?;
    let keystore = state
        .keystore
        .current()
        .ok_or(AuthError::KeystoreUnavailable)?;
    Ok(Authenticated {
        username: session.username.clone(),
        token_hash,
        keystore,
    })
}

fn parse_bearer(req: &HttpRequest) -> Result<String, AuthError> {
    let header = req
        .headers()
        .get(header::AUTHORIZATION)
        .ok_or(AuthError::TokenMissing)?;
    let raw = header.to_str().map_err(|_| AuthError::TokenInvalid)?;
    let trimmed = raw.trim();
    let (scheme, token) = trimmed
        .split_once(' ')
        .ok_or(AuthError::TokenInvalid)?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(AuthError::TokenInvalid);
    }
    let token = token.trim();
    if token.is_empty() {
        return Err(AuthError::TokenMissing);
    }
    Ok(token.to_owned())
}
