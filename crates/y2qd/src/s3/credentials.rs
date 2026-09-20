//! `POST/GET/DELETE /api/v1/s3/credentials` — mint, list, and revoke
//! temporary S3 SigV4 credentials bound to the caller's live session.
//!
//! No S3 credential can outlive the session that minted it: [`mint`] clamps
//! the requested expiry to the session's own `expires_at`, and every S3
//! request re-resolves the credential's `token_hash` through
//! `SessionStore::get_active` (see `crate::s3::auth`) before trusting it —
//! logout, expiry, and revocation on the REST listener therefore kill S3
//! access immediately too.

use actix_web::{HttpResponse, web};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use y2q_core::secmem::SecretString;
use zeroize::Zeroizing;

use crate::auth::session::compute_expiry;
use crate::auth::{AuthError, AuthState, Authenticated};
use crate::s3::state::S3State;

/// `POST /api/v1/s3/credentials` request body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct MintRequest {
    /// Requested credential lifetime in seconds. Always clamped to the
    /// caller's own session expiry, whichever is sooner. Omit to use
    /// `[s3] default_credential_ttl_seconds`.
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

/// `POST /api/v1/s3/credentials` response body. `secret_access_key` is
/// returned exactly once and is not recoverable afterwards.
#[derive(Debug, Serialize, ToSchema)]
pub struct MintResponse {
    pub access_key_id: String,
    #[schema(value_type = String)]
    pub secret_access_key: SecretString,
    pub region: String,
    /// Unix seconds. Never later than the owning session's own expiry.
    pub expires_at: u64,
    /// Unix seconds at which the owning session expires.
    pub session_expires_at: u64,
}

/// One row in `GET /api/v1/s3/credentials`. Never carries a secret.
#[derive(Debug, Serialize, ToSchema)]
pub struct CredentialView {
    pub access_key_id: String,
    pub created_at: u64,
    pub expires_at: u64,
}

/// `GET /api/v1/s3/credentials` response body.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListCredentialsResponse {
    pub credentials: Vec<CredentialView>,
}

fn to_unix(t: std::time::SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Owner passed to `Bytes::from_owner` so the mint response (the only one
/// here carrying a fresh secret) is zeroized once actix drops it after
/// writing the socket. Mirrors `auth::handlers::ScrubbedBody`, which does
/// the same for `POST /api/v1/auth/login`'s bearer token.
struct ScrubbedBody(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for ScrubbedBody {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// `POST /api/v1/s3/credentials` — mint a temporary S3 credential bound to
/// the caller's current session.
#[utoipa::path(
    post,
    path = "/api/v1/s3/credentials",
    request_body = MintRequest,
    responses(
        (status = 200, description = "Credential minted", body = MintResponse, content_type = "application/json"),
        (status = 400, description = "ttl_seconds out of range"),
        (status = 401, description = "Authentication required"),
    ),
    security(("bearer" = [])),
    tag = "s3",
)]
pub async fn mint(
    body: Option<web::Json<MintRequest>>,
    s3: web::Data<S3State>,
    state: web::Data<AuthState>,
    auth: Authenticated,
) -> Result<HttpResponse, AuthError> {
    let requested = body.and_then(|b| b.into_inner().ttl_seconds);
    let expires_at = compute_expiry(
        requested,
        s3.config.default_credential_ttl_seconds,
        state.config.max_ttl_seconds,
    )?
    .min(auth.session.expires_at);

    let (access_key_id, secret_access_key) =
        s3.credentials
            .mint(auth.token_hash, &auth.username, expires_at)?;

    let resp = MintResponse {
        access_key_id,
        secret_access_key,
        region: s3.config.region.clone(),
        expires_at: to_unix(expires_at),
        session_expires_at: to_unix(auth.session.expires_at),
    };
    let mut body = Zeroizing::new(Vec::with_capacity(256));
    serde_json::to_writer(&mut *body, &resp).map_err(|e| AuthError::Backend(e.to_string()))?;
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(Bytes::from_owner(ScrubbedBody(body))))
}

/// `GET /api/v1/s3/credentials` — list the caller's own live credentials.
/// Never returns a secret.
#[utoipa::path(
    get,
    path = "/api/v1/s3/credentials",
    responses(
        (status = 200, description = "Credentials for the caller's session", body = ListCredentialsResponse),
        (status = 401, description = "Authentication required"),
    ),
    security(("bearer" = [])),
    tag = "s3",
)]
pub async fn list(s3: web::Data<S3State>, auth: Authenticated) -> Result<HttpResponse, AuthError> {
    let credentials = s3
        .credentials
        .list_for_session(&auth.token_hash)
        .into_iter()
        .map(|c| CredentialView {
            access_key_id: c.access_key_id.clone(),
            created_at: to_unix(c.created_at),
            expires_at: to_unix(c.expires_at),
        })
        .collect();
    Ok(HttpResponse::Ok().json(ListCredentialsResponse { credentials }))
}

/// `DELETE /api/v1/s3/credentials/{access_key_id}` — revoke one of the
/// caller's own credentials. Returns the same "invalid credential" 403 for
/// an unknown id and for one owned by a different session, so the endpoint
/// cannot be used to enumerate other sessions' access key ids.
#[utoipa::path(
    delete,
    path = "/api/v1/s3/credentials/{access_key_id}",
    params(("access_key_id" = String, Path, description = "Access key id to revoke")),
    responses(
        (status = 204, description = "Credential revoked"),
        (status = 403, description = "Unknown or not owned by the caller"),
    ),
    security(("bearer" = [])),
    tag = "s3",
)]
pub async fn revoke(
    path: web::Path<String>,
    s3: web::Data<S3State>,
    auth: Authenticated,
) -> Result<HttpResponse, AuthError> {
    let access_key_id = path.into_inner();
    let cred = s3
        .credentials
        .get(&access_key_id)
        .ok_or(AuthError::S3CredentialUnknown)?;
    if cred.token_hash != auth.token_hash {
        return Err(AuthError::S3CredentialUnknown);
    }
    s3.credentials.remove(&access_key_id);
    Ok(HttpResponse::NoContent().finish())
}
