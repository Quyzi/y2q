//! HTTP handlers under `/api/v1/auth/*` and `/api/v1/users/*`.
//!
//! All handlers here run user-supplied passwords through Argon2id, which is
//! intentionally CPU-bound. To avoid blocking the actix worker we run the
//! KDF on `tokio::task::spawn_blocking`.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use actix_web::{HttpResponse, web};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use y2q_core::crypto::{DecryptedKeystore, Role, UserRecord, UserSummary, kdf};

use super::error::AuthError;
use super::session::{SessionInfo, compute_expiry};
use super::state::AuthState;
use super::users::validate as validate_username;
use super::{AdminAuthenticated, AdminReadAuthenticated, Authenticated};

/// Parse a role name (case-insensitive) into a [`Role`], with a clean 400 on a
/// bad value rather than a raw JSON deserialization error.
fn parse_role(s: &str) -> Result<Role, AuthError> {
    match s.to_ascii_lowercase().as_str() {
        "admin" => Ok(Role::Admin),
        "user" => Ok(Role::User),
        "readonly" => Ok(Role::ReadOnly),
        "writeonly" => Ok(Role::WriteOnly),
        "auditor" => Ok(Role::Auditor),
        "disabled" => Ok(Role::Disabled),
        _ => Err(AuthError::InvalidRole { role: s.to_owned() }),
    }
}

fn record_login(result_label: &'static str, session_count: Option<usize>) {
    metrics::counter!(
        crate::observability::AUTH_LOGINS_TOTAL,
        "result" => result_label
    )
    .increment(1);
    if let Some(n) = session_count {
        metrics::gauge!(crate::observability::SESSIONS_ACTIVE).set(n as f64);
    }
}

/// `POST /api/v1/auth/login` request body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    /// Optional session lifetime in seconds. Capped by `auth.max_ttl_seconds`.
    /// Omit to use `auth.default_ttl_seconds`.
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

/// Successful response from `POST /api/v1/auth/login` and `POST /api/v1/auth/refresh`.
#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    /// Bearer token. Send back as `Authorization: Bearer <token>`.
    pub token: String,
    /// Expiry as seconds since the Unix epoch.
    pub expires_at: u64,
    /// Username this token is bound to.
    pub username: String,
}

/// `POST /api/v1/auth/password` request body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    pub current: String,
    pub new: String,
}

/// `PUT /api/v1/users/add` request body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddUserRequest {
    pub username: String,
    pub password: String,
    /// Global role for the new user. Defaults to `user`. Only an administrator
    /// can reach this endpoint, so only an administrator can mint another admin.
    #[serde(default)]
    #[schema(value_type = String, example = "user")]
    pub role: Role,
}

/// `PUT /api/v1/users/{user}/role` request body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetRoleRequest {
    /// New global role: `admin`, `user`, `readonly`, `writeonly`, `auditor`, or
    /// `disabled`.
    pub role: String,
}

/// `GET /api/v1/users` response body.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListUsersResponse {
    pub users: Vec<UserView>,
}

/// One row in the user list. Excludes any cryptographic material.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserView {
    pub username: String,
    pub created_at: u64,
    pub last_login: Option<u64>,
    /// Global role: `"admin"` or `"user"`.
    #[schema(value_type = String, example = "user")]
    pub role: Role,
}

impl From<UserSummary> for UserView {
    fn from(s: UserSummary) -> Self {
        Self {
            username: s.username,
            created_at: s.created_at,
            last_login: s.last_login,
            role: s.role,
        }
    }
}

/// `POST /api/v1/auth/login` — validate credentials, mint a session.
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Session created", body = TokenResponse, content_type = "application/json"),
        (status = 400, description = "ttl_seconds out of range or username malformed"),
        (status = 401, description = "Invalid credentials"),
        (status = 429, description = "Account locked out"),
    ),
    tag = "auth",
)]
#[tracing::instrument(skip(state, body), fields(username = %body.username))]
pub async fn login(
    state: web::Data<AuthState>,
    body: web::Json<LoginRequest>,
) -> Result<HttpResponse, AuthError> {
    let username = body.username.clone();
    let password = body.password.clone();
    let ttl_request = body.ttl_seconds;

    // Validate format BEFORE the lockout check so we don't leak whether
    // a malformed-username login is locked vs not.
    validate_username(&username)?;

    // Lockout check (per-username, post-Argon2 floor).
    {
        let mut attempts = state.login_attempts.lock().unwrap();
        if let Err(until) = attempts.check_lockout(&username) {
            record_login("locked", None);
            return Err(AuthError::LockedOut {
                until: SystemTime::now()
                    + until.saturating_duration_since(std::time::Instant::now()),
            });
        }
    }

    let started = std::time::Instant::now();
    let expires_at = compute_expiry(
        ttl_request,
        state.config.default_ttl_seconds,
        state.config.max_ttl_seconds,
    )?;

    // Look up the user record. Treat "not found" as "wrong creds" so we
    // don't disclose user existence.
    let record = state
        .user_store
        .get(&username)
        .map_err(|e| AuthError::Backend(e.to_string()))?;

    let not_found = record.is_none();
    let result = match record {
        Some(rec) => attempt_unwrap(rec, password.clone()).await,
        None => {
            // Run the Argon2id unwrap against a throwaway record so an unknown
            // username costs the same KDF work as a wrong password — otherwise
            // login response time is a username-existence oracle. The result is
            // discarded; this branch always reports invalid credentials.
            let _ = attempt_unwrap(state.dummy_record.clone(), password.clone()).await;
            Err(AuthError::InvalidCredentials)
        }
    };

    match result {
        Ok((rec, sk)) => {
            // A disabled account authenticates but may not obtain a session.
            if rec.role == Role::Disabled {
                record_login("disabled", None);
                apply_floor(state.config.min_login_response_ms, started).await;
                return Err(AuthError::AccountDisabled);
            }
            // Successful auth — derive and install the MEK from the unwrapped
            // secret key (gates metadata encryption on login), then install SK
            // if absent and mint session.
            state.install_mek_from_sk(&sk);
            let pk = state.public_keystore.clone();
            let ks = Arc::new(DecryptedKeystore::new(pk, sk));
            state.keystore.install(ks);

            let info = SessionInfo {
                username: rec.username.clone(),
                role: rec.role,
                created_at: SystemTime::now(),
                expires_at,
            };
            let token = state.sessions.insert(info);
            record_login("success", Some(state.sessions.len()));

            // Update last_login + reset failure counter.
            let mut updated = rec.clone();
            updated.last_login = Some(now_ns());
            if let Err(e) = state.user_store.upsert(&updated) {
                tracing::warn!(error = %e, "failed to persist last_login update");
            }
            state
                .login_attempts
                .lock()
                .unwrap()
                .record_success(&username);

            // Enforce min response time floor.
            apply_floor(state.config.min_login_response_ms, started).await;

            Ok(HttpResponse::Ok().json(TokenResponse {
                token: token.0,
                expires_at: expires_at
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                username: rec.username,
            }))
        }
        Err(e) => {
            let result_label = if not_found {
                "not_found"
            } else {
                "wrong_password"
            };
            record_login(result_label, None);
            state.login_attempts.lock().unwrap().record_failure(
                &username,
                state.config.max_failed_logins,
                Duration::from_secs(state.config.lockout_seconds),
            );
            apply_floor(state.config.min_login_response_ms, started).await;
            Err(e)
        }
    }
}

/// `POST /api/v1/auth/refresh` — present a valid token, get a fresh one.
/// The old token is revoked.
#[utoipa::path(
    post,
    path = "/api/v1/auth/refresh",
    responses(
        (status = 200, description = "Fresh token", body = TokenResponse, content_type = "application/json"),
        (status = 401, description = "Token missing/invalid/expired"),
    ),
    tag = "auth",
)]
#[tracing::instrument(skip(state, auth), fields(username = %auth.username))]
pub async fn refresh(
    state: web::Data<AuthState>,
    auth: Authenticated,
) -> Result<HttpResponse, AuthError> {
    let expires_at = compute_expiry(
        None,
        state.config.default_ttl_seconds,
        state.config.max_ttl_seconds,
    )?;
    let info = SessionInfo {
        username: auth.username.clone(),
        role: auth.role,
        created_at: SystemTime::now(),
        expires_at,
    };
    let token = state.sessions.insert(info);
    state.sessions.revoke(&auth.token_hash);
    Ok(HttpResponse::Ok().json(TokenResponse {
        token: token.0,
        expires_at: expires_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        username: auth.username,
    }))
}

/// `POST /api/v1/auth/logout` — revoke the caller's session.
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    responses(
        (status = 204, description = "Logged out"),
        (status = 401, description = "Token missing/invalid"),
    ),
    tag = "auth",
)]
#[tracing::instrument(skip(state, auth), fields(username = %auth.username))]
pub async fn logout(
    state: web::Data<AuthState>,
    auth: Authenticated,
) -> Result<HttpResponse, AuthError> {
    state.sessions.revoke(&auth.token_hash);
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /api/v1/auth/password` — change the caller's password (re-wrap SK).
#[utoipa::path(
    post,
    path = "/api/v1/auth/password",
    request_body = ChangePasswordRequest,
    responses(
        (status = 204, description = "Password changed"),
        (status = 401, description = "Current password did not verify, or token invalid"),
    ),
    tag = "auth",
)]
#[tracing::instrument(skip(state, auth, body), fields(username = %auth.username))]
pub async fn change_password(
    state: web::Data<AuthState>,
    auth: Authenticated,
    body: web::Json<ChangePasswordRequest>,
) -> Result<HttpResponse, AuthError> {
    let username = auth.username.clone();
    let current = body.current.clone();
    let new = body.new.clone();
    if new.is_empty() {
        return Err(AuthError::InvalidBody {
            reason: "new password must not be empty".to_owned(),
        });
    }

    let rec = state
        .user_store
        .get(&username)
        .map_err(|e| AuthError::Backend(e.to_string()))?
        .ok_or(AuthError::InvalidCredentials)?;
    let (rec, sk) = attempt_unwrap(rec, current).await?;

    let new_params = state.new_argon2_params();
    let wrap_params = new_params.clone();
    let wrapped =
        tokio::task::spawn_blocking(move || kdf::wrap_sk(&sk, new.as_bytes(), &wrap_params))
            .await
            .map_err(|e| AuthError::Backend(format!("kdf join: {e}")))?
            .map_err(|e| AuthError::Backend(e.to_string()))?;

    let updated = UserRecord {
        username: rec.username.clone(),
        created_at: rec.created_at,
        last_login: rec.last_login,
        kdf: new_params,
        wrapped_sk: wrapped,
        role: rec.role,
    };
    state
        .user_store
        .upsert(&updated)
        .map_err(|e| AuthError::Backend(e.to_string()))?;
    Ok(HttpResponse::NoContent().finish())
}

/// `PUT /api/v1/users/add` — wrap the SK from the active session under a new
/// user's password and persist the record.
#[utoipa::path(
    put,
    path = "/api/v1/users/add",
    request_body = AddUserRequest,
    responses(
        (status = 201, description = "User created"),
        (status = 400, description = "Invalid username or empty password"),
        (status = 401, description = "Token missing/invalid"),
        (status = 409, description = "Username already exists"),
    ),
    tag = "users",
)]
#[tracing::instrument(skip(state, auth, body), fields(actor = %auth.0.username, new_user = %body.username))]
pub async fn add_user(
    state: web::Data<AuthState>,
    auth: AdminAuthenticated,
    body: web::Json<AddUserRequest>,
) -> Result<HttpResponse, AuthError> {
    let auth = auth.0;
    let username = body.username.clone();
    let password = body.password.clone();
    let role = body.role;
    validate_username(&username)?;
    if password.is_empty() {
        return Err(AuthError::InvalidBody {
            reason: "password must not be empty".to_owned(),
        });
    }

    if state
        .user_store
        .get(&username)
        .map_err(|e| AuthError::Backend(e.to_string()))?
        .is_some()
    {
        return Err(AuthError::UserExists { username });
    }

    let sk_bytes = auth.keystore.secret_key.to_vec();
    let params = state.new_argon2_params();
    let wrap_params = params.clone();
    let wrapped = tokio::task::spawn_blocking(move || {
        kdf::wrap_sk(&sk_bytes, password.as_bytes(), &wrap_params)
    })
    .await
    .map_err(|e| AuthError::Backend(format!("kdf join: {e}")))?
    .map_err(|e| AuthError::Backend(e.to_string()))?;

    let record = UserRecord {
        username: username.clone(),
        created_at: now_ns(),
        last_login: None,
        kdf: params,
        wrapped_sk: wrapped,
        role,
    };
    state
        .user_store
        .upsert(&record)
        .map_err(|e| AuthError::Backend(e.to_string()))?;
    Ok(HttpResponse::Created().finish())
}

/// `GET /api/v1/users` — list all users (no secret material).
#[utoipa::path(
    get,
    path = "/api/v1/users",
    responses(
        (status = 200, description = "User list", body = ListUsersResponse, content_type = "application/json"),
        (status = 401, description = "Token missing/invalid"),
    ),
    tag = "users",
)]
#[tracing::instrument(skip(state, _auth))]
pub async fn list_users(
    state: web::Data<AuthState>,
    _auth: AdminReadAuthenticated,
) -> Result<HttpResponse, AuthError> {
    let users = state
        .user_store
        .list()
        .map_err(|e| AuthError::Backend(e.to_string()))?;
    Ok(HttpResponse::Ok().json(ListUsersResponse {
        users: users.into_iter().map(UserView::from).collect(),
    }))
}

/// `DELETE /api/v1/users/{user}` — remove a user record. Refuses if it would
/// leave zero users.
#[utoipa::path(
    delete,
    path = "/api/v1/users/{user}",
    params(
        ("user" = String, Path, description = "Username to delete"),
    ),
    responses(
        (status = 204, description = "User deleted"),
        (status = 401, description = "Token missing/invalid"),
        (status = 404, description = "User not found"),
        (status = 409, description = "Cannot delete the last remaining user"),
    ),
    tag = "users",
)]
#[tracing::instrument(skip(state, auth), fields(actor = %auth.0.username, target = %path))]
pub async fn delete_user(
    state: web::Data<AuthState>,
    auth: AdminAuthenticated,
    path: web::Path<String>,
) -> Result<HttpResponse, AuthError> {
    let _ = &auth;
    let username = path.into_inner();
    let users = state
        .user_store
        .list()
        .map_err(|e| AuthError::Backend(e.to_string()))?;
    if users.len() <= 1 {
        return Err(AuthError::CannotDeleteLastUser);
    }
    // Refuse to remove the final administrator, which would lock everyone out
    // of admin endpoints (user management, rebuild, locks, trace).
    let target_is_admin = users
        .iter()
        .any(|u| u.username == username && u.role == Role::Admin);
    if target_is_admin && users.iter().filter(|u| u.role == Role::Admin).count() <= 1 {
        return Err(AuthError::CannotDeleteLastAdmin);
    }
    let removed = state
        .user_store
        .delete(&username)
        .map_err(|e| AuthError::Backend(e.to_string()))?;
    if !removed {
        return Err(AuthError::UserNotFound { username });
    }
    Ok(HttpResponse::NoContent().finish())
}

/// `PUT /api/v1/users/{user}/role` — change a user's global role. Admin only.
///
/// Setting `disabled` suspends the account. The change takes effect immediately:
/// the target's existing sessions are revoked, so it does not wait for session
/// expiry. Refuses to demote the only remaining administrator.
#[utoipa::path(
    put,
    path = "/api/v1/users/{user}/role",
    request_body = SetRoleRequest,
    params(("user" = String, Path, description = "Username whose role to change")),
    responses(
        (status = 204, description = "Role updated"),
        (status = 400, description = "Invalid role"),
        (status = 401, description = "Token missing/invalid"),
        (status = 403, description = "Caller is not an admin"),
        (status = 404, description = "User not found"),
        (status = 409, description = "Would demote the last remaining administrator"),
    ),
    tag = "users",
)]
#[tracing::instrument(skip(state, auth, body), fields(actor = %auth.0.username, target = %path))]
pub async fn set_role(
    state: web::Data<AuthState>,
    auth: AdminAuthenticated,
    path: web::Path<String>,
    body: web::Json<SetRoleRequest>,
) -> Result<HttpResponse, AuthError> {
    let _ = &auth;
    let username = path.into_inner();
    let new_role = parse_role(&body.role)?;

    let mut rec = state
        .user_store
        .get(&username)
        .map_err(|e| AuthError::Backend(e.to_string()))?
        .ok_or_else(|| AuthError::UserNotFound {
            username: username.clone(),
        })?;

    // Don't demote the only administrator.
    if rec.role == Role::Admin && new_role != Role::Admin {
        let admin_count = state
            .user_store
            .list()
            .map_err(|e| AuthError::Backend(e.to_string()))?
            .iter()
            .filter(|u| u.role == Role::Admin)
            .count();
        if admin_count <= 1 {
            return Err(AuthError::CannotDemoteLastAdmin);
        }
    }

    rec.role = new_role;
    state
        .user_store
        .upsert(&rec)
        .map_err(|e| AuthError::Backend(e.to_string()))?;
    // Apply immediately rather than at session expiry.
    state.sessions.revoke_user(&username);
    Ok(HttpResponse::NoContent().finish())
}

/// Run Argon2id-unwrap on a worker thread (CPU-bound).
async fn attempt_unwrap(
    rec: UserRecord,
    password: String,
) -> Result<(UserRecord, Vec<u8>), AuthError> {
    let params = rec.kdf.clone();
    let wrapped = rec.wrapped_sk.clone();
    let sk_result =
        tokio::task::spawn_blocking(move || kdf::unwrap_sk(&wrapped, password.as_bytes(), &params))
            .await
            .map_err(|e| AuthError::Backend(format!("kdf join: {e}")))?;
    match sk_result {
        Ok(sk) => Ok((rec, sk)),
        Err(_) => Err(AuthError::InvalidCredentials),
    }
}

/// Make sure failed-login responses take at least `floor_ms` to send.
async fn apply_floor(floor_ms: u64, started: std::time::Instant) {
    let elapsed = started.elapsed();
    let floor = Duration::from_millis(floor_ms);
    if elapsed < floor {
        tokio::time::sleep(floor - elapsed).await;
    }
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
