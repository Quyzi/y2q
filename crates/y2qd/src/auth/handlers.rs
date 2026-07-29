//! HTTP handlers under `/api/v1/auth/*` and `/api/v1/users/*`.
//!
//! All handlers here run user-supplied passwords through Argon2id, which is
//! intentionally CPU-bound. To avoid blocking the actix worker we run the
//! KDF on `tokio::task::spawn_blocking`.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use actix_web::{HttpResponse, web};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use y2q_core::crypto::{
    CREDENTIAL_SLOTS, CredentialSlot, Role, SlotPayload, UserRecord, UserSummary, kdf,
};
use y2q_core::{AnyStorage, BucketConfig, Listing};
use zeroize::Zeroizing;

use super::error::AuthError;
use super::session::{SessionInfo, compute_expiry};
use super::state::AuthState;
use super::users::validate as validate_username;
use super::{AdminAuthenticated, AdminReadAuthenticated, Authenticated};
use crate::bucket_keys;
use crate::cluster::{self, ClusterRuntime};

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
        Ok((rec, slot_idx, payload)) => {
            // A disabled persona authenticates but may not obtain a session.
            if payload.role == Role::Disabled {
                record_login("disabled", None);
                apply_floor(state.config.min_login_response_ms, started).await;
                return Err(AuthError::AccountDisabled);
            }
            let identity_sk = STANDARD
                .decode(&payload.identity_sk_b64)
                .map_err(|e| AuthError::Backend(format!("decode identity sk: {e}")))?;
            let identity_sk = Zeroizing::new(identity_sk);

            let info = SessionInfo::new(
                rec.username.clone(),
                payload.role,
                SystemTime::now(),
                expires_at,
                slot_idx as u8,
                payload.revoke_other_sessions,
                identity_sk.clone(),
            );
            let token = state.sessions.insert(info);
            record_login("success", Some(state.sessions.len()));

            // A duress-flagged persona silently takes over every other live
            // session on this account, in place — no revocation, no alert,
            // no log line distinguishing it from an ordinary login. Whoever
            // holds one of those tokens keeps working exactly as before,
            // just now scoped to the duress persona's own access, rather
            // than visibly losing their session (a dead session is itself
            // a tell that something happened).
            if payload.revoke_other_sessions {
                state.sessions.switch_user_to_persona(
                    &rec.username,
                    slot_idx as u8,
                    payload.role,
                    payload.revoke_other_sessions,
                    &identity_sk,
                );
            }

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
    let info = SessionInfo::new(
        auth.username.clone(),
        auth.role,
        SystemTime::now(),
        expires_at,
        auth.session.persona,
        auth.session.revoke_other_sessions,
        auth.session.identity_sk.clone(),
    );
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
#[tracing::instrument(skip(state, cluster, auth, body), fields(username = %auth.username))]
pub async fn change_password(
    state: web::Data<AuthState>,
    cluster: Option<web::Data<ClusterRuntime>>,
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
    let (rec, slot_idx, payload) = attempt_unwrap(rec, current).await?;

    // Re-wrap ONLY this slot, under the record's EXISTING salt (a fresh salt
    // would invalidate the other three slots' KEK derivation, since all four
    // share one Argon2Params). Every other slot, and every persona's grants,
    // are untouched — changing a duress password must not disturb the real
    // one and vice versa.
    let params = rec.kdf.clone();
    let username_for_aad = rec.username.clone();
    let new_password = new.clone();
    let identity_pk_b64 = rec.slots[slot_idx].identity_pk_b64.clone();
    let new_slot = tokio::task::spawn_blocking(move || {
        let payload_bytes = payload.to_bytes()?;
        let aad = kdf::slot_wrap_aad(&username_for_aad, slot_idx);
        let wrapped = kdf::wrap_slot(&payload_bytes, new_password.as_bytes(), &params, &aad)?;
        Ok::<CredentialSlot, y2q_core::crypto::CryptoError>(CredentialSlot {
            identity_pk_b64,
            wrapped,
        })
    })
    .await
    .map_err(|e| AuthError::Backend(format!("kdf join: {e}")))?
    .map_err(|e| AuthError::Backend(e.to_string()))?;

    let mut updated = rec.clone();
    updated.slots[slot_idx] = new_slot;
    // Clustered: replicate the re-wrapped record through raft; local otherwise.
    if let Some(rt) = cluster.as_ref() {
        cluster::cluster_upsert_user(rt, state.get_ref(), &updated).await?;
    } else {
        state
            .user_store
            .upsert(&updated)
            .map_err(|e| AuthError::Backend(e.to_string()))?;
    }
    Ok(HttpResponse::NoContent().finish())
}

/// `PUT /api/v1/users/add` — admin-only: create a user with a brand-new,
/// independent identity keypair wrapped under the given password, at a
/// slot position chosen uniformly at random (never a fixed index — see
/// `UserRecord::primary_slot`), plus decoys in the other three. Unrelated
/// to the caller's own identity: this does not require the caller's
/// session to hold any bucket access, only the `admin` role.
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
#[tracing::instrument(skip(state, cluster, auth, body), fields(actor = %auth.0.username, new_user = %body.username))]
pub async fn add_user(
    state: web::Data<AuthState>,
    cluster: Option<web::Data<ClusterRuntime>>,
    auth: AdminAuthenticated,
    body: web::Json<AddUserRequest>,
) -> Result<HttpResponse, AuthError> {
    let _ = &auth;
    let username = body.username.clone();
    let password = body.password.clone();
    let role = body.role;
    validate_username(&username)?;
    if password.is_empty() {
        return Err(AuthError::InvalidBody {
            reason: "password must not be empty".to_owned(),
        });
    }

    // Existence check. Clustered: consult the replicated registry too, so a user
    // created on another node is not silently clobbered (a residual race remains
    // for two truly-simultaneous creates of the same name, last write wins).
    let exists_clustered = match cluster.as_ref() {
        Some(rt) => rt
            .controller
            .control_state()
            .await
            .users
            .contains_key(&username),
        None => false,
    };
    if exists_clustered
        || state
            .user_store
            .get(&username)
            .map_err(|e| AuthError::Backend(e.to_string()))?
            .is_some()
    {
        return Err(AuthError::UserExists { username });
    }

    let params = state.new_argon2_params();
    let username_for_slots = username.clone();
    let (slots, params, primary_slot) = tokio::task::spawn_blocking(move || {
        let (slots, primary_slot) = kdf::new_slots_random(
            &username_for_slots,
            password.as_bytes(),
            &params,
            role,
            false,
        )?;
        Ok::<_, y2q_core::crypto::CryptoError>((slots, params, primary_slot))
    })
    .await
    .map_err(|e| AuthError::Backend(format!("kdf join: {e}")))?
    .map_err(|e| AuthError::Backend(e.to_string()))?;

    let record = UserRecord {
        username: username.clone(),
        created_at: now_ns(),
        last_login: None,
        kdf: params,
        slots,
        primary_slot: primary_slot as u8,
        role,
    };
    if let Some(rt) = cluster.as_ref() {
        cluster::cluster_upsert_user(rt, state.get_ref(), &record).await?;
    } else {
        state
            .user_store
            .upsert(&record)
            .map_err(|e| AuthError::Backend(e.to_string()))?;
    }
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

/// Query params for `DELETE /api/v1/users/{user}`.
#[derive(Debug, Deserialize)]
pub struct DeleteUserQuery {
    /// Skip the bucket-ownership orphan guard and delete anyway.
    #[serde(default)]
    force: bool,
}

/// Buckets where `username` is the *sole* grantee (real or decoy — any
/// username appearing as a key in the newest epoch's `grants` map at all,
/// since a decoy slot only ever gets added as one of an *existing* real
/// grantee's four slots, never as a brand-new map key — see
/// `bucket_keys::seal_grant_slots`) of the newest key epoch: read from the
/// authoritative bucket registry, the replicated control state in a
/// cluster (so every node enforces the guard identically regardless of how
/// far its local filesystem projection has caught up), or the local store
/// single-node. Used by [`delete_user`] to warn before stranding a bucket:
/// once its sole grantee's user record is gone, nobody can ever grant
/// fresh access to it again (existing objects stay readable to whoever
/// already holds a live grant, but the grant list is now frozen). A bucket
/// with no key material yet (never claimed/written to) has nothing to
/// strand and is never included.
async fn sole_grantee_buckets(
    storage: &AnyStorage,
    cluster: Option<&ClusterRuntime>,
    username: &str,
) -> Result<Vec<String>, AuthError> {
    let is_sole_grantee = |cfg: &BucketConfig| -> bool {
        match bucket_keys::current_key(cfg) {
            Some(kv) => kv.grants.len() == 1 && kv.grants.contains_key(username),
            None => false,
        }
    };
    if let Some(rt) = cluster {
        let state = rt.controller.control_state().await;
        return Ok(state
            .buckets
            .into_iter()
            .filter(|(_, cfg)| is_sole_grantee(cfg))
            .map(|(bucket, _)| bucket)
            .collect());
    }
    let buckets = storage
        .list_buckets()
        .await
        .map_err(|e| AuthError::Backend(e.to_string()))?;
    let mut sole = Vec::new();
    for bucket in buckets {
        let cfg = storage
            .get_bucket_config(&bucket)
            .await
            .map_err(|e| AuthError::Backend(e.to_string()))?;
        if is_sole_grantee(&cfg) {
            sole.push(bucket);
        }
    }
    Ok(sole)
}

/// `DELETE /api/v1/users/{user}` — remove a user record. Refuses if it would
/// leave zero users, remove the last administrator, or strand a bucket the
/// user owns (pass `?force=true` to delete anyway).
#[utoipa::path(
    delete,
    path = "/api/v1/users/{user}",
    params(
        ("user" = String, Path, description = "Username to delete"),
        ("force" = Option<bool>, Query, description = "Delete even if it would strand an owned bucket"),
    ),
    responses(
        (status = 204, description = "User deleted"),
        (status = 401, description = "Token missing/invalid"),
        (status = 404, description = "User not found"),
        (status = 409, description = "Cannot delete the last remaining user, the last admin, or (without ?force=true) a bucket owner"),
    ),
    tag = "users",
)]
#[tracing::instrument(skip(state, storage, cluster, auth), fields(actor = %auth.0.username, target = %path))]
pub async fn delete_user(
    state: web::Data<AuthState>,
    storage: web::Data<Arc<AnyStorage>>,
    cluster: Option<web::Data<ClusterRuntime>>,
    auth: AdminAuthenticated,
    path: web::Path<String>,
    query: web::Query<DeleteUserQuery>,
) -> Result<HttpResponse, AuthError> {
    let _ = &auth;
    let username = path.into_inner();

    if !query.force {
        let sole = sole_grantee_buckets(
            storage.get_ref(),
            cluster.as_ref().map(|d| d.get_ref()),
            &username,
        )
        .await?;
        if !sole.is_empty() {
            return Err(AuthError::CannotDeleteSoleGrantee { buckets: sole });
        }
    }

    // (username, role) over the authoritative set: the replicated registry in a
    // cluster (so a freshly-joined node enforces the guards correctly), or the
    // local store single-node.
    let users: Vec<(String, Role)> = match cluster.as_ref() {
        Some(rt) => rt
            .controller
            .control_state()
            .await
            .users
            .values()
            .map(|u| (u.username.clone(), u.role))
            .collect(),
        None => state
            .user_store
            .list()
            .map_err(|e| AuthError::Backend(e.to_string()))?
            .into_iter()
            .map(|u| (u.username, u.role))
            .collect(),
    };

    if users.len() <= 1 {
        return Err(AuthError::CannotDeleteLastUser);
    }
    // Refuse to remove the final administrator, which would lock everyone out
    // of admin endpoints (user management, rebuild, locks, trace).
    let target_is_admin = users
        .iter()
        .any(|(n, r)| n == &username && *r == Role::Admin);
    if target_is_admin && users.iter().filter(|(_, r)| *r == Role::Admin).count() <= 1 {
        return Err(AuthError::CannotDeleteLastAdmin);
    }

    if let Some(rt) = cluster.as_ref() {
        if !users.iter().any(|(n, _)| n == &username) {
            return Err(AuthError::UserNotFound { username });
        }
        cluster::cluster_delete_user(rt, state.get_ref(), &username).await?;
    } else {
        let removed = state
            .user_store
            .delete(&username)
            .map_err(|e| AuthError::Backend(e.to_string()))?;
        if !removed {
            return Err(AuthError::UserNotFound { username });
        }
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
#[tracing::instrument(skip(state, cluster, auth, body), fields(actor = %auth.0.username, target = %path))]
pub async fn set_role(
    state: web::Data<AuthState>,
    cluster: Option<web::Data<ClusterRuntime>>,
    auth: AdminAuthenticated,
    path: web::Path<String>,
    body: web::Json<SetRoleRequest>,
) -> Result<HttpResponse, AuthError> {
    let _ = &auth;
    let username = path.into_inner();
    let new_role = parse_role(&body.role)?;

    // Resolve the target's current role and the admin count from the
    // authoritative set (replicated registry in a cluster, local otherwise).
    let (current_role, admin_count) = match cluster.as_ref() {
        Some(rt) => {
            let users = rt.controller.control_state().await.users;
            let cur = users.get(&username).map(|u| u.role);
            let admins = users.values().filter(|u| u.role == Role::Admin).count();
            (cur, admins)
        }
        None => {
            let cur = state
                .user_store
                .get(&username)
                .map_err(|e| AuthError::Backend(e.to_string()))?
                .map(|u| u.role);
            let admins = state
                .user_store
                .list()
                .map_err(|e| AuthError::Backend(e.to_string()))?
                .iter()
                .filter(|u| u.role == Role::Admin)
                .count();
            (cur, admins)
        }
    };
    let current_role = current_role.ok_or_else(|| AuthError::UserNotFound {
        username: username.clone(),
    })?;

    // Don't demote the only administrator.
    if current_role == Role::Admin && new_role != Role::Admin && admin_count <= 1 {
        return Err(AuthError::CannotDemoteLastAdmin);
    }

    if let Some(rt) = cluster.as_ref() {
        // Replicate the role change; the helper also revokes local sessions and
        // every node revokes on projecting the change.
        cluster::cluster_set_user_role(rt, state.get_ref(), &username, new_role).await?;
    } else {
        let mut rec = state
            .user_store
            .get(&username)
            .map_err(|e| AuthError::Backend(e.to_string()))?
            .ok_or_else(|| AuthError::UserNotFound {
                username: username.clone(),
            })?;
        rec.role = new_role;
        state
            .user_store
            .upsert(&rec)
            .map_err(|e| AuthError::Backend(e.to_string()))?;
        // Apply immediately rather than at session expiry.
        state.sessions.revoke_user(&username);
    }
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /api/v1/users/{user}/reset-identity` request body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ResetIdentityRequest {
    pub password: String,
}

/// `POST /api/v1/users/{user}/reset-identity` response body.
#[derive(Debug, Serialize, ToSchema)]
pub struct ResetIdentityResponse {
    /// Buckets left with zero grantees on their newest key epoch once this
    /// user's (now-unrecoverable) grants were scrubbed.
    pub orphaned_buckets: Vec<String>,
}

/// `POST /api/v1/users/{user}/reset-identity` — the honest replacement for an
/// admin password reset. Rebuilds the target's record with a fresh identity
/// keypair under the supplied password, at a slot position chosen
/// uniformly at random, plus fresh decoys everywhere else, revokes their
/// live sessions, and scrubs every bucket-key grant they held across every
/// bucket — those grants were sealed to the identity public key that just
/// got replaced, so they are unrecoverable garbage the moment this runs,
/// whether or not this endpoint bothers to delete them.
///
/// This restores login. It does not restore access: the target holds no
/// bucket key until someone re-grants their new identity, and the caller
/// (an admin) never touches bucket-key material in the process, so this
/// cannot be used to escalate. It also destroys every persona the user had,
/// including any duress ones — there is no partial reset.
#[utoipa::path(
    post,
    path = "/api/v1/users/{user}/reset-identity",
    request_body = ResetIdentityRequest,
    params(("user" = String, Path, description = "Username to reset")),
    responses(
        (status = 200, description = "Identity reset", body = ResetIdentityResponse, content_type = "application/json"),
        (status = 400, description = "Empty password"),
        (status = 401, description = "Token missing/invalid"),
        (status = 404, description = "User not found"),
    ),
    tag = "users",
)]
#[tracing::instrument(skip(state, storage, cluster, auth, body), fields(actor = %auth.0.username, target = %path))]
pub async fn reset_identity(
    state: web::Data<AuthState>,
    storage: web::Data<Arc<AnyStorage>>,
    cluster: Option<web::Data<ClusterRuntime>>,
    auth: AdminAuthenticated,
    path: web::Path<String>,
    body: web::Json<ResetIdentityRequest>,
) -> Result<HttpResponse, AuthError> {
    let _ = &auth;
    let username = path.into_inner();
    if body.password.is_empty() {
        return Err(AuthError::InvalidBody {
            reason: "password must not be empty".to_owned(),
        });
    }

    let mut rec = match cluster.as_ref() {
        Some(rt) => rt
            .controller
            .control_state()
            .await
            .users
            .get(&username)
            .cloned(),
        None => state
            .user_store
            .get(&username)
            .map_err(|e| AuthError::Backend(e.to_string()))?,
    }
    .ok_or_else(|| AuthError::UserNotFound {
        username: username.clone(),
    })?;

    let password = body.password.clone();
    let username_for_slots = username.clone();
    let role = rec.role;
    let params = rec.kdf.clone();
    let (slots, primary_slot) = tokio::task::spawn_blocking(move || {
        kdf::new_slots_random(
            &username_for_slots,
            password.as_bytes(),
            &params,
            role,
            false,
        )
    })
    .await
    .map_err(|e| AuthError::Backend(format!("kdf join: {e}")))?
    .map_err(|e| AuthError::Backend(e.to_string()))?;
    rec.slots = slots;
    rec.primary_slot = primary_slot as u8;

    if let Some(rt) = cluster.as_ref() {
        cluster::cluster_upsert_user(rt, state.get_ref(), &rec).await?;
    } else {
        state
            .user_store
            .upsert(&rec)
            .map_err(|e| AuthError::Backend(e.to_string()))?;
    }
    // Every live session carries the old (now-replaced) identity secret key.
    state.sessions.revoke_user(&username);

    let orphaned = scrub_user_grants(
        storage.get_ref(),
        cluster.as_ref().map(|d| d.get_ref()),
        &username,
    )
    .await?;

    Ok(HttpResponse::Ok().json(ResetIdentityResponse {
        orphaned_buckets: orphaned,
    }))
}

/// Remove `username`'s grant-map entry from every retained key epoch of
/// every bucket. Their sealed entries are already unrecoverable garbage
/// once [`reset_identity`] replaces their identity keypair — this just
/// keeps `BucketKeyVersion::grants` from accumulating dead rows and reports
/// which buckets' *newest* epoch drops to zero grantees as a result (the
/// caller surfaces that as `orphaned_buckets`).
async fn scrub_user_grants(
    storage: &AnyStorage,
    cluster: Option<&ClusterRuntime>,
    username: &str,
) -> Result<Vec<String>, AuthError> {
    let buckets = match cluster {
        Some(rt) => rt
            .controller
            .control_state()
            .await
            .buckets
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        None => storage
            .list_buckets()
            .await
            .map_err(|e| AuthError::Backend(e.to_string()))?,
    };

    let mut orphaned = Vec::new();
    for bucket in buckets {
        let mut cfg = match cluster {
            Some(rt) => rt
                .controller
                .control_state()
                .await
                .buckets
                .get(&bucket)
                .cloned()
                .unwrap_or_default(),
            None => storage
                .get_bucket_config(&bucket)
                .await
                .map_err(|e| AuthError::Backend(e.to_string()))?,
        };
        let mut changed = false;
        for kv in cfg.keys.iter_mut() {
            if kv.grants.remove(username).is_some() {
                changed = true;
            }
        }
        if !changed {
            continue;
        }
        if let Some(newest) = cfg.keys.last()
            && newest.grants.is_empty()
        {
            orphaned.push(bucket.clone());
        }
        if let Some(rt) = cluster {
            cluster::cluster_set_bucket_config(rt, &bucket, &cfg)
                .await
                .map_err(|e| AuthError::Backend(e.to_string()))?;
        } else {
            storage
                .set_bucket_config(&bucket, &cfg)
                .await
                .map_err(|e| AuthError::Backend(e.to_string()))?;
        }
    }
    Ok(orphaned)
}

/// Run Argon2id-derivation + all-four-slot-unwrap on a worker thread
/// (CPU-bound). Tries every slot's AEAD open regardless of whether an
/// earlier one already matched — timing must not reveal which slot opened
/// or how many of the four are real.
async fn attempt_unwrap(
    rec: UserRecord,
    password: String,
) -> Result<(UserRecord, usize, SlotPayload), AuthError> {
    let params = rec.kdf.clone();
    let slots = rec.slots.clone();
    let username = rec.username.clone();
    let result = tokio::task::spawn_blocking(move || {
        let kek = params.derive_kek(password.as_bytes()).ok()?;
        let mut opened: Option<(usize, SlotPayload)> = None;
        for (i, slot) in slots.iter().enumerate() {
            let aad = kdf::slot_wrap_aad(&username, i);
            if let Ok(payload_bytes) = kdf::unwrap_slot(&slot.wrapped, &kek, &aad)
                && opened.is_none()
                && let Ok(payload) = SlotPayload::from_bytes(&payload_bytes)
            {
                opened = Some((i, payload));
            }
        }
        opened
    })
    .await
    .map_err(|e| AuthError::Backend(format!("kdf join: {e}")))?;
    match result {
        Some((slot, payload)) => Ok((rec, slot, payload)),
        None => Err(AuthError::InvalidCredentials),
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

/// `POST /api/v1/personas` request body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PersonaCreateRequest {
    /// Credential slot to write, `0..CREDENTIAL_SLOTS`. No slot is
    /// privileged from this endpoint's point of view — the account's own
    /// randomly-placed primary slot is protected only because it's always
    /// the slot the caller is currently authenticated through, not because
    /// of its numeric value; see [`create_persona`].
    pub slot: u8,
    pub password: String,
    /// Effective role for sessions opened through this persona. Must not
    /// exceed the account's own global role — enforced server-side, not
    /// merely a UI suggestion.
    #[serde(default)]
    #[schema(value_type = String, example = "user")]
    pub role: Role,
    /// When true, a login through this persona silently switches every
    /// other live session of this account to this persona's identity in
    /// place, rather than revoking them. What makes a persona usable as a
    /// duress slot.
    #[serde(default)]
    pub revoke_other_sessions: bool,
}

/// `POST /api/v1/personas` response body.
#[derive(Debug, Serialize, ToSchema)]
pub struct PersonaCreateResponse {
    /// Always present, regardless of whether the slot held a live persona
    /// before this call — the daemon cannot tell the two apart without
    /// leaking exactly that.
    pub warning: String,
}

/// `GET /api/v1/personas/me` response body. Deliberately omits the
/// account's `revoke_other_sessions` duress flag: reporting it, even only
/// for the caller's own session, would let a technical coercer who queries
/// this endpoint themselves (rather than trusting whatever a victim's CLI
/// told them) read the flag straight off the JSON and know with certainty
/// they'd been handed a duress persona rather than the real one — closing
/// that hole matters more than the minor convenience of a user being able
/// to double-check their own setting via the API.
#[derive(Debug, Serialize, ToSchema)]
pub struct PersonaView {
    pub slot: u8,
    #[schema(value_type = String, example = "user")]
    pub role: Role,
}

/// `POST /api/v1/personas` — write a new persona into the caller's own
/// record at `slot` (`0..CREDENTIAL_SLOTS`), unconditionally overwriting
/// whatever was there — except the slot the caller is *currently*
/// authenticated through (refused outright, to prevent a session from
/// silently invalidating its own login credential) and the account's real
/// `primary_slot` when it differs from the caller's own slot: that write is
/// silently discarded rather than applied, so a duress persona cannot use
/// this endpoint to destroy the account's real identity. The discard is
/// unobservable — same 201, same warning text, same KDF cost paid either
/// way — because a distinguishable response would let a coercer holding
/// only a duress password enumerate the other three slots and read off
/// which one is real from whichever one refuses to change. No slot number
/// otherwise carries any special meaning to this endpoint: each account's
/// real/primary identity lives at a slot chosen uniformly at random on
/// creation (`UserRecord::primary_slot`, never returned by any API), so
/// there is nothing else to hardcode-protect by position. Acts only on the
/// caller's own record: there is no admin route to add a persona for
/// someone else, because such a route would be the first thing a coercer
/// with an admin account would reach for.
#[utoipa::path(
    post,
    path = "/api/v1/personas",
    request_body = PersonaCreateRequest,
    responses(
        (status = 201, description = "Persona written", body = PersonaCreateResponse, content_type = "application/json"),
        (status = 400, description = "Slot out of range, targets the caller's own active slot, role exceeds the account's global role, or empty password"),
        (status = 401, description = "Token missing/invalid"),
        (status = 409, description = "Password already opens one of the caller's credential slots"),
    ),
    security(("bearer" = [])),
    tag = "personas",
)]
#[tracing::instrument(skip(state, auth, body), fields(username = %auth.username))]
pub async fn create_persona(
    state: web::Data<AuthState>,
    auth: Authenticated,
    body: web::Json<PersonaCreateRequest>,
) -> Result<HttpResponse, AuthError> {
    let slot = body.slot as usize;
    if !(0..CREDENTIAL_SLOTS).contains(&slot) {
        return Err(AuthError::InvalidPersonaSlot {
            reason: "slot must be in range 0..CREDENTIAL_SLOTS",
        });
    }
    if slot == auth.session.persona as usize {
        return Err(AuthError::InvalidPersonaSlot {
            reason: "cannot overwrite the slot this session is currently authenticated through",
        });
    }
    if body.password.is_empty() {
        return Err(AuthError::InvalidBody {
            reason: "password must not be empty".to_owned(),
        });
    }
    let role = body.role;

    let rec = state
        .user_store
        .get(&auth.username)
        .map_err(|e| AuthError::Backend(e.to_string()))?
        .ok_or(AuthError::InvalidCredentials)?;

    if !crate::authz::role_permits(role, rec.role) {
        return Err(AuthError::RoleExceedsAccount);
    }

    let username = rec.username.clone();
    let params = rec.kdf.clone();
    let password = body.password.clone();
    let revoke_other_sessions = body.revoke_other_sessions;
    let existing_slots = rec.slots.clone();
    let new_slot = tokio::task::spawn_blocking(
        move || -> Result<Option<CredentialSlot>, y2q_core::crypto::CryptoError> {
            // Password-distinctness: one Argon2 derivation, then try every
            // *current* slot's unwrap without short-circuiting — a reused
            // password must be rejected without timing revealing *which*
            // existing slot it collides with.
            let kek = params.derive_kek(password.as_bytes())?;
            let mut collides = false;
            for (i, s) in existing_slots.iter().enumerate() {
                let aad = kdf::slot_wrap_aad(&username, i);
                if kdf::unwrap_slot(&s.wrapped, &kek, &aad).is_ok() {
                    collides = true;
                }
            }
            if collides {
                return Ok(None);
            }
            let fresh = kdf::new_slot(
                &username,
                slot,
                password.as_bytes(),
                &params,
                role,
                revoke_other_sessions,
            )?;
            Ok(Some(fresh))
        },
    )
    .await
    .map_err(|e| AuthError::Backend(format!("kdf join: {e}")))?
    .map_err(|e| AuthError::Backend(e.to_string()))?
    .ok_or(AuthError::PasswordReused)?;

    let mut updated = rec.clone();
    // Silently no-op against the real primary slot (see the doc comment
    // above) — the response is identical either way.
    if slot != rec.primary_slot as usize {
        updated.slots[slot] = new_slot;
    }
    state
        .user_store
        .upsert(&updated)
        .map_err(|e| AuthError::Backend(e.to_string()))?;

    Ok(HttpResponse::Created().json(PersonaCreateResponse {
        warning: format!("slot {slot} overwritten; any grants sealed to it are gone"),
    }))
}

/// `DELETE /api/v1/personas/{slot}` — overwrite `slot`
/// (`0..CREDENTIAL_SLOTS`, except the caller's own currently-authenticated
/// slot) with a fresh decoy and revoke any live session opened through it.
/// Idempotent: deleting an already-decoy slot is a no-op that still
/// returns 204, and must not reveal which it was. Like [`create_persona`],
/// silently no-ops (same 204, no session revoked) when `slot` is the
/// account's real `primary_slot` and differs from the caller's own active
/// slot — a duress persona cannot use this endpoint to delete the real
/// identity, and the identical response means it cannot even detect that
/// its attempt did nothing.
#[utoipa::path(
    delete,
    path = "/api/v1/personas/{slot}",
    params(("slot" = u8, Path, description = "Credential slot, 0..CREDENTIAL_SLOTS, excluding the caller's own active slot")),
    responses(
        (status = 204, description = "Slot overwritten with a decoy"),
        (status = 400, description = "Slot out of range"),
        (status = 401, description = "Token missing/invalid"),
    ),
    security(("bearer" = [])),
    tag = "personas",
)]
#[tracing::instrument(skip(state, auth), fields(username = %auth.username))]
pub async fn delete_persona(
    state: web::Data<AuthState>,
    auth: Authenticated,
    path: web::Path<u8>,
) -> Result<HttpResponse, AuthError> {
    let slot = path.into_inner() as usize;
    if !(0..CREDENTIAL_SLOTS).contains(&slot) {
        return Err(AuthError::InvalidPersonaSlot {
            reason: "slot must be in range 0..CREDENTIAL_SLOTS",
        });
    }
    if slot == auth.session.persona as usize {
        return Err(AuthError::InvalidPersonaSlot {
            reason: "cannot overwrite the slot this session is currently authenticated through",
        });
    }
    let rec = state
        .user_store
        .get(&auth.username)
        .map_err(|e| AuthError::Backend(e.to_string()))?
        .ok_or(AuthError::InvalidCredentials)?;

    let username = rec.username.clone();
    let params = rec.kdf.clone();
    let decoy = tokio::task::spawn_blocking(move || kdf::decoy_slot(&username, slot, &params))
        .await
        .map_err(|e| AuthError::Backend(format!("kdf join: {e}")))?
        .map_err(|e| AuthError::Backend(e.to_string()))?;

    let mut updated = rec.clone();
    let is_primary = slot == rec.primary_slot as usize;
    if !is_primary {
        updated.slots[slot] = decoy;
    }
    state
        .user_store
        .upsert(&updated)
        .map_err(|e| AuthError::Backend(e.to_string()))?;

    if !is_primary {
        state
            .sessions
            .revoke_user_persona(&auth.username, slot as u8);
    }
    Ok(HttpResponse::NoContent().finish())
}

/// `GET /api/v1/personas/me` — the calling session's own persona slot and
/// role. Never lists any other slot, and never reports the
/// `revoke_other_sessions` duress flag (see [`PersonaView`]'s doc comment
/// for why) — this is the only introspection offered, and what remains of
/// it is deliberately useless to a coercer.
#[utoipa::path(
    get,
    path = "/api/v1/personas/me",
    responses(
        (status = 200, description = "Current persona", body = PersonaView, content_type = "application/json"),
        (status = 401, description = "Token missing/invalid"),
    ),
    security(("bearer" = [])),
    tag = "personas",
)]
#[tracing::instrument(skip(auth), fields(username = %auth.username))]
pub async fn whoami_persona(auth: Authenticated) -> Result<HttpResponse, AuthError> {
    Ok(HttpResponse::Ok().json(PersonaView {
        slot: auth.session.persona,
        role: auth.session.role,
    }))
}
