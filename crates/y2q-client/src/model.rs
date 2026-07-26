use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

// ── Auth ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub token: String,
    pub expires_at: u64,
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct ChangePasswordRequest {
    pub current: String,
    pub new: String,
}

// ── Users ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AddUserRequest {
    pub username: String,
    pub password: String,
    /// Global role: `"admin"` or `"user"`. Omitted (server defaults to `user`)
    /// when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListUsersResponse {
    pub users: Vec<UserView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserView {
    pub username: String,
    pub created_at: u64,
    pub last_login: Option<u64>,
    /// Global role: `"admin"` or `"user"`. Defaults empty when talking to a
    /// server that predates roles.
    #[serde(default)]
    pub role: String,
}

/// Bucket owner + ACL, mirrors the daemon's `AclBody`
/// (`/api/v1/buckets/{bucket}/acl`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AclBody {
    /// Bucket owner (full control). `None` for an unclaimed legacy bucket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Per-user grants: username → `"read"` | `"write"` | `"admin"`.
    #[serde(default)]
    pub grants: BTreeMap<String, String>,
    /// Retained bucket key epochs, ascending. Read-only.
    #[serde(default)]
    pub key_epochs: Vec<u32>,
}

// ── Objects ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ObjectHead {
    pub size: u64,
    pub created: u64,
    pub modified: u64,
    pub checksum_gxhash: String,
    pub labels: BTreeSet<(String, String)>,
    pub cipher_size: Option<u64>,
    pub cipher_checksum: Option<String>,
    pub kem_alg: Option<String>,
    pub aead_alg: Option<String>,
    pub envelope_version: Option<u16>,
}

// ── Listing ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataView {
    pub created: u64,
    pub modified: u64,
    pub size: u64,
    pub checksum_gxhash: String,
    pub bucket: String,
    pub key: String,
    pub url_path: String,
    pub labels: BTreeSet<(String, String)>,
    pub cipher_size: Option<u64>,
    pub cipher_checksum: Option<String>,
    pub kem_alg: Option<String>,
    pub aead_alg: Option<String>,
    pub envelope_version: Option<u16>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListPage {
    pub items: Vec<MetadataView>,
    pub next: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct ListOptions {
    pub prefix: Option<String>,
    pub after: Option<String>,
    pub limit: Option<u32>,
}

/// Options for a label search (`GET /api/v1/search`). The query string itself
/// is passed separately to [`crate::Y2qClient::search_labels`].
#[derive(Debug, Default, Clone)]
pub struct SearchOptions {
    /// Restrict to a single bucket. `None` searches every bucket.
    pub bucket: Option<String>,
    /// Return only keys with this prefix.
    pub prefix: Option<String>,
    /// Opaque continuation cursor from a previous response's `next`.
    pub after: Option<String>,
    /// Maximum number of items per page.
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct ListBucketsResponse {
    pub buckets: Vec<String>,
}

/// Per-bucket configuration (quota / default-SSE / CORS). Mirrors the daemon's
/// `BucketConfigBody`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BucketConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_sse: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cors_allow_origin: Option<String>,
}

// ── Trace ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct TraceEvent {
    #[serde(default)]
    pub request_id: String,
    pub timestamp_ns: u64,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub latency_ms: f64,
    pub req_bytes: Option<u64>,
    pub resp_bytes: Option<u64>,
    pub remote_addr: Option<String>,
}

// ── Admin ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct RebuildStatus {
    pub state: String,
    pub percent: Option<u8>,
    pub reason: Option<String>,
}

/// Response body for `POST /api/v1/buckets/{bucket}/rotate-key`.
#[derive(Debug, Clone, Deserialize)]
pub struct RotateKeyResponse {
    pub epoch: u32,
    pub key_epochs: Vec<u32>,
}

/// Response body for `GET /api/v1/buckets/{bucket}/rekey`. Mirrors
/// [`RebuildStatus`]'s shape, scoped per bucket.
#[derive(Debug, Clone, Deserialize)]
pub struct RekeyStatus {
    pub state: String,
    pub percent: Option<u8>,
    pub reason: Option<String>,
}

/// Response body for `POST /api/v1/users/{user}/reset-identity`.
#[derive(Debug, Clone, Deserialize)]
pub struct ResetIdentityResponse {
    pub orphaned_buckets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaleLockEntry {
    pub bucket: String,
    pub uuid: String,
    pub locked_since_nanos: u64,
    pub age_seconds: u64,
}

#[derive(Debug, Deserialize)]
pub struct ClearStaleLocksResponse {
    pub removed: u64,
}

// ── Personas ─────────────────────────────────────────────────────────────────

/// Request body for `POST /api/v1/personas`.
#[derive(Debug, Serialize)]
pub struct PersonaCreateRequest {
    pub slot: u8,
    pub password: String,
    /// Effective role for sessions opened through this persona. Omitted
    /// (server defaults to `user`) when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default)]
    pub revoke_other_sessions: bool,
}

/// Response body for `POST /api/v1/personas`.
#[derive(Debug, Clone, Deserialize)]
pub struct PersonaCreateResponse {
    pub warning: String,
}

/// Response body for `GET /api/v1/personas/me`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonaView {
    pub slot: u8,
    pub role: String,
    pub revoke_other_sessions: bool,
}

/// Request body for `POST`/`DELETE /api/v1/personas/{slot}/grant`.
#[derive(Debug, Serialize)]
pub struct PersonaGrantBody {
    pub buckets: Vec<String>,
}
