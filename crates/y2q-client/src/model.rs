use std::collections::BTreeMap;

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
}

// ── Objects ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ObjectHead {
    pub size: u64,
    pub created: u64,
    pub modified: u64,
    pub checksum_gxhash: String,
    pub labels: BTreeMap<String, String>,
    pub cipher_size: Option<u64>,
    pub cipher_sha256: Option<String>,
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
    pub disk_path: String,
    pub url_path: String,
    pub labels: BTreeMap<String, String>,
    pub cipher_size: Option<u64>,
    pub cipher_sha256: Option<String>,
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

#[derive(Debug, Deserialize)]
pub struct ListBucketsResponse {
    pub buckets: Vec<String>,
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
