//! Daemon configuration loaded via [`figment`].
//!
//! Values are merged in priority order: `config.toml` (lowest) then
//! environment variables (highest), so any field can be overridden at runtime
//! without editing the file.

use std::path::Path;

use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::Deserialize;
use y2q_core::SyncLevel;

/// Top-level daemon configuration.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// HTTP server settings.
    pub server: ServerConfig,
    /// Object storage settings.
    pub storage: StorageConfig,
    /// Cryptography (keystore + KDF) settings.
    pub crypto: CryptoConfig,
    /// User authentication / session settings.
    pub auth: AuthConfig,
    /// Logging and metrics settings.
    #[serde(default)]
    pub observability: ObservabilityConfig,
    /// Distributed clustering settings. Disabled by default; when disabled the
    /// daemon behaves exactly as a single node.
    #[serde(default)]
    pub cluster: ClusterConfig,
}

/// Log output format.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable text output. Default.
    #[default]
    Text,
    /// Structured JSON output, one object per log line. Suited for log
    /// aggregators (Loki, Elasticsearch, etc.).
    Json,
}

/// Logging and metrics settings.
#[derive(Debug, Deserialize)]
pub struct ObservabilityConfig {
    /// Tracing filter directive in `RUST_LOG` syntax, e.g. `"info"` or
    /// `"y2qd=debug,actix_web=info"`. The `RUST_LOG` environment variable
    /// takes precedence over this value when set.
    #[serde(default = "default_log_filter")]
    pub log_filter: String,
    /// Log output format. Default: `"text"`. Set to `"json"` for structured
    /// output consumed by log aggregators.
    #[serde(default)]
    pub log_format: LogFormat,
    /// Pyroscope continuous-profiling agent. Disabled by default.
    /// Requires building with `--features pyroscope` to take effect.
    #[serde(default)]
    #[cfg_attr(not(feature = "pyroscope"), allow(dead_code))]
    pub pyroscope: PyroscopeConfig,
}

fn default_log_filter() -> String {
    "info".to_string()
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_filter: default_log_filter(),
            log_format: LogFormat::Text,
            pyroscope: PyroscopeConfig::default(),
        }
    }
}

/// Pyroscope continuous-profiling agent settings.
///
/// Disabled by default. Enable by setting `enabled = true` and pointing
/// `server_url` at a Pyroscope server or Grafana Cloud profiling endpoint.
/// Compile the daemon with `--features pyroscope` for this section to take effect.
#[derive(Debug, Deserialize)]
#[cfg_attr(not(feature = "pyroscope"), allow(dead_code))]
pub struct PyroscopeConfig {
    /// Whether to start the Pyroscope agent. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Pyroscope server URL. Default: `"http://localhost:4040"`.
    #[serde(default = "default_pyroscope_url")]
    pub server_url: String,
    /// pprof sampling rate in Hz. Default: 100.
    #[serde(default = "default_pyroscope_sample_rate")]
    pub sample_rate: u32,
    /// HTTP Basic auth username (Grafana Cloud: numeric user ID).
    pub basic_auth_user: Option<String>,
    /// HTTP Basic auth password (Grafana Cloud: API token).
    pub basic_auth_password: Option<String>,
}

fn default_pyroscope_url() -> String {
    "http://localhost:4040".to_string()
}

fn default_pyroscope_sample_rate() -> u32 {
    100
}

impl Default for PyroscopeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_url: default_pyroscope_url(),
            sample_rate: default_pyroscope_sample_rate(),
            basic_auth_user: None,
            basic_auth_password: None,
        }
    }
}

fn default_max_body_bytes() -> usize {
    256 * 1024 * 1024 // 256 MiB
}

fn default_unauthenticated_metrics() -> bool {
    false
}

fn default_backlog() -> u32 {
    1024
}
fn default_max_connections() -> usize {
    25_000
}
fn default_keep_alive_secs() -> u64 {
    5
}
fn default_client_request_timeout_secs() -> u64 {
    5
}
fn default_client_disconnect_timeout_secs() -> u64 {
    1
}
fn default_shutdown_timeout_secs() -> u64 {
    30
}

/// Actix `HttpServer` tuning knobs.
///
/// The entire `[server.actix]` section is optional; omitting it leaves actix's
/// compiled-in defaults in effect.
#[derive(Debug, Deserialize)]
pub struct ActixConfig {
    /// Worker thread count. `None` (omit the key) uses the number of logical CPUs.
    pub workers: Option<usize>,
    /// TCP listen backlog depth. Default: 1024.
    #[serde(default = "default_backlog")]
    pub backlog: u32,
    /// Maximum concurrent connections per worker thread. Default: 25 000.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Keep-alive idle timeout in seconds. `0` disables keep-alive entirely. Default: 5.
    #[serde(default = "default_keep_alive_secs")]
    pub keep_alive_secs: u64,
    /// Time to wait for the first request bytes after a connection is accepted,
    /// in seconds. Default: 5.
    #[serde(default = "default_client_request_timeout_secs")]
    pub client_request_timeout_secs: u64,
    /// Time to wait for the client to close the connection after the final
    /// response has been sent, in seconds. Default: 1.
    #[serde(default = "default_client_disconnect_timeout_secs")]
    pub client_disconnect_timeout_secs: u64,
    /// Graceful shutdown window in seconds — in-flight requests have this long
    /// to complete before the process exits. Default: 30.
    #[serde(default = "default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u64,
}

impl Default for ActixConfig {
    fn default() -> Self {
        Self {
            workers: None,
            backlog: default_backlog(),
            max_connections: default_max_connections(),
            keep_alive_secs: default_keep_alive_secs(),
            client_request_timeout_secs: default_client_request_timeout_secs(),
            client_disconnect_timeout_secs: default_client_disconnect_timeout_secs(),
            shutdown_timeout_secs: default_shutdown_timeout_secs(),
        }
    }
}

/// HTTP listener settings.
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// IP address to bind (e.g. `"127.0.0.1"` or `"0.0.0.0"`).
    pub host: String,
    /// TCP port to listen on.
    pub port: u16,
    /// Maximum request body size in bytes for PUT uploads. Defaults to 256 MiB.
    /// Override via `config.toml` or `Y2QD_SERVER__MAX_BODY_BYTES`.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    /// When `true`, the metrics dashboard, Prometheus scrape endpoint, and
    /// Swagger UI are reachable without a session token. Defaults to `false`,
    /// which makes all three require Bearer auth like every other route.
    #[serde(default = "default_unauthenticated_metrics")]
    pub unauthenticated_metrics: bool,
    /// Actix `HttpServer` tuning knobs.
    #[serde(default)]
    pub actix: ActixConfig,
    /// TLS (HTTPS) settings. Disabled by default.
    #[serde(default)]
    pub tls: TlsConfig,
}

/// TLS settings. When `enabled` is true, the daemon binds HTTPS at
/// `server.port` using rustls and refuses plain HTTP. Both `cert_path` and
/// `key_path` must point to PEM-encoded files (certificate chain and PKCS#8
/// or RSA private key respectively).
///
/// When `client_ca_path` is set, the daemon requires every client to present
/// a certificate chained to the bundled CA(s) — mutual TLS. Otherwise the
/// daemon accepts any client without certificate verification.
#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    /// Whether to bind HTTPS instead of plain HTTP. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Path to the PEM-encoded certificate chain. Required when `enabled`.
    #[serde(default)]
    pub cert_path: Option<String>,
    /// Path to the PEM-encoded private key (PKCS#8, PKCS#1, or SEC1).
    /// Required when `enabled`.
    #[serde(default)]
    pub key_path: Option<String>,
    /// Path to a PEM-encoded CA bundle. When set, the daemon enforces mTLS:
    /// every client must present a certificate chained to one of these CAs
    /// or the handshake is rejected. Unset = no client cert required.
    #[serde(default)]
    pub client_ca_path: Option<String>,
    /// Require a post-quantum key exchange (X25519MLKEM768 hybrid) on every
    /// TLS handshake. When true, the daemon restricts its offered KX groups
    /// to the PQ-hybrid group only; clients that cannot negotiate it are
    /// refused at handshake time. Default: true — refuse to serve TLS without
    /// PQ key agreement.
    #[serde(default = "default_require_pq_kex")]
    pub require_pq_kex: bool,
}

fn default_require_pq_kex() -> bool {
    true
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: None,
            key_path: None,
            client_ca_path: None,
            require_pq_kex: default_require_pq_kex(),
        }
    }
}

/// Argon2id parameters for newly-added user records.
#[derive(Debug, Deserialize, Clone)]
pub struct Argon2Config {
    #[serde(default = "default_argon2_m_cost_kib")]
    pub m_cost_kib: u32,
    #[serde(default = "default_argon2_t_cost")]
    pub t_cost: u32,
    #[serde(default = "default_argon2_p_cost")]
    pub p_cost: u32,
}

fn default_argon2_m_cost_kib() -> u32 {
    65_536
}
fn default_argon2_t_cost() -> u32 {
    3
}
fn default_argon2_p_cost() -> u32 {
    4
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            m_cost_kib: default_argon2_m_cost_kib(),
            t_cost: default_argon2_t_cost(),
            p_cost: default_argon2_p_cost(),
        }
    }
}

/// Keystore + KDF settings.
#[derive(Debug, Deserialize)]
pub struct CryptoConfig {
    /// Directory holding `pubkey.json`, `users.redb`, and the daemon-wide
    /// `.lock` file. Required — no default. Should NOT live under
    /// `storage.base_path`, so a `cp -r` of the storage tree doesn't
    /// accidentally copy or strand authentication state.
    pub keystore_dir: String,
    /// Argon2id parameters for new user records.
    #[serde(default)]
    pub argon2: Argon2Config,
    /// Plaintext chunk size (bytes) for v2 streaming encryption. Default 4 MiB.
    /// Stored per-object in the envelope header, so changing this only affects
    /// objects written afterwards; existing objects keep decrypting with their
    /// own stored chunk size. Bounds enforced at load: 64 KiB ..= 256 MiB.
    #[serde(default = "default_envelope_chunk_size_bytes")]
    pub envelope_chunk_size_bytes: usize,
}

fn default_envelope_chunk_size_bytes() -> usize {
    4 * 1024 * 1024
}

/// Minimum and maximum accepted `envelope_chunk_size_bytes`. The ceiling keeps
/// the value inside the envelope's `u32` header field and bounds per-chunk RAM.
const ENVELOPE_CHUNK_SIZE_MIN: usize = 64 * 1024;
const ENVELOPE_CHUNK_SIZE_MAX: usize = 256 * 1024 * 1024;

fn default_session_ttl_seconds() -> u64 {
    3600
}
fn default_max_session_ttl_seconds() -> u64 {
    86_400
}
fn default_session_sweep_interval_seconds() -> u64 {
    300
}
fn default_min_login_response_ms() -> u64 {
    250
}
fn default_max_failed_logins() -> u32 {
    10
}
fn default_lockout_seconds() -> u64 {
    900
}
fn default_keystore_idle_drop_seconds() -> u64 {
    0
}
fn default_enforce_authorization() -> bool {
    true
}

/// User authentication / session settings.
#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    /// Default token lifetime when `ttl_seconds` is omitted on `POST /api/v1/auth/login`.
    #[serde(default = "default_session_ttl_seconds")]
    pub default_ttl_seconds: u64,
    /// Hard ceiling. Logins requesting `ttl_seconds > max_ttl_seconds` are
    /// rejected with 400.
    #[serde(default = "default_max_session_ttl_seconds")]
    pub max_ttl_seconds: u64,
    /// How often the background sweeper purges expired sessions from memory.
    #[serde(default = "default_session_sweep_interval_seconds")]
    pub session_sweep_interval_seconds: u64,
    /// Minimum delay (ms) before a failed-login response is sent. Argon2id
    /// dominates this already; the floor smooths out timing differences
    /// between known and unknown usernames.
    #[serde(default = "default_min_login_response_ms")]
    pub min_login_response_ms: u64,
    /// After this many consecutive failed logins for a username, lock the
    /// account for `lockout_seconds`. `0` disables lockout.
    #[serde(default = "default_max_failed_logins")]
    pub max_failed_logins: u32,
    /// Lockout duration (seconds) after `max_failed_logins` is exceeded.
    #[serde(default = "default_lockout_seconds")]
    pub lockout_seconds: u64,
    /// Drop the in-memory decrypted SK this many seconds after the last
    /// session expires. `0` = drop immediately. Set higher to forgive brief
    /// gaps between sessions; lower to bound the SK exposure window.
    #[serde(default = "default_keystore_idle_drop_seconds")]
    pub keystore_idle_drop_seconds: u64,
    /// Enforce bucket ownership/ACL and the global admin role. When `false`,
    /// any authenticated user has full access to every bucket and every admin
    /// endpoint (the pre-authorization behavior) — intended for single-user or
    /// migration deployments only.
    #[serde(default = "default_enforce_authorization")]
    pub enforce_authorization: bool,
}

fn default_max_labels() -> usize {
    32
}

fn default_max_label_name_bytes() -> usize {
    64
}

fn default_max_label_value_bytes() -> usize {
    1024
}

fn default_sync_flush_interval_secs() -> u64 {
    5
}

fn default_sync_flush_limit() -> usize {
    64
}

/// Selected storage backend implementation.
///
/// Maps to the on-disk format and I/O strategy used at runtime. Set via
/// `[storage] backend = "..."` in `config.toml` or `Y2QD_STORAGE__BACKEND`.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackend {
    /// Portable [`tokio::fs`]-based backend
    /// ([`y2q_core::FilesystemStorage`]). Default.
    #[default]
    Filesystem,
    /// Linux-only `io_uring` fast path
    /// ([`y2q_core::UringStorage`](https://docs.rs/y2q-core)).
    /// Requires the `uring` cargo feature and a Linux kernel ≥ 5.6.
    Uring,
}

/// io_uring ring builder tunables. All fields default to tokio-uring's own
/// defaults. Only meaningful when `backend = "uring"`.
#[derive(Debug, Deserialize)]
pub struct UringRingConfig {
    /// Number of dedicated tokio-uring worker threads. Defaults to the number
    /// of logical CPUs.
    pub workers: Option<usize>,
    /// Submission queue (SQ) ring size. Must be a power of two. Default: 256.
    #[serde(default = "default_uring_sq_entries")]
    pub sq_entries: u32,
    /// Completion queue (CQ) ring size. `None` (omit) lets the kernel pick
    /// (typically 2x `sq_entries`). Default: omitted.
    pub cq_entries: Option<u32>,
    /// Enable kernel-side SQ polling thread (`IORING_SETUP_SQPOLL`). Requires
    /// `CAP_SYS_NICE` or `CAP_SYS_ADMIN`. Default: false.
    #[serde(default)]
    pub sq_poll: bool,
    /// Milliseconds of SQ poll thread idle before it sleeps. Only meaningful
    /// when `sq_poll = true`. Default: 2000.
    #[serde(default = "default_uring_sq_poll_idle_ms")]
    pub sq_poll_idle_ms: u32,
    /// Pin the SQ poll thread to this CPU index. `None` = no affinity. Only
    /// meaningful when `sq_poll = true`. Default: omitted.
    pub sq_poll_cpu: Option<u32>,
    /// Busy-poll for I/O completions (`IORING_SETUP_IOPOLL`). Useful on NVMe
    /// devices that support polled I/O. Default: false.
    #[serde(default)]
    pub io_poll: bool,
    /// Declare single-thread submission (`IORING_SETUP_SINGLE_ISSUER`). Each
    /// worker thread owns its own ring, so this is always accurate and enables
    /// kernel-side optimisations. Default: true.
    #[serde(default = "default_true")]
    pub single_issuer: bool,
    /// Enable cooperative task-run scheduling (`IORING_SETUP_COOP_TASKRUN`).
    /// Reduces interrupt overhead. Default: false.
    #[serde(default)]
    pub coop_taskrun: bool,
    /// Object size threshold (bytes) at or above which writes use `O_DIRECT`
    /// with aligned buffers. Below this, buffered uring writes are used.
    /// Default: 4 MiB.
    #[serde(default = "default_uring_large_object_bytes")]
    pub large_object_bytes: u64,
}

fn default_uring_sq_entries() -> u32 {
    256
}
fn default_uring_sq_poll_idle_ms() -> u32 {
    2000
}
fn default_true() -> bool {
    true
}
fn default_uring_large_object_bytes() -> u64 {
    4 * 1024 * 1024
}

impl Default for UringRingConfig {
    fn default() -> Self {
        Self {
            workers: None,
            sq_entries: default_uring_sq_entries(),
            cq_entries: None,
            sq_poll: false,
            sq_poll_idle_ms: default_uring_sq_poll_idle_ms(),
            sq_poll_cpu: None,
            io_poll: false,
            single_issuer: true,
            coop_taskrun: false,
            large_object_bytes: default_uring_large_object_bytes(),
        }
    }
}

/// Object storage settings.
#[derive(Debug, Deserialize)]
pub struct StorageConfig {
    /// Which backend implementation to use. Defaults to `filesystem`.
    #[serde(default)]
    pub backend: StorageBackend,
    /// Root directory for the selected storage backend.
    /// The directory is created on first write if it does not exist.
    pub base_path: String,
    /// Path to the redb-backed metadata index file. Defaults to
    /// `<base_path>/_y2q_index.redb` when unset.
    /// Override via `Y2QD_STORAGE__INDEX_PATH`.
    #[serde(default)]
    pub index_path: Option<String>,
    /// Maximum number of `X-Y2Q-<label>` custom labels accepted on a PUT
    /// request. Defaults to 32.
    #[serde(default = "default_max_labels")]
    pub max_labels: usize,
    /// Maximum byte length of a single label name (after `X-Y2Q-` prefix
    /// stripping and lowercasing). Defaults to 64.
    #[serde(default = "default_max_label_name_bytes")]
    pub max_label_name_bytes: usize,
    /// Maximum byte length of a single label value. Defaults to 1024.
    #[serde(default = "default_max_label_value_bytes")]
    pub max_label_value_bytes: usize,
    /// Seconds between background fsync passes for best-effort PUTs. Default: 5.
    #[serde(default = "default_sync_flush_interval_secs")]
    pub sync_flush_interval_secs: u64,
    /// Queue depth that triggers an immediate fsync pass before the timer fires.
    /// Default: 64.
    #[serde(default = "default_sync_flush_limit")]
    pub sync_flush_limit: usize,
    /// Default durability for PUT requests that omit the `X-Y2Q-Sync` header.
    /// `"durable"` (default) — fdatasync + parent dir fsync before returning.
    /// `"best-effort"` — no fsync; higher throughput, not crash-safe.
    #[serde(default)]
    pub default_sync: SyncLevel,
    /// io_uring ring builder tunables. Only used when `backend = "uring"`.
    #[serde(default)]
    pub uring: UringRingConfig,
}

/// Per-request limits on `X-Y2Q-<label>` headers, registered as actix
/// `web::Data` so handlers can access them.
#[derive(Debug, Clone, Copy)]
pub struct LabelLimits {
    pub max_labels: usize,
    pub max_label_name_bytes: usize,
    pub max_label_value_bytes: usize,
}

impl From<&StorageConfig> for LabelLimits {
    fn from(cfg: &StorageConfig) -> Self {
        Self {
            max_labels: cfg.max_labels,
            max_label_name_bytes: cfg.max_label_name_bytes,
            max_label_value_bytes: cfg.max_label_value_bytes,
        }
    }
}

/// Inter-node read consistency mode for clustered reads.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ClusterConsistency {
    /// Linearizable reads: a node holding an in-flight (dirty) version queries
    /// the chain TAIL for the committed version before answering. Default.
    #[default]
    Strong,
    /// Serve the local committed copy even if a newer write is in flight.
    /// Cheapest, may return stale data.
    Eventual,
    /// Serve the local committed copy if it is fresh within
    /// `eventual_bound_ms`; otherwise fall back to a version query.
    EventualBounded,
}

/// Peer-to-peer authentication mechanism for the internal cluster API.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ClusterAuth {
    /// HMAC/bearer of a shared secret. Simplest to bring up. Default.
    #[default]
    SharedSecret,
    /// Mutual TLS using the existing server `client_ca_path` and a client
    /// identity. Recommended production posture.
    Mtls,
}

/// Whether a node participates in the raft voting quorum.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RaftRole {
    /// Voter iff this node's id is in `voter_seeds`, else a learner. Default.
    #[default]
    Auto,
    /// Always a voting member of the controller quorum.
    Voter,
    /// Always a non-voting learner (receives the log, never votes).
    Learner,
}

fn default_replication_factor() -> usize {
    3
}
fn default_virtual_nodes_per_node() -> u32 {
    256
}
fn default_eventual_bound_ms() -> u64 {
    2000
}
fn default_prepare_timeout_ms() -> u64 {
    30_000
}
fn default_ack_timeout_ms() -> u64 {
    30_000
}
fn default_health_probe_interval_ms() -> u64 {
    1000
}
fn default_health_fail_threshold() -> u32 {
    3
}
fn default_cluster_unlock() -> String {
    "provisioned".to_string()
}
fn default_raft_heartbeat_ms() -> u64 {
    250
}
fn default_raft_election_min_ms() -> u64 {
    1000
}
fn default_raft_election_max_ms() -> u64 {
    1500
}

/// Embedded raft control-plane tuning.
// Several fields are part of the deserialized config schema but are not read
// until the cluster runtime is wired in a later phase; allow until then.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct RaftConfig {
    /// Leader heartbeat interval (ms). Default: 250.
    #[serde(default = "default_raft_heartbeat_ms")]
    pub heartbeat_interval_ms: u64,
    /// Lower bound of the randomized election timeout (ms). Default: 1000.
    #[serde(default = "default_raft_election_min_ms")]
    pub election_timeout_min_ms: u64,
    /// Upper bound of the randomized election timeout (ms). Default: 1500.
    #[serde(default = "default_raft_election_max_ms")]
    pub election_timeout_max_ms: u64,
    /// Directory for the raft log/state-machine db and the persisted node id.
    /// Empty => `<storage.base_path>/_y2q_raft`.
    #[serde(default)]
    pub log_dir: String,
    /// Set `true` on exactly one node's first boot to initialize a single-node
    /// raft cluster; other nodes join it.
    #[serde(default)]
    pub bootstrap: bool,
    /// Voter/learner selection strategy. Default: `auto` (use `voter_seeds`).
    #[serde(default)]
    pub role: RaftRole,
    /// Node ids forming the voting controller quorum (size 3/5/7). Every node
    /// should be configured with the same list so all agree on the quorum.
    #[serde(default)]
    pub voter_seeds: Vec<u64>,
}

impl Default for RaftConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_ms: default_raft_heartbeat_ms(),
            election_timeout_min_ms: default_raft_election_min_ms(),
            election_timeout_max_ms: default_raft_election_max_ms(),
            log_dir: String::new(),
            bootstrap: false,
            role: RaftRole::Auto,
            voter_seeds: Vec::new(),
        }
    }
}

/// Distributed clustering settings.
///
/// The entire `[cluster]` section is optional and every field is defaulted, so
/// an existing `config.toml` with no `[cluster]` block deserializes to a
/// disabled cluster — single-node behavior, unchanged.
// Several fields are part of the deserialized config schema but are not read
// until the cluster runtime is wired in a later phase; allow until then.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct ClusterConfig {
    /// Master switch. `false` (default) => single node, zero clustering.
    #[serde(default)]
    pub enabled: bool,
    /// Optional explicit node id (`u64`). Empty => derive and persist one.
    #[serde(default)]
    pub node_id: String,
    /// `host:port` other nodes dial for the `/internal/v1` API. Required when
    /// `enabled`.
    #[serde(default)]
    pub advertise_addr: String,
    /// Chain length `R` (number of replicas per object). Clamped to membership.
    #[serde(default = "default_replication_factor")]
    pub replication_factor: usize,
    /// Virtual nodes per node on the consistent-hash ring.
    #[serde(default = "default_virtual_nodes_per_node")]
    pub virtual_nodes_per_node: u32,
    /// Read consistency mode. Default: `strong`.
    #[serde(default)]
    pub consistency: ClusterConsistency,
    /// Freshness window (ms) for `eventual-bounded` reads.
    #[serde(default = "default_eventual_bound_ms")]
    pub eventual_bound_ms: u64,
    /// Per-hop PREPARE forward timeout (ms).
    #[serde(default = "default_prepare_timeout_ms")]
    pub prepare_timeout_ms: u64,
    /// HEAD wait for the full-chain commit ACK (ms).
    #[serde(default = "default_ack_timeout_ms")]
    pub ack_timeout_ms: u64,
    /// Peer authentication mechanism. Default: `shared-secret`.
    #[serde(default)]
    pub auth: ClusterAuth,
    /// Shared secret for `shared-secret` auth. Prefer `Y2QD_CLUSTER__SHARED_SECRET`.
    #[serde(default)]
    pub shared_secret: String,
    /// Interval between peer health probes (ms).
    #[serde(default = "default_health_probe_interval_ms")]
    pub health_probe_interval_ms: u64,
    /// Consecutive failed probes before a peer is reported suspect/down.
    #[serde(default = "default_health_fail_threshold")]
    pub health_fail_threshold: u32,
    /// MEK unlock strategy. Only `"provisioned"` is implemented: the SK is
    /// unwrapped at boot from a provisioned secret so the node can commit
    /// peer-forwarded writes unattended.
    #[serde(default = "default_cluster_unlock")]
    pub unlock: String,
    /// Path to a file holding the provisioned unlock secret. Alternatively set
    /// `Y2QD_CLUSTER__UNLOCK_SECRET`.
    #[serde(default)]
    pub unlock_secret_file: String,
    /// User whose record the provisioned unlock secret unwraps at boot to
    /// recover the deployment SK. Default: `"root"`.
    #[serde(default = "default_unlock_user")]
    pub unlock_user: String,
    /// Known peers (id + base URL) the controller can dial. The bootstrap node
    /// adds these as learners and promotes those in `raft.voter_seeds`.
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    /// Embedded raft control-plane tuning.
    #[serde(default)]
    pub raft: RaftConfig,
}

/// A configured peer node.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerConfig {
    /// The peer's node id (`u64`).
    pub id: u64,
    /// The peer's base URL, e.g. `https://10.0.0.2:8443`.
    pub url: String,
}

fn default_unlock_user() -> String {
    "root".to_string()
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node_id: String::new(),
            advertise_addr: String::new(),
            replication_factor: default_replication_factor(),
            virtual_nodes_per_node: default_virtual_nodes_per_node(),
            consistency: ClusterConsistency::Strong,
            eventual_bound_ms: default_eventual_bound_ms(),
            prepare_timeout_ms: default_prepare_timeout_ms(),
            ack_timeout_ms: default_ack_timeout_ms(),
            auth: ClusterAuth::SharedSecret,
            shared_secret: String::new(),
            health_probe_interval_ms: default_health_probe_interval_ms(),
            health_fail_threshold: default_health_fail_threshold(),
            unlock: default_cluster_unlock(),
            unlock_secret_file: String::new(),
            unlock_user: default_unlock_user(),
            peers: Vec::new(),
            raft: RaftConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from the TOML file named by `--config` (default: `config.toml`),
    /// then layer `Y2QD_*` environment variables, then any `--set KEY=VALUE` overrides
    /// (highest priority).
    ///
    /// Nested keys in `--set` use `.` as the separator, e.g. `server.port=9090`.
    /// Environment variable keys use `__`, e.g. `Y2QD_SERVER__HOST`.
    ///
    /// # Errors
    ///
    /// Returns a [`figment::Error`] if required keys are missing or a value
    /// cannot be parsed into the expected type.
    pub fn load(cli: &crate::cli::Cli) -> Result<Self, Box<figment::Error>> {
        let config_path = cli
            .config
            .as_deref()
            .unwrap_or_else(|| Path::new("config.toml"));

        let mut figment = Figment::new()
            .merge(Toml::file(config_path))
            .merge(Env::prefixed("Y2QD_").split("__"));

        for (key, val) in &cli.overrides {
            let parts: Vec<&str> = key.split('.').collect();
            let json_val = coerce_cli_value(val);
            let mut map = serde_json::Map::new();
            insert_nested(&mut map, &parts, json_val);
            figment = figment.merge(Serialized::globals(serde_json::Value::Object(map)));
        }

        let cfg: Config = figment.extract().map_err(Box::new)?;

        validate_envelope_chunk_size(cfg.crypto.envelope_chunk_size_bytes)
            .map_err(|msg| Box::new(figment::Error::from(msg)))?;

        validate_cluster(&cfg).map_err(|msg| Box::new(figment::Error::from(msg)))?;

        Ok(cfg)
    }
}

/// Validate the `[cluster]` section against the surrounding [`Config`]. A
/// disabled cluster passes unconditionally.
fn validate_cluster(cfg: &Config) -> Result<(), String> {
    validate_cluster_section(&cfg.cluster, cfg.server.tls.client_ca_path.is_some())
}

/// Pure validation of a [`ClusterConfig`]. `has_client_ca` reports whether
/// `server.tls.client_ca_path` is set (needed only for the mTLS cross-check).
/// Secrets are accepted either inline or via the documented env vars.
fn validate_cluster_section(c: &ClusterConfig, has_client_ca: bool) -> Result<(), String> {
    if !c.enabled {
        return Ok(());
    }
    if c.advertise_addr.trim().is_empty() {
        return Err("cluster.advertise_addr is required when cluster.enabled".to_string());
    }
    if !c.node_id.trim().is_empty() && c.node_id.trim().parse::<u64>().is_err() {
        return Err(format!(
            "cluster.node_id = {:?} must be a u64 (or empty to derive one)",
            c.node_id
        ));
    }
    if c.replication_factor < 1 {
        return Err("cluster.replication_factor must be >= 1".to_string());
    }
    if c.virtual_nodes_per_node == 0 {
        return Err("cluster.virtual_nodes_per_node must be >= 1".to_string());
    }
    if c.auth == ClusterAuth::SharedSecret
        && c.shared_secret.trim().is_empty()
        && std::env::var("Y2QD_CLUSTER__SHARED_SECRET").is_err()
    {
        return Err(
            "cluster.shared_secret (or Y2QD_CLUSTER__SHARED_SECRET) is required when \
             cluster.auth = shared-secret"
                .to_string(),
        );
    }
    if c.auth == ClusterAuth::Mtls && !has_client_ca {
        return Err(
            "cluster.auth = mtls requires server.tls.client_ca_path for peer verification"
                .to_string(),
        );
    }
    if c.unlock != "provisioned" {
        return Err(format!(
            "cluster.unlock = {:?} is unsupported; only \"provisioned\" is implemented",
            c.unlock
        ));
    }
    if c.unlock_secret_file.trim().is_empty()
        && std::env::var("Y2QD_CLUSTER__UNLOCK_SECRET").is_err()
    {
        return Err(
            "cluster provisioned unlock requires cluster.unlock_secret_file or \
             Y2QD_CLUSTER__UNLOCK_SECRET"
                .to_string(),
        );
    }
    Ok(())
}

/// Enforce the accepted bounds for `crypto.envelope_chunk_size_bytes`.
fn validate_envelope_chunk_size(chunk: usize) -> Result<(), String> {
    if (ENVELOPE_CHUNK_SIZE_MIN..=ENVELOPE_CHUNK_SIZE_MAX).contains(&chunk) {
        Ok(())
    } else {
        Err(format!(
            "crypto.envelope_chunk_size_bytes = {chunk} is out of range; \
             must be between {ENVELOPE_CHUNK_SIZE_MIN} and {ENVELOPE_CHUNK_SIZE_MAX} bytes"
        ))
    }
}

/// Encryption parameters registered as actix `web::Data` so the PUT handler can
/// read the configured v2 chunk size and body-size cap without touching the
/// whole [`Config`].
#[derive(Debug, Clone, Copy)]
pub struct EncryptionParams {
    pub chunk_size_bytes: usize,
    /// Maximum plaintext body size accepted for a PUT, enforced mid-stream so
    /// it applies regardless of whether the client sends `Content-Length`
    /// (chunked transfer encoding has none). `web::PayloadConfig` does not
    /// cover this: it only applies to extractors that buffer the whole body
    /// (e.g. `web::Bytes`), not the raw `web::Payload` stream PUT uses.
    pub max_body_bytes: u64,
}

/// Parse a CLI string value as an integer, boolean, or string in that order.
fn coerce_cli_value(s: &str) -> serde_json::Value {
    if let Ok(n) = s.parse::<i64>() {
        return serde_json::Value::Number(n.into());
    }
    match s {
        "true" => return serde_json::Value::Bool(true),
        "false" => return serde_json::Value::Bool(false),
        _ => {}
    }
    serde_json::Value::String(s.to_string())
}

fn insert_nested(
    map: &mut serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
    value: serde_json::Value,
) {
    if keys.is_empty() {
        return;
    }
    if keys.len() == 1 {
        map.insert(keys[0].to_string(), value);
        return;
    }
    let entry = map
        .entry(keys[0].to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if let serde_json::Value::Object(nested) = entry {
        insert_nested(nested, &keys[1..], value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_chunk_size_bounds() {
        assert!(validate_envelope_chunk_size(default_envelope_chunk_size_bytes()).is_ok());
        assert!(validate_envelope_chunk_size(ENVELOPE_CHUNK_SIZE_MIN).is_ok());
        assert!(validate_envelope_chunk_size(ENVELOPE_CHUNK_SIZE_MAX).is_ok());
        // Below the floor, above the ceiling, and zero are rejected.
        assert!(validate_envelope_chunk_size(ENVELOPE_CHUNK_SIZE_MIN - 1).is_err());
        assert!(validate_envelope_chunk_size(ENVELOPE_CHUNK_SIZE_MAX + 1).is_err());
        assert!(validate_envelope_chunk_size(0).is_err());
    }

    #[test]
    fn disabled_cluster_always_passes() {
        let c = ClusterConfig::default();
        assert!(!c.enabled);
        assert!(validate_cluster_section(&c, false).is_ok());
    }

    /// A fully-specified, enabled cluster (shared secret inline) validates.
    fn enabled_cluster() -> ClusterConfig {
        ClusterConfig {
            enabled: true,
            advertise_addr: "10.0.0.1:8443".to_string(),
            shared_secret: "s3cret".to_string(),
            unlock_secret_file: "/etc/y2q/unlock".to_string(),
            ..ClusterConfig::default()
        }
    }

    #[test]
    fn enabled_cluster_with_required_fields_passes() {
        assert!(validate_cluster_section(&enabled_cluster(), false).is_ok());
    }

    #[test]
    fn enabled_cluster_requires_advertise_addr() {
        let c = ClusterConfig {
            advertise_addr: String::new(),
            ..enabled_cluster()
        };
        assert!(validate_cluster_section(&c, false).is_err());
    }

    #[test]
    fn shared_secret_required_for_shared_secret_auth() {
        let c = ClusterConfig {
            shared_secret: String::new(),
            ..enabled_cluster()
        };
        // Only valid if the env var is set; in its absence this must fail.
        if std::env::var("Y2QD_CLUSTER__SHARED_SECRET").is_err() {
            assert!(validate_cluster_section(&c, false).is_err());
        }
    }

    #[test]
    fn mtls_requires_client_ca() {
        let c = ClusterConfig {
            auth: ClusterAuth::Mtls,
            ..enabled_cluster()
        };
        assert!(validate_cluster_section(&c, false).is_err());
        assert!(validate_cluster_section(&c, true).is_ok());
    }

    #[test]
    fn non_u64_node_id_rejected() {
        let c = ClusterConfig {
            node_id: "node-a".to_string(),
            ..enabled_cluster()
        };
        assert!(validate_cluster_section(&c, false).is_err());
        let c = ClusterConfig {
            node_id: "7".to_string(),
            ..enabled_cluster()
        };
        assert!(validate_cluster_section(&c, false).is_ok());
    }

    #[test]
    fn unsupported_unlock_rejected() {
        let c = ClusterConfig {
            unlock: "login-primed".to_string(),
            ..enabled_cluster()
        };
        assert!(validate_cluster_section(&c, false).is_err());
    }

    #[test]
    fn cluster_consistency_parses_kebab_case() {
        use figment::{Figment, providers::Serialized};
        let v: ClusterConsistency = Figment::new()
            .merge(Serialized::default("c", "eventual-bounded"))
            .extract_inner("c")
            .unwrap();
        assert_eq!(v, ClusterConsistency::EventualBounded);
    }
}
