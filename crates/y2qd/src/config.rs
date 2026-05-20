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
}

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

        figment.extract().map_err(Box::new)
    }
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
