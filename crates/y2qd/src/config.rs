//! Daemon configuration loaded via [`figment`].
//!
//! Values are merged in priority order: `config.toml` (lowest) then
//! environment variables (highest), so any field can be overridden at runtime
//! without editing the file.

use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use serde::Deserialize;

/// Top-level daemon configuration.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// HTTP server settings.
    pub server: ServerConfig,
    /// Object storage settings.
    pub storage: StorageConfig,
}

fn default_max_body_bytes() -> usize {
    256 * 1024 * 1024 // 256 MiB
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
    /// Load configuration from `config.toml` in the current directory,
    /// with `Y2QD_*` environment variable overrides.
    ///
    /// Nested keys use `__` as the separator, e.g. `Y2QD_SERVER__HOST`
    /// overrides `server.host`.
    ///
    /// # Errors
    ///
    /// Returns a [`figment::Error`] if required keys are missing or a value
    /// cannot be parsed into the expected type.
    pub fn load() -> Result<Self, Box<figment::Error>> {
        Figment::new()
            .merge(Toml::file("config.toml"))
            .merge(Env::prefixed("Y2QD_").split("__"))
            .extract()
            .map_err(Box::new)
    }
}
