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

/// Object storage settings.
#[derive(Debug, Deserialize)]
pub struct StorageConfig {
    /// Root directory for [`y2q_core::FilesystemStorage`].
    /// The directory is created on first write if it does not exist.
    pub base_path: String,
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
    pub fn load() -> Result<Self, figment::Error> {
        Figment::new()
            .merge(Toml::file("config.toml"))
            .merge(Env::prefixed("Y2QD_").split("__"))
            .extract()
    }
}
