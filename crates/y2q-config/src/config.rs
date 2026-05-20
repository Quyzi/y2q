use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize, Serializer};

use crate::error::ConfigError;

fn config_dir() -> Result<PathBuf, ConfigError> {
    directories::ProjectDirs::from("", "", "y2q")
        .map(|p| p.config_dir().to_owned())
        .ok_or_else(|| ConfigError::Config("cannot determine config directory".to_owned()))
}

pub fn default_config_path() -> Result<PathBuf, ConfigError> {
    Ok(config_dir()?.join("config.toml"))
}

pub fn default_tokens_path() -> Result<PathBuf, ConfigError> {
    Ok(config_dir()?.join("tokens.toml"))
}

/// A server profile. Deserializes `password` but never serializes it.
#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    pub url: String,
    pub username: String,
    #[serde(default)]
    pub password: Option<String>,
    /// Skip TLS certificate verification for this profile. Use only for
    /// self-signed dev/staging servers.
    #[serde(default)]
    pub insecure: bool,
    /// Optional PEM-encoded CA bundle to trust for the server certificate.
    /// Ignored when `insecure` is true.
    #[serde(default)]
    pub ca_cert_path: Option<String>,
    /// Optional client certificate (PEM) presented for mutual TLS.
    #[serde(default)]
    pub client_cert_path: Option<String>,
    /// Optional client private key (PEM) paired with `client_cert_path`.
    #[serde(default)]
    pub client_key_path: Option<String>,
}

impl Serialize for Profile {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut len = 2;
        if self.insecure {
            len += 1;
        }
        if self.ca_cert_path.is_some() {
            len += 1;
        }
        if self.client_cert_path.is_some() {
            len += 1;
        }
        if self.client_key_path.is_some() {
            len += 1;
        }
        let mut state = s.serialize_struct("Profile", len)?;
        state.serialize_field("url", &self.url)?;
        state.serialize_field("username", &self.username)?;
        if self.insecure {
            state.serialize_field("insecure", &self.insecure)?;
        }
        if let Some(p) = &self.ca_cert_path {
            state.serialize_field("ca_cert_path", p)?;
        }
        if let Some(p) = &self.client_cert_path {
            state.serialize_field("client_cert_path", p)?;
        }
        if let Some(p) = &self.client_key_path {
            state.serialize_field("client_key_path", p)?;
        }
        state.end()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CliConfig {
    #[serde(default)]
    pub profiles: IndexMap<String, Profile>,
}

impl CliConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        check_permissions(path);
        let text = std::fs::read_to_string(path)?;
        toml::from_str(&text).map_err(|e| ConfigError::Config(e.to_string()))
    }

    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(self).map_err(|e| ConfigError::Config(e.to_string()))?;
        atomic_write(path, text.as_bytes())?;
        set_mode_600(path);
        Ok(())
    }

    pub fn get_profile(&self, alias: &str) -> Result<&Profile, ConfigError> {
        self.profiles
            .get(alias)
            .ok_or_else(|| ConfigError::UnknownAlias(alias.to_owned()))
    }

    pub fn add_profile(&mut self, alias: String, profile: Profile) {
        self.profiles.insert(alias, profile);
    }

    pub fn remove_profile(&mut self, alias: &str) -> bool {
        self.profiles.shift_remove(alias).is_some()
    }
}

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<(), ConfigError> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(unix)]
pub fn set_mode_600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
pub fn set_mode_600(_path: &Path) {}

pub fn check_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                eprintln!(
                    "Warning: {} has permissions {:04o} — set to 0600 to protect your credentials.",
                    path.display(),
                    mode & 0o777
                );
            }
        }
    }
}
