use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::{atomic_write, check_permissions, set_mode_600};
use crate::error::ConfigError;

const GRACE_SECS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEntry {
    pub token: String,
    pub expires_at: u64,
    pub username: String,
}

impl TokenEntry {
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now + GRACE_SECS >= self.expires_at
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct TokenFile {
    #[serde(default)]
    sessions: HashMap<String, TokenEntry>,
}

#[derive(Debug)]
pub struct TokenStore {
    inner: TokenFile,
}

impl TokenStore {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Ok(Self { inner: TokenFile::default() });
        }
        check_permissions(path);
        let text = std::fs::read_to_string(path)?;
        let inner: TokenFile =
            toml::from_str(&text).map_err(|e| ConfigError::Config(e.to_string()))?;
        Ok(Self { inner })
    }

    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(&self.inner)
            .map_err(|e| ConfigError::Config(e.to_string()))?;
        atomic_write(path, text.as_bytes())?;
        set_mode_600(path);
        Ok(())
    }

    pub fn get(&self, alias: &str) -> Option<&TokenEntry> {
        self.inner.sessions.get(alias)
    }

    pub fn get_valid(&self, alias: &str) -> Option<&TokenEntry> {
        self.get(alias).filter(|e| !e.is_expired())
    }

    pub fn set(&mut self, alias: &str, entry: TokenEntry) {
        self.inner.sessions.insert(alias.to_owned(), entry);
    }

    pub fn clear(&mut self, alias: &str) {
        self.inner.sessions.remove(alias);
    }

    pub fn token_for(&self, alias: &str) -> Option<Zeroizing<String>> {
        self.get_valid(alias).map(|e| Zeroizing::new(e.token.clone()))
    }
}
