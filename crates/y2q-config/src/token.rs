use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
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
    /// Base URL this bearer was minted against. Empty for pre-binding entries;
    /// those are treated as unbound and refused until the user logs in again.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
}

impl TokenEntry {
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now + GRACE_SECS >= self.expires_at
    }

    /// Whether this entry may be presented to `url` as `username`.
    pub fn matches_target(&self, url: &str, username: &str) -> bool {
        !self.url.is_empty() && self.url == url && self.username == username
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
            return Ok(Self {
                inner: TokenFile::default(),
            });
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
        let text =
            toml::to_string_pretty(&self.inner).map_err(|e| ConfigError::Config(e.to_string()))?;
        atomic_write(path, text.as_bytes())?;
        set_mode_600(path);
        Ok(())
    }

    /// Load → mutate → save under an exclusive flock so concurrent login/
    /// logout processes cannot clobber each other's alias entries.
    ///
    /// The lock is a sibling `<path>.lock` so writers serialize even when
    /// `tokens.toml` itself is replaced via rename.
    pub fn update<F>(path: &Path, f: F) -> Result<(), ConfigError>
    where
        F: FnOnce(&mut Self) -> Result<(), ConfigError>,
    {
        let _guard = LockGuard::acquire(path)?;
        let mut store = Self::load(path)?;
        f(&mut store)?;
        store.save(path)
    }

    pub fn get(&self, alias: &str) -> Option<&TokenEntry> {
        self.inner.sessions.get(alias)
    }

    pub fn get_valid(&self, alias: &str) -> Option<&TokenEntry> {
        self.get(alias).filter(|e| !e.is_expired())
    }

    /// Valid, non-expired token bound to exactly this `(url, username)`.
    pub fn get_bound(&self, alias: &str, url: &str, username: &str) -> Option<&TokenEntry> {
        self.get_valid(alias)
            .filter(|e| e.matches_target(url, username))
    }

    pub fn set(&mut self, alias: &str, entry: TokenEntry) {
        self.inner.sessions.insert(alias.to_owned(), entry);
    }

    pub fn clear(&mut self, alias: &str) {
        self.inner.sessions.remove(alias);
    }

    pub fn token_for(&self, alias: &str) -> Option<Zeroizing<String>> {
        self.get_valid(alias)
            .map(|e| Zeroizing::new(e.token.clone()))
    }

    /// Bearer for `alias` only when it is still bound to `url`/`username`.
    pub fn token_for_bound(
        &self,
        alias: &str,
        url: &str,
        username: &str,
    ) -> Option<Zeroizing<String>> {
        self.get_bound(alias, url, username)
            .map(|e| Zeroizing::new(e.token.clone()))
    }
}

/// Exclusive flock held for the duration of a [`TokenStore::update`].
struct LockGuard {
    _file: File,
    /// Kept so the lock path is visible in Debug if needed; unused otherwise.
    #[allow(dead_code)]
    path: PathBuf,
}

impl LockGuard {
    fn acquire(tokens_path: &Path) -> Result<Self, ConfigError> {
        if let Some(parent) = tokens_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let lock_path = lock_path_for(tokens_path);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)?;
        set_mode_600(&lock_path);
        #[cfg(unix)]
        {
            file.lock().map_err(|e| {
                ConfigError::Config(format!("failed to lock {}: {e}", lock_path.display()))
            })?;
        }
        Ok(Self {
            _file: file,
            path: lock_path,
        })
    }
}

fn lock_path_for(tokens_path: &Path) -> PathBuf {
    let mut s = tokens_path.as_os_str().to_owned();
    s.push(".lock");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn entry(alias_user: &str, url: &str) -> TokenEntry {
        TokenEntry {
            token: format!("tok-{alias_user}"),
            expires_at: u64::MAX,
            username: alias_user.to_owned(),
            url: url.to_owned(),
        }
    }

    #[test]
    fn concurrent_updates_preserve_both_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.toml");
        let barrier = Arc::new(Barrier::new(2));

        let p1 = path.clone();
        let b1 = Arc::clone(&barrier);
        let t1 = thread::spawn(move || {
            b1.wait();
            TokenStore::update(&p1, |s| {
                s.set("cli", entry("alice", "http://a"));
                Ok(())
            })
            .unwrap();
        });

        let p2 = path.clone();
        let b2 = Arc::clone(&barrier);
        let t2 = thread::spawn(move || {
            b2.wait();
            TokenStore::update(&p2, |s| {
                s.set("uring", entry("bob", "http://b"));
                Ok(())
            })
            .unwrap();
        });

        t1.join().unwrap();
        t2.join().unwrap();

        let store = TokenStore::load(&path).unwrap();
        assert!(store.get("cli").is_some(), "cli token must survive");
        assert!(store.get("uring").is_some(), "uring token must survive");
    }

    #[test]
    fn bound_token_rejects_url_mismatch() {
        let mut store = TokenStore {
            inner: TokenFile::default(),
        };
        store.set("ua", entry("alice", "http://good"));
        assert!(
            store
                .token_for_bound("ua", "http://good", "alice")
                .is_some()
        );
        assert!(
            store
                .token_for_bound("ua", "http://attacker", "alice")
                .is_none()
        );
        assert!(store.token_for_bound("ua", "http://good", "eve").is_none());
    }

    #[test]
    fn legacy_empty_url_is_unbound() {
        let mut store = TokenStore {
            inner: TokenFile::default(),
        };
        store.set(
            "ua",
            TokenEntry {
                token: "t".into(),
                expires_at: u64::MAX,
                username: "alice".into(),
                url: String::new(),
            },
        );
        assert!(
            store
                .token_for_bound("ua", "http://good", "alice")
                .is_none()
        );
    }
}
