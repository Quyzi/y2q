use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

fn is_false(b: &bool) -> bool {
    !*b
}

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

/// A server alias entry. Deserializes `password` but never serializes it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Alias {
    pub url: String,
    pub username: String,
    /// Accepted on load, never written back out.
    #[serde(default, skip_serializing)]
    pub password: Option<String>,
    /// Skip TLS certificate verification for this alias. Use only for
    /// self-signed dev/staging servers.
    #[serde(default, skip_serializing_if = "is_false")]
    pub insecure: bool,
    /// Optional PEM-encoded CA bundle to trust for the server certificate.
    /// Ignored when `insecure` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert_path: Option<String>,
    /// Optional client certificate (PEM) presented for mutual TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert_path: Option<String>,
    /// Optional client private key (PEM) paired with `client_cert_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_key_path: Option<String>,
}

/// Backwards-compatible alias for code still referencing the pre-rename name.
pub type Profile = Alias;

#[derive(Debug, Clone, Default, Serialize)]
pub struct CliConfig {
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub aliases: IndexMap<String, Alias>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct CliConfigRaw {
    #[serde(default)]
    aliases: IndexMap<String, Alias>,
    /// Legacy field, accepted on load and merged into `aliases`.
    #[serde(default)]
    profiles: IndexMap<String, Alias>,
}

impl CliConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        check_permissions(path);
        let text = std::fs::read_to_string(path)?;
        let raw: CliConfigRaw =
            toml::from_str(&text).map_err(|e| ConfigError::Config(e.to_string()))?;
        let migrated_from_profiles = !raw.profiles.is_empty();
        let mut aliases = raw.aliases;
        for (k, v) in raw.profiles {
            aliases.entry(k).or_insert(v);
        }
        if migrated_from_profiles {
            eprintln!(
                "note: migrated legacy [profiles.*] sections to [aliases.*] in {} on next save",
                path.display()
            );
        }
        Ok(Self { aliases })
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

    pub fn get_alias(&self, alias: &str) -> Result<&Alias, ConfigError> {
        self.aliases
            .get(alias)
            .ok_or_else(|| ConfigError::UnknownAlias(alias.to_owned()))
    }

    pub fn add_alias(&mut self, alias: String, entry: Alias) {
        self.aliases.insert(alias, entry);
    }

    pub fn remove_alias(&mut self, alias: &str) -> bool {
        self.aliases.shift_remove(alias).is_some()
    }
}

/// Write `data` to `path` atomically (write to a temp file, then rename).
///
/// The temp file is created at mode `0600` from the moment it's created,
/// not written-then-chmod'd afterward — files here (config, tokens) can
/// carry a live bearer token, and a widen-then-narrow window would let
/// another local user read it via the deterministic `<path>.tmp` name during
/// that gap.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<(), ConfigError> {
    let tmp = path.with_extension("tmp");
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data)?;
    }
    #[cfg(not(unix))]
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
                    "Warning: {} has permissions {:04o} - set to 0600 to protect your credentials.",
                    path.display(),
                    mode & 0o777
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alias(password: Option<&str>, insecure: bool) -> Alias {
        Alias {
            url: "https://example.invalid".to_owned(),
            username: "user".to_owned(),
            password: password.map(str::to_owned),
            insecure,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
        }
    }

    #[test]
    fn password_never_serialized() {
        let toml = toml::to_string(&alias(Some("hunter2"), false)).unwrap();
        assert!(!toml.contains("password"));
        assert!(!toml.contains("hunter2"));
    }

    #[test]
    fn defaults_omitted_extras_emitted() {
        // insecure=false and all cert paths None -> only url + username.
        let toml = toml::to_string(&alias(None, false)).unwrap();
        assert!(!toml.contains("insecure"));
        assert!(!toml.contains("ca_cert_path"));

        let mut a = alias(None, true);
        a.ca_cert_path = Some("/ca.pem".to_owned());
        a.client_cert_path = Some("/c.pem".to_owned());
        a.client_key_path = Some("/k.pem".to_owned());
        let toml = toml::to_string(&a).unwrap();
        assert!(toml.contains("insecure = true"));
        assert!(toml.contains("ca_cert_path"));
        assert!(toml.contains("client_cert_path"));
        assert!(toml.contains("client_key_path"));
    }

    #[test]
    fn password_round_trips_on_load_but_not_save() {
        let a = alias(Some("secret"), false);
        let toml = toml::to_string(&a).unwrap();
        let reloaded: Alias = toml::from_str(&toml).unwrap();
        assert_eq!(reloaded.password, None);
        assert_eq!(reloaded.url, a.url);
        assert_eq!(reloaded.username, a.username);
    }

    #[test]
    fn load_missing_path_is_default() {
        let dir = std::env::temp_dir().join(format!("y2q-cfg-{}", std::process::id()));
        let path = dir.join("does-not-exist.toml");
        let cfg = CliConfig::load(&path).unwrap();
        assert!(cfg.aliases.is_empty());
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir =
            std::env::temp_dir().join(format!("y2q-cfg-rt-{}-{:p}", std::process::id(), &0u8));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");

        let mut cfg = CliConfig::default();
        cfg.add_alias("prod".to_owned(), alias(Some("pw"), true));
        cfg.save(&path).unwrap();

        // Saved file must not leak the password.
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains("pw"));

        let loaded = CliConfig::load(&path).unwrap();
        let got = loaded.get_alias("prod").unwrap();
        assert!(got.insecure);
        assert_eq!(got.password, None);
        assert!(loaded.get_alias("missing").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn atomic_write_creates_file_at_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir =
            std::env::temp_dir().join(format!("y2q-cfg-perm-{}-{:p}", std::process::id(), &2u8));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tokens.toml");

        atomic_write(&path, b"secret-token-bytes").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_profiles_section_migrates_to_aliases() {
        let dir =
            std::env::temp_dir().join(format!("y2q-cfg-mig-{}-{:p}", std::process::id(), &1u8));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "[profiles.old]\nurl = \"https://x\"\nusername = \"u\"\n",
        )
        .unwrap();

        let mut cfg = CliConfig::load(&path).unwrap();
        assert!(cfg.get_alias("old").is_ok());
        assert!(cfg.remove_alias("old"));
        assert!(!cfg.remove_alias("old"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
