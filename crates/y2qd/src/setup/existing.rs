//! Detection of an existing installation. Recomputed from the paths currently
//! in the form (and from the loaded config's paths) at every Paths validation
//! and at preflight, so editing a path never leaves stale facts behind.

use std::fs;
use std::path::Path;

use toml_edit::DocumentMut;

use super::validate::Probes;

/// A tri-state answer: the probe may be unable to tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tri {
    Yes,
    No,
    Unknown,
}

impl Tri {
    /// Combine two observations of the same fact: `Yes` wins, then `Unknown`.
    pub fn or(self, other: Tri) -> Tri {
        match (self, other) {
            (Tri::Yes, _) | (_, Tri::Yes) => Tri::Yes,
            (Tri::Unknown, _) | (_, Tri::Unknown) => Tri::Unknown,
            _ => Tri::No,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExistingInstall {
    pub config_exists: bool,
    /// Parse result of the existing config; `Ok(empty)` when the file is absent.
    pub config_parse: Result<DocumentMut, String>,
    pub keystore_json: bool,
    pub devices_json: bool,
    pub users_redb: bool,
    pub storage_nonempty: bool,
    pub daemon_running: Tri,
}

/// One (data directory, keystore directory) pair to inspect.
#[derive(Debug, Clone, Copy)]
pub struct PathPair<'a> {
    pub base_path: &'a Path,
    pub keystore_dir: &'a Path,
}

impl ExistingInstall {
    pub fn empty() -> Self {
        Self {
            config_exists: false,
            config_parse: Ok(DocumentMut::new()),
            keystore_json: false,
            devices_json: false,
            users_redb: false,
            storage_nonempty: false,
            daemon_running: Tri::No,
        }
    }

    /// Anything the wizard must warn about before changing it.
    pub fn any(&self) -> bool {
        self.config_exists
            || self.keystore_json
            || self.devices_json
            || self.users_redb
            || self.storage_nonempty
    }

    /// Inspect `config_path` and every pair in `pairs` (current form values and
    /// the loaded config's values); facts are OR-ed across the pairs.
    pub fn detect(config_path: &Path, pairs: &[PathPair<'_>], probes: &dyn Probes) -> Self {
        let mut out = Self::empty();
        match fs::read_to_string(config_path) {
            Ok(text) => {
                out.config_exists = true;
                out.config_parse = text.parse::<DocumentMut>().map_err(|e| e.to_string());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                out.config_exists = config_path.exists();
                out.config_parse = Err(format!("cannot read {}: {e}", config_path.display()));
            }
        }
        for p in pairs {
            out.keystore_json |= p.keystore_dir.join("keystore.json").exists();
            out.devices_json |= p.keystore_dir.join("devices.json").exists();
            out.users_redb |= p.keystore_dir.join("users.redb").exists();
            out.storage_nonempty |= fs::read_dir(p.base_path)
                .map(|mut d| d.next().is_some())
                .unwrap_or(false);
            out.daemon_running = out.daemon_running.or(probes.daemon_running(p.keystore_dir));
        }
        out
    }
}

/// Real daemon-running probe: only when `<dir>/.lock` exists, open it read-only
/// and try the exclusive flock. Never creates the lock or directories, and
/// drops its own lock immediately.
pub fn daemon_running_probe(keystore_dir: &Path) -> Tri {
    use std::fs::TryLockError;
    let lock = keystore_dir.join(".lock");
    let file = match fs::File::open(&lock) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Tri::No,
        Err(_) => return Tri::Unknown,
    };
    match file.try_lock() {
        Ok(()) => {
            // Lock acquired: nobody holds it. Release at once (drop also does).
            let _ = file.unlock();
            Tri::No
        }
        Err(TryLockError::WouldBlock) => Tri::Yes,
        Err(TryLockError::Error(_)) => Tri::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::validate::FakeProbes;

    #[test]
    fn detects_files_across_both_pairs() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        fs::write(b.path().join("keystore.json"), "{}").unwrap();
        fs::write(b.path().join("devices.json"), "{}").unwrap();
        let data = tempfile::tempdir().unwrap();
        fs::write(data.path().join("x"), "1").unwrap();
        let cfg = a.path().join("config.toml");
        fs::write(&cfg, "[server]\nport = 1\n").unwrap();
        let empty = tempfile::tempdir().unwrap();
        let ex = ExistingInstall::detect(
            &cfg,
            &[
                PathPair {
                    base_path: empty.path(),
                    keystore_dir: a.path(),
                },
                PathPair {
                    base_path: data.path(),
                    keystore_dir: b.path(),
                },
            ],
            &FakeProbes::default(),
        );
        assert!(ex.config_exists && ex.config_parse.is_ok());
        assert!(ex.keystore_json && ex.devices_json && !ex.users_redb);
        assert!(ex.storage_nonempty);
        assert!(ex.any());
    }

    #[test]
    fn fresh_dirs_are_empty_and_bad_config_is_reported() {
        let d = tempfile::tempdir().unwrap();
        let cfg = d.path().join("config.toml");
        let pair = PathPair {
            base_path: &d.path().join("nope"),
            keystore_dir: &d.path().join("nope2"),
        };
        let ex = ExistingInstall::detect(&cfg, &[pair], &FakeProbes::default());
        assert!(!ex.any());
        fs::write(&cfg, "[server\n").unwrap();
        let ex = ExistingInstall::detect(&cfg, &[pair], &FakeProbes::default());
        assert!(ex.config_exists && ex.config_parse.is_err());
    }

    #[test]
    fn daemon_probe_sees_a_held_lock_and_never_creates_one() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(daemon_running_probe(d.path()), Tri::No);
        assert!(!d.path().join(".lock").exists());
        let held = fs::File::create(d.path().join(".lock")).unwrap();
        held.lock().unwrap();
        assert_eq!(daemon_running_probe(d.path()), Tri::Yes);
        drop(held);
        assert_eq!(daemon_running_probe(d.path()), Tri::No);
    }

    #[test]
    fn tri_or_prefers_yes_then_unknown() {
        assert_eq!(Tri::No.or(Tri::Unknown), Tri::Unknown);
        assert_eq!(Tri::Unknown.or(Tri::Yes), Tri::Yes);
        assert_eq!(Tri::No.or(Tri::No), Tri::No);
    }
}
