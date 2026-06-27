//! Persistent node identity.
//!
//! Every cluster node has a stable [`NodeId`]. Raft correctness depends on the
//! id surviving restarts, so a derived id is persisted to disk and read back on
//! subsequent boots. An operator may instead pin the id explicitly in config.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rand::Rng;

/// Cluster node identifier.
///
/// A `u64` because openraft requires node ids to be `Ord + Copy`; `u64` is the
/// conventional choice and leaves room for random, collision-resistant ids.
pub type NodeId = u64;

/// Filename, under the raft log directory, holding this node's persisted id.
const NODE_ID_FILE: &str = "node_id";

/// Errors resolving or persisting the node identity.
#[derive(thiserror::Error, Debug)]
pub enum IdentityError {
    /// The on-disk id file exists but does not contain a valid `u64`.
    #[error("node id file {path} is corrupt (not a u64)")]
    Corrupt {
        /// Path to the offending file.
        path: String,
    },
    /// An I/O error reading or writing the id file.
    #[error("node id I/O at {path}: {source}")]
    Io {
        /// Path being read or written.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
}

/// Resolve this node's id.
///
/// Precedence:
/// 1. `configured` (operator-pinned id) wins if `Some`.
/// 2. Otherwise read a previously persisted id from `<dir>/node_id`.
/// 3. Otherwise generate a fresh random id, persist it atomically, and return
///    it.
///
/// `dir` is created if it does not exist.
///
/// # Errors
///
/// Returns [`IdentityError`] if the directory cannot be created, the id file is
/// unreadable, or an existing file does not parse as a `u64`.
pub fn resolve_node_id(dir: &Path, configured: Option<NodeId>) -> Result<NodeId, IdentityError> {
    if let Some(id) = configured {
        return Ok(id);
    }

    let path = dir.join(NODE_ID_FILE);
    match fs::read_to_string(&path) {
        Ok(contents) => contents
            .trim()
            .parse::<NodeId>()
            .map_err(|_| IdentityError::Corrupt {
                path: path.display().to_string(),
            }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let id = generate_node_id();
            persist_node_id(dir, &path, id)?;
            Ok(id)
        }
        Err(source) => Err(IdentityError::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

/// Generate a fresh non-zero random node id. Zero is avoided because it is an
/// easy footgun (it reads like "unset" and some tooling treats it specially).
fn generate_node_id() -> NodeId {
    let mut rng = rand::rng();
    loop {
        let id = rng.next_u64();
        if id != 0 {
            return id;
        }
    }
}

/// Persist `id` to `path` atomically: write a sibling temp file, then rename it
/// into place so a crash never leaves a half-written id file.
fn persist_node_id(dir: &Path, path: &Path, id: NodeId) -> Result<(), IdentityError> {
    fs::create_dir_all(dir).map_err(|source| IdentityError::Io {
        path: dir.display().to_string(),
        source,
    })?;

    let tmp: PathBuf = path.with_extension("tmp");
    fs::write(&tmp, id.to_string()).map_err(|source| IdentityError::Io {
        path: tmp.display().to_string(),
        source,
    })?;
    fs::rename(&tmp, path).map_err(|source| IdentityError::Io {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn configured_id_wins() {
        let dir = tempfile::tempdir().unwrap();
        let id = resolve_node_id(dir.path(), Some(42)).unwrap();
        assert_eq!(id, 42);
        // Nothing is persisted when the id is pinned.
        assert!(!dir.path().join(NODE_ID_FILE).exists());
    }

    #[test]
    fn derived_id_is_stable_across_calls() {
        let dir = tempfile::tempdir().unwrap();
        let first = resolve_node_id(dir.path(), None).unwrap();
        assert_ne!(first, 0);
        // A second resolution reads the persisted value back.
        let second = resolve_node_id(dir.path(), None).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn derived_id_persists_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let id = resolve_node_id(dir.path(), None).unwrap();
        let on_disk: NodeId = fs::read_to_string(dir.path().join(NODE_ID_FILE))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(id, on_disk);
    }

    #[test]
    fn creates_missing_directory() {
        let base = tempfile::tempdir().unwrap();
        let nested = base.path().join("does/not/exist/yet");
        let id = resolve_node_id(&nested, None).unwrap();
        assert_ne!(id, 0);
        assert!(nested.join(NODE_ID_FILE).exists());
    }

    #[test]
    fn corrupt_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(NODE_ID_FILE), "not-a-number").unwrap();
        let err = resolve_node_id(dir.path(), None).unwrap_err();
        assert!(matches!(err, IdentityError::Corrupt { .. }));
    }
}
