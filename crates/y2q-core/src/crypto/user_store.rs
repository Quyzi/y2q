//! redb-backed table of user records.
//!
//! Each record carries the user's KDF parameters and a copy of the
//! deployment secret key wrapped under a key derived from that user's
//! password. Adding a user requires the SK to currently be in process
//! memory (so the new user record can be wrapped); deleting a user just
//! drops their record.

use std::path::Path;
use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};

use super::CryptoError;
use super::kdf::{Argon2Params, WrappedSk};

/// `username` (UTF-8) → JSON-serialized [`UserRecord`].
const USERS: TableDefinition<&str, &[u8]> = TableDefinition::new("users");

/// Global role of a user: an account-wide capability ceiling applied on top of
/// per-bucket ownership and ACL grants. The daemon interprets each role as a
/// set of allowed verbs (read / write / admin) and whether the role can see
/// every bucket; see `y2qd`'s `authz` module for the exact mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Full administrative access: all admin endpoints plus every bucket.
    Admin,
    /// Regular user: no admin endpoints; bucket access governed by ownership
    /// and ACL grants only.
    #[default]
    User,
    /// Read-only on every bucket the user can otherwise reach (owned or
    /// granted). No writes, deletes, or admin actions anywhere.
    ReadOnly,
    /// Write/delete only, on buckets the user can otherwise reach — never read.
    /// A drop-box / ingest account.
    WriteOnly,
    /// Read-only across *all* buckets (global visibility) plus read access to
    /// admin endpoints (user list, rebuild status, lock list, any bucket's
    /// ACL). A look-but-don't-touch administrator. No mutations.
    Auditor,
    /// Suspended: every request is rejected and login is refused, without
    /// deleting the account or its wrapped secret-key copy.
    Disabled,
}

/// One user record. The wrapped SK lets this user (and only this user) recover
/// the deployment secret key after presenting their password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRecord {
    /// Login name, case-sensitive.
    pub username: String,
    /// Nanoseconds since Unix epoch.
    pub created_at: u64,
    /// Nanoseconds since Unix epoch of last successful login (`None` if never).
    pub last_login: Option<u64>,
    /// Argon2id parameters used to derive this user's KEK.
    pub kdf: Argon2Params,
    /// The deployment SK wrapped under this user's KEK.
    pub wrapped_sk: WrappedSk,
    /// Global role. Defaults to [`Role::User`] so records written before this
    /// field existed deserialize as ordinary users (no migration pass needed).
    #[serde(default)]
    pub role: Role,
}

/// Public-safe summary surfaced by `GET /api/v1/users`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSummary {
    /// Login name, case-sensitive.
    pub username: String,
    /// Nanoseconds since Unix epoch when the account was created.
    pub created_at: u64,
    /// Nanoseconds since Unix epoch of the last successful login, or `None` if never.
    pub last_login: Option<u64>,
    /// Global role of the user.
    pub role: Role,
}

impl From<&UserRecord> for UserSummary {
    fn from(r: &UserRecord) -> Self {
        Self {
            username: r.username.clone(),
            created_at: r.created_at,
            last_login: r.last_login,
            role: r.role,
        }
    }
}

/// Cheap-to-clone handle to the user-records redb file.
#[derive(Clone)]
pub struct UserStore {
    db: Arc<Database>,
}

impl UserStore {
    /// Open or create the user-records database at `path`.
    ///
    /// Every record stores a user's Argon2id KDF parameters and their wrapped
    /// copy of the deployment secret key, so the file is created at mode
    /// `0600` from the moment it's created (not widen-then-chmod) to close
    /// any window where it would be world/group-readable. An already-existing
    /// file (e.g. from a build predating this hardening) has its permissions
    /// re-tightened on every open as defense in depth.
    pub fn open(path: &Path) -> Result<Self, CryptoError> {
        let mut open_options = std::fs::OpenOptions::new();
        open_options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open_options.mode(0o600);
        }
        let file = open_options
            .open(path)
            .map_err(|e| CryptoError::UserStore(format!("open {}: {e}", path.display())))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        let db = redb::Builder::new()
            .create_file(file)
            .map_err(|e| CryptoError::UserStore(format!("open {}: {e}", path.display())))?;
        let txn = db
            .begin_write()
            .map_err(|e| CryptoError::UserStore(format!("begin_write: {e}")))?;
        {
            let _ = txn
                .open_table(USERS)
                .map_err(|e| CryptoError::UserStore(format!("open table: {e}")))?;
        }
        txn.commit()
            .map_err(|e| CryptoError::UserStore(format!("commit: {e}")))?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Insert or replace `record`. Caller is responsible for any pre-checks
    /// (e.g. "must not already exist" for the add-user endpoint).
    pub fn upsert(&self, record: &UserRecord) -> Result<(), CryptoError> {
        let payload = serde_json::to_vec(record)
            .map_err(|e| CryptoError::UserStore(format!("serialize record: {e}")))?;
        let txn = self
            .db
            .begin_write()
            .map_err(|e| CryptoError::UserStore(format!("begin_write: {e}")))?;
        {
            let mut t = txn
                .open_table(USERS)
                .map_err(|e| CryptoError::UserStore(format!("open table: {e}")))?;
            t.insert(record.username.as_str(), payload.as_slice())
                .map_err(|e| CryptoError::UserStore(format!("insert: {e}")))?;
        }
        txn.commit()
            .map_err(|e| CryptoError::UserStore(format!("commit: {e}")))?;
        Ok(())
    }

    /// Look up a user record by username. Returns `Ok(None)` if absent.
    pub fn get(&self, username: &str) -> Result<Option<UserRecord>, CryptoError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| CryptoError::UserStore(format!("begin_read: {e}")))?;
        let t = txn
            .open_table(USERS)
            .map_err(|e| CryptoError::UserStore(format!("open table: {e}")))?;
        let row = t
            .get(username)
            .map_err(|e| CryptoError::UserStore(format!("get: {e}")))?;
        match row {
            None => Ok(None),
            Some(g) => {
                let r: UserRecord = serde_json::from_slice(g.value())
                    .map_err(|e| CryptoError::UserStore(format!("deserialize record: {e}")))?;
                Ok(Some(r))
            }
        }
    }

    /// Remove the record for `username`. Returns `true` if a record was
    /// removed, `false` if it didn't exist.
    pub fn delete(&self, username: &str) -> Result<bool, CryptoError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| CryptoError::UserStore(format!("begin_write: {e}")))?;
        let removed;
        {
            let mut t = txn
                .open_table(USERS)
                .map_err(|e| CryptoError::UserStore(format!("open table: {e}")))?;
            removed = t
                .remove(username)
                .map_err(|e| CryptoError::UserStore(format!("remove: {e}")))?
                .is_some();
        }
        txn.commit()
            .map_err(|e| CryptoError::UserStore(format!("commit: {e}")))?;
        Ok(removed)
    }

    /// Return summaries of every user, sorted ascending by username.
    pub fn list(&self) -> Result<Vec<UserSummary>, CryptoError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| CryptoError::UserStore(format!("begin_read: {e}")))?;
        let t = txn
            .open_table(USERS)
            .map_err(|e| CryptoError::UserStore(format!("open table: {e}")))?;
        let mut out = Vec::new();
        for entry in t
            .iter()
            .map_err(|e| CryptoError::UserStore(format!("iter: {e}")))?
        {
            let (_k, v) = entry.map_err(|e| CryptoError::UserStore(format!("iter row: {e}")))?;
            let r: UserRecord = serde_json::from_slice(v.value())
                .map_err(|e| CryptoError::UserStore(format!("deserialize record: {e}")))?;
            out.push(UserSummary::from(&r));
        }
        out.sort_by(|a, b| a.username.cmp(&b.username));
        Ok(out)
    }

    /// Total number of records.
    pub fn count(&self) -> Result<usize, CryptoError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| CryptoError::UserStore(format!("begin_read: {e}")))?;
        let t = txn
            .open_table(USERS)
            .map_err(|e| CryptoError::UserStore(format!("open table: {e}")))?;
        let n = t
            .len()
            .map_err(|e| CryptoError::UserStore(format!("len: {e}")))?;
        Ok(n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::{default_argon2_params, wrap_sk};
    use tempfile::tempdir;

    fn rec(name: &str) -> UserRecord {
        let params = default_argon2_params();
        let wrapped = wrap_sk(b"fake-sk-bytes", b"pw", &params).unwrap();
        UserRecord {
            username: name.to_owned(),
            created_at: 1,
            last_login: None,
            kdf: params,
            wrapped_sk: wrapped,
            role: Role::User,
        }
    }

    #[test]
    fn legacy_record_without_role_defaults_to_user() {
        // Simulate a record written before the `role` field existed by dropping
        // it from the serialized JSON; it must deserialize as `User`.
        let mut r = rec("old");
        r.role = Role::Admin;
        let mut v: serde_json::Value = serde_json::to_value(&r).unwrap();
        v.as_object_mut().unwrap().remove("role");
        let back: UserRecord = serde_json::from_value(v).unwrap();
        assert_eq!(back.role, Role::User);
    }

    #[test]
    fn role_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Role::Admin).unwrap(), "\"admin\"");
        assert_eq!(serde_json::to_string(&Role::User).unwrap(), "\"user\"");
        let r: Role = serde_json::from_str("\"admin\"").unwrap();
        assert_eq!(r, Role::Admin);
    }

    #[test]
    fn summary_carries_role() {
        let mut r = rec("admin-user");
        r.role = Role::Admin;
        let s = UserSummary::from(&r);
        assert_eq!(s.role, Role::Admin);
    }

    #[test]
    fn upsert_get_delete_list() {
        let dir = tempdir().unwrap();
        let s = UserStore::open(&dir.path().join("u.redb")).unwrap();
        s.upsert(&rec("alice")).unwrap();
        s.upsert(&rec("bob")).unwrap();
        assert_eq!(s.count().unwrap(), 2);

        let got = s.get("alice").unwrap().unwrap();
        assert_eq!(got.username, "alice");

        let names: Vec<String> = s.list().unwrap().into_iter().map(|u| u.username).collect();
        assert_eq!(names, vec!["alice", "bob"]);

        assert!(s.delete("alice").unwrap());
        assert!(!s.delete("alice").unwrap());
        assert_eq!(s.count().unwrap(), 1);
    }

    #[test]
    #[cfg(unix)]
    fn opens_with_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("u.redb");
        let _s = UserStore::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
