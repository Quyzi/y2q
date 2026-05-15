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

/// One user record. The wrapped SK lets this user (and only this user) recover
/// the deployment secret key after presenting their password.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

/// Public-safe summary surfaced by `GET /api/v1/users`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSummary {
    pub username: String,
    pub created_at: u64,
    pub last_login: Option<u64>,
}

impl From<&UserRecord> for UserSummary {
    fn from(r: &UserRecord) -> Self {
        Self {
            username: r.username.clone(),
            created_at: r.created_at,
            last_login: r.last_login,
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
    pub fn open(path: &Path) -> Result<Self, CryptoError> {
        let db = Database::create(path)
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
        }
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
}
