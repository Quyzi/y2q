//! redb-backed table of user records.
//!
//! Each record carries the user's Argon2id KDF parameters (shared by all its
//! credential slots) and exactly [`CREDENTIAL_SLOTS`] credential slots. A
//! slot is one password's worth of key material: its own ML-KEM-768 identity
//! keypair and a wrapped payload (role + duress flag). Multiple passwords
//! per user falls out of this directly: password *N* opens slot *N*, which
//! is a different identity holding different bucket grants. Unused slots
//! are filled with real keypairs wrapped under discarded random bytes, so
//! nothing on disk reveals how many passwords are actually in use.

use std::path::Path;
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use pqcrypto::kem::mlkem768;
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};

use super::CryptoError;
use super::kdf::{Argon2Params, WrappedSk};

/// `username` (UTF-8) → JSON-serialized [`UserRecord`].
const USERS: TableDefinition<&str, &[u8]> = TableDefinition::new("users");

/// Fixed number of credential slots every user record carries, occupied or
/// not. Never make this configurable: a deployment running with a different
/// width would leak its own setting, and a per-user width would leak per
/// user. Changing it is a format change, not a tunable.
pub const CREDENTIAL_SLOTS: usize = 4;

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
    /// deleting the account or its credential slots.
    Disabled,
}

/// One credential slot: a password's worth of identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSlot {
    /// This persona's ML-KEM-768 identity public key, standard-base64.
    /// Cleartext — it is what lets a bucket-key holder (phase 3) or the
    /// deployment-grant sealer (phase 1-2) seal a value to this persona
    /// without knowing its password.
    pub identity_pk_b64: String,
    /// `AES-256-GCM(KEK, SlotPayload)`. Opens only under this slot's
    /// password (KEK derived via the record's shared [`UserRecord::kdf`]).
    pub wrapped: WrappedSk,
}

/// Plaintext of a [`CredentialSlot::wrapped`] blob. Never stored in
/// cleartext — `role` and `revoke_other_sessions` living outside the wrap
/// would let an attacker with the disk pick the duress slot out by eye,
/// defeating the deniability property.
#[derive(Clone)]
pub struct SlotPayload {
    /// Raw ML-KEM-768 secret key bytes for this persona, standard-base64.
    pub identity_sk_b64: String,
    /// Effective role for a session opened with this password. Enforced
    /// `<=` the record's cleartext `role` when the slot is written.
    pub role: Role,
    /// When true, a login through this slot revokes every live session of
    /// this username that belongs to a different slot.
    pub revoke_other_sessions: bool,
}

// A derived `Debug` would print the raw secret key; redact it explicitly,
// matching `DecryptedKeystore`'s and `SessionInfo`'s pattern.
impl std::fmt::Debug for SlotPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlotPayload")
            .field("identity_sk_b64", &"<redacted>")
            .field("role", &self.role)
            .field("revoke_other_sessions", &self.revoke_other_sessions)
            .finish()
    }
}

impl SlotPayload {
    /// Fixed-width binary encoding: `[identity_sk | role (1 byte) | revoke
    /// (1 byte)]`. Deliberately not JSON: a JSON encoding of `role` and
    /// `revoke_other_sessions` varies in byte length with their value
    /// (`"admin"` vs `"readonly"`, `true` vs `false`), which would leak
    /// which role or duress flag a slot carries via its wrapped ciphertext
    /// length even though the payload itself stays encrypted. This encoding
    /// is exactly `mlkem768::secret_key_bytes() + 2` bytes for every slot,
    /// occupied or decoy, real role or not.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let sk = STANDARD
            .decode(&self.identity_sk_b64)
            .map_err(|e| CryptoError::Kdf(format!("decode identity sk: {e}")))?;
        if sk.len() != mlkem768::secret_key_bytes() {
            return Err(CryptoError::Kdf(format!(
                "identity secret key wrong size: {} (expected {})",
                sk.len(),
                mlkem768::secret_key_bytes()
            )));
        }
        let mut out = Vec::with_capacity(sk.len() + 2);
        out.extend_from_slice(&sk);
        out.push(role_to_byte(self.role));
        out.push(self.revoke_other_sessions as u8);
        Ok(out)
    }

    /// Inverse of [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let expected = mlkem768::secret_key_bytes() + 2;
        if bytes.len() != expected {
            return Err(CryptoError::Kdf(format!(
                "slot payload wrong size: {} (expected {expected})",
                bytes.len()
            )));
        }
        let (sk, tail) = bytes.split_at(mlkem768::secret_key_bytes());
        let role = role_from_byte(tail[0])
            .ok_or_else(|| CryptoError::Kdf(format!("invalid role byte: {}", tail[0])))?;
        Ok(Self {
            identity_sk_b64: STANDARD.encode(sk),
            role,
            revoke_other_sessions: tail[1] != 0,
        })
    }
}

fn role_to_byte(role: Role) -> u8 {
    match role {
        Role::Admin => 0,
        Role::User => 1,
        Role::ReadOnly => 2,
        Role::WriteOnly => 3,
        Role::Auditor => 4,
        Role::Disabled => 5,
    }
}

fn role_from_byte(b: u8) -> Option<Role> {
    match b {
        0 => Some(Role::Admin),
        1 => Some(Role::User),
        2 => Some(Role::ReadOnly),
        3 => Some(Role::WriteOnly),
        4 => Some(Role::Auditor),
        5 => Some(Role::Disabled),
        _ => None,
    }
}

/// One user record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRecord {
    /// Login name, case-sensitive.
    pub username: String,
    /// Nanoseconds since Unix epoch.
    pub created_at: u64,
    /// Nanoseconds since Unix epoch of last successful login (`None` if never).
    pub last_login: Option<u64>,
    /// Argon2id parameters, shared by every slot (see the module docs on
    /// [`super::kdf`] for why one shared per-record salt is safe).
    pub kdf: Argon2Params,
    /// Always exactly [`CREDENTIAL_SLOTS`] entries. Unused slots are
    /// present and byte-shaped identically to live ones — never trim this.
    pub slots: Vec<CredentialSlot>,
    /// Which slot holds the identity a third party grants (`set_acl`,
    /// `rotate-key`) resolve to for this account — chosen uniformly at
    /// random on creation ([`kdf::new_slots_random`](super::kdf::new_slots_random)),
    /// never a fixed position. This is internal server bookkeeping only:
    /// it is never serialized into any API response (not `UserSummary`,
    /// not `PersonaView`), because a coercer who can read it off a live
    /// session would trivially learn "this exact slot is the real one"
    /// with no cracking required. A disk-holding attacker learns nothing
    /// beyond what a fixed slot-0 convention already gave away for free —
    /// the field only closes the *API-only* leak (a technical coercer
    /// probing `GET /api/v1/personas/me` themselves and reading off a
    /// suspiciously-privileged slot number).
    pub primary_slot: u8,
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
    /// Every record stores a user's Argon2id KDF parameters and their
    /// credential slots, so the file is created at mode `0600` from the
    /// moment it's created (not widen-then-chmod) to close any window where
    /// it would be world/group-readable. An already-existing file (e.g. from
    /// a build predating this hardening) has its permissions re-tightened on
    /// every open as defense in depth.
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
    use crate::crypto::kdf::{self, default_argon2_params};
    use tempfile::tempdir;

    fn rec(name: &str) -> UserRecord {
        let params = default_argon2_params();
        let mut slots = vec![kdf::new_slot(name, 0, b"pw", &params, Role::User, false).unwrap()];
        for i in 1..CREDENTIAL_SLOTS {
            slots.push(kdf::decoy_slot(name, i, &params).unwrap());
        }
        UserRecord {
            username: name.to_owned(),
            created_at: 1,
            last_login: None,
            kdf: params,
            slots,
            primary_slot: 0,
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
    fn record_always_carries_credential_slots() {
        let r = rec("alice");
        assert_eq!(r.slots.len(), CREDENTIAL_SLOTS);
        // Occupied and decoy slots are byte-shape indistinguishable: every
        // wrapped ciphertext is the same length (a fixed-size SlotPayload
        // JSON blob, always the same length regardless of content).
        let lens: Vec<usize> = r.slots.iter().map(|s| s.wrapped.ciphertext.len()).collect();
        assert!(lens.iter().all(|&l| l == lens[0]));
    }

    #[test]
    fn login_shaped_unwrap_opens_exactly_one_slot_and_none_for_a_wrong_password() {
        // Mirrors the daemon's login path (`attempt_unwrap`): one Argon2
        // derivation, then try every slot's unwrap without short-circuiting.
        // A correct password must open exactly the one real slot; a wrong
        // password must open none - proving the login path can't
        // accidentally cross-open a different persona.
        let r = rec("alice");
        let kek = r.kdf.derive_kek(b"pw").unwrap();
        let opened: Vec<usize> = r
            .slots
            .iter()
            .enumerate()
            .filter(|(i, s)| {
                kdf::unwrap_slot(&s.wrapped, &kek, &kdf::slot_wrap_aad("alice", *i)).is_ok()
            })
            .map(|(i, _)| i)
            .collect();
        assert_eq!(opened, vec![0]);

        let wrong_kek = r.kdf.derive_kek(b"not-the-password").unwrap();
        let opened_wrong = r
            .slots
            .iter()
            .enumerate()
            .filter(|(i, s)| {
                kdf::unwrap_slot(&s.wrapped, &wrong_kek, &kdf::slot_wrap_aad("alice", *i)).is_ok()
            })
            .count();
        assert_eq!(opened_wrong, 0);
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
