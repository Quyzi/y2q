//! Keystore manifest (`keystore.json`) plus first-run key generation.
//!
//! The keystore directory holds three things:
//!
//! - `keystore.json` — the [`KeystoreManifest`]: the node-key verifier.
//! - `users.redb` — the user store ([`super::user_store::UserStore`]).
//! - `.lock` — POSIX advisory lock acquired for daemon process lifetime by
//!   the caller; no code in this module touches it.
//!
//! A directory still holding the pre-hierarchy `pubkey.json` is refused
//! outright with [`CryptoError::LegacyKeystore`] — there is no conversion
//! path; re-initialize the deployment.
//!
//! Generating a fresh root persona and writing both files is the
//! [`first_run`] entry point. Subsequent starts go through [`load`], which
//! additionally verifies the supplied node key against the manifest's
//! verifier.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::CryptoError;
use super::kdf::{self, Argon2Params};
use super::node_keys::derive_node_key_verifier;
use super::user_store::{Role, UserRecord, UserStore};

/// On-disk format version written to `keystore.json`.
pub const KEYSTORE_FORMAT_VERSION: u16 = 3;

/// Standard filenames within the keystore directory.
pub struct KeystoreFiles {
    /// Root directory path (the `keystore_dir` from config).
    pub root: PathBuf,
    /// Path to `keystore.json` (the keystore manifest, non-secret).
    pub manifest: PathBuf,
    /// Path to `users.redb` (the user-records database).
    pub users: PathBuf,
    /// Path to `.lock` (POSIX advisory exclusive lock held by the daemon).
    pub lock: PathBuf,
}

impl KeystoreFiles {
    /// Build all standard paths rooted at `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let root: PathBuf = dir.into();
        Self {
            manifest: root.join("keystore.json"),
            users: root.join("users.redb"),
            lock: root.join(".lock"),
            root,
        }
    }
}

/// On-disk shape of `keystore.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeystoreManifest {
    /// Always [`KEYSTORE_FORMAT_VERSION`].
    format_version: u16,
    /// Base64 of `derive_node_key_verifier(NK)`. Detects a wrong node key at
    /// boot and doubles as the cluster admission fingerprint.
    node_key_verifier_b64: String,
    /// Nanoseconds since the Unix epoch.
    created_at: u64,
}

/// Result of a successful first-run setup.
pub struct FirstRunOutcome {
    /// User store with the freshly-created `root` user.
    pub user_store: UserStore,
    /// The randomly-generated root password — print exactly once, then drop.
    pub root_password: String,
    /// Username assigned to the initial user (currently always `"root"`).
    pub root_username: String,
}

/// Load an existing keystore directory, verifying `nk` against the stored
/// node-key verifier.
///
/// Ordering, all failures fatal:
/// 1. A pre-hierarchy `pubkey.json` present → [`CryptoError::LegacyKeystore`]
///    (clean-cutover guard; there is no conversion path).
/// 2. `keystore.json` and `users.redb` both absent →
///    [`CryptoError::KeystoreMissing`] (caller should branch to
///    [`first_run`]).
/// 3. `keystore.json` absent but `users.redb` present →
///    [`CryptoError::KeystoreCorrupt`].
/// 4. `format_version` mismatch → [`CryptoError::KeystoreCorrupt`].
/// 5. Verifier mismatch (constant-time compared) →
///    [`CryptoError::NodeKeyMismatch`].
///
/// Returns the user store.
pub fn load(dir: &Path, nk: &[u8; 32]) -> Result<UserStore, CryptoError> {
    let files = KeystoreFiles::new(dir);

    let legacy_pubkey = files.root.join("pubkey.json");
    if legacy_pubkey.exists() {
        return Err(CryptoError::LegacyKeystore(
            legacy_pubkey.display().to_string(),
        ));
    }

    if !files.manifest.exists() {
        if files.users.exists() {
            return Err(CryptoError::KeystoreCorrupt {
                path: files.manifest.display().to_string(),
                reason: "keystore.json missing but users.redb present".to_owned(),
            });
        }
        return Err(CryptoError::KeystoreMissing(
            files.manifest.display().to_string(),
        ));
    }

    let raw = fs::read(&files.manifest)
        .map_err(|e| CryptoError::KeystoreIo(format!("read {}: {e}", files.manifest.display())))?;
    let parsed: KeystoreManifest =
        serde_json::from_slice(&raw).map_err(|e| CryptoError::KeystoreCorrupt {
            path: files.manifest.display().to_string(),
            reason: format!("parse: {e}"),
        })?;
    if parsed.format_version != KEYSTORE_FORMAT_VERSION {
        return Err(CryptoError::KeystoreCorrupt {
            path: files.manifest.display().to_string(),
            reason: format!(
                "unsupported format_version {} (expected {KEYSTORE_FORMAT_VERSION})",
                parsed.format_version
            ),
        });
    }

    let actual_verifier = STANDARD
        .decode(&parsed.node_key_verifier_b64)
        .map_err(|e| CryptoError::KeystoreCorrupt {
            path: files.manifest.display().to_string(),
            reason: format!("verifier base64 decode: {e}"),
        })?;
    let expected_verifier = derive_node_key_verifier(nk);
    let verifier_matches = actual_verifier.len() == expected_verifier.len()
        && bool::from(actual_verifier.ct_eq(&expected_verifier));
    if !verifier_matches {
        return Err(CryptoError::NodeKeyMismatch);
    }

    UserStore::open(&files.users)
}

/// Generate a fresh root persona, write `keystore.json` and `users.redb`,
/// and return everything the caller needs to print the password and start
/// serving.
///
/// The `params` argument is the Argon2id parameter triple to use for
/// wrapping the root user's credential slots. Callers should source these
/// from `[crypto.argon2]` in `config.toml` so operators can tune them. `nk`
/// is the operator-supplied node key, whose verifier is written into the
/// manifest so a later [`load`] with a different key is caught rather than
/// silently forking the deployment.
pub fn first_run(
    dir: &Path,
    root_username: &str,
    params: Argon2Params,
    nk: &[u8; 32],
) -> Result<FirstRunOutcome, CryptoError> {
    let files = KeystoreFiles::new(dir);
    fs::create_dir_all(&files.root)
        .map_err(|e| CryptoError::KeystoreIo(format!("mkdir {}: {e}", files.root.display())))?;
    if files.manifest.exists() {
        return Err(CryptoError::KeystoreIo(format!(
            "{} already exists; refusing to overwrite",
            files.manifest.display()
        )));
    }

    let root_password = generate_root_password();
    let (slots, primary_slot) = kdf::new_slots_random(
        root_username,
        root_password.as_bytes(),
        &params,
        Role::Admin,
        false,
    )?;

    let manifest = KeystoreManifest {
        format_version: KEYSTORE_FORMAT_VERSION,
        node_key_verifier_b64: STANDARD.encode(derive_node_key_verifier(nk)),
        created_at: now_ns(),
    };
    write_manifest(&files.manifest, &manifest)?;

    let user_store = UserStore::open(&files.users)?;
    let record = UserRecord {
        username: root_username.to_owned(),
        created_at: now_ns(),
        last_login: None,
        kdf: params,
        slots,
        primary_slot: primary_slot as u8,
        // The bootstrap user is the daemon's first administrator.
        role: Role::Admin,
    };
    user_store.upsert(&record)?;

    Ok(FirstRunOutcome {
        user_store,
        root_password,
        root_username: root_username.to_owned(),
    })
}

fn write_manifest(path: &Path, manifest: &KeystoreManifest) -> Result<(), CryptoError> {
    let json = serde_json::to_vec_pretty(manifest)
        .map_err(|e| CryptoError::KeystoreIo(format!("serialize keystore manifest: {e}")))?;
    let mut opts = OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| CryptoError::KeystoreIo(format!("open {} O_EXCL: {e}", path.display())))?;
    f.write_all(&json)
        .map_err(|e| CryptoError::KeystoreIo(format!("write {}: {e}", path.display())))?;
    f.sync_all()
        .map_err(|e| CryptoError::KeystoreIo(format!("fsync {}: {e}", path.display())))?;
    Ok(())
}

/// Filename of the crash-safety journal an offline node-key rotation writes
/// before touching anything, and deletes only once the rotation fully
/// completes (verifier rewritten last). Its presence at boot means a prior
/// rotation was interrupted — the daemon refuses to start until the
/// operator re-runs `--rotate-node-key` to finish it.
const ROTATION_JOURNAL_FILE: &str = "node-key-rotation.json";

/// On-disk shape of the rotation journal. Carries both verifiers so a
/// resuming run can confirm it was handed the *same* key pair as the
/// interrupted one, rather than a third key silently picking up a
/// half-converted tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationJournal {
    pub old_verifier_b64: String,
    pub new_verifier_b64: String,
}

fn rotation_journal_path(dir: &Path) -> PathBuf {
    dir.join(ROTATION_JOURNAL_FILE)
}

/// Whether an interrupted rotation's journal is present in `dir`.
pub fn rotation_journal_exists(dir: &Path) -> bool {
    rotation_journal_path(dir).exists()
}

/// Write the rotation journal for `(old_nk, new_nk)`. Must be called before
/// any object, bucket, or the index is touched — it's what makes the
/// rotation's "offline" property crash-safe rather than merely advisory.
pub fn write_rotation_journal(
    dir: &Path,
    old_nk: &[u8; 32],
    new_nk: &[u8; 32],
) -> Result<(), CryptoError> {
    let journal = RotationJournal {
        old_verifier_b64: STANDARD.encode(derive_node_key_verifier(old_nk)),
        new_verifier_b64: STANDARD.encode(derive_node_key_verifier(new_nk)),
    };
    let json = serde_json::to_vec_pretty(&journal)
        .map_err(|e| CryptoError::KeystoreIo(format!("serialize rotation journal: {e}")))?;
    let path = rotation_journal_path(dir);
    let mut opts = OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&path)
        .map_err(|e| CryptoError::KeystoreIo(format!("create {}: {e}", path.display())))?;
    f.write_all(&json)
        .map_err(|e| CryptoError::KeystoreIo(format!("write {}: {e}", path.display())))?;
    f.sync_all()
        .map_err(|e| CryptoError::KeystoreIo(format!("fsync {}: {e}", path.display())))?;
    Ok(())
}

/// Read the rotation journal, if present.
pub fn read_rotation_journal(dir: &Path) -> Result<Option<RotationJournal>, CryptoError> {
    let path = rotation_journal_path(dir);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read(&path)
        .map_err(|e| CryptoError::KeystoreIo(format!("read {}: {e}", path.display())))?;
    let journal: RotationJournal =
        serde_json::from_slice(&raw).map_err(|e| CryptoError::KeystoreCorrupt {
            path: path.display().to_string(),
            reason: format!("parse rotation journal: {e}"),
        })?;
    Ok(Some(journal))
}

/// Delete the rotation journal — the last step of a successful rotation.
pub fn delete_rotation_journal(dir: &Path) -> Result<(), CryptoError> {
    let path = rotation_journal_path(dir);
    if path.exists() {
        fs::remove_file(&path)
            .map_err(|e| CryptoError::KeystoreIo(format!("remove {}: {e}", path.display())))?;
    }
    Ok(())
}

/// Rewrite `keystore.json`'s node-key verifier after an offline node-key
/// rotation, once every object and bucket directory has already been
/// migrated to `new_nk`. `created_at` is preserved from the existing
/// manifest — this is a rotation, not a re-initialization.
pub fn rewrite_verifier(dir: &Path, new_nk: &[u8; 32]) -> Result<(), CryptoError> {
    let files = KeystoreFiles::new(dir);
    let raw = fs::read(&files.manifest)
        .map_err(|e| CryptoError::KeystoreIo(format!("read {}: {e}", files.manifest.display())))?;
    let mut parsed: KeystoreManifest =
        serde_json::from_slice(&raw).map_err(|e| CryptoError::KeystoreCorrupt {
            path: files.manifest.display().to_string(),
            reason: format!("parse: {e}"),
        })?;
    parsed.node_key_verifier_b64 = STANDARD.encode(derive_node_key_verifier(new_nk));
    let json = serde_json::to_vec_pretty(&parsed)
        .map_err(|e| CryptoError::KeystoreIo(format!("serialize keystore manifest: {e}")))?;
    let tmp = files.manifest.with_extension("json.rotate-tmp");
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&tmp)
        .map_err(|e| CryptoError::KeystoreIo(format!("open {}: {e}", tmp.display())))?;
    f.write_all(&json)
        .map_err(|e| CryptoError::KeystoreIo(format!("write {}: {e}", tmp.display())))?;
    f.sync_all()
        .map_err(|e| CryptoError::KeystoreIo(format!("fsync {}: {e}", tmp.display())))?;
    drop(f);
    fs::rename(&tmp, &files.manifest).map_err(|e| {
        CryptoError::KeystoreIo(format!("rename {}: {e}", files.manifest.display()))
    })?;
    Ok(())
}

fn generate_root_password() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rand::Rng;
    let mut buf = [0u8; 24];
    rand::rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Acquire a POSIX advisory exclusive lock on `<dir>/.lock`. The returned
/// [`File`] must be kept alive for the duration the lock should be held —
/// dropping it (or process exit) releases the lock.
pub fn acquire_lock(dir: &Path) -> Result<File, CryptoError> {
    use fs2::FileExt;
    fs::create_dir_all(dir)
        .map_err(|e| CryptoError::KeystoreIo(format!("mkdir {}: {e}", dir.display())))?;
    let lock_path = dir.join(".lock");
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| CryptoError::KeystoreIo(format!("open lock {}: {e}", lock_path.display())))?;
    f.try_lock_exclusive().map_err(|e| {
        CryptoError::KeystoreIo(format!(
            "another y2qd already holds {}: {e}",
            lock_path.display()
        ))
    })?;
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::super::user_store::CREDENTIAL_SLOTS;
    use super::*;
    use tempfile::tempdir;

    fn nk(seed: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k.fill(seed);
        k
    }

    #[test]
    fn first_run_then_load() {
        let dir = tempdir().unwrap();
        let k = nk(1);
        let root_password = {
            let outcome = first_run(
                dir.path(),
                "root",
                Argon2Params::with_random_salt(8 * 1024, 1, 1),
                &k,
            )
            .unwrap();
            assert!(!outcome.root_password.is_empty());
            outcome.root_password
        };

        let users = load(dir.path(), &k).unwrap();

        // Root's persona lives at a randomly-chosen slot; recover it via
        // primary_slot rather than assuming a fixed index.
        let rec = users.get("root").unwrap().unwrap();
        assert_eq!(rec.slots.len(), CREDENTIAL_SLOTS);
        let slot = rec.primary_slot as usize;
        let kek = rec.kdf.derive_kek(root_password.as_bytes()).unwrap();
        let aad = kdf::slot_wrap_aad("root", slot);
        let payload_bytes = kdf::unwrap_slot(&rec.slots[slot].wrapped, &kek, &aad).unwrap();
        let payload = super::super::user_store::SlotPayload::from_bytes(&payload_bytes).unwrap();
        assert_eq!(payload.role, Role::Admin);
    }

    #[test]
    fn first_run_refuses_overwrite() {
        let dir = tempdir().unwrap();
        let k = nk(1);
        let _ = first_run(
            dir.path(),
            "root",
            Argon2Params::with_random_salt(8 * 1024, 1, 1),
            &k,
        )
        .unwrap();
        assert!(matches!(
            first_run(
                dir.path(),
                "root",
                Argon2Params::with_random_salt(8 * 1024, 1, 1),
                &k
            ),
            Err(CryptoError::KeystoreIo(_))
        ));
    }

    #[test]
    fn load_missing_returns_keystore_missing() {
        let dir = tempdir().unwrap();
        assert!(matches!(
            load(dir.path(), &nk(1)),
            Err(CryptoError::KeystoreMissing(_))
        ));
    }

    #[test]
    fn load_wrong_node_key_returns_mismatch() {
        let dir = tempdir().unwrap();
        first_run(
            dir.path(),
            "root",
            Argon2Params::with_random_salt(8 * 1024, 1, 1),
            &nk(1),
        )
        .unwrap();
        assert!(matches!(
            load(dir.path(), &nk(2)),
            Err(CryptoError::NodeKeyMismatch)
        ));
    }

    #[test]
    fn load_legacy_pubkey_json_is_rejected() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("pubkey.json"), b"{}").unwrap();
        assert!(matches!(
            load(dir.path(), &nk(1)),
            Err(CryptoError::LegacyKeystore(_))
        ));
    }

    #[test]
    fn load_manifest_missing_but_users_present_is_corrupt() {
        let dir = tempdir().unwrap();
        // Simulate a partially-deleted or foreign keystore directory.
        fs::write(dir.path().join("users.redb"), b"not a real redb file").unwrap();
        assert!(matches!(
            load(dir.path(), &nk(1)),
            Err(CryptoError::KeystoreCorrupt { .. })
        ));
    }
}
