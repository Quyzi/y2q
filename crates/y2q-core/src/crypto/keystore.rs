//! Public-key file (`pubkey.json`) plus first-run key generation.
//!
//! The keystore directory holds three things:
//!
//! - `pubkey.json` — the deployment public key (plaintext, non-secret).
//! - `users.redb` — the user store ([`super::user_store::UserStore`]).
//! - `.lock` — POSIX advisory lock acquired for daemon process lifetime by
//!   the caller; no code in this module touches it.
//!
//! Generating a fresh keypair, wrapping the SK under the root password, and
//! writing both files is the [`first_run`] entry point. Subsequent starts go
//! through [`load`].

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use pqcrypto::kem::mlkem768;
use pqcrypto_traits::kem::{PublicKey as KemPublicKeyTrait, SecretKey as KemSecretKeyTrait};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::CryptoError;
use super::envelope::KEM_ALG_NAME;
use super::kdf::{Argon2Params, wrap_sk};
use super::keys::Keystore;
use super::user_store::{UserRecord, UserStore};

/// Standard filenames within the keystore directory.
pub struct KeystoreFiles {
    /// Root directory path (the `keystore_dir` from config).
    pub root: PathBuf,
    /// Path to `pubkey.json` (the deployment public key, non-secret).
    pub pubkey: PathBuf,
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
            pubkey: root.join("pubkey.json"),
            users: root.join("users.redb"),
            lock: root.join(".lock"),
            root,
        }
    }
}

/// On-disk shape of `pubkey.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubkeyFile {
    /// Algorithm identifier; currently always `"ml-kem-768"`.
    pub kem_alg: String,
    /// Standard-base64 encoded raw public key bytes.
    pub public_key_b64: String,
    /// Lowercase-hex SHA-256 over the raw public key bytes. Operators can
    /// publish this fingerprint out-of-band so substitution is detectable.
    pub fingerprint_sha256: String,
}

/// Result of a successful first-run setup.
pub struct FirstRunOutcome {
    /// Loaded public keystore for immediate handoff to the running daemon.
    pub keystore: Keystore,
    /// User store with the freshly-created `root` user.
    pub user_store: UserStore,
    /// The randomly-generated root password — print exactly once, then drop.
    pub root_password: String,
    /// Username assigned to the initial user (currently always `"root"`).
    pub root_username: String,
}

/// Load an existing keystore directory.
///
/// Fails with [`CryptoError::KeystoreMissing`] if `pubkey.json` is absent —
/// caller should branch to [`first_run`].
pub fn load(dir: &Path) -> Result<(Keystore, UserStore), CryptoError> {
    let files = KeystoreFiles::new(dir);
    if !files.pubkey.exists() {
        return Err(CryptoError::KeystoreMissing(
            files.pubkey.display().to_string(),
        ));
    }
    let raw = fs::read(&files.pubkey)
        .map_err(|e| CryptoError::KeystoreIo(format!("read {}: {e}", files.pubkey.display())))?;
    let parsed: PubkeyFile =
        serde_json::from_slice(&raw).map_err(|e| CryptoError::KeystoreCorrupt {
            path: files.pubkey.display().to_string(),
            reason: format!("parse: {e}"),
        })?;
    if parsed.kem_alg != KEM_ALG_NAME {
        return Err(CryptoError::KeystoreCorrupt {
            path: files.pubkey.display().to_string(),
            reason: format!("kem_alg mismatch: {}", parsed.kem_alg),
        });
    }
    let pk_bytes =
        STANDARD
            .decode(&parsed.public_key_b64)
            .map_err(|e| CryptoError::KeystoreCorrupt {
                path: files.pubkey.display().to_string(),
                reason: format!("base64 decode: {e}"),
            })?;
    if pk_bytes.len() != mlkem768::public_key_bytes() {
        return Err(CryptoError::KeystoreCorrupt {
            path: files.pubkey.display().to_string(),
            reason: format!(
                "public key wrong size: {} (expected {})",
                pk_bytes.len(),
                mlkem768::public_key_bytes()
            ),
        });
    }
    let actual_fp = fingerprint(&pk_bytes);
    if actual_fp != parsed.fingerprint_sha256 {
        return Err(CryptoError::KeystoreCorrupt {
            path: files.pubkey.display().to_string(),
            reason: "fingerprint mismatch".to_owned(),
        });
    }

    let keystore = Keystore {
        public_key: Arc::new(pk_bytes),
        kem_alg: parsed.kem_alg,
        fingerprint: parsed.fingerprint_sha256,
    };
    let user_store = UserStore::open(&files.users)?;
    Ok((keystore, user_store))
}

/// Generate a fresh keypair, wrap the SK under a randomly-generated root
/// password, write `pubkey.json` and `users.redb`, and return everything the
/// caller needs to print the password and start serving.
///
/// The `params` argument is the Argon2id parameter triple to use for wrapping
/// the root user's SK. Callers should source these from `[crypto.argon2]` in
/// `config.toml` so operators can tune them.
pub fn first_run(
    dir: &Path,
    root_username: &str,
    params: Argon2Params,
) -> Result<FirstRunOutcome, CryptoError> {
    let files = KeystoreFiles::new(dir);
    fs::create_dir_all(&files.root)
        .map_err(|e| CryptoError::KeystoreIo(format!("mkdir {}: {e}", files.root.display())))?;
    if files.pubkey.exists() {
        return Err(CryptoError::KeystoreIo(format!(
            "{} already exists; refusing to overwrite",
            files.pubkey.display()
        )));
    }

    let (pk, sk) = mlkem768::keypair();
    let pk_bytes = pk.as_bytes().to_vec();
    let sk_bytes = sk.as_bytes().to_vec();
    let fingerprint = fingerprint(&pk_bytes);

    let root_password = generate_root_password();
    let wrapped = wrap_sk(&sk_bytes, root_password.as_bytes(), &params)?;

    write_pubkey(&files.pubkey, &pk_bytes, &fingerprint)?;

    let user_store = UserStore::open(&files.users)?;
    let now_ns = now_ns();
    let record = UserRecord {
        username: root_username.to_owned(),
        created_at: now_ns,
        last_login: None,
        kdf: params,
        wrapped_sk: wrapped,
        // The bootstrap user is the daemon's first administrator.
        role: super::Role::Admin,
    };
    user_store.upsert(&record)?;

    let keystore = Keystore {
        public_key: Arc::new(pk_bytes),
        kem_alg: KEM_ALG_NAME.to_owned(),
        fingerprint,
    };
    Ok(FirstRunOutcome {
        keystore,
        user_store,
        root_password,
        root_username: root_username.to_owned(),
    })
}

/// SHA-256 fingerprint of `pk_bytes`, lowercase hex.
pub fn fingerprint(pk_bytes: &[u8]) -> String {
    let digest = Sha256::digest(pk_bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        write!(s, "{b:02x}").unwrap();
    }
    s
}

fn write_pubkey(path: &Path, pk_bytes: &[u8], fingerprint: &str) -> Result<(), CryptoError> {
    let body = PubkeyFile {
        kem_alg: KEM_ALG_NAME.to_owned(),
        public_key_b64: STANDARD.encode(pk_bytes),
        fingerprint_sha256: fingerprint.to_owned(),
    };
    let json = serde_json::to_vec_pretty(&body)
        .map_err(|e| CryptoError::KeystoreIo(format!("serialize pubkey: {e}")))?;
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|e| CryptoError::KeystoreIo(format!("open {} O_EXCL: {e}", path.display())))?;
    f.write_all(&json)
        .map_err(|e| CryptoError::KeystoreIo(format!("write {}: {e}", path.display())))?;
    f.sync_all()
        .map_err(|e| CryptoError::KeystoreIo(format!("fsync {}: {e}", path.display())))?;
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
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn first_run_then_load() {
        let dir = tempdir().unwrap();
        let fingerprint = {
            let outcome = first_run(
                dir.path(),
                "root",
                Argon2Params::with_random_salt(8 * 1024, 1, 1),
            )
            .unwrap();
            assert!(!outcome.root_password.is_empty());
            assert_eq!(outcome.keystore.kem_alg, KEM_ALG_NAME);
            assert_eq!(outcome.keystore.fingerprint.len(), 64);
            outcome.keystore.fingerprint
        };

        let (loaded, _users) = load(dir.path()).unwrap();
        assert_eq!(loaded.fingerprint, fingerprint);
        assert_eq!(loaded.public_key.len(), mlkem768::public_key_bytes());
    }

    #[test]
    fn first_run_refuses_overwrite() {
        let dir = tempdir().unwrap();
        let _ = first_run(
            dir.path(),
            "root",
            Argon2Params::with_random_salt(8 * 1024, 1, 1),
        )
        .unwrap();
        assert!(matches!(
            first_run(
                dir.path(),
                "root",
                Argon2Params::with_random_salt(8 * 1024, 1, 1)
            ),
            Err(CryptoError::KeystoreIo(_))
        ));
    }

    #[test]
    fn load_missing_returns_keystore_missing() {
        let dir = tempdir().unwrap();
        assert!(matches!(
            load(dir.path()),
            Err(CryptoError::KeystoreMissing(_))
        ));
    }
}
