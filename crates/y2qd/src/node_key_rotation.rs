//! `y2qd --rotate-node-key` — offline, resumable node-key rotation.
//!
//! Walks the whole storage tree (every object's metadata sidecar and
//! filename, every bucket's config sidecar and directory), re-derives every
//! node-derived key under the new node key, rebuilds the metadata index
//! fresh, and finally rewrites `keystore.json`'s verifier. Never touches
//! object bodies — those are sealed under per-object/per-bucket content
//! keys, not the node key.
//!
//! Crash-safety is a journal (`<keystore_dir>/node-key-rotation.json`)
//! written *before* anything else is touched, deleted only after the
//! verifier is rewritten. The daemon's normal boot path refuses to start
//! while that journal exists — see [`crate::node_key_rotation::run`]'s
//! caller in `main.rs` and the matching startup guard.
//!
//! # Device registry
//!
//! When `<keystore_dir>/devices.json` exists, the *old* key is recovered from
//! the registry (a home device, an emergency code, or an away device on a
//! registry with no home devices) instead of from the operator, and the single
//! ciphertext `nk_wrap` is rewritten under the new key immediately before the
//! verifier flips. That branch is taken even when an operator key is
//! configured: rotating around a registry would leave `nk_wrap` holding the
//! dead key. Rotation does not cut off a party that holds the Registry Master
//! Key; that takes a fresh `device init`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use y2q_core::crypto::keystore;
use y2q_core::crypto::node_key;
use y2q_core::crypto::{
    derive_bucket_config_key, derive_container_header_key, derive_node_key_verifier,
    derive_object_metadata_key, derive_path_key,
};
use y2q_core::storage::rotation::rotate_storage_tree;
use y2q_core::{CacheRebuildStatus, FilesystemStorage, Listing, StorageExt};

#[cfg(all(target_os = "linux", feature = "devices"))]
use y2q_core::crypto::CryptoError;
#[cfg(all(target_os = "linux", feature = "devices"))]
use y2q_core::crypto::devices::{self, Authority, DevicePolicy, PinProvider, TimeSource, registry};

use crate::config::Config;

/// Message the daemon's normal boot path exits with when an interrupted
/// rotation's journal is found. Shared so the two call sites stay in sync.
pub const INTERRUPTED_MESSAGE: &str =
    "node key rotation was interrupted; re-run y2qd --rotate-node-key to finish it";

const JOURNAL_MISMATCH_MESSAGE: &str = "an interrupted rotation's journal names a different key pair than the one \
     supplied; supply the exact same old and new keys to resume it";

fn other(msg: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(msg.to_string())
}

/// Providers the device branch of a rotation needs, as a struct so tests can
/// inject doubles and a failure point.
#[cfg(all(target_os = "linux", feature = "devices"))]
pub(crate) struct RotationSeams<'a> {
    pub pins: &'a dyn PinProvider,
    pub time: &'a dyn TimeSource,
    pub now_host: u64,
    /// Test hook: fail between the user-store re-key and the `nk_wrap` rewrite.
    #[cfg(test)]
    pub fail_before_nk_wrap: bool,
}

#[cfg(all(target_os = "linux", feature = "devices"))]
impl<'a> RotationSeams<'a> {
    pub(crate) fn new(pins: &'a dyn PinProvider, time: &'a dyn TimeSource, now_host: u64) -> Self {
        Self {
            pins,
            time,
            now_host,
            #[cfg(test)]
            fail_before_nk_wrap: false,
        }
    }
}

/// Run a full (or resumed) node-key rotation against `cfg`'s storage and
/// keystore, then exit. `new_node_key_file` mirrors `[crypto] node_key_file`
/// but supplies the *new* key (`Y2QD_NEW_NODE_KEY` takes precedence, same
/// rule as the old key's env var over its file).
pub async fn run(cfg: &Config, new_node_key_file: &str) -> std::io::Result<()> {
    let keystore_dir = PathBuf::from(&cfg.crypto.keystore_dir);

    // Exclusive flock — the same one the daemon holds for its whole
    // lifetime, so this refuses to run alongside a live daemon, and two
    // concurrent rotation attempts refuse each other too.
    let _flock = keystore::acquire_lock(&keystore_dir).map_err(other)?;

    #[cfg(not(all(target_os = "linux", feature = "devices")))]
    devices_refuse(&keystore_dir)?;

    #[cfg(all(target_os = "linux", feature = "devices"))]
    if devices::devices_path(&keystore_dir).exists() {
        use y2q_core::crypto::devices::roughtime::RoughtimeTimeSource;

        let policy: DevicePolicy = (&cfg.crypto.devices).into();
        let pins = crate::node_unlock::DaemonPinProvider::new()
            .map_err(|e| other(format!("device unlock: {e}")))?;
        let time = RoughtimeTimeSource::new(policy.roughtime.clone());
        let seams = RotationSeams::new(&pins, &time, devices::now_unix());
        return run_with(cfg, new_node_key_file, seams).await;
    }

    let old_nk = *node_key::load_node_key(&cfg.crypto.node_key_file)
        .map_err(|e| other(format!("old node key: {e}")))?;
    let new_nk = *node_key::load_new_node_key(new_node_key_file).map_err(|e| {
        other(format!(
            "new node key (Y2QD_NEW_NODE_KEY / --new-node-key-file): {e}"
        ))
    })?;

    if old_nk == new_nk {
        return Err(other(
            "--rotate-node-key: the new node key canonicalizes to the same 32 bytes as the old one",
        ));
    }

    // Verifies the old key against keystore.json (NodeKeyMismatch on a wrong
    // key). Deliberately does *not* open users.redb: a resumed rotation may
    // already have re-keyed it, and the re-key step below handles that case.
    keystore::verify_node_key(&keystore_dir, &old_nk)
        .map_err(|e| other(format!("verify old node key against keystore: {e}")))?;

    match keystore::read_rotation_journal(&keystore_dir).map_err(other)? {
        Some(journal) => {
            let old_v = base64_encode(&derive_node_key_verifier(&old_nk));
            let new_v = base64_encode(&derive_node_key_verifier(&new_nk));
            if journal.old_verifier_b64 != old_v || journal.new_verifier_b64 != new_v {
                return Err(other(JOURNAL_MISMATCH_MESSAGE));
            }
            tracing::info!("resuming an interrupted node-key rotation");
        }
        None => write_journal(&keystore_dir, &old_nk, &new_nk)?,
    }

    migrate(cfg, &keystore_dir, &old_nk, &new_nk).await?;
    finish(&keystore_dir, &new_nk)
}

#[cfg(not(all(target_os = "linux", feature = "devices")))]
fn devices_refuse(keystore_dir: &Path) -> std::io::Result<()> {
    y2q_core::crypto::devices::refuse_if_present(keystore_dir).map_err(other)
}

fn write_journal(keystore_dir: &Path, old_nk: &[u8; 32], new_nk: &[u8; 32]) -> std::io::Result<()> {
    keystore::write_rotation_journal(keystore_dir, old_nk, new_nk).map_err(other)?;
    tracing::info!(journal = %keystore_dir.join("node-key-rotation.json").display(), "wrote rotation journal; safe to interrupt and resume from here on");
    Ok(())
}

/// Flip the keystore verifier to the new key and drop the journal.
fn finish(keystore_dir: &Path, new_nk: &[u8; 32]) -> std::io::Result<()> {
    keystore::rewrite_verifier(keystore_dir, new_nk)
        .map_err(|e| other(format!("rewrite keystore verifier: {e}")))?;
    keystore::delete_rotation_journal(keystore_dir)
        .map_err(|e| other(format!("delete rotation journal: {e}")))?;

    tracing::info!("node-key rotation complete");
    Ok(())
}

/// Device-registry rotation: recover the old key from the registry, rotate the
/// storage tree and user store, rewrite `nk_wrap` under the new key, then flip
/// the verifier. The caller holds the keystore flock.
#[cfg(all(target_os = "linux", feature = "devices"))]
pub(crate) async fn run_with(
    cfg: &Config,
    new_node_key_file: &str,
    seams: RotationSeams<'_>,
) -> std::io::Result<()> {
    let keystore_dir = PathBuf::from(&cfg.crypto.keystore_dir);

    // 1. Read the journal before any key comparison.
    let journal = keystore::read_rotation_journal(&keystore_dir).map_err(other)?;

    // 2. Recover the old key from the registry.
    let policy: DevicePolicy = (&cfg.crypto.devices).into();
    let mut out = devices::unlock(
        &keystore_dir,
        &policy,
        seams.pins,
        seams.time,
        seams.now_host,
    )
    .map_err(|e| other(format!("device unlock: {e}")))?;
    let allowed = match &out.authority {
        Authority::Home { .. } | Authority::Emergency { .. } => true,
        Authority::Away { .. } => registry::home_count(&out.registry) == 0,
    };
    if !allowed {
        return Err(other(CryptoError::DeviceAuthorityInsufficient {
            operation: "rotate-node-key".to_owned(),
            required: "a home device, an emergency code, or an away device on a registry with no \
                       home devices"
                .to_owned(),
            by: out.authority.describe(),
        }));
    }

    // 3. The new key.
    let new_nk = node_key::load_new_node_key(new_node_key_file).map_err(|e| {
        other(format!(
            "new node key (Y2QD_NEW_NODE_KEY / --new-node-key-file): {e}"
        ))
    })?;
    let resolved_v = base64_encode(&derive_node_key_verifier(&out.node_key));
    let new_v = base64_encode(&derive_node_key_verifier(&new_nk));

    // 4/5. Guards, then branch.
    match journal {
        Some(journal) => {
            // A wrong new key would otherwise make the final verifier write
            // wrong and delete the journal.
            if journal.new_verifier_b64 != new_v {
                return Err(other(JOURNAL_MISMATCH_MESSAGE));
            }
            if resolved_v == journal.old_verifier_b64 {
                keystore::verify_node_key(&keystore_dir, &out.node_key)
                    .map_err(|e| other(format!("verify old node key against keystore: {e}")))?;
                tracing::info!("resuming an interrupted node-key rotation");
                migrate(cfg, &keystore_dir, &out.node_key, &new_nk).await?;
                rewrite_registry(&seams, &keystore_dir, &mut out, &new_nk)?;
            } else if resolved_v != journal.new_verifier_b64 {
                return Err(other(
                    "the device registry opens under neither the old nor the new node key; \
                     restore the keystore directory from backup",
                ));
            }
            // else: migration and the nk_wrap rewrite already completed.
        }
        None => {
            if resolved_v == new_v {
                return Err(other(
                    "--rotate-node-key: the new node key canonicalizes to the same 32 bytes as the old one",
                ));
            }
            keystore::verify_node_key(&keystore_dir, &out.node_key)
                .map_err(|e| other(format!("verify old node key against keystore: {e}")))?;
            write_journal(&keystore_dir, &out.node_key, &new_nk)?;
            migrate(cfg, &keystore_dir, &out.node_key, &new_nk).await?;
            rewrite_registry(&seams, &keystore_dir, &mut out, &new_nk)?;
        }
    }

    // 7.
    finish(&keystore_dir, &new_nk)
}

/// Step 6: the one ciphertext a rotation rewrites. Placed last because every
/// earlier step needs the *old* key, and the registry is the only place it
/// survives. Grants are untouched: they seal RMK, which rotation does not change.
#[cfg(all(target_os = "linux", feature = "devices"))]
fn rewrite_registry(
    seams: &RotationSeams<'_>,
    keystore_dir: &Path,
    out: &mut y2q_core::crypto::devices::UnlockOutcome,
    new_nk: &[u8; 32],
) -> std::io::Result<()> {
    #[cfg(test)]
    if seams.fail_before_nk_wrap {
        return Err(other("injected failure before the nk_wrap rewrite"));
    }
    #[cfg(not(test))]
    let _ = seams;
    devices::emergency::rewrite_nk_wrap(
        keystore_dir,
        &mut out.registry,
        &out.registry_master_key,
        new_nk,
    )
    .map_err(|e| other(format!("rewrite device registry nk_wrap: {e}")))
}

/// Walk the storage tree, rebuild the index, and re-key the user store, all
/// from `old_nk` to `new_nk`. Every step is idempotent, so a resumed rotation
/// simply re-runs this.
async fn migrate(
    cfg: &Config,
    keystore_dir: &Path,
    old_nk: &[u8; 32],
    new_nk: &[u8; 32],
) -> std::io::Result<()> {
    let old_nk = *old_nk;
    let new_nk = *new_nk;
    let old_path_key = derive_path_key(&old_nk);
    let new_path_key = derive_path_key(&new_nk);
    let old_omk = derive_object_metadata_key(&old_nk);
    let new_omk = derive_object_metadata_key(&new_nk);
    let old_bck = derive_bucket_config_key(&old_nk);
    let new_bck = derive_bucket_config_key(&new_nk);
    let old_chk = derive_container_header_key(&old_nk);
    let new_chk = derive_container_header_key(&new_nk);

    let base_path = PathBuf::from(&cfg.storage.base_path);
    let index_path = cfg
        .storage
        .index_path
        .clone()
        .unwrap_or_else(|| format!("{}/_y2q_index.redb", cfg.storage.base_path));

    // The plaintext bucket list is only readable via the (still old-key-
    // encrypted) index. If it no longer opens under the old key, the only
    // legitimate reason (given the journal already matched above) is that a
    // prior interrupted attempt already got past the tree walk and deleted
    // it — `run()` never deletes the index before `rotate_storage_tree`
    // returns `Ok`, so that ordering is a hard guarantee, not a guess.
    // Confirm that positively (new-key index opens, or the file is simply
    // gone) rather than trusting a failed old-key open on faith: silently
    // skipping a walk that was *not* actually done would rebuild an empty
    // index against still-old-keyed data and look like total data loss.
    let old_probe = FilesystemStorage::new(&base_path, &index_path)
        .map_err(|e| other(format!("open storage: {e}")))?;
    old_probe.install_node_key(old_nk);
    let buckets_needing_walk = match old_probe.list_buckets().await {
        Ok(buckets) => Some(buckets),
        Err(_) => {
            let new_probe = FilesystemStorage::new(&base_path, &index_path)
                .map_err(|e| other(format!("open storage: {e}")))?;
            new_probe.install_node_key(new_nk);
            let new_opens = new_probe.list_buckets().await.is_ok();
            let file_missing = !tokio::fs::try_exists(&index_path).await.unwrap_or(true);
            if !new_opens && !file_missing {
                return Err(other(
                    "the metadata index opens under neither the old nor the new node key, and still \
                     exists — this is not a state an interrupted rotation can produce on its own; \
                     investigate before re-running (do not delete the index by hand)",
                ));
            }
            None
        }
    };

    match buckets_needing_walk {
        Some(buckets) => {
            tracing::info!(
                buckets = buckets.len(),
                "rotating {} bucket(s)",
                buckets.len()
            );
            let stats = rotate_storage_tree(
                &base_path,
                &buckets,
                &y2q_core::storage::rotation::RotationKeys {
                    old_path_key: &old_path_key,
                    new_path_key: &new_path_key,
                    old_omk: &old_omk,
                    new_omk: &new_omk,
                    old_bck: &old_bck,
                    new_bck: &new_bck,
                    old_chk: &old_chk,
                    new_chk: &new_chk,
                },
            )
            .await
            .map_err(|e| other(format!("rotate storage tree: {e}")))?;
            tracing::info!(
                buckets_migrated = stats.buckets_migrated,
                objects_migrated = stats.objects_migrated,
                objects_already_done = stats.objects_already_done,
                "storage tree rotation complete"
            );
        }
        None => {
            tracing::info!(
                "storage tree already fully rotated by a prior interrupted run; skipping straight to the index rebuild"
            );
        }
    }
    // The index is a pure cache reconstructed from the (now new-key-sealed)
    // sidecars — delete and rebuild fresh under the new IFK/IK rather than
    // trying to re-key it in place.
    let _ = std::fs::remove_file(&index_path);
    let new_storage = FilesystemStorage::new(&base_path, &index_path)
        .map_err(|e| other(format!("open storage: {e}")))?;
    new_storage.install_node_key(new_nk);
    new_storage
        .rebuild_cache()
        .await
        .map_err(|e| other(format!("start index rebuild: {e}")))?;
    loop {
        match new_storage
            .rebuild_progress()
            .await
            .map_err(|e| other(format!("index rebuild status: {e}")))?
        {
            CacheRebuildStatus::Completed => break,
            CacheRebuildStatus::Failed(msg) => {
                return Err(other(format!("index rebuild failed: {msg}")));
            }
            CacheRebuildStatus::Idle | CacheRebuildStatus::Running(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    tracing::info!("index rebuilt under the new node key");

    // users.redb is sealed under a node-key-derived file key too, so it must be
    // re-keyed before the verifier flips or the next boot cannot open it.
    keystore::rekey_user_store(keystore_dir, &old_nk, &new_nk)
        .map_err(|e| other(format!("re-key user store: {e}")))?;
    Ok(())
}

/// Re-MAC every object's container header under the current node key, then
/// exit. Drives `--upgrade-container-headers`.
///
/// A one-shot upgrade for deployments written before the header carried an
/// HMAC. Only 128 bytes per object are rewritten and already-upgraded files
/// are skipped, so an interrupted run is simply re-run.
///
/// The caller holds the keystore flock and resolves `nk` (operator or device
/// mode) the same way a normal boot does.
pub async fn upgrade_headers(cfg: &Config, nk: &[u8; 32]) -> std::io::Result<()> {
    let keystore_dir = PathBuf::from(&cfg.crypto.keystore_dir);
    keystore::verify_node_key(&keystore_dir, nk)
        .map_err(|e| other(format!("verify node key against keystore: {e}")))?;

    let path_key = derive_path_key(nk);
    let chk = derive_container_header_key(nk);

    let base_path = PathBuf::from(&cfg.storage.base_path);
    let index_path = cfg
        .storage
        .index_path
        .clone()
        .unwrap_or_else(|| format!("{}/_y2q_index.redb", cfg.storage.base_path));

    // The header MAC does not change how the index is encrypted, so the
    // plaintext bucket list is readable under the current key as usual.
    let storage = FilesystemStorage::new(&base_path, &index_path)
        .map_err(|e| other(format!("open storage: {e}")))?;
    storage.install_node_key(*nk);
    let buckets = storage
        .list_buckets()
        .await
        .map_err(|e| other(format!("list buckets: {e}")))?;

    tracing::info!(buckets = buckets.len(), "upgrading container headers");
    let upgraded = y2q_core::storage::rotation::upgrade_container_headers(
        &base_path, &buckets, &path_key, &chk,
    )
    .await
    .map_err(|e| other(format!("upgrade container headers: {e}")))?;

    tracing::info!(upgraded, "container header upgrade complete");
    Ok(())
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(all(test, target_os = "linux", feature = "devices"))]
mod tests {
    use super::*;
    use crate::node_unlock::TEST_ENV_LOCK as LOCK;
    use y2q_core::crypto::Argon2Params;
    use y2q_core::crypto::devices::{
        DeviceKind, EMERGENCY_KEY_ENV_VAR, NewDevice, Tpm2Params, emergency,
    };
    use y2q_core::secmem::SecretBuf;
    use zeroize::Zeroizing;

    struct NoPins;
    impl PinProvider for NoPins {
        fn pin(&self, _label: &str) -> Result<Zeroizing<String>, CryptoError> {
            Err(CryptoError::DeviceBackend("no pins in test".to_owned()))
        }
    }

    struct NoTime;
    impl TimeSource for NoTime {
        fn attested_now(&self) -> Result<u64, CryptoError> {
            Err(CryptoError::RoughtimeNotConfigured)
        }
    }

    fn hex_key(seed: u8) -> String {
        (0u8..32)
            .map(|i| format!("{:02x}", i.wrapping_mul(37).wrapping_add(seed)))
            .collect()
    }

    fn key_of(hex: &str) -> [u8; 32] {
        *node_key::extract_node_key(
            &(0..32)
                .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
                .collect::<Vec<u8>>(),
        )
    }

    fn set_env(k: &str, v: &str) {
        // SAFETY: serialized on the shared test env lock.
        unsafe { std::env::set_var(k, v) };
    }

    fn clear_env() {
        // SAFETY: see `set_env`.
        unsafe {
            std::env::remove_var(EMERGENCY_KEY_ENV_VAR);
            std::env::remove_var(node_key::NEW_NODE_KEY_ENV_VAR);
            std::env::remove_var(node_key::NODE_KEY_ENV_VAR);
        }
    }

    fn test_cfg(keystore: &Path, storage: &Path) -> Config {
        use figment::providers::{Format, Toml};
        let toml = format!(
            "[server]\nhost = \"127.0.0.1\"\nport = 0\n[storage]\nbase_path = \"{}\"\n\
             [crypto]\nkeystore_dir = \"{}\"\n[auth]\n",
            storage.display(),
            keystore.display()
        );
        figment::Figment::new()
            .merge(Toml::string(&toml))
            .extract()
            .expect("test config parses")
    }

    fn codes_from(printed: &[u8]) -> Vec<String> {
        let text = String::from_utf8(printed.to_vec()).unwrap();
        text.lines()
            .filter_map(|l| {
                let (n, code) = l.trim().split_once(": ")?;
                n.trim().parse::<u8>().ok()?;
                Some(code.trim().to_owned())
            })
            .collect()
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn interrupted_registry_rotation_resumes_only_with_the_same_new_key() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        let ks = tempfile::tempdir().unwrap();
        let st = tempfile::tempdir().unwrap();
        let cfg = test_cfg(ks.path(), st.path());

        // A deployment created the operator way, then adopted into a registry.
        let nk0 = key_of(&hex_key(11));
        let mut argon = Argon2Params::with_random_salt(8, 1, 1);
        argon.m_cost_kib = 8;
        let first =
            keystore::first_run(ks.path(), "root", argon, &nk0).expect("first run succeeds");
        drop(first);

        let device = NewDevice {
            label: "home-test".to_owned(),
            kind: DeviceKind::Tpm2,
            tpm2: Some(Tpm2Params {
                private_b64: "AA==".to_owned(),
                public_b64: "AA==".to_owned(),
                pcr_slots: vec![7],
                pcr_bank: "sha256".to_owned(),
            }),
            fido2: None,
            secret: SecretBuf::random(32).unwrap(),
            sign_count: 0,
        };
        let mut printed: Vec<u8> = Vec::new();
        emergency::init_registry(
            ks.path(),
            device,
            devices::DEFAULT_AWAY_GRANT_SECONDS,
            false,
            devices::now_unix(),
            Some(&nk0),
            &mut printed,
        )
        .expect("registry init");
        let codes = codes_from(&printed);
        assert_eq!(codes.len(), 10);

        let pins = NoPins;
        let time = NoTime;
        let n2 = hex_key(99);
        let n3 = hex_key(131);

        // Interrupted rotation to N2: injected failure before the nk_wrap rewrite.
        set_env(EMERGENCY_KEY_ENV_VAR, &codes[0]);
        set_env(node_key::NEW_NODE_KEY_ENV_VAR, &n2);
        let seams = RotationSeams {
            fail_before_nk_wrap: true,
            ..RotationSeams::new(&pins, &time, devices::now_unix())
        };
        let err = rt().block_on(run_with(&cfg, "", seams)).err().unwrap();
        assert!(err.to_string().contains("injected failure"), "{err}");
        assert!(keystore::rotation_journal_exists(ks.path()));

        // Resume with a different N3: refused, verifier untouched.
        set_env(EMERGENCY_KEY_ENV_VAR, &codes[1]);
        set_env(node_key::NEW_NODE_KEY_ENV_VAR, &n3);
        let err = rt()
            .block_on(run_with(
                &cfg,
                "",
                RotationSeams::new(&pins, &time, devices::now_unix()),
            ))
            .err()
            .unwrap();
        assert!(
            err.to_string()
                .contains("journal names a different key pair"),
            "{err}"
        );
        assert!(keystore::rotation_journal_exists(ks.path()));
        keystore::verify_node_key(ks.path(), &nk0).expect("verifier still the old key");

        // Resume with N2: completes.
        set_env(EMERGENCY_KEY_ENV_VAR, &codes[2]);
        set_env(node_key::NEW_NODE_KEY_ENV_VAR, &n2);
        rt().block_on(run_with(
            &cfg,
            "",
            RotationSeams::new(&pins, &time, devices::now_unix()),
        ))
        .expect("resume completes");
        assert!(!keystore::rotation_journal_exists(ks.path()));
        keystore::verify_node_key(ks.path(), &key_of(&n2)).expect("verifier is N2");

        // The registry now yields N2 from an unburned code.
        set_env(EMERGENCY_KEY_ENV_VAR, &codes[3]);
        let policy: DevicePolicy = (&cfg.crypto.devices).into();
        let out = devices::unlock(ks.path(), &policy, &pins, &time, devices::now_unix())
            .expect("registry unlocks");
        assert_eq!(&out.node_key[..], &key_of(&n2)[..]);
        clear_env();
    }
}
