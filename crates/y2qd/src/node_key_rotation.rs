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

use std::path::PathBuf;
use std::time::Duration;

use y2q_core::crypto::keystore;
use y2q_core::crypto::node_key;
use y2q_core::crypto::{
    derive_bucket_config_key, derive_node_key_verifier, derive_object_metadata_key, derive_path_key,
};
use y2q_core::storage::rotation::rotate_storage_tree;
use y2q_core::{CacheRebuildStatus, FilesystemStorage, Listing, StorageExt};

use crate::config::Config;

/// Message the daemon's normal boot path exits with when an interrupted
/// rotation's journal is found. Shared so the two call sites stay in sync.
pub const INTERRUPTED_MESSAGE: &str =
    "node key rotation was interrupted; re-run y2qd --rotate-node-key to finish it";

fn other(msg: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(msg.to_string())
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

    // Verifies the old key against keystore.json (NodeKeyMismatch on a
    // wrong key) and that users.redb opens cleanly.
    keystore::load(&keystore_dir, &old_nk)
        .map_err(|e| other(format!("verify old node key against keystore: {e}")))?;

    match keystore::read_rotation_journal(&keystore_dir).map_err(other)? {
        Some(journal) => {
            let old_v = base64_encode(&derive_node_key_verifier(&old_nk));
            let new_v = base64_encode(&derive_node_key_verifier(&new_nk));
            if journal.old_verifier_b64 != old_v || journal.new_verifier_b64 != new_v {
                return Err(other(
                    "an interrupted rotation's journal names a different key pair than the one \
                     supplied; supply the exact same old and new keys to resume it",
                ));
            }
            tracing::info!("resuming an interrupted node-key rotation");
        }
        None => {
            keystore::write_rotation_journal(&keystore_dir, &old_nk, &new_nk).map_err(other)?;
            tracing::info!(journal = %keystore_dir.join("node-key-rotation.json").display(), "wrote rotation journal; safe to interrupt and resume from here on");
        }
    }

    let old_path_key = derive_path_key(&old_nk);
    let new_path_key = derive_path_key(&new_nk);
    let old_omk = derive_object_metadata_key(&old_nk);
    let new_omk = derive_object_metadata_key(&new_nk);
    let old_bck = derive_bucket_config_key(&old_nk);
    let new_bck = derive_bucket_config_key(&new_nk);

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

    keystore::rewrite_verifier(&keystore_dir, &new_nk)
        .map_err(|e| other(format!("rewrite keystore verifier: {e}")))?;
    keystore::delete_rotation_journal(&keystore_dir)
        .map_err(|e| other(format!("delete rotation journal: {e}")))?;

    tracing::info!("node-key rotation complete");
    Ok(())
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
