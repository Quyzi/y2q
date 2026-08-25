//! Offline node-key rotation: re-derive every node-derived key across the
//! whole storage tree without touching object bodies (those are sealed
//! under per-object content keys, never the node key).
//!
//! [`rotate_storage_tree`] is the entry point. It is deliberately synchronous
//! in its ordering (one bucket at a time, one object at a time) rather than
//! concurrent — this is an offline, operator-invoked tool where correctness
//! and crash-safety matter far more than throughput, and the plan's own
//! crash-safety story (resume via idempotent per-item work) is much simpler
//! to reason about without concurrent writers touching the same tree.
//!
//! Per-object migration re-encrypts the metadata sidecar under the new
//! Object Metadata Key *and* rebinds its AAD to the new opaque object id
//! (both `OMK` and the on-disk id are keyed by the node key — see
//! `crate::crypto::node_keys` and [`super::filesystem::encode_object_id`]),
//! then writes the object to its new id-derived subpath *within the same,
//! still-old-named bucket directory* and removes the old file. Only after
//! every object (and the bucket config sidecar) in a bucket has migrated is
//! the bucket directory itself renamed to its new opaque name — last, so an
//! interruption always leaves the bucket findable under its old name.
//!
//! Resume is idempotent by construction: each step checks whether its
//! *target* already exists (an already-migrated object's new-id file, an
//! already-renamed bucket's new-name directory) and skips straight past
//! completed work, so re-running after a crash converges without redoing —
//! or corrupting — anything already done.
//!
//! `buckets` (plaintext names) must come from a *still-old-key-openable*
//! index — see [`crate::node_key_rotation`]'s ordering invariant that this
//! function is only ever called while that holds: the caller deletes and
//! rebuilds the index strictly *after* this returns, never before, so if
//! the old-key index is still readable the tree walk genuinely may not be
//! done yet, and if it isn't, the tree walk is *guaranteed* already
//! complete (there is no other way the old index could have gone away).

use std::path::{Path, PathBuf};

use crate::Error;
use crate::crypto::node_keys::{BUCKET_CONFIG_PAD_BLOCK, META_PAD_BLOCK};
use crate::crypto::{decrypt_meta, encrypt_meta};
use crate::storage::filesystem::{
    bucket_dir_path, encode_bucket_dir, encode_object_id, object_id_from_path,
};
use crate::storage::format::{HEADER_SIZE, Header};

/// Filename of the per-bucket JSON config sidecar. Mirrors
/// `filesystem::BUCKET_CONFIG_FILE` (private to that module — duplicated
/// here rather than widened, since the two are allowed to drift only in
/// lockstep and a rename would need to touch both anyway).
const BUCKET_CONFIG_FILE: &str = ".y2q-bucket.json";

/// Outcome counters for a [`rotate_storage_tree`] run, logged by the caller.
#[derive(Debug, Default, Clone, Copy)]
pub struct RotationStats {
    /// Buckets whose directory was renamed during this run (excludes
    /// buckets already fully migrated in a prior interrupted run).
    pub buckets_migrated: usize,
    /// Objects re-encrypted and moved to their new id during this run.
    pub objects_migrated: usize,
    /// Objects found already migrated (resume fast-path; not re-touched).
    pub objects_already_done: usize,
}

fn internal(bucket: &str, operation: &str, message: String) -> Error {
    Error::InternalError {
        bucket: bucket.to_owned(),
        key: String::new(),
        operation: operation.to_owned(),
        message,
    }
}

fn io_err(bucket: &str, operation: &str, e: std::io::Error) -> Error {
    internal(bucket, operation, e.to_string())
}

/// The six old/new key pairs [`rotate_storage_tree`] needs, grouped to avoid
/// a six-`&[u8; 32]`-argument footgun (transposing old/new or path/omk/bck by
/// position is an easy mistake with bare positional args).
pub struct RotationKeys<'a> {
    pub old_path_key: &'a [u8; 32],
    pub new_path_key: &'a [u8; 32],
    pub old_omk: &'a [u8; 32],
    pub new_omk: &'a [u8; 32],
    pub old_bck: &'a [u8; 32],
    pub new_bck: &'a [u8; 32],
}

/// Rotate every bucket in `buckets` (plaintext names, read from the
/// still-old-key-openable index by the caller before this runs) from the
/// old node-derived keys to the new ones. Safe to re-run after an
/// interruption — see the module docs for why.
pub async fn rotate_storage_tree(
    base_path: &Path,
    buckets: &[String],
    keys: &RotationKeys<'_>,
) -> Result<RotationStats, Error> {
    let RotationKeys {
        old_path_key,
        new_path_key,
        old_omk,
        new_omk,
        old_bck,
        new_bck,
    } = *keys;
    let mut stats = RotationStats::default();
    for bucket in buckets {
        let old_dir = bucket_dir_path(base_path, old_path_key, bucket);
        let new_dir = bucket_dir_path(base_path, new_path_key, bucket);

        if tokio::fs::try_exists(&new_dir).await.unwrap_or(false) {
            // Already fully migrated (directory already renamed) in a prior run.
            continue;
        }
        if !tokio::fs::try_exists(&old_dir).await.unwrap_or(false) {
            // Registered bucket with no directory on disk yet — nothing to
            // migrate (an empty bucket that was `create_bucket`'d always
            // gets a directory, so this is tolerated rather than treated as
            // an error: it can only mean the bucket is otherwise empty and
            // untouched).
            continue;
        }

        let obj_files = collect_bucket_obj_files(&old_dir)
            .await
            .map_err(|e| io_err(bucket, "rotate-node-key", e))?;
        for path in obj_files {
            let migrated =
                migrate_object_file(&path, old_omk, new_omk, new_path_key, bucket).await?;
            if migrated {
                stats.objects_migrated += 1;
            } else {
                stats.objects_already_done += 1;
            }
        }

        migrate_bucket_config(
            &old_dir,
            bucket,
            old_path_key,
            new_path_key,
            old_bck,
            new_bck,
        )
        .await?;

        // Rename the bucket directory itself — last, so a crash before this
        // point still finds the bucket under its old name.
        tokio::fs::rename(&old_dir, &new_dir)
            .await
            .map_err(|e| io_err(bucket, "rotate-node-key", e))?;
        stats.buckets_migrated += 1;
    }
    Ok(stats)
}

/// Migrate one `.obj` file in place within its (still old-named) bucket
/// directory. Returns `true` if it was actually re-encrypted/moved this
/// call, `false` if it was already in the new format (resume fast-path).
async fn migrate_object_file(
    path: &Path,
    old_omk: &[u8; 32],
    new_omk: &[u8; 32],
    new_path_key: &[u8; 32],
    bucket: &str,
) -> Result<bool, Error> {
    let current_id = object_id_from_path(path)
        .ok_or_else(|| {
            internal(
                bucket,
                "rotate-node-key",
                "cannot derive object id from path".to_owned(),
            )
        })?
        .to_owned();

    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| io_err(bucket, "rotate-node-key", e))?;
    if bytes.len() < HEADER_SIZE {
        return Err(internal(
            bucket,
            "rotate-node-key",
            "object file shorter than header".to_owned(),
        ));
    }
    let mut header_buf = [0u8; HEADER_SIZE];
    header_buf.copy_from_slice(&bytes[..HEADER_SIZE]);
    let header = Header::decode(&header_buf)
        .map_err(|e| internal(bucket, "rotate-node-key", format!("decode header: {e}")))?;
    if header
        .checked_total_len()
        .is_none_or(|total| total > bytes.len() as u64)
    {
        return Err(internal(
            bucket,
            "rotate-node-key",
            "header fields inconsistent with file length".to_owned(),
        ));
    }
    let data_start = header.data_offset as usize;
    let meta_start = header.meta_offset() as usize;
    let meta_end = meta_start + header.meta_len as usize;
    let data = &bytes[data_start..meta_start];
    let meta_bytes = &bytes[meta_start..meta_end];

    // Idempotent resume fast-path: if this exact file already decrypts
    // under the *new* OMK with its own (necessarily already-new) id as
    // AAD, it was already migrated by a prior run — nothing left to do.
    if decrypt_meta(new_omk, meta_bytes, &current_id).is_ok() {
        return Ok(false);
    }

    let plain_json = decrypt_meta(old_omk, meta_bytes, &current_id)
        .map_err(|_| internal(bucket, "rotate-node-key", format!("object at {}: metadata decrypts under neither the old nor the new node key — possible corruption", path.display())))?;
    let metadata: crate::Metadata = serde_json::from_slice(&plain_json)
        .map_err(|e| internal(bucket, "rotate-node-key", format!("parse metadata: {e}")))?;

    let new_id = encode_object_id(new_path_key, &metadata.bucket, &metadata.key);
    let bucket_dir = path.ancestors().nth(3).ok_or_else(|| {
        internal(
            bucket,
            "rotate-node-key",
            "object path too shallow".to_owned(),
        )
    })?;
    let new_path = bucket_dir
        .join(&new_id[0..2])
        .join(&new_id[2..4])
        .join(format!("{new_id}.obj"));

    if tokio::fs::try_exists(&new_path).await.unwrap_or(false) {
        // The new file was already written by a prior interrupted run; only
        // the old copy's removal didn't complete. Finish that now.
        if new_path != path {
            let _ = tokio::fs::remove_file(path).await;
        }
        return Ok(false);
    }

    let new_meta = encrypt_meta(new_omk, &plain_json, &new_id, META_PAD_BLOCK).map_err(|e| {
        internal(
            bucket,
            "rotate-node-key",
            format!("re-encrypt metadata: {e}"),
        )
    })?;
    // AES-256-GCM ciphertext length is exactly plaintext length + fixed
    // overhead, so re-encrypting the same plaintext always yields the same
    // length — the header's `meta_len` needs no change.
    debug_assert_eq!(new_meta.len(), meta_bytes.len());

    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&header_buf);
    out.resize(data_start, 0); // zero padding up to data_offset (O_DIRECT path)
    out.extend_from_slice(data);
    out.extend_from_slice(&new_meta);
    out.extend_from_slice(&header_buf); // trailer mirrors the header

    if let Some(parent) = new_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| io_err(bucket, "rotate-node-key", e))?;
    }
    // Extension must be exactly `tmp` (not e.g. `obj.rotate-tmp`, whose
    // `Path::extension()` is "rotate-tmp") so a staging file orphaned by a
    // crash mid-rotation is recognized and swept by
    // `filesystem::clear_orphan_tmp_files`. `new_id` (keyed by the *new*
    // path key) essentially never collides with a concurrent regular PUT's
    // `<old-path-key-id>.tmp` in the same shard directory.
    let tmp_path = new_path.with_extension("tmp");
    tokio::fs::write(&tmp_path, &out)
        .await
        .map_err(|e| io_err(bucket, "rotate-node-key", e))?;
    tokio::fs::rename(&tmp_path, &new_path)
        .await
        .map_err(|e| io_err(bucket, "rotate-node-key", e))?;
    if new_path != path {
        tokio::fs::remove_file(path)
            .await
            .map_err(|e| io_err(bucket, "rotate-node-key", e))?;
    }
    Ok(true)
}

/// Re-encrypt the bucket config sidecar (`.y2q-bucket.json`) in place —
/// its path doesn't change (that only happens when the parent directory is
/// renamed), only its ciphertext.
async fn migrate_bucket_config(
    old_dir: &Path,
    bucket: &str,
    old_path_key: &[u8; 32],
    new_path_key: &[u8; 32],
    old_bck: &[u8; 32],
    new_bck: &[u8; 32],
) -> Result<(), Error> {
    let path = old_dir.join(BUCKET_CONFIG_FILE);
    let bytes = match tokio::fs::read(&path).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()), // never claimed
        Err(e) => return Err(io_err(bucket, "rotate-node-key", e)),
    };

    let new_aad = encode_bucket_dir(new_path_key, bucket);
    if decrypt_meta(new_bck, &bytes, &new_aad).is_ok() {
        return Ok(()); // already migrated
    }
    let old_aad = encode_bucket_dir(old_path_key, bucket);
    let plain = decrypt_meta(old_bck, &bytes, &old_aad).map_err(|_| {
        internal(
            bucket,
            "rotate-node-key",
            "bucket config decrypts under neither the old nor the new node key".to_owned(),
        )
    })?;

    let new_bytes =
        encrypt_meta(new_bck, &plain, &new_aad, BUCKET_CONFIG_PAD_BLOCK).map_err(|e| {
            internal(
                bucket,
                "rotate-node-key",
                format!("re-encrypt bucket config: {e}"),
            )
        })?;
    let tmp = path.with_extension("json.rotate-tmp");
    tokio::fs::write(&tmp, &new_bytes)
        .await
        .map_err(|e| io_err(bucket, "rotate-node-key", e))?;
    tokio::fs::rename(&tmp, &path)
        .await
        .map_err(|e| io_err(bucket, "rotate-node-key", e))?;
    Ok(())
}

/// Every `*.obj` file directly under `bucket_dir/<xx>/<yy>/`.
async fn collect_bucket_obj_files(bucket_dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut l1 = tokio::fs::read_dir(bucket_dir).await?;
    while let Some(e1) = l1.next_entry().await? {
        if !e1.file_type().await?.is_dir() {
            continue;
        }
        let mut l2 = tokio::fs::read_dir(e1.path()).await?;
        while let Some(e2) = l2.next_entry().await? {
            if !e2.file_type().await?.is_dir() {
                continue;
            }
            let mut files = tokio::fs::read_dir(e2.path()).await?;
            while let Some(f) = files.next_entry().await? {
                let p = f.path();
                if p.extension().is_some_and(|e| e == "obj") {
                    out.push(p);
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `.obj` file whose header declares far more data than the file
    /// actually holds: `data_offset + data_len + meta_len + HEADER_SIZE`
    /// wildly exceeds the real byte count. Before the bounds check in
    /// `migrate_object_file` this desynced the `data`/`meta` slice bounds
    /// (`&bytes[data_start..meta_start]`) instead of erroring.
    fn write_malformed_obj(dir: &Path) -> PathBuf {
        let header = Header {
            data_len: 1_000_000,
            meta_len: 500,
            data_offset: Header::MIN_DATA_OFFSET,
            flags: 0,
            version: crate::storage::format::VERSION,
        };
        let mut bytes = header.encode().to_vec();
        bytes.extend_from_slice(&[0u8; 32]); // far short of the declared data_len
        let path = dir.join("malformed.obj");
        std::fs::write(&path, &bytes).unwrap();
        path
    }

    #[tokio::test]
    async fn migrate_object_file_rejects_inconsistent_header_instead_of_panicking() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = write_malformed_obj(dir.path());
        let old_omk = [1u8; 32];
        let new_omk = [2u8; 32];
        let new_path_key = [3u8; 32];

        let result = migrate_object_file(&path, &old_omk, &new_omk, &new_path_key, "bucket").await;
        assert!(
            result.is_err(),
            "a malformed header must error, not panic: {result:?}"
        );
    }

    #[tokio::test]
    async fn rotate_tmp_staging_file_is_swept_as_orphan() {
        // Regression test for the `.obj.rotate-tmp` naming bug: that
        // extension is "rotate-tmp" (not "tmp"), so
        // `filesystem::clear_orphan_tmp_files`'s `extension() == "tmp"`
        // filter never collected a rotate-tmp staging file orphaned by a
        // crash mid-rotation. The fixed naming must be swept like any other
        // orphan.
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path().join("data");
        let shard = base.join("bucketdirhex").join("ab").join("cd");
        tokio::fs::create_dir_all(&shard).await.unwrap();

        // Mirror the exact construction `migrate_object_file` now uses: the
        // destination `.obj` path with its extension swapped for `.tmp`.
        let new_obj_path = shard.join("abcd1234.obj");
        let tmp_path = new_obj_path.with_extension("tmp");
        tokio::fs::write(&tmp_path, b"orphaned rotation staging data")
            .await
            .unwrap();

        let future = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
        let removed = crate::storage::filesystem::clear_orphan_tmp_files(&base, future)
            .await
            .unwrap();
        assert_eq!(
            removed, 1,
            "rotate-tmp staging file must be recognized as an orphan and swept"
        );
        assert!(!tmp_path.exists());
    }
}
