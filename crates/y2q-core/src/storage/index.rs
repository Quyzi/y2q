//! Persistent secondary metadata index backed by [`redb`].
//!
//! The index is a redb database with three tables:
//!
//! - `objects`: HMAC-blinded key `(bucket, key)` → AEAD-sealed [`Metadata`].
//! - `labels`: HMAC-blinded key `(label_name, label_value, bucket, key)` →
//!   AEAD-sealed `(bucket, key)`. This is a reverse map enabling fast "find
//!   all objects whose label `X` has value `Y`" queries via a redb range scan
//!   over the blinded `(label_name, label_value)` prefix.
//! - `buckets`: HMAC-blinded key `bucket` → AEAD-sealed bucket name. Registry
//!   of explicitly-created buckets so that empty buckets (no objects) still
//!   appear in `list_buckets`.
//!
//! ## Encryption
//!
//! The entire redb file is encrypted at rest by [`EncryptedFileBackend`], which
//! transparently encrypts every block under a key derived from the
//! operator-supplied node key ([`crate::crypto::derive_index_file_key`]). That
//! layer alone only protects data at rest: once a page is decrypted into
//! redb's own page cache, anything stored in that page sits in cleartext in
//! process memory for as long as the page stays cached — which, given
//! `list_buckets`/`search_labels`/index-rebuild all scan every row, is
//! effectively the daemon's whole uptime. So every table key and value gets a
//! second, row-level layer on top:
//!
//! - Table keys are HMAC-SHA256 blinded under the Index Key (IK, derived from
//!   the node key — see [`crate::crypto::derive_index_key`]) rather than
//!   stored as plaintext composites, so a decrypted redb page never contains a
//!   recoverable bucket name, object key, or label name/value.
//! - Table values are AEAD-sealed under the Object Metadata Key (OMK — the
//!   same key that seals the on-disk `.obj` sidecar) via
//!   [`crate::crypto::encrypt_meta`]/[`decrypt_meta`], bound to the row's
//!   blinded key via AAD so a sealed value can't be replayed into a different
//!   row.
//!
//! Blinding is deterministic (`HMAC(IK, field)`), which is what keeps point
//! lookups and prefix range scans (per-bucket, per-label) working without
//! ever touching the plaintext strings.
//!
//! **Limits.** This closes a decrypted-page-without-the-node-key exposure; it
//! does not raise the bar against a node-key holder or against anyone who can
//! read the running daemon's memory. IK and OMK are both derived from the
//! node key and held, like every tier-0 key, in [`NodeKeySlot`] for the
//! daemon's entire lifetime with no idle-drop — the same memory an attacker
//! would need cache-page access from in the first place. Metadata visibility
//! to a node-key holder is an accepted, documented tradeoff (see
//! `docs/architecture.md`'s threat model); this layer only shrinks exposure
//! for someone who gets a decrypted page (or a process memory/core dump)
//! without independently having the node key.
//!
//! The node key is installed once at boot ([`MetadataIndex::set_node_key`])
//! and never dropped — the daemon cannot serve anything without it, so unlike
//! the pre-hierarchy MEK there is no idle-drop / re-open cycle.
//!
//! **Migration**: a pre-encryption (plaintext redb) index file is incompatible;
//! on first open the backend detects the missing magic and recreates the file
//! empty. A whole-file-encrypted index still written under the older
//! plaintext-composite key/value scheme (schema version 1) is detected via the
//! `meta` table's version marker and wiped the same way. Either case is
//! repopulated by the unconditional startup rebuild (`main.rs` calls
//! `rebuild_cache()` on every boot; see also `POST /api/v1/admin/rebuild-index`)
//! from on-disk object metadata.
//!
//! [`Metadata`]: crate::Metadata
//! [`EncryptedFileBackend`]: crate::storage::EncryptedFileBackend

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use redb::{Builder, Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use zeroize::Zeroizing;

use crate::{
    Error, LabelQuery, ListPage, Metadata, SyncLevel,
    crypto::{decrypt_meta, derive_index_file_key, encrypt_meta, node_keys::NodeKeySlot, prf},
    storage::EncryptedFileBackend,
};

/// HMAC-blinded `(bucket, key)` → AEAD-sealed, JSON-serialized [`Metadata`].
const OBJECTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("objects");

/// HMAC-blinded `(label_name, label_value, bucket, key)` → AEAD-sealed
/// `(bucket, key)`.
///
/// Enables prefix range scans of the form "all objects where label `name` has
/// value `value`".
const LABELS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("labels");

/// HMAC-blinded `bucket` → AEAD-sealed bucket name. Registry of
/// explicitly-created buckets so that empty buckets (no objects) still appear
/// in `list_buckets`.
const BUCKETS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("buckets");

/// `"schema_version"` → single version byte, plaintext (this table holds no
/// secrets — it exists purely so `open_db` can tell a v1 (plaintext
/// composite key / plain JSON value) index apart from the current blinded +
/// sealed layout without trying to parse one as the other).
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const SCHEMA_VERSION_KEY: &str = "schema_version";
/// Bump on any change to the key-blinding or value-sealing scheme below.
const SCHEMA_VERSION: u8 = 2;

/// Default redb page-cache cap for [`MetadataIndex`], applied via
/// [`MetadataIndex::set_cache_size_bytes`] unless overridden.
///
/// redb's own default is 1 GiB. Since a touched page is decrypted plaintext
/// for as long as it stays cached, and routine operations (`list_buckets`,
/// `search_labels`, index rebuild) scan every row at least once, an unbounded
/// cache means the working set ends up fully resident in cleartext for the
/// daemon's uptime. 64 MiB bounds how much of that a root-level memory dump
/// can recover at once without materially hurting lookup/scan latency for
/// realistic index sizes. Blinding/sealing (see the module docs) is the
/// primary defense; this just shrinks the residency window on top of it.
pub const DEFAULT_CACHE_SIZE_BYTES: usize = 64 * 1024 * 1024;

/// A persistent secondary index over object metadata, backed by a
/// whole-file-encrypted redb file.
///
/// The database is opened once at boot, when the node key is installed.
pub struct MetadataIndex {
    /// On-disk path of the encrypted redb file.
    path: PathBuf,
    /// The open database, or `None` if the boot-time open failed.
    db: RwLock<Option<Arc<Database>>>,
    /// Shared holder for the node key. Installed once at boot, then never
    /// cleared. The file key for [`Self::db`] is derived from it.
    slot: Arc<NodeKeySlot>,
    /// Cap on redb's in-memory page cache; see [`DEFAULT_CACHE_SIZE_BYTES`].
    cache_size_bytes: usize,
}

impl MetadataIndex {
    /// Create an unopened index handle for the redb file at `path`.
    ///
    /// Performs no I/O: the encrypted file is only opened once boot installs
    /// the node key via [`Self::set_node_key`].
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            db: RwLock::new(None),
            slot: Arc::new(NodeKeySlot::new()),
            cache_size_bytes: DEFAULT_CACHE_SIZE_BYTES,
        }
    }

    /// Override the redb page-cache cap (default [`DEFAULT_CACHE_SIZE_BYTES`]).
    /// Must be called before [`Self::set_node_key`] to take effect.
    pub fn set_cache_size_bytes(&mut self, bytes: usize) {
        self.cache_size_bytes = bytes;
    }

    /// Install the node key and open the encrypted database if not already
    /// open. Called exactly once, at boot.
    ///
    /// Idempotent for the database: a repeat call while already open is a
    /// no-op. An open failure is logged and leaves the index locked
    /// (operations error until the daemon restarts) — the index is a
    /// rebuildable cache, so this does not abort boot on its own.
    pub fn set_node_key(&self, nk: [u8; 32]) {
        self.slot.install(nk);
        let mut guard = self.db.write().expect("index db poisoned");
        if guard.is_some() {
            return;
        }
        match Self::open_db(&self.path, &nk, self.cache_size_bytes) {
            Ok(db) => *guard = Some(Arc::new(db)),
            Err(e) => {
                tracing::error!(error = %e, path = %self.path.display(),
                    "failed to open encrypted metadata index");
            }
        }
    }

    /// Open (or create) the encrypted redb file at `path` under the file key
    /// derived from `nk`, ensuring all tables exist. Caps redb's page cache at
    /// `cache_size_bytes` (see [`DEFAULT_CACHE_SIZE_BYTES`]) instead of redb's
    /// 1 GiB default.
    ///
    /// If the `meta` table's schema version marker is missing or stale (an
    /// index last written under an older key/value encoding), wipes
    /// `objects`/`labels`/`buckets` and writes the current marker rather than
    /// risking a misread of incompatible rows — the caller's unconditional
    /// startup rebuild repopulates it from on-disk object metadata.
    fn open_db(path: &Path, nk: &[u8; 32], cache_size_bytes: usize) -> Result<Database, Error> {
        let file_key = derive_index_file_key(nk);
        let backend = EncryptedFileBackend::open(path, file_key, super::ForeignFile::Recreate)
            .map_err(map_redb)?;
        let mut builder = Builder::new();
        builder.set_cache_size(cache_size_bytes);
        let db = builder.create_with_backend(backend).map_err(map_redb)?;

        let txn = db.begin_write().map_err(map_redb)?;
        let up_to_date = {
            let meta = txn.open_table(META).map_err(map_redb)?;
            matches!(
                meta.get(SCHEMA_VERSION_KEY).map_err(map_redb)?,
                Some(v) if v.value() == [SCHEMA_VERSION]
            )
        };
        if !up_to_date {
            tracing::warn!(
                path = %path.display(),
                "metadata index schema missing or out of date; resetting \
                 (repopulated by the startup rebuild)"
            );
            txn.delete_table(OBJECTS).map_err(map_redb)?;
            txn.delete_table(LABELS).map_err(map_redb)?;
            txn.delete_table(BUCKETS).map_err(map_redb)?;
        }
        {
            let _ = txn.open_table(OBJECTS).map_err(map_redb)?;
            let _ = txn.open_table(LABELS).map_err(map_redb)?;
            let _ = txn.open_table(BUCKETS).map_err(map_redb)?;
            if !up_to_date {
                let mut meta = txn.open_table(META).map_err(map_redb)?;
                meta.insert(SCHEMA_VERSION_KEY, [SCHEMA_VERSION].as_slice())
                    .map_err(map_redb)?;
            }
        }
        txn.commit().map_err(map_redb)?;
        Ok(db)
    }

    /// Clone the open database handle, or error if the index is locked.
    fn db(&self) -> Result<Arc<Database>, Error> {
        self.db
            .read()
            .expect("index db poisoned")
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| Error::Index {
                message: "metadata index locked; login required".to_owned(),
            })
    }

    /// The Index Key (IK): HMAC-blinds every table key so a decrypted redb
    /// page never contains a recoverable bucket/key/label string.
    fn index_key(&self) -> Result<Zeroizing<[u8; 32]>, Error> {
        self.slot.index_key().ok_or_else(|| Error::Index {
            message: "metadata index locked; login required".to_owned(),
        })
    }

    /// The Object Metadata Key (OMK), reused here — as for the on-disk `.obj`
    /// sidecar — to AEAD-seal every table value.
    fn value_key(&self) -> Result<Zeroizing<[u8; 32]>, Error> {
        self.slot.object_metadata_key().ok_or_else(|| Error::Index {
            message: "metadata index locked; login required".to_owned(),
        })
    }

    /// Return a handle to the shared node-key slot so a storage backend can
    /// share the same slot.
    pub fn node_key_slot(&self) -> Arc<NodeKeySlot> {
        Arc::clone(&self.slot)
    }

    /// Insert or replace the metadata for `(m.bucket, m.key)`.
    ///
    /// If a prior row exists, its label entries are removed before the new
    /// ones are written so that a label that has been deleted in `m` no
    /// longer appears in `lookup_by_label`.
    pub async fn upsert(&self, m: &Metadata, sync: SyncLevel) -> Result<(), Error> {
        let db = self.db()?;
        let ik = self.index_key()?;
        let omk = self.value_key()?;
        let payload = serde_json::to_vec(m).map_err(|e| Error::Index {
            message: format!("serialize metadata: {e}"),
        })?;
        let bucket = m.bucket.clone();
        let key = m.key.clone();
        let new_labels: Vec<(String, String)> = m
            .labels
            .iter()
            .map(|(n, v)| (n.clone(), v.clone()))
            .collect();

        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let object_key = object_row_key(&ik, &bucket, &key);
            let sealed_value = seal_row(&omk, &object_key, &payload)?;

            let mut txn = db.begin_write().map_err(map_redb)?;
            if sync != SyncLevel::Durable {
                let _ = txn.set_durability(Durability::None);
            }
            {
                let mut objects = txn.open_table(OBJECTS).map_err(map_redb)?;
                let mut labels = txn.open_table(LABELS).map_err(map_redb)?;

                // Tear down prior label rows (if any) so stale labels go away.
                if let Some(prev) = objects.get(object_key.as_slice()).map_err(map_redb)? {
                    let prev_json = open_row(&omk, &object_key, prev.value())?;
                    if let Ok(prev_meta) = serde_json::from_slice::<Metadata>(&prev_json) {
                        for (n, v) in &prev_meta.labels {
                            let lk = label_row_key(&ik, n, v, &bucket, &key);
                            labels.remove(lk.as_slice()).map_err(map_redb)?;
                        }
                    }
                }

                objects
                    .insert(object_key.as_slice(), sealed_value.as_slice())
                    .map_err(map_redb)?;
                for (n, v) in &new_labels {
                    let lk = label_row_key(&ik, n, v, &bucket, &key);
                    let pair =
                        serde_json::to_vec(&(bucket.as_str(), key.as_str())).map_err(|e| {
                            Error::Index {
                                message: format!("serialize label pair: {e}"),
                            }
                        })?;
                    let sealed_pair = seal_row(&omk, &lk, &pair)?;
                    labels
                        .insert(lk.as_slice(), sealed_pair.as_slice())
                        .map_err(map_redb)?;
                }
            }
            txn.commit().map_err(map_redb)?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Index {
            message: format!("join: {e}"),
        })?
    }

    /// Remove the row for `(bucket, key)` and any associated label rows.
    ///
    /// Succeeds without error if no row exists.
    pub async fn remove(&self, bucket: &str, key: &str) -> Result<(), Error> {
        let db = self.db()?;
        let ik = self.index_key()?;
        let omk = self.value_key()?;
        let bucket = bucket.to_owned();
        let key = key.to_owned();

        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let object_key = object_row_key(&ik, &bucket, &key);

            let txn = db.begin_write().map_err(map_redb)?;
            {
                let mut objects = txn.open_table(OBJECTS).map_err(map_redb)?;
                let mut labels = txn.open_table(LABELS).map_err(map_redb)?;
                if let Some(prev) = objects.get(object_key.as_slice()).map_err(map_redb)? {
                    let prev_json = open_row(&omk, &object_key, prev.value())?;
                    if let Ok(prev_meta) = serde_json::from_slice::<Metadata>(&prev_json) {
                        for (n, v) in &prev_meta.labels {
                            let lk = label_row_key(&ik, n, v, &bucket, &key);
                            labels.remove(lk.as_slice()).map_err(map_redb)?;
                        }
                    }
                }
                objects.remove(object_key.as_slice()).map_err(map_redb)?;
            }
            txn.commit().map_err(map_redb)?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Index {
            message: format!("join: {e}"),
        })?
    }

    /// Look up the metadata for `(bucket, key)` from the index.
    ///
    /// Returns `Ok(None)` if no row exists.
    pub async fn lookup_by_key(&self, bucket: &str, key: &str) -> Result<Option<Metadata>, Error> {
        let db = self.db()?;
        let ik = self.index_key()?;
        let omk = self.value_key()?;
        let bucket = bucket.to_owned();
        let key = key.to_owned();

        tokio::task::spawn_blocking(move || -> Result<Option<Metadata>, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(OBJECTS).map_err(map_redb)?;
            let object_key = object_row_key(&ik, &bucket, &key);
            match table.get(object_key.as_slice()).map_err(map_redb)? {
                None => Ok(None),
                Some(g) => {
                    let json = open_row(&omk, &object_key, g.value())?;
                    let m: Metadata = serde_json::from_slice(&json).map_err(|e| Error::Index {
                        message: format!("deserialize metadata: {e}"),
                    })?;
                    Ok(Some(m))
                }
            }
        })
        .await
        .map_err(|e| Error::Index {
            message: format!("join: {e}"),
        })?
    }

    /// Return all `(bucket, key)` pairs whose label `name` has value `value`.
    pub async fn lookup_by_label(
        &self,
        name: &str,
        value: &str,
    ) -> Result<Vec<(String, String)>, Error> {
        let db = self.db()?;
        let ik = self.index_key()?;
        let omk = self.value_key()?;
        let name = name.to_owned();
        let value = value.to_owned();

        tokio::task::spawn_blocking(move || -> Result<Vec<(String, String)>, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let label_table = txn.open_table(LABELS).map_err(map_redb)?;
            let mut results = Vec::new();

            // The blinded `(name, value)` prefix is fixed-length (64 bytes),
            // so a range scan starting at it and stopping at the first
            // non-matching row is unambiguous — unlike the old variable-length
            // string prefixes, there's no risk of a longer field's blinded
            // bytes spuriously matching this prefix.
            let prefix = label_prefix(&ik, &name, &value);
            for entry in label_table
                .range::<&[u8]>(prefix.as_slice()..)
                .map_err(map_redb)?
            {
                let (k, v) = entry.map_err(map_redb)?;
                let kbytes = k.value();
                if !kbytes.starts_with(&prefix) {
                    break;
                }
                let pair_json = open_row(&omk, kbytes, v.value())?;
                if let Ok((b, key)) = serde_json::from_slice::<(String, String)>(&pair_json) {
                    results.push((b, key));
                }
            }
            Ok(results)
        })
        .await
        .map_err(|e| Error::Index {
            message: format!("join: {e}"),
        })?
    }

    /// Return every distinct bucket name that has at least one row in the
    /// `objects` table, sorted ascending.
    ///
    /// Skip-ahead implementation: after reading one row from bucket `B`, jump
    /// the range cursor to the lex-successor of `B`'s blinded prefix, so this
    /// is O(num_buckets) reads rather than O(num_objects). The bucket name
    /// itself is recovered by decrypting that one representative row's value
    /// — the row key is opaque HMAC bytes and can't be decoded back.
    pub async fn list_buckets(&self) -> Result<Vec<String>, Error> {
        let db = self.db()?;
        let omk = self.value_key()?;

        tokio::task::spawn_blocking(move || -> Result<Vec<String>, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(OBJECTS).map_err(map_redb)?;

            let mut buckets = Vec::new();
            let mut start: Vec<u8> = Vec::new();
            loop {
                let mut iter = table.range::<&[u8]>(start.as_slice()..).map_err(map_redb)?;
                let Some(entry) = iter.next() else { break };
                let (k, v) = entry.map_err(map_redb)?;
                let kbytes = k.value();

                let json = open_row(&omk, kbytes, v.value())?;
                let m: Metadata = serde_json::from_slice(&json).map_err(|e| Error::Index {
                    message: format!("deserialize metadata: {e}"),
                })?;
                buckets.push(m.bucket);

                // First 32 bytes of every object row key are the blinded
                // bucket prefix (see `object_row_key`).
                let bucket_prefix = &kbytes[..BLIND_LEN.min(kbytes.len())];
                let Some(next) = next_lex_after(bucket_prefix) else {
                    break;
                };
                start = next;
            }
            buckets.sort();
            buckets.dedup();
            Ok(buckets)
        })
        .await
        .map_err(|e| Error::Index {
            message: format!("join: {e}"),
        })?
    }

    /// Return whether `bucket` exists: either explicitly registered (possibly
    /// empty) or holding at least one object. Cheap: an O(1) registry lookup
    /// plus, on miss, a single range probe of the objects table. Neither
    /// branch needs to decrypt a value — existence is decided purely from the
    /// blinded key.
    pub async fn bucket_exists(&self, bucket: &str) -> Result<bool, Error> {
        let db = self.db()?;
        let ik = self.index_key()?;
        let bucket = bucket.to_owned();
        tokio::task::spawn_blocking(move || -> Result<bool, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let bkey = blind_bucket(&ik, &bucket);
            {
                let buckets = txn.open_table(BUCKETS).map_err(map_redb)?;
                if buckets.get(bkey.as_slice()).map_err(map_redb)?.is_some() {
                    return Ok(true);
                }
            }
            let objects = txn.open_table(OBJECTS).map_err(map_redb)?;
            let mut iter = objects
                .range::<&[u8]>(bkey.as_slice()..)
                .map_err(map_redb)?;
            if let Some(entry) = iter.next() {
                let (k, _v) = entry.map_err(map_redb)?;
                if k.value().starts_with(&bkey) {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .await
        .map_err(|e| Error::Index {
            message: format!("join: {e}"),
        })?
    }

    /// Record `bucket` in the bucket registry so it lists even with no objects.
    /// Idempotent.
    pub async fn register_bucket(&self, bucket: &str) -> Result<(), Error> {
        let db = self.db()?;
        let ik = self.index_key()?;
        let omk = self.value_key()?;
        let bucket = bucket.to_owned();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let bkey = blind_bucket(&ik, &bucket);
            let sealed = seal_row(&omk, &bkey, bucket.as_bytes())?;
            let txn = db.begin_write().map_err(map_redb)?;
            {
                let mut buckets = txn.open_table(BUCKETS).map_err(map_redb)?;
                buckets
                    .insert(bkey.as_slice(), sealed.as_slice())
                    .map_err(map_redb)?;
            }
            txn.commit().map_err(map_redb)?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Index {
            message: format!("join: {e}"),
        })?
    }

    /// Remove `bucket` from the bucket registry. Succeeds if absent.
    pub async fn unregister_bucket(&self, bucket: &str) -> Result<(), Error> {
        let db = self.db()?;
        let ik = self.index_key()?;
        let bucket = bucket.to_owned();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let bkey = blind_bucket(&ik, &bucket);
            let txn = db.begin_write().map_err(map_redb)?;
            {
                let mut buckets = txn.open_table(BUCKETS).map_err(map_redb)?;
                buckets.remove(bkey.as_slice()).map_err(map_redb)?;
            }
            txn.commit().map_err(map_redb)?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Index {
            message: format!("join: {e}"),
        })?
    }

    /// Return every explicitly-registered bucket name (including empty ones).
    pub async fn list_registered_buckets(&self) -> Result<Vec<String>, Error> {
        let db = self.db()?;
        let omk = self.value_key()?;
        tokio::task::spawn_blocking(move || -> Result<Vec<String>, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(BUCKETS).map_err(map_redb)?;
            let mut out = Vec::new();
            for entry in table.iter().map_err(map_redb)? {
                let (k, v) = entry.map_err(map_redb)?;
                let name_bytes = open_row(&omk, k.value(), v.value())?;
                if let Ok(name) = String::from_utf8(name_bytes) {
                    out.push(name);
                }
            }
            Ok(out)
        })
        .await
        .map_err(|e| Error::Index {
            message: format!("join: {e}"),
        })?
    }

    /// Return every `(bucket, key)` pair currently stored in the objects table.
    ///
    /// Used by cache-rebuild reconciliation to find rows that should be removed
    /// because their on-disk sidecar no longer exists.
    pub async fn list_all_keys(&self) -> Result<Vec<(String, String)>, Error> {
        let db = self.db()?;
        let omk = self.value_key()?;

        tokio::task::spawn_blocking(move || -> Result<Vec<(String, String)>, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(OBJECTS).map_err(map_redb)?;
            let mut out = Vec::new();
            for entry in table.iter().map_err(map_redb)? {
                let (k, v) = entry.map_err(map_redb)?;
                let json = open_row(&omk, k.value(), v.value())?;
                let m: Metadata = serde_json::from_slice(&json).map_err(|e| Error::Index {
                    message: format!("deserialize metadata: {e}"),
                })?;
                out.push((m.bucket, m.key));
            }
            Ok(out)
        })
        .await
        .map_err(|e| Error::Index {
            message: format!("join: {e}"),
        })?
    }

    /// Scan one page of objects in `bucket`, optionally filtered by `prefix`,
    /// resumed past `after`, and capped at `limit` items.
    ///
    /// Results are sorted ascending by key. The returned [`ListPage::next`] is
    /// `Some(last_key)` if more results may follow, or `None` if the listing
    /// is exhausted.
    pub async fn scan_objects(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<ListPage, Error> {
        let db = self.db()?;
        let ik = self.index_key()?;
        let omk = self.value_key()?;
        let bucket = bucket.to_owned();
        let prefix = prefix.map(str::to_owned);
        let after = after.map(str::to_owned);

        tokio::task::spawn_blocking(move || -> Result<ListPage, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(OBJECTS).map_err(map_redb)?;

            let bkey = blind_bucket(&ik, &bucket);
            let mut items: Vec<Metadata> = Vec::new();
            for entry in table.range::<&[u8]>(bkey.as_slice()..).map_err(map_redb)? {
                let (k, v) = entry.map_err(map_redb)?;
                if !k.value().starts_with(&bkey) {
                    break;
                }
                let json = open_row(&omk, k.value(), v.value())?;
                let m: Metadata = serde_json::from_slice(&json).map_err(|e| Error::Index {
                    message: format!("deserialize metadata: {e}"),
                })?;
                items.push(m);
            }
            items.sort_by(|a, b| a.key.cmp(&b.key));

            let after_ref = after.as_deref();
            let prefix_ref = prefix.as_deref();
            let mut page: Vec<Metadata> = Vec::with_capacity(limit);
            let mut overflowed = false;
            for m in items {
                if let Some(p) = prefix_ref
                    && !m.key.starts_with(p)
                {
                    continue;
                }
                if let Some(a) = after_ref
                    && m.key.as_str() <= a
                {
                    continue;
                }
                if page.len() == limit {
                    overflowed = true;
                    break;
                }
                page.push(m);
            }

            let next = if overflowed {
                page.last().map(|m| m.key.clone())
            } else {
                None
            };
            Ok(ListPage { items: page, next })
        })
        .await
        .map_err(|e| Error::Index {
            message: format!("join: {e}"),
        })?
    }

    /// Find objects whose labels satisfy `query`.
    ///
    /// Scans the `objects` table once, decrypting and deserializing each
    /// [`Metadata`], and keeps rows that satisfy `query` and the optional
    /// `bucket` / key-`prefix` filters. Results are sorted by `(bucket, key)`
    /// and paginated.
    ///
    /// `after` is an opaque continuation cursor: pass back [`ListPage::next`]
    /// from a previous call to resume. `limit` caps the page size.
    pub async fn search_labels(
        &self,
        query: &LabelQuery,
        bucket: Option<&str>,
        prefix: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<ListPage, Error> {
        let db = self.db()?;
        let omk = self.value_key()?;
        let query = query.clone();
        let bucket = bucket.map(str::to_owned);
        let prefix = prefix.map(str::to_owned);
        let after = after.map(str::to_owned);

        tokio::task::spawn_blocking(move || -> Result<ListPage, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(OBJECTS).map_err(map_redb)?;

            let mut matched: Vec<Metadata> = Vec::new();
            for entry in table.iter().map_err(map_redb)? {
                let (k, v) = entry.map_err(map_redb)?;
                let json = open_row(&omk, k.value(), v.value())?;
                let m: Metadata = serde_json::from_slice(&json).map_err(|e| Error::Index {
                    message: format!("deserialize metadata: {e}"),
                })?;
                if let Some(ref b) = bucket
                    && &m.bucket != b
                {
                    continue;
                }
                if let Some(ref p) = prefix
                    && !m.key.starts_with(p)
                {
                    continue;
                }
                if query.matches(&m.labels) {
                    matched.push(m);
                }
            }

            // Sort and paginate on a composite `bucket\0key` cursor so listings
            // remain stable across buckets.
            matched.sort_by(|a, b| (a.bucket.as_str(), a.key.as_str()).cmp(&(&b.bucket, &b.key)));
            let after_ref = after.as_deref();
            let mut page: Vec<Metadata> = Vec::with_capacity(limit);
            let mut overflowed = false;
            for m in matched {
                if let Some(a) = after_ref
                    && cursor(&m).as_str() <= a
                {
                    continue;
                }
                if page.len() == limit {
                    overflowed = true;
                    break;
                }
                page.push(m);
            }

            let next = if overflowed {
                page.last().map(cursor)
            } else {
                None
            };
            Ok(ListPage { items: page, next })
        })
        .await
        .map_err(|e| Error::Index {
            message: format!("join: {e}"),
        })?
    }
}

/// Opaque pagination cursor for cross-bucket searches: `bucket` and `key`
/// joined by a NUL so ordering matches the `(bucket, key)` sort.
fn cursor(m: &Metadata) -> String {
    format!("{}\u{0}{}", m.bucket, m.key)
}

fn map_redb<E: std::fmt::Display>(e: E) -> Error {
    Error::Index {
        message: e.to_string(),
    }
}

fn map_crypto(e: crate::crypto::CryptoError) -> Error {
    Error::Index {
        message: e.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Key blinding and value sealing
// ---------------------------------------------------------------------------
//
// Every table key below is `HMAC-SHA256(IK, domain_label || length-prefixed
// fields...)` — deterministic so point lookups and prefix range scans keep
// working, and domain-separated per field type so e.g. a bucket name and a
// label name can never blind to the same bytes. Every value is AEAD-sealed
// under the OMK via `encrypt_meta`/`decrypt_meta`, bound to its own blinded
// row key via AAD (hex-encoded, since `encrypt_meta` takes a `&str`) so a
// sealed value copied to a different row fails to decrypt. Padding is
// disabled (`pad_block = 0`): unlike the on-disk `.obj` sidecar, nothing here
// exposes a cleartext length field for padding to protect against, and the
// outer whole-file block cipher already normalizes on-disk block boundaries.

/// Length in bytes of one blinded field (an HMAC-SHA256 output).
const BLIND_LEN: usize = 32;

/// Encode a length-prefixed field into `buf` before hashing, so e.g.
/// `bucket="ab", key="c"` can never blind to the same bytes as
/// `bucket="a", key="bc"`.
fn write_len_prefixed(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn blind_bucket(ik: &[u8; 32], bucket: &str) -> [u8; BLIND_LEN] {
    let mut buf = Vec::with_capacity(11 + 4 + bucket.len());
    buf.extend_from_slice(b"idx-bucket\0");
    write_len_prefixed(&mut buf, bucket);
    prf(ik, &buf)
}

fn blind_object(ik: &[u8; 32], bucket: &str, key: &str) -> [u8; BLIND_LEN] {
    let mut buf = Vec::with_capacity(11 + 8 + bucket.len() + key.len());
    buf.extend_from_slice(b"idx-object\0");
    write_len_prefixed(&mut buf, bucket);
    write_len_prefixed(&mut buf, key);
    prf(ik, &buf)
}

fn blind_label_name(ik: &[u8; 32], name: &str) -> [u8; BLIND_LEN] {
    let mut buf = Vec::with_capacity(10 + 4 + name.len());
    buf.extend_from_slice(b"idx-lname\0");
    write_len_prefixed(&mut buf, name);
    prf(ik, &buf)
}

fn blind_label_value(ik: &[u8; 32], name: &str, value: &str) -> [u8; BLIND_LEN] {
    let mut buf = Vec::with_capacity(9 + 8 + name.len() + value.len());
    buf.extend_from_slice(b"idx-lval\0");
    write_len_prefixed(&mut buf, name);
    write_len_prefixed(&mut buf, value);
    prf(ik, &buf)
}

/// Blinded `objects`/`labels`-suffix row key for `(bucket, key)`: the blinded
/// bucket (32 bytes) followed by the blinded `(bucket, key)` pair (32 bytes).
/// Rows for the same bucket share the leading 32 bytes, which preserves
/// bucket-scoped range scans (`scan_objects`, the `list_buckets` skip-ahead)
/// without the table key ever containing the plaintext name.
fn object_row_key(ik: &[u8; 32], bucket: &str, key: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 * BLIND_LEN);
    out.extend_from_slice(&blind_bucket(ik, bucket));
    out.extend_from_slice(&blind_object(ik, bucket, key));
    out
}

/// Blinded `labels` row key: `(label_name, label_value)` prefix (64 bytes)
/// followed by the same `object_row_key` suffix (64 bytes) used in `objects`.
fn label_row_key(ik: &[u8; 32], name: &str, value: &str, bucket: &str, key: &str) -> Vec<u8> {
    let mut out = label_prefix(ik, name, value);
    out.extend_from_slice(&object_row_key(ik, bucket, key));
    out
}

/// Blinded `(label_name, label_value)` prefix shared by every row for that
/// label, used both to build a full [`label_row_key`] and as the range-scan
/// start bound in [`MetadataIndex::lookup_by_label`].
fn label_prefix(ik: &[u8; 32], name: &str, value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 * BLIND_LEN);
    out.extend_from_slice(&blind_label_name(ik, name));
    out.extend_from_slice(&blind_label_value(ik, name, value));
    out
}

/// Lowercase-hex encode `bytes`, used as the AAD string `encrypt_meta`/
/// `decrypt_meta` bind a sealed row to.
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// AEAD-seal `plaintext` under `omk`, bound to `row_key` via AAD. No padding —
/// see the module-level rationale above.
fn seal_row(omk: &[u8; 32], row_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    encrypt_meta(omk, plaintext, &to_hex(row_key), 0).map_err(map_crypto)
}

/// Open a value sealed by [`seal_row`], requiring it to have been sealed for
/// the same `row_key`.
fn open_row(omk: &[u8; 32], row_key: &[u8], blob: &[u8]) -> Result<Vec<u8>, Error> {
    decrypt_meta(omk, blob, &to_hex(row_key)).map_err(map_crypto)
}

/// Smallest byte sequence strictly greater than every key that starts with
/// `prefix`. Returns `None` only if `prefix` is entirely `0xFF` bytes.
fn next_lex_after(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut v = prefix.to_vec();
    for i in (0..v.len()).rev() {
        if v[i] < 0xFF {
            v[i] += 1;
            v.truncate(i + 1);
            return Some(v);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nk(seed: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k.fill(seed);
        k
    }

    fn make(dir: &Path) -> MetadataIndex {
        let idx = MetadataIndex::new(dir.join("idx.redb"));
        idx.set_node_key(nk(1));
        idx
    }

    fn sample_metadata(bucket: &str, key: &str) -> Metadata {
        Metadata {
            created: 0,
            modified: 0,
            size: 4,
            checksum_gxhash: "x".to_owned(),
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            disk_path: PathBuf::from("/tmp/x"),
            url_path: format!("{bucket}/{key}"),
            labels: [("topsecretlabel".to_owned(), "topsecretvalue".to_owned())]
                .into_iter()
                .collect(),
            cipher_size: None,
            cipher_checksum: None,
            kem_alg: None,
            aead_alg: None,
            envelope_version: None,
            version: None,
            committed_at: None,
            key_epoch: None,
        }
    }

    #[test]
    fn blinding_helpers_are_deterministic_and_domain_separated() {
        let ik = nk(1);
        assert_eq!(blind_bucket(&ik, "b"), blind_bucket(&ik, "b"));
        assert_ne!(blind_bucket(&ik, "b"), blind_bucket(&ik, "c"));
        assert_ne!(blind_label_name(&ik, "n"), blind_bucket(&ik, "n"));
        // Length-prefixing prevents a naive-concatenation collision.
        assert_ne!(blind_object(&ik, "ab", "c"), blind_object(&ik, "a", "bc"));
        assert_ne!(
            blind_label_value(&ik, "ab", "c"),
            blind_label_value(&ik, "a", "bc")
        );
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        needle.is_empty() || haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// The core regression test for this module: once redb hands back row
    /// bytes from an *already-open* database (i.e. exactly what would sit in
    /// its page cache), none of them may contain the plaintext bucket, key,
    /// or label strings. Before blinding/sealing was wired in, every one of
    /// these needles would have appeared verbatim.
    #[tokio::test]
    async fn raw_redb_rows_never_contain_plaintext_bucket_key_or_labels() {
        let dir = tempfile::tempdir().unwrap();
        let idx = make(dir.path());
        idx.upsert(
            &sample_metadata("supersecretbucket", "supersecretkey"),
            SyncLevel::Durable,
        )
        .await
        .unwrap();
        idx.register_bucket("supersecretbucket").await.unwrap();

        let db = idx.db().unwrap();
        let txn = db.begin_read().unwrap();
        let needles: &[&[u8]] = &[
            b"supersecretbucket",
            b"supersecretkey",
            b"topsecretlabel",
            b"topsecretvalue",
        ];
        for table_def in [OBJECTS, LABELS, BUCKETS] {
            let table = txn.open_table(table_def).unwrap();
            for entry in table.iter().unwrap() {
                let (k, v) = entry.unwrap();
                for needle in needles {
                    assert!(
                        !contains_subslice(k.value(), needle),
                        "raw key leaked plaintext {needle:?}"
                    );
                    assert!(
                        !contains_subslice(v.value(), needle),
                        "raw value leaked plaintext {needle:?}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn upsert_lookup_and_label_search_round_trip_through_blinding() {
        let dir = tempfile::tempdir().unwrap();
        let idx = make(dir.path());
        idx.upsert(&sample_metadata("b", "k"), SyncLevel::Durable)
            .await
            .unwrap();

        let got = idx.lookup_by_key("b", "k").await.unwrap().unwrap();
        assert_eq!(got.bucket, "b");
        assert_eq!(got.key, "k");

        let hits = idx
            .lookup_by_label("topsecretlabel", "topsecretvalue")
            .await
            .unwrap();
        assert_eq!(hits, vec![("b".to_owned(), "k".to_owned())]);

        idx.remove("b", "k").await.unwrap();
        assert!(idx.lookup_by_key("b", "k").await.unwrap().is_none());
        assert!(
            idx.lookup_by_label("topsecretlabel", "topsecretvalue")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn bucket_listing_and_registry_round_trip_through_blinding() {
        let dir = tempfile::tempdir().unwrap();
        let idx = make(dir.path());
        idx.upsert(&sample_metadata("has-objects", "k"), SyncLevel::Durable)
            .await
            .unwrap();
        idx.register_bucket("empty-registered").await.unwrap();

        assert!(idx.bucket_exists("has-objects").await.unwrap());
        assert!(idx.bucket_exists("empty-registered").await.unwrap());
        assert!(!idx.bucket_exists("nope").await.unwrap());

        assert_eq!(
            idx.list_buckets().await.unwrap(),
            vec!["has-objects".to_owned()]
        );
        assert_eq!(
            idx.list_registered_buckets().await.unwrap(),
            vec!["empty-registered".to_owned()]
        );

        idx.unregister_bucket("empty-registered").await.unwrap();
        assert!(idx.list_registered_buckets().await.unwrap().is_empty());
    }

    /// An index written under the pre-blinding (v1) key/value encoding — or
    /// missing the schema marker entirely — must be wiped rather than
    /// misread, and left in a working state under the current scheme.
    #[tokio::test]
    async fn schema_mismatch_wipes_stale_rows_and_rewrites_the_marker() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("idx.redb");
        let nk_bytes = nk(1);

        // Simulate a v1 index: a plaintext-composite row, no schema marker.
        {
            let file_key = derive_index_file_key(&nk_bytes);
            let backend =
                EncryptedFileBackend::open(&path, file_key, crate::storage::ForeignFile::Recreate)
                    .unwrap();
            let db = Builder::new().create_with_backend(backend).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut objects = txn.open_table(OBJECTS).unwrap();
                objects
                    .insert(
                        b"legacy-plaintext-key".as_slice(),
                        b"legacy-plaintext-value".as_slice(),
                    )
                    .unwrap();
            }
            txn.commit().unwrap();
        }

        let idx = MetadataIndex::new(&path);
        idx.set_node_key(nk_bytes);

        // The legacy row must be gone...
        assert_eq!(idx.list_all_keys().await.unwrap(), Vec::new());
        // ...and the index must be fully usable under the new scheme.
        idx.upsert(&sample_metadata("b", "k"), SyncLevel::Durable)
            .await
            .unwrap();
        assert!(idx.lookup_by_key("b", "k").await.unwrap().is_some());

        // Reopening again (marker now current) must not wipe anything.
        drop(idx);
        let idx = MetadataIndex::new(&path);
        idx.set_node_key(nk_bytes);
        assert!(idx.lookup_by_key("b", "k").await.unwrap().is_some());
    }
}
