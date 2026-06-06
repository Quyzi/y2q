//! Persistent secondary metadata index backed by [`redb`].
//!
//! The index is a redb database with two tables:
//!
//! - `objects`: composite key `(bucket, key)` → JSON-encoded (and optionally
//!   AES-256-GCM encrypted) [`Metadata`].
//! - `labels`: composite key `(label_name, label_value, bucket, key)` → `()`.
//!   This is a reverse map enabling fast "find all objects whose label `X` has
//!   value `Y`" queries via a redb range scan.
//!
//! ## Encryption
//!
//! The entire redb file is encrypted at rest by [`EncryptedFileBackend`], which
//! transparently encrypts every block under a key derived from the login-gated
//! MEK ([`crate::crypto::derive_index_file_key`]). Inside the database, table
//! keys are stored as plaintext length-prefixed composites and values as plain
//! JSON - the whole-file layer is the sole protection.
//!
//! Because the file key only exists while a session is active, the database is
//! opened on the first login ([`MetadataIndex::set_mek`]) and closed when the
//! daemon goes idle ([`MetadataIndex::close`]). While closed, every index
//! operation returns [`Error::Index`] ("metadata index locked"); only ciphertext
//! remains on disk.
//!
//! **Migration**: a pre-encryption (plaintext redb) index file is incompatible.
//! On first open the backend detects the missing magic, recreates the file
//! empty, and the startup rebuild (`POST /api/v1/admin/rebuild-index`)
//! repopulates it from on-disk object metadata.
//!
//! [`Metadata`]: crate::Metadata
//! [`EncryptedFileBackend`]: crate::storage::EncryptedFileBackend

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use redb::{Builder, Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};

use crate::{
    Error, LabelQuery, ListPage, Metadata, SyncLevel,
    crypto::{derive_index_file_key, metadata_key::MekSlot},
    storage::EncryptedFileBackend,
};

/// `(bucket, key)` (length-prefixed or HMAC-blinded) → JSON-serialized [`Metadata`].
const OBJECTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("objects");

/// `(label_name, label_value, bucket, key)` (length-prefixed or HMAC-blinded) → empty.
///
/// Enables prefix range scans of the form "all objects where label `name` has
/// value `value`".
const LABELS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("labels");

/// `bucket_name` → empty. Registry of explicitly-created buckets so that empty
/// buckets (no objects) still appear in `list_buckets`. The on-disk bucket
/// directory name is an opaque keyed HMAC and cannot be reversed, so the
/// plaintext name is kept here inside the whole-file-encrypted index.
const BUCKETS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("buckets");

/// A persistent secondary index over object metadata, backed by a
/// whole-file-encrypted redb file.
///
/// The database is opened lazily on the first login (when the file key becomes
/// derivable from the MEK) and closed when the daemon goes idle. While closed,
/// `db` is `None` and every operation returns [`Error::Index`].
pub struct MetadataIndex {
    /// On-disk path of the encrypted redb file.
    path: PathBuf,
    /// The open database, or `None` while the index is locked (no session).
    db: RwLock<Option<Arc<Database>>>,
    /// Shared, clearable holder for the MEK. Empty until a login installs it;
    /// zeroized when the daemon goes idle. The file key for [`Self::db`] is
    /// derived from this MEK.
    slot: Arc<MekSlot>,
}

impl MetadataIndex {
    /// Create an unopened index handle for the redb file at `path`.
    ///
    /// Performs no I/O: the encrypted file is only opened once a login installs
    /// the MEK via [`Self::set_mek`].
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            db: RwLock::new(None),
            slot: Arc::new(MekSlot::new()),
        }
    }

    /// Install the MEK and open the encrypted database if not already open.
    ///
    /// Idempotent: a re-login while already open is a no-op for the database.
    /// The MEK is deterministic from the deployment secret key, so the file key
    /// (and hence the existing encrypted file) is recovered unchanged after an
    /// idle [`Self::close`]. An open failure is logged and leaves the index
    /// locked (operations error until a subsequent successful open); the index
    /// is a rebuildable cache, so a login is not failed on its account.
    pub fn set_mek(&self, mek: [u8; 32]) {
        self.slot.install(mek);
        let mut guard = self.db.write().expect("index db poisoned");
        if guard.is_some() {
            return;
        }
        match Self::open_db(&self.path, &mek) {
            Ok(db) => *guard = Some(Arc::new(db)),
            Err(e) => {
                tracing::error!(error = %e, path = %self.path.display(),
                    "failed to open encrypted metadata index");
            }
        }
    }

    /// Close the database, releasing the file handle. Called on idle drop so
    /// only ciphertext remains on disk. A subsequent [`Self::set_mek`] reopens.
    pub fn close(&self) {
        *self.db.write().expect("index db poisoned") = None;
    }

    /// Open (or create) the encrypted redb file at `path` under the file key
    /// derived from `mek`, ensuring both tables exist.
    fn open_db(path: &Path, mek: &[u8; 32]) -> Result<Database, Error> {
        let file_key = derive_index_file_key(mek);
        let backend = EncryptedFileBackend::open(path, file_key).map_err(map_redb)?;
        let db = Builder::new()
            .create_with_backend(backend)
            .map_err(map_redb)?;
        let txn = db.begin_write().map_err(map_redb)?;
        {
            let _ = txn.open_table(OBJECTS).map_err(map_redb)?;
            let _ = txn.open_table(LABELS).map_err(map_redb)?;
            let _ = txn.open_table(BUCKETS).map_err(map_redb)?;
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

    /// Return a handle to the shared MEK slot so a storage backend can share the
    /// same slot and observe installs/clears the moment they happen.
    pub fn mek_slot(&self) -> Arc<MekSlot> {
        Arc::clone(&self.slot)
    }

    /// Insert or replace the metadata for `(m.bucket, m.key)`.
    ///
    /// If a prior row exists, its label entries are removed before the new
    /// ones are written so that a label that has been deleted in `m` no
    /// longer appears in `lookup_by_label`.
    pub async fn upsert(&self, m: &Metadata, sync: SyncLevel) -> Result<(), Error> {
        let db = self.db()?;
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
            let object_key = encode_object_key(&bucket, &key);

            let mut txn = db.begin_write().map_err(map_redb)?;
            if sync != SyncLevel::Durable {
                let _ = txn.set_durability(Durability::None);
            }
            {
                let mut objects = txn.open_table(OBJECTS).map_err(map_redb)?;
                let mut labels = txn.open_table(LABELS).map_err(map_redb)?;

                // Tear down prior label rows (if any) so stale labels go away.
                if let Some(prev) = objects.get(object_key.as_slice()).map_err(map_redb)?
                    && let Ok(prev_meta) = serde_json::from_slice::<Metadata>(prev.value())
                {
                    for (n, v) in &prev_meta.labels {
                        let lk = encode_label_key(n, v, &bucket, &key);
                        labels.remove(lk.as_slice()).map_err(map_redb)?;
                    }
                }

                objects
                    .insert(object_key.as_slice(), payload.as_slice())
                    .map_err(map_redb)?;
                for (n, v) in &new_labels {
                    let lk = encode_label_key(n, v, &bucket, &key);
                    labels
                        .insert(lk.as_slice(), [].as_slice())
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
        let bucket = bucket.to_owned();
        let key = key.to_owned();

        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let object_key = encode_object_key(&bucket, &key);

            let txn = db.begin_write().map_err(map_redb)?;
            {
                let mut objects = txn.open_table(OBJECTS).map_err(map_redb)?;
                let mut labels = txn.open_table(LABELS).map_err(map_redb)?;
                if let Some(prev) = objects.get(object_key.as_slice()).map_err(map_redb)?
                    && let Ok(prev_meta) = serde_json::from_slice::<Metadata>(prev.value())
                {
                    for (n, v) in &prev_meta.labels {
                        let lk = encode_label_key(n, v, &bucket, &key);
                        labels.remove(lk.as_slice()).map_err(map_redb)?;
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
        let bucket = bucket.to_owned();
        let key = key.to_owned();

        tokio::task::spawn_blocking(move || -> Result<Option<Metadata>, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(OBJECTS).map_err(map_redb)?;
            let object_key = encode_object_key(&bucket, &key);
            match table.get(object_key.as_slice()).map_err(map_redb)? {
                None => Ok(None),
                Some(g) => {
                    let m: Metadata =
                        serde_json::from_slice(g.value()).map_err(|e| Error::Index {
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
        let name = name.to_owned();
        let value = value.to_owned();

        tokio::task::spawn_blocking(move || -> Result<Vec<(String, String)>, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let label_table = txn.open_table(LABELS).map_err(map_redb)?;
            let mut results = Vec::new();

            // Decode bucket/key directly from the label key suffix.
            let prefix = encode_label_prefix(&name, &value);
            for entry in label_table.iter().map_err(map_redb)? {
                let (k, _v) = entry.map_err(map_redb)?;
                let bytes = k.value();
                if !bytes.starts_with(&prefix) {
                    continue;
                }
                if let Some((b, key)) = decode_label_suffix(&bytes[prefix.len()..]) {
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
    /// the range cursor to the lex-successor of `B`'s encoded prefix, so this
    /// is O(num_buckets) reads rather than O(num_objects).
    pub async fn list_buckets(&self) -> Result<Vec<String>, Error> {
        let db = self.db()?;

        tokio::task::spawn_blocking(move || -> Result<Vec<String>, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(OBJECTS).map_err(map_redb)?;

            let mut buckets = Vec::new();
            let mut start: Vec<u8> = Vec::new();
            loop {
                let mut iter = table.range::<&[u8]>(start.as_slice()..).map_err(map_redb)?;
                let Some(entry) = iter.next() else { break };
                let (k, _v) = entry.map_err(map_redb)?;

                // Decode bucket name from key bytes.
                let Some((bucket, _rest)) = read_len_prefixed(k.value()) else {
                    return Err(Error::Index {
                        message: "malformed object key in index".to_owned(),
                    });
                };
                let bucket_prefix = encode_bucket_prefix(&bucket);
                buckets.push(bucket);
                let Some(next) = next_lex_after(&bucket_prefix) else {
                    break;
                };
                start = next;
            }
            // Encoded keys sort by length first, then bytes — undo that so
            // the caller sees plain string order.
            buckets.sort();
            Ok(buckets)
        })
        .await
        .map_err(|e| Error::Index {
            message: format!("join: {e}"),
        })?
    }

    /// Return whether `bucket` exists: either explicitly registered (possibly
    /// empty) or holding at least one object. Cheap: an O(1) registry lookup
    /// plus, on miss, a single range probe of the objects table.
    pub async fn bucket_exists(&self, bucket: &str) -> Result<bool, Error> {
        let db = self.db()?;
        let bucket = bucket.to_owned();
        tokio::task::spawn_blocking(move || -> Result<bool, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            {
                let buckets = txn.open_table(BUCKETS).map_err(map_redb)?;
                if buckets.get(bucket.as_bytes()).map_err(map_redb)?.is_some() {
                    return Ok(true);
                }
            }
            let objects = txn.open_table(OBJECTS).map_err(map_redb)?;
            let prefix = encode_bucket_prefix(&bucket);
            let mut iter = objects
                .range::<&[u8]>(prefix.as_slice()..)
                .map_err(map_redb)?;
            if let Some(entry) = iter.next() {
                let (k, _v) = entry.map_err(map_redb)?;
                if k.value().starts_with(&prefix) {
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
        let bucket = bucket.to_owned();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let txn = db.begin_write().map_err(map_redb)?;
            {
                let mut buckets = txn.open_table(BUCKETS).map_err(map_redb)?;
                buckets
                    .insert(bucket.as_bytes(), [].as_slice())
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
        let bucket = bucket.to_owned();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let txn = db.begin_write().map_err(map_redb)?;
            {
                let mut buckets = txn.open_table(BUCKETS).map_err(map_redb)?;
                buckets.remove(bucket.as_bytes()).map_err(map_redb)?;
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
        tokio::task::spawn_blocking(move || -> Result<Vec<String>, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(BUCKETS).map_err(map_redb)?;
            let mut out = Vec::new();
            for entry in table.iter().map_err(map_redb)? {
                let (k, _v) = entry.map_err(map_redb)?;
                if let Ok(name) = std::str::from_utf8(k.value()) {
                    out.push(name.to_owned());
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

        tokio::task::spawn_blocking(move || -> Result<Vec<(String, String)>, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(OBJECTS).map_err(map_redb)?;
            let mut out = Vec::new();
            for entry in table.iter().map_err(map_redb)? {
                let (k, _v) = entry.map_err(map_redb)?;
                // Decode bucket and key from key bytes.
                let Some((bucket, rest)) = read_len_prefixed(k.value()) else {
                    return Err(Error::Index {
                        message: "malformed object key in index".to_owned(),
                    });
                };
                let Some((key, _)) = read_len_prefixed(rest) else {
                    return Err(Error::Index {
                        message: "malformed object key in index".to_owned(),
                    });
                };
                out.push((bucket, key));
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
        let bucket = bucket.to_owned();
        let prefix = prefix.map(str::to_owned);
        let after = after.map(str::to_owned);

        tokio::task::spawn_blocking(move || -> Result<ListPage, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(OBJECTS).map_err(map_redb)?;

            let bucket_prefix: Vec<u8> = encode_bucket_prefix(&bucket);
            let mut items: Vec<Metadata> = Vec::new();
            for entry in table
                .range::<&[u8]>(bucket_prefix.as_slice()..)
                .map_err(map_redb)?
            {
                let (k, v) = entry.map_err(map_redb)?;
                if !k.value().starts_with(&bucket_prefix) {
                    break;
                }
                let m: Metadata = serde_json::from_slice(v.value()).map_err(|e| Error::Index {
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
    /// Scans the `objects` table once, deserializing each [`Metadata`] (works
    /// for both the encrypted and plaintext index layouts), and keeps rows that
    /// satisfy `query` and the optional `bucket` / key-`prefix` filters. Results
    /// are sorted by `(bucket, key)` and paginated.
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
        let query = query.clone();
        let bucket = bucket.map(str::to_owned);
        let prefix = prefix.map(str::to_owned);
        let after = after.map(str::to_owned);

        tokio::task::spawn_blocking(move || -> Result<ListPage, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(OBJECTS).map_err(map_redb)?;

            let mut matched: Vec<Metadata> = Vec::new();
            for entry in table.iter().map_err(map_redb)? {
                let (_k, v) = entry.map_err(map_redb)?;
                let m: Metadata = serde_json::from_slice(v.value()).map_err(|e| Error::Index {
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

// ---------------------------------------------------------------------------
// Key encoding
// ---------------------------------------------------------------------------
//
// Table keys are stored as plaintext length-prefixed composites; the
// whole-file encryption layer ([`EncryptedFileBackend`]) is the sole
// protection at rest.

/// Encode a length-prefixed field into `buf`.
///
/// Layout: 4-byte big-endian length followed by the raw bytes.
fn write_len_prefixed(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn encode_object_key(bucket: &str, key: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + bucket.len() + key.len());
    write_len_prefixed(&mut out, bucket);
    write_len_prefixed(&mut out, key);
    out
}

fn encode_bucket_prefix(bucket: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bucket.len());
    write_len_prefixed(&mut out, bucket);
    out
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

fn encode_label_key(name: &str, value: &str, bucket: &str, key: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + name.len() + value.len() + bucket.len() + key.len());
    write_len_prefixed(&mut out, name);
    write_len_prefixed(&mut out, value);
    write_len_prefixed(&mut out, bucket);
    write_len_prefixed(&mut out, key);
    out
}

fn encode_label_prefix(name: &str, value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + name.len() + value.len());
    write_len_prefixed(&mut out, name);
    write_len_prefixed(&mut out, value);
    out
}

/// Decode the `(bucket, key)` suffix of a label key after the `(name, value)`
/// prefix has been stripped.
fn decode_label_suffix(buf: &[u8]) -> Option<(String, String)> {
    let (bucket, rest) = read_len_prefixed(buf)?;
    let (key, _rest) = read_len_prefixed(rest)?;
    Some((bucket, key))
}

fn read_len_prefixed(buf: &[u8]) -> Option<(String, &[u8])> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes(buf[0..4].try_into().ok()?) as usize;
    if buf.len() < 4 + len {
        return None;
    }
    let s = std::str::from_utf8(&buf[4..4 + len]).ok()?.to_owned();
    Some((s, &buf[4 + len..]))
}
