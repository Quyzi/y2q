//! Persistent secondary metadata index backed by [`redb`].
//!
//! The index is a redb database with two tables:
//!
//! - `objects`: composite key `(bucket, key)` → JSON-encoded [`Metadata`].
//! - `labels`: composite key `(label_name, label_value, bucket, key)` → `()`.
//!   This is a reverse map enabling fast "find all objects whose label `X` has
//!   value `Y`" queries via a redb range scan.
//!
//! All redb operations are synchronous, so the public API wraps each call in
//! [`tokio::task::spawn_blocking`]. The on-disk JSON sidecar managed by
//! [`FilesystemStorage`] is the source of truth; the index can be rebuilt from
//! a full sidecar scan if it becomes corrupt or out of sync.
//!
//! [`Metadata`]: crate::Metadata
//! [`FilesystemStorage`]: crate::FilesystemStorage

use std::path::Path;
use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::{Error, ListPage, Metadata};

/// `(bucket, key)` (length-prefixed) → JSON-serialized [`Metadata`].
const OBJECTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("objects");

/// `(label_name, label_value, bucket, key)` (length-prefixed) → empty.
///
/// Enables prefix range scans of the form "all objects where label `name` has
/// value `value`".
const LABELS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("labels");

/// A persistent secondary index over object metadata, backed by a redb file.
///
/// Cloning is cheap: the underlying [`redb::Database`] is wrapped in an
/// [`Arc`].
#[derive(Clone)]
pub struct MetadataIndex {
    db: Arc<Database>,
}

impl MetadataIndex {
    /// Open or create the redb database at `path`.
    ///
    /// Synchronous; intended to be called once at startup. Returns
    /// [`Error::Index`] on any redb failure.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let db = Database::create(path).map_err(map_redb)?;
        // Ensure both tables exist so first-write doesn't race with first-read.
        let txn = db.begin_write().map_err(map_redb)?;
        {
            let _ = txn.open_table(OBJECTS).map_err(map_redb)?;
            let _ = txn.open_table(LABELS).map_err(map_redb)?;
        }
        txn.commit().map_err(map_redb)?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Insert or replace the metadata for `(m.bucket, m.key)`.
    ///
    /// If a prior row exists, its label entries are removed before the new
    /// ones are written so that a label that has been deleted in `m` no
    /// longer appears in `lookup_by_label`.
    pub async fn upsert(&self, m: &Metadata) -> Result<(), Error> {
        let db = self.db.clone();
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
            let txn = db.begin_write().map_err(map_redb)?;
            {
                let mut objects = txn.open_table(OBJECTS).map_err(map_redb)?;
                let mut labels = txn.open_table(LABELS).map_err(map_redb)?;

                let object_key = encode_object_key(&bucket, &key);
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
        let db = self.db.clone();
        let bucket = bucket.to_owned();
        let key = key.to_owned();

        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let txn = db.begin_write().map_err(map_redb)?;
            {
                let mut objects = txn.open_table(OBJECTS).map_err(map_redb)?;
                let mut labels = txn.open_table(LABELS).map_err(map_redb)?;
                let object_key = encode_object_key(&bucket, &key);
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
    /// Returns `Ok(None)` if no row exists. Note: [`FilesystemStorage::describe`]
    /// reads the on-disk sidecar directly and does not consult the index.
    ///
    /// [`FilesystemStorage::describe`]: crate::FilesystemStorage
    pub async fn lookup_by_key(&self, bucket: &str, key: &str) -> Result<Option<Metadata>, Error> {
        let db = self.db.clone();
        let bucket = bucket.to_owned();
        let key = key.to_owned();

        tokio::task::spawn_blocking(move || -> Result<Option<Metadata>, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(OBJECTS).map_err(map_redb)?;
            let object_key = encode_object_key(&bucket, &key);
            let row = table.get(object_key.as_slice()).map_err(map_redb)?;
            match row {
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
        let db = self.db.clone();
        let name = name.to_owned();
        let value = value.to_owned();

        tokio::task::spawn_blocking(move || -> Result<Vec<(String, String)>, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(LABELS).map_err(map_redb)?;
            let prefix = encode_label_prefix(&name, &value);
            let mut results = Vec::new();
            for entry in table.iter().map_err(map_redb)? {
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
        let db = self.db.clone();

        tokio::task::spawn_blocking(move || -> Result<Vec<String>, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(OBJECTS).map_err(map_redb)?;

            let mut buckets = Vec::new();
            let mut start: Vec<u8> = Vec::new();
            loop {
                let mut iter = table.range::<&[u8]>(start.as_slice()..).map_err(map_redb)?;
                let Some(entry) = iter.next() else { break };
                let (k, _v) = entry.map_err(map_redb)?;
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

    /// Return every `(bucket, key)` pair currently stored in the objects
    /// table, in the order they appear on disk (encoded-key order, not
    /// string order).
    ///
    /// Used by cache-rebuild reconciliation to find rows that should be
    /// removed because their on-disk sidecar no longer exists. Holds the
    /// entire key set in memory — fine for the target scale of ~10⁵ objects
    /// per bucket.
    pub async fn list_all_keys(&self) -> Result<Vec<(String, String)>, Error> {
        let db = self.db.clone();

        tokio::task::spawn_blocking(move || -> Result<Vec<(String, String)>, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(OBJECTS).map_err(map_redb)?;
            let mut out = Vec::new();
            for entry in table.iter().map_err(map_redb)? {
                let (k, _v) = entry.map_err(map_redb)?;
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
    ///
    /// Implementation note: the redb composite key encoding sorts by encoded
    /// bytes (length prefix first), which does not match string order. We
    /// therefore range-scan only the rows belonging to `bucket`, then sort
    /// and paginate in memory. This is acceptable for buckets up to ~10⁵
    /// objects; beyond that the encoding should be migrated to a
    /// string-sortable form.
    pub async fn scan_objects(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<ListPage, Error> {
        let db = self.db.clone();
        let bucket = bucket.to_owned();
        let prefix = prefix.map(str::to_owned);
        let after = after.map(str::to_owned);

        tokio::task::spawn_blocking(move || -> Result<ListPage, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(OBJECTS).map_err(map_redb)?;

            let bucket_prefix = encode_bucket_prefix(&bucket);
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
}

fn map_redb<E: std::fmt::Display>(e: E) -> Error {
    Error::Index {
        message: e.to_string(),
    }
}

/// Encode a length-prefixed field into `buf`.
///
/// Layout: 4-byte big-endian length followed by the raw bytes. Big-endian so
/// lexicographic byte ordering of encoded keys is meaningful for range scans.
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

/// Encode just the length-prefixed bucket portion of an object key, used as a
/// `starts_with` predicate and range-scan start when listing a bucket.
fn encode_bucket_prefix(bucket: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bucket.len());
    write_len_prefixed(&mut out, bucket);
    out
}

/// Smallest byte sequence strictly greater than every key that starts with
/// `prefix`. Returns `None` only if `prefix` is entirely `0xFF` bytes, in
/// which case no such successor exists.
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

/// Decode the `(bucket, key)` suffix of a label key, after the `(name, value)`
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
