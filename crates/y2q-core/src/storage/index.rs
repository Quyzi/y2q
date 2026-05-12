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

use redb::{Database, ReadableTable, TableDefinition};

use crate::{Error, Metadata};

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
