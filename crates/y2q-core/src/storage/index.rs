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
//! When a Metadata Encryption Key (MEK) is set via [`MetadataIndex::set_mek`],
//! both table keys and values are protected:
//!
//! - **Values** in the `objects` table are AES-256-GCM encrypted via
//!   [`encrypt_meta`] / [`decrypt_meta`] using the MEK directly.
//! - **Keys** in both tables are HMAC-SHA256 blinded using an Index Key (IK)
//!   derived as `IK = HMAC-SHA256(MEK, "y2q-index-key-v1")`. Each string field
//!   in a composite key is replaced with `HMAC-SHA256(IK, tag || field_bytes)`,
//!   producing a fixed-length 32-byte block. Range-scan and prefix-scan
//!   semantics are preserved because all blocks are the same length.
//!
//! When no MEK is set, the index uses plaintext length-prefixed keys and
//! unencrypted JSON values (legacy behaviour).
//!
//! **Migration**: the plaintext and encrypted key encodings are incompatible.
//! Enabling encryption requires a full index rebuild via
//! `POST /api/v1/admin/rebuild-index`.
//!
//! [`Metadata`]: crate::Metadata
//! [`encrypt_meta`]: crate::crypto::encrypt_meta
//! [`decrypt_meta`]: crate::crypto::decrypt_meta

use std::path::Path;
use std::sync::{Arc, OnceLock};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::{
    Error, ListPage, Metadata,
    crypto::{decrypt_meta, encrypt_meta, metadata_key::derive_index_key, metadata_key::prf},
};

/// `(bucket, key)` (length-prefixed or HMAC-blinded) → JSON-serialized [`Metadata`].
const OBJECTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("objects");

/// `(label_name, label_value, bucket, key)` (length-prefixed or HMAC-blinded) → empty.
///
/// Enables prefix range scans of the form "all objects where label `name` has
/// value `value`".
const LABELS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("labels");

/// A persistent secondary index over object metadata, backed by a redb file.
///
/// Cloning is cheap: the underlying [`redb::Database`] is wrapped in an [`Arc`].
#[derive(Clone)]
pub struct MetadataIndex {
    db: Arc<Database>,
    /// AES-256-GCM key for value encryption.
    mek: Arc<OnceLock<[u8; 32]>>,
    /// HMAC key for blinding index key fields; derived from `mek`.
    ik: Arc<OnceLock<[u8; 32]>>,
}

impl MetadataIndex {
    /// Open or create the redb database at `path`.
    ///
    /// Synchronous; intended to be called once at startup. Returns
    /// [`Error::Index`] on any redb failure. Call [`Self::set_mek`] before
    /// any reads or writes if index encryption is desired.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let db = Database::create(path).map_err(map_redb)?;
        let txn = db.begin_write().map_err(map_redb)?;
        {
            let _ = txn.open_table(OBJECTS).map_err(map_redb)?;
            let _ = txn.open_table(LABELS).map_err(map_redb)?;
        }
        txn.commit().map_err(map_redb)?;
        Ok(Self {
            db: Arc::new(db),
            mek: Arc::new(OnceLock::new()),
            ik: Arc::new(OnceLock::new()),
        })
    }

    /// Enable index encryption.
    ///
    /// Derives `IK = HMAC-SHA256(MEK, "y2q-index-key-v1")` and stores both.
    /// Must be called before any reads or writes. Has no effect if called more
    /// than once (the `OnceLock` silently ignores subsequent sets).
    pub fn set_mek(&self, mek: [u8; 32]) {
        let _ = self.ik.set(derive_index_key(&mek));
        let _ = self.mek.set(mek);
    }

    /// Insert or replace the metadata for `(m.bucket, m.key)`.
    ///
    /// If a prior row exists, its label entries are removed before the new
    /// ones are written so that a label that has been deleted in `m` no
    /// longer appears in `lookup_by_label`.
    pub async fn upsert(&self, m: &Metadata) -> Result<(), Error> {
        let db = self.db.clone();
        let raw_json = serde_json::to_vec(m).map_err(|e| Error::Index {
            message: format!("serialize metadata: {e}"),
        })?;
        let mek = self.mek.get().copied();
        let ik = self.ik.get().copied();
        let bucket = m.bucket.clone();
        let key = m.key.clone();
        let new_labels: Vec<(String, String)> = m
            .labels
            .iter()
            .map(|(n, v)| (n.clone(), v.clone()))
            .collect();

        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let payload = match mek {
                Some(ref mek) => encrypt_meta(mek, &raw_json).map_err(|_| Error::Index {
                    message: "encrypt metadata".to_owned(),
                })?,
                None => raw_json,
            };

            let object_key = match ik {
                Some(ref ik) => encode_object_key_enc(ik, &bucket, &key),
                None => encode_object_key(&bucket, &key),
            };

            let txn = db.begin_write().map_err(map_redb)?;
            {
                let mut objects = txn.open_table(OBJECTS).map_err(map_redb)?;
                let mut labels = txn.open_table(LABELS).map_err(map_redb)?;

                // Tear down prior label rows (if any) so stale labels go away.
                if let Some(prev) = objects.get(object_key.as_slice()).map_err(map_redb)?
                    && let Ok(prev_json) = decrypt_blob(mek.as_ref(), prev.value())
                    && let Ok(prev_meta) = serde_json::from_slice::<Metadata>(&prev_json)
                {
                    for (n, v) in &prev_meta.labels {
                        let lk = match ik {
                            Some(ref ik) => encode_label_key_enc(ik, n, v, &bucket, &key),
                            None => encode_label_key(n, v, &bucket, &key),
                        };
                        labels.remove(lk.as_slice()).map_err(map_redb)?;
                    }
                }

                objects
                    .insert(object_key.as_slice(), payload.as_slice())
                    .map_err(map_redb)?;
                for (n, v) in &new_labels {
                    let lk = match ik {
                        Some(ref ik) => encode_label_key_enc(ik, n, v, &bucket, &key),
                        None => encode_label_key(n, v, &bucket, &key),
                    };
                    labels.insert(lk.as_slice(), [].as_slice()).map_err(map_redb)?;
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
        let mek = self.mek.get().copied();
        let ik = self.ik.get().copied();
        let bucket = bucket.to_owned();
        let key = key.to_owned();

        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let object_key = match ik {
                Some(ref ik) => encode_object_key_enc(ik, &bucket, &key),
                None => encode_object_key(&bucket, &key),
            };

            let txn = db.begin_write().map_err(map_redb)?;
            {
                let mut objects = txn.open_table(OBJECTS).map_err(map_redb)?;
                let mut labels = txn.open_table(LABELS).map_err(map_redb)?;
                if let Some(prev) = objects.get(object_key.as_slice()).map_err(map_redb)?
                    && let Ok(prev_json) = decrypt_blob(mek.as_ref(), prev.value())
                    && let Ok(prev_meta) = serde_json::from_slice::<Metadata>(&prev_json)
                {
                    for (n, v) in &prev_meta.labels {
                        let lk = match ik {
                            Some(ref ik) => encode_label_key_enc(ik, n, v, &bucket, &key),
                            None => encode_label_key(n, v, &bucket, &key),
                        };
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
        let db = self.db.clone();
        let mek = self.mek.get().copied();
        let ik = self.ik.get().copied();
        let bucket = bucket.to_owned();
        let key = key.to_owned();

        tokio::task::spawn_blocking(move || -> Result<Option<Metadata>, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(OBJECTS).map_err(map_redb)?;
            let object_key = match ik {
                Some(ref ik) => encode_object_key_enc(ik, &bucket, &key),
                None => encode_object_key(&bucket, &key),
            };
            match table.get(object_key.as_slice()).map_err(map_redb)? {
                None => Ok(None),
                Some(g) => {
                    let json = decrypt_blob(mek.as_ref(), g.value())?;
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
    ///
    /// When the index is encrypted, each label key match is resolved to a
    /// `(bucket, key)` by looking up the corresponding row in the `objects`
    /// table and decrypting its value.
    pub async fn lookup_by_label(
        &self,
        name: &str,
        value: &str,
    ) -> Result<Vec<(String, String)>, Error> {
        let db = self.db.clone();
        let mek = self.mek.get().copied();
        let ik = self.ik.get().copied();
        let name = name.to_owned();
        let value = value.to_owned();

        tokio::task::spawn_blocking(move || -> Result<Vec<(String, String)>, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let label_table = txn.open_table(LABELS).map_err(map_redb)?;
            let mut results = Vec::new();

            if let Some(ref ik) = ik {
                // Encrypted: prefix = 64 bytes (two HMACs). The suffix is the
                // 64-byte object key; join via the objects table to recover
                // bucket and key names.
                let obj_table = txn.open_table(OBJECTS).map_err(map_redb)?;
                let prefix = encode_label_prefix_enc(ik, &name, &value);
                for entry in label_table.iter().map_err(map_redb)? {
                    let (k, _v) = entry.map_err(map_redb)?;
                    let bytes = k.value();
                    if !bytes.starts_with(&prefix) {
                        continue;
                    }
                    // Last 64 bytes of the label key == the full object key.
                    let obj_key = &bytes[prefix.len()..];
                    if obj_key.len() != 64 {
                        continue;
                    }
                    if let Some(obj) = obj_table.get(obj_key).map_err(map_redb)? {
                        let json = decrypt_blob(mek.as_ref(), obj.value())?;
                        if let Ok(m) = serde_json::from_slice::<Metadata>(&json) {
                            results.push((m.bucket, m.key));
                        }
                    }
                }
            } else {
                // Plaintext: decode bucket/key directly from label key suffix.
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
    ///
    /// When encrypted, the bucket name is recovered by decrypting the value;
    /// the 32-byte HMAC prefix of the key is used for the skip-ahead jump.
    pub async fn list_buckets(&self) -> Result<Vec<String>, Error> {
        let db = self.db.clone();
        let mek = self.mek.get().copied();
        let ik = self.ik.get().copied();

        tokio::task::spawn_blocking(move || -> Result<Vec<String>, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(OBJECTS).map_err(map_redb)?;

            let mut buckets = Vec::new();
            let mut start: Vec<u8> = Vec::new();
            loop {
                let mut iter = table.range::<&[u8]>(start.as_slice()..).map_err(map_redb)?;
                let Some(entry) = iter.next() else { break };
                let (k, v) = entry.map_err(map_redb)?;

                if ik.is_some() {
                    // Encrypted: first 32 bytes of key = HMAC(IK, "b\x00" || bucket).
                    // Recover bucket name from decrypted value.
                    let key_bytes = k.value();
                    if key_bytes.len() < 32 {
                        return Err(Error::Index {
                            message: "malformed encrypted object key in index".to_owned(),
                        });
                    }
                    let json = decrypt_blob(mek.as_ref(), v.value())?;
                    let m: Metadata = serde_json::from_slice(&json).map_err(|e| Error::Index {
                        message: format!("deserialize metadata: {e}"),
                    })?;
                    let bucket_hash = &key_bytes[..32];
                    buckets.push(m.bucket);
                    let Some(next) = next_lex_after(bucket_hash) else { break };
                    start = next;
                } else {
                    // Plaintext: decode bucket name from key bytes.
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

    /// Return every `(bucket, key)` pair currently stored in the objects table.
    ///
    /// Used by cache-rebuild reconciliation to find rows that should be removed
    /// because their on-disk sidecar no longer exists.
    pub async fn list_all_keys(&self) -> Result<Vec<(String, String)>, Error> {
        let db = self.db.clone();
        let mek = self.mek.get().copied();
        let ik = self.ik.get().copied();

        tokio::task::spawn_blocking(move || -> Result<Vec<(String, String)>, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(OBJECTS).map_err(map_redb)?;
            let mut out = Vec::new();
            for entry in table.iter().map_err(map_redb)? {
                let (k, v) = entry.map_err(map_redb)?;
                if ik.is_some() {
                    // Encrypted: recover bucket and key from decrypted value.
                    let json = decrypt_blob(mek.as_ref(), v.value())?;
                    let m: Metadata = serde_json::from_slice(&json).map_err(|e| Error::Index {
                        message: format!("deserialize metadata: {e}"),
                    })?;
                    out.push((m.bucket, m.key));
                } else {
                    // Plaintext: decode from key bytes.
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
        let db = self.db.clone();
        let mek = self.mek.get().copied();
        let ik = self.ik.get().copied();
        let bucket = bucket.to_owned();
        let prefix = prefix.map(str::to_owned);
        let after = after.map(str::to_owned);

        tokio::task::spawn_blocking(move || -> Result<ListPage, Error> {
            let txn = db.begin_read().map_err(map_redb)?;
            let table = txn.open_table(OBJECTS).map_err(map_redb)?;

            let bucket_prefix: Vec<u8> = match ik {
                Some(ref ik) => encode_bucket_prefix_enc(ik, &bucket).to_vec(),
                None => encode_bucket_prefix(&bucket),
            };
            let mut items: Vec<Metadata> = Vec::new();
            for entry in table
                .range::<&[u8]>(bucket_prefix.as_slice()..)
                .map_err(map_redb)?
            {
                let (k, v) = entry.map_err(map_redb)?;
                if !k.value().starts_with(&bucket_prefix) {
                    break;
                }
                let json = decrypt_blob(mek.as_ref(), v.value())?;
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
}

fn map_redb<E: std::fmt::Display>(e: E) -> Error {
    Error::Index {
        message: e.to_string(),
    }
}

/// Decrypt a value blob when MEK is set; otherwise return a copy as-is.
fn decrypt_blob(mek: Option<&[u8; 32]>, blob: &[u8]) -> Result<Vec<u8>, Error> {
    match mek {
        Some(mek) => decrypt_meta(mek, blob).map_err(|_| Error::Index {
            message: "decrypt index value".to_owned(),
        }),
        None => Ok(blob.to_vec()),
    }
}

// ---------------------------------------------------------------------------
// Plaintext key encoding (legacy — no MEK)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Encrypted key encoding — HMAC-SHA256 blinded with IK
// ---------------------------------------------------------------------------
//
// Each string field becomes `HMAC-SHA256(IK, tag || field_bytes)` = 32 bytes.
// Tags (`b\x00`, `k\x00`, `ln\x00`, `lv\x00`) prevent cross-field collisions.
// Fixed-length blocks preserve range-scan semantics without length prefixes.

fn field_hmac(ik: &[u8; 32], tag: &[u8], s: &str) -> [u8; 32] {
    let mut input = Vec::with_capacity(tag.len() + s.len());
    input.extend_from_slice(tag);
    input.extend_from_slice(s.as_bytes());
    prf(ik, &input)
}

/// Object key: `HMAC(IK, "b\x00" || bucket) || HMAC(IK, "k\x00" || key)` = 64 bytes.
fn encode_object_key_enc(ik: &[u8; 32], bucket: &str, key: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&field_hmac(ik, b"b\x00", bucket));
    out.extend_from_slice(&field_hmac(ik, b"k\x00", key));
    out
}

/// Bucket prefix: first 32 bytes of the encrypted object key.
fn encode_bucket_prefix_enc(ik: &[u8; 32], bucket: &str) -> [u8; 32] {
    field_hmac(ik, b"b\x00", bucket)
}

/// Label key: four 32-byte HMAC blocks = 128 bytes total.
fn encode_label_key_enc(ik: &[u8; 32], name: &str, value: &str, bucket: &str, key: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&field_hmac(ik, b"ln\x00", name));
    out.extend_from_slice(&field_hmac(ik, b"lv\x00", value));
    out.extend_from_slice(&field_hmac(ik, b"b\x00", bucket));
    out.extend_from_slice(&field_hmac(ik, b"k\x00", key));
    out
}

/// Label prefix: first 64 bytes of the encrypted label key.
fn encode_label_prefix_enc(ik: &[u8; 32], name: &str, value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&field_hmac(ik, b"ln\x00", name));
    out.extend_from_slice(&field_hmac(ik, b"lv\x00", value));
    out
}
