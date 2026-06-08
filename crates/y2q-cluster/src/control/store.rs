//! redb-backed openraft storage for the control plane.
//!
//! Implements the storage-v2 trait pair against a single redb database:
//! [`LogStore`] holds the raft log + vote + committed pointers, and
//! [`StateMachineStore`] holds the applied [`ControlState`] plus snapshots. Only
//! control metadata is ever stored here — never object data.
//!
//! Correctness is validated against openraft's own conformance `Suite` (see the
//! tests at the bottom), which exercises every method's contract.

// Every function here returns openraft's `StorageError`, whose size is fixed by
// openraft's trait signatures and not under our control; the large-err lint is
// unactionable for these call sites.
#![allow(clippy::result_large_err)]

use std::io::Cursor;
use std::ops::RangeBounds;
use std::path::Path;
use std::sync::Arc;

use openraft::storage::{LogFlushed, RaftLogStorage, RaftStateMachine};
use openraft::{
    BasicNode, Entry, EntryPayload, LogId, LogState, OptionalSend, RaftLogReader,
    RaftSnapshotBuilder, Snapshot, SnapshotMeta, StorageError, StorageIOError, StoredMembership,
    Vote,
};
use redb::{Builder, Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, watch};

use crate::control::raft_impl::TypeConfig;
use crate::control::types::{ControlResp, ControlState};

type NodeId = u64;

/// Log entries, keyed by log index.
const LOGS: TableDefinition<u64, &[u8]> = TableDefinition::new("raft_logs");
/// Small singleton values (vote, committed pointer, purge pointer, snapshot,
/// state machine), keyed by a fixed string.
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("raft_meta");

const META_VOTE: &str = "vote";
const META_COMMITTED: &str = "committed";
const META_PURGED: &str = "last_purged";
const META_SNAPSHOT: &str = "snapshot";
const META_SM: &str = "state_machine";

/// Map a redb/serde error to an openraft read-side storage error.
fn sto_r<E: std::error::Error + 'static>(e: E) -> StorageError<NodeId> {
    StorageIOError::read(&e).into()
}

/// Map a redb/serde error to an openraft write-side storage error.
fn sto_w<E: std::error::Error + 'static>(e: E) -> StorageError<NodeId> {
    StorageIOError::write(&e).into()
}

/// Open (creating if needed) the control-plane raft store at `path`, returning a
/// log store and a state-machine store that share one database. The state
/// machine is loaded from disk so a restart resumes the last applied state.
pub fn open(path: &Path) -> Result<(LogStore, StateMachineStore), StorageError<NodeId>> {
    let db = Builder::new().create(path).map_err(sto_w)?;
    let db = Arc::new(db);

    // Ensure both tables exist so later read transactions don't fail on a fresh
    // database.
    {
        let txn = db.begin_write().map_err(sto_w)?;
        txn.open_table(LOGS).map_err(sto_w)?;
        txn.open_table(META).map_err(sto_w)?;
        txn.commit().map_err(sto_w)?;
    }

    let log = LogStore { db: db.clone() };
    let sm = StateMachineStore::load(db)?;
    Ok((log, sm))
}

/// Read a serde-JSON value from the META table.
fn read_meta<T: for<'de> Deserialize<'de>>(
    db: &Database,
    key: &str,
) -> Result<Option<T>, StorageError<NodeId>> {
    let txn = db.begin_read().map_err(sto_r)?;
    let table = txn.open_table(META).map_err(sto_r)?;
    match table.get(key).map_err(sto_r)? {
        Some(v) => Ok(Some(serde_json::from_slice(v.value()).map_err(sto_r)?)),
        None => Ok(None),
    }
}

/// Write a serde-JSON value to the META table in its own transaction.
fn write_meta<T: Serialize>(
    db: &Database,
    key: &str,
    value: &T,
) -> Result<(), StorageError<NodeId>> {
    let bytes = serde_json::to_vec(value).map_err(sto_w)?;
    let txn = db.begin_write().map_err(sto_w)?;
    {
        let mut table = txn.open_table(META).map_err(sto_w)?;
        table.insert(key, bytes.as_slice()).map_err(sto_w)?;
    }
    txn.commit().map_err(sto_w)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Log store
// ---------------------------------------------------------------------------

/// redb-backed raft log store. Cheaply cloneable (shares the database handle);
/// the clone doubles as the [`RaftLogReader`].
#[derive(Clone)]
pub struct LogStore {
    db: Arc<Database>,
}

impl RaftLogReader<TypeConfig> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + std::fmt::Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeId>> {
        let txn = self.db.begin_read().map_err(sto_r)?;
        let table = txn.open_table(LOGS).map_err(sto_r)?;
        let mut out = Vec::new();
        for item in table.range(range).map_err(sto_r)? {
            let (_k, v) = item.map_err(sto_r)?;
            let entry: Entry<TypeConfig> = serde_json::from_slice(v.value()).map_err(sto_r)?;
            out.push(entry);
        }
        Ok(out)
    }
}

impl RaftLogStorage<TypeConfig> for LogStore {
    type LogReader = LogStore;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<NodeId>> {
        let last_purged: Option<LogId<NodeId>> = read_meta(&self.db, META_PURGED)?;

        let txn = self.db.begin_read().map_err(sto_r)?;
        let table = txn.open_table(LOGS).map_err(sto_r)?;
        let last = table.last().map_err(sto_r)?;
        let last_log_id = match last {
            Some((_k, v)) => {
                let entry: Entry<TypeConfig> = serde_json::from_slice(v.value()).map_err(sto_r)?;
                Some(entry.log_id)
            }
            None => last_purged,
        };

        Ok(LogState {
            last_purged_log_id: last_purged,
            last_log_id,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        write_meta(&self.db, META_VOTE, vote)
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        read_meta(&self.db, META_VOTE)
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<NodeId>>,
    ) -> Result<(), StorageError<NodeId>> {
        write_meta(&self.db, META_COMMITTED, &committed)
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        // The stored value is itself an `Option<LogId>`; an absent key means none.
        Ok(read_meta::<Option<LogId<NodeId>>>(&self.db, META_COMMITTED)?.flatten())
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        {
            let txn = self.db.begin_write().map_err(sto_w)?;
            {
                let mut table = txn.open_table(LOGS).map_err(sto_w)?;
                for entry in entries {
                    let bytes = serde_json::to_vec(&entry).map_err(sto_w)?;
                    table
                        .insert(entry.log_id.index, bytes.as_slice())
                        .map_err(sto_w)?;
                }
            }
            txn.commit().map_err(sto_w)?;
        }
        // The write is durable on disk now (commit fsyncs), so report completion.
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let txn = self.db.begin_write().map_err(sto_w)?;
        {
            let mut table = txn.open_table(LOGS).map_err(sto_w)?;
            let keys: Vec<u64> = table
                .range(log_id.index..)
                .map_err(sto_w)?
                .map(|item| item.map(|(k, _v)| k.value()))
                .collect::<Result<_, _>>()
                .map_err(sto_w)?;
            for k in keys {
                table.remove(k).map_err(sto_w)?;
            }
        }
        txn.commit().map_err(sto_w)?;
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        // Record the purge point first so a crash mid-delete never loses the
        // last-purged marker.
        write_meta(&self.db, META_PURGED, &log_id)?;

        let txn = self.db.begin_write().map_err(sto_w)?;
        {
            let mut table = txn.open_table(LOGS).map_err(sto_w)?;
            let keys: Vec<u64> = table
                .range(..=log_id.index)
                .map_err(sto_w)?
                .map(|item| item.map(|(k, _v)| k.value()))
                .collect::<Result<_, _>>()
                .map_err(sto_w)?;
            for k in keys {
                table.remove(k).map_err(sto_w)?;
            }
        }
        txn.commit().map_err(sto_w)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// State machine store
// ---------------------------------------------------------------------------

/// The persisted state-machine contents.
#[derive(Clone, Default, Serialize, Deserialize)]
struct StoredSm {
    last_applied: Option<LogId<NodeId>>,
    last_membership: StoredMembership<NodeId, BasicNode>,
    state: ControlState,
}

/// A persisted snapshot: its metadata plus the serialized state-machine bytes.
#[derive(Clone, Serialize, Deserialize)]
struct StoredSnapshot {
    meta: SnapshotMeta<NodeId, BasicNode>,
    data: Vec<u8>,
}

/// redb-backed raft state machine holding the applied [`ControlState`].
///
/// Cloneable (shares the database + in-memory cache); the clone doubles as the
/// [`RaftSnapshotBuilder`]. Every apply/install publishes the new
/// [`ControlState`] on a watch channel the data plane reads lock-free.
#[derive(Clone)]
pub struct StateMachineStore {
    db: Arc<Database>,
    sm: Arc<Mutex<StoredSm>>,
    watch_tx: Arc<watch::Sender<Arc<ControlState>>>,
    snapshot_seq: Arc<Mutex<u64>>,
}

impl StateMachineStore {
    /// Load the state machine from `db`, defaulting to empty on a fresh store.
    fn load(db: Arc<Database>) -> Result<Self, StorageError<NodeId>> {
        let stored: StoredSm = read_meta(&db, META_SM)?.unwrap_or_default();
        let (tx, _rx) = watch::channel(Arc::new(stored.state.clone()));
        Ok(Self {
            db,
            sm: Arc::new(Mutex::new(stored)),
            watch_tx: Arc::new(tx),
            snapshot_seq: Arc::new(Mutex::new(0)),
        })
    }

    /// Subscribe to control-state updates published on every apply/install.
    pub fn subscribe(&self) -> watch::Receiver<Arc<ControlState>> {
        self.watch_tx.subscribe()
    }

    /// A snapshot of the current control state.
    pub async fn control_state(&self) -> ControlState {
        self.sm.lock().await.state.clone()
    }

    /// Persist the in-memory state machine to redb.
    fn persist(&self, sm: &StoredSm) -> Result<(), StorageError<NodeId>> {
        write_meta(&self.db, META_SM, sm)
    }
}

impl RaftStateMachine<TypeConfig> for StateMachineStore {
    type SnapshotBuilder = StateMachineStore;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<NodeId>>, StoredMembership<NodeId, BasicNode>), StorageError<NodeId>>
    {
        let sm = self.sm.lock().await;
        Ok((sm.last_applied, sm.last_membership.clone()))
    }

    #[tracing::instrument(skip_all, name = "raft.apply")]
    async fn apply<I>(&mut self, entries: I) -> Result<Vec<ControlResp>, StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let mut sm = self.sm.lock().await;
        let mut responses = Vec::new();
        for entry in entries {
            sm.last_applied = Some(entry.log_id);
            match entry.payload {
                EntryPayload::Blank => responses.push(ControlResp {
                    epoch: sm.state.epoch,
                }),
                EntryPayload::Normal(cmd) => {
                    let resp = sm.state.apply(&cmd);
                    responses.push(resp);
                }
                EntryPayload::Membership(membership) => {
                    sm.last_membership = StoredMembership::new(Some(entry.log_id), membership);
                    responses.push(ControlResp {
                        epoch: sm.state.epoch,
                    });
                }
            }
        }
        self.persist(&sm)?;
        self.watch_tx.send_replace(Arc::new(sm.state.clone()));
        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NodeId>> {
        let bytes = (*snapshot).into_inner();
        let restored: StoredSm = serde_json::from_slice(&bytes).map_err(sto_r)?;

        let mut sm = self.sm.lock().await;
        *sm = restored;
        // The metadata is authoritative for the applied pointers.
        sm.last_applied = meta.last_log_id;
        sm.last_membership = meta.last_membership.clone();
        self.persist(&sm)?;

        let stored = StoredSnapshot {
            meta: meta.clone(),
            data: bytes,
        };
        write_meta(&self.db, META_SNAPSHOT, &stored)?;

        self.watch_tx.send_replace(Arc::new(sm.state.clone()));
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<NodeId>> {
        let stored: Option<StoredSnapshot> = read_meta(&self.db, META_SNAPSHOT)?;
        Ok(stored.map(|s| Snapshot {
            meta: s.meta,
            snapshot: Box::new(Cursor::new(s.data)),
        }))
    }
}

impl RaftSnapshotBuilder<TypeConfig> for StateMachineStore {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<NodeId>> {
        let (data, last_applied, last_membership) = {
            let sm = self.sm.lock().await;
            let data = serde_json::to_vec(&*sm).map_err(sto_w)?;
            (data, sm.last_applied, sm.last_membership.clone())
        };

        let seq = {
            let mut s = self.snapshot_seq.lock().await;
            *s += 1;
            *s
        };
        let snapshot_id = match last_applied {
            Some(log_id) => format!("{}-{}-{}", log_id.leader_id, log_id.index, seq),
            None => format!("empty-{seq}"),
        };

        let meta = SnapshotMeta {
            last_log_id: last_applied,
            last_membership,
            snapshot_id,
        };
        let stored = StoredSnapshot {
            meta: meta.clone(),
            data: data.clone(),
        };
        write_meta(&self.db, META_SNAPSHOT, &stored)?;

        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openraft::testing::StoreBuilder;
    use openraft::testing::Suite;
    use tempfile::TempDir;

    /// Builds a fresh redb-backed store in a temp dir for each Suite case; the
    /// `TempDir` guard cleans up when dropped.
    struct RedbStoreBuilder;

    impl StoreBuilder<TypeConfig, LogStore, StateMachineStore, TempDir> for RedbStoreBuilder {
        async fn build(
            &self,
        ) -> Result<(TempDir, LogStore, StateMachineStore), StorageError<NodeId>> {
            let dir = tempfile::tempdir().unwrap();
            let (log, sm) = open(&dir.path().join("raft.redb"))?;
            Ok((dir, log, sm))
        }
    }

    /// Run openraft's full storage conformance suite against the redb store.
    #[test]
    fn openraft_storage_conformance() -> Result<(), StorageError<NodeId>> {
        Suite::test_all(RedbStoreBuilder)
    }
}
