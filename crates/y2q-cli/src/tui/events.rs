use crossterm::event::{KeyEvent, MouseEvent};
use y2q_client::{MetadataView, ObjectHead, StaleLockEntry, UserView};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Event {
    Tick,
    Render,
    Key(KeyEvent),
    Mouse(MouseEvent),
    Resize(u16, u16),
    FocusGained,
    FocusLost,
    /// Result of an async remote directory fetch.
    RemoteFetched {
        alias: String,
        path: RemoteFetchPath,
        result: RemoteFetchResult,
    },
    /// Progress update for an in-flight transfer.
    TransferUpdate {
        id: u64,
        bytes_done: u64,
        speed_bps: u64,
    },
    /// Transfer completed (ok = bytes, err = message).
    TransferDone {
        id: u64,
        result: Result<u64, String>,
    },
    /// Async admin data arrived.
    RebuildStatus {
        alias: String,
        state: String,
        percent: Option<u8>,
        reason: Option<String>,
    },
    UsersLoaded {
        alias: String,
        users: Vec<UserView>,
    },
    LocksLoaded {
        alias: String,
        locks: Vec<StaleLockEntry>,
    },
    /// HEAD result for the object-stat popup.
    ObjectStatFetched {
        path: String,
        result: Result<ObjectHead, String>,
    },
    Quit,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum RemoteFetchPath {
    Buckets,
    Objects {
        bucket: String,
        prefix: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub enum RemoteFetchResult {
    Buckets(Vec<String>),
    Objects(Vec<MetadataView>, Option<String>),
    Error(String),
}
