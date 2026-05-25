use crossterm::event::{KeyEvent, MouseEvent};
use y2q_client::{MetadataView, ObjectHead, StaleLockEntry, TraceEvent, UserView};

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
    /// Prometheus scrape body (or error) for the Metrics tab.
    MetricsLoaded {
        alias: String,
        result: Result<String, String>,
    },
    /// A live trace event arrived for the Events tab.
    TraceEventArrived {
        alias: String,
        event: TraceEvent,
    },
    /// The trace stream ended (network drop or error).
    TraceStreamEnded {
        alias: String,
        error: Option<String>,
    },
    /// A background action failed; surface the message as an error popup.
    ActionFailed {
        message: String,
    },
    /// An object's labels were fetched or updated; opens/refreshes the editor.
    LabelsLoaded {
        alias: String,
        bucket: String,
        key: String,
        labels: std::collections::BTreeMap<String, String>,
    },
    /// A bucket's configuration was fetched; opens the config editor.
    BucketConfigLoaded {
        alias: String,
        bucket: String,
        quota_bytes: Option<u64>,
        default_sse: Option<String>,
    },
    /// A read-only result list (search / find) is ready to display.
    ResultsLoaded {
        title: String,
        lines: Vec<String>,
    },
    /// A mirror plan was computed and awaits confirmation.
    MirrorPlanned {
        alias: String,
        bucket: String,
        local_root: std::path::PathBuf,
        keys: Vec<String>,
        deletions: usize,
        skipped: u64,
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
