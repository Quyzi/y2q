#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum FocusedPane {
    #[default]
    Local,
    Remote,
}

impl FocusedPane {
    pub fn toggle(&self) -> Self {
        match self {
            Self::Local => Self::Remote,
            Self::Remote => Self::Local,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ConfirmAction {
    DeleteRemote {
        alias: String,
        bucket: String,
        key: String,
    },
    DeleteBucket {
        alias: String,
        bucket: String,
    },
    DeleteUser {
        alias: String,
        username: String,
    },
    ClearLocks {
        alias: String,
        older_than: String,
    },
    RemoveAlias {
        alias: String,
    },
    /// Apply a pending local->remote mirror (uploads only).
    ApplyMirror {
        uploads: usize,
        deletions: usize,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AdminTab {
    #[default]
    Rebuild,
    Locks,
    Users,
    Metrics,
    Events,
}

impl AdminTab {
    pub fn next(&self) -> Self {
        match self {
            Self::Rebuild => Self::Locks,
            Self::Locks => Self::Users,
            Self::Users => Self::Metrics,
            Self::Metrics => Self::Events,
            Self::Events => Self::Rebuild,
        }
    }
    pub fn prev(&self) -> Self {
        match self {
            Self::Rebuild => Self::Events,
            Self::Locks => Self::Rebuild,
            Self::Users => Self::Locks,
            Self::Metrics => Self::Users,
            Self::Events => Self::Metrics,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputAction {
    CreateBucket {
        alias: String,
    },
    RenameObject {
        alias: String,
        bucket: String,
        key: String,
    },
    RangeGet {
        alias: String,
        bucket: String,
        key: String,
    },
    SetLabel {
        alias: String,
        bucket: String,
        key: String,
    },
    SetQuota {
        alias: String,
        bucket: String,
    },
    SetSse {
        alias: String,
        bucket: String,
    },
    SearchQuery {
        alias: String,
        bucket: Option<String>,
        prefix: Option<String>,
    },
    FindName {
        alias: String,
        bucket: String,
        prefix: Option<String>,
    },
    AddUserUsername {
        alias: String,
    },
    AddUserPassword {
        alias: String,
        username: String,
    },
    LoginUsername {
        alias: String,
    },
    LoginPassword {
        alias: String,
        username: String,
    },
    PasswdCurrent {
        alias: String,
    },
    PasswdNew {
        alias: String,
        current: String,
    },
    SetEventFilter,
    ImportAliases,
    NewAliasName,
    NewAliasUrl {
        name: String,
    },
    NewAliasUser {
        name: String,
        url: String,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Browse,
    Confirm(ConfirmAction),
    Admin(AdminTab),
    Error(String),
    Input {
        prompt: String,
        value: String,
        action: InputAction,
    },
    /// Object stat popup — pre-formatted lines ready to render.
    ObjectStat {
        path: String,
        lines: Vec<String>,
    },
    /// Interactive label editor for a single object.
    Labels {
        alias: String,
        bucket: String,
        key: String,
        labels: Vec<(String, String)>,
        selected: usize,
    },
    /// Per-bucket configuration editor (quota + default SSE).
    BucketConfig {
        alias: String,
        bucket: String,
        quota_bytes: Option<u64>,
        default_sse: Option<String>,
        selected: usize,
    },
    /// Read-only result list (search / find), scrollable.
    Results {
        title: String,
        lines: Vec<String>,
        selected: usize,
    },
    /// Full keybinding reference, scrollable.
    Help {
        lines: Vec<String>,
        selected: usize,
    },
}
