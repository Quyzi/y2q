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
    DeleteRemote { alias: String, bucket: String, key: String },
    DeleteUser { alias: String, username: String },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AdminTab {
    #[default]
    Rebuild,
    Locks,
    Users,
}

impl AdminTab {
    pub fn next(&self) -> Self {
        match self {
            Self::Rebuild => Self::Locks,
            Self::Locks => Self::Users,
            Self::Users => Self::Rebuild,
        }
    }
    pub fn prev(&self) -> Self {
        match self {
            Self::Rebuild => Self::Users,
            Self::Locks => Self::Rebuild,
            Self::Users => Self::Locks,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputAction {
    CreateBucket { alias: String },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Browse,
    Confirm(ConfirmAction),
    Admin(AdminTab),
    Error(String),
    Input { prompt: String, value: String, action: InputAction },
}
