use crate::error::CliError;

/// A parsed remote path of the form `alias[/bucket[/key]]`.
#[derive(Debug, Clone)]
pub struct RemotePath {
    pub alias: String,
    pub bucket: Option<String>,
    pub key: Option<String>,
}

impl RemotePath {
    /// Parse `alias`, `alias/bucket`, `alias/bucket/`, or `alias/bucket/key`.
    pub fn parse(s: &str) -> Result<Self, CliError> {
        if !s.contains('/') {
            return Err(CliError::InvalidPath(
                s.to_owned(),
                "remote paths must be alias/bucket/key".to_owned(),
            ));
        }
        let mut parts = s.splitn(3, '/');
        let alias = parts.next().unwrap_or("").to_owned();
        if alias.is_empty() {
            return Err(CliError::InvalidPath(
                s.to_owned(),
                "alias must not be empty".to_owned(),
            ));
        }
        let bucket = parts.next().filter(|s| !s.is_empty()).map(|s| s.to_owned());
        let key = parts.next().filter(|s| !s.is_empty()).map(|s| s.to_owned());
        Ok(Self { alias, bucket, key })
    }
}

/// A source or destination for `cp`: either a local path string or a remote path.
#[derive(Debug, Clone)]
pub enum CpEndpoint {
    Local(String),
    Remote(RemotePath),
}

impl CpEndpoint {
    pub fn parse(s: &str) -> Self {
        // Glob chars or stdin → always local
        if s == "-" || !s.contains('/') || s.contains(['*', '?', '[']) {
            return Self::Local(s.to_owned());
        }
        match RemotePath::parse(s) {
            Ok(r) => Self::Remote(r),
            Err(_) => Self::Local(s.to_owned()),
        }
    }

    pub fn is_remote(&self) -> bool {
        matches!(self, Self::Remote(_))
    }
}
