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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_path_variants() {
        let r = RemotePath::parse("a/b/c").unwrap();
        assert_eq!(r.alias, "a");
        assert_eq!(r.bucket.as_deref(), Some("b"));
        assert_eq!(r.key.as_deref(), Some("c"));

        let r = RemotePath::parse("a/b/").unwrap();
        assert_eq!(r.bucket.as_deref(), Some("b"));
        assert_eq!(r.key, None);

        let r = RemotePath::parse("a/b").unwrap();
        assert_eq!(r.bucket.as_deref(), Some("b"));
        assert_eq!(r.key, None);

        // key may itself contain slashes (splitn(3))
        let r = RemotePath::parse("a/b/c/d").unwrap();
        assert_eq!(r.key.as_deref(), Some("c/d"));
    }

    #[test]
    fn remote_path_rejects_bad_input() {
        assert!(RemotePath::parse("noslash").is_err());
        assert!(RemotePath::parse("/bucket/key").is_err());
    }

    #[test]
    fn cp_endpoint_classification() {
        assert!(matches!(CpEndpoint::parse("-"), CpEndpoint::Local(_)));
        assert!(matches!(
            CpEndpoint::parse("local.txt"),
            CpEndpoint::Local(_)
        ));
        assert!(matches!(CpEndpoint::parse("a/*.txt"), CpEndpoint::Local(_)));
        assert!(matches!(CpEndpoint::parse("a/b/c"), CpEndpoint::Remote(_)));
        assert!(CpEndpoint::parse("a/b/c").is_remote());
        assert!(!CpEndpoint::parse("local.txt").is_remote());
    }
}
