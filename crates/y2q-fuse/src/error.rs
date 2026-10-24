use thiserror::Error;

#[derive(Debug, Error)]
pub enum FuseError {
    #[error("client error: {0}")]
    Client(#[from] y2q_client::ClientError),

    #[error("config error: {0}")]
    Config(#[from] y2q_config::ConfigError),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not logged in to alias `{0}` — run `y2q login {0}` first")]
    NotLoggedIn(String),

    #[error("{0}")]
    Other(String),
}

pub fn to_errno(e: &y2q_client::ClientError) -> fuser::Errno {
    use y2q_client::ClientError;
    match e {
        ClientError::NotFound { .. } => fuser::Errno::ENOENT,
        ClientError::Unauthenticated => fuser::Errno::EACCES,
        ClientError::Conflict { .. } => fuser::Errno::EEXIST,
        ClientError::BadRequest { .. } => fuser::Errno::EINVAL,
        // Permission denied (e.g. ACL grant lacks the verb) — not a disk fault.
        ClientError::ServerError { status: 403, .. } => fuser::Errno::EACCES,
        ClientError::ServerError { .. }
        | ClientError::Redirect { .. }
        | ClientError::Io(_)
        | ClientError::Http(_) => fuser::Errno::EIO,
    }
}

#[cfg(test)]
mod tests {
    use super::to_errno;
    use y2q_client::ClientError;

    #[test]
    fn to_errno_maps_403_to_eacces() {
        let e = ClientError::ServerError {
            status: 403,
            message: "forbidden".into(),
        };
        assert_eq!(to_errno(&e), fuser::Errno::EACCES);
    }

    #[test]
    fn to_errno_maps_500_to_eio() {
        let e = ClientError::ServerError {
            status: 500,
            message: "boom".into(),
        };
        assert_eq!(to_errno(&e), fuser::Errno::EIO);
    }

    #[test]
    fn to_errno_maps_404_to_enoent() {
        let e = ClientError::NotFound {
            message: "gone".into(),
        };
        assert_eq!(to_errno(&e), fuser::Errno::ENOENT);
    }

    #[test]
    fn to_errno_maps_401_to_eacces() {
        assert_eq!(
            to_errno(&ClientError::Unauthenticated),
            fuser::Errno::EACCES
        );
    }
}
