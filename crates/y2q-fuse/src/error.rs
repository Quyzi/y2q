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
        ClientError::ServerError { .. } | ClientError::Io(_) | ClientError::Http(_) => {
            fuser::Errno::EIO
        }
    }
}
