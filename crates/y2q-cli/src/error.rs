use thiserror::Error;
use y2q_client::ClientError;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    Client(#[from] ClientError),

    #[error("unknown alias `{0}` — add it with `y2q config add`")]
    UnknownAlias(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid path `{0}`: {1}")]
    InvalidPath(String, String),

    #[error("remote-to-remote copy is not supported")]
    RemoteToRemote,

    #[error("{0}")]
    Other(String),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Client(ClientError::Unauthenticated) => 2,
            Self::Client(ClientError::NotFound { .. }) => 3,
            Self::Client(ClientError::Conflict { .. }) => 4,
            Self::Client(ClientError::BadRequest { .. }) => 5,
            Self::Client(ClientError::ServerError { .. }) => 6,
            Self::Client(ClientError::Io(_) | ClientError::Http(_)) => 1,
            Self::UnknownAlias(_) => 9,
            Self::Config(_) => 8,
            Self::Io(_) => 7,
            Self::InvalidPath(_, _) | Self::RemoteToRemote => 5,
            Self::Other(_) => 1,
        }
    }
}
