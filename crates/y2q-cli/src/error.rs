use thiserror::Error;
use y2q_client::ClientError;
use y2q_config::ConfigError;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    Client(#[from] ClientError),

    #[error("{0}")]
    Config(#[from] ConfigError),

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
            Self::Config(ConfigError::UnknownAlias(_)) => 9,
            Self::Config(_) => 8,
            Self::Io(_) => 7,
            Self::InvalidPath(_, _) | Self::RemoteToRemote => 5,
            Self::Other(_) => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(s: &str) -> String {
        s.to_owned()
    }

    #[test]
    fn exit_codes_per_variant() {
        let cases = [
            (CliError::Client(ClientError::Unauthenticated), 2),
            (
                CliError::Client(ClientError::NotFound { message: msg("x") }),
                3,
            ),
            (
                CliError::Client(ClientError::Conflict { message: msg("x") }),
                4,
            ),
            (
                CliError::Client(ClientError::BadRequest { message: msg("x") }),
                5,
            ),
            (
                CliError::Client(ClientError::ServerError {
                    status: 500,
                    message: msg("x"),
                }),
                6,
            ),
            (
                CliError::Client(ClientError::Io(std::io::Error::other("io"))),
                1,
            ),
            (CliError::Config(ConfigError::UnknownAlias(msg("a"))), 9),
            (CliError::Config(ConfigError::Config(msg("c"))), 8),
            (CliError::Io(std::io::Error::other("io")), 7),
            (CliError::InvalidPath(msg("p"), msg("why")), 5),
            (CliError::RemoteToRemote, 5),
            (CliError::Other(msg("o")), 1),
        ];
        for (err, code) in cases {
            assert_eq!(err.exit_code(), code, "{err:?}");
        }
    }
}
