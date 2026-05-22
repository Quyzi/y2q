use thiserror::Error;
use y2q_config::ConfigError;

#[derive(Debug, Error)]
pub enum WarpError {
    #[error("{0}")]
    Config(#[from] ConfigError),

    #[error("client error: {0}")]
    Client(#[from] y2q_client::ClientError),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("csv error: {0}")]
    Csv(#[from] csv::Error),

    #[error("{0}")]
    Other(String),
}

impl WarpError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Config(ConfigError::UnknownAlias(_)) => 9,
            Self::Config(_) => 8,
            Self::Client(_) => 2,
            Self::Http(_) | Self::Io(_) => 1,
            Self::Csv(_) => 3,
            Self::Other(_) => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes() {
        assert_eq!(
            WarpError::Config(ConfigError::UnknownAlias("a".into())).exit_code(),
            9
        );
        assert_eq!(
            WarpError::Config(ConfigError::Config("c".into())).exit_code(),
            8
        );
        assert_eq!(
            WarpError::Client(y2q_client::ClientError::Unauthenticated).exit_code(),
            2
        );
        assert_eq!(WarpError::Io(std::io::Error::other("io")).exit_code(), 1);
        assert_eq!(WarpError::Other("x".into()).exit_code(), 1);
    }
}
