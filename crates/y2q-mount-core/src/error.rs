use thiserror::Error;

#[derive(Debug, Error)]
pub enum MountCoreError {
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
