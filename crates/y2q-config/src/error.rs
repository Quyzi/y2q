use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("unknown alias `{0}` — add it with `y2q config add`")]
    UnknownAlias(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}
