use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("not authenticated — run `y2q login <alias>`")]
    Unauthenticated,

    #[error("not found: {message}")]
    NotFound { message: String },

    #[error("conflict: {message}")]
    Conflict { message: String },

    #[error("bad request: {message}")]
    BadRequest { message: String },

    #[error("server error ({status}): {message}")]
    ServerError { status: u16, message: String },

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
}
