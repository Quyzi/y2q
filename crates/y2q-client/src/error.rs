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

    /// The server answered with a 3xx. Redirects are never followed: doing so
    /// would replay the login body (307/308) or keep the bearer token on a
    /// target the operator never vetted.
    #[error(
        "server redirected the request ({status}){}; y2q does not follow redirects \
         (credentials would be re-sent) - fix the configured server URL (alias or --nodes) \
         to point at the final URL",
        .location.as_deref().map(|l| format!(" to {l}")).unwrap_or_default()
    )]
    Redirect {
        status: u16,
        location: Option<String>,
    },

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
}
