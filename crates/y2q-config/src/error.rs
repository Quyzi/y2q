use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("unknown alias `{0}` — add it with `y2q alias set`")]
    UnknownAlias(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for #200: the `config add` -> `alias set` rename left the
    /// unknown-alias error pointing at the old subcommand.
    #[test]
    fn unknown_alias_error_points_at_alias_set() {
        let msg = ConfigError::UnknownAlias("m".to_string()).to_string();
        assert!(
            msg.contains("y2q alias set"),
            "error should name the current subcommand: {msg}"
        );
        assert!(
            !msg.contains("y2q config add"),
            "error still references the renamed-away subcommand: {msg}"
        );
    }
}
