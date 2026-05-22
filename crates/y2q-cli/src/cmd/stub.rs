//! Shared handler for daemon-gated commands that are part of the mc-style CLI
//! surface but not yet backed by a daemon capability. Returns a structured
//! [`CliError::NotYetSupported`] (exit code 64) so scripts can detect it.

use crate::error::CliError;
use crate::output::{OutputMode, print_json};

pub fn not_yet_supported(
    command: &str,
    daemon_gate: &str,
    mode: OutputMode,
) -> Result<(), CliError> {
    if mode == OutputMode::Json {
        print_json(&serde_json::json!({
            "error": "not_yet_supported",
            "command": command,
            "gate": daemon_gate,
        }));
    }
    Err(CliError::NotYetSupported {
        command: command.to_owned(),
        daemon_gate: daemon_gate.to_owned(),
    })
}
