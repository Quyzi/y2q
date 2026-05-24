//! Server liveness probing shared by the CLI (`ping`/`ready`) and the TUI.

use std::time::{Duration, Instant};

use y2q_client::{ClientError, Y2qClient};

/// A single liveness probe: issues a lightweight authenticated request and
/// returns its round-trip latency on success.
pub async fn probe(client: &Y2qClient) -> Result<Duration, ClientError> {
    let started = Instant::now();
    client.list_buckets().await?;
    Ok(started.elapsed())
}
