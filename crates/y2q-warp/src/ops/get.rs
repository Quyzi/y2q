use std::time::{SystemTime, UNIX_EPOCH};

use futures::StreamExt;

use crate::metrics::OpRecord;

fn wall_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// GET with TTFB measurement. Bypasses Y2qClient::get_to_writer to intercept
/// the first chunk of the response body stream.
pub async fn get_op(
    client: &reqwest::Client,
    base_url: &str,
    token: &str,
    bucket: &str,
    key: &str,
    run_id: &str,
) -> OpRecord {
    let start_ns = wall_ns();
    let url = format!("{}/{bucket}/{key}", base_url.trim_end_matches('/'));

    let result = client.get(&url).bearer_auth(token).send().await;

    let resp = match result {
        Err(e) => {
            return OpRecord {
                run_id: run_id.to_owned(),
                op: "GET".to_owned(),
                start_ns,
                end_ns: wall_ns(),
                first_byte_ns: None,
                bytes: 0,
                key: format!("{bucket}/{key}"),
                error: Some(e.to_string()),
            };
        }
        Ok(r) => r,
    };

    if !resp.status().is_success() {
        let status = resp.status();
        // Drain the body so reqwest can reuse the connection; don't record bytes on error.
        let _ = resp.bytes().await;
        return OpRecord {
            run_id: run_id.to_owned(),
            op: "GET".to_owned(),
            start_ns,
            end_ns: wall_ns(),
            first_byte_ns: None,
            bytes: 0,
            key: format!("{bucket}/{key}"),
            error: Some(format!("HTTP {status}")),
        };
    }

    let mut stream = resp.bytes_stream();
    let mut total_bytes = 0u64;
    let mut first_byte_ns = None;
    let mut error = None;

    while let Some(chunk_result) = stream.next().await {
        match chunk_result {
            Ok(chunk) => {
                if first_byte_ns.is_none() {
                    first_byte_ns = Some(wall_ns());
                }
                total_bytes += chunk.len() as u64;
            }
            Err(e) => {
                error = Some(e.to_string());
                break;
            }
        }
    }

    OpRecord {
        run_id: run_id.to_owned(),
        op: "GET".to_owned(),
        start_ns,
        end_ns: wall_ns(),
        first_byte_ns,
        bytes: total_bytes,
        key: format!("{bucket}/{key}"),
        error,
    }
}
