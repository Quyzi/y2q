use std::time::{SystemTime, UNIX_EPOCH};

use y2q_client::Y2qClient;

use crate::metrics::OpRecord;

fn wall_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

pub async fn stat_op(client: &Y2qClient, bucket: &str, key: &str, run_id: &str) -> OpRecord {
    let start_ns = wall_ns();
    let result = client.head(bucket, key).await;
    let end_ns = wall_ns();

    let bytes = result.as_ref().map(|h| h.size).unwrap_or(0);

    OpRecord {
        run_id: run_id.to_owned(),
        op: "STAT".to_owned(),
        start_ns,
        end_ns,
        first_byte_ns: None,
        bytes,
        key: format!("{bucket}/{key}"),
        error: result.err().map(|e| e.to_string()),
    }
}
