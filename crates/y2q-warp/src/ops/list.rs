use std::time::{SystemTime, UNIX_EPOCH};

use y2q_client::{ListOptions, Y2qClient};

use crate::metrics::OpRecord;

fn wall_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

pub async fn list_op(client: &Y2qClient, bucket: &str, run_id: &str) -> OpRecord {
    let start_ns = wall_ns();
    let opts = ListOptions {
        prefix: None,
        after: None,
        limit: Some(1000),
    };
    let result = client.list_objects(bucket, &opts).await;
    let end_ns = wall_ns();

    let bytes = result
        .as_ref()
        .map(|page| page.items.iter().map(|m| m.key.len() as u64).sum::<u64>())
        .unwrap_or(0);

    OpRecord {
        run_id: run_id.to_owned(),
        op: "LIST".to_owned(),
        start_ns,
        end_ns,
        first_byte_ns: None,
        bytes,
        key: format!("{bucket}/"),
        error: result.err().map(|e| e.to_string()),
    }
}
