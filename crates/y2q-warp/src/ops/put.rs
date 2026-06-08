use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use y2q_client::Y2qClient;

use crate::generator::BoundedRepeatReader;
use crate::metrics::OpRecord;

fn wall_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

pub async fn put_op(
    client: &Y2qClient,
    bucket: &str,
    key: &str,
    size: u64,
    run_id: &str,
) -> OpRecord {
    let start_ns = wall_ns();
    let reader = BoundedRepeatReader::new(size);
    let result = client
        .put_from_reader(bucket, key, reader, Some(size), &BTreeSet::new(), None)
        .await;
    let end_ns = wall_ns();

    OpRecord {
        run_id: run_id.to_owned(),
        op: "PUT".to_owned(),
        start_ns,
        end_ns,
        first_byte_ns: None,
        bytes: if result.is_ok() { size } else { 0 },
        key: format!("{bucket}/{key}"),
        error: result.err().map(|e| e.to_string()),
        node: String::new(),
    }
}
