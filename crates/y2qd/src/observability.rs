//! Per-request Prometheus instrumentation.
//!
//! Emits four metrics with labels `method`, `path`, and (when the matched
//! route captures one) `bucket`. The literal object `key` is intentionally
//! excluded — both via the `path` label (which is the *route pattern* such as
//! `/{bucket}/{tail}*`, not the literal request path) and by reading only the
//! `bucket` capture, never the `tail` capture.
//!
//! | Metric                              | Type      | Extra labels |
//! |-------------------------------------|-----------|--------------|
//! | `y2qd_requests_received_total`      | counter   | —            |
//! | `y2qd_responses_sent_total`         | counter   | `status`     |
//! | `y2qd_request_payload_bytes`        | histogram | —            |
//! | `y2qd_response_payload_bytes`       | histogram | `status`     |
//! | `y2qd_request_duration_milliseconds`| histogram | `status`     |
//!
//! Payload histograms are recorded only when the corresponding `Content-Length`
//! header is present and parses as an unsigned integer. Request duration is
//! measured from middleware entry to inner-service completion.

use std::time::Instant;

use actix_web::{
    Error,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    http::header,
    middleware::Next,
};
use metrics::{Unit, counter, describe_counter, describe_histogram, histogram};

const METRIC_REQUESTS_RECEIVED: &str = "y2qd_requests_received_total";
const METRIC_RESPONSES_SENT: &str = "y2qd_responses_sent_total";
const METRIC_REQUEST_PAYLOAD: &str = "y2qd_request_payload_bytes";
const METRIC_RESPONSE_PAYLOAD: &str = "y2qd_response_payload_bytes";
/// Public so the Prometheus recorder can target it via `Matcher::Full`.
pub const DURATION_METRIC_NAME: &str = "y2qd_request_duration_milliseconds";

/// Public metric names for storage operations — used in `y2q-core` and
/// here for Prometheus descriptor registration.
pub const STORAGE_OPS_TOTAL: &str = "y2qd_storage_ops_total";
pub const STORAGE_OP_DURATION: &str = "y2qd_storage_op_duration_milliseconds";
pub const AUTH_LOGINS_TOTAL: &str = "y2qd_auth_logins_total";
pub const SESSIONS_ACTIVE: &str = "y2qd_sessions_active";
/// Count of internal cluster requests rejected because their epoch predated the
/// receiver's committed epoch (stale-topology fence).
pub const CLUSTER_STALE_EPOCH_REJECTIONS: &str = "y2qd_cluster_stale_epoch_rejections_total";

// --- Cluster (distributed storage) metrics ---
//
// Emitted only when `[cluster] enabled = true`. Names are matched for histogram
// bucketing in `main.rs`; the gauges are refreshed each maintenance tick.

/// Per-hop CRAQ PREPARE service latency at a chain member (histogram, ms),
/// labelled `result` = ok | err.
pub const CLUSTER_PREPARE_HOP_DURATION: &str = "y2qd_cluster_prepare_hop_duration_milliseconds";
/// Full-chain commit latency measured at the contact/HEAD node (histogram, ms),
/// labelled `result` = ok | err.
pub const CLUSTER_COMMIT_DURATION: &str = "y2qd_cluster_commit_duration_milliseconds";
/// CRAQ version queries served by a chain TAIL (counter).
pub const CLUSTER_VERSION_QUERIES: &str = "y2qd_cluster_version_queries_total";
/// Apportioned reads, labelled `kind` = local | remote (counter).
pub const CLUSTER_READS: &str = "y2qd_cluster_reads_total";
/// Backfill objects fetched by a recovering node (counter).
pub const CLUSTER_BACKFILL_OBJECTS: &str = "y2qd_cluster_backfill_objects_total";
/// Backfill envelope bytes served to recovering peers (counter).
pub const CLUSTER_BACKFILL_BYTES_SERVED: &str = "y2qd_cluster_backfill_bytes_served_total";
/// Raft term observed by this node (gauge).
pub const CLUSTER_RAFT_TERM: &str = "y2qd_cluster_raft_term";
/// 1 if this node currently believes it is the raft leader, else 0 (gauge).
pub const CLUSTER_IS_LEADER: &str = "y2qd_cluster_is_leader";
/// Highest raft log index applied to this node's state machine (gauge).
pub const CLUSTER_RAFT_LAST_APPLIED: &str = "y2qd_cluster_raft_last_applied";
/// Committed cluster topology epoch (gauge).
pub const CLUSTER_EPOCH: &str = "y2qd_cluster_epoch";
/// Number of nodes the committed control state lists as Active (gauge).
pub const CLUSTER_ACTIVE_NODES: &str = "y2qd_cluster_active_nodes";

/// Bucket boundaries for both payload-size histograms, in bytes.
/// Spans small JSON bodies (~256 B) through the default 256 MiB upload cap.
pub const PAYLOAD_BUCKETS_BYTES: &[f64] = &[
    256.0,
    1_024.0,
    4_096.0,
    16_384.0,
    65_536.0,
    262_144.0,
    1_048_576.0,
    4_194_304.0,
    16_777_216.0,
    67_108_864.0,
    268_435_456.0,
];

/// Bucket boundaries for the request-duration histogram, in milliseconds.
/// Spans sub-millisecond cached responses through multi-second large-object writes.
pub const DURATION_BUCKETS_MILLIS: &[f64] = &[
    0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1_000.0, 2_500.0, 5_000.0, 10_000.0,
];

/// Bucket boundaries for storage-operation duration histograms, in milliseconds.
/// Spans fast metadata lookups (~0.1 ms) through large-object I/O (~5 s).
pub const STORAGE_DURATION_BUCKETS_MILLIS: &[f64] = &[
    0.1, 0.5, 1.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1_000.0, 5_000.0,
];

/// Matcher suffix used to apply [`STORAGE_DURATION_BUCKETS_MILLIS`] to the
/// storage operation duration histogram via [`DashboardInput`].
pub const STORAGE_DURATION_METRIC_SUFFIX: &str = "storage_op_duration_milliseconds";

/// Register HELP text for every metric emitted by [`metrics_middleware`].
///
/// Call once after the Prometheus recorder is installed and before serving
/// traffic, so `/metrics` includes `# HELP` and `# TYPE` lines.
pub fn describe_metrics() {
    describe_counter!(
        METRIC_REQUESTS_RECEIVED,
        "HTTP requests received by the daemon, labelled by method, route pattern, and bucket (when matched)"
    );
    describe_counter!(
        METRIC_RESPONSES_SENT,
        "HTTP responses sent by the daemon, labelled by method, route pattern, bucket (when matched), and status code"
    );
    describe_histogram!(
        METRIC_REQUEST_PAYLOAD,
        Unit::Bytes,
        "Distribution of request body sizes (from Content-Length)"
    );
    describe_histogram!(
        METRIC_RESPONSE_PAYLOAD,
        Unit::Bytes,
        "Distribution of response body sizes (from Content-Length)"
    );
    describe_histogram!(
        DURATION_METRIC_NAME,
        Unit::Milliseconds,
        "Wall-clock time spent serving a request, in milliseconds"
    );
    describe_counter!(
        STORAGE_OPS_TOTAL,
        "Storage operations completed, labelled by op, backend, and result (ok/err)"
    );
    describe_histogram!(
        STORAGE_OP_DURATION,
        Unit::Milliseconds,
        "Wall-clock time spent in storage operations, in milliseconds"
    );
    describe_counter!(
        AUTH_LOGINS_TOTAL,
        "Login attempts, labelled by result (success/wrong_password/not_found/locked)"
    );
    metrics::describe_gauge!(
        SESSIONS_ACTIVE,
        "Number of active (non-expired) sessions currently held in memory"
    );
    describe_counter!(
        CLUSTER_STALE_EPOCH_REJECTIONS,
        "Internal cluster requests rejected because their epoch predated the receiver's committed epoch"
    );
    describe_histogram!(
        CLUSTER_PREPARE_HOP_DURATION,
        Unit::Milliseconds,
        "Per-hop CRAQ PREPARE service latency at a chain member, labelled by result"
    );
    describe_histogram!(
        CLUSTER_COMMIT_DURATION,
        Unit::Milliseconds,
        "Full-chain CRAQ commit latency measured at the contact/HEAD node, labelled by result"
    );
    describe_counter!(
        CLUSTER_VERSION_QUERIES,
        "CRAQ version queries served by a chain TAIL"
    );
    describe_counter!(
        CLUSTER_READS,
        "Apportioned reads served, labelled local vs remote (proxied to the TAIL)"
    );
    describe_counter!(
        CLUSTER_BACKFILL_OBJECTS,
        "Objects fetched by a recovering node during back-fill"
    );
    describe_counter!(
        CLUSTER_BACKFILL_BYTES_SERVED,
        "Envelope bytes served to recovering peers during back-fill"
    );
    metrics::describe_gauge!(CLUSTER_RAFT_TERM, "Current raft term observed by this node");
    metrics::describe_gauge!(
        CLUSTER_IS_LEADER,
        "1 if this node currently believes it is the raft leader, else 0"
    );
    metrics::describe_gauge!(
        CLUSTER_RAFT_LAST_APPLIED,
        "Highest raft log index applied to this node's state machine"
    );
    metrics::describe_gauge!(CLUSTER_EPOCH, "Committed cluster topology epoch");
    metrics::describe_gauge!(
        CLUSTER_ACTIVE_NODES,
        "Number of nodes the committed control state lists as Active"
    );
}

/// Matcher suffix used to apply [`PAYLOAD_BUCKETS_BYTES`] to both payload
/// histograms via [`DashboardInput`].
pub const PAYLOAD_METRIC_SUFFIX: &str = "_payload_bytes";

/// Actix-web middleware that records request and response counters plus
/// payload-size histograms. Designed for use with
/// [`actix_web::middleware::from_fn`].
pub async fn metrics_middleware<B: MessageBody>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error> {
    // Read the request body size before handing the request off; the headers
    // map is moved into the inner service when `next.call` consumes `req`.
    let request_payload = content_length(req.headers());
    let started = Instant::now();

    let res = next.call(req).await?;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;

    let method = res.request().method().as_str().to_owned();
    // match_pattern is the *route* (e.g. "/{bucket}/{tail}*"), not the literal
    // path — so it has bounded cardinality. Unlike `path`, the `{bucket}`
    // path segment is attacker-controlled and unauthenticated (this
    // middleware runs before auth), so it is deliberately never used as a
    // label value — doing so would let anyone mint unbounded Prometheus
    // label combinations (a memory-exhaustion DoS) just by hitting distinct
    // bucket names.
    let path = res
        .request()
        .match_pattern()
        .unwrap_or_else(|| "<unmatched>".to_owned());
    let status = res.status().as_u16().to_string();

    let request_labels: Vec<(&'static str, String)> = vec![("method", method), ("path", path)];

    counter!(METRIC_REQUESTS_RECEIVED, &request_labels).increment(1);
    if let Some(bytes) = request_payload {
        histogram!(METRIC_REQUEST_PAYLOAD, &request_labels).record(bytes as f64);
    }

    let mut response_labels = request_labels;
    response_labels.push(("status", status));
    counter!(METRIC_RESPONSES_SENT, &response_labels).increment(1);
    histogram!(DURATION_METRIC_NAME, &response_labels).record(elapsed_ms);
    if let Some(bytes) = content_length(res.headers()) {
        histogram!(METRIC_RESPONSE_PAYLOAD, &response_labels).record(bytes as f64);
    }

    Ok(res)
}

fn content_length(headers: &header::HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse::<u64>()
        .ok()
}
