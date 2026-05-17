use hdrhistogram::Histogram;
use serde::{Deserialize, Serialize};

use crate::ops::OpKind;

/// One completed operation — one row in the output CSV.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpRecord {
    pub run_id: String,
    pub op: String,
    /// Wall-clock nanoseconds since Unix epoch.
    pub start_ns: u64,
    pub end_ns: u64,
    /// TTFB: wall-clock ns when the first response body bytes arrived (GET only).
    pub first_byte_ns: Option<u64>,
    /// Plaintext bytes transferred.
    pub bytes: u64,
    /// "{bucket}/{key}"
    pub key: String,
    pub error: Option<String>,
}

impl OpRecord {
    pub fn latency_ns(&self) -> u64 {
        self.end_ns.saturating_sub(self.start_ns)
    }

    pub fn ttfb_ns(&self) -> Option<u64> {
        self.first_byte_ns.map(|fb| fb.saturating_sub(self.start_ns))
    }

    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

/// Aggregated statistics for one op kind over a time window.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Aggregate {
    pub op: OpKind,
    pub n_ops: u64,
    pub n_errors: u64,
    pub total_bytes: u64,
    pub duration_s: f64,
    pub throughput_mibps: f64,
    pub ops_per_sec: f64,
    pub p50_ns: u64,
    pub p90_ns: u64,
    pub p99_ns: u64,
    pub p999_ns: u64,
    pub mean_ns: f64,
    pub ttfb_p50_ns: Option<u64>,
    pub ttfb_p90_ns: Option<u64>,
    pub ttfb_p99_ns: Option<u64>,
}

/// One 1-second segment bucket for time-series analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    pub op: String,
    pub window_start_ns: u64,
    pub n_ops: u64,
    pub n_errors: u64,
    pub bytes: u64,
    pub throughput_mibps: f64,
    pub ops_per_sec: f64,
}

/// Accumulates histograms for one op kind over the lifetime of a run.
pub struct OpHistograms {
    pub op: OpKind,
    pub latency: Histogram<u64>,
    pub ttfb: Histogram<u64>,
    pub total_bytes: u64,
    pub n_ops: u64,
    pub n_errors: u64,
    pub first_ns: u64,
    pub last_ns: u64,
}

impl OpHistograms {
    pub fn new(op: OpKind) -> Self {
        Self {
            op,
            latency: Histogram::new(3).expect("valid histogram"),
            ttfb: Histogram::new(3).expect("valid histogram"),
            total_bytes: 0,
            n_ops: 0,
            n_errors: 0,
            first_ns: u64::MAX,
            last_ns: 0,
        }
    }

    pub fn record(&mut self, rec: &OpRecord) {
        self.n_ops += 1;
        self.first_ns = self.first_ns.min(rec.start_ns);
        self.last_ns = self.last_ns.max(rec.end_ns);
        if rec.is_error() {
            self.n_errors += 1;
            return;
        }
        self.total_bytes += rec.bytes;
        let _ = self.latency.record(rec.latency_ns().max(1));
        if let Some(ttfb) = rec.ttfb_ns() {
            let _ = self.ttfb.record(ttfb.max(1));
        }
    }

    pub fn aggregate(&self) -> Option<Aggregate> {
        if self.n_ops == 0 || self.last_ns <= self.first_ns {
            return None;
        }
        let duration_s = (self.last_ns - self.first_ns) as f64 / 1e9;
        let throughput_mibps = (self.total_bytes as f64 / (1024.0 * 1024.0)) / duration_s;
        let ops_per_sec = (self.n_ops - self.n_errors) as f64 / duration_s;

        let ttfb_p50 = if self.ttfb.len() > 0 {
            Some(self.ttfb.value_at_quantile(0.50))
        } else {
            None
        };
        let ttfb_p90 = if self.ttfb.len() > 0 {
            Some(self.ttfb.value_at_quantile(0.90))
        } else {
            None
        };
        let ttfb_p99 = if self.ttfb.len() > 0 {
            Some(self.ttfb.value_at_quantile(0.99))
        } else {
            None
        };

        Some(Aggregate {
            op: self.op,
            n_ops: self.n_ops,
            n_errors: self.n_errors,
            total_bytes: self.total_bytes,
            duration_s,
            throughput_mibps,
            ops_per_sec,
            p50_ns: self.latency.value_at_quantile(0.50),
            p90_ns: self.latency.value_at_quantile(0.90),
            p99_ns: self.latency.value_at_quantile(0.99),
            p999_ns: self.latency.value_at_quantile(0.999),
            mean_ns: self.latency.mean(),
            ttfb_p50_ns: ttfb_p50,
            ttfb_p90_ns: ttfb_p90,
            ttfb_p99_ns: ttfb_p99,
        })
    }
}

pub fn ns_to_ms_str(ns: u64) -> String {
    format!("{:.1}ms", ns as f64 / 1_000_000.0)
}
