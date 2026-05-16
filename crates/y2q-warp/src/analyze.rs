use std::collections::HashMap;
use std::path::Path;

use crate::error::WarpError;
use crate::metrics::{Aggregate, OpHistograms, OpRecord, Segment, ns_to_ms_str};
use crate::ops::OpKind;

const SEGMENT_NS: u64 = 1_000_000_000;

pub fn run_analyze(
    files: &[&Path],
    filter_op: Option<&str>,
    skip_ns: u64,
    out: Option<&Path>,
) -> Result<(), WarpError> {
    let mut records: Vec<OpRecord> = Vec::new();

    for path in files {
        let file = std::fs::File::open(path)?;
        let decoder = zstd::Decoder::new(file)?;
        let mut rdr = csv::Reader::from_reader(decoder);
        for result in rdr.deserialize::<OpRecord>() {
            match result {
                Ok(rec) => records.push(rec),
                Err(e) => eprintln!("warning: skipping malformed row: {e}"),
            }
        }
    }

    if records.is_empty() {
        eprintln!("no records found");
        return Ok(());
    }

    let min_start = records.iter().map(|r| r.start_ns).min().unwrap_or(0);
    let skip_until = min_start + skip_ns;
    records.retain(|r| r.start_ns >= skip_until);

    if let Some(op_filter) = filter_op {
        let upper = op_filter.to_ascii_uppercase();
        records.retain(|r| r.op == upper);
    }

    // Aggregate per op kind
    let mut histograms: HashMap<OpKind, OpHistograms> = HashMap::new();
    let mut segment_buckets: HashMap<(OpKind, u64), (u64, u64, u64)> = HashMap::new();

    for rec in &records {
        let op = match rec.op.as_str() {
            "PUT" => OpKind::Put,
            "GET" => OpKind::Get,
            "DELETE" => OpKind::Delete,
            "STAT" => OpKind::Stat,
            "LIST" => OpKind::List,
            _ => continue,
        };
        histograms.entry(op).or_insert_with(|| OpHistograms::new(op)).record(rec);
        let window = rec.start_ns / SEGMENT_NS;
        let entry = segment_buckets.entry((op, window)).or_default();
        entry.0 += 1;
        if rec.error.is_some() {
            entry.1 += 1;
        }
        entry.2 += rec.bytes;
    }

    let mut aggregates: Vec<Aggregate> = histograms.values()
        .filter_map(|h| h.aggregate())
        .collect();
    aggregates.sort_by_key(|a| a.op.as_str());

    let duration_s = if aggregates.is_empty() {
        0.0
    } else {
        aggregates.iter().map(|a| a.duration_s).fold(0.0_f64, f64::max)
    };

    println!("=== y2q-warp analysis ===");
    if skip_ns > 0 {
        println!("Warmup skipped: {:.1}s", skip_ns as f64 / 1e9);
    }
    println!("Duration: {:.1}s", duration_s);
    println!();

    println!(
        "{:<8} {:>10} {:>8} {:>14} {:>10} {:>8} {:>8} {:>8}",
        "Op", "Ops", "Errors", "Throughput", "Ops/s", "P50", "P90", "P99"
    );
    println!("{}", "─".repeat(80));

    for agg in &aggregates {
        println!(
            "{:<8} {:>10} {:>8} {:>12.1} MiB/s {:>10.0} {:>8} {:>8} {:>8}",
            agg.op.as_str(),
            agg.n_ops,
            agg.n_errors,
            agg.throughput_mibps,
            agg.ops_per_sec,
            ns_to_ms_str(agg.p50_ns),
            ns_to_ms_str(agg.p90_ns),
            ns_to_ms_str(agg.p99_ns),
        );
        if let (Some(p50), Some(p90), Some(p99)) = (agg.ttfb_p50_ns, agg.ttfb_p90_ns, agg.ttfb_p99_ns) {
            println!(
                "  TTFB:                                          P50={}  P90={}  P99={}",
                ns_to_ms_str(p50),
                ns_to_ms_str(p90),
                ns_to_ms_str(p99),
            );
        }
    }

    // Segment analysis
    let mut segs: Vec<Segment> = segment_buckets
        .into_iter()
        .map(|((op, window), (n_ops, n_errors, bytes))| {
            let ok = n_ops - n_errors;
            Segment {
                op: op.as_str().to_owned(),
                window_start_ns: window * SEGMENT_NS,
                n_ops,
                n_errors,
                bytes,
                throughput_mibps: bytes as f64 / (1024.0 * 1024.0),
                ops_per_sec: ok as f64,
            }
        })
        .collect();
    segs.sort_by(|a, b| a.throughput_mibps.partial_cmp(&b.throughput_mibps).unwrap());

    if !segs.is_empty() {
        println!();
        println!("Time-series segments (1s windows):");
        let fastest = segs.last().unwrap();
        let slowest = segs.first().unwrap();
        let median = &segs[segs.len() / 2];
        println!("  Fastest:  {:.1} MiB/s ({} ops)", fastest.throughput_mibps, fastest.n_ops);
        println!("  Median:   {:.1} MiB/s ({} ops)", median.throughput_mibps, median.n_ops);
        println!("  Slowest:  {:.1} MiB/s ({} ops)", slowest.throughput_mibps, slowest.n_ops);
    }

    // Write segment CSV if requested
    if let Some(out_path) = out {
        let mut w = csv::Writer::from_path(out_path)?;
        for seg in &segs {
            w.serialize(seg)?;
        }
        w.flush()?;
        println!();
        println!("Segment data written to {}", out_path.display());
    }

    Ok(())
}
