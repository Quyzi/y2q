use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::display::DisplayMsg;
use crate::metrics::{OpHistograms, OpRecord, Segment};
use crate::ops::OpKind;

const SEGMENT_NS: u64 = 1_000_000_000;

pub struct Recorder {
    rx: mpsc::Receiver<OpRecord>,
    agg_tx: mpsc::Sender<DisplayMsg>,
    csv_writer: Option<csv::Writer<Box<dyn std::io::Write + Send>>>,
    histograms: HashMap<OpKind, OpHistograms>,
    segment_buckets: HashMap<(OpKind, u64), (u64, u64, u64)>,
    last_display: Instant,
    display_interval: Duration,
}

impl Recorder {
    pub fn new(
        rx: mpsc::Receiver<OpRecord>,
        agg_tx: mpsc::Sender<DisplayMsg>,
        output_path: &Path,
    ) -> Result<Self, crate::error::WarpError> {
        let file = std::fs::File::create(output_path)?;
        let encoder = zstd::Encoder::new(file, 3)?.auto_finish();
        let boxed: Box<dyn std::io::Write + Send> = Box::new(encoder);
        let csv_writer = csv::Writer::from_writer(boxed);

        Ok(Self {
            rx,
            agg_tx,
            csv_writer: Some(csv_writer),
            histograms: HashMap::new(),
            segment_buckets: HashMap::new(),
            last_display: Instant::now(),
            display_interval: Duration::from_millis(500),
        })
    }

    pub async fn run(mut self) {
        while let Some(rec) = self.rx.recv().await {
            self.ingest(&rec);
            if self.last_display.elapsed() >= self.display_interval {
                self.snapshot_and_send().await;
                self.last_display = Instant::now();
            }
        }
        // Channel closed — final snapshot
        self.snapshot_and_send().await;
        // Flush CSV
        if let Some(mut w) = self.csv_writer.take() {
            let _ = w.flush();
        }
    }

    fn ingest(&mut self, rec: &OpRecord) {
        let op = match rec.op.as_str() {
            "PUT" => OpKind::Put,
            "GET" => OpKind::Get,
            "DELETE" => OpKind::Delete,
            "STAT" => OpKind::Stat,
            "LIST" => OpKind::List,
            _ => return,
        };

        self.histograms.entry(op).or_insert_with(|| OpHistograms::new(op)).record(rec);

        // Segment accounting
        let window = rec.start_ns / SEGMENT_NS;
        let entry = self.segment_buckets.entry((op, window)).or_default();
        entry.0 += 1;
        if rec.error.is_some() {
            entry.1 += 1;
        }
        entry.2 += rec.bytes;

        // Write to CSV
        if let Some(ref mut w) = self.csv_writer {
            let _ = w.serialize(rec);
        }
    }

    async fn snapshot_and_send(&mut self) {
        let mut map = HashMap::new();
        for (op, hist) in &self.histograms {
            if let Some(agg) = hist.aggregate() {
                map.insert(*op, agg);
            }
        }
        let _ = self.agg_tx.try_send(DisplayMsg::Running(map));
    }

    #[allow(dead_code)]
    pub fn into_segments(self) -> Vec<Segment> {
        let mut segs = Vec::new();
        for ((op, window_start), (n_ops, n_errors, bytes)) in self.segment_buckets {
            let duration_s = 1.0_f64;
            let ok_ops = n_ops - n_errors;
            segs.push(Segment {
                op: op.as_str().to_owned(),
                window_start_ns: window_start * SEGMENT_NS,
                n_ops,
                n_errors,
                bytes,
                throughput_mibps: (bytes as f64 / (1024.0 * 1024.0)) / duration_s,
                ops_per_sec: ok_ops as f64 / duration_s,
            });
        }
        segs.sort_by_key(|s| s.window_start_ns);
        segs
    }
}
