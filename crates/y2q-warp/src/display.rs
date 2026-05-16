use std::collections::HashMap;
use std::io::{IsTerminal, Write, stderr};
use std::time::Duration;

use crossterm::cursor::MoveUp;
use crossterm::execute;
use crossterm::terminal::{Clear, ClearType};
use tokio::sync::mpsc;

use crate::metrics::{Aggregate, ns_to_ms_str};
use crate::ops::OpKind;

const DISPLAY_LINES: u16 = 3;

pub async fn run_display(
    mut rx: mpsc::Receiver<HashMap<OpKind, Aggregate>>,
    op: OpKind,
    total_duration: Duration,
    start: std::time::Instant,
) {
    let is_tty = stderr().is_terminal();
    let mut first = true;

    let mut interval = tokio::time::interval(Duration::from_millis(500));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = interval.tick() => {}
            maybe = rx.recv() => {
                if maybe.is_none() {
                    break;
                }
                // Drain any queued messages without sleeping
            }
        }

        // Drain all pending
        let mut latest = None;
        while let Ok(m) = rx.try_recv() {
            latest = Some(m);
        }

        let elapsed = start.elapsed();
        if elapsed >= total_duration {
            break;
        }

        let agg = latest.and_then(|m| m.get(&op).cloned());
        render(op, elapsed, total_duration, agg.as_ref(), is_tty, &mut first);
    }
}

fn render(
    op: OpKind,
    elapsed: Duration,
    total: Duration,
    agg: Option<&Aggregate>,
    is_tty: bool,
    first: &mut bool,
) {
    let elapsed_s = elapsed.as_secs();
    let total_s = total.as_secs();
    let bar_width = 20usize;
    let filled = ((elapsed_s as f64 / total_s as f64) * bar_width as f64) as usize;
    let filled = filled.min(bar_width);
    let bar = format!("[{}{}]", "=".repeat(filled), " ".repeat(bar_width - filled));

    let line1 = format!(
        "y2q-warp  {op}  {elapsed_s}s / {total_s}s  {bar}"
    );

    let (throughput_line, latency_line) = if let Some(agg) = agg {
        let tl = format!(
            "  Throughput: {:.1} MiB/s   {:.0} ops/s   {} errors",
            agg.throughput_mibps, agg.ops_per_sec, agg.n_errors
        );
        let ll = if let (Some(p50), Some(p90), Some(p99)) =
            (agg.ttfb_p50_ns, agg.ttfb_p90_ns, agg.ttfb_p99_ns)
        {
            format!(
                "  Latency:    P50={}  P90={}  P99={}   TTFB P50={}  P90={}  P99={}",
                ns_to_ms_str(agg.p50_ns),
                ns_to_ms_str(agg.p90_ns),
                ns_to_ms_str(agg.p99_ns),
                ns_to_ms_str(p50),
                ns_to_ms_str(p90),
                ns_to_ms_str(p99),
            )
        } else {
            format!(
                "  Latency:    P50={}  P90={}  P99={}",
                ns_to_ms_str(agg.p50_ns),
                ns_to_ms_str(agg.p90_ns),
                ns_to_ms_str(agg.p99_ns),
            )
        };
        (tl, ll)
    } else {
        ("  Throughput: --".to_owned(), "  Latency:    --".to_owned())
    };

    let mut err = stderr();
    if is_tty && !*first {
        let _ = execute!(err, MoveUp(DISPLAY_LINES), Clear(ClearType::FromCursorDown));
    }
    *first = false;

    if is_tty {
        let _ = writeln!(err, "{line1}");
        let _ = writeln!(err, "{throughput_line}");
        let _ = writeln!(err, "{latency_line}");
    } else {
        let _ = writeln!(err, "{line1} | {throughput_line} | {latency_line}");
    }
}
