use chrono::{DateTime, Local};
use serde::Serialize;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OutputMode {
    #[default]
    Human,
    Json,
}

pub fn print_json<T: Serialize>(value: &T) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).unwrap_or_default()
    );
}

/// Format nanosecond timestamp to a local datetime string.
pub fn fmt_ns(ns: u64) -> String {
    let secs = (ns / 1_000_000_000) as i64;
    let nanos = (ns % 1_000_000_000) as u32;
    match DateTime::from_timestamp(secs, nanos) {
        Some(dt) => {
            let local: DateTime<Local> = dt.into();
            local.format("%Y-%m-%d %H:%M:%S").to_string()
        }
        None => ns.to_string(),
    }
}

/// Format byte count as human-readable string.
pub fn fmt_bytes(n: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;
    const KIB: u64 = 1024;
    if n >= GIB {
        format!("{:.2} GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.2} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.2} KiB", n as f64 / KIB as f64)
    } else {
        format!("{n} B")
    }
}

/// Format speed in bytes/sec.
pub fn fmt_speed(bps: u64) -> String {
    format!("{}/s", fmt_bytes(bps))
}

/// Print a table. `headers` is the column names, `rows` is a vec of row vecs.
/// Column widths are computed from content.
pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    if rows.is_empty() {
        return;
    }
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len().min(80));
            }
        }
    }

    let header_line: String = headers
        .iter()
        .zip(&widths)
        .map(|(h, &w)| format!("{h:<w$}"))
        .collect::<Vec<_>>()
        .join("  ");
    println!("{header_line}");
    println!("{}", "-".repeat(header_line.len()));

    for row in rows {
        let line: String = row
            .iter()
            .zip(&widths)
            .map(|(cell, &w)| format!("{cell:<w$}"))
            .collect::<Vec<_>>()
            .join("  ");
        println!("{line}");
    }
}
