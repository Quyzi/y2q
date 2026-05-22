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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_bytes_scales() {
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(1024), "1.00 KiB");
        assert_eq!(fmt_bytes(1024 * 1024), "1.00 MiB");
        assert_eq!(fmt_bytes(1024 * 1024 * 1024), "1.00 GiB");
    }

    #[test]
    fn fmt_speed_appends_per_sec() {
        assert_eq!(fmt_speed(1024), "1.00 KiB/s");
    }

    #[test]
    fn fmt_ns_formats_timestamp() {
        // epoch renders as a Y-m-d H:M:S string (local tz), not raw digits.
        let s = fmt_ns(0);
        assert!(s.contains('-') && s.contains(':'), "{s}");
        // A large but in-range value still formats as a date, not raw digits.
        let s = fmt_ns(1_700_000_000_000_000_000);
        assert!(s.starts_with("2023") || s.starts_with("2024"), "{s}");
    }

    #[test]
    fn print_table_empty_is_noop() {
        // Just exercises the empty + populated branches without panicking.
        print_table(&["a", "b"], &[]);
        print_table(
            &["name", "size"],
            &[
                vec!["x".to_owned(), "10".to_owned()],
                vec!["longer-name".to_owned(), "2000".to_owned()],
            ],
        );
    }
}
