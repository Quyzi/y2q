//! `find` — filter a remote listing by name/size/time.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use y2q_client::{ListOptions, MetadataView};

use crate::cmd::objects::make_client;
use crate::error::CliError;
use crate::output::{OutputMode, fmt_bytes, fmt_ns, print_json, print_table};
use crate::path::RemotePath;

/// `+1k` / `-2M` / `100` style size filters.
#[derive(Debug, Clone, Copy)]
enum SizeFilter {
    AtLeast(u64),
    AtMost(u64),
    Equal(u64),
}

impl SizeFilter {
    fn parse(s: &str) -> Result<Self, CliError> {
        let (op, rest) = match s.chars().next() {
            Some('+') => (Some('+'), &s[1..]),
            Some('-') => (Some('-'), &s[1..]),
            _ => (None, s),
        };
        let n = parse_bytes(rest)?;
        Ok(match op {
            Some('+') => Self::AtLeast(n),
            Some('-') => Self::AtMost(n),
            _ => Self::Equal(n),
        })
    }

    fn matches(&self, size: u64) -> bool {
        match *self {
            Self::AtLeast(n) => size >= n,
            Self::AtMost(n) => size <= n,
            Self::Equal(n) => size == n,
        }
    }
}

fn parse_bytes(s: &str) -> Result<u64, CliError> {
    let s = s.trim();
    let (num, suffix) = s
        .find(|c: char| c.is_ascii_alphabetic())
        .map(|i| s.split_at(i))
        .unwrap_or((s, ""));
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|e| CliError::Other(format!("invalid size `{s}`: {e}")))?;
    let mult = match suffix.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 1u64,
        "K" | "KB" => 1_000,
        "KI" | "KIB" => 1_024,
        "M" | "MB" => 1_000_000,
        "MI" | "MIB" => 1_024 * 1_024,
        "G" | "GB" => 1_000_000_000,
        "GI" | "GIB" => 1_024 * 1_024 * 1_024,
        other => return Err(CliError::Other(format!("unknown size unit `{other}`"))),
    };
    Ok(n.saturating_mul(mult))
}

fn parse_duration(s: &str) -> Result<Duration, CliError> {
    humantime::parse_duration(s)
        .map_err(|e| CliError::Other(format!("invalid duration `{s}`: {e}")))
}

pub async fn run(
    path: String,
    name: Option<String>,
    size: Option<String>,
    older_than: Option<String>,
    newer_than: Option<String>,
    mode: OutputMode,
) -> Result<(), CliError> {
    let remote = RemotePath::parse(&path)?;
    let bucket = remote.bucket.as_deref().ok_or_else(|| {
        CliError::InvalidPath(format!("{}/", remote.alias), "missing bucket".into())
    })?;

    let name_pattern = name
        .as_ref()
        .map(|n| glob::Pattern::new(n))
        .transpose()
        .map_err(|e| CliError::Other(format!("invalid --name pattern: {e}")))?;
    let size_filter = size.as_deref().map(SizeFilter::parse).transpose()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let older_ns = older_than
        .as_deref()
        .map(parse_duration)
        .transpose()?
        .map(|d| d.as_nanos() as u64);
    let newer_ns = newer_than
        .as_deref()
        .map(parse_duration)
        .transpose()?
        .map(|d| d.as_nanos() as u64);

    let client = make_client(&remote.alias).await?;
    let prefix = remote.key.clone();
    let mut after: Option<String> = None;
    let mut matches_meta: Vec<MetadataView> = Vec::new();

    loop {
        let page = client
            .list_objects(
                bucket,
                &ListOptions {
                    prefix: prefix.clone(),
                    after: after.clone(),
                    limit: Some(1000),
                },
            )
            .await?;
        for item in page.items {
            if let Some(p) = &name_pattern {
                let basename = item.key.rsplit('/').next().unwrap_or(&item.key);
                if !p.matches(basename) {
                    continue;
                }
            }
            if let Some(s) = &size_filter
                && !s.matches(item.size)
            {
                continue;
            }
            if let Some(o) = older_ns
                && now.saturating_sub(item.modified) < o
            {
                continue;
            }
            if let Some(n) = newer_ns
                && now.saturating_sub(item.modified) > n
            {
                continue;
            }
            matches_meta.push(item);
        }
        match page.next {
            Some(c) => after = Some(c),
            None => break,
        }
    }

    if mode == OutputMode::Json {
        print_json(&matches_meta);
    } else if matches_meta.is_empty() {
        eprintln!("No matches.");
    } else {
        let rows: Vec<Vec<String>> = matches_meta
            .iter()
            .map(|m| {
                vec![
                    format!("{}/{bucket}/{}", remote.alias, m.key),
                    fmt_bytes(m.size),
                    fmt_ns(m.modified),
                ]
            })
            .collect();
        print_table(&["PATH", "SIZE", "MODIFIED"], &rows);
    }
    Ok(())
}
