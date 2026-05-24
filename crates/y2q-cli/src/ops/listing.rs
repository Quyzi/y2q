//! Listing / query operations shared by the CLI and the TUI: label search and
//! attribute-filtered find.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use y2q_client::{ClientError, ListOptions, MetadataView, SearchOptions, Y2qClient};

/// Run a server-side label query, following pagination to completion.
/// `bucket`/`prefix` scope the search (both optional).
pub async fn search(
    client: &Y2qClient,
    bucket: Option<String>,
    prefix: Option<String>,
    query: &str,
) -> Result<Vec<MetadataView>, ClientError> {
    let mut after: Option<String> = None;
    let mut hits: Vec<MetadataView> = Vec::new();
    loop {
        let page = client
            .search_labels(
                query,
                &SearchOptions {
                    bucket: bucket.clone(),
                    prefix: prefix.clone(),
                    after: after.clone(),
                    limit: Some(1000),
                },
            )
            .await?;
        hits.extend(page.items);
        match page.next {
            Some(c) => after = Some(c),
            None => break,
        }
    }
    Ok(hits)
}

/// A `+1k` / `-2M` / `100` style size filter.
#[derive(Debug, Clone, Copy)]
pub enum SizeFilter {
    AtLeast(u64),
    AtMost(u64),
    Equal(u64),
}

impl SizeFilter {
    pub fn parse(s: &str) -> Result<Self, String> {
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

/// Parse a byte count with optional decimal (k/m/g) or binary (ki/mi/gi) suffix.
pub fn parse_bytes(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, suffix) = s
        .find(|c: char| c.is_ascii_alphabetic())
        .map(|i| s.split_at(i))
        .unwrap_or((s, ""));
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|e| format!("invalid size `{s}`: {e}"))?;
    let mult = match suffix.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 1u64,
        "K" | "KB" => 1_000,
        "KI" | "KIB" => 1_024,
        "M" | "MB" => 1_000_000,
        "MI" | "MIB" => 1_024 * 1_024,
        "G" | "GB" => 1_000_000_000,
        "GI" | "GIB" => 1_024 * 1_024 * 1_024,
        other => return Err(format!("unknown size unit `{other}`")),
    };
    Ok(n.saturating_mul(mult))
}

/// Parse a human duration like `7d` or `30m`.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    humantime::parse_duration(s).map_err(|e| format!("invalid duration `{s}`: {e}"))
}

/// A compiled set of `find` filters. Any unset field matches everything.
#[derive(Debug, Default)]
pub struct FindFilter {
    pub name: Option<glob::Pattern>,
    pub size: Option<SizeFilter>,
    /// Only entries older than this many nanoseconds.
    pub older_than_ns: Option<u64>,
    /// Only entries newer than this many nanoseconds.
    pub newer_than_ns: Option<u64>,
}

impl FindFilter {
    /// Build a filter from raw CLI/TUI strings.
    pub fn build(
        name: Option<&str>,
        size: Option<&str>,
        older_than: Option<&str>,
        newer_than: Option<&str>,
    ) -> Result<Self, String> {
        let name = name
            .map(glob::Pattern::new)
            .transpose()
            .map_err(|e| format!("invalid --name pattern: {e}"))?;
        let size = size.map(SizeFilter::parse).transpose()?;
        let older_than_ns = older_than
            .map(parse_duration)
            .transpose()?
            .map(|d| d.as_nanos() as u64);
        let newer_than_ns = newer_than
            .map(parse_duration)
            .transpose()?
            .map(|d| d.as_nanos() as u64);
        Ok(Self {
            name,
            size,
            older_than_ns,
            newer_than_ns,
        })
    }

    fn matches(&self, item: &MetadataView, now_ns: u64) -> bool {
        if let Some(p) = &self.name {
            let basename = item.key.rsplit('/').next().unwrap_or(&item.key);
            if !p.matches(basename) {
                return false;
            }
        }
        if let Some(s) = &self.size
            && !s.matches(item.size)
        {
            return false;
        }
        let age = now_ns.saturating_sub(item.modified);
        if let Some(o) = self.older_than_ns
            && age < o
        {
            return false;
        }
        if let Some(n) = self.newer_than_ns
            && age > n
        {
            return false;
        }
        true
    }
}

/// List objects under `bucket`/`prefix` and return those matching `filter`.
pub async fn find(
    client: &Y2qClient,
    bucket: &str,
    prefix: Option<String>,
    filter: &FindFilter,
) -> Result<Vec<MetadataView>, ClientError> {
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut after: Option<String> = None;
    let mut out: Vec<MetadataView> = Vec::new();
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
            if filter.matches(&item, now_ns) {
                out.push(item);
            }
        }
        match page.next {
            Some(c) => after = Some(c),
            None => break,
        }
    }
    Ok(out)
}

// ── Disk usage (du) ─────────────────────────────────────────────────────────

/// Grouped disk-usage totals: group name -> (bytes, object count).
pub type DuGroups = BTreeMap<String, (u64, u64)>;

/// Sum sizes under `bucket`/`prefix`. When `depth > 0`, also bucket the totals
/// by the first `depth` path segments after the prefix. Returns
/// `(total_bytes, total_count, grouped)`.
pub async fn du(
    client: &Y2qClient,
    bucket: &str,
    prefix: Option<&str>,
    depth: u32,
) -> Result<(u64, u64, DuGroups), ClientError> {
    let mut total = 0u64;
    let mut count = 0u64;
    let mut groups: DuGroups = BTreeMap::new();
    let mut after: Option<String> = None;
    let prefix_trim = prefix.map(|p| p.trim_end_matches('/').to_owned());

    loop {
        let page = client
            .list_objects(
                bucket,
                &ListOptions {
                    prefix: prefix.map(str::to_owned),
                    after: after.clone(),
                    limit: Some(1000),
                },
            )
            .await?;
        for item in &page.items {
            total += item.size;
            count += 1;
            if depth > 0 {
                let relative = match &prefix_trim {
                    Some(p) if !p.is_empty() => item.key.strip_prefix(p).unwrap_or(&item.key),
                    _ => &item.key,
                };
                let relative = relative.trim_start_matches('/');
                let group = relative
                    .split('/')
                    .take(depth as usize)
                    .collect::<Vec<_>>()
                    .join("/");
                let entry = groups.entry(group).or_insert((0, 0));
                entry.0 += item.size;
                entry.1 += 1;
            }
        }
        match page.next {
            Some(c) => after = Some(c),
            None => break,
        }
    }
    Ok((total, count, groups))
}

/// Summarize every bucket on the server: `(bucket, bytes, count)` per row.
pub async fn du_buckets(client: &Y2qClient) -> Result<Vec<(String, u64, u64)>, ClientError> {
    let buckets = client.list_buckets().await?;
    let mut out = Vec::with_capacity(buckets.len());
    for b in buckets {
        let (bytes, count, _) = du(client, &b, None, 0).await?;
        out.push((b, bytes, count));
    }
    Ok(out)
}

// ── Tree ────────────────────────────────────────────────────────────────────

/// A node in a remote directory tree built from object keys.
#[derive(Default, Debug)]
pub struct TreeNode {
    pub children: BTreeMap<String, TreeNode>,
    pub leaf: bool,
}

impl TreeNode {
    fn insert(&mut self, parts: &[&str]) {
        let Some((head, rest)) = parts.split_first() else {
            self.leaf = true;
            return;
        };
        let entry = self.children.entry((*head).to_owned()).or_default();
        if rest.is_empty() {
            entry.leaf = true;
        } else {
            entry.insert(rest);
        }
    }

    /// Render the tree as text lines (without the root label).
    pub fn render_lines(&self, show_files: bool, max_depth: u32) -> Vec<String> {
        let mut out = Vec::new();
        self.render_into("", show_files, 1, max_depth, &mut out);
        out
    }

    fn render_into(
        &self,
        prefix: &str,
        show_files: bool,
        depth: u32,
        max_depth: u32,
        out: &mut Vec<String>,
    ) {
        if max_depth > 0 && depth > max_depth {
            return;
        }
        let entries: Vec<_> = self
            .children
            .iter()
            .filter(|(_, n)| show_files || !n.children.is_empty())
            .collect();
        let n = entries.len();
        for (i, (name, child)) in entries.iter().enumerate() {
            let last = i + 1 == n;
            let connector = if last { "└── " } else { "├── " };
            let suffix = if child.children.is_empty() { "" } else { "/" };
            out.push(format!("{prefix}{connector}{name}{suffix}"));
            let next_prefix = format!("{prefix}{}", if last { "    " } else { "│   " });
            child.render_into(&next_prefix, show_files, depth + 1, max_depth, out);
        }
    }

    /// JSON representation rooted at `name`.
    pub fn to_json(&self, name: &str) -> serde_json::Value {
        let children: Vec<_> = self.children.iter().map(|(n, c)| c.to_json(n)).collect();
        serde_json::json!({
            "name": name,
            "leaf": self.leaf,
            "children": children,
        })
    }
}

/// Build a directory tree from the object keys under `bucket`/`prefix`.
pub async fn build_tree(
    client: &Y2qClient,
    bucket: &str,
    prefix: Option<&str>,
) -> Result<TreeNode, ClientError> {
    let prefix_trim = prefix.map(|p| p.trim_end_matches('/').to_owned());
    let mut root = TreeNode::default();
    let mut after: Option<String> = None;
    loop {
        let page = client
            .list_objects(
                bucket,
                &ListOptions {
                    prefix: prefix.map(str::to_owned),
                    after: after.clone(),
                    limit: Some(1000),
                },
            )
            .await?;
        for item in &page.items {
            let relative = match &prefix_trim {
                Some(p) if !p.is_empty() => item.key.strip_prefix(p).unwrap_or(&item.key),
                _ => &item.key,
            };
            let relative = relative.trim_start_matches('/');
            let parts: Vec<&str> = relative.split('/').filter(|p| !p.is_empty()).collect();
            if !parts.is_empty() {
                root.insert(&parts);
            }
        }
        match page.next {
            Some(c) => after = Some(c),
            None => break,
        }
    }
    Ok(root)
}
