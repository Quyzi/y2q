//! Listing / query operations shared by the CLI and the TUI: label search and
//! attribute-filtered find.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
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

// ── Diff ────────────────────────────────────────────────────────────────────

/// One side of a tree comparison: relative key -> (size, optional checksum).
#[derive(Debug, Clone)]
pub struct DiffEntry {
    pub size: u64,
    pub checksum: Option<String>,
}

pub type DiffEntries = BTreeMap<String, DiffEntry>;

/// A single difference between two trees. `op` is `<` (only in src), `>` (only
/// in dst), or `!` (present in both but differing).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiffRow {
    pub op: &'static str,
    pub key: String,
    pub src_size: Option<u64>,
    pub dst_size: Option<u64>,
}

/// Collect a local file tree rooted at `root`, keyed by relative path.
pub fn collect_local_entries(root: &Path) -> Result<DiffEntries, String> {
    let mut entries: DiffEntries = BTreeMap::new();
    if !root.exists() {
        return Ok(entries);
    }
    if root.is_file() {
        let meta = std::fs::metadata(root).map_err(|e| e.to_string())?;
        let key = root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        entries.insert(
            key,
            DiffEntry {
                size: meta.len(),
                checksum: None,
            },
        );
        return Ok(entries);
    }
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let rel: PathBuf = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_owned();
        let key = rel.to_string_lossy().replace('\\', "/");
        let meta = entry.metadata().map_err(|e| format!("metadata: {e}"))?;
        entries.insert(
            key,
            DiffEntry {
                size: meta.len(),
                checksum: None,
            },
        );
    }
    Ok(entries)
}

/// Collect a remote object tree under `bucket`/`prefix`, keyed by the path
/// relative to the prefix.
pub async fn collect_remote_entries(
    client: &Y2qClient,
    bucket: &str,
    prefix: Option<&str>,
) -> Result<DiffEntries, ClientError> {
    let prefix_trim = prefix.map(|p| p.trim_end_matches('/').to_owned());
    let mut entries: DiffEntries = BTreeMap::new();
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
        for item in page.items {
            let key = match &prefix_trim {
                Some(p) if !p.is_empty() => item
                    .key
                    .strip_prefix(p)
                    .map(|s| s.trim_start_matches('/').to_owned())
                    .unwrap_or(item.key.clone()),
                _ => item.key.clone(),
            };
            entries.insert(
                key,
                DiffEntry {
                    size: item.size,
                    checksum: if item.checksum_gxhash.is_empty() {
                        None
                    } else {
                        Some(item.checksum_gxhash)
                    },
                },
            );
        }
        match page.next {
            Some(c) => after = Some(c),
            None => break,
        }
    }
    Ok(entries)
}

/// Compare two collected trees, returning the sorted list of differences.
pub fn diff_entries(src: &DiffEntries, dst: &DiffEntries) -> Vec<DiffRow> {
    let mut rows: Vec<DiffRow> = Vec::new();
    for (key, s) in src {
        match dst.get(key) {
            Some(d) if d.size != s.size => rows.push(DiffRow {
                op: "!",
                key: key.clone(),
                src_size: Some(s.size),
                dst_size: Some(d.size),
            }),
            Some(d) if s.checksum.is_some() && d.checksum.is_some() && s.checksum != d.checksum => {
                rows.push(DiffRow {
                    op: "!",
                    key: key.clone(),
                    src_size: Some(s.size),
                    dst_size: Some(d.size),
                });
            }
            Some(_) => {}
            None => rows.push(DiffRow {
                op: "<",
                key: key.clone(),
                src_size: Some(s.size),
                dst_size: None,
            }),
        }
    }
    for (key, d) in dst {
        if !src.contains_key(key) {
            rows.push(DiffRow {
                op: ">",
                key: key.clone(),
                src_size: None,
                dst_size: Some(d.size),
            });
        }
    }
    rows.sort_by(|a, b| a.key.cmp(&b.key));
    rows
}

// ── Mirror ──────────────────────────────────────────────────────────────────

/// What a mirror would do to a given key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorAction {
    /// Key missing from the destination.
    Copy,
    /// Key present but differing.
    Update,
}

impl MirrorAction {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Copy => "copy",
            Self::Update => "update",
        }
    }
}

/// A one-way mirror plan derived from two collected trees.
#[derive(Debug, Default)]
pub struct MirrorPlan {
    /// Keys to copy/update, in source order.
    pub actions: Vec<(String, MirrorAction)>,
    /// Destination-only keys (applied only when `--remove`), in dst order.
    pub deletions: Vec<String>,
    /// Count of keys present and identical (left untouched).
    pub skipped: u64,
}

/// Compute the actions needed to make `dst` match `src`. When `overwrite` is
/// set, equal-size entries with differing checksums are also updated.
pub fn mirror_plan(src: &DiffEntries, dst: &DiffEntries, overwrite: bool) -> MirrorPlan {
    let mut plan = MirrorPlan::default();
    for (key, s) in src {
        let action = match dst.get(key) {
            None => MirrorAction::Copy,
            Some(d) if d.size != s.size => MirrorAction::Update,
            Some(d)
                if overwrite
                    && s.checksum.is_some()
                    && d.checksum.is_some()
                    && s.checksum != d.checksum =>
            {
                MirrorAction::Update
            }
            Some(_) => {
                plan.skipped += 1;
                continue;
            }
        };
        plan.actions.push((key.clone(), action));
    }
    for key in dst.keys() {
        if !src.contains_key(key) {
            plan.deletions.push(key.clone());
        }
    }
    plan
}
