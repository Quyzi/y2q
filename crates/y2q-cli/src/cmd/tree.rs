//! `tree` — render a remote prefix as a directory tree.

use std::collections::BTreeMap;

use y2q_client::ListOptions;

use crate::cmd::objects::make_client;
use crate::error::CliError;
use crate::output::{OutputMode, print_json};
use crate::path::RemotePath;

#[derive(Default, Debug)]
struct Node {
    children: BTreeMap<String, Node>,
    leaf: bool,
}

impl Node {
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

    fn print(&self, prefix: &str, show_files: bool, depth: u32, max_depth: u32) {
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
            println!("{prefix}{connector}{name}{suffix}");
            let next_prefix = format!("{prefix}{}", if last { "    " } else { "│   " });
            child.print(&next_prefix, show_files, depth + 1, max_depth);
        }
    }

    fn to_json(&self, name: &str) -> serde_json::Value {
        let children: Vec<_> = self.children.iter().map(|(n, c)| c.to_json(n)).collect();
        serde_json::json!({
            "name": name,
            "leaf": self.leaf,
            "children": children,
        })
    }
}

pub async fn run(
    path: String,
    depth: Option<u32>,
    show_files: bool,
    mode: OutputMode,
) -> Result<(), CliError> {
    let remote = RemotePath::parse(&path)?;
    let bucket = remote.bucket.as_deref().ok_or_else(|| {
        CliError::InvalidPath(format!("{}/", remote.alias), "missing bucket".into())
    })?;

    let client = make_client(&remote.alias).await?;
    let prefix = remote.key.as_deref();
    let prefix_trim = prefix.map(|p| p.trim_end_matches('/').to_owned());

    let mut root = Node::default();
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

    if mode == OutputMode::Json {
        print_json(&root.to_json(&path));
        return Ok(());
    }

    println!("{path}");
    root.print("", show_files, 1, depth.unwrap_or(0));
    Ok(())
}
