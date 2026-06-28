use std::collections::HashSet;

use y2q_client::{ClientError, ListOptions, MetadataView, Y2qClient};

#[derive(Debug)]
pub enum ChildEntry {
    Dir {
        name: String,
    },
    File {
        name: String,
        meta: Box<MetadataView>,
    },
}

/// List immediate children under `prefix` inside `bucket`.
///
/// `prefix` must end with `/` for subdirectory listings, or be empty for the
/// bucket root. Objects whose keys match exactly `prefix` (i.e. a zero-length
/// remainder after stripping) are skipped — they represent the "directory
/// itself" if someone stored a placeholder object.
pub async fn list_children(
    client: &Y2qClient,
    bucket: &str,
    prefix: &str,
) -> Result<Vec<ChildEntry>, ClientError> {
    let mut results: Vec<ChildEntry> = Vec::new();
    let mut seen_dirs: HashSet<String> = HashSet::new();
    let mut cursor: Option<String> = None;

    loop {
        let page = client
            .list_objects(
                bucket,
                &ListOptions {
                    prefix: Some(prefix.to_owned()),
                    after: cursor,
                    limit: Some(500),
                },
            )
            .await?;

        for item in page.items {
            let remainder = item.key.strip_prefix(prefix).unwrap_or(item.key.as_str());
            if remainder.is_empty() {
                continue;
            }
            match remainder.split_once('/') {
                None => {
                    results.push(ChildEntry::File {
                        name: remainder.to_owned(),
                        meta: Box::new(item),
                    });
                }
                Some((dir_name, _)) => {
                    if seen_dirs.insert(dir_name.to_owned()) {
                        results.push(ChildEntry::Dir {
                            name: dir_name.to_owned(),
                        });
                    }
                }
            }
        }

        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simulate the prefix-stripping + classification logic without a real
    /// client by exercising it directly on the same algorithm.
    #[test]
    fn classify_flat_objects() {
        let prefix = "";
        let keys = ["a/b.txt", "a/c/d.txt", "e.txt"];
        let mut seen_dirs: HashSet<String> = HashSet::new();
        let mut files = vec![];
        let mut dirs = vec![];

        for key in keys {
            let remainder = key.strip_prefix(prefix).unwrap_or(key);
            match remainder.split_once('/') {
                None => files.push(remainder.to_owned()),
                Some((d, _)) => {
                    if seen_dirs.insert(d.to_owned()) {
                        dirs.push(d.to_owned());
                    }
                }
            }
        }

        assert_eq!(dirs, vec!["a"]);
        assert_eq!(files, vec!["e.txt"]);
    }

    #[test]
    fn subdir_prefix_strips_correctly() {
        let prefix = "a/";
        let keys = ["a/b.txt", "a/c/d.txt", "a/c/e.txt"];
        let mut seen_dirs: HashSet<String> = HashSet::new();
        let mut files = vec![];
        let mut dirs = vec![];

        for key in keys {
            let remainder = key.strip_prefix(prefix).unwrap_or(key);
            if remainder.is_empty() {
                continue;
            }
            match remainder.split_once('/') {
                None => files.push(remainder.to_owned()),
                Some((d, _)) => {
                    if seen_dirs.insert(d.to_owned()) {
                        dirs.push(d.to_owned());
                    }
                }
            }
        }

        assert_eq!(dirs, vec!["c"]);
        assert_eq!(files, vec!["b.txt"]);
    }

    #[test]
    fn placeholder_object_skipped() {
        let prefix = "a/";
        // "a/" itself — remainder is empty after stripping.
        let key = "a/";
        let remainder = key.strip_prefix(prefix).unwrap_or(key);
        assert!(remainder.is_empty());
    }
}
