use std::collections::{HashMap, HashSet};

use y2q_client::{ClientError, ListOptions, MetadataView, Y2qClient};

/// Kernel `NAME_MAX` on Linux; FUSE dirents longer than this make `readdir`
/// fail with `EIO` for the whole listing.
const MAX_NAME_LEN: usize = 255;

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

/// Whether a single path component is safe to emit as a FUSE dirent name.
///
/// Empty / `.` / `..` make the kernel reject the dirent (or add a second `..`);
/// embedded NUL or over-long names likewise turn a whole `readdir` into `EIO`.
pub fn is_safe_child_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('\0')
        && name.len() <= MAX_NAME_LEN
}

/// List immediate children under `prefix` inside `bucket`.
///
/// `prefix` must end with `/` for subdirectory listings, or be empty for the
/// bucket root. Objects whose keys match exactly `prefix` (i.e. a zero-length
/// remainder after stripping) are skipped — they represent the "directory
/// itself" if someone stored a placeholder object.
///
/// Unsafe components (empty, `.`, `..`, NUL, over-long) are skipped with a
/// single warning. When a file and a prefix share the same name, the file
/// keeps the plain name and the directory is exposed as `{name}~dir`.
pub async fn list_children(
    client: &Y2qClient,
    bucket: &str,
    prefix: &str,
) -> Result<Vec<ChildEntry>, ClientError> {
    let mut files: HashMap<String, MetadataView> = HashMap::new();
    let mut dirs: HashSet<String> = HashSet::new();
    let mut skipped_logged = false;
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
                    if !is_safe_child_name(remainder) {
                        if !skipped_logged {
                            tracing::warn!(
                                bucket,
                                prefix,
                                key = %item.key,
                                "skipping unlistable object key component in readdir"
                            );
                            skipped_logged = true;
                        }
                        continue;
                    }
                    files.insert(remainder.to_owned(), item);
                }
                Some((dir_name, _)) => {
                    if !is_safe_child_name(dir_name) {
                        if !skipped_logged {
                            tracing::warn!(
                                bucket,
                                prefix,
                                key = %item.key,
                                "skipping unlistable directory key component in readdir"
                            );
                            skipped_logged = true;
                        }
                        continue;
                    }
                    dirs.insert(dir_name.to_owned());
                }
            }
        }

        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }

    let mut results: Vec<ChildEntry> = Vec::with_capacity(files.len() + dirs.len());
    let file_names: HashSet<String> = files.keys().cloned().collect();

    for (name, meta) in files {
        results.push(ChildEntry::File {
            name,
            meta: Box::new(meta),
        });
    }

    for dir_name in dirs {
        let name = if file_names.contains(&dir_name) {
            let escaped = format!("{dir_name}~dir");
            if !is_safe_child_name(&escaped) || file_names.contains(&escaped) {
                tracing::warn!(
                    bucket,
                    prefix,
                    dir = %dir_name,
                    "directory shadowed by file; omitting from readdir"
                );
                continue;
            }
            tracing::warn!(
                bucket,
                prefix,
                dir = %dir_name,
                escaped = %escaped,
                "directory shadowed by file; exposing under escaped name"
            );
            escaped
        } else {
            dir_name
        };
        results.push(ChildEntry::Dir { name });
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_safe_child_name_rejects_bad_components() {
        assert!(!is_safe_child_name(""));
        assert!(!is_safe_child_name("."));
        assert!(!is_safe_child_name(".."));
        assert!(!is_safe_child_name("a\0b"));
        assert!(!is_safe_child_name(&"x".repeat(MAX_NAME_LEN + 1)));
        assert!(is_safe_child_name("ok.txt"));
        assert!(is_safe_child_name(&"x".repeat(MAX_NAME_LEN)));
    }

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

    #[test]
    fn shadowed_dir_gets_escaped_name() {
        let files: HashSet<&str> = HashSet::from(["hello.txt"]);
        let dirs = ["hello.txt"];
        let mut out = vec![];
        for dir_name in dirs {
            let name = if files.contains(dir_name) {
                format!("{dir_name}~dir")
            } else {
                dir_name.to_owned()
            };
            out.push(name);
        }
        assert_eq!(out, vec!["hello.txt~dir"]);
    }
}
