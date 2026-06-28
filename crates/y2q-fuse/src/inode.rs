use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, Instant};

pub const ROOT_INO: u64 = 1;
pub const ATTR_TTL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InodePath {
    Root,
    Bucket(String),
    VirtualDir { bucket: String, prefix: String },
    Object { bucket: String, key: String },
}

#[derive(Debug, Clone)]
pub struct CachedMeta {
    pub size: u64,
    /// Nanoseconds since UNIX epoch (from y2q Metadata).
    pub created: u64,
    /// Nanoseconds since UNIX epoch (from y2q Metadata).
    pub modified: u64,
    pub checksum_gxhash: String,
    pub labels: BTreeSet<(String, String)>,
}

#[derive(Debug)]
pub struct InodeEntry {
    pub path: InodePath,
    pub cached_meta: Option<CachedMeta>,
    pub cached_at: Option<Instant>,
}

impl InodeEntry {
    pub fn meta_fresh(&self) -> bool {
        self.cached_at.is_some_and(|t| t.elapsed() < ATTR_TTL)
    }
}

pub struct InodeTable {
    next_ino: u64,
    by_ino: HashMap<u64, InodeEntry>,
    by_path: HashMap<InodePath, u64>,
}

impl InodeTable {
    pub fn new() -> Self {
        let mut t = Self {
            next_ino: 2,
            by_ino: HashMap::new(),
            by_path: HashMap::new(),
        };
        // Root inode is always 1.
        let root = InodeEntry {
            path: InodePath::Root,
            cached_meta: None,
            cached_at: None,
        };
        t.by_ino.insert(ROOT_INO, root);
        t.by_path.insert(InodePath::Root, ROOT_INO);
        t
    }

    /// Return the inode number for `path`, allocating one if unseen.
    pub fn get_or_assign(&mut self, path: InodePath) -> u64 {
        if let Some(&ino) = self.by_path.get(&path) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        let entry = InodeEntry {
            path: path.clone(),
            cached_meta: None,
            cached_at: None,
        };
        self.by_ino.insert(ino, entry);
        self.by_path.insert(path, ino);
        ino
    }

    pub fn get(&self, ino: u64) -> Option<&InodeEntry> {
        self.by_ino.get(&ino)
    }

    pub fn update_meta(&mut self, ino: u64, meta: CachedMeta) {
        if let Some(e) = self.by_ino.get_mut(&ino) {
            e.cached_meta = Some(meta);
            e.cached_at = Some(Instant::now());
        }
    }

    pub fn remove(&mut self, ino: u64) {
        if let Some(e) = self.by_ino.remove(&ino) {
            self.by_path.remove(&e.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_always_one() {
        let t = InodeTable::new();
        assert!(matches!(t.get(ROOT_INO).unwrap().path, InodePath::Root));
    }

    #[test]
    fn get_or_assign_is_idempotent() {
        let mut t = InodeTable::new();
        let path = InodePath::Bucket("mybucket".into());
        let ino1 = t.get_or_assign(path.clone());
        let ino2 = t.get_or_assign(path);
        assert_eq!(ino1, ino2);
        assert_ne!(ino1, ROOT_INO);
    }

    #[test]
    fn distinct_paths_get_distinct_inodes() {
        let mut t = InodeTable::new();
        let a = t.get_or_assign(InodePath::Bucket("a".into()));
        let b = t.get_or_assign(InodePath::Bucket("b".into()));
        assert_ne!(a, b);
    }

    #[test]
    fn remove_clears_both_maps() {
        let mut t = InodeTable::new();
        let path = InodePath::Object {
            bucket: "b".into(),
            key: "k".into(),
        };
        let ino = t.get_or_assign(path.clone());
        t.remove(ino);
        assert!(t.get(ino).is_none());
        // Re-assign allocates a new ino (path gone from by_path).
        let ino2 = t.get_or_assign(path);
        assert_ne!(ino, ino2);
    }
}
