use std::collections::BTreeSet;

/// Which buckets a mount exposes: every bucket as a top-level directory, or a
/// single bucket mounted as the filesystem root.
#[derive(Debug, Clone)]
pub enum MountMode {
    Multi,
    Single(String),
}

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
    pub cipher_size: Option<u64>,
    pub cipher_sha256: Option<String>,
    pub kem_alg: Option<String>,
    pub aead_alg: Option<String>,
    pub envelope_version: Option<u16>,
}
