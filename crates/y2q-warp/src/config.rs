use std::path::PathBuf;
use std::time::Duration;

use rand::Rng;

use crate::ops::OpKind;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RunConfig {
    pub base_url: String,
    pub bucket: String,
    pub concurrent: usize,
    pub duration: Duration,
    pub obj_size: ObjSize,
    pub output: PathBuf,
    pub no_cleanup: bool,
    pub workload: WorkloadConfig,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct WorkloadConfig {
    pub op: OpKind,
    pub objects: u32,
    pub run_id: String,
    pub mixed_weights: Option<MixedWeights>,
}

#[derive(Debug, Clone, Copy)]
pub struct MixedWeights {
    pub get: u32,
    pub put: u32,
    pub delete: u32,
    pub stat: u32,
}

impl Default for MixedWeights {
    fn default() -> Self {
        Self { get: 45, put: 15, delete: 25, stat: 15 }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ObjSize {
    Fixed(u64),
    Random { min: u64, max: u64 },
}

impl ObjSize {
    pub fn sample(&self, rng: &mut impl Rng) -> u64 {
        match self {
            Self::Fixed(n) => *n,
            Self::Random { min, max } => rng.gen_range(*min..=*max),
        }
    }

    #[allow(dead_code)]
    pub fn max(&self) -> u64 {
        match self {
            Self::Fixed(n) => *n,
            Self::Random { max, .. } => *max,
        }
    }
}

/// Parse a human-readable size string like "4MiB", "1024KiB", "512" (bytes).
pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, suffix) = s
        .find(|c: char| c.is_alphabetic())
        .map(|i| s.split_at(i))
        .unwrap_or((s, ""));
    let base: u64 = num.trim().parse().map_err(|_| format!("invalid size: {s}"))?;
    let mult = match suffix.to_ascii_uppercase().as_str() {
        "" | "B" => 1,
        "K" | "KB" | "KIB" => 1024,
        "M" | "MB" | "MIB" => 1024 * 1024,
        "G" | "GB" | "GIB" => 1024 * 1024 * 1024,
        other => return Err(format!("unknown size suffix: {other}")),
    };
    Ok(base * mult)
}
