use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "y2q-warp", about = "Load benchmarking tool for y2q")]
pub struct Cli {
    /// Server alias from ~/.config/y2q/config.toml (not required for analyze)
    pub alias: Option<String>,

    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<std::path::PathBuf>,

    /// Override TLS certificate verification for this invocation.
    /// Use only against self-signed dev/staging endpoints.
    #[arg(long, global = true)]
    pub insecure: bool,

    /// Trust this PEM CA bundle for this invocation, overriding the alias's CA.
    #[arg(long, global = true, value_name = "PATH")]
    pub ca_cert: Option<std::path::PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Upload benchmark
    Put(WorkloadArgs),
    /// Download benchmark (measures TTFB)
    Get(WorkloadArgs),
    /// Delete benchmark
    Delete(WorkloadArgs),
    /// HEAD request benchmark
    Stat(WorkloadArgs),
    /// List benchmark
    List(WorkloadArgs),
    /// Mixed PUT/GET/DELETE/STAT workload
    Mixed(MixedArgs),
    /// Pre-seed objects without running a timed benchmark
    Prepare(PrepareArgs),
    /// Remove all objects seeded by a previous run
    Cleanup(CleanupArgs),
    /// Analyze previously recorded benchmark data
    Analyze(AnalyzeArgs),
}

#[derive(Args, Debug)]
pub struct WorkloadArgs {
    /// Target bucket
    #[arg(long, default_value = "warp")]
    pub bucket: String,

    /// Number of concurrent workers
    #[arg(long, default_value = "8")]
    pub concurrent: usize,

    /// Benchmark duration (e.g. 30s, 5m)
    #[arg(long, default_value = "5m")]
    pub duration: String,

    /// Number of objects to pre-seed (for GET/STAT/DELETE)
    #[arg(long, default_value = "1000")]
    pub objects: u32,

    /// Fixed object size (e.g. 4MiB, 512KiB)
    #[arg(long, default_value = "4MiB", conflicts_with_all = ["obj_size_min", "obj_size_max"])]
    pub obj_size: String,

    /// Minimum random object size
    #[arg(long, requires = "obj_size_max")]
    pub obj_size_min: Option<String>,

    /// Maximum random object size
    #[arg(long, requires = "obj_size_min")]
    pub obj_size_max: Option<String>,

    /// Output file for raw data (default: warp-{op}-{timestamp}.csv.zst)
    #[arg(long)]
    pub output: Option<std::path::PathBuf>,

    /// Skip teardown after the benchmark
    #[arg(long)]
    pub no_cleanup: bool,

    /// Password (overrides stored token; env: Y2QWARP_PASSWORD)
    #[arg(long, env = "Y2QWARP_PASSWORD")]
    pub password: Option<String>,
}

#[derive(Args, Debug)]
pub struct MixedArgs {
    #[command(flatten)]
    pub common: WorkloadArgs,

    /// Weight for GET operations
    #[arg(long, default_value = "45")]
    pub get_weight: u32,

    /// Weight for PUT operations
    #[arg(long, default_value = "15")]
    pub put_weight: u32,

    /// Weight for DELETE operations
    #[arg(long, default_value = "25")]
    pub delete_weight: u32,

    /// Weight for STAT operations
    #[arg(long, default_value = "15")]
    pub stat_weight: u32,
}

#[derive(Args, Debug)]
pub struct PrepareArgs {
    #[arg(long, default_value = "warp")]
    pub bucket: String,

    #[arg(long, default_value = "1000")]
    pub objects: u32,

    #[arg(long, default_value = "4MiB")]
    pub obj_size: String,

    #[arg(long, conflicts_with_all = ["obj_size_min", "obj_size_max"])]
    pub obj_size_min: Option<String>,

    #[arg(long)]
    pub obj_size_max: Option<String>,

    #[arg(long, env = "Y2QWARP_PASSWORD")]
    pub password: Option<String>,
}

#[derive(Args, Debug)]
pub struct CleanupArgs {
    #[arg(long, default_value = "warp")]
    pub bucket: String,

    /// Only clean objects from a specific run ID (default: all warp/ objects)
    #[arg(long)]
    pub run_id: Option<String>,

    #[arg(long, env = "Y2QWARP_PASSWORD")]
    pub password: Option<String>,
}

#[derive(Args, Debug)]
pub struct AnalyzeArgs {
    /// Input .csv.zst files
    pub files: Vec<std::path::PathBuf>,

    /// Filter to a single operation type
    #[arg(long, value_name = "OP")]
    pub op: Option<String>,

    /// Skip initial warmup period (e.g. 5s)
    #[arg(long, default_value = "0s")]
    pub skip: String,

    /// Write per-segment CSV to file
    #[arg(long, value_name = "FILE")]
    pub out: Option<std::path::PathBuf>,
}
