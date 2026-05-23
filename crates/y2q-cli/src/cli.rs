use clap::{Parser, Subcommand};
use clap_complete::Shell;

#[derive(Parser, Debug)]
#[command(name = "y2q", about = "Post-quantum secure object storage CLI")]
pub struct Cli {
    /// Emit machine-readable JSON instead of human-friendly text.
    #[arg(long, short, global = true, env = "Y2Q_OUTPUT", value_name = "FORMAT")]
    pub json: bool,

    /// Increase verbosity (pass multiple times: -v info, -vv debug, -vvv+ trace).
    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Silence progress / non-error output. Errors still print on stderr.
    #[arg(long, short, global = true)]
    pub quiet: bool,

    /// Disable ANSI colors (also honors the NO_COLOR env var).
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Shortcut for maximum verbosity (-vvvv).
    #[arg(long, global = true)]
    pub debug: bool,

    /// Override TLS certificate verification for this invocation.
    /// Use only against self-signed dev/staging endpoints.
    #[arg(long, global = true)]
    pub insecure: bool,

    /// Trust this PEM CA bundle for this invocation, overriding the alias's CA.
    #[arg(long, global = true, value_name = "PATH")]
    pub ca_cert: Option<std::path::PathBuf>,

    /// Config file path [default: ~/.config/y2q/config.toml].
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<std::path::PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Manage server aliases (formerly `config`).
    Alias {
        #[command(subcommand)]
        cmd: AliasCmd,
    },
    /// Log in to a server alias and cache the session token.
    Login {
        alias: String,
        #[arg(long, short)]
        user: Option<String>,
        #[arg(long, short)]
        password: Option<String>,
        #[arg(long, value_name = "SECONDS")]
        ttl: Option<u64>,
    },
    /// Revoke the cached session token for an alias.
    Logout { alias: String },
    /// Change password for an alias.
    Passwd {
        alias: String,
        #[arg(long)]
        current: Option<String>,
        #[arg(long)]
        new: Option<String>,
    },
    /// Copy files between local and remote storage.
    Cp {
        src: String,
        dst: String,
        #[arg(long, value_name = "KEY=VALUE", number_of_values = 1)]
        label: Vec<String>,
        #[arg(long, value_name = "durable|best-effort")]
        sync: Option<String>,
        #[arg(long, short = 'r', help = "Recursively upload a directory")]
        recursive: bool,
    },
    /// Move (rename) an object: copies to the destination then deletes the source.
    Mv {
        src: String,
        dst: String,
        #[arg(long, value_name = "KEY=VALUE", number_of_values = 1)]
        label: Vec<String>,
        #[arg(long, value_name = "durable|best-effort")]
        sync: Option<String>,
    },
    /// Explicit upload (alias of `cp LOCAL REMOTE`).
    Put {
        src: String,
        dst: String,
        #[arg(long, value_name = "KEY=VALUE", number_of_values = 1)]
        label: Vec<String>,
        #[arg(long, value_name = "durable|best-effort")]
        sync: Option<String>,
        #[arg(long, short = 'r')]
        recursive: bool,
    },
    /// Explicit download (alias of `cp REMOTE LOCAL`).
    Get { src: String, dst: String },
    /// Read from stdin and PUT to a remote path.
    Pipe {
        dst: String,
        #[arg(long, value_name = "KEY=VALUE", number_of_values = 1)]
        label: Vec<String>,
        #[arg(long, value_name = "durable|best-effort")]
        sync: Option<String>,
    },
    /// Delete a remote object (supports glob patterns, e.g. alias/bucket/*.log).
    Rm {
        path: String,
        #[arg(
            long,
            short = 'f',
            help = "Skip confirmation when deleting multiple objects"
        )]
        force: bool,
    },
    /// Show metadata for a remote object.
    Stat { path: String },
    /// Stream a remote object to stdout.
    Cat { path: String },
    /// Print the first N bytes of a remote object to stdout.
    Head {
        path: String,
        /// Number of bytes to print (default 1024).
        #[arg(long, short = 'c', value_name = "BYTES", default_value_t = 1024)]
        bytes: u64,
    },
    /// List buckets or objects.
    Ls {
        path: Option<String>,
        #[arg(long)]
        limit: Option<u32>,
        #[arg(long, conflicts_with = "all")]
        after: Option<String>,
        #[arg(long, conflicts_with = "after")]
        all: bool,
    },
    /// Disk usage summary across a remote prefix.
    Du {
        path: String,
        /// Group results by the first N path components after the prefix.
        #[arg(long, value_name = "N")]
        depth: Option<u32>,
    },
    /// Render a remote prefix as a directory tree.
    Tree {
        path: String,
        /// Maximum tree depth (0 = unlimited).
        #[arg(long, value_name = "N")]
        depth: Option<u32>,
        /// Include leaf files (off by default — directories only).
        #[arg(long)]
        files: bool,
    },
    /// Filter a remote listing by name, size, and modified time.
    Find {
        path: String,
        /// Glob pattern matched against the object basename.
        #[arg(long, value_name = "GLOB")]
        name: Option<String>,
        /// Size filter: `+N` = ≥, `-N` = ≤, `N` = exact. Suffixes: k/K, m/M, g/G (decimal) or ki/Ki, mi/Mi, gi/Gi (binary).
        #[arg(long, value_name = "EXPR")]
        size: Option<String>,
        /// Only entries older than this duration (e.g. `7d`, `30m`).
        #[arg(long, value_name = "DUR")]
        older_than: Option<String>,
        /// Only entries newer than this duration.
        #[arg(long, value_name = "DUR")]
        newer_than: Option<String>,
    },
    /// Search objects by a label query: `alias/`, `alias/bucket`, or
    /// `alias/bucket/prefix`. Operators: `==` `!=` `=~` (regex) `^=` (prefix)
    /// `$=` (suffix); combine with `and`/`or`/`not` and parentheses.
    Search {
        /// Remote scope: `alias/` (all buckets), `alias/bucket`, or `alias/bucket/prefix`.
        path: String,
        /// Label query, e.g. `env == prod and tier != test`.
        #[arg(long, value_name = "EXPR")]
        query: String,
    },
    /// Compare two trees and report what differs.
    Diff { src: String, dst: String },
    /// rsync-style one-way sync from src to dst.
    Mirror {
        src: String,
        dst: String,
        /// Overwrite destination entries when checksums differ.
        #[arg(long)]
        overwrite: bool,
        /// Delete destination entries that are not present in source.
        #[arg(long)]
        remove: bool,
        /// Glob patterns excluded from the sync.
        #[arg(long, value_name = "GLOB", number_of_values = 1)]
        exclude: Vec<String>,
    },
    /// Stream live PUT/DELETE/GET/HEAD events matching a remote prefix.
    Watch {
        path: String,
        /// Restrict to specific HTTP methods (default: PUT, DELETE, GET, HEAD).
        #[arg(long, value_name = "METHOD", number_of_values = 1)]
        event: Vec<String>,
    },
    /// Probe liveness of a server alias.
    Ping {
        alias: String,
        /// Number of probes to send.
        #[arg(long, default_value_t = 4)]
        count: u32,
        /// Interval between probes in milliseconds.
        #[arg(long, default_value_t = 1000)]
        interval: u64,
        /// Print only failed probes.
        #[arg(long)]
        error_only: bool,
    },
    /// Single readiness check; exit status is non-zero if the alias is not ready.
    Ready { alias: String },

    /// Create a bucket.
    Mb {
        target: String,
        #[arg(long)]
        ignore_existing: bool,
    },
    /// Remove a bucket and all its objects.
    Rb {
        target: String,
        #[arg(long)]
        force: bool,
    },
    /// Manage object tags (labels).
    Tag {
        #[command(subcommand)]
        cmd: TagCmd,
    },
    /// Manage object attributes (labels; same store as tags).
    Attribute {
        #[command(subcommand)]
        cmd: AttributeCmd,
    },
    /// Manage per-bucket size quotas.
    Quota {
        #[command(subcommand)]
        cmd: QuotaCmd,
    },
    /// Manage a bucket's recorded default encryption (informational).
    Encrypt {
        #[command(subcommand)]
        cmd: EncryptCmd,
    },

    /// Manage users and admin operations.
    Admin {
        #[command(subcommand)]
        cmd: AdminCmd,
    },
    /// Launch the interactive TUI file explorer.
    Tui,
    /// Print a shell completion script to stdout.
    ///
    /// Example: y2q completions fish > ~/.config/fish/completions/y2q.fish
    Completions {
        #[arg(value_name = "SHELL")]
        shell: Shell,
    },
}

#[derive(Subcommand, Debug)]
pub enum TagCmd {
    /// Set tags on an object (KEY=VALUE pairs; merges into existing).
    Set {
        target: String,
        #[arg(value_name = "KEY=VALUE")]
        tags: Vec<String>,
    },
    /// List tags on an object.
    #[command(alias = "ls")]
    List { target: String },
    /// Remove all tags from an object.
    #[command(alias = "rm")]
    Remove { target: String },
}

#[derive(Subcommand, Debug)]
pub enum AttributeCmd {
    /// Set attributes (KEY=VALUE pairs; merges into existing).
    Set {
        target: String,
        #[arg(value_name = "KEY=VALUE")]
        attrs: Vec<String>,
    },
    /// List attributes.
    #[command(alias = "ls")]
    List { target: String },
    /// Remove all attributes.
    #[command(alias = "rm")]
    Remove { target: String },
}

#[derive(Subcommand, Debug)]
pub enum QuotaCmd {
    /// Set a bucket size quota (e.g. 500m, 2g).
    Set {
        target: String,
        #[arg(long)]
        size: String,
    },
    /// Clear a bucket quota.
    Clear { target: String },
    /// Show a bucket quota.
    Info { target: String },
}

#[derive(Subcommand, Debug)]
pub enum EncryptCmd {
    /// Record a bucket's default SSE algorithm (informational).
    Set {
        target: String,
        algo: Option<String>,
    },
    /// Show the bucket's recorded default SSE.
    Info { target: String },
    /// Clear the bucket's recorded default SSE.
    Clear { target: String },
}

#[derive(Subcommand, Debug)]
pub enum AliasCmd {
    /// Add or update a server alias entry.
    Set {
        alias: String,
        url: String,
        #[arg(long, short)]
        user: Option<String>,
        /// Skip TLS certificate verification (dangerous - dev/staging only).
        #[arg(long)]
        insecure: bool,
        /// Path to a PEM CA bundle used to verify the server certificate.
        #[arg(long, value_name = "PATH")]
        ca_cert: Option<std::path::PathBuf>,
        /// Path to a PEM client certificate (mutual TLS); requires --client-key.
        #[arg(long, value_name = "PATH", requires = "client_key")]
        client_cert: Option<std::path::PathBuf>,
        /// Path to a PEM client private key (mutual TLS); requires --client-cert.
        #[arg(long, value_name = "PATH", requires = "client_cert")]
        client_key: Option<std::path::PathBuf>,
    },
    /// List configured aliases.
    #[command(alias = "ls")]
    List,
    /// Remove an alias.
    #[command(alias = "rm")]
    Remove { alias: String },
    /// Print all aliases as TOML on stdout.
    Export,
    /// Read alias entries from stdin (TOML) and merge into the configured set.
    Import {
        /// Overwrite existing entries with the same name instead of skipping them.
        #[arg(long)]
        merge: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum AdminCmd {
    /// Manage users.
    User {
        #[command(subcommand)]
        cmd: UserCmd,
    },
    /// Manage the metadata index rebuild.
    Rebuild {
        #[command(subcommand)]
        cmd: RebuildCmd,
    },
    /// Manage stale write locks.
    Locks {
        #[command(subcommand)]
        cmd: LocksCmd,
    },
    /// Stream live request/response trace from a server.
    Trace {
        alias: String,
        /// Show only requests with status 400 or above.
        #[arg(long, short = 'e')]
        errors: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum UserCmd {
    /// Add a new user.
    Add {
        alias: String,
        username: String,
        #[arg(long, short)]
        password: Option<String>,
    },
    /// List users.
    #[command(alias = "ls")]
    List { alias: String },
    /// Delete a user.
    #[command(alias = "rm")]
    Remove { alias: String, username: String },
}

#[derive(Subcommand, Debug)]
pub enum RebuildCmd {
    /// Start a metadata index rebuild.
    Start { alias: String },
    /// Show current rebuild status.
    Status { alias: String },
}

#[derive(Subcommand, Debug)]
pub enum LocksCmd {
    /// List stale write locks.
    #[command(alias = "ls")]
    List {
        alias: String,
        #[arg(long)]
        older_than: String,
    },
    /// Clear stale write locks.
    Clear {
        alias: String,
        #[arg(long)]
        older_than: String,
    },
}
