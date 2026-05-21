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

    /// Reserved for compatibility with mc-style API negotiation. Currently a no-op.
    #[arg(long, global = true, value_name = "API")]
    pub api: Option<String>,

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
    /// Stream live request/response trace from a server (like `mc admin trace`).
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
