use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "y2q", about = "Post-quantum secure object storage CLI")]
pub struct Cli {
    #[arg(long, short, global = true, env = "Y2Q_OUTPUT", value_name = "FORMAT")]
    /// Output as JSON
    pub json: bool,

    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    /// Increase verbosity (pass multiple times)
    pub verbose: u8,

    #[arg(long, global = true, value_name = "PATH")]
    /// Config file path [default: ~/.config/y2q/config.toml]
    pub config: Option<std::path::PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Manage server profiles
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// Log in to a server profile and cache the session token
    Login {
        alias: String,
        #[arg(long, short)]
        user: Option<String>,
        #[arg(long, short)]
        password: Option<String>,
        #[arg(long, value_name = "SECONDS")]
        ttl: Option<u64>,
    },
    /// Revoke the cached session token for a profile
    Logout { alias: String },
    /// Change password for a profile
    Passwd {
        alias: String,
        #[arg(long)]
        current: Option<String>,
        #[arg(long)]
        new: Option<String>,
    },
    /// Copy a file between local and remote storage
    Cp {
        src: String,
        dst: String,
        #[arg(long, value_name = "KEY=VALUE", number_of_values = 1)]
        label: Vec<String>,
        #[arg(long, value_name = "durable|best-effort")]
        sync: Option<String>,
    },
    /// Delete a remote object
    Rm { path: String },
    /// Show metadata for a remote object
    Stat { path: String },
    /// Stream a remote object to stdout
    Cat { path: String },
    /// List buckets or objects
    Ls {
        path: Option<String>,
        #[arg(long)]
        limit: Option<u32>,
        #[arg(long, conflicts_with = "all")]
        after: Option<String>,
        #[arg(long, conflicts_with = "after")]
        all: bool,
    },
    /// Manage users and admin operations
    Admin {
        #[command(subcommand)]
        cmd: AdminCmd,
    },
    /// Launch the interactive TUI file explorer
    Tui,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    /// Add or update a server profile
    Add {
        alias: String,
        url: String,
        #[arg(long, short)]
        user: Option<String>,
    },
    /// List configured profiles
    Ls,
    /// Remove a profile
    Rm { alias: String },
}

#[derive(Subcommand, Debug)]
pub enum AdminCmd {
    /// Manage users
    User {
        #[command(subcommand)]
        cmd: UserCmd,
    },
    /// Manage the metadata index rebuild
    Rebuild {
        #[command(subcommand)]
        cmd: RebuildCmd,
    },
    /// Manage stale write locks
    Locks {
        #[command(subcommand)]
        cmd: LocksCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum UserCmd {
    /// Add a new user
    Add {
        alias: String,
        username: String,
        #[arg(long, short)]
        password: Option<String>,
    },
    /// List users
    Ls { alias: String },
    /// Delete a user
    Rm { alias: String, username: String },
}

#[derive(Subcommand, Debug)]
pub enum RebuildCmd {
    /// Start a metadata index rebuild
    Start { alias: String },
    /// Show current rebuild status
    Status { alias: String },
}

#[derive(Subcommand, Debug)]
pub enum LocksCmd {
    /// List stale write locks
    Ls {
        alias: String,
        #[arg(long)]
        older_than: String,
    },
    /// Clear stale write locks
    Clear {
        alias: String,
        #[arg(long)]
        older_than: String,
    },
}
