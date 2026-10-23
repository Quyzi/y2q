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
        #[arg(long, short, allow_hyphen_values = true)]
        user: Option<String>,
        #[arg(long, short, allow_hyphen_values = true)]
        password: Option<String>,
        #[arg(long, value_name = "SECONDS")]
        ttl: Option<u64>,
    },
    /// Revoke the cached session token for an alias.
    Logout { alias: String },
    /// Change password for an alias.
    Passwd {
        alias: String,
        #[arg(long, allow_hyphen_values = true)]
        current: Option<String>,
        #[arg(long, allow_hyphen_values = true)]
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
    Get {
        src: String,
        dst: String,
        /// Download only an inclusive byte range, e.g. `--range 0-1023`.
        #[arg(long, value_name = "START-END")]
        range: Option<String>,
    },
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
    Cat {
        path: String,
        /// Output only an inclusive byte range, e.g. `--range 0-1023`.
        #[arg(long, value_name = "START-END")]
        range: Option<String>,
    },
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
        #[arg(long, conflicts_with = "all", allow_hyphen_values = true)]
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
        #[arg(long, value_name = "GLOB", allow_hyphen_values = true)]
        name: Option<String>,
        /// Size filter: `+N` = ≥, `-N` = ≤, `N` = exact. Suffixes: k/K, m/M, g/G (decimal) or ki/Ki, mi/Mi, gi/Gi (binary).
        #[arg(long, value_name = "EXPR", allow_hyphen_values = true)]
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
        #[arg(
            long,
            value_name = "GLOB",
            number_of_values = 1,
            allow_hyphen_values = true
        )]
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
    /// Manage your own personas (multiple passwords per account, usable as
    /// duress passwords). Ordinary user commands - not admin subcommands.
    Persona {
        #[command(subcommand)]
        cmd: PersonaCmd,
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
        #[arg(long, short, allow_hyphen_values = true)]
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
    /// Manage per-bucket ownership and access-control lists.
    Acl {
        #[command(subcommand)]
        cmd: AclCmd,
    },
    /// Create a new bucket key epoch. New writes use it immediately;
    /// existing objects keep decrypting under their own epoch until
    /// `rekey` migrates them.
    RotateKey { alias: String, bucket: String },
    /// Migrate a bucket's existing objects onto its newest key epoch and
    /// prune retired ones.
    Rekey {
        #[command(subcommand)]
        cmd: RekeyCmd,
    },
    /// Stream live request/response trace from a server.
    Trace {
        alias: String,
        /// Show only requests with status 400 or above.
        #[arg(long, short = 'e')]
        errors: bool,
    },
    /// Generate a random 32-byte node key (standard base64), for
    /// `[crypto] node_key_file` or `Y2QD_NODE_KEY`. Pure local generator —
    /// takes no alias, makes no HTTP call.
    ///
    /// Without --output the key is printed to stdout; a shell redirect
    /// (`> file`) creates the file with your umask (usually world-readable) and
    /// the daemon refuses to start on such a file. Prefer --output.
    GenNodeKey {
        /// Write the key to PATH instead of stdout. The file is created
        /// exclusively with mode 0400 (unix); an existing path is never overwritten.
        #[arg(long, short = 'o', value_name = "PATH")]
        output: Option<std::path::PathBuf>,
    },
    /// Manage the hardware devices that can unlock this deployment's node key.
    /// Local keystore surgery: no alias, no HTTP. Mutating subcommands require the
    /// daemon to be stopped (`systemctl stop y2qd`), because it holds the keystore lock.
    ///
    /// Device commands must run as the registry owner: the user that owns `devices.json`,
    /// normally the key-agent user (for example `sudo -u y2q-keyd y2q admin device ...`).
    /// A root-owned registry cannot be read or swept by the key agent.
    Device {
        #[command(subcommand)]
        cmd: DeviceCmd,
    },
    /// Show which of the ten one-time emergency codes remain unused. Never prints the
    /// codes themselves — they are displayed exactly once, by `device init`.
    EmergencyKeys {
        #[arg(long, value_name = "DIR")]
        keystore_dir: std::path::PathBuf,
    },
    /// Reset a user's identity keypair and password. Restores login; does
    /// not restore bucket access (every grant they held is scrubbed, since
    /// it was sealed to the identity keypair this replaces).
    ResetIdentity {
        alias: String,
        username: String,
        #[arg(long, short, allow_hyphen_values = true)]
        password: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum UserCmd {
    /// Add a new user.
    Add {
        alias: String,
        username: String,
        #[arg(long, short, allow_hyphen_values = true)]
        password: Option<String>,
        /// Global role for the new user: `admin` or `user` (default).
        #[arg(long, default_value = "user")]
        role: String,
    },
    /// List users.
    #[command(alias = "ls")]
    List { alias: String },
    /// Delete a user.
    #[command(alias = "rm")]
    Remove {
        alias: String,
        username: String,
        /// Delete even if this user owns a bucket that would become
        /// unrecoverable (no other identity could ever open its bucket key
        /// again).
        #[arg(long)]
        force: bool,
    },
    /// Change a user's global role.
    Role {
        alias: String,
        username: String,
        /// New role: admin, user, readonly, writeonly, auditor, or disabled.
        role: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum AclCmd {
    /// Show a bucket's owner and grants.
    #[command(alias = "show")]
    Get { alias: String, bucket: String },
    /// Grant a user read/write/admin access to a bucket.
    Grant {
        alias: String,
        bucket: String,
        username: String,
        /// Permission level: `read`, `write`, or `admin`.
        permission: String,
    },
    /// Revoke a user's access to a bucket.
    Revoke {
        alias: String,
        bucket: String,
        username: String,
    },
    /// Transfer ownership of a bucket to another user.
    Chown {
        alias: String,
        bucket: String,
        username: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum RebuildCmd {
    /// Start a metadata index rebuild.
    Start { alias: String },
    /// Show current rebuild status.
    Status { alias: String },
}

#[derive(Subcommand, Debug)]
pub enum RekeyCmd {
    /// Start a bucket rekey.
    Start { alias: String, bucket: String },
    /// Show the current rekey status for a bucket.
    Status { alias: String, bucket: String },
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

#[derive(Subcommand, Debug)]
pub enum PersonaCmd {
    /// Write (or overwrite) a persona into a credential slot
    /// (`0..CREDENTIAL_SLOTS`). No slot is privileged - each account's real
    /// identity lives at a slot chosen randomly on creation, changed via
    /// `y2q passwd`. The server refuses to overwrite whichever slot the
    /// current session is authenticated through.
    Add {
        alias: String,
        #[arg(long)]
        slot: u8,
        /// Effective role for sessions opened through this persona: admin,
        /// user, readonly, writeonly, auditor, or disabled. Must not exceed
        /// the account's own global role. Defaults to the account's role.
        #[arg(long)]
        role: Option<String>,
        /// Revoke every other live session of this account on login
        /// through this persona - what makes it usable as a duress slot.
        #[arg(long)]
        duress: bool,
    },
    /// Overwrite a persona slot (excluding the one the current session is
    /// authenticated through) with a fresh decoy and revoke any live
    /// session opened through it.
    #[command(alias = "remove")]
    Rm {
        alias: String,
        #[arg(long)]
        slot: u8,
    },
    /// Show the current session's persona slot and role. The server never
    /// reports the duress flag, even for your own session.
    Whoami { alias: String },
    /// Share buckets your current persona holds with one of your own
    /// other personas.
    Grant {
        alias: String,
        #[arg(long)]
        slot: u8,
        buckets: Vec<String>,
    },
    /// Revoke a persona's access to buckets (your own persona keeps its
    /// access).
    Revoke {
        alias: String,
        #[arg(long)]
        slot: u8,
        buckets: Vec<String>,
    },
}

/// One `--roughtime-server NAME=ADDR=KEY_B64` value.
// Fields are read only by the device-enabled build.
#[cfg_attr(not(all(target_os = "linux", feature = "devices")), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoughtimeServerArg {
    pub name: String,
    pub addr: String,
    pub public_key_b64: String,
}

/// Split on the first two `=` only: a base64 key ends in `=`.
pub fn parse_roughtime_server(s: &str) -> Result<RoughtimeServerArg, String> {
    let mut parts = s.splitn(3, '=');
    let (Some(name), Some(addr), Some(key)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(format!("expected NAME=ADDR=KEY_B64, got `{s}`"));
    };
    if name.is_empty() || addr.is_empty() || key.is_empty() {
        return Err(format!("expected NAME=ADDR=KEY_B64, got `{s}`"));
    }
    Ok(RoughtimeServerArg {
        name: name.to_owned(),
        addr: addr.to_owned(),
        public_key_b64: key.to_owned(),
    })
}

/// Roughtime flags shared by every device command that can read attested time.
/// The CLI reads no `config.toml`, so these are the only source of servers.
// Fields are read only by the device-enabled build.
#[cfg_attr(not(all(target_os = "linux", feature = "devices")), allow(dead_code))]
#[derive(clap::Args, Debug, Clone)]
pub struct RoughtimeArgs {
    /// Roughtime server as NAME=ADDR=KEY_B64 (repeatable). KEY_B64 is the server's
    /// base64 Ed25519 public key.
    #[arg(long = "roughtime-server", value_name = "NAME=ADDR=KEY_B64", value_parser = parse_roughtime_server)]
    pub roughtime_server: Vec<RoughtimeServerArg>,
    /// Number of independent servers that must answer.
    #[arg(long, value_name = "N", default_value_t = 2)]
    pub roughtime_min_responses: u8,
    /// Per-server query timeout in milliseconds.
    #[arg(long, value_name = "MS", default_value_t = 3000)]
    pub roughtime_timeout_ms: u64,
}

// Fields are read only by the device-enabled build.
#[cfg_attr(not(all(target_os = "linux", feature = "devices")), allow(dead_code))]
#[derive(Subcommand, Debug)]
pub enum DeviceCmd {
    /// Create the device registry with its first device and print the ten
    /// one-time emergency codes (once).
    Init {
        #[arg(long, value_name = "DIR")]
        keystore_dir: std::path::PathBuf,
        /// First device is a TPM 2.0 home device.
        #[arg(long, conflicts_with = "fido2")]
        tpm: bool,
        /// First device is a FIDO2 away device (requires --permanent-away).
        #[arg(long)]
        fido2: bool,
        /// Device label (default `home-tpm` with --tpm, `away-fido2` with --fido2).
        #[arg(long)]
        label: Option<String>,
        #[arg(long, value_name = "STR", default_value = "device:/dev/tpmrm0")]
        tpm_tcti: String,
        /// SHA-256 PCR indices the TPM policy is bound to. 7 alone survives kernel and
        /// initrd updates; adding 0 or 4 binds firmware and the boot binary but requires
        /// `device reseal-tpm` — which needs a home device or an emergency code — after
        /// every such update.
        #[arg(long, value_delimiter = ',', default_value = "7")]
        pcrs: Vec<u8>,
        /// Register the authenticator without user verification (no PIN).
        #[arg(long)]
        no_uv: bool,
        /// HID path of the authenticator when several are attached.
        #[arg(long, value_name = "PATH")]
        hid_path: Option<String>,
        /// How long an away device may unlock after a home unlock, in seconds
        /// (60 .. 2592000). Fixed at init and bound into the node-key wrap, so it cannot
        /// be changed by editing the registry — use `device set-grant-period`.
        #[arg(long, value_name = "SECONDS", default_value_t = 43_200)]
        away_grant_seconds: u32,
        /// With zero home devices, give FIDO2 devices a permanent wrap (no time-box).
        #[arg(long, requires = "fido2")]
        permanent_away: bool,
        /// Wrap the node key this deployment already uses instead of generating one.
        #[arg(long)]
        adopt_existing_node_key: bool,
        /// File holding the existing node key (with --adopt-existing-node-key);
        /// `Y2QD_NODE_KEY` is honoured. The file must have no group/other
        /// permission bits (e.g. 0400).
        #[arg(long, value_name = "PATH")]
        node_key_file: Option<std::path::PathBuf>,
        /// Accept a PCR-7 policy that any bootable medium can satisfy (Secure Boot
        /// not enforcing). For test rigs only.
        #[arg(long)]
        allow_secure_boot_off: bool,
        #[command(flatten)]
        roughtime: RoughtimeArgs,
    },
    /// Register a TPM 2.0 home device.
    AddTpm {
        #[arg(long, value_name = "DIR")]
        keystore_dir: std::path::PathBuf,
        #[arg(long, default_value = "home-tpm")]
        label: String,
        #[arg(long, value_name = "STR", default_value = "device:/dev/tpmrm0")]
        tpm_tcti: String,
        /// SHA-256 PCR indices the TPM policy is bound to. 7 alone survives kernel and
        /// initrd updates; adding 0 or 4 binds firmware and the boot binary but requires
        /// `device reseal-tpm` — which needs a home device or an emergency code — after
        /// every such update.
        #[arg(long, value_delimiter = ',', default_value = "7")]
        pcrs: Vec<u8>,
        /// Accept a PCR-7 policy that any bootable medium can satisfy (Secure Boot
        /// not enforcing). For test rigs only.
        #[arg(long)]
        allow_secure_boot_off: bool,
        #[command(flatten)]
        roughtime: RoughtimeArgs,
    },
    /// Register a FIDO2 away device.
    AddFido2 {
        #[arg(long, value_name = "DIR")]
        keystore_dir: std::path::PathBuf,
        #[arg(long, default_value = "away-fido2")]
        label: String,
        /// Register the authenticator without user verification (no PIN).
        #[arg(long)]
        no_uv: bool,
        /// HID path of the authenticator when several are attached.
        #[arg(long, value_name = "PATH")]
        hid_path: Option<String>,
        #[arg(long, value_name = "STR", default_value = "device:/dev/tpmrm0")]
        tpm_tcti: String,
        #[command(flatten)]
        roughtime: RoughtimeArgs,
    },
    /// List registered devices (read-only; works against a running daemon).
    #[command(alias = "ls")]
    List {
        #[arg(long, value_name = "DIR")]
        keystore_dir: std::path::PathBuf,
    },
    /// Remove a registered device by id or label.
    #[command(alias = "rm")]
    Remove {
        #[arg(long, value_name = "DIR")]
        keystore_dir: std::path::PathBuf,
        /// Device id or label.
        selector: String,
        #[arg(long, value_name = "STR", default_value = "device:/dev/tpmrm0")]
        tpm_tcti: String,
        #[command(flatten)]
        roughtime: RoughtimeArgs,
    },
    /// Re-seal a TPM device to the current PCR values.
    ResealTpm {
        #[arg(long, value_name = "DIR")]
        keystore_dir: std::path::PathBuf,
        /// Device id or label.
        id: String,
        #[arg(long, value_name = "STR", default_value = "device:/dev/tpmrm0")]
        tpm_tcti: String,
        #[command(flatten)]
        roughtime: RoughtimeArgs,
        /// Accept a PCR-7 policy that any bootable medium can satisfy (Secure Boot
        /// not enforcing). For test rigs only.
        #[arg(long)]
        allow_secure_boot_off: bool,
    },
    /// Set or clear the second factor of a TPM home device. With a factor the node
    /// can no longer boot unattended: each start must be armed with the factor
    /// (`y2qd --key-arm --prompt-passcode` / `--prompt-pin`).
    #[command(group(
        clap::ArgGroup::new("factor").required(true).multiple(false).args(["passcode", "fido2", "none"])
    ))]
    SetHomeFactor {
        #[arg(long, value_name = "DIR")]
        keystore_dir: std::path::PathBuf,
        /// Home (TPM) device id or label.
        selector: String,
        #[arg(long, value_name = "STR", default_value = "device:/dev/tpmrm0")]
        tpm_tcti: String,
        /// Use a passcode (prompted twice on the terminal) as the second factor.
        #[arg(long)]
        passcode: bool,
        /// Use a registered FIDO2 away device (label or id) as the second factor.
        #[arg(long, value_name = "LABEL_OR_ID")]
        fido2: Option<String>,
        /// Remove the second factor.
        #[arg(long)]
        none: bool,
        /// Argon2id memory cost of the passcode factor, in KiB.
        #[arg(long, value_name = "KIB", default_value_t = 65_536, conflicts_with_all = ["fido2", "none"])]
        passcode_m_cost_kib: u32,
        /// Argon2id iteration count of the passcode factor.
        #[arg(long, value_name = "N", default_value_t = 3, conflicts_with_all = ["fido2", "none"])]
        passcode_t_cost: u32,
        /// Argon2id parallelism of the passcode factor.
        #[arg(long, value_name = "N", default_value_t = 1, conflicts_with_all = ["fido2", "none"])]
        passcode_p_cost: u32,
        #[command(flatten)]
        roughtime: RoughtimeArgs,
    },
    /// Mint a fresh grant for every away device (home authority only).
    Refresh {
        #[arg(long, value_name = "DIR")]
        keystore_dir: std::path::PathBuf,
        #[arg(long, value_name = "STR", default_value = "device:/dev/tpmrm0")]
        tpm_tcti: String,
        #[command(flatten)]
        roughtime: RoughtimeArgs,
    },
    /// Change the away-grant period. Drops every existing grant.
    SetGrantPeriod {
        #[arg(long, value_name = "DIR")]
        keystore_dir: std::path::PathBuf,
        /// New period in seconds (60 .. 2592000).
        #[arg(long)]
        seconds: u32,
        #[arg(long, value_name = "STR", default_value = "device:/dev/tpmrm0")]
        tpm_tcti: String,
        #[command(flatten)]
        roughtime: RoughtimeArgs,
    },
    /// Re-sign a registry whose state MAC does not verify (drops every grant).
    RepairState {
        #[arg(long, value_name = "DIR")]
        keystore_dir: std::path::PathBuf,
        #[arg(long, value_name = "STR", default_value = "device:/dev/tpmrm0")]
        tpm_tcti: String,
        /// With zero home devices, allow an away device to authorize the repair.
        #[arg(long)]
        allow_away_repair: bool,
        /// Acknowledge that the printed inventory was reviewed; required to write.
        #[arg(long)]
        accept_current_inventory: bool,
    },
    /// Query the configured Roughtime servers and print the attested time.
    CheckTime {
        #[command(flatten)]
        roughtime: RoughtimeArgs,
    },
}
