use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about = "y2qd — post-quantum secure object store daemon")]
pub struct Cli {
    /// Path to the configuration file. Defaults to `config.toml` in the working directory.
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Override a config value, e.g. `--set server.port=9090`.
    /// Keys use dotted notation matching the TOML structure. May be repeated.
    /// Values are interpreted as integers, booleans, or strings in that order.
    #[arg(short = 's', long = "set", value_name = "KEY=VALUE", value_parser = parse_key_value)]
    pub overrides: Vec<(String, String)>,

    /// Run an offline node-key rotation instead of starting the server: walk
    /// every object and bucket in `storage.base_path`, re-deriving every
    /// node-derived key under the new node key, then exit. Requires the
    /// keystore flock (refuses if a daemon is already running against this
    /// keystore). The old key comes from the normal supply path
    /// (`Y2QD_NODE_KEY` / `[crypto] node_key_file`); the new key from
    /// `Y2QD_NEW_NODE_KEY` or `--new-node-key-file`.
    #[arg(long)]
    pub rotate_node_key: bool,

    /// Serve exactly one key-helper connection from standard input, then exit.
    /// Meant to be spawned by a systemd socket unit with `Accept=yes` (stdin is
    /// the accepted unix socket) under the key-owner uid: handles one `arm` or
    /// `fetch` request from `[crypto.devices] key_agent_socket` and never keeps
    /// RMK past the process. Opens no storage or user store.
    #[arg(long, conflicts_with_all = ["key_sweep", "key_arm", "rotate_node_key", "upgrade_container_headers"])]
    pub key_serve: bool,

    /// One-shot grant sweep / re-mint (run from a systemd timer): unlock the
    /// registry with a home device that needs no second factor, refresh grants,
    /// and exit. A home device with a passcode or FIDO2 factor cannot be
    /// unlocked unattended; that is logged and the exit status is 0.
    #[arg(long, conflicts_with_all = ["key_serve", "key_arm", "rotate_node_key", "upgrade_container_headers"])]
    pub key_sweep: bool,

    /// Arm the key helper for the next `fetch`: send one-time authorization to
    /// `[crypto.devices] key_agent_socket` (run as `key_agent_arm_uid`, default
    /// root). Without a `--prompt-*` flag it arms with empty authorization.
    #[arg(long, conflicts_with_all = ["key_serve", "key_sweep", "rotate_node_key", "upgrade_container_headers"])]
    pub key_arm: bool,

    /// With `--key-arm`: prompt on the terminal for a home-device passcode and
    /// send it over the socket.
    #[arg(long, requires = "key_arm")]
    pub prompt_passcode: bool,

    /// With `--key-arm`: prompt on the terminal for a FIDO2 PIN and send it
    /// over the socket.
    #[arg(long, requires = "key_arm")]
    pub prompt_pin: bool,

    /// With `--key-arm`: prompt on the terminal for an emergency code and send
    /// it over the socket.
    #[arg(long, requires = "key_arm")]
    pub prompt_emergency_code: bool,

    /// New node key material for `--rotate-node-key`, as a file path (same
    /// hex/base64/raw encoding rules as `[crypto] node_key_file`).
    /// `Y2QD_NEW_NODE_KEY` takes precedence when set.
    #[arg(long, value_name = "FILE")]
    pub new_node_key_file: Option<PathBuf>,

    /// Re-MAC every object's 64-byte container header instead of starting the
    /// server, then exit. Needed once when upgrading a deployment written
    /// before the header carried an HMAC: version-1 headers no longer decode,
    /// so objects are unreadable until this has run.
    ///
    /// Rewrites only 128 bytes per object (header + trailer) and skips files
    /// already at version 2, so it is fast and safe to re-run after an
    /// interruption. Takes the same keystore flock as `--rotate-node-key` and
    /// refuses to run against a live daemon.
    #[arg(long)]
    pub upgrade_container_headers: bool,
}

fn parse_key_value(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected KEY=VALUE, got {s:?}"))
}
