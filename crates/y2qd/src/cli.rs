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

    /// New node key material for `--rotate-node-key`, as a file path (same
    /// hex/base64/raw encoding rules as `[crypto] node_key_file`).
    /// `Y2QD_NEW_NODE_KEY` takes precedence when set.
    #[arg(long, value_name = "FILE")]
    pub new_node_key_file: Option<PathBuf>,
}

fn parse_key_value(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected KEY=VALUE, got {s:?}"))
}
