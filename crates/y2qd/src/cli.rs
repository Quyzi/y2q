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
}

fn parse_key_value(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected KEY=VALUE, got {s:?}"))
}
