//! `y2q-keyarm` — root-pre hook that arms the key helper for the next fetch.
//!
//! Shipped as a separate binary from `y2qd` so `ExecStartPre=+` does not point
//! at the network daemon inode. Install mode `0700 root:root` (or `0750
//! root:y2q`); never hardlink to `y2qd`.

use std::path::PathBuf;

use clap::Parser;

/// CLI for the arm-only helper. No daemon, `--key-serve`, or `--key-sweep`.
#[derive(Parser, Debug)]
#[command(
    name = "y2q-keyarm",
    version,
    about = "Arm the y2q key helper for the next daemon fetch (root-pre hook)"
)]
struct Cli {
    /// Path to the configuration file. Defaults to `config.toml` in the working directory.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Override a config value, e.g. `--set server.port=9090`.
    #[arg(short = 's', long = "set", value_name = "KEY=VALUE", value_parser = parse_key_value)]
    overrides: Vec<(String, String)>,

    /// Prompt on the terminal for a home-device passcode and send it over the socket.
    #[arg(long)]
    prompt_passcode: bool,

    /// Prompt on the terminal for a FIDO2 PIN and send it over the socket.
    #[arg(long)]
    prompt_pin: bool,

    /// Prompt on the terminal for an emergency code and send it over the socket.
    #[arg(long)]
    prompt_emergency_code: bool,
}

fn parse_key_value(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected KEY=VALUE, got {s:?}"))
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("y2q-keyarm: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> std::io::Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cli;
        return Err(std::io::Error::other("y2q-keyarm requires Linux"));
    }
    #[cfg(target_os = "linux")]
    {
        let cfg = y2qd::config::Config::load(cli.config.as_deref(), &cli.overrides)
            .map_err(|e| std::io::Error::other(format!("failed to load config: {e}")))?;
        y2qd::key_agent::run_arm(
            &cfg,
            y2qd::key_agent::ArmFlags {
                passcode: cli.prompt_passcode,
                pin: cli.prompt_pin,
                emergency_code: cli.prompt_emergency_code,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("y2q-keyarm").chain(args.iter().copied()))
    }

    #[test]
    fn parses_config_and_prompt_flags() {
        let cli = parse(&[
            "--config",
            "/etc/y2q/config.toml",
            "--prompt-passcode",
            "--prompt-pin",
            "--set",
            "server.port=9",
        ])
        .unwrap();
        assert_eq!(
            cli.config.as_deref(),
            Some(std::path::Path::new("/etc/y2q/config.toml"))
        );
        assert!(cli.prompt_passcode);
        assert!(cli.prompt_pin);
        assert!(!cli.prompt_emergency_code);
        assert_eq!(cli.overrides, vec![("server.port".into(), "9".into())]);
    }

    #[test]
    fn does_not_expose_key_serve_or_daemon_flags() {
        let help = Cli::command().render_long_help().to_string();
        for flag in [
            "--key-serve",
            "--key-sweep",
            "--key-arm",
            "--rotate-node-key",
            "--upgrade-container-headers",
            "setup",
        ] {
            assert!(
                !help.contains(flag),
                "help must not advertise {flag}: {help}"
            );
        }
        assert!(parse(&["--key-serve"]).is_err());
        assert!(parse(&["--key-arm"]).is_err());
        assert!(parse(&["setup"]).is_err());
    }
}
