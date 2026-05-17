mod cli;
mod cmd;
mod config;
mod error;
mod output;
mod path;
mod progress;
mod token;
mod tui;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use cli::{AdminCmd, Cli, Commands};
use config::{CliConfig, default_config_path};
use error::CliError;
use output::OutputMode;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .with_writer(std::io::stderr)
        .init();

    if let Err(e) = run(cli).await {
        eprintln!("error: {e}");
        std::process::exit(e.exit_code());
    }
}

async fn run(cli: Cli) -> Result<(), CliError> {
    let mode = if cli.json {
        OutputMode::Json
    } else {
        OutputMode::Human
    };

    match cli.command {
        None | Some(Commands::Tui) => {
            let config_path = cli
                .config
                .unwrap_or_else(|| default_config_path().unwrap_or_default());
            let config = CliConfig::load(&config_path)?;
            tui::run_tui(config).await
        }
        Some(Commands::Config { cmd }) => cmd::config::run(cmd, mode).await,
        Some(Commands::Login {
            alias,
            user,
            password,
            ttl,
        }) => cmd::auth::login(&alias, user, password, ttl, mode).await,
        Some(Commands::Logout { alias }) => cmd::auth::logout(&alias, mode).await,
        Some(Commands::Passwd {
            alias,
            current,
            new,
        }) => cmd::auth::passwd(&alias, current, new, mode).await,
        Some(Commands::Ls {
            path,
            limit,
            after,
            all,
        }) => cmd::listing::run(path, limit, after, all, mode).await,
        Some(Commands::Rm { path, force }) => cmd::objects::rm(path, force, mode).await,
        Some(Commands::Stat { path }) => cmd::objects::stat(path, mode).await,
        Some(Commands::Cat { path }) => cmd::objects::cat(path).await,
        Some(Commands::Cp {
            src,
            dst,
            label,
            sync,
            recursive,
        }) => cmd::cp::run(src, dst, label, sync, recursive, mode).await,
        Some(Commands::Completions { shell }) => {
            cmd::completions::run(shell);
            Ok(())
        }
        Some(Commands::Admin { cmd }) => match cmd {
            AdminCmd::User { cmd } => cmd::users::run(cmd, mode).await,
            AdminCmd::Rebuild { cmd } => cmd::admin::rebuild(cmd, mode).await,
            AdminCmd::Locks { cmd } => cmd::admin::locks(cmd, mode).await,
            AdminCmd::Trace { alias, errors } => cmd::admin::trace(&alias, errors).await,
        },
    }
}
