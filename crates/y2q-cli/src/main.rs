mod cli;
mod client_builder;
mod cmd;
mod config;
mod error;
mod output;
mod path;
mod progress;
mod stubs;
mod token;
mod tui;

use clap::{CommandFactory, Parser};
use tracing_subscriber::EnvFilter;

use cli::{AdminCmd, Cli, Commands};
use config::{CliConfig, default_config_path};
use error::CliError;
use output::OutputMode;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.no_color || std::env::var_os("NO_COLOR").is_some() {
        // Honor NO_COLOR universally for downstream code that consults the env.
        // SAFETY: single-threaded at startup.
        unsafe {
            std::env::set_var("NO_COLOR", "1");
        }
    }

    let effective_verbose = if cli.debug { 4 } else { cli.verbose };
    let filter = if cli.quiet && !cli.debug {
        "error"
    } else {
        match effective_verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
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

    let Some(command) = cli.command else {
        // Bare invocation: print help instead of launching the TUI. Run `y2q tui`
        // for the interactive explorer.
        Cli::command().print_help().ok();
        println!();
        return Ok(());
    };

    match command {
        Commands::Tui => {
            let config_path = cli
                .config
                .unwrap_or_else(|| default_config_path().unwrap_or_default());
            let config = CliConfig::load(&config_path)?;
            tui::run_tui(config).await
        }
        Commands::Alias { cmd } => cmd::alias::run(cmd, mode).await,
        Commands::Login {
            alias,
            user,
            password,
            ttl,
        } => cmd::auth::login(&alias, user, password, ttl, mode).await,
        Commands::Logout { alias } => cmd::auth::logout(&alias, mode).await,
        Commands::Passwd {
            alias,
            current,
            new,
        } => cmd::auth::passwd(&alias, current, new, mode).await,
        Commands::Ls {
            path,
            limit,
            after,
            all,
        } => cmd::listing::run(path, limit, after, all, mode).await,
        Commands::Rm { path, force } => cmd::objects::rm(path, force, mode).await,
        Commands::Stat { path } => cmd::objects::stat(path, mode).await,
        Commands::Cat { path } => cmd::objects::cat(path).await,
        Commands::Head { path, bytes } => cmd::head::run(path, bytes).await,
        Commands::Cp {
            src,
            dst,
            label,
            sync,
            recursive,
        } => cmd::cp::run(src, dst, label, sync, recursive, mode).await,
        Commands::Mv {
            src,
            dst,
            label,
            sync,
        } => cmd::mv::run(src, dst, label, sync, mode).await,
        Commands::Put {
            src,
            dst,
            label,
            sync,
            recursive,
        } => cmd::cp::run(src, dst, label, sync, recursive, mode).await,
        Commands::Get { src, dst } => cmd::cp::run(src, dst, Vec::new(), None, false, mode).await,
        Commands::Pipe { dst, label, sync } => cmd::pipe::run(dst, label, sync, mode).await,
        Commands::Du { path, depth } => cmd::du::run(path, depth, mode).await,
        Commands::Tree { path, depth, files } => cmd::tree::run(path, depth, files, mode).await,
        Commands::Find {
            path,
            name,
            size,
            older_than,
            newer_than,
        } => cmd::find::run(path, name, size, older_than, newer_than, mode).await,
        Commands::Diff { src, dst } => cmd::diff::run(src, dst, mode).await,
        Commands::Mirror {
            src,
            dst,
            overwrite,
            remove,
            exclude,
        } => {
            cmd::mirror::run(
                src,
                dst,
                cmd::mirror::Options {
                    overwrite,
                    remove,
                    exclude,
                },
                mode,
            )
            .await
        }
        Commands::Watch { path, event } => cmd::watch::run(path, event, mode).await,
        Commands::Ping {
            alias,
            count,
            interval,
            error_only,
        } => cmd::health::ping(&alias, count, interval, error_only, mode).await,
        Commands::Ready { alias } => cmd::health::ready(&alias, mode).await,

        // ── Tier 2 stubs ──
        Commands::Mb { .. } => cmd::stub::not_yet_supported(
            "mb",
            "needs a bucket-create endpoint (buckets are implicit on first PUT today)",
            mode,
        ),
        Commands::Rb { .. } => {
            cmd::stub::not_yet_supported("rb", "needs a bucket-delete endpoint", mode)
        }
        Commands::Tag { .. } => cmd::stub::not_yet_supported(
            "tag",
            "needs a labels-only PATCH route and a remove-all endpoint",
            mode,
        ),
        Commands::Attribute { .. } => {
            cmd::stub::not_yet_supported("attribute", "needs a labels-only PATCH route", mode)
        }
        Commands::Version { .. } => cmd::stub::not_yet_supported(
            "version",
            "needs object versioning in the storage backend",
            mode,
        ),
        Commands::Undo { .. } => {
            cmd::stub::not_yet_supported("undo", "needs object versioning", mode)
        }
        Commands::Retention { .. } => {
            cmd::stub::not_yet_supported("retention", "needs WORM object-lock metadata", mode)
        }
        Commands::Legalhold { .. } => {
            cmd::stub::not_yet_supported("legalhold", "needs a WORM legal-hold flag", mode)
        }
        Commands::Share { .. } => {
            cmd::stub::not_yet_supported("share", "needs a presigned-URL signing route", mode)
        }
        Commands::Anonymous { .. } => {
            cmd::stub::not_yet_supported("anonymous", "needs per-bucket access policy", mode)
        }
        Commands::Cors { .. } => {
            cmd::stub::not_yet_supported("cors", "needs per-bucket CORS metadata", mode)
        }
        Commands::Quota { .. } => {
            cmd::stub::not_yet_supported("quota", "needs per-bucket quota metadata", mode)
        }
        Commands::Inventory { .. } => {
            cmd::stub::not_yet_supported("inventory", "needs a scheduled inventory generator", mode)
        }
        Commands::Ilm { .. } => {
            cmd::stub::not_yet_supported("ilm", "needs a lifecycle engine", mode)
        }
        Commands::Encrypt { .. } => cmd::stub::not_yet_supported(
            "encrypt",
            "needs per-bucket default-SSE config (y2q encrypts unconditionally today)",
            mode,
        ),
        Commands::Event { .. } => {
            cmd::stub::not_yet_supported("event", "needs notification dispatch", mode)
        }
        Commands::Batch { .. } => {
            cmd::stub::not_yet_supported("batch", "needs a server-side YAML batch runner", mode)
        }

        Commands::Completions { shell } => {
            cmd::completions::run(shell);
            Ok(())
        }
        Commands::Admin { cmd } => match cmd {
            AdminCmd::User { cmd } => cmd::users::run(cmd, mode).await,
            AdminCmd::Rebuild { cmd } => cmd::admin::rebuild(cmd, mode).await,
            AdminCmd::Locks { cmd } => cmd::admin::locks(cmd, mode).await,
            AdminCmd::Trace { alias, errors } => cmd::admin::trace(&alias, errors).await,
        },
    }
}
