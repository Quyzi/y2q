mod analyze;
mod auth;
mod cli;
mod config;
mod display;
mod error;
mod generator;
mod metrics;
mod ops;
mod prepare;
mod recorder;
mod worker;

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use clap::Parser;
use tokio::sync::{mpsc, watch};
use tracing_subscriber::{EnvFilter, fmt};
use uuid::Uuid;
use zeroize::Zeroizing;

use auth::{build_client, resolve_token, spawn_refresh_task};
use cli::{Cli, Commands, WorkloadArgs};
use config::{MixedWeights, ObjSize, RunConfig, WorkloadConfig, parse_size};
use display::DisplayMsg;
use error::WarpError;
use generator::ObjectPool;
use ops::OpKind;
use prepare::{cleanup, prepare};
use recorder::Recorder;

#[tokio::main]
async fn main() {
    fmt().with_env_filter(EnvFilter::from_default_env()).with_writer(std::io::stderr).init();

    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("error: {e}");
        std::process::exit(e.exit_code());
    }
}

async fn run(cli: Cli) -> Result<(), WarpError> {
    match cli.command {
        Commands::Analyze(args) => {
            let skip_ns = parse_duration_ns(&args.skip)?;
            let paths: Vec<&std::path::Path> = args.files.iter().map(|p| p.as_path()).collect();
            analyze::run_analyze(&paths, args.op.as_deref(), skip_ns, args.out.as_deref())
        }

        Commands::Prepare(args) => {
            let alias = require_alias(&cli.alias)?;
            let (_, client, _, _) =
                init_client(&alias, &cli.config, args.password.as_deref()).await?;
            let obj_size = resolve_obj_size(
                &args.obj_size,
                args.obj_size_min.as_deref(),
                args.obj_size_max.as_deref(),
            )?;
            let run_id = Uuid::new_v4().to_string();
            prepare(&client, &args.bucket, &run_id, args.objects, &obj_size, 8, None).await?;
            println!("run_id: {run_id}");
            Ok(())
        }

        Commands::Cleanup(args) => {
            let alias = require_alias(&cli.alias)?;
            let (_, client, _, _) =
                init_client(&alias, &cli.config, args.password.as_deref()).await?;
            let prefix = match &args.run_id {
                Some(id) => format!("warp/{id}/"),
                None => "warp/".to_owned(),
            };
            cleanup(&client, &args.bucket, &prefix, 8).await?;
            Ok(())
        }

        Commands::Put(args) => {
            let alias = require_alias(&cli.alias)?;
            bench(&alias, &cli.config, OpKind::Put, args, None).await
        }
        Commands::Get(args) => {
            let alias = require_alias(&cli.alias)?;
            bench(&alias, &cli.config, OpKind::Get, args, None).await
        }
        Commands::Delete(args) => {
            let alias = require_alias(&cli.alias)?;
            bench(&alias, &cli.config, OpKind::Delete, args, None).await
        }
        Commands::Stat(args) => {
            let alias = require_alias(&cli.alias)?;
            bench(&alias, &cli.config, OpKind::Stat, args, None).await
        }
        Commands::List(args) => {
            let alias = require_alias(&cli.alias)?;
            bench(&alias, &cli.config, OpKind::List, args, None).await
        }

        Commands::Mixed(args) => {
            let alias = require_alias(&cli.alias)?;
            let weights = MixedWeights {
                get: args.get_weight,
                put: args.put_weight,
                delete: args.delete_weight,
                stat: args.stat_weight,
            };
            bench(&alias, &cli.config, OpKind::Put, args.common, Some(weights)).await
        }
    }
}

async fn bench(
    alias: &str,
    config_path: &Option<std::path::PathBuf>,
    op: OpKind,
    args: WorkloadArgs,
    mixed_weights: Option<MixedWeights>,
) -> Result<(), WarpError> {
    let (profile, client, expires_at, initial_token) =
        init_client(alias, config_path, args.password.as_deref()).await?;

    let duration = parse_duration(&args.duration)?;
    let obj_size = resolve_obj_size(
        &args.obj_size,
        args.obj_size_min.as_deref(),
        args.obj_size_max.as_deref(),
    )?;

    let run_id = Uuid::new_v4().to_string();
    let op_label = if mixed_weights.is_some() {
        "mixed".to_owned()
    } else {
        op.as_str().to_lowercase()
    };
    let output = args.output.unwrap_or_else(|| {
        let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
        std::path::PathBuf::from(format!("warp-{op_label}-{ts}.csv.zst"))
    });

    let needs_pool = matches!(op, OpKind::Get | OpKind::Delete | OpKind::Stat)
        || mixed_weights.is_some();

    // Display channel and task start before prepare so seeding appears in TUI.
    let (disp_tx, disp_rx) = mpsc::channel::<DisplayMsg>(32);
    let display_op = op;
    let mut display_task =
        tokio::spawn(display::run_display(disp_rx, display_op, duration));

    // Prepare phase — progress messages go through the TUI.
    let pool = if needs_pool {
        let progress_tx = disp_tx.clone();
        let result = prepare(
            &client,
            &args.bucket,
            &run_id,
            args.objects,
            &obj_size,
            args.concurrent,
            Some(progress_tx),
        )
        .await;
        match result {
            Ok(keys) => Some(ObjectPool::new(run_id.clone(), keys, args.objects)),
            Err(e) => {
                drop(disp_tx);
                let _ = display_task.await;
                return Err(e);
            }
        }
    } else {
        None
    };

    // If the user quit during prepare, stop here.
    if display_task.is_finished() {
        return Ok(());
    }

    // Token watch channel — workers read this to get the current bearer token for raw HTTP GETs.
    let (tok_tx, tok_rx) = watch::channel::<Zeroizing<String>>(initial_token);
    spawn_refresh_task(
        client.clone(),
        alias.to_owned(),
        profile.username.clone(),
        expires_at,
        tok_tx,
    );

    let workload = WorkloadConfig {
        op,
        objects: args.objects,
        run_id: run_id.clone(),
        mixed_weights,
    };

    let run_config = Arc::new(RunConfig {
        base_url: profile.url.clone(),
        bucket: args.bucket.clone(),
        concurrent: args.concurrent,
        duration,
        obj_size,
        output: output.clone(),
        no_cleanup: args.no_cleanup,
        workload,
    });

    let (rec_tx, rec_rx) = mpsc::channel::<metrics::OpRecord>(8192);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Recorder owns disp_tx; dropping it at end signals the display to finish.
    let recorder = Recorder::new(rec_rx, disp_tx, &output)?;
    let recorder_handle = tokio::spawn(recorder.run());

    let raw_http = client.inner_client().clone();
    let put_seq = Arc::new(AtomicU64::new(args.objects as u64));

    let mut worker_handles = Vec::new();
    for _ in 0..args.concurrent {
        let cfg = run_config.clone();
        let wc = client.clone();
        let rh = raw_http.clone();
        let tr = tok_rx.clone();
        let tx = rec_tx.clone();
        let sd = shutdown_rx.clone();
        let ps = put_seq.clone();
        let pl = pool.clone();
        worker_handles.push(tokio::spawn(worker::run_worker(cfg, wc, rh, tr, tx, sd, ps, pl)));
    }
    drop(rec_tx);

    // Run until duration elapses or user quits the TUI.
    tokio::select! {
        _ = tokio::time::sleep(duration) => {}
        _ = &mut display_task => {}
    }
    let _ = shutdown_tx.send(true);

    for h in worker_handles {
        let _ = h.await;
    }
    // Recorder drop closes disp_tx → display sees channel close → exits cleanly.
    recorder_handle.await.ok();
    display_task.await.ok();

    eprintln!("\nresults written to {}", output.display());
    analyze::run_analyze(&[output.as_path()], None, 0, None)?;

    if !args.no_cleanup && needs_pool {
        let prefix = format!("warp/{run_id}/");
        cleanup(&client, &args.bucket, &prefix, args.concurrent).await?;
    }

    Ok(())
}

/// Initialise a Y2qClient for the given alias.
/// Returns: (profile, authed client, token expiry secs, token string)
async fn init_client(
    alias: &str,
    config_path: &Option<std::path::PathBuf>,
    password: Option<&str>,
) -> Result<(y2q_config::Profile, y2q_client::Y2qClient, u64, Zeroizing<String>), WarpError> {
    let cfg_path = match config_path {
        Some(p) => p.clone(),
        None => y2q_config::default_config_path()?,
    };
    let cfg = y2q_config::CliConfig::load(&cfg_path)?;
    let profile = cfg.get_profile(alias)?.clone();

    // Build an unauthenticated client solely for the login call if needed
    let base_client = y2q_client::Y2qClient::new(y2q_client::ClientConfig {
        base_url: profile.url.clone(),
        token: None,
    })?;

    let effective_pw = password.or(profile.password.as_deref());
    let (token, expires_at) =
        resolve_token(&base_client, alias, &profile.username, effective_pw).await?;

    let client = build_client(&profile.url, &token)?;
    Ok((profile, client, expires_at, token))
}

fn require_alias(alias: &Option<String>) -> Result<String, WarpError> {
    alias
        .clone()
        .ok_or_else(|| WarpError::Other("alias is required for this subcommand".to_owned()))
}

fn resolve_obj_size(
    fixed: &str,
    min: Option<&str>,
    max: Option<&str>,
) -> Result<ObjSize, WarpError> {
    if let (Some(min_s), Some(max_s)) = (min, max) {
        let lo = parse_size(min_s).map_err(WarpError::Other)?;
        let hi = parse_size(max_s).map_err(WarpError::Other)?;
        Ok(ObjSize::Random { min: lo, max: hi })
    } else {
        let n = parse_size(fixed).map_err(WarpError::Other)?;
        Ok(ObjSize::Fixed(n))
    }
}

fn parse_duration(s: &str) -> Result<std::time::Duration, WarpError> {
    humantime::parse_duration(s).map_err(|e| WarpError::Other(e.to_string()))
}

fn parse_duration_ns(s: &str) -> Result<u64, WarpError> {
    let d = humantime::parse_duration(s).map_err(|e| WarpError::Other(e.to_string()))?;
    Ok(d.as_nanos() as u64)
}
