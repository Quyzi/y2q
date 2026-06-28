mod auth;
mod dir;
mod error;
mod fs;
mod inode;

use std::path::PathBuf;

use clap::Parser;
use fuser::MountOption;

use crate::error::FuseError;
use crate::fs::{MountMode, Y2qFuse};

#[derive(Parser, Debug)]
#[command(
    name = "y2q-fuse",
    about = "Mount a y2q object store as a FUSE filesystem",
    long_about = "Mounts a y2q object store at MOUNTPOINT using FUSE.\n\
                  Run `y2q login <alias>` before mounting.\n\
                  Unmount with Ctrl+C or SIGTERM.\n\n\
                  --allow-other requires `user_allow_other` in /etc/fuse.conf."
)]
struct Args {
    /// Server alias to use.
    #[arg(long, value_name = "NAME")]
    alias: String,

    /// Config file path (default: platform config dir).
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Mount a single bucket as the filesystem root.
    /// Default: all buckets appear as top-level directories.
    #[arg(long, value_name = "BUCKET")]
    bucket: Option<String>,

    /// Disable all write operations.
    #[arg(long)]
    read_only: bool,

    /// Allow other users to access the mount point.
    /// Requires `user_allow_other` in /etc/fuse.conf.
    #[arg(long)]
    allow_other: bool,

    /// Directory to mount the filesystem at.
    mountpoint: PathBuf,
}

fn main() -> Result<(), FuseError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let args = Args::parse();

    // Multi-threaded runtime kept alive for the duration of the mount.
    // The FUSE event loop runs in a background thread (via Session::spawn) and
    // uses Handle::block_on inside each callback — valid here because those
    // callbacks run on non-tokio threads.
    let rt = tokio::runtime::Runtime::new().map_err(FuseError::Io)?;
    let handle = rt.handle().clone();

    let (client, expires_at) = auth::resolve_client(args.config.as_deref(), &args.alias)?;
    auth::spawn_token_refresh(handle.clone(), client.clone(), expires_at);

    let mode = match args.bucket {
        Some(ref b) => MountMode::Single(b.clone()),
        None => MountMode::Multi,
    };

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let fs = Y2qFuse::new(client, handle.clone(), args.read_only, mode, uid, gid);

    let mut opts = vec![
        MountOption::FSName("y2q".into()),
        MountOption::Subtype("y2q".into()),
        MountOption::DefaultPermissions,
        MountOption::NoExec,
        MountOption::NoDev,
    ];
    if args.allow_other {
        opts.push(MountOption::AllowOther);
    }
    if args.read_only {
        opts.push(MountOption::RO);
    }

    let mountpoint = args.mountpoint.clone();
    tracing::info!(mountpoint = %mountpoint.display(), "mounting y2q");

    let session = fuser::Session::new(fs, &mountpoint, &opts).map_err(FuseError::Io)?;
    let bg = session.spawn().map_err(FuseError::Io)?;

    // Block until SIGINT or SIGTERM, then unmount and exit cleanly.
    handle.block_on(async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c().await.ok();
    });

    tracing::info!(mountpoint = %mountpoint.display(), "unmounting y2q");
    std::process::Command::new("fusermount3")
        .args(["-u", mountpoint.to_str().unwrap_or("")])
        .status()
        .or_else(|_| {
            // Fall back to fusermount (FUSE 2) if fusermount3 isn't present.
            std::process::Command::new("fusermount")
                .args(["-u", mountpoint.to_str().unwrap_or("")])
                .status()
        })
        .ok();
    bg.join();

    Ok(())
}
