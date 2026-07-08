use std::path::PathBuf;

use clap::Parser;

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

#[cfg(unix)]
fn main() -> Result<(), y2q_fuse::FuseError> {
    use y2q_fuse::MountMode;

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
    let rt = tokio::runtime::Runtime::new().map_err(y2q_fuse::FuseError::Io)?;
    let handle = rt.handle().clone();

    let (client, expires_at) =
        y2q_mount_core::client::resolve_client(args.config.as_deref(), &args.alias)?;
    y2q_mount_core::client::spawn_token_refresh(handle.clone(), client.clone(), expires_at);

    let mode = match args.bucket {
        Some(ref b) => MountMode::Single(b.clone()),
        None => MountMode::Multi,
    };

    let mut mount_handle = y2q_fuse::mount(
        client,
        handle.clone(),
        &args.mountpoint,
        args.read_only,
        mode,
        args.allow_other,
    )?;

    // Block until SIGINT or SIGTERM, then unmount and exit cleanly.
    handle.block_on(async {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    });

    tracing::info!(mountpoint = %args.mountpoint.display(), "unmounting y2q");
    if let Err(e) = mount_handle.unmount() {
        tracing::warn!("unmount: {e}");
    }

    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!(
        "y2q-fuse has no Windows backend (fuser wraps libfuse/macFUSE only). \
         Use y2q-mount-windows instead."
    );
    std::process::exit(1);
}
