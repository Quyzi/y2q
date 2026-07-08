use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "y2q-mount-windows",
    about = "Mount a y2q object store as a Windows drive via WinFsp",
    long_about = "Mounts a y2q object store at MOUNTPOINT using WinFsp.\n\
                  Run `y2q login <alias>` before mounting.\n\
                  Requires WinFsp: https://winfsp.dev/rel/"
)]
struct Args {
    /// Server alias to use.
    #[arg(long, value_name = "NAME")]
    alias: String,

    /// Config file path (default: platform config dir).
    #[arg(long, value_name = "PATH")]
    config: Option<std::path::PathBuf>,

    /// Mount a single bucket as the filesystem root.
    /// Default: all buckets appear as top-level directories.
    #[arg(long, value_name = "BUCKET")]
    bucket: Option<String>,

    /// Disable all write operations.
    #[arg(long)]
    read_only: bool,

    /// Drive letter (e.g. "X:") or directory to mount at. Omit to let
    /// WinFsp pick the next free drive letter.
    mountpoint: Option<String>,
}

#[cfg(windows)]
fn main() -> Result<(), y2q_mount_windows::WinMountError> {
    use y2q_mount_windows::{MountMode, WindowsMountPoint};

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let args = Args::parse();

    let rt = tokio::runtime::Runtime::new().map_err(|e| {
        y2q_mount_windows::WinMountError::Other(format!("failed to start async runtime: {e}"))
    })?;
    let handle = rt.handle().clone();

    let (client, expires_at) =
        y2q_mount_core::client::resolve_client(args.config.as_deref(), &args.alias)?;
    y2q_mount_core::client::spawn_token_refresh(handle.clone(), client.clone(), expires_at);

    let mode = match args.bucket {
        Some(ref b) => MountMode::Single(b.clone()),
        None => MountMode::Multi,
    };
    let mountpoint = match args.mountpoint {
        Some(p) => WindowsMountPoint::Path(p),
        None => WindowsMountPoint::Auto,
    };

    let mut mount_handle =
        y2q_mount_windows::mount(client, handle.clone(), mountpoint, args.read_only, mode)?;

    // Block until Ctrl+C, then unmount and exit cleanly.
    handle.block_on(async {
        tokio::signal::ctrl_c().await.ok();
    });

    tracing::info!("unmounting y2q");
    if let Err(e) = mount_handle.unmount() {
        tracing::warn!("unmount: {e}");
    }

    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("y2q-mount-windows only runs on Windows (WinFsp). Use y2q-fuse instead.");
    std::process::exit(1);
}
