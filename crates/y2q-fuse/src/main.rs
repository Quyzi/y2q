mod auth;
mod dir;
mod error;
mod fs;
mod inode;

use std::path::PathBuf;

use clap::Parser;
use fuser::{Config, MountOption, SessionACL};

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
    ///
    /// Without --allow-other-gid, every local user gets read access to every
    /// file (mode 0644/0755) — not just the intended one.
    #[arg(long)]
    allow_other: bool,

    /// Used with --allow-other: restrict the extra access it grants to this
    /// group (mode 0640/0750, group-owned by GID) instead of every local
    /// user (0644/0755).
    #[arg(long, value_name = "GID", requires = "allow_other")]
    allow_other_gid: Option<u32>,

    /// Used with --allow-other instead of --allow-other-gid: explicitly opt
    /// into exposing the mount to every local user (mode 0644/0755), rather
    /// than scoping it to one group. Without one of the two, --allow-other
    /// alone refuses to start.
    #[arg(long, requires = "allow_other")]
    allow_other_any_user: bool,

    /// Directory in which to create write-buffer temp files (used to
    /// buffer decrypted object bodies during writable opens and renames)
    /// instead of the OS temp directory. Restricting this away from a
    /// world-writable shared /tmp reduces exposure of decrypted plaintext
    /// to other local users. Default: `std::env::temp_dir()`.
    #[arg(long, value_name = "PATH")]
    write_buf_dir: Option<PathBuf>,

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

    if let Err(msg) = validate_allow_other(
        args.allow_other,
        args.allow_other_gid,
        args.allow_other_any_user,
    ) {
        return Err(FuseError::Other(msg.to_owned()));
    }

    // Best-effort: remove any write-buffer tempfiles orphaned by a prior
    // SIGKILL/crash (normal exit cleans these up via Drop, which a hard kill
    // skips). Never blocks or fails startup.
    fs::sweep_orphaned_tempfiles(args.write_buf_dir.as_deref());

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

    let fs = Y2qFuse::new(
        client,
        handle.clone(),
        args.read_only,
        mode,
        uid,
        gid,
        args.allow_other_gid,
        args.write_buf_dir.clone(),
    );

    let mut mount_options = vec![
        MountOption::FSName("y2q".into()),
        MountOption::DefaultPermissions,
    ];
    // macFUSE's mount helper doesn't guarantee support for these; a rejected
    // option fails the whole mount, so keep them Linux-only.
    #[cfg(target_os = "linux")]
    mount_options.extend([
        MountOption::Subtype("y2q".into()),
        MountOption::NoExec,
        MountOption::NoDev,
    ]);
    if args.read_only {
        mount_options.push(MountOption::RO);
    }
    let mut config = Config::default();
    config.mount_options = mount_options;
    config.acl = if args.allow_other {
        SessionACL::All
    } else {
        SessionACL::Owner
    };

    let mountpoint = args.mountpoint.clone();
    tracing::info!(mountpoint = %mountpoint.display(), "mounting y2q");

    let mut session = fuser::Session::new(fs, &mountpoint, &config).map_err(FuseError::Io)?;
    let mut unmounter = session.unmount_callable();
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
    if let Err(e) = unmounter.unmount() {
        tracing::warn!("unmount: {e}");
    }
    if let Err(e) = bg.join() {
        tracing::warn!("session join: {e}");
    }

    Ok(())
}

/// Refuse an `--allow-other` mount that neither scopes the extra access to
/// a group (`--allow-other-gid`) nor explicitly opts into exposing it to
/// every local user (`--allow-other-any-user`). `--allow-other` alone
/// grants every local user read access to every file (mode 0644/0755); an
/// operator has to make that an explicit, informed choice.
///
/// Not expressed via clap's `requires`/`conflicts_with`, since the
/// relationship is an either/or (one of two flags satisfies it, not both
/// mandatory) rather than an unconditional dependency.
fn validate_allow_other(
    allow_other: bool,
    allow_other_gid: Option<u32>,
    allow_other_any_user: bool,
) -> Result<(), &'static str> {
    if allow_other && allow_other_gid.is_none() && !allow_other_any_user {
        return Err(
            "--allow-other alone exposes the mount to every local user; pass \
             --allow-other-gid <GID> to scope it to a group, or \
             --allow-other-any-user to explicitly allow every local user",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_other_without_gid_or_escape_hatch_is_rejected() {
        assert!(validate_allow_other(true, None, false).is_err());
    }

    #[test]
    fn allow_other_with_gid_is_accepted() {
        assert!(validate_allow_other(true, Some(1000), false).is_ok());
    }

    #[test]
    fn allow_other_with_any_user_escape_hatch_is_accepted() {
        assert!(validate_allow_other(true, None, true).is_ok());
    }

    #[test]
    fn allow_other_disabled_is_always_accepted() {
        assert!(validate_allow_other(false, None, false).is_ok());
        assert!(validate_allow_other(false, Some(1000), false).is_ok());
        assert!(validate_allow_other(false, None, true).is_ok());
        assert!(validate_allow_other(false, Some(1000), true).is_ok());
    }

    #[test]
    fn write_buf_dir_flag_is_parsed() {
        let args = Args::try_parse_from([
            "y2q-fuse",
            "--alias",
            "test",
            "--write-buf-dir",
            "/some/path",
            "/mnt/y2q",
        ])
        .unwrap();
        assert_eq!(args.write_buf_dir, Some(PathBuf::from("/some/path")));
    }

    #[test]
    fn write_buf_dir_flag_defaults_to_none() {
        let args = Args::try_parse_from(["y2q-fuse", "--alias", "test", "/mnt/y2q"]).unwrap();
        assert_eq!(args.write_buf_dir, None);
    }

    #[test]
    fn allow_other_any_user_flag_requires_allow_other() {
        let err = Args::try_parse_from([
            "y2q-fuse",
            "--alias",
            "test",
            "--allow-other-any-user",
            "/mnt/y2q",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }
}
