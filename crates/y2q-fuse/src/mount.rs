use std::path::Path;
use std::sync::{Arc, RwLock};

use fuser::{Config, MountOption, SessionACL};
use y2q_client::Y2qClient;
use y2q_mount_core::path::MountMode;

use crate::error::FuseError;
use crate::fs::Y2qFuse;

/// A live FUSE mount. Dropping this without calling [`unmount`](MountHandle::unmount)
/// leaves the mount attached — always unmount explicitly before exiting.
pub struct MountHandle {
    background: Option<fuser::BackgroundSession>,
}

impl MountHandle {
    pub fn unmount(&mut self) -> Result<(), FuseError> {
        if let Some(bg) = self.background.take() {
            // `BackgroundSession::umount_and_join` owns the real `Mount` (moved
            // in by `Session::spawn`), so this is the one that actually
            // unmounts. A separately-held `SessionUnmounter` obtained *before*
            // `spawn()` is a dud — `spawn()` steals the `Mount` out from under
            // it via `mem::take`, so calling it later silently no-ops and the
            // subsequent join then blocks forever waiting for a FUSE session
            // that was never actually unmounted.
            bg.umount_and_join().map_err(FuseError::Io)?;
        }
        Ok(())
    }
}

/// Mount a y2q object store at `mountpoint` using FUSE. The FUSE event loop
/// runs on a background thread (via `fuser::Session::spawn`); this call
/// returns as soon as the mount is established.
pub fn mount(
    client: Arc<RwLock<Y2qClient>>,
    rt: tokio::runtime::Handle,
    mountpoint: &Path,
    read_only: bool,
    mode: MountMode,
    allow_other: bool,
) -> Result<MountHandle, FuseError> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let fs = Y2qFuse::new(client, rt, read_only, mode, uid, gid);

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
    if read_only {
        mount_options.push(MountOption::RO);
    }
    let mut config = Config::default();
    config.mount_options = mount_options;
    config.acl = if allow_other {
        SessionACL::All
    } else {
        SessionACL::Owner
    };

    tracing::info!(mountpoint = %mountpoint.display(), "mounting y2q");

    let session = fuser::Session::new(fs, mountpoint, &config).map_err(FuseError::Io)?;
    let background = session.spawn().map_err(FuseError::Io)?;

    Ok(MountHandle {
        background: Some(background),
    })
}
