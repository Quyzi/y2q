//! Thin platform switch over the two mount backends so the rest of the GUI
//! never has to `#[cfg]` on OS itself.

use std::sync::{Arc, RwLock};

use y2q_client::Y2qClient;
use y2q_mount_core::path::MountMode;

#[cfg(unix)]
pub type MountHandle = y2q_fuse::MountHandle;
#[cfg(windows)]
pub type MountHandle = y2q_mount_windows::MountHandle;

/// `mountpoint`: a directory path on Linux/macOS (created if missing); a
/// drive letter like `"X:"`, a directory path, or empty (auto-assign a
/// drive letter) on Windows.
#[cfg(unix)]
pub fn mount(
    client: Arc<RwLock<Y2qClient>>,
    rt: tokio::runtime::Handle,
    mountpoint: &str,
    read_only: bool,
    mode: MountMode,
) -> Result<MountHandle, String> {
    let path = std::path::PathBuf::from(mountpoint);
    std::fs::create_dir_all(&path).map_err(|e| format!("create mountpoint: {e}"))?;
    y2q_fuse::mount(client, rt, &path, read_only, mode, false).map_err(|e| e.to_string())
}

#[cfg(windows)]
pub fn mount(
    client: Arc<RwLock<Y2qClient>>,
    rt: tokio::runtime::Handle,
    mountpoint: &str,
    read_only: bool,
    mode: MountMode,
) -> Result<MountHandle, String> {
    use y2q_mount_windows::WindowsMountPoint;
    let mp = if mountpoint.trim().is_empty() {
        WindowsMountPoint::Auto
    } else {
        WindowsMountPoint::Path(mountpoint.trim().to_owned())
    };
    y2q_mount_windows::mount(client, rt, mp, read_only, mode).map_err(|e| e.to_string())
}

pub fn unmount(handle: &mut MountHandle) -> Result<(), String> {
    handle.unmount().map_err(|e| e.to_string())
}
