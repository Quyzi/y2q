use std::sync::{Arc, RwLock};

use winfsp_wrs::{FileSystem, Params, U16CString, VolumeParams, filetime_now, u16cstr};
use y2q_client::Y2qClient;
use y2q_mount_core::path::MountMode;

use crate::context::Y2qWinFs;
use crate::error::WinMountError;

/// Where to mount on Windows. WinFsp supports both a drive letter (e.g.
/// `"X:"`) and an arbitrary NTFS directory as a mount point; `Auto` lets
/// WinFsp pick the next free drive letter counting down from `Z:`.
pub enum WindowsMountPoint {
    Auto,
    Path(String),
}

pub struct MountHandle {
    fs: Option<FileSystem>,
}

impl MountHandle {
    pub fn unmount(&mut self) -> Result<(), WinMountError> {
        if let Some(fs) = self.fs.take() {
            fs.stop();
        }
        Ok(())
    }
}

/// Mount a y2q object store at `mountpoint` using WinFsp.
pub fn mount(
    client: Arc<RwLock<Y2qClient>>,
    rt: tokio::runtime::Handle,
    mountpoint: WindowsMountPoint,
    read_only: bool,
    mode: MountMode,
) -> Result<MountHandle, WinMountError> {
    winfsp_wrs::init().map_err(|_| WinMountError::WinFspNotInstalled)?;

    let mp =
        match &mountpoint {
            WindowsMountPoint::Auto => None,
            WindowsMountPoint::Path(p) => Some(U16CString::from_str(p).map_err(|_| {
                WinMountError::Other("mountpoint contains an embedded NUL".to_owned())
            })?),
        };

    let mut volume_params = VolumeParams::default();
    volume_params
        .set_sector_size(4096)
        .set_sectors_per_allocation_unit(1)
        .set_volume_creation_time(filetime_now())
        .set_file_info_timeout(1000)
        .set_case_sensitive_search(true)
        .set_case_preserved_names(true)
        .set_unicode_on_disk(true)
        .set_persistent_acls(false)
        .set_read_only_volume(read_only)
        .set_file_system_name(u16cstr!("y2q"))
        .unwrap();

    let params = Params {
        volume_params,
        ..Default::default()
    };

    tracing::info!(mountpoint = ?mp, "mounting y2q");

    let fs_impl = Y2qWinFs::new(client, rt, read_only, mode)?;
    let winfs = FileSystem::start(params, mp.as_deref(), fs_impl).map_err(WinMountError::WinFsp)?;

    Ok(MountHandle { fs: Some(winfs) })
}
