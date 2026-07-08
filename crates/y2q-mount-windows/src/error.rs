use thiserror::Error;

#[derive(Debug, Error)]
pub enum WinMountError {
    #[error(transparent)]
    Core(#[from] y2q_mount_core::MountCoreError),

    #[error(
        "WinFsp is not installed or could not be loaded — install it from https://winfsp.dev/rel/"
    )]
    WinFspNotInstalled,

    #[error("winfsp error: NTSTATUS 0x{0:08X}")]
    WinFsp(winfsp_wrs::NTSTATUS),

    #[error("{0}")]
    Other(String),
}

/// Map a y2q client error to the closest matching NTSTATUS for a WinFsp
/// callback to return.
pub fn to_ntstatus(e: &y2q_client::ClientError) -> winfsp_wrs::NTSTATUS {
    use winfsp_wrs::{
        STATUS_ACCESS_DENIED, STATUS_INVALID_PARAMETER, STATUS_IO_DEVICE_ERROR,
        STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND,
    };
    use y2q_client::ClientError;
    match e {
        ClientError::NotFound { .. } => STATUS_OBJECT_NAME_NOT_FOUND,
        ClientError::Unauthenticated => STATUS_ACCESS_DENIED,
        ClientError::Conflict { .. } => STATUS_OBJECT_NAME_COLLISION,
        ClientError::BadRequest { .. } => STATUS_INVALID_PARAMETER,
        ClientError::ServerError { .. } | ClientError::Io(_) | ClientError::Http(_) => {
            STATUS_IO_DEVICE_ERROR
        }
    }
}
