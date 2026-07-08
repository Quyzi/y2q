use thiserror::Error;

#[derive(Debug, Error)]
pub enum FuseError {
    #[error(transparent)]
    Core(#[from] y2q_mount_core::MountCoreError),

    #[error("i/o error: {0}")]
    Io(std::io::Error),
}

pub fn to_errno(e: &y2q_client::ClientError) -> fuser::Errno {
    use y2q_client::ClientError;
    match e {
        ClientError::NotFound { .. } => fuser::Errno::ENOENT,
        ClientError::Unauthenticated => fuser::Errno::EACCES,
        ClientError::Conflict { .. } => fuser::Errno::EEXIST,
        ClientError::BadRequest { .. } => fuser::Errno::EINVAL,
        ClientError::ServerError { .. } | ClientError::Io(_) | ClientError::Http(_) => {
            fuser::Errno::EIO
        }
    }
}
