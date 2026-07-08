use crate::mount_backend::MountHandle;

pub enum GuiEvent {
    /// Login step only — on success the same background task continues on
    /// to mount and will separately send `Mount`.
    Login {
        alias: String,
        result: Result<(), String>,
    },
    Mount {
        alias: String,
        result: Result<(String, MountHandle), String>,
    },
    Unmount {
        alias: String,
        result: Result<(), String>,
    },
}
