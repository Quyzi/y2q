//! FUSE mount backend for y2q (Linux via libfuse3, macOS via macFUSE). Wraps
//! `fuser`, which has no Windows support — see `y2q-mount-windows` for that
//! platform. Not compiled on non-unix targets.

#![cfg(unix)]

mod error;
pub mod fs;
pub mod inode;
mod mount;

pub use error::FuseError;
pub use mount::{MountHandle, mount};
pub use y2q_mount_core::path::MountMode;
