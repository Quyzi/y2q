//! WinFsp mount backend for y2q (Windows only) — the counterpart to
//! `y2q-fuse`'s FUSE backend on Linux/macOS. Not compiled on non-Windows
//! targets.
//!
//! Uses `winfsp_wrs` (Scille, MIT) rather than `winfsp`/winfsp-rs
//! (SnowflakePowered), which is GPL-3.0 for the crate itself — see
//! CLAUDE.md's Architecture Notes for why that distinction matters here.

#![cfg(windows)]

mod context;
mod error;
mod mount;

pub use error::WinMountError;
pub use mount::{MountHandle, WindowsMountPoint, mount};
pub use y2q_mount_core::path::MountMode;
