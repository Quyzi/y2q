//! Backend-agnostic pieces shared by the FUSE (`y2q-fuse`) and WinFsp
//! (`y2q-mount-windows`) mount backends: client/token resolution, remote
//! directory listing, and the path/metadata types used to resolve a mount
//! request against the object store. Filesystem-trait-specific glue (inode
//! tables, WinFsp file contexts, OS error-code mapping) stays in each
//! backend crate — those shapes differ too much to usefully share.

pub mod client;
pub mod dir;
pub mod path;

mod error;

pub use error::MountCoreError;
