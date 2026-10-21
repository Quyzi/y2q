//! Download destination that is only touched after the whole transfer succeeded.
//!
//! `File::create(dest)` truncates `dest` immediately, so a 404, 416, 5xx or a
//! broken connection used to destroy the local file the operator meant to
//! overwrite. [`StagedFile`] downloads into a hidden sibling file and renames it
//! over `dest` in [`StagedFile::commit`]; dropping it without committing removes
//! the stage and leaves `dest` exactly as it was.
//!
//! Staging is only used where there is something to protect and a rename is
//! safe: `dest` is missing, or resolves to a regular file. Anything else
//! (directory, device, FIFO, anything under `/dev` or `/proc` such as
//! `/dev/stdout`, a dangling symlink, a trailing separator) keeps the plain
//! `File::create` behaviour.
//!
//! A writable file in a directory we cannot create files in is staged in the
//! temp dir; `commit` then copies the finished download over it in place, so
//! the destination is still untouched until the transfer has fully succeeded.
//!
//! Not preserved by the rename: owner/group, hard links, xattrs/ACLs. The mode
//! bits (minus setuid/setgid/sticky) are. Drop does not run when the process is
//! killed or interrupted (SIGKILL, SIGTERM, Ctrl+C), which leaves one
//! `.y2q-part-*` file behind; `dest` itself is never half-written.

use std::io::{ErrorKind, SeekFrom};
use std::path::{Path, PathBuf};

use rand::Rng;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::error::CliError;

pub(crate) struct StagedFile {
    file: File,
    /// Hidden file being written; `None` in direct mode and after a successful
    /// rename. Removed on drop while `Some`.
    stage: Option<PathBuf>,
    /// Final path (symlinks already resolved when staging).
    target: PathBuf,
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if let Some(stage) = self.stage.take() {
            let _ = std::fs::remove_file(stage);
        }
    }
}

impl StagedFile {
    pub(crate) async fn create(dest: &Path) -> Result<Self, CliError> {
        let Some((target, existing)) = staging_target(dest).await else {
            return Self::direct(dest).await;
        };

        if existing.is_some() {
            // `rename` would bypass the write permission `File::create` enforces
            // (e.g. a 0444 file in a writable directory): keep failing up front.
            OpenOptions::new().write(true).open(&target).await?;
        }

        let (file, stage) = match open_stage(stage_dir(&target), existing.is_some()).await {
            Ok(v) => v,
            // Writable file inside a directory we cannot create in. Stage in
            // the temp dir instead: the destination stays untouched until the
            // download is complete, then `commit` copies it over in place.
            // (Truncating here would reintroduce the lose-the-file-on-404 bug.)
            Err(e)
                if existing.is_some()
                    && matches!(
                        e.kind(),
                        ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem
                    ) =>
            {
                open_stage(&std::env::temp_dir(), true).await?
            }
            Err(e) => return Err(e.into()),
        };
        // Guard first so a failure below cannot leak the stage.
        let guard = Self {
            file,
            stage: Some(stage),
            target,
        };

        if let Some(md) = existing {
            let mut perms = md.permissions();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // Drop setuid/setgid/sticky: a write by an unprivileged
                // process clears them, new content must not inherit them.
                perms.set_mode(perms.mode() & 0o777);
            }
            guard.file.set_permissions(perms).await?;
        }
        Ok(guard)
    }

    async fn direct(dest: &Path) -> Result<Self, CliError> {
        Ok(Self {
            file: File::create(dest).await?,
            stage: None,
            target: dest.to_path_buf(),
        })
    }

    /// The writer to download into.
    pub(crate) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Publish the finished download. Call only after the transfer succeeded.
    pub(crate) async fn commit(mut self) -> Result<(), CliError> {
        self.file.flush().await?;
        let Some(stage) = self.stage.clone() else {
            return Ok(());
        };
        // Without this a crash right after the rename can leave an empty file
        // under the final name on some filesystems.
        self.file.sync_all().await?;

        if tokio::fs::rename(&stage, &self.target).await.is_ok() {
            self.stage = None;
            return Ok(());
        }

        // Rename refused (sticky directory, bind-mounted file, ...): the old
        // in-place overwrite worked there, and the download is already
        // complete, so copy it over.
        self.file.seek(SeekFrom::Start(0)).await?;
        let mut out = File::create(&self.target).await?;
        let copied = async {
            tokio::io::copy(&mut self.file, &mut out).await?;
            out.flush().await
        }
        .await;
        if let Err(e) = copied {
            // The target is already truncated; the stage is the only complete
            // copy, so keep it.
            self.stage = None;
            return Err(CliError::Other(format!(
                "writing {}: {e}; the complete download was kept at {}",
                self.target.display(),
                stage.display()
            )));
        }
        Ok(())
    }
}

/// `Some((final path, metadata of the file being replaced))` when staging
/// applies, `None` for direct `File::create` semantics.
async fn staging_target(dest: &Path) -> Option<(PathBuf, Option<std::fs::Metadata>)> {
    let bytes = dest.as_os_str().as_encoded_bytes();
    // `/dev/stdout`, `/dev/fd/N`, `/proc/self/fd/N` name whatever the caller
    // redirected to; never resolve them to a real path and rename over it.
    if dest.file_name().is_none()
        || dest.starts_with("/dev")
        || dest.starts_with("/proc")
        || bytes
            .last()
            .is_some_and(|b| std::path::is_separator(*b as char))
    {
        return None;
    }
    match tokio::fs::metadata(dest).await {
        Ok(md) if md.is_file() => {
            let target = tokio::fs::canonicalize(dest).await.ok()?;
            Some((target, Some(md)))
        }
        Ok(_) => None,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            // Missing for real, not a dangling symlink (whose target the old
            // code would have created).
            match tokio::fs::symlink_metadata(dest).await {
                Err(e) if e.kind() == ErrorKind::NotFound => Some((dest.to_path_buf(), None)),
                _ => None,
            }
        }
        Err(_) => None,
    }
}

/// Directory the stage is created in: next to `target` so the rename stays on
/// one filesystem. A bare `out.bin` has parent `""`, which is not a usable path.
fn stage_dir(target: &Path) -> &Path {
    match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// Create the hidden stage in `dir`. `restrict` makes it owner-only from the
/// start (used when replacing a file whose real mode is applied afterwards).
async fn open_stage(dir: &Path, restrict: bool) -> std::io::Result<(File, PathBuf)> {
    let stage = dir.join(stage_name());
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create_new(true);
    #[cfg(unix)]
    if restrict {
        // Never let decrypted bytes sit in a more permissive file than the
        // one being replaced; real mode is applied right after, before any write.
        opts.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = restrict;
    let file = opts.open(&stage).await?;
    Ok((file, stage))
}

fn stage_name() -> String {
    let mut raw = [0u8; 16];
    rand::rng().fill_bytes(&mut raw);
    let mut name = String::from(".y2q-part-");
    for b in raw {
        name.push_str(&format!("{b:02x}"));
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".y2q-part-"))
            .collect()
    }

    #[tokio::test]
    async fn dropped_stage_leaves_existing_dest_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("precious.txt");
        std::fs::write(&dest, b"PRECIOUS DATA").unwrap();

        let mut s = StagedFile::create(&dest).await.unwrap();
        s.file_mut().write_all(b"partial").await.unwrap();
        drop(s);

        assert_eq!(std::fs::read(&dest).unwrap(), b"PRECIOUS DATA");
        assert!(leftovers(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn dropped_stage_does_not_create_missing_dest() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("new.txt");

        let s = StagedFile::create(&dest).await.unwrap();
        drop(s);

        assert!(!dest.exists());
        assert!(leftovers(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn commit_replaces_longer_file_without_stale_tail() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("f.bin");
        std::fs::write(&dest, b"a much longer previous body").unwrap();

        let mut s = StagedFile::create(&dest).await.unwrap();
        s.file_mut().write_all(b"new").await.unwrap();
        // Not visible until commit.
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"a much longer previous body"
        );
        s.commit().await.unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
        assert!(leftovers(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn commit_creates_missing_dest() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("new.txt");

        let mut s = StagedFile::create(&dest).await.unwrap();
        s.file_mut().write_all(b"hello").await.unwrap();
        s.commit().await.unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"hello");
        assert!(leftovers(dir.path()).is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn existing_mode_applies_to_stage_before_any_write_and_survives_commit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("f");
        std::fs::write(&dest, b"old").unwrap();
        // setuid bit must not be carried over; 0640 must.
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o4640)).unwrap();

        let mut s = StagedFile::create(&dest).await.unwrap();
        let stage = s.stage.clone().unwrap();
        let stage_mode = std::fs::metadata(&stage).unwrap().permissions().mode() & 0o7777;
        assert_eq!(stage_mode, 0o640, "stage must already carry the dest mode");
        s.file_mut().write_all(b"new").await.unwrap();
        s.commit().await.unwrap();

        let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o640);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_dest_is_updated_through_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.txt");
        let link = dir.path().join("link.txt");
        std::fs::write(&real, b"old").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let mut s = StagedFile::create(&link).await.unwrap();
        s.file_mut().write_all(b"new").await.unwrap();
        s.commit().await.unwrap();

        assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(std::fs::read(&real).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dangling_symlink_creates_its_target_like_file_create() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.txt");
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let mut s = StagedFile::create(&link).await.unwrap();
        s.file_mut().write_all(b"x").await.unwrap();
        s.commit().await.unwrap();

        assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(std::fs::read(&real).unwrap(), b"x");
        assert!(leftovers(dir.path()).is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn device_and_symlink_to_device_are_written_through() {
        use std::os::unix::fs::FileTypeExt;
        let null = Path::new("/dev/null");
        if !null.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("null-link");
        std::os::unix::fs::symlink(null, &link).unwrap();

        for dest in [null, link.as_path()] {
            let mut s = StagedFile::create(dest).await.unwrap();
            assert!(s.stage.is_none(), "{} must not be staged", dest.display());
            s.file_mut().write_all(b"discard").await.unwrap();
            s.commit().await.unwrap();
        }
        assert!(
            std::fs::metadata(null)
                .unwrap()
                .file_type()
                .is_char_device()
        );
        assert!(leftovers(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn directory_and_trailing_separator_error_like_before() {
        let dir = tempfile::tempdir().unwrap();
        assert!(StagedFile::create(dir.path()).await.is_err());
        assert!(dir.path().is_dir());

        let trailing = format!("{}/missing/", dir.path().display());
        assert!(StagedFile::create(Path::new(&trailing)).await.is_err());
        assert!(leftovers(dir.path()).is_empty());
    }

    #[tokio::test]
    async fn missing_parent_directory_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("nope").join("f");
        assert!(StagedFile::create(&dest).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn readonly_dest_still_fails_up_front() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("ro");
        std::fs::write(&dest, b"keep").unwrap();
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o444)).unwrap();
        if std::fs::OpenOptions::new().write(true).open(&dest).is_ok() {
            return; // running as root: permission bits do not apply
        }

        let err = StagedFile::create(&dest).await.err().expect("must fail");
        assert!(matches!(&err, CliError::Io(e) if e.kind() == ErrorKind::PermissionDenied));
        assert_eq!(std::fs::read(&dest).unwrap(), b"keep");
        assert!(leftovers(dir.path()).is_empty());
    }

    /// Runs `body` with `dir` made read-only; returns `None` (skip) as root,
    /// where directory permission bits do not apply.
    #[cfg(unix)]
    async fn with_readonly_dir<F, Fut>(dir: &Path, body: F) -> Option<()>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        use std::os::unix::fs::PermissionsExt;
        let set = |m| std::fs::set_permissions(dir, std::fs::Permissions::from_mode(m));
        set(0o555).unwrap();
        if std::fs::File::create(dir.join("probe")).is_ok() {
            set(0o755).unwrap();
            return None;
        }
        body().await;
        set(0o755).unwrap();
        Some(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_download_keeps_file_in_unwritable_dir() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("f");
        std::fs::write(&dest, b"PRECIOUS").unwrap();

        let d = dest.clone();
        with_readonly_dir(dir.path(), || async move {
            let mut s = StagedFile::create(&d).await.unwrap();
            assert!(s.stage.is_some(), "must stage, not truncate in place");
            // The destination is untouched while the download is in flight...
            assert_eq!(std::fs::read(&d).unwrap(), b"PRECIOUS");
            s.file_mut().write_all(b"partial").await.unwrap();
            // ...and when it fails (guard dropped without commit).
            drop(s);
            assert_eq!(std::fs::read(&d).unwrap(), b"PRECIOUS");
        })
        .await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn writable_file_in_unwritable_dir_is_replaced_on_commit() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("f");
        std::fs::write(&dest, b"a longer old body").unwrap();

        let d = dest.clone();
        let ran = with_readonly_dir(dir.path(), || async move {
            let mut s = StagedFile::create(&d).await.unwrap();
            s.file_mut().write_all(b"new").await.unwrap();
            s.commit().await.unwrap();
        })
        .await
        .is_some();
        if ran {
            assert_eq!(std::fs::read(&dest).unwrap(), b"new");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dev_paths_are_never_staged() {
        // Whatever /dev/stdout points at (file, pipe, tty), do not resolve it
        // to a real path and rename over it.
        for p in ["/dev/stdout", "/dev/fd/1", "/proc/self/fd/1"] {
            assert!(staging_target(Path::new(p)).await.is_none(), "{p}");
        }
    }

    #[tokio::test]
    async fn stage_name_does_not_depend_on_dest_name() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("x".repeat(250));
        std::fs::write(&dest, b"old").unwrap();

        let mut s = StagedFile::create(&dest).await.unwrap();
        s.file_mut().write_all(b"new").await.unwrap();
        s.commit().await.unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
    }

    #[test]
    fn stage_dir_of_bare_relative_file_is_cwd() {
        assert_eq!(stage_dir(Path::new("out.bin")), Path::new("."));
        assert_eq!(stage_dir(Path::new("a/out.bin")), Path::new("a"));
        assert_eq!(stage_dir(Path::new("/out.bin")), Path::new("/"));
    }
}
