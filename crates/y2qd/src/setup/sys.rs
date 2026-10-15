//! Thin safe wrappers over `libc` and `std` for the host facts and file
//! operations the setup wizard needs. Every `unsafe` call is in its own block
//! with a `// SAFETY:` justification.

use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr;

/// Initial `getpwnam_r`-family buffer size; doubled on `ERANGE` up to
/// [`NSS_BUF_MAX`].
const NSS_BUF_START: usize = 1024;
const NSS_BUF_MAX: usize = 1 << 20;

/// A resolved account from the passwd database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
}

/// The effective uid of this process.
pub fn euid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, cannot fail and touches no memory.
    unsafe { libc::geteuid() }
}

/// Run a `get*_r` style query, growing the scratch buffer on `ERANGE`.
/// `query` receives the output struct, the scratch buffer and the result
/// pointer slot, and returns the call's error number (0 on success).
fn passwd_query(
    query: impl Fn(&mut libc::passwd, &mut [u8], &mut *mut libc::passwd) -> libc::c_int,
) -> Option<User> {
    let mut size = NSS_BUF_START;
    loop {
        let mut buf = vec![0u8; size];
        // SAFETY: `passwd` is a plain C struct of integers and pointers; the
        // all-zero bit pattern is valid (null pointers, zero ids).
        let mut pwd: libc::passwd = unsafe { mem::zeroed() };
        let mut res: *mut libc::passwd = ptr::null_mut();
        let rc = query(&mut pwd, &mut buf, &mut res);
        if rc == libc::ERANGE && size < NSS_BUF_MAX {
            size *= 2;
            continue;
        }
        if rc != 0 || res.is_null() || pwd.pw_name.is_null() {
            return None;
        }
        // SAFETY: the call succeeded with a non-null result, so `pw_name`
        // points at a NUL-terminated string inside `buf`, which is alive.
        let name = unsafe { CStr::from_ptr(pwd.pw_name) }
            .to_string_lossy()
            .into_owned();
        return Some(User {
            uid: pwd.pw_uid,
            gid: pwd.pw_gid,
            name,
        });
    }
}

/// Group-database analogue of [`passwd_query`], returning `(gid, name)`.
fn group_query(
    query: impl Fn(&mut libc::group, &mut [u8], &mut *mut libc::group) -> libc::c_int,
) -> Option<(u32, String)> {
    let mut size = NSS_BUF_START;
    loop {
        let mut buf = vec![0u8; size];
        // SAFETY: `group` is a plain C struct of integers and pointers; the
        // all-zero bit pattern is valid.
        let mut grp: libc::group = unsafe { mem::zeroed() };
        let mut res: *mut libc::group = ptr::null_mut();
        let rc = query(&mut grp, &mut buf, &mut res);
        if rc == libc::ERANGE && size < NSS_BUF_MAX {
            size *= 2;
            continue;
        }
        if rc != 0 || res.is_null() || grp.gr_name.is_null() {
            return None;
        }
        // SAFETY: the call succeeded with a non-null result, so `gr_name`
        // points at a NUL-terminated string inside `buf`, which is alive.
        let name = unsafe { CStr::from_ptr(grp.gr_name) }
            .to_string_lossy()
            .into_owned();
        return Some((grp.gr_gid, name));
    }
}

/// Look up an account by name. `None` when it does not exist or the name
/// contains a NUL byte.
pub fn lookup_user(name: &str) -> Option<User> {
    let cname = CString::new(name).ok()?;
    passwd_query(|pwd, buf, res| {
        // SAFETY: `cname` is NUL-terminated and outlives the call; `pwd`,
        // `buf` (with its true length) and `res` are valid exclusive
        // references supplied by `passwd_query`.
        unsafe { libc::getpwnam_r(cname.as_ptr(), pwd, buf.as_mut_ptr().cast(), buf.len(), res) }
    })
}

/// Look up an account by uid.
pub fn lookup_uid(uid: u32) -> Option<User> {
    passwd_query(|pwd, buf, res| {
        // SAFETY: `pwd`, `buf` (with its true length) and `res` are valid
        // exclusive references supplied by `passwd_query`.
        unsafe { libc::getpwuid_r(uid, pwd, buf.as_mut_ptr().cast(), buf.len(), res) }
    })
}

/// Look up a group by name, returning its gid.
pub fn lookup_group(name: &str) -> Option<u32> {
    let cname = CString::new(name).ok()?;
    group_query(|grp, buf, res| {
        // SAFETY: `cname` is NUL-terminated and outlives the call; `grp`,
        // `buf` (with its true length) and `res` are valid exclusive
        // references supplied by `group_query`.
        unsafe { libc::getgrnam_r(cname.as_ptr(), grp, buf.as_mut_ptr().cast(), buf.len(), res) }
    })
    .map(|(gid, _)| gid)
}

/// Name of the group with this gid.
pub fn group_name(gid: u32) -> Option<String> {
    group_query(|grp, buf, res| {
        // SAFETY: `grp`, `buf` (with its true length) and `res` are valid
        // exclusive references supplied by `group_query`.
        unsafe { libc::getgrgid_r(gid, grp, buf.as_mut_ptr().cast(), buf.len(), res) }
    })
    .map(|(_, name)| name)
}

/// Whether `user` is a member of `group` (primary or supplementary). `false`
/// when either does not exist.
pub fn user_in_group(user: &str, group: &str) -> bool {
    let Some(account) = lookup_user(user) else {
        return false;
    };
    let Some(gid) = lookup_group(group) else {
        return false;
    };
    if account.gid == gid {
        return true;
    }
    let Ok(cname) = CString::new(user) else {
        return false;
    };
    let mut groups: Vec<libc::gid_t> = vec![0; 32];
    // The kernel's NGROUPS_MAX is 65536; stop growing there.
    for _ in 0..12 {
        let mut n = libc::c_int::try_from(groups.len()).unwrap_or(libc::c_int::MAX);
        // SAFETY: `cname` is NUL-terminated; `groups` holds `n` writable
        // gid_t slots and `n` is a valid in/out count.
        let rc =
            unsafe { libc::getgrouplist(cname.as_ptr(), account.gid, groups.as_mut_ptr(), &mut n) };
        if rc >= 0 {
            let n = usize::try_from(n).unwrap_or(0).min(groups.len());
            return groups[..n].contains(&gid);
        }
        // Buffer too small: `n` now holds the required count. Guarantee
        // growth even if a libc leaves it untouched.
        let needed = usize::try_from(n).unwrap_or(0);
        let new_len = needed.max(groups.len() * 2);
        groups.resize(new_len, 0);
    }
    false
}

/// File status, with the full `st_mode` (type bits included).
#[derive(Debug, Clone, Copy)]
pub struct Stat {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    pub dev: u64,
}

impl Stat {
    fn from_metadata(m: &std::fs::Metadata) -> Stat {
        Stat {
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            nlink: m.nlink(),
            dev: m.dev(),
        }
    }

    fn file_type(&self) -> u32 {
        self.mode & libc::S_IFMT
    }

    pub fn is_dir(&self) -> bool {
        self.file_type() == libc::S_IFDIR
    }

    pub fn is_file(&self) -> bool {
        self.file_type() == libc::S_IFREG
    }

    pub fn is_symlink(&self) -> bool {
        self.file_type() == libc::S_IFLNK
    }

    /// Permission bits including setuid/setgid/sticky (`mode & 0o7777`).
    pub fn perm(&self) -> u32 {
        self.mode & 0o7777
    }
}

/// `stat(2)`: follows symlinks.
pub fn stat(path: &Path) -> io::Result<Stat> {
    std::fs::metadata(path).map(|m| Stat::from_metadata(&m))
}

/// `lstat(2)`: does not follow a final symlink.
pub fn lstat(path: &Path) -> io::Result<Stat> {
    std::fs::symlink_metadata(path).map(|m| Stat::from_metadata(&m))
}

/// `fstat(2)` on an open file.
pub fn fstat(f: &File) -> io::Result<Stat> {
    f.metadata().map(|m| Stat::from_metadata(&m))
}

/// `open(2)` with `O_NOFOLLOW | O_CLOEXEC` added to `flags` (`libc::O_*`,
/// including the access mode). `mode` is the creation mode. A final symlink
/// fails with `ELOOP`.
pub fn open_nofollow(path: &Path, flags: i32, mode: u32) -> io::Result<File> {
    let cpath = path_cstring(path)?;
    // SAFETY: `cpath` is NUL-terminated and outlives the call. `open` returns
    // a new fd or -1; the creation mode is passed as the variadic `c_uint`.
    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly opened descriptor that nothing else owns.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

fn path_cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

/// `fchown(2)` on an open file; `None` leaves that id unchanged.
pub fn fchown(f: &File, uid: Option<u32>, gid: Option<u32>) -> io::Result<()> {
    std::os::unix::fs::fchown(f, uid, gid)
}

/// `fchmod(2)` on an open file: sets all of `mode` (no umask applies).
pub fn fchmod(f: &File, mode: u32) -> io::Result<()> {
    // SAFETY: `f` is an open descriptor for the duration of the call.
    let rc = unsafe { libc::fchmod(f.as_raw_fd(), mode) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `path` itself if something exists there (symlinks count, not followed),
/// otherwise its nearest existing ancestor. A relative path with no existing
/// component yields `.`; an absolute one yields `/`.
pub fn nearest_existing_ancestor(path: &Path) -> PathBuf {
    let mut cur = path;
    loop {
        if !cur.as_os_str().is_empty() && std::fs::symlink_metadata(cur).is_ok() {
            return cur.to_path_buf();
        }
        match cur.parent() {
            Some(parent) => cur = parent,
            None => {
                return if path.is_absolute() {
                    PathBuf::from("/")
                } else {
                    PathBuf::from(".")
                };
            }
        }
    }
}

/// Bytes available to unprivileged users on the filesystem holding `path`.
#[allow(clippy::unnecessary_cast)] // statvfs field widths differ per target
pub fn free_bytes(path: &Path) -> io::Result<u64> {
    let cpath = path_cstring(path)?;
    // SAFETY: `statvfs` is a plain C struct of integers; all-zero is valid.
    let mut st: libc::statvfs = unsafe { mem::zeroed() };
    // SAFETY: `cpath` is NUL-terminated; `st` is a valid exclusive output.
    let rc = unsafe { libc::statvfs(cpath.as_ptr(), &mut st) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

/// Whether `path` lives on a tmpfs. `false` on any error.
#[allow(clippy::unnecessary_cast)] // statfs field/constant widths differ per target
pub fn is_tmpfs(path: &Path) -> bool {
    let Ok(cpath) = path_cstring(path) else {
        return false;
    };
    // SAFETY: `statfs` is a plain C struct of integers; all-zero is valid.
    let mut st: libc::statfs = unsafe { mem::zeroed() };
    // SAFETY: `cpath` is NUL-terminated; `st` is a valid exclusive output.
    let rc = unsafe { libc::statfs(cpath.as_ptr(), &mut st) };
    rc == 0 && (st.f_type as i64) == (libc::TMPFS_MAGIC as i64)
}

/// Soft `RLIMIT_MEMLOCK` in bytes; `RLIM_INFINITY` maps to `u64::MAX`.
#[allow(clippy::unnecessary_cast)] // rlim_t width differs per target
pub fn rlimit_memlock() -> Option<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid exclusive `rlimit` output.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) };
    if rc != 0 {
        return None;
    }
    if lim.rlim_cur == libc::RLIM_INFINITY {
        Some(u64::MAX)
    } else {
        Some(lim.rlim_cur as u64)
    }
}

/// `uname(2)` release string, e.g. `6.8.0-45-generic`.
pub fn kernel_release() -> Option<String> {
    // SAFETY: `utsname` is a plain C struct of char arrays; all-zero is valid.
    let mut uts: libc::utsname = unsafe { mem::zeroed() };
    // SAFETY: `uts` is a valid exclusive output.
    if unsafe { libc::uname(&mut uts) } != 0 {
        return None;
    }
    // SAFETY: on success `release` is a NUL-terminated string inside `uts`.
    let release = unsafe { CStr::from_ptr(uts.release.as_ptr()) };
    Some(release.to_string_lossy().into_owned())
}

/// `"6.8.0-45-generic"` -> `(6, 8)`; `"5.15"` -> `(5, 15)`; anything without a
/// numeric `major.minor` prefix -> `None`.
pub fn parse_kernel(release: &str) -> Option<(u32, u32)> {
    let (major, rest) = release.trim().split_once('.')?;
    let major = major.parse().ok()?;
    let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    let minor = rest[..digits].parse().ok()?;
    Some((major, minor))
}

/// `MemTotal` from `/proc/meminfo`, in KiB.
pub fn meminfo_total_kib() -> Option<u64> {
    parse_meminfo(&std::fs::read_to_string("/proc/meminfo").ok()?)
}

/// The `MemTotal:   16384 kB` line of a `/proc/meminfo` text, in KiB.
pub fn parse_meminfo(text: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn errno_text(what: &str) -> String {
    format!("{what}: {}", io::Error::last_os_error())
}

/// Create, size, map and unmap a `memfd_secret` region, the sequence the
/// daemon's secure memory uses. Always closes the descriptor.
pub fn probe_memfd_secret() -> Result<(), String> {
    const LEN: usize = 4096;
    // SAFETY: `SYS_memfd_secret` takes one flags word; `O_CLOEXEC` is the only
    // accepted bit. It returns a new fd or -1 with errno set.
    let fd = unsafe { libc::syscall(libc::SYS_memfd_secret, libc::O_CLOEXEC as libc::c_long) };
    if fd < 0 {
        return Err(errno_text("memfd_secret"));
    }
    // SAFETY: `fd` is a freshly created descriptor that nothing else owns;
    // `OwnedFd` closes it on every return path.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    // SAFETY: `fd` is open for the duration of the call.
    if unsafe { libc::ftruncate(fd.as_raw_fd(), LEN as libc::off_t) } != 0 {
        return Err(errno_text("ftruncate on memfd_secret"));
    }
    // SAFETY: a null hint lets the kernel choose the address; `fd` is open and
    // sized to `LEN`; `MAP_SHARED` is required by secretmem.
    let map = unsafe {
        libc::mmap(
            ptr::null_mut(),
            LEN,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            0,
        )
    };
    if map == libc::MAP_FAILED {
        return Err(errno_text("mmap of memfd_secret"));
    }
    // SAFETY: `map` is the live `LEN`-byte mapping created above and is not
    // used afterwards.
    unsafe { libc::munmap(map, LEN) };
    Ok(())
}

/// `io_uring_setup(1, ...)` and close the ring. `Err` carries the errno text
/// (`ENOSYS` and `EPERM` are the interesting ones).
pub fn probe_io_uring() -> Result<(), String> {
    // `libc` has no `io_uring_params`; the kernel struct is 120 bytes and
    // all-zero is a valid request.
    let mut params = [0u8; 120];
    let entries: libc::c_long = 1;
    // SAFETY: `io_uring_setup(entries, params*)` reads and writes at most the
    // 120-byte `io_uring_params` that `params` provides; it returns a new fd or
    // -1 with errno set.
    let fd = unsafe { libc::syscall(libc::SYS_io_uring_setup, entries, params.as_mut_ptr()) };
    if fd < 0 {
        return Err(errno_text("io_uring_setup"));
    }
    // SAFETY: `fd` is a freshly created descriptor that nothing else owns;
    // dropping the `OwnedFd` closes it.
    drop(unsafe { OwnedFd::from_raw_fd(fd as i32) });
    Ok(())
}

/// Discard pending, unread terminal input on stdin. Errors are ignored.
pub fn tcflush_stdin() {
    // SAFETY: `tcflush` on fd 0 takes no pointers; failure (not a tty) is
    // deliberately ignored.
    unsafe { libc::tcflush(0, libc::TCIFLUSH) };
}

/// Keeps fd 2 pointed at `/dev/null` until dropped.
#[cfg_attr(not(feature = "devices"), allow(dead_code))]
pub struct StderrGuard {
    /// Duplicate of the original fd 2, or -1 when nothing was redirected.
    saved: i32,
}

impl Drop for StderrGuard {
    fn drop(&mut self) {
        if self.saved < 0 {
            return;
        }
        // SAFETY: `saved` is a descriptor this guard owns; `dup2` onto fd 2
        // and `close` take no pointers.
        unsafe {
            libc::dup2(self.saved, 2);
            libc::close(self.saved);
        }
        self.saved = -1;
    }
}

/// Redirect fd 2 to `/dev/null` until the guard drops, so hardware probes that
/// write to stderr cannot garble the TUI. If the redirect cannot be set up,
/// stderr is left untouched.
// Used by the device probes only; without `devices` nothing calls it.
#[cfg_attr(not(feature = "devices"), allow(dead_code))]
pub fn silence_stderr() -> StderrGuard {
    let Ok(null) = std::fs::OpenOptions::new()
        .write(true)
        .open(OsStr::new("/dev/null"))
    else {
        return StderrGuard { saved: -1 };
    };
    // SAFETY: `dup` on fd 2 takes no pointers; it returns a new fd or -1.
    let saved = unsafe { libc::dup(2) };
    if saved < 0 {
        return StderrGuard { saved: -1 };
    }
    // SAFETY: `null` is an open descriptor; `dup2` onto fd 2 takes no pointers.
    if unsafe { libc::dup2(null.as_raw_fd(), 2) } < 0 {
        // SAFETY: `saved` is the descriptor `dup` just returned; close it.
        unsafe { libc::close(saved) };
        return StderrGuard { saved: -1 };
    }
    StderrGuard { saved }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn parse_kernel_extracts_major_minor() {
        assert_eq!(parse_kernel("6.8.0-45-generic"), Some((6, 8)));
        assert_eq!(parse_kernel("5.15"), Some((5, 15)));
        assert_eq!(parse_kernel("6.12-rc1"), Some((6, 12)));
        assert_eq!(parse_kernel("6.x.0"), None);
        assert_eq!(parse_kernel("6"), None);
        assert_eq!(parse_kernel(""), None);
        assert_eq!(parse_kernel("garbage"), None);
    }

    #[test]
    fn parse_meminfo_reads_memtotal() {
        let text = "MemTotal:       16384256 kB\nMemFree:         1000 kB\n";
        assert_eq!(parse_meminfo(text), Some(16_384_256));
        assert_eq!(parse_meminfo("MemFree: 1 kB\n"), None);
        assert_eq!(parse_meminfo("MemTotal: lots kB\n"), None);
    }

    #[test]
    fn nearest_existing_ancestor_walks_up() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(nearest_existing_ancestor(dir.path()), dir.path());
        let deep = dir.path().join("a/b/c");
        assert_eq!(nearest_existing_ancestor(&deep), dir.path());
        std::fs::create_dir_all(dir.path().join("a")).unwrap();
        assert_eq!(nearest_existing_ancestor(&deep), dir.path().join("a"));
    }

    #[test]
    fn nearest_existing_ancestor_counts_dangling_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("dangling");
        symlink(dir.path().join("nowhere"), &link).unwrap();
        assert_eq!(nearest_existing_ancestor(&link.join("x")), link);
    }

    #[test]
    fn root_account_lookups_agree() {
        let by_name = lookup_user("root").expect("root exists");
        assert_eq!(by_name.uid, 0);
        let by_uid = lookup_uid(0).expect("uid 0 exists");
        assert_eq!(by_uid.name, by_name.name);
        assert_eq!(by_uid, by_name);
        assert_eq!(group_name(0).as_deref(), Some("root"));
        assert_eq!(lookup_group("root"), Some(0));
    }

    #[test]
    fn lookups_reject_unknown_and_nul() {
        assert_eq!(lookup_user("y2q-no-such-user-xyz"), None);
        assert_eq!(lookup_user("ro\0ot"), None);
        assert_eq!(lookup_group("y2q-no-such-group-xyz"), None);
        assert_eq!(lookup_group("ro\0ot"), None);
    }

    #[test]
    fn user_in_group_covers_primary_group_and_missing_names() {
        let root = lookup_user("root").unwrap();
        let group = group_name(root.gid).expect("primary group has a name");
        assert!(user_in_group("root", &group));
        assert!(!user_in_group("y2q-no-such-user-xyz", &group));
        assert!(!user_in_group("root", "y2q-no-such-group-xyz"));
    }

    #[test]
    fn euid_matches_libc() {
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        assert_eq!(euid(), unsafe { libc::geteuid() });
    }

    #[test]
    fn stat_predicates_distinguish_types() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"abc").unwrap();
        let link = dir.path().join("l");
        symlink(&file, &link).unwrap();

        let d = stat(dir.path()).unwrap();
        assert!(d.is_dir() && !d.is_file() && !d.is_symlink());
        let f = stat(&file).unwrap();
        assert!(f.is_file() && !f.is_dir());
        assert_eq!(f.nlink, 1);
        // `stat` follows the link, `lstat` does not.
        assert!(stat(&link).unwrap().is_file());
        let l = lstat(&link).unwrap();
        assert!(l.is_symlink() && !l.is_file());
        assert_eq!(f.perm(), f.mode & 0o7777);
    }

    #[test]
    fn open_nofollow_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        let link = dir.path().join("l");
        symlink(&file, &link).unwrap();

        let err = open_nofollow(&link, libc::O_RDONLY, 0).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
        open_nofollow(&file, libc::O_RDONLY, 0).expect("regular file opens");
    }

    #[test]
    fn open_nofollow_creates_with_exact_mode_and_excl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new");
        let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL;
        let f = open_nofollow(&path, flags, 0o400).unwrap();
        // Creation mode is subject to umask, which can only narrow 0o400.
        assert_eq!(fstat(&f).unwrap().perm() & !0o400, 0);
        let again = open_nofollow(&path, flags, 0o400).unwrap_err();
        assert_eq!(again.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn fchmod_fchown_fstat_lstat_on_tempfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        let f = open_nofollow(&path, libc::O_RDWR | libc::O_CREAT, 0o644).unwrap();

        fchmod(&f, 0o640).unwrap();
        assert_eq!(fstat(&f).unwrap().perm(), 0o640);
        assert_eq!(lstat(&path).unwrap().perm(), 0o640);

        // Chown to the ids it already has: always permitted, no root needed.
        let before = fstat(&f).unwrap();
        fchown(&f, Some(before.uid), Some(before.gid)).unwrap();
        fchown(&f, None, None).unwrap();
        let after = lstat(&path).unwrap();
        assert_eq!((after.uid, after.gid), (before.uid, before.gid));
        assert_eq!(after.uid, euid());
    }

    #[test]
    fn free_bytes_and_tmpfs_do_not_fail_on_existing_path() {
        let dir = tempfile::tempdir().unwrap();
        assert!(free_bytes(dir.path()).is_ok());
        assert!(free_bytes(&dir.path().join("missing")).is_err());
        assert!(!is_tmpfs(&dir.path().join("missing")));
    }

    #[test]
    fn stderr_guard_restores_original_fd() {
        // Identity (dev, ino) of whatever fd 2 currently points at.
        let ident = || {
            let m = std::fs::metadata("/proc/self/fd/2").expect("fd 2 is open");
            (m.dev(), m.ino())
        };
        let null = std::fs::metadata("/dev/null").unwrap();
        let before = ident();
        {
            let _guard = silence_stderr();
            assert_eq!(ident(), (null.dev(), null.ino()));
        }
        assert_eq!(ident(), before);
    }
}
