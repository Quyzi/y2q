//! Guarded memory for long-lived and transient secret material.
//!
//! This is *not* a crypto primitive module (see [`crate::crypto`] for that);
//! it is a memory-safety layer that sits underneath the crypto layer and the
//! daemon's session store. It buys one property: a memory disclosure of a
//! running process (core dump, swap/hibernation image, same-uid `ptrace` /
//! `/proc/<pid>/mem` read, or a VM snapshot taken while no request is
//! mid-flight) does not yield plaintext key material.
//!
//! Two allocation shapes:
//! - [`SecretBuf`] — a long-lived secret. Its pages are `PROT_NONE` at rest;
//!   [`SecretBuf::unlock`] briefly makes them readable for the duration of a
//!   held [`SecretRead`] guard.
//! - [`SecretVec`] — a transient plaintext workspace, readable for its whole
//!   (short) life, used as the destination of a decrypt or the source of an
//!   encrypt.
//!
//! [`MemoryKey`] wraps long-lived secrets as AES-256-GCM ciphertext
//! ([`SealedSecret`]) under a process-ephemeral key that itself lives in a
//! [`SecretBuf`].
//!
//! [`harden_process`] additionally disables core dumps and same-uid debugger
//! attach for the whole process. Call it once at boot, before any secret is
//! loaded.
//!
//! Linux gets the full guarded-memory implementation (`mmap` + `mprotect` +
//! `mlock` + `madvise`), gated the same way the io_uring storage backend is
//! ([`crate::storage::uring`]): compiled only on Linux. Other targets get a
//! [`Zeroizing`]-backed fallback behind the same API, with a one-time startup
//! warning that memory protection is unavailable.

use std::fmt;
use std::ops::Deref;
use std::sync::OnceLock;

use aes_gcm::{Aes256Gcm, KeyInit, aead::AeadInOut};
use rand::Rng;
use zeroize::Zeroize;

use crate::crypto::CryptoError;

type Nonce = aes_gcm::aead::Nonce<Aes256Gcm>;

/// Whether a guarded-memory allocation failure is fatal.
///
/// Set once, at boot, via [`harden_process`]; every subsequent allocation
/// consults [`policy`]. Defaults to [`Policy::BestEffort`] until
/// `harden_process` runs (so unit tests that never call it aren't at the
/// mercy of the test runner's `RLIMIT_MEMLOCK`).
#[derive(Clone, Copy, Debug)]
pub enum Policy {
    /// A failed `mlock` (or, on Linux, a failed `mprotect`/`mmap`) is fatal.
    Require,
    /// A failed `mlock` degrades to an unlocked (but still `mmap`-backed,
    /// still zeroized-on-drop) allocation, logged once.
    BestEffort,
}

static POLICY: OnceLock<Policy> = OnceLock::new();

/// The globally installed [`Policy`]. `BestEffort` until [`harden_process`]
/// runs.
pub fn policy() -> Policy {
    match POLICY.get() {
        Some(p) => *p,
        None => Policy::BestEffort,
    }
}

/// Errors raised by the guarded-memory layer.
#[derive(thiserror::Error, Debug)]
pub enum SecMemError {
    /// `mmap` of a guarded region failed.
    #[error("mmap of {bytes} guarded bytes failed: {errno}")]
    Map {
        /// Total bytes requested, including guard pages.
        bytes: usize,
        /// `errno` from the failed syscall.
        errno: i32,
    },
    /// `mlock` failed and [`Policy::Require`] is in effect.
    #[error(
        "mlock failed ({errno}); raise RLIMIT_MEMLOCK or set [server] allow_unprotected_memory = true"
    )]
    Lock {
        /// `errno` from the failed syscall.
        errno: i32,
    },
    /// `mprotect` failed.
    #[error("mprotect failed: {errno}")]
    Protect {
        /// `errno` from the failed syscall.
        errno: i32,
    },
    /// `prctl(PR_SET_DUMPABLE)` failed.
    #[error("prctl(PR_SET_DUMPABLE) failed: {errno}")]
    Dumpable {
        /// `errno` from the failed syscall.
        errno: i32,
    },
    /// A [`SecretVec`] write would exceed its fixed capacity.
    #[error("secret buffer capacity {cap} exceeded by {needed} bytes")]
    Capacity {
        /// The buffer's fixed capacity.
        cap: usize,
        /// The length that was needed to satisfy the write.
        needed: usize,
    },
    /// A secret buffer's content was requested as `&str` but is not valid
    /// UTF-8.
    #[error("secret is not valid UTF-8")]
    NotUtf8,
}

/// Volatile-zero every byte of a plain-old-data value.
///
/// # Safety
/// `T` must be POD with no validity invariants (an all-zero bit pattern must
/// be a legal value of `T`) and no `Drop` implementation that depends on its
/// prior content. Intended for the KEM `SharedSecret`'s `Copy` newtype over
/// `[u8; N]`, which has no `Drop` of its own.
pub unsafe fn scrub_pod<T: Copy>(value: &mut T) {
    let len = std::mem::size_of::<T>();
    let ptr = (value as *mut T).cast::<u8>();
    for i in 0..len {
        // SAFETY: `ptr` is derived from a valid `&mut T` and `i < size_of::<T>()`.
        unsafe { std::ptr::write_volatile(ptr.add(i), 0u8) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Linux: mmap-backed guarded regions.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_region {
    use std::sync::{Mutex, Once};

    use zeroize::Zeroize;

    use super::{Policy, SecMemError, policy};

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    fn page_size() -> usize {
        static PAGE_SIZE: std::sync::LazyLock<usize> = std::sync::LazyLock::new(|| {
            // SAFETY: `sysconf` with `_SC_PAGESIZE` is always safe to call.
            let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            if ps > 0 { ps as usize } else { 4096 }
        });
        *PAGE_SIZE
    }

    fn warn_mlock_once(errno: i32) {
        static WARNED: Once = Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                errno,
                "mlock failed; guarded memory running in best-effort mode \
                 (secrets may be written to swap)"
            );
        });
    }

    fn debug_madvise_once(advice: &'static str) {
        static WARNED_DONTDUMP: Once = Once::new();
        static WARNED_WIPEONFORK: Once = Once::new();
        let once = if advice == "MADV_DONTDUMP" {
            &WARNED_DONTDUMP
        } else {
            &WARNED_WIPEONFORK
        };
        once.call_once(|| {
            tracing::debug!(advice, "madvise hint unsupported on this kernel");
        });
    }

    /// A guarded `mmap` region: an inaccessible guard page, then a
    /// page-aligned data region, then another inaccessible guard page.
    pub(super) struct Region {
        base: *mut u8,
        pub(super) data: *mut u8,
        pub(super) data_len: usize,
        map_len: usize,
        locked: bool,
    }

    // SAFETY: the mapping is uniquely owned by the `Region` that holds it;
    // it has no thread affinity, and all mutation goes through `&self`
    // syscalls (`mprotect`) that are safe to call concurrently.
    unsafe impl Send for Region {}
    // SAFETY: see above; concurrent `mprotect`/reads are safe because the
    // kernel serializes page-table updates and readers only ever observe
    // either the old or the new protection, never torn state.
    unsafe impl Sync for Region {}

    impl Region {
        pub(super) fn alloc(min_len: usize) -> Result<Self, SecMemError> {
            let ps = page_size();
            let data_len = min_len.max(1).div_ceil(ps) * ps;
            let map_len = data_len + 2 * ps;

            // SAFETY: anonymous private mapping, no fd, valid arguments.
            let base = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    map_len,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if base == libc::MAP_FAILED {
                return Err(SecMemError::Map {
                    bytes: map_len,
                    errno: errno(),
                });
            }
            let base = base.cast::<u8>();
            // SAFETY: `base` is the start of a `map_len`-byte mapping, so
            // `base + ps` is within bounds (guarded by the `data_len` check
            // above: `map_len == data_len + 2 * ps`).
            let data = unsafe { base.add(ps) };

            // SAFETY: `data..data+data_len` lies entirely within the mapping.
            let rc = unsafe {
                libc::mprotect(
                    data.cast::<libc::c_void>(),
                    data_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            };
            if rc != 0 {
                let e = errno();
                // SAFETY: `base`/`map_len` are the exact mapping just created.
                unsafe { libc::munmap(base.cast::<libc::c_void>(), map_len) };
                return Err(SecMemError::Protect { errno: e });
            }

            // SAFETY: as above.
            let mlock_rc = unsafe { libc::mlock(data.cast::<libc::c_void>(), data_len) };
            let locked = if mlock_rc == 0 {
                true
            } else {
                let e = errno();
                match policy() {
                    Policy::Require => {
                        // SAFETY: as above.
                        unsafe { libc::munmap(base.cast::<libc::c_void>(), map_len) };
                        return Err(SecMemError::Lock { errno: e });
                    }
                    Policy::BestEffort => {
                        warn_mlock_once(e);
                        false
                    }
                }
            };

            // SAFETY: as above. Both hints are best-effort; failure is
            // tolerated (older kernels lack one or both).
            unsafe {
                if libc::madvise(data.cast::<libc::c_void>(), data_len, libc::MADV_DONTDUMP) != 0 {
                    debug_madvise_once("MADV_DONTDUMP");
                }
                if libc::madvise(data.cast::<libc::c_void>(), data_len, libc::MADV_WIPEONFORK) != 0
                {
                    debug_madvise_once("MADV_WIPEONFORK");
                }
            }

            Ok(Region {
                base,
                data,
                data_len,
                map_len,
                locked,
            })
        }

        /// # Safety
        /// Caller must ensure no other reference derived from this region's
        /// data pointer is live for the duration the returned slice is used.
        pub(super) unsafe fn data_slice(&self) -> &[u8] {
            // SAFETY: `data..data+data_len` was `mprotect`ed readable at
            // construction and is only ever set back to `PROT_NONE` while no
            // `SecretRead`/`SecretVec` slice is alive (enforced by callers).
            unsafe { std::slice::from_raw_parts(self.data, self.data_len) }
        }

        pub(super) fn data_slice_mut(&mut self) -> &mut [u8] {
            // SAFETY: `&mut self` proves unique access; the region is always
            // `PROT_READ | PROT_WRITE` while a `&mut Region` is reachable
            // (construction, or `SecretVec`, which never drops to
            // `PROT_NONE`).
            unsafe { std::slice::from_raw_parts_mut(self.data, self.data_len) }
        }

        pub(super) fn protect(&self, prot: libc::c_int) -> Result<(), SecMemError> {
            // SAFETY: `data..data+data_len` lies entirely within the mapping.
            let rc =
                unsafe { libc::mprotect(self.data.cast::<libc::c_void>(), self.data_len, prot) };
            if rc != 0 {
                return Err(SecMemError::Protect { errno: errno() });
            }
            Ok(())
        }
    }

    impl Drop for Region {
        fn drop(&mut self) {
            // SAFETY: restoring RW before scrubbing; the region may already
            // be RW (SecretVec) or PROT_NONE (SecretBuf at rest) — either is
            // a valid prior state for `mprotect` to transition from.
            unsafe {
                let _ = libc::mprotect(
                    self.data.cast::<libc::c_void>(),
                    self.data_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                );
            }
            // SAFETY: `data..data+data_len` is now RW and uniquely owned by
            // this `Region`, which is being dropped.
            let slice = unsafe { std::slice::from_raw_parts_mut(self.data, self.data_len) };
            slice.zeroize();
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
            // SAFETY: `data`/`data_len` describe the locked region exactly.
            unsafe {
                if self.locked {
                    libc::munlock(self.data.cast::<libc::c_void>(), self.data_len);
                }
                libc::munmap(self.base.cast::<libc::c_void>(), self.map_len);
            }
        }
    }

    /// Guard counter behind a `Mutex`: `0 -> 1` makes the region readable,
    /// `1 -> 0` (on drop) restores `PROT_NONE`. Nesting is required because
    /// one [`super::MemoryKey`] is shared by every request thread.
    pub(super) struct GuardCount(pub(super) Mutex<usize>);

    impl GuardCount {
        pub(super) fn new() -> Self {
            Self(Mutex::new(0))
        }
    }
}

// ---------------------------------------------------------------------------
// SecretBuf
// ---------------------------------------------------------------------------

/// A long-lived secret. Its data pages are `PROT_NONE` unless a
/// [`SecretRead`] guard is currently alive (Linux); on other platforms the
/// content is always resident in an ordinary (zeroize-on-drop) allocation.
#[cfg(target_os = "linux")]
pub struct SecretBuf {
    region: linux_region::Region,
    len: usize,
    active: linux_region::GuardCount,
}

#[cfg(not(target_os = "linux"))]
pub struct SecretBuf {
    data: zeroize::Zeroizing<Vec<u8>>,
}

impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

// SAFETY: the guarded region (or, on the fallback path, the heap buffer) is
// uniquely owned and has no thread affinity; all mutation goes through
// interior syscalls/mutexes safe to call from any thread.
unsafe impl Send for SecretBuf {}
// SAFETY: see above; `unlock`'s guard counter serializes protection changes.
unsafe impl Sync for SecretBuf {}

#[cfg(target_os = "linux")]
impl SecretBuf {
    /// Copy `src` into a freshly allocated guarded region.
    pub fn from_slice(src: &[u8]) -> Result<Self, SecMemError> {
        let mut region = linux_region::Region::alloc(src.len())?;
        region.data_slice_mut()[..src.len()].copy_from_slice(src);
        region.protect(libc::PROT_NONE)?;
        Ok(Self {
            region,
            len: src.len(),
            active: linux_region::GuardCount::new(),
        })
    }

    /// Fill a freshly allocated guarded region with `len` random bytes.
    pub fn random(len: usize) -> Result<Self, SecMemError> {
        let mut region = linux_region::Region::alloc(len)?;
        rand::rng().fill_bytes(&mut region.data_slice_mut()[..len]);
        region.protect(libc::PROT_NONE)?;
        Ok(Self {
            region,
            len,
            active: linux_region::GuardCount::new(),
        })
    }

    /// Number of secret bytes held.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether this buffer holds zero bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Make the buffer's content readable for the lifetime of the returned
    /// guard. Nested/concurrent calls are reference-counted: the pages stay
    /// readable until every outstanding [`SecretRead`] is dropped.
    pub fn unlock(&self) -> Result<SecretRead<'_>, SecMemError> {
        let mut count = self.active.0.lock().unwrap_or_else(|e| e.into_inner());
        if *count == 0 {
            self.region.protect(libc::PROT_READ)?;
        }
        *count += 1;
        Ok(SecretRead { buf: self })
    }

    fn exposed_slice(&self) -> &[u8] {
        // SAFETY: only called from `SecretRead::deref`, which can only exist
        // while `unlock`'s guard count is nonzero, i.e. the region is
        // `PROT_READ`.
        &(unsafe { self.region.data_slice() })[..self.len]
    }
}

#[cfg(all(test, target_os = "linux"))]
impl SecretBuf {
    fn data_ptr(&self) -> *const u8 {
        self.region.data
    }
}

#[cfg(not(target_os = "linux"))]
impl SecretBuf {
    /// Copy `src` into a freshly allocated secret buffer.
    pub fn from_slice(src: &[u8]) -> Result<Self, SecMemError> {
        Ok(Self {
            data: zeroize::Zeroizing::new(src.to_vec()),
        })
    }

    /// Fill a freshly allocated secret buffer with `len` random bytes.
    pub fn random(len: usize) -> Result<Self, SecMemError> {
        let mut v = vec![0u8; len];
        rand::rng().fill_bytes(&mut v);
        Ok(Self {
            data: zeroize::Zeroizing::new(v),
        })
    }

    /// Number of secret bytes held.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether this buffer holds zero bytes.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns a no-op guard: the fallback path has no page protection to
    /// toggle.
    pub fn unlock(&self) -> Result<SecretRead<'_>, SecMemError> {
        Ok(SecretRead { buf: self })
    }

    fn exposed_slice(&self) -> &[u8] {
        &self.data
    }
}

/// Guard returned by [`SecretBuf::unlock`]. Derefs to the buffer's plaintext
/// for as long as it's held.
pub struct SecretRead<'a> {
    buf: &'a SecretBuf,
}

impl Deref for SecretRead<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.buf.exposed_slice()
    }
}

// SAFETY: `&'a SecretBuf` is `Send` because `SecretBuf: Sync`; stated
// explicitly because request handlers hold a `SecretRead` across `.await`
// points.
unsafe impl Send for SecretRead<'_> {}

#[cfg(target_os = "linux")]
impl Drop for SecretRead<'_> {
    fn drop(&mut self) {
        let mut count = self.buf.active.0.lock().unwrap_or_else(|e| e.into_inner());
        *count = count.saturating_sub(1);
        if *count == 0
            && let Err(e) = self.buf.region.protect(libc::PROT_NONE)
        {
            tracing::error!(error = %e, "failed to re-lock guarded secret buffer");
        }
    }
}

// ---------------------------------------------------------------------------
// SecretVec
// ---------------------------------------------------------------------------

/// A transient plaintext workspace: readable for its whole (short) life,
/// with a fixed capacity fixed at construction. Used as the destination of a
/// decrypt or the source of an encrypt.
#[cfg(target_os = "linux")]
pub struct SecretVec {
    region: linux_region::Region,
    len: usize,
    cap: usize,
}

#[cfg(not(target_os = "linux"))]
pub struct SecretVec {
    data: zeroize::Zeroizing<Vec<u8>>,
    cap: usize,
}

impl fmt::Debug for SecretVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

// SAFETY: see `SecretBuf`'s `Send` impl; `SecretVec` is not `Sync` (no
// internal synchronization for concurrent mutation).
unsafe impl Send for SecretVec {}

#[cfg(target_os = "linux")]
impl SecretVec {
    /// Set the number of written bytes without touching capacity.
    fn set_len(&mut self, new_len: usize) {
        self.len = new_len;
    }

    /// Allocate `len` zeroed bytes (already the case: `mmap` anonymous
    /// pages are zero-filled).
    pub fn zeroed(len: usize) -> Result<Self, SecMemError> {
        let region = linux_region::Region::alloc(len)?;
        Ok(Self {
            region,
            len,
            cap: len,
        })
    }

    /// Allocate `cap` bytes of headroom with nothing written yet.
    pub fn with_capacity(cap: usize) -> Result<Self, SecMemError> {
        let region = linux_region::Region::alloc(cap)?;
        Ok(Self {
            region,
            len: 0,
            cap,
        })
    }

    /// Copy `src` into a freshly allocated, exactly-sized buffer.
    pub fn from_slice(src: &[u8]) -> Result<Self, SecMemError> {
        let mut v = Self::with_capacity(src.len())?;
        v.push_slice(src)?;
        Ok(v)
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: `SecretVec`'s region is always `PROT_READ | PROT_WRITE`
        // for its whole life (never dropped to `PROT_NONE`).
        &(unsafe { self.region.data_slice() })[..self.len]
    }

    /// Number of bytes currently written.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether zero bytes have been written.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Fixed capacity set at construction.
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// The written bytes, mutably.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.region.data_slice_mut()[..self.len]
    }

    /// Append `src`, failing rather than reallocating if it would exceed
    /// [`SecretVec::capacity`].
    pub fn push_slice(&mut self, src: &[u8]) -> Result<(), SecMemError> {
        let needed = self.len + src.len();
        if needed > self.cap {
            return Err(SecMemError::Capacity {
                cap: self.cap,
                needed,
            });
        }
        let start = self.len;
        self.region.data_slice_mut()[start..needed].copy_from_slice(src);
        self.len = needed;
        Ok(())
    }

    /// Interpret the written bytes as UTF-8.
    pub fn as_str(&self) -> Result<&str, SecMemError> {
        std::str::from_utf8(self.as_slice()).map_err(|_| SecMemError::NotUtf8)
    }
}

#[cfg(not(target_os = "linux"))]
impl SecretVec {
    /// Set the number of written bytes without touching capacity.
    fn set_len(&mut self, new_len: usize) {
        self.data.truncate(new_len);
    }

    /// Allocate `len` zeroed bytes.
    pub fn zeroed(len: usize) -> Result<Self, SecMemError> {
        Ok(Self {
            data: zeroize::Zeroizing::new(vec![0u8; len]),
            cap: len,
        })
    }

    /// Allocate `cap` bytes of headroom with nothing written yet.
    pub fn with_capacity(cap: usize) -> Result<Self, SecMemError> {
        Ok(Self {
            data: zeroize::Zeroizing::new(Vec::with_capacity(cap)),
            cap,
        })
    }

    /// Copy `src` into a freshly allocated, exactly-sized buffer.
    pub fn from_slice(src: &[u8]) -> Result<Self, SecMemError> {
        Ok(Self {
            data: zeroize::Zeroizing::new(src.to_vec()),
            cap: src.len(),
        })
    }

    fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Number of bytes currently written.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether zero bytes have been written.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Fixed capacity set at construction.
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// The written bytes, mutably.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Append `src`, failing rather than reallocating if it would exceed
    /// [`SecretVec::capacity`].
    pub fn push_slice(&mut self, src: &[u8]) -> Result<(), SecMemError> {
        let needed = self.data.len() + src.len();
        if needed > self.cap {
            return Err(SecMemError::Capacity {
                cap: self.cap,
                needed,
            });
        }
        self.data.extend_from_slice(src);
        Ok(())
    }

    /// Interpret the written bytes as UTF-8.
    pub fn as_str(&self) -> Result<&str, SecMemError> {
        std::str::from_utf8(&self.data).map_err(|_| SecMemError::NotUtf8)
    }
}

impl Deref for SecretVec {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for SecretVec {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for SecretVec {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl aes_gcm::aead::Buffer for SecretVec {
    fn extend_from_slice(&mut self, other: &[u8]) -> aes_gcm::aead::Result<()> {
        self.push_slice(other).map_err(|_| aes_gcm::aead::Error)
    }

    fn truncate(&mut self, new_len: usize) {
        let cur = self.len();
        if new_len < cur {
            self.as_mut_slice()[new_len..cur].zeroize();
            self.set_len(new_len);
        }
    }
}

// ---------------------------------------------------------------------------
// MemoryKey / SealedSecret
// ---------------------------------------------------------------------------

/// A process-ephemeral AES-256-GCM key held in a [`SecretBuf`]. Used to wrap
/// long-lived secrets (identity keys, bucket keys) as [`SealedSecret`]
/// ciphertext so they never sit as plaintext in ordinary heap between uses.
pub struct MemoryKey {
    key: SecretBuf,
}

impl fmt::Debug for MemoryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// AES-256-GCM ciphertext produced by [`MemoryKey::seal`]. Inert: safe to
/// hold in ordinary heap, clone, and move between sessions (opening it
/// requires both the sealing [`MemoryKey`] and the original AAD).
#[derive(Clone)]
pub struct SealedSecret {
    nonce: [u8; 12],
    ct: Vec<u8>,
}

impl fmt::Debug for SealedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl MemoryKey {
    /// Generate a fresh 32-byte key in guarded memory.
    pub fn generate() -> Result<Self, SecMemError> {
        Ok(Self {
            key: SecretBuf::random(32)?,
        })
    }

    /// Encrypt `plaintext`, binding it to `aad`. The plaintext transits a
    /// guarded [`SecretVec`], never an ordinary heap `Vec`.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<SealedSecret, CryptoError> {
        let guard = self.key.unlock()?;
        let cipher = Aes256Gcm::new_from_slice(&guard)
            .map_err(|_| CryptoError::Aead("memory key length"))?;
        drop(guard);

        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);

        // Capacity is plaintext + 16-byte GCM tag, appended in place by
        // `encrypt_in_place` via `Buffer::extend_from_slice`.
        let mut buf = SecretVec::with_capacity(plaintext.len() + 16)?;
        buf.push_slice(plaintext)?;
        cipher
            .encrypt_in_place(&Nonce::from(nonce_bytes), aad, &mut buf)
            .map_err(|_| CryptoError::Aead("memory key seal"))?;

        Ok(SealedSecret {
            nonce: nonce_bytes,
            ct: buf.to_vec(),
        })
    }

    /// Decrypt `sealed`, requiring the same `aad` it was sealed with.
    /// Decrypts directly into a guarded [`SecretVec`]; the plaintext never
    /// lands in an ordinary heap `Vec`.
    pub fn open(&self, sealed: &SealedSecret, aad: &[u8]) -> Result<SecretVec, CryptoError> {
        let guard = self.key.unlock()?;
        let cipher = Aes256Gcm::new_from_slice(&guard)
            .map_err(|_| CryptoError::Aead("memory key length"))?;
        drop(guard);

        let mut buf = SecretVec::from_slice(&sealed.ct)?;
        cipher
            .decrypt_in_place(&Nonce::from(sealed.nonce), aad, &mut buf)
            .map_err(|_| CryptoError::AuthFailed)?;
        Ok(buf)
    }
}

// ---------------------------------------------------------------------------
// SecretString
// ---------------------------------------------------------------------------

/// A secret UTF-8 string backed by a [`SecretVec`].
pub struct SecretString(SecretVec);

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl SecretString {
    /// Borrow the content as `&str`.
    ///
    /// Panics only if the buffer's invariant (content is always written as
    /// valid UTF-8 by [`SecretString::from_str`]) has somehow been violated,
    /// which is otherwise unreachable.
    pub fn expose(&self) -> &str {
        std::str::from_utf8(&self.0).expect("SecretString invariant: content is valid UTF-8")
    }

    /// Borrow the content as raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Build a `SecretString` by copying `s` into guarded memory.
    ///
    /// Deliberately not `impl FromStr`: that trait's `Err` type can't carry
    /// `SecMemError`'s guarded-allocation failure without an `Infallible`-style
    /// widening, and every call site names the type explicitly anyway.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, SecMemError> {
        Ok(Self(SecretVec::from_slice(s.as_bytes())?))
    }

    /// Explicit copy. `SecretString` deliberately does not implement
    /// `Clone` so that copies are always a conscious choice.
    pub fn try_clone(&self) -> Result<Self, SecMemError> {
        Ok(Self(SecretVec::from_slice(&self.0)?))
    }
}

/// Serializes as a plain JSON string. Required by exactly one wire type,
/// `TokenResponse::token`, so a freshly issued bearer token can be handed
/// back to the client that authenticated for it.
impl serde::Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.expose())
    }
}

impl<'de> serde::Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = SecretString;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                SecretString::from_str(v).map_err(E::custom)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                SecretString::from_str(v).map_err(E::custom)
            }

            fn visit_string<E>(self, mut v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let out = SecretString::from_str(&v).map_err(E::custom);
                v.zeroize();
                out
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

// ---------------------------------------------------------------------------
// Process hardening
// ---------------------------------------------------------------------------

/// Disable core dumps and same-uid debugger attach, install `policy` as the
/// process-wide guarded-memory policy, then probe that guarded allocation
/// actually works (allocates and drops a 1-page [`SecretBuf`]) so a
/// too-low `RLIMIT_MEMLOCK` fails at boot rather than at first login.
///
/// `PR_SET_DUMPABLE = 0` also blocks same-uid `gdb`/`perf`/`strace -p`
/// attach against this process — that is the point, and
/// `[server] allow_unprotected_memory = true` is the escape hatch for
/// operators who need it (e.g. local debugging).
///
/// Call once, at boot, before loading any secret (including a node key).
pub fn harden_process(policy: Policy) -> Result<(), SecMemError> {
    let _ = POLICY.set(policy);

    #[cfg(target_os = "linux")]
    {
        // SAFETY: `prctl(PR_SET_DUMPABLE, 0)` takes no pointer arguments.
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if rc != 0 {
            return Err(SecMemError::Dumpable {
                errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }

        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `rlim` is a valid, fully initialized `rlimit`.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) } != 0 {
            tracing::warn!(
                errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                "failed to disable core dumps (RLIMIT_CORE); a crash may write a core file \
                 containing session key material"
            );
        }

        let probe = SecretBuf::from_slice(&[0u8])?;
        drop(probe);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        tracing::warn!(
            "guarded memory protection is unavailable on this platform; secrets remain in \
             ordinary swappable, dumpable, debuggable heap"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn secret_buf_pages_are_unreadable_at_rest() {
        let buf = SecretBuf::from_slice(&[0xABu8; 64]).unwrap();

        let mut out = [0u8; 64];
        let local_iov = libc::iovec {
            iov_base: out.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: 64,
        };
        let remote_iov = libc::iovec {
            iov_base: buf.data_ptr().cast_mut().cast::<libc::c_void>(),
            iov_len: 64,
        };
        let pid = unsafe { libc::getpid() };
        // SAFETY: iovecs point at valid, correctly sized buffers.
        let n = unsafe { libc::process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0) };
        assert_eq!(
            n, -1,
            "expected process_vm_readv to fail against a PROT_NONE page"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EFAULT)
        );

        let guard = buf.unlock().unwrap();
        assert_eq!(&guard[..], &[0xABu8; 64][..]);
    }

    #[test]
    fn memory_key_round_trip_and_aad_binding() {
        let key = MemoryKey::generate().unwrap();
        let sealed = key.seal(b"hello world", b"aad-1").unwrap();

        let opened = key.open(&sealed, b"aad-1").unwrap();
        assert_eq!(&opened[..], b"hello world");

        let err = key.open(&sealed, b"aad-2").unwrap_err();
        assert!(matches!(err, CryptoError::AuthFailed));
    }

    #[test]
    fn secret_vec_rejects_overflow() {
        let mut v = SecretVec::with_capacity(4).unwrap();
        v.push_slice(&[1, 2, 3, 4]).unwrap();
        let err = v.push_slice(&[5]).unwrap_err();
        assert!(matches!(err, SecMemError::Capacity { .. }));
    }

    #[test]
    fn secret_string_round_trips_and_redacts_debug() {
        let s = SecretString::from_str("hunter2").unwrap();
        assert_eq!(s.expose(), "hunter2");
        assert_eq!(format!("{s:?}"), "<redacted>");
        let cloned = s.try_clone().unwrap();
        assert_eq!(cloned.expose(), "hunter2");
    }
}
