//! Uninitialized byte-buffer allocation helpers for read paths.
//!
//! `vec![0u8; N]` performs a `memset` of N zero bytes before the read fills
//! them. The profile showed `alloc::vec::from_elem` accounting for ~2.7% of
//! request-handler CPU. These helpers replace the pattern with a
//! `Vec::with_capacity(N)` plus `set_len(N)` on uninitialized memory; the
//! subsequent `read_exact_at` overwrites all N bytes.
//!
//! Recycling buffers across requests was considered but rejected: io_uring's
//! `read_exact_at` reads to the buffer's `capacity`, not its `len`, so a
//! pooled buffer whose capacity exceeds the requested size would over-read
//! into the file. Fresh `Vec::with_capacity(n)` returns a buffer with
//! capacity exactly `n`, so the read length is bounded correctly.

/// Allocate a `Vec<u8>` of length exactly `n` with uninitialized contents.
///
/// # Safety
///
/// The returned vec has `len == n` and `capacity == n`, but its bytes are
/// uninitialized memory. Callers must fully overwrite all `n` bytes before
/// reading any byte. Used with `io_uring::read_exact_at`, which writes
/// exactly `capacity` bytes on success.
pub unsafe fn acquire_uninit(n: usize) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let mut v = Vec::with_capacity(n);
    debug_assert_eq!(v.capacity(), n);
    // SAFETY: capacity == n; caller promises to fully overwrite all n bytes
    // before any read.
    unsafe { v.set_len(n) };
    v
}

/// No-op placeholder retained so call sites that release buffers on error
/// paths read symmetrically with the acquire call. Recycling would require
/// the buffer's capacity to exactly match the next requested size, which is
/// rare for variable-size reads — direct allocation wins.
#[inline]
pub fn release(_v: Vec<u8>) {}
