//! Aligned-buffer support for the `O_DIRECT` large-object write path.
//!
//! `O_DIRECT` requires that user buffers, file offsets, and transfer sizes
//! are all aligned to the underlying device's logical block size — 4 KiB
//! on every NVMe device currently sold. [`AlignedBuf`] wraps
//! [`aligned_vec::AVec`] and implements [`tokio_uring::buf::IoBuf`] /
//! [`IoBufMut`] so it can be passed straight to `read_at` / `write_all_at`.
//!
//! The pool / `io_uring_register_buffers` optimization the plan calls for
//! lands as a benchmark-driven follow-up — for the first cut we allocate
//! one [`AlignedBuf`] per chunk write. The per-chunk alloc is dwarfed by
//! the underlying disk write at the 1 MiB chunk size we use.

use aligned_vec::{AVec, ConstAlign};
use tokio_uring::buf::{IoBuf, IoBufMut};

/// Required alignment for `O_DIRECT` buffers, offsets, and lengths.
///
/// Matches the logical block size of every NVMe SSD currently sold. If a
/// future device requires more, [`UringStorage`](super::UringStorage) should
/// query `statx`'s `stx_dio_mem_align` field at open time and refuse to
/// enable `O_DIRECT` if it exceeds this constant.
pub const DIRECT_IO_ALIGN: usize = 4 * 1024;

/// Default size of each chunk submitted to uring on the large-object path.
pub const DIRECT_IO_CHUNK: usize = 1024 * 1024;

/// A `Vec<u8>`-like buffer whose backing allocation is aligned to
/// [`DIRECT_IO_ALIGN`], suitable for `O_DIRECT` reads/writes.
///
/// The capacity is always rounded up to [`DIRECT_IO_ALIGN`] by
/// [`Self::with_capacity`], so a single submission's `(ptr, len)` pair will
/// be aligned end-to-end.
pub struct AlignedBuf {
    /// `ConstAlign<DIRECT_IO_ALIGN>` is required because `aligned-vec`'s
    /// runtime `align` argument must be ≤ the marker's compile-time bound;
    /// the default `AVec<u8>` uses `ConstAlign<128>` and would assert.
    inner: AVec<u8, ConstAlign<DIRECT_IO_ALIGN>>,
}

impl AlignedBuf {
    /// Copy `src` into a freshly allocated aligned buffer of exactly
    /// `src.len()` bytes.
    pub fn from_slice(src: &[u8]) -> Self {
        let mut inner =
            AVec::<u8, ConstAlign<DIRECT_IO_ALIGN>>::with_capacity(DIRECT_IO_ALIGN, src.len());
        inner.extend_from_slice(src);
        Self { inner }
    }
}

// SAFETY: the backing storage is owned by `AVec`, which keeps its pointer
// stable for the buffer's lifetime, and the alignment is guaranteed by
// `AVec::with_capacity(DIRECT_IO_ALIGN, _)`.
unsafe impl IoBuf for AlignedBuf {
    fn stable_ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }

    fn bytes_init(&self) -> usize {
        self.inner.len()
    }

    fn bytes_total(&self) -> usize {
        self.inner.capacity()
    }
}

// SAFETY: same as the `IoBuf` impl — pointer stability is provided by AVec,
// and `set_init` is upheld by only ever advancing `len` up to `capacity()`.
unsafe impl IoBufMut for AlignedBuf {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.inner.as_mut_ptr()
    }

    unsafe fn set_init(&mut self, pos: usize) {
        debug_assert!(pos <= self.inner.capacity());
        // SAFETY: caller promises `pos` bytes from the start are initialised.
        unsafe { self.inner.set_len(pos) };
    }
}
