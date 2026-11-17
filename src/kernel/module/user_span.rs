//! A caller's bulk `data` span, valid for one call.
//!
//! The kernel never follows an address a module wrote into bytes: the only
//! module memory a provider touches is the call's `arg` record (a slice) and
//! its `data` span (this type). A `UserSpan` is built in exactly two places:
//! the gateway, after it has checked the span against the gated caller's own
//! regions, and the ungated syscall-table entry, whose caller is trusted with
//! its own memory. The lifetime ties it to the call that built it, so a
//! provider that needs memory past its return must hold a lend instead.

use core::marker::PhantomData;
use core::ptr::NonNull;

/// A span of the caller's memory for the duration of one call.
pub struct UserSpan<'a> {
    ptr: NonNull<u8>,
    len: usize,
    _call: PhantomData<&'a mut [u8]>,
}

impl<'a> UserSpan<'a> {
    /// The empty span: a call with no `data`.
    pub const fn empty() -> Self {
        Self {
            ptr: NonNull::dangling(),
            len: 0,
            _call: PhantomData,
        }
    }

    /// The span `[ptr, ptr + len)`, or `None` when `ptr` is null and `len`
    /// is not zero. A zero length is the empty span whatever `ptr` is.
    ///
    /// # Safety
    /// For `'a`, `[ptr, ptr + len)` is memory the caller may hand the kernel:
    /// readable, and writable if the op writes it, not referenced by any
    /// other live reference the kernel holds (the call's `arg` included), and
    /// not freed.
    pub unsafe fn from_checked(ptr: *mut u8, len: usize) -> Option<Self> {
        if len == 0 {
            return Some(Self::empty());
        }
        NonNull::new(ptr).map(|ptr| Self {
            ptr,
            len,
            _call: PhantomData,
        })
    }

    /// A span over a kernel-owned buffer, for the kernel calling a provider
    /// itself.
    pub fn of(buf: &'a mut [u8]) -> Self {
        // SAFETY: an exclusive borrow for `'a` is exactly the contract.
        match unsafe { Self::from_checked(buf.as_mut_ptr(), buf.len()) } {
            Some(s) => s,
            None => Self::empty(),
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The span's bytes, to read.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `from_checked`'s contract: valid and unaliased for `'a`.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// The span as the two words a module's `extern "C"` dispatch takes:
    /// the same memory handed on to a provider that is module code.
    pub fn as_raw(&mut self) -> (*mut u8, usize) {
        if self.len == 0 {
            (core::ptr::null_mut(), 0)
        } else {
            (self.ptr.as_ptr(), self.len)
        }
    }

    /// Re-borrow for a nested call, leaving this span usable after it.
    pub fn reborrow(&mut self) -> UserSpan<'_> {
        UserSpan {
            ptr: self.ptr,
            len: self.len,
            _call: PhantomData,
        }
    }
}

/// The span's bytes, to write.
impl AsMut<[u8]> for UserSpan<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: as `as_slice`; `&mut self` makes the borrow exclusive.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

/// Whether two caller spans share a byte. A call whose `arg` and `data`
/// overlap is refused: the provider holds both at once.
pub fn overlaps(a: *const u8, a_len: usize, b: *const u8, b_len: usize) -> bool {
    if a_len == 0 || b_len == 0 {
        return false;
    }
    let (a, b) = (a as usize, b as usize);
    a < b.saturating_add(b_len) && b < a.saturating_add(a_len)
}
