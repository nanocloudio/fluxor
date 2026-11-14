// ============================================================================
// Heap Allocation Helpers
// ============================================================================
//
// Wrappers for the kernel-managed per-module heap. Modules that export
// a non-zero `arena:` in `module_facts!` receive a
// heap arena. These helpers call through the SyscallTable function pointers.
//
// The heap is bounded per-module: allocation failures return null.
// Modules MUST check for null returns and handle gracefully.

use crate::*;

/// Allocate `size` bytes from this module's heap arena.
///
/// Returns a pointer to the allocated memory, or null if the heap is
/// exhausted or if this module has no heap. Size is rounded up to 16-byte
/// alignment internally by the kernel allocator.
///
/// # Safety
/// Caller must ensure `sys` points to a valid SyscallTable.
#[inline(always)]
pub unsafe fn heap_alloc(sys: &SyscallTable, size: u32) -> *mut u8 {
    (sys.heap_alloc)(size)
}

/// Free memory previously allocated by `heap_alloc`.
///
/// Passing null is a no-op. Passing a pointer not returned by `heap_alloc`
/// for this module is detected by the kernel (logged, not crashed).
///
/// # Safety
/// Caller must ensure `sys` points to a valid SyscallTable.
/// `ptr` must be null or a pointer previously returned by `heap_alloc`.
#[inline(always)]
pub unsafe fn heap_free(sys: &SyscallTable, ptr: *mut u8) {
    (sys.heap_free)(ptr)
}

/// Reallocate memory to `new_size` bytes.
///
/// Returns a new pointer on success, or null on failure. If null is returned,
/// the original allocation at `ptr` is unchanged (not freed).
///
/// If `ptr` is null, behaves like `heap_alloc(sys, new_size)`.
/// If `new_size` is 0, behaves like `heap_free(sys, ptr)` and returns null.
///
/// # Safety
/// Caller must ensure `sys` points to a valid SyscallTable.
/// `ptr` must be null or a pointer previously returned by `heap_alloc`.
#[inline(always)]
pub unsafe fn heap_realloc(sys: &SyscallTable, ptr: *mut u8, new_size: u32) -> *mut u8 {
    (sys.heap_realloc)(ptr, new_size)
}

/// This module's heap statistics (`abi::heap_stats`): all zero if it has
/// no heap or the query is refused.
///
/// # Safety
/// Caller must ensure `sys` points to a valid SyscallTable.
#[inline(always)]
pub unsafe fn heap_stats(sys: &SyscallTable) -> abi::heap_stats::HeapStats {
    use abi::heap_stats::{HeapStats, LEN};
    let mut buf = [0u8; LEN];
    let r = (sys.provider_query)(
        -1,
        abi::kernel_abi::query_key::HEAP_STATS,
        buf.as_mut_ptr(),
        LEN,
    );
    if r != LEN as i32 {
        return HeapStats::default();
    }
    HeapStats::decode(&buf)
}
