// ============================================================================
// Heap Allocation Helpers
// ============================================================================
//
// Wrappers for the kernel-managed per-module heap. Modules that export
// `module_arena_size() -> u32` with a non-zero return value receive a
// heap arena. These helpers call through the SyscallTable function pointers.
//
// The heap is bounded per-module: allocation failures return null.
// Modules MUST check for null returns and handle gracefully.

/// Allocate `size` bytes from this module's heap arena.
///
/// Returns a pointer to the allocated memory, or null if the heap is
/// exhausted or if this module has no heap. Size is rounded up to 16-byte
/// alignment internally by the kernel allocator.
///
/// # Safety
/// Caller must ensure `sys` points to a valid SyscallTable.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
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
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
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
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
pub unsafe fn heap_realloc(sys: &SyscallTable, ptr: *mut u8, new_size: u32) -> *mut u8 {
    (sys.heap_realloc)(ptr, new_size)
}

/// Query heap statistics for this module.
///
/// Returns a HeapStats tuple `(arena_size, allocated, alloc_count,
/// total_allocs, high_water, free_blocks, largest_free)`. All
/// fields are zero if this module has no heap.
///
/// Wire layout (24 bytes, repr(C), little-endian — matches
/// `kernel::mem::heap::HeapStats`):
///   bytes 0..4   arena_size: u32
///   bytes 4..8   allocated: u32
///   bytes 8..10  alloc_count: u16
///   bytes 10..12 total_allocs: u16
///   bytes 12..16 high_water: u32
///   bytes 16..18 free_blocks: u16
///   bytes 18..20 _pad (align to u32)
///   bytes 20..24 largest_free: u32
///
/// # Safety
/// Caller must ensure `sys` points to a valid SyscallTable.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
pub unsafe fn heap_stats(sys: &SyscallTable) -> (u32, u32, u16, u16, u32, u16, u32) {
    // Query via provider_query with HEAP_STATS key (6). Buffer
    // sized to the kernel-side `HeapStats` struct — the kernel
    // returns E_INVAL if we pass a buffer smaller than the struct
    // it's about to copy in.
    let mut buf = [0u8; 24];
    let r = (sys.provider_query)(-1, 6, buf.as_mut_ptr(), 24);
    if r < 0 {
        return (0, 0, 0, 0, 0, 0, 0);
    }
    let arena_size = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let allocated = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let alloc_count = u16::from_le_bytes([buf[8], buf[9]]);
    let total_allocs = u16::from_le_bytes([buf[10], buf[11]]);
    let high_water = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
    let free_blocks = u16::from_le_bytes([buf[16], buf[17]]);
    // bytes 18..20 are alignment padding — skipped.
    let largest_free = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
    (
        arena_size,
        allocated,
        alloc_count,
        total_allocs,
        high_water,
        free_blocks,
        largest_free,
    )
}
