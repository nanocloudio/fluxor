// ============================================================================
// Runtime parameter store (persists across reboots)
// ============================================================================

/// Store a parameter override that persists across reboots.
/// `tag`: TLV v2 tag number for this module's param.
/// `value`: pointer to raw value bytes.
/// `len`: value byte count (max 250).
/// Returns 0 on success, negative errno on error.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_param_store(sys: &SyscallTable, tag: u8, value: *const u8, len: usize) -> i32 {
    let mut buf = [0u8; 252]; // 1 tag + 250 max value + 1 spare
    let bp = buf.as_mut_ptr();
    *bp = tag;
    let copy_len = if len > 250 { 250 } else { len };
    let mut i = 0usize;
    while i < copy_len {
        *bp.add(1 + i) = *value.add(i);
        i += 1;
    }
    (sys.provider_call)(
        -1,
        abi::contracts::storage::runtime_params::STORE,
        bp,
        1 + copy_len,
    )
}

/// Store a u8 parameter override.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_param_store_u8(sys: &SyscallTable, tag: u8, val: u8) -> i32 {
    let mut buf = [tag, val];
    (sys.provider_call)(
        -1,
        abi::contracts::storage::runtime_params::STORE,
        buf.as_mut_ptr(),
        2,
    )
}

/// Store a string parameter override.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_param_store_str(sys: &SyscallTable, tag: u8, s: *const u8, len: usize) -> i32 {
    dev_param_store(sys, tag, s, len)
}

/// Delete a parameter override (reverts to compiled default on next boot).
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_param_delete(sys: &SyscallTable, tag: u8) -> i32 {
    let mut buf = [tag];
    (sys.provider_call)(
        -1,
        abi::contracts::storage::runtime_params::DELETE,
        buf.as_mut_ptr(),
        1,
    )
}

/// Clear all runtime overrides for this module.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_param_clear_all(sys: &SyscallTable) -> i32 {
    (sys.provider_call)(
        -1,
        abi::contracts::storage::runtime_params::CLEAR_ALL,
        core::ptr::null_mut(),
        0,
    )
}

/// Get this module's arena allocation (from module_arena_size export).
/// Returns (ptr, size). ptr is null and size is 0 if no arena was allocated.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_arena_get(sys: &SyscallTable) -> (*mut u8, u32) {
    let mut buf = [0u8; 4];
    let size = (sys.provider_call)(-1, abi::kernel_abi::ARENA_GET, buf.as_mut_ptr(), 4);
    let addr = u32::from_le_bytes(buf);
    (addr as *mut u8, if size > 0 { size as u32 } else { 0 })
}

// ============================================================================
// Paged Arena (demand-paged memory larger than RAM)
// ============================================================================

/// Paged arena stats returned by dev_paged_arena_stats.
#[repr(C)]
#[derive(Clone, Copy, Default)]
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
struct PagedArenaStats {
    resident: u32,
    faults: u32,
    evictions: u32,
    dirty: u32,
    writebacks: u32,
    hit_ratio_q8: u16,
    _reserved: u16,
}

/// Get paged arena base address and size.
/// Returns (base_ptr, size, status). status=1 if active, 0 if not.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_paged_arena_get(sys: &SyscallTable) -> (*mut u8, usize, u32) {
    let mut buf = [0u8; 20];
    let rc = (sys.provider_call)(-1, abi::kernel_abi::PAGED_ARENA_GET, buf.as_mut_ptr(), 20);
    if rc < 0 {
        return (core::ptr::null_mut(), 0, 0);
    }
    let base = u64::from_le_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    let size = u64::from_le_bytes([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    ]);
    let status = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
    (base as *mut u8, size as usize, status)
}

/// Get paged arena statistics.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_paged_arena_stats(sys: &SyscallTable) -> PagedArenaStats {
    let mut stats = PagedArenaStats::default();
    let p = &mut stats as *mut _ as *mut u8;
    (sys.provider_call)(
        -1,
        abi::internal::monitor::PAGED_ARENA_STATS,
        p,
        core::mem::size_of::<PagedArenaStats>(),
    );
    stats
}

/// Prefault pages into the paged arena.
/// `offset`: starting page index, `count`: number of pages to prefault.
/// Returns number of pages actually prefaulted.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[inline(always)]
unsafe fn dev_paged_arena_prefault(sys: &SyscallTable, offset: u32, count: u32) -> u32 {
    let mut buf = [0u8; 8];
    let bp = buf.as_mut_ptr();
    let ob = offset.to_le_bytes();
    let cb = count.to_le_bytes();
    *bp = ob[0];
    *bp.add(1) = ob[1];
    *bp.add(2) = ob[2];
    *bp.add(3) = ob[3];
    *bp.add(4) = cb[0];
    *bp.add(5) = cb[1];
    *bp.add(6) = cb[2];
    *bp.add(7) = cb[3];
    let rc = (sys.provider_call)(-1, abi::kernel_abi::PAGED_ARENA_PREFAULT, bp, 8);
    if rc > 0 {
        rc as u32
    } else {
        0
    }
}
