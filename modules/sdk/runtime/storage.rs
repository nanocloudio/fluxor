// ============================================================================
// Runtime parameter store (persists across reboots)
// ============================================================================

/// Store a parameter override that persists across reboots.
/// `tag`: params TLV tag number for this module's param.
/// `value`: pointer to raw value bytes.
/// `len`: value byte count (max 250).
/// Returns 0 on success, negative errno on error.
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
#[inline(always)]
unsafe fn dev_param_store_str(sys: &SyscallTable, tag: u8, s: *const u8, len: usize) -> i32 {
    dev_param_store(sys, tag, s, len)
}

/// Delete a parameter override (reverts to compiled default on next boot).
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
#[inline(always)]
unsafe fn dev_arena_get(sys: &SyscallTable) -> (*mut u8, u32) {
    let mut buf = [0u8; 4];
    let size = (sys.provider_call)(-1, abi::kernel_abi::ARENA_GET, buf.as_mut_ptr(), 4);
    let addr = u32::from_le_bytes(buf);
    (addr as *mut u8, if size > 0 { size as u32 } else { 0 })
}
