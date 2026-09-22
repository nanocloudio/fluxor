// ============================================================================
// Bridge channel helpers (SYSTEM class 0x0CE0-0x0CE3)
// ============================================================================

/// Write data to a bridge channel. Returns 0 on success, -EAGAIN if ring full.
#[inline(always)]
unsafe fn dev_bridge_write(sys: &SyscallTable, bridge_fd: i32, data: *const u8, len: usize) -> i32 {
    (sys.provider_call)(bridge_fd, 0x0CE0, data as *mut u8, len)
}

/// Read data from a bridge channel. Returns bytes read, -EAGAIN if empty/no new.
#[inline(always)]
unsafe fn dev_bridge_read(sys: &SyscallTable, bridge_fd: i32, buf: *mut u8, len: usize) -> i32 {
    (sys.provider_call)(bridge_fd, 0x0CE1, buf, len)
}

/// Poll bridge readiness. Returns 1 if readable, 0 if not.
#[inline(always)]
unsafe fn dev_bridge_poll(sys: &SyscallTable, bridge_fd: i32) -> i32 {
    (sys.provider_call)(bridge_fd, 0x0CE2, core::ptr::null_mut(), 0)
}

/// Get bridge info. Returns 12 bytes: [type, from, to, _, drops:u32, seq:u32].
#[inline(always)]
unsafe fn dev_bridge_info(sys: &SyscallTable, bridge_fd: i32, buf: &mut [u8; 12]) -> i32 {
    (sys.provider_call)(bridge_fd, 0x0CE3, buf.as_mut_ptr(), 12)
}
