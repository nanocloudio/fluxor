// ============================================================================
// Bridge channel helpers (SYSTEM class `bridge::WRITE`-`bridge::INFO`)
// ============================================================================

use crate::*;

/// Write data to a bridge channel. Returns 0 on success, -EAGAIN if ring full.
#[inline(always)]
pub unsafe fn dev_bridge_write(
    sys: &SyscallTable,
    bridge_fd: i32,
    data: *const u8,
    len: usize,
) -> i32 {
    (sys.provider_call)(
        bridge_fd,
        abi::registry::bridge::WRITE,
        core::ptr::null_mut(),
        0,
        data as *mut u8,
        len,
    )
}

/// Read data from a bridge channel. Returns bytes read, -EAGAIN if empty/no new.
#[inline(always)]
pub unsafe fn dev_bridge_read(sys: &SyscallTable, bridge_fd: i32, buf: *mut u8, len: usize) -> i32 {
    (sys.provider_call)(
        bridge_fd,
        abi::registry::bridge::READ,
        core::ptr::null_mut(),
        0,
        buf,
        len,
    )
}

/// Poll bridge readiness. Returns 1 if readable, 0 if not.
#[inline(always)]
pub unsafe fn dev_bridge_poll(sys: &SyscallTable, bridge_fd: i32) -> i32 {
    (sys.provider_call)(
        bridge_fd,
        abi::registry::bridge::POLL,
        core::ptr::null_mut(),
        0,
        core::ptr::null_mut(),
        0,
    )
}

/// Get bridge info into `buf`: `[type u8][0 u8][from u16][to u16][0 u16]
/// [drops u32][seq u32]`, all LE. Returns 16.
#[inline(always)]
pub unsafe fn dev_bridge_info(sys: &SyscallTable, bridge_fd: i32, buf: &mut [u8; 16]) -> i32 {
    (sys.provider_call)(
        bridge_fd,
        abi::registry::bridge::INFO,
        buf.as_mut_ptr(),
        16,
        core::ptr::null_mut(),
        0,
    )
}
