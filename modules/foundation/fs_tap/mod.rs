//! fs_tap — diagnostic FS_CONTRACT consumer.
//!
//! Opens a file via `provider_call(-1, FS_OPEN, path, len)` and logs
//! the contents as `[fs_tap] <text>` lines. Non-printable bytes are
//! replaced with `.` so a binary file doesn't produce garbled UDP
//! frames. Lines are flushed on newline, buffer-full, or periodic
//! tick (so short payloads without `\n` still surface).
//!
//! Sits at the end of a `nvme → fat32 → fs_tap` chain to confirm
//! that a known string on disk reaches the log viewer verbatim.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

/// Maximum line length before forcing a flush.
const LINE_MAX: usize = 128;
/// Maximum path length accepted by the `path` param.
const MAX_PATH_LEN: usize = 96;

const FS_OPEN:  u32 = 0x0900;
const FS_READ:  u32 = 0x0901;
const FS_CLOSE: u32 = 0x0903;

#[repr(C)]
struct FsTapState {
    syscalls:    *const SyscallTable,
    /// FS_CONTRACT handle for the open file (-1 between opens / after close).
    fs_fd:       i32,
    /// Bytes accumulated in `line_buf` since the last flush.
    fill:        u16,
    /// 1 = `path` configured, 0 = nothing to do.
    have_path:   u8,
    /// 1 = file exhausted (FS_CLOSE issued, no further reads).
    done:        u8,

    /// Tick counter for the periodic flush + heartbeat path.
    step_count:  u32,

    /// Length of `path` in bytes.
    path_len:    u8,
    _pad0:       [u8; 3],
    /// Absolute path passed to FS_OPEN at first step.
    path:        [u8; MAX_PATH_LEN],

    /// Line accumulator.
    line_buf:    [u8; LINE_MAX],
}

mod params_def {
    use super::FsTapState;
    use super::SCHEMA_MAX;

    define_params! {
        FsTapState;

        1, path, str, 0
            => |s, d, len| {
                if len == 0 || len > super::MAX_PATH_LEN { return; }
                let dst = s.path.as_mut_ptr();
                let mut i = 0usize;
                while i < len {
                    *dst.add(i) = *d.add(i);
                    i += 1;
                }
                s.path_len = len as u8;
                s.have_path = 1;
            };
    }
}

unsafe fn flush_line(s: &mut FsTapState) {
    if s.fill == 0 { return; }
    let mut out = [0u8; LINE_MAX + 16];
    let prefix = b"[fs_tap] ";
    let mut pos = 0usize;
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), out.as_mut_ptr(), prefix.len());
    pos += prefix.len();
    let mut i = 0usize;
    while i < s.fill as usize {
        let b = *s.line_buf.as_ptr().add(i);
        *out.as_mut_ptr().add(pos) =
            if (0x20..=0x7e).contains(&b) { b } else { b'.' };
        pos += 1;
        i += 1;
    }
    dev_log(&*s.syscalls, 3, out.as_ptr(), pos);
    s.fill = 0;
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<FsTapState>()
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32, _out_chan: i32, _ctrl_chan: i32,
    params: *const u8, params_len: usize,
    state: *mut u8, state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<FsTapState>() { return -2; }
        let s = &mut *(state as *mut FsTapState);
        core::ptr::write_bytes(s as *mut FsTapState as *mut u8, 0, core::mem::size_of::<FsTapState>());
        s.syscalls = syscalls as *const SyscallTable;
        s.fs_fd = -1;

        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        dev_log(&*s.syscalls, 3, b"[fs_tap] init\0".as_ptr(), 13);
        0
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut FsTapState);
    let sys = &*s.syscalls;

    s.step_count = s.step_count.wrapping_add(1);

    // Periodic line flush + status — short payloads without a
    // trailing newline would otherwise sit in the line buffer until
    // it filled. The status line doubles as a liveness ping when no
    // data is flowing.
    if s.step_count % 5000 == 0 {
        flush_line(s);
        let msg: &[u8] = if s.done != 0 {
            b"[fs_tap] drained"
        } else if s.have_path == 0 {
            b"[fs_tap] no path configured"
        } else if s.fs_fd < 0 {
            b"[fs_tap] waiting on FS provider"
        } else {
            b"[fs_tap] reading"
        };
        dev_log(sys, 3, msg.as_ptr(), msg.len());
    }

    if s.have_path == 0 || s.done != 0 { return 0; }

    // First step (or after a transient FS_OPEN failure): try to open
    // the configured path. Failure is non-fatal — we'll retry on the
    // next tick (the FS provider may not be ready yet).
    if s.fs_fd < 0 {
        let mut path = [0u8; MAX_PATH_LEN];
        let n = s.path_len as usize;
        path[..n].copy_from_slice(&s.path[..n]);
        let fd = (sys.provider_call)(-1, FS_OPEN, path.as_mut_ptr(), n);
        if fd < 0 { return 0; }
        s.fs_fd = fd;
    }

    // Read one chunk per tick into the line accumulator. The buffer
    // is flushed on every newline + once at EOF.
    let space = LINE_MAX - s.fill as usize;
    if space == 0 {
        flush_line(s);
        return 0;
    }
    let dst = s.line_buf.as_mut_ptr().add(s.fill as usize);
    let n = (sys.provider_call)(s.fs_fd, FS_READ, dst, space);
    if n <= 0 {
        // EOF (n == 0) or error (n < 0). Either way, flush + close.
        flush_line(s);
        (sys.provider_call)(s.fs_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.fs_fd = -1;
        s.done = 1;
        dev_log(sys, 3, b"[fs_tap] eof\0".as_ptr(), 12);
        return 0;
    }

    s.fill = (s.fill as usize + n as usize) as u16;

    // Scan for newlines and flush each line. The tail (no trailing
    // newline) survives until the next tick or the eof flush above.
    loop {
        let end = s.fill as usize;
        let mut i = 0usize;
        let mut found = usize::MAX;
        while i < end {
            if *s.line_buf.as_ptr().add(i) == b'\n' { found = i; break; }
            i += 1;
        }
        if found == usize::MAX { break; }
        s.fill = found as u16;
        flush_line(s);
        let tail = end - (found + 1);
        if tail > 0 {
            core::ptr::copy(
                s.line_buf.as_ptr().add(found + 1),
                s.line_buf.as_mut_ptr(),
                tail,
            );
        }
        s.fill = tail as u16;
    }

    if s.fill as usize >= LINE_MAX {
        flush_line(s);
    }
    2 // Burst — keep reading while data flows.
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/wasm_entry.rs");
