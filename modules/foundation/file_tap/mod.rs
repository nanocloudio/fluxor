//! file_tap — diagnostic consumer that logs the byte stream on its
//! input channel as text.
//!
//! Accumulates up to LINE_MAX bytes into a scratch buffer and emits a
//! `[file_tap] <text>` log line either when a newline is seen, the
//! buffer fills, or (for a short tail) when an explicit flush is
//! triggered. Non-printable bytes are replaced with `.` so a binary
//! file doesn't produce garbled UDP frames.
//!
//! Intended use: end of the `nvme → fat32 → file_tap` acceptance chain
//! for NVMe Phase 5 — prove that a known string on the drive reaches
//! the log viewer verbatim.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

const LINE_MAX: usize = 128;

#[repr(C)]
struct FileTapState {
    syscalls:    *const SyscallTable,
    in_chan:     i32,
    fill:        u16,
    /// 1 until we've sent the initial `IOCTL_NOTIFY(file_index=0)` to
    /// the upstream file producer (e.g. fat32). Producers in this
    /// chain stay idle until a consumer asks for a file.
    need_request: u8,
    _pad:        u8,
    /// Tick counter driving the periodic flush of the partial-line
    /// buffer — short no-newline payloads would otherwise sit in the
    /// buffer forever.
    step_count:  u32,
    buf:         [u8; LINE_MAX],
}

unsafe fn flush_line(s: &mut FileTapState) {
    if s.fill == 0 { return; }
    let mut out = [0u8; LINE_MAX + 16];
    let prefix = b"[file_tap] ";
    let mut pos = 0usize;
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), out.as_mut_ptr(), prefix.len());
    pos += prefix.len();
    let mut i = 0usize;
    while i < s.fill as usize {
        let b = *s.buf.as_ptr().add(i);
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
    core::mem::size_of::<FileTapState>()
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32, _out_chan: i32, _ctrl_chan: i32,
    _params: *const u8, _params_len: usize,
    state: *mut u8, state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<FileTapState>() { return -2; }
        let s = &mut *(state as *mut FileTapState);
        core::ptr::write_bytes(s as *mut FileTapState as *mut u8, 0, core::mem::size_of::<FileTapState>());
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.need_request = 1;
        dev_log(&*s.syscalls, 3, b"[file_tap] init\0".as_ptr(), 15);
        0
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut FileTapState);
    if s.in_chan < 0 { return 0; }
    let sys = &*s.syscalls;

    s.step_count = s.step_count.wrapping_add(1);
    if s.step_count % 5000 == 0 {
        // Flush any pending bytes periodically — short files (e.g.
        // `hello.txt` containing "nvme works") don't carry a newline
        // and won't fill the 128-byte buffer, so without this they'd
        // never reach the log viewer.
        flush_line(s);
        // Minimal liveness ping + `need_request` state so a silent
        // chain (producer idle, consumer waiting) is diagnosable from
        // the log alone.
        let msg: &[u8] = if s.need_request != 0 {
            b"[file_tap] waiting on producer\0"
        } else {
            b"[file_tap] drained\0"
        };
        dev_log(sys, 3, msg.as_ptr(), msg.len() - 1);
    }

    // Ask the upstream file producer (e.g. fat32) to start streaming
    // file index 0 on the first tick. Producers in this chain wait
    // for a consumer-originated IOCTL_NOTIFY before emitting data.
    if s.need_request != 0 {
        let mut idx: u32 = 0;
        let rc = dev_channel_ioctl(
            sys, s.in_chan,
            IOCTL_NOTIFY,
            &mut idx as *mut u32 as *mut u8,
        );
        if rc >= 0 { s.need_request = 0; }
        return 0;
    }

    // Drain the channel one chunk at a time. Stop when the read
    // returns 0 (nothing to read right now) so we don't starve peers.
    let space = LINE_MAX - s.fill as usize;
    if space == 0 {
        flush_line(s);
        return 0;
    }
    let dst = s.buf.as_mut_ptr().add(s.fill as usize);
    let n = (sys.channel_read)(s.in_chan, dst, space);
    if n <= 0 { return 0; }

    let grown = n as usize;
    s.fill = (s.fill as usize + grown) as u16;

    // Scan the whole valid buffer for a newline (not just the newly
    // arrived bytes — a previous iteration may have left a newline
    // still present after a shift). Emit one line per newline; stop
    // when no more newlines are found so the tail survives to the
    // next tick.
    loop {
        let end = s.fill as usize;
        let mut i = 0usize;
        let mut found = usize::MAX;
        while i < end {
            if *s.buf.as_ptr().add(i) == b'\n' { found = i; break; }
            i += 1;
        }
        if found == usize::MAX { break; }
        s.fill = found as u16;
        flush_line(s);
        let tail = end - (found + 1);
        if tail > 0 {
            core::ptr::copy(
                s.buf.as_ptr().add(found + 1),
                s.buf.as_mut_ptr(),
                tail,
            );
        }
        s.fill = tail as u16;
    }

    if s.fill as usize >= LINE_MAX {
        flush_line(s);
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
