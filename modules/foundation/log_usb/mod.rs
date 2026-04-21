//! log_usb — kernel-log forwarder over the platform's USB CDC-ACM endpoint.
//!
//! Drains the kernel log ring (LOG_RING_DRAIN (diag) 0x0C64) and pushes
//! bytes into the USB TX pipe via USB_WRITE_RAW (diag) (0x0C66). The
//! embassy CDC task drains the pipe and writes CDC packets. Use when
//! running RP hardware with USB attached and no serial cable.
//!
//! Unlike UART_WRITE_RAW (synchronous, always-writes-all), USB_WRITE_RAW
//! is *enqueue* — if the USB pipe is full, it accepts fewer bytes than
//! requested. The module holds the unaccepted tail in a staging buffer
//! and retries next step, so no log bytes are lost to short writes.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

const LOG_RING_DRAIN: u32 = 0x0C64;
const USB_WRITE_RAW: u32 = 0x0C66;

const CHUNK_SIZE: usize = 512;

#[repr(C)]
struct LogUsbState {
    syscalls: *const SyscallTable,
    /// Bytes staged but not yet accepted by the USB pipe. Drained before
    /// pulling new bytes from the log ring.
    pending_len: u16,
    /// Offset into `chunk` where the next retry should start. Non-zero
    /// only when a partial enqueue wrote some bytes and the rest is held
    /// for the next step.
    chunk_written: u16,
    chunk: [u8; CHUNK_SIZE],
}

impl LogUsbState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.pending_len = 0;
        self.chunk_written = 0;
    }
}

/// Try to write `pending_len` bytes starting at `chunk_written` offset
/// via USB_WRITE_RAW. Updates state to reflect partial progress. Returns
/// true iff the whole pending region has now been consumed.
unsafe fn flush_pending(s: &mut LogUsbState) -> bool {
    if s.pending_len == 0 {
        return true;
    }
    let sys_ptr = s.syscalls;
    let offset = s.chunk_written as usize;
    let remaining = (s.pending_len as usize) - offset;
    let ptr = s.chunk.as_mut_ptr().add(offset);
    let rc = ((*sys_ptr).provider_call)(-1, USB_WRITE_RAW, ptr, remaining);
    if rc <= 0 {
        return false;
    }
    let written = rc as usize;
    if written >= remaining {
        s.pending_len = 0;
        s.chunk_written = 0;
        true
    } else {
        s.chunk_written = (offset + written) as u16;
        false
    }
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<LogUsbState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() { return -2; }
        if state.is_null() { return -5; }
        if state_size < core::mem::size_of::<LogUsbState>() { return -6; }
        let s = &mut *(state as *mut LogUsbState);
        s.init(syscalls as *const SyscallTable);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() { return -1; }
        let s = &mut *(state as *mut LogUsbState);
        if s.syscalls.is_null() { return -1; }

        // Flush any staged bytes first. If the USB pipe is still full,
        // stop without draining new bytes from the log ring.
        if !flush_pending(s) {
            return 0;
        }

        let sys_ptr = s.syscalls;
        let chunk_ptr = s.chunk.as_mut_ptr();
        let ret = ((*sys_ptr).provider_call)(-1, LOG_RING_DRAIN, chunk_ptr, CHUNK_SIZE);
        if ret <= 0 {
            return 0;
        }
        let len = ((ret as u32) & 0xFFFF) as usize;
        let dropped = ((ret as u32) >> 16) & 0xFFFF;

        // Drop marker — fire-and-forget via a local stack buffer so it
        // doesn't collide with the staging buffer. Uses the same pipe so
        // it's ordered correctly relative to the following chunk.
        if dropped > 0 {
            let mut mark = [0u8; 40];
            let prefix = b"[log_usb: dropped 0x";
            let mut pos = 0usize;
            while pos < prefix.len() { mark[pos] = prefix[pos]; pos += 1; }
            let hex = b"0123456789abcdef";
            let mut shift: i32 = 12;
            while shift >= 0 {
                let nib = ((dropped >> shift as u32) & 0xF) as usize;
                mark[pos] = hex[nib];
                pos += 1;
                shift -= 4;
            }
            let suffix = b" bytes]\r\n";
            let mut k = 0usize;
            while k < suffix.len() && pos < mark.len() {
                mark[pos] = suffix[k];
                pos += 1;
                k += 1;
            }
            // Best-effort: if the pipe can't accept this, we drop the
            // marker (the real data still makes it in).
            let _ = ((*sys_ptr).provider_call)(-1, USB_WRITE_RAW, mark.as_mut_ptr(), pos);
        }

        if len > 0 {
            let rc = ((*sys_ptr).provider_call)(-1, USB_WRITE_RAW, chunk_ptr, len);
            let written = if rc > 0 { rc as usize } else { 0 };
            if written < len {
                // Stage the unaccepted tail for next step.
                s.pending_len = len as u16;
                s.chunk_written = written as u16;
            }
            return 2;
        }
        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
