//! log_uart — kernel-log forwarder that drives the platform UART.
//!
//! Drains the kernel log ring (LOG_RING_DRAIN (diag) 0x0C64) and forwards
//! each chunk via UART_WRITE_RAW (diag) (0x0C65). Symmetric with log_net
//! but targets the local UART wire instead of a UDP socket — use when a
//! serial cable is available and the overhead of an IP stack isn't wanted.
//!
//! UART_WRITE_RAW is synchronous and blocking (spins on TXFF). Every drain
//! call therefore either writes all bytes or hangs — there is no partial
//! send, no channel-full backpressure, and no staging buffer required.
//!
//! Zero ports, no params. Activated by the `debug: { to: uart }` overlay.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

const LOG_RING_DRAIN: u32 = 0x0C64;
const UART_WRITE_RAW: u32 = 0x0C65;

/// Drained bytes per step. Sized so a burst of logs can be emitted in one
/// syscall round-trip, without starving other modules of scheduler time.
const CHUNK_SIZE: usize = 512;

#[repr(C)]
struct LogUartState {
    syscalls: *const SyscallTable,
    /// Informational stats — readable via memory dump.
    chunks_written: u32,
    bytes_written: u32,
    chunk: [u8; CHUNK_SIZE],
}

impl LogUartState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.chunks_written = 0;
        self.bytes_written = 0;
    }
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<LogUartState>() as u32
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
        if state_size < core::mem::size_of::<LogUartState>() { return -6; }
        let s = &mut *(state as *mut LogUartState);
        s.init(syscalls as *const SyscallTable);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() { return -1; }
        let s = &mut *(state as *mut LogUartState);
        if s.syscalls.is_null() { return -1; }

        let sys_ptr = s.syscalls;
        let chunk_ptr = s.chunk.as_mut_ptr();

        // Drain up to CHUNK_SIZE bytes.
        let ret = ((*sys_ptr).provider_call)(-1, LOG_RING_DRAIN, chunk_ptr, CHUNK_SIZE);
        if ret <= 0 {
            return 0;
        }
        let len = ((ret as u32) & 0xFFFF) as usize;
        let dropped = ((ret as u32) >> 16) & 0xFFFF;

        // Drop marker (hex-encoded, division-free).
        if dropped > 0 {
            let mut mark = [0u8; 40];
            let prefix = b"[log_uart: dropped 0x";
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
            let _ = ((*sys_ptr).provider_call)(-1, UART_WRITE_RAW, mark.as_mut_ptr(), pos);
        }

        if len > 0 {
            // UART_WRITE_RAW is synchronous — returns bytes written (== len)
            // or a negative errno. Failure here means the platform has no
            // UART, which is a config error, not something to retry.
            let rc = ((*sys_ptr).provider_call)(-1, UART_WRITE_RAW, chunk_ptr, len);
            if rc > 0 {
                s.chunks_written = s.chunks_written.wrapping_add(1);
                s.bytes_written = s.bytes_written.wrapping_add(len as u32);
            }
            return 2; // Burst — drain more if available
        }

        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
