//! DMA probe — verifies the `DMA_ALLOC_CONTIG` kernel bridge and the
//! non-cacheable DMA arena plumbing from a PIC module.
//!
//! On first step the module:
//!   1. Calls `dev_dma_alloc(size, align)` to obtain a physical address.
//!   2. Writes a magic 32-bit pattern `0xFEEDF00D` at offset 0.
//!   3. Reads it back through the same pointer (proves CPU/arena coherence).
//!   4. Logs the physical address, size, alignment, and readback value.
//!
//! **Params:**
//!   size  (u32, tag 1): bytes to allocate (default 4096)
//!   align (u32, tag 2): alignment in bytes (default 4096)
//!
//! **Pipeline:** standalone — no channels required.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

const MAGIC: u32 = 0xFEED_F00D;

#[repr(C)]
struct DmaProbeState {
    syscalls: *const SyscallTable,
    size: u32,
    align: u32,
    done: u8,
    _pad: [u8; 7],
    phys: u64,
}

mod params_def {
    use super::DmaProbeState;
    use super::p_u32;
    use super::SCHEMA_MAX;

    define_params! {
        DmaProbeState;

        1, size, u32, 4096
            => |s, d, len| { s.size = p_u32(d, len, 0, 4096); };

        2, align, u32, 4096
            => |s, d, len| { s.align = p_u32(d, len, 0, 4096); };
    }
}

fn hexdigit(n: u8) -> u8 {
    if n < 10 { b'0' + n } else { b'a' + (n - 10) }
}

fn fmt_hex64(v: u64, out: &mut [u8; 18]) {
    out[0] = b'0';
    out[1] = b'x';
    let mut i = 0usize;
    while i < 16 {
        let shift = 60 - i * 4;
        out[2 + i] = hexdigit(((v >> shift) & 0xF) as u8);
        i += 1;
    }
}

fn fmt_hex32(v: u32, out: &mut [u8; 10]) {
    out[0] = b'0';
    out[1] = b'x';
    let mut i = 0usize;
    while i < 8 {
        let shift = 28 - i * 4;
        out[2 + i] = hexdigit(((v >> shift) & 0xF) as u8);
        i += 1;
    }
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<DmaProbeState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32, _out_chan: i32, _ctrl_chan: i32,
    params: *const u8, params_len: usize,
    state: *mut u8, state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() { return -2; }
        if state.is_null() || state_size < core::mem::size_of::<DmaProbeState>() { return -3; }

        let s = &mut *(state as *mut DmaProbeState);
        s.syscalls = syscalls as *const SyscallTable;
        s.done = 0;
        s.phys = 0;

        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut DmaProbeState);
        if s.done != 0 { return 1; } // Done
        s.done = 1;

        let sys = &*s.syscalls;

        let phys = dev_dma_alloc(sys, s.size, s.align);
        s.phys = phys;

        if phys == 0 {
            dev_log(sys, 1, b"[dma_probe] allocation failed\0".as_ptr(), 28);
            return 1;
        }

        // Write magic at offset 0, read back.
        let ptr = phys as usize as *mut u32;
        core::ptr::write_volatile(ptr, MAGIC);
        // DSB so the store is visible before the readback — cheap insurance
        // even on Normal Non-cacheable memory where it's architecturally
        // redundant.
        core::arch::asm!("dsb sy", options(nostack));
        let readback = core::ptr::read_volatile(ptr);

        // Log: "[dma_probe] phys=0x0000000012345678 size=0x00001000 rb=0xfeedf00d"
        let mut msg = [0u8; 80];
        let mp = msg.as_mut_ptr();
        let prefix = b"[dma_probe] phys=";
        core::ptr::copy_nonoverlapping(prefix.as_ptr(), mp, prefix.len());
        let mut pos = prefix.len();

        let mut hex64 = [0u8; 18];
        fmt_hex64(phys, &mut hex64);
        core::ptr::copy_nonoverlapping(hex64.as_ptr(), mp.add(pos), 18);
        pos += 18;

        let size_tag = b" size=";
        core::ptr::copy_nonoverlapping(size_tag.as_ptr(), mp.add(pos), size_tag.len());
        pos += size_tag.len();

        let mut hex32 = [0u8; 10];
        fmt_hex32(s.size, &mut hex32);
        core::ptr::copy_nonoverlapping(hex32.as_ptr(), mp.add(pos), 10);
        pos += 10;

        let rb_tag = b" rb=";
        core::ptr::copy_nonoverlapping(rb_tag.as_ptr(), mp.add(pos), rb_tag.len());
        pos += rb_tag.len();

        fmt_hex32(readback, &mut hex32);
        core::ptr::copy_nonoverlapping(hex32.as_ptr(), mp.add(pos), 10);
        pos += 10;

        dev_log(sys, 3, mp, pos);

        if readback != MAGIC {
            dev_log(sys, 1, b"[dma_probe] MAGIC MISMATCH\0".as_ptr(), 25);
        } else {
            dev_log(sys, 3, b"[dma_probe] OK\0".as_ptr(), 14);
        }

        1 // Done
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");
