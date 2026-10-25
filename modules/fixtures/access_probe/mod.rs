//! Access probe — the bounds on `MMIO_READ32` and the DMA cache-maintenance
//! opcodes, from a PIC module holding `platform_raw` and `dma`, on QEMU virt.
//!
//! On its first step it checks, in order (the case number is what a failure
//! names):
//!   1. a register read in DRAM (0x4000_0000) is refused EFAULT;
//!   2. a read of the PL011's PeriphID0 (0x0900_0FE0) is served;
//!   3. an unaligned read (0x0900_0FE1) is refused EFAULT;
//!   4. a read in a gigabyte with nothing behind it (0x1_0000_0000 at
//!      `-m 2G`) is refused EFAULT;
//!   5. a cache flush of this module's own state is refused EFAULT;
//!   6. a flush of a streaming DMA buffer it was given is served;
//!   7. a flush of that buffer whose end wraps is refused EFAULT.
//!
//! **Pipeline:** standalone — no channels required.

#![no_std]
#![allow(
    dead_code,
    reason = "the PIC build mounts the whole of modules/sdk/* via include!, so every \
              module's compile sees the entire ABI surface while using a subset. This \
              allow is the SDK's textual mounting showing through"
)]
#![allow(
    unused_imports,
    reason = "same cause: the mounted SDK brings names this module does not reach for"
)]
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

const MMIO_READ32: u32 = 0x0CE4;
const EFAULT: i32 = -14;

#[repr(C)]
struct AccessProbeState {
    syscalls: *const SyscallTable,
    done: u8,
    _pad: [u8; 7],
}

unsafe fn mmio_read(sys: &SyscallTable, addr: u64) -> i32 {
    let mut buf = [0u8; 12];
    let ab = addr.to_le_bytes();
    let bp = buf.as_mut_ptr();
    let mut i = 0usize;
    while i < 8 {
        *bp.add(i) = ab[i];
        i += 1;
    }
    (sys.provider_call)(-1, MMIO_READ32, bp, 12)
}

/// The first failing case, or 0 when every case holds.
unsafe fn run_cases(sys: &SyscallTable, own_state: u64) -> u8 {
    if mmio_read(sys, 0x4000_0000) != EFAULT {
        return 1;
    }
    if mmio_read(sys, 0x0900_0FE0) != 0 {
        return 2;
    }
    if mmio_read(sys, 0x0900_0FE1) != EFAULT {
        return 3;
    }
    if mmio_read(sys, 0x1_0000_0000) != EFAULT {
        return 4;
    }
    if dev_dma_flush(sys, own_state, 64) != EFAULT {
        return 5;
    }
    let buf = dev_dma_alloc_streaming(sys, 64, 64);
    if buf == 0 || dev_dma_flush(sys, buf, 64) != 0 {
        return 6;
    }
    if dev_dma_flush(sys, u64::MAX - 31, 64) != EFAULT {
        return 7;
    }
    0
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<AccessProbeState>()
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes and `syscalls` the kernel's syscall table.
#[no_mangle]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if syscalls.is_null() {
        return -2;
    }
    if state.is_null() || state_size < core::mem::size_of::<AccessProbeState>() {
        return -3;
    }
    let s = &mut *(state as *mut AccessProbeState);
    s.syscalls = syscalls as *const SyscallTable;
    s.done = 0;
    0
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[no_mangle]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut u8) -> i32 {
    let s = &mut *(state as *mut AccessProbeState);
    if s.done != 0 {
        return 1; // Done
    }
    s.done = 1;
    let sys = &*s.syscalls;
    let case = run_cases(sys, state as u64);
    if case == 0 {
        dev_log(sys, 3, c"[access_probe] ok".as_ptr().cast(), 17);
    } else {
        let mut msg = *b"[access_probe] FAIL case=0";
        let last = msg.len() - 1;
        if let Some(d) = msg.get_mut(last) {
            *d = b'0' + case;
        }
        dev_log(sys, 1, msg.as_ptr(), msg.len());
    }
    1 // Done
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");
