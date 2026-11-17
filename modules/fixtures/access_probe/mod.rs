//! Access probe — the bounds on register access through a `metal_device`
//! aperture and on the DMA cache-maintenance opcodes, from a PIC module
//! holding `metal_device` with its `mmio` and `dma` grants, on QEMU virt.
//!
//! On its first step it checks, in order (the case number is what a failure
//! names):
//!   1. opening an aperture past the machine's last is refused ENOENT, and a
//!      read through a handle naming none is refused EBADF;
//!   2. a read of the PL011's PeriphID0 (offset 0x0900_0FE0 in aperture 0,
//!      the first gigabyte) is served;
//!   3. an unaligned read (offset 0x0900_0FE1) is refused EFAULT;
//!   4. a read past the aperture's end is refused EFAULT;
//!   5. a cache flush naming no allocation of its own is refused EBADF;
//!   6. a flush of a streaming DMA buffer it was given is served;
//!   7. a flush running past that buffer's end, or whose end wraps, is
//!      refused EFAULT.
//!
//! **Pipeline:** standalone — no channels required.

#![no_std]
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

use abi::contracts::hal::metal_device as md;

const ENOENT: i32 = -2;
const EFAULT: i32 = -14;
const EBADF: i32 = -9;

#[repr(C)]
struct AccessProbeState {
    syscalls: *const SyscallTable,
    done: u8,
    _pad: [u8; 7],
}

/// Open aperture `index`: its handle and length, or the errno.
unsafe fn mmio_open(sys: &SyscallTable, index: u8) -> Result<(i32, u32), i32> {
    let mut arg = [0u8; md::mmio::OPEN_LEN];
    arg[0] = index;
    let h = (sys.provider_call)(
        -1,
        md::MMIO_OPEN,
        arg.as_mut_ptr(),
        arg.len(),
        core::ptr::null_mut(),
        0,
    );
    if h < 0 {
        return Err(h);
    }
    Ok((h, u32::from_le_bytes([arg[8], arg[9], arg[10], arg[11]])))
}

unsafe fn mmio_read(sys: &SyscallTable, aperture: i32, offset: u32) -> i32 {
    let mut arg = md::mmio::arg(offset, 0);
    (sys.provider_call)(
        aperture,
        md::MMIO_READ32,
        arg.as_mut_ptr(),
        arg.len(),
        core::ptr::null_mut(),
        0,
    )
}

/// The first failing case, or 0 when every case holds.
unsafe fn run_cases(sys: &SyscallTable) -> u8 {
    let forged = abi::kernel_abi::handle::encode(abi::registry::metal_device::ID, 0, 0x3FFF);
    if mmio_open(sys, 0xFF) != Err(ENOENT) || mmio_read(sys, forged, 0x0900_0FE0) != EBADF {
        return 1;
    }
    let Ok((ap, len)) = mmio_open(sys, 0) else {
        return 2;
    };
    if mmio_read(sys, ap, 0x0900_0FE0) != 0 {
        return 2;
    }
    if mmio_read(sys, ap, 0x0900_0FE1) != EFAULT {
        return 3;
    }
    if mmio_read(sys, ap, len) != EFAULT {
        return 4;
    }
    if dev_dma_flush(sys, -1, 0, 64) != EBADF || dev_dma_flush(sys, forged, 0, 64) != EBADF {
        return 5;
    }
    let Some(buf) = dev_dma_alloc_streaming(sys, 64, 64) else {
        return 6;
    };
    if dev_dma_flush(sys, buf.handle, 0, 64) != 0 {
        return 6;
    }
    if dev_dma_flush(sys, buf.handle, 32, 64) != EFAULT
        || dev_dma_flush(sys, buf.handle, u32::MAX - 31, 64) != EFAULT
    {
        return 7;
    }
    0
}

fluxor_rt::module_facts! { state: AccessProbeState }

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
pub unsafe extern "C" fn module_step(state: *mut u8) -> StepReturn {
    let s = &mut *(state as *mut AccessProbeState);
    if s.done != 0 {
        return StepReturn::Done;
    }
    s.done = 1;
    let sys = &*s.syscalls;
    let case = run_cases(sys);
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
    StepReturn::Done
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `crates/fluxor-rt/src/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
fluxor_rt::wasm_entry!();
