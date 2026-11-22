//! heap_block — takes one block near its declared arena in `module_new`.
//!
//! A type that keeps its tables in one heap block declares an arena that holds
//! it and allocates it when constructed. The kernel commits the declared
//! arena whole at instantiation, so the block fits whatever room a graph
//! grants above it. Construction fails with -12 when it does not.

#![no_std]

use core::ffi::c_void;

use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

/// The heap the module declares: its working set.
const ARENA_BYTES: u32 = 147_488;
/// The one block it takes in `module_new`.
const BLOCK_BYTES: u32 = 131_106;

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    block: *mut u8,
}

fluxor_rt::module_facts! { state: State, arena: ARENA_BYTES }

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
    if state.is_null() || syscalls.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<State>() {
        return -2;
    }
    unsafe {
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.block = ((*s.syscalls).heap_alloc)(BLOCK_BYTES);
        if s.block.is_null() {
            return -12;
        }
    }
    0
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(_state: *mut u8) -> StepReturn {
    StepReturn::Continue
}
