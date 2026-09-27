//! Goes deeper than its recorded stack depth, once, to show the scheduler's
//! stack fence reports it.
//!
//! The build measures a module's stack from the compiler's frame directives.
//! Inline assembly that moves the stack pointer is not in them, so this
//! module's recorded depth is its own small frame, and the composer admits it
//! on that. Its first step then lowers the stack pointer by `DEPTH`, writes
//! every word of the range, and restores it — a frame the compiler never saw,
//! which crosses the fence the scheduler armed at the admitted depth.
//!
//! Logs `[stack_fence_probe] going deep` before and `[stack_fence_probe] back`
//! after, so a scenario can tell the write happened and the module returned.

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

/// How far below its entry the probe writes: past any admitted depth on an RP
/// part, well inside the stack region.
/// How far below its entry the probe writes: past the kernel stack less its
/// reserve on RP (the fence), past the 1 MiB EL1 stack on bcm2712 (its guard
/// page).
#[cfg(target_arch = "aarch64")]
const DEPTH: usize = 2 * 1024 * 1024;
#[cfg(not(target_arch = "aarch64"))]
const DEPTH: usize = 16 * 1024;

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    done: u32,
}

declare_module_state_bytes!(State);

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
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
    if state.is_null() || syscalls.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<State>() {
        return -2;
    }
    // SAFETY: `state` is at least `size_of::<State>()` bytes, checked above.
    unsafe {
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.done = 0;
    }
    0
}

/// Lower the stack pointer by `DEPTH`, write every word of the range, and put
/// it back.
/// Write downward from the stack pointer, a word every 128 bytes, until
/// `DEPTH` below it — the order a real overflow takes, so the first thing
/// crossed is whatever bounds the stack (the fence words, the guard page),
/// never memory beyond it.
#[inline(never)]
fn go_deep() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "mov {cur}, sp",
            "sub {end}, {cur}, {n}",
            "2:",
            "sub {cur}, {cur}, #128",
            "str xzr, [{cur}]",
            "cmp {cur}, {end}",
            "b.hi 2b",
            cur = out(reg) _,
            end = out(reg) _,
            n = in(reg) DEPTH,
        );
    }
    #[cfg(not(target_arch = "aarch64"))]
    unsafe {
        core::arch::asm!(
            "mov {cur}, sp",
            "mov {end}, sp",
            "subs {end}, {end}, {n}",
            "movs {z}, #0",
            "2:",
            "subs {cur}, #128",
            "str {z}, [{cur}]",
            "cmp {cur}, {end}",
            "bhi 2b",
            cur = out(reg) _,
            end = out(reg) _,
            z = out(reg) _,
            n = in(reg) DEPTH,
        );
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    if state.is_null() {
        return -1;
    }
    // SAFETY: the scheduler passes the state `module_new` initialised.
    let s = unsafe { &mut *(state as *mut State) };
    if s.done != 0 || s.syscalls.is_null() {
        return 0;
    }
    s.done = 1;
    // SAFETY: `module_new` stored the kernel's syscall table.
    let sys = unsafe { &*s.syscalls };
    let before = b"[stack_fence_probe] going deep";
    // SAFETY: `before` is a live buffer of the length passed.
    unsafe { dev_log(sys, 3, before.as_ptr(), before.len()) };
    go_deep();
    let back = b"[stack_fence_probe] back";
    // SAFETY: `back` is a live buffer of the length passed.
    unsafe { dev_log(sys, 3, back.as_ptr(), back.len()) };
    0
}

include!("../../sdk/runtime/wasm_entry.rs");
