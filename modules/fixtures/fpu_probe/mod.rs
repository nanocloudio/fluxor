//! Steps one `f32` addition, to show what the RP kernel does with it.
//!
//! Logs `[fpu_probe] before f32`, then adds two `f32`s it cannot see the
//! values of, then logs `[fpu_probe] f32 ran`. On rp2350 the second line never
//! appears: the addition is a VFP instruction, the FPU is not enabled, and the
//! node takes a NOCP fault. Modules build soft-float, where `f32` arithmetic
//! does not link, so on Arm the addition is written as the instruction itself
//! rather than left to the compiler. It lives in its own never-inlined
//! function so nothing of it can be scheduled ahead of the first log line.

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

/// One `f32` addition the compiler cannot fold, as the raw bits of its result.
#[cfg(target_arch = "arm")]
#[inline(never)]
fn add_f32() -> u32 {
    let mut bits = core::hint::black_box(1.5f32.to_bits());
    let other = core::hint::black_box(2.5f32.to_bits());
    // SAFETY: two moves into single-precision registers, one addition, one
    // move back. The soft-float ABI gives the compiler no use of s0/s1, so
    // nothing it holds is clobbered; with the FPU off the first instruction
    // faults, which is the point.
    unsafe {
        core::arch::asm!(
            ".fpu fpv5-sp-d16",
            "vmov s0, {a}",
            "vmov s1, {b}",
            "vadd.f32 s0, s0, s1",
            "vmov {a}, s0",
            a = inout(reg) bits,
            b = in(reg) other,
            options(nomem, nostack),
        );
    }
    bits
}

/// The same addition where the compiler may emit it.
#[cfg(not(target_arch = "arm"))]
#[inline(never)]
fn add_f32() -> u32 {
    (core::hint::black_box(1.5f32) + core::hint::black_box(2.5f32)).to_bits()
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
    let before = b"[fpu_probe] before f32";
    // SAFETY: `before` is a live buffer of the length passed.
    unsafe { dev_log(sys, 3, before.as_ptr(), before.len()) };
    if add_f32() == 4.0f32.to_bits() {
        let ran = b"[fpu_probe] f32 ran";
        // SAFETY: `ran` is a live buffer of the length passed.
        unsafe { dev_log(sys, 3, ran.as_ptr(), ran.len()) };
    }
    0
}

include!("../../sdk/runtime/wasm_entry.rs");
