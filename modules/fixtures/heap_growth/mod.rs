//! heap_growth — grows its elastic heap on every step.
//!
//! Each step allocates one `CHUNK` and keeps it, so the heap commits a new
//! segment from the state arena whenever its committed segments are full —
//! on the step, where no zeroing may land. When the cap refuses an
//! allocation it frees every chunk it holds and starts the next cycle. A
//! heap keeps the segments it has committed, so the first cycle is the one
//! that carves (eight segments up to the cap); the later ones reallocate
//! within them. The kernel's `[heap] zstep=` heartbeat is the measurement;
//! this module's own line is the evidence that the growth happened.

#![cfg_attr(not(feature = "host-test"), no_std)]
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

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

/// Bytes allocated per step.
const CHUNK: u32 = 16 * 1024;
/// The heap's cap. Elastic: the kernel commits it a segment at a time, the
/// first `ARENA_BYTES >> 7`, each later one doubling what is committed.
const ARENA_BYTES: u32 = 32 * 1024 * 1024;
/// Chunks held at most: the cap's worth.
const HELD_MAX: usize = (ARENA_BYTES / CHUNK) as usize;

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    held: [*mut u8; HELD_MAX],
    count: u32,
    cycles: u32,
    peak: u32,
    fails: u32,
    steps: u32,
}

fn put(line: &mut [u8], n: &mut usize, b: &[u8]) {
    for &c in b {
        if let Some(slot) = line.get_mut(*n) {
            *slot = c;
            *n += 1;
        }
    }
}

fn put_dec(line: &mut [u8], n: &mut usize, mut v: u32) {
    let mut d = [0u8; 10];
    let mut k = 0;
    loop {
        if let Some(slot) = d.get_mut(k) {
            *slot = b'0' + (v % 10) as u8;
        }
        k += 1;
        v /= 10;
        if v == 0 || k >= d.len() {
            break;
        }
    }
    while k > 0 {
        k -= 1;
        put(line, n, d.get(k..k + 1).unwrap_or(&[]));
    }
}

declare_module_state_bytes!(State);
declare_module_arena_bytes!(ARENA_BYTES);

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_state_size")]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

/// The heap arena, for a loader that asks instead of reading the manifest.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_arena_size")]
pub extern "C" fn module_arena_size() -> u32 {
    ARENA_BYTES
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_init")]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes and `syscalls` the kernel's syscall table.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_new")]
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
    if syscalls.is_null() || state.is_null() || state_size < core::mem::size_of::<State>() {
        return -22;
    }
    core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
    let s = &mut *(state as *mut State);
    s.syscalls = syscalls as *const SyscallTable;
    0
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut State);
    let sys = &*s.syscalls;
    s.steps = s.steps.wrapping_add(1);
    let p = (sys.heap_alloc)(CHUNK);
    let slot = s.held.get_mut(s.count as usize);
    match (p.is_null(), slot) {
        (false, Some(slot)) => {
            // Touch the chunk, as a real allocation's user would.
            core::ptr::write_volatile(p, 1);
            *slot = p;
            s.count += 1;
            s.peak = s.peak.max(s.count * CHUNK);
        }
        (false, None) => (sys.heap_free)(p),
        (true, _) => {
            // The cap: let everything go and grow again.
            s.fails = s.fails.wrapping_add(1);
            for q in s.held.iter_mut().take(s.count as usize) {
                (sys.heap_free)(*q);
                *q = core::ptr::null_mut();
            }
            s.count = 0;
            s.cycles = s.cycles.wrapping_add(1);
        }
    }
    if s.steps % 1024 == 1 {
        let mut line = [0u8; 96];
        let mut n = 0;
        put(&mut line, &mut n, b"[heap_growth] cycle=");
        put_dec(&mut line, &mut n, s.cycles);
        put(&mut line, &mut n, b" held=");
        put_dec(&mut line, &mut n, s.count * CHUNK);
        put(&mut line, &mut n, b" peak=");
        put_dec(&mut line, &mut n, s.peak);
        put(&mut line, &mut n, b" fails=");
        put_dec(&mut line, &mut n, s.fails);
        dev_log(sys, 3, line.as_ptr(), n);
    }
    0
}

include!("../../sdk/runtime/wasm_entry.rs");
