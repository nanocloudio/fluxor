//! Isolated heap module — proves a gated module's heap end to end: it
//! allocates from its own per-module arena and frees back to it through the
//! gateway (its `SyscallTable`'s `heap_alloc` / `heap_free` are veneers that
//! trap), touches the allocation directly, and hands the gateway a pointer it
//! does not own.
//!
//! Each step after a short warm-up is one cycle:
//!
//! 1. `heap_alloc(CHUNK)` — the gateway returns an allocation only if it lies
//!    inside this module's heap region.
//! 2. write a pattern across it and read it back directly.
//! 3. `heap_free(state)` — a pointer outside its heap. The gateway refuses it
//!    before the kernel allocator sees it (and logs the refusal).
//! 4. `heap_free(p)`, then allocate again: first-fit + coalesce must return
//!    the same address, which proves the refused free left the allocator
//!    untouched. The module logs `[iso_heap] cycle ok ptr=… reuse=1`.
//!
//! Any breach returns a negative outcome, which the scheduler turns into a
//! contained `MON_FAULT` — the observable fail marker.

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

// ============================================================================
// Module State
// ============================================================================

/// Bytes allocated per cycle. Small + fixed so the freed chunk coalesces back
/// to the same first-fit slot, making reuse deterministic.
const CHUNK: usize = 256;

/// Heap arena bytes. Two pages hold one `CHUNK` allocation plus the
/// allocator's block headers.
const ARENA_BYTES: u32 = 8192;

#[repr(C)]
struct IsoHeapState {
    syscalls: *const SyscallTable,
    /// Step counter.
    step_count: u32,
    /// Clean cycles to run before the first probe (lets the fixture observe a
    /// few healthy round-trips first).
    delay_steps: u16,
    /// Cycles completed, for the rate-limited success line.
    cycles: u32,
}

declare_module_state_bytes!(IsoHeapState);

// ============================================================================
// Exported functions
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<IsoHeapState>() as u32
}

declare_module_arena_bytes!(ARENA_BYTES);

/// The heap arena, for a loader that asks instead of reading the manifest.
#[no_mangle]
#[link_section = ".text.module_arena_size"]
pub extern "C" fn module_arena_size() -> u32 {
    ARENA_BYTES
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
    // Runs gated like `module_step`: `dev_log` below is a gateway call.
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() || state_size < core::mem::size_of::<IsoHeapState>() {
            return -3;
        }
        let s = &mut *(state as *mut IsoHeapState);
        s.syscalls = syscalls as *const SyscallTable;
        s.step_count = 0;
        s.delay_steps = 3;
        s.cycles = 0;
        dev_log(&*s.syscalls, 3, b"[iso_heap] init\0".as_ptr(), 16);
        0 // Ready
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut IsoHeapState);
        let sys = &*s.syscalls;
        s.step_count += 1;
        if s.step_count <= s.delay_steps as u32 {
            return 0; // Continue
        }

        // 1. Allocate from our own heap through the gateway.
        let p = (sys.heap_alloc)(CHUNK as u32);
        if p.is_null() {
            return -100; // heap exhausted / no arena → fault
        }
        // 2. Write a pattern across it and read it back.
        for i in 0..CHUNK {
            core::ptr::write_volatile(p.add(i), (i as u8) ^ 0xA5);
        }
        for i in 0..CHUNK {
            if core::ptr::read_volatile(p.add(i)) != ((i as u8) ^ 0xA5) {
                (sys.heap_free)(p);
                return -101;
            }
        }
        // 3. A free of memory we do not own: refused by the gateway.
        (sys.heap_free)(state);
        // 4. Free ours, allocate again: the same address means the refused
        //    free left the allocator untouched.
        (sys.heap_free)(p);
        let q = (sys.heap_alloc)(CHUNK as u32);
        if q != p {
            if !q.is_null() {
                (sys.heap_free)(q);
            }
            return -102;
        }
        (sys.heap_free)(q);

        s.cycles += 1;
        if s.cycles <= 4 || s.cycles % 256 == 0 {
            let mut line = [0u8; 64];
            let prefix = b"[iso_heap] cycle ok ptr=0x";
            line[..prefix.len()].copy_from_slice(prefix);
            let mut n = prefix.len();
            let addr = p as usize as u64;
            let mut shift = 60i32;
            while shift >= 0 {
                let d = ((addr >> shift) & 0xF) as u8;
                line[n] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
                n += 1;
                shift -= 4;
            }
            let tail = b" reuse=1";
            line[n..n + tail.len()].copy_from_slice(tail);
            n += tail.len();
            dev_log(sys, 3, line.as_ptr(), n);
        }
        0 // Continue
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/runtime/wasm_entry.rs");
