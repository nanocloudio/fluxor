//! EL0 isolated heap module — proves the `SVC #1` heap-mediation slice end to
//! end: an isolated module that runs entirely at EL0 under its own page table
//! and exercises its **own per-module heap** through mediated `heap_alloc` /
//! `heap_free` syscalls, with zero access to kernel memory or the
//! `SyscallTable` function pointers.
//!
//! Wire it as an `protection: isolated` module; see
//! `examples/iso_heap/cm5.yaml`.
//!
//! ## What each `module_step` proves (one full cycle per step)
//!
//! 1. **alloc at EL0** — `heap_alloc(CHUNK)` via `SVC #1`; the kernel returns
//!    a pointer that, by construction and by the gateway's own bounds check,
//!    lies inside this module's EL0-mapped heap region.
//! 2. **write + read at EL0** — the module writes a byte pattern across the
//!    whole allocation and reads it back, touching the heap directly (it is
//!    mapped RW at EL0 — no syscall needed for the data access itself).
//! 3. **rejected invalid free** — it asks the gateway to free a pointer it
//!    does NOT own (its own *state* address, which is outside the heap
//!    region). The gateway must reject with `EFAULT` (-14) WITHOUT touching
//!    the kernel allocator — proving a hostile/buggy free pointer cannot
//!    drive an arbitrary kernel write. A non-error return means the boundary
//!    failed → the module reports a hard error.
//! 4. **free at EL0** — `heap_free(ptr)` returns success (0).
//! 5. **reuse** — every step is a full allocate/free cycle, so the next
//!    cycle's allocation of the same size returns the same address (first-fit
//!    after free+coalesce). The constant `ptr=` in the gateway's `heap_alloc
//!    ok` log line is the observable proof the arena is genuinely reused.
//!
//! Success is reported by returning `Continue` every step (the kernel logs
//! `[el0] … el0 step ok` + `[el0] … heap_alloc ok`); any boundary failure
//! returns a negative `StepOutcome`, which the scheduler turns into a
//! contained `MON_FAULT` — the observable fail marker.
//!
//! **Requires `protection: isolated`.** Run non-isolated it would execute at
//! EL1, where `svc #1` traps to the current-EL vector (no syscall path) — so
//! this module is only meaningful under EL0 isolation.

#![no_std]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset."
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

// ---- EL0 syscall gateway (SVC #1) — heap slice ----------------------------
//
// Mirrors `kernel::el0_abi`. Heap ops reuse the shared register file:
//   x0 = op, x3 = size (alloc) / x2 = ptr (free) -> x0 = i64 result.
const SYS_HEAP_ALLOC: u64 = 3;
const SYS_HEAP_FREE: u64 = 4;

/// `EFAULT` as the gateway returns it for a rejected free pointer.
const GATEWAY_EFAULT: i64 = -14;

/// `heap_alloc(size)` via `SVC #1`. Returns the allocation pointer, or null
/// when the heap is exhausted / the module has no heap. Only valid at EL0.
///
/// # Safety
/// Only meaningful at EL0 under the isolated page table.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn heap_alloc_svc(size: usize) -> *mut u8 {
    let ret: i64;
    core::arch::asm!(
        "svc #1",
        in("x0") SYS_HEAP_ALLOC,
        in("x1") 0i64,   // chan unused for heap ops
        in("x2") 0u64,   // ptr unused for alloc
        in("x3") size,
        lateout("x0") ret,
        clobber_abi("C"),
    );
    // i64 -> pointer: a heap pointer fits the low VA window; 0 == null.
    ret as u64 as *mut u8
}
#[cfg(not(target_arch = "aarch64"))]
unsafe fn heap_alloc_svc(_size: usize) -> *mut u8 {
    core::ptr::null_mut()
}

/// `heap_free(ptr)` via `SVC #1`. Returns 0 on success/no-op, or a negative
/// errno (e.g. `EFAULT`) if the gateway rejected the pointer. Only valid at
/// EL0.
///
/// # Safety
/// Only meaningful at EL0 under the isolated page table.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn heap_free_svc(ptr: *mut u8) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "svc #1",
        in("x0") SYS_HEAP_FREE,
        in("x1") 0i64,   // chan unused for heap ops
        in("x2") ptr as u64,
        in("x3") 0usize, // size unused for free
        lateout("x0") ret,
        clobber_abi("C"),
    );
    ret
}
#[cfg(not(target_arch = "aarch64"))]
unsafe fn heap_free_svc(_ptr: *mut u8) -> i64 {
    GATEWAY_EFAULT
}

// ============================================================================
// Module State
// ============================================================================

/// Bytes allocated per cycle. Small + fixed so the freed chunk coalesces back
/// to the same first-fit slot, making reuse deterministic.
const CHUNK: usize = 256;

/// Heap arena bytes requested via `module_arena_size`. Two pages comfortably
/// hold one `CHUNK` allocation plus the allocator's block headers, and is
/// page-aligned/padded by `loader::alloc_isolated` so `build_table`'s
/// page-clean check passes.
const ARENA_BYTES: u32 = 8192;

#[repr(C)]
struct IsoHeapState {
    syscalls: *const SyscallTable,
    /// Step counter.
    step_count: u32,
    /// Clean cycles to run before the first probe (lets the fixture observe a
    /// few healthy EL0 round-trips first).
    delay_steps: u16,
}

// ============================================================================
// Exported functions
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<IsoHeapState>() as u32
}

/// Request a per-module heap arena. Non-zero → the loader allocates the arena
/// (page-aligned for isolated modules) and inits this module's `ModuleHeap`,
/// then maps the arena RW at EL0.
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
    // Runs at EL1 during instantiation — `dev_log` is allowed here.
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
        dev_log(&*s.syscalls, 3, b"[iso_heap] init\0".as_ptr(), 16);
        0 // Ready
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // Runs at EL0 under the module's page table. HEAP-MEDIATED: alloc/free go
    // through `SVC #1`; the allocation is touched directly (it is mapped RW at
    // EL0). No kernel pointer is dereferenced.
    unsafe {
        let s = &mut *(state as *mut IsoHeapState);
        s.step_count += 1;

        // A few clean round-trips first so the fixture observes healthy EL0
        // execution before any heap activity.
        if s.step_count <= s.delay_steps as u32 {
            return 0; // Continue
        }

        // --- 1. Allocate from our own heap via the gateway. Each step is a
        //     full allocate/free cycle, so the arena is reused every tick;
        //     first-fit + coalesce returns the same slot each time (visible
        //     as a constant `ptr=` in the gateway's `heap_alloc ok` log). ---
        let p = heap_alloc_svc(CHUNK);
        if p.is_null() {
            return -100; // heap exhausted / no arena → fault
        }

        // --- 2. Write a pattern across the whole allocation and read it
        //     back at EL0 (the heap is mapped RW in this module's table). --
        for i in 0..CHUNK {
            core::ptr::write_volatile(p.add(i), (i as u8) ^ 0xA5);
        }
        for i in 0..CHUNK {
            let v = core::ptr::read_volatile(p.add(i));
            if v != ((i as u8) ^ 0xA5) {
                // Free before bailing so a transient mismatch doesn't leak the
                // chunk (defensive; a real mismatch means isolation is broken).
                let _ = heap_free_svc(p);
                return -101; // write/read mismatch → fault
            }
        }

        // --- 3. Rejected invalid free: hand the gateway a pointer we do NOT
        //     own (our own state address, outside the heap region). The
        //     gateway must reject it with EFAULT without touching the kernel
        //     allocator. A success return is an authorization/validation
        //     breach. ------------------------------------------------------
        let foreign = state; // state region != heap region
        let r = heap_free_svc(foreign);
        if r != GATEWAY_EFAULT {
            // Either it freed a non-heap pointer (breach) or returned an
            // unexpected code. Free our real chunk, then fault hard.
            let _ = heap_free_svc(p);
            return -102;
        }

        // --- 4. Free our real allocation. Must succeed (0). ---------------
        let f = heap_free_svc(p);
        if f != 0 {
            return -103; // unexpected free error → fault
        }

        0 // Continue — full alloc/write/read/reject-bad-free/free cycle ok
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/wasm_entry.rs");
