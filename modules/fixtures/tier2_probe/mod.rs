//! Tier-2 (IRQ-owned) validation probe.
//!
//! A minimal PIC module placed on a `tier: 2` domain. The kernel binds its
//! declared `irq:` to `isr_tier2_trampoline`, so the module's `module_isr_entry`
//! is dispatched straight from interrupt context (never the cooperative
//! `module_step`). Each dispatch increments a private counter and exercises the
//! ISR-safe bridge ABI by calling `SELF_BRIDGES` (0x0C44) — proving on real
//! silicon that (a) Tier-2 dispatch reaches `module_isr_entry`, and (b) the
//! §D7-exempt bridge syscalls are reachable from ISR context. The kernel's
//! global `tier2_dispatch_count` (surfaced on the `[therm]` line as `t2disp=`)
//! climbs once per dispatch — the observable over UDP telemetry.
//!
//! Build flag `test_tier2_sgi` drives the IRQ (SGI 15 → core 1) from core 0.

#![no_std]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

/// `bridge::SELF_BRIDGES` opcode — enumerate this module's own bridge fds.
/// ISR-safe (exempt from the §D7 provider_call deny). Mirrors
/// `modules/sdk/internal/bridge.rs::SELF_BRIDGES`.
const SELF_BRIDGES: u32 = 0x0C44;

#[repr(C)]
struct Tier2ProbeState {
    syscalls: *const SyscallTable,
    out_chan: i32,
    /// Count of `module_isr_entry` dispatches (incremented from ISR context).
    isr_calls: u32,
    /// Last `SELF_BRIDGES` return code (proves the ISR-bridge ABI is reachable).
    self_bridges_rc: i32,
    in_count: u8,
    out_count: u8,
    _pad: [u8; 2],
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<Tier2ProbeState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<Tier2ProbeState>() {
            return -2;
        }
        let s = &mut *(state as *mut Tier2ProbeState);
        s.syscalls = syscalls as *const SyscallTable;
        s.out_chan = out_chan;
        s.isr_calls = 0;
        s.self_bridges_rc = 0;
        s.in_count = 0;
        s.out_count = 0;
        0
    }
}

/// Tier-2 modules are NOT stepped cooperatively — this exists only to satisfy
/// the module ABI (the scheduler skips ISR-tier modules in `step_*`).
#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(_state: *mut u8) -> i32 {
    0 // Continue
}

/// IRQ entry point — dispatched by `isr_tier2_trampoline` from interrupt
/// context. `current_module_index` is set to this module for the call, so the
/// §D7 syscall gate is armed: only the ISR-exempt bridge ops succeed.
#[no_mangle]
#[link_section = ".text.module_isr_entry"]
pub extern "C" fn module_isr_entry(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut Tier2ProbeState);
        s.isr_calls = s.isr_calls.wrapping_add(1);
        // Exercise the ISR-safe bridge ABI from real ISR context. With no
        // bridges wired this returns -ENODEV, but the call COMPLETING (not
        // EACCES, not a fault that would stall dispatch) validates that the
        // §D7 exemption + SELF_BRIDGES enumeration work on silicon.
        if !s.syscalls.is_null() {
            let sys = &*s.syscalls;
            let mut buf = [0u8; 36]; // SELF_BRIDGES_BUF_LEN = 4 + 8*4
            s.self_bridges_rc =
                (sys.provider_call)(-1, SELF_BRIDGES, buf.as_mut_ptr(), buf.len());
            s.in_count = buf[0];
            s.out_count = buf[1];
        }
        0
    }
}

include!("../../sdk/wasm_entry.rs");
