//! `irq` (IRQ-owned) validation probe.
//!
//! A minimal PIC module placed on an `exec: irq` domain. The kernel binds its
//! declared `irq:` to `irq_trampoline`, so the module's `module_isr_entry`
//! is dispatched straight from interrupt context (never the cooperative
//! `module_step`). `module_new` takes the module's first input bridge
//! (`bridge::SELF_BRIDGE`); each dispatch increments a private counter and
//! polls that bridge (`bridge::POLL`) — proving on real silicon that (a) `irq`
//! dispatch reaches `module_isr_entry`, and (b) the §D7-exempt bridge syscalls
//! are reachable from ISR context. The kernel's
//! global `irq::dispatch_count` (surfaced on the `[therm]` line as `irqdisp=`)
//! climbs once per dispatch — the observable over UDP telemetry.
//!
//! The `sgi_driver` fixture on core 0 raises the IRQ (`SIGNAL_CORE`, SGI 15
//! to core 1).

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
use fluxor_rt::StepReturn;

use abi::internal::bridge;

#[repr(C)]
struct IrqProbeState {
    syscalls: *const SyscallTable,
    out_chan: i32,
    /// Count of `module_isr_entry` dispatches (incremented from ISR context).
    isr_calls: u32,
    /// The first input bridge's handle, or the errno `SELF_BRIDGE` answered.
    in_bridge: i32,
    /// Last bridge `POLL` return code (proves the ISR-bridge ABI is reachable).
    poll_rc: i32,
}

fluxor_rt::module_facts! { state: IrqProbeState }

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
        if state_size < core::mem::size_of::<IrqProbeState>() {
            return -2;
        }
        let s = &mut *(state as *mut IrqProbeState);
        s.syscalls = syscalls as *const SyscallTable;
        s.out_chan = out_chan;
        s.isr_calls = 0;
        s.poll_rc = 0;
        // A bridge handle is a kernel route: taken here, on the scheduler,
        // never from the ISR entry.
        let sys = &*s.syscalls;
        let mut arg = [bridge::DIR_IN, 0];
        s.in_bridge = (sys.provider_call)(
            -1,
            bridge::SELF_BRIDGE,
            arg.as_mut_ptr(),
            arg.len(),
            core::ptr::null_mut(),
            0,
        );
        0
    }
}

/// `irq` modules are NOT stepped cooperatively — this exists only to satisfy
/// the module ABI (the scheduler skips interrupt-mode modules in `step_*`).
#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(_state: *mut u8) -> StepReturn {
    StepReturn::Continue
}

/// IRQ entry point — dispatched by `irq_trampoline` from interrupt
/// context. `current_module_index` is set to this module for the call, so the
/// §D7 syscall gate is armed: only the ISR-exempt bridge ops succeed.
#[no_mangle]
#[link_section = ".text.module_isr_entry"]
pub extern "C" fn module_isr_entry(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut IrqProbeState);
        s.isr_calls = s.isr_calls.wrapping_add(1);
        // Exercise the ISR-safe bridge ABI from real ISR context. With no
        // bridge wired the poll is refused, but the call COMPLETING (not
        // EACCES, not a fault that would stall dispatch) validates that the
        // §D7 exemption works on silicon.
        if !s.syscalls.is_null() {
            let sys = &*s.syscalls;
            s.poll_rc = (sys.provider_call)(
                s.in_bridge,
                bridge::POLL,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                0,
            );
        }
        0
    }
}

fluxor_rt::wasm_entry!();
