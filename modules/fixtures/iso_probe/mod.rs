//! EL0 isolation probe — a purpose-built PIC module for the CM5
//! module-isolation walking skeleton (`protection: isolated`).
//!
//! The probe runs **at EL0 under its own page table** and demonstrates, one
//! `mode` at a time, that the hardware boundary behaves as designed:
//!
//! | mode | name          | expected result on CM5                              |
//! |------|---------------|-----------------------------------------------------|
//! | 0    | `self_rw`     | reads+writes its own state, returns Continue (OK)   |
//! | 1    | `kernel_read` | dereferences a kernel pointer → EL0 data abort      |
//! | 2    | `oob_read`    | reads far outside its regions → EL0 data abort      |
//! | 3    | `exec_state`  | jumps into its (XN) state buffer → instruction abort|
//! | 4    | `write_code`  | writes its own (RO) code → permission abort         |
//! | 5    | `done`        | returns Done (clean EL0 round-trip)                 |
//! | 6    | `bad_channel` | `SVC #1` read on a FOREIGN handle → gateway EPERM (Continue) |
//!
//! Mode 6 is the channel-authorization probe: each step it issues an `SVC #1`
//! `channel_read` naming a handle it was never granted. The kernel gateway
//! (`el0_syscall_dispatch` → `el0_chan_ok`) must reject it with `EPERM`
//! (-1) WITHOUT touching channel state — proving an isolated module cannot
//! reach unrelated graph edges. On the expected EPERM the probe returns
//! Continue; if the call returns >= 0 the authorization failed (a breach) and
//! the probe returns a hard error (-120).
//!
//! Note: mode 6 deliberately uses the SANCTIONED `SVC #1` gateway (legal at
//! EL0 for an isolated module), NOT a direct `SyscallTable` call — the
//! syscall-free constraint below applies to the EL1 kernel function pointers,
//! which remain unmapped at EL0.
//!
//! Modes 1-4 are *expected* faults: the kernel's lower-EL abort handler
//! turns each into a module protection fault (MON_FAULT + an `[el0]` log
//! line carrying the EC/ESR/FAR), runs the configured Skip/Restart policy,
//! and **leaves a healthy sibling module stepping** — never a core hang.
//!
//! ## EL0 / syscall constraint (walking skeleton)
//!
//! `module_step` MUST be syscall-free. Every `SyscallTable` entry is a
//! direct EL1 kernel code pointer that is *not mapped* at EL0, so calling
//! one would itself fault. The probe therefore touches only its own mapped
//! regions and reports results through the **StepOutcome return value**
//! (Continue / Done / Error) and through the faults it deliberately raises.
//! `dev_log` is used only in `module_new`, which runs at EL1 during
//! instantiation. A minimal SVC syscall gateway is a documented follow-up
//! (see `docs/architecture/cm5_el0_isolation.md`).

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
include!("../../sdk/params.rs");

// ============================================================================
// Module State
// ============================================================================

#[repr(C)]
struct IsoProbeState {
    /// Kernel syscall table pointer. Stored at EL1 in `module_new`; in mode
    /// `kernel_read` the probe dereferences it from EL0 to prove kernel
    /// memory is unreachable.
    syscalls: *const SyscallTable,
    /// Input channel handle captured at `module_new` (EL1). Mode `bad_channel`
    /// derives a deliberately-foreign handle from it for the authz probe.
    in_chan: i32,
    /// Probe mode (see table above).
    mode: u8,
    /// Steps to run cleanly before performing the probed access. Lets the
    /// fixture observe a few healthy EL0 round-trips first.
    delay_steps: u16,
    /// Step counter.
    step_count: u32,
    /// Sentinel the probe writes to (and reads back from) its own state in
    /// mode `self_rw`, proving own-state RW works at EL0.
    sentinel: u32,
    /// Scratch the probe reads OOB values into so the load can't be
    /// optimised away.
    sink: u64,
}

const SENTINEL_MAGIC: u32 = 0x5130_B0E0; // "iso probe"

/// `SVC #1` gateway op selector for the `bad_channel` probe.
const SYS_CHANNEL_READ: u64 = 0;

/// Issue one `SVC #1` channel syscall (valid only at EL0, i.e. when this
/// module is `protection: isolated`). Mirrors the gateway calling convention:
/// `x0 = op`, `x1 = channel handle`, `x2 = buffer ptr`, `x3 = len` → result in
/// `x0`. Used by mode `bad_channel` to probe the gateway's handle allowlist.
///
/// # Safety
/// Only valid at EL0 under the isolated page table; `ptr`/`len` must lie in the
/// module's own mapped region.
#[cfg(target_arch = "aarch64")]
unsafe fn svc1(op: u64, chan: i32, ptr: *mut u8, len: usize) -> i32 {
    let result: i64;
    core::arch::asm!(
        "svc #1",
        in("x0") op,
        in("x1") chan as i64,
        in("x2") ptr,
        in("x3") len,
        lateout("x0") result,
        clobber_abi("C"),
    );
    result as i32
}
#[cfg(not(target_arch = "aarch64"))]
unsafe fn svc1(_op: u64, _chan: i32, _ptr: *mut u8, _len: usize) -> i32 {
    -1
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::p_u16;
    use super::p_u8;
    use super::IsoProbeState;
    use super::SCHEMA_MAX;

    define_params! {
        IsoProbeState;

        1, mode, u8, 0,
            enum { self_rw=0, kernel_read=1, oob_read=2, exec_state=3, write_code=4, done=5, bad_channel=6 }
            => |s, d, len| { s.mode = p_u8(d, len, 0, 0); };

        2, delay_steps, u16, 3
            => |s, d, len| { s.delay_steps = p_u16(d, len, 0, 3); };
    }
}

// ============================================================================
// Exported functions
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<IsoProbeState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    // Runs at EL1 during instantiation — `dev_log` is allowed here.
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() || state_size < core::mem::size_of::<IsoProbeState>() {
            return -3;
        }
        let s = &mut *(state as *mut IsoProbeState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.step_count = 0;
        s.sentinel = 0;
        s.sink = 0;

        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        dev_log(
            &*s.syscalls,
            3, // INFO
            b"[iso_probe] init\0".as_ptr(),
            16,
        );
        0 // Ready
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // Runs at EL0 under the module's page table when `protection: isolated`.
    // SYSCALL-FREE — see the module header. Reports via the return value
    // and via deliberately-raised faults.
    unsafe {
        let s = &mut *(state as *mut IsoProbeState);
        s.step_count += 1;

        // A few clean round-trips first so the fixture observes healthy EL0
        // execution before any probed access.
        if s.step_count <= s.delay_steps as u32 {
            // Own-state RW always exercised on the warm-up path.
            s.sentinel = SENTINEL_MAGIC ^ s.step_count;
            if s.sentinel != (SENTINEL_MAGIC ^ s.step_count) {
                return -100; // own state RW broken (should be impossible)
            }
            return 0; // Continue
        }

        match s.mode {
            // Own state read/write works at EL0.
            0 => {
                s.sentinel = SENTINEL_MAGIC;
                let read_back = core::ptr::read_volatile(&s.sentinel);
                if read_back == SENTINEL_MAGIC {
                    0 // Continue — isolation lets the module touch its own state
                } else {
                    -101
                }
            }
            // Dereference a kernel pointer → EL0 data abort (kernel memory
            // is not mapped in the module's page table).
            1 => {
                let kptr = s.syscalls as *const u64;
                s.sink = core::ptr::read_volatile(kptr);
                // Reaching here means isolation FAILED (kernel memory was
                // readable). Signal a hard error so the test flags it.
                -110
            }
            // Read far outside any mapped region (stands in for a neighbour
            // module's state / arbitrary kernel RAM) → EL0 data abort.
            2 => {
                let oob = (state as usize).wrapping_add(0x0040_0000) as *const u64; // +4 MiB
                s.sink = core::ptr::read_volatile(oob);
                -111
            }
            // Execute the (execute-never) state buffer → instruction abort.
            3 => {
                let f: extern "C" fn() = core::mem::transmute::<*mut u8, extern "C" fn()>(state);
                f();
                -112
            }
            // Write the module's own (read-only at EL0) code → permission
            // abort. `module_step` is in the RO+X code region.
            4 => {
                let code = module_step as *mut u32;
                core::ptr::write_volatile(code, 0);
                -113
            }
            // Clean finish — proves the full EL0→SVC→EL1 round-trip with a
            // terminal outcome.
            5 => 1, // Done
            // Channel authorization: issue an SVC #1 channel_read naming a
            // FOREIGN handle (one this module was never granted). The gateway
            // must reject it with EPERM (-1) before touching channel state. A
            // non-negative result means the read was serviced on an edge we
            // don't own → authorization breach → hard error.
            6 => {
                // DENIED path: read a handle guaranteed NOT in our [in,out,ctrl]
                // allowlist. `+1000` lands outside any real handle; the gateway
                // rejects by allowlist membership regardless of whether it names
                // a real channel. Buffer is our own state, so only the handle
                // check (not the pointer check) can reject it → must EPERM (-1).
                let foreign = s.in_chan.wrapping_add(1000);
                let r = svc1(
                    SYS_CHANNEL_READ,
                    foreign,
                    core::ptr::addr_of_mut!(s.sink) as *mut u8,
                    core::mem::size_of::<u64>(),
                );
                if r == -1 {
                    // EPERM as required (authz held). Return an error so the
                    // scheduler's restart policy re-steps this instance (restart
                    // flushes channels + clears backoff but does NOT call
                    // module_new — state persists, so each cycle re-issues the
                    // denied read). The kernel logs the gateway's denial; a breach
                    // would instead service the read and emit no denial.
                    -121
                } else {
                    -120 // serviced a foreign edge → breach
                }
            }
            _ => 0,
        }
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/wasm_entry.rs");
