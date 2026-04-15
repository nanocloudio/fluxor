//! Live Graph Reconfigure — PIC Module
//!
//! Drives the reconfigure state machine
//! (RUNNING → DRAINING → MIGRATING → RUNNING) using kernel primitives
//! exposed via the `dev_system` reconfigure opcodes (0x0C67-0x0C6F).
//! Graphs that do not include this module carry none of the drain,
//! transition, or timeout logic.
//!
//! Input:
//!   - ctrl channel: reading any byte starts a reconfigure. The main loop
//!     reloads STATIC_CONFIG; the trigger payload is not consumed.
//!
//! Params (TLV, optional):
//!   - tag 1: drain_timeout_ms (u32 LE, default 5000)

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

// ============================================================================
// Opcodes (mirror modules/sdk/abi.rs::dev_system)
// ============================================================================

const SYS_RECONFIG_SELF_INDEX: u32      = 0x0C67;
const SYS_RECONFIG_SET_PHASE: u32       = 0x0C68;
const SYS_RECONFIG_CALL_DRAIN: u32      = 0x0C69;
const SYS_RECONFIG_MARK_FINISHED: u32   = 0x0C6A;
const SYS_RECONFIG_MODULE_COUNT: u32    = 0x0C6B;
const SYS_RECONFIG_MODULE_INFO: u32     = 0x0C6C;
const SYS_RECONFIG_TRIGGER_REBUILD: u32 = 0x0C6D;
const SYS_RECONFIG_MODULE_UPSTREAM: u32 = 0x0C6E;
const SYS_RECONFIG_MODULE_DONE: u32     = 0x0C6F;

// Optional graph_slot integration. When a graph_slot provider is
// registered, the reconfigure module activates the staged slot so the
// post-rebuild boot loads its modules and config.
const SYS_GRAPH_SLOT_ACTIVATE: u32      = 0x0C94;

// Fault monitor integration. Raise a fault against a module whose drain
// exceeded its deadline so the unified fault pipeline (monitor CLI,
// metrics sinks) records it alongside step-guard and MPU faults.
const SYS_FAULT_RAISE: u32              = 0x0C56;
const FAULT_KIND_DRAIN_TIMEOUT: u8      = 5;

// Phase values mirror scheduler::ReconfigurePhase.
const PHASE_RUNNING: u8   = 0;
const PHASE_DRAINING: u8  = 1;
const PHASE_MIGRATING: u8 = 2;

// Per-module drain classification (local bookkeeping).
const DS_SURVIVING: u8         = 0;
const DS_DRAINING: u8          = 1;
const DS_DRAINED: u8           = 2;
const DS_PENDING_TERMINATE: u8 = 3;

// Bits returned by RECONFIGURE_MODULE_INFO.
const INFO_DRAIN_CAPABLE: u32 = 0x01;

// Matches the 32-bit upstream_mask the kernel exposes.
const MAX_TRACKED_MODULES: usize = 32;

// StepOutcome return values.
const CONTINUE: i32 = 0;
const READY: i32    = 3;

// Sentinel for "self index not yet resolved".
const SELF_IDX_UNKNOWN: u8 = 0xFF;

// Status event kinds emitted on the output channel. Each record is
// 8 bytes: `[kind:u8, module_idx:u8, extra:u16 LE, tick:u32 LE]`.
const STATUS_DRAINING_ENTERED: u8   = 0x01;
const STATUS_MODULE_DRAINED: u8     = 0x02;
const STATUS_MODULE_FORCED: u8      = 0x03;
const STATUS_MIGRATING_ENTERED: u8  = 0x04;
const STATUS_RECORD_SIZE: usize     = 8;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    ctrl_chan: i32,
    /// Output channel for structured status events. `-1` when the graph
    /// does not wire an output; events are silently dropped in that case.
    status_chan: i32,
    phase: u8,
    self_idx: u8,
    signaled_ready: u8,
    _pad0: u8,
    tick_count: u32,
    drain_start_tick: u32,
    drain_timeout_ms: u32,
    drain_state: [u8; MAX_TRACKED_MODULES],
}

// ============================================================================
// Syscall wrappers
// ============================================================================

unsafe fn sys_self_index(sys: &SyscallTable) -> i32 {
    (sys.dev_call)(-1, SYS_RECONFIG_SELF_INDEX, core::ptr::null_mut(), 0)
}

unsafe fn sys_set_phase(sys: &SyscallTable, phase: u8) {
    let mut arg = [phase];
    (sys.dev_call)(-1, SYS_RECONFIG_SET_PHASE, arg.as_mut_ptr(), 1);
}

unsafe fn sys_call_drain(sys: &SyscallTable, idx: u8) -> i32 {
    let mut arg = [idx];
    (sys.dev_call)(-1, SYS_RECONFIG_CALL_DRAIN, arg.as_mut_ptr(), 1)
}

unsafe fn sys_mark_finished(sys: &SyscallTable, idx: u8) {
    let mut arg = [idx];
    (sys.dev_call)(-1, SYS_RECONFIG_MARK_FINISHED, arg.as_mut_ptr(), 1);
}

unsafe fn sys_fault_raise(sys: &SyscallTable, idx: u8, kind: u8) {
    let mut arg = [idx, kind];
    (sys.dev_call)(-1, SYS_FAULT_RAISE, arg.as_mut_ptr(), 2);
}

/// Write a single 8-byte status record to the output channel. Silently
/// drops the event if the channel is not wired or the ring is full.
unsafe fn emit_status(s: &State, sys: &SyscallTable, kind: u8, module_idx: u8, extra: u16) {
    if s.status_chan < 0 { return; }
    let mut rec = [0u8; STATUS_RECORD_SIZE];
    let p = rec.as_mut_ptr();
    core::ptr::write_volatile(p.add(0), kind);
    core::ptr::write_volatile(p.add(1), module_idx);
    let eb = extra.to_le_bytes();
    core::ptr::write_volatile(p.add(2), eb[0]);
    core::ptr::write_volatile(p.add(3), eb[1]);
    let tb = s.tick_count.to_le_bytes();
    core::ptr::write_volatile(p.add(4), tb[0]);
    core::ptr::write_volatile(p.add(5), tb[1]);
    core::ptr::write_volatile(p.add(6), tb[2]);
    core::ptr::write_volatile(p.add(7), tb[3]);
    let _ = (sys.channel_write)(s.status_chan, rec.as_ptr(), STATUS_RECORD_SIZE);
}

unsafe fn sys_module_count(sys: &SyscallTable) -> i32 {
    (sys.dev_call)(-1, SYS_RECONFIG_MODULE_COUNT, core::ptr::null_mut(), 0)
}

unsafe fn sys_module_info(sys: &SyscallTable, idx: u8) -> u32 {
    let mut arg = [idx];
    let rc = (sys.dev_call)(-1, SYS_RECONFIG_MODULE_INFO, arg.as_mut_ptr(), 1);
    if rc < 0 { 0 } else { rc as u32 }
}

unsafe fn sys_module_upstream(sys: &SyscallTable, idx: u8) -> u32 {
    let mut arg = [idx];
    let rc = (sys.dev_call)(-1, SYS_RECONFIG_MODULE_UPSTREAM, arg.as_mut_ptr(), 1);
    if rc < 0 { 0 } else { rc as u32 }
}

unsafe fn sys_module_done(sys: &SyscallTable, idx: u8) -> bool {
    let mut arg = [idx];
    (sys.dev_call)(-1, SYS_RECONFIG_MODULE_DONE, arg.as_mut_ptr(), 1) == 1
}

unsafe fn sys_trigger_rebuild(sys: &SyscallTable, ptr: usize, len: usize) {
    // Arg layout: [ptr:usize, len:usize] in platform-native width.
    let ptr_bytes = ptr.to_le_bytes();
    let len_bytes = len.to_le_bytes();
    let psz = core::mem::size_of::<usize>();
    let mut buf = [0u8; 16]; // fits up to 64-bit usize
    let mut i = 0;
    while i < psz {
        core::ptr::write_volatile(buf.as_mut_ptr().add(i), *ptr_bytes.as_ptr().add(i));
        core::ptr::write_volatile(buf.as_mut_ptr().add(psz + i), *len_bytes.as_ptr().add(i));
        i += 1;
    }
    (sys.dev_call)(-1, SYS_RECONFIG_TRIGGER_REBUILD, buf.as_mut_ptr(), psz * 2);
}

// ============================================================================
// Drain-state accessors (pointer arithmetic — PIC modules avoid array indexing)
// ============================================================================

unsafe fn ds_get(s: &State, i: usize) -> u8 {
    if i >= MAX_TRACKED_MODULES { return DS_SURVIVING; }
    core::ptr::read(s.drain_state.as_ptr().add(i))
}

unsafe fn ds_set(s: &mut State, i: usize, v: u8) {
    if i >= MAX_TRACKED_MODULES { return; }
    core::ptr::write_volatile(s.drain_state.as_mut_ptr().add(i), v);
}

// ============================================================================
// State-machine transitions
// ============================================================================

unsafe fn begin_draining(s: &mut State, sys: &SyscallTable) {
    let count = sys_module_count(sys);
    if count <= 0 { return; }
    let count = count as usize;
    let count = if count > MAX_TRACKED_MODULES { MAX_TRACKED_MODULES } else { count };

    sys_set_phase(sys, PHASE_DRAINING);
    s.phase = PHASE_DRAINING;
    s.drain_start_tick = s.tick_count;

    // Classify every module. The reconfigure module itself is marked
    // Surviving so the scheduler keeps stepping it; drain-capable modules
    // enter Draining; the rest are terminated immediately.
    let mut draining = 0u16;
    let mut i = 0;
    while i < count {
        let idx = i as u8;
        if idx == s.self_idx {
            ds_set(s, i, DS_SURVIVING);
        } else {
            let flags = sys_module_info(sys, idx);
            if (flags & INFO_DRAIN_CAPABLE) != 0 {
                ds_set(s, i, DS_DRAINING);
                draining += 1;
            } else {
                ds_set(s, i, DS_PENDING_TERMINATE);
                sys_mark_finished(sys, idx);
            }
        }
        i += 1;
    }

    // Signal drain-start to every drain-capable module. Ordering between
    // producers and consumers is handled in `check_drain` via the upstream
    // mask (RFC Section 3.2: drain completion follows forward topo order).
    let mut i = 0;
    while i < count {
        let idx = i as u8;
        if ds_get(s, i) == DS_DRAINING {
            let _ = sys_call_drain(sys, idx);
        }
        i += 1;
    }

    emit_status(s, sys, STATUS_DRAINING_ENTERED, 0, draining);
}

/// Returns true once every non-surviving module is Drained or
/// PendingTerminate.
unsafe fn check_drain(s: &mut State, sys: &SyscallTable) -> bool {
    let count = sys_module_count(sys);
    if count <= 0 { return true; }
    let count = count as usize;
    let count = if count > MAX_TRACKED_MODULES { MAX_TRACKED_MODULES } else { count };

    let elapsed = s.tick_count.wrapping_sub(s.drain_start_tick);
    let timed_out = elapsed >= s.drain_timeout_ms;

    // Promote Draining → Drained when the module has returned Done and all
    // its upstream-draining peers are already Drained.
    let mut i = 0;
    while i < count {
        if ds_get(s, i) == DS_DRAINING {
            let idx = i as u8;
            if sys_module_done(sys, idx) {
                let upstream = sys_module_upstream(sys, idx);
                let mut upstream_ok = true;
                let mut j = 0;
                while j < count {
                    if j != i
                        && (upstream & (1u32 << j)) != 0
                        && ds_get(s, j) == DS_DRAINING
                    {
                        upstream_ok = false;
                        break;
                    }
                    j += 1;
                }
                if upstream_ok {
                    ds_set(s, i, DS_DRAINED);
                    sys_mark_finished(sys, idx);
                    emit_status(s, sys, STATUS_MODULE_DRAINED, idx, 0);
                }
            } else if timed_out {
                ds_set(s, i, DS_DRAINED);
                sys_mark_finished(sys, idx);
                sys_fault_raise(sys, idx, FAULT_KIND_DRAIN_TIMEOUT);
                emit_status(s, sys, STATUS_MODULE_FORCED, idx, 0);
            }
        }
        i += 1;
    }

    let mut i = 0;
    while i < count {
        if ds_get(s, i) == DS_DRAINING {
            return false;
        }
        i += 1;
    }
    true
}

unsafe fn begin_migrating(s: &mut State, sys: &SyscallTable) {
    sys_set_phase(sys, PHASE_MIGRATING);
    s.phase = PHASE_MIGRATING;
    let elapsed = s.tick_count.wrapping_sub(s.drain_start_tick);
    let elapsed_u16 = if elapsed > u16::MAX as u32 { u16::MAX } else { elapsed as u16 };
    emit_status(s, sys, STATUS_MIGRATING_ENTERED, 0, elapsed_u16);
    // If a graph_slot provider is registered and an activation succeeds,
    // the kernel's boot-time layout scan will pick the newly-live slot on
    // the next rebuild. A negative return means no graph_slot is present
    // (ENOSYS) or the staged slot failed integrity — either way we fall
    // back to the current STATIC_CONFIG, which is the same image we are
    // already running. The rebuild path is therefore idempotent on failure.
    let _ = (sys.dev_call)(-1, SYS_GRAPH_SLOT_ACTIVATE, core::ptr::null_mut(), 0);
    sys_trigger_rebuild(sys, 0, 0);
}

// ============================================================================
// Module entry points
// ============================================================================

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
    out_chan: i32,
    ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<State>() {
            return -2;
        }
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.ctrl_chan = ctrl_chan;
        s.status_chan = out_chan;
        s.phase = PHASE_RUNNING;
        s.self_idx = SELF_IDX_UNKNOWN;
        s.signaled_ready = 0;
        s.tick_count = 0;
        s.drain_start_tick = 0;
        s.drain_timeout_ms = 5000;

        // TLV params: tag 1 (u32 LE) = drain_timeout_ms.
        if !params.is_null() && params_len >= 2 {
            let mut off = 0usize;
            while off + 2 <= params_len {
                let tag = *params.add(off);
                let len = *params.add(off + 1) as usize;
                off += 2;
                if off + len > params_len { break; }
                if tag == 1 && len == 4 {
                    let mut v = 0u32;
                    let mut i = 0;
                    while i < 4 {
                        v |= (*params.add(off + i) as u32) << (i * 8);
                        i += 1;
                    }
                    s.drain_timeout_ms = v;
                }
                off += len;
            }
        }
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() { return -1; }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() { return -1; }
        let sys = &*s.syscalls;

        s.tick_count = s.tick_count.wrapping_add(1);

        if s.signaled_ready == 0 {
            s.signaled_ready = 1;
            let rc = sys_self_index(sys);
            if rc >= 0 && rc < MAX_TRACKED_MODULES as i32 {
                s.self_idx = rc as u8;
            }
            return READY;
        }

        match s.phase {
            PHASE_RUNNING => {
                if s.ctrl_chan >= 0 {
                    let mut b = [0u8; 1];
                    let rc = (sys.channel_read)(s.ctrl_chan, b.as_mut_ptr(), 1);
                    if rc > 0 {
                        begin_draining(s, sys);
                    }
                }
            }
            PHASE_DRAINING => {
                if check_drain(s, sys) {
                    begin_migrating(s, sys);
                }
            }
            PHASE_MIGRATING => {
                // The main loop takes over once the rebuild request has been
                // observed. Continuing to step here is a no-op.
            }
            _ => {}
        }

        CONTINUE
    }
}

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(_state: *mut u8) -> i32 {
    // No self-drain work: report immediately drained.
    1
}

#[no_mangle]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> i32 { 1 }

// ============================================================================
// Panic handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
