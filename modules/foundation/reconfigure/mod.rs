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
// Opcodes — imported from the layered ABI, not hardcoded.
// ============================================================================

use abi::internal::reconfigure::{
    CALL_DRAIN as SYS_RECONFIG_CALL_DRAIN, MARK_FINISHED as SYS_RECONFIG_MARK_FINISHED,
    MODULE_COUNT as SYS_RECONFIG_MODULE_COUNT, MODULE_DONE as SYS_RECONFIG_MODULE_DONE,
    MODULE_INFO as SYS_RECONFIG_MODULE_INFO, MODULE_UPSTREAM as SYS_RECONFIG_MODULE_UPSTREAM,
    SELF_INDEX as SYS_RECONFIG_SELF_INDEX, SET_PHASE as SYS_RECONFIG_SET_PHASE,
    TRIGGER_REBUILD as SYS_RECONFIG_TRIGGER_REBUILD,
};

// Optional graph_slot integration. When a graph_slot provider is
// registered (wire `reconfigure.gs_req` → `graph_slot.requests`), the
// reconfigure module activates the staged slot via the graph_slot
// channel protocol so the post-rebuild boot loads its modules and
// config. The activation is fire-and-forget; if graph_slot is not
// wired or the staged slot fails SHA-256 validation, the rebuild
// falls back to the current STATIC_CONFIG, which is idempotent.
use abi::contracts::storage::graph_slot::channel::{FRAME_HDR as GS_FRAME_HDR, REQ_ACTIVATE};

// Fault monitor integration. Raise a fault against a module whose drain
// exceeded its deadline so the unified fault pipeline (monitor CLI,
// metrics sinks) records it alongside step-guard and MPU faults.
use abi::internal::monitor::FAULT_RAISE as SYS_FAULT_RAISE;
const FAULT_KIND_DRAIN_TIMEOUT: u8 = 5;

// Phase values mirror scheduler::ReconfigurePhase.
const PHASE_RUNNING: u8 = 0;
const PHASE_DRAINING: u8 = 1;
const PHASE_MIGRATING: u8 = 2;

// Per-module drain classification (local bookkeeping).
const DS_SURVIVING: u8 = 0;
const DS_DRAINING: u8 = 1;
const DS_DRAINED: u8 = 2;
const DS_PENDING_TERMINATE: u8 = 3;

// Bits returned by RECONFIGURE_MODULE_INFO.
const INFO_DRAIN_CAPABLE: u32 = 0x01;

// Drain-state capacity: one state byte per module slot the kernel's profile
// holds, so every module of the graph is classified and drained.
const MAX_TRACKED_MODULES: usize = abi::config::kernel::MAX_MODULES;

// StepOutcome return values.
const CONTINUE: i32 = 0;
const READY: i32 = 3;

// Sentinel for "self index not yet resolved".
const SELF_IDX_UNKNOWN: u16 = 0xFFFF;

// Status event kinds emitted on the output channel. Each record is
// 12 bytes: `[kind:u8, 0:u8, module_idx:u16 LE, extra:u16 LE, 0:u16,
// tick:u32 LE]`.
const STATUS_DRAINING_ENTERED: u8 = 0x01;
const STATUS_MODULE_DRAINED: u8 = 0x02;
const STATUS_MODULE_FORCED: u8 = 0x03;
const STATUS_MIGRATING_ENTERED: u8 = 0x04;
const STATUS_RECORD_SIZE: usize = 12;

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
    /// Output port 1 — graph_slot request channel. `-1` when unwired.
    gs_req_chan: i32,
    phase: u8,
    signaled_ready: u8,
    self_idx: u16,
    tick_count: u32,
    drain_start_tick: u32,
    drain_timeout_ms: u32,
    drain_state: [u8; MAX_TRACKED_MODULES],
}

// ============================================================================
// Syscall wrappers
// ============================================================================

unsafe fn sys_self_index(sys: &SyscallTable) -> i32 {
    (sys.provider_call)(-1, SYS_RECONFIG_SELF_INDEX, core::ptr::null_mut(), 0)
}

unsafe fn sys_set_phase(sys: &SyscallTable, phase: u8) {
    let mut arg = [phase];
    (sys.provider_call)(-1, SYS_RECONFIG_SET_PHASE, arg.as_mut_ptr(), 1);
}

unsafe fn sys_call_drain(sys: &SyscallTable, idx: u16) -> i32 {
    let mut arg = idx.to_le_bytes();
    (sys.provider_call)(-1, SYS_RECONFIG_CALL_DRAIN, arg.as_mut_ptr(), 2)
}

unsafe fn sys_mark_finished(sys: &SyscallTable, idx: u16) {
    let mut arg = idx.to_le_bytes();
    (sys.provider_call)(-1, SYS_RECONFIG_MARK_FINISHED, arg.as_mut_ptr(), 2);
}

unsafe fn sys_fault_raise(sys: &SyscallTable, idx: u16, kind: u8) {
    let i = idx.to_le_bytes();
    let mut arg = [i[0], i[1], kind];
    (sys.provider_call)(-1, SYS_FAULT_RAISE, arg.as_mut_ptr(), 3);
}

/// Write a single 12-byte status record to the output channel. Silently
/// drops the event if the channel is not wired or the ring is full.
unsafe fn emit_status(s: &State, sys: &SyscallTable, kind: u8, module_idx: u16, extra: u16) {
    if s.status_chan < 0 {
        return;
    }
    let mut rec = [0u8; STATUS_RECORD_SIZE];
    rec[0] = kind;
    rec[2..4].copy_from_slice(&module_idx.to_le_bytes());
    rec[4..6].copy_from_slice(&extra.to_le_bytes());
    rec[8..12].copy_from_slice(&s.tick_count.to_le_bytes());
    let _ = (sys.channel_write)(s.status_chan, rec.as_ptr(), STATUS_RECORD_SIZE);
}

unsafe fn sys_module_count(sys: &SyscallTable) -> i32 {
    (sys.provider_call)(-1, SYS_RECONFIG_MODULE_COUNT, core::ptr::null_mut(), 0)
}

unsafe fn sys_module_info(sys: &SyscallTable, idx: u16) -> u32 {
    let mut arg = idx.to_le_bytes();
    let rc = (sys.provider_call)(-1, SYS_RECONFIG_MODULE_INFO, arg.as_mut_ptr(), 2);
    if rc < 0 {
        0
    } else {
        rc as u32
    }
}

/// Upstream-mask words per the `MODULE_UPSTREAM` wire contract: one bit per
/// module slot of the kernel's profile.
const UPSTREAM_WORDS: usize = MAX_TRACKED_MODULES.div_ceil(64);

unsafe fn sys_module_upstream(sys: &SyscallTable, idx: u16) -> [u64; UPSTREAM_WORDS] {
    // Arg layout: arg[0..2] = module idx in (u16 LE), arg[2..] = mask words
    // u64 LE out (low word first); the kernel writes as many words as fit
    // and returns its full word count.
    let mut arg = [0u8; 2 + 8 * UPSTREAM_WORDS];
    arg[0..2].copy_from_slice(&idx.to_le_bytes());
    let rc = (sys.provider_call)(
        -1,
        SYS_RECONFIG_MODULE_UPSTREAM,
        arg.as_mut_ptr(),
        arg.len(),
    );
    let mut mask = [0u64; UPSTREAM_WORDS];
    if rc > 0 {
        for (w, word) in mask.iter_mut().enumerate().take(rc as usize) {
            let off = 2 + w * 8;
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&arg[off..off + 8]);
            *word = u64::from_le_bytes(bytes);
        }
    }
    mask
}

/// Bit `j` of a flattened upstream mask.
fn upstream_bit(mask: &[u64; UPSTREAM_WORDS], j: usize) -> bool {
    j < UPSTREAM_WORDS * 64 && (mask[j / 64] >> (j % 64)) & 1 != 0
}

unsafe fn sys_module_done(sys: &SyscallTable, idx: u16) -> bool {
    let mut arg = idx.to_le_bytes();
    (sys.provider_call)(-1, SYS_RECONFIG_MODULE_DONE, arg.as_mut_ptr(), 2) == 1
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
    (sys.provider_call)(-1, SYS_RECONFIG_TRIGGER_REBUILD, buf.as_mut_ptr(), psz * 2);
}

// ============================================================================
// Drain-state accessors (pointer arithmetic — PIC modules avoid array indexing)
// ============================================================================

unsafe fn ds_get(s: &State, i: usize) -> u8 {
    if i >= MAX_TRACKED_MODULES {
        return DS_SURVIVING;
    }
    core::ptr::read(s.drain_state.as_ptr().add(i))
}

unsafe fn ds_set(s: &mut State, i: usize, v: u8) {
    if i >= MAX_TRACKED_MODULES {
        return;
    }
    core::ptr::write_volatile(s.drain_state.as_mut_ptr().add(i), v);
}

// ============================================================================
// State-machine transitions
// ============================================================================

unsafe fn begin_draining(s: &mut State, sys: &SyscallTable) {
    let count = sys_module_count(sys);
    if count <= 0 {
        return;
    }
    let count = count as usize;
    let count = if count > MAX_TRACKED_MODULES {
        MAX_TRACKED_MODULES
    } else {
        count
    };

    sys_set_phase(sys, PHASE_DRAINING);
    s.phase = PHASE_DRAINING;
    s.drain_start_tick = s.tick_count;

    // Classify every module. The reconfigure module itself is marked
    // Surviving so the scheduler keeps stepping it; drain-capable modules
    // enter Draining; the rest are terminated immediately.
    let mut draining = 0u16;
    let mut i = 0;
    while i < count {
        let idx = i as u16;
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
    // mask: drain completion follows forward topological order.
    let mut i = 0;
    while i < count {
        let idx = i as u16;
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
    if count <= 0 {
        return true;
    }
    let count = count as usize;
    let count = if count > MAX_TRACKED_MODULES {
        MAX_TRACKED_MODULES
    } else {
        count
    };

    let elapsed = s.tick_count.wrapping_sub(s.drain_start_tick);
    let timed_out = elapsed >= s.drain_timeout_ms;

    // Promote Draining → Drained when the module has returned Done and all
    // its upstream-draining peers are already Drained.
    let mut i = 0;
    while i < count {
        if ds_get(s, i) == DS_DRAINING {
            let idx = i as u16;
            if sys_module_done(sys, idx) {
                let upstream = sys_module_upstream(sys, idx);
                let mut upstream_ok = true;
                let mut j = 0;
                while j < count {
                    if j != i && upstream_bit(&upstream, j) && ds_get(s, j) == DS_DRAINING {
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
    let elapsed_u16 = if elapsed > u16::MAX as u32 {
        u16::MAX
    } else {
        elapsed as u16
    };
    emit_status(s, sys, STATUS_MIGRATING_ENTERED, 0, elapsed_u16);
    // If graph_slot is wired, ask it to activate the staged slot. An
    // activated slot is what the kernel's boot-time layout scan selects at
    // the next reset; the rebuild below re-instantiates the running
    // STATIC_CONFIG on RP, from the slot that was running, which
    // graph_slot never writes. Fire-and-forget: if nothing is wired, or
    // the staged slot fails SHA-256, there is nothing activated and the
    // next boot keeps the running slot (ACTIVATE is idempotent).
    if s.gs_req_chan >= 0 {
        let mut frame = [0u8; GS_FRAME_HDR];
        frame[0] = (REQ_ACTIVATE & 0xFF) as u8;
        frame[1] = ((REQ_ACTIVATE >> 8) & 0xFF) as u8;
        frame[2] = ((REQ_ACTIVATE >> 16) & 0xFF) as u8;
        frame[3] = (REQ_ACTIVATE >> 24) as u8;
        // len = 0 (bare request)
        frame[4] = 0;
        frame[5] = 0;
        let _ = (sys.channel_write)(s.gs_req_chan, frame.as_ptr(), GS_FRAME_HDR);
    }
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

// Same figure as data, so `pack` records it in the manifest and a graph's
// state-arena demand is summable host-side.
declare_module_state_bytes!(State);

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
        s.gs_req_chan = -1; // resolved in module_step once syscalls are live
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
                if off + len > params_len {
                    break;
                }
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
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() {
            return -1;
        }
        let sys = &*s.syscalls;

        s.tick_count = s.tick_count.wrapping_add(1);

        if s.signaled_ready == 0 {
            s.signaled_ready = 1;
            let rc = sys_self_index(sys);
            if rc >= 0 && rc < MAX_TRACKED_MODULES as i32 {
                s.self_idx = rc as u16;
            }
            // Resolve graph_slot request channel (out port 1). -1 if unwired.
            let mut port_arg = [1u8, 1u8]; // port_type=1(out), index=1
            s.gs_req_chan = (sys.provider_call)(
                -1,
                abi::kernel_abi::channel::PORT,
                port_arg.as_mut_ptr(),
                port_arg.len(),
            );
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
pub extern "C" fn module_deferred_ready() -> i32 {
    1
}

// ============================================================================
// Panic handler
// ============================================================================

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");
