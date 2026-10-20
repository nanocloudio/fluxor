//! Live Graph Reconfigure — PIC Module
//!
//! Drives the reconfigure state machine
//! (RUNNING → DRAINING → MIGRATING → RUNNING) using kernel primitives
//! exposed via the `dev_system` reconfigure opcodes (0x0C67-0x0C6F, and
//! `SLOT_CAPACITY` at 0x0C23).
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
    SLOT_CAPACITY as SYS_RECONFIG_SLOT_CAPACITY, TRIGGER_REBUILD as SYS_RECONFIG_TRIGGER_REBUILD,
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

// Drain round width: the module slots one round classifies and drains, one
// state byte each. The kernel's module-slot count is kernel capacity, not ABI,
// so it is not compiled in: the module asks for it (`SLOT_CAPACITY`) and
// drains every slot below it. Slots, not the module count, because a graph's
// modules need not be contiguous — a live add places a workload's modules in
// whichever slots are free — and a module at a slot past the count would be
// torn down by the rebuild without being drained. An empty slot is classified
// like a module with no drain export and costs one query. A slot domain wider
// than one round is drained over successive rounds in index order. Within a
// round, drain completion follows the upstream masks; a module waits only on
// upstream peers of its own round, because earlier rounds have finished and
// later ones have not yet been asked to drain. Each round has the full
// `drain_timeout_ms`. The widths match the slot counts of the kernels each
// class runs on, so one round is the usual case.
const DRAIN_WINDOW: usize = if abi::config::TARGET_CLASS == abi::config::target_class::HOST {
    1024
} else {
    32
};

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
    /// The kernel's module-slot count (`SLOT_CAPACITY`), read on the first
    /// step; 0 until then.
    slot_capacity: u32,
    /// Module slots the drain covers: the kernel's slot count, or the
    /// graph's module count (`MODULE_COUNT`) on a kernel that does not answer
    /// `SLOT_CAPACITY`.
    drain_count: u32,
    /// First module index of the current drain round.
    round_base: u32,
    /// One past the last module index of the current drain round.
    round_end: u32,
    /// Drain state of modules `round_base..round_end`, indexed from the
    /// round's base.
    drain_state: [u8; DRAIN_WINDOW],
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

unsafe fn sys_slot_capacity(sys: &SyscallTable) -> i32 {
    (sys.provider_call)(-1, SYS_RECONFIG_SLOT_CAPACITY, core::ptr::null_mut(), 0)
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

/// Upstream-mask words one read covers: every module of a drain round, which
/// need not start on a word boundary.
const UPSTREAM_WORDS: usize = DRAIN_WINDOW.div_ceil(64) + 1;

/// Read the window of module `idx`'s upstream mask that starts at mask word
/// `first_word`, `UPSTREAM_WORDS` wide. Words past the kernel's mask read as 0.
unsafe fn sys_module_upstream(
    sys: &SyscallTable,
    idx: u16,
    first_word: u16,
    mask: &mut [u64; UPSTREAM_WORDS],
) {
    // Arg layout: in `[module_idx:u16 LE][first_word:u16 LE]`, out mask words
    // u64 LE from offset 4; the kernel writes as many words as fit and returns
    // its full word count.
    let mut arg = [0u8; 4 + 8 * UPSTREAM_WORDS];
    let i = idx.to_le_bytes();
    let f = first_word.to_le_bytes();
    let p = arg.as_mut_ptr();
    core::ptr::write(p, i[0]);
    core::ptr::write(p.add(1), i[1]);
    core::ptr::write(p.add(2), f[0]);
    core::ptr::write(p.add(3), f[1]);
    let rc = (sys.provider_call)(-1, SYS_RECONFIG_MODULE_UPSTREAM, p, arg.len());
    let avail = if rc > first_word as i32 {
        (rc - first_word as i32) as usize
    } else {
        0
    };
    for (w, word) in mask.iter_mut().enumerate() {
        *word = if w < avail {
            u64::from_le_bytes(core::ptr::read_unaligned(p.add(4 + w * 8) as *const [u8; 8]))
        } else {
            0
        };
    }
}

/// Whether any module of the current round other than `i` is set in the
/// upstream mask window `mask` (which starts at mask word `first_word`) and
/// is still Draining. Walks the window's set bits, so the cost is the
/// module's upstream peers, not the round's width.
unsafe fn upstream_draining(
    s: &State,
    mask: &[u64; UPSTREAM_WORDS],
    first_word: usize,
    i: usize,
) -> bool {
    let mut w = 0;
    while w < UPSTREAM_WORDS {
        let mut bits = core::ptr::read(mask.as_ptr().add(w));
        while bits != 0 {
            let j = (first_word + w) * 64 + bits.trailing_zeros() as usize;
            bits &= bits - 1;
            if j != i && ds_get(s, j) == DS_DRAINING {
                return true;
            }
        }
        w += 1;
    }
    false
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

/// Drain state of module `i`, which must lie in the current round; any other
/// module reads as Surviving (an earlier round has finished it, a later one has
/// not begun).
unsafe fn ds_get(s: &State, i: usize) -> u8 {
    let base = s.round_base as usize;
    if i < base || i >= s.round_end as usize || i - base >= DRAIN_WINDOW {
        return DS_SURVIVING;
    }
    core::ptr::read(s.drain_state.as_ptr().add(i - base))
}

unsafe fn ds_set(s: &mut State, i: usize, v: u8) {
    let base = s.round_base as usize;
    if i < base || i >= s.round_end as usize || i - base >= DRAIN_WINDOW {
        return;
    }
    core::ptr::write_volatile(s.drain_state.as_mut_ptr().add(i - base), v);
}

// ============================================================================
// State-machine transitions
// ============================================================================

unsafe fn begin_draining(s: &mut State, sys: &SyscallTable) {
    let count = sys_module_count(sys);
    if count <= 0 {
        return;
    }

    sys_set_phase(sys, PHASE_DRAINING);
    s.phase = PHASE_DRAINING;
    s.drain_count = if s.slot_capacity > 0 {
        s.slot_capacity
    } else {
        count as u32
    };
    s.round_base = 0;
    begin_round(s, sys);
}

/// Classify and signal the modules of the round that starts at `round_base`.
unsafe fn begin_round(s: &mut State, sys: &SyscallTable) {
    let base = s.round_base as usize;
    let count = s.drain_count as usize;
    let end = if count - base > DRAIN_WINDOW {
        base + DRAIN_WINDOW
    } else {
        count
    };
    s.round_end = end as u32;
    s.drain_start_tick = s.tick_count;
    let mut k = 0;
    while k < DRAIN_WINDOW {
        core::ptr::write_volatile(s.drain_state.as_mut_ptr().add(k), DS_SURVIVING);
        k += 1;
    }

    // Classify every module of the round. The reconfigure module itself is
    // marked Surviving so the scheduler keeps stepping it; drain-capable
    // modules enter Draining; the rest are terminated immediately.
    let mut draining = 0u16;
    let mut i = base;
    while i < end {
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
    let mut i = base;
    while i < end {
        let idx = i as u16;
        if ds_get(s, i) == DS_DRAINING {
            let _ = sys_call_drain(sys, idx);
        }
        i += 1;
    }

    // `module_idx` carries the round's first module, so a multi-round drain
    // reports one DRAINING_ENTERED per round.
    emit_status(s, sys, STATUS_DRAINING_ENTERED, base as u16, draining);
}

/// Returns true once every non-surviving module of every round is Drained or
/// PendingTerminate. A finished round that is not the last starts the next.
unsafe fn check_drain(s: &mut State, sys: &SyscallTable) -> bool {
    let base = s.round_base as usize;
    let end = s.round_end as usize;
    if end <= base {
        return true;
    }
    let first_word = base / 64;

    let elapsed = s.tick_count.wrapping_sub(s.drain_start_tick);
    let timed_out = elapsed >= s.drain_timeout_ms;

    // Promote Draining → Drained when the module has returned Done and all
    // its upstream-draining peers are already Drained.
    let mut upstream = [0u64; UPSTREAM_WORDS];
    let mut i = base;
    while i < end {
        if ds_get(s, i) == DS_DRAINING {
            let idx = i as u16;
            if sys_module_done(sys, idx) {
                sys_module_upstream(sys, idx, first_word as u16, &mut upstream);
                if !upstream_draining(s, &upstream, first_word, i) {
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

    let mut i = base;
    while i < end {
        if ds_get(s, i) == DS_DRAINING {
            return false;
        }
        i += 1;
    }
    if end < s.drain_count as usize {
        s.round_base = end as u32;
        begin_round(s, sys);
        return false;
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

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[no_mangle]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
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
        s.slot_capacity = 0;
        s.drain_count = 0;
        s.round_base = 0;
        s.round_end = 0;

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
            let cap = sys_slot_capacity(sys);
            s.slot_capacity = if cap > 0 { cap as u32 } else { 0 };
            // The module's own slot must be known before any drain, or the
            // drain would classify and finish the module running it. The
            // slot count bounds it when the kernel states one.
            let rc = sys_self_index(sys);
            if rc >= 0
                && rc < SELF_IDX_UNKNOWN as i32
                && (s.slot_capacity == 0 || (rc as u32) < s.slot_capacity)
            {
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
