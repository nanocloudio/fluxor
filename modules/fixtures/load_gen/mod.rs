//! Synthetic load generator — adaptive-tick validation workload.
//!
//! A self-driven module (no I/O channels) that alternates between a "busy"
//! and an "idle" phase on a wall-clock duty cycle. During the busy phase it
//! returns `StepOutcome::Burst` a bounded number of times per tick — which is
//! exactly the signal the adaptive-tick pacer reads as "this domain has work"
//! (RFC adaptive_tick §5.6). During the idle phase it returns `Continue` with
//! no burst, so the pacer sees the domain as idle.
//!
//! This lets a rig fixture exercise mechanism (b)'s AIMD cadence on bcm2712
//! with a controllable, deterministic load — the real network poll-stack never
//! bursts, so it always looks idle to the pacer. Per-step work is deliberately
//! tiny so the §5.3 floor (worst_step × margin) stays near `tick_min`, giving
//! (b) the full range between `tick_min` and `tick_max` to move in.
//!
//! **Params (TLV):**
//!   1: busy_ms        (u32, default 15000) — busy-phase duration
//!   2: idle_ms        (u32, default 15000) — idle-phase duration
//!   3: bursts_per_tick(u32, default 4)     — Burst re-steps emitted per busy tick

#![no_std]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset. unreachable_patterns: defensive `_ => Error` arms in enum state-machine matches are intentional"
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
struct LoadGenState {
    syscalls: *const SyscallTable,
    signaled_ready: bool,
    _pad: [u8; 3],
    /// Burst re-steps still owed in the current busy tick.
    burst_remaining: u32,
    /// Busy-phase / idle-phase durations (ms) and bursts per busy tick.
    busy_ms: u32,
    idle_ms: u32,
    bursts_per_tick: u32,
    /// LCG iterations per busy step — controls per-step cost (and thus the §5.3
    /// floor / `domain_worst_step_us`). Small ⇒ floor ≈ tick_min (wide (b)
    /// range); large ⇒ a heavy step that spikes worst_us for the AC7 heat→cool
    /// floor-decay test.
    heavy_iters: u32,
    /// Lane id (distinguishes instances in telemetry, for the AC9 fairness test).
    lane_id: u32,
    /// Total step() calls — logged periodically so a rig can confirm every lane
    /// in a domain keeps advancing at the floor (no starvation, AC9).
    step_count: u64,
    /// Wall-clock of the last step-count log emit.
    last_log_ms: u64,
    /// Tiny work accumulator so each step does a little real (but bounded) work.
    work_acc: u64,
}

impl LoadGenState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.signaled_ready = false;
        self.burst_remaining = 0;
        self.busy_ms = 15_000;
        self.idle_ms = 15_000;
        self.bursts_per_tick = 4;
        self.heavy_iters = 8;
        self.lane_id = 0;
        self.step_count = 0;
        self.last_log_ms = 0;
        self.work_acc = 0;
    }

    unsafe fn sys(&self) -> &SyscallTable {
        // SAFETY: syscalls is set in module_new before any step runs.
        unsafe { &*self.syscalls }
    }
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::p_u32;
    use super::LoadGenState;
    use super::SCHEMA_MAX;

    define_params! {
        LoadGenState;

        1, busy_ms, u32, 15000
            => |s, d, len| { s.busy_ms = p_u32(d, len, 0, 15000); };

        2, idle_ms, u32, 15000
            => |s, d, len| { s.idle_ms = p_u32(d, len, 0, 15000); };

        3, bursts_per_tick, u32, 4
            => |s, d, len| { s.bursts_per_tick = p_u32(d, len, 0, 4); };

        4, heavy_iters, u32, 8
            => |s, d, len| { s.heavy_iters = p_u32(d, len, 0, 8); };

        5, lane_id, u32, 0
            => |s, d, len| { s.lane_id = p_u32(d, len, 0, 0); };
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Emit `[lg lN s########]` (lane id + low-32 step count, hex) every ~3 s so a
/// rig can confirm each lane advances under load (AC9 fairness).
#[inline]
unsafe fn maybe_log_progress(s: &mut LoadGenState) {
    // SAFETY: syscalls set in module_new; dev_millis/dev_log are side-effecting
    // but benign diagnostics.
    let now = unsafe { dev_millis(s.sys()) };
    if now.wrapping_sub(s.last_log_ms) < 3000 {
        return;
    }
    s.last_log_ms = now;
    let mut msg = *b"[lg lX s00000000]\0";
    msg[5] = b'0' + (s.lane_id % 10) as u8;
    let sc = s.step_count as u32;
    let mut i = 0;
    while i < 8 {
        msg[8 + i] = HEX[((sc >> (28 - i * 4)) & 0xf) as usize];
        i += 1;
    }
    unsafe { dev_log(s.sys(), 3, msg.as_ptr(), 17) };
}

// ============================================================================
// Tiny bounded work — keeps worst_step (and thus the §5.3 floor) small.
// ============================================================================

#[inline(always)]
fn tiny_work(s: &mut LoadGenState) {
    // `heavy_iters` LCG iterations: real, bounded work. Small ⇒ ~tens of ns
    // (floor near tick_min); large ⇒ a heavy step that raises worst_us.
    let mut acc = s.work_acc;
    let mut i = 0u32;
    while i < s.heavy_iters {
        acc = acc.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        i += 1;
    }
    s.work_acc = acc;
}

// ============================================================================
// Exported functions
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<LoadGenState>() as u32
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
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() || state_size < core::mem::size_of::<LoadGenState>() {
            return -3;
        }
        let s = &mut *(state as *mut LoadGenState);
        s.init(syscalls as *const SyscallTable);

        let is_tlv = !params.is_null()
            && params_len >= 4
            && *params == 0xFE
            && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        0
    }
}

/// Step. Busy phase ⇒ emit up to `bursts_per_tick` Burst re-steps (the pacer's
/// "busy" signal). Idle phase ⇒ Continue with no burst. Phase is chosen from a
/// wall-clock duty cycle so the load is deterministic and self-driven.
#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut LoadGenState);
        if s.syscalls.is_null() {
            return -1;
        }

        // One-shot readiness so downstream gating (if any) releases.
        if !s.signaled_ready {
            s.signaled_ready = true;
            return 3; // StepOutcome::Ready
        }

        // Count every step and periodically log this lane's progress (AC9).
        s.step_count = s.step_count.wrapping_add(1);
        maybe_log_progress(s);

        // Re-step within an in-progress busy tick: these carry the Burst
        // (busy) signal only — NO heavy work. Doing the heavy step just once
        // per tick keeps per-tick cost ≈ one worst_step, so the §5.3 floor
        // (worst × margin) covers it and the budget is not overrun (AC3).
        if s.burst_remaining > 0 {
            s.burst_remaining -= 1;
            return if s.burst_remaining > 0 { 2 } else { 0 };
        }

        // Fresh tick: pick the phase from the wall-clock duty cycle. Use u32
        // math for the modulo — rp2350 (Cortex-M33) has no 64-bit HW divide,
        // so `u64 % u64` would emit `__aeabi_uldivmod`, which the PIC module
        // build does not link. `dev_millis` is ms-since-boot; any real rig
        // window is far below the u32-ms wrap (~49.7 days), so truncating to
        // u32 is exact for the test. u32 `%` lowers to the Cortex-M UDIV insn.
        let now_ms = dev_millis(s.sys()) as u32;
        let cycle = s.busy_ms.saturating_add(s.idle_ms).max(1);
        let busy = (now_ms % cycle) < s.busy_ms;
        if !busy || s.bursts_per_tick == 0 {
            return 0; // idle tick → Continue, no burst signal
        }

        // Busy tick: do the heavy work ONCE, then emit `bursts_per_tick` Burst
        // re-steps (the trivial re-steps above) so the pacer sees "busy".
        tiny_work(s);
        s.burst_remaining = s.bursts_per_tick;
        2 // first Burst — signals busy
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/wasm_entry.rs");
