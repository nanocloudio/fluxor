//! monitor — emit `MON_HIST` telemetry lines for the `fluxor rig monitor` CLI.
//!
//! Polls the step-timing histogram for every active module on a slow
//! cadence and emits one `MON_HIST` line per module via `log::info!`.
//! The kernel emits `MON_FAULT` directly (see `step_guard::push_fault`),
//! so enabling this module is enough to feed the host-side dashboard
//! over whichever log transports are active.
//!
//! `MON_STATE` reports each module's scheduler-visible state through
//! `MODULE_STATE_QUERY`: whether the slot is present, whether the module
//! has signalled ready, whether it has finished, its fault state, its
//! step period, and how many consecutive ticks the readiness gate has
//! been blocking it. Together those settle why a module is not being
//! stepped, which absence from `MON_HIST` only ever hinted at.
//!
//! Parameters:
//!   `interval_ms` — how often to emit a round of histograms (default
//!                   5000 ms). A full round is all active modules back to
//!                   back.

#![no_std]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset. unreachable_patterns: defensive `_ => Error` arms in enum state-machine matches are intentional — adding a new variant should not silently bypass the error path"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

// Opcodes imported from the layered ABI — no hardcoded 0x0Cxx here.
use abi::internal::monitor::{
    module_state_flags, MODULE_STATE_LEN, MODULE_STATE_MAX, MODULE_STATE_QUERY,
    STEP_HISTOGRAM_QUERY,
};
use abi::internal::reconfigure::MODULE_COUNT as RECONFIGURE_MODULE_COUNT;
use abi::kernel_abi::LOG_WRITE as SYSTEM_LOG;

/// Small stack buffer for building one MON_HIST line. 8 buckets × up to
/// 10 decimal digits each + key names + mod idx + spaces = ~140 chars max.
const LINE_BUF: usize = 180;

#[repr(C)]
struct MonitorState {
    syscalls: *const SyscallTable,
    /// User-configurable period between rounds, in milliseconds.
    interval_ms: u32,
    /// Remaining ticks before next emission round. Counted down by step().
    countdown_ticks: u32,
    /// Ticks per round, derived from interval_ms in module_new.
    round_ticks: u32,
}

impl MonitorState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.interval_ms = 5000;
        self.countdown_ticks = 0;
        self.round_ticks = 0;
    }
}

mod params_def {
    use super::p_u32;
    use super::MonitorState;
    use super::SCHEMA_MAX;

    define_params! {
        MonitorState;

        1, interval_ms, u32, 5000
            => |s, d, len| { s.interval_ms = p_u32(d, len, 0, 5000); };
    }
}

// ============================================================================
// Division-free u32 → decimal, for MON_HIST bucket values.
// ============================================================================
//
// The fluxor-monitor CLI parses values with `str::parse::<u32>`, so decimal
// is mandatory. PIC modules on RP2350 can't link `panic_const_div_by_zero`,
// so the "obvious" n/10 loop is a linker trap. Subtracting pre-computed
// powers of 10 avoids any `/` or `%` operators.

const POW10: [u32; 10] = [
    1_000_000_000,
    100_000_000,
    10_000_000,
    1_000_000,
    100_000,
    10_000,
    1_000,
    100,
    10,
    1,
];

fn emit_decimal(val: u32, out: &mut [u8], pos: &mut usize) {
    let mut n = val;
    let mut started = false;
    let mut i = 0;
    while i < POW10.len() {
        let pow = POW10[i];
        let mut digit = 0u32;
        while n >= pow {
            n -= pow;
            digit += 1;
        }
        if digit != 0 || started || i == POW10.len() - 1 {
            if *pos < out.len() {
                out[*pos] = b'0' + digit as u8;
                *pos += 1;
            }
            started = true;
        }
        i += 1;
    }
}

fn emit_bytes(s: &[u8], out: &mut [u8], pos: &mut usize) {
    let mut i = 0;
    while i < s.len() && *pos < out.len() {
        out[*pos] = s[i];
        *pos += 1;
        i += 1;
    }
}

// ============================================================================
// Histogram emission
// ============================================================================

/// Build one MON_HIST line for module `mod_idx` into `out`. Returns bytes
/// written, or 0 if the query failed (caller should skip this module).
unsafe fn build_mon_hist(sys: &SyscallTable, mod_idx: u8, out: &mut [u8]) -> usize {
    let mut buckets = [0u32; 8];
    let bp = buckets.as_mut_ptr() as *mut u8;
    let rc = (sys.provider_call)(mod_idx as i32, STEP_HISTOGRAM_QUERY, bp, 32);
    if rc < 0 {
        return 0;
    }

    let mut pos = 0usize;
    emit_bytes(b"MON_HIST mod=", out, &mut pos);
    emit_decimal(mod_idx as u32, out, &mut pos);
    let mut bi = 0usize;
    while bi < 8 {
        emit_bytes(b" b", out, &mut pos);
        // Single-digit bucket index: always 0..7.
        if pos < out.len() {
            out[pos] = b'0' + bi as u8;
            pos += 1;
        }
        emit_bytes(b"=", out, &mut pos);
        emit_decimal(buckets[bi], out, &mut pos);
        bi += 1;
    }
    pos
}

/// Build one MON_STATE line for module `mod_idx` into `out`. Returns
/// bytes written, or 0 if the query failed (caller should skip).
unsafe fn build_mon_state(sys: &SyscallTable, mod_idx: u8, out: &mut [u8]) -> usize {
    let mut st = [0u8; MODULE_STATE_MAX];
    let rc = (sys.provider_call)(
        mod_idx as i32,
        MODULE_STATE_QUERY,
        st.as_mut_ptr(),
        MODULE_STATE_MAX,
    );
    // The query answers with the width it wrote; anything short of the
    // fixed header is not a record.
    if rc < MODULE_STATE_LEN as i32 {
        return 0;
    }
    let flags = st[1];
    // An empty slot has no state worth a line; reporting one would make
    // every unused slot look like a stalled module.
    if flags & module_state_flags::PRESENT == 0 {
        return 0;
    }

    let u16_at = |a: usize| -> u32 { (st[a] as u32) | ((st[a + 1] as u32) << 8) };
    let u32_at = |a: usize| -> u32 {
        (st[a] as u32)
            | ((st[a + 1] as u32) << 8)
            | ((st[a + 2] as u32) << 16)
            | ((st[a + 3] as u32) << 24)
    };
    let bit = |m: u8| -> u32 { u32::from(flags & m != 0) };

    let mut pos = 0usize;
    emit_bytes(b"MON_STATE mod=", out, &mut pos);
    emit_decimal(mod_idx as u32, out, &mut pos);
    // `name` and `state` are the keys the host dashboard reads; the rest
    // are the diagnostic fields, which it ignores as unknown keys.
    let name_len = st[18] as usize;
    if name_len > 0 && MODULE_STATE_LEN + name_len <= rc as usize {
        emit_bytes(b" name=", out, &mut pos);
        emit_bytes(
            &st[MODULE_STATE_LEN..MODULE_STATE_LEN + name_len],
            out,
            &mut pos,
        );
    }
    emit_bytes(b" state=", out, &mut pos);
    emit_bytes(
        match st[2] {
            0 => b"running".as_slice(),
            1 => b"faulted".as_slice(),
            2 => b"recovering".as_slice(),
            _ => b"terminated".as_slice(),
        },
        out,
        &mut pos,
    );
    emit_bytes(b" ready=", out, &mut pos);
    emit_decimal(bit(module_state_flags::READY), out, &mut pos);
    emit_bytes(b" finished=", out, &mut pos);
    emit_decimal(bit(module_state_flags::FINISHED), out, &mut pos);
    emit_bytes(b" restarts=", out, &mut pos);
    emit_decimal(u16_at(8), out, &mut pos);
    emit_bytes(b" domain=", out, &mut pos);
    emit_decimal(st[7] as u32, out, &mut pos);
    emit_bytes(b" period=", out, &mut pos);
    emit_decimal(st[6] as u32, out, &mut pos);
    // The field that answers "why is it not stepping": non-zero means
    // the readiness gate has been refusing it for that many ticks.
    emit_bytes(b" inactive=", out, &mut pos);
    emit_decimal(u32_at(10), out, &mut pos);
    emit_bytes(b" gen=", out, &mut pos);
    emit_decimal(u32_at(14), out, &mut pos);
    pos
}

// ============================================================================
// Module interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<MonitorState>() as u32
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
        if state.is_null() {
            return -5;
        }
        if state_size < core::mem::size_of::<MonitorState>() {
            return -6;
        }

        let s = &mut *(state as *mut MonitorState);
        s.init(syscalls as *const SyscallTable);

        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // The scheduler's tick period isn't exposed to PIC modules, so
        // assume the documented dev default of tick_us=100 when
        // converting interval_ms to ticks. If your config sets a
        // different tick_us, interval_ms becomes nominal.
        const ASSUMED_TICK_US: u32 = 100;
        let ticks = s.interval_ms.saturating_mul(1000) / ASSUMED_TICK_US;
        // Floor at 1000 ticks (100 ms) so a tiny interval_ms doesn't
        // hammer the system.
        s.round_ticks = if ticks < 1000 { 1000 } else { ticks };
        s.countdown_ticks = s.round_ticks;

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
        let s = &mut *(state as *mut MonitorState);
        if s.syscalls.is_null() {
            return -1;
        }

        if s.countdown_ticks > 0 {
            s.countdown_ticks -= 1;
            return 0;
        }
        s.countdown_ticks = s.round_ticks;

        let sys_ptr = s.syscalls;
        let count =
            (((*sys_ptr).provider_call)(-1, RECONFIGURE_MODULE_COUNT, core::ptr::null_mut(), 0))
                as i32;
        if count <= 0 {
            return 0;
        }

        let mut line = [0u8; LINE_BUF];
        let mut idx: i32 = 0;
        while idx < count && idx < 64 {
            let n = build_mon_hist(&*sys_ptr, idx as u8, &mut line);
            if n > 0 {
                // Level 3 = info. LOG_WRITE routes through `syscall_log`
                // which calls `log::info!` — bytes land in the ring and
                // flow out the active transport overlay.
                ((*sys_ptr).provider_call)(3, SYSTEM_LOG, line.as_mut_ptr(), n);
            }
            let n = build_mon_state(&*sys_ptr, idx as u8, &mut line);
            if n > 0 {
                ((*sys_ptr).provider_call)(3, SYSTEM_LOG, line.as_mut_ptr(), n);
            }
            idx += 1;
        }

        0
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");
