//! observe — the observability collector.
//!
//! Subsumes the `monitor` module and adds the module-scope signal path:
//!
//!   1. **Module-scope** — drains `TelemetryRecord`s from its `telemetry`
//!      input port (`Telemetry` content type) each step and renders each as a
//!      `MON_METRIC` / `MON_SPAN` text line (the console exporter — the same
//!      transport-agnostic `log_ring` path the rest of the `MON_*` protocol
//!      uses).
//!   2. **Kernel-scope** — on a slow cadence, pulls the per-module step-time
//!      histogram (`STEP_HISTOGRAM_QUERY`) and emits one `MON_HIST` line per
//!      active module. `MON_FAULT` is emitted by the kernel directly.
//!
//! This is the console exporter inline. Pluggable exporter modules
//! (`otel_udp_sample`, `otlp_http`) and id→name resolution live downstream at
//! the host collector; the device emits id-interned records and MON_ text.
//!
//! Parameters:
//!   `interval_ms` — how often to emit a round of kernel-scope histograms
//!                   (default 5000 ms). The module-scope drain runs every step.

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
include!("../../sdk/params.rs");

use abi::contracts::telemetry as tlm;
use abi::internal::monitor::STEP_HISTOGRAM_QUERY;
use abi::internal::reconfigure::MODULE_COUNT as RECONFIGURE_MODULE_COUNT;
use abi::kernel_abi::LOG_WRITE as SYSTEM_LOG;

/// Build buffer for one MON_ line. MON_HIST with eight 10-digit buckets is the
/// widest at ~140 chars; round up.
const LINE_BUF: usize = 192;

/// Largest single telemetry record (histogram = 80 B). One record is drained,
/// rendered, and discarded per iteration, so this need only hold one.
const REC_BUF: usize = 96;

/// Bound on records drained per step so a flooded port can't starve the tick.
const MAX_DRAIN_PER_STEP: u32 = 32;

#[repr(C)]
struct ObserveState {
    syscalls: *const SyscallTable,
    /// Input channel carrying `TelemetryRecord`s (the `telemetry` port).
    telemetry_in_chan: i32,
    /// User-configurable period between kernel-scope rounds, in milliseconds.
    interval_ms: u32,
    /// Remaining ticks before the next kernel-scope round.
    countdown_ticks: u32,
    /// Ticks per round, derived from interval_ms in module_new.
    round_ticks: u32,
}

impl ObserveState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.telemetry_in_chan = -1;
        self.interval_ms = 5000;
        self.countdown_ticks = 0;
        self.round_ticks = 0;
    }
}

mod params_def {
    use super::ObserveState;
    use super::p_u32;
    use super::SCHEMA_MAX;

    define_params! {
        ObserveState;

        1, interval_ms, u32, 5000
            => |s, d, len| { s.interval_ms = p_u32(d, len, 0, 5000); };
    }
}

// ============================================================================
// Division-free decimal — PIC modules on RP2350 can't link the div-by-zero
// panic path, so emit by subtracting pre-computed powers of ten.
// ============================================================================

const POW10_64: [u64; 20] = [
    10_000_000_000_000_000_000,
    1_000_000_000_000_000_000,
    100_000_000_000_000_000,
    10_000_000_000_000_000,
    1_000_000_000_000_000,
    100_000_000_000_000,
    10_000_000_000_000,
    1_000_000_000_000,
    100_000_000_000,
    10_000_000_000,
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

fn emit_decimal(val: u64, out: &mut [u8], pos: &mut usize) {
    let mut n = val;
    let mut started = false;
    let mut i = 0;
    while i < POW10_64.len() {
        let pow = POW10_64[i];
        let mut digit = 0u64;
        while n >= pow {
            n -= pow;
            digit += 1;
        }
        if digit != 0 || started || i == POW10_64.len() - 1 {
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
// Console exporter — render one record / one histogram as a MON_ line.
// ============================================================================

/// Render a drained `TelemetryRecord` into `out`. Returns bytes written, or 0
/// to skip. Names are emitted as `(module, id)` pairs; the host collector
/// resolves them to OTel names from the generated id-table.
fn render_record(rec: &[u8], out: &mut [u8]) -> usize {
    let mut pos = 0usize;
    let module = tlm::module(rec) as u64;
    let knd = tlm::kind(rec) as u64;
    match tlm::signal(rec) {
        x if x == tlm::SIGNAL_METRIC => {
            emit_bytes(b"MON_METRIC mod=", out, &mut pos);
            emit_decimal(module, out, &mut pos);
            emit_bytes(b" id=", out, &mut pos);
            emit_decimal(tlm::metric_id(rec) as u64, out, &mut pos);
            emit_bytes(b" kind=", out, &mut pos);
            emit_decimal(knd, out, &mut pos);
            if knd == tlm::METRIC_HISTOGRAM as u64 {
                let mut bi = 0usize;
                while bi < tlm::HIST_BUCKETS {
                    emit_bytes(b" b", out, &mut pos);
                    if pos < out.len() {
                        out[pos] = b'0' + bi as u8;
                        pos += 1;
                    }
                    emit_bytes(b"=", out, &mut pos);
                    let off = 16 + bi * 8;
                    emit_decimal(read_u64(rec, off), out, &mut pos);
                    bi += 1;
                }
            } else {
                emit_bytes(b" val=", out, &mut pos);
                emit_decimal(tlm::metric_scalar_value(rec), out, &mut pos);
            }
            pos
        }
        x if x == tlm::SIGNAL_SPAN => {
            emit_bytes(b"MON_SPAN mod=", out, &mut pos);
            emit_decimal(module, out, &mut pos);
            emit_bytes(b" name=", out, &mut pos);
            emit_decimal(tlm::span_name_id(rec) as u64, out, &mut pos);
            emit_bytes(b" kind=", out, &mut pos);
            emit_decimal(knd, out, &mut pos);
            emit_bytes(b" status=", out, &mut pos);
            emit_decimal(tlm::span_status(rec) as u64, out, &mut pos);
            emit_bytes(b" dur_us=", out, &mut pos);
            let dur = tlm::span_end_micros(rec).saturating_sub(tlm::span_start_micros(rec));
            emit_decimal(dur, out, &mut pos);
            pos
        }
        _ => 0,
    }
}

fn read_u64(buf: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        buf[at],
        buf[at + 1],
        buf[at + 2],
        buf[at + 3],
        buf[at + 4],
        buf[at + 5],
        buf[at + 6],
        buf[at + 7],
    ])
}

/// Build one MON_HIST line for module `mod_idx`. Returns bytes written, or 0
/// if the query failed.
unsafe fn build_mon_hist(sys: &SyscallTable, mod_idx: u8, out: &mut [u8]) -> usize {
    let mut buckets = [0u32; 8];
    let bp = buckets.as_mut_ptr() as *mut u8;
    let rc = (sys.provider_call)(mod_idx as i32, STEP_HISTOGRAM_QUERY, bp, 32);
    if rc < 0 {
        return 0;
    }
    let mut pos = 0usize;
    emit_bytes(b"MON_HIST mod=", out, &mut pos);
    emit_decimal(mod_idx as u64, out, &mut pos);
    let mut bi = 0usize;
    while bi < 8 {
        emit_bytes(b" b", out, &mut pos);
        if pos < out.len() {
            out[pos] = b'0' + bi as u8;
            pos += 1;
        }
        emit_bytes(b"=", out, &mut pos);
        emit_decimal(buckets[bi] as u64, out, &mut pos);
        bi += 1;
    }
    pos
}

/// Drain the telemetry input port: read whole records (sized from the header)
/// and emit each as a MON_ line. Bounded so a flooded port can't starve the
/// tick.
unsafe fn drain_telemetry(s: &ObserveState) {
    if s.telemetry_in_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let chan = s.telemetry_in_chan;
    let mut rec = [0u8; REC_BUF];
    let mut line = [0u8; LINE_BUF];

    let mut drained = 0u32;
    while drained < MAX_DRAIN_PER_STEP {
        // Shared self-sizing read (header → record_len → body).
        let len = dev_read_telemetry_record(sys, chan, rec.as_mut_ptr(), REC_BUF);
        if len == 0 {
            break; // no full record, or unrecognised header.
        }
        let n = render_record(&rec[..len], &mut line);
        if n > 0 {
            (sys.provider_call)(3, SYSTEM_LOG, line.as_mut_ptr(), n);
        }
        drained += 1;
    }
}

// ============================================================================
// Module interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ObserveState>() as u32
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
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() {
            return -5;
        }
        if state_size < core::mem::size_of::<ObserveState>() {
            return -6;
        }

        let s = &mut *(state as *mut ObserveState);
        s.init(syscalls as *const SyscallTable);
        s.telemetry_in_chan = in_chan;

        let is_tlv = !params.is_null()
            && params_len >= 4
            && *params == 0xFE
            && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // The scheduler tick period isn't exposed to PIC modules; assume the
        // documented dev default of tick_us=100 when converting interval_ms to
        // ticks (same convention as `monitor`).
        const ASSUMED_TICK_US: u32 = 100;
        let ticks = s.interval_ms.saturating_mul(1000) / ASSUMED_TICK_US;
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
        let s = &mut *(state as *mut ObserveState);
        if s.syscalls.is_null() {
            return -1;
        }

        // Module-scope: drain the telemetry port every step (bounded).
        drain_telemetry(s);

        // Kernel-scope: emit a histogram round on the slow cadence.
        if s.countdown_ticks > 0 {
            s.countdown_ticks -= 1;
            return 0;
        }
        s.countdown_ticks = s.round_ticks;

        let sys_ptr = s.syscalls;
        let count = (((*sys_ptr).provider_call)(
            -1,
            RECONFIGURE_MODULE_COUNT,
            core::ptr::null_mut(),
            0,
        )) as i32;
        if count <= 0 {
            return 0;
        }

        let mut line = [0u8; LINE_BUF];
        let mut idx: i32 = 0;
        while idx < count && idx < 64 {
            let n = build_mon_hist(&*sys_ptr, idx as u8, &mut line);
            if n > 0 {
                ((*sys_ptr).provider_call)(3, SYSTEM_LOG, line.as_mut_ptr(), n);
            }
            idx += 1;
        }

        0
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/wasm_entry.rs");
