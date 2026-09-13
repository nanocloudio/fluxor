//! observe — the observability collector.
//!
//! A pure telemetry-ring consumer: it drains the kernel ring each step and
//! renders every `TelemetryRecord` as a `MON_` text line —
//!   - `MON_METRIC` / `MON_SPAN` from module-scope metric/span records,
//!   - `MON_HIST` / `MON_RES` from the kernel-pushed PSTATUS step-histogram and
//!     arena/fault records.
//! `MON_FAULT` is emitted by the kernel directly. All lines ride the same
//! transport-agnostic `log_ring` path as the rest of the `MON_*` protocol, so
//! whatever debug transport is configured carries them.
//!
//! This is the console exporter, inline. The pluggable export path (the `otel`
//! engine plus a transport carrier such as `transport_buffer`) and id→name
//! resolution live downstream at the host collector; the device emits
//! id-interned records and MON_ text.
//!
//! Parameters:
//!   `interval_ms` — the kernel PSTATUS cadence, declared via
//!                   `TLM_SUBSCRIBE`: how often the kernel pushes its
//!                   step-histogram / arena round (default 5000 ms). The
//!                   ring drain itself runs every step.

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

use abi::contracts::telemetry as tlm;
use abi::kernel_abi::LOG_WRITE as SYSTEM_LOG;

/// Build buffer for one MON_ line. MON_METRIC kind=4 (histogram16) with
/// sixteen 20-digit buckets plus mod/id/kind/dim prefix is the widest at
/// ~450 chars; round up.
const LINE_BUF: usize = 512;

/// Records drained per step, in bytes. `TLM_DRAIN` copies whole records into
/// this buffer, so it doubles as the bound that keeps a flooded ring from
/// starving the tick.
const BATCH_BUF: usize = 512;

#[repr(C)]
struct ObserveState {
    syscalls: *const SyscallTable,
    /// Telemetry-ring drain slot claimed via `TLM_SUBSCRIBE` (`-1` = none).
    tlm_slot: i32,
    /// Declared to the kernel PSTATUS cadence via TLM_SUBSCRIBE; the kernel
    /// produces the step-histogram/arena records this module renders.
    interval_ms: u32,
}

impl ObserveState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.tlm_slot = -1;
        self.interval_ms = 5000;
    }
}

mod params_def {
    use super::p_u32;
    use super::ObserveState;
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
            // Composite dimension index: omitted when DIM_NONE, so a line
            // for an undimensioned instrument carries no `dim=` field.
            let dim = tlm::metric_dim(rec);
            if dim != tlm::DIM_NONE {
                emit_bytes(b" dim=", out, &mut pos);
                emit_decimal(dim as u64, out, &mut pos);
            }
            let nbuckets = tlm::hist_bucket_count(knd as u8);
            if nbuckets > 0 {
                let mut bi = 0usize;
                while bi < nbuckets {
                    emit_bytes(b" b", out, &mut pos);
                    emit_decimal(bi as u64, out, &mut pos);
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
        x if x == tlm::SIGNAL_PSTATUS => {
            // Kernel-pushed per-module process status. STEP renders as a
            // MON_HIST line; RES surfaces arena + fault state.
            if knd == tlm::PSTATUS_STEP as u64 {
                emit_bytes(b"MON_HIST mod=", out, &mut pos);
                emit_decimal(module, out, &mut pos);
                let mut bi = 0usize;
                while bi < tlm::HIST_BUCKETS {
                    emit_bytes(b" b", out, &mut pos);
                    if pos < out.len() {
                        out[pos] = b'0' + bi as u8;
                        pos += 1;
                    }
                    emit_bytes(b"=", out, &mut pos);
                    emit_decimal(tlm::pstatus_step_bucket(rec, bi) as u64, out, &mut pos);
                    bi += 1;
                }
                pos
            } else if knd == tlm::PSTATUS_RES as u64 {
                emit_bytes(b"MON_RES mod=", out, &mut pos);
                emit_decimal(module, out, &mut pos);
                emit_bytes(b" arena=", out, &mut pos);
                emit_decimal(tlm::pstatus_res_arena_used(rec) as u64, out, &mut pos);
                emit_bytes(b"/", out, &mut pos);
                emit_decimal(tlm::pstatus_res_arena_cap(rec) as u64, out, &mut pos);
                emit_bytes(b" faults=", out, &mut pos);
                emit_decimal(tlm::pstatus_res_faults(rec) as u64, out, &mut pos);
                pos
            } else {
                0
            }
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

/// Drain the telemetry input port: read whole records (sized from the header)
/// and emit each as a MON_ line. Bounded so a flooded port can't starve the
/// tick.
unsafe fn drain_telemetry(s: &ObserveState) {
    if s.tlm_slot < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let mut batch = [0u8; BATCH_BUF];
    // TLM_DRAIN copies whole records for this slot into the buffer and advances
    // the tail; `handle` is the slot id.
    let n = (sys.provider_call)(s.tlm_slot, tlm::TLM_DRAIN, batch.as_mut_ptr(), BATCH_BUF);
    if n <= 0 {
        return;
    }
    let n = n as usize;
    let mut line = [0u8; LINE_BUF];
    let mut off = 0usize;
    while off + tlm::HEADER_SIZE <= n {
        let rlen = tlm::record_len(tlm::signal(&batch[off..]), tlm::kind(&batch[off..]));
        if rlen == 0 || off + rlen > n {
            break; // corrupt tail — stop rather than spin (ring is record-atomic)
        }
        let m = render_record(&batch[off..off + rlen], &mut line);
        if m > 0 {
            (sys.provider_call)(3, SYSTEM_LOG, line.as_mut_ptr(), m);
        }
        off += rlen;
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
        // Subscribe to the kernel telemetry ring (all signal types). The old
        // `telemetry` input port is gone — emission is ring-based now.
        // `in_chan` is unused.
        let _ = in_chan;
        let sys = &*s.syscalls;

        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // Subscribe to the ring (all signals) AND declare the PSTATUS cadence
        // in one call: `[filter u32][interval ms u64]`. The kernel produces
        // the step-histogram/arena records the console renders, so the
        // collector's `interval_ms` sets that emit rate.
        let mut sub = [0u8; tlm::SUBSCRIBE_INTERVAL_OFFSET + 8];
        sub[..4].copy_from_slice(&tlm::FILTER_ALL.to_le_bytes());
        sub[tlm::SUBSCRIBE_INTERVAL_OFFSET..]
            .copy_from_slice(&(s.interval_ms as u64).to_le_bytes());
        s.tlm_slot = (sys.provider_call)(-1, tlm::TLM_SUBSCRIBE, sub.as_mut_ptr(), sub.len());

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

        // Drain the ring every step and render each record as a MON_ line.
        // The ring carries the whole signal set — metrics, spans, and the
        // kernel-pushed PSTATUS step-histogram/arena records
        // (MON_HIST/MON_RES) — so no separate pull round is needed.
        drain_telemetry(s);

        0
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/runtime/wasm_entry.rs");
