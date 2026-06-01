//! otel_udp_sample — compact-UDP telemetry exporter.
//!
//! Drains module-scope `TelemetryRecord`s from its `telemetry` input port (the
//! same `Telemetry` edge the `observe` collector consumes), packs them verbatim
//! behind one batch envelope per UDP datagram
//! (`modules/sdk/contracts/telemetry.rs`), and forwards them through the IP
//! module's datagram surface. Records leave the device id-interned (no strings
//! on the wire); a host collector resolves `(module, id) -> name` from the
//! generated id-table and produces OTLP.
//!
//! This is the pluggable UDP exporter the observability RFC calls for — it
//! complements `log_net` (which forwards the log_ring) by forwarding the
//! metric/span stream the same way. Tee an instrumented module's `telemetry`
//! output to both `observe` and here to export over UDP while still seeing
//! `MON_` lines locally.
//!
//! # Wiring
//!
//!   ip.net_out  →  otel_udp_sample.net_in    (inbound frames from ip)
//!   otel_udp_sample.net_out  →  ip.net_in     (CMD_DG_BIND + CMD_DG_SEND_TO)
//!   <module>.telemetry  →  otel_udp_sample.telemetry
//!
//! # Parameters
//!
//! | Tag | Name      | Type | Default      | Description                          |
//! |-----|-----------|------|--------------|--------------------------------------|
//! | 1   | dst_ip    | u32  | 0 (disabled) | Destination IP (LE). `0` / broadcast leaves the module dormant. |
//! | 2   | dst_port  | u16  | 4317         | UDP destination port (OTLP-adjacent). |
//! | 3   | bind_port | u16  | 4316         | Local UDP source port.               |
//! | 4   | flush_ms  | u32  | 1000         | Max time a partial batch waits before it is flushed. |
//!
//! # Host-side capture
//!
//!   socat -u UDP-RECV:4317 - | xxd        # raw batches; decode via the id-table

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

// ============================================================================
// Constants
// ============================================================================

/// Largest single `TelemetryRecord` (histogram = 80 B). The batch is flushed
/// whenever fewer than this many bytes remain, so any drained record fits.
const MAX_RECORD: usize = tlm::METRIC_HIST_SIZE;

/// Records region budget per datagram (after the batch header). Keeps the whole
/// frame — NET_FRAME_HDR + DG_V4_PREFIX + BATCH_HEADER + records — under a
/// single ~512 B payload.
const BATCH_RECORDS_MAX: usize = 480;
/// Batch payload buffer: envelope header + records region.
const BATCH_PAYLOAD_MAX: usize = tlm::BATCH_HEADER_SIZE + BATCH_RECORDS_MAX;

/// Frame assembly scratch: NET_FRAME_HDR + DG_V4_PREFIX + batch payload.
const NET_BUF_SIZE: usize = NET_FRAME_HDR + DG_V4_PREFIX + BATCH_PAYLOAD_MAX + 8;

/// Scratch for one drained record before it is copied into the batch.
const REC_BUF: usize = 96;

/// Bound on records drained per step so a flooded port can't starve the tick.
const MAX_DRAIN_PER_STEP: u32 = 64;

/// Backoff window between bind retries — wall-clock, tick-rate independent.
const BACKOFF_MICROS: u64 = 100_000; // 100 ms

/// Give up binding after this many consecutive failures (stays faultless).
const MAX_BIND_ATTEMPTS: u16 = 50;

// ============================================================================
// State
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Init = 0,
    Binding = 1,
    WaitBound = 2,
    Serving = 3,
    Backoff = 4,
    /// `dst_ip` unset / broadcast — terminal dormant with a one-shot warning.
    Disabled = 5,
}

#[repr(C)]
struct OtelUdpState {
    syscalls: *const SyscallTable,
    telemetry_in_chan: i32,
    net_in_chan: i32,
    net_out_chan: i32,

    dst_ip: u32,
    dst_port: u16,
    bind_port: u16,

    phase: Phase,
    /// datagram endpoint id from MSG_DG_BOUND. `0xFF` = unallocated.
    ep_id: u8,

    /// Wall-clock micros until which the module stays in Backoff.
    backoff_until_micros: u64,
    bind_attempts: u16,

    /// Configured forced-flush cadence in milliseconds. Timing is wall-clock
    /// (`dev_micros`), independent of the scheduler tick rate.
    flush_ms: u32,
    /// Wall-clock micros at the last forced flush.
    last_flush_micros: u64,

    /// Bytes used in `batch` (starts at BATCH_HEADER_SIZE — header is written
    /// at flush time). Records are appended after the reserved header.
    batch_len: u16,
    /// Number of records currently staged in `batch`.
    batch_count: u16,

    /// Stats (informational; readable via memory dump).
    datagrams_sent: u32,
    records_forwarded: u32,

    /// Batch payload: [reserved 8 B header][records…].
    batch: [u8; BATCH_PAYLOAD_MAX],
    /// Frame assembly scratch for CMD_DG_BIND / CMD_DG_SEND_TO and net_in drain.
    net_buf: [u8; NET_BUF_SIZE],
    /// Scratch for one drained record.
    rec: [u8; REC_BUF],
}

impl OtelUdpState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.telemetry_in_chan = -1;
        self.net_in_chan = -1;
        self.net_out_chan = -1;
        self.dst_ip = 0;
        self.dst_port = 4317;
        self.bind_port = 4316;
        self.phase = Phase::Init;
        self.ep_id = 0xFF;
        self.backoff_until_micros = 0;
        self.bind_attempts = 0;
        self.flush_ms = 0;
        self.last_flush_micros = 0;
        self.batch_len = tlm::BATCH_HEADER_SIZE as u16;
        self.batch_count = 0;
        self.datagrams_sent = 0;
        self.records_forwarded = 0;
    }

    fn reset_batch(&mut self) {
        self.batch_len = tlm::BATCH_HEADER_SIZE as u16;
        self.batch_count = 0;
    }
}

// ============================================================================
// Parameters
// ============================================================================

mod params_def {
    use super::OtelUdpState;
    use super::p_u16;
    use super::p_u32;
    use super::SCHEMA_MAX;

    define_params! {
        OtelUdpState;

        1, dst_ip, u32, 0
            => |s, d, len| { s.dst_ip = p_u32(d, len, 0, 0); };

        2, dst_port, u16, 4317
            => |s, d, len| { s.dst_port = p_u16(d, len, 0, 4317); };

        3, bind_port, u16, 4316
            => |s, d, len| { s.bind_port = p_u16(d, len, 0, 4316); };

        4, flush_ms, u32, 1000
            => |s, d, len| { s.flush_ms = p_u32(d, len, 0, 1000); };
    }
}

// ============================================================================
// Batch flush
// ============================================================================

/// Write the envelope header over the reserved prefix and send the staged
/// records as one UDP datagram. Returns true iff the datagram was accepted (or
/// there was nothing to send); on a full output channel the batch is kept.
unsafe fn flush(s: &mut OtelUdpState) -> bool {
    if s.batch_count == 0 {
        return true;
    }
    if s.net_out_chan < 0 || s.ep_id == 0xFF {
        return false;
    }
    let count = s.batch_count;
    let total = s.batch_len as usize;
    tlm::write_batch_header(&mut s.batch[..], count);

    let sys = &*s.syscalls;
    let chan = s.net_out_chan;
    let ep = s.ep_id;
    let dst_ip = s.dst_ip;
    let dst_port = s.dst_port;
    let data = s.batch.as_ptr();
    let scratch = s.net_buf.as_mut_ptr();

    let n = dev_dg_send_to_v4(sys, chan, ep, dst_ip, dst_port, data, total, scratch, NET_BUF_SIZE);
    if n > 0 {
        s.datagrams_sent = s.datagrams_sent.wrapping_add(1);
        s.records_forwarded = s.records_forwarded.wrapping_add(count as u32);
        s.reset_batch();
        true
    } else {
        false
    }
}

/// Drain whole telemetry records into the batch, flushing whenever the next
/// record might not fit. A record is only read once there is guaranteed room,
/// so nothing is consumed that can't be stored. Stops (leaving records in the
/// port) if a needed flush can't make room.
unsafe fn drain_into_batch(s: &mut OtelUdpState) {
    if s.telemetry_in_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let chan = s.telemetry_in_chan;

    let mut drained = 0u32;
    while drained < MAX_DRAIN_PER_STEP {
        // Make room for any record before committing to a (header, body) read.
        if BATCH_PAYLOAD_MAX - (s.batch_len as usize) < MAX_RECORD && !flush(s) {
            break; // channel full — retry next step; records stay queued.
        }

        // Shared self-sizing read (header → record_len → body).
        let len = dev_read_telemetry_record(sys, chan, s.rec.as_mut_ptr(), REC_BUF);
        if len == 0 {
            break; // no full record, or unrecognised header.
        }
        let off = s.batch_len as usize;
        core::ptr::copy_nonoverlapping(s.rec.as_ptr(), s.batch.as_mut_ptr().add(off), len);
        s.batch_len += len as u16;
        s.batch_count += 1;
        drained += 1;
    }
}

/// Drain any inbound frame on net_in and discard. ip may publish
/// MSG_DG_RX_FROM for our bound endpoint — we forward, not receive.
unsafe fn discard_net_in(s: &mut OtelUdpState) {
    if s.net_in_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let chan = s.net_in_chan;
    let poll = (sys.channel_poll)(chan, 0x01 /* POLL_IN */);
    if poll > 0 && (poll & 0x01) != 0 {
        let buf = s.net_buf.as_mut_ptr();
        // Alignment-safe: net_in is fanned from ip.net_out, so it can carry
        // stream MSG_DATA fragments up to MAX_DATA_FRAGMENT (1460) — larger than
        // this datagram exporter's small scratch. The aligned reader drains the
        // tail rather than leaving it to desync the FIFO.
        let _ = net_read_frame_aligned(sys, chan, buf, NET_BUF_SIZE);
    }
}

// ============================================================================
// Module interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<OtelUdpState>() as u32
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
        if state_size < core::mem::size_of::<OtelUdpState>() {
            return -6;
        }

        let s = &mut *(state as *mut OtelUdpState);
        s.init(syscalls as *const SyscallTable);

        // Two inputs (telemetry, net_in) + one output (net_out) — discover all
        // by port index rather than the single in/out_chan args.
        let sys = &*s.syscalls;
        s.telemetry_in_chan = dev_channel_port(sys, 0, 0); // in[0]: telemetry
        s.net_in_chan = dev_channel_port(sys, 0, 1); // in[1]: frames from ip
        s.net_out_chan = dev_channel_port(sys, 1, 0); // out[0]: frames to ip

        let is_tlv = !params.is_null()
            && params_len >= 4
            && *params == 0xFE
            && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // Flush cadence is wall-clock (see `last_flush_micros`); seed the clock
        // so the first forced flush waits a full interval.
        s.last_flush_micros = dev_micros(sys);

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
        let s = &mut *(state as *mut OtelUdpState);
        if s.syscalls.is_null() {
            return -1;
        }

        match s.phase {
            Phase::Init => {
                if s.dst_ip == 0 || s.dst_ip == 0xFFFF_FFFF {
                    let sys = &*s.syscalls;
                    let msg = if s.dst_ip == 0 {
                        b"[otel_udp_sample] dst_ip unset; UDP telemetry export disabled\0".as_ref()
                    } else {
                        b"[otel_udp_sample] dst_ip = broadcast rejected; export disabled\0".as_ref()
                    };
                    dev_log(sys, 2, msg.as_ptr(), msg.len() - 1);
                    s.phase = Phase::Disabled;
                    return 0;
                }
                s.phase = Phase::Binding;
            }

            Phase::Disabled => return 0,

            Phase::Binding => {
                if s.net_out_chan < 0 {
                    return 0;
                }
                if s.bind_attempts >= MAX_BIND_ATTEMPTS {
                    return 0;
                }
                let sys = &*s.syscalls;
                let out_chan = s.net_out_chan;
                let buf = s.net_buf.as_mut_ptr();
                // CMD_DG_BIND payload: [port: u16 LE][flags: u8 = 0]
                let mut payload = [0u8; 3];
                let port = s.bind_port.to_le_bytes();
                payload[0] = port[0];
                payload[1] = port[1];
                payload[2] = 0;
                let wrote = net_write_frame(
                    sys, out_chan, DG_CMD_BIND, payload.as_ptr(), 3, buf, NET_BUF_SIZE,
                );
                if wrote == 0 {
                    return 0;
                }
                s.bind_attempts += 1;
                s.phase = Phase::WaitBound;
                return 2;
            }

            Phase::WaitBound => {
                if s.net_in_chan < 0 {
                    return 0;
                }
                let sys = &*s.syscalls;
                let in_chan = s.net_in_chan;
                let poll = (sys.channel_poll)(in_chan, 0x01);
                if poll <= 0 || (poll & 0x01) == 0 {
                    return 0;
                }
                let buf = s.net_buf.as_mut_ptr();
                let (msg_type, payload_len) = net_read_frame(sys, in_chan, buf, NET_BUF_SIZE);
                if msg_type == DG_MSG_BOUND && payload_len >= 3 {
                    let bound_port = (*buf.add(4) as u16) | ((*buf.add(5) as u16) << 8);
                    if bound_port == s.bind_port {
                        s.ep_id = *buf.add(3);
                        s.phase = Phase::Serving;
                        s.bind_attempts = 0;
                        return 2;
                    }
                } else if msg_type == DG_MSG_ERROR {
                    s.phase = Phase::Backoff;
                    s.backoff_until_micros = dev_micros(sys).wrapping_add(BACKOFF_MICROS);
                    return 0;
                }
                // Other message — stay in WaitBound.
            }

            Phase::Backoff => {
                let sys = &*s.syscalls;
                if dev_micros(sys) < s.backoff_until_micros {
                    return 0;
                }
                s.phase = Phase::Binding;
            }

            Phase::Serving => {
                discard_net_in(s);
                drain_into_batch(s);

                // Forced flush on cadence so a low-rate partial batch still
                // leaves the device promptly.
                let sys = &*s.syscalls;
                let now = dev_micros(sys);
                if now.wrapping_sub(s.last_flush_micros) >= (s.flush_ms as u64) * 1000 {
                    s.last_flush_micros = now;
                    let _ = flush(s);
                }
                return 2;
            }
        }

        0
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/wasm_entry.rs");
