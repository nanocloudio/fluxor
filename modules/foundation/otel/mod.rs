//! OTEL export engine — the telemetry-ring consumer that batches records and
//! emits them on `export` for a transport-blind carrier to deliver
//! (`rfc_observability_surface.md` §5.5).
//!
//! It subscribes to the kernel telemetry ring (`TLM_SUBSCRIBE`), drains whole
//! records each step (`TLM_DRAIN`), accumulates them, and on a flush cadence
//! frames one length-prefixed payload onto the `export` output channel. A
//! carrier module wired to `export` carries the bytes; this engine is
//! transport-blind — it never opens a socket or builds a request.
//!
//! Encodings (`encoding` param): `fxtl-compact` (default) is the raw
//! `TelemetryRecord` batch behind an `FXTL` envelope, decoded by a host
//! collector (minimum device cost — no id-table). `otlp-json` and `otlp-proto`
//! build a full OTLP metrics document on-device (`otlp_json`/`otlp_proto` cores)
//! for a downstream HTTP/gRPC client. When the `delivery` input is wired otel
//! runs in reliable mode: it retains the flushed batch and resends on `RETRY`.
//!
//! **Params (TLV v2):** tag 3 `flush_ms` (u32, default 1000) — max wall-clock a
//! partial batch waits before it is flushed; tag 4 `encoding` (u8, default 2 =
//! `fxtl-compact`; 0 = `otlp-json`, 1 = `otlp-proto`).

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

use abi::contracts::telemetry as tlm;

/// OTLP/JSON encoder core — the reusable `cores/otlp_json` implementation,
/// `include!`d verbatim so this module and the host tests compile the same bytes.
mod otlp {
    include!("../../sdk/cores/otlp_json.rs");
}

/// OTLP/protobuf encoder core — the binary sibling of `otlp`, for the
/// `otlp-proto` encoding (a gRPC/HTTP client posts these bytes to `/v1/metrics`).
mod otlp_pb {
    include!("../../sdk/cores/otlp_proto.rs");
}

/// Raw records staged between flushes (rfc_observability_surface.md §11.2).
///
/// Target-split rather than flat: the ring this drains is itself scaled (32 KiB
/// on bcm2712) and the sibling forwarders scale their channel buffers per
/// target, so a flat 512 left an application processor staging 1/64th of what
/// the ring holds. `cfg(target_arch)` is the established idiom for a
/// module-internal array (cf. `tls`, `ip`, `dns`); a manifest `buffer_size`
/// sizes *channel* rings and cannot reach a static like this one.
///
/// The bound is the path MTU, NOT available RAM: one batch is one datagram on
/// the UDP carrier, so a batch past the MTU fragments and any single lost
/// fragment destroys the whole batch. 1280 B of records + the 12 B envelope
/// sits well inside a 1500 B Ethernet MTU with room for encapsulation.
#[cfg(target_arch = "aarch64")]
const ACCUM_MAX: usize = 1280;
#[cfg(not(target_arch = "aarch64"))]
const ACCUM_MAX: usize = 512;
/// Resends of one retained batch before it is dropped. A carrier that cannot
/// place a batch after this many attempts is not going to, and holding it
/// forever would stop draining and stall every later record behind it.
const MAX_RESENDS: u8 = 3;
/// Ack deadline as a multiple of the flush cadence. A carrier that neither acks
/// nor errors (wedged connection, lost `delivery` frame) must not pin the batch
/// indefinitely — past the deadline the batch is resent, then dropped.
const ACK_TIMEOUT_FLUSHES: u64 = 5;
/// Carrier frame header: `[msg_type: u8][len: u16 LE]` (the `net_proto` framing
/// in `sdk/runtime/net.rs`). The `export` payload is length-prefixed so a
/// transport-blind carrier recovers one message per write off a byte FIFO.
const FRAME_HDR: usize = 3;
/// Frame `msg_type` marking one export payload (a full encoded batch/document).
const EXPORT_MSG: u8 = 0x01;
/// Output frame: carrier header + FXTL batch envelope + one full accumulation.
const OUT_MAX: usize = FRAME_HDR + tlm::BATCH_HEADER_SIZE + ACCUM_MAX;
/// OTLP/JSON body buffer — a full `ACCUM_MAX` of scalar metrics expands to a
/// few KB of JSON (carrier header + document). Scales with `ACCUM_MAX`: the
/// ~8x expansion factor is a property of the encoding, not of the target.
#[cfg(target_arch = "aarch64")]
const JSON_MAX: usize = FRAME_HDR + 10240;
#[cfg(not(target_arch = "aarch64"))]
const JSON_MAX: usize = FRAME_HDR + 4096;

#[repr(C)]
struct OtelState {
    syscalls: *const SyscallTable,
    /// Ring drain slot from `TLM_SUBSCRIBE` (`-1` = not subscribed).
    tlm_slot: i32,
    /// `export` output channel.
    export_chan: i32,
    /// `delivery` input channel (`-1` = unwired → fire-and-forget). When wired,
    /// otel runs in reliable mode: it retains the flushed batch (the `accum`
    /// records) until the carrier acks it, resending on `RETRY` (§5.5).
    delivery_chan: i32,
    /// Flush cadence (ms) and the wall-clock micros of the last flush.
    flush_ms: u32,
    last_flush_micros: u64,
    /// On-wire encoding: `ENCODING_FXTL_COMPACT` (default) | `ENCODING_OTLP_JSON`
    /// | `ENCODING_OTLP_PROTO`.
    encoding: u8,
    /// Reliable mode only: a batch was sent and is held in `accum` awaiting a
    /// delivery ack. Draining pauses and the cadence flush is suppressed until
    /// the carrier reports `DELIVERED`/`DROP` (clear) or `RETRY` (resend), or
    /// the ack deadline expires.
    awaiting_ack: bool,
    /// Reliable mode only: wall-clock micros past which the retained batch is
    /// resent (or dropped, once `resends` is spent). Bounds every stall — a
    /// silent carrier, a lost ack, a resend the carrier could not accept.
    ack_deadline_micros: u64,
    /// Resends spent on the currently retained batch.
    resends: u8,
    /// Cumulative ring drops for our slot, sampled at each flush and stamped
    /// into the batch envelope (rfc_observability_surface.md §11.2). Held
    /// across flushes so a retained/resent batch reports the value that was
    /// true when it was built.
    dropped: u32,
    accum_len: u16,
    accum: [u8; ACCUM_MAX],
    out: [u8; OUT_MAX],
    json: [u8; JSON_MAX],
}

impl OtelState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.tlm_slot = -1;
        self.export_chan = -1;
        self.delivery_chan = -1;
        self.flush_ms = 1000;
        self.last_flush_micros = 0;
        self.encoding = tlm::ENCODING_FXTL_COMPACT;
        self.awaiting_ack = false;
        self.ack_deadline_micros = 0;
        self.resends = 0;
        self.dropped = 0;
        self.accum_len = 0;
    }
}

mod params_def {
    use super::OtelState;
    use super::SCHEMA_MAX;
    use super::{p_u32, p_u8};

    define_params! {
        OtelState;
        3, flush_ms, u32, 1000 => |s, d, len| { s.flush_ms = p_u32(d, len, 0, 1000); };
        4, encoding, u8, 2 => |s, d, len| { s.encoding = p_u8(d, len, 0, 2); };
    }
}

/// Write `v` as decimal digits into `out`. Returns the byte length.
fn write_u16_dec(mut v: u16, out: &mut [u8]) -> usize {
    let mut tmp = [0u8; 5];
    let mut n = 0;
    loop {
        tmp[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let mut w = 0;
    while n > 0 && w < out.len() {
        n -= 1;
        out[w] = tmp[n];
        w += 1;
    }
    w
}

/// Format a synthetic metric name `m<module>.<id>` into `out`. The device holds
/// no id-table; a host collector resolves `(module, id) -> name`. Returns the
/// byte length.
fn synthetic_name(module: u16, id: u16, out: &mut [u8]) -> usize {
    let mut pos = 0usize;
    if pos < out.len() {
        out[pos] = b'm';
        pos += 1;
    }
    pos += write_u16_dec(module, &mut out[pos..]);
    if pos < out.len() {
        out[pos] = b'.';
        pos += 1;
    }
    pos += write_u16_dec(id, &mut out[pos..]);
    pos
}

/// Encode the accumulated **metric** records as one OTLP/JSON metrics document
/// into `json`. Spans in the batch are skipped (a traces document is a
/// follow-up). Returns the body length, or 0 if nothing was encoded / it
/// overflowed. `t_nanos` is the record's `t_micros × 1000` (boot-relative in
/// v1 — a real epoch anchor is a follow-up; the collector may re-stamp).
fn encode_metrics_json(accum: &[u8], json: &mut [u8]) -> usize {
    let mut doc = otlp::MetricDoc::begin(json, b"fluxor");
    let mut off = 0usize;
    let mut namebuf = [0u8; 16];
    while off + tlm::HEADER_SIZE <= accum.len() {
        let rec = &accum[off..];
        let signal = tlm::signal(rec);
        let kind = tlm::kind(rec);
        let rlen = tlm::record_len(signal, kind);
        if rlen == 0 || off + rlen > accum.len() {
            break;
        }
        if signal == tlm::SIGNAL_METRIC {
            let module = tlm::module(rec);
            let id = tlm::metric_id(rec);
            let t_nanos = tlm::t_micros(rec).wrapping_mul(1000);
            let n = synthetic_name(module, id, &mut namebuf);
            let name = &namebuf[..n];
            if kind == tlm::METRIC_HISTOGRAM {
                // Histogram body: buckets are 8×u64 at offset 16 (after the
                // 12-byte header + id u16 + 2 pad).
                let mut buckets = [0u64; tlm::HIST_BUCKETS];
                for (i, b) in buckets.iter_mut().enumerate() {
                    let base = 16 + i * 8;
                    let mut v = [0u8; 8];
                    v.copy_from_slice(&rec[base..base + 8]);
                    *b = u64::from_le_bytes(v);
                }
                doc.histogram(name, module, t_nanos, &buckets);
            } else {
                let value = tlm::metric_scalar_value(rec);
                doc.sum(name, module, t_nanos, value, kind == tlm::METRIC_COUNTER);
            }
        }
        off += rlen;
    }
    if doc.metric_count() == 0 {
        return 0;
    }
    doc.finish().unwrap_or(0)
}

/// Encode the accumulated **metric** records as one OTLP/protobuf metrics
/// document into `out` (the binary sibling of [`encode_metrics_json`]; spans are
/// skipped). Returns the byte length, or 0 if nothing encoded / it overflowed.
fn encode_metrics_proto(accum: &[u8], out: &mut [u8]) -> usize {
    let mut doc = otlp_pb::MetricProtoDoc::begin(out, b"fluxor");
    let mut off = 0usize;
    let mut namebuf = [0u8; 16];
    while off + tlm::HEADER_SIZE <= accum.len() {
        let rec = &accum[off..];
        let signal = tlm::signal(rec);
        let kind = tlm::kind(rec);
        let rlen = tlm::record_len(signal, kind);
        if rlen == 0 || off + rlen > accum.len() {
            break;
        }
        if signal == tlm::SIGNAL_METRIC {
            let module = tlm::module(rec);
            let id = tlm::metric_id(rec);
            let t_nanos = tlm::t_micros(rec).wrapping_mul(1000);
            let n = synthetic_name(module, id, &mut namebuf);
            let name = &namebuf[..n];
            if kind == tlm::METRIC_HISTOGRAM {
                let mut buckets = [0u64; tlm::HIST_BUCKETS];
                for (i, b) in buckets.iter_mut().enumerate() {
                    let base = 16 + i * 8;
                    let mut v = [0u8; 8];
                    v.copy_from_slice(&rec[base..base + 8]);
                    *b = u64::from_le_bytes(v);
                }
                doc.histogram(name, module, t_nanos, &buckets);
            } else {
                let value = tlm::metric_scalar_value(rec);
                doc.sum(name, module, t_nanos, value, kind == tlm::METRIC_COUNTER);
            }
        }
        off += rlen;
    }
    if doc.metric_count() == 0 {
        return 0;
    }
    doc.finish().unwrap_or(0)
}

/// Number of whole records currently staged (advisory `count` for the envelope).
fn record_count(accum: &[u8]) -> u16 {
    let mut off = 0usize;
    let mut n = 0u16;
    while off + tlm::HEADER_SIZE <= accum.len() {
        let rl = tlm::record_len(tlm::signal(&accum[off..]), tlm::kind(&accum[off..]));
        if rl == 0 || off + rl > accum.len() {
            break;
        }
        off += rl;
        n += 1;
    }
    n
}

unsafe fn step_drain(s: &mut OtelState) {
    // In reliable mode, hold the drain while a batch awaits its delivery ack —
    // the retained batch IS `accum`, so it must not grow or be overwritten.
    if s.tlm_slot < 0 || s.awaiting_ack {
        return;
    }
    let sys = &*s.syscalls;
    let used = s.accum_len as usize;
    let room = ACCUM_MAX - used;
    // TLM_DRAIN copies as many WHOLE records as fit in the offered room.
    if room >= tlm::MAX_RECORD_SIZE {
        let n = (sys.provider_call)(
            s.tlm_slot,
            tlm::TLM_DRAIN,
            s.accum.as_mut_ptr().add(used),
            room,
        );
        if n > 0 {
            s.accum_len += n as u16;
        }
    }
}

/// Encode the staged `accum` batch and write it to `export` once, if the carrier
/// is ready. Returns true iff the frame was sent. Does NOT touch `accum_len` —
/// the caller decides whether to clear (fire-and-forget) or retain (reliable).
unsafe fn emit_batch(s: &mut OtelState) -> bool {
    if s.accum_len == 0 || s.export_chan < 0 {
        return false;
    }
    let sys = &*s.syscalls;
    let out_poll = (sys.channel_poll)(s.export_chan, POLL_OUT);
    if out_poll <= 0 || (out_poll as u32) & POLL_OUT == 0 {
        return false; // carrier not ready — hold the batch for a later step
    }
    let used = s.accum_len as usize;
    // Each encoding lays its payload after a reserved `FRAME_HDR` prefix; the
    // carrier header is stamped last so it covers the exact encoded length.
    if s.encoding == tlm::ENCODING_OTLP_JSON || s.encoding == tlm::ENCODING_OTLP_PROTO {
        // On-device OTLP metrics document (JSON or protobuf) → carrier posts it
        // as the request body.
        let n = if s.encoding == tlm::ENCODING_OTLP_PROTO {
            encode_metrics_proto(&s.accum[..used], &mut s.json[FRAME_HDR..])
        } else {
            encode_metrics_json(&s.accum[..used], &mut s.json[FRAME_HDR..])
        };
        if n == 0 {
            return false;
        }
        write_frame_header(&mut s.json, n);
        (sys.channel_write)(s.export_chan, s.json.as_ptr(), FRAME_HDR + n) == (FRAME_HDR + n) as i32
    } else {
        // Compact FXTL: the raw record batch a host collector decodes.
        let count = record_count(&s.accum[..used]);
        let Some(hdr) = tlm::write_batch_header(&mut s.out[FRAME_HDR..], count, s.dropped) else {
            return false;
        };
        s.out[FRAME_HDR + hdr..FRAME_HDR + hdr + used].copy_from_slice(&s.accum[..used]);
        let payload = hdr + used;
        write_frame_header(&mut s.out, payload);
        (sys.channel_write)(s.export_chan, s.out.as_ptr(), FRAME_HDR + payload)
            == (FRAME_HDR + payload) as i32
    }
}

unsafe fn step_flush(s: &mut OtelState) {
    // While a batch is in flight (reliable mode), the cadence flush is
    // suppressed — resends are driven by delivery acks, not the clock.
    if s.accum_len == 0 || s.awaiting_ack {
        return;
    }
    let sys = &*s.syscalls;
    let now = dev_micros(sys);
    // Two triggers (rfc_observability_surface.md §11.2): the cadence, and a
    // full accumulator. Without the size trigger a burst that fills `accum`
    // stalls `step_drain` (which refuses to drain into less than one whole
    // record of room) until the timer fires, pushing the overflow back onto
    // the ring to be dropped. Flushing when full decouples burst capacity
    // from cadence and leaves `flush_ms` a pure freshness knob.
    let full = ACCUM_MAX - (s.accum_len as usize) < tlm::MAX_RECORD_SIZE;
    if !full && now.wrapping_sub(s.last_flush_micros) < (s.flush_ms as u64) * 1000 {
        return;
    }
    // Sample our slot's cumulative ring drops so the batch reports the export
    // path's own fidelity in-band. Best-effort: a failed read keeps the last
    // known value rather than reporting a false zero.
    // The slot bound is load-bearing, not defensive noise: `stats` is a fixed
    // TLM_STATS_LEN buffer holding RING_CONSUMERS counters, so a slot outside
    // that range would index past it.
    if s.tlm_slot >= 0 && (s.tlm_slot as usize) < tlm::RING_CONSUMERS {
        let mut stats = [0u8; tlm::TLM_STATS_LEN];
        let n = (sys.provider_call)(s.tlm_slot, tlm::TLM_STATS, stats.as_mut_ptr(), stats.len());
        if n >= tlm::TLM_STATS_LEN as i32 {
            let off = 4 + (s.tlm_slot as usize) * 4;
            s.dropped =
                u32::from_le_bytes([stats[off], stats[off + 1], stats[off + 2], stats[off + 3]]);
        }
    }
    if !emit_batch(s) {
        return; // carrier not ready / nothing encoded — retry next step.
    }
    s.last_flush_micros = now;
    if s.delivery_chan >= 0 {
        // Reliable: retain the batch (in `accum`) until the carrier acks it or
        // the deadline expires.
        s.awaiting_ack = true;
        s.resends = 0;
        s.ack_deadline_micros = ack_deadline(s, now);
    } else {
        // Fire-and-forget (UDP/UART): the batch is gone once written.
        s.accum_len = 0;
    }
}

/// Deadline for the next ack, `ACK_TIMEOUT_FLUSHES` flush cadences out.
fn ack_deadline(s: &OtelState, now: u64) -> u64 {
    now.wrapping_add((s.flush_ms as u64) * 1000 * ACK_TIMEOUT_FLUSHES)
}

/// Release the retained batch and resume draining.
fn release_batch(s: &mut OtelState) {
    s.awaiting_ack = false;
    s.ack_deadline_micros = 0;
    s.resends = 0;
    s.accum_len = 0;
}

/// Resend the retained batch, or drop it once the resend budget is spent.
/// Every path either re-arms the deadline or releases the batch, so a retained
/// batch always makes progress.
unsafe fn retry_batch(s: &mut OtelState) {
    if s.resends >= MAX_RESENDS {
        release_batch(s);
        return;
    }
    let sent = emit_batch(s);
    if sent {
        s.resends += 1;
    }
    // Re-arm even when the carrier refused the write: the next expiry retries.
    s.ack_deadline_micros = ack_deadline(s, dev_micros(&*s.syscalls));
}

/// Reliable mode: drop or resend a retained batch whose ack never arrived. A
/// carrier that neither acks nor errors would otherwise pin `accum` forever,
/// and with draining paused behind it telemetry would stop for good.
unsafe fn step_ack_timeout(s: &mut OtelState) {
    if !s.awaiting_ack {
        return;
    }
    if dev_micros(&*s.syscalls) < s.ack_deadline_micros {
        return;
    }
    retry_batch(s);
}

/// Reliable mode: consume delivery-status frames from the carrier and act on the
/// retained batch. Frame = `[msg_type][len: u16 LE][status: u8]` where status is
/// `DELIVERY_DELIVERED`/`RETRY`/`DROP` (§5.5). DELIVERED/DROP clear the retained
/// batch and resume draining; RETRY resends it within the resend budget.
unsafe fn step_delivery(s: &mut OtelState) {
    if s.delivery_chan < 0 || !s.awaiting_ack {
        return;
    }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.delivery_chan, POLL_IN);
    if poll <= 0 || (poll as u32) & POLL_IN == 0 {
        return;
    }
    let (_msg, payload_len) = net_read_frame(sys, s.delivery_chan, s.out.as_mut_ptr(), OUT_MAX);
    if payload_len == 0 {
        return;
    }
    let status = s.out[FRAME_HDR];
    match status {
        x if x == tlm::DELIVERY_RETRY => {
            // Resend within budget, re-arming the deadline. If the carrier
            // cannot take the write now, the expiry path retries it.
            retry_batch(s);
        }
        _ => {
            // DELIVERED or DROP (or anything else) → release the batch. A DROP is
            // permanent; retrying it would wedge the pipe.
            release_batch(s);
        }
    }
}

/// Stamp the carrier frame header `[EXPORT_MSG][len: u16 LE]` over `buf[0..3]`.
/// `payload_len` is the encoded body that follows at `buf[FRAME_HDR..]`.
fn write_frame_header(buf: &mut [u8], payload_len: usize) {
    let len = (payload_len as u16).to_le_bytes();
    buf[0] = EXPORT_MSG;
    buf[1] = len[0];
    buf[2] = len[1];
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<OtelState>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32,
    out_chan: i32,
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
        if state.is_null() || state_size < core::mem::size_of::<OtelState>() {
            return -5;
        }
        let s = &mut *(state as *mut OtelState);
        s.init(syscalls as *const SyscallTable);
        let sys = &*s.syscalls;

        s.export_chan = out_chan; // out[0]
                                  // Optional `delivery` input (in[0]): a carrier that reports per-batch
                                  // delivery status wires it; fire-and-forget carriers (UDP/UART) leave it
                                  // unwired (`-1`), keeping otel in fire-and-forget mode.
        s.delivery_chan = dev_channel_port(sys, 0, 0);
        let filter = tlm::FILTER_ALL.to_le_bytes();
        s.tlm_slot = (sys.provider_call)(-1, tlm::TLM_SUBSCRIBE, filter.as_ptr() as *mut u8, 4);

        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        s.last_flush_micros = dev_micros(sys);
        0
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut OtelState);
        if s.syscalls.is_null() {
            return -1;
        }
        // Delivery acks first: release/resend a retained batch before draining
        // new records or flushing a new one. The timeout sweep follows, so a
        // batch whose ack never arrives still clears.
        step_delivery(s);
        step_ack_timeout(s);
        step_drain(s);
        step_flush(s);
        0
    }
}

include!("../../sdk/runtime/wasm_entry.rs");
