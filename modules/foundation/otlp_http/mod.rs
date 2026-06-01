//! otlp_http — OTLP/HTTP (JSON) telemetry exporter.
//!
//! Drains module-scope `TelemetryRecord`s from its `telemetry` input port,
//! resolves each metric's `(module, id)` to a name on-device, and POSTs them as
//! OpenTelemetry Protocol JSON (`application/json`) to an OTLP/HTTP collector
//! over an outbound TCP connection through the IP module's stream surface
//! (net_proto / Stream Surface v1). The metric/span analogue of `log_net`, but
//! producing OTLP directly so no host decoder is needed.
//!
//! Names are resolved from a compiled-in id-table delivered as a parameter
//! (tag 10): `[module u16][id u16][name_len u8][name…]` entries. The `fluxor`
//! config compiler builds this from the resolved graph's `[observability]`
//! declarations. Unresolved ids fall back to a synthetic `m<idx>.<id>` name so
//! the exporter still produces valid OTLP if the table is absent or truncated.
//!
//! # Wiring
//!
//!   ip.net_out  →  otlp_http.net_in     (MSG_CONNECTED / MSG_DATA / MSG_CLOSED)
//!   otlp_http.net_out  →  ip.net_in      (CMD_CONNECT / CMD_SEND / CMD_CLOSE)
//!   <module>.telemetry  →  otlp_http.telemetry
//!
//! # Parameters
//!
//! | Tag | Name      | Type | Default      | Description                          |
//! |-----|-----------|------|--------------|--------------------------------------|
//! | 1   | dst_ip    | u32  | 0 (disabled) | Collector IP (LE). `0` leaves dormant. |
//! | 2   | dst_port  | u16  | 4318         | OTLP/HTTP port.                      |
//! | 3   | flush_ms  | u32  | 1000         | Max time a pending batch waits before a POST. |
//! | 10  | id_table  | blob | (synthetic)  | `(module,id)->name` map; injected by the compiler. |
//!
//! # Host-side
//!
//!   any OTLP/HTTP collector (OpenTelemetry Collector `otlphttp`, etc.) on :4318
//!   POST /v1/metrics  Content-Type: application/json

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

use abi::contracts::net::net_proto as np;
use abi::contracts::otlp;
use abi::contracts::telemetry as tlm;

// ============================================================================
// Constants
// ============================================================================

const MAX_RECORD: usize = tlm::METRIC_HIST_SIZE; // 80
/// Raw records staged between POSTs.
const ACCUM_MAX: usize = 640;
/// OTLP/JSON body buffer. Sized for an `ACCUM_MAX` batch expanded to JSON — a
/// metric expands ~8×, a span ~4×, and metrics and spans build into this same
/// buffer sequentially (one doc at a time), so the worst realistic batch (a few
/// metrics + a burst of `tcp.connection` spans) fits without dropping a doc.
const JSON_MAX: usize = 4096;
/// HTTP request buffer (headers + body copy).
const REQ_MAX: usize = JSON_MAX + 256;
/// net_proto frame scratch (read + CMD_SEND assembly).
const NET_BUF_SIZE: usize = 640;
/// Id-table text blob (delivered as `str` TLV chunks of ≤255 B each, appended).
/// Sized for a large instrumented graph; the compiler bounds the injected table
/// to this and warns rather than silently truncating mid-entry.
const IDTABLE_MAX: usize = 1024;
/// Scratch for a resolved-or-synthesised metric name.
const NAME_MAX: usize = 48;

const REC_BUF: usize = 96;
const MAX_DRAIN_PER_STEP: u32 = 64;
const BACKOFF_TICKS: u16 = 5000; // 500 ms at tick_us=100
const MAX_CONNECT_ATTEMPTS: u16 = 50;

/// Id-table parameter tag (compiler-injected; see module docs).
const PARAM_ID_TABLE: u8 = 10;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Init = 0,
    Connecting = 1,
    WaitConnected = 2,
    /// Connected, idle — accumulating records, waiting for the flush cadence.
    Idle = 3,
    /// A request is being written to net_out across ticks.
    Sending = 4,
    /// Request sent; draining the HTTP response.
    WaitResponse = 5,
    Backoff = 6,
    Disabled = 7,
}

#[repr(C)]
struct OtlpState {
    syscalls: *const SyscallTable,
    telemetry_in_chan: i32,
    net_in_chan: i32,
    net_out_chan: i32,

    dst_ip: u32,
    dst_port: u16,

    flush_ticks: u32,
    flush_countdown: u32,

    phase: Phase,
    connected: bool,
    conn_id: u8,
    connect_attempts: u16,
    backoff_ticks: u16,

    /// Accumulated raw records since the last POST.
    accum_len: u16,
    accum_count: u16,
    /// Bytes of the current request already handed to net_out.
    req_len: u16,
    req_sent: u16,

    /// Id-table blob length (0 = synthetic names).
    idtable_len: u16,

    /// A flush builds two documents from one accumulated batch and POSTs each to
    /// its own endpoint sequentially over the keep-alive connection: metrics to
    /// `/v1/metrics`, spans to `/v1/traces`. These track what's still to send;
    /// the accum is held until both are done.
    send_metrics: bool,
    send_traces: bool,

    posts_sent: u32,
    posts_ok: u32,

    accum: [u8; ACCUM_MAX],
    json: [u8; JSON_MAX],
    req: [u8; REQ_MAX],
    net_buf: [u8; NET_BUF_SIZE],
    rec: [u8; REC_BUF],
    idtable: [u8; IDTABLE_MAX],
}

impl OtlpState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.telemetry_in_chan = -1;
        self.net_in_chan = -1;
        self.net_out_chan = -1;
        self.dst_ip = 0;
        self.dst_port = 4318;
        self.flush_ticks = 0;
        self.flush_countdown = 0;
        self.phase = Phase::Init;
        self.connected = false;
        self.conn_id = 0;
        self.connect_attempts = 0;
        self.backoff_ticks = 0;
        self.accum_len = 0;
        self.accum_count = 0;
        self.req_len = 0;
        self.req_sent = 0;
        self.idtable_len = 0;
        self.send_metrics = false;
        self.send_traces = false;
        self.posts_sent = 0;
        self.posts_ok = 0;
    }
}

// ============================================================================
// Parameters
// ============================================================================

mod params_def {
    use super::OtlpState;
    use super::p_u16;
    use super::p_u32;
    use super::IDTABLE_MAX;
    use super::PARAM_ID_TABLE;
    use super::SCHEMA_MAX;

    define_params! {
        OtlpState;

        1, dst_ip, u32, 0
            => |s, d, len| { s.dst_ip = p_u32(d, len, 0, 0); };

        2, dst_port, u16, 4318
            => |s, d, len| { s.dst_port = p_u16(d, len, 0, 4318); };

        3, flush_ms, u32, 1000
            => |s, d, len| { s.flush_ticks = p_u32(d, len, 0, 1000); };

        10, id_table, str, 0
            => |s, d, len| { unsafe { super::store_idtable(s, d, len); } };
    }
}

/// Append an id-table text chunk into state. A `str` param is delivered as one
/// or more ≤255-byte TLV chunks sharing the tag, so chunks are concatenated.
unsafe fn store_idtable(s: &mut OtlpState, d: *const u8, len: usize) {
    let mut written = s.idtable_len as usize;
    let mut i = 0;
    while i < len && written < IDTABLE_MAX {
        s.idtable[written] = *d.add(i);
        written += 1;
        i += 1;
    }
    s.idtable_len = written as u16;
}

// ============================================================================
// Name resolution
// ============================================================================

/// Resolve `(module, id)` to a name via the shared `module:id=name;` text-table
/// parser, writing into `out`. Falls back to a synthetic `m<idx>.<id>` name on a
/// miss, so the exporter still emits valid OTLP if the table is absent.
fn resolve_name(idtable: &[u8], module: u16, id: u16, out: &mut [u8]) -> usize {
    if let Some(name) = otlp::resolve_in_table(idtable, module, id) {
        let n = if name.len() > out.len() { out.len() } else { name.len() };
        out[..n].copy_from_slice(&name[..n]);
        return n;
    }
    synthetic_name(module, id, out)
}

/// Write `m<module>.<id>` into `out`. Division-free decimals.
fn synthetic_name(module: u16, id: u16, out: &mut [u8]) -> usize {
    let mut pos = 0usize;
    push(out, &mut pos, b'm');
    push_dec(out, &mut pos, module as u32);
    push(out, &mut pos, b'.');
    push_dec(out, &mut pos, id as u32);
    pos
}

fn push(out: &mut [u8], pos: &mut usize, b: u8) {
    if *pos < out.len() {
        out[*pos] = b;
        *pos += 1;
    }
}

/// `val` → ASCII decimal via constant-divisor `/10` (PIC-safe — no
/// `__aeabi_uldivmod`, no panic path; see otlp::MetricDoc::put_u64). Values here
/// are small (module/id u16, IP octets, body length), so u32 is ample.
fn push_dec(out: &mut [u8], pos: &mut usize, val: u32) {
    if val == 0 {
        push(out, pos, b'0');
        return;
    }
    let mut n = val;
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    while n > 0 && len < tmp.len() {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    let mut i = 0;
    while i < len {
        push(out, pos, tmp[len - 1 - i]);
        i += 1;
    }
}

// ============================================================================
// Build the OTLP/JSON body + HTTP request
// ============================================================================

/// Resolve a span name_id to a name via the span-family id-table, synthetic
/// `m<idx>.s<id>` on a miss. Mirrors `resolve_name` for the metric family.
fn resolve_span_name(idtable: &[u8], module: u16, id: u16, out: &mut [u8]) -> usize {
    if let Some(name) = otlp::resolve_span_in_table(idtable, module, id) {
        let n = if name.len() > out.len() { out.len() } else { name.len() };
        out[..n].copy_from_slice(&name[..n]);
        return n;
    }
    // Synthetic fallback: `m<module>.s<id>`.
    let mut pos = 0usize;
    push(out, &mut pos, b'm');
    push_dec(out, &mut pos, module as u32);
    push(out, &mut pos, b'.');
    push(out, &mut pos, b's');
    push_dec(out, &mut pos, id as u32);
    pos
}

/// Render accumulated SPAN records into `json` as one OTLP/JSON traces
/// (`resourceSpans`) document. Returns the body length, or 0 on overflow / no
/// spans.
fn build_traces_json(accum: &[u8], idtable: &[u8], json: &mut [u8]) -> usize {
    let mut doc = otlp::SpanDoc::begin(json, b"fluxor");
    let mut name = [0u8; NAME_MAX];
    let mut off = 0usize;
    while off + tlm::HEADER_SIZE <= accum.len() {
        let rec0 = &accum[off..];
        let len = tlm::record_len(tlm::signal(rec0), tlm::kind(rec0));
        if len < tlm::HEADER_SIZE || off + len > accum.len() {
            break;
        }
        let rec = &accum[off..off + len];
        if tlm::signal(rec) == tlm::SIGNAL_SPAN {
            let module = tlm::module(rec);
            let nid = tlm::span_name_id(rec);
            let nlen = resolve_span_name(idtable, module, nid, &mut name);
            let trace_id = tlm::span_trace_id(rec);
            let span_id = tlm::span_span_id(rec);
            let parent_id = tlm::span_parent_id(rec);
            let span_kind = tlm::kind(rec); // span kind rides in header[1]
            let status = tlm::span_status(rec);
            let start = tlm::span_start_micros(rec).wrapping_mul(1000);
            let end = tlm::span_end_micros(rec).wrapping_mul(1000);
            doc.span(
                &name[..nlen],
                module,
                &trace_id,
                &span_id,
                &parent_id,
                span_kind,
                status,
                start,
                end,
            );
        }
        off += len;
    }
    if doc.span_count() == 0 {
        return 0;
    }
    doc.finish().unwrap_or(0)
}

/// Render the accumulated records into `json` as one OTLP/JSON metrics
/// document. Returns the body length, or 0 on overflow / no metrics.
fn build_metrics_json(accum: &[u8], idtable: &[u8], json: &mut [u8]) -> usize {
    let mut doc = otlp::MetricDoc::begin(json, b"fluxor");
    let mut name = [0u8; NAME_MAX];
    let mut off = 0usize;
    while off + tlm::HEADER_SIZE <= accum.len() {
        let rec = &accum[off..];
        let len = tlm::record_len(tlm::signal(rec), tlm::kind(rec));
        if len < tlm::HEADER_SIZE || off + len > accum.len() {
            break;
        }
        let rec = &accum[off..off + len];
        if tlm::signal(rec) == tlm::SIGNAL_METRIC {
            let module = tlm::module(rec);
            let knd = tlm::kind(rec);
            let t_nanos = tlm::t_micros(rec).wrapping_mul(1000);
            if knd == tlm::METRIC_HISTOGRAM {
                let id = tlm::metric_id(rec);
                let nlen = resolve_name(idtable, module, id, &mut name);
                let mut buckets = [0u64; tlm::HIST_BUCKETS];
                let mut bi = 0;
                while bi < tlm::HIST_BUCKETS {
                    let bo = 16 + bi * 8;
                    buckets[bi] = u64::from_le_bytes([
                        rec[bo], rec[bo + 1], rec[bo + 2], rec[bo + 3],
                        rec[bo + 4], rec[bo + 5], rec[bo + 6], rec[bo + 7],
                    ]);
                    bi += 1;
                }
                doc.histogram(&name[..nlen], module, t_nanos, &buckets);
            } else {
                let id = tlm::metric_id(rec);
                let nlen = resolve_name(idtable, module, id, &mut name);
                let value = tlm::metric_scalar_value(rec);
                let monotonic = knd == tlm::METRIC_COUNTER;
                doc.sum(&name[..nlen], module, t_nanos, value, monotonic);
            }
        }
        off += len;
    }
    if doc.metric_count() == 0 {
        return 0;
    }
    doc.finish().unwrap_or(0)
}

/// Assemble the full HTTP/1.1 POST (request line + headers + body) into `req`
/// for `path` (`/v1/metrics` or `/v1/traces`). Returns the total length, or 0 on
/// overflow.
fn build_request(dst_ip: u32, path: &[u8], body: &[u8], req: &mut [u8]) -> usize {
    let mut pos = 0usize;
    putb(req, &mut pos, b"POST ");
    putb(req, &mut pos, path);
    putb(req, &mut pos, b" HTTP/1.1\r\nHost: ");
    let ip = dst_ip.to_le_bytes(); // dst_ip stored LE per param convention
    push_dec(req, &mut pos, ip[0] as u32);
    putb(req, &mut pos, b".");
    push_dec(req, &mut pos, ip[1] as u32);
    putb(req, &mut pos, b".");
    push_dec(req, &mut pos, ip[2] as u32);
    putb(req, &mut pos, b".");
    push_dec(req, &mut pos, ip[3] as u32);
    putb(req, &mut pos, b"\r\nContent-Type: application/json\r\nContent-Length: ");
    push_dec(req, &mut pos, body.len() as u32);
    putb(req, &mut pos, b"\r\nConnection: keep-alive\r\n\r\n");
    // Body.
    if pos + body.len() > req.len() {
        return 0;
    }
    req[pos..pos + body.len()].copy_from_slice(body);
    pos += body.len();
    pos
}

fn putb(out: &mut [u8], pos: &mut usize, bytes: &[u8]) {
    let mut i = 0;
    while i < bytes.len() && *pos < out.len() {
        out[*pos] = bytes[i];
        *pos += 1;
        i += 1;
    }
}

/// Build and queue the next pending signal's POST over the keep-alive
/// connection: metrics → `/v1/metrics` first, then spans → `/v1/traces`. Sets
/// `Phase::Sending` and returns true if a request was queued; otherwise the
/// batch is exhausted, so the accum is dropped and false returned (the caller
/// returns to Idle). A signal that renders empty is simply skipped.
fn kick_next_post(s: &mut OtlpState) -> bool {
    let dst_ip = s.dst_ip;

    if s.send_metrics {
        s.send_metrics = false;
        let body_len = build_metrics_json(
            &s.accum[..s.accum_len as usize],
            &s.idtable[..s.idtable_len as usize],
            &mut s.json,
        );
        if body_len > 0 {
            let req_len = {
                let (json, req) = (&s.json, &mut s.req);
                build_request(dst_ip, b"/v1/metrics", &json[..body_len], req)
            };
            if req_len > 0 {
                s.req_len = req_len as u16;
                s.req_sent = 0;
                s.posts_sent = s.posts_sent.wrapping_add(1);
                s.phase = Phase::Sending;
                return true;
            }
        }
    }

    if s.send_traces {
        s.send_traces = false;
        let body_len = build_traces_json(
            &s.accum[..s.accum_len as usize],
            &s.idtable[..s.idtable_len as usize],
            &mut s.json,
        );
        if body_len > 0 {
            let req_len = {
                let (json, req) = (&s.json, &mut s.req);
                build_request(dst_ip, b"/v1/traces", &json[..body_len], req)
            };
            if req_len > 0 {
                s.req_len = req_len as u16;
                s.req_sent = 0;
                s.posts_sent = s.posts_sent.wrapping_add(1);
                s.phase = Phase::Sending;
                return true;
            }
        }
    }

    // Batch exhausted — drop it and idle.
    s.accum_len = 0;
    s.accum_count = 0;
    false
}

// ============================================================================
// Telemetry drain (same discipline as otel_udp_sample)
// ============================================================================

unsafe fn drain_into_accum(s: &mut OtlpState) {
    if s.telemetry_in_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let chan = s.telemetry_in_chan;
    let mut drained = 0u32;
    while drained < MAX_DRAIN_PER_STEP {
        // Stop accumulating if there's no room for another max-size record;
        // the next flush sends what we have.
        if ACCUM_MAX - (s.accum_len as usize) < MAX_RECORD {
            break;
        }
        // Shared self-sizing read (header → record_len → body).
        let len = dev_read_telemetry_record(sys, chan, s.rec.as_mut_ptr(), REC_BUF);
        if len == 0 {
            break; // no full record, or unrecognised header.
        }
        let off = s.accum_len as usize;
        core::ptr::copy_nonoverlapping(s.rec.as_ptr(), s.accum.as_mut_ptr().add(off), len);
        s.accum_len += len as u16;
        s.accum_count += 1;
        drained += 1;
    }
}

// ============================================================================
// Net helpers
// ============================================================================

/// Emit CMD_CONNECT to the collector. Returns true if the frame was accepted.
unsafe fn send_connect(s: &mut OtlpState) -> bool {
    let sys = &*s.syscalls;
    let buf = s.net_buf.as_mut_ptr();
    let mut payload = [0u8; 7];
    payload[0] = np::SOCK_TYPE_STREAM;
    let ip = s.dst_ip.to_le_bytes();
    payload[1] = ip[0];
    payload[2] = ip[1];
    payload[3] = ip[2];
    payload[4] = ip[3];
    let port = s.dst_port.to_le_bytes();
    payload[5] = port[0];
    payload[6] = port[1];
    net_write_frame(sys, s.net_out_chan, np::CMD_CONNECT, payload.as_ptr(), 7, buf, NET_BUF_SIZE) > 0
}

/// Send as much of req[req_sent..req_len] as net_out accepts this tick, one
/// CMD_SEND frame ([conn_id][data]) at a time. Returns true once fully sent.
unsafe fn pump_send(s: &mut OtlpState) -> bool {
    let sys = &*s.syscalls;
    let max_data = NET_BUF_SIZE - NET_FRAME_HDR - 1;
    while (s.req_sent as usize) < (s.req_len as usize) {
        let remaining = (s.req_len - s.req_sent) as usize;
        let chunk = if remaining > max_data { max_data } else { remaining };
        let buf = s.net_buf.as_mut_ptr();
        // CMD_SEND payload: [conn_id][data...] — assemble payload then frame.
        *buf.add(NET_FRAME_HDR) = s.conn_id;
        core::ptr::copy_nonoverlapping(
            s.req.as_ptr().add(s.req_sent as usize),
            buf.add(NET_FRAME_HDR + 1),
            chunk,
        );
        // net_write_frame writes the 3-byte header then copies payload from
        // `payload` into scratch[3..]; here payload already lives in scratch, so
        // frame it in place.
        let payload_len = chunk + 1;
        let total = NET_FRAME_HDR + payload_len;
        *buf = np::CMD_SEND;
        let lb = (payload_len as u16).to_le_bytes();
        *buf.add(1) = lb[0];
        *buf.add(2) = lb[1];
        let wrote = (sys.channel_write)(s.net_out_chan, buf, total);
        if wrote != total as i32 {
            return false; // channel full — resume next tick.
        }
        s.req_sent += chunk as u16;
    }
    true
}

/// Drain the HTTP response. Returns Some(true) on a 2xx status line seen,
/// Some(false) on a non-2xx, None if nothing conclusive yet.
unsafe fn read_response(s: &mut OtlpState) -> Option<bool> {
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.net_in_chan, 0x01);
    if poll <= 0 || (poll & 0x01) == 0 {
        return None;
    }
    let buf = s.net_buf.as_mut_ptr();
    let (msg_type, payload_len) = net_read_frame(sys, s.net_in_chan, buf, NET_BUF_SIZE);
    if msg_type == np::MSG_DATA && payload_len > 1 {
        // [conn_id][http bytes…] — look for "HTTP/1.1 2" in the first bytes.
        let data = buf.add(NET_FRAME_HDR + 1);
        let dlen = payload_len - 1;
        if dlen >= 12 {
            // "HTTP/1.x " then status digit.
            let status0 = *data.add(9);
            return Some(status0 == b'2');
        }
        return None;
    } else if msg_type == np::MSG_CLOSED {
        s.connected = false;
        s.conn_id = 0;
        return Some(false);
    }
    None
}

unsafe fn close_conn(s: &mut OtlpState) {
    if s.connected && s.net_out_chan >= 0 {
        let sys = &*s.syscalls;
        let buf = s.net_buf.as_mut_ptr();
        let payload = [s.conn_id];
        net_write_frame(sys, s.net_out_chan, np::CMD_CLOSE, payload.as_ptr(), 1, buf, NET_BUF_SIZE);
    }
    s.connected = false;
    s.conn_id = 0;
}

// ============================================================================
// Module interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<OtlpState>() as u32
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
        if state_size < core::mem::size_of::<OtlpState>() {
            return -6;
        }

        let s = &mut *(state as *mut OtlpState);
        s.init(syscalls as *const SyscallTable);

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

        const ASSUMED_TICK_US: u32 = 100;
        let ticks = s.flush_ticks.saturating_mul(1000) / ASSUMED_TICK_US;
        s.flush_ticks = if ticks < 1 { 1 } else { ticks };
        s.flush_countdown = s.flush_ticks;

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
        let s = &mut *(state as *mut OtlpState);
        if s.syscalls.is_null() {
            return -1;
        }

        // Always accumulate telemetry, regardless of connection phase.
        if s.phase != Phase::Disabled {
            drain_into_accum(s);
        }

        match s.phase {
            Phase::Init => {
                if s.dst_ip == 0 || s.dst_ip == 0xFFFF_FFFF {
                    let sys = &*s.syscalls;
                    let msg = b"[otlp_http] dst_ip unset; OTLP/HTTP export disabled\0";
                    dev_log(sys, 2, msg.as_ptr(), msg.len() - 1);
                    s.phase = Phase::Disabled;
                    return 0;
                }
                s.phase = Phase::Connecting;
            }

            Phase::Disabled => return 0,

            Phase::Connecting => {
                if s.net_out_chan < 0 {
                    return 0;
                }
                if s.connect_attempts >= MAX_CONNECT_ATTEMPTS {
                    return 0;
                }
                if send_connect(s) {
                    s.connect_attempts += 1;
                    s.phase = Phase::WaitConnected;
                    return 2;
                }
                return 0;
            }

            Phase::WaitConnected => {
                let sys = &*s.syscalls;
                let poll = (sys.channel_poll)(s.net_in_chan, 0x01);
                if poll <= 0 || (poll & 0x01) == 0 {
                    return 0;
                }
                let buf = s.net_buf.as_mut_ptr();
                let (msg_type, payload_len) = net_read_frame(sys, s.net_in_chan, buf, NET_BUF_SIZE);
                if msg_type == np::MSG_CONNECTED && payload_len >= 1 {
                    s.conn_id = *buf.add(NET_FRAME_HDR);
                    s.connected = true;
                    s.connect_attempts = 0;
                    s.flush_countdown = s.flush_ticks;
                    s.phase = Phase::Idle;
                    return 2;
                } else if msg_type == np::MSG_ERROR {
                    s.phase = Phase::Backoff;
                    s.backoff_ticks = BACKOFF_TICKS;
                    return 0;
                }
            }

            Phase::Idle => {
                // Drop the connection if the peer closed it under us.
                let sys = &*s.syscalls;
                let poll = (sys.channel_poll)(s.net_in_chan, 0x01);
                if poll > 0 && (poll & 0x01) != 0 {
                    let buf = s.net_buf.as_mut_ptr();
                    let (mt, _pl) = net_read_frame(sys, s.net_in_chan, buf, NET_BUF_SIZE);
                    if mt == np::MSG_CLOSED {
                        s.connected = false;
                        s.conn_id = 0;
                        s.phase = Phase::Connecting;
                        return 0;
                    }
                }

                if s.flush_countdown > 0 {
                    s.flush_countdown -= 1;
                    return 0;
                }
                s.flush_countdown = s.flush_ticks;
                if s.accum_count == 0 {
                    return 0;
                }

                // One batch → a metrics POST then a traces POST, each to its own
                // endpoint over the keep-alive conn. kick_next_post builds the
                // first non-empty signal and transitions to Sending.
                s.send_metrics = true;
                s.send_traces = true;
                if kick_next_post(s) {
                    return 2;
                }
                return 0;
            }

            Phase::Sending => {
                if pump_send(s) {
                    s.phase = Phase::WaitResponse;
                }
                return 2;
            }

            Phase::WaitResponse => {
                match read_response(s) {
                    Some(true) => {
                        s.posts_ok = s.posts_ok.wrapping_add(1);
                        // Post the next signal of this batch, or idle if done.
                        if !kick_next_post(s) {
                            s.phase = Phase::Idle;
                        }
                    }
                    Some(false) => {
                        if s.connected {
                            // Non-2xx but conn alive — continue the batch.
                            if !kick_next_post(s) {
                                s.phase = Phase::Idle;
                            }
                        } else {
                            // Peer closed mid-batch — drop the rest, reconnect.
                            s.send_metrics = false;
                            s.send_traces = false;
                            s.accum_len = 0;
                            s.accum_count = 0;
                            s.phase = Phase::Connecting;
                        }
                    }
                    None => {}
                }
                return 0;
            }

            Phase::Backoff => {
                if s.backoff_ticks > 0 {
                    s.backoff_ticks -= 1;
                    return 0;
                }
                s.phase = Phase::Connecting;
            }
        }

        0
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/wasm_entry.rs");
