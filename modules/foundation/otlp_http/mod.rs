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
//! | 3   | flush_ms  | u32  | 1000         | Max time a pending batch waits before a POST (wall-clock). |
//! | 4   | epoch_sec | u32  | 0 (REQUIRED) | Unix seconds at boot (a boot-synchronised anchor). Added to every `timeUnixNano`. `0` (unset) DISABLES direct export — OTLP requires Unix-epoch timestamps, which the device can't synthesise from boot-relative micros alone. |
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
/// Worst-case JSON one record expands to (a scalar metric: name ≤48 + fixed
/// keys/values + the module attr). Spans and histograms are individually larger
/// records but fewer fit in `ACCUM_MAX`, so the all-scalar case bounds the doc.
const MAX_JSON_PER_RECORD: usize = 256;
/// Smallest record (a scalar metric) — the densest packing of `ACCUM_MAX`.
const MIN_RECORD: usize = tlm::METRIC_SCALAR_SIZE; // 24
/// OTLP/JSON body buffer. Sized so a FULL `ACCUM_MAX` batch always fits in ONE
/// doc — the previous 4096 silently dropped a doc once ~24 scalar metrics
/// (~4.5 KB JSON) accumulated. `metrics` and `spans` build here sequentially
/// (one doc at a time); the all-scalar metrics case is the worst. The
/// compile-time assertion below keeps this provably true if the sizes change.
const JSON_MAX: usize = 8192;
const JSON_ENVELOPE_MAX: usize = 256; // begin (~150) + finish (~6), rounded up.
const _: () = assert!(JSON_MAX >= JSON_ENVELOPE_MAX + (ACCUM_MAX / MIN_RECORD + 1) * MAX_JSON_PER_RECORD);
/// HTTP request buffer (headers + body copy).
const REQ_MAX: usize = JSON_MAX + 256;
/// Response head scratch (status line + headers up to `\r\n\r\n`). A response
/// whose head exceeds this is drained-to-close rather than mis-parsed.
const RESP_HEAD_MAX: usize = 256;
/// net_proto frame scratch (read + CMD_SEND assembly). Sized > one TCP MSS
/// (~1460 B) so a full-size collector response frame fits without the
/// alignment-safe read dropping a tail and forcing a reconnect.
const NET_BUF_SIZE: usize = 1600;
/// Max wall-clock micros to wait for a complete HTTP response before dropping
/// the connection and reconnecting (guards a server that stalls or speaks an
/// unframed body forever).
const RESP_TIMEOUT_MICROS: u64 = 10_000_000; // 10 s
/// Id-table text blob (delivered as `str` TLV chunks of ≤255 B each, appended).
/// Sized for a large instrumented graph; the compiler bounds the injected table
/// to this and warns rather than silently truncating mid-entry.
const IDTABLE_MAX: usize = 1024;
/// Scratch for a resolved-or-synthesised metric name.
const NAME_MAX: usize = 48;

const REC_BUF: usize = 96;
const MAX_DRAIN_PER_STEP: u32 = 64;
const BACKOFF_MICROS: u64 = 500_000; // 500 ms — wall-clock, tick-rate independent
const MAX_CONNECT_ATTEMPTS: u16 = 50;

/// Id-table parameter tag (compiler-injected; see module docs).
const PARAM_ID_TABLE: u8 = 10;

// HTTP/1.1 response body framing modes.
const RESP_MODE_CONTENT_LENGTH: u8 = 0;
const RESP_MODE_CHUNKED: u8 = 1;
/// No Content-Length and not chunked → body runs until the peer closes (only
/// valid with `Connection: close`; the keep-alive conn is not reused).
const RESP_MODE_CLOSE: u8 = 2;

// Chunked-decode sub-states.
const CHUNK_SIZE: u8 = 0; // accumulating the hex chunk-size line
const CHUNK_EXT: u8 = 1; // chunk extension (`;name=val`) — skip to CR
const CHUNK_SIZE_CR: u8 = 2; // saw the size line CR, expecting its '\n'
const CHUNK_DATA: u8 = 3; // draining chunk bytes
const CHUNK_DATA_CR: u8 = 4; // expecting '\r' after chunk data
const CHUNK_DATA_LF: u8 = 5; // expecting '\n' after chunk data
// After the 0-size chunk: an optional trailer section ends with a bare CRLF.
const CHUNK_TRAILER: u8 = 6; // at the start of a trailer line
const CHUNK_TRAILER_LINE: u8 = 7; // inside a trailer line, skipping to CR
const CHUNK_TRAILER_LINE_LF: u8 = 8; // expecting '\n' ending a trailer line
const CHUNK_TRAILER_END_LF: u8 = 9; // bare CR seen → expecting final '\n' (done)

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

    /// Configured flush cadence in milliseconds. Timing is wall-clock
    /// (`dev_micros`), so it is independent of the scheduler tick rate.
    flush_ms: u32,
    /// Wall-clock micros at the last flush; the next flush fires once
    /// `now - last_flush_micros >= flush_ms * 1000`.
    last_flush_micros: u64,

    phase: Phase,
    connected: bool,
    conn_id: u8,
    connect_attempts: u16,
    /// Wall-clock micros until which the module stays in Backoff.
    backoff_until_micros: u64,

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

    /// Unix-epoch nanoseconds at boot, from the `epoch_sec` param (0 = unset →
    /// timestamps stay boot-relative monotonic). Added to every record's
    /// monotonic-micros so OTLP `timeUnixNano` is true wall-clock when known.
    epoch_nanos: u64,

    // ── HTTP/1.1 response parse (one keep-alive response per POST) ──────────
    /// Bytes of the response head accumulated until the `\r\n\r\n` terminator.
    resp_head_len: u16,
    /// True once the header terminator was seen and the body mode is set.
    resp_headers_done: bool,
    /// 3-digit status from the response line (0 until parsed).
    resp_code: u16,
    /// Body framing mode: `RESP_MODE_CONTENT_LENGTH` / `_CHUNKED` / `_CLOSE`.
    resp_mode: u8,
    /// Content-Length body bytes still to drain (mode = CONTENT_LENGTH).
    resp_body_remaining: u32,
    /// Chunked decode sub-state (`CHUNK_*`) and the bytes left in the current
    /// chunk (mode = CHUNKED).
    resp_chunk_state: u8,
    resp_chunk_remaining: u32,
    /// Hex accumulator for the chunk-size line being parsed.
    resp_chunk_size_acc: u32,
    /// Wall-clock micros after which an incomplete response is abandoned.
    resp_deadline_micros: u64,

    accum: [u8; ACCUM_MAX],
    json: [u8; JSON_MAX],
    req: [u8; REQ_MAX],
    net_buf: [u8; NET_BUF_SIZE],
    rec: [u8; REC_BUF],
    idtable: [u8; IDTABLE_MAX],
    /// Response-head scratch (status line + headers up to `\r\n\r\n`).
    resp_head: [u8; RESP_HEAD_MAX],
}

impl OtlpState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.telemetry_in_chan = -1;
        self.net_in_chan = -1;
        self.net_out_chan = -1;
        self.dst_ip = 0;
        self.dst_port = 4318;
        self.flush_ms = 0;
        self.last_flush_micros = 0;
        self.phase = Phase::Init;
        self.connected = false;
        self.conn_id = 0;
        self.connect_attempts = 0;
        self.backoff_until_micros = 0;
        self.accum_len = 0;
        self.accum_count = 0;
        self.req_len = 0;
        self.req_sent = 0;
        self.idtable_len = 0;
        self.send_metrics = false;
        self.send_traces = false;
        self.posts_sent = 0;
        self.posts_ok = 0;
        self.epoch_nanos = 0;
        self.resp_deadline_micros = 0;
        self.resp_reset();
    }

    /// Reset the response parser before draining a new POST's reply. The
    /// deadline is (re)armed by the caller when the POST finishes sending.
    fn resp_reset(&mut self) {
        self.resp_head_len = 0;
        self.resp_headers_done = false;
        self.resp_code = 0;
        self.resp_mode = RESP_MODE_CONTENT_LENGTH;
        self.resp_body_remaining = 0;
        self.resp_chunk_state = CHUNK_SIZE;
        self.resp_chunk_remaining = 0;
        self.resp_chunk_size_acc = 0;
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
            => |s, d, len| { s.flush_ms = p_u32(d, len, 0, 1000); };

        4, epoch_sec, u32, 0
            => |s, d, len| { s.epoch_nanos = (p_u32(d, len, 0, 0) as u64) * 1_000_000_000; };

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
fn build_traces_json(accum: &[u8], idtable: &[u8], epoch_nanos: u64, json: &mut [u8]) -> usize {
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
            let flags = tlm::span_flags(rec) as u32; // W3C trace-flags (low 8 bits)
            let start = epoch_nanos.wrapping_add(tlm::span_start_micros(rec).wrapping_mul(1000));
            let end = epoch_nanos.wrapping_add(tlm::span_end_micros(rec).wrapping_mul(1000));
            doc.span(
                &name[..nlen],
                module,
                &trace_id,
                &span_id,
                &parent_id,
                span_kind,
                status,
                flags,
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
fn build_metrics_json(accum: &[u8], idtable: &[u8], epoch_nanos: u64, json: &mut [u8]) -> usize {
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
            let t_nanos = epoch_nanos.wrapping_add(tlm::t_micros(rec).wrapping_mul(1000));
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
            s.epoch_nanos,
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
            s.epoch_nanos,
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
    // [sock,ip:4,port:2,requester_tag] — the tag is our module index so IP
    // echoes it in MSG_CONNECTED and we recognise our own connection on an
    // ip.net_out that's fanned to TLS as well.
    let mut payload = [0u8; 8];
    payload[0] = np::SOCK_TYPE_STREAM;
    let ip = s.dst_ip.to_le_bytes();
    payload[1] = ip[0];
    payload[2] = ip[1];
    payload[3] = ip[2];
    payload[4] = ip[3];
    let port = s.dst_port.to_le_bytes();
    payload[5] = port[0];
    payload[6] = port[1];
    payload[7] = dev_requester_tag(sys);
    net_write_frame(sys, s.net_out_chan, np::CMD_CONNECT, payload.as_ptr(), 8, buf, NET_BUF_SIZE) > 0
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

/// Case-insensitive substring search. Returns the start index of `needle` in
/// `hay`, or `None`. Used to find `Content-Length` regardless of header casing.
fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        let mut k = 0;
        while k < needle.len()
            && hay[i + k].to_ascii_lowercase() == needle[k].to_ascii_lowercase()
        {
            k += 1;
        }
        if k == needle.len() {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Parse the numeric status code out of an HTTP response head
/// (`HTTP/1.1 200 OK\r\n…`). Returns 0 if no code is found.
fn parse_status_code(head: &[u8]) -> u16 {
    let mut i = 0;
    while i < head.len() && head[i] != b' ' {
        i += 1;
    }
    i += 1; // skip the space after `HTTP/1.x`
    let mut code = 0u16;
    let mut k = 0;
    while i < head.len() && k < 3 && head[i].is_ascii_digit() {
        code = code * 10 + (head[i] - b'0') as u16;
        i += 1;
        k += 1;
    }
    code
}

/// Parse `Content-Length` from a response head. Returns `u32::MAX` when the
/// header is absent (caller drains until the peer closes).
fn parse_content_length(head: &[u8]) -> u32 {
    let Some(pos) = find_ci(head, b"content-length:") else {
        return u32::MAX;
    };
    let mut i = pos + b"content-length:".len();
    while i < head.len() && head[i] == b' ' {
        i += 1;
    }
    let mut v = 0u32;
    let mut any = false;
    while i < head.len() && head[i].is_ascii_digit() {
        v = v.saturating_mul(10).saturating_add((head[i] - b'0') as u32);
        i += 1;
        any = true;
    }
    if any {
        v
    } else {
        u32::MAX
    }
}

/// Determine the response body framing from the parsed head (RFC 7230 §3.3.3):
/// `Transfer-Encoding: chunked` takes precedence over `Content-Length`; absent
/// both, the body is close-delimited. Returns `(mode, content_length)`.
fn parse_response_mode(head: &[u8]) -> (u8, u32) {
    if let Some(pos) = find_ci(head, b"transfer-encoding:") {
        let mut end = pos;
        while end < head.len() && head[end] != b'\r' {
            end += 1;
        }
        if find_ci(&head[pos..end], b"chunked").is_some() {
            return (RESP_MODE_CHUNKED, 0);
        }
    }
    let cl = parse_content_length(head);
    if cl != u32::MAX {
        (RESP_MODE_CONTENT_LENGTH, cl)
    } else {
        (RESP_MODE_CLOSE, 0)
    }
}

/// Hex digit value for `0-9 a-f A-F`, else `None`. (Chunk sizes are hex; HTTP
/// permits either case here — unlike the strict W3C traceparent.)
#[inline(always)]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Feed `data[i..dlen]` through the chunked-transfer decoder, advancing the
/// per-connection chunk state. Returns `Some(true)` when the terminating
/// zero-length chunk has been fully consumed (response complete), `Some(false)`
/// when more data is needed, or `None` on a malformed encoding.
unsafe fn drain_chunked(s: &mut OtlpState, data: *const u8, start: usize, dlen: usize) -> Option<bool> {
    let mut i = start;
    while i < dlen {
        let b = *data.add(i);
        match s.resp_chunk_state {
            CHUNK_SIZE => {
                if b == b'\r' {
                    s.resp_chunk_state = CHUNK_SIZE_CR;
                } else if let Some(h) = hex_val(b) {
                    s.resp_chunk_size_acc =
                        s.resp_chunk_size_acc.wrapping_mul(16).wrapping_add(h as u32);
                } else if b == b';' {
                    // Start of a chunk extension — its bytes must NOT be folded
                    // into the size (e.g. `;name=cafe` contains hex digits).
                    s.resp_chunk_state = CHUNK_EXT;
                } else {
                    return None; // malformed size token
                }
                i += 1;
            }
            CHUNK_EXT => {
                // Skip the extension to the line CR; the data is irrelevant.
                if b == b'\r' {
                    s.resp_chunk_state = CHUNK_SIZE_CR;
                }
                i += 1;
            }
            CHUNK_SIZE_CR => {
                if b != b'\n' {
                    return None;
                }
                i += 1;
                s.resp_chunk_remaining = s.resp_chunk_size_acc;
                s.resp_chunk_size_acc = 0;
                s.resp_chunk_state = if s.resp_chunk_remaining == 0 {
                    CHUNK_TRAILER
                } else {
                    CHUNK_DATA
                };
            }
            CHUNK_DATA => {
                let avail = (dlen - i) as u32;
                let take = avail.min(s.resp_chunk_remaining);
                i += take as usize;
                s.resp_chunk_remaining -= take;
                if s.resp_chunk_remaining == 0 {
                    s.resp_chunk_state = CHUNK_DATA_CR;
                }
            }
            CHUNK_DATA_CR => {
                if b != b'\r' {
                    return None;
                }
                i += 1;
                s.resp_chunk_state = CHUNK_DATA_LF;
            }
            CHUNK_DATA_LF => {
                if b != b'\n' {
                    return None;
                }
                i += 1;
                s.resp_chunk_state = CHUNK_SIZE;
            }
            CHUNK_TRAILER => {
                // Start of a line in the trailer section. A bare CRLF terminates
                // the message; anything else is a trailer field to skip.
                if b == b'\r' {
                    s.resp_chunk_state = CHUNK_TRAILER_END_LF;
                } else {
                    s.resp_chunk_state = CHUNK_TRAILER_LINE;
                }
                i += 1;
            }
            CHUNK_TRAILER_LINE => {
                if b == b'\r' {
                    s.resp_chunk_state = CHUNK_TRAILER_LINE_LF;
                }
                i += 1;
            }
            CHUNK_TRAILER_LINE_LF => {
                if b != b'\n' {
                    return None;
                }
                i += 1;
                s.resp_chunk_state = CHUNK_TRAILER; // next trailer line or the end
            }
            CHUNK_TRAILER_END_LF => {
                if b != b'\n' {
                    return None;
                }
                return Some(true); // final CRLF consumed — message complete
            }
            _ => return None,
        }
    }
    Some(false)
}

/// Close the keep-alive connection (best-effort `CMD_CLOSE`) and clear local
/// connection state so the next POST reconnects rather than targeting a stale
/// or zero conn_id. Used on timeout / oversized-frame / malformed-response.
unsafe fn drop_conn(s: &mut OtlpState) {
    close_conn(s); // sends CMD_CLOSE while still connected, then clears state.
}

/// Drain ALL pending net_in frames this step, discarding everything except our
/// own connection's MSG_CLOSED. `ip.net_out` is fanned (broadcast tee) to this
/// exporter AND the application stream consumers, so it receives every app
/// frame. The tee BLOCKS the whole stream surface if any output branch fills, so
/// the exporter must keep its branch drained in EVERY phase (especially while
/// Sending a multi-tick request) — not just respond to its own frames. Returns
/// true if our connection closed. (Used outside WaitResponse, which has its own
/// response-parsing drain; no owned MSG_DATA is expected in Idle/Sending.)
unsafe fn drain_foreign_frames(s: &mut OtlpState) -> bool {
    let sys = &*s.syscalls;
    let mut frames = 0u32;
    let mut closed = false;
    loop {
        let poll = (sys.channel_poll)(s.net_in_chan, 0x01);
        if poll <= 0 || (poll & 0x01) == 0 {
            break;
        }
        frames += 1;
        if frames > MAX_DRAIN_PER_STEP {
            break;
        }
        let buf = s.net_buf.as_mut_ptr();
        let (mt, copied, _full) = net_read_frame_aligned(sys, s.net_in_chan, buf, NET_BUF_SIZE);
        if mt == 0 {
            break;
        }
        if mt == np::MSG_CLOSED && copied >= 1 && *buf.add(NET_FRAME_HDR) == s.conn_id {
            s.connected = false;
            s.conn_id = 0;
            closed = true;
        }
    }
    closed
}

/// Drain the HTTP response for the in-flight POST. Accumulates the response head
/// (status line + headers, possibly split across frames) until `\r\n\r\n`, then
/// drains the body by its explicit framing mode — `Content-Length`, chunked, or
/// close-delimited — so the keep-alive stream stays frame-aligned for the next
/// response. Returns `Some(true)` once a full 2xx response is consumed,
/// `Some(false)` on non-2xx / premature close / timeout / malformed framing
/// (connection dropped), or `None` while the response is still arriving. Uses
/// the alignment-safe read so an oversized frame can't desync the FIFO.
unsafe fn read_response(s: &mut OtlpState) -> Option<bool> {
    let sys = &*s.syscalls;
    // Bound the wait: a stalled server or an unframed keep-alive body would
    // otherwise hang this POST forever.
    if dev_micros(sys) >= s.resp_deadline_micros {
        drop_conn(s);
        return Some(false);
    }
    let mut frames = 0u32;
    loop {
        let poll = (sys.channel_poll)(s.net_in_chan, 0x01);
        if poll <= 0 || (poll & 0x01) == 0 {
            return None;
        }
        frames += 1;
        if frames > MAX_DRAIN_PER_STEP {
            return None; // yield; resume draining next tick.
        }
        let buf = s.net_buf.as_mut_ptr();
        let (msg_type, copied, payload) =
            net_read_frame_aligned(sys, s.net_in_chan, buf, NET_BUF_SIZE);
        if msg_type == 0 {
            return None; // no full frame yet.
        }
        if msg_type == np::MSG_CLOSED {
            // Frames for other connections share this fanned queue — only ours.
            if copied >= 1 && *buf.add(NET_FRAME_HDR) == s.conn_id {
                // A close COMPLETES a close-delimited response; for
                // Content-Length / chunked it is premature → failure. The peer
                // already closed, so no CMD_CLOSE — just clear and reconnect.
                let ok = s.resp_mode == RESP_MODE_CLOSE
                    && s.resp_headers_done
                    && (200..300).contains(&s.resp_code);
                s.connected = false;
                s.conn_id = 0;
                return Some(ok);
            }
            continue;
        }
        if msg_type != np::MSG_DATA || copied < 1 {
            continue;
        }
        if *buf.add(NET_FRAME_HDR) != s.conn_id {
            continue; // another connection's data on the shared queue.
        }
        if payload > copied {
            // Frame larger than our scratch; the tail was dropped to keep the
            // FIFO aligned, but we lost body bytes — close and reconnect rather
            // than mis-count the body. (NET_BUF_SIZE > MSS makes this rare.)
            drop_conn(s);
            return Some(false);
        }
        // MSG_DATA payload is `[conn_id][http bytes…]`.
        let data = buf.add(NET_FRAME_HDR + 1);
        let dlen = copied - 1;
        let mut i = 0usize;

        if !s.resp_headers_done {
            while i < dlen && (s.resp_head_len as usize) < RESP_HEAD_MAX {
                let b = *data.add(i);
                i += 1;
                s.resp_head[s.resp_head_len as usize] = b;
                s.resp_head_len += 1;
                let n = s.resp_head_len as usize;
                if n >= 4 && &s.resp_head[n - 4..n] == b"\r\n\r\n" {
                    s.resp_code = parse_status_code(&s.resp_head[..n]);
                    let (mut mode, mut body_len) = parse_response_mode(&s.resp_head[..n]);
                    // RFC 7230 §3.3.3: 1xx / 204 / 304 carry NO body regardless of
                    // Content-Length / Transfer-Encoding. Frame them as a zero
                    // Content-Length so the message completes right at the head.
                    if s.resp_code == 204
                        || s.resp_code == 304
                        || (100..200).contains(&s.resp_code)
                    {
                        mode = RESP_MODE_CONTENT_LENGTH;
                        body_len = 0;
                    }
                    s.resp_mode = mode;
                    s.resp_body_remaining = body_len;
                    s.resp_headers_done = true;
                    break;
                }
            }
            if !s.resp_headers_done {
                if (s.resp_head_len as usize) >= RESP_HEAD_MAX {
                    // Head exceeds the scratch — can't frame the body safely.
                    drop_conn(s);
                    return Some(false);
                }
                continue; // need more frames to finish the head.
            }
        }

        // Body, framed by mode.
        match s.resp_mode {
            RESP_MODE_CONTENT_LENGTH => {
                let body_here = (dlen - i) as u32;
                let consume = body_here.min(s.resp_body_remaining);
                s.resp_body_remaining -= consume;
                if s.resp_body_remaining == 0 {
                    return Some((200..300).contains(&s.resp_code));
                }
            }
            RESP_MODE_CHUNKED => match drain_chunked(s, data, i, dlen) {
                Some(true) => return Some((200..300).contains(&s.resp_code)),
                Some(false) => {}
                None => {
                    drop_conn(s);
                    return Some(false);
                }
            },
            _ => {
                // Close-delimited — completion arrives as MSG_CLOSED; just
                // consume these bytes and keep waiting.
            }
        }
    }
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

        // Flush cadence is wall-clock (see `last_flush_micros`); a 0-ms config
        // means "flush as soon as records exist". Seed the clock so the first
        // flush waits a full interval rather than firing on tick 1.
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
        let s = &mut *(state as *mut OtlpState);
        if s.syscalls.is_null() {
            return -1;
        }

        // Accumulate telemetry — but FREEZE the accumulator while a batch is in
        // flight (Sending / WaitResponse). A flush builds a metrics doc and then
        // a traces doc from the SAME `accum` snapshot, clearing it only when both
        // complete; draining mid-batch would make the two docs disagree and could
        // drop records cleared with the batch. Frozen-out records stay queued in
        // the telemetry channel (bounded backpressure) and drain once we idle.
        if !matches!(s.phase, Phase::Sending | Phase::WaitResponse | Phase::Disabled) {
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
                // OTLP requires Unix-epoch `timeUnixNano`. Without an epoch
                // anchor (`epoch_sec`) the device only has boot-relative
                // monotonic micros, which would emit non-conformant timestamps
                // (and zero-ish values OTLP collectors reject). Refuse to export
                // directly rather than ship invalid telemetry — set `epoch_sec`
                // to a boot-synchronised Unix time to enable it.
                if s.epoch_nanos == 0 {
                    let sys = &*s.syscalls;
                    let msg = b"[otlp_http] epoch_sec unset; OTLP needs a Unix-epoch anchor for timeUnixNano \xe2\x80\x94 direct export disabled\0";
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
                // Alignment-safe: ip.net_out may be fanned to TLS too, so this
                // queue can carry large MSG_DATA frames for other connections.
                let (msg_type, copied, _payload) =
                    net_read_frame_aligned(sys, s.net_in_chan, buf, NET_BUF_SIZE);
                if msg_type == np::MSG_CONNECTED && copied >= 2 {
                    // Claim only our own outbound connection (tag = our index).
                    let conn = *buf.add(NET_FRAME_HDR);
                    let tag = *buf.add(NET_FRAME_HDR + 1);
                    if tag == dev_requester_tag(sys) {
                        s.conn_id = conn;
                        s.connected = true;
                        s.connect_attempts = 0;
                        s.last_flush_micros = dev_micros(sys);
                        s.phase = Phase::Idle;
                        return 2;
                    }
                    // Another consumer's connection — ignore, keep waiting.
                } else if msg_type == np::MSG_ERROR {
                    // Connect failure carries our tag at payload[2]
                    // ([conn_id][errno][tag]); back off only for our own.
                    let etag = if copied >= 3 { *buf.add(NET_FRAME_HDR + 2) } else { 0 };
                    if etag == 0 || etag == dev_requester_tag(sys) {
                        s.phase = Phase::Backoff;
                        s.backoff_until_micros = dev_micros(sys).wrapping_add(BACKOFF_MICROS);
                    }
                    return 0;
                }
            }

            Phase::Idle => {
                let sys = &*s.syscalls;
                // Keep the fanned net_in branch drained (foreign app frames) so
                // the broadcast tee never stalls the stream surface; reconnect if
                // OUR connection closed.
                if drain_foreign_frames(s) {
                    s.phase = Phase::Connecting;
                    return 0;
                }

                // RESUME an in-flight batch first. A close-delimited collector
                // (`Connection: close`) closes after each response, so we land
                // back in Idle (via Connecting) with the metrics POST done but
                // `send_traces` still pending and `accum` intact. Resuming the
                // remaining signal — rather than waiting for the next flush and
                // re-setting both flags — avoids re-POSTing metrics (replay) and
                // traces starving.
                if s.send_metrics || s.send_traces {
                    if kick_next_post(s) {
                        return 2;
                    }
                    return 0;
                }

                let now = dev_micros(sys);
                if now.wrapping_sub(s.last_flush_micros) < (s.flush_ms as u64) * 1000 {
                    return 0;
                }
                s.last_flush_micros = now;
                if s.accum_count == 0 {
                    return 0;
                }

                // Start a NEW batch → a metrics POST then a traces POST, each to
                // its own endpoint. kick_next_post builds the first non-empty
                // signal and transitions to Sending.
                s.send_metrics = true;
                s.send_traces = true;
                if kick_next_post(s) {
                    return 2;
                }
                return 0;
            }

            Phase::Sending => {
                // Sending can span many ticks; keep the fanned net_in branch
                // drained throughout so foreign app frames don't back up and
                // stall the broadcast tee. Abort if our own connection closed.
                if drain_foreign_frames(s) {
                    s.send_metrics = false;
                    s.send_traces = false;
                    s.accum_len = 0;
                    s.accum_count = 0;
                    s.phase = Phase::Connecting;
                    return 0;
                }
                if pump_send(s) {
                    s.resp_reset();
                    // Arm the response timeout from when the request is fully sent.
                    s.resp_deadline_micros =
                        dev_micros(&*s.syscalls).wrapping_add(RESP_TIMEOUT_MICROS);
                    s.phase = Phase::WaitResponse;
                }
                return 2;
            }

            Phase::WaitResponse => {
                match read_response(s) {
                    Some(true) => {
                        s.posts_ok = s.posts_ok.wrapping_add(1);
                        if !s.connected {
                            // The response completed by closing the connection
                            // (close-delimited); reconnect before the next signal
                            // rather than POST against a cleared conn_id.
                            s.phase = Phase::Connecting;
                        } else if !kick_next_post(s) {
                            // Post the next signal of this batch, or idle if done.
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
                let sys = &*s.syscalls;
                if dev_micros(sys) < s.backoff_until_micros {
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
