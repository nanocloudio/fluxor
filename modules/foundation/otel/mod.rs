//! OTEL export engine — the telemetry-ring consumer that batches records and
//! emits them on `export` for a transport-blind carrier to deliver.
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
//! **Params (TLV v2):** tag 3 `flush_ms` (u32, default 1000) — max wall-clock
//! a partial batch waits before it is flushed; tag 4 `encoding` (u8, default 2
//! = `fxtl-compact`; 0 = `otlp-json`, 1 = `otlp-proto`); tag 5 `table_digest`
//! (u32, default 0) — the build-time id-table digest, injected by the config
//! builder and stamped into every FXTL batch envelope.

#![cfg_attr(not(feature = "host-test"), no_std)]
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
include!("../../sdk/runtime/params.rs");

use abi::contracts::telemetry as tlm;

/// OTLP/JSON encoder core — the reusable `cores/otlp_json` implementation,
/// `include!`d verbatim so this module and the host tests compile the same bytes.
/// Variant-gated (`[[variant]]` in the manifest): the `min` build ships the
/// `fxtl-compact` path only — no OTLP encoder in flash — and refuses an OTLP
/// `encoding` param at `module_new` rather than silently falling back. Host
/// tests always compile the full surface.
#[cfg(any(feature = "otlp", feature = "host-test"))]
mod otlp {
    include!("../../sdk/cores/otlp_json.rs");
}

/// OTLP/protobuf encoder core — the binary sibling of `otlp`, for the
/// `otlp-proto` encoding (a gRPC/HTTP client posts these bytes to `/v1/metrics`).
#[cfg(any(feature = "otlp", feature = "host-test"))]
mod otlp_pb {
    include!("../../sdk/cores/otlp_proto.rs");
}

/// Raw records staged between flushes.
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
#[cfg(any(feature = "otlp", feature = "host-test"))]
#[cfg(target_arch = "aarch64")]
const JSON_MAX: usize = FRAME_HDR + 10240;
#[cfg(any(feature = "otlp", feature = "host-test"))]
#[cfg(not(target_arch = "aarch64"))]
const JSON_MAX: usize = FRAME_HDR + 4096;

/// Bounds-table capacity: rows (instruments with declared bounds in this
/// graph, injected at build) × per-row bound count (15 for histogram16;
/// a histogram row carries 7 and zero-fills the rest).
const BOUNDS_ROWS: usize = 8;
const BOUNDS_MAX: usize = 15;
/// Decoded bounds blob at full table capacity: `[count u8]` then per row
/// `[module u16][id u16][nbounds u8][bound_us u32 × BOUNDS_MAX]`.
const BOUNDS_BLOB_MAX: usize = 1 + BOUNDS_ROWS * (5 + 4 * BOUNDS_MAX);
/// The blob's hex text, as the `bounds` param carries it.
const BOUNDS_HEX_MAX: usize = 2 * BOUNDS_BLOB_MAX;

#[repr(C)]
struct OtelState {
    syscalls: *const SyscallTable,
    /// Ring drain slot from `TLM_SUBSCRIBE` (`-1` = not subscribed).
    tlm_slot: i32,
    /// `export` output channel.
    export_chan: i32,
    /// `delivery` input channel (`-1` = unwired → fire-and-forget). When wired,
    /// otel runs in reliable mode: it retains the flushed batch (the `accum`
    /// records) until the carrier acks it, resending on `RETRY`.
    delivery_chan: i32,
    /// Flush cadence (ms) and the wall-clock micros of the last flush.
    flush_ms: u32,
    /// Build-injected id-table digest, stamped into every FXTL batch
    /// envelope so the host collector can refuse a mismatched table. `0` =
    /// not injected (unverified resolution).
    table_digest: u32,
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
    /// into the batch envelope. Held across flushes so a retained/resent
    /// batch reports the value that was true when it was built.
    dropped: u32,
    /// Build-injected per-instrument histogram bounds (µs), keyed by
    /// `(module, id)` — the on-device slice of the id-table: lets the OTLP
    /// encoders emit `histogram16` records with their DECLARED bounds instead
    /// of skipping them. Zero rows = nothing injected; hist16 records are
    /// then skipped by the on-device encodings (the fxtl path always carries
    /// them for the host collector). One-shot: an OTLP encoding met a batch
    /// with NOTHING it can encode (only skipped record kinds — e.g. hist16
    /// without injected bounds, or PSTATUS). Such a batch is DISCARDED, not
    /// retained: retaining it pins the accumulator forever and wedges the
    /// whole export — the silent-stall class this exists to kill. Logged
    /// once;
    /// after that the discard is routine.
    unencodable_warned: u8,
    bounds_rows: u8,
    bounds_mod: [u16; BOUNDS_ROWS],
    bounds_id: [u16; BOUNDS_ROWS],
    bounds_n: [u8; BOUNDS_ROWS],
    bounds_us: [[u32; BOUNDS_MAX]; BOUNDS_ROWS],
    /// The `bounds` param's hex text as received. It arrives as TLV entries
    /// of at most 255 bytes, so chunk boundaries fall mid-byte; the text is
    /// kept whole and the table decoded from the start after each chunk.
    bounds_hex: [u8; BOUNDS_HEX_MAX],
    bounds_hex_len: u16,
    accum_len: u16,
    accum: [u8; ACCUM_MAX],
    out: [u8; OUT_MAX],
    /// OTLP document build buffer — variant-gated with the encoders, so the
    /// `min` build's state arena does not pay for a document it cannot build.
    #[cfg(any(feature = "otlp", feature = "host-test"))]
    json: [u8; JSON_MAX],
}

impl OtelState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.tlm_slot = -1;
        self.export_chan = -1;
        self.delivery_chan = -1;
        self.flush_ms = 1000;
        self.table_digest = 0;
        self.unencodable_warned = 0;
        self.bounds_rows = 0;
        self.bounds_mod = [0; BOUNDS_ROWS];
        self.bounds_id = [0; BOUNDS_ROWS];
        self.bounds_n = [0; BOUNDS_ROWS];
        self.bounds_us = [[0; BOUNDS_MAX]; BOUNDS_ROWS];
        self.bounds_hex_len = 0;
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
        5, table_digest, u32, 0 => |s, d, len| { s.table_digest = p_u32(d, len, 0, 0); };
        // Hex text of `[count u8]` then per row
        // `[module u16 LE][id u16 LE][nbounds u8][bound_us u32 LE × nbounds]`,
        // injected by the config builder from the graph's id-table. The
        // builder splits it across TLV entries of at most 255 bytes under
        // this tag; each chunk is appended and the whole text decoded again
        // from the start, so a nibble straddling a chunk boundary completes
        // when the next chunk lands. A row that does not fit is dropped
        // whole (the encoder then skips that instrument — degraded, never
        // wrong).
        6, bounds, str_chunked, 0 => |s, d, len| {
            let have = s.bounds_hex_len as usize;
            let n = len.min(super::BOUNDS_HEX_MAX - have);
            let mut i = 0usize;
            while i < n {
                s.bounds_hex[have + i] = *d.add(i);
                i += 1;
            }
            s.bounds_hex_len = (have + n) as u16;

            let mut raw = [0u8; super::BOUNDS_BLOB_MAX];
            let mut rn = 0usize;
            let mut i = 0usize;
            while i + 1 < have + n {
                let hi = super::hex_nibble(s.bounds_hex[i]);
                let lo = super::hex_nibble(s.bounds_hex[i + 1]);
                let (Some(hi), Some(lo)) = (hi, lo) else { break };
                raw[rn] = (hi << 4) | lo;
                rn += 1;
                i += 2;
            }
            super::parse_bounds_blob(s, &raw[..rn]);
        };
    }
}

/// One hex nibble, or `None` for a non-hex byte (stops the blob parse).
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode the injected bounds blob into the state table, rebuilding it from
/// row 0. Malformed tails are dropped whole — a half-read row would attach
/// wrong bounds to an id.
fn parse_bounds_blob(s: &mut OtelState, raw: &[u8]) {
    s.bounds_rows = 0;
    let Some(&count) = raw.first() else { return };
    let mut off = 1usize;
    let mut row = 0usize;
    while row < (count as usize).min(BOUNDS_ROWS) {
        if off + 5 > raw.len() {
            return;
        }
        let module = u16::from_le_bytes([raw[off], raw[off + 1]]);
        let id = u16::from_le_bytes([raw[off + 2], raw[off + 3]]);
        let n = raw[off + 4] as usize;
        off += 5;
        if n > BOUNDS_MAX || off + n * 4 > raw.len() {
            return;
        }
        for k in 0..n {
            let b = off + k * 4;
            s.bounds_us[row][k] = u32::from_le_bytes([raw[b], raw[b + 1], raw[b + 2], raw[b + 3]]);
        }
        s.bounds_mod[row] = module;
        s.bounds_id[row] = id;
        s.bounds_n[row] = n as u8;
        off += n * 4;
        row += 1;
        s.bounds_rows = row as u8;
    }
}

/// Copyable view of the bounds table, so the encode fns can take it alongside
/// a `&mut` borrow of the output buffer (disjoint from the state fields).
#[derive(Clone, Copy)]
struct BoundsView<'a> {
    rows: u8,
    modules: &'a [u16; BOUNDS_ROWS],
    ids: &'a [u16; BOUNDS_ROWS],
    ns: &'a [u8; BOUNDS_ROWS],
    us: &'a [[u32; BOUNDS_MAX]; BOUNDS_ROWS],
}

impl<'a> BoundsView<'a> {
    fn of(s: &'a OtelState) -> Self {
        BoundsView {
            rows: s.bounds_rows,
            modules: &s.bounds_mod,
            ids: &s.bounds_id,
            ns: &s.bounds_n,
            us: &s.bounds_us,
        }
    }

    /// Declared bounds (µs, ascending) for `(module, id)`, or `None`.
    fn find(&self, module: u16, id: u16) -> Option<&'a [u32]> {
        let mut r = 0usize;
        while r < self.rows as usize {
            if self.modules[r] == module && self.ids[r] == id {
                return Some(&self.us[r][..self.ns[r] as usize]);
            }
            r += 1;
        }
        None
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
#[cfg(any(feature = "otlp", feature = "host-test"))]
fn encode_metrics_json(accum: &[u8], json: &mut [u8], bounds: BoundsView<'_>) -> usize {
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
            let dim = tlm::metric_dim(rec);
            let t_nanos = tlm::t_micros(rec).wrapping_mul(1000);
            let n = synthetic_name(module, id, &mut namebuf);
            let name = &namebuf[..n];
            if kind == tlm::METRIC_HISTOGRAM {
                // Histogram body: buckets are 8×u64 at offset 16 (after the
                // 12-byte header + id u16 + dim u16).
                let mut buckets = [0u64; tlm::HIST_BUCKETS];
                for (i, b) in buckets.iter_mut().enumerate() {
                    let base = 16 + i * 8;
                    let mut v = [0u8; 8];
                    v.copy_from_slice(&rec[base..base + 8]);
                    *b = u64::from_le_bytes(v);
                }
                // A declared per-instrument ladder (build-injected bounds
                // param) overrides the fixed one.
                let mut b64 = [0u64; BOUNDS_MAX];
                let eb: &[u64] = match bounds.find(module, id) {
                    Some(us) if us.len() == tlm::HIST_BUCKETS - 1 => {
                        for (k, v) in us.iter().enumerate() {
                            b64[k] = *v as u64;
                        }
                        &b64[..us.len()]
                    }
                    _ => &otlp::HIST_BOUNDS_US,
                };
                doc.histogram_bounded(name, module, dim, t_nanos, &buckets, eb);
            } else if kind == tlm::METRIC_HISTOGRAM_16 {
                // hist16 bounds are per-instrument id-table metadata. When the
                // build injected them (`bounds` param, the on-device
                // slice) the record encodes with its DECLARED ladder; without
                // them it is skipped — a made-up ladder would be unsound. The
                // fxtl-compact path always forwards it verbatim for the host
                // collector.
                if let Some(us) = bounds.find(module, id) {
                    if us.len() == tlm::HIST16_BUCKETS - 1 {
                        let mut buckets = [0u64; tlm::HIST16_BUCKETS];
                        for (i, b) in buckets.iter_mut().enumerate() {
                            let base = 16 + i * 8;
                            let mut v = [0u8; 8];
                            v.copy_from_slice(&rec[base..base + 8]);
                            *b = u64::from_le_bytes(v);
                        }
                        let mut b64 = [0u64; BOUNDS_MAX];
                        for (k, v) in us.iter().enumerate() {
                            b64[k] = *v as u64;
                        }
                        doc.histogram_bounded(
                            name,
                            module,
                            dim,
                            t_nanos,
                            &buckets,
                            &b64[..us.len()],
                        );
                    }
                }
            } else {
                let value = tlm::metric_scalar_value(rec);
                doc.sum_dim(
                    name,
                    module,
                    dim,
                    t_nanos,
                    value,
                    kind == tlm::METRIC_COUNTER,
                );
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
#[cfg(any(feature = "otlp", feature = "host-test"))]
fn encode_metrics_proto(accum: &[u8], out: &mut [u8], bounds: BoundsView<'_>) -> usize {
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
            let dim = tlm::metric_dim(rec);
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
                let mut bits = [0u64; BOUNDS_MAX];
                let eb: &[u64] = match bounds.find(module, id) {
                    Some(us) if us.len() == tlm::HIST_BUCKETS - 1 => {
                        for (k, v) in us.iter().enumerate() {
                            bits[k] = otlp_pb::f64_bits_from_u64(*v as u64);
                        }
                        &bits[..us.len()]
                    }
                    _ => &otlp_pb::HIST_BOUNDS_BITS,
                };
                doc.histogram_bounded(name, module, dim, t_nanos, &buckets, eb);
            } else if kind == tlm::METRIC_HISTOGRAM_16 {
                // Same contract as the JSON path: declared bounds when
                // injected, skip otherwise.
                if let Some(us) = bounds.find(module, id) {
                    if us.len() == tlm::HIST16_BUCKETS - 1 {
                        let mut buckets = [0u64; tlm::HIST16_BUCKETS];
                        for (i, b) in buckets.iter_mut().enumerate() {
                            let base = 16 + i * 8;
                            let mut v = [0u8; 8];
                            v.copy_from_slice(&rec[base..base + 8]);
                            *b = u64::from_le_bytes(v);
                        }
                        let mut bits = [0u64; BOUNDS_MAX];
                        for (k, v) in us.iter().enumerate() {
                            bits[k] = otlp_pb::f64_bits_from_u64(*v as u64);
                        }
                        doc.histogram_bounded(
                            name,
                            module,
                            dim,
                            t_nanos,
                            &buckets,
                            &bits[..us.len()],
                        );
                    }
                }
            } else {
                let value = tlm::metric_scalar_value(rec);
                doc.sum_dim(
                    name,
                    module,
                    dim,
                    t_nanos,
                    value,
                    kind == tlm::METRIC_COUNTER,
                );
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
    // TLM_DRAIN copies as many WHOLE records as fit in the offered room, so
    // the gate only needs to clear the SMALLEST record (a 24 B scalar), not
    // MAX_RECORD_SIZE — gating on the maximum reserved a full 144 B of every
    // batch for a record kind most graphs never emit (on rp2040's 512 B
    // accumulator that is 28% of the batch). If the record at the ring head is
    // larger than `room`, the kernel copies nothing and the size-triggered
    // flush below clears the accumulator — no stall either way.
    if room >= tlm::METRIC_SCALAR_SIZE {
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
    #[cfg(any(feature = "otlp", feature = "host-test"))]
    if s.encoding == tlm::ENCODING_OTLP_JSON || s.encoding == tlm::ENCODING_OTLP_PROTO {
        // On-device OTLP metrics document (JSON or protobuf) → carrier posts it
        // as the request body. Early-return so the fxtl path below stays the
        // unconditional tail — the `min` variant compiles this block away and
        // `module_new` has already refused an OTLP encoding there.
        let bv = BoundsView {
            rows: s.bounds_rows,
            modules: &s.bounds_mod,
            ids: &s.bounds_id,
            ns: &s.bounds_n,
            us: &s.bounds_us,
        };
        let n = if s.encoding == tlm::ENCODING_OTLP_PROTO {
            encode_metrics_proto(&s.accum[..used], &mut s.json[FRAME_HDR..], bv)
        } else {
            encode_metrics_json(&s.accum[..used], &mut s.json[FRAME_HDR..], bv)
        };
        if n == 0 {
            // Nothing in this batch is encodable under this encoding. Keeping
            // it would pin `accum` and wedge the export permanently (drain
            // refuses a full accumulator; flush can never clear it), so the
            // batch is dropped whole — loudly, once.
            if s.unencodable_warned == 0 {
                s.unencodable_warned = 1;
                let msg = b"[otel] batch had no OTLP-encodable records; discarded (check hist16 bounds injection)";
                dev_log(sys, 2, msg.as_ptr(), msg.len());
            }
            s.accum_len = 0;
            return false;
        }
        write_frame_header(&mut s.json, n);
        return (sys.channel_write)(s.export_chan, s.json.as_ptr(), FRAME_HDR + n)
            == (FRAME_HDR + n) as i32;
    }
    // Compact FXTL: the raw record batch a host collector decodes.
    let count = record_count(&s.accum[..used]);
    let Some(hdr) =
        tlm::write_batch_header(&mut s.out[FRAME_HDR..], count, s.dropped, s.table_digest)
    else {
        return false;
    };
    s.out[FRAME_HDR + hdr..FRAME_HDR + hdr + used].copy_from_slice(&s.accum[..used]);
    let payload = hdr + used;
    write_frame_header(&mut s.out, payload);
    (sys.channel_write)(s.export_chan, s.out.as_ptr(), FRAME_HDR + payload)
        == (FRAME_HDR + payload) as i32
}

unsafe fn step_flush(s: &mut OtelState) {
    // While a batch is in flight (reliable mode), the cadence flush is
    // suppressed — resends are driven by delivery acks, not the clock.
    if s.accum_len == 0 || s.awaiting_ack {
        return;
    }
    let sys = &*s.syscalls;
    let now = dev_micros(sys);
    // Two triggers: the cadence, and a full accumulator. Without the size
    // trigger a burst that fills `accum` stalls `step_drain` (which refuses
    // to drain into less than one whole record of room) until the timer
    // fires, pushing the overflow back onto the ring to be dropped.
    // Flushing when full decouples burst capacity from cadence and leaves
    // `flush_ms` a pure freshness knob.
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

/// Reliable mode: consume delivery-status frames from the carrier and act on
/// the retained batch. Frame = `[msg_type][len: u16 LE][status: u8]` where
/// status is `DELIVERY_DELIVERED`/`RETRY`/`DROP`. DELIVERED/DROP clear the
/// retained batch and resume draining; RETRY resends it within the resend
/// budget.
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
        // Variant fail-closed: a `min` build carries no OTLP encoder, so a
        // graph that selects an OTLP `encoding` against it must fault at
        // instantiation — loudly, at bring-up — never silently export
        // fxtl-compact bytes a JSON/protobuf sink cannot take.
        #[cfg(not(any(feature = "otlp", feature = "host-test")))]
        if s.encoding != tlm::ENCODING_FXTL_COMPACT {
            return -7;
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
