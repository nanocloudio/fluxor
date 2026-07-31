// Contract: telemetry — observability signal envelope.
//
// Layer: contracts/telemetry (public, stable).
//
// Carried on a `Telemetry` content-type edge (CONTENT_TYPES, fluxor-contracts)
// from instrumented modules to the `observe` collector. Each record carries one
// metric or span signal. Logs ride `log_ring` separately; SIGNAL_LOG is
// reserved for a unified log stream.
//
// All multi-byte fields are little-endian. No strings on the wire: a metric or
// span references its name by a per-module `id` (interned at build time from the
// module's `[observability]` declarations); the collector resolves
// `(module, id) -> name` from the generated id-table. See
// `standards/observability.md`.
//
// The 12-byte header carries `signal` and `kind`, so a reader sizes the whole
// record from the header alone (`record_len`) before draining the body — the
// `Telemetry` edge is a byte FIFO, not a message channel.
//
//   header   [signal u8][kind u8][module u16][t_micros u64]
//   metric   [id u16][_rsvd u16][value u64]                  (scalar → 24 B)
//   metric   [id u16][_rsvd u16][bucket u64 × 8]             (histogram → 80 B)
//   span     [name_id u16][status u8][flags u8]
//            [trace_id 16][span_id 8][parent_id 8][start u64][end u64]  (→ 64 B)
//
// `flags` is the W3C trace-flags byte (low bit = `sampled`); it occupies what
// was a reserved byte, so the record size is unchanged.

// ── Signal discriminator (header[0]) ────────────────────────────────
pub const SIGNAL_LOG: u8 = 1; // reserved — logs ride log_ring
pub const SIGNAL_METRIC: u8 = 2;
pub const SIGNAL_SPAN: u8 = 3;

// ── Metric instrument kind (header[1] when signal == METRIC) ────────
pub const METRIC_COUNTER: u8 = 1;
pub const METRIC_UPDOWN: u8 = 2;
pub const METRIC_HISTOGRAM: u8 = 3;

// ── Span kind (header[1] when signal == SPAN; OpenTelemetry SpanKind) ─
pub const SPAN_INTERNAL: u8 = 0;
pub const SPAN_SERVER: u8 = 1;
pub const SPAN_CLIENT: u8 = 2;
pub const SPAN_PRODUCER: u8 = 3;
pub const SPAN_CONSUMER: u8 = 4;

// ── Span status (OpenTelemetry StatusCode) ──────────────────────────
pub const STATUS_UNSET: u8 = 0;
pub const STATUS_OK: u8 = 1;
pub const STATUS_ERROR: u8 = 2;

/// Number of histogram buckets (log2-spaced; matches the kernel step
/// histogram: <64, <128, <256, <512, <1024, <2048, <4096, >=4096 µs).
pub const HIST_BUCKETS: usize = 8;

// ── Layout ──────────────────────────────────────────────────────────
pub const HEADER_SIZE: usize = 12;
pub const METRIC_SCALAR_SIZE: usize = HEADER_SIZE + 12;
pub const METRIC_HIST_SIZE: usize = HEADER_SIZE + 4 + HIST_BUCKETS * 8;
pub const SPAN_SIZE: usize = HEADER_SIZE + 52;

/// W3C trace-context id widths.
pub const TRACE_ID_LEN: usize = 16;
pub const SPAN_ID_LEN: usize = 8;

/// W3C trace-flags `sampled` bit (low bit of the flags byte). The device does
/// no probabilistic sampling, so a minted root sets this; ingress-propagated
/// contexts carry whatever the caller decided.
pub const TRACE_FLAGS_SAMPLED: u8 = 0x01;

// ── UDP batch envelope (otel_udp_sample exporter → host collector) ──────
//
// The `otel_udp_sample` exporter forwards drained records verbatim, packed
// behind one envelope per UDP datagram:
//
//   [magic u32 = BATCH_MAGIC][version u8][_rsvd u8][count u16][record × count]
//
// Records are concatenated raw (each self-sizing via `record_len`), so the
// host walks them without per-record framing. `count` is advisory — a decoder
// that trusts the byte length can ignore it, but it catches truncation.
pub const BATCH_MAGIC: u32 = 0x4C54_5846; // b"FXTL" little-endian
pub const BATCH_VERSION: u8 = 1;
pub const BATCH_HEADER_SIZE: usize = 8;

/// Write the 8-byte batch envelope header. Returns its length, or `None` if
/// `buf` is too small.
pub fn write_batch_header(buf: &mut [u8], count: u16) -> Option<usize> {
    if buf.len() < BATCH_HEADER_SIZE {
        return None;
    }
    buf[0..4].copy_from_slice(&BATCH_MAGIC.to_le_bytes());
    buf[4] = BATCH_VERSION;
    buf[5] = 0;
    buf[6..8].copy_from_slice(&count.to_le_bytes());
    Some(BATCH_HEADER_SIZE)
}

pub fn batch_magic(buf: &[u8]) -> u32 {
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

pub fn batch_version(buf: &[u8]) -> u8 {
    buf[4]
}

pub fn batch_count(buf: &[u8]) -> u16 {
    u16::from_le_bytes([buf[6], buf[7]])
}

// Compile-time invariants — checked when the SDK compiles during module build.
const _: () = assert!(HEADER_SIZE == 12);
const _: () = assert!(METRIC_SCALAR_SIZE == 24);
const _: () = assert!(METRIC_HIST_SIZE == 80);
const _: () = assert!(SPAN_SIZE == 64);
const _: () = assert!(BATCH_HEADER_SIZE == 8);

/// Total record length for a `(signal, kind)` header pair, or 0 if the pair is
/// unrecognised. Lets a reader size a record from its header before draining.
pub fn record_len(signal: u8, kind: u8) -> usize {
    match signal {
        SIGNAL_METRIC if kind == METRIC_HISTOGRAM => METRIC_HIST_SIZE,
        SIGNAL_METRIC => METRIC_SCALAR_SIZE,
        SIGNAL_SPAN => SPAN_SIZE,
        _ => 0,
    }
}

// ── Header ──────────────────────────────────────────────────────────

/// Write the 12-byte header into `buf`. Returns the header length, or `None`
/// if `buf` is too small.
pub fn write_header(buf: &mut [u8], signal: u8, kind: u8, module: u16, t_micros: u64) -> Option<usize> {
    if buf.len() < HEADER_SIZE {
        return None;
    }
    buf[0] = signal;
    buf[1] = kind;
    buf[2..4].copy_from_slice(&module.to_le_bytes());
    buf[4..12].copy_from_slice(&t_micros.to_le_bytes());
    Some(HEADER_SIZE)
}

pub fn signal(buf: &[u8]) -> u8 {
    buf[0]
}

pub fn kind(buf: &[u8]) -> u8 {
    buf[1]
}

pub fn module(buf: &[u8]) -> u16 {
    u16::from_le_bytes([buf[2], buf[3]])
}

pub fn t_micros(buf: &[u8]) -> u64 {
    read_u64(buf, 4)
}

// ── Metric ──────────────────────────────────────────────────────────

/// Encode a scalar metric (counter / up-down) record. Returns the total record
/// length, or `None` if `buf` is too small.
pub fn write_metric_scalar(
    buf: &mut [u8],
    module: u16,
    t_micros: u64,
    kind: u8,
    id: u16,
    value: u64,
) -> Option<usize> {
    if buf.len() < METRIC_SCALAR_SIZE {
        return None;
    }
    write_header(buf, SIGNAL_METRIC, kind, module, t_micros)?;
    buf[12..14].copy_from_slice(&id.to_le_bytes());
    buf[14] = 0;
    buf[15] = 0;
    buf[16..24].copy_from_slice(&value.to_le_bytes());
    Some(METRIC_SCALAR_SIZE)
}

/// Encode a histogram metric record with `HIST_BUCKETS` log2-spaced counts.
pub fn write_metric_histogram(
    buf: &mut [u8],
    module: u16,
    t_micros: u64,
    id: u16,
    buckets: &[u64; HIST_BUCKETS],
) -> Option<usize> {
    if buf.len() < METRIC_HIST_SIZE {
        return None;
    }
    write_header(buf, SIGNAL_METRIC, METRIC_HISTOGRAM, module, t_micros)?;
    buf[12..14].copy_from_slice(&id.to_le_bytes());
    buf[14] = 0;
    buf[15] = 0;
    for (i, v) in buckets.iter().enumerate() {
        let off = 16 + i * 8;
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
    Some(METRIC_HIST_SIZE)
}

pub fn metric_id(buf: &[u8]) -> u16 {
    u16::from_le_bytes([buf[12], buf[13]])
}

pub fn metric_scalar_value(buf: &[u8]) -> u64 {
    read_u64(buf, 16)
}

// ── Span ────────────────────────────────────────────────────────────

/// A decoded W3C trace context plus span identity, used to encode a span body.
pub struct SpanContext {
    pub trace_id: [u8; TRACE_ID_LEN],
    pub span_id: [u8; SPAN_ID_LEN],
    pub parent_id: [u8; SPAN_ID_LEN],
    /// W3C trace-flags byte (low bit = `sampled`). See [`TRACE_FLAGS_SAMPLED`].
    pub flags: u8,
}

/// Encode a span record. Returns the total record length, or `None` if `buf` is
/// too small.
#[allow(
    clippy::too_many_arguments,
    reason = "a span record carries the full W3C context (trace/span/parent ids) plus timing as flat args to stay allocation-free on the emit path"
)]
pub fn write_span(
    buf: &mut [u8],
    module: u16,
    t_micros: u64,
    name_id: u16,
    span_kind: u8,
    status: u8,
    ctx: &SpanContext,
    start_micros: u64,
    end_micros: u64,
) -> Option<usize> {
    if buf.len() < SPAN_SIZE {
        return None;
    }
    write_header(buf, SIGNAL_SPAN, span_kind, module, t_micros)?;
    buf[12..14].copy_from_slice(&name_id.to_le_bytes());
    buf[14] = status;
    buf[15] = ctx.flags;
    buf[16..32].copy_from_slice(&ctx.trace_id);
    buf[32..40].copy_from_slice(&ctx.span_id);
    buf[40..48].copy_from_slice(&ctx.parent_id);
    buf[48..56].copy_from_slice(&start_micros.to_le_bytes());
    buf[56..64].copy_from_slice(&end_micros.to_le_bytes());
    Some(SPAN_SIZE)
}

pub fn span_name_id(buf: &[u8]) -> u16 {
    u16::from_le_bytes([buf[12], buf[13]])
}

pub fn span_status(buf: &[u8]) -> u8 {
    buf[14]
}

/// W3C trace-flags byte (low bit = `sampled`). See [`TRACE_FLAGS_SAMPLED`].
pub fn span_flags(buf: &[u8]) -> u8 {
    buf[15]
}

pub fn span_start_micros(buf: &[u8]) -> u64 {
    read_u64(buf, 48)
}

pub fn span_end_micros(buf: &[u8]) -> u64 {
    read_u64(buf, 56)
}

/// Copy the span's 16-byte trace id out of a record.
pub fn span_trace_id(buf: &[u8]) -> [u8; TRACE_ID_LEN] {
    let mut id = [0u8; TRACE_ID_LEN];
    id.copy_from_slice(&buf[16..32]);
    id
}

/// Copy the span's own 8-byte span id out of a record.
pub fn span_span_id(buf: &[u8]) -> [u8; SPAN_ID_LEN] {
    let mut id = [0u8; SPAN_ID_LEN];
    id.copy_from_slice(&buf[32..40]);
    id
}

/// Copy the span's 8-byte parent id out of a record (all-zero = root).
pub fn span_parent_id(buf: &[u8]) -> [u8; SPAN_ID_LEN] {
    let mut id = [0u8; SPAN_ID_LEN];
    id.copy_from_slice(&buf[40..48]);
    id
}

// ── W3C Trace Context ───────────────────────────────────────────────
//
// Ingress propagation: a producer (e.g. http) parses an incoming `traceparent`
// request header so its span joins the caller's trace. Format (version 00):
//   `00-<32hex trace-id>-<16hex parent-id>-<2hex flags>`  (55 bytes)
// The low bit of `flags` is `sampled`. On-device the context lives as the
// fixed-layout fields above; the ASCII form only appears at ingress/egress.

/// `sampled` bit of the trace-flags byte.
pub const TRACE_FLAG_SAMPLED: u8 = 0x01;

/// Parse a W3C `traceparent` header value. Returns
/// `(trace_id, parent_span_id, flags)`, or `None` if malformed, an unsupported
/// version, or an all-zero trace/span id (both forbidden by the spec).
///
/// Strict to W3C version `00`: the value must be EXACTLY 55 bytes and all hex
/// digits LOWERCASE (`decode_hex` / `hex_byte` reject uppercase). Trailing bytes
/// — which a later version might append — are rejected here because no later
/// version is defined.
pub fn parse_traceparent(s: &[u8]) -> Option<([u8; TRACE_ID_LEN], [u8; SPAN_ID_LEN], u8)> {
    if s.len() != 55 || s[2] != b'-' || s[35] != b'-' || s[52] != b'-' {
        return None;
    }
    if hex_byte(s[0], s[1])? != 0 {
        return None; // only version 00 is defined.
    }
    let mut trace_id = [0u8; TRACE_ID_LEN];
    decode_hex(&s[3..35], &mut trace_id)?;
    let mut span_id = [0u8; SPAN_ID_LEN];
    decode_hex(&s[36..52], &mut span_id)?;
    let flags = hex_byte(s[53], s[54])?;
    if trace_id.iter().all(|b| *b == 0) || span_id.iter().all(|b| *b == 0) {
        return None;
    }
    Some((trace_id, span_id, flags))
}

/// Lowercase-only hex digit decode. W3C `traceparent` mandates lowercase, so an
/// uppercase digit is a malformed header (rejected), not an alternate spelling.
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn hex_byte(hi: u8, lo: u8) -> Option<u8> {
    Some((hex_val(hi)? << 4) | hex_val(lo)?)
}

/// Decode `src` (must be exactly `2 * dst.len()` hex digits) into `dst`.
fn decode_hex(src: &[u8], dst: &mut [u8]) -> Option<()> {
    if src.len() != dst.len() * 2 {
        return None;
    }
    let mut i = 0;
    while i < dst.len() {
        dst[i] = hex_byte(src[i * 2], src[i * 2 + 1])?;
        i += 1;
    }
    Some(())
}

// ── helpers ─────────────────────────────────────────────────────────

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
