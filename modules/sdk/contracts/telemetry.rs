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
//   metric   [id u16][dim_id u16][value u64]                 (scalar → 24 B)
//   metric   [id u16][dim_id u16][bucket u64 × 8]            (histogram → 80 B)
//   metric   [id u16][dim_id u16][bucket u64 × 16]           (histogram16 → 144 B)
//   span     [name_id u16][status u8][flags u8]
//            [trace_id 16][span_id 8][parent_id 8][start u64][end u64]  (→ 64 B)
//
// `flags` is the W3C trace-flags byte (low bit = `sampled`).

// ── Signal discriminator (header[0]) ────────────────────────────────
pub const SIGNAL_LOG: u8 = 1; // reserved — logs ride log_ring
pub const SIGNAL_METRIC: u8 = 2;
pub const SIGNAL_SPAN: u8 = 3;
/// Kernel-produced per-module process status (step timing, arena, faults),
/// pushed to the telemetry ring on a cadence.
pub const SIGNAL_PSTATUS: u8 = 4;

// ── Process-status kind (header[1] when signal == PSTATUS) ───────────
/// Step timing: total step count + the kernel's native u32×8 step histogram.
pub const PSTATUS_STEP: u8 = 1;
/// Resource state: arena used/cap, fault count, flags.
pub const PSTATUS_RES: u8 = 2;
/// Resource-ledger pool state: capacity, in-use, peak, denials.
/// Pool ids and classes are the `resource` contract's registry.
pub const PSTATUS_POOL: u8 = 3;

// ── Syscall op numbers ────────── TLM_EMIT is an implicit primitive (any
// module, like LOG_WRITE); the consumer ops require the read-only `observe`
// permission. Kept out of the monitor range `0x0C52..=0x0C5F` (blanket
// monitor-gated).
/// Append one record to the telemetry ring (kernel stamps identity).
pub const TLM_EMIT: u32 = 0x0C3E;
/// Claim a drain slot with a filter word; returns the slot id (or negative).
pub const TLM_SUBSCRIBE: u32 = 0x0C4D;
/// Copy whole records from a slot into a buffer; advances the tail.
pub const TLM_DRAIN: u32 = 0x0C4E;
/// Ring head + per-slot lag/drop counters.
pub const TLM_STATS: u32 = 0x0C4F;

/// Consumer slots the ring exposes — the `TLM_STATS` reply is
/// `[head u32][dropped u32 × RING_CONSUMERS]`, so a caller sizes its buffer
/// and indexes its own slot from this. Mirror of
/// `kernel::sys::telemetry_ring::CONSUMERS`, pinned by `telemetry_ring.rs`'s
/// wire test.
pub const RING_CONSUMERS: usize = 4;
/// Byte length of a `TLM_STATS` reply.
pub const TLM_STATS_LEN: usize = 4 + RING_CONSUMERS * 4;

/// `TLM_SUBSCRIBE` arg layout: a 4-byte filter word, optionally followed by an
/// 8-byte LE PSTATUS cadence (ms) the subscriber wants the kernel to emit at.
/// Folding the cadence into subscribe avoids a separate op in the full
/// `0x0C4x` space; `0` / a 4-byte arg leaves the kernel default.
pub const SUBSCRIBE_INTERVAL_OFFSET: usize = 4;

// ── Reserved module identities (kernel-stamped) ─────────────── The kernel
// stamps the `module` header field at emit time so a module cannot forge
// another's identity. Two indices are reserved and never assigned to a real
// module: `UNATTRIBUTED` (emitted outside a step bracket — provider re-entry,
// host built-ins) and `KERNEL` (the kernel's own PSTATUS records).
pub const MODULE_UNATTRIBUTED: u16 = 0xFFFF;
pub const MODULE_KERNEL: u16 = 0xFFFE;

// ── Metric instrument kind (header[1] when signal == METRIC) ────────
pub const METRIC_COUNTER: u8 = 1;
pub const METRIC_UPDOWN: u8 = 2;
pub const METRIC_HISTOGRAM: u8 = 3;
/// 16-bucket histogram (15 declared bounds + implicit `+Inf`), for
/// distributions the 8-bucket ladder cannot resolve.
pub const METRIC_HISTOGRAM_16: u8 = 4;

// ── Metric dimension (bytes 14..16 of a metric body) ───── The row-major
// composite index over an instrument's DECLARED dimension domains (product
// ≤ 65534, enforced at build, so every index stays clear of the reserved
// `0xFFFF`). `0` is what an undimensioned instrument writes, and `0xFFFF` =
// `__other__`, the fold target for any tuple with a component outside its
// declared domain (folded and counted, never dropped, so totals stay
// correct).
pub const DIM_NONE: u16 = 0;
pub const DIM_OTHER: u16 = 0xFFFF;
/// Ceiling on the product of an instrument's declared domain sizes, so the
/// largest index it can produce stays below the reserved `DIM_OTHER`
/// (`DIM_NONE` overlaps index 0 of
/// an undimensioned instrument by construction).
pub const DIM_MAX_PRODUCT: u32 = 65534;

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
/// Bucket count of a `METRIC_HISTOGRAM_16` record: 15 per-instrument bounds
/// declared in the manifest (shipped to consumers via the id-table — bounds
/// are metadata, never sample data) plus the implicit `+Inf` bucket.
pub const HIST16_BUCKETS: usize = 16;

// ── Layout ──────────────────────────────────────────────────────────
pub const HEADER_SIZE: usize = 12;
pub const METRIC_SCALAR_SIZE: usize = HEADER_SIZE + 12;
pub const METRIC_HIST_SIZE: usize = HEADER_SIZE + 4 + HIST_BUCKETS * 8;
pub const METRIC_HIST16_SIZE: usize = HEADER_SIZE + 4 + HIST16_BUCKETS * 8;
pub const SPAN_SIZE: usize = HEADER_SIZE + 52;
/// PSTATUS step body: `[step_count u64][bucket u32 × 8]` (40 B → 52 total).
pub const PSTATUS_STEP_SIZE: usize = HEADER_SIZE + 8 + HIST_BUCKETS * 4;
/// PSTATUS resource body: `[arena_used u32][arena_cap u32][faults u32][flags u32]`
/// (16 B → 28 total).
pub const PSTATUS_RES_SIZE: usize = HEADER_SIZE + 16;
/// PSTATUS pool body: `[pool u16][class u8][_rsvd u8][cap u32][cur u32]
/// [peak u32][denials u32]` (20 B → 32 total). Units are the pool's own
/// (bytes for arenas, slots for tables — see the `resource` contract).
pub const PSTATUS_POOL_SIZE: usize = HEADER_SIZE + 20;
/// Largest record the ring must reserve atomically — a 16-bucket histogram
/// metric (144 B).
pub const MAX_RECORD_SIZE: usize = METRIC_HIST16_SIZE;

/// W3C trace-context id widths.
pub const TRACE_ID_LEN: usize = 16;
pub const SPAN_ID_LEN: usize = 8;

/// W3C trace-flags `sampled` bit (low bit of the flags byte). The device does
/// no probabilistic sampling, so a minted root sets this; ingress-propagated
/// contexts carry whatever the caller decided.
pub const TRACE_FLAGS_SAMPLED: u8 = 0x01;

// ── FXTL batch envelope (otel `fxtl-compact` → host collector) ─────────
//
// The `otel` engine forwards drained records verbatim, packed behind one
// envelope per flush (a `transport_buffer` sends each envelope as one datagram):
//
//   [magic u32 = BATCH_MAGIC][version u8][_rsvd u8][count u16][dropped u32]
//   [table_digest u32]
//   [record × count]
//
// Records are concatenated raw (each self-sizing via `record_len`), so the
// host walks them without per-record framing. `count` is advisory — a decoder
// that trusts the byte length can ignore it, but it catches truncation.
//
// `dropped` is the CUMULATIVE count of records the ring discarded for this
// consumer slot since boot — the export path's own fidelity, reported in-band.
// Cumulative rather than per-batch so the series is monotone: a lost datagram
// costs resolution, not truth, and the host recovers the gap by differencing.
// Without it a saturated exporter is indistinguishable from an idle one, which
// is precisely the failure this closes.
pub const BATCH_MAGIC: u32 = 0x4C54_5846; // b"FXTL" little-endian
pub const BATCH_VERSION: u8 = 1;
// 16: `table_digest` — the FNV-1a32 of the build-time
// id-table, injected as an `otel` param so a host collector can REFUSE to
// resolve names against a table from a different image instead of reporting
// wrong ones. `0` = no digest injected (collector may resolve, and should say
// it is unverified). This lands together with the first in-tree decoder
// (`fluxor-collect`), which ENDS the no-consumer exemption: any later
// envelope change is a real migration with deployed readers.
pub const BATCH_HEADER_SIZE: usize = 16;

/// Write the batch envelope header. Returns its length, or `None` if `buf` is
/// too small. `dropped` is the cumulative ring-drop count for the emitting
/// consumer slot (see the envelope comment above).
pub fn write_batch_header(
    buf: &mut [u8],
    count: u16,
    dropped: u32,
    table_digest: u32,
) -> Option<usize> {
    if buf.len() < BATCH_HEADER_SIZE {
        return None;
    }
    buf[0..4].copy_from_slice(&BATCH_MAGIC.to_le_bytes());
    buf[4] = BATCH_VERSION;
    buf[5] = 0;
    buf[6..8].copy_from_slice(&count.to_le_bytes());
    buf[8..12].copy_from_slice(&dropped.to_le_bytes());
    buf[12..16].copy_from_slice(&table_digest.to_le_bytes());
    Some(BATCH_HEADER_SIZE)
}

/// The id-table digest this batch's emitter was built with (`0` = none
/// injected — resolution is unverified, not wrong).
pub fn batch_table_digest(buf: &[u8]) -> u32 {
    u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]])
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

/// Cumulative records dropped by the ring for the emitting consumer slot.
/// Difference successive batches for the per-interval loss.
pub fn batch_dropped(buf: &[u8]) -> u32 {
    u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]])
}

// Compile-time invariants — checked when the SDK compiles during module build.
const _: () = assert!(HEADER_SIZE == 12);
const _: () = assert!(METRIC_SCALAR_SIZE == 24);
const _: () = assert!(METRIC_HIST_SIZE == 80);
const _: () = assert!(METRIC_HIST16_SIZE == 144);
const _: () = assert!(SPAN_SIZE == 64);
const _: () = assert!(PSTATUS_STEP_SIZE == 52);
const _: () = assert!(PSTATUS_RES_SIZE == 28);
const _: () = assert!(PSTATUS_POOL_SIZE == 32);
const _: () = assert!(MAX_RECORD_SIZE == 144);
const _: () = assert!(BATCH_HEADER_SIZE == 16);

/// Total record length for a `(signal, kind)` header pair, or 0 if the pair is
/// unrecognised. Lets a reader size a record from its header before draining.
pub fn record_len(signal: u8, kind: u8) -> usize {
    match signal {
        SIGNAL_METRIC if kind == METRIC_HISTOGRAM => METRIC_HIST_SIZE,
        SIGNAL_METRIC if kind == METRIC_HISTOGRAM_16 => METRIC_HIST16_SIZE,
        SIGNAL_METRIC => METRIC_SCALAR_SIZE,
        SIGNAL_SPAN => SPAN_SIZE,
        SIGNAL_PSTATUS if kind == PSTATUS_STEP => PSTATUS_STEP_SIZE,
        SIGNAL_PSTATUS if kind == PSTATUS_RES => PSTATUS_RES_SIZE,
        SIGNAL_PSTATUS if kind == PSTATUS_POOL => PSTATUS_POOL_SIZE,
        _ => 0,
    }
}

// ── Per-slot drain filter ──────── A subscribe-time filter word: a
// signal-type mask in the low bits plus a span sample-shift (keep 1-in-2^n
// spans) in the high byte. Applied at drain time on the header, so records are
// never duplicated per consumer.
pub const FILTER_METRIC: u32 = 1 << 0;
pub const FILTER_SPAN: u32 = 1 << 1;
pub const FILTER_PSTATUS: u32 = 1 << 2;
/// Mask selecting all signal types — the default "take everything" filter.
pub const FILTER_ALL: u32 = FILTER_METRIC | FILTER_SPAN | FILTER_PSTATUS;
/// Span sample-shift lives in bits 24..32: keep 1-in-2^shift spans.
pub const FILTER_SPAN_SHIFT_POS: u32 = 24;

/// Does a record with this `(signal, kind)` pass `filter`? Kind is unused today
/// (the mask is per-signal) but kept in the signature for forward room.
pub fn filter_admits(filter: u32, signal: u8, _kind: u8) -> bool {
    let bit = match signal {
        SIGNAL_METRIC => FILTER_METRIC,
        SIGNAL_SPAN => FILTER_SPAN,
        SIGNAL_PSTATUS => FILTER_PSTATUS,
        _ => 0,
    };
    filter & bit != 0
}

// ── Export delivery status (otel `delivery` backchannel) ─────── One byte per
// batch, reported by a transport carrier back to `otel` so it can
// retain/retry. Fire-and-forget carriers (UDP/UART) never send one.
pub const DELIVERY_DELIVERED: u8 = 0;
pub const DELIVERY_RETRY: u8 = 1; // transient — connect fail, 429/503, timeout
pub const DELIVERY_DROP: u8 = 2; // permanent — other 4xx

// ── Export encoding selector (otel `encoding` param) ───────────
pub const ENCODING_OTLP_JSON: u8 = 0;
pub const ENCODING_OTLP_PROTO: u8 = 1;
pub const ENCODING_FXTL_COMPACT: u8 = 2;

// ── Header ──────────────────────────────────────────────────────────

/// Write the 12-byte header into `buf`. Returns the header length, or `None`
/// if `buf` is too small.
pub fn write_header(
    buf: &mut [u8],
    signal: u8,
    kind: u8,
    module: u16,
    t_micros: u64,
) -> Option<usize> {
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
/// length, or `None` if `buf` is too small. Emits `DIM_NONE` — the
/// dimensioned form is [`write_metric_scalar_dim`].
pub fn write_metric_scalar(
    buf: &mut [u8],
    module: u16,
    t_micros: u64,
    kind: u8,
    id: u16,
    value: u64,
) -> Option<usize> {
    write_metric_scalar_dim(buf, module, t_micros, kind, id, DIM_NONE, value)
}

/// Encode a scalar metric record carrying a composite dimension
/// index. `dim` is the row-major index over the instrument's declared
/// domains; `DIM_NONE` for an undimensioned instrument, `DIM_OTHER`
/// for a tuple that fell outside them.
pub fn write_metric_scalar_dim(
    buf: &mut [u8],
    module: u16,
    t_micros: u64,
    kind: u8,
    id: u16,
    dim: u16,
    value: u64,
) -> Option<usize> {
    if buf.len() < METRIC_SCALAR_SIZE {
        return None;
    }
    write_header(buf, SIGNAL_METRIC, kind, module, t_micros)?;
    buf[12..14].copy_from_slice(&id.to_le_bytes());
    buf[14..16].copy_from_slice(&dim.to_le_bytes());
    buf[16..24].copy_from_slice(&value.to_le_bytes());
    Some(METRIC_SCALAR_SIZE)
}

/// Encode a histogram metric record with `HIST_BUCKETS` log2-spaced counts.
/// Emits `DIM_NONE`; the dimensioned/16-bucket forms are below.
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
    buf[14..16].copy_from_slice(&DIM_NONE.to_le_bytes());
    for (i, v) in buckets.iter().enumerate() {
        let off = 16 + i * 8;
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
    Some(METRIC_HIST_SIZE)
}

/// Encode a 16-bucket histogram record (`METRIC_HISTOGRAM_16`): cumulative
/// counts against the instrument's 15 declared bounds plus `+Inf`, with a
/// composite dimension index (`DIM_NONE` when undimensioned).
pub fn write_metric_histogram16(
    buf: &mut [u8],
    module: u16,
    t_micros: u64,
    id: u16,
    dim: u16,
    buckets: &[u64; HIST16_BUCKETS],
) -> Option<usize> {
    if buf.len() < METRIC_HIST16_SIZE {
        return None;
    }
    write_header(buf, SIGNAL_METRIC, METRIC_HISTOGRAM_16, module, t_micros)?;
    buf[12..14].copy_from_slice(&id.to_le_bytes());
    buf[14..16].copy_from_slice(&dim.to_le_bytes());
    for (i, v) in buckets.iter().enumerate() {
        let off = 16 + i * 8;
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
    Some(METRIC_HIST16_SIZE)
}

pub fn metric_id(buf: &[u8]) -> u16 {
    u16::from_le_bytes([buf[12], buf[13]])
}

/// The composite dimension index of a metric record (`DIM_NONE` when the
/// instrument is undimensioned).
pub fn metric_dim(buf: &[u8]) -> u16 {
    u16::from_le_bytes([buf[14], buf[15]])
}

/// Bucket count for a histogram record's `kind`, or 0 for a scalar kind.
pub fn hist_bucket_count(kind: u8) -> usize {
    match kind {
        METRIC_HISTOGRAM => HIST_BUCKETS,
        METRIC_HISTOGRAM_16 => HIST16_BUCKETS,
        _ => 0,
    }
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

// ── Process status (PSTATUS) ────────────────────────────────────────
//
// Kernel-produced per-module status, pushed to the ring on a cadence.
// `STEP` carries the module's step count
// and the kernel's native u32×8 step-time histogram (the `MON_HIST` source);
// `RES` carries arena + fault state. Body layouts (after the 12-byte header):
//   STEP: `[step_count u64][bucket u32 × 8]`  (offsets 12, 20..52)
//   RES:  `[arena_used u32][arena_cap u32][faults u32][flags u32]`  (12..28)

/// Encode a PSTATUS `STEP` record: total step count + the u32×8 step histogram.
pub fn write_pstatus_step(
    buf: &mut [u8],
    module: u16,
    t_micros: u64,
    step_count: u64,
    buckets: &[u32; HIST_BUCKETS],
) -> Option<usize> {
    if buf.len() < PSTATUS_STEP_SIZE {
        return None;
    }
    write_header(buf, SIGNAL_PSTATUS, PSTATUS_STEP, module, t_micros)?;
    buf[12..20].copy_from_slice(&step_count.to_le_bytes());
    for (i, v) in buckets.iter().enumerate() {
        let off = 20 + i * 4;
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    Some(PSTATUS_STEP_SIZE)
}

/// Encode a PSTATUS `RES` record: arena used/cap, fault count, and a flags word.
pub fn write_pstatus_res(
    buf: &mut [u8],
    module: u16,
    t_micros: u64,
    arena_used: u32,
    arena_cap: u32,
    faults: u32,
    flags: u32,
) -> Option<usize> {
    if buf.len() < PSTATUS_RES_SIZE {
        return None;
    }
    write_header(buf, SIGNAL_PSTATUS, PSTATUS_RES, module, t_micros)?;
    buf[12..16].copy_from_slice(&arena_used.to_le_bytes());
    buf[16..20].copy_from_slice(&arena_cap.to_le_bytes());
    buf[20..24].copy_from_slice(&faults.to_le_bytes());
    buf[24..28].copy_from_slice(&flags.to_le_bytes());
    Some(PSTATUS_RES_SIZE)
}

/// PSTATUS `STEP`: total step count.
pub fn pstatus_step_count(buf: &[u8]) -> u64 {
    read_u64(buf, 12)
}

/// PSTATUS `STEP`: histogram bucket `i` (0..`HIST_BUCKETS`).
pub fn pstatus_step_bucket(buf: &[u8], i: usize) -> u32 {
    read_u32(buf, 20 + i * 4)
}

/// PSTATUS `RES`: arena bytes in use.
pub fn pstatus_res_arena_used(buf: &[u8]) -> u32 {
    read_u32(buf, 12)
}

/// PSTATUS `RES`: arena capacity in bytes.
pub fn pstatus_res_arena_cap(buf: &[u8]) -> u32 {
    read_u32(buf, 16)
}

/// PSTATUS `RES`: cumulative fault count.
pub fn pstatus_res_faults(buf: &[u8]) -> u32 {
    read_u32(buf, 20)
}

/// PSTATUS `RES`: status flags word.
pub fn pstatus_res_flags(buf: &[u8]) -> u32 {
    read_u32(buf, 24)
}

/// Encode a PSTATUS `POOL` record: one resource-ledger pool's state.
#[expect(
    clippy::too_many_arguments,
    reason = "wire-record encoder; the argument list mirrors the record's field layout"
)]
pub fn write_pstatus_pool(
    buf: &mut [u8],
    module: u16,
    t_micros: u64,
    pool: u16,
    class: u8,
    cap: u32,
    cur: u32,
    peak: u32,
    denials: u32,
) -> Option<usize> {
    if buf.len() < PSTATUS_POOL_SIZE {
        return None;
    }
    write_header(buf, SIGNAL_PSTATUS, PSTATUS_POOL, module, t_micros)?;
    buf[12..14].copy_from_slice(&pool.to_le_bytes());
    buf[14] = class;
    buf[15] = 0;
    buf[16..20].copy_from_slice(&cap.to_le_bytes());
    buf[20..24].copy_from_slice(&cur.to_le_bytes());
    buf[24..28].copy_from_slice(&peak.to_le_bytes());
    buf[28..32].copy_from_slice(&denials.to_le_bytes());
    Some(PSTATUS_POOL_SIZE)
}

/// PSTATUS `POOL`: pool id (the `resource` contract's registry).
pub fn pstatus_pool_id(buf: &[u8]) -> u16 {
    u16::from_le_bytes([buf[12], buf[13]])
}

/// PSTATUS `POOL`: resource class (`resource::CLASS_*`).
pub fn pstatus_pool_class(buf: &[u8]) -> u8 {
    buf[14]
}

/// PSTATUS `POOL`: capacity in the pool's own units.
pub fn pstatus_pool_cap(buf: &[u8]) -> u32 {
    read_u32(buf, 16)
}

/// PSTATUS `POOL`: units currently in use.
pub fn pstatus_pool_cur(buf: &[u8]) -> u32 {
    read_u32(buf, 20)
}

/// PSTATUS `POOL`: high-water mark of `cur`.
pub fn pstatus_pool_peak(buf: &[u8]) -> u32 {
    read_u32(buf, 24)
}

/// PSTATUS `POOL`: cumulative denied requests.
pub fn pstatus_pool_denials(buf: &[u8]) -> u32 {
    read_u32(buf, 28)
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

fn read_u32(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
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
