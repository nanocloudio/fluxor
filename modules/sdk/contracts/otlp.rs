// Contract: otlp — OTLP/JSON encoder for the metric signal.
//
// Layer: contracts/otlp (public, stable).
//
// Produces OpenTelemetry Protocol JSON (`application/json`, the OTLP/HTTP JSON
// encoding) for metrics, built incrementally into a caller-owned byte buffer —
// `no_std`, allocation-free, division-free (PIC link-trap safe). The
// `otlp_http` exporter wraps the output in an HTTP/1.1 POST to `/v1/metrics`.
//
// Shape (flat — one resource, one scope, repeated metric entries; a collector
// merges same-name metrics):
//
//   {"resourceMetrics":[{
//     "resource":{"attributes":[{"key":"service.name",
//                                "value":{"stringValue":"<svc>"}}]},
//     "scopeMetrics":[{"scope":{"name":"fluxor"},"metrics":[ <metric>, … ]}]}]}
//
// Each metric carries the producing module index as a `fluxor.module.index` data-point
// attribute, so a collector keeps per-module series without the device grouping
// them. `timeUnixNano` is the device's best-effort monotonic micros×1000 — not
// epoch-anchored; a collector re-stamps or the device syncs time upstream.

/// Explicit histogram bucket upper bounds (µs), matching the telemetry
/// histogram's log2 spacing: <64, <128, …, <4096, >=4096. Seven bounds delimit
/// eight buckets.
pub const HIST_BOUNDS_US: [u64; 7] = [64, 128, 256, 512, 1024, 2048, 4096];

/// Shared incremental writer over a fixed buffer: appends bytes, decimals, hex,
/// and JSON-escaped strings, latching `ok = false` on any overflow so a caller
/// detects truncation once at `finish` instead of checking every call. Backs
/// both [`MetricDoc`] and [`SpanDoc`].
struct JsonBuf<'a> {
    buf: &'a mut [u8],
    pos: usize,
    ok: bool,
}

impl<'a> JsonBuf<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        JsonBuf {
            buf,
            pos: 0,
            ok: true,
        }
    }

    fn put(&mut self, bytes: &[u8]) {
        if !self.ok {
            return;
        }
        if self.pos + bytes.len() > self.buf.len() {
            self.ok = false;
            return;
        }
        let mut i = 0;
        while i < bytes.len() {
            self.buf[self.pos] = bytes[i];
            self.pos += 1;
            i += 1;
        }
    }

    fn put_byte(&mut self, b: u8) {
        let one = [b];
        self.put(&one);
    }

    fn put_module_attr(&mut self, module: u16) {
        // Canonical semconv key (contracts/src/observability.rs FLUXOR_MODULE_INDEX).
        self.put(b"\"attributes\":[{\"key\":\"fluxor.module.index\",\"value\":{\"intValue\":\"");
        self.put_u64(module as u64);
        self.put(b"\"}}]");
    }

    /// Lowercase-hex encode `bytes` (used for OTLP trace/span ids).
    fn put_hex(&mut self, bytes: &[u8]) {
        let mut i = 0;
        while i < bytes.len() {
            self.put_byte(hex_nibble((bytes[i] >> 4) & 0xF));
            self.put_byte(hex_nibble(bytes[i] & 0xF));
            i += 1;
        }
    }

    /// Write a string with the JSON-significant bytes escaped. Instrument names
    /// are dotted-lowercase so escaping rarely fires, but `service.name` is
    /// user-supplied — keep the output well-formed regardless.
    fn put_json_str(&mut self, s: &[u8]) {
        let mut i = 0;
        while i < s.len() {
            let c = s[i];
            match c {
                b'"' => self.put(b"\\\""),
                b'\\' => self.put(b"\\\\"),
                b'\n' => self.put(b"\\n"),
                b'\r' => self.put(b"\\r"),
                b'\t' => self.put(b"\\t"),
                0x00..=0x1F => {
                    self.put(b"\\u00");
                    self.put_byte(hex_nibble((c >> 4) & 0xF));
                    self.put_byte(hex_nibble(c & 0xF));
                }
                _ => self.put_byte(c),
            }
            i += 1;
        }
    }

    /// u64 → ASCII decimal with **no division anywhere** — RP2350 (thumbv8m,
    /// Cortex-M33) has no cheap 64-bit divide, so even `n / 10` by a constant
    /// lowers to an `__aeabi_uldivmod` libcall the PIC module cannot link.
    /// Subtracts pre-computed powers of ten; `black_box` on the running
    /// remainder stops LLVM's loop-idiom pass from rewriting the subtraction
    /// back into that same division. Writes ≥1 digit.
    fn put_u64(&mut self, val: u64) {
        let mut n = val;
        let mut started = false;
        let mut i = 0;
        while i < POW10.len() {
            let pow = POW10[i];
            let mut digit = 0u8;
            while n >= pow {
                n = core::hint::black_box(n - pow);
                digit += 1;
            }
            if digit != 0 || started || i == POW10.len() - 1 {
                self.put_byte(b'0' + digit);
                started = true;
            }
            i += 1;
        }
    }
}

/// Incremental OTLP/JSON **metrics**-document writer. On any overflow `finish`
/// returns `None`, so a caller detects truncation without checking every call.
pub struct MetricDoc<'a> {
    j: JsonBuf<'a>,
    metric_count: u32,
}

impl<'a> MetricDoc<'a> {
    /// Begin a document with the given `service.name`. Writes everything up to
    /// (and including) the opening of the `metrics` array.
    pub fn begin(buf: &'a mut [u8], service_name: &[u8]) -> Self {
        let mut j = JsonBuf::new(buf);
        j.put(b"{\"resourceMetrics\":[{\"resource\":{\"attributes\":[{\"key\":\"service.name\",\"value\":{\"stringValue\":\"");
        j.put_json_str(service_name);
        j.put(b"\"}}]},\"scopeMetrics\":[{\"scope\":{\"name\":\"fluxor\"},\"metrics\":[");
        MetricDoc { j, metric_count: 0 }
    }

    /// Append a scalar metric (counter / up-down) as an OTLP `sum`.
    /// `monotonic` distinguishes a counter (true) from an up-down (false).
    pub fn sum(&mut self, name: &[u8], module: u16, t_nanos: u64, value: u64, monotonic: bool) {
        self.metric_sep();
        self.j.put(b"{\"name\":\"");
        self.j.put_json_str(name);
        self.j.put(b"\",\"sum\":{\"aggregationTemporality\":2,\"isMonotonic\":");
        self.j.put(if monotonic { b"true" } else { b"false" });
        self.j.put(b",\"dataPoints\":[{\"asInt\":\"");
        self.j.put_u64(value);
        self.j.put(b"\",\"timeUnixNano\":\"");
        self.j.put_u64(t_nanos);
        self.j.put(b"\",");
        self.j.put_module_attr(module);
        self.j.put(b"}]}}");
    }

    /// Append a histogram metric as an OTLP `histogram` with explicit bounds.
    pub fn histogram(&mut self, name: &[u8], module: u16, t_nanos: u64, buckets: &[u64]) {
        self.metric_sep();
        let mut count = 0u64;
        let mut i = 0;
        while i < buckets.len() {
            count = count.wrapping_add(buckets[i]);
            i += 1;
        }
        self.j.put(b"{\"name\":\"");
        self.j.put_json_str(name);
        self.j.put(b"\",\"histogram\":{\"aggregationTemporality\":2,\"dataPoints\":[{\"count\":\"");
        self.j.put_u64(count);
        self.j.put(b"\",\"timeUnixNano\":\"");
        self.j.put_u64(t_nanos);
        self.j.put(b"\",\"bucketCounts\":[");
        i = 0;
        while i < buckets.len() {
            if i > 0 {
                self.j.put(b",");
            }
            self.j.put(b"\"");
            self.j.put_u64(buckets[i]);
            self.j.put(b"\"");
            i += 1;
        }
        self.j.put(b"],\"explicitBounds\":[");
        i = 0;
        while i < HIST_BOUNDS_US.len() {
            if i > 0 {
                self.j.put(b",");
            }
            self.j.put_u64(HIST_BOUNDS_US[i]);
            i += 1;
        }
        self.j.put(b"],");
        self.j.put_module_attr(module);
        self.j.put(b"}]}}");
    }

    /// Close the document. Returns the total byte length, or `None` if any write
    /// overflowed the buffer (in which case the contents are unusable).
    pub fn finish(mut self) -> Option<usize> {
        self.j.put(b"]}]}]}");
        if self.j.ok {
            Some(self.j.pos)
        } else {
            None
        }
    }

    /// Number of metrics appended so far (a caller flushes an empty doc never).
    pub fn metric_count(&self) -> u32 {
        self.metric_count
    }

    fn metric_sep(&mut self) {
        if self.metric_count > 0 {
            self.j.put(b",");
        }
        self.metric_count += 1;
    }
}

/// Incremental OTLP/JSON **traces** (`resourceSpans`) document writer, posted to
/// `/v1/traces`. Same overflow discipline as [`MetricDoc`].
pub struct SpanDoc<'a> {
    j: JsonBuf<'a>,
    span_count: u32,
}

impl<'a> SpanDoc<'a> {
    /// Begin a traces document. Writes up to (and including) the `spans` array.
    pub fn begin(buf: &'a mut [u8], service_name: &[u8]) -> Self {
        let mut j = JsonBuf::new(buf);
        j.put(b"{\"resourceSpans\":[{\"resource\":{\"attributes\":[{\"key\":\"service.name\",\"value\":{\"stringValue\":\"");
        j.put_json_str(service_name);
        j.put(b"\"}}]},\"scopeSpans\":[{\"scope\":{\"name\":\"fluxor\"},\"spans\":[");
        SpanDoc { j, span_count: 0 }
    }

    /// Append one span. `telemetry_kind` is the on-device `SPAN_*` value
    /// (0=internal…); OTLP SpanKind is that plus one (1=internal…). `parent_id`
    /// all-zero marks a root span. Times are unix-nanos (device micros×1000).
    #[allow(
        clippy::too_many_arguments,
        reason = "an OTLP span is a flat record — name, ids, kind, status, and timing — written allocation-free; a struct would just move the arg list"
    )]
    pub fn span(
        &mut self,
        name: &[u8],
        module: u16,
        trace_id: &[u8],
        span_id: &[u8],
        parent_id: &[u8],
        telemetry_kind: u8,
        status: u8,
        start_nanos: u64,
        end_nanos: u64,
    ) {
        if self.span_count > 0 {
            self.j.put(b",");
        }
        self.span_count += 1;
        self.j.put(b"{\"traceId\":\"");
        self.j.put_hex(trace_id);
        self.j.put(b"\",\"spanId\":\"");
        self.j.put_hex(span_id);
        // OTLP roots carry an EMPTY parentSpanId — never all-zero hex.
        self.j.put(b"\",\"parentSpanId\":\"");
        if parent_id.iter().any(|b| *b != 0) {
            self.j.put_hex(parent_id);
        }
        self.j.put(b"\",\"name\":\"");
        self.j.put_json_str(name);
        self.j.put(b"\",\"kind\":");
        self.j.put_u64(telemetry_kind as u64 + 1);
        self.j.put(b",\"startTimeUnixNano\":\"");
        self.j.put_u64(start_nanos);
        self.j.put(b"\",\"endTimeUnixNano\":\"");
        self.j.put_u64(end_nanos);
        self.j.put(b"\",\"status\":{\"code\":");
        self.j.put_u64(status as u64);
        self.j.put(b"},");
        self.j.put_module_attr(module);
        self.j.put(b"}");
    }

    pub fn finish(mut self) -> Option<usize> {
        self.j.put(b"]}]}]}");
        if self.j.ok {
            Some(self.j.pos)
        } else {
            None
        }
    }

    pub fn span_count(&self) -> u32 {
        self.span_count
    }
}

const POW10: [u64; 20] = [
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

// ── id-table resolution ─────────────────────────────────────────────────
//
// The `otlp_http` exporter resolves `(module, id) -> name` on-device so it can
// emit real OTLP instrument names. The table is a text blob the config compiler
// injects (a `str` param): `module<sep>id=name;` entries, decimal indices. The
// separator distinguishes the family — `:` for metrics, `/` for spans — so the
// two never collide in the shared `(module, id)` space. Text keeps the compiled
// config debuggable and the injection a plain string set.

/// Resolve a metric `(module, id)` to a name (`module:id=name;` entries).
pub fn resolve_in_table(table: &[u8], module: u16, id: u16) -> Option<&[u8]> {
    resolve_sep(table, module, id, b':')
}

/// Resolve a span `(module, name_id)` to a name (`module/id=name;` entries).
pub fn resolve_span_in_table(table: &[u8], module: u16, id: u16) -> Option<&[u8]> {
    resolve_sep(table, module, id, b'/')
}

/// Scan the text table for `module<sep>id=name;`, returning the name slice on a
/// match or `None`. Entries with a different separator (the other family) are
/// skipped. Pure (no I/O), so the harness can pin the format.
fn resolve_sep(table: &[u8], module: u16, id: u16, sep: u8) -> Option<&[u8]> {
    let mut i = 0usize;
    while i < table.len() {
        // Skip any leading separators / whitespace between entries.
        while i < table.len() && !is_digit(table[i]) {
            i += 1;
        }
        if i >= table.len() {
            break;
        }
        let (m, after_m) = parse_u16(table, i);
        // Expect the family separator; a mismatch is the other family — skip it.
        if after_m >= table.len() || table[after_m] != sep {
            i = skip_entry(table, after_m);
            continue;
        }
        let (entry_id, after_id) = parse_u16(table, after_m + 1);
        if after_id >= table.len() || table[after_id] != b'=' {
            i = skip_entry(table, after_id);
            continue;
        }
        let name_start = after_id + 1;
        let mut name_end = name_start;
        while name_end < table.len() && table[name_end] != b';' {
            name_end += 1;
        }
        if m == module && entry_id == id {
            return Some(&table[name_start..name_end]);
        }
        i = if name_end < table.len() {
            name_end + 1
        } else {
            name_end
        };
    }
    None
}

fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

/// Parse a decimal u16 starting at `at`; returns (value, index past the
/// digits). `u16 * 10` needs no 64-bit divide, so this is PIC-safe.
fn parse_u16(buf: &[u8], at: usize) -> (u16, usize) {
    let mut v: u16 = 0;
    let mut i = at;
    while i < buf.len() && is_digit(buf[i]) {
        v = v.wrapping_mul(10).wrapping_add((buf[i] - b'0') as u16);
        i += 1;
    }
    (v, i)
}

/// Advance past the current entry to just after the next ';' (or to the end).
fn skip_entry(buf: &[u8], from: usize) -> usize {
    let mut i = from;
    while i < buf.len() && buf[i] != b';' {
        i += 1;
    }
    if i < buf.len() {
        i + 1
    } else {
        i
    }
}

fn hex_nibble(n: u8) -> u8 {
    if n < 10 {
        b'0' + n
    } else {
        b'a' + (n - 10)
    }
}
