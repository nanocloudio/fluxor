// Core: otlp_proto — OTLP/protobuf encoder for the metric signal.
//
// Layer: cores (reusable SDK implementation, `include!`d by consumers — NOT a
// wire contract). The protobuf sibling of `cores/otlp_json.rs`: it produces the
// binary `application/x-protobuf` OTLP encoding (`opentelemetry.proto.metrics.v1
// .MetricsData`) an `otel(otlp-proto) → gRPC/HTTP client` posts to `/v1/metrics`.
//
// Same discipline as the JSON core: `no_std`, allocation-free, division-free
// (PIC link-trap safe — protobuf varints are pure shift/mask, and the fixed64 /
// double fields are byte writes, never a `__aeabi_uldivmod` or float libcall;
// the histogram bounds are emitted as pre-computed IEEE-754 bit patterns so no
// `u64 as f64` conversion is linked).
//
// Wire shape (proto3 field numbers from metrics.proto):
//   MetricsData      { repeated ResourceMetrics resource_metrics = 1 }
//   ResourceMetrics  { Resource resource = 1; repeated ScopeMetrics scope_metrics = 2 }
//   Resource         { repeated KeyValue attributes = 1 }          // service.name
//   ScopeMetrics     { InstrumentationScope scope = 1; repeated Metric metrics = 2 }
//   Metric           { string name = 1; Sum sum = 7 | Histogram histogram = 9 }
//   Sum              { repeated NumberDataPoint data_points = 1;
//                      AggregationTemporality aggregation_temporality = 2; bool is_monotonic = 3 }
//   NumberDataPoint  { fixed64 time_unix_nano = 3; sfixed64 as_int = 6;
//                      repeated KeyValue attributes = 7 }
//   Histogram        { repeated HistogramDataPoint data_points = 1;
//                      AggregationTemporality aggregation_temporality = 2 }
//   HistogramDataPoint { fixed64 time_unix_nano = 3; fixed64 count = 4;
//                      repeated fixed64 bucket_counts = 6 (packed);
//                      repeated double explicit_bounds = 7 (packed);
//                      repeated KeyValue attributes = 9 }
//   KeyValue { string key = 1; AnyValue value = 2 }   AnyValue { int64 int_value = 3 }
//
// Each metric carries the producing module index as a `fluxor.module.index`
// data-point attribute (int_value), mirroring the JSON core. `time_unix_nano` is
// the device's monotonic micros×1000 in v1 (the exporter re-anchors to epoch).

/// Protobuf wire types used here.
const WIRE_VARINT: u8 = 0;
const WIRE_I64: u8 = 1; // fixed64 / sfixed64 / double
const WIRE_LEN: u8 = 2;

/// IEEE-754 bit patterns of the histogram bucket bounds (µs), emitted as packed
/// `double`s. Pre-computed so no runtime `u64 as f64` conversion is linked into
/// the PIC module. Matches `otlp_json::HIST_BOUNDS_US` = [64,128,…,4096].
pub const HIST_BOUNDS_BITS: [u64; 7] = [
    0x4050_0000_0000_0000, // 64.0
    0x4060_0000_0000_0000, // 128.0
    0x4070_0000_0000_0000, // 256.0
    0x4080_0000_0000_0000, // 512.0
    0x4090_0000_0000_0000, // 1024.0
    0x40A0_0000_0000_0000, // 2048.0
    0x40B0_0000_0000_0000, // 4096.0
];

/// Incremental writer over a fixed buffer: appends protobuf primitives, latching
/// `ok = false` on overflow so a caller detects truncation once at `finish`.
struct ProtoBuf<'a> {
    buf: &'a mut [u8],
    pos: usize,
    ok: bool,
}

impl<'a> ProtoBuf<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        ProtoBuf {
            buf,
            pos: 0,
            ok: true,
        }
    }

    fn put_byte(&mut self, b: u8) {
        if !self.ok {
            return;
        }
        if self.pos >= self.buf.len() {
            self.ok = false;
            return;
        }
        // Bounds checked above; `get_unchecked_mut` keeps the PIC module
        // panic-free (a panicking index would pull in unlinkable `panic_fmt`).
        unsafe {
            *self.buf.get_unchecked_mut(self.pos) = b;
        }
        self.pos += 1;
    }

    fn put_bytes(&mut self, bytes: &[u8]) {
        if !self.ok {
            return;
        }
        if self.pos + bytes.len() > self.buf.len() {
            self.ok = false;
            return;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.buf.as_mut_ptr().add(self.pos),
                bytes.len(),
            );
        }
        self.pos += bytes.len();
    }

    /// LEB128 varint — pure shift/mask, no division.
    fn put_varint(&mut self, mut v: u64) {
        loop {
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            if v != 0 {
                self.put_byte(byte | 0x80);
            } else {
                self.put_byte(byte);
                break;
            }
        }
    }

    fn put_tag(&mut self, field: u32, wire: u8) {
        self.put_varint(((field << 3) | wire as u32) as u64);
    }

    /// A little-endian 8-byte value (fixed64 / sfixed64 / double bit pattern).
    fn put_fixed64(&mut self, v: u64) {
        self.put_bytes(&v.to_le_bytes());
    }

    /// A length-delimited field: tag + varint(len) + bytes.
    fn put_len_field(&mut self, field: u32, bytes: &[u8]) {
        self.put_tag(field, WIRE_LEN);
        self.put_varint(bytes.len() as u64);
        self.put_bytes(bytes);
    }

    fn len_or_zero(&self) -> usize {
        if self.ok {
            self.pos
        } else {
            0
        }
    }
}

/// `AnyValue { int64 int_value = 3 }` → returns byte length, 0 on overflow.
fn build_any_value_int(v: u64, out: &mut [u8]) -> usize {
    let mut p = ProtoBuf::new(out);
    p.put_tag(3, WIRE_VARINT);
    p.put_varint(v);
    p.len_or_zero()
}

/// `KeyValue { string key = 1; AnyValue value = 2 }` for the module attribute.
fn build_module_attr(module: u16, out: &mut [u8]) -> usize {
    let mut av = [0u8; 16];
    let avlen = build_any_value_int(module as u64, &mut av);
    let mut p = ProtoBuf::new(out);
    // Canonical semconv key (contracts/src/observability.rs FLUXOR_MODULE_INDEX).
    p.put_len_field(1, b"fluxor.module.index");
    p.put_len_field(2, av.get(..avlen).unwrap_or(&[]));
    p.len_or_zero()
}

/// `NumberDataPoint { time_unix_nano = 3; as_int = 6; attributes = 7 }`.
fn build_number_dp(t_nanos: u64, value: u64, module: u16, out: &mut [u8]) -> usize {
    let mut attr = [0u8; 48];
    let alen = build_module_attr(module, &mut attr);
    let mut p = ProtoBuf::new(out);
    p.put_tag(3, WIRE_I64);
    p.put_fixed64(t_nanos);
    p.put_tag(6, WIRE_I64); // as_int (sfixed64, two's complement — value bits verbatim)
    p.put_fixed64(value);
    p.put_len_field(7, attr.get(..alen).unwrap_or(&[]));
    p.len_or_zero()
}

/// `Sum { data_points = 1; aggregation_temporality = 2; is_monotonic = 3 }`.
fn build_sum(t_nanos: u64, value: u64, module: u16, monotonic: bool, out: &mut [u8]) -> usize {
    let mut ndp = [0u8; 96];
    let nlen = build_number_dp(t_nanos, value, module, &mut ndp);
    let mut p = ProtoBuf::new(out);
    p.put_len_field(1, ndp.get(..nlen).unwrap_or(&[]));
    p.put_tag(2, WIRE_VARINT);
    p.put_varint(2); // AGGREGATION_TEMPORALITY_CUMULATIVE
    p.put_tag(3, WIRE_VARINT);
    p.put_varint(if monotonic { 1 } else { 0 });
    p.len_or_zero()
}

/// `HistogramDataPoint`: time, count, packed bucket_counts, packed
/// explicit_bounds, module attribute.
fn build_hist_dp(t_nanos: u64, buckets: &[u64], module: u16, out: &mut [u8]) -> usize {
    let mut count = 0u64;
    for b in buckets {
        count = count.wrapping_add(*b);
    }
    // Packed repeated fixed64 bucket_counts (each 8 bytes).
    let mut bc = [0u8; 8 * 16];
    let mut bcw = ProtoBuf::new(&mut bc);
    for b in buckets {
        bcw.put_fixed64(*b);
    }
    let bclen = bcw.len_or_zero();
    // Packed repeated double explicit_bounds (pre-computed bit patterns).
    let mut eb = [0u8; 8 * 8];
    let mut ebw = ProtoBuf::new(&mut eb);
    for bits in HIST_BOUNDS_BITS.iter() {
        ebw.put_fixed64(*bits);
    }
    let eblen = ebw.len_or_zero();
    let mut attr = [0u8; 48];
    let alen = build_module_attr(module, &mut attr);

    let mut p = ProtoBuf::new(out);
    p.put_tag(3, WIRE_I64);
    p.put_fixed64(t_nanos);
    p.put_tag(4, WIRE_I64);
    p.put_fixed64(count);
    p.put_len_field(6, bc.get(..bclen).unwrap_or(&[]));
    p.put_len_field(7, eb.get(..eblen).unwrap_or(&[]));
    p.put_len_field(9, attr.get(..alen).unwrap_or(&[]));
    p.len_or_zero()
}

/// `Histogram { data_points = 1; aggregation_temporality = 2 }`.
fn build_histogram(t_nanos: u64, buckets: &[u64], module: u16, out: &mut [u8]) -> usize {
    let mut dp = [0u8; 256];
    let dlen = build_hist_dp(t_nanos, buckets, module, &mut dp);
    let mut p = ProtoBuf::new(out);
    p.put_len_field(1, dp.get(..dlen).unwrap_or(&[]));
    p.put_tag(2, WIRE_VARINT);
    p.put_varint(2); // CUMULATIVE
    p.len_or_zero()
}

/// Incremental OTLP/protobuf **metrics**-document writer. Mirrors
/// [`super::otlp_json::MetricDoc`]'s API so a consumer dispatches on encoding
/// with the same call shape. Each `sum`/`histogram` appends one `Metric` (with
/// its `ScopeMetrics.metrics` field-2 tag) into the buffer; `finish` prepends
/// the resource/scope wrappers.
pub struct MetricProtoDoc<'a> {
    buf: &'a mut [u8],
    /// Bytes written so far — the concatenated `tag(2,LEN)+len+Metric` entries.
    pos: usize,
    ok: bool,
    metric_count: u32,
    /// `service.name` for the resource wrapper written at `finish`.
    service: [u8; 32],
    service_len: usize,
}

impl<'a> MetricProtoDoc<'a> {
    pub fn begin(buf: &'a mut [u8], service_name: &[u8]) -> Self {
        let mut service = [0u8; 32];
        let n = service_name.len().min(service.len());
        unsafe {
            core::ptr::copy_nonoverlapping(service_name.as_ptr(), service.as_mut_ptr(), n);
        }
        MetricProtoDoc {
            buf,
            pos: 0,
            ok: true,
            metric_count: 0,
            service,
            service_len: n,
        }
    }

    /// Append `metric_bytes` as one `ScopeMetrics.metrics = 2` entry.
    fn append_metric(&mut self, metric_bytes: &[u8]) {
        if !self.ok || metric_bytes.is_empty() {
            self.ok = false;
            return;
        }
        let mut p = ProtoBuf::new(self.buf.get_mut(self.pos..).unwrap_or(&mut []));
        p.put_len_field(2, metric_bytes);
        let n = p.len_or_zero();
        if n == 0 {
            self.ok = false;
            return;
        }
        self.pos += n;
        self.metric_count += 1;
    }

    /// Append a scalar metric as an OTLP `Sum` (`Metric { name; sum }`).
    pub fn sum(&mut self, name: &[u8], module: u16, t_nanos: u64, value: u64, monotonic: bool) {
        let mut sum = [0u8; 128];
        let slen = build_sum(t_nanos, value, module, monotonic, &mut sum);
        let mut metric = [0u8; 160];
        let mut mp = ProtoBuf::new(&mut metric);
        mp.put_len_field(1, name); // Metric.name
        mp.put_len_field(7, sum.get(..slen).unwrap_or(&[])); // Metric.sum
        let mlen = mp.len_or_zero();
        self.append_metric(metric.get(..mlen).unwrap_or(&[]));
    }

    /// Append a histogram metric as an OTLP `Histogram` (`Metric { name; histogram }`).
    pub fn histogram(&mut self, name: &[u8], module: u16, t_nanos: u64, buckets: &[u64]) {
        let mut hist = [0u8; 288];
        let hlen = build_histogram(t_nanos, buckets, module, &mut hist);
        let mut metric = [0u8; 320];
        let mut mp = ProtoBuf::new(&mut metric);
        mp.put_len_field(1, name); // Metric.name
        mp.put_len_field(9, hist.get(..hlen).unwrap_or(&[])); // Metric.histogram
        let mlen = mp.len_or_zero();
        self.append_metric(metric.get(..mlen).unwrap_or(&[]));
    }

    pub fn metric_count(&self) -> u32 {
        self.metric_count
    }

    /// Wrap the accumulated metrics in `MetricsData > ResourceMetrics >
    /// ScopeMetrics`, prepending the resource (`service.name`) + scope
    /// (`fluxor`). Returns the total byte length, or `None` on overflow.
    pub fn finish(self) -> Option<usize> {
        if !self.ok {
            return None;
        }
        let metrics_len = self.pos;

        // Resource { attributes = [ KeyValue{ service.name, string_value } ] }.
        // AnyValue { string string_value = 1 }.
        let mut av = [0u8; 40];
        let mut avp = ProtoBuf::new(&mut av);
        avp.put_len_field(1, self.service.get(..self.service_len).unwrap_or(&[]));
        let avlen = avp.len_or_zero();
        let mut kv = [0u8; 64];
        let mut kvp = ProtoBuf::new(&mut kv);
        kvp.put_len_field(1, b"service.name");
        kvp.put_len_field(2, av.get(..avlen).unwrap_or(&[]));
        let kvlen = kvp.len_or_zero();
        let mut resource = [0u8; 80];
        let mut rp = ProtoBuf::new(&mut resource);
        rp.put_len_field(1, kv.get(..kvlen).unwrap_or(&[])); // Resource.attributes = 1
        let rlen = rp.len_or_zero();

        // InstrumentationScope { name = "fluxor" }.
        let mut scope = [0u8; 16];
        let mut sp = ProtoBuf::new(&mut scope);
        sp.put_len_field(1, b"fluxor");
        let sclen = sp.len_or_zero();

        // ScopeMetrics content = scope(field 1) + <metrics block already in buf>.
        // Build the scope field header; the metrics follow it.
        let mut sm_scope = [0u8; 24];
        let mut smp = ProtoBuf::new(&mut sm_scope);
        smp.put_len_field(1, scope.get(..sclen).unwrap_or(&[]));
        let sm_scope_len = smp.len_or_zero();
        let sm_content_len = sm_scope_len + metrics_len;

        // The full prefix that must precede the metrics block:
        //   MetricsData.resource_metrics(1) hdr
        //   + ResourceMetrics.resource(1) + ResourceMetrics.scope_metrics(2) hdr
        //   + ScopeMetrics.scope(1)
        let mut prefix = [0u8; 128];
        let mut pp = ProtoBuf::new(&mut prefix);
        // ResourceMetrics content len = resource field + scope_metrics field header.
        // resource field = tag(1,LEN)+len(rlen)+resource
        // scope_metrics  = tag(2,LEN)+len(sm_content_len) ... then SM content.
        // Compute RM content length by building the RM prefix (everything up to,
        // but not including, the SM content that lives after in the buffer).
        let mut rm_prefix = [0u8; 96];
        let mut rmp = ProtoBuf::new(&mut rm_prefix);
        rmp.put_len_field(1, resource.get(..rlen).unwrap_or(&[])); // RM.resource
        rmp.put_tag(2, WIRE_LEN); // RM.scope_metrics header
        rmp.put_varint(sm_content_len as u64);
        let rm_prefix_len = rmp.len_or_zero();
        let rm_content_len = rm_prefix_len + sm_content_len;

        pp.put_tag(1, WIRE_LEN); // MetricsData.resource_metrics
        pp.put_varint(rm_content_len as u64);
        pp.put_bytes(rm_prefix.get(..rm_prefix_len).unwrap_or(&[]));
        pp.put_bytes(sm_scope.get(..sm_scope_len).unwrap_or(&[]));
        let prefix_len = pp.len_or_zero();
        if prefix_len == 0 {
            return None;
        }

        // Make room and place the doc at buf[0]: shift the metrics block right by
        // `prefix_len`, then write the prefix at the front.
        let total = prefix_len + metrics_len;
        if total > self.buf.len() {
            return None;
        }
        // Shift the metrics block right (overlapping, dest > src → `ptr::copy`),
        // then write the prefix at the front. Both bounded by the `total` check.
        unsafe {
            let base = self.buf.as_mut_ptr();
            core::ptr::copy(base, base.add(prefix_len), metrics_len);
            core::ptr::copy_nonoverlapping(prefix.as_ptr(), base, prefix_len);
        }
        Some(total)
    }
}
