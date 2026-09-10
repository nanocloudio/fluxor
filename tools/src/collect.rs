//! `fluxor-collect` core — the host-side telemetry
//! collector.
//!
//! Decodes `fxtl-compact` batches (the FXTL envelope + raw `TelemetryRecord`s
//! a device's `otel(encoding=fxtl-compact)` exports over UDP/UART), resolves
//! id-interned names, histogram bounds, and composite dimension indices from
//! the build-time id-table (`fluxor id-table` JSON), keeps a latest-value
//! table, and renders two outputs:
//!
//!   * Prometheus text exposition (`render_prometheus`) — the pull surface
//!     served on `GET /metrics` by the `fluxor-collect` bin. Served
//!     directly: the latest-value table exists anyway, and a consumer
//!     retiring its own `/metrics` binary needs this surface first.
//!   * OTLP/JSON metrics documents (`render_otlp_json`) — the push surface
//!     POSTed to an OTel collector's `/v1/metrics`.
//!
//! **Digest handshake (mandatory):** every batch envelope carries the
//! id-table digest its emitter was built with. A mismatch against the loaded
//! table is REFUSED — counted, never resolved — because resolving names from
//! the wrong table reports wrong metric names while every health signal stays
//! green. A zero digest (no injection) resolves, flagged unverified.
//!
//! **Boot-epoch re-anchoring:** device records carry free-running monotonic
//! micros (`standards/observability.md` §4). Each source's boot epoch is
//! estimated as `recv_wall − t_micros` (an upper bound tightened over time);
//! a device timestamp that jumps backwards is a reboot — the epoch resets,
//! which is also what gives OTLP its `startTimeUnixNano` and Prometheus its
//! counter-reset semantics, for free.

use std::collections::BTreeMap;

/// Wire contract, `include!`d verbatim from the module SDK so the host
/// decoder and the device emitter compile the same bytes — the same
/// single-source pattern the test harness uses for encoder cores.
pub mod tlm {
    #![allow(dead_code, reason = "host decoder consumes a subset of the contract")]
    include!("../../modules/sdk/contracts/telemetry.rs");
}

use crate::manifest::InstrumentKind;

// ── Id-table view ───────────────────────────────────────────────────

/// One metric's resolved metadata from the id-table JSON.
#[derive(Debug, Clone)]
pub struct MetricMeta {
    pub name: String,
    pub kind: Option<InstrumentKind>,
    pub bounds_us: Vec<u64>,
    /// Declared dimension keys with their domain, composite-index order.
    pub dimensions: Vec<(String, DimView)>,
}

#[derive(Debug, Clone)]
pub enum DimView {
    Numeric { max: u32 },
    Enum { values: Vec<String> },
}

impl DimView {
    fn size(&self) -> u32 {
        match self {
            DimView::Numeric { max } => *max,
            DimView::Enum { values } => values.len() as u32,
        }
    }

    fn label(&self, index: u32) -> String {
        match self {
            DimView::Numeric { .. } => index.to_string(),
            DimView::Enum { values } => values
                .get(index as usize)
                .cloned()
                .unwrap_or_else(|| "__other__".into()),
        }
    }
}

/// Parsed id-table (`fluxor id-table` JSON export).
#[derive(Debug, Default)]
pub struct TableView {
    pub digest: u32,
    pub metrics: BTreeMap<(u16, u16), MetricMeta>,
    pub spans: BTreeMap<(u16, u16), String>,
    pub module_names: BTreeMap<u16, String>,
}

impl TableView {
    /// Parse the exporter's JSON. Unknown fields are ignored (the exporter is
    /// the same tree, but a collector should not crash on a newer table).
    pub fn from_json(v: &serde_json::Value) -> Result<Self, String> {
        let mut t = TableView::default();
        let digest_str = v
            .get("digest")
            .and_then(|d| d.as_str())
            .ok_or("id-table: missing digest")?;
        t.digest = u32::from_str_radix(digest_str.trim_start_matches("0x"), 16)
            .map_err(|e| format!("id-table: bad digest {digest_str:?}: {e}"))?;
        let modules = v
            .get("modules")
            .and_then(|m| m.as_array())
            .ok_or("id-table: missing modules")?;
        for m in modules {
            let idx = m.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as u16;
            if let Some(name) = m.get("name").and_then(|n| n.as_str()) {
                t.module_names.insert(idx, name.to_string());
            }
            for row in m
                .get("metrics")
                .and_then(|x| x.as_array())
                .unwrap_or(&vec![])
            {
                let id = row.get("id").and_then(|i| i.as_u64()).unwrap_or(0) as u16;
                let name = row
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                let kind = row
                    .get("kind")
                    .and_then(|k| k.as_str())
                    .and_then(|k| match k {
                        "counter" => Some(InstrumentKind::Counter),
                        "updown" => Some(InstrumentKind::UpDown),
                        "histogram" => Some(InstrumentKind::Histogram),
                        "histogram16" => Some(InstrumentKind::Histogram16),
                        _ => None,
                    });
                let bounds_us = row
                    .get("bounds_us")
                    .and_then(|b| b.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_u64()).collect())
                    .unwrap_or_default();
                let mut dimensions = Vec::new();
                for d in row
                    .get("dimensions")
                    .and_then(|x| x.as_array())
                    .unwrap_or(&vec![])
                {
                    let key = d
                        .get("key")
                        .and_then(|k| k.as_str())
                        .unwrap_or("")
                        .to_string();
                    let view = match d.get("domain").and_then(|x| x.as_str()) {
                        Some("numeric") => DimView::Numeric {
                            max: d.get("max").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
                        },
                        Some("enum") => DimView::Enum {
                            values: d
                                .get("values")
                                .and_then(|x| x.as_array())
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|x| x.as_str().map(str::to_string))
                                        .collect()
                                })
                                .unwrap_or_default(),
                        },
                        _ => continue,
                    };
                    dimensions.push((key, view));
                }
                t.metrics.insert(
                    (idx, id),
                    MetricMeta {
                        name,
                        kind,
                        bounds_us,
                        dimensions,
                    },
                );
            }
            for row in m.get("spans").and_then(|x| x.as_array()).unwrap_or(&vec![]) {
                let id = row.get("id").and_then(|i| i.as_u64()).unwrap_or(0) as u16;
                if let Some(name) = row.get("name").and_then(|n| n.as_str()) {
                    t.spans.insert((idx, id), name.to_string());
                }
            }
        }
        Ok(t)
    }

    /// Decode a composite dimension index against `meta`'s declared domains
    /// (row-major, `dim = ((i0·s1)+i1)·s2+…`) into label pairs. `DIM_OTHER`
    /// folds every key to `__other__`; an out-of-range composite (a domain
    /// the table doesn't cover) does the same rather than invent component
    /// values.
    pub fn decode_dim(meta: &MetricMeta, dim: u16) -> Vec<(String, String)> {
        if meta.dimensions.is_empty() {
            return Vec::new();
        }
        if dim == tlm::DIM_OTHER {
            return meta
                .dimensions
                .iter()
                .map(|(k, _)| (k.clone(), "__other__".into()))
                .collect();
        }
        let sizes: Vec<u32> = meta.dimensions.iter().map(|(_, d)| d.size()).collect();
        let product: u64 = sizes.iter().map(|&s| s.max(1) as u64).product();
        if (dim as u64) >= product {
            return meta
                .dimensions
                .iter()
                .map(|(k, _)| (k.clone(), "__other__".into()))
                .collect();
        }
        // Row-major decode, last key varies fastest.
        let mut rem = dim as u64;
        let mut indices = vec![0u32; sizes.len()];
        for i in (0..sizes.len()).rev() {
            let s = sizes[i].max(1) as u64;
            indices[i] = (rem % s) as u32;
            rem /= s;
        }
        meta.dimensions
            .iter()
            .zip(indices)
            .map(|((k, d), i)| (k.clone(), d.label(i)))
            .collect()
    }
}

// ── Collector state ─────────────────────────────────────────────────

/// Latest value of one series: `(module, metric_id, dim)`.
#[derive(Debug, Clone)]
pub enum Sample {
    Scalar { kind: u8, value: u64 },
    Histogram { buckets: Vec<u64> },
}

#[derive(Debug, Clone, Default)]
pub struct SeriesState {
    pub sample: Option<Sample>,
    /// Device-monotonic stamp of the newest sample (µs since boot).
    pub t_micros: u64,
    /// Wall-clock receive time of the newest sample (unix nanos).
    pub recv_unix_nanos: u64,
}

/// Per-emitting-module stream state (reset detection + loss accounting).
#[derive(Debug, Clone, Default)]
pub struct SourceState {
    /// Estimated unix-nanos of device boot: `recv_wall − t_micros·1000`,
    /// tightened downward over time, reset on reboot detection.
    pub boot_epoch_nanos: u64,
    /// Highest device timestamp seen — a big backwards jump = reboot.
    pub high_t_micros: u64,
    /// The envelope's cumulative ring-drop counter, as last reported.
    pub ring_dropped: u32,
}

#[derive(Debug, Default)]
pub struct IngestStats {
    pub records: usize,
    pub metrics: usize,
    pub spans: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum IngestError {
    /// Not an FXTL batch (bad magic) — silently skippable traffic.
    BadMagic,
    Truncated,
    /// The emitter's id-table digest does not match the loaded table.
    /// Refused rather than resolved; both digests reported.
    DigestMismatch {
        envelope: u32,
        table: u32,
    },
}

/// A device timestamp this far below the per-source high-water mark is a
/// reboot, not jitter. 5 s of slack absorbs cross-record reordering inside
/// one flush without mistaking it for a reset.
const REBOOT_SLACK_MICROS: u64 = 5_000_000;

#[derive(Default)]
pub struct Collector {
    pub table: Option<TableView>,
    pub series: BTreeMap<(u16, u16, u16), SeriesState>,
    pub span_counts: BTreeMap<(u16, u16), u64>,
    pub sources: BTreeMap<u16, SourceState>,
    pub datagrams: u64,
    pub refused: u64,
    /// Batches that carried digest 0 (no injection): resolution proceeded but
    /// is UNVERIFIED — surfaced as a self-metric so nobody mistakes it.
    pub unverified: u64,
}

impl Collector {
    pub fn new(table: Option<TableView>) -> Self {
        Collector {
            table,
            ..Default::default()
        }
    }

    /// Ingest one received datagram (an FXTL batch). `recv_unix_nanos` is the
    /// host wall clock at receive.
    pub fn ingest(&mut self, buf: &[u8], recv_unix_nanos: u64) -> Result<IngestStats, IngestError> {
        // transport_buffer sends the bare envelope; tolerate a leading
        // `[msg_type][len u16]` net_proto frame header from a raw capture.
        let buf = if buf.len() >= 4 + tlm::BATCH_HEADER_SIZE
            && tlm::batch_magic(&buf[3..]) == tlm::BATCH_MAGIC
            && tlm::batch_magic(buf) != tlm::BATCH_MAGIC
        {
            &buf[3..]
        } else {
            buf
        };
        if buf.len() < tlm::BATCH_HEADER_SIZE {
            return Err(IngestError::Truncated);
        }
        if tlm::batch_magic(buf) != tlm::BATCH_MAGIC {
            return Err(IngestError::BadMagic);
        }
        self.datagrams += 1;
        let envelope_digest = tlm::batch_table_digest(buf);
        if let Some(t) = &self.table {
            if envelope_digest != 0 && envelope_digest != t.digest {
                self.refused += 1;
                return Err(IngestError::DigestMismatch {
                    envelope: envelope_digest,
                    table: t.digest,
                });
            }
        }
        if envelope_digest == 0 {
            self.unverified += 1;
        }
        let ring_dropped = tlm::batch_dropped(buf);

        let mut stats = IngestStats::default();
        let mut off = tlm::BATCH_HEADER_SIZE;
        while off + tlm::HEADER_SIZE <= buf.len() {
            let rec = &buf[off..];
            let rlen = tlm::record_len(tlm::signal(rec), tlm::kind(rec));
            if rlen == 0 || off + rlen > buf.len() {
                break; // unknown or truncated tail — stop, don't mis-frame
            }
            let rec = &buf[off..off + rlen];
            stats.records += 1;
            let module = tlm::module(rec);
            let t_micros = tlm::t_micros(rec);

            // Reset detection + boot-epoch estimate, per emitting module.
            let src = self.sources.entry(module).or_default();
            if src.high_t_micros > t_micros + REBOOT_SLACK_MICROS {
                // Device timestamp jumped backwards: reboot. New epoch.
                src.boot_epoch_nanos = 0;
                src.high_t_micros = 0;
            }
            src.high_t_micros = src.high_t_micros.max(t_micros);
            src.ring_dropped = src.ring_dropped.max(ring_dropped);
            let epoch = recv_unix_nanos.saturating_sub(t_micros.saturating_mul(1000));
            if src.boot_epoch_nanos == 0 || epoch < src.boot_epoch_nanos {
                src.boot_epoch_nanos = epoch;
            }

            match tlm::signal(rec) {
                s if s == tlm::SIGNAL_METRIC => {
                    stats.metrics += 1;
                    let id = tlm::metric_id(rec);
                    let dim = tlm::metric_dim(rec);
                    let kind = tlm::kind(rec);
                    let nbuckets = tlm::hist_bucket_count(kind);
                    let sample = if nbuckets > 0 {
                        let mut buckets = vec![0u64; nbuckets];
                        for (i, b) in buckets.iter_mut().enumerate() {
                            let base = 16 + i * 8;
                            *b = u64::from_le_bytes(rec[base..base + 8].try_into().unwrap());
                        }
                        Sample::Histogram { buckets }
                    } else {
                        Sample::Scalar {
                            kind,
                            value: tlm::metric_scalar_value(rec),
                        }
                    };
                    let st = self.series.entry((module, id, dim)).or_default();
                    st.sample = Some(sample);
                    st.t_micros = t_micros;
                    st.recv_unix_nanos = recv_unix_nanos;
                }
                s if s == tlm::SIGNAL_SPAN => {
                    stats.spans += 1;
                    let name_id = tlm::span_name_id(rec);
                    *self.span_counts.entry((module, name_id)).or_default() += 1;
                }
                _ => {} // PSTATUS et al — not surfaced in v1
            }
            off += rlen;
        }
        Ok(stats)
    }

    fn module_name(&self, module: u16) -> String {
        self.table
            .as_ref()
            .and_then(|t| t.module_names.get(&module))
            .filter(|n| !n.is_empty())
            .cloned()
            .unwrap_or_else(|| format!("m{module}"))
    }

    fn metric_meta(&self, module: u16, id: u16) -> Option<&MetricMeta> {
        self.table
            .as_ref()
            .and_then(|t| t.metrics.get(&(module, id)))
    }

    /// Render the whole latest-value table as Prometheus text exposition.
    ///
    /// Naming: `fluxor_<instrument>` with dots→underscores, labeled by
    /// `module` / `module_index` plus the decoded dimension keys (dots→
    /// underscores). Histograms render `_bucket{le=…}` (cumulative, from the
    /// record's per-bucket counts) + `_count`; `_sum` is omitted — the record
    /// does not carry one, and `histogram_quantile()` needs only `_bucket`.
    pub fn render_prometheus(&self) -> String {
        use std::fmt::Write as _;
        let mut families: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
        for (&(module, id, dim), st) in &self.series {
            let Some(sample) = &st.sample else { continue };
            let meta = self.metric_meta(module, id);
            let raw_name = meta
                .map(|m| m.name.clone())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| format!("m{module}_id{id}"));
            let prom_name = format!("fluxor_{}", sanitize(&raw_name));
            let mut labels = vec![
                ("module".to_string(), self.module_name(module)),
                ("module_index".to_string(), module.to_string()),
            ];
            if let Some(m) = meta {
                labels.extend(TableView::decode_dim(m, dim));
            } else if dim != 0 {
                labels.push(("dim".into(), dim.to_string()));
            }
            if meta.is_none() {
                labels.push(("unresolved".into(), "true".into()));
            }
            match sample {
                Sample::Scalar { kind, value } => {
                    let (ty, name) = if *kind == tlm::METRIC_COUNTER {
                        // Prometheus counter convention: `_total` suffix,
                        // not doubled when the instrument already carries it.
                        let n = if prom_name.ends_with("_total") {
                            prom_name.clone()
                        } else {
                            format!("{prom_name}_total")
                        };
                        ("counter", n)
                    } else {
                        ("gauge", prom_name.clone())
                    };
                    let fam = families
                        .entry(name.clone())
                        .or_insert_with(|| (ty.to_string(), Vec::new()));
                    fam.1.push(format!("{name}{} {value}", fmt_labels(&labels)));
                }
                Sample::Histogram { buckets } => {
                    let bounds: Vec<u64> = meta
                        .map(|m| m.bounds_us.clone())
                        .filter(|b| b.len() + 1 == buckets.len())
                        .unwrap_or_else(|| {
                            // 8-bucket records without a declared row carry
                            // the contract's fixed log2 ladder.
                            if buckets.len() == tlm::HIST_BUCKETS {
                                vec![64, 128, 256, 512, 1024, 2048, 4096]
                            } else {
                                Vec::new()
                            }
                        });
                    let total: u64 = buckets.iter().sum();
                    if bounds.len() + 1 != buckets.len() {
                        // A histogram16 with no declared bounds row: `le`
                        // values are unknowable and fabricating them would
                        // mislabel every bucket — render only the total, so
                        // the loss is visible instead of wrong.
                        let fam = families
                            .entry(format!("{prom_name}_count"))
                            .or_insert_with(|| ("gauge".to_string(), Vec::new()));
                        fam.1
                            .push(format!("{prom_name}_count{} {total}", fmt_labels(&labels)));
                        continue;
                    }
                    let fam = families
                        .entry(format!("{prom_name}_bucket"))
                        .or_insert_with(|| ("histogram".to_string(), Vec::new()));
                    let mut cum = 0u64;
                    for (i, b) in buckets.iter().enumerate() {
                        cum = cum.wrapping_add(*b);
                        let le = bounds
                            .get(i)
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "+Inf".into());
                        let mut l = labels.clone();
                        l.push(("le".into(), le));
                        fam.1
                            .push(format!("{prom_name}_bucket{} {cum}", fmt_labels(&l)));
                    }
                    fam.1
                        .push(format!("{prom_name}_count{} {cum}", fmt_labels(&labels)));
                }
            }
        }
        // Span activity: one counter family, so RPS-from-spans is scrapeable.
        for (&(module, name_id), count) in &self.span_counts {
            let name = self
                .table
                .as_ref()
                .and_then(|t| t.spans.get(&(module, name_id)))
                .cloned()
                .unwrap_or_else(|| format!("span{name_id}"));
            let labels = vec![
                ("module".to_string(), self.module_name(module)),
                ("span".to_string(), name),
            ];
            let fam = families
                .entry("fluxor_spans_received_total".into())
                .or_insert_with(|| ("counter".to_string(), Vec::new()));
            fam.1.push(format!(
                "fluxor_spans_received_total{} {count}",
                fmt_labels(&labels)
            ));
        }
        // Collector self-accounting — saturation is counted, never absorbed.
        let mut out = String::new();
        for (name, (ty, lines)) in &families {
            let base = name.strip_suffix("_bucket").unwrap_or(name);
            let _ = writeln!(out, "# TYPE {base} {ty}");
            for l in lines {
                let _ = writeln!(out, "{l}");
            }
        }
        let _ = writeln!(out, "# TYPE fluxor_collect_datagrams_total counter");
        let _ = writeln!(out, "fluxor_collect_datagrams_total {}", self.datagrams);
        let _ = writeln!(out, "# TYPE fluxor_collect_refused_total counter");
        let _ = writeln!(out, "fluxor_collect_refused_total {}", self.refused);
        let _ = writeln!(out, "# TYPE fluxor_collect_unverified_total counter");
        let _ = writeln!(out, "fluxor_collect_unverified_total {}", self.unverified);
        let _ = writeln!(out, "# TYPE fluxor_ring_dropped_total counter");
        for (&module, src) in &self.sources {
            let labels = vec![("module".to_string(), self.module_name(module))];
            let _ = writeln!(
                out,
                "fluxor_ring_dropped_total{} {}",
                fmt_labels(&labels),
                src.ring_dropped
            );
        }
        out
    }

    /// Render the latest-value table as one OTLP/JSON metrics document for a
    /// `POST /v1/metrics` push. `startTimeUnixNano` = the source's estimated
    /// boot epoch (reset detection falls out of re-anchoring).
    pub fn render_otlp_json(&self, service_name: &str) -> serde_json::Value {
        use serde_json::json;
        let mut metrics: Vec<serde_json::Value> = Vec::new();
        for (&(module, id, dim), st) in &self.series {
            let Some(sample) = &st.sample else { continue };
            let meta = self.metric_meta(module, id);
            let name = meta
                .map(|m| m.name.clone())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| format!("m{module}.id{id}"));
            let start = self
                .sources
                .get(&module)
                .map(|s| s.boot_epoch_nanos)
                .unwrap_or(0);
            let t_nanos = start.saturating_add(st.t_micros.saturating_mul(1000));
            let mut attrs = vec![
                json!({"key":"fluxor.module.index","value":{"intValue":module.to_string()}}),
                json!({"key":"service.name","value":{"stringValue":self.module_name(module)}}),
            ];
            if let Some(m) = meta {
                for (k, v) in TableView::decode_dim(m, dim) {
                    attrs.push(json!({"key":k,"value":{"stringValue":v}}));
                }
            } else if dim != 0 {
                attrs.push(json!({"key":"fluxor.dim","value":{"intValue":dim.to_string()}}));
            }
            match sample {
                Sample::Scalar { kind, value } => {
                    metrics.push(json!({
                        "name": name,
                        "sum": {
                            "aggregationTemporality": 2,
                            "isMonotonic": *kind == tlm::METRIC_COUNTER,
                            "dataPoints": [{
                                "asInt": value.to_string(),
                                "startTimeUnixNano": start.to_string(),
                                "timeUnixNano": t_nanos.to_string(),
                                "attributes": attrs,
                            }],
                        },
                    }));
                }
                Sample::Histogram { buckets } => {
                    let bounds: Vec<u64> = meta
                        .map(|m| m.bounds_us.clone())
                        .filter(|b| b.len() + 1 == buckets.len())
                        .unwrap_or_else(|| vec![64, 128, 256, 512, 1024, 2048, 4096]);
                    let count: u64 = buckets.iter().sum();
                    metrics.push(json!({
                        "name": name,
                        "histogram": {
                            "aggregationTemporality": 2,
                            "dataPoints": [{
                                "count": count.to_string(),
                                "startTimeUnixNano": start.to_string(),
                                "timeUnixNano": t_nanos.to_string(),
                                "bucketCounts": buckets.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
                                "explicitBounds": bounds,
                                "attributes": attrs,
                            }],
                        },
                    }));
                }
            }
        }
        json!({
            "resourceMetrics": [{
                "resource": {"attributes": [
                    {"key":"service.name","value":{"stringValue":service_name}}
                ]},
                "scopeMetrics": [{
                    "scope": {"name":"fluxor-collect"},
                    "metrics": metrics,
                }],
            }],
        })
    }
}

/// Prometheus metric-name sanitisation: dots and any other invalid byte
/// become underscores.
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == ':' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn fmt_labels(labels: &[(String, String)]) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let inner: Vec<String> = labels
        .iter()
        .map(|(k, v)| {
            format!(
                "{}=\"{}\"",
                sanitize(k),
                v.replace('\\', "\\\\").replace('"', "\\\"")
            )
        })
        .collect();
    format!("{{{}}}", inner.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn table() -> TableView {
        TableView::from_json(&json!({
            "version": 1,
            "digest": "0x00000042",
            "modules": [{
                "index": 3,
                "name": "http",
                "metrics": [
                    {"id": 0, "name": "bytes_in"},
                    {"id": 18, "name": "requests_total", "kind": "counter"},
                    {"id": 19, "name": "request_latency_us", "kind": "histogram16",
                     "bounds_us": [250,500,1000,2500,5000,10000,25000,50000,100000,250000,500000,1000000,2500000,5000000,10000000]},
                    {"id": 20, "name": "consumer_lag", "kind": "updown",
                     "dimensions": [
                        {"key": "messaging.destination.partition.id", "domain": "numeric", "max": 4},
                        {"key": "messaging.consumer.group.name", "domain": "enum", "values": ["ingest","audit"]}
                     ]},
                ],
                "spans": [{"id": 0, "name": "http.server.request"}],
            }],
        }))
        .expect("table parses")
    }

    fn batch(records: &[Vec<u8>], digest: u32) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        for r in records {
            body.extend_from_slice(r);
        }
        let mut out = vec![0u8; tlm::BATCH_HEADER_SIZE];
        tlm::write_batch_header(&mut out, records.len() as u16, 7, digest).unwrap();
        out.extend_from_slice(&body);
        out
    }

    fn scalar(module: u16, id: u16, dim: u16, value: u64, t: u64) -> Vec<u8> {
        let mut b = vec![0u8; tlm::METRIC_SCALAR_SIZE];
        tlm::write_metric_scalar_dim(&mut b, module, t, tlm::METRIC_COUNTER, id, dim, value)
            .unwrap();
        b
    }

    #[test]
    fn digest_mismatch_refuses_resolution() {
        let mut c = Collector::new(Some(table()));
        let err = c
            .ingest(&batch(&[scalar(3, 0, 0, 1, 10)], 0xDEAD), 1_000)
            .unwrap_err();
        assert_eq!(
            err,
            IngestError::DigestMismatch {
                envelope: 0xDEAD,
                table: 0x42
            }
        );
        assert_eq!(c.refused, 1);
        assert!(c.series.is_empty(), "refused batches resolve NOTHING");
    }

    #[test]
    fn zero_digest_resolves_but_counts_unverified() {
        let mut c = Collector::new(Some(table()));
        c.ingest(&batch(&[scalar(3, 18, 0, 5, 10)], 0), 1_000)
            .unwrap();
        assert_eq!(c.unverified, 1);
        let text = c.render_prometheus();
        assert!(
            text.contains("fluxor_requests_total{") && text.contains("} 5"),
            "{text}"
        );
        assert!(!text.contains("_total_total"), "{text}");
    }

    #[test]
    fn composite_dim_decodes_row_major() {
        // sizes: partition max=4, group enum len=2 → dim = p*2 + g.
        let mut c = Collector::new(Some(table()));
        let dim = 3 * 2 + 1; // partition 3, group "audit"
        c.ingest(&batch(&[scalar(3, 20, dim as u16, 42, 10)], 0x42), 1_000)
            .unwrap();
        let text = c.render_prometheus();
        assert!(
            text.contains(r#"messaging_destination_partition_id="3""#),
            "{text}"
        );
        assert!(
            text.contains(r#"messaging_consumer_group_name="audit""#),
            "{text}"
        );
    }

    #[test]
    fn dim_other_folds_every_key() {
        let mut c = Collector::new(Some(table()));
        c.ingest(&batch(&[scalar(3, 20, tlm::DIM_OTHER, 9, 10)], 0x42), 1_000)
            .unwrap();
        let text = c.render_prometheus();
        assert!(text.contains(r#"messaging_destination_partition_id="__other__""#));
        assert!(text.contains(r#"messaging_consumer_group_name="__other__""#));
    }

    #[test]
    fn hist16_renders_declared_bounds_cumulatively() {
        let mut buckets = [0u64; tlm::HIST16_BUCKETS];
        buckets[2] = 5; // (500, 1000]
        buckets[15] = 1; // +Inf
        let mut rec = vec![0u8; tlm::METRIC_HIST16_SIZE];
        tlm::write_metric_histogram16(&mut rec, 3, 10, 19, 0, &buckets).unwrap();
        let mut c = Collector::new(Some(table()));
        c.ingest(&batch(&[rec], 0x42), 1_000).unwrap();
        let text = c.render_prometheus();
        assert!(text.contains(r#"le="1000""#), "{text}");
        // cumulative: 5 at le=1000 …
        assert!(text.contains(r#"le="1000"} 5"#), "{text}");
        // … and 6 at +Inf (the overflow bucket still registers).
        assert!(text.contains(r#"le="+Inf"} 6"#), "{text}");
        assert!(text.contains("fluxor_request_latency_us_count"), "{text}");
    }

    #[test]
    fn unresolved_hist16_renders_no_fabricated_bounds() {
        let buckets = [1u64; tlm::HIST16_BUCKETS];
        let mut rec = vec![0u8; tlm::METRIC_HIST16_SIZE];
        tlm::write_metric_histogram16(&mut rec, 9, 10, 2, 0, &buckets).unwrap();
        let mut c = Collector::new(None); // no table at all
        c.ingest(&batch(&[rec], 0), 1_000).unwrap();
        let text = c.render_prometheus();
        assert!(
            !text.contains("_bucket"),
            "no le labels can be honest: {text}"
        );
        assert!(text.contains("_count{"), "total still visible: {text}");
    }

    #[test]
    fn reboot_resets_boot_epoch() {
        let mut c = Collector::new(None);
        // First sample at device-time 100 s, wall 1e18 ns.
        c.ingest(
            &batch(&[scalar(3, 0, 0, 1, 100_000_000)], 0),
            1_000_000_000_000_000_000,
        )
        .unwrap();
        let e1 = c.sources[&3].boot_epoch_nanos;
        // Device timestamp collapses to 1 s: reboot. New epoch ≈ recv − 1 s.
        c.ingest(
            &batch(&[scalar(3, 0, 0, 2, 1_000_000)], 0),
            1_000_000_200_000_000_000,
        )
        .unwrap();
        let e2 = c.sources[&3].boot_epoch_nanos;
        assert!(e2 > e1, "epoch must move forward across a reboot");
    }

    #[test]
    fn frame_header_prefix_is_tolerated() {
        let mut c = Collector::new(None);
        let b = batch(&[scalar(1, 0, 0, 1, 10)], 0);
        let mut framed = vec![0x01, (b.len() & 0xFF) as u8, (b.len() >> 8) as u8];
        framed.extend_from_slice(&b);
        c.ingest(&framed, 1_000).unwrap();
        assert_eq!(c.datagrams, 1);
    }

    #[test]
    fn otlp_json_carries_start_time_and_dims() {
        let mut c = Collector::new(Some(table()));
        c.ingest(
            &batch(&[scalar(3, 20, 1, 42, 50_000_000)], 0x42),
            2_000_000_000_000_000_000,
        )
        .unwrap();
        let doc = c.render_otlp_json("bench");
        let s = doc.to_string();
        assert!(s.contains("startTimeUnixNano"));
        assert!(s.contains("messaging.consumer.group.name"));
        assert!(s.contains("resourceMetrics"));
    }
}
