//! Build-time instrument id-table for observability telemetry.
//!
//! Module-scope metrics and spans are referenced on the wire by a per-module
//! `id` — its index in the module's `[observability]` declaration. This builds
//! the `(module_index, id) -> name` resolution table the `observe` collector and
//! exporters ship, from the resolved graph's modules and their manifests'
//! `[observability]` tables. Global identity is `module_index:local_id`, so ids
//! never collide across modules and external modules add their own without
//! central coordination.
//!
//! Declaration order is the contract: a module's Nth declared metric (or span)
//! name is local id N, and the emitter references it by that same index.

use crate::manifest::{DimDomain, InstrumentDecl, Manifest, Observability};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// A `[[ci.observability.exemption]]` row from `fluxor.toml` — the
/// project-level escape hatch for a data-moving module whose manifest can't be
/// edited (e.g. a vendored/downstream module). Equivalent to a per-manifest
/// `[observability] exempt = "..."`, but declared centrally. See
/// `standards/observability.md` §9.
#[derive(Debug, Clone, Deserialize)]
pub struct TomlExemption {
    /// Module path as it appears in the lint (e.g. `foundation/quic`), matched
    /// against the manifest's directory path under `modules/`.
    pub module: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "documentation-only at scan time, mirrors hygiene exemptions"
    )]
    pub expires: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ExemptToml {
    #[serde(default)]
    ci: ExemptCi,
}
#[derive(Debug, Default, Deserialize)]
struct ExemptCi {
    #[serde(default)]
    observability: ExemptCfg,
}
#[derive(Debug, Default, Deserialize)]
struct ExemptCfg {
    #[serde(default)]
    exemption: Vec<TomlExemption>,
}

/// Load `[[ci.observability.exemption]]` rows from `<project_root>/fluxor.toml`.
/// Tolerant: a missing or unparseable file yields no exemptions (the
/// per-manifest `exempt` field remains the primary mechanism, so a broken
/// fluxor.toml never silently widens the gate).
pub fn load_toml_exemptions(project_root: &Path) -> Vec<TomlExemption> {
    let path = project_root.join("fluxor.toml");
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    match toml::from_str::<ExemptToml>(&raw) {
        Ok(parsed) => parsed.ci.observability.exemption,
        Err(_) => Vec::new(),
    }
}

/// A module's place in the resolved graph plus its declared instruments.
pub struct ModuleInstruments<'a> {
    pub name: &'a str,
    pub index: u16,
    pub observability: &'a Observability,
}

/// Instrument family — metrics and spans share the `(module, id)` space but are
/// looked up separately.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Family {
    Metric,
    Span,
}

impl Family {
    pub fn as_str(self) -> &'static str {
        match self {
            Family::Metric => "metric",
            Family::Span => "span",
        }
    }
}

/// Resolution table: `(module_index, family, local_id) -> name`, plus the
/// per-instrument metadata rows (`[[observability.instrument]]`): kind,
/// declared histogram bounds, and dimension domains. Bounds and dimensions
/// are metadata a consumer resolves — they never ride a sample.
#[derive(Default, Debug)]
pub struct IdTable {
    entries: BTreeMap<(u16, Family, u16), String>,
    /// `(module_index, metric_id) -> declaration` for instruments that
    /// declared metadata; plain counters have no row.
    meta: BTreeMap<(u16, u16), InstrumentDecl>,
    /// `module_index -> module name`, for the exported table.
    module_names: BTreeMap<u16, String>,
}

impl IdTable {
    /// Build the table from the resolved graph's instrumented modules.
    pub fn build(modules: &[ModuleInstruments<'_>]) -> Self {
        let mut table = IdTable::default();
        for m in modules {
            table.module_names.insert(m.index, m.name.to_string());
            for (i, name) in m.observability.metrics.iter().enumerate() {
                table
                    .entries
                    .insert((m.index, Family::Metric, i as u16), name.clone());
                if let Some(decl) = m.observability.instruments.iter().find(|d| &d.name == name) {
                    table.meta.insert((m.index, i as u16), decl.clone());
                }
            }
            for (i, name) in m.observability.spans.iter().enumerate() {
                table
                    .entries
                    .insert((m.index, Family::Span, i as u16), name.clone());
            }
        }
        table
    }

    /// The declared metadata for a wire `(module, metric_id)` pair, when the
    /// manifest carried an `[[observability.instrument]]` row for it.
    pub fn instrument_meta(&self, module: u16, id: u16) -> Option<&InstrumentDecl> {
        self.meta.get(&(module, id))
    }

    /// The canonical JSON export a host collector loads (`fluxor id-table`),
    /// carrying names, instrument metadata, and the table digest.
    pub fn to_json(&self) -> serde_json::Value {
        let mut body = self.to_json_body();
        let digest = self.digest();
        body["digest"] = serde_json::Value::String(format!("{digest:#010x}"));
        body
    }

    /// FNV-1a32 over the canonical (digest-less, compact, sorted) JSON body —
    /// the value the FXTL batch envelope carries so a collector refuses to
    /// resolve names against a table from a different image.
    pub fn digest(&self) -> u32 {
        crate::hash::fnv1a_hash(self.to_json_body().to_string().as_bytes())
    }

    /// The on-device bounds blob (`otel` param tag 6): hex text of `[count
    /// u8]` then per row `[module u16 LE][id u16 LE][nbounds u8] [bound_us
    /// u32 LE × nbounds]`, one row per instrument with declared bounds.
    /// `None` when the graph declares none. Capped at the module's 8-row
    /// table; rows past the cap are dropped with a stderr note — the encoder
    /// then skips those instruments on-device (degraded, never wrong; the
    /// fxtl path still carries them).
    pub fn bounds_blob_hex(&self) -> Option<String> {
        const ROW_CAP: usize = 8;
        let rows: Vec<(u16, u16, &InstrumentDecl)> = self
            .meta
            .iter()
            .filter(|(_, d)| !d.bounds_us.is_empty())
            .map(|(&(m, i), d)| (m, i, d))
            .collect();
        if rows.is_empty() {
            return None;
        }
        if rows.len() > ROW_CAP {
            eprintln!(
                "id-table: {} instruments declare bounds but the on-device \
                 table holds {ROW_CAP}; the rest encode host-side only",
                rows.len()
            );
        }
        let take = rows.len().min(ROW_CAP);
        let mut blob = vec![take as u8];
        for (m, i, d) in rows.into_iter().take(take) {
            blob.extend_from_slice(&m.to_le_bytes());
            blob.extend_from_slice(&i.to_le_bytes());
            blob.push(d.bounds_us.len() as u8);
            for b in &d.bounds_us {
                blob.extend_from_slice(&(*b as u32).to_le_bytes());
            }
        }
        Some(blob.iter().map(|b| format!("{b:02x}")).collect())
    }

    fn to_json_body(&self) -> serde_json::Value {
        use serde_json::{json, Value};
        let mut modules: Vec<Value> = Vec::new();
        // BTreeMap iteration is sorted, so the body — and therefore the
        // digest — is deterministic for a given table.
        let indices: Vec<u16> = {
            let mut v: Vec<u16> = self
                .entries
                .keys()
                .map(|&(m, _, _)| m)
                .chain(self.module_names.keys().copied())
                .collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        for idx in indices {
            let mut metrics: Vec<Value> = Vec::new();
            let mut spans: Vec<Value> = Vec::new();
            for (&(m, family, id), name) in &self.entries {
                if m != idx {
                    continue;
                }
                match family {
                    Family::Metric => {
                        let mut row = json!({ "id": id, "name": name });
                        if let Some(decl) = self.meta.get(&(m, id)) {
                            row["kind"] = json!(decl.kind.as_str());
                            if !decl.bounds_us.is_empty() {
                                row["bounds_us"] = json!(decl.bounds_us);
                            }
                            if !decl.dimensions.is_empty() {
                                let dims: Vec<Value> = decl
                                    .dimensions
                                    .iter()
                                    .map(|d| match &d.domain {
                                        DimDomain::Numeric { max } => {
                                            json!({ "key": d.key, "domain": "numeric", "max": max })
                                        }
                                        DimDomain::Enum { values } => {
                                            json!({ "key": d.key, "domain": "enum", "values": values })
                                        }
                                    })
                                    .collect();
                                row["dimensions"] = json!(dims);
                            }
                        }
                        metrics.push(row);
                    }
                    Family::Span => spans.push(json!({ "id": id, "name": name })),
                }
            }
            modules.push(json!({
                "index": idx,
                "name": self.module_names.get(&idx).cloned().unwrap_or_default(),
                "metrics": metrics,
                "spans": spans,
            }));
        }
        json!({ "version": 1, "modules": modules })
    }

    /// Resolve a metric name from a wire `(module, id)` pair.
    pub fn metric_name(&self, module: u16, id: u16) -> Option<&str> {
        self.entries
            .get(&(module, Family::Metric, id))
            .map(String::as_str)
    }

    /// Resolve a span name from a wire `(module, name_id)` pair.
    pub fn span_name(&self, module: u16, id: u16) -> Option<&str> {
        self.entries
            .get(&(module, Family::Span, id))
            .map(String::as_str)
    }

    /// Deterministic iteration over every `(module, family, id, name)` entry,
    /// sorted by key — the form an exporter ships to a host collector.
    pub fn entries(&self) -> impl Iterator<Item = (u16, Family, u16, &str)> {
        self.entries
            .iter()
            .map(|(&(module, family, id), name)| (module, family, id, name.as_str()))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── Instrumentation-contract lint (standards/observability.md §6) ───────────

/// A module's standing against the instrumentation contract.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObsStatus {
    /// Declares `[observability]` metrics and/or spans.
    Instrumented,
    /// Opts out with a stated reason.
    Exempt,
    /// Moves data but declares neither instruments nor an exemption — a gap.
    Uninstrumented,
    /// Has no non-control data port, so the contract does not apply.
    NotDataMoving,
}

/// The attribute-key vocabulary (`standards/observability.md` §5): the OTel
/// semantic-convention keys the standard names for reuse, extracted into a
/// checkable list so `fluxor lint observability` enforces the semantic
/// conventions as a live contract instead of prose. Keep this list in sync
/// with `standards/observability.md` §5 — a
/// key used by a manifest that is neither here nor `fluxor.*` is a lint
/// error, which is exactly the drift the rule exists to stop.
pub const SEMCONV_KEYS: &[&str] = &[
    // Resource
    "service.name",
    "service.instance.id",
    "service.version",
    "host.arch",
    // Network
    "network.transport",
    "network.peer.address",
    "network.peer.port",
    "network.io.direction",
    // TLS
    "tls.protocol.version",
    "tls.cipher",
    "tls.resumed",
    // HTTP
    "http.request.method",
    "http.route",
    "http.response.status_code",
    // Messaging (OTel canonical forms — partition / consumer-group)
    "messaging.destination.partition.id",
    "messaging.consumer.group.name",
    "messaging.operation.name",
    // Database
    "db.operation.name",
    "db.collection.name",
    "db.response.status_code",
    // Storage / FS
    "storage.operation",
    "storage.io.size",
];

/// A dimension key is valid when it is a semantic-convention key or lives
/// in the `fluxor.*` namespace (dotted lowercase, per the capability-surface
/// grammar). Everything else is a vocabulary error, not a style warning.
pub fn is_valid_attribute_key(key: &str) -> bool {
    if SEMCONV_KEYS.contains(&key) {
        return true;
    }
    key.starts_with("fluxor.") && is_valid_instrument_name(key)
}

/// An instrument name is dotted lowercase / `snake_case` (`bytes_in`,
/// `http.server.request`), matching the capability-surface grammar.
pub fn is_valid_instrument_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
}

/// Classify one module against the contract from its data-moving status and
/// `[observability]` declaration. Pure — the unit of the lint.
pub fn module_status(data_moving: bool, obs: &Observability) -> ObsStatus {
    if obs.exempt.is_some() {
        ObsStatus::Exempt
    } else if !obs.metrics.is_empty() || !obs.spans.is_empty() {
        ObsStatus::Instrumented
    } else if data_moving {
        ObsStatus::Uninstrumented
    } else {
        ObsStatus::NotDataMoving
    }
}

/// Result of scanning a module tree against the instrumentation contract.
#[derive(Default, Debug)]
pub struct ObsLintReport {
    pub scanned: usize,
    pub instrumented: usize,
    /// Data-moving modules missing both instruments and an exemption.
    pub uninstrumented: Vec<String>,
    /// `(module, reason)` for declared exemptions.
    pub exempt: Vec<(String, String)>,
    /// `(module, bad_name)` for malformed instrument names — hard errors.
    pub invalid_names: Vec<(String, String)>,
    /// `(module, bad_key)` for dimension keys outside the vocabulary —
    /// hard errors, so a typo cannot mint a new label key silently.
    pub invalid_attr_keys: Vec<(String, String)>,
}

impl ObsLintReport {
    /// Only malformed instrument names are hard errors. A data-moving module
    /// missing instrumentation is recorded in the gap list for reporting but
    /// does not fail the lint.
    pub fn has_errors(&self) -> bool {
        !self.invalid_names.is_empty() || !self.invalid_attr_keys.is_empty()
    }
}

/// Walk every `manifest.toml` under `root` and check the instrumentation
/// contract. A port with direction `input` (0) or `output` (1) — not `ctrl`
/// (2/3) — makes a module data-moving.
pub fn lint(root: &Path) -> ObsLintReport {
    lint_with_exemptions(root, &[])
}

/// As [`lint`], but a module whose path matches a `fluxor.toml`
/// `[[ci.observability.exemption]]` row is treated as `Exempt` even when its
/// manifest declares neither instruments nor an `exempt` reason. The
/// per-manifest field takes precedence; the toml list only rescues otherwise-
/// uninstrumented modules. See `standards/observability.md` §9.
pub fn lint_with_exemptions(root: &Path, toml_exemptions: &[TomlExemption]) -> ObsLintReport {
    let mut report = ObsLintReport::default();
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_name() != "manifest.toml" {
            continue;
        }
        let manifest = match Manifest::from_toml(entry.path()) {
            Ok(m) => m,
            Err(_) => continue, // not all manifest.toml parse as modules; skip
        };
        let name = entry
            .path()
            .parent()
            .and_then(|p| p.strip_prefix(root).ok())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| entry.path().display().to_string());

        report.scanned += 1;
        let obs = &manifest.observability;
        for n in obs.metrics.iter().chain(obs.spans.iter()) {
            if !is_valid_instrument_name(n) {
                report.invalid_names.push((name.clone(), n.clone()));
            }
        }
        for inst in &obs.instruments {
            for d in &inst.dimensions {
                if !is_valid_attribute_key(&d.key) {
                    report.invalid_attr_keys.push((name.clone(), d.key.clone()));
                }
            }
        }
        let data_moving = manifest
            .ports
            .iter()
            .any(|p| p.direction == 0 || p.direction == 1);
        match module_status(data_moving, obs) {
            ObsStatus::Instrumented => report.instrumented += 1,
            ObsStatus::Exempt => report
                .exempt
                .push((name.clone(), obs.exempt.clone().unwrap_or_default())),
            ObsStatus::Uninstrumented => {
                // A fluxor.toml exemption rescues an otherwise-uninstrumented
                // data-moving module (the downstream/vendored escape hatch).
                // Match tolerantly: the lint name is the path under `modules/`
                // (e.g. `foundation/quic`), so accept a row written either way
                // (`foundation/quic` or `modules/foundation/quic`).
                if let Some(ex) = toml_exemptions.iter().find(|e| {
                    let m = e.module.strip_prefix("modules/").unwrap_or(&e.module);
                    m == name
                }) {
                    report
                        .exempt
                        .push((name.clone(), format!("{} (fluxor.toml)", ex.reason)));
                } else {
                    report.uninstrumented.push(name.clone());
                }
            }
            ObsStatus::NotDataMoving => {}
        }
    }
    report.uninstrumented.sort();
    report.exempt.sort();
    report.invalid_names.sort();
    report.invalid_attr_keys.sort();
    report
}

/// Build the id-table for a STACK-EXPANDED graph config: module index =
/// position in `modules:` — the scheduler instantiates in declaration order,
/// which is why stack expansion PREPENDS its modules before this runs — and
/// each entry's type resolves to its source `[observability]` table by
/// locating `<root>/**/<type>/manifest.toml` across `roots` in order. A type
/// with no locatable manifest (a built-in, or a dependency shipped only as an
/// .fmod) still consumes its index with an empty row, so later modules keep
/// the index the kernel stamps.
///
/// Determinism note: the digest of the resulting table covers exactly what
/// these `roots` can see, so the exporter (`fluxor id-table`) and the builder
/// injection (`stack_expand`) must use the same roots or the collector will
/// refuse the mismatch — which is the correct outcome for two genuinely
/// different tables.
/// The manifest-lookup roots BOTH the id-table exporter and the build-time
/// digest/bounds injection resolve against for `project_root`: the project's
/// own `modules/` plus any `[observability] id_table_dirs` rows from its
/// `fluxor.toml` (paths relative to the project root — a consumer repo lists
/// its dependency checkouts here so store-resolved foundation modules get
/// name-complete rows). One function so the two sides CANNOT diverge — a
/// digest computed over different roots than the export is exactly the
/// mismatch the handshake refuses.
pub fn id_table_roots(project_root: &Path) -> Vec<std::path::PathBuf> {
    let mut roots = vec![project_root.join("modules")];
    if let Ok(text) = std::fs::read_to_string(project_root.join("fluxor.toml")) {
        if let Ok(v) = toml::from_str::<toml::Value>(&text) {
            if let Some(dirs) = v
                .get("observability")
                .and_then(|o| o.get("id_table_dirs"))
                .and_then(|d| d.as_array())
            {
                for d in dirs {
                    if let Some(rel) = d.as_str() {
                        roots.push(project_root.join(rel));
                    }
                }
            }
        }
    }
    roots
}

pub fn id_table_for_expanded_config(
    config: &serde_json::Value,
    roots: &[std::path::PathBuf],
) -> IdTable {
    let mut obs_cache: BTreeMap<String, Option<Observability>> = BTreeMap::new();
    let mut lookup = |ty: &str| -> Option<Observability> {
        if let Some(hit) = obs_cache.get(ty) {
            return hit.clone();
        }
        let mut found = None;
        'roots: for root in roots {
            for entry in walkdir::WalkDir::new(root)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_name() != "manifest.toml" {
                    continue;
                }
                let parent_is_type = entry
                    .path()
                    .parent()
                    .and_then(|p| p.file_name())
                    .is_some_and(|n| n == ty);
                if !parent_is_type {
                    continue;
                }
                if let Ok(m) = Manifest::from_toml(entry.path()) {
                    found = Some(m.observability);
                    break 'roots;
                }
            }
        }
        obs_cache.insert(ty.to_string(), found.clone());
        found
    };

    let mut owned: Vec<(String, Observability)> = Vec::new();
    if let Some(modules) = config.get("modules").and_then(|m| m.as_array()) {
        for entry in modules {
            let name = entry
                .as_str()
                .or_else(|| entry.get("name").and_then(|v| v.as_str()))
                .unwrap_or("<unnamed>");
            let ty = entry.get("type").and_then(|v| v.as_str()).unwrap_or(name);
            owned.push((name.to_string(), lookup(ty).unwrap_or_default()));
        }
    }
    let rows: Vec<ModuleInstruments<'_>> = owned
        .iter()
        .enumerate()
        .map(|(i, (name, obs))| ModuleInstruments {
            name,
            index: i as u16,
            observability: obs,
        })
        .collect();
    IdTable::build(&rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(metrics: &[&str], spans: &[&str]) -> Observability {
        Observability {
            metrics: metrics.iter().map(|s| s.to_string()).collect(),
            spans: spans.iter().map(|s| s.to_string()).collect(),
            exempt: None,
            instruments: vec![],
        }
    }

    #[test]
    fn ids_are_declaration_order_and_namespaced_by_module() {
        let ip = obs(&["bytes_in", "bytes_out", "bp_steps"], &["tcp.connection"]);
        let http = obs(&["requests"], &["http.server.request"]);
        let modules = [
            ModuleInstruments {
                name: "ip",
                index: 4,
                observability: &ip,
            },
            ModuleInstruments {
                name: "http",
                index: 7,
                observability: &http,
            },
        ];
        let table = IdTable::build(&modules);

        // Local ids follow declaration order, scoped to the module index.
        assert_eq!(table.metric_name(4, 0), Some("bytes_in"));
        assert_eq!(table.metric_name(4, 2), Some("bp_steps"));
        assert_eq!(table.span_name(4, 0), Some("tcp.connection"));
        // Same local id 0 in a different module resolves independently.
        assert_eq!(table.metric_name(7, 0), Some("requests"));
        assert_eq!(table.span_name(7, 0), Some("http.server.request"));
        // Unknown ids resolve to nothing, not a neighbouring name.
        assert_eq!(table.metric_name(4, 9), None);
        assert_eq!(table.span_name(7, 1), None);
        assert_eq!(table.len(), 6);
    }

    #[test]
    fn entries_are_sorted_and_complete() {
        let m = obs(&["a", "b"], &["s"]);
        let modules = [ModuleInstruments {
            name: "m",
            index: 1,
            observability: &m,
        }];
        let table = IdTable::build(&modules);
        let collected: Vec<_> = table.entries().collect();
        assert_eq!(
            collected,
            vec![
                (1, Family::Metric, 0, "a"),
                (1, Family::Metric, 1, "b"),
                (1, Family::Span, 0, "s"),
            ]
        );
    }

    fn exempt(reason: &str) -> Observability {
        Observability {
            metrics: vec![],
            spans: vec![],
            exempt: Some(reason.to_string()),
            instruments: vec![],
        }
    }

    #[test]
    fn module_status_classifies_the_contract() {
        // Data-moving + declared instruments → instrumented.
        assert_eq!(
            module_status(true, &obs(&["bytes_in"], &[])),
            ObsStatus::Instrumented
        );
        // Data-moving + nothing declared → a gap.
        assert_eq!(
            module_status(true, &obs(&[], &[])),
            ObsStatus::Uninstrumented
        );
        // Data-moving + exemption → exempt, not a gap.
        assert_eq!(
            module_status(true, &exempt("hard real-time inner loop")),
            ObsStatus::Exempt
        );
        // No data port → the contract does not apply.
        assert_eq!(
            module_status(false, &obs(&[], &[])),
            ObsStatus::NotDataMoving
        );
    }

    #[test]
    fn instrument_names_are_dotted_lowercase() {
        assert!(is_valid_instrument_name("bytes_in"));
        assert!(is_valid_instrument_name("http.server.request"));
        assert!(!is_valid_instrument_name("BytesIn")); // uppercase
        assert!(!is_valid_instrument_name("bytes in")); // space
        assert!(!is_valid_instrument_name("")); // empty
    }

    #[test]
    fn report_fails_only_on_malformed_names() {
        let mut r = ObsLintReport::default();
        r.uninstrumented.push("modules/foo".into());
        assert!(
            !r.has_errors(),
            "missing instrumentation is a soft gap, not a hard error"
        );
        r.invalid_names
            .push(("modules/bar".into(), "Bad Name".into()));
        assert!(
            r.has_errors(),
            "a malformed instrument name is a hard error"
        );
    }

    /// Write a minimal data-moving manifest (one input + one output port, no
    /// `[observability]`) under `<root>/modules/<rel>/manifest.toml`.
    fn write_uninstrumented_module(modules_root: &Path, rel: &str) {
        let dir = modules_root.join(rel);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("manifest.toml"),
            "version = \"1.0.0\"\nhardware_targets = [\"rp2350\"]\n\n\
             [[ports]]\nname = \"in0\"\ndirection = \"input\"\ncontent_type = \"OctetStream\"\n\n\
             [[ports]]\nname = \"out0\"\ndirection = \"output\"\ncontent_type = \"OctetStream\"\n",
        )
        .unwrap();
    }

    #[test]
    fn fluxor_toml_exemption_rescues_an_uninstrumented_module() {
        let tmp = tempfile::tempdir().unwrap();
        let modules_root = tmp.path().join("modules");
        write_uninstrumented_module(&modules_root, "foundation/widget");

        // No exemptions → the module is an uninstrumented gap.
        let bare = lint(&modules_root);
        assert_eq!(bare.uninstrumented, vec!["foundation/widget".to_string()]);
        assert!(bare.exempt.is_empty());

        // A matching fluxor.toml row (bare path) rescues it to exempt.
        let ex = vec![TomlExemption {
            module: "foundation/widget".into(),
            reason: "vendored — owner instruments upstream".into(),
            expires: None,
        }];
        let rescued = lint_with_exemptions(&modules_root, &ex);
        assert!(rescued.uninstrumented.is_empty());
        assert_eq!(rescued.exempt.len(), 1);
        assert_eq!(rescued.exempt[0].0, "foundation/widget");
        assert!(rescued.exempt[0].1.contains("fluxor.toml"));

        // The `modules/`-prefixed form matches the same module.
        let ex_prefixed = vec![TomlExemption {
            module: "modules/foundation/widget".into(),
            reason: "vendored".into(),
            expires: None,
        }];
        assert!(
            lint_with_exemptions(&modules_root, &ex_prefixed)
                .uninstrumented
                .is_empty(),
            "a `modules/`-prefixed exemption path must match too"
        );

        // A non-matching row leaves the gap in place.
        let ex_miss = vec![TomlExemption {
            module: "foundation/other".into(),
            reason: "x".into(),
            expires: None,
        }];
        assert_eq!(
            lint_with_exemptions(&modules_root, &ex_miss).uninstrumented,
            vec!["foundation/widget".to_string()]
        );
    }

    #[test]
    fn load_toml_exemptions_parses_rows_and_tolerates_absence() {
        let tmp = tempfile::tempdir().unwrap();
        // Missing fluxor.toml → empty, no error.
        assert!(load_toml_exemptions(tmp.path()).is_empty());

        std::fs::write(
            tmp.path().join("fluxor.toml"),
            "[[ci.observability.exemption]]\n\
             module = \"foundation/widget\"\n\
             reason = \"vendored\"\n",
        )
        .unwrap();
        let rows = load_toml_exemptions(tmp.path());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].module, "foundation/widget");
        assert_eq!(rows[0].reason, "vendored");
    }
    /// `id_table_roots` is the single source both the exporter and the
    /// build-time injection resolve manifests from; the `fluxor.toml`
    /// `[observability] id_table_dirs` rows extend it project-relative.
    #[test]
    fn id_table_roots_reads_project_dirs() {
        let tmp = std::env::temp_dir().join(format!("fx_roots_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        std::fs::write(
            tmp.join("fluxor.toml"),
            "[observability]\nid_table_dirs = [\"../dep_a/modules\", \"../dep_b/modules\"]\n",
        )
        .unwrap();
        let roots = id_table_roots(&tmp);
        assert_eq!(roots[0], tmp.join("modules"));
        assert_eq!(roots[1], tmp.join("../dep_a/modules"));
        assert_eq!(roots[2], tmp.join("../dep_b/modules"));
        // No fluxor.toml (or no key) → the project tree alone.
        let bare = std::env::temp_dir().join(format!("fx_roots_bare_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&bare);
        assert_eq!(id_table_roots(&bare), vec![bare.join("modules")]);
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_dir_all(&bare);
    }

    /// The on-device bounds blob layout is a wire contract with otel's
    /// `parse_bounds_blob` (param tag 6): `[count u8]` then per row
    /// `[module u16][id u16][nbounds u8][bound_us u32 × n]`, all LE, hex text.
    #[test]
    fn bounds_blob_pins_the_device_wire_layout() {
        use crate::manifest::{InstrumentDecl, InstrumentKind};
        let mut obs = obs(&["latency_us"], &[]);
        obs.instruments.push(InstrumentDecl {
            name: "latency_us".into(),
            kind: InstrumentKind::Histogram16,
            bounds_us: vec![250, 500, 1000],
            dimensions: vec![],
        });
        let rows = [ModuleInstruments {
            name: "http",
            index: 3,
            observability: &obs,
        }];
        let hex = IdTable::build(&rows).bounds_blob_hex().expect("blob");
        // count=1 | module=3 | id=0 | n=3 | 250,500,1000 LE.
        assert_eq!(
            hex,
            "0103000000".to_owned() + "03" + "fa000000f4010000e8030000"
        );
        // A table with no declared bounds injects nothing.
        assert!(IdTable::build(&[ModuleInstruments {
            name: "ip",
            index: 0,
            observability: &obs_plain(),
        }])
        .bounds_blob_hex()
        .is_none());
    }

    fn obs_plain() -> Observability {
        obs(&["bytes_in"], &[])
    }

    /// Vocabulary: semconv keys and `fluxor.*` pass; anything else —
    /// including a malformed fluxor key — is a hard error, so a typo cannot
    /// mint a new label key silently.
    #[test]
    fn attribute_keys_validate_against_the_semconv_vocabulary() {
        assert!(is_valid_attribute_key("messaging.consumer.group.name"));
        assert!(is_valid_attribute_key("messaging.destination.partition.id"));
        assert!(is_valid_attribute_key("db.operation.name"));
        assert!(is_valid_attribute_key("fluxor.dim"));
        assert!(is_valid_attribute_key("fluxor.conn_id"));
        assert!(!is_valid_attribute_key("my.random.key"));
        assert!(!is_valid_attribute_key("fluxor.BAD"));
        assert!(!is_valid_attribute_key(""));
    }
}
