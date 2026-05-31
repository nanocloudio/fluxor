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

use crate::manifest::{Manifest, Observability};
use std::collections::BTreeMap;
use std::path::Path;

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

/// Resolution table: `(module_index, family, local_id) -> name`.
#[derive(Default, Debug)]
pub struct IdTable {
    entries: BTreeMap<(u16, Family, u16), String>,
}

impl IdTable {
    /// Build the table from the resolved graph's instrumented modules.
    pub fn build(modules: &[ModuleInstruments<'_>]) -> Self {
        let mut table = IdTable::default();
        for m in modules {
            for (i, name) in m.observability.metrics.iter().enumerate() {
                table
                    .entries
                    .insert((m.index, Family::Metric, i as u16), name.clone());
            }
            for (i, name) in m.observability.spans.iter().enumerate() {
                table
                    .entries
                    .insert((m.index, Family::Span, i as u16), name.clone());
            }
        }
        table
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
}

impl ObsLintReport {
    /// Only malformed instrument names are hard errors. A data-moving module
    /// missing instrumentation is recorded in the gap list for reporting but
    /// does not fail the lint.
    pub fn has_errors(&self) -> bool {
        !self.invalid_names.is_empty()
    }
}

/// Walk every `manifest.toml` under `root` and check the instrumentation
/// contract. A port with direction `input` (0) or `output` (1) — not `ctrl`
/// (2/3) — makes a module data-moving.
pub fn lint(root: &Path) -> ObsLintReport {
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
        let data_moving = manifest
            .ports
            .iter()
            .any(|p| p.direction == 0 || p.direction == 1);
        match module_status(data_moving, obs) {
            ObsStatus::Instrumented => report.instrumented += 1,
            ObsStatus::Exempt => report
                .exempt
                .push((name.clone(), obs.exempt.clone().unwrap_or_default())),
            ObsStatus::Uninstrumented => report.uninstrumented.push(name.clone()),
            ObsStatus::NotDataMoving => {}
        }
    }
    report.uninstrumented.sort();
    report.exempt.sort();
    report.invalid_names.sort();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(metrics: &[&str], spans: &[&str]) -> Observability {
        Observability {
            metrics: metrics.iter().map(|s| s.to_string()).collect(),
            spans: spans.iter().map(|s| s.to_string()).collect(),
            exempt: None,
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
}
