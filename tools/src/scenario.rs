//! Deployment scenarios — declarative multi-graph orchestration.
//!
//! A *scenario* is a YAML manifest that describes which Fluxor graphs
//! participate in a deployment, on which runtimes they run, and how they
//! bind to each other. See `.context/rfc_deployment_scenarios.md` for the
//! full design.
//!
//! This module implements **PRs 1–2** of the RFC's five-PR rollout:
//!   - Serde structs mirroring the §5 schema.
//!   - Path resolution + structural validation.
//!   - Component-graph reachability + runtime_override sanity checks
//!     (no module-mask check yet — that lands in PR 5 alongside the
//!     auto-rebuild path).
//!   - **PR 2** Real synthesiser: builds a `serde_json::Value` graph
//!     that the existing `tools::board::validate_config` accepts as
//!     a hand-written linux YAML.
//!   - **PR 2** Binding route merger: reads each component's graph,
//!     mutates the named http module's `routes:` array, detects
//!     conflicts on `path:`, cites the offending file (line numbers
//!     deferred — serde_yaml does not surface them for `Value` reads).
//!   - **PR 2** Re-validation of the merged config via
//!     `tools::board::validate_config`.
//!   - `--list` scenario discovery in a directory.
//!   - `--print-synthesised`, `--print-merged`, `--graph` dumps.
//!
//! Out of scope here (deferred to later PRs):
//!   - Process orchestration / spawning (PRs 3–4).
//!   - `runtime_override:` auto-rebuild (PR 5).
//!   - Scenario nesting (§16 Q5; later PR).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Error, Result};

// ============================================================================
// Schema
// ============================================================================

/// Top-level scenario document.
///
/// Mirrors the §5 RFC schema. `kind: scenario` is required (sniffed by
/// the dispatcher before this struct is deserialised; the field is kept
/// in the struct so a stray graph YAML with `kind: scenario` round-trips
/// rather than silently mis-parses).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub kind: String,
    pub name: String,
    pub components: BTreeMap<String, ComponentSpec>,
    #[serde(default)]
    pub host: Option<HostSpec>,
    #[serde(default)]
    pub bindings: Vec<Binding>,
    #[serde(default)]
    pub sequential: bool,
}

/// One component inside a scenario.
///
/// Exactly one of `graph` or `scenario` must be set (mutual exclusion
/// is checked in [`validate`]). The `scenario` variant is reserved for
/// nesting (§16 Q5) and rejected with a clear message in PR 1.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentSpec {
    #[serde(default)]
    pub graph: Option<PathBuf>,
    #[serde(default)]
    pub scenario: Option<PathBuf>,
    #[serde(default)]
    pub runtime_override: Option<String>,
    #[serde(default)]
    pub host_page: Option<PathBuf>,
    #[serde(default)]
    pub duration: Option<u32>,
    /// Per-module scalar overrides applied at deploy time.  Parsed
    /// here so PR 1's validator can reject malformed shapes early; the
    /// actual deploy-time merge lives in the route-merger / spawn path
    /// (PRs 2–4).
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
    )]
    pub params: BTreeMap<String, BTreeMap<String, serde_yaml::Value>>,
}

/// Synthesised-host knobs. Optional — present only when at least one
/// binding wants to mount on an implicit linux origin.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSpec {
    pub port: u16,
}

/// Cross-component plumbing. Tagged-by-presence rather than by an
/// explicit `kind:` field so the YAML stays uncluttered for one-line
/// bindings (`- serve: viewer`). The choice is bikeshed-worthy (§16
/// open question, deferred); we keep `serve:` / `list:` as siblings
/// today.
#[derive(Debug, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Binding {
    Serve(ServeBinding),
    List(ListBinding),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServeBinding {
    pub serve: String,
    /// `<component>.<module>` — http module to mount on.  When `None`,
    /// the binding lands on the synthesised host.
    #[serde(default)]
    pub on: Option<String>,
    #[serde(default = "default_prefix")]
    pub prefix: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListBinding {
    pub list: PathBuf,
    #[serde(default)]
    pub formats: Vec<String>,
    #[serde(default)]
    pub on: Option<String>,
    #[serde(default = "default_list_path")]
    pub path: String,
}

fn default_prefix() -> String {
    "/".into()
}
fn default_list_path() -> String {
    "/api/list".into()
}

// ============================================================================
// Parsing
// ============================================================================

/// Read and parse a scenario YAML file.  Validates `kind: scenario`
/// before deserialising the body (so users see "this is a graph, not a
/// scenario" rather than a serde error citing a missing
/// `components:` field).
pub fn parse(path: &Path) -> Result<Scenario> {
    let text = fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("scenario {}: {}", path.display(), e)))?;

    // Pre-flight sniff: read just the `kind:` field.
    let probe: serde_yaml::Value = serde_yaml::from_str(&text).map_err(|e| {
        Error::Config(format!(
            "scenario {}: YAML parse error: {}",
            path.display(),
            e
        ))
    })?;
    match probe.get("kind").and_then(|v| v.as_str()) {
        Some("scenario") => {}
        Some(other) => {
            return Err(Error::Config(format!(
                "scenario {}: top-level `kind:` is {:?}, expected \"scenario\"",
                path.display(),
                other
            )));
        }
        None => {
            return Err(Error::Config(format!(
                "scenario {}: missing top-level `kind: scenario` (this looks like a graph YAML; \
                 use `fluxor run` on the graph directly, or wrap it in a scenario)",
                path.display()
            )));
        }
    }

    let scenario: Scenario = serde_yaml::from_str(&text)
        .map_err(|e| Error::Config(format!("scenario {}: {}", path.display(), e)))?;
    Ok(scenario)
}

/// Cheap sniff: returns `Ok(true)` iff the file's top-level YAML map
/// carries `kind: scenario`.  Used by `cmd_run` to dispatch without
/// fully deserialising.
pub fn is_scenario_file(path: &Path) -> bool {
    let Ok(text) = fs::read_to_string(path) else {
        return false;
    };
    let Ok(probe) = serde_yaml::from_str::<serde_yaml::Value>(&text) else {
        return false;
    };
    probe
        .get("kind")
        .and_then(|v| v.as_str())
        .map(|s| s == "scenario")
        .unwrap_or(false)
}

// ============================================================================
// Inline scenario: orchestration block embedded in a graph YAML
// ============================================================================
//
// A graph YAML can carry an optional top-level `scenario:` block that
// names the graph's deployment shape:
//
//   target: cm5
//   modules: [...]
//   wiring:  [...]
//
//   scenario:
//     name: image_viewer_cm5
//     companions:
//       viewer: ../wasm/image_viewer_thin.yaml
//     bindings:
//       - serve: viewer
//         on: main.http      # `main` is the host graph itself
//         prefix: /viewer
//
// When `fluxor run` sees this block on a graph YAML, it synthesises
// an in-memory `Scenario` (with the host graph as the "main"
// component) and dispatches through the regular scenario flow. The
// result: one file per example per platform — no separate
// standalone scenario sibling needed.
//
// The block fields mirror the explicit-scenario schema (§5) one-to-
// one minus the always-implicit primary component:
//   * `name`             — scenario name
//   * `companions`       — map of `<name>: <path>` graphs to spawn alongside
//   * `bindings`         — same shape as the scenario-file `bindings:`
//   * `host`             — same shape as the scenario-file `host:`
//   * `sequential`       — same as the scenario-file flag
//   * `runtime_override` — applied to `main`; the dev-iteration knob for
//                          running a silicon-target graph as a linux process

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InlineScenarioBlock {
    pub name: String,
    #[serde(default)]
    pub companions: BTreeMap<String, PathBuf>,
    #[serde(default)]
    pub bindings: Vec<Binding>,
    #[serde(default)]
    pub host: Option<HostSpec>,
    #[serde(default)]
    pub sequential: bool,
    /// `runtime_override:` applied to the host graph (the `main`
    /// component). Same semantics as `ComponentSpec::runtime_override`
    /// in an explicit scenario: typically `linux` or `qemu` so a
    /// silicon-target graph can be exercised end-to-end on a
    /// workstation. Untouched silicon (no override) is the production
    /// flash path; the rig harness builds via `build_one`, which does
    /// not go through the inline-scenario flow.
    #[serde(default)]
    pub runtime_override: Option<String>,
}

/// If `graph_path` is a graph YAML with a top-level `scenario:` block,
/// synthesise a [`Scenario`] in memory so the regular scenario
/// dispatch flow (validation, build, spawn) Just Works. Returns
/// `Ok(None)` if the file is missing the block.
///
/// The synthesised scenario has one component named `"main"` that
/// references the graph path itself (so `revalidate_all` re-reads the
/// graph via the same FS path the user typed), plus one component per
/// entry in `companions:`. Bindings are copied through verbatim — they
/// reference components by name exactly like an explicit scenario file
/// would.
pub fn synthesize_from_graph(graph_path: &Path) -> Result<Option<Scenario>> {
    let text = fs::read_to_string(graph_path)
        .map_err(|e| Error::Config(format!("graph {}: {}", graph_path.display(), e)))?;
    let probe: serde_yaml::Value = serde_yaml::from_str(&text).map_err(|e| {
        Error::Config(format!(
            "graph {}: YAML parse error: {}",
            graph_path.display(),
            e
        ))
    })?;
    let Some(block_value) = probe.get("scenario") else {
        return Ok(None);
    };
    let block: InlineScenarioBlock = serde_yaml::from_value(block_value.clone()).map_err(|e| {
        Error::Config(format!(
            "graph {}: invalid `scenario:` block: {}",
            graph_path.display(),
            e
        ))
    })?;

    // Path resolution for an inline scenario uses the graph YAML's
    // parent as the base (companions: paths are relative to it, same
    // as a standalone `kind: scenario` file). The `main` component's graph
    // is therefore just the graph file's basename — joining it with
    // the same parent yields the original path back. Storing the full
    // path here would double-prepend the parent dir during validation
    // / merge (`base.join(component.graph)`).
    let main_graph_rel = graph_path
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| graph_path.to_path_buf());
    let mut components = BTreeMap::new();
    components.insert(
        "main".to_string(),
        ComponentSpec {
            graph: Some(main_graph_rel),
            scenario: None,
            runtime_override: block.runtime_override.clone(),
            host_page: None,
            duration: None,
            params: BTreeMap::new(),
        },
    );
    for (name, path) in block.companions {
        if name == "main" {
            return Err(Error::Config(format!(
                "graph {}: companion name `main` is reserved (it refers to the host graph itself)",
                graph_path.display()
            )));
        }
        components.insert(
            name,
            ComponentSpec {
                graph: Some(path),
                scenario: None,
                runtime_override: None,
                host_page: None,
                duration: None,
                params: BTreeMap::new(),
            },
        );
    }

    Ok(Some(Scenario {
        kind: "scenario".to_string(),
        name: block.name,
        components,
        host: block.host,
        bindings: block.bindings,
        sequential: block.sequential,
    }))
}

// ============================================================================
// Validation
// ============================================================================

/// Validate a parsed scenario against the §5 schema rules and the §16
/// invariants. `scenario_path` is used for path resolution (`graph:`,
/// `host_page:`, `list:` all resolve relative to the scenario YAML's
/// directory) and for error messages.
///
/// PR 1 scope:
///   - Component existence (`graph:` path exists and is readable).
///   - Mutual exclusion of `graph:` / `scenario:`.
///   - `kind: scenario` is set to `"scenario"`.
///   - At least one component.
///   - Wasm components have a host or a serve-binding with `on:` set.
///   - `host:` present iff at least one binding's `on:` is omitted.
///   - Binding references resolve (`serve:` / `on:` name defined
///     components).
///   - `runtime_override:` is one of {linux, qemu}; never on a wasm
///     component (§16 Q3).
///   - `host_page:` exists on disk (when set).
///   - `list:` directory exists on disk (when set).
///   - Binding dependency graph is a DAG (cycle → hard error).
///   - Under `sequential: true`, every component declares `duration:`
///     OR exits on its own (heuristic: any component whose graph
///     target is wasm exits on tab-close, not on its own — flag it).
///     Per RFC: "every component that does not exit on its own must
///     declare `duration:`". PR 1 conservatively warns; PR 4 enforces.
///
/// Deferred to PR 2: route-conflict detection (requires parsing each
/// component's graph YAML and walking its http module's `routes:`
/// table — done in the route merger).
///
/// Deferred to PR 5: module-mask compatibility check for
/// `runtime_override:` (requires loading every module's manifest).
pub fn validate(scenario: &Scenario, scenario_path: &Path) -> Result<()> {
    let base = scenario_path
        .parent()
        .ok_or_else(|| Error::Config("scenario path has no parent dir".into()))?;

    if scenario.kind != "scenario" {
        return Err(Error::Config(format!(
            "scenario {}: `kind:` must be \"scenario\" (saw {:?})",
            scenario_path.display(),
            scenario.kind
        )));
    }

    if scenario.components.is_empty() {
        return Err(Error::Config(format!(
            "scenario {}: must declare at least one component under `components:`",
            scenario_path.display()
        )));
    }

    // --- per-component checks ---
    let mut graph_targets: HashMap<String, String> = HashMap::new();
    for (name, comp) in &scenario.components {
        match (&comp.graph, &comp.scenario) {
            (Some(_), Some(_)) => {
                return Err(Error::Config(format!(
                    "scenario {}: component `{}` declares both `graph:` and `scenario:` \
                     — they are mutually exclusive (see RFC §5).",
                    scenario_path.display(),
                    name
                )));
            }
            (None, None) => {
                return Err(Error::Config(format!(
                    "scenario {}: component `{}` declares neither `graph:` nor `scenario:`.",
                    scenario_path.display(),
                    name
                )));
            }
            (None, Some(_)) => {
                return Err(Error::Config(format!(
                    "scenario {}: component `{}` uses `scenario:` (nesting). \
                     Scenario nesting is designed-in (RFC §16 Q5) but not yet implemented — \
                     a follow-up PR will wire the recursive runner.",
                    scenario_path.display(),
                    name
                )));
            }
            (Some(graph_path), None) => {
                let resolved = base.join(graph_path);
                if !resolved.is_file() {
                    return Err(Error::Config(format!(
                        "scenario {}: component `{}` references graph {} \
                         (resolved {}), which does not exist or is not a file.",
                        scenario_path.display(),
                        name,
                        graph_path.display(),
                        resolved.display()
                    )));
                }
                // Sniff the graph's `target:` so we can validate
                // wasm-must-have-host and runtime_override rules
                // without fully loading the graph.
                let target = sniff_graph_target(&resolved).unwrap_or_default();
                graph_targets.insert(name.clone(), target);
            }
        }

        if let Some(ovr) = &comp.runtime_override {
            match ovr.as_str() {
                "linux" | "qemu" => {}
                "wasm" => {
                    return Err(Error::Config(format!(
                        "scenario {}: component `{}` has `runtime_override: wasm`. \
                         Wasm bundles execute in a browser; the runtime cannot be coerced \
                         (RFC §16 Q3).",
                        scenario_path.display(),
                        name
                    )));
                }
                other => {
                    return Err(Error::Config(format!(
                        "scenario {}: component `{}` has `runtime_override: {}`. \
                         Must be one of {{linux, qemu}}.",
                        scenario_path.display(),
                        name,
                        other
                    )));
                }
            }
            // Wasm graphs cannot be overridden (their bundle target is fixed).
            if graph_targets.get(name).map(String::as_str) == Some("wasm") {
                return Err(Error::Config(format!(
                    "scenario {}: component `{}` has `runtime_override:` but the underlying \
                     graph targets wasm. Wasm bundles always build for the wasm target \
                     (RFC §16 Q3); remove the override.",
                    scenario_path.display(),
                    name
                )));
            }
        }

        if let Some(host_page) = &comp.host_page {
            let resolved = base.join(host_page);
            if !resolved.is_file() {
                return Err(Error::Config(format!(
                    "scenario {}: component `{}` declares host_page: {} \
                     (resolved {}), which does not exist.",
                    scenario_path.display(),
                    name,
                    host_page.display(),
                    resolved.display()
                )));
            }
        }
    }

    // --- binding checks ---
    let mut has_default_origin_binding = false;
    for (idx, binding) in scenario.bindings.iter().enumerate() {
        match binding {
            Binding::Serve(serve) => {
                if !scenario.components.contains_key(&serve.serve) {
                    return Err(Error::Config(format!(
                        "scenario {}: bindings[{}] `serve: {}` references an undefined component.",
                        scenario_path.display(),
                        idx,
                        serve.serve
                    )));
                }
                if let Some(target) = &serve.on {
                    check_on_reference(target, scenario, scenario_path, idx)?;
                } else {
                    has_default_origin_binding = true;
                }
                if !serve.prefix.starts_with('/') {
                    return Err(Error::Config(format!(
                        "scenario {}: bindings[{}] `prefix: {}` must start with `/`.",
                        scenario_path.display(),
                        idx,
                        serve.prefix
                    )));
                }
            }
            Binding::List(list) => {
                let resolved = base.join(&list.list);
                if !resolved.is_dir() {
                    return Err(Error::Config(format!(
                        "scenario {}: bindings[{}] `list: {}` (resolved {}) \
                         must reference an existing directory.",
                        scenario_path.display(),
                        idx,
                        list.list.display(),
                        resolved.display()
                    )));
                }
                if let Some(target) = &list.on {
                    check_on_reference(target, scenario, scenario_path, idx)?;
                } else {
                    has_default_origin_binding = true;
                }
                if !list.path.starts_with('/') {
                    return Err(Error::Config(format!(
                        "scenario {}: bindings[{}] `path: {}` must start with `/`.",
                        scenario_path.display(),
                        idx,
                        list.path
                    )));
                }
            }
        }
    }

    // --- host requirement ---
    let needs_default_origin = scenario
        .components
        .iter()
        .any(|(n, _)| graph_targets.get(n).map(String::as_str) == Some("wasm"))
        && !scenario.bindings.iter().any(|b| match b {
            Binding::Serve(s) => s.on.is_some(),
            _ => false,
        });

    if needs_default_origin && scenario.host.is_none() {
        return Err(Error::Config(format!(
            "scenario {}: declares a wasm component but neither a `host:` block \
             nor a `serve:` binding with `on:` pointing at a non-wasm component's http \
             module — wasm cannot run without an origin (RFC §5).",
            scenario_path.display()
        )));
    }

    if has_default_origin_binding && scenario.host.is_none() {
        return Err(Error::Config(format!(
            "scenario {}: has bindings without `on:` (i.e. mounting on the synthesised \
             host) but no `host:` block is declared. Add `host: {{ port: <PORT> }}`.",
            scenario_path.display()
        )));
    }

    // --- binding dependency DAG ---
    check_binding_dag(scenario, scenario_path)?;

    // --- sequential + duration consistency (warn-only PR 1; PR 4 enforces) ---
    if scenario.sequential {
        for (name, comp) in &scenario.components {
            if comp.duration.is_none() {
                let target = graph_targets.get(name).map(String::as_str).unwrap_or("");
                if target != "wasm" {
                    eprintln!(
                        "warning: scenario {}: sequential mode without `duration:` on \
                         component `{}` (target {:?}) — component must exit on its own. \
                         Will be enforced as a hard error in PR 4.",
                        scenario_path.display(),
                        name,
                        target
                    );
                }
            }
        }
    }

    Ok(())
}

fn check_on_reference(
    on: &str,
    scenario: &Scenario,
    scenario_path: &Path,
    idx: usize,
) -> Result<()> {
    let (comp, _module) = on.split_once('.').ok_or_else(|| {
        Error::Config(format!(
            "scenario {}: bindings[{}] `on: {}` must be `<component>.<module>` \
             (e.g. `decoder.http`).",
            scenario_path.display(),
            idx,
            on
        ))
    })?;
    if !scenario.components.contains_key(comp) {
        return Err(Error::Config(format!(
            "scenario {}: bindings[{}] `on: {}` references undefined component `{}`.",
            scenario_path.display(),
            idx,
            on,
            comp
        )));
    }
    // Module existence inside the graph is verified by the route
    // merger (PR 2); PR 1 only catches typo'd component names.
    Ok(())
}

fn check_binding_dag(scenario: &Scenario, scenario_path: &Path) -> Result<()> {
    // Build a producer→consumer graph: `serve: A` with `on: B.http`
    // means A's bundle is served by B → B starts before A's customer.
    // For cycle detection we treat each binding as an edge
    // `serve_target → on_component`.
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for binding in &scenario.bindings {
        let Binding::Serve(serve) = binding else {
            continue;
        };
        let Some(on) = &serve.on else { continue };
        let Some((on_comp, _)) = on.split_once('.') else {
            continue;
        };
        adj.entry(serve.serve.as_str()).or_default().push(on_comp);
    }

    let mut color: HashMap<&str, u8> = HashMap::new(); // 0=white, 1=gray, 2=black
    fn dfs<'a>(
        node: &'a str,
        adj: &'a HashMap<&str, Vec<&str>>,
        color: &mut HashMap<&'a str, u8>,
        path: &mut Vec<&'a str>,
    ) -> std::result::Result<(), Vec<String>> {
        color.insert(node, 1);
        path.push(node);
        if let Some(succs) = adj.get(node) {
            for &succ in succs {
                match color.get(succ).copied().unwrap_or(0) {
                    1 => {
                        // cycle: from succ's first appearance in path → end → succ
                        let start = path.iter().position(|&n| n == succ).unwrap_or(0);
                        let mut cycle: Vec<String> =
                            path[start..].iter().map(|s| (*s).to_string()).collect();
                        cycle.push(succ.to_string());
                        return Err(cycle);
                    }
                    2 => {}
                    _ => dfs(succ, adj, color, path)?,
                }
            }
        }
        path.pop();
        color.insert(node, 2);
        Ok(())
    }

    for node in adj.keys().copied().collect::<Vec<_>>() {
        if color.get(node).copied().unwrap_or(0) == 0 {
            let mut path = Vec::new();
            if let Err(cycle) = dfs(node, &adj, &mut color, &mut path) {
                return Err(Error::Config(format!(
                    "scenario {}: cyclic binding dependency: {}. \
                     A binding's `on:` target must not (transitively) depend on the \
                     binding's `serve:` source (RFC §14, §16).",
                    scenario_path.display(),
                    cycle.join(" → ")
                )));
            }
        }
    }
    Ok(())
}

/// Sniff a graph YAML's `target:` field cheaply. Returns the raw string
/// (e.g. `"wasm"`, `"cm5"`, `"linux"`, `"pico2w"`); empty string on any
/// parse error. We deliberately do NOT fully parse the graph here —
/// that's `cmd_build`'s job.
fn sniff_graph_target(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let probe: serde_yaml::Value = serde_yaml::from_str(&text).ok()?;
    probe
        .get("target")
        .and_then(|v| v.as_str())
        .map(String::from)
}

// ============================================================================
// PR 2: real synthesiser + binding route merger + re-validation
// ============================================================================

/// Construct the synthesised host graph as a `serde_json::Value`
/// equivalent to what a human would write in
/// `examples/serve_wasm/linux.yaml`. Returns `None` when the scenario
/// has no `host:` block (every binding has explicit `on:`).
///
/// The returned Value is the same shape `tools::board::validate_config`
/// consumes, so the caller can round-trip it through validation before
/// printing or spawning.
pub fn synthesise_host_config(
    scenario: &Scenario,
    scenario_path: &Path,
) -> Result<Option<serde_json::Value>> {
    let Some(host) = &scenario.host else {
        return Ok(None);
    };
    let base = scenario_path
        .parent()
        .ok_or_else(|| Error::Config("scenario path has no parent dir".into()))?;

    let routes = synthesise_host_routes(scenario, base, scenario_path)?;
    let http_module = serde_json::json!({
        "name": "http",
        "port": host.port,
        "host_tcp": 1,
        "routes": routes,
    });

    let config = serde_json::json!({
        "target": "linux",
        "platform": { "net": {} },
        // The http <-> linux_net wiring is the canonical 2-cycle
        // every linux http example carries. Until typed feedback
        // edges land in the scheduler (see RFC §13 "Known issue
        // blocking PR 3 end-to-end"), the synthesised host opts
        // explicitly into cycle acceptance so the scheduler stops
        // rejecting the graph at `prepare_graph` time. The cycle is
        // bidirectional and safe — each module just pumps its
        // respective channel.
        "scheduler": { "accept_cycles": true },
        "modules": [http_module],
        "wiring": [
            { "from": "linux_net.net_out", "to": "http.net_in" },
            { "from": "http.net_out",      "to": "linux_net.net_in" },
        ],
    });

    Ok(Some(config))
}

/// Canonical wasm runtime shell — the HTML page and JS shim that
/// every wasm bundle is served alongside. **Baked into
/// `fluxor-tools` at compile time** via `include_str!` because they
/// are shared infrastructure (byte-identical across every wasm
/// scenario in the tree), not per-scenario data.
///
/// Partition principle: per-scenario things go in the `.wasm`
/// bundle (assets, PIC modules, config blob); shared infra lives
/// in the orchestrator. The shell is the browser-side analog of
/// `target/wasm/firmware.wasm` — built once into the orchestrator,
/// served once per scenario. Same shape as how `fluxor-linux`
/// hosts countless `bcm2712` configs without those configs
/// shipping their own kernel.
///
/// Edits to either file rebuild `fluxor-tools` automatically —
/// `include_str!` registers the file as a build dependency.
const CANONICAL_RUNTIME_HTML_RAW: &str = include_str!("../../src/platform/wasm/host/runtime.html");
const CANONICAL_HOST_SHIMS_JS_RAW: &str =
    include_str!("../../src/platform/wasm/host/host_shims.js");
/// Generic browser-overlay renderer (`presentation.shell`). Inlined
/// into the served runtime.html (rather than a separate route) so it
/// costs no slot against the kernel's `MAX_ROUTES = 8`. Defines
/// `window.FluxorOverlay`; dormant until a scenario carries a
/// `presentation.shell` block.
const CANONICAL_OVERLAY_JS_RAW: &str =
    include_str!("../../src/platform/wasm/host/browser_overlay_runtime.js");
/// Marker in runtime.html where the overlay `<script>` is injected.
const OVERLAY_MARKER: &str = "<!--FLUXOR_OVERLAY_RUNTIME-->";

/// Escape every `${` so the config-load env-var substitutor passes
/// the content through verbatim. The shell HTML / JS contains lots
/// of JS template literals (`${msg}`, `${n}`, `${assetUrl}`, etc.)
/// that look like env-var refs but aren't; the substitutor's
/// existing `$${...}` escape syntax (see `substitute_env_vars`)
/// then collapses our `$${` back to literal `${` so the browser
/// sees the original source.
fn escape_for_env_substitution(s: &str) -> String {
    s.replace("${", "$${")
}

fn canonical_runtime_html_body() -> String {
    // Inline the overlay renderer at its marker before env-escaping, so
    // any `${` in the JS is escaped alongside the rest of the document.
    // If the marker is absent (older runtime.html), this is a no-op.
    let html = CANONICAL_RUNTIME_HTML_RAW.replace(
        OVERLAY_MARKER,
        &format!("<script>\n{CANONICAL_OVERLAY_JS_RAW}\n</script>"),
    );
    escape_for_env_substitution(&html)
}

fn canonical_host_shims_js_body() -> String {
    escape_for_env_substitution(CANONICAL_HOST_SHIMS_JS_RAW)
}

/// Walk a `list:` directory and build the `fluxor-manifest.json` entries
/// the wasm `storage.namespace` provider fetches at boot — one
/// `{ key, size, mtime, etag }` per file. Browsers can't `readdir` an
/// HTTP origin, so this synth-time directory snapshot is how a runtime
/// `storage.namespace` LIST enumerates shipped content. `key` is the
/// object key the `storage.object` provider fetches *as a URL*, so it
/// must equal the path the file is served at — `<path_prefix>/<relpath>`
/// with forward slashes and no leading slash, matching the `list:`
/// `path:` mount. `formats` (if non-empty) restricts to those extensions.
fn fluxor_manifest_entries(
    dir: &Path,
    path_prefix: &str,
    formats: &[String],
) -> Vec<serde_json::Value> {
    let prefix = path_prefix.trim_matches('/');
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        if !formats.is_empty() {
            let ext = p
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if !formats
                .iter()
                .any(|f| f.trim_start_matches('.').eq_ignore_ascii_case(&ext))
            {
                continue;
            }
        }
        let rel = match p.strip_prefix(dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let mut rel_str = String::new();
        for (i, comp) in rel.components().enumerate() {
            if i > 0 {
                rel_str.push('/');
            }
            rel_str.push_str(&comp.as_os_str().to_string_lossy());
        }
        let key = if prefix.is_empty() {
            rel_str
        } else {
            format!("{prefix}/{rel_str}")
        };
        let md = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let size = md.len();
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        out.push(serde_json::json!({
            "key": key,
            "size": size,
            "mtime": mtime,
            "etag": format!("{size:x}-{mtime:x}"),
        }));
    }
    out.sort_by(|a, b| {
        a["key"]
            .as_str()
            .unwrap_or("")
            .cmp(b["key"].as_str().unwrap_or(""))
    });
    out
}

/// Build the `routes:` array for the synthesised host. Mounts the
/// canonical wasm runtime assets + bundle + scenario metadata, plus
/// any user `serve:` host_page override and `list:` binding-injected
/// gallery routes.
///
/// Route plan:
///   - `/`              → `serve:` host_page OR canonical runtime.html
///   - `/fluxor.wasm`   → built bundle (from `serve:` component or default)
///   - `/host_shims.js` → canonical JS shim
///   - `/scenario.json` → inline JSON (presentation + playlist source)
///   - `/api/list`...   → `list:` bindings (dual-mode listing + file-serve)
///
/// Five routes baseline + N `list:` bindings, well under
/// `MAX_ROUTES = 8` (PR 10).
fn synthesise_host_routes(
    scenario: &Scenario,
    base: &Path,
    scenario_path: &Path,
) -> Result<Vec<serde_json::Value>> {
    let mut routes = Vec::new();

    // ── Track the active `serve:` binding so we can synthesise the
    //    `/`, `/fluxor.wasm`, and `/scenario.json` routes coherently.
    //    Multiple `serve:` bindings (one wasm + multiple host-page
    //    overrides) are not supported on the synth host today —
    //    the first one wins; subsequent ones would need explicit
    //    `on:` targets to mount elsewhere.
    //
    // The default page is the embedded canonical runtime shell
    // (`canonical_runtime_html_body`). A `host_page:` override on
    // the component swaps in a user-provided file via fs_path.
    let mut serve_component: Option<&str> = None;
    let mut runtime_prefix: String = "/".to_string();
    let mut bundle_route_url: String = "/fluxor.wasm".to_string();
    let mut runtime_override_fs_path: Option<PathBuf> = None;
    // Accumulated `fluxor-manifest.json` entries across all `list:`
    // bindings — the directory snapshot a runtime `storage.namespace`
    // LIST enumerates (browsers can't readdir an HTTP origin).
    let mut manifest_entries: Vec<serde_json::Value> = Vec::new();

    for binding in &scenario.bindings {
        match binding {
            Binding::Serve(serve) if serve.on.is_none() => {
                if serve_component.is_some() {
                    return Err(Error::Config(format!(
                        "scenario {}: multiple `serve:` bindings without `on:` are not \
                         supported on the synthesised host (each one would try to mount \
                         a different page at `/`). Give all but one an explicit `on:` target.",
                        scenario_path.display()
                    )));
                }
                serve_component = Some(serve.serve.as_str());
                runtime_prefix = serve.prefix.clone();
                bundle_route_url = if serve.prefix == "/" {
                    "/fluxor.wasm".to_string()
                } else {
                    format!("{}/fluxor.wasm", serve.prefix.trim_end_matches('/'))
                };
                let comp = scenario.components.get(&serve.serve).ok_or_else(|| {
                    Error::Config(format!(
                        "scenario {}: bindings reference undefined component `{}`",
                        scenario_path.display(),
                        serve.serve
                    ))
                })?;
                // host_page is OPTIONAL: when unset, the synth host
                // serves the canonical runtime shell embedded in
                // fluxor-tools. Custom shells (test harness,
                // research prototypes) still set
                // `host_page: my_shell.html` to override with an
                // on-disk file.
                if let Some(host_page) = &comp.host_page {
                    runtime_override_fs_path = Some(absolute_or_join(base, host_page));
                }
                let desc = format!("serve: {} (host_page)", serve.serve);

                // ── /  → host page (canonical embedded shell OR
                //    user fs_path override).
                if let Some(ref override_path) = runtime_override_fs_path {
                    check_fs_path_length(override_path, 0, &desc, scenario_path)?;
                    routes.push(serde_json::json!({
                        "path": runtime_prefix,
                        "fs_path": override_path.display().to_string(),
                        "content_type": "text/html",
                    }));
                } else {
                    routes.push(serde_json::json!({
                        "path": runtime_prefix,
                        "body": canonical_runtime_html_body(),
                        "content_type": "text/html",
                    }));
                }

                // ── /fluxor.wasm → built bundle for this component.
                //    Stays as fs_path — per-scenario artifact, often
                //    multi-MB, not appropriate for inlining.
                let bundle_path = bundle_path_for(scenario_path, &serve.serve, comp)?;
                check_fs_path_length(&bundle_path, 0, &desc, scenario_path)?;
                routes.push(serde_json::json!({
                    "path": bundle_route_url,
                    "fs_path": bundle_path.display().to_string(),
                    "content_type": "application/wasm",
                }));
            }
            Binding::List(list) if list.on.is_none() => {
                let dir = absolute_or_join(base, &list.list);
                let desc = format!("list: {}", list.list.display());
                check_fs_path_length(&dir, 0, &desc, scenario_path)?;
                let mut entry = serde_json::Map::new();
                entry.insert("path".into(), serde_json::Value::String(list.path.clone()));
                entry.insert(
                    "fs_list".into(),
                    serde_json::Value::String(dir.display().to_string()),
                );
                if !list.formats.is_empty() {
                    entry.insert(
                        "fs_filter".into(),
                        serde_json::Value::String(list.formats.join(",")),
                    );
                }
                routes.push(serde_json::Value::Object(entry));
                // Snapshot the directory into the manifest so a runtime
                // `storage.namespace` LIST can enumerate it in-browser.
                manifest_entries.extend(fluxor_manifest_entries(&dir, &list.path, &list.formats));
            }
            _ => {}
        }
    }

    // ── /fluxor-manifest.json → directory snapshot for the wasm
    //    `storage.namespace` provider (fetched once at boot). Only
    //    emitted when there's at least one `list:` binding.
    if !manifest_entries.is_empty() {
        let manifest_url = if runtime_prefix == "/" {
            "/fluxor-manifest.json".to_string()
        } else {
            format!(
                "{}/fluxor-manifest.json",
                runtime_prefix.trim_end_matches('/')
            )
        };
        routes.push(serde_json::json!({
            "path": manifest_url,
            "body": serde_json::Value::Array(manifest_entries).to_string(),
            "content_type": "application/json",
        }));
    }

    // ── /host_shims.js → canonical JS shim (always mounted).
    //    Embedded in fluxor-tools at compile time — required by
    //    runtime.html AND by any user-written shell, since the wasm
    //    kernel imports 20+ `host_*` extern fns and the shim
    //    provides them all. There is no per-scenario host_shims.js;
    //    the kernel ABI is fixed across every wasm bundle.
    let shims_url = if runtime_prefix == "/" {
        "/host_shims.js".to_string()
    } else {
        format!("{}/host_shims.js", runtime_prefix.trim_end_matches('/'))
    };
    routes.push(serde_json::json!({
        "path": shims_url,
        "body": canonical_host_shims_js_body(),
        "content_type": "application/javascript",
    }));

    // ── /scenario.json → inline static body with the wasm component's
    //    presentation block + playlist source + bundle URL. The shell
    //    fetches this before instantiating; it's how runtime.html
    //    knows what surfaces to compose and where the gallery lives.
    let scenario_json_url = if runtime_prefix == "/" {
        "/scenario.json".to_string()
    } else {
        format!("{}/scenario.json", runtime_prefix.trim_end_matches('/'))
    };
    let scenario_json_body =
        build_scenario_json(scenario, scenario_path, serve_component, &bundle_route_url)?;
    routes.push(serde_json::json!({
        "path": scenario_json_url,
        "body": scenario_json_body,
        "content_type": "application/json",
    }));

    Ok(routes)
}

/// Emit the JSON body the wasm runtime shell fetches at boot. Shape:
///
/// ```json
/// {
///   "scenario": "image_viewer",
///   "bundle":   "/fluxor.wasm",
///   "playlist": { "source": "/api/list", "filter": "image" },
///   "presentation": { ... }   // verbatim from the wasm component graph
/// }
/// ```
///
/// The `playlist` field is derived from the first `list:` binding
/// whose `on:` is unset (the gallery). The `presentation` field is
/// pulled verbatim from the active wasm component's graph YAML if
/// the component declares one; otherwise we synthesise a sensible
/// default based on which display/audio modules the graph wires.
fn build_scenario_json(
    scenario: &Scenario,
    scenario_path: &Path,
    serve_component: Option<&str>,
    bundle_route_url: &str,
) -> Result<String> {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "scenario".into(),
        serde_json::Value::String(scenario.name.clone()),
    );
    obj.insert(
        "bundle".into(),
        serde_json::Value::String(bundle_route_url.to_string()),
    );

    // playlist: first list: binding on the synth host.
    for binding in &scenario.bindings {
        if let Binding::List(list) = binding {
            if list.on.is_none() {
                let filter = playlist_filter_for_formats(&list.formats);
                let mut pl = serde_json::Map::new();
                pl.insert(
                    "source".into(),
                    serde_json::Value::String(list.path.clone()),
                );
                pl.insert("filter".into(), serde_json::Value::String(filter.into()));
                obj.insert("playlist".into(), serde_json::Value::Object(pl));
                break;
            }
        }
    }

    // presentation: verbatim from the component's graph YAML, or a
    // synthesised default. We read the graph file to find the
    // `presentation:` block.
    let presentation = serve_component
        .and_then(|c| {
            read_component_presentation(scenario, scenario_path, c)
                .ok()
                .flatten()
        })
        .unwrap_or_else(default_presentation);
    obj.insert("presentation".into(), presentation);

    serde_json::to_string_pretty(&serde_json::Value::Object(obj))
        .map_err(|e| Error::Config(format!("serialise scenario.json: {e}")))
}

/// Map a `list:` binding's `formats:` extension list to a coarse
/// content class the runtime shell uses to filter the playlist.
fn playlist_filter_for_formats(formats: &[String]) -> &'static str {
    let mut has_image = false;
    let mut has_audio = false;
    for f in formats {
        let f = f.to_ascii_lowercase();
        if matches!(
            f.as_str(),
            ".png" | ".jpg" | ".jpeg" | ".gif" | ".bmp" | ".webp"
        ) {
            has_image = true;
        }
        if matches!(f.as_str(), ".wav" | ".mp3" | ".aac" | ".ogg" | ".flac") {
            has_audio = true;
        }
    }
    match (has_image, has_audio) {
        (true, false) => "image",
        (false, true) => "audio",
        _ => "any",
    }
}

/// Read the named component's graph YAML and extract its top-level
/// `presentation:` block, if any. Returns the block as a JSON Value
/// so it can be embedded verbatim in `/scenario.json`.
fn read_component_presentation(
    scenario: &Scenario,
    scenario_path: &Path,
    comp_name: &str,
) -> Result<Option<serde_json::Value>> {
    let comp = scenario
        .components
        .get(comp_name)
        .ok_or_else(|| Error::Config(format!("undefined component `{comp_name}`")))?;
    let base = scenario_path
        .parent()
        .ok_or_else(|| Error::Config("scenario path has no parent dir".into()))?;
    let Some(graph_path) = &comp.graph else {
        return Ok(None);
    };
    let resolved = base.join(graph_path);
    let text = fs::read_to_string(&resolved)
        .map_err(|e| Error::Config(format!("read {}: {}", resolved.display(), e)))?;
    let value: serde_json::Value = serde_yaml::from_str(&text)
        .map_err(|e| Error::Config(format!("parse {}: {}", resolved.display(), e)))?;
    Ok(value.get("presentation").cloned())
}

/// Default presentation for wasm graphs that don't declare one
/// explicitly. Picks a single display surface — the safe choice for
/// the image-viewer-style canonical, and a placeholder for graphs
/// that wire `wasm_browser_audio` but never set up a player UI.
fn default_presentation() -> serde_json::Value {
    serde_json::json!({
        "layout": "stacked",
        "surfaces": [
            { "id": "main", "role": "display", "module": "display" }
        ]
    })
}

/// Resolve a path relative to `base`, then canonicalise if possible.
/// Falls back to the joined path on canonicalise failure (target/wasm
/// artefacts won't exist until the build runs in PR 3).
fn absolute_or_join(base: &Path, p: &Path) -> PathBuf {
    let joined = base.join(p);
    joined.canonicalize().unwrap_or(joined)
}

/// Where the built wasm bundle for a component will live.  The
/// scenario runner pins this to `target/wasm/<stem>.wasm` (and passes
/// the same path to `build_one()` as `output_override` at spawn time)
/// so the synthesised host's `fs_path:` route and the actual build
/// artefact agree byte-for-byte.
fn bundle_path_for(
    _scenario_path: &Path,
    comp_name: &str,
    comp: &ComponentSpec,
) -> Result<PathBuf> {
    let rel = wasm_bundle_target_path(comp_name, comp)?;
    let mut abs = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    abs.push(rel);
    Ok(abs)
}

/// Render a `serde_json::Value` graph as a YAML document with a
/// human-readable header banner.  Used by `--print-synthesised` and
/// `--print-merged`.
fn render_value_as_yaml(value: &serde_json::Value, banner: &str) -> Result<String> {
    let body = serde_yaml::to_string(value)
        .map_err(|e| Error::Config(format!("serialise synthesised graph: {e}")))?;
    Ok(format!("{banner}\n{body}"))
}

/// Emit the synthesised host graph YAML to stdout (or anywhere — the
/// caller decides).  PR 2 builds a real `serde_json::Value` and
/// serialises it through `serde_yaml`, so the output round-trips
/// through `tools::board::validate_config`.
///
/// Returns `None` when the scenario has no synthesised host (every
/// binding has explicit `on:`); the caller should report "no
/// synthesised host" rather than printing an empty file.
pub fn render_synthesised_host(
    scenario: &Scenario,
    scenario_path: &Path,
) -> Result<Option<String>> {
    let Some(config) = synthesise_host_config(scenario, scenario_path)? else {
        return Ok(None);
    };
    let banner = format!(
        "# Synthesised by `fluxor run --print-synthesised {}` from\n\
         # the scenario's `host:` block + bindings whose `on:` is unset.\n\
         # This is a real Fluxor graph — freeze it as a linux YAML if you\n\
         # outgrow what the scenario primitive exposes.\n",
        scenario_path.display()
    );
    Ok(Some(render_value_as_yaml(&config, &banner)?))
}

// ----------------------------------------------------------------------------
// Binding route merger
// ----------------------------------------------------------------------------

/// Load a component's graph YAML and merge any bindings that target it
/// into its http module's `routes:` array.  Returns the augmented
/// `serde_json::Value` — exactly the config the kernel will see at
/// spawn time (PR 3).
///
/// Conflict detection: if a binding mounts at a `path:` already
/// declared by the component, the error names the binding, cites the
/// conflicting route's `path:`, and suggests the fix (RFC §7,
/// §14 "Error UX").
///
/// Host-FS gate: if the target component's effective target is not
/// linux (i.e. cm5 silicon without `runtime_override: linux`), the
/// merger refuses to inject `fs_path:`/`fs_list:` routes (RFC §7,
/// §16 Q9).
pub fn merge_bindings_for_component(
    comp_name: &str,
    scenario: &Scenario,
    scenario_path: &Path,
) -> Result<serde_json::Value> {
    let comp = scenario.components.get(comp_name).ok_or_else(|| {
        Error::Config(format!(
            "scenario {}: --print-merged references undefined component `{}`.",
            scenario_path.display(),
            comp_name
        ))
    })?;
    let base = scenario_path
        .parent()
        .ok_or_else(|| Error::Config("scenario path has no parent dir".into()))?;
    let graph_path = comp.graph.as_ref().ok_or_else(|| {
        Error::Config(format!(
            "scenario {}: component `{}` has no `graph:` to merge into.",
            scenario_path.display(),
            comp_name
        ))
    })?;
    let resolved_graph = base.join(graph_path);
    let text = fs::read_to_string(&resolved_graph).map_err(|e| {
        Error::Config(format!(
            "scenario {}: reading {} for merge: {}",
            scenario_path.display(),
            resolved_graph.display(),
            e
        ))
    })?;
    let mut config: serde_json::Value = serde_yaml::from_str(&text).map_err(|e| {
        Error::Config(format!(
            "scenario {}: parsing {} for merge: {}",
            scenario_path.display(),
            resolved_graph.display(),
            e
        ))
    })?;

    // Apply runtime_override into the loaded config so the eventual
    // target validator runs against the effective target (§8 — though
    // the actual rebuild is PR 5).
    let effective_target = effective_target_for(comp);
    if let Some(target) = &effective_target {
        config["target"] = serde_json::Value::String(target.clone());

        // When a cm5/pico/rp graph is run through `runtime_override:
        // linux` the stack expander swaps the silicon-side network
        // modules (`rp1_gem`, `ip`, `wifi`, `cyw43`) for `linux_net`,
        // but it doesn't touch the user's hand-written wiring. A
        // graph that says `from: ip.net_out` still references `ip`
        // after expansion — and `ip` is no longer in the module list,
        // so config validation fails with
        //   `no manifest found for module 'ip'`.
        //
        // The two modules expose the same `net_in`/`net_out` ports
        // with the same `NetProto` content_type, so a name-level
        // rewrite is sufficient: replace `ip.X` with `linux_net.X`
        // in both endpoints of every wiring edge. We do this once,
        // immediately after the target flip so the rest of the
        // pipeline sees a self-consistent config.
        if target == "linux" || target == "qemu" {
            rewrite_wiring_module(&mut config, "ip", "linux_net");
        }
    }

    // Host-FS gate: per RFC §7, binding-injected fs_path routes work
    // only when the effective target has a host filesystem accessible
    // to the kernel.  Linux + qemu (with -hda or virtfs) qualify; cm5
    // silicon without override does not.
    let target_str = config
        .get("target")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let has_bindings_for_us = scenario
        .bindings
        .iter()
        .any(|b| binding_targets(b, comp_name));
    if has_bindings_for_us && !target_supports_host_fs(&target_str) {
        return Err(Error::Config(format!(
            "scenario {}: binding(s) target `{}.<http>` but `{}`'s effective target is `{}`, \
             which has no shared host filesystem reachable from a static fs_path: route. \
             Either add `runtime_override: linux` (or qemu) to the component, or stage the \
             asset onto the silicon's actual filesystem and write the route explicitly in \
             {}. See RFC §16 Q9.",
            scenario_path.display(),
            comp_name,
            comp_name,
            target_str,
            graph_path.display(),
        )));
    }

    // Inject every binding whose `on:` targets this component into the
    // named http module's `routes:` table.
    for (idx, binding) in scenario.bindings.iter().enumerate() {
        let (target_module, new_routes) = match binding {
            Binding::Serve(s) if binding_targets(binding, comp_name) => {
                let on = s.on.as_ref().unwrap(); // gated by binding_targets
                let (_c, m) = on.split_once('.').ok_or_else(|| {
                    Error::Config(format!(
                        "scenario {}: bindings[{}] `on: {}` must be `<component>.<module>`",
                        scenario_path.display(),
                        idx,
                        on
                    ))
                })?;
                (
                    m.to_string(),
                    serve_binding_routes(s, scenario, base, scenario_path)?,
                )
            }
            Binding::List(l) if binding_targets(binding, comp_name) => {
                let on = l.on.as_ref().unwrap();
                let (_c, m) = on.split_once('.').ok_or_else(|| {
                    Error::Config(format!(
                        "scenario {}: bindings[{}] `on: {}` must be `<component>.<module>`",
                        scenario_path.display(),
                        idx,
                        on
                    ))
                })?;
                (m.to_string(), vec![list_binding_route(l, base)?])
            }
            _ => continue,
        };

        inject_routes_into_module(
            &mut config,
            &target_module,
            new_routes,
            comp_name,
            &resolved_graph,
            idx,
            binding,
            scenario_path,
        )?;
    }

    Ok(config)
}

fn binding_targets(b: &Binding, comp_name: &str) -> bool {
    let on = match b {
        Binding::Serve(s) => s.on.as_deref(),
        Binding::List(l) => l.on.as_deref(),
    };
    match on {
        Some(s) => s.split_once('.').map(|(c, _)| c) == Some(comp_name),
        None => false,
    }
}

fn effective_target_for(comp: &ComponentSpec) -> Option<String> {
    comp.runtime_override.clone()
}

/// Rewrite `from:` / `to:` strings in the config's `wiring:` array
/// that reference `<old_name>.<port>` to `<new_name>.<port>`.
///
/// Used at the runtime_override pivot: when a silicon graph
/// references the silicon-side net module by name (`ip`) but the
/// expanded linux stack provides `linux_net` with the same port
/// surface (`net_in`/`net_out` carrying `NetProto`), we patch the
/// user's wiring so it points at the module the linux stack
/// actually exports. No-op when neither endpoint references
/// `old_name`.
///
/// Only the leading `<name>.` segment is rewritten; ports are
/// untouched. Wiring entries that aren't of the canonical
/// `"module.port"` shape are left alone.
fn rewrite_wiring_module(config: &mut serde_json::Value, old_name: &str, new_name: &str) {
    let Some(wiring) = config.get_mut("wiring").and_then(|w| w.as_array_mut()) else {
        return;
    };
    let prefix = format!("{old_name}.");
    let replacement = format!("{new_name}.");
    for edge in wiring {
        for field in ["from", "to"] {
            let Some(val) = edge.get_mut(field) else {
                continue;
            };
            let Some(s) = val.as_str() else { continue };
            if let Some(rest) = s.strip_prefix(&prefix) {
                *val = serde_json::Value::String(format!("{replacement}{rest}"));
            }
        }
    }
}

fn target_supports_host_fs(target: &str) -> bool {
    matches!(target, "linux" | "qemu" | "qemu-virt")
}

/// Per-target ceiling on a route's `fs_path:` byte length.  Must
/// agree with `modules/sdk/config.rs::http::MAX_FS_PATH` for the
/// effective target — over-length paths get silently truncated by
/// the http module's route table, causing `linux_fs_dispatch::OPEN`
/// to operate on the wrong filename (typically creating an empty
/// file via `O_CREAT`) and surfacing as 200-OK-with-0-byte-body
/// responses.  Discovered while bringing PR 6's image_viewer
/// scenario end-to-end.
const MAX_FS_PATH_HOST: usize = 256;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
const MAX_FS_PATH_EMBEDDED: usize = 64;

fn check_fs_path_length(
    fs_path: &Path,
    binding_idx: usize,
    binding_desc: &str,
    scenario_path: &Path,
) -> Result<()> {
    let len = fs_path.as_os_str().as_encoded_bytes().len();
    if len > MAX_FS_PATH_HOST {
        return Err(Error::Config(format!(
            "scenario {}: bindings[{}] `{}` resolves to {} ({} bytes), which exceeds the \
             host http module's MAX_FS_PATH ceiling of {}. Move the asset under a \
             shorter path, or extend `modules/sdk/config.rs::http::MAX_FS_PATH`.",
            scenario_path.display(),
            binding_idx,
            binding_desc,
            fs_path.display(),
            len,
            MAX_FS_PATH_HOST,
        )));
    }
    Ok(())
}

fn serve_binding_routes(
    s: &ServeBinding,
    scenario: &Scenario,
    base: &Path,
    scenario_path: &Path,
) -> Result<Vec<serde_json::Value>> {
    let comp = scenario.components.get(&s.serve).ok_or_else(|| {
        Error::Config(format!(
            "scenario {}: bindings reference undefined component `{}`",
            scenario_path.display(),
            s.serve
        ))
    })?;
    // host_page is OPTIONAL — when omitted, the canonical wasm
    // runtime shell embedded in fluxor-tools is mounted instead.
    // Custom shells (test harness, bespoke research UIs) still set
    // `host_page:` explicitly to override with an on-disk file.
    let override_page_path: Option<PathBuf> =
        comp.host_page.as_ref().map(|hp| absolute_or_join(base, hp));
    let bundle_path = bundle_path_for(scenario_path, &s.serve, comp)?;
    let bundle_url = if s.prefix == "/" {
        "/fluxor.wasm".to_string()
    } else {
        format!("{}/fluxor.wasm", s.prefix.trim_end_matches('/'))
    };
    let desc = format!("serve: {}", s.serve);
    if let Some(ref p) = override_page_path {
        check_fs_path_length(p, 0, &desc, scenario_path)?;
    }
    check_fs_path_length(&bundle_path, 0, &desc, scenario_path)?;

    // /<prefix>/host_shims.js — canonical wasm host shim. Embedded
    // in fluxor-tools at compile time so the orchestrator is
    // self-contained; same kernel ABI as the synth host's root
    // /host_shims.js route.
    let shims_url = if s.prefix == "/" {
        "/host_shims.js".to_string()
    } else {
        format!("{}/host_shims.js", s.prefix.trim_end_matches('/'))
    };
    let scenario_json_url = if s.prefix == "/" {
        "/scenario.json".to_string()
    } else {
        format!("{}/scenario.json", s.prefix.trim_end_matches('/'))
    };
    let scenario_json_body =
        build_scenario_json(scenario, scenario_path, Some(&s.serve), &bundle_url)?;

    // Serve the page at BOTH `<prefix>` and `<prefix>/`. The http
    // module's route matcher is exact-only for non-trailing-slash
    // routes (and prefix-only for trailing-slash routes), so a
    // browser navigating to `/viewer/` (the natural folder-style
    // URL the user types) would 404 against a `/viewer` route, and
    // vice versa. Two routes is the simplest fix; route table has
    // headroom (MAX_ROUTES=8, this binding uses 5 — page+slash-page
    // +wasm+shims+scenario).
    let prefix_no_slash = s.prefix.trim_end_matches('/').to_string();
    let prefix_with_slash = if prefix_no_slash.is_empty() {
        "/".to_string()
    } else {
        format!("{prefix_no_slash}/")
    };
    // Build the page-route value (embedded body OR override fs_path).
    let make_page_route = |path: String| -> serde_json::Value {
        if let Some(ref override_path) = override_page_path {
            serde_json::json!({
                "path": path,
                "fs_path": override_path.display().to_string(),
                "content_type": "text/html",
            })
        } else {
            serde_json::json!({
                "path": path,
                "body": canonical_runtime_html_body(),
                "content_type": "text/html",
            })
        }
    };
    let mut routes = vec![make_page_route(if prefix_no_slash.is_empty() {
        "/".to_string()
    } else {
        prefix_no_slash.clone()
    })];
    if prefix_with_slash != prefix_no_slash && prefix_no_slash != "/" && !prefix_no_slash.is_empty()
    {
        routes.push(make_page_route(prefix_with_slash));
    }
    routes.push(serde_json::json!({
        "path": bundle_url,
        "fs_path": bundle_path.display().to_string(),
        "content_type": "application/wasm",
    }));
    routes.push(serde_json::json!({
        "path": shims_url,
        "body": canonical_host_shims_js_body(),
        "content_type": "application/javascript",
    }));
    routes.push(serde_json::json!({
        "path": scenario_json_url,
        "body": scenario_json_body,
        "content_type": "application/json",
    }));
    Ok(routes)
}

fn list_binding_route(l: &ListBinding, base: &Path) -> Result<serde_json::Value> {
    let dir = absolute_or_join(base, &l.list);
    let desc = format!("list: {}", l.list.display());
    check_fs_path_length(&dir, 0, &desc, base)?;
    let mut entry = serde_json::Map::new();
    entry.insert("path".into(), serde_json::Value::String(l.path.clone()));
    entry.insert(
        "fs_list".into(),
        serde_json::Value::String(dir.display().to_string()),
    );
    if !l.formats.is_empty() {
        entry.insert(
            "fs_filter".into(),
            serde_json::Value::String(l.formats.join(",")),
        );
    }
    Ok(serde_json::Value::Object(entry))
}

#[expect(
    clippy::too_many_arguments,
    reason = "ABI-shaped function; argument list mirrors the syscall / register signature"
)]
fn inject_routes_into_module(
    config: &mut serde_json::Value,
    module_name: &str,
    new_routes: Vec<serde_json::Value>,
    comp_name: &str,
    comp_path: &Path,
    binding_idx: usize,
    binding: &Binding,
    scenario_path: &Path,
) -> Result<()> {
    let modules = config
        .get_mut("modules")
        .and_then(|m| m.as_array_mut())
        .ok_or_else(|| {
            Error::Config(format!(
                "scenario {}: component `{}` graph {} has no `modules:` array",
                scenario_path.display(),
                comp_name,
                comp_path.display()
            ))
        })?;

    let module = modules
        .iter_mut()
        .find(|m| m.get("name").and_then(|n| n.as_str()) == Some(module_name))
        .ok_or_else(|| {
            Error::Config(format!(
                "scenario {}: bindings[{}] `on: {}.{}` — component `{}`'s graph ({}) has no \
                 module named `{}`.",
                scenario_path.display(),
                binding_idx,
                comp_name,
                module_name,
                comp_name,
                comp_path.display(),
                module_name,
            ))
        })?;

    let existing_paths: HashSet<String> = module
        .get("routes")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| r.get("path").and_then(|p| p.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();

    for new_route in &new_routes {
        let new_path = new_route
            .get("path")
            .and_then(|p| p.as_str())
            .unwrap_or_default();
        if existing_paths.contains(new_path) {
            let binding_desc = match binding {
                Binding::Serve(s) => format!("serve: {}", s.serve),
                Binding::List(l) => format!("list: {}", l.list.display()),
            };
            let suggested_prefix = match binding {
                Binding::Serve(s) => format!(
                    " Disambiguate by adding `prefix: /{}` to the binding.",
                    s.serve
                ),
                Binding::List(_) => " Disambiguate with a different `path:` on the binding.".into(),
            };
            return Err(Error::Config(format!(
                "scenario {}: binding `{}` cannot mount at {:?} on {}.{} — that route is \
                 already declared in {}. {}",
                scenario_path.display(),
                binding_desc,
                new_path,
                comp_name,
                module_name,
                comp_path.display(),
                suggested_prefix,
            )));
        }
    }

    let routes_array = module
        .as_object_mut()
        .unwrap()
        .entry("routes")
        .or_insert_with(|| serde_json::Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| {
            Error::Config(format!(
                "scenario {}: module `{}.{}` has a non-array `routes:` field — graph YAML \
                 is malformed.",
                scenario_path.display(),
                comp_name,
                module_name
            ))
        })?;
    routes_array.extend(new_routes);
    Ok(())
}

/// Render a merged component config as YAML with a banner header
/// pointing back at the scenario.  Used by `--print-merged`.
pub fn render_merged_component(
    comp_name: &str,
    scenario: &Scenario,
    scenario_path: &Path,
) -> Result<String> {
    let merged = merge_bindings_for_component(comp_name, scenario, scenario_path)?;
    let banner = format!(
        "# Merged config for component `{}` of scenario {}.\n\
         # Synthesised by `fluxor run --print-merged {}`.\n\
         # Original graph YAML augmented with binding-injected routes (RFC §7).\n",
        comp_name,
        scenario_path.display(),
        comp_name,
    );
    render_value_as_yaml(&merged, &banner)
}

// ----------------------------------------------------------------------------
// PR 3 helpers: spawn-side support (build artefact paths, URL,
// synthesised-host YAML on disk)
// ----------------------------------------------------------------------------

/// Working directory for build artefacts derived from a scenario.
/// Lives under `target/scenarios/<name>/` so multiple scenarios on
/// the same machine don't trample each other's synthesised host YAML
/// or config.bin output.
pub fn scenario_work_dir(scenario: &Scenario) -> PathBuf {
    PathBuf::from(format!("target/scenarios/{}", scenario.name))
}

/// Write the synthesised host graph to disk as a real YAML file so
/// the existing `build_one()` path can consume it.  Returns the path.
/// Returns `Ok(None)` when the scenario has no synthesised host.
pub fn write_synthesised_host_yaml(
    scenario: &Scenario,
    scenario_path: &Path,
) -> Result<Option<PathBuf>> {
    let Some(config) = synthesise_host_config(scenario, scenario_path)? else {
        return Ok(None);
    };
    let work_dir = scenario_work_dir(scenario);
    fs::create_dir_all(&work_dir).map_err(|e| {
        Error::Config(format!(
            "scenario {}: cannot create work dir {}: {}",
            scenario_path.display(),
            work_dir.display(),
            e
        ))
    })?;
    let banner = format!(
        "# Auto-generated by `fluxor run {}` from the scenario's `host:` block.\n\
         # DO NOT EDIT — overwritten on every run.\n",
        scenario_path.display()
    );
    let yaml = render_value_as_yaml(&config, &banner)?;
    let host_path = work_dir.join("host.yaml");
    fs::write(&host_path, yaml).map_err(|e| {
        Error::Config(format!(
            "scenario {}: cannot write {}: {}",
            scenario_path.display(),
            host_path.display(),
            e
        ))
    })?;
    Ok(Some(host_path))
}

/// URL of the synthesised host (`http://localhost:<port>/`), if any.
pub fn synthesised_host_url(scenario: &Scenario) -> Option<String> {
    scenario
        .host
        .as_ref()
        .map(|h| format!("http://localhost:{}/", h.port))
}

/// Port the synthesised host listens on, if any.
pub fn synthesised_host_port(scenario: &Scenario) -> Option<u16> {
    scenario.host.as_ref().map(|h| h.port)
}

/// Where the wasm bundle for a component should land on disk.  The
/// scenario runner passes this to `build_one()` as an explicit
/// `output_override` so the synthesised host's `fs_path:` route and
/// the actual build artefact agree byte-for-byte.
pub fn wasm_bundle_target_path(comp_name: &str, comp: &ComponentSpec) -> Result<PathBuf> {
    let graph = comp
        .graph
        .as_ref()
        .ok_or_else(|| Error::Config(format!("component `{comp_name}` has no `graph:`")))?;
    let stem = graph.file_stem().and_then(|s| s.to_str()).ok_or_else(|| {
        Error::Config(format!(
            "component `{comp_name}` graph has no filename stem"
        ))
    })?;
    Ok(PathBuf::from(format!("target/wasm/{stem}.wasm")))
}

/// True when this scenario has exactly one component. Kept for
/// introspection / future fast-path dispatch; PR 4's spawn path
/// handles single-component scenarios as a degenerate case of the
/// generic multi-component flow.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
pub fn is_single_component(scenario: &Scenario) -> bool {
    scenario.components.len() == 1
}

/// Effective target for a component: the `runtime_override:` (if set)
/// wins, otherwise the graph's declared `target:`. Used by PR 4 to
/// classify components as wasm (passive, build-bundle-only) vs.
/// linux/qemu/cm5 (active, spawn-a-kernel).
pub fn effective_target(scenario_path: &Path, comp: &ComponentSpec) -> String {
    if let Some(ovr) = &comp.runtime_override {
        return ovr.clone();
    }
    let Some(base) = scenario_path.parent() else {
        return String::new();
    };
    let Some(graph) = &comp.graph else {
        return String::new();
    };
    sniff_graph_target(&base.join(graph)).unwrap_or_default()
}

/// Find the http module's `port:` in a parsed component config.
/// Returns `None` for graphs that have no http module or no port —
/// such components are still legal in PR 4 (e.g. headless capturers),
/// but the readiness probe falls back to "child has exited" instead
/// of "child bound a listener".
pub fn extract_http_port(config: &serde_json::Value) -> Option<u16> {
    config.get("modules")?.as_array()?.iter().find_map(|m| {
        // The convention is `name: http` for the http module; if
        // a future scenario names it differently we'd need
        // explicit per-component port hints in the schema.
        let name = m.get("name").and_then(|n| n.as_str())?;
        if name != "http" {
            return None;
        }
        m.get("port")
            .and_then(|p| p.as_u64())
            .and_then(|p| u16::try_from(p).ok())
    })
}

/// Write a merged-config YAML to disk under
/// `target/scenarios/<name>/<component>.yaml` so PR 4's spawn path
/// can hand it straight to `build_one()`.
pub fn write_merged_component_yaml(
    comp_name: &str,
    scenario: &Scenario,
    scenario_path: &Path,
) -> Result<PathBuf> {
    let merged = merge_bindings_for_component(comp_name, scenario, scenario_path)?;
    let work_dir = scenario_work_dir(scenario);
    fs::create_dir_all(&work_dir).map_err(|e| {
        Error::Config(format!(
            "scenario {}: cannot create work dir {}: {}",
            scenario_path.display(),
            work_dir.display(),
            e
        ))
    })?;
    let banner = format!(
        "# Auto-generated by `fluxor run {}` — merged config for component `{}`.\n\
         # Original graph YAML augmented with binding-injected routes (RFC §7).\n\
         # DO NOT EDIT — overwritten on every run.\n",
        scenario_path.display(),
        comp_name,
    );
    let yaml = render_value_as_yaml(&merged, &banner)?;
    let path = work_dir.join(format!("{comp_name}.yaml"));
    fs::write(&path, yaml).map_err(|e| {
        Error::Config(format!(
            "scenario {}: cannot write {}: {}",
            scenario_path.display(),
            path.display(),
            e
        ))
    })?;
    Ok(path)
}

// ----------------------------------------------------------------------------
// PR 5: module hardware_targets validation against effective target
// ----------------------------------------------------------------------------

/// Per-effective-target aliases — which manifest `hardware_targets:`
/// strings the runtime accepts.
///
/// linux fluxor-linux reuses bcm2712 PIC modules (it loads aarch64
/// .fmod blobs built for the bcm2712 silicon), so a module declaring
/// `hardware_targets = ["bcm2712"]` is legal under
/// `runtime_override: linux`. Same idea for qemu-virt (bcm2712
/// firmware ELF run under qemu).
fn target_aliases(target: &str) -> &'static [&'static str] {
    match target {
        "linux" => &["linux", "bcm2712"],
        "cm5" => &["cm5", "bcm2712"],
        "qemu" | "qemu-virt" => &["qemu", "qemu-virt", "bcm2712"],
        "bcm2712" => &["bcm2712"],
        "rp2350" => &["rp2350", "rp2350b"],
        "rp2350a" => &["rp2350a"],
        "rp2040" => &["rp2040"],
        "pico2w" => &["pico2w", "rp2350", "rp2350b"],
        "picow" => &["picow", "rp2040"],
        "wasm" => &["wasm"],
        _ => &[],
    }
}

/// Standard module-search directories — mirrors
/// `tools::config::load_module_manifests_with_extra`'s order. Kept
/// in-sync by convention; if it ever drifts, the scenario validator
/// will miss a manifest and report a false negative.
const STANDARD_MANIFEST_DIRS: &[&str] = &[
    "modules/drivers",
    "modules/foundation",
    "modules/app",
    "modules/builtin/linux",
    "modules/builtin/host",
    "modules/builtin/wasm",
    "modules/builtin/qemu",
    "modules",
];

/// Slim toml schema for `validate_module_targets`. We re-parse the
/// manifest here (rather than going through `tools::manifest::Manifest`)
/// because the parsed `Manifest` struct lossy-encodes hardware_targets
/// into a u16 RP-family mask — losing the original strings we need to
/// cite back to the user.
#[derive(Deserialize)]
struct ManifestTargetsOnly {
    hardware_targets: Option<Vec<String>>,
}

/// PR 5: walk every component's graph and check that each declared
/// module's `manifest.toml` carries the effective target string (with
/// the alias map). Errors cite the manifest path so the user can
/// `grep` the line.
///
/// Called from `revalidate_all` so `--validate-only` catches mask
/// mismatches at scenario-load time, before any build runs.
pub fn validate_module_targets(scenario: &Scenario, scenario_path: &Path) -> Result<()> {
    let base = scenario_path
        .parent()
        .ok_or_else(|| Error::Config("scenario path has no parent dir".into()))?;
    let project_root = crate::project::root();

    for (comp_name, comp) in &scenario.components {
        let target = effective_target(scenario_path, comp);
        if target.is_empty() {
            continue;
        }
        let Some(graph_rel) = &comp.graph else {
            continue;
        };
        let graph_abs = base.join(graph_rel);
        let yaml: serde_json::Value = match fs::read_to_string(&graph_abs)
            .ok()
            .and_then(|t| serde_yaml::from_str(&t).ok())
        {
            Some(v) => v,
            None => continue, // graph existence already checked by validate()
        };
        let modules = match yaml.get("modules").and_then(|m| m.as_array()) {
            Some(m) => m,
            None => continue,
        };
        let aliases = target_aliases(&target);
        for module in modules {
            let module_name = module
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("<unnamed>");
            let type_name = module
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or(module_name);
            let Some(manifest_path) = find_manifest_for(type_name, &project_root) else {
                // Not finding a manifest is not a PR 5 concern — the
                // build path catches it with a clearer error.  Skip.
                continue;
            };
            let manifest_targets = match read_manifest_hardware_targets(&manifest_path) {
                Ok(v) => v,
                Err(_) => continue, // unparseable manifest — build path will report.
            };
            // Empty hardware_targets in the manifest is permissive
            // ("works everywhere") — historically used by a few
            // built-ins.  Don't reject; the build path will catch any
            // real mismatch.
            if manifest_targets.is_empty() {
                continue;
            }
            if !manifest_targets
                .iter()
                .any(|m| aliases.iter().any(|a| a == m))
            {
                return Err(Error::Config(format!(
                    "scenario {}: component `{}` uses module `{}` (type `{}`) — its \
                     manifest at {} declares hardware_targets = {:?}, which does not \
                     match the component's effective target `{}` (accepted aliases: {:?}). \
                     Either remove `runtime_override:`, or pick a different module type, \
                     or extend the manifest's hardware_targets list. See RFC §8.",
                    scenario_path.display(),
                    comp_name,
                    module_name,
                    type_name,
                    manifest_path.display(),
                    manifest_targets,
                    target,
                    aliases,
                )));
            }
        }
    }
    Ok(())
}

fn find_manifest_for(type_name: &str, project_root: &Path) -> Option<PathBuf> {
    for dir in STANDARD_MANIFEST_DIRS {
        let candidate = project_root.join(dir).join(type_name).join("manifest.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn read_manifest_hardware_targets(path: &Path) -> Result<Vec<String>> {
    let text = fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("read {}: {}", path.display(), e)))?;
    let parsed: ManifestTargetsOnly = toml::from_str(&text)
        .map_err(|e| Error::Config(format!("parse {}: {}", path.display(), e)))?;
    Ok(parsed.hardware_targets.unwrap_or_default())
}

// ----------------------------------------------------------------------------
// Re-validation
// ----------------------------------------------------------------------------

/// Re-validate every component config (synthesised host + every
/// merged component graph) using the existing
/// `tools::board::validate_config` machinery.  Per RFC §7, this catches
/// binding-induced misconfigurations at scenario-load time rather than
/// at kernel-load time with worse error messages.
///
/// Errors aggregate across components; the caller sees one Err per
/// validation pass.
pub fn revalidate_all(scenario: &Scenario, scenario_path: &Path) -> Result<()> {
    use crate::target::load_target;
    let project_root = crate::project::root();

    // PR 5: module hardware_targets ↔ effective_target consistency,
    // checked before any expensive validation downstream.
    validate_module_targets(scenario, scenario_path)?;

    // Synthesised host first, if present.
    if let Some(mut host_cfg) = synthesise_host_config(scenario, scenario_path)? {
        let target_desc = load_target("linux", &project_root)?;
        let _ = &mut host_cfg; // future: stack_expand may mutate
        let result = crate::board::validate_config(&host_cfg, &target_desc)?;
        if !result.is_ok() {
            return Err(Error::Config(format!(
                "scenario {}: synthesised host failed re-validation: {}",
                scenario_path.display(),
                result.errors.join("; ")
            )));
        }
    }

    // Each component that receives at least one binding gets its
    // merged config re-validated against the effective target.
    let mut touched: HashSet<&str> = HashSet::new();
    for b in &scenario.bindings {
        let on = match b {
            Binding::Serve(s) => s.on.as_deref(),
            Binding::List(l) => l.on.as_deref(),
        };
        if let Some(on) = on {
            if let Some((c, _)) = on.split_once('.') {
                touched.insert(c);
            }
        }
    }
    for comp_name in touched {
        let comp = scenario.components.get(comp_name).unwrap();
        let merged = merge_bindings_for_component(comp_name, scenario, scenario_path)?;
        let effective = effective_target_for(comp)
            .or_else(|| {
                merged
                    .get("target")
                    .and_then(|t| t.as_str())
                    .map(String::from)
            })
            .unwrap_or_else(|| "linux".to_string());
        let target_desc = match load_target(&effective, &project_root) {
            Ok(d) => d,
            Err(_) => {
                // Unknown target name — skip the validate step but
                // warn.  Can happen for board IDs the registry doesn't
                // yet know about; PR 5 will tighten the override path.
                eprintln!(
                    "warning: scenario {}: no target descriptor for `{}`; skipping \
                     merged-config re-validation for component `{}`.",
                    scenario_path.display(),
                    effective,
                    comp_name
                );
                continue;
            }
        };
        let result = crate::board::validate_config(&merged, &target_desc)?;
        if !result.is_ok() {
            return Err(Error::Config(format!(
                "scenario {}: merged config for component `{}` failed re-validation: {}",
                scenario_path.display(),
                comp_name,
                result.errors.join("; ")
            )));
        }
    }
    Ok(())
}

// ============================================================================
// `--list`
// ============================================================================

/// Enumerate every runnable scenario in a directory (non-recursive).
/// Kind is detected from file content (`kind: scenario` line), not
/// from filename — the legacy `*.scenario.yaml` infix is gone.
///
/// Two kinds of runnable orchestration:
///   1. standalone `kind: scenario` file (multi-graph harness).
///   2. graph YAML carrying an inline `scenario:` block.
///
/// Returns `(path, name)` pairs — `name` is the scenario's `name:`
/// field, or the file stem if `name:` is missing.
pub fn list_scenarios(dir: &Path) -> Result<Vec<(PathBuf, String)>> {
    if !dir.is_dir() {
        return Err(Error::Config(format!(
            "--list: {} is not a directory",
            dir.display()
        )));
    }
    let mut out = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let entries = fs::read_dir(dir)
        .map_err(|e| Error::Config(format!("--list: read_dir({}): {}", dir.display(), e)))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !(name.ends_with(".yaml") || name.ends_with(".yml")) {
            continue;
        }
        if !seen.insert(path.clone()) {
            continue;
        }
        let display_name = if is_scenario_file(&path) {
            // Standalone scenario — best-effort parse. A file that
            // fails to parse still gets listed with an error tag so
            // the user can see it's there.
            match parse(&path) {
                Ok(s) => s.name,
                Err(_) => format!(
                    "{} (parse error)",
                    path.file_stem().and_then(|s| s.to_str()).unwrap_or("?")
                ),
            }
        } else {
            // Inline-scenario probe: only list the graph when it
            // actually carries a `scenario:` block. Plain graphs
            // (e.g. the thin viewer half of a split) aren't
            // standalone-runnable and don't belong in --list.
            match synthesize_from_graph(&path) {
                Ok(Some(s)) => s.name,
                Ok(None) => continue,
                Err(_) => format!(
                    "{} (parse error)",
                    path.file_stem().and_then(|s| s.to_str()).unwrap_or("?")
                ),
            }
        };
        out.push((path, display_name));
    }
    Ok(out)
}

// ============================================================================
// `--graph` (Graphviz DOT)
// ============================================================================

/// Emit a Graphviz DOT representation of a scenario: nodes are
/// components (plus an implicit `host` node if `host:` is set), edges
/// are bindings.  Intentionally tiny — `dot -Tpng` is the consumer.
pub fn render_graphviz(scenario: &Scenario) -> String {
    let mut out = String::new();
    out.push_str(&format!("digraph \"{}\" {{\n", scenario.name));
    out.push_str("  rankdir=LR;\n  node [shape=box, style=rounded];\n");
    if scenario.host.is_some() {
        out.push_str("  host [shape=box, style=\"rounded,filled\", fillcolor=\"#eef\", label=\"host\\n(synthesised)\"];\n");
    }
    let mut nodes: HashSet<&str> = scenario.components.keys().map(String::as_str).collect();
    for name in &nodes {
        out.push_str(&format!("  \"{name}\" [label=\"{name}\"];\n"));
    }
    nodes.clear();
    for binding in &scenario.bindings {
        match binding {
            Binding::Serve(s) => {
                let dst =
                    s.on.as_deref()
                        .and_then(|on| on.split_once('.'))
                        .map(|(c, _)| c.to_string())
                        .unwrap_or_else(|| "host".to_string());
                out.push_str(&format!(
                    "  \"{}\" -> \"{}\" [label=\"serve\"];\n",
                    s.serve, dst
                ));
            }
            Binding::List(l) => {
                let dst =
                    l.on.as_deref()
                        .and_then(|on| on.split_once('.'))
                        .map(|(c, _)| c.to_string())
                        .unwrap_or_else(|| "host".to_string());
                out.push_str(&format!(
                    "  \"{}\" -> \"{}\" [label=\"list {}\"];\n",
                    l.list.display(),
                    dst,
                    l.path
                ));
            }
        }
    }
    out.push_str("}\n");
    out
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Create a temp scenario tree:
    ///   <tmp>/scenario.yaml
    ///   <tmp>/viewer/graph.yaml        target: wasm
    ///   <tmp>/viewer/viewer.html
    ///   <tmp>/assets/                  (an empty dir)
    /// Returns `(TempDir, scenario_path)` — the caller must hold the
    /// `TempDir` for the lifetime of the test so the on-disk tree is
    /// cleaned up automatically when the test ends.
    fn make_temp_tree(name: &str, scenario_yaml: &str) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::Builder::new()
            .prefix(&format!("fluxor_scenario_test_{name}_"))
            .tempdir()
            .expect("temp dir");
        let dir = tmp.path();
        fs::create_dir_all(dir.join("viewer")).unwrap();
        fs::create_dir_all(dir.join("assets")).unwrap();
        let graph = dir.join("viewer/graph.yaml");
        write!(
            fs::File::create(&graph).unwrap(),
            "target: wasm\nmodules: []\nwiring: []\n"
        )
        .unwrap();
        write!(
            fs::File::create(dir.join("viewer/viewer.html")).unwrap(),
            "<html></html>"
        )
        .unwrap();
        let scenario = dir.join("scenario.yaml");
        write!(fs::File::create(&scenario).unwrap(), "{scenario_yaml}").unwrap();
        (tmp, scenario)
    }

    #[test]
    fn minimal_wasm_scenario_round_trips() {
        let (_tmp, path) = make_temp_tree(
            "round_trip",
            "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
host:
  port: 9876
bindings:
  - serve: viewer
  - list: assets
    formats: [.png, .jpg]
",
        );
        let s = parse(&path).unwrap();
        assert_eq!(s.kind, "scenario");
        assert_eq!(s.name, "viewer");
        assert_eq!(s.components.len(), 1);
        assert_eq!(s.bindings.len(), 2);
        validate(&s, &path).unwrap();
    }

    #[test]
    fn wasm_without_origin_is_rejected() {
        let (_tmp, path) = make_temp_tree(
            "no_origin",
            "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
bindings:
  - serve: viewer
",
        );
        let s = parse(&path).unwrap();
        let err = validate(&s, &path).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("`host:`") || msg.contains("origin"),
            "expected host-missing error, got: {msg}"
        );
    }

    #[test]
    fn runtime_override_wasm_is_rejected() {
        let (_tmp, path) = make_temp_tree(
            "override_wasm",
            "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
    runtime_override: wasm
    host_page: viewer/viewer.html
host:
  port: 9876
bindings:
  - serve: viewer
",
        );
        let s = parse(&path).unwrap();
        let err = validate(&s, &path).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("runtime_override") && msg.contains("wasm"),
            "expected runtime_override: wasm rejection, got: {msg}"
        );
    }

    #[test]
    fn missing_kind_is_rejected_with_helpful_message() {
        let _tmp = tempfile::Builder::new()
            .prefix("fluxor_scenario_test_mk_")
            .tempdir()
            .unwrap();
        let dir = _tmp.path();
        let path = dir.join("not_a_scenario.yaml");
        write!(
            fs::File::create(&path).unwrap(),
            "target: linux\nmodules: []\n"
        )
        .unwrap();
        let err = parse(&path).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("graph YAML") || msg.contains("kind"),
            "expected helpful kind: error, got: {msg}"
        );
    }

    #[test]
    fn missing_graph_file_is_rejected() {
        let _tmp = tempfile::Builder::new()
            .prefix("fluxor_scenario_test_nograph_")
            .tempdir()
            .unwrap();
        let dir = _tmp.path();
        let path = dir.join("scenario.yaml");
        write!(
            fs::File::create(&path).unwrap(),
            "\
kind: scenario
name: x
components:
  viewer:
    graph: missing/graph.yaml
host:
  port: 9876
"
        )
        .unwrap();
        let s = parse(&path).unwrap();
        let err = validate(&s, &path).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("does not exist") && msg.contains("missing"),
            "expected missing-graph error, got: {msg}"
        );
    }

    #[test]
    fn print_synthesised_emits_host_routes() {
        let (_tmp, path) = make_temp_tree(
            "synth",
            "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
host:
  port: 9876
bindings:
  - serve: viewer
  - list: assets
    formats: [.png, .jpg]
",
        );
        let s = parse(&path).unwrap();
        let yaml = render_synthesised_host(&s, &path).unwrap().unwrap();
        assert!(yaml.contains("target: linux"));
        assert!(yaml.contains("port: 9876"));
        assert!(yaml.contains("/fluxor.wasm"));
        assert!(yaml.contains("viewer.html"));
        assert!(yaml.contains("fs_list"));
        assert!(yaml.contains(".png,.jpg"));
    }

    #[test]
    fn render_synthesised_returns_none_without_host() {
        // A scenario whose only binding has explicit `on:` and no
        // `host:` section — render_synthesised_host returns None.
        let _tmp = tempfile::Builder::new()
            .prefix("fluxor_scenario_test_nosynth_")
            .tempdir()
            .unwrap();
        let dir = _tmp.path();
        fs::create_dir_all(dir.join("decoder")).unwrap();
        fs::create_dir_all(dir.join("viewer")).unwrap();
        write!(
            fs::File::create(dir.join("decoder/graph.yaml")).unwrap(),
            "target: linux\nmodules: []\nwiring: []\n"
        )
        .unwrap();
        write!(
            fs::File::create(dir.join("viewer/graph.yaml")).unwrap(),
            "target: wasm\nmodules: []\nwiring: []\n"
        )
        .unwrap();
        write!(
            fs::File::create(dir.join("viewer/viewer.html")).unwrap(),
            "<html></html>"
        )
        .unwrap();
        let path = dir.join("scenario.yaml");
        write!(
            fs::File::create(&path).unwrap(),
            "\
kind: scenario
name: split
components:
  decoder:
    graph: decoder/graph.yaml
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
bindings:
  - serve: viewer
    on: decoder.http
"
        )
        .unwrap();
        let s = parse(&path).unwrap();
        validate(&s, &path).unwrap();
        assert!(render_synthesised_host(&s, &path).unwrap().is_none());
    }

    #[test]
    fn list_scenarios_finds_and_filters() {
        let _tmp = tempfile::Builder::new()
            .prefix("fluxor_scenario_test_list_")
            .tempdir()
            .unwrap();
        let dir = _tmp.path();
        // A real scenario.
        write!(
            fs::File::create(dir.join("foo.scenario.yaml")).unwrap(),
            "kind: scenario\nname: foo\ncomponents:\n  x:\n    graph: x.yaml\nhost:\n  port: 80\n"
        )
        .unwrap();
        // Another, with .yml extension.
        write!(
            fs::File::create(dir.join("bar.scenario.yml")).unwrap(),
            "kind: scenario\nname: bar\ncomponents:\n  x:\n    graph: x.yaml\nhost:\n  port: 80\n"
        )
        .unwrap();
        // A plain YAML — should NOT show up.
        writeln!(
            fs::File::create(dir.join("not_a_scenario.yaml")).unwrap(),
            "target: linux"
        )
        .unwrap();
        // A graph YAML carrying an inline `scenario:` block — listed
        // under the inline block's name.
        write!(
            fs::File::create(dir.join("inline.yaml")).unwrap(),
            "target: linux\nscenario:\n  name: inline_baz\n  host:\n    port: 80\n  bindings:\n    - serve: main\n"
        )
        .unwrap();
        // A scenario with a parse error — still listed.
        write!(
            fs::File::create(dir.join("broken.scenario.yaml")).unwrap(),
            "kind: scenario\nname: [["
        )
        .unwrap();
        let mut out = list_scenarios(dir).unwrap();
        out.sort();
        let names: Vec<&str> = out.iter().map(|(_, n)| n.as_str()).collect();
        assert!(names.contains(&"foo"));
        assert!(names.contains(&"bar"));
        assert!(names.contains(&"inline_baz"));
        assert!(names.iter().any(|n| n.contains("parse error")));
        assert!(!names.iter().any(|n| n.contains("not_a_scenario")));
    }

    // -------------------------------------------------------------
    // PR 2 tests: synthesiser shape, route merger, conflict
    // detection, host-FS gate.
    // -------------------------------------------------------------

    fn make_split_tree(
        name: &str,
        decoder_yaml: &str,
        scenario_yaml: &str,
    ) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::Builder::new()
            .prefix(&format!("fluxor_scenario_test_{name}_"))
            .tempdir()
            .unwrap();
        let dir = tmp.path();
        fs::create_dir_all(dir.join("decoder")).unwrap();
        fs::create_dir_all(dir.join("viewer")).unwrap();
        write!(
            fs::File::create(dir.join("decoder/graph.yaml")).unwrap(),
            "{decoder_yaml}"
        )
        .unwrap();
        write!(
            fs::File::create(dir.join("viewer/graph.yaml")).unwrap(),
            "target: wasm\nmodules: []\nwiring: []\n"
        )
        .unwrap();
        write!(
            fs::File::create(dir.join("viewer/viewer.html")).unwrap(),
            "<html></html>"
        )
        .unwrap();
        let scenario = dir.join("scenario.yaml");
        write!(fs::File::create(&scenario).unwrap(), "{scenario_yaml}").unwrap();
        (tmp, scenario)
    }

    #[test]
    fn synthesised_host_opts_into_accept_cycles() {
        // PR 6: the synthesised host's `http <-> linux_net` wiring is
        // a 2-cycle that the v1 scheduler would otherwise reject.
        // The synthesiser sets `scheduler.accept_cycles: true` so the
        // kernel's prepare_graph accepts it under the explicit
        // attestation.
        let (_tmp, path) = make_temp_tree(
            "synth_accept_cycles",
            "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
host:
  port: 9876
bindings:
  - serve: viewer
",
        );
        let s = parse(&path).unwrap();
        let config = synthesise_host_config(&s, &path).unwrap().unwrap();
        let scheduler = config.get("scheduler").expect("scheduler block missing");
        let accept = scheduler
            .get("accept_cycles")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        assert!(
            accept,
            "synthesised host must opt into accept_cycles, got: {scheduler:?}"
        );
    }

    #[test]
    fn synthesised_host_has_canonical_shape() {
        let (_tmp, path) = make_temp_tree(
            "synth_shape",
            "\
kind: scenario
name: viewer
components:
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
host:
  port: 9876
bindings:
  - serve: viewer
  - list: assets
    formats: [.png, .jpg]
",
        );
        let s = parse(&path).unwrap();
        let config = synthesise_host_config(&s, &path).unwrap().unwrap();
        // Top-level shape mirrors what `examples/serve_wasm/linux.yaml` carries.
        assert_eq!(config["target"], "linux");
        assert!(config["platform"]["net"].is_object());
        let modules = config["modules"].as_array().unwrap();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0]["name"], "http");
        assert_eq!(modules[0]["port"], 9876);
        assert_eq!(modules[0]["host_tcp"], 1);
        let routes = modules[0]["routes"].as_array().unwrap();
        // serve binding contributes /, /fluxor.wasm (2 routes);
        // synthesiser auto-mounts /host_shims.js + /scenario.json
        // (2 more); list binding contributes /api/list (1 more).
        // Total = 5.
        assert_eq!(routes.len(), 5);
        let paths: Vec<&str> = routes.iter().map(|r| r["path"].as_str().unwrap()).collect();
        assert!(paths.contains(&"/"));
        assert!(paths.contains(&"/fluxor.wasm"));
        assert!(paths.contains(&"/host_shims.js"));
        assert!(paths.contains(&"/scenario.json"));
        assert!(paths.contains(&"/api/list"));
        // wiring is the canonical 2-edge linux net loop
        let wiring = config["wiring"].as_array().unwrap();
        assert_eq!(wiring.len(), 2);
    }

    #[test]
    fn merger_injects_routes_into_named_module() {
        let (_tmp, path) = make_split_tree(
            "merge_inject",
            "\
target: linux
modules:
  - name: http
    port: 9090
    routes:
      - path: /api/list
        fs_list: /images
",
            "\
kind: scenario
name: split
components:
  decoder:
    graph: decoder/graph.yaml
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
bindings:
  - serve: viewer
    on: decoder.http
",
        );
        let s = parse(&path).unwrap();
        let merged = merge_bindings_for_component("decoder", &s, &path).unwrap();
        let routes = merged["modules"][0]["routes"].as_array().unwrap();
        // Original /api/list + 4 binding-injected routes (page,
        // bundle, host_shims.js, scenario.json — commit 1c).
        assert_eq!(routes.len(), 5);
        let paths: Vec<&str> = routes.iter().map(|r| r["path"].as_str().unwrap()).collect();
        assert!(paths.contains(&"/api/list"));
        assert!(paths.contains(&"/"));
        assert!(paths.contains(&"/fluxor.wasm"));
        assert!(paths.contains(&"/host_shims.js"));
        assert!(paths.contains(&"/scenario.json"));
    }

    #[test]
    fn merger_detects_route_conflict_with_helpful_error() {
        let (_tmp, path) = make_split_tree(
            "merge_conflict",
            "\
target: linux
modules:
  - name: http
    port: 9090
    routes:
      - path: /
        fs_path: /existing.html
",
            "\
kind: scenario
name: split
components:
  decoder:
    graph: decoder/graph.yaml
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
bindings:
  - serve: viewer
    on: decoder.http
",
        );
        let s = parse(&path).unwrap();
        let err = merge_bindings_for_component("decoder", &s, &path).unwrap_err();
        let msg = format!("{err}");
        // Per RFC §7 the error must name the binding, cite the file,
        // and suggest a `prefix:` value.
        assert!(
            msg.contains("serve: viewer"),
            "should name the binding, got: {msg}"
        );
        assert!(
            msg.contains("decoder/graph.yaml"),
            "should cite the file, got: {msg}"
        );
        assert!(
            msg.contains("prefix:"),
            "should suggest a prefix, got: {msg}"
        );
    }

    #[test]
    fn merger_blocks_binding_on_silicon_without_override() {
        let (_tmp, path) = make_split_tree(
            "merge_silicon",
            "\
target: cm5
modules:
  - name: http
    port: 9090
    routes:
      - path: /api/list
        fs_list: /images
",
            "\
kind: scenario
name: split
components:
  decoder:
    graph: decoder/graph.yaml
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
bindings:
  - serve: viewer
    on: decoder.http
",
        );
        let s = parse(&path).unwrap();
        let err = merge_bindings_for_component("decoder", &s, &path).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("host filesystem") && msg.contains("runtime_override"),
            "should explain host-FS gate (RFC §16 Q9), got: {msg}"
        );
    }

    #[test]
    fn runtime_override_flips_effective_target_in_merged_config() {
        let (_tmp, path) = make_split_tree(
            "merge_override",
            "\
target: cm5
modules:
  - name: http
    port: 9090
    routes:
      - path: /api/list
        fs_list: /images
",
            "\
kind: scenario
name: split
components:
  decoder:
    graph: decoder/graph.yaml
    runtime_override: linux
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
bindings:
  - serve: viewer
    on: decoder.http
",
        );
        let s = parse(&path).unwrap();
        let merged = merge_bindings_for_component("decoder", &s, &path).unwrap();
        assert_eq!(merged["target"], "linux");
    }

    #[test]
    fn binding_targeting_missing_module_errors_clearly() {
        let (_tmp, path) = make_split_tree(
            "merge_no_module",
            "\
target: linux
modules:
  - name: NOT_http
    port: 9090
",
            "\
kind: scenario
name: split
components:
  decoder:
    graph: decoder/graph.yaml
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
bindings:
  - serve: viewer
    on: decoder.http
",
        );
        let s = parse(&path).unwrap();
        let err = merge_bindings_for_component("decoder", &s, &path).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("no module named") && msg.contains("http"),
            "should name the missing module clearly, got: {msg}"
        );
    }

    // -------------------------------------------------------------
    // PR 4 tests: effective_target, extract_http_port,
    // write_merged_component_yaml.
    // -------------------------------------------------------------

    #[test]
    fn effective_target_honours_runtime_override() {
        let (_tmp, path) = make_split_tree(
            "et_override",
            "target: cm5\nmodules: []\nwiring: []\n",
            "\
kind: scenario
name: split
components:
  decoder:
    graph: decoder/graph.yaml
    runtime_override: linux
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
bindings:
  - serve: viewer
    on: decoder.http
",
        );
        let s = parse(&path).unwrap();
        let decoder = s.components.get("decoder").unwrap();
        let viewer = s.components.get("viewer").unwrap();
        assert_eq!(effective_target(&path, decoder), "linux");
        assert_eq!(effective_target(&path, viewer), "wasm");
    }

    #[test]
    fn extract_http_port_walks_modules() {
        let v: serde_json::Value = serde_yaml::from_str(
            "modules:\n  - name: ws\n    type: ws_stream\n  - name: http\n    port: 9090\n",
        )
        .unwrap();
        assert_eq!(extract_http_port(&v), Some(9090));
        let v_no_http: serde_json::Value =
            serde_yaml::from_str("modules:\n  - name: ws\n    type: ws_stream\n").unwrap();
        assert_eq!(extract_http_port(&v_no_http), None);
    }

    #[test]
    fn write_merged_component_yaml_lands_under_target_scenarios() {
        let (_tmp, path) = make_split_tree(
            "wmc_yaml",
            "\
target: linux
modules:
  - name: http
    port: 9090
",
            "\
kind: scenario
name: write_merge_test
components:
  decoder:
    graph: decoder/graph.yaml
  viewer:
    graph: viewer/graph.yaml
    host_page: viewer/viewer.html
bindings:
  - serve: viewer
    on: decoder.http
",
        );
        let s = parse(&path).unwrap();
        let out = write_merged_component_yaml("decoder", &s, &path).unwrap();
        assert!(out.is_file(), "merged yaml not written: {}", out.display());
        let content = fs::read_to_string(&out).unwrap();
        assert!(content.contains("/fluxor.wasm"));
        // Bonus: the on-disk YAML must parse back as a valid config Value.
        let parsed: serde_json::Value = serde_yaml::from_str(&content).unwrap();
        assert_eq!(parsed["target"], "linux");
        // Cleanup
        let _ = fs::remove_dir_all(scenario_work_dir(&s));
    }

    // -------------------------------------------------------------
    // PR 5 tests: target_aliases, manifest hardware_targets check.
    // -------------------------------------------------------------

    /// Process-wide mutex serialising tests that mutate
    /// `std::env::set_current_dir`. Without this they race against
    /// each other and against tests that read CWD (e.g.
    /// `wasm_bundle_target_path` via `std::env::current_dir`),
    /// surfacing as `cargo test`-only intermittent failures.
    /// `validate_module_targets`'s manifest lookup walks
    /// `std::env::current_dir().join("modules/...")`, so the test
    /// has to pin CWD to the project root.
    static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn target_aliases_table_is_sensible() {
        // Linux reuses bcm2712 PIC modules — that's the whole point
        // of `runtime_override: linux` working for cm5 graphs.
        assert!(target_aliases("linux").contains(&"bcm2712"));
        // cm5 board uses bcm2712 silicon — manifests can declare
        // either.
        assert!(target_aliases("cm5").contains(&"bcm2712"));
        assert!(target_aliases("cm5").contains(&"cm5"));
        // wasm is wasm — no aliasing.
        assert_eq!(target_aliases("wasm"), &["wasm"]);
        // Unknown target → empty (no aliases means strict
        // never-matches; the build path will surface this with its
        // own error).
        assert!(target_aliases("definitely-not-a-real-target").is_empty());
    }

    #[test]
    fn read_manifest_hardware_targets_walks_real_manifests() {
        // Sanity-check against an actual repo manifest so a refactor
        // of `ManifestTargetsOnly` is caught early.
        let path = std::env::current_dir()
            .unwrap()
            .join("../modules/foundation/http/manifest.toml");
        if !path.is_file() {
            // Test runner cwd ≠ repo root in some environments;
            // skip rather than fail.
            eprintln!("skipping: {} not found", path.display());
            return;
        }
        let targets = read_manifest_hardware_targets(&path).unwrap();
        assert!(targets.iter().any(|t| t == "bcm2712" || t == "rp2350"));
    }

    #[test]
    fn validate_module_targets_rejects_silicon_mismatch_with_actionable_error() {
        // A real linux scenario that lists a rp2350-only module —
        // should be rejected. We use `wifi` (CYW43-only RP module)
        // because its hardware_targets manifest definitely doesn't
        // include linux or bcm2712.
        let _tmp = tempfile::Builder::new()
            .prefix("fluxor_scenario_test_mask_")
            .tempdir()
            .unwrap();
        let dir = _tmp.path();
        let graph = dir.join("graph.yaml");
        write!(
            fs::File::create(&graph).unwrap(),
            "target: linux\nmodules:\n  - name: wifi\nwiring: []\n"
        )
        .unwrap();
        let scenario = dir.join("scenario.yaml");
        write!(
            fs::File::create(&scenario).unwrap(),
            "kind: scenario\nname: test\ncomponents:\n  c:\n    graph: graph.yaml\n"
        )
        .unwrap();
        let s = parse(&scenario).unwrap();

        // Must run from the repo root so find_manifest_for can locate
        // wifi's manifest under modules/foundation/wifi/manifest.toml.
        let _g = CWD_LOCK.lock().unwrap();
        let repo_root = std::env::current_dir().unwrap();
        let project_root = if repo_root.ends_with("tools") {
            repo_root.parent().unwrap().to_path_buf()
        } else {
            repo_root.clone()
        };
        // Swap CWD so find_manifest_for picks up the real tree.
        std::env::set_current_dir(&project_root).unwrap();
        let res = validate_module_targets(&s, &scenario);
        std::env::set_current_dir(&repo_root).unwrap();

        let err = match res {
            Ok(()) => {
                // If wifi's manifest isn't in this tree, we can't
                // exercise the check — skip without failing.
                let manifest = project_root.join("modules/foundation/wifi/manifest.toml");
                if !manifest.is_file() {
                    eprintln!("skipping: {} not present", manifest.display());
                    return;
                }
                panic!("expected mismatch error, got Ok");
            }
            Err(e) => format!("{e}"),
        };
        assert!(
            err.contains("hardware_targets") && err.contains("effective target"),
            "expected helpful mask error, got: {err}"
        );
        assert!(
            err.contains("modules/foundation/wifi/manifest.toml") || err.contains("wifi"),
            "expected manifest path / module name cited, got: {err}"
        );
    }

    #[test]
    fn validate_module_targets_accepts_bcm2712_under_runtime_override_linux() {
        // The split-decoder pattern: a cm5 graph using foundation/http
        // (hardware_targets = ["rp2350", "bcm2712"]) coerced to linux
        // — should pass because target_aliases("linux") includes
        // "bcm2712".
        let _tmp = tempfile::Builder::new()
            .prefix("fluxor_scenario_test_mask_ok_")
            .tempdir()
            .unwrap();
        let dir = _tmp.path();
        let graph = dir.join("graph.yaml");
        write!(
            fs::File::create(&graph).unwrap(),
            "target: cm5\nmodules:\n  - name: http\n    port: 9090\nwiring: []\n"
        )
        .unwrap();
        let scenario = dir.join("scenario.yaml");
        write!(
            fs::File::create(&scenario).unwrap(),
            "kind: scenario\nname: test\ncomponents:\n  c:\n    graph: graph.yaml\n    runtime_override: linux\n"
        )
        .unwrap();
        let s = parse(&scenario).unwrap();

        let _g = CWD_LOCK.lock().unwrap();
        let repo_root = std::env::current_dir().unwrap();
        let project_root = if repo_root.ends_with("tools") {
            repo_root.parent().unwrap().to_path_buf()
        } else {
            repo_root.clone()
        };
        std::env::set_current_dir(&project_root).unwrap();
        let res = validate_module_targets(&s, &scenario);
        std::env::set_current_dir(&repo_root).unwrap();

        match res {
            Ok(()) => {}
            Err(e) => panic!("expected pass under runtime_override: linux, got: {e}"),
        }
    }

    #[test]
    fn binding_cycle_is_caught() {
        // Two components, each whose serve-binding points at the
        // other's http — degenerate, but the dependency graph forms
        // a cycle.
        let _tmp = tempfile::Builder::new()
            .prefix("fluxor_scenario_test_cycle_")
            .tempdir()
            .unwrap();
        let dir = _tmp.path();
        fs::create_dir_all(dir.join("a")).unwrap();
        fs::create_dir_all(dir.join("b")).unwrap();
        write!(
            fs::File::create(dir.join("a/graph.yaml")).unwrap(),
            "target: wasm\nmodules: []\nwiring: []\n"
        )
        .unwrap();
        write!(
            fs::File::create(dir.join("b/graph.yaml")).unwrap(),
            "target: wasm\nmodules: []\nwiring: []\n"
        )
        .unwrap();
        write!(
            fs::File::create(dir.join("a/page.html")).unwrap(),
            "<html></html>"
        )
        .unwrap();
        write!(
            fs::File::create(dir.join("b/page.html")).unwrap(),
            "<html></html>"
        )
        .unwrap();
        let path = dir.join("scenario.yaml");
        write!(
            fs::File::create(&path).unwrap(),
            "\
kind: scenario
name: cycle
components:
  a:
    graph: a/graph.yaml
    host_page: a/page.html
  b:
    graph: b/graph.yaml
    host_page: b/page.html
bindings:
  - serve: a
    on: b.http
  - serve: b
    on: a.http
"
        )
        .unwrap();
        let s = parse(&path).unwrap();
        let err = validate(&s, &path).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("cyclic"), "expected cycle error, got: {msg}");
    }
}
