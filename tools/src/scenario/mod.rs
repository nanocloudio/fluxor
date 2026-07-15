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

// ── Split for navigability (flat `include!` scope; compiles identically) ─────
include!("parse.rs"); // scenario-file parsing + inline-block synthesis
include!("validate.rs"); // scenario + binding-DAG validation
include!("synthesise.rs"); // host-config synthesiser, route merger, re-validation
include!("tests.rs"); // #[cfg(test)] suites
