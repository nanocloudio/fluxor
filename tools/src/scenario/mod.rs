//! Deployment scenarios — declarative multi-graph orchestration.
//!
//! A *scenario* is a YAML manifest that describes which Fluxor graphs
//! participate in a deployment, on which runtimes they run, and how they
//! bind to each other.
//!
//! What this module does:
//!   - Serde structs for the scenario schema (components, host knobs,
//!     bindings).
//!   - Path resolution + structural validation.
//!   - Component-graph reachability + `runtime_override` sanity checks.
//!   - Synthesiser: builds a `serde_json::Value` graph that the existing
//!     `tools::board::validate_config` accepts as a hand-written linux
//!     YAML.
//!   - Binding route merger: reads each component's graph, mutates the
//!     named http module's `routes:` array, detects conflicts on `path:`
//!     and cites the offending file (no line numbers — serde_yaml does
//!     not surface them for `Value` reads).
//!   - Re-validation of the merged config via
//!     `tools::board::validate_config`.
//!   - `--list` scenario discovery in a directory.
//!   - `--print-synthesised`, `--print-merged`, `--graph` dumps.
//!
//! Not implemented:
//!   - Process orchestration / spawning.
//!   - Checking a `runtime_override:` against the target's module mask,
//!     and rebuilding the runtime to match.
//!   - Scenario nesting (a component naming another scenario instead of
//!     a graph): the schema accepts the shape, the validator rejects it.

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
/// `kind: scenario` is required (sniffed by the dispatcher before this
/// struct is deserialised; the field is kept in the struct so a stray
/// graph YAML with `kind: scenario` round-trips rather than silently
/// mis-parses).
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
/// is checked in [`validate`]). The `scenario` variant names a nested
/// scenario; the shape parses, but [`validate`] rejects it with a clear
/// message because nesting is not implemented.
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
    /// Per-module scalar overrides applied at deploy time. Parsed here
    /// so [`validate`] can reject malformed shapes early; the actual
    /// deploy-time merge lives in the route-merger / spawn path.
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
/// bindings (`- serve: viewer`): `serve:` and `list:` are siblings, and
/// which key is present selects the variant.
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
