//! Deployment scenarios — declarative multi-graph orchestration.
//!
//! A *scenario* is a YAML manifest that describes which Fluxor graphs
//! participate in a run, on which runtimes they run, and what the
//! synthesised host serves for them.
//!
//! What this module does:
//!   - Serde structs for the scenario schema (components, host knobs,
//!     bindings).
//!   - Path resolution + structural validation, `runtime_override` sanity
//!     checks, and each component's modules held to the runtime of its
//!     effective target.
//!   - Synthesiser: writes the scenario's document root and builds the
//!     linux host graph that serves it, including the `@file_server`
//!     stack the scenario's project binds.
//!   - Re-validation of the host graph, its includes expanded, via
//!     `tools::board::validate_config`.
//!   - `--list` scenario discovery in a directory.
//!   - `--print-synthesised`, `--print-merged`, `--graph` dumps.
//!
//! Not implemented: scenario nesting (a component naming another scenario
//! instead of a graph). The schema accepts the shape; the validator
//! rejects it.

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
    /// The TCP port a spawned component listens on. The run waits for the
    /// component to bind it before it counts as ready; a component without
    /// one counts as ready once it has stayed up through a short grace
    /// period. A wasm component is served, not spawned, and takes none.
    #[serde(default)]
    pub port: Option<u16>,
}

/// Synthesised-host knobs: the port the host serves the document root on.
/// Required when the scenario has a binding or a wasm component.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSpec {
    pub port: u16,
}

/// What the synthesised host serves. Tagged-by-presence rather than by an
/// explicit `kind:` field so the YAML stays uncluttered for one-line
/// bindings (`- serve: viewer`): `serve:` and `list:` are siblings, and
/// which key is present selects the variant. Every binding lands on the
/// host's document root.
#[derive(Debug, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Binding {
    Serve(ServeBinding),
    List(ListBinding),
}

/// Serve a wasm component — its page, bundle and the shell's files — under
/// `prefix` on the host. Two `serve:` bindings need distinct prefixes.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServeBinding {
    pub serve: String,
    #[serde(default = "default_prefix")]
    pub prefix: String,
}

/// Serve a directory at `path` on the host, and list its files (those with
/// one of `formats`' extensions, when given) in `fluxor-manifest.json`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListBinding {
    pub list: PathBuf,
    #[serde(default)]
    pub formats: Vec<String>,
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
include!("synthesise.rs"); // host synthesiser, document root, re-validation
include!("tests.rs"); // #[cfg(test)] suites
