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
//   target: pi5
//   modules: [...]
//   wiring:  [...]
//
//   scenario:
//     name: image_viewer_pi5
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

