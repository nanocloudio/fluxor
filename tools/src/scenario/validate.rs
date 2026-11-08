// ============================================================================
// Validation
// ============================================================================

/// Validate a parsed scenario's structure. `scenario_path` is used for
/// path resolution (`graph:`, `host_page:`, `list:` all resolve relative
/// to the scenario YAML's directory) and for error messages.
///
/// Checks:
///   - Component existence (`graph:` path exists and is readable).
///   - Mutual exclusion of `graph:` / `scenario:`.
///   - `kind: scenario` is set to `"scenario"`.
///   - At least one component.
///   - `host:` is declared when there is a binding or a wasm component:
///     every binding lands on the host, and wasm runs only from an origin.
///   - `serve:` names a defined wasm component.
///   - Two `serve:` bindings have distinct `prefix`es; a `list:` binding's
///     `path` names a directory below `/`.
///   - `runtime_override:` is one of {linux, qemu-virt}; never on a wasm
///     component.
///   - `port:` and `duration:` are never on a wasm component: it is served,
///     not spawned.
///   - `host_page:` exists on disk (when set).
///   - `list:` directory exists on disk (when set).
///   - `sequential: true` takes no `host:`: it runs each component to
///     completion in turn, and the host serves until it is stopped. A
///     component without `duration:` draws a warning that it must exit on
///     its own, which only running it can show.
///
/// Where each binding's files land is checked when the document root is
/// written.
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
                     — they are mutually exclusive.",
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
                     Scenario nesting is not supported by the runner — flatten the \
                     components into this scenario.",
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
                "linux" | "qemu-virt" => {}
                "wasm" => {
                    return Err(Error::Config(format!(
                        "scenario {}: component `{}` has `runtime_override: wasm`. \
                         Wasm bundles execute in a browser; the runtime cannot be \
                         coerced.",
                        scenario_path.display(),
                        name
                    )));
                }
                other => {
                    return Err(Error::Config(format!(
                        "scenario {}: component `{}` has `runtime_override: {}`. \
                         Must be one of {{linux, qemu-virt}}.",
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
                     graph targets wasm. Wasm bundles always build for the wasm target; \
                     remove the override.",
                    scenario_path.display(),
                    name
                )));
            }
        }

        if graph_targets.get(name).map(String::as_str) == Some("wasm") {
            let spawn_only = [
                ("port", comp.port.is_some()),
                ("duration", comp.duration.is_some()),
            ];
            if let Some((key, _)) = spawn_only.iter().find(|(_, set)| *set) {
                return Err(Error::Config(format!(
                    "scenario {}: component `{}` declares `{key}:`, but it targets wasm: a \
                     wasm component is served by the host, not spawned, so the run neither \
                     waits on a port of its own nor stops it — drop `{key}:`.",
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
    let mut prefixes: HashMap<String, usize> = HashMap::new();
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
                if graph_targets.get(&serve.serve).map(String::as_str) != Some("wasm") {
                    return Err(Error::Config(format!(
                        "scenario {}: bindings[{}] `serve: {}` names a component that does not \
                         target wasm — the host serves a wasm bundle and its page; any other \
                         component is spawned and serves its own routes.",
                        scenario_path.display(),
                        idx,
                        serve.serve
                    )));
                }
                if !serve.prefix.starts_with('/') {
                    return Err(Error::Config(format!(
                        "scenario {}: bindings[{}] `prefix: {}` must start with `/`.",
                        scenario_path.display(),
                        idx,
                        serve.prefix
                    )));
                }
                let key = serve.prefix.trim_end_matches('/').to_string();
                if let Some(first) = prefixes.insert(key, idx) {
                    return Err(Error::Config(format!(
                        "scenario {}: bindings[{}] and bindings[{}] both serve at `prefix: {}` \
                         — every `serve:` lands on the host, so give each a distinct `prefix`.",
                        scenario_path.display(),
                        first,
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
                if !list.path.starts_with('/') || list.path.trim_matches('/').is_empty() {
                    return Err(Error::Config(format!(
                        "scenario {}: bindings[{}] `path: {}` must start with `/` and name a \
                         directory below it (the default is `/api/list`).",
                        scenario_path.display(),
                        idx,
                        list.path
                    )));
                }
            }
        }
    }

    // --- sequential mode ---
    let has_wasm = scenario
        .components
        .keys()
        .any(|n| graph_targets.get(n).map(String::as_str) == Some("wasm"));
    if scenario.sequential {
        if scenario.host.is_some() || has_wasm || !scenario.bindings.is_empty() {
            return Err(Error::Config(format!(
                "scenario {}: `sequential: true` runs each component to completion in turn, \
                 and the host serves until it is stopped — a sequential scenario takes no \
                 `host:` block, no binding and no wasm component.",
                scenario_path.display()
            )));
        }
        for (name, comp) in &scenario.components {
            if comp.duration.is_none() {
                eprintln!(
                    "warning: scenario {}: sequential mode without `duration:` on \
                     component `{}` — it must exit on its own.",
                    scenario_path.display(),
                    name
                );
            }
        }
    }

    // --- host requirement ---
    if scenario.host.is_none() && (has_wasm || !scenario.bindings.is_empty()) {
        return Err(Error::Config(format!(
            "scenario {}: {} but no `host:` block is declared — every binding lands on the \
             synthesised host, and wasm runs only from an origin. Add \
             `host: {{ port: <PORT> }}`.",
            scenario_path.display(),
            if has_wasm {
                "declares a wasm component"
            } else {
                "has bindings"
            }
        )));
    }

    Ok(())
}

/// Sniff a graph YAML's `target:` field cheaply. Returns the raw string
/// (e.g. `"wasm"`, `"pi5"`, `"linux"`, `"pico2w"`); empty string on any
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
