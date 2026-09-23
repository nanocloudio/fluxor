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
///   - `runtime_override:` is one of {linux, qemu-virt}; never on a wasm
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
                     graph targets wasm. Wasm bundles always build for the wasm target \
                     remove the override.",
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
             module — wasm cannot run without an origin.",
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
                     binding's `serve:` source.",
                    scenario_path.display(),
                    cycle.join(" → ")
                )));
            }
        }
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

