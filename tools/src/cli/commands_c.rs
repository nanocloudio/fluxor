/// Tie a spawned `fluxor-linux` to this process's lifetime: PR_SET_PDEATHSIG
/// delivers SIGKILL to the child the moment its parent dies. Without this, a
/// caller that kills (or `timeout`s) the `fluxor` CLI orphans the runtime,
/// which then runs its scheduler loop forever holding its full state arena —
/// the classic "endless memory-hungry fluxor-linux processes" leak. Graphs are
/// servers by design and never exit on their own, so the parent's lifetime is
/// the only lifetime they have.
pub fn tie_to_parent(cmd: &mut std::process::Command) -> &mut std::process::Command {
    use std::os::unix::process::CommandExt as _;
    // SAFETY: the pre_exec closure runs post-fork in the child, where only
    // async-signal-safe calls are permitted — prctl(PR_SET_PDEATHSIG) is one,
    // touches no memory shared with the parent, and only affects the child
    // being exec'd. The disposition survives the subsequent exec (the runtime
    // binary is neither setuid nor file-capability'd, which would clear it).
    unsafe {
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            Ok(())
        })
    }
}

fn cmd_build(path: &Path, output: Option<&std::path::Path>, verbose: bool) -> Result<()> {
    // A workload source manifest — a `.toml` with a `[workload]` table —
    // emits the committed bundle + per-target blobs instead of a single
    // image. Any other `.toml` falls through.
    if workload_src::is_source_manifest(path) {
        workload_src::emit_bundle(path, verbose)?;
        return Ok(());
    }
    if path.is_dir() {
        // Glob for all YAML files recursively
        let mut yamls: Vec<PathBuf> = Vec::new();
        collect_yaml_files(path, &mut yamls);
        yamls.sort();

        if yamls.is_empty() {
            return Err(Error::Config(format!(
                "No YAML files found in {}",
                path.display()
            )));
        }

        let total = yamls.len();
        let mut built = 0;
        let mut failed = 0;

        for yaml in &yamls {
            match build_one(yaml, None, verbose) {
                Ok(_) => built += 1,
                Err(e) => {
                    eprintln!("\x1b[1;33mWarn:\x1b[0m {} -- {}", yaml.display(), e);
                    failed += 1;
                }
            }
        }

        println!("\nBuilt {built}/{total} configs ({failed} failed)");
        if failed > 0 && built == 0 {
            return Err(Error::Config("All builds failed".into()));
        }
        Ok(())
    } else {
        build_one(path, output, verbose)?;
        Ok(())
    }
}

/// Recursively collect *.yaml files from a directory.
fn collect_yaml_files(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                collect_yaml_files(&p, out);
            } else if p
                .extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
            {
                out.push(p);
            }
        }
    }
}

/// Cross-check a Linux YAML config against the `fluxor-linux` binary's
/// compiled-in features. Module types and per-mode values that need an
/// optional backend are matched against the feature set the binary
/// reports via `--print-features`; any mismatch fails the build with
/// the matching `cargo build` invocation in the error message.
///
/// Skipped silently when the binary is absent (`build_one` errors on
/// that path before we reach here) or when `--print-features` exits
/// non-zero (the binary is too old to expose its feature set).
fn validate_linux_runtime_features(yaml_path: &std::path::Path) -> Result<()> {
    let linux_bin = crate::project::root_for_config(yaml_path)
        .join("target/aarch64-unknown-linux-gnu/release/fluxor-linux");
    if !linux_bin.exists() {
        return Ok(());
    }

    let output = std::process::Command::new(&linux_bin)
        .arg("--print-features")
        .output()
        .map_err(|e| {
            Error::Config(format!(
                "failed to query features from {}: {}",
                linux_bin.display(),
                e
            ))
        })?;
    if !output.status.success() {
        eprintln!(
            "warning: {} --print-features failed; skipping feature cross-check",
            linux_bin.display()
        );
        return Ok(());
    }
    let features: std::collections::HashSet<String> = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    // Parse the YAML and walk modules. We don't reuse the full
    // generation pipeline — we just need module type + relevant fields.
    let content = substitute_env_vars(&std::fs::read_to_string(yaml_path)?)?;
    let mut config: serde_json::Value = if yaml_path
        .extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&content)?
    } else {
        serde_json::from_str(&content)?
    };
    let target_desc = resolve_target(&config, None)?;
    // Resolve from the CONFIG's location, not the cwd: the rig and
    // cross-repo builds invoke this from another project's root, and a
    // cwd-resolved root gave the id-table digest injection the wrong
    // `[observability] id_table_dirs` (a digest the exporter can never
    // match).
    let project_root = crate::project::root_for_config(yaml_path);
    stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;

    let modules = match config.get("modules").and_then(|m| m.as_array()) {
        Some(m) => m,
        None => return Ok(()),
    };
    for entry in modules {
        let name = entry
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("<unnamed>");
        let module_type = entry.get("type").and_then(|v| v.as_str()).unwrap_or(name);

        // Module-presence checks: if the YAML uses a module type that
        // requires a feature absent from the binary, fail.
        let required_for_type: Option<&str> = match module_type {
            "host_image_codec" => Some("host-image"),
            _ => None,
        };
        if let Some(feat) = required_for_type {
            if !features.contains(feat) {
                return Err(Error::Config(format!(
                    "module '{name}' (type '{module_type}') requires `fluxor-linux` to be built \
                     with `--features {feat}` — current binary lacks it. \
                     Rebuild with: cargo build --release --bin fluxor-linux \
                     --no-default-features --features {feat} \
                     --target aarch64-unknown-linux-gnu",
                )));
            }
        }

        // Per-mode-value checks for built-ins where the mode picks an
        // optional backend.
        let mode_value = entry
            .get("mode")
            .or_else(|| {
                entry
                    .get("params")
                    .and_then(|p| p.as_object())
                    .and_then(|p| p.get("mode"))
            })
            .and_then(|v| v.as_str());
        let required_for_mode: Option<&str> = match (module_type, mode_value) {
            ("linux_display", Some("window")) => Some("host-window"),
            ("linux_audio", Some("playback")) => Some("host-playback"),
            _ => None,
        };
        if let Some(feat) = required_for_mode {
            if !features.contains(feat) {
                return Err(Error::Config(format!(
                    "module '{}' (type '{}', mode '{}') requires `fluxor-linux` \
                     to be built with `--features {}` — current binary lacks it. \
                     Either change `mode:` or rebuild with: cargo build --release \
                     --bin fluxor-linux --no-default-features --features {} \
                     --target aarch64-unknown-linux-gnu",
                    name,
                    module_type,
                    mode_value.unwrap_or(""),
                    feat,
                    feat,
                )));
            }
        }
    }
    Ok(())
}

/// Optional flags accepted by `fluxor run` for scenario YAMLs. For
/// graph YAMLs they are all ignored (and we error out if the user
/// passed one alongside a graph — see [`cmd_run_dispatch`]).
struct RunFlags {
    print_synthesised: bool,
    print_merged: Option<String>,
    validate_only: bool,
    graph: bool,
    /// `Some(dir)` if `--list[=DIR]` was set on the command line.
    list: Option<PathBuf>,
    open: bool,
    /// `--ca <PEM>`: operator anchors for client-mode tls/quic instances.
    /// A linux graph or a bundle only.
    ca: Option<PathBuf>,
}

impl RunFlags {
    /// True when at least one scenario-only flag was set.  `--open`
    /// counts here too — but unlike the dump flags it does NOT
    /// short-circuit the spawn (it triggers after readiness fires).
    fn any_scenario_flag(&self) -> bool {
        self.print_synthesised
            || self.print_merged.is_some()
            || self.validate_only
            || self.graph
            || self.list.is_some()
            || self.open
    }
}

/// Top-level dispatch for `fluxor run`. Sniffs the YAML's `kind:`
/// field; routes graph YAMLs to [`cmd_run`] (unchanged from
/// pre-scenario behaviour) and scenario YAMLs to [`cmd_run_scenario`].
fn cmd_run_dispatch(config_path: Option<&PathBuf>, flags: RunFlags, verbose: bool) -> Result<()> {
    // `--list` short-circuits: enumerate, print, exit.
    if let Some(dir) = &flags.list {
        let scenarios = scenario::list_scenarios(dir)?;
        if scenarios.is_empty() {
            eprintln!("(no scenarios in {})", dir.display());
        } else {
            for (path, name) in scenarios {
                println!("{}\t{}", path.display(), name);
            }
        }
        return Ok(());
    }

    let config_path = config_path.ok_or_else(|| {
        Error::Config("fluxor run: missing <CONFIG> argument (omit only with --list)".into())
    })?;

    // A workload bundle — source manifest, bundle root, or target
    // subdir: resolve an implementation with the agent's own resolver
    // and exec its built blobs.
    if workload_src::is_bundle_path(config_path) {
        if flags.any_scenario_flag() {
            return Err(Error::Config(
                "fluxor run <bundle>: scenario-only flags do not apply to a workload bundle".into(),
            ));
        }
        return workload_src::run_bundle_with_ca(config_path, flags.ca.as_deref(), verbose);
    }

    if flags.ca.is_some()
        && (scenario::is_scenario_file(config_path)
            || scenario::synthesize_from_graph(config_path)?.is_some())
    {
        return Err(Error::Config(
            "fluxor run --ca applies to a graph or a bundle, not a scenario".into(),
        ));
    }

    if scenario::is_scenario_file(config_path) {
        return cmd_run_scenario(config_path, &flags, verbose);
    }

    // Inline-scenario fast path: the graph YAML may carry a top-level
    // `scenario:` block (orchestration baked into the same file as the
    // graph). When present, synthesise a `Scenario` in memory and
    // dispatch through the regular scenario flow — same code path as
    // a standalone `kind: scenario` file, one less file per example.
    if let Some(synth) = scenario::synthesize_from_graph(config_path)? {
        return cmd_run_inline_scenario(synth, config_path, &flags, verbose);
    }

    // Bare graph YAML — every scenario-only flag is a user error.
    if flags.any_scenario_flag() {
        return Err(Error::Config(format!(
            "fluxor run {}: the supplied YAML is a graph (no `kind: scenario`); \
             scenario-only flags (--print-synthesised, --print-merged, --validate-only, \
             --graph) require a scenario YAML or an inline `scenario:` block on the graph.",
            config_path.display()
        )));
    }

    cmd_run(config_path, flags.ca.as_deref(), verbose)
}

/// Scenario flow for an in-memory `Scenario` synthesised from a graph
/// YAML's inline `scenario:` block. Mirrors `cmd_run_scenario` but
/// skips the file parse (the caller has already done it). `host_path`
/// is the graph YAML — used by `revalidate_all` for path resolution
/// (companion graph references resolve relative to it) and by error
/// messages.
fn cmd_run_inline_scenario(
    s: scenario::Scenario,
    host_path: &Path,
    flags: &RunFlags,
    verbose: bool,
) -> Result<()> {
    scenario::validate(&s, host_path)?;

    if flags.validate_only {
        scenario::revalidate_all(&s, host_path)?;
        println!(
            "graph {} (inline scenario): validation passed ({} component(s), {} binding(s); \
             merged-config re-validation green).",
            host_path.display(),
            s.components.len(),
            s.bindings.len()
        );
        return Ok(());
    }
    if flags.print_synthesised {
        match scenario::render_synthesised_host(&s, host_path)? {
            Some(yaml) => print!("{yaml}"),
            None => eprintln!(
                "graph {}: no synthesised host (every binding has an explicit `on:` and no \
                 `host:` block is declared).",
                host_path.display()
            ),
        }
        return Ok(());
    }
    if let Some(comp) = &flags.print_merged {
        print!(
            "{}",
            scenario::render_merged_component(comp, &s, host_path)?
        );
        return Ok(());
    }
    if flags.graph {
        print!("{}", scenario::render_graphviz(&s));
        return Ok(());
    }

    spawn_scenario(&s, host_path, flags, verbose)
}

/// Scenario dispatcher: the dump-only flags and `--validate` return
/// early; anything else spawns the scenario.
fn cmd_run_scenario(scenario_path: &Path, flags: &RunFlags, _verbose: bool) -> Result<()> {
    let s = scenario::parse(scenario_path)?;
    scenario::validate(&s, scenario_path)?;

    if flags.validate_only {
        scenario::revalidate_all(&s, scenario_path)?;
        println!(
            "scenario {}: validation passed ({} component(s), {} binding(s); \
             merged-config re-validation green).",
            scenario_path.display(),
            s.components.len(),
            s.bindings.len()
        );
        return Ok(());
    }

    if flags.print_synthesised {
        match scenario::render_synthesised_host(&s, scenario_path)? {
            Some(yaml) => print!("{yaml}"),
            None => {
                eprintln!(
                    "scenario {}: no synthesised host (every binding has an explicit `on:` \
                     and no `host:` block is declared).",
                    scenario_path.display()
                );
            }
        }
        return Ok(());
    }

    if let Some(comp) = &flags.print_merged {
        print!(
            "{}",
            scenario::render_merged_component(comp, &s, scenario_path)?
        );
        return Ok(());
    }

    if flags.graph {
        print!("{}", scenario::render_graphviz(&s));
        return Ok(());
    }

    // Real spawn: single-component, multi-component, or sequential mode.
    spawn_scenario(&s, scenario_path, flags, _verbose)
}

/// Spawn a scenario.
///
/// Single-component scenarios (`is_single_component` true) take the
/// single-component path: build component → write synth host → build host → spawn
/// fluxor-linux → readiness probe → wait → propagate exit.
///
/// Multi-component scenarios take the multi-component path: build every wasm
/// component (passive — bundles served as static artefacts) and every
/// non-wasm component (active — gets a fluxor-linux process each),
/// plus the synth host if `host:` is declared. Then:
///
///   - `sequential: true` runs active components one at a time in
///     declaration order, propagating the first non-zero exit and
///     enforcing per-component `duration:` (SIGTERM → SIGKILL after
///     2 s). This is the codec-test-harness mode.
///   - Otherwise spawn all actives in parallel, wait for any to exit,
///     SIGTERM the rest, and propagate the first exit.
///
/// In both cases Ctrl-C in the terminal sends SIGINT to the
/// foreground process group; each spawned `fluxor-linux` inherits it
/// and dies, and our `.wait()` returns the propagated exit status.
fn spawn_scenario(
    scenario: &scenario::Scenario,
    scenario_path: &Path,
    flags: &RunFlags,
    verbose: bool,
) -> Result<()> {
    scenario::revalidate_all(scenario, scenario_path)?;

    let scenario_dir = scenario_path
        .parent()
        .ok_or_else(|| Error::Config("scenario path has no parent dir".into()))?;

    // Anchor to the scenario's project root so `fluxor run <scenario>` finds the
    // runtime binary regardless of the caller's cwd.
    let linux_bin = crate::project::root_for_config(scenario_path)
        .join("target/aarch64-unknown-linux-gnu/release/fluxor-linux");
    if !linux_bin.exists() {
        return Err(Error::Config(format!(
            "fluxor-linux binary not found at {}. Run `make build` first.",
            linux_bin.display()
        )));
    }

    // --- 1: build every component, classified by effective target. ---
    let mut actives: Vec<ActiveComponent> = Vec::new();
    for (comp_name, comp) in &scenario.components {
        let target = scenario::effective_target(scenario_path, comp);
        if target == "wasm" {
            // Passive: build the bundle into the canonical location
            // the synthesised host's fs_path: route already points at.
            let graph_rel = comp
                .graph
                .as_ref()
                .ok_or_else(|| Error::Config(format!("component `{comp_name}` has no `graph:`")))?;
            let graph_abs = scenario_dir.join(graph_rel);
            let bundle_target = scenario::wasm_bundle_target_path(comp_name, comp)?;
            eprintln!(
                "[scenario] {}: building component `{}` (wasm, {}) → {}",
                scenario.name,
                comp_name,
                graph_abs.display(),
                bundle_target.display()
            );
            build_one(&graph_abs, Some(&bundle_target), verbose)?;
            continue;
        }

        // Active: merge bindings into the component's graph, write to
        // disk, build, and queue for spawn.
        let merged_yaml =
            scenario::write_merged_component_yaml(comp_name, scenario, scenario_path)?;
        eprintln!(
            "[scenario] {}: building component `{}` ({}) → {}",
            scenario.name,
            comp_name,
            target,
            merged_yaml.display()
        );
        let build = build_one(&merged_yaml, None, verbose)?;
        if build.family != "linux" {
            return Err(Error::Config(format!(
                "scenario {}: component `{}` built for family {:?}; only linux components \
                 are spawned (use `runtime_override: linux` for pi5 graphs).",
                scenario_path.display(),
                comp_name,
                build.family
            )));
        }
        let dir = build.output_path.parent().ok_or_else(|| {
            Error::Config(format!(
                "component `{comp_name}` build has no output parent"
            ))
        })?;
        let merged_config: serde_json::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&merged_yaml)?)
                .map_err(|e| Error::Config(format!("parse merged yaml: {e}")))?;
        let port = scenario::extract_http_port(&merged_config);
        actives.push(ActiveComponent {
            display: comp_name.clone(),
            config_bin: dir.join("config.bin"),
            modules_bin: dir.join("modules.bin"),
            port,
            url: port.map(|p| format!("http://localhost:{p}/")),
            duration: comp
                .duration
                .map(|d| std::time::Duration::from_secs(d as u64)),
        });
    }

    // --- 2: synthesised host (acts like another active component). ---
    if let Some(host_yaml) = scenario::write_synthesised_host_yaml(scenario, scenario_path)? {
        eprintln!(
            "[scenario] {}: synthesised host written to {}",
            scenario.name,
            host_yaml.display()
        );
        let host_build = build_one(&host_yaml, None, verbose)?;
        if host_build.family != "linux" {
            return Err(Error::Config(format!(
                "scenario {}: synthesised host built for family {:?}; expected linux",
                scenario_path.display(),
                host_build.family
            )));
        }
        let dir = host_build
            .output_path
            .parent()
            .ok_or_else(|| Error::Config("host build has no output parent".into()))?;
        actives.push(ActiveComponent {
            display: "host".into(),
            config_bin: dir.join("config.bin"),
            modules_bin: dir.join("modules.bin"),
            port: scenario::synthesised_host_port(scenario),
            url: scenario::synthesised_host_url(scenario),
            duration: None,
        });
    }

    if actives.is_empty() {
        return Err(Error::Config(format!(
            "scenario {}: no active components to spawn (every component is wasm and no \
             `host:` block is declared).",
            scenario_path.display()
        )));
    }

    // --- 3: spawn — sequential or parallel. ---
    if scenario.sequential {
        run_actives_sequential(&scenario.name, &linux_bin, actives, flags, scenario_path)
    } else {
        run_actives_parallel(&scenario.name, &linux_bin, actives, flags, scenario_path)
    }
}

/// One active (= spawned-as-a-kernel-process) component in a
/// scenario. Built ahead of the spawn loop; the spawn loop just
/// invokes `fluxor-linux` with the config / modules pair.
struct ActiveComponent {
    /// Display name — the scenario component name, or `"host"` for
    /// the synthesised host.
    display: String,
    config_bin: PathBuf,
    modules_bin: PathBuf,
    /// http listen port (sniffed from the merged config). `None` for
    /// headless components — the readiness probe degrades to "child
    /// still alive after a startup grace period".
    port: Option<u16>,
    url: Option<String>,
    duration: Option<std::time::Duration>,
}

/// Sequential mode: run actives one at a time. First non-zero exit
/// aborts the scenario.
fn run_actives_sequential(
    name: &str,
    linux_bin: &Path,
    actives: Vec<ActiveComponent>,
    flags: &RunFlags,
    scenario_path: &Path,
) -> Result<()> {
    for (i, a) in actives.into_iter().enumerate() {
        eprintln!(
            "[scenario] {}: [sequential {}/N] starting `{}`",
            name,
            i + 1,
            a.display
        );
        let status = spawn_and_wait_one(name, linux_bin, &a, flags, scenario_path)?;
        eprintln!(
            "[scenario] {}: [sequential {}/N] `{}` exit {}",
            name,
            i + 1,
            a.display,
            status
        );
        if !status.success() {
            return Err(Error::Config(format!(
                "scenario {}: sequential mode aborted — `{}` exited with status {}",
                scenario_path.display(),
                a.display,
                status
            )));
        }
    }
    Ok(())
}

/// Parallel mode: spawn every active, race them for exit. First to
/// exit propagates its status; the rest get SIGTERMed (then SIGKILL
/// after 2 s if they linger).
fn run_actives_parallel(
    name: &str,
    linux_bin: &Path,
    actives: Vec<ActiveComponent>,
    flags: &RunFlags,
    scenario_path: &Path,
) -> Result<()> {
    let mut spawned: Vec<SpawnedActive> = Vec::new();
    for a in actives {
        eprintln!(
            "[scenario] {}: spawning `{}` (config={}, modules={})",
            name,
            a.display,
            a.config_bin.display(),
            a.modules_bin.display()
        );
        let s = spawn_one(linux_bin, &a, scenario_path)?;
        spawned.push(s);
    }

    // Run readiness probes for each spawned child in parallel.
    let deadline_per_child = std::time::Duration::from_secs(5);
    let mut probe_error: Option<(String, ReadyOutcome)> = None;
    for s in spawned.iter_mut() {
        let outcome = race_probe(&mut s.child, &s.probe, s.port, deadline_per_child);
        match outcome {
            ReadyOutcome::Ready => {
                if let Some(u) = &s.url {
                    eprintln!("[scenario] {}: ready — `{}` at {}", name, s.display, u);
                }
            }
            other => {
                let disp = s.display.clone();
                probe_error = Some((disp, other));
                break;
            }
        }
    }
    if let Some((disp, outcome)) = probe_error {
        match outcome {
            ReadyOutcome::ChildExited(status) => {
                eprintln!("[scenario] {name}: `{disp}` exited during startup ({status})");
                teardown_remaining(&mut spawned);
                return Err(Error::Config(format!(
                    "scenario {}: component `{}` exited before its http listener bound \
                     (status {}). The kernel's diagnostic appears above.",
                    scenario_path.display(),
                    disp,
                    status
                )));
            }
            ReadyOutcome::Timeout => {
                eprintln!("[scenario] {name}: `{disp}` did not bind within 5 s");
                teardown_remaining(&mut spawned);
                return Err(Error::Config(format!(
                    "scenario {}: component `{}` did not bind its http listener within 5 s.",
                    scenario_path.display(),
                    disp
                )));
            }
            ReadyOutcome::Ready => unreachable!(),
        }
    }

    // Optional --open: launch the browser on the first non-host URL,
    // falling back to the synth host URL.
    if flags.open {
        if let Some(s) = spawned
            .iter()
            .find(|s| s.url.is_some() && s.display != "host")
            .or_else(|| spawned.iter().find(|s| s.url.is_some()))
        {
            launch_browser(s.url.as_ref().unwrap());
        }
    }

    // Wait for any spawned child to exit; tear down the rest.
    let first_exit = wait_first_exit(&mut spawned);
    teardown_remaining(&mut spawned);
    if !first_exit.success() {
        return Err(Error::Config(format!(
            "scenario {}: one component exited with status {}",
            scenario_path.display(),
            first_exit
        )));
    }
    eprintln!("[scenario] {name}: terminated cleanly");
    Ok(())
}

/// Spawn one active and wait for it, honouring `duration:` if set.
fn spawn_and_wait_one(
    name: &str,
    linux_bin: &Path,
    active: &ActiveComponent,
    flags: &RunFlags,
    scenario_path: &Path,
) -> Result<std::process::ExitStatus> {
    let mut s = spawn_one(linux_bin, active, scenario_path)?;
    let outcome = race_probe(
        &mut s.child,
        &s.probe,
        s.port,
        std::time::Duration::from_secs(5),
    );
    match outcome {
        ReadyOutcome::Ready => {
            if let Some(u) = &s.url {
                eprintln!("[scenario] {}: ready — `{}` at {}", name, s.display, u);
            }
            if flags.open {
                if let Some(u) = &s.url {
                    launch_browser(u);
                }
            }
        }
        ReadyOutcome::ChildExited(status) => {
            if let Some(p) = s.probe.take() {
                p.join();
            }
            return Err(Error::Config(format!(
                "scenario {}: component `{}` exited before its http listener bound \
                 (status {}). The kernel's diagnostic appears above.",
                scenario_path.display(),
                s.display,
                status
            )));
        }
        ReadyOutcome::Timeout => {
            let _ = s.child.kill();
            let _ = s.child.wait();
            if let Some(p) = s.probe.take() {
                p.join();
            }
            return Err(Error::Config(format!(
                "scenario {}: component `{}` did not bind its http listener within 5 s.",
                scenario_path.display(),
                s.display
            )));
        }
    }

    let outcome = if let Some(d) = active.duration {
        wait_with_duration(&mut s.child, d)
    } else {
        let status = s
            .child
            .wait()
            .map_err(|e| Error::Config(format!("waiting for {}: {}", s.display, e)))?;
        DurationOutcome::NaturalExit(status)
    };
    if let Some(p) = s.probe.take() {
        p.join();
    }
    Ok(match outcome {
        // Natural exit on its own → caller decides based on status.
        DurationOutcome::NaturalExit(s) => s,
        // Duration expired → component ran for as long as the
        // scenario asked. Treat as success regardless of the signal
        // we used to wind it down.
        DurationOutcome::DurationExpired => synthetic_success_exit_status(),
    })
}

/// Outcome of [`wait_with_duration`]. Distinguishes "child exited on
/// its own" (caller decides based on the status) from "we killed it
/// because its `duration:` expired" (sequential mode treats that as
/// success — the scenario specified that wall-clock budget).
enum DurationOutcome {
    NaturalExit(std::process::ExitStatus),
    DurationExpired,
}

fn synthetic_success_exit_status() -> std::process::ExitStatus {
    // Build a "exit 0" ExitStatus.  Unix-only; the spawn paths are
    // Linux/macOS only by construction.
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(0)
    }
    #[cfg(not(unix))]
    {
        unimplemented!("scenario runner is unix-only");
    }
}

struct SpawnedActive {
    display: String,
    child: std::process::Child,
    probe: Option<scenario_readiness_probe::Probe>,
    port: Option<u16>,
    url: Option<String>,
}

fn spawn_one(
    linux_bin: &Path,
    active: &ActiveComponent,
    _scenario_path: &Path,
) -> Result<SpawnedActive> {
    let mut cmd = std::process::Command::new(linux_bin);
    cmd.arg("--config")
        .arg(&active.config_bin)
        .arg("--modules")
        .arg(&active.modules_bin)
        .stderr(std::process::Stdio::piped());
    let mut child = tie_to_parent(&mut cmd)
        .spawn()
        .map_err(|e| {
            Error::Config(format!(
                "spawning fluxor-linux for `{}`: {}",
                active.display, e
            ))
        })?;
    let stderr_pipe = child.stderr.take().ok_or_else(|| {
        Error::Config(format!(
            "`{}`: fluxor-linux has no stderr pipe",
            active.display
        ))
    })?;
    let probe = scenario_readiness_probe::Probe::start(stderr_pipe, active.port.unwrap_or(0));
    Ok(SpawnedActive {
        display: active.display.clone(),
        child,
        probe: Some(probe),
        port: active.port,
        url: active.url.clone(),
    })
}

fn race_probe(
    child: &mut std::process::Child,
    probe: &Option<scenario_readiness_probe::Probe>,
    port: Option<u16>,
    deadline: std::time::Duration,
) -> ReadyOutcome {
    let probe = probe.as_ref().expect("probe must exist while spawned");
    let start = std::time::Instant::now();
    // For headless components (no port) the probe never fires; we
    // grant a short startup grace period then declare "ready" if the
    // child is still alive.
    let headless_grace = std::time::Duration::from_millis(500);
    loop {
        if probe.ready() {
            return ReadyOutcome::Ready;
        }
        if let Some(status) = child.try_wait().ok().flatten() {
            return ReadyOutcome::ChildExited(status);
        }
        let elapsed = start.elapsed();
        if port.is_none() && elapsed >= headless_grace {
            return ReadyOutcome::Ready;
        }
        if elapsed >= deadline {
            return ReadyOutcome::Timeout;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Wait up to `duration` for the child to exit on its own. After
/// the deadline, SIGTERM; after another 2 s, SIGKILL. Returns
/// [`DurationOutcome::NaturalExit`] iff the child died on its own,
/// otherwise [`DurationOutcome::DurationExpired`].
fn wait_with_duration(
    child: &mut std::process::Child,
    duration: std::time::Duration,
) -> DurationOutcome {
    let deadline = std::time::Instant::now() + duration;
    while std::time::Instant::now() < deadline {
        if let Some(s) = child.try_wait().ok().flatten() {
            return DurationOutcome::NaturalExit(s);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    // Duration expired — wind the child down. SIGTERM, 2 s grace,
    // SIGKILL. We treat all of these as "duration expired", not
    // failure — the scenario asked for this wall-clock budget.
    let _ = child.kill();
    let grace = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::time::Instant::now() < grace {
        if child.try_wait().ok().flatten().is_some() {
            return DurationOutcome::DurationExpired;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = child.wait();
    DurationOutcome::DurationExpired
}

fn wait_first_exit(spawned: &mut [SpawnedActive]) -> std::process::ExitStatus {
    loop {
        for s in spawned.iter_mut() {
            if let Some(status) = s.child.try_wait().ok().flatten() {
                return status;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn teardown_remaining(spawned: &mut [SpawnedActive]) {
    for s in spawned.iter_mut() {
        if s.child.try_wait().ok().flatten().is_none() {
            let _ = s.child.kill();
        }
    }
    // Grace period.
    std::thread::sleep(std::time::Duration::from_millis(500));
    for s in spawned.iter_mut() {
        let _ = s.child.wait();
    }
    for s in spawned.iter_mut() {
        if let Some(probe) = s.probe.take() {
            probe.join();
        }
    }
}

fn launch_browser(url: &str) {
    let cmd = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    match std::process::Command::new(cmd).arg(url).spawn() {
        Ok(_) => eprintln!("[scenario]   --open: launched `{cmd}` on {url}"),
        Err(e) => eprintln!(
            "[scenario]   --open: WARNING failed to launch `{cmd}` ({e}); open {url} manually"
        ),
    }
}

/// Outcome of racing the readiness probe against the spawned
/// fluxor-linux's exit status.  Used by
/// [`spawn_single_component_scenario`].
enum ReadyOutcome {
    Ready,
    ChildExited(std::process::ExitStatus),
    Timeout,
}

/// Readiness-probe machinery for the scenario runner.  The probe
/// runs one thread:
///
///   - **stderr tee**: reads `fluxor-linux`'s stderr line-by-line,
///     forwards each line to our own stderr (so the user still sees
///     kernel logs in real time), and signals "ready" the first time
///     it sees `[linux_net] listening on port <PORT>`.
///
/// Readiness is taken from that log line alone, never from polling the
/// port: a TCP connect succeeds against any other process already
/// holding it (a stale `python3 -m http.server`, say), which reads as
/// ready when the scenario has not even bound.  The kernel's
/// `linux_net::cmd_bind` log line is reliable, so the stderr signal is
/// sufficient on its own; a port poll would only be needed on a runtime
/// where stderr is muted by default.
mod scenario_readiness_probe {
    use std::io::{BufRead, BufReader, Read};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    pub struct Probe {
        ready: Arc<AtomicBool>,
        tee_handle: Option<std::thread::JoinHandle<()>>,
        stop: Arc<AtomicBool>,
    }

    impl Probe {
        pub fn start<R: Read + Send + 'static>(stderr: R, _port: u16) -> Self {
            let ready = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));

            let tee_ready = ready.clone();
            let tee_handle = std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines() {
                    let Ok(line) = line else { break };
                    // Tee: forward to our own stderr so users see logs.
                    eprintln!("{line}");
                    if line.contains("[linux_net] listening on port") {
                        tee_ready.store(true, Ordering::Release);
                    }
                }
            });

            Self {
                ready,
                tee_handle: Some(tee_handle),
                stop,
            }
        }

        /// Block until the probe fires or `timeout` elapses.  Returns
        /// `true` iff the probe fired.  Kept for the non-racing case;
        /// the scenario runner usually polls [`ready`] in its own loop
        /// alongside `child.try_wait()` so a child crash short-circuits
        /// the 5 s wait.
        #[allow(
            dead_code,
            reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
        )]
        pub fn wait(&self, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                if self.ready.load(Ordering::Acquire) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            self.ready.load(Ordering::Acquire)
        }

        /// Non-blocking: has the probe signalled "ready"?
        pub fn ready(&self) -> bool {
            self.ready.load(Ordering::Acquire)
        }

        /// Tear down the probe.  The stderr tee thread terminates on
        /// EOF, which happens when fluxor-linux's stderr closes (i.e.
        /// when the child exits).
        pub fn join(mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(h) = self.tee_handle.take() {
                let _ = h.join();
            }
        }
    }
}

fn cmd_run(config_path: &PathBuf, ca: Option<&Path>, verbose: bool) -> Result<()> {
    const QEMU_CONFIG_BLOB_ADDR: u64 = 0x6100_0000;
    const QEMU_MODULES_BLOB_ADDR: u64 = 0x6200_0000;

    // Synced fmods and the runtime binary live under `target/`, which
    // `cargo clean` wipes; refill lockfile-recorded holes before running.
    fluxor_tools::store_sync::ensure_synced(&crate::project::root_for_config(config_path))
        .map_err(|e| Error::Config(e.to_string()))?;

    let result = build_one(config_path, None, verbose)?;

    if ca.is_some() && result.family != "linux" {
        return Err(Error::Config(
            "fluxor run --ca: operator anchors apply to linux runs only".into(),
        ));
    }

    match result.family.as_str() {
        "linux" => {
            let out_dir = result.output_path.parent().unwrap();
            let mut config_bin = out_dir.join("config.bin");
            let modules_bin = out_dir.join("modules.bin");
            // Operator anchors are appended to a copy of the built blob,
            // named for what it is, so the build product itself carries
            // exactly what the graph said.
            if let Some(pem) = ca {
                let widened = out_dir.join("config.operator.bin");
                workload_src::write_widened_config(&config_bin, &widened, pem)?;
                config_bin = widened;
            }
            // Anchor to the resolved project root so `fluxor run <config>` finds
            // the runtime binary regardless of the caller's cwd.
            let linux_bin = crate::project::root_for_config(config_path)
                .join("target/aarch64-unknown-linux-gnu/release/fluxor-linux");

            if !linux_bin.exists() {
                return Err(Error::Config(format!(
                    "Linux binary not found at {}. Run 'make build' first.",
                    linux_bin.display()
                )));
            }

            eprintln!(
                "Running: {} --config {} --modules {}",
                linux_bin.display(),
                config_bin.display(),
                modules_bin.display()
            );

            let mut cmd = std::process::Command::new(&linux_bin);
            cmd.arg("--config")
                .arg(&config_bin)
                .arg("--modules")
                .arg(&modules_bin);
            let status = tie_to_parent(&mut cmd).status()?;

            if !status.success() {
                return Err(Error::Config(format!(
                    "fluxor-linux exited with status {status}"
                )));
            }
        }
        "bcm" => {
            // Check if this is qemu-virt board
            let is_qemu = result
                .board_id
                .as_deref()
                .map(|b| b == "qemu-virt")
                .unwrap_or(false);

            if is_qemu {
                let elf_path = PathBuf::from("target/aarch64-unknown-none/release/fluxor");
                if !elf_path.exists() {
                    return Err(Error::Config(format!(
                        "Firmware ELF not found at {}. Run 'make firmware TARGET=qemu-virt' first.",
                        elf_path.display()
                    )));
                }

                let out_dir = result.output_path.parent().unwrap();
                let config_blob = out_dir.join("config.bin");
                let modules_blob = out_dir.join("modules.bin");

                let (config, target_desc) = load_config_with_defaults(config_path, verbose)?;
                let modules_dir = crate::modules_build::modules_dir_for(&target_desc);
                if !modules_dir.exists() {
                    return Err(Error::Config(format!(
                        "Modules not found at {}. Run 'fluxor modules build --target {}' first.",
                        modules_dir.display(),
                        target_desc.id
                    )));
                }
                let (modules_data, config_data) = build_packaged_blobs(
                    &config,
                    modules_dir.as_path(),
                    &[],
                    &target_desc,
                    verbose,
                    &crate::project::root_for_config(config_path),
                )?;
                let modules_data = modules_data.ok_or_else(|| {
                    Error::Config("QEMU bare-metal run requires at least one module blob".into())
                })?;
                std::fs::write(&config_blob, &config_data)?;
                std::fs::write(&modules_blob, &modules_data)?;

                // Extract HTTP port from config YAML for QEMU port forwarding
                let yaml_text = std::fs::read_to_string(config_path)?;
                let yaml: serde_yaml::Value = serde_yaml::from_str(&yaml_text)
                    .map_err(|e| Error::Config(format!("YAML parse: {e}")))?;
                let guest_port = yaml
                    .get("modules")
                    .and_then(|m| m.as_sequence())
                    .and_then(|mods| {
                        mods.iter()
                            .find(|m| m.get("name").and_then(|n| n.as_str()) == Some("http"))
                    })
                    .and_then(|http| http.get("port"))
                    .and_then(|p| p.as_u64())
                    .unwrap_or(80);
                let host_port = if guest_port < 1024 {
                    guest_port + 18000
                } else {
                    guest_port
                };
                let hostfwd = format!("user,id=net0,hostfwd=tcp::{host_port}-:{guest_port}");

                eprintln!(
                    "Running: qemu-system-aarch64 -kernel {}",
                    elf_path.display()
                );
                eprintln!("  Port forward: host {host_port} -> guest {guest_port}");
                eprintln!(
                    "  Side-load: config={} @ 0x{:08x}, modules={} @ 0x{:08x}",
                    config_blob.display(),
                    QEMU_CONFIG_BLOB_ADDR,
                    modules_blob.display(),
                    QEMU_MODULES_BLOB_ADDR
                );

                let mut qemu_args: Vec<&str> = vec![
                    "-machine",
                    "virt",
                    "-cpu",
                    "cortex-a76",
                    "-smp",
                    "1",
                    "-m",
                    "1G",
                    "-nographic",
                ];
                qemu_args.extend_from_slice(&[
                    "-device",
                    "virtio-net-device,netdev=net0,mac=52:54:00:12:34:56",
                ]);
                let hostfwd_ref: &str = &hostfwd;
                let config_loader = format!(
                    "loader,file={},addr=0x{:x},force-raw=on",
                    config_blob.display(),
                    QEMU_CONFIG_BLOB_ADDR
                );
                let modules_loader = format!(
                    "loader,file={},addr=0x{:x},force-raw=on",
                    modules_blob.display(),
                    QEMU_MODULES_BLOB_ADDR
                );
                qemu_args.extend_from_slice(&[
                    "-netdev",
                    hostfwd_ref,
                    "-device",
                    config_loader.as_str(),
                    "-device",
                    modules_loader.as_str(),
                    "-kernel",
                ]);

                let status = std::process::Command::new("qemu-system-aarch64")
                    .args(&qemu_args)
                    .arg(&elf_path)
                    .status()?;

                if !status.success() {
                    return Err(Error::Config(format!("QEMU exited with status {status}")));
                }
            } else {
                eprintln!("Use 'fluxor flash' for hardware targets");
                return Err(Error::Config(
                    "Cannot run BCM hardware targets directly. Use 'fluxor flash' instead.".into(),
                ));
            }
        }
        "rp2" => {
            eprintln!("Use 'fluxor flash' for hardware targets");
            return Err(Error::Config(
                "Cannot run RP targets directly. Use 'fluxor flash' instead.".into(),
            ));
        }
        _ => {
            return Err(Error::Config(format!(
                "Unsupported target family '{}' for run",
                result.family
            )));
        }
    }

    Ok(())
}

fn cmd_flash(config_path: &Path, verbose: bool) -> Result<()> {
    let result = build_one(config_path, None, verbose)?;

    match result.family.as_str() {
        "rp2" => {
            // Look for mounted Pico in BOOTSEL mode
            let mut mount_point = None;
            if let Ok(entries) = std::fs::read_dir("/media") {
                for entry in entries.flatten() {
                    let user_dir = entry.path();
                    if user_dir.is_dir() {
                        if let Ok(sub_entries) = std::fs::read_dir(&user_dir) {
                            for sub in sub_entries.flatten() {
                                let p = sub.path();
                                if p.file_name().is_some_and(|n| n == "RPI-RP2") {
                                    mount_point = Some(p);
                                    break;
                                }
                            }
                        }
                    }
                    if mount_point.is_some() {
                        break;
                    }
                }
            }

            // Also check /run/media/ (some distros)
            if mount_point.is_none() {
                if let Ok(entries) = std::fs::read_dir("/run/media") {
                    for entry in entries.flatten() {
                        let user_dir = entry.path();
                        if user_dir.is_dir() {
                            if let Ok(sub_entries) = std::fs::read_dir(&user_dir) {
                                for sub in sub_entries.flatten() {
                                    let p = sub.path();
                                    if p.file_name().is_some_and(|n| n == "RPI-RP2") {
                                        mount_point = Some(p);
                                        break;
                                    }
                                }
                            }
                        }
                        if mount_point.is_some() {
                            break;
                        }
                    }
                }
            }

            if let Some(ref mp) = mount_point {
                let dest = mp.join(result.output_path.file_name().unwrap_or_default());
                eprintln!(
                    "Copying {} -> {}",
                    result.output_path.display(),
                    dest.display()
                );
                std::fs::copy(&result.output_path, &dest)?;
                println!(
                    "\x1b[1;32mFlashed\x1b[0m {}",
                    result
                        .output_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                );
            } else {
                // Try picotool as fallback
                let picotool = std::process::Command::new("picotool")
                    .args(["load", "-f"])
                    .arg(&result.output_path)
                    .status();

                match picotool {
                    Ok(status) if status.success() => {
                        println!(
                            "\x1b[1;32mFlashed\x1b[0m {} via picotool",
                            result
                                .output_path
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                        );
                    }
                    _ => {
                        return Err(Error::Config(
                            "No Pico found in BOOTSEL mode (checked /media/*/RPI-RP2/) and picotool not available. \
                             Hold BOOTSEL and plug in the Pico, then retry."
                                .into(),
                        ));
                    }
                }
            }
        }
        "bcm" => {
            let is_pi5 = result
                .board_id
                .as_deref()
                .map(|b| b == "pi5")
                .unwrap_or(false);

            if is_pi5 {
                let dest = PathBuf::from("/boot/firmware/kernel8.img");
                eprintln!(
                    "\x1b[1;33mWarning:\x1b[0m This will replace {}",
                    dest.display()
                );
                eprintln!(
                    "Copying {} -> {}",
                    result.output_path.display(),
                    dest.display()
                );
                std::fs::copy(&result.output_path, &dest)?;
                println!("\x1b[1;32mFlashed\x1b[0m kernel8.img — reboot to apply");
            } else {
                return Err(Error::Config(
                    "Only pi5 targets support flash. Use 'fluxor run' for QEMU targets.".into(),
                ));
            }
        }
        "linux" => {
            return Err(Error::Config(
                "Linux targets run directly. Use 'fluxor run' instead.".into(),
            ));
        }
        _ => {
            return Err(Error::Config(format!(
                "Unsupported target family '{}' for flash",
                result.family
            )));
        }
    }

    Ok(())
}

/// Generate / inspect an Ed25519 module-signing keypair. Ensures a 32-byte
/// private seed exists at `key_path` (generated 0600 from the OS RNG if absent,
/// or `--force`d), then prints the matching 64-hex-char PUBLIC key to stdout —
/// the value the kernel embeds via `FLUXOR_SIGNING_PUBKEY_HEX`. Human notes go
/// to stderr so stdout is exactly the pubkey (capturable in `$(...)`).
fn cmd_keygen(key_path: &PathBuf, force: bool) -> Result<()> {
    use std::fs;
    use std::io::Write as _;

    let exists = key_path.exists();
    if !exists || force {
        // Exactly 32 bytes from the OS RNG (Linux build host). MUST use
        // read_exact, not fs::read — /dev/urandom is an endless stream and
        // reading it to EOF never returns (OOMs).
        use std::io::Read as _;
        let mut seed = [0u8; 32];
        fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut seed))
            .map_err(|e| Error::Module(format!("read /dev/urandom: {e}")))?;
        if let Some(dir) = key_path.parent() {
            if !dir.as_os_str().is_empty() {
                fs::create_dir_all(dir)
                    .map_err(|e| Error::Module(format!("mkdir {}: {e}", dir.display())))?;
            }
        }
        let mut f = fs::File::create(key_path)
            .map_err(|e| Error::Module(format!("create {}: {e}", key_path.display())))?;
        // 0600 — a signing seed must not be world/group readable.
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut perm = f
                .metadata()
                .map_err(|e| Error::Module(format!("stat key: {e}")))?
                .permissions();
            perm.set_mode(0o600);
            f.set_permissions(perm)
                .map_err(|e| Error::Module(format!("chmod key: {e}")))?;
        }
        f.write_all(&seed)
            .map_err(|e| Error::Module(format!("write key: {e}")))?;
        eprintln!(
            "\x1b[1;32mGenerated\x1b[0m signing seed {} (0600){}",
            key_path.display(),
            if force && exists { " [rotated]" } else { "" }
        );
    } else {
        eprintln!("Using existing signing seed {}", key_path.display());
    }

    let seed_bytes = fs::read(key_path).map_err(|e| Error::Module(format!("read key: {e}")))?;
    if seed_bytes.len() != 32 {
        return Err(Error::Module(format!(
            "key must be exactly 32 bytes, got {}",
            seed_bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let pk = crypto::derive_public_key(&seed);
    // stdout = JUST the pubkey hex, so `FLUXOR_SIGNING_PUBKEY_HEX=$(fluxor modules keygen …)` works.
    let mut s = String::with_capacity(64);
    for &b in pk.iter() {
        s.push_str(&format!("{b:02x}"));
    }
    println!("{s}");
    Ok(())
}

/// Sign a packed .fmod module with an Ed25519 seed, appending a v2 manifest
/// carrying the signature + signer fingerprint. Writes either in place or to
/// `output`.
fn cmd_sign(
    input: &PathBuf,
    key_path: &PathBuf,
    output: Option<&std::path::Path>,
    verbose: bool,
) -> Result<()> {
    use std::fs;

    let seed_bytes = fs::read(key_path)
        .map_err(|e| Error::Module(format!("read key {}: {}", key_path.display(), e)))?;
    if seed_bytes.len() != 32 {
        return Err(Error::Module(format!(
            "key must be exactly 32 bytes, got {}",
            seed_bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let fmod =
        fs::read(input).map_err(|e| Error::Module(format!("read {}: {}", input.display(), e)))?;
    use modules::MODULE_HEADER_SIZE;
    if fmod.len() < MODULE_HEADER_SIZE {
        return Err(Error::Module("fmod file too small".into()));
    }

    // Locate the manifest section from the module header.
    let code_size = u32::from_le_bytes([fmod[8], fmod[9], fmod[10], fmod[11]]) as usize;
    let data_size = u32::from_le_bytes([fmod[12], fmod[13], fmod[14], fmod[15]]) as usize;
    let export_count = u16::from_le_bytes([fmod[24], fmod[25]]) as usize;
    let export_table_size = export_count * 8;
    let schema_size = u16::from_le_bytes([fmod[62], fmod[63]]) as usize;
    let manifest_size = u16::from_le_bytes([fmod[64], fmod[65]]) as usize;

    let manifest_offset =
        MODULE_HEADER_SIZE + code_size + data_size + export_table_size + schema_size;
    if manifest_offset + manifest_size > fmod.len() {
        return Err(Error::Module("fmod truncated before manifest".into()));
    }

    let mut manifest =
        manifest::Manifest::from_bytes(&fmod[manifest_offset..manifest_offset + manifest_size])?;

    use sha2::Digest as _;
    // (1) Integrity hash = SHA256(code || data) — a corruption check, stored in
    // the manifest. Identical to what the module-pack step stamps, so unsigned
    // dev modules stay loadable; the kernel re-checks this on load.
    let code_data = &fmod[MODULE_HEADER_SIZE..MODULE_HEADER_SIZE + code_size + data_size];
    let mut ih = sha2::Sha256::new();
    ih.update(code_data);
    let mut integrity_hash = [0u8; 32];
    integrity_hash.copy_from_slice(&ih.finalize());

    // (2) SIGNING ENVELOPE hash = the full security-relevant image. The Ed25519
    // signature is taken over THIS, not the integrity hash, so a tampered header
    // / export table / schema / manifest-capability field breaks the signature
    // even though code||data is untouched. MUST byte-match the kernel loader's
    // signature-verification envelope (`validate_module`):
    //   header[0..64]  (skip manifest_size @64..66 — signing grows it)
    //   || header[66..80] || code || data || export-table || schema
    //   || manifest[0..hash_offset] with flags byte 14 bits 0-1 masked
    //     (has_integrity / has_signature — the only [0..hash_offset] bytes that
    //      differ between the unsigned and signed image).
    // The manifest header+var region [0..hash_offset] is independent of the
    // hash/signature VALUES, so serialize with placeholder integrity+sig to get
    // the final layout, hash [0..hash_offset], then fill in the real values
    // (which only touch bytes at/after hash_offset).
    manifest.integrity_hash = Some(integrity_hash);
    manifest.signature = Some([0u8; 64]);
    manifest.signer_fp = Some([0u8; 32]);
    let layout = manifest.to_bytes();
    let var_size = manifest.ports.len() * 4
        + manifest.resources.len() * 4
        + manifest.dependencies.len() * 8
        + if layout[14] & 0x20 != 0 {
            // Port-capacity section (flag bit 5) sits before the hash —
            // covered by the signing envelope. Must mirror the kernel
            // verifier's offset math exactly.
            manifest.ports.len() * 8
        } else {
            0
        };
    let hash_offset = 17 + var_size; // = MANIFEST_HEADER_SIZE (u16 permissions)
    if hash_offset + 32 > layout.len() {
        return Err(Error::Module("manifest layout too small for hash".into()));
    }
    let mut h = sha2::Sha256::new();
    h.update(&fmod[0..64]);
    h.update(&fmod[66..manifest_offset]);
    h.update(&layout[0..14]);
    h.update([layout[14] & 0xFC]);
    h.update(&layout[15..hash_offset]);
    // ABI-surface attestation (trailing 32 bytes when flag bit 4 is set):
    // signed, so a stale artifact can't be re-labeled compatible by
    // rewriting the attestation while keeping a valid signature. MUST
    // byte-match the kernel verifier.
    if layout[14] & 0x10 != 0 {
        h.update(&layout[layout.len() - 32..]);
    }
    let mut envelope_hash = [0u8; 32];
    envelope_hash.copy_from_slice(&h.finalize());

    let (pk, sig) = crypto::sign(&seed, &envelope_hash);
    let signer_fp = crypto::sha256(&pk);
    if !crypto::verify(&pk, &envelope_hash, &sig) {
        return Err(Error::Module("internal: round-trip verify failed".into()));
    }

    // integrity_hash already set above (code||data); attach the signature.
    manifest.signature = Some(sig);
    manifest.signer_fp = Some(signer_fp);
    let new_manifest_bytes = manifest.to_bytes();
    let new_manifest_size = new_manifest_bytes.len();

    let mut out_bytes = Vec::with_capacity(manifest_offset + new_manifest_size);
    out_bytes.extend_from_slice(&fmod[..manifest_offset]);
    out_bytes.extend_from_slice(&new_manifest_bytes);

    let manifest_size_le = (new_manifest_size as u16).to_le_bytes();
    out_bytes[64] = manifest_size_le[0];
    out_bytes[65] = manifest_size_le[1];

    let out_path = output.unwrap_or(input.as_path());
    fs::write(out_path, &out_bytes)
        .map_err(|e| Error::Module(format!("write {}: {}", out_path.display(), e)))?;

    use fluxor_tools::hash::hex;

    if verbose {
        println!("Signed {} ({} bytes)", out_path.display(), out_bytes.len());
        println!("  pubkey:    {}", hex(&pk));
        println!("  signer_fp: {}", hex(&signer_fp));
    } else {
        let full = hex(&pk);
        println!(
            "\x1b[1;32mSigned\x1b[0m {} pubkey={}...{}",
            out_path.display(),
            &full[..8],
            &full[full.len() - 8..]
        );
    }

    Ok(())
}

/// `fluxor lint hygiene` — drive the AST scanner over a project root,
/// honour `fluxor.toml::[ci.hygiene]`, and surface every violation in
/// a single pass. Exit code is non-zero on any violation or stale
/// exemption row.
fn cmd_lint_hygiene(project_root_override: Option<&Path>, json: bool) -> Result<()> {
    let root = match project_root_override {
        Some(p) => p.to_path_buf(),
        None => crate::project::root(),
    };

    let config = hygiene::Config::load(&root)
        .map_err(|e| Error::Config(format!("loading fluxor.toml: {e}")))?;
    let report =
        hygiene::scan(&root, &config).map_err(|e| Error::Config(format!("scanning: {e}")))?;

    if json {
        let payload = serde_json::json!({
            "files_scanned": report.files_scanned,
            "mode": match config.mode {
                hygiene::Mode::Strict => "strict",
                hygiene::Mode::Permissive => "permissive",
            },
            "violations": report.violations.iter().map(|v| serde_json::json!({
                "path": v.path.to_string_lossy(),
                "line": v.line,
                "rule": v.rule.as_str(),
                "message": v.message,
            })).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
        if !report.ok() {
            std::process::exit(1);
        }
        return Ok(());
    }

    for v in &report.violations {
        eprintln!(
            "\x1b[1;31m{rule}\x1b[0m {path}:{line}: {message}",
            rule = v.rule.as_str(),
            path = v.path.display(),
            line = v.line,
            message = v.message,
        );
    }
    let n_v = report.violations.len();
    if n_v == 0 {
        eprintln!(
            "\x1b[1;32mhygiene clean\x1b[0m ({} files scanned)",
            report.files_scanned,
        );
        return Ok(());
    }
    eprintln!(
        "\x1b[1;31mhygiene\x1b[0m {n_v} violation(s) across {} files",
        report.files_scanned,
    );
    std::process::exit(1);
}

fn resolve_project_root(override_arg: Option<&Path>) -> PathBuf {
    override_arg
        .map(Path::to_path_buf)
        .unwrap_or_else(crate::project::root)
}

/// `fluxor lint observability` — check the instrumentation contract across
/// every module manifest. Reports the gap list (data-moving modules with no
/// `[observability]`); fails only on malformed instrument names
/// (standards/observability.md §6, §9).
fn cmd_lint_observability(
    project_root_override: Option<&Path>,
    json: bool,
    strict: bool,
) -> Result<()> {
    let root = resolve_project_root(project_root_override);
    let toml_exempt = fluxor_tools::observability::load_toml_exemptions(&root);
    let report =
        fluxor_tools::observability::lint_with_exemptions(&root.join("modules"), &toml_exempt);
    // In `--strict` (CI) mode an uninstrumented data-moving module is a hard
    // error; otherwise it is a warning and only malformed names fail.
    let fail = report.has_errors() || (strict && !report.uninstrumented.is_empty());

    if json {
        let payload = serde_json::json!({
            "scanned": report.scanned,
            "instrumented": report.instrumented,
            "uninstrumented": report.uninstrumented,
            "exempt": report.exempt.iter()
                .map(|(m, r)| serde_json::json!({ "module": m, "reason": r }))
                .collect::<Vec<_>>(),
            "invalid_names": report.invalid_names.iter()
                .map(|(m, n)| serde_json::json!({ "module": m, "name": n }))
                .collect::<Vec<_>>(),
            "invalid_attr_keys": report.invalid_attr_keys.iter()
                .map(|(m, k)| serde_json::json!({ "module": m, "key": k }))
                .collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
        if fail {
            std::process::exit(1);
        }
        return Ok(());
    }

    for (m, n) in &report.invalid_names {
        eprintln!(
            "\x1b[1;31mobservability\x1b[0m {m}: invalid instrument name {n:?} \
             (instrument names are dotted lowercase)"
        );
    }
    for (m, k) in &report.invalid_attr_keys {
        eprintln!(
            "\x1b[1;31mobservability\x1b[0m {m}: dimension key {k:?} is neither an \
             OTel semantic-convention key from standards/observability.md §5 nor \
             `fluxor.*`"
        );
    }
    for m in &report.uninstrumented {
        let (colour, level) = if strict {
            ("1;31", "error")
        } else {
            ("1;33", "warn")
        };
        eprintln!(
            "\x1b[{colour}mobservability\x1b[0m {m}: data-moving module declares no \
             `[observability]` metrics/spans and no `exempt` reason ({level})"
        );
    }
    eprintln!(
        "\x1b[1;32mobservability\x1b[0m {} scanned, {} instrumented, {} exempt, \
         {} uninstrumented, {} invalid",
        report.scanned,
        report.instrumented,
        report.exempt.len(),
        report.uninstrumented.len(),
        report.invalid_names.len() + report.invalid_attr_keys.len(),
    );
    if fail {
        std::process::exit(1);
    }
    Ok(())
}

/// `fluxor lint presentation` — run the placement resolver over every config's
/// `presentation.shell` and fail on any unplaceable `essential` control.
fn cmd_lint_presentation(project_root_override: Option<&Path>) -> Result<()> {
    let root = resolve_project_root(project_root_override);
    let mut scanned = 0usize;
    let mut with_shell = 0usize;
    let mut violations: Vec<(String, String)> = Vec::new();

    for entry in walkdir::WalkDir::new(&root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // Generated artefacts under target/ aren't source configs.
        if path.components().any(|c| c.as_os_str() == "target") {
            continue;
        }
        match path.extension().and_then(|e| e.to_str()) {
            Some("yaml") | Some("yml") => {}
            _ => continue,
        }
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => continue,
        };
        // Not every .yaml is a Fluxor config; skip anything that doesn't parse.
        let cfg: serde_json::Value = match serde_yaml::from_str(&text) {
            Ok(v) => v,
            Err(_) => continue,
        };
        scanned += 1;
        if cfg.pointer("/presentation/shell").is_some() {
            with_shell += 1;
        }
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .display()
            .to_string();
        for msg in fluxor_tools::presentation_resolver::lint_config(&cfg) {
            violations.push((rel.clone(), msg));
        }
    }

    for (file, msg) in &violations {
        eprintln!("\x1b[1;31mpresentation\x1b[0m {file}: {msg}");
    }
    if violations.is_empty() {
        println!(
            "\x1b[1;32mpresentation clean\x1b[0m ({scanned} configs scanned, \
             {with_shell} with a presentation.shell)"
        );
        Ok(())
    } else {
        eprintln!(
            "\npresentation: {} unplaceable essential control(s)",
            violations.len()
        );
        std::process::exit(1);
    }
}

/// `fluxor modules build` — drive the PIC / wasm module pipeline.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "CLI boolean flags map 1:1 to clap fields; collapsing them adds indirection without clarifying intent"
)]
fn cmd_modules_build(
    target: Option<String>,
    all: bool,
    out: &Path,
    strict: bool,
    lenient: bool,
    project_root: Option<&Path>,
    verbose: bool,
) -> Result<()> {
    let project_root = resolve_project_root(project_root);
    let out_root = if out.is_absolute() {
        out.to_path_buf()
    } else {
        project_root.join(out)
    };

    let selector = match (target, all) {
        (Some(t), false) => modules_build::TargetSelector::One(t),
        (None, true) => modules_build::TargetSelector::All,
        (None, false) => {
            return Err(Error::Module(
                "`fluxor modules build` requires `--target T` or `--all`".to_string(),
            ));
        }
        (Some(_), true) => {
            // clap's `conflicts_with` should catch this, but guard
            // anyway so the error surfaces as a Module error rather
            // than a clap panic.
            return Err(Error::Module(
                "`--target` and `--all` are mutually exclusive".to_string(),
            ));
        }
    };

    let opts = modules_build::BuildOpts {
        project_root,
        selector,
        out_root,
        // `--lenient` is the implicit default when neither flag is set.
        strict: strict && !lenient,
        verbose,
    };
    let report = modules_build::run(&opts)?;
    let mut had_failure = false;
    for tr in &report.per_target {
        println!(
            "Modules ({target}/{silicon}): built {} of {}, up-to-date {}, skipped {}, failed {}",
            tr.built.len(),
            tr.built.len() + tr.up_to_date.len() + tr.skipped.len() + tr.failed.len(),
            tr.up_to_date.len(),
            tr.skipped.len(),
            tr.failed.len(),
            target = tr.target,
            silicon = tr.silicon,
        );
        for (name, reason) in &tr.skipped {
            println!("  skipped: {name} — {reason}");
        }
        for (name, reason) in &tr.failed {
            eprintln!("  FAILED:  {name} — {reason}");
            had_failure = true;
        }
    }
    if had_failure {
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_modules_clean(out: &Path) -> Result<()> {
    let project_root = crate::project::root();
    let out_root = if out.is_absolute() {
        out.to_path_buf()
    } else {
        project_root.join(out)
    };
    let opts = modules_build::BuildOpts {
        project_root,
        selector: modules_build::TargetSelector::All,
        out_root,
        strict: false,
        verbose: false,
    };
    let removed = modules_build::clean(&opts)?;
    println!("modules clean: removed {removed} artefact file(s)");
    Ok(())
}

fn cmd_modules_list(project_root: Option<&Path>, json: bool) -> Result<()> {
    let project_root = resolve_project_root(project_root);
    let summaries = modules_build::list(&project_root)?;
    if json {
        let payload = serde_json::json!({
            "project_root": project_root.to_string_lossy(),
            "modules": summaries.iter().map(|s| serde_json::json!({
                "name": s.name,
                "entry": s.entry.to_string_lossy(),
                "manifest": s.manifest.to_string_lossy(),
                "hardware_targets": s.hardware_targets,
                "type_id": s.type_id,
                "builtin": s.builtin,
            })).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
        return Ok(());
    }
    println!("Modules under {}:", project_root.display());
    for s in &summaries {
        let targets = if s.hardware_targets.is_empty() {
            "<all>".to_string()
        } else {
            s.hardware_targets.join(",")
        };
        // A `builtin = true` module is compiled into the kernel and
        // has no entry file to name (standards/fluxor-modules.md §0.1).
        let entry = if s.builtin {
            "<builtin>".to_string()
        } else {
            s.entry.display().to_string()
        };
        println!("  {name:24} type={type_id} targets={targets} entry={entry}", name = s.name, type_id = s.type_id);
    }
    println!("({} modules)", summaries.len());
    Ok(())
}

fn cmd_modules_resolve(target: &str, out: &Path) -> Result<()> {
    let project_root = crate::project::root();
    let out_root = if out.is_absolute() {
        out.to_path_buf()
    } else {
        project_root.join(out)
    };
    let path = modules_build::resolve(&project_root, &out_root, target);
    println!("{}", path.display());
    Ok(())
}

/// `fluxor ci` — orchestrate the full CI gate.
fn cmd_ci(skip: &[String], project_root: Option<&Path>, verbose: bool) -> Result<()> {
    let project_root = resolve_project_root(project_root);
    let skip_set = ci::SkipSet::from_strs(skip).map_err(Error::Config)?;
    let results = ci::run(&project_root, &skip_set, verbose)?;
    println!("{}", ci::format_summary(&results));
    if !ci::all_ok(&results) {
        std::process::exit(1);
    }
    // Green FULL run: stamp the input digests it covered so `publish`
    // can annotate `io.fluxor.ci-digest` on matching artifacts —
    // information for `inspect`/promotion, never a gate. A run with
    // any `--skip` flag proved less than the full gate, so it must
    // not stamp (the ci-digest would claim coverage it doesn't have).
    if skip.is_empty() {
        match fluxor_tools::store_publish::write_ci_green_stamp(&project_root) {
            Ok(_) => {}
            Err(e) => eprintln!("warning: could not write ci green stamp: {e}"),
        }
    }
    Ok(())
}

/// `fluxor help` — CLI help, or (`--make`) the canonical `make help`
/// block for this checkout, which a Makefile's `help:` target emits
/// verbatim.
fn cmd_help(make: bool, project_root: Option<&Path>, command: Option<&str>) -> Result<()> {
    if make {
        print!(
            "{}",
            fluxor_tools::lifecycle::make_help(&resolve_project_root(project_root))
        );
        return Ok(());
    }
    let mut cli = <Cli as clap::CommandFactory>::command();
    match command {
        None => cli.print_help(),
        Some(name) => match cli.find_subcommand_mut(name) {
            Some(sub) => sub.print_help(),
            None => {
                return Err(Error::Config(format!(
                    "`{name}` is not a fluxor command (see `fluxor --help`)"
                )))
            }
        },
    }
    .map_err(|e| Error::Config(e.to_string()))?;
    println!();
    Ok(())
}

// ── Polymorphic `fluxor build` ───────────────────────────────────────

/// Flag bundle for `fluxor build` — the absorbed
/// generate/combine/graph-image/mktable-config/validate forms route to
/// their original implementations unchanged (byte-identity by
/// construction).
struct BuildFlags {
    output: Option<PathBuf>,
    emit: Option<String>,
    check: bool,
    firmware: Option<PathBuf>,
    modules_dir: Vec<PathBuf>,
    target: Option<String>,
    epoch: u64,
}

/// `fluxor build` — the whole project (no argument), or one named
/// config (a path). Same stage, two scopes; the argument's presence is
/// the discriminator, and every flag belongs to the config form.
fn cmd_build_dispatch(path: Option<&PathBuf>, flags: BuildFlags, verbose: bool) -> Result<()> {
    let Some(path) = path else {
        if flags.check
            || flags.emit.is_some()
            || flags.output.is_some()
            || flags.firmware.is_some()
            || !flags.modules_dir.is_empty()
            || flags.target.is_some()
        {
            return Err(Error::Config(
                "`fluxor build`'s flags belong to the config form — name a config file or \
                 directory, or drop the flags for the lifecycle build"
                    .into(),
            ));
        }
        return lifted(fluxor_tools::lifecycle::build(
            &crate::project::root(),
            verbose,
        ));
    };
    if flags.check {
        if flags.emit.is_some() {
            return Err(Error::Config(
                "--check validates without building; drop --emit".into(),
            ));
        }
        return cmd_validate(path, flags.target.as_deref());
    }
    let require_output = |what: &str| {
        flags
            .output
            .clone()
            .ok_or_else(|| Error::Config(format!("--emit={what} requires --output <FILE>")))
    };
    match flags.emit.as_deref() {
        None => cmd_build(path, flags.output.as_deref(), verbose),
        Some("uf2") => cmd_generate(
            path,
            flags.output.as_deref(),
            flags.modules_dir.first().map(PathBuf::as_path),
            false,
        ),
        Some("bin") => cmd_generate(
            path,
            flags.output.as_deref(),
            flags.modules_dir.first().map(PathBuf::as_path),
            true,
        ),
        Some("combined") => {
            let firmware = flags.firmware.as_ref().ok_or_else(|| {
                Error::Config("--emit=combined requires --firmware <UF2>".into())
            })?;
            let output = require_output("combined")?;
            cmd_combine(firmware, path, &output, verbose)
        }
        Some("image") => {
            let output = require_output("image")?;
            cmd_graph_image(
                path,
                &output,
                flags.target.as_deref(),
                flags.epoch,
                flags.modules_dir.first().map(PathBuf::as_path),
                verbose,
            )
        }
        Some("table") => {
            let output = require_output("table")?;
            cmd_mktable_config(path, &flags.modules_dir, &output)
        }
        Some(other) => Err(Error::Config(format!(
            "unknown --emit form '{other}' (expected uf2|bin|combined|image|table)"
        ))),
    }
}

/// `fluxor id-table` — export a graph's observability id-table:
/// instance-ordered instrument names plus per-instrument kind / bounds /
/// dimension metadata and the FNV-1a32 table digest. Runs the same stack
/// expansion the image build runs, so the exported indices are the indices
/// the kernel stamps into records.
///
/// NOTE: extra `--modules-dir` roots change the table and therefore the
/// digest; the build's injected digest (stack_expand) uses the project's
/// `modules/` only, so pass extras only when the build did the same.
fn cmd_id_table(
    yaml_path: &Path,
    out: Option<&Path>,
    extra_roots: &[PathBuf],
) -> Result<()> {
    let content = substitute_env_vars(&std::fs::read_to_string(yaml_path)?)?;
    let mut config: serde_json::Value = if yaml_path
        .extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&content)?
    } else {
        serde_json::from_str(&content)?
    };
    let target_desc = resolve_target(&config, None)?;
    // Resolve from the CONFIG's location, not the cwd: the rig and
    // cross-repo builds invoke this from another project's root, and a
    // cwd-resolved root gave the id-table digest injection the wrong
    // `[observability] id_table_dirs` (a digest the exporter can never
    // match).
    let project_root = fluxor_tools::project::root_for_config(yaml_path);
    stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;

    // Default roots = the SAME set the build's digest injection uses
    // (project modules/ + fluxor.toml [observability] id_table_dirs), so the
    // exported digest matches the injected one by construction. --modules-dir
    // extras change both the table and the digest; use them only when the
    // build did the same.
    let mut roots = fluxor_tools::observability::id_table_roots(&project_root);
    roots.extend(extra_roots.iter().cloned());
    let table = fluxor_tools::observability::id_table_for_expanded_config(&config, &roots);
    let json = serde_json::to_string_pretty(&table.to_json()).unwrap_or_default();
    match out {
        Some(p) => {
            std::fs::write(p, &json)?;
            eprintln!(
                "id-table: {} instruments, digest {:#010x} -> {}",
                table.len(),
                table.digest(),
                p.display()
            );
        }
        None => println!("{json}"),
    }
    Ok(())
}
