fn cmd_validate(config_path: &PathBuf, target_override: Option<&str>) -> Result<()> {
    let content = substitute_env_vars(&std::fs::read_to_string(config_path)?)?;
    let config: serde_json::Value = if config_path
        .extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&content)?
    } else {
        serde_json::from_str(&content)?
    };

    let mut config = config;
    let target_desc = resolve_target(&config, target_override)?;
    let project_root = crate::project::root();
    stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;

    println!(
        "Validating {} against target '{}'...",
        config_path.display(),
        target_desc.display_name()
    );

    let mut result = board::validate_config(&config, &target_desc)?;

    // Validate the `presentation_groups` block here as well as in the
    // build path so `fluxor validate` catches authority / multihead /
    // protected-path errors without compiling. The module-search dirs
    // mirror `cmd_build`'s derivation so a project-local manifest
    // reachable from `fluxor build` is also reachable from `fluxor
    // validate`.
    if let Some(modules) = config.get("modules") {
        let module_names: Vec<String> = modules
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let search_paths = crate::config::extract_module_search_paths(&config, config_path);
        let extra_dirs: Vec<&std::path::Path> = search_paths.iter().map(|p| p.as_path()).collect();
        // Config-anchored root so a cross-project `fluxor validate ../x.yaml`
        // reads the CONFIG's fluxor.lock pins, not the cwd's.
        let cfg_root = crate::project::root_for_config(config_path);
        let manifests =
            crate::config::load_module_manifests_with_extra(modules, &extra_dirs, &cfg_root);
        if let Err(e) =
            crate::config::validate_presentation_groups(&config, &module_names, &manifests)
        {
            result.add_error(e.to_string());
        }
        // Session continuity classes (rfc_protocols.md §7.3) — same
        // dual-path treatment as presentation groups so `fluxor
        // validate` catches missing anchors / roles / R1–R5 capability
        // providers without compiling.
        if let Err(e) = crate::config::validate_continuity(&config, &module_names, &manifests) {
            result.add_error(e.to_string());
        }
    }

    // Dry-run the full config-generation pipeline so missing
    // manifests, malformed wiring, unknown content types, and tier
    // admission errors all surface as `fluxor validate` failures
    // instead of waiting for `fluxor build` (which needs firmware
    // + .fmod files on disk). The result blob is discarded —
    // validate is read-only.
    //
    // The module directory and pin/pio bounds use the target's
    // declared geometry so a host-target validate doesn't try to
    // load .fmod files from an embedded target tree.
    let modules_dir_default = format!("target/fluxor/{}/modules", target_desc.id);
    let modules_dir = std::path::PathBuf::from(&modules_dir_default);
    let search_paths = crate::config::extract_module_search_paths(&config, config_path);
    let extra_dirs: Vec<&std::path::Path> = search_paths.iter().map(|p| p.as_path()).collect();
    let dry_run_builder = ConfigBuilder::new();
    if let Err(e) = config::generate_config_ext(
        &config,
        &dry_run_builder,
        &[],
        &modules_dir,
        &extra_dirs,
        target_desc.max_pin + 1,
        target_desc.pio_count,
        Some(&target_desc.id),
        &crate::project::root_for_config(config_path),
    ) {
        result.add_error(format!("{e}"));
    }

    // Print warnings (yellow)
    for warning in &result.warnings {
        println!("  \x1b[1;33mWARNING:\x1b[0m {warning}");
    }

    // Print errors (red)
    for error in &result.errors {
        println!("  \x1b[1;31mERROR:\x1b[0m {error}");
    }

    // Summary
    println!();
    if result.is_ok() {
        if result.warnings.is_empty() {
            println!("\x1b[1;32mValidation passed.\x1b[0m");
        } else {
            println!(
                "\x1b[1;32mValidation passed\x1b[0m with {} warning(s).",
                result.warnings.len()
            );
        }
        Ok(())
    } else {
        println!(
            "\x1b[1;31mValidation FAILED:\x1b[0m {} error(s), {} warning(s)",
            result.errors.len(),
            result.warnings.len()
        );
        Err(error::Error::Config("Validation failed".into()))
    }
}

fn cmd_target_info(target_name: &str, field: Option<&str>) -> Result<()> {
    let root = crate::project::root();
    let desc = target::load_target(target_name, &root)?;

    if let Some(field) = field {
        // Machine-readable: print just the requested field value
        match field {
            "rust_target" => {
                if let Some(ref b) = desc.build {
                    println!("{}", b.rust_target);
                }
            }
            "cargo_features" => {
                if let Some(ref b) = desc.build {
                    println!("{}", b.cargo_features.join(","));
                }
            }
            "uf2_family_id" => {
                if let Some(ref b) = desc.build {
                    println!("0x{:08x}", b.uf2_family_id);
                }
            }
            "module_target" => {
                if let Some(ref b) = desc.build {
                    println!("{}", b.module_target);
                }
            }
            "max_pin" => println!("{}", desc.max_pin),
            "family" => println!("{}", desc.family),
            "id" => println!("{}", desc.id),
            "pio_count" => println!("{}", desc.pio_count),
            "spi_count" => println!("{}", desc.spi_count),
            "i2c_count" => println!("{}", desc.i2c_count),
            "dma_channels" => println!("{}", desc.dma_channels),
            _ => {
                return Err(error::Error::Config(format!(
                    "Unknown field '{field}'. Available: rust_target, cargo_features, uf2_family_id, \
                     module_target, max_pin, family, id, pio_count, spi_count, i2c_count, dma_channels"
                )));
            }
        }
        return Ok(());
    }

    // Human-readable output
    println!("Target: {}", desc.display_name());
    println!("  Silicon: {} ({})", desc.id, desc.family);
    if let Some(ref board) = desc.board_id {
        println!(
            "  Board: {} ({})",
            board,
            desc.board_description.as_deref().unwrap_or("")
        );
    }
    if let Some(ref b) = desc.build {
        println!("  Rust target: {}", b.rust_target);
        println!("  Features: {}", b.cargo_features.join(", "));
        println!("  UF2 family: 0x{:08x}", b.uf2_family_id);
        println!("  Module target: {}", b.module_target);
    } else {
        println!("  Build: validation only (no kernel build support)");
    }
    println!(
        "  GPIO: 0-{} (reserved: {})",
        desc.max_pin,
        if desc.reserved_pins.is_empty() {
            "none".to_string()
        } else {
            desc.reserved_pins
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    println!(
        "  Peripherals: SPI={}, I2C={}, UART={}, ADC={}, PWM={}, PIO={} ({}SM each), DMA={}",
        desc.spi_count,
        desc.i2c_count,
        desc.uart_count,
        desc.adc_channels,
        desc.pwm_slices,
        desc.pio_count,
        desc.pio_state_machines,
        desc.dma_channels
    );
    if let Some(ref mem) = desc.memory {
        println!(
            "  Memory: flash={}K @ 0x{:08x}, RAM={}K @ 0x{:08x}",
            mem.flash_size / 1024,
            mem.flash_base,
            mem.ram_size / 1024,
            mem.ram_base
        );
    }

    Ok(())
}

/// `fluxor abi-regen [--check]` — the single writer of the ABI-surface pin.
/// Recomputes the SDK source hash + surface digest and rewrites all checked-in
/// sites together (so they cannot drift). The shared computation lives in
/// `crate::abi_pin`, so `fluxor ci`'s read-only gate uses the exact same logic.
fn cmd_abi_regen(check: bool) -> Result<()> {
    let repo = crate::abi_pin::repo_root_from(&std::env::current_dir()?)?;
    let plan = crate::abi_pin::compute(&repo)?;
    if check {
        let stale = plan.stale_sites()?;
        if stale.is_empty() {
            println!("ABI-surface pin current (digest {}).", plan.digest_hex);
            Ok(())
        } else {
            let names: Vec<String> = stale.iter().map(|p| p.display().to_string()).collect();
            Err(Error::Config(format!(
                "ABI-surface pin STALE — run `fluxor abi-regen`. Out-of-date: {}",
                names.join(", ")
            )))
        }
    } else {
        plan.write()?;
        println!("ABI-surface pin regenerated ({} sites):", plan.edits.len());
        println!("  digest   {}", plan.digest_hex);
        println!("Rebuild the tools so callers pick up the new const.");
        Ok(())
    }
}

fn cmd_targets() -> Result<()> {
    let root = crate::project::root();
    let names = target::list_targets(&root);

    if names.is_empty() {
        println!("No targets found. Check targets/ directory.");
        return Ok(());
    }

    println!("Available targets:");
    for name in &names {
        match target::load_target(name, &root) {
            Ok(desc) => {
                let kind = if desc.board_id.is_some() {
                    "board"
                } else if desc.is_host() {
                    "host"
                } else if desc.build.is_some() {
                    "silicon"
                } else {
                    "validation"
                };
                println!("  {:20} {:12} {}", name, kind, desc.description);
            }
            Err(_) => {
                println!("  {name:20} (error loading)");
            }
        }
    }

    Ok(())
}

/// `fluxor inspect [config] [--json]` — diagnostic surface for
/// "what does fluxor resolve to from here?" Prints:
///
/// 1. The resolved project root + how it was discovered (env var,
///    `.fluxor` marker, source-tree heuristic, CWD fallback) plus
///    the `$FLUXOR_PROJECT_ROOT` setting if any.
/// 2. The available targets (`targets/boards/*.toml` +
///    `targets/silicon/*.toml`) — same listing as `fluxor targets`.
/// 3. The available stacks (`stacks/*.toml`) — file listing only;
///    expansion happens against a specific platform during build.
/// 4. **If a config is given**: the YAML's declared target, the
///    resolved target descriptor, the platform stacks the build
///    would expand, and the manifest search paths
///    `extract_module_search_paths` produces.
///
/// With `--json`, emits the same data as a stable JSON object
/// (top-level keys: `project_root`, `install_root`, `targets`,
/// `stacks`, `rig`, `scenarios`, optionally `config`).
///
/// This subcommand is read-only — it never touches `target/` or
/// produces build artefacts. Safe to run from anywhere.
fn cmd_inspect(config_path: Option<&Path>, json: bool) -> Result<()> {
    if json {
        return cmd_inspect_json(config_path);
    }
    let pr = crate::project::discover();

    println!("Project root");
    println!("  path:                 {}", pr.path.display());
    println!(
        "  source:               {}",
        format_discovery_source(&pr.source)
    );
    if pr.starting_cwd != pr.path {
        println!("  cwd:                  {}", pr.starting_cwd.display());
    }
    match &pr.env_var_value {
        Some(v) if pr.source == crate::project::DiscoverySource::EnvVar => {
            println!("  $FLUXOR_PROJECT_ROOT: {v} (active)");
        }
        Some(v) => {
            println!("  $FLUXOR_PROJECT_ROOT: {v} (set but unusable; ignored)");
        }
        None => {
            println!("  $FLUXOR_PROJECT_ROOT: <unset>");
        }
    }

    // Install root — separate from project root so an external
    // user project can ship its own targets/stacks while still
    // falling back to bundled defaults. `target::load_target` and
    // `stack_expand::load_stack` consult this layered lookup
    // automatically; `inspect` surfaces it so the user knows what
    // fluxor would fall back to.
    match crate::project::install_root() {
        Some(install) => {
            println!("  install root:         {}", install.path.display());
            println!(
                "    via:                {}",
                format_install_source(&install.source)
            );
            if install.path == pr.path {
                println!("    (same as project root — no fallback in effect)");
            }
        }
        None => {
            println!("  install root:         <none discovered>");
        }
    }
    println!();

    // Targets — merged view across project root + install root.
    // `target::load_target` falls back from project to install at
    // runtime; inspect must mirror that, otherwise an external
    // `.fluxor` project with no local `targets/` would report
    // "no targets" while the build pipeline would happily resolve
    // bundled ones. Source annotation per entry shows which root
    // each target lives under (and which one "wins" when both
    // carry the same name).
    let install_root = crate::project::install_root();
    let install_path_ref = install_root.as_ref().map(|i| i.path.as_path());
    let install_distinct = install_path_ref.filter(|p| **p != *pr.path);
    print_inspect_targets_block(&pr.path, install_distinct);

    // Stacks — same dual-root pattern. Stacks are file-listings
    // (expansion is per-target) so the annotation is just "which
    // root carries this file and is it shadowed by a project-side
    // override."
    print_inspect_stacks_block(&pr.path, install_distinct);

    // Rig configuration. Tangential to the build path but the same
    // discoverability question — "what rigs does fluxor see from
    // here?" — so the unified `inspect` surface answers it
    // alongside targets/stacks rather than forcing the user to
    // remember a separate `fluxor rig list` verb.
    inspect_rig_config();

    // Scenarios. Same discoverability principle: `fluxor run
    // --list <dir>` is the focused enumerator, but a one-screen
    // `inspect` should surface what's available without forcing
    // the user to know where scenarios live.
    inspect_scenarios(&pr.path);

    // Per-config resolution.
    if let Some(cfg_path) = config_path {
        inspect_config(cfg_path, &pr.path)?;
    } else {
        println!("Tip: pass a config (`fluxor inspect path/to/graph.yaml`) to see the");
        println!("     resolved target, expanded stacks, and module search paths for it.");
    }

    Ok(())
}

/// Machine-readable shape of `fluxor inspect`. The JSON form is the
/// stable v1 surface for CI / IDE / dashboard integrations. Field
/// names map 1:1 to the text rendering so a user can grep either
/// output and find the same data:
///
/// ```text
/// {
///   "project_root": { "path", "source", "starting_cwd", "env_var": {…} },
///   "install_root": null | { "path", "source" },
///   "targets":      [ { "name", "kind", "description" } ],
///   "stacks":       [ "audio", "debug", … ],
///   "rig":          { "active_lab", "lab_env_set", "available_labs", "rigs" },
///   "scenarios":    { "scanned_dirs", "found", "errors" },
///   "config":       null | { "path", "declared_target", … }
/// }
/// ```
///
/// Order of keys is stable but unspecified by JSON; downstream
/// consumers should pick by name, not position.
fn cmd_inspect_json(config_path: Option<&Path>) -> Result<()> {
    let pr = crate::project::discover();
    let mut out = serde_json::json!({});

    // Project root.
    out["project_root"] = serde_json::json!({
        "path": pr.path.display().to_string(),
        "source": match pr.source {
            crate::project::DiscoverySource::EnvVar => "env_var",
            crate::project::DiscoverySource::DotFluxorMarker => "dot_fluxor_marker",
            crate::project::DiscoverySource::SourceTreeMarker => "source_tree_marker",
            crate::project::DiscoverySource::CwdFallback => "cwd_fallback",
        },
        "starting_cwd": pr.starting_cwd.display().to_string(),
        "env_var": match &pr.env_var_value {
            Some(v) => serde_json::json!({
                "value": v,
                "active": pr.source == crate::project::DiscoverySource::EnvVar,
            }),
            None => serde_json::Value::Null,
        },
    });

    // Install root.
    out["install_root"] = match crate::project::install_root() {
        Some(install) => {
            let (source_tag, project_name) = match &install.source {
                crate::project::InstallDiscoverySource::EnvVar => ("env_var", None),
                crate::project::InstallDiscoverySource::WorkspaceMember { project_name } => {
                    ("workspace_member", Some(project_name.clone()))
                }
                crate::project::InstallDiscoverySource::ExePrefixShare => {
                    ("exe_prefix_share", None)
                }
                crate::project::InstallDiscoverySource::ExePrefixFlat => ("exe_prefix_flat", None),
            };
            let mut entry = serde_json::json!({
                "path": install.path.display().to_string(),
                "source": source_tag,
                "same_as_project": install.path == pr.path,
            });
            if let Some(name) = project_name {
                entry["workspace_project"] = serde_json::Value::String(name);
            }
            entry
        }
        None => serde_json::Value::Null,
    };

    // Targets — merged project + install view with per-entry
    // source annotation. Mirrors the text output's dual-root
    // semantics. Each entry carries `source` ∈ {"project",
    // "install", "project+install"} (last value = present in
    // both, project wins). Stable v1 shape.
    let install_root_for_json = crate::project::install_root();
    let install_path_for_json = install_root_for_json
        .as_ref()
        .map(|i| i.path.clone())
        .filter(|p| *p != pr.path);
    let project_target_names = target::list_targets_under(&pr.path);
    let install_target_names: Vec<String> = install_path_for_json
        .as_deref()
        .map(target::list_targets_under)
        .unwrap_or_default();
    let mut targets_arr = Vec::new();
    use std::collections::BTreeMap;
    let mut tgt_by_name: BTreeMap<String, (bool, bool)> = BTreeMap::new();
    for n in &project_target_names {
        tgt_by_name.entry(n.clone()).or_default().0 = true;
    }
    for n in &install_target_names {
        tgt_by_name.entry(n.clone()).or_default().1 = true;
    }
    for (name, (in_project, in_install)) in &tgt_by_name {
        let source = match (in_project, in_install) {
            (true, true) => "project+install",
            (true, false) => "project",
            (false, true) => "install",
            (false, false) => "unknown",
        };
        let entry = match target::load_target(name, &pr.path) {
            Ok(desc) => {
                let kind = if desc.board_id.is_some() {
                    "board"
                } else if desc.is_host() {
                    "host"
                } else if desc.build.is_some() {
                    "silicon"
                } else {
                    "validation"
                };
                serde_json::json!({
                    "name": name,
                    "kind": kind,
                    "description": desc.description,
                    "source": source,
                })
            }
            Err(e) => serde_json::json!({
                "name": name,
                "kind": "error",
                "description": e.to_string(),
                "source": source,
            }),
        };
        targets_arr.push(entry);
    }
    out["targets"] = serde_json::Value::Array(targets_arr);

    // Stacks — same dual-root pattern. v1 shape change: stacks
    // is now an array of objects `{"name", "source"}` instead of
    // an array of name strings. Tooling consumers that ignore
    // extra fields keep working; the source annotation is new.
    let project_stack_names = stack_expand::list_available_stack_names(&pr.path);
    let install_stack_names: Vec<String> = install_path_for_json
        .as_deref()
        .map(stack_expand::list_available_stack_names)
        .unwrap_or_default();
    let mut stk_by_name: BTreeMap<String, (bool, bool)> = BTreeMap::new();
    for n in &project_stack_names {
        stk_by_name.entry(n.clone()).or_default().0 = true;
    }
    for n in &install_stack_names {
        stk_by_name.entry(n.clone()).or_default().1 = true;
    }
    let stacks: Vec<serde_json::Value> = stk_by_name
        .iter()
        .map(|(name, (in_project, in_install))| {
            let source = match (in_project, in_install) {
                (true, true) => "project+install",
                (true, false) => "project",
                (false, true) => "install",
                (false, false) => "unknown",
            };
            serde_json::json!({ "name": name, "source": source })
        })
        .collect();
    out["stacks"] = serde_json::json!(stacks);

    // Rig.
    let lab_env = std::env::var("FLUXOR_LAB").ok();
    let active_lab = lab_env.clone().unwrap_or_else(|| "default".to_string());
    let labs = crate::rig::enumerate_labs().unwrap_or_default();
    let rigs = crate::rig::enumerate_rigs(&active_lab).unwrap_or_default();
    let rigs_json: Vec<serde_json::Value> = rigs
        .iter()
        .map(|r| {
            let path =
                crate::rig::default_profile_path(&active_lab, r).map(|p| p.display().to_string());
            serde_json::json!({ "name": r, "profile_path": path })
        })
        .collect();
    out["rig"] = serde_json::json!({
        "active_lab": active_lab,
        "lab_env_set": lab_env.is_some(),
        "available_labs": labs,
        "rigs": rigs_json,
    });

    // Scenarios.
    let scenario_dirs = [
        pr.path.join("examples"),
        pr.path.join("examples/test_harness"),
        pr.path.join("tests/hardware"),
    ];
    let mut scanned: Vec<String> = Vec::new();
    let mut found_pairs: Vec<(PathBuf, String)> = Vec::new();
    let mut errors: Vec<serde_json::Value> = Vec::new();
    for dir in &scenario_dirs {
        if !dir.is_dir() {
            continue;
        }
        scanned.push(dir.display().to_string());
        match scenario::list_scenarios(dir) {
            Ok(rows) => found_pairs.extend(rows),
            Err(e) => errors.push(serde_json::json!({
                "dir": dir.display().to_string(),
                "message": e.to_string(),
            })),
        }
    }
    // Dedupe by canonical path.
    let mut seen: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
    found_pairs.retain(|(p, _)| {
        let key = p.canonicalize().unwrap_or_else(|_| p.clone());
        seen.insert(key)
    });
    found_pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let found_arr: Vec<serde_json::Value> = found_pairs
        .iter()
        .map(|(path, name)| {
            let rel = path
                .strip_prefix(&pr.path)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| path.display().to_string());
            serde_json::json!({
                "path": path.display().to_string(),
                "relative_path": rel,
                "name": name,
            })
        })
        .collect();
    out["scenarios"] = serde_json::json!({
        "scanned_dirs": scanned,
        "found": found_arr,
        "errors": errors,
    });

    // Optional per-config block.
    if let Some(cfg_path) = config_path {
        out["config"] = config_inspection_json(cfg_path, &pr.path);
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&out)
            .map_err(|e| error::Error::Config(format!("inspect json: {e}")))?
    );
    Ok(())
}

/// Build the JSON sub-object for the `config` block — mirrors the
/// human-text `Config:` rendering. Read-only; never mutates state.
fn config_inspection_json(config_path: &Path, project_root: &Path) -> serde_json::Value {
    let raw = match std::fs::read_to_string(config_path)
        .and_then(|s| substitute_env_vars(&s).map_err(|e| std::io::Error::other(e.to_string())))
    {
        Ok(s) => s,
        Err(e) => {
            return serde_json::json!({
                "path": config_path.display().to_string(),
                "error": format!("read: {e}"),
            })
        }
    };
    let parse_result: std::result::Result<serde_json::Value, String> = if config_path
        .extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&raw).map_err(|e| e.to_string())
    } else {
        serde_json::from_str(&raw).map_err(|e| e.to_string())
    };
    let parsed = match parse_result {
        Ok(v) => v,
        Err(e) => {
            return serde_json::json!({
                "path": config_path.display().to_string(),
                "error": format!("parse: {e}"),
            })
        }
    };

    let declared = parsed
        .get("target")
        .and_then(|v| v.as_str())
        .map(String::from);
    let resolved = match resolve_target(&parsed, None) {
        Ok(desc) => Some(serde_json::json!({
            "id": desc.id,
            "kind": if desc.board_id.is_some() {
                "board"
            } else if desc.is_host() {
                "host"
            } else if desc.build.is_some() {
                "silicon"
            } else {
                "validation"
            },
            "board_id": desc.board_id.as_ref(),
        })),
        Err(_) => None,
    };

    let mut probe = parsed.clone();
    let probe_yaml_dir = config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let _ = inline_route_body_files(&mut probe, &probe_yaml_dir);
    let expanded_stack_modules: Vec<String> = if let Ok(desc) = resolve_target(&parsed, None) {
        stack_expand::expand_platform_stacks(&mut probe, &desc, project_root).unwrap_or_default()
    } else {
        Vec::new()
    };

    let search_paths: Vec<String> = config::extract_module_search_paths(&probe, config_path)
        .iter()
        .map(|p| p.display().to_string())
        .collect();

    serde_json::json!({
        "path": config_path.display().to_string(),
        "declared_target": declared,
        "resolved_target": resolved,
        "expanded_stack_modules": expanded_stack_modules,
        "module_search_paths": search_paths,
    })
}

/// Aggregate scenario discovery across the conventional roots
/// (`examples/`, `examples/test_harness/`, `tests/hardware/`). Calls
/// `scenario::list_scenarios` per directory — it already filters for
/// `kind: scenario` files and graphs with inline `scenario:` blocks,
/// so this function just unions the results.
///
/// Output mirrors `fluxor run --list <dir>` but unified across the
/// well-known locations so the user sees the whole catalogue at a
/// glance. Paths are rendered relative to the project root so the
/// output stays terse on long absolute paths.
fn inspect_scenarios(project_root: &Path) {
    let candidate_dirs = [
        project_root.join("examples"),
        project_root.join("examples/test_harness"),
        project_root.join("tests/hardware"),
    ];

    println!("Scenarios");

    let mut findings: Vec<(PathBuf, String)> = Vec::new();
    let mut errors: Vec<(PathBuf, String)> = Vec::new();
    let mut scanned_dirs: Vec<PathBuf> = Vec::new();
    for dir in &candidate_dirs {
        if !dir.is_dir() {
            continue;
        }
        scanned_dirs.push(dir.clone());
        match scenario::list_scenarios(dir) {
            Ok(rows) => findings.extend(rows),
            Err(e) => errors.push((dir.clone(), e.to_string())),
        }
    }

    if scanned_dirs.is_empty() {
        println!(
            "  <no conventional scenario directories under {}>",
            project_root.display()
        );
        println!();
        return;
    }

    println!("  scanned:");
    for dir in &scanned_dirs {
        println!("    {}", dir.display());
    }

    // Dedupe by canonical path. `list_scenarios` already dedupes
    // within a directory; the cross-directory case fires when the
    // same scenario is symlinked, which is rare but worth handling
    // so the count is accurate.
    let mut seen: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
    findings.retain(|(p, _)| {
        let key = p.canonicalize().unwrap_or_else(|_| p.clone());
        seen.insert(key)
    });
    findings.sort_by(|a, b| a.0.cmp(&b.0));

    if findings.is_empty() {
        println!("  <no scenarios found>");
    } else {
        println!("  found:");
        for (path, name) in &findings {
            // Render path relative to project_root for terseness.
            let rel = path
                .strip_prefix(project_root)
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|_| path.clone());
            println!("    {:40} {}", rel.display(), name);
        }
    }
    for (dir, msg) in errors {
        println!("  warning: enumerating {}: {}", dir.display(), msg);
    }
    println!();
}

/// Render the `Targets` block with project + install merge and
/// per-entry source annotation. Mirrors the build path's
/// `target::load_target` fallback behaviour so an external
/// project with no local `targets/` still sees bundled targets
/// listed (with `[install]` annotation), and a project-side
/// override of a bundled name surfaces both copies — the project
/// one marked `[project, shadows install]` and the install one
/// marked `[install, shadowed]`.
///
/// `install_distinct` is `Some` only when an install root is
/// discovered AND distinct from the project root (running from
/// the fluxor source tree puts them at the same path, in which
/// case no source annotation adds signal).
fn print_inspect_targets_block(project_root: &Path, install_distinct: Option<&Path>) {
    let project_names = target::list_targets_under(project_root);
    let install_names: Vec<String> = install_distinct
        .map(target::list_targets_under)
        .unwrap_or_default();

    if project_names.is_empty() && install_names.is_empty() {
        println!("Targets");
        println!(
            "  <none — neither {} nor any install root has a targets/ dir>",
            project_root.display()
        );
        println!();
        return;
    }

    println!("Targets");
    println!(
        "  project root:         {}",
        project_root.join("targets").display()
    );
    if let Some(install) = install_distinct {
        println!(
            "  install root:         {}",
            install.join("targets").display()
        );
    }

    // Build a deduped name list with per-name source info.
    use std::collections::BTreeMap;
    let mut by_name: BTreeMap<String, (bool, bool)> = BTreeMap::new();
    for n in &project_names {
        by_name.entry(n.clone()).or_default().0 = true;
    }
    for n in &install_names {
        by_name.entry(n.clone()).or_default().1 = true;
    }

    if by_name.is_empty() {
        println!("  <no targets found in either root>");
    } else {
        for (name, (in_project, in_install)) in &by_name {
            // Resolve from project_root so the layered lookup
            // matches the build path. `load_target` consults the
            // install root on miss, so the description always
            // reflects the resolved descriptor.
            let desc_line = match target::load_target(name, project_root) {
                Ok(desc) => {
                    let kind = if desc.board_id.is_some() {
                        "board"
                    } else if desc.is_host() {
                        "host"
                    } else if desc.build.is_some() {
                        "silicon"
                    } else {
                        "validation"
                    };
                    format!("{kind:9}  {}", desc.description)
                }
                Err(_) => "<error loading>".to_string(),
            };
            let source_tag = match (install_distinct.is_some(), in_project, in_install) {
                // No install root → no annotation needed.
                (false, _, _) => String::new(),
                // Both → project shadows install.
                (true, true, true) => "  [project, shadows install]".to_string(),
                (true, true, false) => "  [project]".to_string(),
                (true, false, true) => "  [install]".to_string(),
                // BTreeMap entries always have at least one source.
                (true, false, false) => String::new(),
            };
            println!("  {name:20} {desc_line}{source_tag}");
        }
    }
    println!();
}

/// Render the `Stacks` block with the same dual-root merge as the
/// targets block. `load_stack` walks project then install; this
/// view reflects that.
fn print_inspect_stacks_block(project_root: &Path, install_distinct: Option<&Path>) {
    let project_names = stack_expand::list_available_stack_names(project_root);
    let install_names: Vec<String> = install_distinct
        .map(stack_expand::list_available_stack_names)
        .unwrap_or_default();

    if project_names.is_empty() && install_names.is_empty() {
        println!("Stacks");
        println!(
            "  <none — neither {} nor any install root has a stacks/ dir>",
            project_root.display()
        );
        println!();
        return;
    }

    println!("Stacks");
    println!(
        "  project root:         {}",
        project_root.join("stacks").display()
    );
    if let Some(install) = install_distinct {
        println!(
            "  install root:         {}",
            install.join("stacks").display()
        );
    }

    use std::collections::BTreeMap;
    let mut by_name: BTreeMap<String, (bool, bool)> = BTreeMap::new();
    for n in &project_names {
        by_name.entry(n.clone()).or_default().0 = true;
    }
    for n in &install_names {
        by_name.entry(n.clone()).or_default().1 = true;
    }
    if by_name.is_empty() {
        println!("  <no stacks found in either root>");
    } else {
        for (name, (in_project, in_install)) in &by_name {
            let source_tag = match (install_distinct.is_some(), in_project, in_install) {
                (false, _, _) => String::new(),
                (true, true, true) => "  [project, shadows install]".to_string(),
                (true, true, false) => "  [project]".to_string(),
                (true, false, true) => "  [install]".to_string(),
                (true, false, false) => String::new(),
            };
            println!("  {name}{source_tag}");
        }
    }
    println!();
}

fn inspect_rig_config() {
    println!("Rig configuration");

    // Active lab: $FLUXOR_LAB → "default". Same precedence
    // `rig::cli` uses to pick the lab namespace.
    let lab_env = std::env::var("FLUXOR_LAB").ok();
    let active_lab = lab_env.clone().unwrap_or_else(|| "default".to_string());
    println!("  active lab:           {active_lab}");
    match lab_env {
        Some(_) => println!("  $FLUXOR_LAB:          set"),
        None => println!("  $FLUXOR_LAB:          <unset> (defaulting to 'default')"),
    }

    // Available labs.
    let labs_root = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .map(|h| h.join(".config/fluxor/labs"));
    if let Some(ref dir) = labs_root {
        match crate::rig::enumerate_labs() {
            Ok(labs) if labs.is_empty() => {
                println!(
                    "  available labs:       <none configured under {}>",
                    dir.display()
                );
            }
            Ok(labs) => {
                println!("  available labs:");
                for lab in &labs {
                    let marker = if *lab == active_lab { " (active)" } else { "" };
                    println!("    {lab}{marker}");
                }
            }
            Err(e) => {
                println!("  available labs:       <error: {e}>");
            }
        }
    } else {
        println!("  available labs:       <$HOME unset; cannot enumerate>");
    }

    // Rigs in the active lab.
    match crate::rig::enumerate_rigs(&active_lab) {
        Ok(rigs) if rigs.is_empty() => {
            println!("  rigs in active lab:   <none>");
            if let Some(ref dir) = labs_root {
                println!(
                    "  (rig profiles live under {}/{}/rigs/<rig>.toml)",
                    dir.display(),
                    active_lab
                );
            }
        }
        Ok(rigs) => {
            println!("  rigs in active lab:");
            for r in &rigs {
                // Resolve each rig's profile path so the user knows
                // where the descriptor lives without grepping for
                // `default_profile_path`.
                let path = crate::rig::default_profile_path(&active_lab, r)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<$HOME unset>".into());
                println!("    {r:24} {path}");
            }
        }
        Err(e) => {
            println!("  rigs in active lab:   <error: {e}>");
        }
    }

    println!();
}

fn format_discovery_source(source: &crate::project::DiscoverySource) -> &'static str {
    match source {
        crate::project::DiscoverySource::EnvVar => "$FLUXOR_PROJECT_ROOT override",
        crate::project::DiscoverySource::DotFluxorMarker => ".fluxor marker file",
        crate::project::DiscoverySource::SourceTreeMarker => {
            "source-tree heuristic (targets/ + stacks/)"
        }
        crate::project::DiscoverySource::CwdFallback => "CWD fallback (no marker found)",
    }
}

fn format_install_source(source: &crate::project::InstallDiscoverySource) -> String {
    match source {
        crate::project::InstallDiscoverySource::EnvVar => "$FLUXOR_INSTALL_ROOT override".into(),
        crate::project::InstallDiscoverySource::WorkspaceMember { project_name } => {
            format!("workspace member `{project_name}`")
        }
        crate::project::InstallDiscoverySource::ExePrefixShare => {
            "exe-prefix `<prefix>/share/fluxor/`".into()
        }
        crate::project::InstallDiscoverySource::ExePrefixFlat => "exe-prefix `<prefix>/`".into(),
    }
}

fn inspect_config(config_path: &Path, project_root: &Path) -> Result<()> {
    // Wrap the read with explicit path context so a missing file
    // (the common typo case for `fluxor inspect`) surfaces as
    // "Cannot read config /path/foo.yaml: No such file…" rather
    // than the bare "No such file or directory" the IO error's
    // Display gives.
    let content = std::fs::read_to_string(config_path).map_err(|e| {
        error::Error::Config(format!("Cannot read config {}: {e}", config_path.display()))
    })?;
    let content = substitute_env_vars(&content)?;
    let raw: serde_json::Value = if config_path
        .extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&content).map_err(|e| {
            error::Error::Config(format!(
                "Cannot parse {} as YAML: {e}",
                config_path.display()
            ))
        })?
    } else {
        serde_json::from_str(&content).map_err(|e| {
            error::Error::Config(format!(
                "Cannot parse {} as JSON: {e}",
                config_path.display()
            ))
        })?
    };

    println!("Config: {}", config_path.display());

    let declared = raw
        .get("target")
        .and_then(|v| v.as_str())
        .unwrap_or("<not set>");
    println!("  declared target:      {declared}");

    // Resolve target. When `declared` names a board, the loader
    // walks the board → silicon link and returns the silicon
    // descriptor with `desc.id` = silicon id and `desc.board_id`
    // = the original board name. Display both so the user sees
    // exactly what the build resolved to.
    match resolve_target(&raw, None) {
        Ok(desc) => {
            if let Some(board_id) = &desc.board_id {
                println!("  resolved target:      {board_id} (board)");
                println!("  via board → silicon:  {}", desc.id);
            } else {
                let kind = if desc.build.is_some() {
                    "silicon"
                } else {
                    "validation"
                };
                println!("  resolved target:      {} ({})", desc.id, kind);
            }
        }
        Err(e) => {
            println!("  resolved target:      <error: {e}>");
        }
    }

    // Stack expansion preview. Cloning here so the inspection
    // doesn't mutate the original (in case future expansion does
    // more in place).
    let mut probe = raw.clone();
    if let Ok(desc) = resolve_target(&raw, None) {
        let mut probe_yaml_dir = config_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        if probe_yaml_dir.as_os_str().is_empty() {
            probe_yaml_dir = std::path::PathBuf::from(".");
        }
        let _ = inline_route_body_files(&mut probe, &probe_yaml_dir);
        match stack_expand::expand_platform_stacks(&mut probe, &desc, project_root) {
            Ok(added) if added.is_empty() => {
                println!("  expanded stacks:      <none added>");
            }
            Ok(added) => {
                println!("  expanded stacks:      {} module(s) added", added.len());
                for m in &added {
                    println!("    + {m}");
                }
            }
            Err(e) => {
                println!("  expanded stacks:      <error: {e}>");
            }
        }
    }

    // Manifest search paths.
    let search_paths = config::extract_module_search_paths(&probe, config_path);
    println!("  module search paths:");
    if search_paths.is_empty() {
        println!("    <none>");
    } else {
        for p in &search_paths {
            println!("    {}", p.display());
        }
    }

    Ok(())
}

/// Build a module table blob from .fmod files in a directory.
fn cmd_mktable(dir: &PathBuf, output: &PathBuf) -> Result<()> {
    use std::fs;

    let mut fmod_files: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("fmod") {
            fmod_files.push(path);
        }
    }
    fmod_files.sort();

    if fmod_files.is_empty() {
        return Err(Error::Module("No .fmod files found".into()));
    }

    let mut modules = Vec::new();
    for path in &fmod_files {
        let info = modules::ModuleInfo::from_file(path)?;
        modules.push(info);
    }

    let table = build_module_table(&modules)?;
    fs::write(output, &table)?;

    println!(
        "{} modules, {} bytes → {}",
        modules.len(),
        table.len(),
        output.display()
    );
    for m in &modules {
        println!("  {} ({} bytes)", m.name, m.data.len());
    }

    Ok(())
}

fn cmd_mktable_config(config_path: &Path, modules_dirs: &[PathBuf], output: &Path) -> Result<()> {
    let content = substitute_env_vars(&std::fs::read_to_string(config_path)?)?;
    let mut config: serde_json::Value = if config_path
        .extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&content)?
    } else {
        serde_json::from_str(&content)?
    };
    let yaml_dir = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    inline_route_body_files(&mut config, yaml_dir)?;

    // Apply platform-stack injection so configs using e.g.
    // `platform: storage: { media: nvme }` report the full injected
    // module set — matches the behaviour of `combine` / `validate`.
    let target_desc = resolve_target(&config, None)?;
    // Config-anchored root so a cross-cwd `fluxor run ../x.yaml` reads the
    // CONFIG's fluxor.lock pins (symmetric with the build/validate paths).
    let project_root = crate::project::root_for_config(config_path);
    stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;

    let primary_dir = if modules_dirs.is_empty() {
        return Err(Error::Module("--modules-dir is required".into()));
    } else {
        &modules_dirs[0]
    };
    let extra_dirs: Vec<&std::path::Path> =
        modules_dirs.iter().skip(1).map(|p| p.as_path()).collect();
    // Pins are SILICON-tagged, and for the linux host that silicon is not its
    // own id — it loads the aarch64 modules built for `bcm2712`. Filter to the
    // silicon the .fmods actually come from, else a store-composed provider
    // never resolves for a host `fluxor run`.
    let pin_silicon = target_desc.module_silicon();
    let store_fb = store_cli::lock_store_resolver(&project_root, pin_silicon, None);
    let modules = parse_modules_from_config_multi(
        &config,
        primary_dir,
        &extra_dirs,
        store_fb.as_deref().map(|f| f as _),
    )?;
    // All-builtin configs (e.g. linux_display + host_image_codec) leave
    // `modules` empty; emit a valid 16-byte header-only table so the
    // host loader sees module_count=0 and instantiates only built-ins.
    let table = build_module_table(&modules)?;
    std::fs::write(output, &table)?;

    println!(
        "{} modules from {} → {}",
        modules.len(),
        config_path.display(),
        output.display()
    );
    for m in &modules {
        println!("  {} ({} bytes)", m.name, m.data.len());
    }

    Ok(())
}

fn cmd_diff(old_path: &PathBuf, new_path: &PathBuf, target_override: Option<&str>) -> Result<()> {
    let old_content = substitute_env_vars(&std::fs::read_to_string(old_path)?)?;
    let new_content = substitute_env_vars(&std::fs::read_to_string(new_path)?)?;

    let old_config: serde_json::Value = serde_yaml::from_str(&old_content)?;
    let new_config: serde_json::Value = serde_yaml::from_str(&new_content)?;

    let target_desc = resolve_target(&new_config, target_override)?;
    let modules_dir_path = format!("target/fluxor/{}/modules", target_desc.id);
    let modules_dir = std::path::Path::new(&modules_dir_path);

    let plan = reconfigure::compute_transition_plan(&old_config, &new_config, modules_dir);

    print!("{}", reconfigure::format_plan(&plan));

    Ok(())
}

// ── Build / Run / Flash ────────────────────────────────────────────────────

/// Result of a successful single-config build.
struct BuildResult {
    output_path: PathBuf,
    family: String,
    board_id: Option<String>,
}

/// Derive the output subdirectory from a YAML path relative to `examples/`.
/// e.g. `examples/led_patterns/pico2w.yaml` -> "pico2w", otherwise empty string.
fn subdir_from_path(yaml_path: &std::path::Path) -> String {
    // Walk components looking for "examples" then take the next component
    let components: Vec<_> = yaml_path.components().collect();
    for (i, c) in components.iter().enumerate() {
        if let std::path::Component::Normal(s) = c {
            if *s == "examples" {
                if let Some(std::path::Component::Normal(next)) = components.get(i + 1) {
                    // Only use as subdir if the YAML is deeper (not directly in examples/)
                    if i + 2 < components.len() {
                        return next.to_string_lossy().to_string();
                    }
                }
            }
        }
    }
    String::new()
}

/// Build a single YAML config into its output artifact.
fn build_one(
    yaml_path: &std::path::Path,
    output_override: Option<&std::path::Path>,
    verbose: bool,
) -> Result<BuildResult> {
    // Load and parse config
    let content = substitute_env_vars(&std::fs::read_to_string(yaml_path)?)?;
    let config: serde_json::Value = if yaml_path
        .extension()
        .is_some_and(|ext| ext == "yaml" || ext == "yml")
    {
        serde_yaml::from_str(&content)?
    } else {
        serde_json::from_str(&content)?
    };

    let mut config = config;
    let target_desc = resolve_target(&config, None)?;
    // Anchor to the config file's own location so a build/run works from any
    // cwd (a subdirectory, or outside the tree with an absolute config path),
    // while still honoring FLUXOR_PROJECT_ROOT.
    let project_root = crate::project::root_for_config(yaml_path);
    stack_expand::expand_platform_stacks(&mut config, &target_desc, &project_root)?;
    let family = target_desc.family.clone();
    let silicon_id = target_desc.id.clone();
    // Silicon the PIC modules come from — the target's own for firmware
    // families, `bcm2712` for the aarch64 linux host.
    let module_silicon = target_desc.module_silicon().to_string();
    let build_id = target_desc.build_id().to_string();
    let board_id = target_desc.board_id.clone();

    // Artifact layout:
    //   firmware  target/{build_id}/firmware.bin   (board-specific when cargo
    //                                               features differ per board)
    //   modules   target/fluxor/{silicon_id}/modules/  (byte-identical per
    //                                               silicon + module target)
    //   output    target/{build_id}/{images|uf2}/<subdir>/<name>.{img|uf2}
    let firmware_path = PathBuf::from(format!("target/{build_id}/firmware.bin"));
    let modules_dir = PathBuf::from(format!("target/fluxor/{silicon_id}/modules"));

    let name = yaml_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let subdir = subdir_from_path(yaml_path);

    let output_path = if let Some(o) = output_override {
        o.to_path_buf()
    } else {
        match family.as_str() {
            "rp2" => {
                let mut p = PathBuf::from(format!("target/{build_id}/uf2"));
                if !subdir.is_empty() {
                    p.push(&subdir);
                }
                p.push(format!("{name}.uf2"));
                p
            }
            "bcm" => {
                let mut p = PathBuf::from(format!("target/{build_id}/images"));
                if !subdir.is_empty() {
                    p.push(&subdir);
                }
                p.push(format!("{name}.img"));
                p
            }
            "linux" => {
                let mut p = PathBuf::from(format!("target/linux/{name}"));
                // Linux produces two files; the "output_path" is the directory
                p.push("config.bin");
                p
            }
            "wasm" => {
                let mut p = PathBuf::from(format!("target/{build_id}/wasm"));
                if !subdir.is_empty() {
                    p.push(&subdir);
                }
                p.push(format!("{name}.wasm"));
                p
            }
            _ => {
                return Err(Error::Config(format!(
                    "Unsupported target family '{family}' for build"
                )));
            }
        }
    };

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    match family.as_str() {
        "rp2" | "bcm" => {
            if !firmware_path.exists() {
                let abs = firmware_path.canonicalize().unwrap_or_else(|_| {
                    std::env::current_dir()
                        .unwrap_or_default()
                        .join(&firmware_path)
                });
                return Err(Error::Config(format!(
                    "Firmware not found at {} (resolved to {}). Run 'make firmware TARGET={}' from the \
                     project root (`fluxor inspect` shows where that is) to produce it.",
                    firmware_path.display(),
                    abs.display(),
                    build_id
                )));
            }
            if !modules_dir.exists() {
                let abs = modules_dir.canonicalize().unwrap_or_else(|_| {
                    std::env::current_dir()
                        .unwrap_or_default()
                        .join(&modules_dir)
                });
                return Err(Error::Config(format!(
                    "Modules not found at {} (resolved to {}). Run 'fluxor modules build --target {}' from the \
                     project root (`fluxor inspect` shows where that is) to produce them.",
                    modules_dir.display(),
                    abs.display(),
                    build_id
                )));
            }
            cmd_combine(
                &firmware_path,
                &yaml_path.to_path_buf(),
                &output_path,
                verbose,
            )?;
        }
        "linux" => {
            let out_dir = output_path
                .parent()
                .unwrap_or(std::path::Path::new("target/linux"));
            std::fs::create_dir_all(out_dir)?;

            let config_bin_path = out_dir.join("config.bin");
            let modules_bin_path = out_dir.join("modules.bin");

            // The host loads whichever silicon's PIC modules the descriptor
            // names (`module_silicon`, bcm2712 for the aarch64 host). Anchor to
            // the resolved project root (not the caller's cwd) so `fluxor run
            // <path>` finds them regardless of where it is invoked from — a bare
            // `fluxor run examples/hello/linux.yaml` from a subdirectory must
            // resolve the same modules as from the repo root. When fluxor is
            // consumed as a submodule, accept a sibling copy under
            // ../deps/fluxor/target/fluxor/<silicon>/modules.
            let modules_rel = format!("target/fluxor/{module_silicon}/modules");
            let modules_dir = project_root.join(&modules_rel);
            let mut fmod_dirs: Vec<PathBuf> = Vec::new();
            if modules_dir.exists() {
                fmod_dirs.push(modules_dir.clone());
            }
            if let Some(config_parent) = yaml_path.parent().and_then(|p| p.parent()) {
                let ext_modules = config_parent.join(format!("deps/fluxor/{modules_rel}"));
                if ext_modules.exists() {
                    fmod_dirs.push(ext_modules);
                }
            }
            if fmod_dirs.is_empty() {
                return Err(Error::Config(format!(
                    "Modules not found at {}. Run 'fluxor modules build --target {}' from the project \
                     root (`fluxor inspect` shows where that is) first.",
                    modules_dir.display(),
                    module_silicon
                )));
            }
            // Cross-check the YAML against the linux binary's
            // compiled-in features (host-image / host-window /
            // host-playback). A YAML that asks for a backend the
            // binary can't provide fails here with the matching
            // `cargo build` command in the error message.
            validate_linux_runtime_features(yaml_path)?;
            cmd_mktable_config(yaml_path, &fmod_dirs, &modules_bin_path)?;
            cmd_generate(
                yaml_path,
                Some(config_bin_path.as_path()),
                Some(modules_dir.as_path()),
                true,
            )?;
        }
        "wasm" => {
            // wasm produces one self-contained `.wasm` file: the
            // kernel `firmware.wasm` with its embedded modules-blob
            // and config-blob placeholders rewritten in-place. See
            // `docs/architecture/wasm_platform.md` and the
            // `wasm_bundle` module for the rewrite mechanics.
            let kernel_wasm_path = PathBuf::from(format!("target/{build_id}/firmware.wasm"));
            if !kernel_wasm_path.exists() {
                return Err(Error::Config(format!(
                    "Kernel wasm not found at {}. Run 'make firmware TARGET=wasm' first.",
                    kernel_wasm_path.display()
                )));
            }
            if !modules_dir.exists() {
                return Err(Error::Config(format!(
                    "Modules not found at {}. Run 'fluxor modules build --target wasm' first.",
                    modules_dir.display()
                )));
            }

            // Build modules.bin and config.bin in a workspace dir so
            // intermediate artifacts are inspectable but don't
            // pollute the final output path.
            let work_dir = output_path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from(format!("target/{build_id}/wasm")));
            std::fs::create_dir_all(&work_dir)?;
            let modules_bin_path = work_dir.join(format!("{name}.modules.bin"));
            let config_bin_path = work_dir.join(format!("{name}.config.bin"));

            let extra_dirs: Vec<PathBuf> = Vec::new();
            let fmod_dirs: Vec<PathBuf> = std::iter::once(modules_dir.clone())
                .chain(extra_dirs)
                .collect();
            cmd_mktable_config(yaml_path, &fmod_dirs, &modules_bin_path)?;
            cmd_generate(
                yaml_path,
                Some(config_bin_path.as_path()),
                Some(modules_dir.as_path()),
                true,
            )?;

            let kernel_bytes = std::fs::read(&kernel_wasm_path)?;
            let modules_bin = std::fs::read(&modules_bin_path)?;
            let config_bin = std::fs::read(&config_bin_path)?;
            let mut bundled = wasm_bundle::bundle(&kernel_bytes, &modules_bin, &config_bin)?;

            // Asset bank: bake graph-declared assets into the wasm via
            // a `fluxor.assets` custom section. Off when no `assets:`
            // block is present. Resolves paths relative to the graph
            // YAML's directory so demos can use `../../assets/foo.png`.
            let assets = extract_asset_pairs(&config, yaml_path)?;
            let asset_count = assets.len();
            let entries = asset_bank::load_assets(&assets)?;
            let asset_bytes: usize = entries.iter().map(|e| e.bytes.len()).sum();
            asset_bank::append_asset_bank(&mut bundled, &entries)?;

            std::fs::write(&output_path, &bundled)?;

            if verbose {
                eprintln!(
                    "wasm bundle: {} bytes (modules={} config={} assets={}/{} bytes)",
                    bundled.len(),
                    modules_bin.len(),
                    config_bin.len(),
                    asset_count,
                    asset_bytes,
                );
            }
        }
        _ => {
            return Err(Error::Config(format!(
                "Unsupported target family '{family}' for build"
            )));
        }
    }

    Ok(BuildResult {
        output_path,
        family,
        board_id,
    })
}

/// Pull `assets:` out of a graph YAML and return resolved `(name, path)`
/// pairs the asset-bank builder can consume. Two shapes are accepted:
///
/// 1. Bare string — `assets: [examples/test_harness/assets/spiral.png, ...]`.
///    The asset's logical name is the basename. Paths resolve
///    relative to the graph YAML's directory.
/// 2. Per-entry map — `assets: [{ path: ..., name: spiral.png }, ...]`.
///    Explicit name override is useful when two folders ship files
///    with the same basename.
///
/// Returns an empty vec when the YAML has no `assets:` field. Errors
/// on schema mismatch or a relative-path traversal trying to escape
/// the workspace via excessive `..` segments.
fn extract_asset_pairs(
    config: &serde_json::Value,
    yaml_path: &std::path::Path,
) -> Result<Vec<(String, PathBuf)>> {
    let Some(arr) = config.get("assets").and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };

    let base_dir = yaml_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    let mut out = Vec::with_capacity(arr.len());
    for (i, entry) in arr.iter().enumerate() {
        let (raw_path, override_name) = match entry {
            serde_json::Value::String(s) => (s.clone(), None),
            serde_json::Value::Object(m) => {
                let p = m
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        Error::Config(format!(
                            "graph `{}`: assets[{}] missing `path:` field",
                            yaml_path.display(),
                            i
                        ))
                    })?
                    .to_string();
                let n = m
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                (p, n)
            }
            _ => {
                return Err(Error::Config(format!(
                    "graph `{}`: assets[{}] must be a string or a map with `path:`",
                    yaml_path.display(),
                    i
                )));
            }
        };

        let resolved = base_dir.join(&raw_path);
        let name = override_name.unwrap_or_else(|| {
            std::path::Path::new(&raw_path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(&raw_path)
                .to_string()
        });
        out.push((name, resolved));
    }
    Ok(out)
}

