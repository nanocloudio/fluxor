/// Generate binary config in FXWR format (version 1)
///
/// Layout:
/// - Header (8 bytes): magic (u32), version (u16), checksum (u16)
/// - Counts (8 bytes): module_count, edge_count, reserved[6]
/// - Module section header (6 bytes): module_count, reserved, section_size (u32)
/// - Module entries (variable length each)
/// - Graph section (64 bytes): edge_count, flags, reserved[2], edges[15]
/// - Hardware section: spi_count, i2c_count, gpio_count, reserved, configs...
///
/// Module capability info for buffer aliasing and manifest validation.
pub struct ModuleCaps {
    pub name: String,
    /// Can safely consume from mailbox channels (header flags bit 0)
    pub mailbox_safe: bool,
    /// Uses buffer_acquire_inplace to modify buffer (header flags bit 1)
    pub in_place_writer: bool,
    pub manifest: crate::manifest::Manifest,
}

/// Generate config with extra module search directories (for external projects).
///
/// `resolved_target` is the silicon-or-board id chosen by the CLI's
/// `--target` flag (or the default), already resolved by the caller via
/// `target::load_target`. When `Some`, it overrides any literal
/// `target:` field in the YAML config — that's what makes the
/// `[requires]` hardware-capability check honour the actual build
/// target rather than a stale YAML default. `None` means fall back to
/// the YAML's literal value, which is the documented opt-in behaviour
/// for legacy configs / fixtures with no declared target.
#[expect(
    clippy::too_many_arguments,
    reason = "ABI-shaped function; argument list mirrors the syscall / register signature"
)]
pub fn generate_config_ext(
    config: &Value,
    _template: &ConfigBuilder,
    module_caps: &[ModuleCaps],
    modules_dir: &Path,
    extra_module_dirs: &[&Path],
    max_gpio: u8,
    pio_count: u8,
    resolved_target: Option<&str>,
    project_root: &Path,
) -> Result<Vec<u8>> {
    generate_config_impl(
        config,
        _template,
        module_caps,
        modules_dir,
        extra_module_dirs,
        max_gpio,
        pio_count,
        resolved_target,
        project_root,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "ABI-shaped function; argument list mirrors the syscall / register signature"
)]
fn generate_config_impl(
    config: &Value,
    _template: &ConfigBuilder,
    module_caps: &[ModuleCaps],
    modules_dir: &Path,
    extra_module_dirs: &[&Path],
    max_gpio: u8,
    pio_count: u8,
    resolved_target: Option<&str>,
    project_root: &Path,
) -> Result<Vec<u8>> {
    let modules = config
        .get("modules")
        .ok_or_else(|| Error::Config("modules section required".into()))?;

    // Parse graph-level sample_rate (top-level or under graph: key)
    let graph_sample_rate: u32 = config
        .get("sample_rate")
        .or_else(|| config.get("graph").and_then(|g| g.get("sample_rate")))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    // Parse tick_us (top-level or under execution:)
    let tick_us: u16 = config
        .get("tick_us")
        .or_else(|| config.get("execution").and_then(|e| e.get("tick_us")))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u16;

    // Validate tick_us range.
    //
    // The floor is a config-authoring bound, not a kernel limit — the kernel's
    // protection is the per-module `step_deadline_us` guard, which is
    // independent of tick period. It sits at 20 to leave room for
    // latency-bound graphs: on a pipelined chain the tick is the unit of
    // latency, since a request crosses one module boundary per tick wherever
    // the consumer's scheduler slot precedes the producer's, and burst does
    // not recover it (it re-steps the same module rather than advancing to
    // the next).
    //
    // 20 is permitted, not recommended. Per-tick module work scales with
    // concurrent session count — modules that iterate every session per step
    // cost an order of magnitude more at high concurrency than at one
    // connection — so a tick sized on a single-connection measurement will
    // exceed its budget under load, and it does so with every drop counter at
    // zero. Size the tick against peak-concurrency per-tick work. Where
    // latency and concurrency genuinely conflict, adaptive tick
    // (`tick_min_us`/`tick_max_us`) is the mechanism, not a smaller fixed one.
    if tick_us > 0 && !(20..=50000).contains(&tick_us) {
        return Err(Error::Config(format!(
            "tick_us {tick_us} out of range (valid: 20-50000, or 0 for default 1000)"
        )));
    }

    // Parse execution.domains. Hard-reject if the list exceeds
    // the kernel's `MAX_DOMAINS = 4` ceiling. The config writer
    // serialises exactly 4 domain-metadata entries
    // (`domain metadata: 4 entries × …` in the graph section), so
    // a 5th declared domain would either be silently dropped on
    // the wire OR (worse) a module assigned to it would resolve
    // to a domain id the kernel can't address (`domain_count`
    // clamps to 4 in `prepare_graph`). Reject at source so the
    // user sees a single clear error rather than odd runtime
    // behaviour.
    let mut domain_names: Vec<String> = Vec::new();
    let mut domain_tick_us: Vec<u16> = Vec::new();
    if let Some(exec) = config.get("execution") {
        if let Some(domains) = exec.get("domains").and_then(|d| d.as_array()) {
            if domains.len() > MAX_DOMAINS {
                return Err(Error::Config(format!(
                    "execution.domains has {} entries; the kernel supports at most {} \
                     (MAX_DOMAINS — one per physical or logical scheduling partition). \
                     Drop the extras or merge their modules into existing domains.",
                    domains.len(),
                    MAX_DOMAINS
                )));
            }
            for domain in domains {
                let name = domain
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("default");
                domain_names.push(name.to_string());
                let dtick = domain.get("tick_us").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                domain_tick_us.push(dtick);
            }
        }
    }
    // Domain count is inferred by the kernel from module domain_id assignments.
    // domain_names is still used for edge_class validation below.

    // Warn if tick_us < 500 with many modules
    let module_list = modules
        .as_array()
        .ok_or_else(|| Error::Config("modules must be a list".into()))?;
    if tick_us > 0 && tick_us < 500 && module_list.len() > 8 {
        eprintln!(
            "warning: tick_us={} with {} modules may exceed tick budget",
            tick_us,
            module_list.len()
        );
    }

    // Resident-pod modules (RFC adaptive_tick_extra §7) are admitted into REAL
    // execution domains and share their domain's runner, budget, and timing/ISR
    // constraints, so they must pass the SAME admission checks as base modules —
    // not a weaker pod-only path. Build an augmented list (base + every pod's
    // modules) and run the budget / ISR-tier / pre-tick / adaptive-timer-class /
    // hardware validators over it. The config-EMIT path is unchanged: base
    // entries from `modules`, pods from `build_pod_section`. With no `pods:` the
    // augmented list is the base list (byte-identical validation).
    // Pod module local names are scoped to their pod, so two pods (or a pod and
    // the base graph) may legitimately reuse a name. The manifest map
    // (`load_module_manifests_with_extra`) is keyed by `name` ALONE and silently
    // overwrites on collision — so a flat base+pod list could resolve a module to
    // the WRONG manifest (wrong ISR safety / timer class / hardware / pre_tick
    // metadata). Give every pod module a graph-scoped unique `name` for the
    // validation list while preserving its `type` (manifests resolve by type), so
    // each module is validated against its own manifest with no overwrite. This
    // is validation-only; the emit path (`build_pod_section`) is unaffected.
    let pod_modules: Vec<Value> = config
        .get("pods")
        .and_then(|p| p.as_array())
        .map(|pods| {
            pods.iter()
                .enumerate()
                .flat_map(|(pi, pod)| {
                    pod.get("modules")
                        .and_then(|m| m.as_array())
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .enumerate()
                        .map(move |(li, mut m)| {
                            if let Some(obj) = m.as_object_mut() {
                                // Give EVERY pod module an INDEX-based graph-scoped
                                // identity (`__pod{pi}__m{li}`), including `type`-only
                                // entries and duplicate local names. A name-derived
                                // identity would collide for two modules sharing a
                                // local name in one pod (and the manifest loader skips
                                // nameless modules), letting a tick-counted module
                                // dodge the timer-class gate. Index identities are
                                // unique by construction; `type` is preserved
                                // (manifests resolve by type). Duplicate local names
                                // are separately rejected in `build_pod_section`.
                                obj.insert(
                                    "name".to_string(),
                                    Value::String(format!("__pod{pi}__m{li}")),
                                );
                            }
                            m
                        })
                })
                .collect()
        })
        .unwrap_or_default();
    let validation_modules: Vec<Value> = if pod_modules.is_empty() {
        module_list.clone()
    } else {
        let mut v = module_list.clone();
        v.extend(pod_modules.iter().cloned());
        v
    };
    let validation_list: &[Value] = &validation_modules;

    // Fail closed on a pinned module whose `manifest.toml` can't be resolved
    // from the store, ahead of every gate below that reads the manifest map.
    // The map-building loader can only warn-and-omit, and an omitted manifest
    // is indistinguishable from "module has no manifest" — so without this
    // the pin's whole purpose (validating wiring against the surface the
    // pinned bytes ship) is silently skipped.
    crate::config::assert_pinned_manifests_resolvable(
        &Value::Array(validation_modules.clone()),
        resolved_target,
        project_root,
    )?;

    // Budget validation: prove step_deadlines, burst budgets, and
    // per-domain tick budgets fit together before the kernel ever
    // boots the graph. Until this lands, a config could declare
    // `step_deadline_us: 5000` on a module in a domain with
    // `tick_us: 1000` and the deadline would silently force every
    // step over budget — observable only as missed-deadline timeouts
    // at runtime.
    validate_scheduler_budgets(
        config,
        validation_list,
        tick_us,
        &domain_names,
        &domain_tick_us,
    )?;
    // NOTE: validate_adaptive_tick is deferred to AFTER the manifest map is
    // built (below) — its timer-class gate must consult the SAME resolver
    // (`load_module_manifests_with_extra`, incl. extra_module_dirs) the rest of
    // config-gen uses, or an external/project tick_counted module would fail
    // open on an adaptive domain.

    // ISR-tier admission: every module routed to a Tier 1b/2 domain
    // must declare `isr_safe = true` in its manifest, and the wiring
    // touching it cannot use an edge class incompatible with bridge
    // routing. The build-time gate is half of D6 — the runtime
    // routing in `channel_open` is the other half. See
    // `.context/rfc_isr_tier_surface.md` for the full contract.
    validate_isr_tier_admission(
        config,
        validation_list,
        modules_dir,
        extra_module_dirs,
        resolved_target,
        project_root,
    )?;

    // Tier 1c pre-pass drain admission: a module flagged
    // `pre_tick_drain = true` in its manifest is cooperative-only —
    // the kernel iterates pre-tick modules before the regular
    // `domain_exec_order` rotation, and the entry point still calls
    // through `step_one_module` which assumes cooperative context.
    // Placement in Tier 1b/2/3 domains is rejected here so the
    // misconfiguration surfaces at build time rather than as silent
    // misbehaviour at runtime. See `.context/rfc_isr_tier_surface.md`
    // §D8 for the contract.
    validate_pre_tick_drain_admission(config, validation_list, extra_module_dirs, project_root)?;

    // Inject graph sample_rate into modules that don't declare their own
    let modules_with_rate;
    let modules_ref = if graph_sample_rate > 0 {
        let mut list = module_list.clone();
        for m in &mut list {
            if m.get("sample_rate").is_none() {
                if let Some(obj) = m.as_object_mut() {
                    obj.insert("sample_rate".to_string(), json!(graph_sample_rate));
                }
            }
        }
        modules_with_rate = Value::Array(list);
        &modules_with_rate
    } else {
        modules
    };

    // Get data section for preset resolution
    let data_section = config.get("data");

    // Load manifests FIRST (via the rich resolver — standard module
    // dirs + project/install roots + caller-supplied extras) so that
    // `parse_modules_map` / `build_module_entry` can read per-module
    // flags like `pre_tick_drain` from the resolved manifest instead
    // of doing a second, narrower lookup that may miss modules
    // outside the hard-coded `Manifest::from_source_tree` search
    // list (e.g. modules in the install root or in extras).
    // Manifests for the AUGMENTED set (base + pod modules) so the adaptive
    // timer-class gate below resolves pod modules too; `parse_modules_map` (emit,
    // base-only) just ignores the extra pod entries keyed by type.
    let manifest_src = Value::Array(validation_modules.clone());
    let manifests = load_module_manifests_with_extra_for_target(
        &manifest_src,
        extra_module_dirs,
        resolved_target,
        project_root,
    );

    // Adaptive-tick validation (range/D8/D9/D10 + timer-class gate). Run here,
    // after the full manifest map exists, so the timer-class gate resolves
    // external/project modules via the same resolver (not the narrower
    // from_source_tree) — closing the fail-open for non-bundled modules.
    validate_adaptive_tick(
        config,
        validation_list,
        tick_us,
        &domain_names,
        &domain_tick_us,
        &manifests,
        extra_module_dirs,
        resolved_target,
    )?;

    let (module_entries, module_names) =
        parse_modules_map(modules_ref, data_section, config, modules_dir, &manifests)?;

    // Hardware-capability validation. Each module's `[requires]`
    // block declares what the silicon must provide (FPU / NEON /
    // MMU). Reject placement on a silicon that doesn't satisfy the
    // request BEFORE generating a binary that would silently
    // soft-float on RP2040 or fail to link NEON on Cortex-M.
    //
    // The CLI-resolved target wins over any literal `target:` in the
    // YAML — that's the contract that lets `--target` override a
    // checked-in default. Legacy fixtures without either omit the
    // check entirely; that's by design, since the default `requires`
    // is all-false and satisfies every silicon.
    // YAML `target:` carries a board or host token; capability lookup is
    // silicon-keyed, so resolve through the registry first. Falls back to
    // the raw token (which then fails closed in `for_silicon`) when the
    // registry doesn't know the name.
    let target_opt = resolved_target.or_else(|| config.get("target").and_then(|t| t.as_str()));
    let silicon_owned = target_opt.map(|t| {
        crate::target::load_target(t, &crate::project::root())
            .map(|d| d.module_silicon().to_string())
            .unwrap_or_else(|_| t.to_string())
    });
    if let Some(silicon) = silicon_owned.as_deref() {
        // Cover base AND pod modules — a pod module runs on the same silicon and
        // must satisfy the same `[requires]` (FPU/NEON/MMU).
        for (i, m) in validation_list.iter().enumerate() {
            let name = m
                .get("name")
                .and_then(|n| n.as_str())
                .or_else(|| m.get("type").and_then(|n| n.as_str()))
                .unwrap_or("?");
            if let Some(manifest) = manifests.get(name) {
                if let Err(e) =
                    crate::manifest::check_target_capabilities(manifest.requires, silicon)
                {
                    return Err(Error::Config(format!("modules[{i}] ({name}): {e}")));
                }
            }
        }
    }

    let (edges, force_flags, from_specs, to_specs) = if config.get("wiring").is_some() {
        parse_wiring_edges(&config["wiring"], &module_names, &manifests)?
    } else {
        return Err(Error::Config("wiring section required".into()));
    };

    // Validate content-type compatibility
    validate_wiring_types(
        &edges,
        &force_flags,
        &module_names,
        &manifests,
        &from_specs,
        &to_specs,
    )?;

    // Per-edge capacity + rate-class validation.
    {
        // `silicon_owned` is the registry-resolved silicon id (board
        // "pico2w" → silicon "rp2350"); the small-buffer-arena profile
        // is the rp2 family.
        let embedded = silicon_owned
            .as_deref()
            .map(|s| s == "rp2040" || s == "rp2350")
            .unwrap_or(false);
        validate_wiring_capacity(
            config,
            &edges,
            &module_names,
            &manifests,
            &from_specs,
            &to_specs,
            embedded,
        )?;
    }

    // Required-input-unwired detector. Manifests mark some input
    // ports `required: true` — those MUST have a wiring edge
    // connecting to them or the module will block on an empty
    // input ring at runtime with no diagnostic. Catching this at
    // build time turns a silent runtime stall into a loud
    // validate-time failure.
    validate_required_inputs_wired(&edges, &module_names, &manifests)?;

    // (Considered: warn on declared-but-never-wired modules. Real
    // bug class — refactor leftovers, typo'd wire references —
    // but the false-positive rate on legitimate standalone modules
    // (`debug`, monitor, alive heartbeat) is too high to justify
    // a default warning. Filed for revisit if a manifest-side
    // `standalone: true` opt-in lands so the check can be precise.)

    validate_presentation_groups(config, &module_names, &manifests)?;

    // Session continuity classes as a validated graph property
    // (rfc_protocols.md §7.3). Graphs without a `continuity` block are
    // unaffected.
    validate_continuity(config, &module_names, &manifests)?;

    // Presentation-shell / browser-overlay descriptor validation
    // (RFC browser_overlay §19). Scenarios without a `presentation.shell`
    // block are unaffected. Lives in a standalone, unit-testable module.
    crate::presentation_shell::validate(config, &module_names).map_err(Error::Config)?;

    if edges.len() > MAX_GRAPH_EDGES {
        return Err(Error::Config(format!(
            "Too many graph edges: {} > {}",
            edges.len(),
            MAX_GRAPH_EDGES
        )));
    }

    // Validate per-module port indices against `MAX_PORTS`. The
    // kernel's `populate_ports()` enforces the same bound at module
    // instantiation; catching it at build time gives a clear error
    // instead of a cryptic boot failure. Must equal
    // `src/kernel/scheduler.rs::MAX_PORTS`. The wire encoding
    // (`port_byte` is two 4-bit fields, indices 0..=15) is the
    // ultimate ceiling.
    const MAX_PORTS: u8 = 16;
    for &(from_id, to_id, _to_port, from_port_index, to_port_index) in &edges {
        if from_port_index >= MAX_PORTS {
            return Err(Error::Config(format!(
                "Module '{}' output port index {} exceeds limit (max {})",
                module_names[from_id as usize],
                from_port_index,
                MAX_PORTS - 1
            )));
        }
        if to_port_index >= MAX_PORTS {
            return Err(Error::Config(format!(
                "Module '{}' input port index {} exceeds limit (max {})",
                module_names[to_id as usize],
                to_port_index,
                MAX_PORTS - 1
            )));
        }
    }

    // Mirrors `kernel::config`'s version check. The format is latest-only
    // (kernel + tools ship together), so a stale blob is rejected by the
    // body-size/CRC check, not by a version number. Standing rule: never bump
    // format versions — it breaks every sibling consumer.
    let version: u16 = 1;

    let mut result = Vec::new();

    // Header (8 bytes): magic, version, checksum
    result.extend_from_slice(&MAGIC_LEGACY.to_le_bytes()); // "FXWR"
    result.extend_from_slice(&version.to_le_bytes());
    result.extend_from_slice(&0u16.to_le_bytes()); // checksum (computed later)

    // Counts (8 bytes): module_count(1), edge_count(1), tick_us(2), graph_sample_rate(4)
    result.push(module_entries.len() as u8); // module_count
    result.push(edges.len() as u8); // edge_count
    result.extend_from_slice(&tick_us.to_le_bytes()); // tick_us (u16, bytes 10-11)
    result.extend_from_slice(&graph_sample_rate.to_le_bytes()); // graph_sample_rate (u32, bytes 12-15)

    // Calculate total module section size
    let module_section_size: usize = module_entries.iter().map(|e| e.len()).sum();

    // Module section header (6 bytes). `section_size` is u32 so the
    // synth host can carry per-component embedded shells (~60 KiB
    // each) without overflowing — split scenarios that mount a
    // viewer/player alongside a producer easily sum to >64 KiB of
    // module data when both halves' http modules inline their
    // shells. Embedded targets (rp/bcm) still fit in u16 worth of
    // bytes in practice; the wider field costs 2 bytes per config.
    result.push(module_entries.len() as u8); // module_count
    result.push(0); // reserved
    result.extend_from_slice(&(module_section_size as u32).to_le_bytes()); // section_size

    // Module entries (variable length)
    for entry in &module_entries {
        result.extend_from_slice(entry);
    }

    // Validate manifests: check dependencies and resource conflicts
    if !module_caps.is_empty() {
        validate_manifests(&module_names, module_caps)?;
    }

    // Validate service dependencies from YAML `services:` section
    validate_services(config, &module_names, &manifests)?;

    // Assign buffer groups for aliasable edge chains, then apply
    // per-edge YAML overrides. The auto-assign pass only groups
    // edges where the destination is an in-place-safe chain interior
    // — it can't see "this edge needs mailbox semantics for transport
    // atomicity" (e.g. WsFrame envelopes between ws_stream and http).
    // A non-zero `buffer_group:` field on a wiring entry enables
    // mailbox mode on that channel (see
    // `src/kernel/scheduler/mod.rs::open_channels` — mailbox flag is
    // set when buffer_group != 0). Without this, the channel is a
    // byte-streaming FIFO and structured envelopes get fragmented.
    let mut buffer_groups = assign_buffer_groups(&edges, &module_names, module_caps)?;
    if let Some(wiring) = config.get("wiring").and_then(|w| w.as_array()) {
        for (i, entry) in wiring.iter().enumerate() {
            if let Some(g) = entry.get("buffer_group").and_then(|v| v.as_u64()) {
                if g > 0 && g <= 31 && i < buffer_groups.len() {
                    buffer_groups[i] = g as u8;
                }
            }
        }
    }

    // Resolve per-edge edge_class from wiring entries
    let edge_classes = resolve_edge_classes(config, &module_names, &domain_names)?;
    // Resolve per-edge rate classes for the binary edge entries —
    // the kernel's MODULE_FLOW_BUDGET query reads byte 8. Same
    // resolution the wiring-capacity validator applied.
    let edge_rate_classes: Vec<u8> = {
        let wiring_arr = config
            .get("wiring")
            .and_then(|w| w.as_array())
            .cloned()
            .unwrap_or_default();
        edges
            .iter()
            .enumerate()
            .map(|(i, &(from_id, to_id, to_port, from_pi, to_pi))| {
                let entry = wiring_arr.get(i);
                let from_port = module_names
                    .get(from_id as usize)
                    .and_then(|n| manifests.get(n))
                    .and_then(|m| m.find_port_spec(1, from_pi));
                let to_dir = if to_port == 1 { 2u8 } else { 0u8 };
                let to_spec = module_names
                    .get(to_id as usize)
                    .and_then(|n| manifests.get(n))
                    .and_then(|m| m.find_port_spec(to_dir, to_pi));
                resolve_edge_rate_class(entry, from_port, to_spec)
                    .map(|c| c as u8)
                    .unwrap_or(0)
            })
            .collect()
    };
    // Resolve per-edge `buffer_bytes` overrides from wiring entries.
    // Parallel array; entries default to 0 ("use module hints").
    let edge_buffer_bytes = resolve_edge_buffer_bytes(config);

    // Per-edge wake-on-write (`wake: true`, RFC idle_skip_wake):
    // channel_write on the flagged edge latches the consumer's
    // event-wake bit and rings the scheduler doorbell, cutting the idle
    // sleep short. Restricted to control/transaction rate classes as
    // the intent gate — a bulk or media stream waking the scheduler per
    // write would defeat demand-driven idle (the ENFORCED bound is the
    // woken-path domain budget; this gate keeps the intent visible at
    // config time).
    let edge_wake_flags: Vec<u8> = {
        let wiring_arr = config
            .get("wiring")
            .and_then(|w| w.as_array())
            .cloned()
            .unwrap_or_default();
        let mut flags = Vec::with_capacity(edges.len());
        for (i, _) in edges.iter().enumerate() {
            let wake = match wiring_arr.get(i).and_then(|e| e.get("wake")) {
                None => false,
                Some(v) => v.as_bool().ok_or_else(|| {
                    crate::error::Error::Config(format!(
                        "wiring[{i}]: `wake:` must be a boolean, got `{v}`"
                    ))
                })?,
            };
            if wake {
                let rc = edge_rate_classes.get(i).copied().unwrap_or(0);
                // 0 = control, 4 = transaction (byte-8 encoding above).
                if rc != 0 && rc != 4 {
                    return Err(crate::error::Error::Config(format!(
                        "wiring[{i}]: `wake: true` is only valid on control/transaction-class \
                         edges (resolved rate class {rc}) — a bulk/media stream waking the \
                         scheduler per write defeats demand-driven idle. Reclassify the edge \
                         (`rate:`) or drop the flag."
                    )));
                }
            }
            flags.push(wake as u8);
        }
        flags
    };

    // Graph section.
    //   header (4 bytes): edge_count, flags, reserved[2]
    //   edges  (MAX_GRAPH_EDGES * GRAPH_EDGE_SIZE bytes)
    //   domain metadata (DOMAIN_META_SIZE bytes)
    //
    // Edge format (GRAPH_EDGE_SIZE bytes; mirrors
    // `kernel::config::parse_graph_edge`):
    //   byte 0:    from_id
    //   byte 1:    to_id
    //   byte 2:    bit 7    = to_port
    //              bits 6:5 = edge_class (2 bits)
    //              bits 4:0 = buffer_group (5 bits, 0..31)
    //   byte 3:    bits 7:4 = from_port_index (4 bits, 0..15)
    //              bits 3:0 = to_port_index   (4 bits, 0..15)
    //   bytes 4-7: buffer_bytes (u32 LE; 0 = use module hints)
    //   byte 8:    rate_class (0=control, 1=audio, 2=video, 3=bulk, 4=transaction)
    //              — resolved at build time from the per-edge `rate:`
    //              override or the consumer/producer port's content-
    //              type default. Consumed by the kernel's
    //              MODULE_FLOW_BUDGET query.
    //   byte 9:    bit 0 = wake_on_write (`wake: true`, RFC idle_skip_wake
    //              — control/transaction classes only); bits 1-7 reserved
    //   bytes 10-11: reserved (0)
    //
    // Both ports get 4 bits; the runtime cap is `MAX_PORTS=16`. The
    // 5-bit `buffer_group` ceiling (31) is enforced by
    // `assign_buffer_groups`.
    // Graph section header layout — must agree with the parser at
    // `src/kernel/config.rs::read_config_at_into` (graph_flags read).
    //   byte 0: edge_count
    //   byte 1: graph_flags (bit 0 = ACCEPT_CYCLES; bits 1-7 reserved)
    //   bytes 2-3: reserved (must be 0)
    let accept_cycles = config
        .get("scheduler")
        .and_then(|s| s.get("accept_cycles"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let graph_flags: u8 = if accept_cycles { 0x01 } else { 0x00 };

    let mut graph_section = Vec::with_capacity(GRAPH_SECTION_SIZE);
    graph_section.push(edges.len() as u8);
    graph_section.push(graph_flags);
    graph_section.extend_from_slice(&[0u8; 2]);
    for (i, (from_id, to_id, to_port, from_port_index, to_port_index)) in edges.iter().enumerate() {
        let group = buffer_groups.get(i).copied().unwrap_or(0);
        let ec = edge_classes.get(i).copied().unwrap_or(0);
        let buffer_bytes = edge_buffer_bytes.get(i).copied().unwrap_or(0);
        graph_section.push(*from_id);
        graph_section.push(*to_id);
        graph_section.push((to_port << 7) | ((ec & 0x03) << 5) | (group & 0x1F));
        graph_section.push(((from_port_index & 0x0F) << 4) | (to_port_index & 0x0F));
        graph_section.extend_from_slice(&buffer_bytes.to_le_bytes());
        graph_section.push(edge_rate_classes.get(i).copied().unwrap_or(0));
        // byte 9: bit 0 = wake_on_write (RFC idle_skip_wake); bits 1-7
        // reserved. bytes 10-11 reserved.
        graph_section.push(edge_wake_flags.get(i).copied().unwrap_or(0) & 0x01);
        graph_section.extend_from_slice(&[0u8; 2]);
    }
    // Pad edge entries to fixed offset, then write domain metadata
    while graph_section.len() < 4 + MAX_GRAPH_EDGES * GRAPH_EDGE_SIZE {
        graph_section.push(0);
    }
    // Domain metadata: 4 entries × DOMAIN_META_ENTRY_SIZE (4) bytes:
    //   tick_us:u16 LE | exec_mode:u8 | adaptive_flags:u8
    // tick_min_us/tick_max_us are appended in the post-body adaptive section
    // AFTER the checksum (see below), NOT in this entry — growing the checksummed
    // body_size hangs the bare-metal Pi 5 boot.
    let domains_arr = config
        .get("execution")
        .and_then(|e| e.get("domains"))
        .and_then(|d| d.as_array());
    for d in 0..4usize {
        let dtick = domain_tick_us.get(d).copied().unwrap_or(0);
        let dom = domains_arr.and_then(|a| a.get(d));
        let mode = dom
            .map(|x| parse_domain_tier_to_exec_mode(x).unwrap_or(0))
            .unwrap_or(0);
        // Adaptive-tick per-domain config (RFC adaptive_tick §8), all optional.
        // 0 ⇒ adaptive off / "use tick_us" (the kernel parser default-fills
        // tick_min/tick_max to the domain's tick), so a domain that sets none
        // of these is byte-identical in behaviour to today's fixed tick.
        let flags = dom
            .and_then(|x| x.get("adaptive_flags"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8;
        let tmin = dom
            .and_then(|x| x.get("tick_min_us"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;
        let tmax = dom
            .and_then(|x| x.get("tick_max_us"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;
        let _ = (tmin, tmax); // not stored in the wire (4-byte entry, no growth)
        graph_section.extend_from_slice(&dtick.to_le_bytes());
        graph_section.push(mode);
        graph_section.push(flags); // adaptive_flags = byte 3 of the domain entry
    }
    while graph_section.len() < GRAPH_SECTION_SIZE {
        graph_section.push(0);
    }
    result.extend_from_slice(&graph_section);

    // Hardware section
    let hw_section =
        build_hardware_section(&config["hardware"], &module_names, max_gpio, pio_count)?;
    result.extend_from_slice(&hw_section);

    // Compute CRC16-CCITT checksum of body (bytes 8 onwards)
    let checksum = crc16_ccitt(&result[8..]);
    result[6..8].copy_from_slice(&checksum.to_le_bytes());

    // Adaptive-tick post-body section: 4 domains × [tick_min_us:u16 LE,
    // tick_max_us:u16 LE] = 16 bytes, appended AFTER the checksum so it sits
    // PAST body_size (the kernel reads it at total_size). Deliberately not in
    // body_size / not checksum-covered: growing body_size hangs the bare-metal
    // Pi 5 boot, but trailing bytes past it are harmless (both rig-proven).
    // Mirrors `kernel::config::ADAPTIVE_POST_SIZE`; default 0 ⇒ kernel uses the
    // domain tick (adaptive is a no-op when unconfigured).
    let adaptive_domains = config
        .get("execution")
        .and_then(|e| e.get("domains"))
        .and_then(|d| d.as_array());
    for d in 0..4usize {
        let dom = adaptive_domains.and_then(|a| a.get(d));
        let tmin = dom
            .and_then(|x| x.get("tick_min_us"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;
        let tmax = dom
            .and_then(|x| x.get("tick_max_us"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;
        result.extend_from_slice(&tmin.to_le_bytes());
        result.extend_from_slice(&tmax.to_le_bytes());
    }

    // Resident-pod section (RFC adaptive_tick_extra §7): each top-level `pods:`
    // entry becomes a self-contained `AddSubgraph` (FLXA) blob the kernel admits
    // at boot via `apply_add`. Appended right AFTER the 16-byte adaptive post-body
    // (so the kernel reads it at `total_size + ADAPTIVE_POST_SIZE`), also PAST the
    // checksummed body — same additive discipline, no format-version bump. Absent
    // `pods:` ⇒ empty ⇒ byte-identical single-graph config.
    let pod_section = build_pod_section(config, modules_dir, extra_module_dirs)?;
    result.extend_from_slice(&pod_section);

    Ok(result)
}

/// Build the resident-pod config section from the optional top-level `pods:`
/// list (RFC adaptive_tick_extra §7). Each pod is a self-contained subgraph:
/// modules referenced by `name_hash` (FNV-1a of type) with inline-TLV params (the
/// same `build_params_from_schema` packing base modules use), and optional
/// intra-pod `wiring:` (`from`/`to` by pod-local module name). Cross-pod edges
/// are not supported in v1 (strict isolation). Returns an empty Vec with no pods.
fn build_pod_section(
    config: &Value,
    modules_dir: &Path,
    extra_module_dirs: &[&Path],
) -> Result<Vec<u8>> {
    let Some(pods_yaml) = config.get("pods").and_then(|p| p.as_array()) else {
        return Ok(Vec::new());
    };
    if pods_yaml.is_empty() {
        return Ok(Vec::new());
    }
    let data_section = config.get("data");
    // Manifest search path for the pre_tick_drain check: mirror the validators'
    // resolution (extra_module_dirs first — they shadow bundled modules), then
    // `modules_dir` as a fallback so an external/project module is found and
    // checked rather than silently passing and losing its pre-tick semantics.
    let manifest_search: Vec<&Path> = {
        let mut v: Vec<&Path> = extra_module_dirs.to_vec();
        v.push(modules_dir);
        v
    };
    // Per-domain exec_mode (Tier) so pods can be rejected from ISR-tier domains.
    // The FLXA pod codec carries NO exec-mode / `isr_safe` / `pre_tick_drain`
    // metadata, and pod admission runs AFTER the platform registers ISR handlers
    // (bcm2712.rs) — so an ISR-tier pod would be admitted yet never dispatched
    // (the cooperative runner skips ISR domains) and a `pre_tick_drain` pod would
    // silently lose its pre-pass semantics. Reject both until the codec and
    // post-admission registration support them.
    let mut domain_exec_mode: [u8; 4] = [0; 4];
    if let Some(domains) = config
        .get("execution")
        .and_then(|e| e.get("domains"))
        .and_then(|d| d.as_array())
    {
        for (i, dom) in domains.iter().take(4).enumerate() {
            if let Some(m) = parse_domain_tier_to_exec_mode(dom) {
                domain_exec_mode[i] = m;
            }
        }
    }
    let mut pods = Vec::new();
    for (pi, pod_yaml) in pods_yaml.iter().enumerate() {
        let mods_yaml = pod_yaml
            .get("modules")
            .and_then(|m| m.as_array())
            .ok_or_else(|| Error::Config(format!("pod {pi}: missing `modules:` array")))?;
        // Deterministic pod_uid: 0xD0 marker + index (host composer / kernel both
        // treat the UID as opaque identity; uniqueness within the bundle suffices).
        let mut pod_uid = [0u8; 16];
        pod_uid[0] = 0xD0;
        pod_uid[1] = pi as u8;
        let mut name_to_local: HashMap<String, u8> = HashMap::new();
        let mut modules = Vec::new();
        for (li, m) in mods_yaml.iter().enumerate() {
            let mname = m
                .get("name")
                .and_then(|v| v.as_str())
                .or_else(|| m.get("type").and_then(|v| v.as_str()))
                .ok_or_else(|| {
                    Error::Config(format!("pod {pi} module {li}: needs a `name` or `type`"))
                })?;
            let mtype = m.get("type").and_then(|v| v.as_str()).unwrap_or(mname);
            // PIC-only: the FLXA pod codec admits modules via the loader by
            // name_hash; a built-in has no .fmod and apply_add cannot decode it.
            if crate::modules::is_builtin_module(mtype) {
                return Err(Error::Config(format!(
                    "pod {pi} module '{mtype}' is a kernel built-in; resident pods are PIC-only \
                     (no .fmod for apply_add to load). Use a PIC module, or place it in the base graph."
                )));
            }
            // Reject duplicate local names within a pod: `name_to_local` resolves
            // `wiring:` endpoints, so a silent overwrite would mis-wire edges to the
            // wrong module. Names must be unique per pod (a module's `name` defaults
            // to its `type`, so two same-type modules need explicit distinct names).
            if name_to_local.insert(mname.to_string(), li as u8).is_some() {
                return Err(Error::Config(format!(
                    "pod {pi}: duplicate module name '{mname}' — pod-local module names must be \
                     unique (they resolve `wiring:` endpoints). Give each module a distinct `name` \
                     (two modules of the same `type` default to the same name)."
                )));
            }
            let name_hash = crate::hash::fnv1a_hash(mtype.as_bytes());
            // Domain is a NAME resolved against execution.domains (same namespace
            // as base modules), so pod modules share their domain's runner/budget
            // and the admission validators resolve them identically.
            let domain_id = resolve_domain_id(m, config)?;
            // Reject ISR-tier (1b/2) pod placement — the codec cannot represent it
            // and the cooperative runner would never dispatch it.
            let exec_mode = *domain_exec_mode.get(domain_id as usize).unwrap_or(&0);
            if exec_mode == 2 || exec_mode == 4 {
                return Err(Error::Config(format!(
                    "pod {pi} module '{mtype}' targets an ISR-tier domain (tier 1b/2). Resident \
                     pods are cooperative-only in v1: the FLXA codec carries no ISR metadata and \
                     pod admission runs after ISR registration, so an ISR-tier pod would never \
                     execute. Place ISR-tier modules in the base graph."
                )));
            }
            // Reject `pre_tick_drain` pod modules — the codec drops the flag, so a
            // pod module would silently run as an ordinary cooperative module,
            // losing its Tier-1c pre-pass drain semantics.
            if let Some(root) = resolve_module_root(mtype, &manifest_search) {
                let mpath = root.join("manifest.toml");
                if mpath.exists() {
                    if let Ok(man) = Manifest::from_toml(&mpath) {
                        if man.pre_tick_drain {
                            return Err(Error::Config(format!(
                                "pod {pi} module '{mtype}' is a pre_tick_drain (Tier 1c) module, \
                                 which resident pods do not support in v1: the FLXA codec carries \
                                 no pre_tick_drain flag, so the module would silently run as an \
                                 ordinary cooperative module. Place pre_tick_drain modules in the \
                                 base graph."
                            )));
                        }
                    }
                }
            }
            // Inline-TLV params — identical packing to base modules, so the kernel
            // reads them via `params_ptr` exactly the same way.
            let params =
                if let Some(param_schema) = schema::load_schema_for_module(mtype, modules_dir)? {
                    let mut buf = vec![0u8; MAX_MODULE_PARAMS_SIZE];
                    let plen = schema::build_params_from_schema(
                        m,
                        &param_schema,
                        &mut buf,
                        0,
                        data_section,
                        mtype,
                    )
                    .map_err(Error::Config)?;
                    buf.truncate(plen);
                    buf
                } else {
                    Vec::new()
                };
            modules.push(crate::add_subgraph::PodModule {
                name_hash,
                domain_id,
                params,
            });
        }
        let mut edges = Vec::new();
        if let Some(wiring) = pod_yaml.get("wiring").and_then(|w| w.as_array()) {
            for (ei, e) in wiring.iter().enumerate() {
                let resolve = |key: &str| -> Result<u8> {
                    let n = e.get(key).and_then(|v| v.as_str()).ok_or_else(|| {
                        Error::Config(format!(
                            "pod {pi} wiring {ei}: `{key}` must be a module name"
                        ))
                    })?;
                    name_to_local.get(n).copied().ok_or_else(|| {
                        Error::Config(format!(
                            "pod {pi} wiring {ei}: unknown module `{n}` (cross-pod edges are not \
                             supported in v1 — pods are self-contained)"
                        ))
                    })
                };
                let from_local = resolve("from")?;
                let to_local = resolve("to")?;
                // Reject cross-domain pod edges (v1). On bcm2712 a cross-domain
                // edge needs the SPSC bridge provisioned at boot (base edges get
                // it before pod admission, bcm2712.rs); `apply_add` opens an
                // ordinary channel, so a cross-domain pod edge would silently lose
                // the bridge. Until pod admission provisions the bridge, require
                // intra-domain pod wiring on every target (self-contained pods).
                let from_dom = modules[from_local as usize].domain_id;
                let to_dom = modules[to_local as usize].domain_id;
                if from_dom != to_dom {
                    return Err(Error::Config(format!(
                        "pod {pi} wiring {ei}: cross-domain edge (domain {from_dom} → {to_dom}) is \
                         not supported — a cross-domain edge needs the SPSC bridge that pod \
                         admission does not yet provision (notably on bcm2712). Keep pod modules \
                         that are wired together in the same domain."
                    )));
                }
                edges.push(crate::add_subgraph::PodEdge {
                    from_local,
                    from_port: e.get("from_port").and_then(|v| v.as_u64()).unwrap_or(0) as u8,
                    to_local,
                    to_port: e.get("to_port").and_then(|v| v.as_u64()).unwrap_or(0) as u8,
                    buffer_bytes: e.get("buffer_bytes").and_then(|v| v.as_u64()).unwrap_or(0)
                        as u32,
                });
            }
        }
        let state_cap = pod_yaml
            .get("state_cap")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let buffer_cap = pod_yaml
            .get("buffer_cap")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        // §6.5 idle-safe attestation: the operator asserts (pod-level
        // `idle_safe: true`) that this pod is demand-driven and may be parked when
        // idle. Absent/false ⇒ fail-closed: the kernel relaxes it to the `tick_max`
        // backstop cadence rather than parking it.
        let idle_safe = pod_yaml
            .get("idle_safe")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        pods.push(crate::add_subgraph::Pod {
            pod_uid,
            state_cap,
            buffer_cap,
            modules,
            edges,
            idle_safe,
        });
    }
    crate::add_subgraph::encode_pod_section(&pods).map_err(Error::Config)
}

/// Assign buffer group IDs for aliasable edge chains.
///
/// Identifies linear chains of edges where intermediate modules are in-place-safe
/// (single data input, single data output, marked in_place_safe in .fmod header).
/// Edges in the same chain get the same non-zero group ID, enabling the scheduler
/// to alias them to the same channel buffer at runtime.
///
/// Returns a Vec of group IDs parallel to the edges slice. Group 0 = no aliasing.
fn assign_buffer_groups(
    edges: &[(u8, u8, u8, u8, u8)],
    module_names: &[String],
    module_caps: &[ModuleCaps],
) -> Result<Vec<u8>> {
    let n = edges.len();
    let mut groups = vec![0u8; n];

    // If no module caps provided, no aliasing possible
    if module_caps.is_empty() {
        return Ok(groups);
    }

    // Build lookups: module_name -> capability flags
    let is_chain_interior_capable = |module_id: u8| -> bool {
        let id = module_id as usize;
        if id >= module_names.len() {
            return false;
        }
        let name = &module_names[id];
        // Chain interior requires BOTH: can consume mailbox AND modifies in-place
        module_caps
            .iter()
            .any(|c| &c.name == name && c.mailbox_safe && c.in_place_writer)
    };

    // Count data edges per module (only data edges, to_port == 0)
    let num_modules = module_names.len();
    let mut data_in_count = vec![0u8; num_modules];
    let mut data_out_count = vec![0u8; num_modules];
    for (_, to_id, to_port, _, _) in edges {
        if *to_port == 0 {
            let idx = *to_id as usize;
            if idx < num_modules {
                data_in_count[idx] += 1;
            }
        }
        // All edges have an implicit "from out" so count from_id outputs
    }
    for (from_id, _, _, _, _) in edges {
        let idx = *from_id as usize;
        if idx < num_modules {
            data_out_count[idx] += 1;
        }
    }

    // Chain interior: 1-in, 1-out, mailbox_safe AND in_place_writer.
    // These modules read+write the same aliased buffer via acquire_inplace.
    let is_chain_interior = |module_id: u8| -> bool {
        let idx = module_id as usize;
        idx < num_modules
            && data_in_count[idx] == 1
            && data_out_count[idx] == 1
            && is_chain_interior_capable(module_id)
    };

    // Find the single data-out edge index for a module
    let find_out_edge = |module_id: u8| -> Option<usize> {
        edges
            .iter()
            .position(|(from_id, _, _, _, _)| *from_id == module_id)
    };

    let mut next_group: u8 = 1;

    // For each edge, if destination is a chain-interior module, try to form/extend a chain
    for i in 0..n {
        let (_, to_id, to_port, _, _) = edges[i];
        // Only consider data edges
        if to_port != 0 {
            continue;
        }
        // Destination must be in-place-safe with 1-in/1-out
        if !is_chain_interior(to_id) {
            continue;
        }

        // This edge feeds an in-place module. Find the output edge from that module.
        if let Some(out_idx) = find_out_edge(to_id) {
            // Both edges share a group so the in-place writer aliases
            // its input/output buffers. Group 0 means "no aliasing", so
            // 31 distinct chain ids are available before the 5-bit
            // `buffer_group` field is exhausted.
            let existing_group = if groups[i] != 0 {
                groups[i]
            } else if groups[out_idx] != 0 {
                groups[out_idx]
            } else {
                if next_group > 31 {
                    return Err(Error::Config(
                        "graph has more than 31 in-place chains; buffer_group field is 5 bits"
                            .into(),
                    ));
                }
                let g = next_group;
                next_group += 1;
                g
            };
            groups[i] = existing_group;
            groups[out_idx] = existing_group;
        }
    }

    // Propagate: if an edge has a group, and its destination is in-place-safe,
    // extend the group to the output edge (handles chains of 3+)
    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..n {
            if groups[i] == 0 {
                continue;
            }
            let (_, to_id, to_port, _, _) = edges[i];
            if to_port != 0 {
                continue;
            }
            if !is_chain_interior(to_id) {
                continue;
            }
            if let Some(out_idx) = find_out_edge(to_id) {
                if groups[out_idx] != groups[i] {
                    groups[out_idx] = groups[i];
                    changed = true;
                }
            }
        }
    }

    Ok(groups)
}

/// Validate module manifests: check dependencies and resource conflicts.
fn validate_manifests(module_names: &[String], module_caps: &[ModuleCaps]) -> Result<()> {
    use crate::hash::fnv1a_hash;

    // Build hash map and detect collisions
    let mut hash_to_name: std::collections::HashMap<u32, &str> = std::collections::HashMap::new();
    for name in module_names {
        let h = fnv1a_hash(name.as_bytes());
        if let Some(existing) = hash_to_name.get(&h) {
            return Err(Error::Config(format!(
                "FNV-1a hash collision: '{existing}' and '{name}' both hash to 0x{h:08x}",
            )));
        }
        hash_to_name.insert(h, name);
    }
    let available_hashes: std::collections::HashSet<u32> = hash_to_name.keys().copied().collect();

    // Check dependencies
    for cap in module_caps {
        for dep in &cap.manifest.dependencies {
            if !available_hashes.contains(&dep.name_hash) {
                return Err(Error::Config(format!(
                    "module '{}' requires dependency (hash 0x{:08x}) not present in config",
                    cap.name, dep.name_hash,
                )));
            }
        }
    }

    // Check exclusive resource conflicts (instance-aware).
    // Chain providers (access_mode 3) sit on top of exclusive providers via the
    // provider chain pattern (CHAIN_NEXT dispatch). They coexist with exclusive
    // providers and with each other on the same device class.
    // (device_class, instance, module_name)
    let mut exclusive_claims: Vec<(u8, u8, &str)> = Vec::new();
    for cap in module_caps {
        for res in &cap.manifest.resources {
            if res.access_mode == 2 {
                // exclusive — conflict when same class AND instances overlap
                // instances overlap when either is 0xFF (any) or they are equal
                if let Some((_, _, other)) = exclusive_claims.iter().find(|(c, inst, _)| {
                    *c == res.device_class
                        && (*inst == 0xFF || res.instance == 0xFF || *inst == res.instance)
                }) {
                    let inst_msg = if res.instance != 0xFF {
                        format!(" instance {}", res.instance)
                    } else {
                        String::new()
                    };
                    return Err(Error::Config(format!(
                        "resource conflict: both '{}' and '{}' claim exclusive access to device class 0x{:02x}{}",
                        other, cap.name, res.device_class, inst_msg,
                    )));
                }
                exclusive_claims.push((res.device_class, res.instance, &cap.name));
            }
            // access_mode 3 (chain) — no conflict check, chains stack on top
        }
    }

    Ok(())
}

/// Validate service dependencies declared in the YAML `services:` section.
///
/// Each entry maps a service name to a provider module name. Validation checks:
/// 1. The provider module exists in the config
/// 2. The provider module's manifest declares `provides` for that service
fn validate_services(
    config: &serde_json::Value,
    module_names: &[String],
    manifests: &std::collections::HashMap<String, crate::manifest::Manifest>,
) -> Result<()> {
    let services = match config.get("services") {
        Some(s) => s,
        None => return Ok(()), // no services section — skip validation
    };

    let services_map = match services.as_object() {
        Some(m) => m,
        None => {
            return Err(Error::Config(
                "services must be a mapping of service_name: provider_module".into(),
            ))
        }
    };

    for (service_name, provider_val) in services_map {
        let provider = provider_val.as_str().ok_or_else(|| {
            Error::Config(format!(
                "services.{service_name}: provider must be a string"
            ))
        })?;

        // Check provider module exists in config
        // Module names come from either name or type field — check by type too
        let provider_found = module_names.iter().any(|n| n == provider);
        if !provider_found {
            return Err(Error::Config(format!(
                "services.{service_name}: provider module '{provider}' not found in config modules",
            )));
        }

        // Check provider's manifest declares this service
        if let Some(manifest) = manifests.get(provider) {
            if !manifest.provides.iter().any(|p| p == service_name) {
                return Err(Error::Config(format!(
                    "services.{service_name}: module '{provider}' does not declare 'provides = [\"{service_name}\"]' in its manifest",
                )));
            }
        }
        // If no manifest found, skip the provides check (backward compat)
    }

    Ok(())
}

/// CRC16-CCITT calculation (matching C++ implementation)
fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

