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
/// for configs and fixtures that declare no target.
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
    if config.get("boot").is_some() {
        return Err(Error::Config(
            "`boot:` is not a graph key: a machine's rig behaviour (summary cadence, \
             uptime, fault and lockup probes) is not part of a graph's configuration"
                .into(),
        ));
    }

    // The module ABI `modules_dir` holds artefacts for, which tags the pins
    // consulted when a `.fmod` is absent from it. Stated here from the
    // target, never read off the directory: `--module-root` can name any
    // path. A graph naming no resolvable target consults no pins.
    let module_abi = resolved_target
        .or_else(|| config.get("target").and_then(|t| t.as_str()))
        .and_then(|t| crate::target::load_target(t, project_root).ok())
        .map(|d| d.module_abi().to_string())
        .unwrap_or_default();
    let loc = schema::ModuleLocation {
        dir: modules_dir,
        abi: &module_abi,
        project_root,
    };

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

    // Parse execution.domains. Hard-reject if the list exceeds the
    // kernel's `MAX_DOMAINS` ceiling: the config carries one domain record
    // per declared domain and the kernel refuses a config declaring more
    // than it has. Reject at source so the user sees the limit by name at
    // build rather than a refused boot.
    let mut domain_names: Vec<String> = Vec::new();
    let mut domain_tick_us: Vec<u16> = Vec::new();
    let mut domain_modes: Vec<boot_config::ExecMode> = Vec::new();
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
            // A `timer` domain's tick is its period, from `rate_hz`.
            for (domain, (label, exec)) in domains.iter().zip(parse_domain_execs(config)?) {
                let name = domain
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("default");
                domain_names.push(name.to_string());
                let dtick = if exec.mode == boot_config::ExecMode::Timer {
                    exec.timer_period_us
                } else {
                    let t = domain.get("tick_us").and_then(Value::as_u64).unwrap_or(0);
                    u16::try_from(t).map_err(|_| {
                        Error::Config(format!(
                            "execution.domains entry '{label}': tick_us {t} does not fit the \
                             domain record's u16"
                        ))
                    })?
                };
                domain_tick_us.push(dtick);
                domain_modes.push(exec.mode);
            }
        }
    }
    // Every module's domain is an index into `execution.domains`, or 0 when
    // it names none (`resolve_domain_id`), so the declared list (at least
    // one) is every domain the graph uses.

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

    // Resident-workload modules are admitted into REAL
    // execution domains and share their domain's loop, budget, and timing/ISR
    // constraints, so they must pass the SAME admission checks as node-graph modules —
    // not a weaker workload-only path. Build an augmented list (node graph + every workload's
    // modules) and run the budget / interrupt-mode / pre-pass / adaptive-timer-class /
    // hardware validators over it. The config-EMIT path is unchanged: base
    // entries from `modules`, workloads from `build_workload_section`. With no `workloads:` the
    // augmented list is the base list (byte-identical validation).
    // Workload module local names are scoped to their workload, so two workloads (or a workload and
    // the node graph) may legitimately reuse a name. The manifest map
    // (`load_module_manifests_with_extra`) is keyed by `name` ALONE and silently
    // overwrites on collision — so a flat base+workload list could resolve a module to
    // the WRONG manifest (wrong ISR safety / timer class / hardware / pre_pass
    // metadata). Give every workload module a graph-scoped unique `name` for the
    // validation list while preserving its `type` (manifests resolve by type), so
    // each module is validated against its own manifest with no overwrite. This
    // is validation-only; the emit path (`build_workload_section`) is unaffected.
    let workload_modules: Vec<Value> = config
        .get("workloads")
        .and_then(|p| p.as_array())
        .map(|workloads| {
            workloads
                .iter()
                .enumerate()
                .flat_map(|(pi, workload)| {
                    workload
                        .get("modules")
                        .and_then(|m| m.as_array())
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .enumerate()
                        .map(move |(li, mut m)| {
                            if let Some(obj) = m.as_object_mut() {
                                // Give EVERY workload module an INDEX-based graph-scoped
                                // identity (`__workload{pi}__m{li}`), including `type`-only
                                // entries and duplicate local names. A name-derived
                                // identity would collide for two modules sharing a
                                // local name in one workload (and the manifest loader skips
                                // nameless modules), letting a tick-counted module
                                // dodge the timer-class gate. Index identities are
                                // unique by construction; `type` is preserved
                                // (manifests resolve by type). Duplicate local names
                                // are separately rejected in `build_workload_section`.
                                obj.insert(
                                    "name".to_string(),
                                    Value::String(format!("__workload{pi}__m{li}")),
                                );
                            }
                            m
                        })
                })
                .collect()
        })
        .unwrap_or_default();
    let validation_modules: Vec<Value> = if workload_modules.is_empty() {
        module_list.clone()
    } else {
        let mut v = module_list.clone();
        v.extend(workload_modules.iter().cloned());
        v
    };
    let validation_list: &[Value] = &validation_modules;

    // Fail closed on a module whose manifest is found but rejected — a pin
    // the store cannot serve, or a `manifest.toml` that does not parse or
    // validate — ahead of every gate below that reads the manifest map. The
    // map-building loader can only warn-and-omit, and an omitted manifest is
    // indistinguishable from "module has no manifest": wiring would then
    // report the module as never found.
    crate::config::assert_module_manifests_resolvable(
        &Value::Array(validation_modules.clone()),
        extra_module_dirs,
        resolved_target,
        project_root,
    )?;

    // Budget validation: prove step_deadlines, burst budgets, and
    // per-domain tick budgets fit together before the kernel ever
    // boots the graph. Without this gate a config could declare
    // `step_deadline_us: 5000` on a module in a domain with
    // `tick_us: 1000`, and the deadline would silently force every
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

    // Interrupt-mode admission: every module routed to a `timer`/`irq` domain
    // must declare `interrupt_safe = true` in its manifest, and the wiring
    // touching it cannot use an edge class incompatible with bridge
    // routing. This build-time gate is one half of the contract; the
    // runtime routing in `channel_open` is the other.
    validate_interrupt_admission(
        config,
        validation_list,
        modules_dir,
        extra_module_dirs,
        resolved_target,
        project_root,
    )?;

    // Pre-pass admission: a module flagged
    // `pre_pass = true` in its manifest is cooperative-only —
    // the kernel iterates pre-pass modules before the regular
    // `domain_exec_order` rotation, and the entry point still calls
    // through `step_one_module` which assumes cooperative context.
    // Placement outside a `tick` domain is rejected here so the
    // misconfiguration surfaces at build time rather than as silent
    // misbehaviour at runtime.
    validate_pre_pass_admission(
        config,
        validation_list,
        extra_module_dirs,
        resolved_target,
        project_root,
    )?;

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

    // Load manifests FIRST (via the rich resolver — standard module
    // dirs + project/install roots + caller-supplied extras) so that
    // `parse_modules_map` / `build_module_entry` can read per-module
    // flags like `pre_pass` from the resolved manifest instead
    // of doing a second, narrower lookup that may miss modules
    // outside the hard-coded `Manifest::from_source_tree` search
    // list (e.g. modules in the install root or in extras).
    // Manifests for the AUGMENTED set (node graph + workload modules) so the adaptive
    // timer-class gate below resolves workload modules too; `parse_modules_map` (emit,
    // node-graph-only) just ignores the extra workload entries keyed by type.
    let manifest_src = Value::Array(validation_modules.clone());
    let mut manifests = load_module_manifests_with_extra_for_target(
        &manifest_src,
        extra_module_dirs,
        resolved_target,
        project_root,
    );
    bind_capability_facts(&validation_modules, &mut manifests, &|entry, param| {
        bound_param_value(entry, param, loc)
    })?;
    let manifests = manifests;

    // Send pools are sized from the graph: what each instance retains for
    // its consumers depends on who consumes it, which the wiring says.
    let modules_with_pools;
    let modules_ref = match (modules_ref.as_array(), config.get("wiring")) {
        (Some(list), Some(wiring)) => {
            let names: Vec<String> = list
                .iter()
                .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(str::to_string))
                .collect();
            // A wiring that does not parse is refused below, by name.
            match parse_wiring_edges(wiring, &names, &manifests) {
                Ok((edges, ..)) => {
                    let mut list = list.clone();
                    let default_of = |entry: &Value, param: &str| -> Option<u64> {
                        let name = entry.get("name").and_then(Value::as_str)?;
                        let mtype = entry.get("type").and_then(Value::as_str).unwrap_or(name);
                        let schema = schema::load_schema_for_entry(entry, mtype, loc).ok()??;
                        let p = schema.params.iter().find(|p| p.name == param)?;
                        Some(u64::from(p.default))
                    };
                    derive_send_pools(&mut list, &edges, &names, &manifests, &default_of)?;
                    modules_with_pools = Value::Array(list);
                    &modules_with_pools
                }
                Err(_) => modules_ref,
            }
        }
        _ => modules_ref,
    };

    // Get data section for preset resolution
    let data_section = config.get("data");

    // Adaptive-tick validation (range checks + timer-class gate). Run here,
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

    // Module-count ceiling for the target's kernel profile
    // (`capacity::kernel_max_modules`, read from the kernel's profile).
    // Configs with no resolved target build for the Linux profile.
    let max_modules = crate::capacity::kernel_max_modules(resolved_target.unwrap_or("linux"));
    // The edge ceiling follows the same profile (`capacity::kernel_max_edges`):
    // a static profile's compiled slot count, or the format's bound where the
    // graph section is laid out for the graph.
    let max_edges = crate::capacity::kernel_max_edges(resolved_target.unwrap_or("linux"));
    // The target's isolation facts: each module's protection tag carries the
    // level the target provides rather than what was asked, and a device
    // window the block the target resolves its name to.
    let isolation = resolved_target
        .and_then(|t| crate::target::load_target(t, project_root).ok())
        .map(|t| t.isolation)
        .unwrap_or_default();
    // Heap caps a `heap_per_demand` rule sizes need the graph's declared
    // demand, which is counted from every instance's packed params: the graph
    // is packed once under a counting plan, and the planned caps are written
    // over the placeholders it leaves (`apply_heap_plan`).
    let counting = HeapPlan::counting();
    let (mut module_entries, module_names) = parse_modules_map(
        modules_ref,
        data_section,
        config,
        loc,
        &manifests,
        max_modules,
        &isolation,
        &counting,
    )?;
    // YAML `target:` carries a board, silicon or host token; capabilities,
    // facts and placement are all properties of the RUNTIME it resolves to
    // (`crate::runtime_abi`). Falls back to the raw token (which then fails
    // closed in `for_runtime`) when the registry doesn't know the name.
    let target_opt = resolved_target.or_else(|| config.get("target").and_then(|t| t.as_str()));
    let target_desc =
        target_opt.and_then(|t| crate::target::load_target(t, &crate::project::root()).ok());
    let runtime_owned = target_opt.map(|t| {
        target_desc
            .as_ref()
            .map_or_else(|| t.to_string(), |d| d.runtime().to_string())
    });
    let (mut workloads, workload_demand, workload_heaps) =
        build_workloads_counted(config, loc, extra_module_dirs, runtime_owned.as_deref())?;
    let mut demand = base_demand(modules_ref, &module_entries, &module_names, &manifests, loc)?;
    refuse_restart_of_subscribers(modules_ref, &demand)?;
    demand.extend(workload_demand);
    let mut heaps = base_planned_heaps(modules_ref, &module_names, &manifests);
    heaps.extend(workload_heaps);
    let plan = heap_plan(resolved_target.unwrap_or("linux"), config, &demand);
    apply_heap_plan(&plan, &heaps, &mut module_entries, &mut workloads)?;
    let module_entries = module_entries;

    // Hardware-capability validation. Each module's `[requires]`
    // block declares what the runtime must provide (FPU / NEON /
    // MMU). Reject placement on a runtime that doesn't satisfy the
    // request BEFORE generating a binary that would silently
    // soft-float on RP2040 or fail to link NEON on Cortex-M.
    //
    // The CLI-resolved target wins over any literal `target:` in the
    // YAML — that's the contract that lets `--target` override a
    // checked-in default. A config with neither omits the check
    // entirely; that's by design, since the default `requires`
    // is all-false and satisfies every runtime.
    if let Some(runtime) = runtime_owned.as_deref() {
        // Cover base AND workload modules — a workload module runs on the same runtime and
        // must satisfy the same placement and `[requires]` (FPU/NEON/MMU).
        for (i, m) in validation_list.iter().enumerate() {
            let name = m
                .get("name")
                .and_then(|n| n.as_str())
                .or_else(|| m.get("type").and_then(|n| n.as_str()))
                .unwrap_or("?");
            // An identity key the target cannot sign with is refused here,
            // and a key file that cannot be read is too when the graph named
            // one: an instance whose identity is missing is not an instance
            // that will serve, and the composer is where that is cheapest to
            // hear.
            // A check without the key file (`params::checking`) cannot
            // classify a key it does not have; the build that has it does.
            // Only the embedded form is read here: a key named by a bare
            // path is the module's to read, and to refuse, at runtime.
            // A workload's modules are judged where its workload is built
            // (`build_workloads_counted`), against what serves a workload.
            if i < module_list.len() {
                let fs_served = fs_reachable(runtime, ProviderCaller::Node)
                    || manifests
                        .values()
                        .any(|mm| mm.provides.iter().any(|p| surface_contract(p) == "fs"));
                refuse_credential_forms(
                    m,
                    Some(runtime),
                    fs_served,
                    &format!("modules[{i}] ({name})"),
                )?;
            }
            if let Some(key_path) = m
                .get("key_file")
                .and_then(|v| v.as_str())
                .and_then(crate::trust_anchors::file_source)
                .filter(|p| check_stand_in(p, "key_file").is_none())
            {
                let der = crate::trust_anchors::read_der_file(
                    std::path::Path::new(key_path),
                    crate::trust_anchors::KEY_LABELS,
                )
                .map_err(|e| Error::Config(format!("modules[{i}] ({name}): key_file: {e}")))?;
                let facts = crate::target_facts::TargetFacts::for_runtime(runtime);
                let key = crate::identity_key::classify(&der);
                if let Err(e) =
                    crate::identity_key::admit_identity(key, runtime, facts.vault_suites)
                {
                    return Err(Error::Config(format!("modules[{i}] ({name}): {e}")));
                }
            }
            if let Some(manifest) = manifests.get(name) {
                // Placement: the module's signed runtime mask must name this
                // runtime.
                if let Some(why) =
                    crate::runtime_abi::placement_refusal(name, manifest.hardware_targets, runtime)
                {
                    return Err(Error::Config(format!("modules[{i}] ({name}): {why}")));
                }
                if let Err(e) =
                    crate::manifest::check_target_capabilities(manifest.requires, runtime)
                {
                    return Err(Error::Config(format!("modules[{i}] ({name}): {e}")));
                }
                // `[[requires_when]]`: a target-provided capability needed
                // only under one of this instance's parameter values. The
                // value comes from this entry's YAML or the schema default,
                // so the check sees the posture the module will actually
                // run under.
                if !manifest.requires_when.is_empty() {
                    let mtype = m.get("type").and_then(|t| t.as_str()).unwrap_or(name);
                    let param_schema = schema::load_schema_for_entry(m, mtype, loc)?;
                    let facts = target_desc.as_ref().map_or_else(
                        || crate::target_facts::TargetFacts::for_runtime(runtime),
                        crate::target_facts::TargetFacts::for_target,
                    );
                    for rw in &manifest.requires_when {
                        let resolutions: Vec<crate::target_facts::ParamResolution> = rw
                            .when
                            .iter()
                            .map(|(param, values)| match &param_schema {
                                None => crate::target_facts::ParamResolution::NoSchema,
                                Some(ps) => match schema::param_is_one_of(m, ps, param, values) {
                                    None => crate::target_facts::ParamResolution::Undeclared,
                                    Some(hit) => crate::target_facts::ParamResolution::Matches(hit),
                                },
                            })
                            .collect();
                        if let Err(e) = crate::target_facts::check_requires_when(
                            &resolutions,
                            rw,
                            &facts,
                            runtime,
                        ) {
                            return Err(Error::Config(format!("modules[{i}] ({name}): {e}")));
                        }
                    }
                }
            }
        }
    }

    // A member placed on another node has no instance here for a wire to
    // land on; say so before the generic unknown-module lookup would.
    refuse_wiring_to_remote(config)?;
    let (edges, force_flags, from_specs, to_specs) = if config.get("wiring").is_some() {
        parse_wiring_edges(&config["wiring"], &module_names, &manifests)?
    } else {
        return Err(Error::Config("wiring section required".into()));
    };
    let grouped = group_framed_edges(config, &edges, &module_names, &manifests)?;
    let config = &grouped;

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
        // The registry-resolved runtime (board "pico2w" → "rp2350"); the
        // small-buffer-arena profile is the rp2 family.
        let embedded = runtime_owned
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

    validate_record_limits(
        config,
        &edges,
        &module_names,
        &manifests,
        &from_specs,
        &to_specs,
    )?;

    // Required-input-unwired detector. Manifests mark some input
    // ports `required: true` — those MUST have a wiring edge
    // connecting to them or the module will block on an empty
    // input ring at runtime with no diagnostic. Catching this at
    // build time turns a silent runtime stall into a loud
    // validate-time failure.
    validate_required_inputs_wired(&edges, &module_names, &manifests)?;

    // A module no wire touches is not reported: standalone modules
    // (`debug`, a monitor, an alive heartbeat) are legitimate, and nothing
    // in a manifest tells them apart from a module left unwired by mistake.
    // An unwired REQUIRED input is the case that stalls, and is refused
    // above.

    validate_presentation_groups(config, &module_names, &manifests)?;

    // Session continuity classes as a validated graph property. Graphs
    // without a `continuity` block are unaffected. Members placed on
    // another node count here and nowhere else: their manifests are
    // resolved for their capabilities and facts, against no target, since
    // the silicon they run on is their own graph's business.
    let remote_list = Value::Array(remote_members(config));
    let mut remote_manifests = load_module_manifests_with_extra_for_target(
        &remote_list,
        extra_module_dirs,
        None,
        project_root,
    );
    bind_capability_facts(
        remote_list.as_array().map(Vec::as_slice).unwrap_or(&[]),
        &mut remote_manifests,
        &|entry, param| bound_param_value(entry, param, loc),
    )?;
    for name in remote_member_names(config) {
        if !remote_manifests.contains_key(&name) {
            let node = instance_node(config, &name).unwrap_or_default();
            return Err(Error::Config(format!(
                "module `{name}` is placed on node `{node}` but its manifest cannot be \
                 resolved; a placed member is admitted on its manifest's capabilities and \
                 facts, and a member with none is not evidence of anything"
            )));
        }
    }
    validate_exchange_placement(config, &edges, &module_names, &manifests, &remote_manifests)?;
    let mut continuity_names = module_names.clone();
    continuity_names.extend(remote_member_names(config));
    let mut continuity_manifests = manifests.clone();
    continuity_manifests.extend(remote_manifests);
    validate_continuity_on(
        config,
        &continuity_names,
        &continuity_manifests,
        resolved_target,
    )?;
    // Execution-envelope claim. Graphs without an
    // `execution.profile` claim nothing and are unaffected.
    validate_execution_profile(config, &module_names, &manifests, resolved_target)?;
    validate_port_capabilities(config, &manifests)?;
    validate_port_facts(config, &manifests, &|entry, param| {
        bound_param_value(entry, param, loc)
    })?;
    validate_connector_addressing(config)?;

    // One provider per (surface, selector), and every claim reaching a
    // provider that answers it. See storage_capability_surface.md.
    let claim_manifests = exercised_claims(
        config
            .get("modules")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]),
        &manifests,
        schema_param_is_one_of(loc),
    )?;
    validate_single_provider(
        config,
        &module_names,
        &claim_manifests,
        ProviderReach {
            runtime: runtime_owned.as_deref(),
            caller: ProviderCaller::Node,
        },
    )?;
    enforce_required_contracts(
        required_contract_refusals(
            config,
            &module_names,
            &claim_manifests,
            ProviderReach {
                runtime: runtime_owned.as_deref(),
                caller: ProviderCaller::Node,
            },
        ),
        "",
    )?;
    // One writer of the network stack's `addr_ctl` on a node that creates
    // workloads: the kernel.
    validate_net_identity_writers(config, &module_names, &manifests)?;
    // One keeper of the key vault's durable image.
    validate_vault_store(config, &manifests)?;
    // A module provider and the modules it serves share a domain (provider
    // code runs on the caller's core); one live-added workloads may reach
    // sits in the primary domain.
    validate_provider_domains(
        config,
        validation_list,
        &manifests,
        resolved_target.unwrap_or("linux"),
    )?;
    // An edge contract's client and server meet across one edge, in one
    // domain.
    validate_edge_contracts(config, validation_list, &manifests)?;

    // Resume-style fault recovery. `fault_policy: restart` resumes the
    // module's existing state after releasing its handles and flushing
    // its channels; nothing at instantiation time can tell whether that
    // is safe, so the module must attest it in its manifest.
    validate_fault_policy(config, &module_names, &manifests)?;

    // Presentation-shell / browser-overlay descriptor validation.
    // Scenarios without a `presentation.shell`
    // block are unaffected. Lives in a standalone, unit-testable module.
    crate::presentation_shell::validate(config, &module_names).map_err(Error::Config)?;

    if edges.len() > max_edges {
        return Err(Error::Config(format!(
            "Too many graph edges: {} > {}",
            edges.len(),
            max_edges
        )));
    }

    // Validate per-module port indices against `MAX_PORTS`. The
    // kernel's `populate_ports()` enforces the same bound at module
    // instantiation; catching it at build time gives a clear error
    // instead of a cryptic boot failure. Must equal
    // `src/kernel/exec/scheduler/mod.rs::MAX_PORTS`. The wire encoding
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
    // `src/kernel/exec/scheduler/mod.rs::open_channels` — mailbox flag is
    // set when buffer_group != 0). Without this, the channel is a
    // byte-streaming FIFO and structured envelopes get fragmented.
    let mut buffer_groups = assign_buffer_groups(&edges, &module_names, module_caps)?;
    let mut explicit_group = vec![false; buffer_groups.len()];
    if let Some(wiring) = config.get("wiring").and_then(|w| w.as_array()) {
        for (i, entry) in wiring.iter().enumerate() {
            if let Some(g) = entry.get("buffer_group").and_then(|v| v.as_u64()) {
                if g > 0 && g <= 31 && i < buffer_groups.len() {
                    buffer_groups[i] = g as u8;
                    explicit_group[i] = true;
                }
            }
        }
    }
    ungroup_gated_edges(
        &edges,
        &mut buffer_groups,
        &explicit_group,
        &gated_modules(config, &module_names, &isolation.levels),
        &module_names,
    )?;

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
    // Per-edge `buffer_bytes` from the wiring entries, a parallel array;
    // 0 sizes the ring by the port capacities.
    let edge_buffer_bytes = resolve_edge_buffer_bytes(config)?;

    // Per-edge wake-on-write (`wake: true`):
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
            let retains = edges
                .get(i)
                .and_then(|&(_, to_id, to_port, _, to_pi)| {
                    let to_dir = if to_port == 1 { 2u8 } else { 0u8 };
                    module_names
                        .get(to_id as usize)
                        .and_then(|n| manifests.get(n))
                        .and_then(|m| m.find_port_spec(to_dir, to_pi))
                })
                .is_some_and(|p| p.retains_send);
            flags.push(wake as u8 | (u8::from(retains) << 1));
        }
        flags
    };

    let accept_cycles = config
        .get("scheduler")
        .and_then(|s| s.get("accept_cycles"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // One record per edge, in wiring order: its index is its channel id.
    let edge_records: Vec<graph::EdgeRecord> = edges
        .iter()
        .enumerate()
        .map(
            |(i, &(from, to, to_port, from_port, to_port_index))| graph::EdgeRecord {
                from: graph::Endpoint::New(from),
                from_port,
                to: graph::Endpoint::New(to),
                to_port: to_port_index,
                to_ctrl: to_port == 1,
                class: match edge_classes.get(i).copied().unwrap_or(0) {
                    1 => graph::EdgeClass::DmaOwned,
                    2 => graph::EdgeClass::CrossCore,
                    3 => graph::EdgeClass::NicRing,
                    _ => graph::EdgeClass::Local,
                },
                buffer_group: buffer_groups.get(i).copied().unwrap_or(0),
                rate_class: edge_rate_classes.get(i).copied().unwrap_or(0),
                wake_on_write: edge_wake_flags.get(i).copied().unwrap_or(0) & 0x01 != 0,
                retains_send: edge_wake_flags.get(i).copied().unwrap_or(0) & 0x02 != 0,
                buffer_bytes: edge_buffer_bytes.get(i).copied().unwrap_or(0),
            },
        )
        .collect();

    // The composed graph: the declared modules are nodes `0..n` in config
    // order (a module's index is its id), its fans after them.
    let runtime = runtime_owned.as_deref().unwrap_or("linux");
    let fan_manifests = load_module_manifests_with_extra_for_target(
        &fan_entries(),
        extra_module_dirs,
        resolved_target,
        project_root,
    );
    let graph_modules: Vec<crate::add_subgraph::GraphModule> = module_entries
        .iter()
        .zip(&module_names)
        .map(|(e, name)| graph_module(e, name, manifests.get(name), runtime))
        .collect();
    let composition = crate::add_subgraph::compose(
        &graph_modules,
        &edge_records,
        crate::add_subgraph::Placement {
            platform: crate::ring_demand::platform_of(runtime),
            accept_cycles,
            domain_names: &domain_names,
        },
        &crate::add_subgraph::Composer {
            describe: &|e| crate::ring_demand::refusal(e, &module_names, &manifests, runtime),
            fan_params: &|fan, scratch| fan_module_params(fan, scratch, &fan_manifests),
        },
    )
    .map_err(Error::Config)?;

    // One record per declared domain, at least one. A domain's tick of 0
    // takes the graph's; tick_min_us/tick_max_us of 0 take the domain's
    // tick (adaptive is a no-op when unconfigured). Their ranges were
    // checked by `validate_adaptive_tick`.
    let domains_arr = config
        .get("execution")
        .and_then(|e| e.get("domains"))
        .and_then(|d| d.as_array());
    let field_u16 = |dom: Option<&Value>, key: &str| -> u16 {
        dom.and_then(|x| x.get(key))
            .and_then(Value::as_u64)
            .unwrap_or(0) as u16
    };
    let domain_records: Vec<boot_config::DomainRecord> = (0..domain_tick_us.len().max(1))
        .map(|d| {
            let dom = domains_arr.and_then(|a| a.get(d));
            boot_config::DomainRecord {
                tick_us: domain_tick_us.get(d).copied().unwrap_or(0),
                tick_min_us: field_u16(dom, "tick_min_us"),
                tick_max_us: field_u16(dom, "tick_max_us"),
                exec_mode: domain_modes.get(d).copied().unwrap_or_default(),
                adaptive_flags: dom
                    .and_then(|x| x.get("adaptive_flags"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as u8,
            }
        })
        .collect();

    // The hardware section is RP pin policy, decoded by the RP platform
    // alone: an RP config always carries it (counts of zero when the graph
    // declares no `hardware:`), and any other target refuses a `hardware:`
    // that configures anything, since its kernel would refuse the section.
    let hw_section =
        build_hardware_section(&config["hardware"], &module_names, max_gpio, pio_count)?;
    let rp_target = runtime_owned
        .as_deref()
        .is_some_and(|r| r == "rp2040" || r == "rp2350");
    let hardware = if rp_target {
        Some(hw_section.as_slice())
    } else if hw_section.len() > HARDWARE_HEADER_LEN {
        return Err(Error::Config(format!(
            "`hardware:` configures buses or pins, but the {} runtime has no hardware \
             section: its drivers claim what they use at runtime",
            runtime_owned.as_deref().unwrap_or("linux")
        )));
    } else {
        None
    };

    // Resident workloads: each top-level `workloads:` entry is a
    // self-contained composed graph the kernel admits at boot.
    let workload_blobs: Vec<(bool, Vec<u8>)> = workloads
        .iter()
        .map(|w| crate::add_subgraph::encode_workload(w).map(|b| (w.idle_safe, b)))
        .collect::<std::result::Result<_, String>>()
        .map_err(Error::Config)?;
    let workload_records: Vec<boot_config::WorkloadRecord<'_>> = workload_blobs
        .iter()
        .map(|(idle_safe, blob)| boot_config::WorkloadRecord {
            idle_safe: *idle_safe,
            blob,
        })
        .collect();

    // The capacity envelope: the optional top-level `capacity:` map, each
    // entry a pool's live-add reserve (an arena's size). Absent `capacity:`
    // writes no section, and every pool takes the profile's default reserve.
    let target = resolved_target.unwrap_or("linux");
    let envelope = envelope_entries(config, target)?;
    let envelope_records = envelope_pool_entries(&envelope);
    // Declared demand: what the graph's modules declare of the kernel pools,
    // which the kernel adds to their derived sizes. Absent when nothing
    // declares.
    let declared = declared_demand(config, &module_names, &manifests, &demand)?;
    if let Some(line) = heap_per_demand_report(&plan, &demand, &module_entries) {
        println!("{line}");
    }
    let demand_records: Vec<boot_config::PoolEntry> = declared
        .iter()
        .map(|&(_, pool, n)| boot_config::PoolEntry { pool, n })
        .collect();
    // The kernel's boot plan for this config, run here: a pool whose ceiling
    // (derived + reserve) the target's kernel cannot hold is refused at build,
    // naming the pool, instead of at boot.
    let (workload_count, workload_modules, workload_edges) =
        crate::capacity::resident_demand(&workload_records);
    // The composed graph's shape: its fans are modules, their joining
    // edges edges.
    let composed_edges = composed_edge_tuples(&composition.edges);
    let smp = crate::target::smp_of(target);
    let crossings = crate::capacity::crossing_count(
        &smp,
        composition.edges.iter().map(|e| {
            let domain = |end: graph::Endpoint| {
                end.new_index()
                    .and_then(|i| composition.modules.get(i))
                    .map(|m| m.domain)
            };
            (
                domain(e.from),
                domain(e.to),
                e.class == graph::EdgeClass::CrossCore,
            )
        }),
    );
    let shape = crate::capacity::GraphShape {
        modules: composition.modules.len() as u64,
        edges: composition.edges.len() as u64,
        fans: crate::capacity::fan_count(&composed_edges),
        workloads: workload_count,
        workload_modules,
        workload_edges,
        crossings,
    };
    let entries: Vec<(String, u64)> = envelope
        .iter()
        .map(|&(name, _, n)| (name.to_string(), n))
        .collect();
    let declared: Vec<(String, u64)> = declared
        .iter()
        .map(|&(name, _, n)| (name.to_string(), u64::from(n)))
        .collect();
    let summary = crate::capacity::check_boot_plan(target, &shape, &entries, &declared)
        .map_err(Error::Config)?;
    println!("{summary}");

    let records = composition.records();
    boot_config::encode(&boot_config::BootConfigSpec {
        tick_us,
        graph_sample_rate,
        domains: &domain_records,
        graph: composition.spec(&records),
        hardware,
        workloads: (!workload_records.is_empty()).then_some(workload_records.as_slice()),
        envelope: (!envelope_records.is_empty()).then_some(envelope_records.as_slice()),
        demand: (!demand_records.is_empty()).then_some(demand_records.as_slice()),
    })
    .map_err(|e| Error::Config(e.to_string()))
}

/// The fan module types as manifest entries, for the resolver every other
/// module is resolved by.
fn fan_entries() -> Value {
    json!([{ "name": "tee" }, { "name": "merge" }])
}

/// A declared module as composition sees it: its record's fields, and what
/// its manifest says of its ports. A module the node runs built in declares
/// no ports to the composer (the kernel holds no manifest for it), and the
/// Linux network provider keeps one channel per edge
/// (`ring_demand::multi_channel`).
fn graph_module(
    entry: &ModuleEntry,
    name: &str,
    manifest: Option<&Manifest>,
    runtime: &str,
) -> crate::add_subgraph::GraphModule {
    let loaded = manifest.filter(|m| !m.builtin);
    crate::add_subgraph::GraphModule {
        name: name.to_string(),
        name_hash: entry.name_hash,
        domain: entry.domain,
        pre_pass: entry.pre_pass,
        budget: entry.budget,
        params: entry.params.clone(),
        ports: loaded.map(crate::add_subgraph::plan_ports).unwrap_or_default(),
        mailbox_safe: loaded.is_some_and(|m| m.facts.mailbox_safe),
        multi_channel: crate::ring_demand::multi_channel(runtime, entry.name_hash),
    }
}

/// A fan's params TLV: its frame kind, frames per step and scratch
/// (`plan::fan_params`), with the heap cap its module type derives for that
/// scratch (`[capacities] heap_per_param`, params tag 0xEF) as for any
/// instance of the type. `manifests` holds the fan types' manifests by type.
fn fan_module_params(
    fan: &plan::Fan,
    scratch: u32,
    manifests: &HashMap<String, Manifest>,
) -> std::result::Result<Vec<u8>, String> {
    let ty = match fan.dir {
        plan::FanDir::Out => "tee",
        plan::FanDir::In => "merge",
    };
    let manifest = manifests.get(ty).ok_or_else(|| {
        format!(
            "the graph wires one port to several, which a `{ty}` module joins, and no `{ty}` \
             manifest resolves: `{ty}` is a Fluxor module — a project that depends on fluxor \
             pins it (`fluxor update`), and Fluxor builds it (`fluxor modules build`)"
        )
    })?;
    let tlv = plan::fan_params(fan.kind, plan::FRAMES_PER_STEP_DEFAULT, scratch).to_vec();
    insert_heap_tags(tlv, &json!({}), ty, Some(manifest), &HeapPlan::default())
        .map_err(|e| e.to_string())
}

/// A composed graph's edges as `capacity::fan_count` reads them:
/// `(from, to, to_port, from_port_index, to_port_index)`, by node index, an
/// end outside the graph as `u16::MAX`.
fn composed_edge_tuples(edges: &[graph::EdgeRecord]) -> Vec<(u16, u16, u8, u8, u8)> {
    let node = |end: graph::Endpoint| end.new_index().map_or(u16::MAX, |i| i as u16);
    edges
        .iter()
        .map(|e| {
            (
                node(e.from),
                node(e.to),
                u8::from(e.to_ctrl),
                e.from_port,
                e.to_port,
            )
        })
        .collect()
}

/// Bytes of the hardware section's counts header (spi, i2c, gpio, pio,
/// reserved, uart), before any record.
const HARDWARE_HEADER_LEN: usize = 6;

/// The capacity envelope from the top-level `capacity:` map:
/// [`envelope_entries`] as the codec's records. Empty without a `capacity:`
/// block.
#[cfg(test)]
fn build_capacity_envelope(
    config: &Value,
    resolved_target: Option<&str>,
) -> Result<Vec<boot_config::PoolEntry>> {
    let entries = envelope_entries(config, resolved_target.unwrap_or("linux"))?;
    Ok(envelope_pool_entries(&entries))
}

/// `entries` (`(pool, id, n)`) as envelope records, each figure encoded in
/// its pool's unit (`capacity::encode_entry`).
fn envelope_pool_entries(entries: &[(&'static str, u16, u64)]) -> Vec<boot_config::PoolEntry> {
    entries
        .iter()
        .map(|&(_, id, n)| boot_config::PoolEntry {
            pool: id,
            n: crate::capacity::encode_entry(id, n).expect("checked by envelope_entries"),
        })
        .collect()
}

/// The top-level `capacity:` map (`pool name: n`) as `(pool, id, n)` envelope
/// entries for `target`. Every name must be a pool `target`'s kernel has a
/// table for (an entry for one it has not would bound nothing). The kernel
/// sizes each table from what the graph derives and declares, and an entry is
/// that pool's live-add reserve on top; an arena's entry is its size, in
/// bytes. Whether the kernel can hold the result is the boot plan's question
/// (`capacity::check_boot_plan`). Prints the envelope so a deployment's
/// capacity choices are visible at compose time.
fn envelope_entries(config: &Value, target: &str) -> Result<Vec<(&'static str, u16, u64)>> {
    let Some(cap_map) = config.get("capacity") else {
        return Ok(Vec::new());
    };
    let obj = cap_map.as_object().ok_or_else(|| {
        Error::Config("capacity: must be a map of pool name → count/bytes".into())
    })?;
    let mut entries = Vec::new();
    println!("Capacity envelope ({target}):");
    for (name, val) in obj {
        let Some(&(pool, pool_id)) = crate::capacity::POOL_IDS.iter().find(|(n, _)| n == name)
        else {
            let known: Vec<&str> = crate::capacity::POOL_IDS.iter().map(|(n, _)| *n).collect();
            return Err(Error::Config(format!(
                "capacity: unknown pool '{name}' (known: {})",
                known.join(", ")
            )));
        };
        if pool == "config_arena" {
            // Observed, never allocated: the kernel borrows module params from
            // the config blob in place and reports them against the blob's
            // length, so an envelope entry would bound nothing.
            return Err(Error::Config(
                "capacity: 'config_arena' cannot be sized: module params are borrowed from \
                 the config blob in place, so the pool holds no allocation an envelope could \
                 bound"
                    .into(),
            ));
        }
        if !crate::capacity::kernel_has_pool(target, pool) {
            return Err(Error::Config(format!(
                "capacity: the {target} kernel has no '{pool}' table (`{}` names no such pool), \
                 so an entry for it would bound nothing",
                crate::capacity::kernel_profile(target)
            )));
        }
        let sized = crate::capacity::is_arena_name(pool);
        let n = val.as_u64().filter(|&n| n > 0 || !sized).ok_or_else(|| {
            Error::Config(format!(
                "capacity: '{pool}' must be a {} integer",
                if sized { "positive" } else { "non-negative" }
            ))
        })?;
        // An arena's entry is exact bytes below 2 GiB and KiB past it
        // (`resource::decode_entry`), so a byte-precise budget stays exact and
        // a large machine's arena still fits the entry's u32.
        if crate::capacity::encode_entry(pool_id, n).is_none() {
            return Err(Error::Config(format!(
                "capacity: '{pool}' = {n} overflows the envelope entry"
            )));
        }
        let what = if sized { "size" } else { "reserve" };
        match crate::capacity::kernel_pool_static_size(target, pool) {
            Some(table) => println!("  {pool}: {what} {n} (static table {table})"),
            None => println!("  {pool}: {what} {n} (sized at boot)"),
        }
        entries.push((pool, pool_id, n));
    }
    Ok(entries)
}

/// One instance's declared demand: `(pool, n)` per pool it declares, and the
/// type's `heap_per_demand` rule, for the plan.
#[derive(Debug, Clone)]
pub(crate) struct InstanceDemand {
    /// How the plan's report names the instance.
    pub(crate) name: String,
    pub(crate) figures: Vec<(&'static str, u64)>,
    pub(crate) heap_per_demand: Option<crate::manifest::HeapPerDemand>,
}

/// Where an instance's params TLV sits: a node-graph module entry (from its
/// header on), or a workload module's params.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParamsAt {
    Base(usize),
    Workload(usize, usize),
}

/// An instance of a `heap_per_demand` type, packed under a counting plan:
/// what [`patch_heap_cap`] needs to write its planned cap.
#[derive(Debug, Clone)]
pub(crate) struct PlannedHeap {
    pub(crate) at: ParamsAt,
    /// The instance's name in its graph (a workload module's local name).
    pub(crate) name: String,
    pub(crate) module: Value,
    pub(crate) manifest: Manifest,
}

/// The node graph's `heap_per_demand` instances, by entry index.
fn base_planned_heaps(
    modules: &Value,
    names: &[String],
    manifests: &HashMap<String, Manifest>,
) -> Vec<PlannedHeap> {
    let list = modules.as_array().map(Vec::as_slice).unwrap_or(&[]);
    list.iter()
        .zip(names)
        .enumerate()
        .filter_map(|(i, (module, name))| {
            let manifest = manifests
                .get(name)
                .filter(|m| m.heap_per_demand.is_some())?;
            Some(PlannedHeap {
                at: ParamsAt::Base(i),
                name: name.clone(),
                module: module.clone(),
                manifest: manifest.clone(),
            })
        })
        .collect()
}

/// Write each `heap_per_demand` instance's cap under `plan` over the
/// placeholder its counting pass packed (`patch_heap_cap`).
fn apply_heap_plan(
    plan: &HeapPlan,
    heaps: &[PlannedHeap],
    entries: &mut [ModuleEntry],
    workloads: &mut [crate::add_subgraph::Workload],
) -> Result<()> {
    for h in heaps {
        let tlv = match h.at {
            ParamsAt::Base(i) => entries.get_mut(i).map(|e| e.params.as_mut_slice()),
            ParamsAt::Workload(w, m) => workloads
                .get_mut(w)
                .and_then(|w| w.graph.modules.get_mut(m))
                .map(|m| m.params.as_mut_slice()),
        };
        let tlv = tlv.ok_or_else(|| {
            Error::Config(format!("module '{}': no packed params to size", h.name))
        })?;
        patch_heap_cap(&h.name, &h.module, Some(&h.manifest), tlv, plan)?;
    }
    Ok(())
}

/// What one instance declares it will ask of each kernel pool at run time
/// (`capacity::DECLARED_DEMAND`), `(pool, n)` for each it declares:
///
/// - the graph's own figure for the instance, `demand: { <pool>: n }` on its
///   module entry, wins;
/// - else the type's `[capacities] demand_from_params` rule for that pool,
///   counted from the instance's params TLV `tlv`, with `integers` the
///   type's integer params and their schema defaults ([`integer_params`]);
/// - else the type's `[capacities]` constant under the pool's key.
pub(crate) fn instance_demand(
    module: &Value,
    name: &str,
    manifest: Option<&Manifest>,
    tlv: &[u8],
    integers: &[(u8, u32)],
) -> Result<Vec<(&'static str, u64)>> {
    let explicit = module.get("demand");
    if let Some(e) = explicit {
        let obj = e.as_object().ok_or_else(|| {
            Error::Config(format!(
                "module '{name}': demand must be a map of pool name → count \
                 (e.g. `demand: {{ store_subs: 4 }}`)"
            ))
        })?;
        for (pool, n) in obj {
            if !crate::capacity::DECLARED_DEMAND
                .iter()
                .any(|&(_, p)| p == pool)
            {
                let known: Vec<&str> = crate::capacity::DECLARED_DEMAND
                    .iter()
                    .map(|&(_, p)| p)
                    .collect();
                return Err(Error::Config(format!(
                    "module '{name}': demand names '{pool}', which is not a pool a module \
                     declares demand on (one of: {})",
                    known.join(", ")
                )));
            }
            if n.as_u64().is_none() {
                return Err(Error::Config(format!(
                    "module '{name}': demand.{pool} must be a non-negative integer (got {n})"
                )));
            }
        }
    }
    let mut out = Vec::new();
    for &(key, pool) in crate::capacity::DECLARED_DEMAND {
        let n = if let Some(n) = explicit.and_then(|e| e.get(pool)).and_then(Value::as_u64) {
            n
        } else if let Some(rule) =
            manifest.and_then(|m| m.demand_from_params.iter().find(|r| r.pool == pool))
        {
            rule.declared_count(tlv, integers)
        } else if let Some(&n) = manifest.and_then(|m| m.capacities.get(key)) {
            u64::from(n)
        } else {
            continue;
        };
        if n > 0 {
            out.push((pool, n));
        }
    }
    Ok(out)
}

/// `(tag, schema default)` of each integer param (`u8`, `u16`, `u32`) in a
/// module's schema: what a `demand_from_params` rule counts by value.
fn integer_params(schema: Option<&schema::ParamSchema>) -> Vec<(u8, u32)> {
    schema
        .map(|s| {
            s.params
                .iter()
                .filter(|p| {
                    matches!(
                        p.ptype,
                        schema::ParamType::U8 | schema::ParamType::U16 | schema::ParamType::U32
                    )
                })
                .map(|p| (p.tag, p.default))
                .collect()
        })
        .unwrap_or_default()
}

/// The node graph's per-instance demand: each module entry's params (its TLV
/// from the entry header on) read with its YAML entry, its manifest and, for
/// a type with a `demand_from_params` rule, its param schema from `loc`.
fn base_demand(
    modules: &Value,
    entries: &[ModuleEntry],
    names: &[String],
    manifests: &HashMap<String, Manifest>,
    loc: schema::ModuleLocation<'_>,
) -> Result<Vec<InstanceDemand>> {
    let list = modules.as_array().map(Vec::as_slice).unwrap_or(&[]);
    let mut out = Vec::new();
    for ((module, entry), name) in list.iter().zip(entries).zip(names) {
        let manifest = manifests.get(name);
        let tlv = entry.params.as_slice();
        let integers = if manifest.is_some_and(|m| !m.demand_from_params.is_empty()) {
            let ty = module.get("type").and_then(Value::as_str).unwrap_or(name);
            integer_params(schema::load_schema_for_entry(module, ty, loc)?.as_ref())
        } else {
            Vec::new()
        };
        out.push(InstanceDemand {
            name: format!("module '{name}'"),
            figures: instance_demand(module, name, manifest, tlv, &integers)?,
            heap_per_demand: manifest.and_then(|m| m.heap_per_demand.clone()),
        });
    }
    Ok(out)
}

/// Refuse `fault_policy: restart` to a node-graph instance that declares
/// store subscriptions or the events they ring (`store_subs`, `events`), by
/// its type's rule, constant or its own `demand:`. The restart releases the
/// module's kernel events and moves its slot generation, so the store drops
/// every subscription it made, and the module resumes believing it is
/// subscribed — never woken by a change again. `demand` is the node graph's,
/// one per entry of `modules` in order ([`base_demand`]).
fn refuse_restart_of_subscribers(modules: &Value, demand: &[InstanceDemand]) -> Result<()> {
    let list = modules.as_array().map(Vec::as_slice).unwrap_or(&[]);
    for (module, d) in list.iter().zip(demand) {
        if module.get("fault_policy").and_then(Value::as_str) != Some("restart") {
            continue;
        }
        if let Some(&(pool, n)) = d
            .figures
            .iter()
            .find(|&&(p, n)| n > 0 && (p == "store_subs" || p == "events"))
        {
            return Err(Error::Config(format!(
                "{}: fault_policy = \"restart\" is not available to an instance that \
                 declares {n} `{pool}` — a store subscriber. The restart releases the kernel \
                 events its subscriptions ring and moves its slot generation, so the store \
                 drops every subscription it made, and the module resumes believing it is \
                 subscribed — never woken by a change again. Configure it to subscribe to \
                 nothing, or choose `fault_policy: \"skip\"`.",
                d.name
            )));
        }
    }
    Ok(())
}

/// `pool`'s total over `demand`.
fn demand_total(demand: &[InstanceDemand], pool: &str) -> u64 {
    demand
        .iter()
        .flat_map(|d| d.figures.iter())
        .filter(|&&(p, _)| p == pool)
        .map(|&(_, n)| n)
        .sum()
}

/// The top-level `capacity:` map's figures, `(pool, n)`, unchecked: what the
/// plan reads before `envelope_entries` validates and prints them.
fn envelope_figures(config: &Value) -> Vec<(String, u64)> {
    config
        .get("capacity")
        .and_then(Value::as_object)
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_u64()?)))
                .collect()
        })
        .unwrap_or_default()
}

/// The [`HeapPlan`] for a graph whose instances declare `demand`: the full
/// planned ceiling on `target` of every pool a `heap_per_demand` rule names —
/// what the graph declares for it (all of it, a module-provided pool's
/// included: the provider serves it), plus the `capacity:` entry, else the
/// profile's default reserve. Those pools have no structural part
/// (`manifest::heap_per_demand_pool_allowed`), so the graph's shape is not
/// needed.
fn heap_plan(target: &str, config: &Value, demand: &[InstanceDemand]) -> HeapPlan {
    let declared: Vec<(String, u64)> = crate::capacity::DECLARED_DEMAND
        .iter()
        .map(|&(_, pool)| (pool.to_string(), demand_total(demand, pool)))
        .collect();
    let entries = envelope_figures(config);
    let mut plan = HeapPlan::default();
    for rule in demand.iter().filter_map(|d| d.heap_per_demand.as_ref()) {
        let ceiling = crate::capacity::plan_pool(
            target,
            &rule.pool,
            &crate::capacity::GraphShape::default(),
            &declared,
            &entries,
        )
        .ceiling();
        plan.ceilings.insert(rule.pool.clone(), ceiling);
    }
    plan
}

/// The unkeyed module provider of `contract` in the node graph, if any: a
/// module whose manifest `provides` it with no `volume:` selector, so it is
/// the layer class-byte calls reach.
fn unkeyed_module_provider<'a>(
    config: &Value,
    module_names: &'a [String],
    manifests: &HashMap<String, Manifest>,
    contract: &str,
) -> Option<&'a str> {
    module_names
        .iter()
        .find(|n| {
            manifests
                .get(*n)
                .is_some_and(|m| m.provides.iter().any(|p| p == contract))
                && provider_volume(config, n).is_empty()
        })
        .map(String::as_str)
}

/// The graph's declared demand on the kernel's tables, `(pool, id, n)`: per
/// pool, what its instances declare ([`instance_demand`]), node graph and
/// resident workloads summed. The kernel adds it to the pool's derived size,
/// so a pool sized by its consumers — the store's subscription table — grows
/// with the graph that boots. The `DMND` section carries it; empty when
/// nothing declares.
///
/// A pool a module provider serves from its own heap
/// (`capacity::MODULE_PROVIDED_POOLS`) is left out when the node graph has an
/// unkeyed module provider of its contract: the consumers call that module,
/// not the host table, and the demand is spent once — on the provider's
/// `heap_per_demand` figure — rather than twice.
fn declared_demand(
    config: &Value,
    module_names: &[String],
    manifests: &HashMap<String, Manifest>,
    demand: &[InstanceDemand],
) -> Result<Vec<(&'static str, u16, u32)>> {
    let mut entries = Vec::new();
    for &(_, pool) in crate::capacity::DECLARED_DEMAND {
        let total = demand_total(demand, pool);
        if total == 0 {
            continue;
        }
        let Some(&(_, id)) = crate::capacity::POOL_IDS.iter().find(|(n, _)| *n == pool) else {
            continue;
        };
        let n = u32::try_from(total).map_err(|_| {
            Error::Config(format!(
                "the graph declares {total} {pool}, which overflows u32"
            ))
        })?;
        let provider = crate::capacity::MODULE_PROVIDED_POOLS
            .iter()
            .find(|&&(p, _)| p == pool)
            .and_then(|&(_, contract)| {
                unkeyed_module_provider(config, module_names, manifests, contract)
                    .map(|m| (m, contract))
            });
        if let Some((module, contract)) = provider {
            let per_demand = manifests
                .get(module)
                .and_then(|m| m.heap_per_demand.as_ref())
                .is_some_and(|r| r.pool == pool);
            println!(
                "Declared demand: {pool} {n}, served by module '{module}' (provides `{contract}`){}; \
                 not added to the host table",
                if per_demand {
                    ", sized into its heap by `heap_per_demand`"
                } else {
                    ""
                }
            );
            continue;
        }
        println!("Declared demand: {pool} {n}");
        entries.push((pool, id, n));
    }
    Ok(entries)
}

/// One line for the composer's report: the heap bytes `heap_per_demand`
/// rules add (each instance's, under `plan`) beside the total of the heap
/// caps the composer set in the graph's module entries (params tag 0xEF).
/// `None` when no rule adds any.
fn heap_per_demand_report(
    plan: &HeapPlan,
    demand: &[InstanceDemand],
    entries: &[ModuleEntry],
) -> Option<String> {
    let mut parts = Vec::new();
    let mut per_demand = 0u64;
    for d in demand {
        let Some(rule) = &d.heap_per_demand else {
            continue;
        };
        let Some(&ceiling) = plan.ceilings.get(&rule.pool) else {
            continue;
        };
        let extra = rule.extra_for(ceiling);
        if extra == 0 {
            continue;
        }
        per_demand += extra;
        parts.push(format!(
            "{} +{extra} B ({} B × `{}` {ceiling})",
            d.name, rule.bytes_each, rule.pool
        ));
    }
    if parts.is_empty() {
        return None;
    }
    let caps: u64 = entries
        .iter()
        .filter_map(|e| {
            let tlv = e.params.as_slice();
            let off = heap_cap_offset(tlv)?;
            Some(u64::from(u32::from_le_bytes(
                tlv[off..off + 4].try_into().ok()?,
            )))
        })
        .sum();
    Some(format!(
        "Heap per demand: {per_demand} B ({}); heap caps the composer set total {caps} B",
        parts.join(", ")
    ))
}

/// The graph's resident workloads as the composed graphs a config's `WKLD`
/// section carries, from the optional top-level `workloads:` list. Each
/// workload is a self-contained subgraph: modules referenced by `name_hash`
/// (FNV-1a of type) with inline-TLV params (the same
/// `build_params_from_schema` packing node-graph modules use), and optional
/// intra-workload `wiring:` (`module.port` ends among the workload's modules,
/// the node's network as `linux_net`, see [`workload_edges`]). Cross-workload
/// edges are refused (strict isolation). Empty with no workloads.
#[cfg(test)]
fn build_workload_section(
    config: &Value,
    loc: schema::ModuleLocation<'_>,
    extra_module_dirs: &[&Path],
) -> Result<Vec<Vec<u8>>> {
    build_workloads(config, loc, extra_module_dirs, "linux")?
        .iter()
        .map(|w| crate::add_subgraph::encode_workload(w).map_err(Error::Config))
        .collect()
}

/// The manifests as the provider checks read them: each instance's claims
/// limited to the ones its build and its params exercise. A claim naming
/// `variants` counts only when the instance is built as one of them; a claim
/// with a `when` counts only when every condition holds for the instance's
/// params, its schema's defaults standing in for unset ones (the
/// `[[requires_when]]` resolution, [`schema_param_is_one_of`]).
///
/// `is_one_of(module_type, entry, param, values)` answers whether the
/// instance's effective value of `param` is one of `values`: `Ok(None)` when
/// the module has no schema, `Ok(Some(None))` when the schema does not declare
/// the param or values.
pub(crate) fn exercised_claims(
    entries: &[Value],
    manifests: &HashMap<String, Manifest>,
    is_one_of: impl Fn(&str, &Value, &str, &[String]) -> Result<Option<Option<bool>>>,
) -> Result<HashMap<String, Manifest>> {
    let mut out = HashMap::with_capacity(manifests.len());
    for (name, m) in manifests {
        let mut m = m.clone();
        let entry = entries
            .iter()
            .find(|e| e.get("name").and_then(Value::as_str) == Some(name.as_str()));
        let mut kept = Vec::with_capacity(m.resources.len());
        for claim in std::mem::take(&mut m.resources) {
            if !claim.variants.is_empty()
                && !m
                    .selected_variant
                    .as_ref()
                    .is_some_and(|v| claim.variants.contains(v))
            {
                continue;
            }
            if !claim.when.is_empty() {
                let empty = Value::Object(Default::default());
                let entry = entry.unwrap_or(&empty);
                let mtype = entry.get("type").and_then(Value::as_str).unwrap_or(name);
                let mut holds = true;
                for (param, values) in &claim.when {
                    let Some(answer) = is_one_of(mtype, entry, param, values)? else {
                        return Err(Error::Config(format!(
                            "module '{name}': a `{}` claim is conditioned on params (`when`), \
                             but the module has no parameter schema to resolve them against",
                            crate::manifest::contract_name_to_str(claim.device_class)
                        )));
                    };
                    match answer {
                        Some(hit) => holds &= hit,
                        None => {
                            return Err(Error::Config(format!(
                                "module '{name}': a `{}` claim's `when` names `{param}` = \
                                 {values:?}, which its schema does not declare",
                                crate::manifest::contract_name_to_str(claim.device_class)
                            )))
                        }
                    }
                }
                if !holds {
                    continue;
                }
            }
            kept.push(claim);
        }
        m.resources = kept;
        out.insert(name.clone(), m);
    }
    Ok(out)
}

/// [`exercised_claims`]'s value test against the module's built schema.
fn schema_param_is_one_of(
    loc: schema::ModuleLocation<'_>,
) -> impl Fn(&str, &Value, &str, &[String]) -> Result<Option<Option<bool>>> + '_ {
    move |mtype, entry, param, values| {
        Ok(schema::load_schema_for_entry(entry, mtype, loc)?
            .map(|ps| schema::param_is_one_of(entry, &ps, param, values)))
    }
}

/// The value of integer param `param` for the module instance `entry`:
/// what the graph sets, or the schema default. The schema is the built
/// artefact's, or a native module's manifest.
fn bound_param_value(
    entry: &Value,
    param: &str,
    loc: schema::ModuleLocation<'_>,
) -> Result<BoundParam> {
    let Some(name) = entry.get("name").and_then(Value::as_str) else {
        return Ok(BoundParam::NoSchema);
    };
    let mtype = entry.get("type").and_then(Value::as_str).unwrap_or(name);
    let Some(ps) = schema::load_schema_for_entry(entry, mtype, loc)?
        .or_else(|| load_native_param_schema(mtype).map(|(_, s)| s))
    else {
        return Ok(BoundParam::NoSchema);
    };
    Ok(bound_param_in(entry, &ps, param))
}

/// [`bound_param_value`] against a schema at hand.
fn bound_param_in(entry: &Value, ps: &schema::ParamSchema, param: &str) -> BoundParam {
    let integer = ps.find(param).is_some_and(|p| {
        matches!(
            p.ptype,
            schema::ParamType::U8 | schema::ParamType::U16 | schema::ParamType::U32
        )
    });
    match schema::effective_param_value(entry, ps, param) {
        Some(v) if integer => BoundParam::Value(v),
        _ => BoundParam::NotAnInteger,
    }
}

/// The graph's `workloads:` section, each as the subgraph the kernel admits
/// (`add_subgraph::Workload`): modules by name_hash with their params, and
/// the edges between them. Empty when the graph declares none. The resident
/// workload section and a workload image (`--emit=workload`) encode these.
///
/// A `heap_per_demand` module's cap is planned from these workloads' own
/// declared demand and `target`'s reserve, as a graph plans its own.
pub fn build_workloads(
    config: &Value,
    loc: schema::ModuleLocation<'_>,
    extra_module_dirs: &[&Path],
    target: &str,
) -> Result<Vec<crate::add_subgraph::Workload>> {
    let runtime = crate::target::load_target(target, loc.project_root)
        .map(|d| d.runtime().to_string())
        .ok();
    let (mut workloads, demand, heaps) =
        build_workloads_counted(config, loc, extra_module_dirs, runtime.as_deref())?;
    let plan = heap_plan(target, config, &demand);
    apply_heap_plan(&plan, &heaps, &mut [], &mut workloads)?;
    Ok(workloads)
}

/// Whether the platform of `runtime` answers `caller`'s `fs` calls.
fn fs_reachable(runtime: &str, caller: ProviderCaller) -> bool {
    platform_contracts(runtime, caller).is_some_and(|c| c.iter().any(|x| x == "fs"))
}

/// Refuse a credential form the instance could not use where it runs.
///
/// `cert_file`, `key_file` and `trust` written `${file:<path>}` are embedded
/// at build. An image for the Linux runtime refuses that form: there the
/// module reads its credentials at runtime from the file surface it is
/// given (the host's paths for a node graph, a workload's root and lent
/// volumes), so the image carries no credential and no deployment's trust,
/// and a build reads nothing. Elsewhere the embedded form is how a target
/// with no file surface at runtime is given its credentials, and a bare
/// path — read at runtime through `fs` — is refused when nothing serves
/// `fs` to the instance (`fs_served`), since it could never be read.
pub(crate) fn refuse_credential_forms(
    module: &Value,
    runtime: Option<&str>,
    fs_served: bool,
    label: &str,
) -> Result<()> {
    let Some(runtime) = runtime else {
        return Ok(());
    };
    for key in CREDENTIAL_KEYS {
        let Some(spec) = module.get(key).and_then(|v| v.as_str()) else {
            continue;
        };
        if let Some(path) = crate::trust_anchors::file_source(spec) {
            if runtime == "linux" {
                // A runtime path must be absolute (`validate` refuses a relative one), so the
                // suggestion is too.
                let abs = if path.starts_with('/') {
                    path.to_string()
                } else {
                    format!("/…/{path}")
                };
                return Err(Error::Config(format!(
                    "{label}: {key} \"{spec}\" embeds a build-host file, and a Linux image takes \
                     its credentials at runtime: name the absolute path the module reads where it \
                     runs (`{key}: {abs}`, or `{key}: ${{param:NAME}}` so each run supplies it), \
                     or bind it in a workload (`{key}: {{env: NAME}}`)"
                )));
            }
            continue;
        }
        let runtime_path = spec.starts_with('/');
        if runtime_path && !fs_served {
            return Err(Error::Config(format!(
                "{label}: {key} \"{spec}\" is read at runtime through the `fs` contract, and \
                 nothing serves `fs` to this instance on {runtime}: embed the file at build \
                 (`{key}: \"${{file:{spec}}}\"`), or give the graph an `fs` provider"
            )));
        }
    }
    Ok(())
}

/// The workloads [`build_workloads`] builds, packed under a counting
/// [`HeapPlan`], with each workload module's declared demand
/// ([`instance_demand`]) and its `heap_per_demand` instances: resident
/// workloads are counted in the graph's plan as its node-graph modules are.
fn build_workloads_counted(
    config: &Value,
    loc: schema::ModuleLocation<'_>,
    extra_module_dirs: &[&Path],
    runtime: Option<&str>,
) -> Result<(
    Vec<crate::add_subgraph::Workload>,
    Vec<InstanceDemand>,
    Vec<PlannedHeap>,
)> {
    let plan = HeapPlan::counting();
    let mut demand = Vec::new();
    let mut heaps = Vec::new();
    let Some(workloads_yaml) = config.get("workloads").and_then(|p| p.as_array()) else {
        return Ok((Vec::new(), demand, heaps));
    };
    if workloads_yaml.is_empty() {
        return Ok((Vec::new(), demand, heaps));
    }
    let data_section = config.get("data");
    // Manifest search path for the pre_pass check: mirror the validators'
    // resolution (extra_module_dirs first — they shadow bundled modules), then
    // `modules_dir` as a fallback so an external/project module is found and
    // checked rather than silently passing and losing its pre-pass semantics.
    let manifest_search: Vec<&Path> = {
        let mut v: Vec<&Path> = extra_module_dirs.to_vec();
        v.push(loc.dir);
        v
    };
    // Per-domain execution mode, so workloads can be refused from interrupt-mode
    // domains. A workload's graph carries NO exec-mode / `interrupt_safe`
    // metadata, and workload admission runs AFTER the platform registers ISR
    // handlers (bcm2712.rs) — so an interrupt-mode workload would be admitted
    // yet never dispatched (a cooperative domain loop skips interrupt-mode
    // domains). It is refused.
    let domain_exec_mode: Vec<boot_config::ExecMode> = parse_domain_execs(config)?
        .into_iter()
        .map(|(_, exec)| exec.mode)
        .collect();
    // Every manifest a workload needs resolves as a node graph's do: its pin
    // in the project's `fluxor.lock` first, then the search paths.
    let workload_abi = (!loc.abi.is_empty()).then_some(loc.abi);
    let pins =
        crate::store_cli::lock_store_manifest_resolver(loc.project_root, workload_abi, None);
    // The fan types, resolved as the workload's own modules are: a fan a
    // workload's wiring needs runs as one of its modules.
    let mut fan_manifests: HashMap<String, Manifest> = HashMap::new();
    for ty in ["tee", "merge"] {
        match type_manifest(ty, ty, None, &manifest_search, workload_abi, pins.as_ref()) {
            TypeManifest::Found(man) => {
                fan_manifests.insert(ty.to_string(), *man);
            }
            TypeManifest::Rejected(why) => return Err(Error::Config(why)),
            TypeManifest::Absent => {}
        }
    }
    let mut workloads = Vec::new();
    for (pi, workload_yaml) in workloads_yaml.iter().enumerate() {
        let mods_yaml = workload_yaml
            .get("modules")
            .and_then(|m| m.as_array())
            .ok_or_else(|| Error::Config(format!("workload {pi}: missing `modules:` array")))?;
        // Deterministic owner_uid: 0xD0 marker + index (host composer / kernel both
        // treat the UID as opaque identity; uniqueness within the graph suffices).
        let mut owner_uid = [0u8; 16];
        owner_uid[0] = 0xD0;
        owner_uid[1] = pi as u8;
        let mut name_to_local: HashMap<String, u8> = HashMap::new();
        let mut modules = Vec::new();
        // The workload's own instances (each under its local name) and
        // manifests, for the provider checks: a workload reaches only
        // providers of its own and the platform.
        let mut local_entries: Vec<Value> = Vec::new();
        let mut local_names: Vec<String> = Vec::new();
        let mut local_manifests: HashMap<String, Manifest> = HashMap::new();
        for (li, m) in mods_yaml.iter().enumerate() {
            let mname = m
                .get("name")
                .and_then(|v| v.as_str())
                .or_else(|| m.get("type").and_then(|v| v.as_str()))
                .ok_or_else(|| {
                    Error::Config(format!(
                        "workload {pi} module {li}: needs a `name` or `type`"
                    ))
                })?;
            let mtype = m.get("type").and_then(|v| v.as_str()).unwrap_or(mname);
            refuse_credential_forms(
                m,
                runtime,
                runtime.is_some_and(|r| fs_reachable(r, ProviderCaller::Workload)),
                &format!("workload {pi} module '{mname}'"),
            )?;
            // PIC-only: a workload's modules are admitted via the loader by
            // name_hash; a native module has no .fmod for apply_add to load.
            if crate::modules::is_native_module(mtype) {
                if WORKLOAD_NET_ENDS.contains(&mtype) {
                    return Err(Error::Config(format!(
                        "workload {pi} module '{mname}': `{mtype}` is the node's network, not a \
                         module of the workload — drop the entry; the workload's wires to \
                         `{mtype}.net_in` and from `{mtype}.net_out` are its lanes"
                    )));
                }
                return Err(Error::Config(format!(
                    "workload {pi} module '{mtype}' is a native module; resident workloads are PIC-only \
                     (no .fmod for apply_add to load). Use a PIC module, or place it in the node graph."
                )));
            }
            // Reject duplicate local names within a workload: `name_to_local` resolves
            // `wiring:` endpoints, so a silent overwrite would mis-wire edges to the
            // wrong module. Names must be unique per workload (a module's `name` defaults
            // to its `type`, so two same-type modules need explicit distinct names).
            if name_to_local.insert(mname.to_string(), li as u8).is_some() {
                return Err(Error::Config(format!(
                    "workload {pi}: duplicate module name '{mname}' — workload-local module names must be \
                     unique (they resolve `wiring:` endpoints). Give each module a distinct `name` \
                     (two modules of the same `type` default to the same name)."
                )));
            }
            let name_hash = crate::hash::fnv1a_hash(mtype.as_bytes());
            // Domain is a NAME resolved against execution.domains (same namespace
            // as node-graph modules), so workload modules share their domain's loop and budget
            // and the admission validators resolve them identically.
            let domain_id = resolve_domain_id(m, config)?;
            // Reject interrupt-mode workload placement — the codec cannot represent it
            // and no cooperative domain loop would ever dispatch it.
            let exec_mode = domain_exec_mode
                .get(domain_id as usize)
                .copied()
                .unwrap_or_default();
            if exec_mode.is_interrupt() {
                return Err(Error::Config(format!(
                    "workload {pi} module '{mtype}' targets an `exec: {}` domain. Resident \
                     workloads are cooperative: a workload's graph carries no interrupt-mode \
                     metadata and workload admission runs after ISR registration, so such a \
                     workload would never execute. Place interrupt-mode modules in the base \
                     graph.",
                    exec_mode.name()
                )));
            }
            // Resolved for the target's module ABI and the instance's
            // variant, as node-graph manifests are: the heap rule below
            // reads per-ABI, per-variant figures.
            let manifest = match type_manifest(
                mname,
                mtype,
                m.get("variant").and_then(Value::as_str),
                &manifest_search,
                workload_abi,
                pins.as_ref(),
            ) {
                TypeManifest::Found(man) => Some(*man),
                TypeManifest::Rejected(why) => {
                    return Err(Error::Config(format!("workload {pi}: {why}")));
                }
                TypeManifest::Absent => None,
            };
            let mut local = m.clone();
            if let Some(obj) = local.as_object_mut() {
                obj.insert("name".to_string(), Value::String(mname.to_string()));
            }
            local_entries.push(local);
            local_names.push(mname.to_string());
            if let Some(man) = manifest.as_ref() {
                local_manifests.insert(mname.to_string(), man.clone());
            }
            // Reject `pre_pass` workload modules: a domain's pre-pass is
            // the node's graph's, and a workload built apart from the node
            // cannot know how many of its domain's places the node fills.
            if manifest.as_ref().is_some_and(|man| man.pre_pass) {
                return Err(Error::Config(format!(
                    "workload {pi} module '{mtype}' is a pre_pass module, \
                     which resident workloads do not run: a domain's pre-pass holds \
                     at most {} modules and belongs to the node's own graph. Place \
                     pre_pass modules in the node graph.",
                    graph::MAX_PRE_PASS_PER_DOMAIN
                )));
            }
            // Inline-TLV params — identical packing to node-graph modules, so the kernel
            // reads them via `params_ptr` exactly the same way.
            let param_schema = schema::load_schema_for_entry(m, mtype, loc)?;
            refuse_workload_node_keys(m, param_schema.as_ref(), pi, mname)?;
            validate_variant_key(m, mname)?;
            let integers = integer_params(param_schema.as_ref());
            let params = if let Some(param_schema) = param_schema {
                // tls / quic peer names: checked and packed as a node
                // graph's are, an `{env: NAME}` binding left for CREATE.
                let declares = |key: &str| param_schema.find(key).is_some();
                let m = &normalize_peer_names(mname, mtype, m.clone(), declares)?;
                pack_params_growing(m, &param_schema, data_section, mtype)?
            } else {
                Vec::new()
            };
            // The heap flags act on the module's own heap: a workload module
            // takes them as a node-graph module does, in its params TLV.
            demand.push(InstanceDemand {
                name: format!("workload {pi} module '{mname}'"),
                figures: instance_demand(m, mname, manifest.as_ref(), &params, &integers)?,
                heap_per_demand: manifest.as_ref().and_then(|m| m.heap_per_demand.clone()),
            });
            if let Some(man) = manifest.as_ref().filter(|m| m.heap_per_demand.is_some()) {
                heaps.push(PlannedHeap {
                    at: ParamsAt::Workload(workloads.len(), modules.len()),
                    name: mname.to_string(),
                    module: m.clone(),
                    manifest: man.clone(),
                });
            }
            let params = insert_heap_tags(params, m, mname, manifest.as_ref(), &plan)?;
            // What the kernel refuses in a workload's params, refused here by
            // the bytes it would read.
            if let Some(tag) = crate::add_subgraph::params_node_tag(&params) {
                return Err(Error::Config(format!(
                    "workload {pi} module '{mname}': its params carry node tag {tag:#04x}, \
                     which a node refuses in a workload (see `is_node_param_tag`)"
                )));
            }
            // The step budget rides the module record, never the params
            // TLV: the kernel takes a live-added module's deadline and fault
            // policy from the record alone, and refuses one outside what it
            // admits a workload — refused here first, with the reason.
            let budget =
                workload_step_budget(m, config, &format!("workload {pi} module '{mname}'"))?;
            modules.push(crate::add_subgraph::GraphModule {
                name: mname.to_string(),
                name_hash,
                domain: domain_id,
                pre_pass: false,
                budget,
                params,
                ports: manifest
                    .as_ref()
                    .map(crate::add_subgraph::plan_ports)
                    .unwrap_or_default(),
                mailbox_safe: manifest.as_ref().is_some_and(|m| m.facts.mailbox_safe),
                multi_channel: false,
            });
        }
        let local_claims = exercised_claims(
            &local_entries,
            &local_manifests,
            schema_param_is_one_of(loc),
        )?;
        validate_single_provider(
            &json!({
                "modules": local_entries,
                "wiring": workload_yaml.get("wiring").cloned().unwrap_or(Value::Null),
                "data": data_section.cloned().unwrap_or(Value::Null),
            }),
            &local_names,
            &local_claims,
            ProviderReach {
                runtime,
                caller: ProviderCaller::Workload,
            },
        )
        .map_err(|e| match e {
            Error::Config(why) => Error::Config(format!("workload {pi}: {why}")),
            other => other,
        })?;
        enforce_required_contracts(
            required_contract_refusals(
                &json!({
                    "modules": local_entries,
                    "wiring": workload_yaml.get("wiring").cloned().unwrap_or(Value::Null),
                    "data": data_section.cloned().unwrap_or(Value::Null),
                }),
                &local_names,
                &local_claims,
                ProviderReach {
                    runtime,
                    caller: ProviderCaller::Workload,
                },
            ),
            &format!("workload {pi}: "),
        )?;
        // `wiring:` is the graph syntax: `module.port` (a bare `module` is
        // its first output in `from:`, its first input in `to:`), resolved
        // against the module's manifest. The node's network is the platform
        // provider a node graph names, `linux_net` (or `ip`), which a
        // workload does not declare: each module wired to it gets a lane of
        // its own, keyed in the order the wiring first names the module —
        // its edge from `linux_net.net_out` is the lane's events, its edge
        // to `linux_net.net_in` the lane's commands.
        let wiring = match workload_yaml.get("wiring") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(w)) => w.clone(),
            Some(_) => {
                return Err(Error::Config(format!(
                    "workload {pi}: `wiring` must be a list"
                )))
            }
        };
        let edges = workload_edges(pi, &wiring, &name_to_local, &local_names, &local_manifests)?;
        for e in &edges {
            // The domain check applies between two of the workload's
            // modules; a lane has no domain of its own.
            let (from_local, to_local) = match (e.from, e.to) {
                (graph::Endpoint::New(f), graph::Endpoint::New(t)) => (f, t),
                (graph::Endpoint::New(l), _) | (_, graph::Endpoint::New(l)) => (l, l),
                // Refused by `workload_edges`.
                _ => continue,
            };
            // Reject cross-domain workload edges. On bcm2712 a cross-domain
            // edge needs the SPSC bridge provisioned at boot (node-graph edges get
            // it before workload admission, bcm2712.rs); `apply_add` opens an
            // ordinary channel, so a cross-domain workload edge would silently lose
            // the bridge. Workload admission provisions none, so workload wiring
            // is intra-domain on every target (self-contained workloads).
            let from_dom = modules[from_local as usize].domain;
            let to_dom = modules[to_local as usize].domain;
            if from_dom != to_dom {
                return Err(Error::Config(format!(
                    "workload {pi}: edge {} -> {}: cross-domain edge (domain {from_dom} → {to_dom}) is \
                     not supported — a cross-domain edge needs an SPSC bridge, and workload \
                     admission provisions none (notably on bcm2712). Keep workload modules \
                     that are wired together in the same domain.",
                    local_names[from_local as usize], local_names[to_local as usize],
                )));
            }
        }
        // The kernel's lane rule, checked again on the encoded edges.
        crate::add_subgraph::check_net_lanes(&edges)
            .map_err(|why| Error::Config(format!("workload {pi}: {why}")))?;
        let state_cap = workload_yaml
            .get("state_cap")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let buffer_cap = workload_yaml
            .get("buffer_cap")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        // Idle-safe attestation: the operator asserts (workload-level
        // `idle_safe: true`) that this workload is demand-driven and may be parked when
        // idle. Absent/false ⇒ fail-closed: the kernel relaxes it to the `tick_max`
        // backstop cadence rather than parking it.
        let idle_safe = workload_yaml
            .get("idle_safe")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        // Composed as a node graph is, over the workload's own modules. A
        // node steps a workload's cycles in declaration order: a live add
        // carries no `accept_cycles`.
        let graph = crate::add_subgraph::compose(
            &modules,
            &edges,
            crate::add_subgraph::Placement {
                platform: crate::ring_demand::platform_of(runtime.unwrap_or("linux")),
                accept_cycles: true,
                domain_names: &[],
            },
            &crate::add_subgraph::Composer {
                describe: &|e| {
                    crate::ring_demand::refusal(
                        e,
                        &local_names,
                        &local_manifests,
                        runtime.unwrap_or("linux"),
                    )
                },
                fan_params: &|fan, scratch| fan_module_params(fan, scratch, &fan_manifests),
            },
        )
        .map_err(|why| Error::Config(format!("workload {pi}: {why}")))?;
        workloads.push(crate::add_subgraph::Workload {
            owner_uid,
            state_cap,
            buffer_cap,
            graph,
            idle_safe,
        });
    }
    Ok((workloads, demand, heaps))
}

/// The node's network as a workload's `wiring:` names it
/// ([`fluxor_tools::stack::WORKLOAD_NET_ENDS`]). A workload never declares
/// it: its modules reach the network through lanes of their own.
const WORKLOAD_NET_ENDS: &[&str] = fluxor_tools::stack::WORKLOAD_NET_ENDS;

/// One end of a workload wire as written.
enum WireEnd {
    /// One of the workload's modules, the port's index, and whether the
    /// port is a control input.
    Module(u8, u8, bool),
    /// The node's network.
    Net,
}

/// A workload's `wiring:` as the edges its graph carries. Ends are written as a
/// graph writes them — `module.port`, resolved against the module's
/// manifest, or a bare `module` (its first output in `from:`, first input
/// in `to:`). An end naming the node's network ([`WORKLOAD_NET_ENDS`]) is a
/// lane: every module wired to it gets one of its own, keyed in the order
/// the wiring first names the module, and is wired to it exactly once each
/// way — `linux_net.net_out -> <module>.<port>` (the lane's events) and
/// `<module>.<port> -> linux_net.net_in` (its commands).
fn workload_edges(
    pi: usize,
    wiring: &[Value],
    name_to_local: &HashMap<String, u8>,
    local_names: &[String],
    manifests: &HashMap<String, Manifest>,
) -> Result<Vec<graph::EdgeRecord>> {
    let mut lanes: Vec<u8> = Vec::new();
    let mut edges = Vec::new();
    for (ei, e) in wiring.iter().enumerate() {
        let at = |why: String| Error::Config(format!("workload {pi} wiring {ei}: {why}"));
        for key in ["from_port", "to_port"] {
            if e.get(key).is_some() {
                return Err(at(format!(
                    "`{key}` is not a wiring key: name the port as a graph does \
                     (`from: <module>.<port>`, `to: <module>.<port>`)"
                )));
            }
        }
        let end = |key: &str, is_from: bool| -> Result<WireEnd> {
            let spec = e
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| at(format!("`{key}` must be `<module>.<port>` or `<module>`")))?;
            if spec.starts_with("net:") {
                return Err(at(format!(
                    "`{spec}`: the node's network is the platform's `linux_net` — wire \
                     `linux_net.net_out` to the module's input and its output to \
                     `linux_net.net_in`; each module wired so gets a lane of its own"
                )));
            }
            let module = spec.split('.').next().unwrap_or(spec).trim();
            if let Some(&local) = name_to_local.get(module) {
                let (_, direction, index) =
                    resolve_port_spec(spec, is_from, manifests, local_names)
                        .map_err(|why| at(format!("{key} `{spec}`: {why}")))?;
                if index > graph::MAX_PORT_INDEX {
                    return Err(at(format!(
                        "{key} `{spec}`: port index {index} is past what an edge carries"
                    )));
                }
                return Ok(WireEnd::Module(local, index, !is_from && direction == 2));
            }
            if WORKLOAD_NET_ENDS.contains(&module) {
                let port = spec.split_once('.').map(|(_, p)| p.trim());
                let lane_port = if is_from { "net_out" } else { "net_in" };
                if port.is_some_and(|p| p != lane_port) {
                    return Err(at(format!(
                        "{key} `{spec}`: a workload reaches the node's network through its lane \
                         alone — `{module}.net_out` in `from:`, `{module}.net_in` in `to:`"
                    )));
                }
                return Ok(WireEnd::Net);
            }
            let hint = crate::target::closest_match(module, local_names, 3)
                .map(|s| format!(" Did you mean '{s}'?"))
                .unwrap_or_default();
            Err(at(format!(
                "{key} `{spec}`: unknown module `{module}`.{hint} A workload's wiring names \
                 its own modules, and the node's network as `linux_net` (cross-workload \
                 edges are not supported — workloads are self-contained)"
            )))
        };
        let from = end("from", true)?;
        let to = end("to", false)?;
        let mut lane = |local: u8| -> Result<u8> {
            let key = match lanes.iter().position(|&l| l == local) {
                Some(k) => k,
                None => {
                    lanes.push(local);
                    lanes.len() - 1
                }
            };
            u8::try_from(key)
                .map_err(|_| at("more than 256 modules are wired to the node's network".into()))
        };
        let local = |i: u8| graph::Endpoint::New(u16::from(i));
        let (from, from_port, to, to_port, to_ctrl) = match (from, to) {
            (WireEnd::Module(f, fp, _), WireEnd::Module(t, tp, ctrl)) => {
                (local(f), fp, local(t), tp, ctrl)
            }
            (WireEnd::Net, WireEnd::Module(t, tp, ctrl)) => {
                (graph::Endpoint::Net(lane(t)?), 0, local(t), tp, ctrl)
            }
            (WireEnd::Module(f, fp, _), WireEnd::Net) => {
                (local(f), fp, graph::Endpoint::Net(lane(f)?), 0, false)
            }
            (WireEnd::Net, WireEnd::Net) => {
                return Err(at(
                    "the node's network connects to a module of the workload, not to itself".into(),
                ))
            }
        };
        edges.push(graph::EdgeRecord {
            from,
            from_port,
            to,
            to_port,
            to_ctrl,
            buffer_bytes: e.get("buffer_bytes").and_then(Value::as_u64).unwrap_or(0) as u32,
            ..graph::EdgeRecord::default()
        });
    }
    // The kernel's lane rule, said of the module it binds: one edge each
    // way between a module and the network.
    for (key, &local) in lanes.iter().enumerate() {
        let k = graph::Endpoint::Net(key as u8);
        let into = edges.iter().filter(|x| x.to == k).count();
        let out = edges.iter().filter(|x| x.from == k).count();
        if into != 1 || out != 1 {
            let m = &local_names[local as usize];
            return Err(Error::Config(format!(
                "workload {pi}: `{m}` is wired to the node's network {into} time(s) toward it and \
                 {out} time(s) from it; a module's lane is exactly one of each \
                 (`{m}.<port> -> linux_net.net_in`, `linux_net.net_out -> {m}.<port>`)"
            )));
        }
    }
    Ok(edges)
}
/// YAML keys a node-graph module turns into node tags (the params TLV's
/// trust class, protection level, device window, ISR budget, IRQ, quarantine
/// partner and restart settings), or that would emit one (`voices:` packs
/// each voice under tag 0xFD, the device-window tag). A workload module runs
/// for its own owner: these grants are the node's to make, and a node
/// refuses a workload module whose params carry any of them. `irq` is a
/// node key only when the module's schema has no `irq` param of its own.
const WORKLOAD_NODE_KEYS: &[&str] = &[
    "trust_class",
    "protection",
    "device_window",
    "isr_budget_cycles",
    "irq",
    "quarantine_partner",
    "quarantine_partner_idx",
    "max_restarts",
    "restart_backoff_ms",
    "voices",
];

/// A workload module's or a fan's `heap:` keys as params TLV entries (0xF8
/// zero on free, 0xF9 fault on alloc failure, 0xFA canary, 0xEF the
/// instance's heap cap, 0xEE a heap committed whole: `declares_raw_arena`), with the node graph's
/// validation and encoding, inserted before the TLV's end marker. A module
/// with no schema params gets a TLV of its own for them. The heap cap is the
/// node graph's too: `heap.arena_bytes`, else what the type's `[capacities]
/// heap_from_params`, `heap_per_demand` and `heap_per_param` rules derive
/// (`instance_heap_cap`).
pub(crate) fn insert_heap_tags(
    params: Vec<u8>,
    module: &Value,
    mname: &str,
    manifest: Option<&Manifest>,
    plan: &HeapPlan,
) -> Result<Vec<u8>> {
    validate_heap_subtree(module, mname)?;
    let heap = module.get("heap");
    let flag = |key: &str| heap.and_then(|h| h.get(key));
    let mut entries = Vec::new();
    if let Some(v) = flag("zero_on_free").and_then(|v| v.as_bool()) {
        entries.extend_from_slice(&[0xF8, 1, u8::from(v)]);
    }
    if flag("alloc_failure_policy").and_then(|v| v.as_str()) == Some("fault") {
        entries.extend_from_slice(&[0xF9, 1, 1]);
    }
    if flag("canary_enabled").and_then(|v| v.as_bool()) == Some(true) {
        entries.extend_from_slice(&[0xFA, 1, 1]);
    }
    if let Some(n) = instance_heap_cap(mname, module, manifest, &params, plan)? {
        entries.extend_from_slice(&[0xEF, 4]);
        entries.extend_from_slice(&n.to_le_bytes());
    }
    if declares_raw_arena(module, manifest) {
        entries.extend_from_slice(&[0xEE, 1, 1]);
    }
    if entries.is_empty() {
        return Ok(params);
    }
    let mut params = if params.is_empty() {
        vec![0xFE, 0x01, 2, 0, 0xFF, 0x00]
    } else {
        params
    };
    // The end marker: the first `0xFF` tag of the TLV walk.
    let Some(pos) = schema::tlv_basic_end(&params).map(|end| end - 2) else {
        return Err(Error::Config(format!(
            "module '{mname}': its params are not a TLV the heap flags can join"
        )));
    };
    // The header's length runs to the byte past the end marker, saturating
    // past 64 KiB (readers walk to the terminator).
    let len = schema::tlv_payload_len_field(pos + 2 + entries.len() - 4);
    params.splice(pos..pos, entries);
    params[2..4].copy_from_slice(&len);
    Ok(params)
}

/// Refuse a workload module that declares a [`WORKLOAD_NODE_KEYS`] key.
fn refuse_workload_node_keys(
    module: &Value,
    param_schema: Option<&schema::ParamSchema>,
    pi: usize,
    mname: &str,
) -> Result<()> {
    for key in WORKLOAD_NODE_KEYS {
        let Some(v) = module.get(*key) else {
            continue;
        };
        if v.is_null() {
            continue;
        }
        if *key == "irq" && param_schema.is_some_and(|s| s.find("irq").is_some()) {
            continue;
        }
        let why = match *key {
            "voices" => {
                "voice presets are packed under params tag 0xFD, the device-window tag, \
                         which a node refuses in a workload"
            }
            "max_restarts" | "restart_backoff_ms" => {
                "a workload module's fault policy is skip or tolerate, and neither restarts"
            }
            _ => "it is a grant of the node's, which only the node's own graph makes",
        };
        return Err(Error::Config(format!(
            "workload {pi} module '{mname}': `{key}` is not available to a workload module: {why}"
        )));
    }
    Ok(())
}

/// Assign buffer group IDs for aliasable edge chains.
///
/// Identifies linear chains of edges where intermediate modules are in-place-safe
/// (single data input, single data output, marked in_place_safe in .fmod header).
/// Edges in the same chain get the same non-zero group ID, enabling the scheduler
/// to alias them to the same channel buffer at runtime.
///
/// Returns a Vec of group IDs parallel to the edges slice. Group 0 = no aliasing.
/// Which modules, by index, run at a gated level on this target.
fn gated_modules(
    config: &Value,
    module_names: &[String],
    levels: &[crate::protection::Level],
) -> Vec<bool> {
    let entries = crate::protection::module_entries(config);
    module_names
        .iter()
        .map(|name| {
            entries
                .iter()
                .find(|(_, m)| m.get("name").and_then(|n| n.as_str()) == Some(name.as_str()))
                .and_then(|(_, m)| crate::protection::resolve(m, config, levels).ok())
                .is_some_and(|r| r.provided.is_gated())
        })
        .collect()
}

/// A gated module reaches channels only through the gateway, which copies,
/// so no zero-copy (buffer-group) edge may touch one: the kernel refuses such
/// a graph at load. A group the auto-assign pass formed is an optimisation
/// and is dropped whole; a `buffer_group:` the graph wrote is refused.
fn ungroup_gated_edges(
    edges: &[(u16, u16, u8, u8, u8)],
    groups: &mut [u8],
    explicit: &[bool],
    gated: &[bool],
    module_names: &[String],
) -> Result<()> {
    let is_gated = |id: u16| gated.get(id as usize).copied().unwrap_or(false);
    let mut dropped = [false; 32];
    for (i, &(from, to, ..)) in edges.iter().enumerate() {
        let g = groups[i];
        if g == 0 || !(is_gated(from) || is_gated(to)) {
            continue;
        }
        if explicit[i] {
            let m = if is_gated(from) { from } else { to };
            return Err(Error::Config(format!(
                "wiring[{i}]: buffer_group {g} makes a zero-copy edge at gated module '{}'; a \
                 gated module reaches channels only through the gateway, which copies",
                module_names
                    .get(m as usize)
                    .map(String::as_str)
                    .unwrap_or("?")
            )));
        }
        dropped[g as usize & 31] = true;
    }
    for (i, g) in groups.iter_mut().enumerate() {
        if *g != 0 && dropped[*g as usize & 31] && !explicit[i] {
            *g = 0;
        }
    }
    Ok(())
}

/// Give every framed edge the wiring left ungrouped a mailbox group of its own.
///
/// A framed content type carries whole records, and only a mailbox channel
/// delivers a record whole: a byte FIFO can hand the consumer part of one. The
/// content type already says which edges those are, so the graph does not —
/// each such edge gets a group nobody else uses, numbered down from the top of
/// the 5-bit range so it never meets the in-place chain groups
/// [`assign_buffer_groups`] numbers up from 1. A group the wiring names is kept.
fn group_framed_edges(
    config: &Value,
    edges: &[(u16, u16, u8, u8, u8)],
    module_names: &[String],
    manifests: &HashMap<String, Manifest>,
) -> Result<Value> {
    const GROUP_MAX: u64 = 31;
    let mut out = config.clone();
    let Some(wiring) = out.get_mut("wiring").and_then(|w| w.as_array_mut()) else {
        return Ok(out);
    };
    let mut used = [false; GROUP_MAX as usize + 1];
    for entry in wiring.iter() {
        if let Some(g) = entry.get("buffer_group").and_then(|v| v.as_u64()) {
            if g <= GROUP_MAX {
                used[g as usize] = true;
            }
        }
    }
    let mut next = GROUP_MAX;
    for (i, edge) in edges.iter().enumerate() {
        let Some(entry) = wiring.get_mut(i) else {
            continue;
        };
        let grouped = entry
            .get("buffer_group")
            .and_then(|v| v.as_u64())
            .is_some_and(|g| g != 0);
        if grouped || edge_framed_type(edge, module_names, manifests).is_none() {
            continue;
        }
        while next > 0 && used[next as usize] {
            next -= 1;
        }
        if next == 0 {
            return Err(Error::Config(format!(
                "wiring[{i}]: more record-carrying edges than the {GROUP_MAX} mailbox \
                 groups a graph has"
            )));
        }
        used[next as usize] = true;
        if let Some(map) = entry.as_object_mut() {
            map.insert("buffer_group".into(), Value::from(next));
        }
    }
    Ok(out)
}

fn assign_buffer_groups(
    edges: &[(u16, u16, u8, u8, u8)],
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
    let is_chain_interior_capable = |module_id: u16| -> bool {
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

    // Count data edges per module. An edge is a data edge when it lands on
    // a data input (`to_port == 0`); the same edge is the producer's data
    // output. A control or status edge leaving a module is not a second
    // data output, so it must not stop that module from being a chain
    // interior — and, equally, wiring an unrelated consumer to a module's
    // status port must not change how its data edges are aliased.
    let num_modules = module_names.len();
    let mut data_in_count = vec![0u8; num_modules];
    let mut data_out_count = vec![0u8; num_modules];
    for (from_id, to_id, to_port, _, _) in edges {
        if *to_port != 0 {
            continue;
        }
        let to = *to_id as usize;
        if to < num_modules {
            data_in_count[to] = data_in_count[to].saturating_add(1);
        }
        let from = *from_id as usize;
        if from < num_modules {
            data_out_count[from] = data_out_count[from].saturating_add(1);
        }
    }

    // Chain interior: 1-in, 1-out, mailbox_safe AND in_place_writer.
    // These modules read+write the same aliased buffer via acquire_inplace.
    let is_chain_interior = |module_id: u16| -> bool {
        let idx = module_id as usize;
        idx < num_modules
            && data_in_count[idx] == 1
            && data_out_count[idx] == 1
            && is_chain_interior_capable(module_id)
    };

    // Find the single data-out edge of a module.
    let find_out_edge = |module_id: u16| -> Option<usize> {
        edges
            .iter()
            .position(|(from_id, _, to_port, _, _)| *from_id == module_id && *to_port == 0)
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
        // A module with no manifest has no `provides` list to check against.
    }

    Ok(())
}

#[cfg(test)]
mod buffer_group_tests {
    use super::*;

    fn caps(name: &str, in_place: bool) -> ModuleCaps {
        ModuleCaps {
            name: name.into(),
            mailbox_safe: in_place,
            in_place_writer: in_place,
            manifest: crate::manifest::Manifest::default(),
        }
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// src → filter → sink, with `filter` in-place: both data edges alias.
    #[test]
    fn a_one_in_one_out_in_place_module_aliases_its_edges() {
        let names = names(&["src", "filter", "sink"]);
        let caps = vec![
            caps("src", false),
            caps("filter", true),
            caps("sink", false),
        ];
        let edges = [(0u16, 1u16, 0u8, 0u8, 0u8), (1, 2, 0, 0, 0)];
        let groups = assign_buffer_groups(&edges, &names, &caps).unwrap();
        assert_eq!(groups, vec![1, 1]);
    }

    /// A status edge leaving the in-place module is not a second data
    /// output: the data edges still alias, and the status edge does not.
    #[test]
    fn a_control_edge_out_of_the_interior_does_not_break_the_chain() {
        let names = names(&["src", "filter", "sink", "monitor"]);
        let caps = vec![
            caps("src", false),
            caps("filter", true),
            caps("sink", false),
            caps("monitor", false),
        ];
        let edges = [
            (1u16, 3u16, 1u8, 1u8, 0u8),
            (0, 1, 0, 0, 0),
            (1, 2, 0, 0, 0),
        ];
        let groups = assign_buffer_groups(&edges, &names, &caps).unwrap();
        assert_eq!(groups, vec![0, 1, 1]);
    }

    /// Two data outputs is a fan-out, never an in-place interior.
    #[test]
    fn a_second_data_output_disqualifies_the_interior() {
        let names = names(&["src", "filter", "a", "b"]);
        let caps = vec![
            caps("src", false),
            caps("filter", true),
            caps("a", false),
            caps("b", false),
        ];
        let edges = [
            (0u16, 1u16, 0u8, 0u8, 0u8),
            (1, 2, 0, 0, 0),
            (1, 3, 0, 1, 0),
        ];
        let groups = assign_buffer_groups(&edges, &names, &caps).unwrap();
        assert_eq!(groups, vec![0, 0, 0]);
    }
}
