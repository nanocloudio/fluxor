/// Validate the optional top-level `presentation_groups` block. Members,
/// clock authority, and policy fields are checked against the manifest
/// capabilities of each named module. Presentation groups are
/// compile-time only — there is no binary representation in the
/// compiled config.
///
/// Schema and capability semantics live in
/// `docs/architecture/av_capability_surface.md`. In short:
///
/// ```yaml
/// presentation_groups:
///   - id: living_room
///     clock_authority: hdmi_audio
///     members: [hdmi_audio, lcd_panel]
///     latency_budget_ms: 40
///     skew_budget_ms: 8
///     cutover_policy: boundary_cut
///     continuity_policy: drain
///     mirror_policy: independent
///     protected: false
///     multihead: false
/// ```
pub fn validate_presentation_groups(
    config: &Value,
    module_names: &[String],
    manifests: &HashMap<String, Manifest>,
) -> Result<()> {
    let groups = match config.get("presentation_groups") {
        Some(v) => v,
        None => return Ok(()),
    };
    let list = groups
        .as_array()
        .ok_or_else(|| Error::Config("presentation_groups must be a list".into()))?;

    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (gi, g) in list.iter().enumerate() {
        let id = g
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Error::Config(format!(
                    "presentation_groups[{gi}]: required field `id` missing"
                ))
            })?
            .to_string();
        if !seen_ids.insert(id.clone()) {
            return Err(Error::Config(format!(
                "presentation_groups: duplicate id `{id}`"
            )));
        }

        let clock_authority = g
            .get("clock_authority")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Error::Config(format!(
                    "presentation_group `{id}`: required field `clock_authority` missing"
                ))
            })?
            .to_string();

        let members_raw = g.get("members").and_then(|v| v.as_array()).ok_or_else(|| {
            Error::Config(format!(
                "presentation_group `{id}`: required field `members` missing"
            ))
        })?;
        let mut members: Vec<String> = Vec::with_capacity(members_raw.len());
        for (mi, raw) in members_raw.iter().enumerate() {
            let s = raw.as_str().ok_or_else(|| {
                Error::Config(format!(
                    "presentation_group `{}`: members[{}] must be a string (got {})",
                    id,
                    mi,
                    json_kind(raw)
                ))
            })?;
            members.push(s.to_string());
        }
        if members.is_empty() {
            return Err(Error::Config(format!(
                "presentation_group `{id}`: `members` is empty"
            )));
        }
        for m in &members {
            if !module_names.iter().any(|n| n == m) {
                return Err(Error::Config(format!(
                    "presentation_group `{id}`: unknown member `{m}`"
                )));
            }
        }
        if !members.iter().any(|m| m == &clock_authority) {
            return Err(Error::Config(format!(
                "presentation_group `{id}`: clock_authority `{clock_authority}` is not in members {members:?}"
            )));
        }

        let manifest_caps = |name: &str| -> &[String] {
            manifests
                .get(name)
                .map(|m| m.capabilities.as_slice())
                .unwrap_or(&[])
        };
        let has_cap = |caps: &[String], wanted: &str| -> bool { caps.iter().any(|c| c == wanted) };
        let has_any_cap = |caps: &[String], wanted: &[&str]| -> bool {
            caps.iter().any(|c| wanted.contains(&c.as_str()))
        };

        if !has_cap(manifest_caps(&clock_authority), "presentation.clock") {
            return Err(Error::Config(format!(
                "presentation_group `{id}`: clock_authority `{clock_authority}` does not declare \
                 capability `presentation.clock` (add it to the module's manifest, \
                 or pick an authority that does)"
            )));
        }

        if let Some(cp) = g.get("cutover_policy").and_then(|v| v.as_str()) {
            check_enum("cutover_policy", cp, CUTOVER_POLICIES, &id)?;
        }
        if let Some(cp) = g.get("continuity_policy").and_then(|v| v.as_str()) {
            check_enum("continuity_policy", cp, CONTINUITY_POLICIES, &id)?;
        }
        if let Some(mp) = g.get("mirror_policy").and_then(|v| v.as_str()) {
            check_enum("mirror_policy", mp, MIRROR_POLICIES, &id)?;
        }

        // Protected playback: every audio sink must declare
        // `audio.output.protected`; every video sink must declare either
        // `display.scanout.protected` or `video.decode.protected`. A
        // protected path is end-to-end or it isn't a protected path.
        if g.get("protected")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            for m in &members {
                let caps = manifest_caps(m);
                if has_any_cap(caps, AUDIO_SINK_CAPS) && !has_cap(caps, "audio.output.protected") {
                    return Err(Error::Config(format!(
                        "presentation_group `{id}`: protected=true but audio member \
                         `{m}` does not declare `audio.output.protected`"
                    )));
                }
                if has_any_cap(caps, VIDEO_SINK_CAPS) && !has_any_cap(caps, VIDEO_PROTECTED_CAPS) {
                    return Err(Error::Config(format!(
                        "presentation_group `{id}`: protected=true but video member \
                         `{m}` does not declare `display.scanout.protected` or \
                         `video.decode.protected`"
                    )));
                }
            }
        }

        // Multihead: at least two members must be independently bindable
        // paced display outputs.
        if g.get("multihead")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            let scanout_count = members
                .iter()
                .filter(|m| has_cap(manifest_caps(m), "display.scanout"))
                .count();
            if scanout_count < 2 {
                return Err(Error::Config(format!(
                    "presentation_group `{id}`: multihead=true but only {scanout_count} member(s) \
                     declare `display.scanout` (need ≥2)"
                )));
            }
        }

        for k in &["latency_budget_ms", "skew_budget_ms"] {
            if let Some(v) = g.get(*k) {
                let n = v.as_u64().ok_or_else(|| {
                    Error::Config(format!(
                        "presentation_group `{id}`: `{k}` must be an unsigned integer (ms)"
                    ))
                })?;
                if n > MAX_PRESENTATION_BUDGET_MS {
                    return Err(Error::Config(format!(
                        "presentation_group `{id}`: `{k}` = {n} ms exceeds the {MAX_PRESENTATION_BUDGET_MS} ms \
                         sanity bound (typical lip-sync budgets are ≤ 100 ms)"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// True when a module's declared capability satisfies `wanted` under
/// the parent-matches-child rule (`capability_surface.md`): an exact
/// match, or a declared child of the wanted parent
/// (`transport.anchor.stream` satisfies `transport.anchor`). The
/// reverse never holds, and `.secure` variants are ordinary children —
/// security orthogonality is enforced by *which* name is wanted.
fn cap_satisfies(declared: &str, wanted: &str) -> bool {
    declared == wanted
        || (declared.len() > wanted.len()
            && declared.starts_with(wanted)
            && declared.as_bytes()[wanted.len()] == b'.')
}

/// Validate the optional top-level `continuity` block — session
/// continuity classes as a validated graph property (rfc_protocols.md
/// §7.3; `protocol_surfaces.md` §Continuity Classes). Compile-time
/// only; no binary representation in the compiled config.
///
/// ```yaml
/// continuity:
///   - id: echo_edge
///     class: edge_anchored          # one of the five classes
///     anchor: echo_anchor           # module owning client transport
///     workers: [echo_worker]        # movable session workers
///     directory: session_dir        # placement metadata service
///     # transport_migratable only:
///     mechanism: platform_replicated_state
///     aead: on_wire_sequence        # platform_replicated_state only
///     failover_budget_ms: 8000      # declared worst-case sum (§12.4)
///     client_keepalive_ms: 20000    # deployed client's timeout
/// ```
///
/// The checks are *structural* (§7.3): the required roles and
/// capabilities exist in the graph. What cannot be checked here —
/// whether the failover budget actually fits under the client
/// keepalive at runtime, or whether R1–R5 hold under fault — is a
/// measured/tested gate, not a static one. The validator still rejects
/// a declared budget that is not below the declared keepalive, since a
/// declaration that fails on its own constants cannot pass measurement.
pub fn validate_continuity(
    config: &Value,
    module_names: &[String],
    manifests: &HashMap<String, Manifest>,
) -> Result<()> {
    let block = match config.get("continuity") {
        Some(v) => v,
        None => return Ok(()),
    };
    let list = block
        .as_array()
        .ok_or_else(|| Error::Config("continuity must be a list".into()))?;

    let manifest_caps = |name: &str| -> &[String] {
        manifests
            .get(name)
            .map(|m| m.capabilities.as_slice())
            .unwrap_or(&[])
    };
    let module_has = |name: &str, wanted: &str| -> bool {
        manifest_caps(name).iter().any(|c| cap_satisfies(c, wanted))
    };
    let graph_has = |wanted: &str| -> bool { module_names.iter().any(|m| module_has(m, wanted)) };

    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (gi, g) in list.iter().enumerate() {
        let id = g
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Config(format!("continuity[{gi}]: required field `id` missing")))?
            .to_string();
        if !seen_ids.insert(id.clone()) {
            return Err(Error::Config(format!("continuity: duplicate id `{id}`")));
        }
        let err = |msg: String| Error::Config(format!("continuity `{id}`: {msg}"));

        let class = g
            .get("class")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err("required field `class` missing".into()))?;
        if !CONTINUITY_CLASSES.contains(&class) {
            return Err(err(format!(
                "class `{}` is invalid (expected {})",
                class,
                CONTINUITY_CLASSES.join(" | ")
            )));
        }

        // Member resolution — every named module must exist.
        let anchor = g.get("anchor").and_then(|v| v.as_str());
        let directory = g.get("directory").and_then(|v| v.as_str());
        let workers: Vec<&str> = g
            .get("workers")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|w| w.as_str()).collect())
            .unwrap_or_default();
        for m in anchor.iter().chain(directory.iter()).chain(workers.iter()) {
            if !module_names.iter().any(|n| n == m) {
                return Err(err(format!("unknown module `{m}`")));
            }
        }

        // Mechanism / AEAD fields only mean something on
        // transport_migratable — a declaration on a weaker class is a
        // mis-statement, not decoration (selection policy §9.5).
        let mechanism = g.get("mechanism").and_then(|v| v.as_str());
        let aead = g.get("aead").and_then(|v| v.as_str());
        if class != "transport_migratable" {
            if mechanism.is_some() {
                return Err(err(format!(
                    "`mechanism` is only valid with class transport_migratable (class is `{class}`)"
                )));
            }
            if aead.is_some() {
                return Err(err(format!(
                    "`aead` is only valid with class transport_migratable (class is `{class}`)"
                )));
            }
        }

        match class {
            // No structural obligations: flows may drop / drain.
            "reroutable" | "drain_only" => {}

            // §7.3: resumption state must exist somewhere in the
            // declared member set.
            "resumable" => {
                let members: Vec<&str> = anchor.iter().chain(workers.iter()).copied().collect();
                if members.is_empty() {
                    return Err(err(
                        "class resumable needs at least one member (`anchor` or `workers`) \
                         declaring `session.resume`"
                            .into(),
                    ));
                }
                if !members.iter().any(|m| module_has(m, "session.resume")) {
                    return Err(err(
                        "class resumable but no declared member provides `session.resume`".into(),
                    ));
                }
            }

            // §7.3: a transport anchor must exist; workers are the
            // movable half and must be declared as such. With more
            // than one worker (a swap target) the workers must also
            // support opaque export/import handoff (§13.1).
            "edge_anchored" => {
                let a = anchor
                    .ok_or_else(|| err("class edge_anchored requires an `anchor` module".into()))?;
                if !module_has(a, "transport.anchor") {
                    return Err(err(format!(
                        "anchor `{a}` does not declare a `transport.anchor.*` capability \
                         (add it to the module's manifest, or pick a module that does)"
                    )));
                }
                if workers.is_empty() {
                    return Err(err(
                        "class edge_anchored requires at least one `workers` entry".into(),
                    ));
                }
                for w in &workers {
                    if !module_has(w, "session.worker") {
                        return Err(err(format!(
                            "worker `{w}` does not declare `session.worker`"
                        )));
                    }
                }
                if workers.len() > 1 {
                    for w in &workers {
                        if !module_has(w, "session.handoff") {
                            return Err(err(format!(
                                "multiple workers declared (anchor-preserved swap) but worker \
                                 `{w}` does not declare `session.handoff`"
                            )));
                        }
                    }
                }
            }

            // §7.3: the mechanism decides the obligations.
            "transport_migratable" => {
                let mech = mechanism.ok_or_else(|| {
                    err(format!(
                        "class transport_migratable requires `mechanism` (one of {})",
                        MIGRATION_MECHANISMS.join(" | ")
                    ))
                })?;
                if !MIGRATION_MECHANISMS.contains(&mech) {
                    return Err(err(format!(
                        "mechanism `{}` is invalid (expected {})",
                        mech,
                        MIGRATION_MECHANISMS.join(" | ")
                    )));
                }
                match mech {
                    "native_primitive" => {
                        // The wire protocol itself carries migration —
                        // a natively-migratable mux transport must be
                        // present (e.g. transport.mux.quic).
                        if !graph_has("transport.mux") {
                            return Err(err(
                                "mechanism native_primitive but no module in the graph \
                                 provides a `transport.mux.*` transport"
                                    .into(),
                            ));
                        }
                    }
                    "platform_replicated_state" => {
                        // AEAD class decides whether the class is even
                        // reachable (§13.7.2): implicit-contiguous
                        // counters cannot skip forward — their honest
                        // ceiling is resumable-with-seamless-state.
                        let ac = aead.ok_or_else(|| {
                            err(format!(
                                "mechanism platform_replicated_state requires `aead` \
                                 (one of {})",
                                AEAD_CLASSES.join(" | ")
                            ))
                        })?;
                        if !AEAD_CLASSES.contains(&ac) {
                            return Err(err(format!(
                                "aead `{}` is invalid (expected {})",
                                ac,
                                AEAD_CLASSES.join(" | ")
                            )));
                        }
                        if ac == "implicit_counter" {
                            return Err(err(
                                "aead implicit_counter cannot reach transport_migratable: \
                                 an implicit-contiguous AEAD counter cannot skip forward on \
                                 takeover (rfc_protocols.md §13.7.2). Declare class \
                                 `resumable` — seamless-state resume is this transport's \
                                 honest ceiling"
                                    .into(),
                            ));
                        }

                        // Anchor + single-writer directory are the
                        // mechanism's backbone.
                        let a = anchor.ok_or_else(|| {
                            err("platform_replicated_state requires an `anchor` module".into())
                        })?;
                        if !module_has(a, "transport.anchor.datagram") {
                            return Err(err(format!(
                                "anchor `{a}` does not declare `transport.anchor.datagram` \
                                 (platform-replicated-state migration is defined for \
                                 fully-owned datagram transports)"
                            )));
                        }
                        let d = directory.ok_or_else(|| {
                            err("platform_replicated_state requires a `directory` module \
                                 (single-writer authority per session generation)"
                                .into())
                        })?;
                        if !module_has(d, "session.directory") {
                            return Err(err(format!(
                                "directory `{d}` does not declare `session.directory`"
                            )));
                        }

                        // §9.2 / §13.7.6 structural requirements R1–R5.
                        for cap in PRS_REQUIRED_CAPS {
                            if !graph_has(cap) {
                                return Err(err(format!(
                                    "platform_replicated_state requires a `{cap}` provider \
                                     in the graph (rfc_protocols.md §13.7.6); without it the \
                                     honest class is resumable"
                                )));
                            }
                        }

                        // §12.4: the budget is declared here and PROVEN
                        // by measurement (Phase 7 failover-latency test).
                        // A declaration that fails on its own constants
                        // can be rejected statically.
                        let budget = g
                            .get("failover_budget_ms")
                            .and_then(|v| v.as_u64())
                            .ok_or_else(|| {
                                err("platform_replicated_state requires \
                                         `failover_budget_ms` (declared worst-case \
                                         detect+fence+VIP-move+resume sum, §12.4)"
                                    .into())
                            })?;
                        let keepalive = g
                            .get("client_keepalive_ms")
                            .and_then(|v| v.as_u64())
                            .ok_or_else(|| {
                                err("platform_replicated_state requires \
                                     `client_keepalive_ms` (the deployed client's \
                                     transport timeout, §12.4)"
                                    .into())
                            })?;
                        if budget >= keepalive {
                            return Err(err(format!(
                                "failover_budget_ms ({budget}) must be strictly below \
                                 client_keepalive_ms ({keepalive}) — a budget that does not \
                                 fit under the client's timeout cannot deliver invisible \
                                 failover; declare class resumable instead"
                            )));
                        }
                    }
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }
    Ok(())
}

/// Compose a clear "unknown module in wiring" error. For logical sink
/// names that the platform stack would normally provide, hint at the
/// missing `platform.<stack>:` block instead of leaving the developer
/// to guess. For everything else, run a Levenshtein lookup against
/// the declared module list — the most common cause is a typo (e.g.
/// `wiring: [from: my_modul.out]` against `name: my_module`).
fn unknown_module_in_wiring(name: &str, declared_names: &[String]) -> String {
    let stack_hint = match name {
        "display" => Some("did you forget `platform.display:` in your config?".to_string()),
        "audio_out" => Some("did you forget `platform.audio:` in your config?".to_string()),
        _ => None,
    };
    let typo_hint = crate::target::closest_match(name, declared_names, 3)
        .map(|s| format!("did you mean '{s}'?"));
    let hints: Vec<String> = stack_hint.into_iter().chain(typo_hint).collect();
    if hints.is_empty() {
        format!("Unknown module in wiring: {name}")
    } else {
        format!("Unknown module in wiring: {name} ({})", hints.join("; "))
    }
}

/// One entry per wire: `(from_id, to_id, to_port, from_port_index, to_port_index)`.
/// `to_port`: 0 = data input, 1 = control input.
type WireTuple = (u8, u8, u8, u8, u8);

/// Result bundle from `parse_wiring_edges`: tuples, force flags,
/// and the original source/destination spec strings (parallel arrays).
type WiringEdges = (Vec<WireTuple>, Vec<bool>, Vec<String>, Vec<String>);

/// Parse wiring edges from YAML config.
/// Supports indexed port syntax: "bank.out[1]" → from_port_index=1
/// Supports named port syntax: "http.net_out" → resolves via manifest
fn parse_wiring_edges(
    wiring: &Value,
    names: &[String],
    manifests: &HashMap<String, Manifest>,
) -> Result<WiringEdges> {
    let list = wiring
        .as_array()
        .ok_or_else(|| Error::Config("wiring must be a list".into()))?;

    let mut edges = Vec::new();
    let mut force_flags = Vec::new();
    let mut from_specs = Vec::new();
    let mut to_specs = Vec::new();

    for w in list {
        let from = w["from"].as_str().unwrap_or("");
        let to = w["to"].as_str().unwrap_or("");
        let force = w["force"].as_bool().unwrap_or(false);

        let (from_name, _from_port_type, from_port_index) =
            resolve_port_spec(from, true, manifests, names)
                .map_err(|e| Error::Config(format!("wiring from '{from}': {e}")))?;
        let (to_name, to_port_type, to_port_index) = resolve_port_spec(to, false, manifests, names)
            .map_err(|e| Error::Config(format!("wiring to '{to}': {e}")))?;

        // Map destination port type to wire format: in(0)→0, ctrl(2)→1
        let to_port = if to_port_type == 2 { 1u8 } else { 0u8 };

        let from_id = names
            .iter()
            .position(|n| n == from_name)
            .ok_or_else(|| Error::Config(unknown_module_in_wiring(from_name, names)))?
            as u8;
        let to_id = names
            .iter()
            .position(|n| n == to_name)
            .ok_or_else(|| Error::Config(unknown_module_in_wiring(to_name, names)))?
            as u8;

        edges.push((from_id, to_id, to_port, from_port_index, to_port_index));
        force_flags.push(force);
        from_specs.push(from.to_string());
        to_specs.push(to.to_string());
    }
    Ok((edges, force_flags, from_specs, to_specs))
}

/// Validate GPIO pin number against target's max_gpio.
fn validate_gpio_pin(pin: u64, context: &str, max_gpio: u8) -> Result<u8> {
    if pin >= max_gpio as u64 {
        return Err(Error::Config(format!(
            "{}: GPIO pin {} out of range (0-{})",
            context,
            pin,
            max_gpio - 1
        )));
    }
    Ok(pin as u8)
}

/// Build hardware section binary
///
/// Format (must match firmware config.rs parse_hardware_section):
/// - spi_count (u8)
/// - i2c_count (u8)
/// - gpio_count (u8)
/// - pio_count (u8)
/// - spi_configs[spi_count] (8 bytes each): bus, miso, mosi, sck, freq_hz(u32)
/// - i2c_configs[i2c_count] (8 bytes each): bus, sda, scl, reserved, freq_hz(u32)
/// - gpio_configs[gpio_count] (5 bytes each): pin, flags, initial, owner_module_id, reserved
/// - pio_configs[pio_count] (4 bytes each): pio_idx, data_pin, clk_pin, extra_pin
fn build_hardware_section(
    hardware: &Value,
    module_names: &[String],
    max_gpio: u8,
    pio_count: u8,
) -> Result<Vec<u8>> {
    let mut result = Vec::new();

    let spi_configs = hardware["spi"]
        .as_array()
        .map(|a| a.to_vec())
        .unwrap_or_default();
    let i2c_configs = hardware["i2c"]
        .as_array()
        .map(|a| a.to_vec())
        .unwrap_or_default();
    let uart_configs = hardware["uart"]
        .as_array()
        .map(|a| a.to_vec())
        .unwrap_or_default();
    let gpio_configs = hardware["gpio"]
        .as_array()
        .map(|a| a.to_vec())
        .unwrap_or_default();
    let pio_configs = hardware["pio"]
        .as_array()
        .map(|a| a.to_vec())
        .unwrap_or_default();

    if spi_configs.len() > MAX_HW_SPI {
        return Err(Error::Config(format!(
            "Too many SPI configs: {} > {}",
            spi_configs.len(),
            MAX_HW_SPI
        )));
    }
    if i2c_configs.len() > MAX_HW_I2C {
        return Err(Error::Config(format!(
            "Too many I2C configs: {} > {}",
            i2c_configs.len(),
            MAX_HW_I2C
        )));
    }
    if uart_configs.len() > MAX_HW_UART {
        return Err(Error::Config(format!(
            "Too many UART configs: {} > {}",
            uart_configs.len(),
            MAX_HW_UART
        )));
    }
    if gpio_configs.len() > MAX_HW_GPIO {
        return Err(Error::Config(format!(
            "Too many GPIO configs: {} > {}",
            gpio_configs.len(),
            MAX_HW_GPIO
        )));
    }
    if pio_configs.len() > MAX_HW_PIO {
        return Err(Error::Config(format!(
            "Too many PIO configs: {} > {}",
            pio_configs.len(),
            MAX_HW_PIO
        )));
    }

    // Header: counts + max_gpio + uart_count (6 bytes)
    result.push(spi_configs.len() as u8);
    result.push(i2c_configs.len() as u8);
    result.push(gpio_configs.len() as u8);
    result.push(pio_configs.len() as u8);
    result.push(max_gpio);
    result.push(uart_configs.len() as u8);

    // SPI configs (8 bytes each)
    for (i, spi) in spi_configs.iter().enumerate() {
        let bus = spi["bus"].as_u64().unwrap_or(0) as u8;
        let miso = validate_gpio_pin(
            spi["miso"].as_u64().unwrap_or(16),
            &format!("hardware.spi[{i}].miso"),
            max_gpio,
        )?;
        let mosi = validate_gpio_pin(
            spi["mosi"].as_u64().unwrap_or(19),
            &format!("hardware.spi[{i}].mosi"),
            max_gpio,
        )?;
        let sck = validate_gpio_pin(
            spi["sck"].as_u64().unwrap_or(18),
            &format!("hardware.spi[{i}].sck"),
            max_gpio,
        )?;
        let freq_hz = spi["freq_hz"].as_u64().unwrap_or(400_000) as u32;

        result.push(bus);
        result.push(miso);
        result.push(mosi);
        result.push(sck);
        result.extend_from_slice(&freq_hz.to_le_bytes());
    }

    // I2C configs (8 bytes each)
    for (i, i2c) in i2c_configs.iter().enumerate() {
        let bus = i2c["bus"].as_u64().unwrap_or(0) as u8;
        let sda = validate_gpio_pin(
            i2c["sda"].as_u64().unwrap_or(4),
            &format!("hardware.i2c[{i}].sda"),
            max_gpio,
        )?;
        let scl = validate_gpio_pin(
            i2c["scl"].as_u64().unwrap_or(5),
            &format!("hardware.i2c[{i}].scl"),
            max_gpio,
        )?;
        let freq_hz = i2c["freq_hz"].as_u64().unwrap_or(100_000) as u32;

        result.push(bus);
        result.push(sda);
        result.push(scl);
        result.push(0); // reserved
        result.extend_from_slice(&freq_hz.to_le_bytes());
    }

    // UART configs (8 bytes each): bus, tx_pin, rx_pin, reserved, baudrate(u32)
    for (i, uart) in uart_configs.iter().enumerate() {
        let bus = uart["bus"].as_u64().unwrap_or(0) as u8;
        let tx_pin = validate_gpio_pin(
            uart["tx_pin"].as_u64().unwrap_or(0),
            &format!("hardware.uart[{i}].tx_pin"),
            max_gpio,
        )?;
        let rx_pin = validate_gpio_pin(
            uart["rx_pin"].as_u64().unwrap_or(1),
            &format!("hardware.uart[{i}].rx_pin"),
            max_gpio,
        )?;
        let baudrate = uart["baudrate"].as_u64().unwrap_or(115200) as u32;

        result.push(bus);
        result.push(tx_pin);
        result.push(rx_pin);
        result.push(0); // reserved
        result.extend_from_slice(&baudrate.to_le_bytes());
    }

    // GPIO configs (5 bytes each): pin, flags, initial, owner_module_id, reserved
    for (i, gpio) in gpio_configs.iter().enumerate() {
        let pin = validate_gpio_pin(
            gpio["pin"].as_u64().unwrap_or(0),
            &format!("hardware.gpio[{i}].pin"),
            max_gpio,
        )?;

        // Direction: "output" or "input" (default: output)
        let direction = match gpio["direction"].as_str().unwrap_or("output") {
            "input" | "in" => 0u8,
            _ => 1u8, // output
        };

        // Pull: "none", "up", "down" (default: none)
        let pull = match gpio["pull"].as_str().unwrap_or("none") {
            "up" => 1u8,
            "down" => 2u8,
            _ => 0u8, // none
        };

        // Initial level: "high" or "low" (default: high for outputs)
        let initial = match gpio["initial"].as_str() {
            Some("low") | Some("0") => 0u8,
            Some("high") | Some("1") => 1u8,
            None => {
                // Default based on numeric value or true/false
                if let Some(n) = gpio["initial"].as_u64() {
                    if n == 0 {
                        0u8
                    } else {
                        1u8
                    }
                } else if let Some(b) = gpio["initial"].as_bool() {
                    if b {
                        1u8
                    } else {
                        0u8
                    }
                } else {
                    1u8 // default high
                }
            }
            _ => 1u8,
        };

        // Owner module: resolve name to index, 0xFF = kernel-owned
        let owner_module_id: u8 = if let Some(owner_name) = gpio["owner"].as_str() {
            match module_names.iter().position(|n| n == owner_name) {
                Some(idx) => idx as u8,
                None => {
                    return Err(Error::Config(format!(
                        "hardware.gpio[{i}].owner: unknown module '{owner_name}'"
                    )));
                }
            }
        } else {
            0xFF // kernel-owned (default)
        };

        // flags: bit0 = direction (0=in, 1=out), bit1-2 = pull (0=none, 1=up, 2=down)
        let flags = direction | (pull << 1);

        result.push(pin);
        result.push(flags);
        result.push(initial);
        result.push(owner_module_id);
        result.push(0); // reserved
    }

    // PIO configs (4 bytes each): pio_idx, data_pin, clk_pin, extra_pin
    for (i, pio) in pio_configs.iter().enumerate() {
        let pio_idx = pio["pio_idx"].as_u64().unwrap_or(0) as u8;
        if pio_idx >= pio_count {
            return Err(Error::Config(format!(
                "hardware.pio[{i}].pio_idx {pio_idx} >= target pio_count {pio_count}"
            )));
        }
        let data_pin = validate_gpio_pin(
            pio["data_pin"].as_u64().unwrap_or(0),
            &format!("hardware.pio[{i}].data_pin"),
            max_gpio,
        )?;
        let clk_pin = validate_gpio_pin(
            pio["clk_pin"].as_u64().unwrap_or(0),
            &format!("hardware.pio[{i}].clk_pin"),
            max_gpio,
        )?;
        let extra_pin = pio["extra_pin"].as_u64().unwrap_or(0xFF) as u8;

        result.push(pio_idx);
        result.push(data_pin);
        result.push(clk_pin);
        result.push(extra_pin);
    }

    Ok(result)
}

/// Resolve edge_class for each wiring entry.
///
/// Reads `edge_class` field from each wiring entry:
/// - "local" (default) → 0
/// - "dma_owned" → 1
/// - "cross_core" → 2
///
/// Also validates: cross_core edges must connect modules in different domains.
fn resolve_edge_classes(
    config: &Value,
    _module_names: &[String],
    domain_names: &[String],
) -> Result<Vec<u8>> {
    let wiring = match config.get("wiring").and_then(|w| w.as_array()) {
        Some(w) => w,
        None => return Ok(Vec::new()),
    };

    let mut classes = Vec::with_capacity(wiring.len());

    // Build module_name → domain_id lookup. Surfaces an unknown-domain
    // typo here too so cross_core edge-class validation can't fall back
    // to a phantom domain 0.
    let modules_list = config.get("modules").and_then(|m| m.as_array());
    let mut module_domain: std::collections::HashMap<String, u8> = std::collections::HashMap::new();
    if let Some(mods) = modules_list {
        for m in mods {
            if let Some(name) = m.get("name").and_then(|n| n.as_str()) {
                let domain = resolve_domain_id(m, config)?;
                module_domain.insert(name.to_string(), domain);
            }
        }
    }

    for (i, entry) in wiring.iter().enumerate() {
        let ec_str = entry
            .get("edge_class")
            .and_then(|v| v.as_str())
            .unwrap_or("local");
        let ec = match ec_str {
            "dma_owned" => 1u8,
            "cross_core" => {
                // Validate: from and to must be in different domains
                if let (Some(from_spec), Some(to_spec)) = (
                    entry.get("from").and_then(|v| v.as_str()),
                    entry.get("to").and_then(|v| v.as_str()),
                ) {
                    let from_mod = from_spec.split('.').next().unwrap_or("");
                    let to_mod = to_spec.split('.').next().unwrap_or("");
                    let from_d = module_domain.get(from_mod).copied().unwrap_or(0);
                    let to_d = module_domain.get(to_mod).copied().unwrap_or(0);
                    if from_d == to_d && !domain_names.is_empty() {
                        eprintln!("warning: wiring[{i}] edge_class=cross_core but '{from_mod}' and '{to_mod}' are in same domain {from_d}");
                    }
                }
                2u8
            }
            "nic_ring" => 3u8,
            _ => 0u8, // "local" or unknown
        };
        classes.push(ec);
    }

    Ok(classes)
}

/// Resolve `buffer_bytes` for each wiring entry.
///
/// Reads the optional `buffer_bytes` field on each `wiring[]` entry.
/// `0` (or missing) means "use module hints / default". Non-zero
/// values are clamped to `[64, MAX_CHAN_BYTES = 2 MiB]`; the kernel
/// rounds up to the next power of two at channel-open time, so the
/// encoded value is the lower bound the producer needs.
///
/// Per-edge sizing matters when edge bandwidth depends on graph
/// composition rather than module type — e.g. a `spectrum_video →
/// wasm_browser_canvas` raster edge that must carry 98 KiB per
/// frame at 50 fps doesn't share a default with a low-rate
/// telemetry edge from the same producer.
fn resolve_edge_buffer_bytes(config: &Value) -> Vec<u32> {
    // Must match the kernel's channel/scheduler cap (src/kernel/ipc/channel.rs +
    // scheduler/mod.rs = 4 MiB). This is the config-build clamp: it was stale at
    // 256 KiB while the kernel allowed 2 MiB, so a wiring asking for 2 MiB (a
    // GPU-offload frame channel — dense frames near 1 MiB) was silently clamped
    // to 256 KiB, and a frame larger than the channel gated across ticks and
    // FROZE the display. Raised to 4 MiB to match the kernel (chunk's GPU command
    // ring carries a chunk mesh + far-terrain LOD ring in one step).
    const MAX_CHAN_BYTES: u32 = 4 * 1024 * 1024;
    let wiring = match config.get("wiring").and_then(|w| w.as_array()) {
        Some(w) => w,
        None => return Vec::new(),
    };
    let mut out = Vec::with_capacity(wiring.len());
    for (i, entry) in wiring.iter().enumerate() {
        let raw = entry
            .get("buffer_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let clamped = if raw == 0 {
            0
        } else if raw < 64 {
            eprintln!("warning: wiring[{i}] buffer_bytes={raw} below minimum 64; rounding up");
            64
        } else if raw > MAX_CHAN_BYTES as u64 {
            eprintln!(
                "warning: wiring[{i}] buffer_bytes={raw} exceeds MAX_CHAN_BYTES={MAX_CHAN_BYTES}; clamping"
            );
            MAX_CHAN_BYTES
        } else {
            raw as u32
        };
        out.push(clamped);
    }
    out
}

/// Contracts that tolerate more than one provider in a single graph
/// because callers fan through them via the `CHAIN_NEXT` flag rather
/// than letting the last registration win. Nothing declares
/// chain-awareness today — `CHAIN_NEXT` is defined but unset by every
/// module — so this list is empty and every duplicate provider is an
/// error. It exists so the rule has a documented escape hatch rather than
/// an invented user.
const CHAIN_AWARE_PROVIDES: &[&str] = &[];

/// Surfaces that are NOT routed by class-byte contract dispatch, so multiple
/// providers of them do NOT shadow. `storage.block` is exposed through
/// per-driver block-IO ioctls on each driver's own channels (wired by port
/// name, e.g. `nvme.blocks -> fat32.blocks`), never through a single class
/// byte — so an SD card + a flash blob store both providing `storage.block`
/// is a legitimate composition, not a silent shadow. The single-provider
/// rule targets class-byte dispatch shadowing (FS / storage.namespace /
/// storage.object), so these are exempt.
const NON_DISPATCH_SURFACES: &[&str] = &["storage.block"];

/// The per-module `volume:` param — the instance selector that keys an
/// FS/namespace provider. Empty string = the default (unkeyed) provider.
/// Two providers of one surface may coexist ONLY with distinct selectors:
/// the kernel reaches each keyed volume via `provider_call_sel` and the
/// `mount` module routes paths to them.
///
/// The literal key `"volume"` mirrors the provider module's own selector
/// param (`fat32`'s `define_params!` tag `volume`, which feeds
/// `module_provider_selector`) — a rename must touch both sides.
fn provider_volume<'a>(config: &'a Value, name: &str) -> &'a str {
    config
        .get("modules")
        .and_then(|m| m.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|e| e.get("name").and_then(|n| n.as_str()) == Some(name))
        })
        .and_then(|e| e.get("params"))
        .and_then(|p| p.get("volume"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

/// Reject a graph in which two modules provide the same contract surface
/// (a `provides = [..]` entry) with the SAME instance selector.
///
/// Contract providers are auto-registered by the loader after each module
/// reaches Ready, in module-index order. The class-byte dispatch path
/// takes the top-most unkeyed (selector 0) layer, and a second unkeyed
/// provider of the same surface silently shadows the first: two `fat32`
/// volumes without distinct `volume:` selectors do not resolve by path —
/// every `FS_OPEN` reaches the same one and the other drive is
/// unreachable. This turns that into a build error, naming both modules.
///
/// Multiple providers of one surface ARE allowed when each declares a
/// distinct `volume:` selector: they register as instance-keyed layers a
/// `mount` module binds and routes between. The escape hatch
/// `CHAIN_AWARE_PROVIDES` (empty today) additionally exempts a contract
/// whose callers fan through `CHAIN_NEXT`.
pub fn validate_single_provider(
    config: &Value,
    module_names: &[String],
    manifests: &HashMap<String, Manifest>,
) -> Result<()> {
    // (surface, selector) -> first module declaring it. A later module
    // with the SAME (surface, selector) would shadow it at runtime.
    let mut seen: HashMap<(&str, &str), &str> = HashMap::new();
    for name in module_names {
        let Some(m) = manifests.get(name) else {
            continue;
        };
        let sel = provider_volume(config, name);
        for surface in &m.provides {
            if CHAIN_AWARE_PROVIDES.contains(&surface.as_str())
                || NON_DISPATCH_SURFACES.contains(&surface.as_str())
            {
                continue;
            }
            let key = (surface.as_str(), sel);
            match seen.get(&key) {
                None => {
                    seen.insert(key, name.as_str());
                }
                Some(earlier) if *earlier == name.as_str() => {}
                Some(earlier) => {
                    let detail = if sel.is_empty() {
                        format!(
                            "both are default (unkeyed) `{surface}` providers, so `{name}` silently \
                             shadows `{earlier}` at runtime — whatever `{earlier}` backs becomes \
                             unreachable with no diagnostic. Give each a distinct `volume:` param \
                             and route between them with a `mount` module, or split them across \
                             graphs."
                        )
                    } else {
                        format!(
                            "both declare `volume = \"{sel}\"` for `{surface}`, so their provider \
                             registrations collide. Give each volume backend a distinct `volume:`."
                        )
                    };
                    return Err(Error::Config(format!(
                        "two modules provide the contract `{surface}`: `{earlier}` and `{name}` — {detail}"
                    )));
                }
            }
        }
    }

    // A surface whose providers are ALL instance-keyed has no router: the
    // class-byte (`handle == -1`) path that every `requires_contract` consumer
    // uses resolves to nothing, and the kernel answers ENOSYS. Catch it here,
    // where both the module names and the fix are in hand.
    let mut keyed: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut has_default: HashMap<&str, bool> = HashMap::new();
    for name in module_names {
        let Some(m) = manifests.get(name) else {
            continue;
        };
        let sel = provider_volume(config, name);
        for surface in &m.provides {
            if CHAIN_AWARE_PROVIDES.contains(&surface.as_str())
                || NON_DISPATCH_SURFACES.contains(&surface.as_str())
            {
                continue;
            }
            if sel.is_empty() {
                has_default.insert(surface.as_str(), true);
            } else {
                keyed.entry(surface.as_str()).or_default().push(name.as_str());
            }
        }
    }
    for (surface, backends) in keyed {
        if has_default.get(surface).copied().unwrap_or(false) {
            continue;
        }
        let list = backends.join("`, `");
        return Err(Error::Config(format!(
            "every provider of `{surface}` is instance-keyed (`{list}`) and none is the \
             default — a consumer calling this contract without naming a volume has \
             nothing to route it, and the kernel returns ENOSYS. Add a router that \
             provides `{surface}` with no `volume:` (the `mount` module), or drop \
             `volume:` from the single backend that should serve it."
        )));
    }
    Ok(())
}

/// Reject `fault_policy: restart` for a module whose manifest does not
/// attest that it can resume after an arbitrary fault.
///
/// The kernel's restart path releases every provider handle the module
/// owned, flushes every connected input / output / control channel, and
/// then resumes the **same** state allocation: state is not zeroed and
/// `module_new` is not re-called. A module carrying an invariant across
/// steps therefore resumes with its own bookkeeping describing handles
/// and in-flight work that no longer exist — silent corruption, not
/// recovery. Nothing at instantiation time can infer whether that is
/// safe, so the module attests it in its own manifest
/// (`resume_after_fault = true`) and this is where the claim is required.
///
/// A module with no manifest in the map is not gated — the same
/// convention the other validators in this file use for modules supplied
/// from outside the resolved set.
pub fn validate_fault_policy(
    config: &Value,
    module_names: &[String],
    manifests: &HashMap<String, Manifest>,
) -> Result<()> {
    let Some(entries) = config.get("modules").and_then(|m| m.as_array()) else {
        return Ok(());
    };
    for entry in entries {
        let Some(name) = entry.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        if !module_names.iter().any(|m| m == name) {
            continue;
        }
        if entry.get("fault_policy").and_then(|v| v.as_str()) != Some("restart") {
            continue;
        }
        let Some(m) = manifests.get(name) else {
            continue;
        };
        if m.resume_after_fault {
            continue;
        }
        return Err(Error::Config(format!(
            "module '{name}': fault_policy = \"restart\" requires the module to attest \
             that it can resume after a fault, and `{name}`'s manifest does not. \
             This policy does NOT re-instantiate the module: it releases every provider \
             handle the module holds, flushes every connected channel, and resumes the \
             SAME state allocation without zeroing it and without re-running \
             `module_new`. A module with state that spans steps therefore resumes with \
             stale handles and stale bookkeeping. Either add `resume_after_fault = true` \
             to `{name}`'s manifest.toml (only if every externally visible transition \
             completes inside one step, no provider handle is held across steps, and \
             discarding in-flight channel data loses nothing the module's protocol does \
             not already treat as loss), or choose `fault_policy: \"skip\"` to terminate \
             the module and let the operator drain and reload, or \
             `fault_policy: \"restart_graph\"` to re-instantiate the whole graph."
        )));
    }
    Ok(())
}

