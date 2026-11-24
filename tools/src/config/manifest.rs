/// Resolve a port spec using named ports from the module manifest.
///
/// Supported forms:
/// - `module` (bare name) — default to out[0] for "from:", in[0] for "to:"
/// - `module.portname` — look up named port in manifest
///
/// `context_is_from`: true if this is a `from:` spec (must resolve to output),
///                     false if this is a `to:` spec (must resolve to input or ctrl).
fn resolve_port_spec<'a>(
    spec: &'a str,
    context_is_from: bool,
    manifests: &HashMap<String, Manifest>,
    declared_names: &[String],
) -> std::result::Result<(&'a str, u8, u8), String> {
    let parts: Vec<&str> = spec.split('.').collect();
    let module_name = parts.first().unwrap_or(&spec).trim();

    if parts.len() < 2 {
        // Bare module name — default to out[0] for "from:", in[0] for "to:"
        let port_type = if context_is_from { 1 } else { 0 };
        return Ok((module_name, port_type, 0));
    }

    let port_part = parts[1].trim();

    // Named port — look up in manifest. Every declared module's manifest
    // resolved before wiring is read (`ModuleResolver::graph_modules`), so a
    // name with none is not a declared module: a typo, most often.
    let manifest = manifests.get(module_name).ok_or_else(|| {
        let typo_hint = crate::target::closest_match(module_name, declared_names, 3)
            .map(|s| format!("Did you mean '{s}'? "))
            .unwrap_or_default();
        format!(
            "no manifest found for module '{module_name}' (needed to resolve port name \
             '{port_part}'). {typo_hint}Common causes:\n\
             \x20\x20- the module name is misspelled or doesn't match a `name:` declared \
             under `modules:`;\n\
             \x20\x20- the module's `type:` field is misspelled or refers to a module that \
             doesn't exist;\n\
             \x20\x20- the project / install roots don't include the module's source tree \
             (run `fluxor inspect` to see the search paths in use);\n\
             \x20\x20- the module is a native module whose feature isn't compiled into this \
             `fluxor` binary."
        )
    })?;

    let (direction, index, _content_type) =
        manifest.find_port_by_name(port_part).ok_or_else(|| {
            // Build helpful error with available port names + a
            // Levenshtein "did you mean" suggestion. `notess` →
            // 'notes' is the most common shape — the same pattern
            // every other typo-prone surface in this tool uses.
            let available: Vec<String> = manifest
                .ports
                .iter()
                .filter_map(|p| p.name.clone())
                .collect();
            if available.is_empty() {
                format!("module '{module_name}' has no named ports in its manifest")
            } else {
                let did_you_mean = crate::text_distance::closest_match(port_part, &available, 3)
                    .map(|h| format!(" Did you mean '{h}'?"))
                    .unwrap_or_default();
                format!(
                    "module '{module_name}' has no port named '{port_part}'.{did_you_mean} \
                     Available: {}",
                    available.join(", ")
                )
            }
        })?;

    // Validate direction matches context
    if context_is_from && direction != 1 && direction != 3 {
        return Err(format!(
            "port '{}.{}' is {} but used in 'from:' (must be output or ctrl_output)",
            module_name,
            port_part,
            manifest::direction_to_str(direction)
        ));
    }
    if !context_is_from && direction == 1 {
        return Err(format!(
            "port '{module_name}.{port_part}' is output but used in 'to:' (must be input or ctrl)"
        ));
    }

    Ok((module_name, direction, index))
}

/// Reject configs where a module declares an input port as
/// `required: true` in its manifest but no wiring edge connects to
/// that port. Without this check, the build silently succeeds and
/// the runtime instance blocks forever on an empty input ring (or
/// produces uninitialised output) — exactly the kind of "config
/// passes but graph runs wrong" failure that's most painful to
/// debug because nothing is logged.
///
/// Edges are checked against the resolved `to_port_index` field
/// (the per-direction index `parse_wiring_edges` computed from
/// either the bare-name shorthand or the explicit
/// `module.portname` form). A module with multiple required inputs
/// must have one edge per required input.
///
/// **Scope:** data inputs (direction == 0) only. Control inputs
/// (direction == 2) are usually rare-event signaling channels that
/// are typically optional; the manifest can still mark them
/// `required: true` if a module genuinely can't initialise without
/// the control wire, but the common case is "left unconnected".
/// If a need surfaces to enforce required ctrl inputs too, this
/// validator extends easily.
fn validate_required_inputs_wired(
    edges: &[(u16, u16, u8, u8, u8)],
    module_names: &[String],
    manifests: &HashMap<String, Manifest>,
) -> Result<()> {
    use std::collections::BTreeSet;

    // Index every (to_module_id, to_port_index) pair an edge
    // delivers into. `to_port` (the wire format's 0=in/1=ctrl
    // distinction) is also tracked so we can match against the
    // manifest's direction byte.
    //   wire_to_port 0 + manifest direction 0 → data input.
    //   wire_to_port 1 + manifest direction 2 → ctrl input.
    let mut covered_data: BTreeSet<(u16, u8)> = BTreeSet::new();
    for &(_, to_id, to_port, _, to_port_index) in edges {
        if to_port == 0 {
            covered_data.insert((to_id, to_port_index));
        }
    }

    let mut violations: Vec<String> = Vec::new();
    for (module_id, name) in module_names.iter().enumerate() {
        let manifest = match manifests.get(name) {
            Some(m) => m,
            // No manifest → already an error class handled by the
            // wiring/manifest validator. Skip silently here to
            // avoid double-reporting.
            None => continue,
        };
        for port in &manifest.ports {
            // direction == 0 = data input. Skip output (1) and
            // ctrl input/output (2/3) — see scope comment above.
            if port.direction != 0 {
                continue;
            }
            // flags bit 0 = required (`Manifest::from_toml`). A non-required
            // input left unconnected is fine — module handles
            // empty input by design.
            if port.flags & 0x01 == 0 {
                continue;
            }
            if covered_data.contains(&(module_id as u16, port.index)) {
                continue;
            }
            // Build the most actionable label: prefer the port's
            // human name if the manifest declares one, else fall
            // back to `in[N]` so the user can spot which slot
            // needs wiring.
            let port_label = port
                .name
                .as_deref()
                .map(|n| format!("'{n}' (in[{}])", port.index))
                .unwrap_or_else(|| format!("in[{}]", port.index));
            violations.push(format!(
                "module '{name}' declares input port {port_label} as required, but no \
                 wiring edge connects to it. Add a `wiring:` entry of the form \
                 `to: {name}{port_specifier}`.",
                port_specifier = match &port.name {
                    Some(n) => format!(".{n}"),
                    None if port.index == 0 => String::new(),
                    None => format!(" (port index {})", port.index),
                }
            ));
        }
    }

    if !violations.is_empty() {
        return Err(Error::Config(format!(
            "Required input(s) left unwired — these modules will block at runtime:\n  - {}",
            violations.join("\n  - ")
        )));
    }
    Ok(())
}

/// Resolve one edge's rate class: per-edge `rate:` override, else the
/// consumer port's own declared `rate_class_default`, else the
/// producer's, else the consumer's content-type default, else the
/// producer's, else control. Shared by the wiring-capacity validator
/// and the binary edge emitter.
///
/// A port's own `rate_class_default` takes priority over the generic
/// content-type table: a content type like `NetProto` is shared by
/// modules with wildly different real traffic (RTP media vs. DNS
/// lookups vs. HTTP admin loopback), so the content-type default can
/// only ever be a reasonable-for-nobody-in-particular fallback. A
/// module that knows its own edges' true shape declares it once, in
/// its own manifest, instead of every consuming config repeating a
/// per-edge `rate:` override.
fn resolve_edge_rate_class(
    wiring_entry: Option<&Value>,
    from_port: Option<&crate::manifest::PortSpec>,
    to_port_spec: Option<&crate::manifest::PortSpec>,
) -> Result<fluxor_contracts::RateClass> {
    use fluxor_contracts::{RateClass, CONTENT_RATE_CLASS};
    if let Some(r) = wiring_entry
        .and_then(|e| e.get("rate"))
        .and_then(|v| v.as_str())
    {
        return RateClass::from_str_opt(r).ok_or_else(|| {
            Error::Config(format!(
                "unknown rate class '{r}' (control | transaction | audio | video | bulk)"
            ))
        });
    }
    if let Some(class) = to_port_spec
        .and_then(|p| p.rate_class_default)
        .or_else(|| from_port.and_then(|p| p.rate_class_default))
    {
        return Ok(class);
    }
    let ct_class = |spec: Option<&crate::manifest::PortSpec>| {
        spec.and_then(|p| CONTENT_RATE_CLASS.get(p.content_type as usize))
            .copied()
    };
    Ok(ct_class(to_port_spec)
        .or_else(|| ct_class(from_port))
        .unwrap_or(RateClass::Control))
}

/// The content type of an edge that carries whole records, or `None` for a
/// byte-stream edge. An edge is framed when either end's port is: by its
/// content type's framing, or by the port's own `framed = true`.
fn edge_framed_type(
    edge: &(u16, u16, u8, u8, u8),
    module_names: &[String],
    manifests: &HashMap<String, Manifest>,
) -> Option<u8> {
    use fluxor_contracts::{Framing, CONTENT_FRAMING};
    let &(_, _, to_port, from_port_index, to_port_index) = edge;

    // The type table is the primary source: it owns framing, so a producer and
    // a consumer cannot disagree about it. A port may ALSO declare
    // `framed = true` (flags bit 1), which is the escape hatch for a record
    // carried over an ambiguous type — `OctetStream` is `Streamed` by default
    // and rightly so, but a module emitting fixed record frames over it still
    // needs mailbox delivery. Minting a content type for every such record
    // would move the ABI surface digest and force a coordinated rebuild of
    // every `.fmod` in every workspace member, so the port declares it and
    // only the declaring module bears the requirement.
    let framed_of = |spec: Option<&crate::manifest::PortSpec>| {
        spec.and_then(|p| {
            let by_type = CONTENT_FRAMING
                .get(p.content_type as usize)
                .is_some_and(|f| *f == Framing::Framed);
            (by_type || p.flags & 0x02 != 0).then_some(p.content_type)
        })
    };
    let from_port = manifests
        .get(&module_names[edge.0 as usize])
        .and_then(|m| m.find_port_spec(1, from_port_index));
    let to_direction = if to_port == 1 { 2u8 } else { 0u8 };
    let to_port_spec = manifests
        .get(&module_names[edge.1 as usize])
        .and_then(|m| m.find_port_spec(to_direction, to_port_index));

    framed_of(from_port).or_else(|| framed_of(to_port_spec))
}

/// Per-edge capacity + rate-class validation.
///
/// The runtime `open_channels` enforcement over each wiring entry as
/// written, by the kernel's ring rule (`fluxor_contracts::ring_size`) and the manifests' port capacities: for
/// every FIFO edge, take the ring the kernel grants and check
///   1. producer `max_record` fits it (wedge exclusion — an
///      all-or-nothing write larger than the ring can never succeed);
///   2. no request exceeds the 4 MiB channel ceiling;
///   3. the edge's rate class is satisfiable on this profile at all;
///   4. class floor ≤ ring × nominal tick rate (a necessary-condition
///      screen for order-of-magnitude misprovisioning, NOT a proof of
///      sufficiency — that is the module's step logic).
///
/// The rings of the graph as the kernel prepares it, with its tees, merges
/// and mailbox groups, are summed and checked again by `ring_demand`.
///
/// Edge class = per-edge `rate:` override, else the consumer port's
/// content-type default (`CONTENT_RATE_CLASS`), else the producer's.
/// Grouped (mailbox) edges are skipped here: a group's ring is its largest
/// member's request, which `ring_demand` checks over the prepared graph.
fn validate_wiring_capacity(
    config: &Value,
    edges: &[(u16, u16, u8, u8, u8)],
    module_names: &[String],
    manifests: &HashMap<String, Manifest>,
    from_specs: &[String],
    to_specs: &[String],
    embedded_profile: bool,
) -> Result<()> {
    use fluxor_contracts::{rate_class_floor, RateClass};

    let tick_us = config
        .get("tick_us")
        .and_then(|t| t.as_u64())
        .unwrap_or(1000)
        .max(1);
    let ticks_per_sec = 1_000_000u64 / tick_us;

    let wiring = config
        .get("wiring")
        .and_then(|w| w.as_array())
        .cloned()
        .unwrap_or_default();

    for (i, &(_, _, to_port, from_port_index, to_port_index)) in edges.iter().enumerate() {
        let entry = wiring.get(i);
        let buffer_group = entry
            .and_then(|e| e.get("buffer_group"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if buffer_group != 0 {
            continue; // sized at its group's largest; `ring_demand` checks it
        }
        debug_assert!(
            edge_framed_type(&edges[i], module_names, manifests).is_none(),
            "every framed edge is grouped before capacity is checked"
        );

        let buffer_bytes = entry
            .and_then(|e| e.get("buffer_bytes"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let from_name = &module_names[edges[i].0 as usize];
        let to_name = &module_names[edges[i].1 as usize];
        let from_port = manifests
            .get(from_name)
            .and_then(|m| m.find_port_spec(1, from_port_index));
        let to_direction = if to_port == 1 { 2u8 } else { 0u8 };
        let to_port_spec = manifests
            .get(to_name)
            .and_then(|m| m.find_port_spec(to_direction, to_port_index));

        // Resolve the edge's rate class (shared helper — the same
        // resolution feeds the binary edge emitter).
        let class = resolve_edge_rate_class(entry, from_port, to_port_spec).map_err(|e| {
            Error::Config(format!(
                "wiring[{i}] ({} → {}): {e}",
                from_specs[i], to_specs[i]
            ))
        })?;

        // A producer port may cap the class its step logic is
        // engineered for; a faster edge fails at build. `severity()`
        // is the single source of truth for this comparison — see
        // `RateClass`'s doc comment for why it deliberately isn't
        // `Ord`.
        if let Some(cap) = from_port.and_then(|p| p.rate_class_max) {
            if class.exceeds(cap) {
                return Err(Error::Config(format!(
                    "wiring[{i}] ({} → {}): edge rate class '{}' exceeds the \
                     producer port's declared rate_class_max '{}'.",
                    from_specs[i],
                    to_specs[i],
                    class.as_str(),
                    cap.as_str(),
                )));
            }
        }

        // Control means "no sustained-throughput guarantee" — tiny
        // event rings (a 64-byte button edge) are legitimate. Only
        // streaming classes get floor arithmetic; wedge/ceiling
        // checks below still apply to every edge.
        let floor = if class == RateClass::Control {
            None
        } else {
            Some(match rate_class_floor(class, embedded_profile) {
                Some(f) => f,
                None => {
                    return Err(Error::Config(format!(
                        "wiring[{i}] ({} → {}): rate class '{}' is unsatisfiable on \
                         this target profile (embedded buffer arenas cannot host \
                         {}-class rings). Lower the edge's rate or move the stream \
                         off this target.",
                        from_specs[i],
                        to_specs[i],
                        class.as_str(),
                        class.as_str(),
                    )));
                }
            })
        };

        // The runtime grant, by the kernel's rule.
        let prod_size = from_port.map(|p| p.buffer_size).unwrap_or(0);
        let cons_size = to_port_spec.map(|p| p.buffer_size).unwrap_or(0);
        let request = fluxor_contracts::ring_size::edge_request(prod_size, cons_size, buffer_bytes);
        // (2) ceiling.
        let Some(granted) = fluxor_contracts::ring_size::ring_for(request) else {
            return Err(Error::Config(format!(
                "wiring[{i}] ({} → {}): requested buffer {} exceeds the channel \
                 ceiling {} — lower the request or split the stream.",
                from_specs[i],
                to_specs[i],
                request,
                fluxor_contracts::ring_size::MAX_RING_BYTES
            )));
        };

        // (1) wedge exclusion.
        let max_record = from_port.map(|p| p.max_record).unwrap_or(0);
        if max_record > 0 && max_record > granted {
            return Err(Error::Config(format!(
                "wiring[{i}] ({} → {}): producer declares max_record={} but the \
                 ring grants {} bytes (requested {}); an all-or-nothing write \
                 larger than the ring can never succeed. Raise buffer_bytes / \
                 the port's buffer_size, or lower max_record.",
                from_specs[i], to_specs[i], max_record, granted, request
            )));
        }

        // (4) order-of-magnitude screen: the ring must be able to
        // carry the class floor at the nominal tick rate even if it
        // were drained once per tick.
        let Some(floor) = floor else { continue };
        let ring_rate_ceiling = granted as u64 * ticks_per_sec;
        if (floor as u64) > ring_rate_ceiling {
            // An edge a stack inserted is not in the author's YAML, so
            // telling them to raise `buffer_bytes` on it names a line
            // they never wrote and cannot find. Say where it came from
            // and what they can actually change.
            let remedy = match entry
                .and_then(|e| e.get("_from_stack"))
                .and_then(|v| v.as_str())
            {
                Some(stack) => format!(
                    " The '{stack}' stack inserted this edge; it is not in this \
                     config, so there is no buffer_bytes here to raise. Lower \
                     tick_us, or give the producing port a rate_class_default \
                     matching the traffic it really carries."
                ),
                None => " Raise buffer_bytes or lower the edge's rate class.".to_string(),
            };
            return Err(Error::Config(format!(
                "wiring[{i}] ({} → {}): rate class '{}' needs ≥ {} B/s but the \
                 {}-byte ring at tick_us={} sustains at most {} B/s.{}",
                from_specs[i],
                to_specs[i],
                class.as_str(),
                floor,
                granted,
                tick_us,
                ring_rate_ceiling,
                remedy
            )));
        }
    }
    Ok(())
}

/// A module entry's value for `param`, at the top level or inside its
/// `params:` wrapper.
fn entry_param<'a>(module: &'a Value, param: &str) -> Option<&'a Value> {
    module
        .get(param)
        .or_else(|| module.get("params").and_then(|p| p.get(param)))
}

/// Whether a consumer input leaves retention to the provider feeding it:
/// it keeps no copy of what it sends (`retains_send`) and may open a stream
/// (not `datagram_only`).
fn leaves_retention(in_port: &crate::manifest::PortSpec) -> bool {
    !in_port.retains_send && !in_port.datagram_only
}

/// Size every send pool from the graph (`send_pool_param` on an output).
///
/// An instance that sets the param keeps its figure. One that leaves it
/// unset gets 0 when no consumer of the port leaves retention to it (each
/// keeps its own copy, or opens no stream) and it serves no workload lane
/// (`send_pool_lanes_param`, the graph's value else the schema default);
/// otherwise the buffers its type's default pool holds, each of the
/// instance's `send_buffer_param`. The value is written into the entry, so
/// it is packed, and a `heap_per_param` rule over it grows the heap by it.
/// `default_of(entry, param)` is the param's default in the module the
/// entry is built from (its schema, for the target); a param with none
/// refuses the graph, since no pool can be derived from a figure that
/// does not exist.
fn derive_send_pools(
    modules: &mut [Value],
    edges: &[(u16, u16, u8, u8, u8)],
    module_names: &[String],
    manifests: &HashMap<String, Manifest>,
    default_of: &dyn Fn(&Value, &str) -> Option<u64>,
) -> Result<()> {
    for (i, name) in module_names.iter().enumerate() {
        let Some(manifest) = manifests.get(name) else {
            continue;
        };
        let Some(module) = modules
            .iter_mut()
            .find(|m| m.get("name").and_then(|n| n.as_str()) == Some(name.as_str()))
        else {
            continue;
        };
        let value_of = |module: &Value, param: &str| -> Result<u64> {
            match entry_param(module, param) {
                Some(v) => v.as_u64().ok_or_else(|| {
                    Error::Config(format!(
                        "module `{name}`: `{param}` is not a count of bytes"
                    ))
                }),
                None => default_of(module, param).ok_or_else(|| {
                    Error::Config(format!(
                        "module `{name}`: its port declares `{param}` for its send pool, but \
                         the module has no such parameter to derive the pool from"
                    ))
                }),
            }
        };
        for out_port in manifest.ports.iter().filter(|p| p.direction == 1) {
            let (Some(pool_param), Some(buf_param)) = (
                out_port.send_pool_param.as_deref(),
                out_port.send_buffer_param.as_deref(),
            ) else {
                continue;
            };
            if entry_param(module, pool_param).is_some() {
                continue;
            }
            let stream_consumer = edges.iter().any(|&(from, to, to_port, fpi, tpi)| {
                from as usize == i
                    && fpi == out_port.index
                    && manifests
                        .get(&module_names[to as usize])
                        .and_then(|m| m.find_port_spec(if to_port == 1 { 2 } else { 0 }, tpi))
                        .is_some_and(leaves_retention)
            });
            let lanes = match out_port.send_pool_lanes_param.as_deref() {
                Some(p) => value_of(module, p)?,
                None => 0,
            };
            let pool = if stream_consumer || lanes > 0 {
                let missing = |param: &str| {
                    Error::Config(format!(
                        "module `{name}`: its port declares `{param}` for its send pool, but \
                         the module has no such parameter to derive the pool from"
                    ))
                };
                let pool_default =
                    default_of(module, pool_param).ok_or_else(|| missing(pool_param))?;
                let buf_default =
                    default_of(module, buf_param).ok_or_else(|| missing(buf_param))?;
                let buffers = pool_default.checked_div(buf_default).unwrap_or(0);
                value_of(module, buf_param)? * buffers
            } else {
                0
            };
            if let Some(obj) = module.as_object_mut() {
                obj.insert(pool_param.to_string(), serde_json::json!(pool));
            }
        }
    }
    Ok(())
}

/// Per-edge record bounds and send retention.
///
/// 1. A producer port's `max_record` (the largest frame it writes, header
///    included) must not exceed the consumer port's `accepts_record` (the
///    largest it reads). Checked per wiring entry, so every consumer of a
///    fanned output is held to it.
/// 2. An output that names a `send_buffer_param` retains what it sends for
///    consumers that do not: an instance that sets that parameter — or its
///    `send_pool_param` — to 0 may only feed consumers whose input declares
///    `retains_send` or `datagram_only`.
fn validate_record_limits(
    config: &Value,
    edges: &[(u16, u16, u8, u8, u8)],
    module_names: &[String],
    manifests: &HashMap<String, Manifest>,
    from_specs: &[String],
    to_specs: &[String],
) -> Result<()> {
    let instance_param = |name: &str, key: &str| -> Option<u64> {
        config
            .get("modules")
            .and_then(|m| m.as_array())?
            .iter()
            .find(|m| m.get("name").and_then(|n| n.as_str()) == Some(name))?
            .get(key)?
            .as_u64()
    };
    for (i, &(from, to, to_port, from_port_index, to_port_index)) in edges.iter().enumerate() {
        let from_name = &module_names[from as usize];
        let to_name = &module_names[to as usize];
        let Some(out_port) = manifests
            .get(from_name)
            .and_then(|m| m.find_port_spec(1, from_port_index))
        else {
            continue;
        };
        let to_direction = if to_port == 1 { 2u8 } else { 0u8 };
        let Some(in_port) = manifests
            .get(to_name)
            .and_then(|m| m.find_port_spec(to_direction, to_port_index))
        else {
            continue;
        };
        if out_port.max_record > 0
            && in_port.accepts_record > 0
            && out_port.max_record > in_port.accepts_record
        {
            return Err(Error::Config(format!(
                "wiring[{i}] ({} → {}): the producer writes records of up to {} B \
                 (`max_record`) but the consumer accepts at most {} B (`accepts_record`); \
                 a record past the consumer's bound is one it cannot read. Raise the \
                 consumer's bound or lower the producer's.",
                from_specs[i], to_specs[i], out_port.max_record, in_port.accepts_record
            )));
        }
        let retention_params = out_port
            .send_buffer_param
            .iter()
            .chain(out_port.send_pool_param.iter());
        for param in retention_params {
            if leaves_retention(in_port) && instance_param(from_name, param) == Some(0) {
                return Err(Error::Config(format!(
                    "wiring[{i}] ({} → {}): `{from_name}` sets `{param}: 0`, so it keeps no \
                     copy of what its consumers send, but `{}` does not retain what it sends \
                     (`retains_send`) and may open a stream — a segment lost on the wire could \
                     never be sent again. Give `{param}` a size or wire only retaining consumers.",
                    from_specs[i], to_specs[i], to_specs[i]
                )));
            }
        }
    }
    Ok(())
}

fn validate_wiring_types(
    edges: &[(u16, u16, u8, u8, u8)],
    force_flags: &[bool],
    module_names: &[String],
    manifests: &HashMap<String, Manifest>,
    from_specs: &[String],
    to_specs: &[String],
) -> Result<()> {
    // OctetStream content type ID = 0 (first in CONTENT_TYPES list)
    const OCTET_STREAM: u8 = 0;

    for (i, &(from_id, to_id, to_port, from_port_index, to_port_index)) in edges.iter().enumerate()
    {
        if force_flags.get(i).copied().unwrap_or(false) {
            continue;
        }

        let from_name = &module_names[from_id as usize];
        let to_name = &module_names[to_id as usize];

        // Look up content types from manifests
        let from_ct = manifests
            .get(from_name)
            .and_then(|m| m.find_port(1, from_port_index)); // direction=1 (output)
        let to_direction = if to_port == 1 { 2u8 } else { 0u8 }; // ctrl=2, in=0
        let to_ct = manifests
            .get(to_name)
            .and_then(|m| m.find_port(to_direction, to_port_index));

        // Both must be known to validate
        if let (Some(from_ct), Some(to_ct)) = (from_ct, to_ct) {
            // OctetStream is universal — matches anything
            if from_ct == OCTET_STREAM || to_ct == OCTET_STREAM {
                continue;
            }
            if from_ct != to_ct {
                return Err(Error::Config(format!(
                    "content type mismatch: {} produces {} but {} expects {}\n  \
                     Add 'force: true' to the edge to override.",
                    from_specs[i],
                    manifest::content_type_to_str(from_ct),
                    to_specs[i],
                    manifest::content_type_to_str(to_ct),
                )));
            }
        }
    }
    Ok(())
}

const CUTOVER_POLICIES: &[&str] = &["boundary_cut", "resumable", "anchor_preserved"];
const CONTINUITY_POLICIES: &[&str] = &["drain", "anchor_preserved"];

/// The five session continuity classes (`protocol_surfaces.md`). Distinct
/// from the AV `continuity_policy` enum above, which governs
/// presentation-group cutover only.
const CONTINUITY_CLASSES: &[&str] = &[
    "reroutable",
    "drain_only",
    "resumable",
    "edge_anchored",
    "transport_migratable",
];

/// `transport_migratable` migration mechanisms.
const MIGRATION_MECHANISMS: &[&str] = &["native_primitive", "platform_replicated_state"];

/// AEAD classes for platform-replicated-state migration
/// mechanism.
const AEAD_CLASSES: &[&str] = &["on_wire_sequence", "implicit_counter", "unencrypted"];

/// Capabilities every platform-replicated-state `transport_migratable`
/// declaration must resolve somewhere in the graph. Presence, not
/// fault-correctness: the replication invariants are proven by test, the
/// timing budget by measurement.
const PRS_REQUIRED_CAPS: &[&str] = &[
    "session.reservation",
    "security.key_wrap",
    "fence.enforceable",
    "durable.rpo_zero",
];
const MIRROR_POLICIES: &[&str] = &["independent", "strict_mirror", "partition"];
const AUDIO_SINK_CAPS: &[&str] = &["audio.sample", "audio.encoded"];
const VIDEO_SINK_CAPS: &[&str] = &["video.raster", "video.scanout", "video.encoded"];
const VIDEO_PROTECTED_CAPS: &[&str] = &["display.scanout.protected", "video.decode.protected"];

/// Maximum value (in ms) accepted for `latency_budget_ms` /
/// `skew_budget_ms`. Beyond this the value almost certainly indicates a
/// unit confusion (microseconds, frames) rather than an honest budget.
const MAX_PRESENTATION_BUDGET_MS: u64 = 10_000;

fn json_kind(v: &Value) -> &'static str {
    if v.is_string() {
        "string"
    } else if v.is_number() {
        "number"
    } else if v.is_boolean() {
        "boolean"
    } else if v.is_null() {
        "null"
    } else if v.is_array() {
        "array"
    } else {
        "object"
    }
}

fn check_enum(field: &str, value: &str, allowed: &[&str], group_id: &str) -> Result<()> {
    if !allowed.contains(&value) {
        return Err(Error::Config(format!(
            "presentation_group `{}`: {} `{}` is invalid (expected {})",
            group_id,
            field,
            value,
            allowed.join(" | ")
        )));
    }
    Ok(())
}
