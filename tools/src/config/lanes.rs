// =============================================================================
// Lanes of the node's own graph
// =============================================================================

/// The ports of a lane target its lanes stand for: the wiring names a
/// lane's commands `<target>.net_in` and its events `<target>.net_out`, and
/// every edge to either is a lane of the node owner, never a port.
const LANE_COMMANDS_PORT: &str = "net_in";
const LANE_EVENTS_PORT: &str = "net_out";

/// The `edge_class` that puts an edge into a lane target's commands into
/// the one lane its target shares among every edge so marked.
const MERGE_EDGE_CLASS: &str = "merge";

/// A module of the node's graph that serves lanes, and the lanes its wiring
/// gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct NodeLanes {
    /// The target's index among the graph's modules.
    module: u16,
    /// The name its lanes are reached by: FNV-1a of its type, the name it
    /// declares them under (`lanes::declare`).
    target: u32,
    /// Per wiring edge, the key of the lane it carries the commands or the
    /// events of; `None` for an edge that is no lane of this target.
    keys: Vec<Option<u8>>,
    /// The lanes: one per edge into `net_in`, one for every edge marked
    /// `edge_class: merge` together.
    count: usize,
}

/// The lane targets of the node's graph: every module whose manifest
/// declares lanes (`[lanes]`) and the two ports they stand for, with the
/// index of each.
fn lane_targets(
    names: &[String],
    types: &[String],
    manifests: &HashMap<String, Manifest>,
) -> Vec<(u16, u32, u8, u8)> {
    let mut out = Vec::new();
    for (m, name) in names.iter().enumerate() {
        let Some(manifest) = manifests.get(name).filter(|mf| mf.lanes.is_some()) else {
            continue;
        };
        let (Some((_, commands, _)), Some((_, events, _))) = (
            manifest.find_port_by_name(LANE_COMMANDS_PORT),
            manifest.find_port_by_name(LANE_EVENTS_PORT),
        ) else {
            continue;
        };
        let ty = types.get(m).map_or(name.as_str(), String::as_str);
        out.push((m as u16, fluxor_abi::wire::fnv1a32(ty.as_bytes()), commands, events));
    }
    out
}

/// Whether wiring entry `i` is marked `edge_class: merge`.
fn merge_marked(config: &Value, i: usize) -> bool {
    config
        .get("wiring")
        .and_then(|w| w.get(i))
        .and_then(|e| e.get("edge_class"))
        .and_then(Value::as_str)
        == Some(MERGE_EDGE_CLASS)
}

/// The lanes the node's graph wires to each of its lane targets.
///
/// - Each edge into a target's `net_in` is a lane of its own, keyed in
///   wiring order; every edge marked `edge_class: merge` shares one lane,
///   keyed where the first of them is wired.
/// - An edge out of `net_out` carries the events of the lane its consumer
///   produces into: the consumer's own lane, or the shared lane when the
///   consumer produces into none of its own.
/// - Refused: a `merge` edge that reaches no target's `net_in`; a module
///   producing into one target twice, or both alone and in the shared lane
///   (its events would have two lanes); a consumer of `net_out` with no
///   lane to read; a lane whose events reach no one; and a lane edge with a
///   class other than `local` or `merge`, since a lane's channels are taken
///   by its target whole and never split.
fn assign_node_lanes(
    config: &Value,
    edges: &[(u16, u16, u8, u8, u8)],
    names: &[String],
    types: &[String],
    manifests: &HashMap<String, Manifest>,
) -> Result<Vec<NodeLanes>> {
    let targets = lane_targets(names, types, manifests);
    let wiring = config.get("wiring").and_then(Value::as_array);
    let class_of = |i: usize| {
        wiring
            .and_then(|w| w.get(i))
            .and_then(|e| e.get("edge_class"))
            .and_then(Value::as_str)
            .unwrap_or("local")
    };
    let spec = |i: usize, key: &str| {
        wiring
            .and_then(|w| w.get(i))
            .and_then(|e| e.get(key))
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string()
    };
    let into = |i: usize, t: (u16, u32, u8, u8)| {
        let e = edges[i];
        e.1 == t.0 && e.2 == 0 && e.4 == t.2
    };
    let out_of = |i: usize, t: (u16, u32, u8, u8)| {
        let e = edges[i];
        e.0 == t.0 && e.3 == t.3
    };
    for i in 0..edges.len() {
        if merge_marked(config, i) && !targets.iter().any(|&t| into(i, t)) {
            return Err(Error::Config(format!(
                "wiring[{i}] ({} → {}): `edge_class: merge` puts an edge into a lane target's \
                 `{LANE_COMMANDS_PORT}` into the lane it shares; this edge reaches no lane",
                spec(i, "from"),
                spec(i, "to")
            )));
        }
    }
    let mut out = Vec::new();
    for t in targets {
        let target_name = &names[usize::from(t.0)];
        let mut keys: Vec<Option<u8>> = vec![None; edges.len()];
        // (producer, key) of each lane of its own, and the shared lane.
        let mut own: Vec<(u16, u8)> = Vec::new();
        let mut shared: Option<u8> = None;
        let mut shared_producers: Vec<u16> = Vec::new();
        let mut count = 0usize;
        for i in (0..edges.len()).filter(|&i| into(i, t) || out_of(i, t)) {
            let class = class_of(i);
            if class != "local" && class != MERGE_EDGE_CLASS {
                return Err(Error::Config(format!(
                    "wiring[{i}] ({} → {}): a lane of `{target_name}` is `edge_class: {class}`; \
                     a lane's channels are its target's to take whole, never split or \
                     handed to a device",
                    spec(i, "from"),
                    spec(i, "to")
                )));
            }
        }
        for i in (0..edges.len()).filter(|&i| into(i, t)) {
            let p = edges[i].0;
            let producer = &names[usize::from(p)];
            let twice = || {
                Error::Config(format!(
                    "wiring[{i}] ({} → {}): `{producer}` already produces into a lane of \
                     `{target_name}`; one module's events would have two lanes. Wire it once, \
                     or mark every one of its edges `edge_class: merge`",
                    spec(i, "from"),
                    spec(i, "to")
                ))
            };
            let key = if merge_marked(config, i) {
                if own.iter().any(|&(q, _)| q == p) {
                    return Err(twice());
                }
                shared_producers.push(p);
                *shared.get_or_insert_with(|| {
                    count += 1;
                    (count - 1) as u8
                })
            } else {
                if own.iter().any(|&(q, _)| q == p) || shared_producers.contains(&p) {
                    return Err(twice());
                }
                count += 1;
                own.push((p, (count - 1) as u8));
                (count - 1) as u8
            };
            if count > crate::capacity::kernel_lane_ceiling() as usize {
                return Err(Error::Config(format!(
                    "`{target_name}`: {count} lanes in the node's graph, past the {} a lane \
                     key names",
                    crate::capacity::kernel_lane_ceiling()
                )));
            }
            keys[i] = Some(key);
        }
        let mut read = vec![false; count];
        for i in (0..edges.len()).filter(|&i| out_of(i, t)) {
            let c = edges[i].1;
            let key = match own.iter().find(|&&(q, _)| q == c) {
                Some(&(_, k)) => k,
                None => shared.ok_or_else(|| {
                    Error::Config(format!(
                        "wiring[{i}] ({} → {}): `{}` reads `{target_name}`'s events but \
                         produces into no lane of it, and no edge is marked `edge_class: \
                         merge` to give it the shared lane",
                        spec(i, "from"),
                        spec(i, "to"),
                        names[usize::from(c)]
                    ))
                })?,
            };
            read[usize::from(key)] = true;
            keys[i] = Some(key);
        }
        if let Some(k) = (0..count).find(|&k| !read[k]) {
            let who = match own.iter().find(|&&(_, key)| usize::from(key) == k) {
                Some(&(p, _)) => format!("`{}`", names[usize::from(p)]),
                None => "the shared lane (`edge_class: merge`)".to_string(),
            };
            return Err(Error::Config(format!(
                "{who} produces into `{target_name}.{LANE_COMMANDS_PORT}` and nothing reads \
                 its lane's events: wire `{target_name}.{LANE_EVENTS_PORT}` to it"
            )));
        }
        if count > 0 {
            out.push(NodeLanes {
                module: t.0,
                target: t.1,
                keys,
                count,
            });
        }
    }
    Ok(out)
}

/// The lane key edge `i` carries, and its target, when it is a lane.
fn lane_of_edge(lanes: &[NodeLanes], i: usize) -> Option<(&NodeLanes, u8)> {
    lanes
        .iter()
        .find_map(|l| l.keys.get(i).copied().flatten().map(|k| (l, k)))
}

/// The name of a lane target's capacity param in instance `entry`: the
/// manifest's, or, for a manifest read back from a packed module, the
/// schema's param under its tag.
fn lanes_param_name(entry: &Value, manifest: &Manifest, r: &ModuleResolver) -> Option<String> {
    let decl = manifest.lanes.as_ref()?;
    if !decl.param.is_empty() {
        return Some(decl.param.clone());
    }
    let schema = schema::entry_schema(entry, r).ok()??;
    schema
        .params
        .iter()
        .find(|p| p.tag == decl.tag)
        .map(|p| p.name.clone())
}

/// Give every lane target the node graph's lanes beside its workload lanes:
/// its capacity param becomes what the instance states for workloads — or,
/// left unset, the param's default in the module it is built from
/// (`default_of`) — plus the lanes [`assign_node_lanes`] gives it, at most a
/// lane key's range.
fn add_node_lanes(
    modules: &mut [Value],
    lanes: &[NodeLanes],
    names: &[String],
    manifests: &HashMap<String, Manifest>,
    default_of: &dyn Fn(&Value, &str) -> Option<u64>,
    r: &ModuleResolver,
) -> Result<()> {
    let ceiling = crate::capacity::kernel_lane_ceiling();
    for l in lanes {
        let name = &names[usize::from(l.module)];
        let Some(manifest) = manifests.get(name) else {
            continue;
        };
        let Some(module) = modules
            .iter_mut()
            .find(|m| m.get("name").and_then(Value::as_str) == Some(name.as_str()))
        else {
            continue;
        };
        let Some(param) = lanes_param_name(module, manifest, r) else {
            return Err(Error::Config(format!(
                "`{name}` serves lanes, and its build names no param their capacity is read \
                 from"
            )));
        };
        let workload = match entry_param(module, &param) {
            Some(v) => v.as_u64().ok_or_else(|| {
                Error::Config(format!("`{name}`: `{param}` is not a count of lanes"))
            })?,
            None => default_of(module, &param)
                .unwrap_or_else(|| u64::from(manifest.lanes.as_ref().map_or(0, |d| d.default))),
        };
        let total = workload + l.count as u64;
        if total > ceiling {
            return Err(Error::Config(format!(
                "`{name}` serves {workload} workload lane(s) (`{param}`) and the node's graph \
                 wires {} lane(s) to it: {total}, past the {ceiling} a lane key names",
                l.count
            )));
        }
        if let Some(obj) = module.as_object_mut() {
            obj.insert(param, json!(total));
        }
    }
    Ok(())
}

/// The lanes the node's graph declares together, against what the target's
/// kernel holds: at most `MAX_TARGETS` lane targets, and on a kernel whose
/// lane table is compiled in (`STATIC_LANES`, wasm) at most that many lanes,
/// workload lanes included, across them. Where the table is sized at boot it
/// is held by the memory it is sized from, which the boot plan checks.
fn check_lane_capacity(
    modules: &[Value],
    names: &[String],
    manifests: &HashMap<String, Manifest>,
    target: &str,
    r: &ModuleResolver,
) -> Result<()> {
    let mut declared: Vec<(String, u64)> = Vec::new();
    for name in names {
        let Some(manifest) = manifests.get(name).filter(|m| m.lanes.is_some()) else {
            continue;
        };
        let Some(module) = modules
            .iter()
            .find(|m| m.get("name").and_then(Value::as_str) == Some(name.as_str()))
        else {
            continue;
        };
        let cap = lanes_param_name(module, manifest, r)
            .and_then(|p| entry_param(module, &p).and_then(Value::as_u64))
            .unwrap_or_else(|| u64::from(manifest.lanes.as_ref().map_or(0, |d| d.default)));
        if cap > 0 {
            declared.push((name.clone(), cap));
        }
    }
    let targets = crate::capacity::kernel_lane_targets();
    if declared.len() as u64 > targets {
        return Err(Error::Config(format!(
            "{} modules serve lanes ({}), past the {targets} lane targets the kernel holds",
            declared.len(),
            declared
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    if let Some(table) = crate::capacity::kernel_static_lanes(target) {
        let total: u64 = declared.iter().map(|(_, c)| c).sum();
        if total > table {
            return Err(Error::Config(format!(
                "the graph declares {total} lanes ({}), past the {table} the {target} kernel's \
                 lane table holds (`STATIC_LANES`)",
                declared
                    .iter()
                    .map(|(n, c)| format!("{n} {c}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
    }
    Ok(())
}
