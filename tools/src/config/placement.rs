// Members composed from another node.
//
// A graph is instantiated on one node, but a continuity declaration may
// name members that live elsewhere — a session directory on a cluster
// node, a fence agent on a host outside the failure domain. A `modules[]`
// entry placed with `node: <name>` is such a member: the composer reads
// its manifest, so the declaration can count on its capabilities and
// facts, and instantiates nothing for it here. The graph reaches it over
// a remote channel it wires explicitly; a wire that names it directly is
// refused, because there is no local instance for the wire to land on.
//
// Placed members are lifted out of `modules` into `remote_members` while
// the graph is normalised, ahead of every pass that reads the module
// list, so nothing downstream has to know that a placement exists: the
// list holds exactly what this node runs, and the two accessors below are
// the only way to the rest.

/// The top-level key placed members are lifted into.
pub const REMOTE_MEMBERS_KEY: &str = "remote_members";

/// The keys a placed member may carry: what identifies the module and
/// where it runs. Its parameters and its wiring belong to the graph that
/// instantiates it, and `variant` is part of the identity because it
/// selects which surface the manifest publishes.
const REMOTE_MEMBER_KEYS: &[&str] = &["name", "type", "node", "variant"];

/// Move every `modules[]` entry carrying a non-empty `node` into
/// `remote_members`. Idempotent: a graph already lifted is unchanged.
pub fn lift_remote_members(config: &mut Value) -> Result<()> {
    let Some(list) = config.get("modules").and_then(|m| m.as_array()).cloned() else {
        return Ok(());
    };
    let mut local = Vec::with_capacity(list.len());
    let mut remote = Vec::new();
    for entry in list {
        match entry.get("node") {
            None | Some(Value::Null) => local.push(entry),
            Some(Value::String(node)) if node.is_empty() => {
                return Err(Error::Config(format!(
                    "module `{}`: `node` names the node a member is placed on and cannot be \
                     empty; drop the key for a member this graph instantiates",
                    entry_name(&entry)
                )));
            }
            Some(Value::String(_)) => {
                if let Some(obj) = entry.as_object() {
                    let extra: Vec<&String> = obj
                        .keys()
                        .filter(|k| !REMOTE_MEMBER_KEYS.contains(&k.as_str()))
                        .collect();
                    if !extra.is_empty() {
                        return Err(Error::Config(format!(
                            "module `{}` is placed on node `{}` and carries {}: a placed member \
                             is declared by name, type, node and variant only — its \
                             parameters and its wiring belong to the graph that instantiates \
                             it",
                            entry_name(&entry),
                            entry["node"].as_str().unwrap_or_default(),
                            extra
                                .iter()
                                .map(|k| format!("`{k}`"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )));
                    }
                }
                if entry.get("name").and_then(|n| n.as_str()).is_none() {
                    return Err(Error::Config(
                        "a placed member (`node:`) needs a `name`".into(),
                    ));
                }
                remote.push(entry);
            }
            Some(other) => {
                return Err(Error::Config(format!(
                    "module `{}`: `node` must be a string (got {other})",
                    entry_name(&entry)
                )));
            }
        }
    }
    if remote.is_empty() {
        return Ok(());
    }
    let Some(obj) = config.as_object_mut() else {
        return Ok(());
    };
    obj.insert("modules".into(), Value::Array(local));
    let existing = obj
        .get(REMOTE_MEMBERS_KEY)
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut all = existing;
    all.extend(remote);
    obj.insert(REMOTE_MEMBERS_KEY.into(), Value::Array(all));
    Ok(())
}

fn entry_name(entry: &Value) -> String {
    entry
        .get("name")
        .and_then(|n| n.as_str())
        .or_else(|| entry.get("type").and_then(|t| t.as_str()))
        .unwrap_or("?")
        .to_string()
}

/// The placed members of a lifted graph.
pub fn remote_members(config: &Value) -> Vec<Value> {
    config
        .get(REMOTE_MEMBERS_KEY)
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default()
}

/// The names of a lifted graph's placed members.
pub fn remote_member_names(config: &Value) -> Vec<String> {
    remote_members(config)
        .iter()
        .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect()
}

/// Refuse any wire whose endpoint names a placed member.
pub fn refuse_wiring_to_remote(config: &Value) -> Result<()> {
    let remote = remote_member_names(config);
    if remote.is_empty() {
        return Ok(());
    }
    let Some(wiring) = config.get("wiring").and_then(|w| w.as_array()) else {
        return Ok(());
    };
    for wire in wiring {
        for end in ["from", "to"] {
            let Some(spec) = wire.get(end).and_then(|v| v.as_str()) else {
                continue;
            };
            let module = spec.split('.').next().unwrap_or(spec);
            if let Some(name) = remote.iter().find(|n| n.as_str() == module) {
                let node = remote_members(config)
                    .iter()
                    .find(|m| m.get("name").and_then(|n| n.as_str()) == Some(name))
                    .and_then(|m| m.get("node").and_then(|n| n.as_str()).map(String::from))
                    .unwrap_or_default();
                return Err(Error::Config(format!(
                    "wiring `{end}: {spec}` names `{name}`, a member placed on node `{node}`; \
                     nothing is instantiated for it here, so no wire can land on it — reach it \
                     through a remote channel this graph wires explicitly"
                )));
            }
        }
    }
    Ok(())
}

// ── Exchange endpoints ──────────────────────────────────────────────────────
//
// A requester reaches a provider on another node through a
// `remote_channel` with `exchange: near`, wired as the provider would be
// (`request_in`, `response_out`); beside the provider, an instance with
// `exchange: far` is wired as the requester would be (`request_out`,
// `response_in`). What one graph shows is checked here: each instance's
// mode against the ports its wiring uses, each endpoint's pair landing on
// one module, and a near endpoint for every placed exchange provider. Which
// near endpoint dials which placed provider is the endpoint's `authority`,
// a network name, and the far side is in another node's graph — so neither
// is checked here.

/// The module type that carries exchanges across nodes.
const REMOTE_CHANNEL: &str = "remote_channel";

/// A remote channel's exchange side, from its `exchange` parameter.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ExchangeSide {
    None,
    Near,
    Far,
}

fn exchange_side(entry: &Value) -> Result<ExchangeSide> {
    let v = entry
        .get("exchange")
        .or_else(|| entry.get("params").and_then(|p| p.get("exchange")));
    match v {
        None | Some(Value::Null) => Ok(ExchangeSide::None),
        Some(Value::String(s)) if s == "none" => Ok(ExchangeSide::None),
        Some(Value::String(s)) if s == "near" => Ok(ExchangeSide::Near),
        Some(Value::String(s)) if s == "far" => Ok(ExchangeSide::Far),
        Some(v) if v.as_u64() == Some(0) => Ok(ExchangeSide::None),
        Some(v) if v.as_u64() == Some(1) => Ok(ExchangeSide::Near),
        Some(v) if v.as_u64() == Some(2) => Ok(ExchangeSide::Far),
        Some(other) => Err(Error::Config(format!(
            "remote_channel `{}`: `exchange` is `near`, `far` or `none` (got {other})",
            entry_name(entry)
        ))),
    }
}

/// Whether a manifest serves exchanges: a request input and a response
/// output.
fn is_exchange_provider(manifest: &Manifest) -> bool {
    let ct = |name: &str| {
        fluxor_contracts::CONTENT_TYPES
            .iter()
            .position(|t| *t == name)
            .map(|i| i as u8)
    };
    let (Some(req), Some(resp)) = (ct("ExchangeRequest"), ct("ExchangeResponse")) else {
        return false;
    };
    manifest
        .ports
        .iter()
        .any(|p| p.direction == 0 && p.content_type == req)
        && manifest
            .ports
            .iter()
            .any(|p| p.direction == 1 && p.content_type == resp)
}

/// Check every `remote_channel`'s exchange endpoint against its wiring, and
/// that each placed exchange provider has a near endpoint to reach it by.
///
/// `edges` are the resolved wires (`from`, `to`, `to_port` 1 for a control
/// input, `from` port index, `to` port index) over `module_names`;
/// `manifests` are the local modules' by instance name, `remote_manifests`
/// the placed members'.
pub fn validate_exchange_placement(
    config: &Value,
    edges: &[(u16, u16, u8, u8, u8)],
    module_names: &[String],
    manifests: &HashMap<String, Manifest>,
    remote_manifests: &HashMap<String, Manifest>,
) -> Result<()> {
    let modules: Vec<&Value> = config
        .get("modules")
        .and_then(|m| m.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let mut near_endpoints = 0usize;
    for (id, entry) in modules.iter().enumerate() {
        let name = entry_name(entry);
        let ty = entry.get("type").and_then(|t| t.as_str()).unwrap_or(&name);
        if ty != REMOTE_CHANNEL {
            continue;
        }
        let side = exchange_side(entry)?;
        let Some(manifest) = manifests.get(&name) else {
            continue;
        };
        let index = |direction: u8, port: &str| {
            manifest
                .ports
                .iter()
                .find(|p| p.direction == direction && p.name.as_deref() == Some(port))
                .map(|p| p.index)
        };
        let id = id as u16;
        // The modules wired into input `port` / out of output `port`.
        let into = |port: &str| -> Vec<&str> {
            let Some(i) = index(0, port) else {
                return Vec::new();
            };
            edges
                .iter()
                .filter(|e| e.1 == id && e.2 == 0 && e.4 == i)
                .map(|e| module_names[e.0 as usize].as_str())
                .collect()
        };
        let out_of = |port: &str| -> Vec<&str> {
            let Some(i) = index(1, port) else {
                return Vec::new();
            };
            edges
                .iter()
                .filter(|e| e.0 == id && e.3 == i)
                .map(|e| module_names[e.1 as usize].as_str())
                .collect()
        };
        let request_in = into("request_in");
        let response_out = out_of("response_out");
        let request_out = out_of("request_out");
        let response_in = into("response_in");
        let wired = |ports: &[(&str, &Vec<&str>)]| -> Vec<String> {
            ports
                .iter()
                .filter(|(_, w)| !w.is_empty())
                .map(|(p, _)| format!("`{p}`"))
                .collect()
        };
        let near_ports = wired(&[("request_in", &request_in), ("response_out", &response_out)]);
        let far_ports = wired(&[("request_out", &request_out), ("response_in", &response_in)]);
        // The endpoint's own pair, and the module both its edges must reach.
        let (pair, other, peer_role, a, b) = match side {
            ExchangeSide::None => {
                let any: Vec<String> = near_ports.iter().chain(&far_ports).cloned().collect();
                if !any.is_empty() {
                    return Err(Error::Config(format!(
                        "remote_channel `{name}` has `exchange: none` but its exchange port(s) \
                         {} are wired; set `exchange: near` where it stands in for a provider \
                         on another node (the requester's side), or `exchange: far` where it \
                         stands in for the remote requester (beside the provider)",
                        any.join(", ")
                    )));
                }
                continue;
            }
            ExchangeSide::Near => (
                near_ports,
                far_ports,
                "requester",
                (&request_in, "request_in"),
                (&response_out, "response_out"),
            ),
            ExchangeSide::Far => (
                far_ports,
                near_ports,
                "provider",
                (&request_out, "request_out"),
                (&response_in, "response_in"),
            ),
        };
        let (mode, stands_in, other_mode) = match side {
            ExchangeSide::Near => ("near", "the remote provider", "far"),
            _ => ("far", "the remote requester", "near"),
        };
        if !other.is_empty() {
            return Err(Error::Config(format!(
                "remote_channel `{name}` is `exchange: {mode}` — it stands in for {stands_in}, \
                 with `{}` and `{}` — but {} {} wired, which are the `exchange: {other_mode}` \
                 side's; set `exchange: {other_mode}`, or wire the {peer_role} to `{}` and `{}`",
                a.1,
                b.1,
                other.join(" and "),
                if other.len() == 1 { "is" } else { "are" },
                a.1,
                b.1,
            )));
        }
        if pair.len() != 2 {
            let (have, missing) = if a.0.is_empty() {
                (b.1, a.1)
            } else {
                (a.1, b.1)
            };
            return Err(Error::Config(if pair.is_empty() {
                format!(
                    "remote_channel `{name}` is `exchange: {mode}` but neither `{}` nor `{}` \
                     is wired: it stands in for {stands_in}, so wire the {peer_role} to both, \
                     or drop `exchange`",
                    a.1, b.1
                )
            } else {
                format!(
                    "remote_channel `{name}` is `exchange: {mode}` and wires `{have}` but not \
                     `{missing}`: an exchange crosses as a pair, so wire the {peer_role} to both"
                )
            }));
        }
        if a.0.len() > 1 || b.0.len() > 1 {
            return Err(Error::Config(format!(
                "remote_channel `{name}` (`exchange: {mode}`) is wired to {} on `{}` and {} on \
                 `{}`: an endpoint carries one {peer_role}'s exchange — ids cross verbatim, so \
                 {peer_role}s that share it go through a local relay that owns their ids",
                a.0.join(", "),
                a.1,
                b.0.join(", "),
                b.1
            )));
        }
        if a.0[0] != b.0[0] {
            return Err(Error::Config(format!(
                "remote_channel `{name}` (`exchange: {mode}`) takes `{}` from `{}` but `{}` goes \
                 to `{}`: both halves of the exchange are one {peer_role}'s, wired to the same \
                 module",
                a.1, a.0[0], b.1, b.0[0]
            )));
        }
        if side == ExchangeSide::Near {
            near_endpoints += 1;
        }
    }

    let placed: Vec<String> = remote_members(config)
        .iter()
        .filter_map(|m| {
            let name = m.get("name").and_then(|n| n.as_str())?;
            let manifest = remote_manifests.get(name)?;
            is_exchange_provider(manifest).then(|| {
                let node = m.get("node").and_then(|n| n.as_str()).unwrap_or_default();
                format!("`{name}` (node `{node}`)")
            })
        })
        .collect();
    if placed.len() > near_endpoints {
        return Err(Error::Config(format!(
            "{} {} an exchange provider placed on another node, and this graph has {} \
             `remote_channel` with `exchange: near` to reach {}: a requester reaches a placed \
             provider only through a near endpoint, wired to `request_in` and `response_out` \
             as the provider would be — one endpoint per placed provider",
            placed.join(", "),
            if placed.len() == 1 { "is" } else { "are" },
            near_endpoints,
            if placed.len() == 1 { "it" } else { "them" },
        )));
    }
    Ok(())
}

#[cfg(test)]
mod placement_tests {
    use super::*;

    #[test]
    fn lift_moves_placed_members_out_of_modules() {
        let mut cfg = json!({"modules": [
            {"name": "a", "x": 1},
            {"name": "b", "type": "agent", "node": "bench"}]});
        lift_remote_members(&mut cfg).unwrap();
        assert_eq!(cfg["modules"].as_array().unwrap().len(), 1);
        assert_eq!(remote_member_names(&cfg), vec!["b".to_string()]);
        // Idempotent.
        lift_remote_members(&mut cfg).unwrap();
        assert_eq!(remote_member_names(&cfg), vec!["b".to_string()]);
    }

    #[test]
    fn lift_refuses_parameters_on_a_placed_member() {
        let mut cfg = json!({"modules": [
            {"name": "b", "type": "agent", "node": "bench", "rig": "pi5-a"}]});
        let e = lift_remote_members(&mut cfg).unwrap_err();
        assert!(format!("{e:?}").contains("`rig`"), "got: {e:?}");
    }

    #[test]
    fn lift_keeps_the_variant_that_selects_a_members_surface() {
        // A variant decides which ports and capabilities the manifest
        // publishes, so it is part of naming the member, not a parameter.
        let mut cfg = json!({"modules": [
            {"name": "b", "type": "agent", "variant": "slim", "node": "bench"}]});
        lift_remote_members(&mut cfg).unwrap();
        let placed = remote_members(&cfg);
        assert_eq!(placed[0]["variant"], "slim");
    }

    #[test]
    fn lift_refuses_empty_or_non_string_node() {
        let mut cfg = json!({"modules": [{"name": "b", "node": ""}]});
        assert!(lift_remote_members(&mut cfg).is_err());
        let mut cfg = json!({"modules": [{"name": "b", "node": 3}]});
        assert!(lift_remote_members(&mut cfg).is_err());
    }

    #[test]
    fn wiring_to_a_placed_member_is_refused() {
        let mut cfg = json!({"modules": [
            {"name": "a"},
            {"name": "b", "node": "bench"}],
            "wiring": [{"from": "a.out", "to": "b.in"}]});
        lift_remote_members(&mut cfg).unwrap();
        let e = refuse_wiring_to_remote(&cfg).unwrap_err();
        assert!(
            format!("{e:?}").contains("placed on node `bench`"),
            "got: {e:?}"
        );
        let cfg = json!({"modules": [{"name": "a"}], "wiring": [{"from": "a.out", "to": "a.in"}]});
        refuse_wiring_to_remote(&cfg).unwrap();
    }

    fn rc_manifest() -> Manifest {
        let port = |direction: u8, index: u8, name: &str, ct: &str| crate::manifest::PortSpec {
            direction,
            content_type: fluxor_contracts::CONTENT_TYPES
                .iter()
                .position(|t| *t == ct)
                .unwrap() as u8,
            flags: 0,
            name: Some(name.to_string()),
            index,
            buffer_size: 0,
            max_record: 0,
            rate_class_max: None,
            rate_class_default: None,
            requires_capability: None,
            facts: Default::default(),
        };
        Manifest {
            ports: vec![
                port(0, 10, "request_in", "ExchangeRequest"),
                port(0, 11, "response_in", "ExchangeResponse"),
                port(1, 10, "response_out", "ExchangeResponse"),
                port(1, 11, "request_out", "ExchangeRequest"),
            ],
            ..Default::default()
        }
    }

    fn provider_manifest() -> Manifest {
        let mut m = rc_manifest();
        // A provider: requests in, responses out.
        m.ports.retain(|p| {
            p.name.as_deref() == Some("request_in") || p.name.as_deref() == Some("response_out")
        });
        m
    }

    /// `app` (0) and the endpoint `link` (1) with `exchange: side`, wired by
    /// `wires` as `(from, from port index, to, to port index)`, and a placed
    /// provider `objects` when `placed`.
    fn exchange_graph(side: &str, wires: &[(u16, u8, u16, u8)], placed: bool) -> Result<()> {
        let mut cfg = json!({"modules": [
            {"name": "app", "type": "requester"},
            {"name": "link", "type": "remote_channel", "exchange": side},
            {"name": "store", "type": "requester"}]});
        if placed {
            cfg["modules"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name": "objects", "type": "object_store", "node": "b"}));
        }
        lift_remote_members(&mut cfg).unwrap();
        let names: Vec<String> = ["app", "link", "store"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let edges: Vec<(u16, u16, u8, u8, u8)> = wires
            .iter()
            .map(|&(f, fp, t, tp)| (f, t, 0, fp, tp))
            .collect();
        let manifests = HashMap::from([("link".to_string(), rc_manifest())]);
        let remote = HashMap::from([("objects".to_string(), provider_manifest())]);
        validate_exchange_placement(&cfg, &edges, &names, &manifests, &remote)
    }

    // app.request_out is output 0, app.response_in input 0.
    const NEAR: [(u16, u8, u16, u8); 2] = [(0, 0, 1, 10), (1, 10, 0, 0)];
    const FAR: [(u16, u8, u16, u8); 2] = [(1, 11, 0, 0), (0, 0, 1, 11)];

    #[test]
    fn a_placed_provider_reached_through_a_near_endpoint_passes() {
        exchange_graph("near", &NEAR, true).unwrap();
        exchange_graph("far", &FAR, false).unwrap();
        exchange_graph("none", &[], false).unwrap();
    }

    #[test]
    fn a_placed_provider_without_a_near_endpoint_is_refused() {
        let e = exchange_graph("none", &[], true).unwrap_err().to_string();
        assert!(
            e.contains("`objects` (node `b`) is an exchange provider"),
            "{e}"
        );
        assert!(
            e.contains("has 0 `remote_channel` with `exchange: near`"),
            "{e}"
        );
    }

    #[test]
    fn an_endpoint_wired_as_the_other_side_is_refused() {
        let e = exchange_graph("far", &NEAR, true).unwrap_err().to_string();
        assert!(e.contains("is `exchange: far`"), "{e}");
        assert!(e.contains("set `exchange: near`"), "{e}");
        let e = exchange_graph("none", &NEAR, false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("has `exchange: none`"), "{e}");
    }

    #[test]
    fn a_near_pair_wired_inconsistently_is_refused() {
        // Only half the pair.
        let e = exchange_graph("near", &NEAR[..1], false)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("wires `request_in` but not `response_out`"),
            "{e}"
        );
        // Requests from app, answers to store.
        let e = exchange_graph("near", &[(0, 0, 1, 10), (1, 10, 2, 0)], false)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("takes `request_in` from `app` but `response_out` goes to `store`"),
            "{e}"
        );
        // Two requesters on one endpoint.
        let e = exchange_graph(
            "near",
            &[(0, 0, 1, 10), (2, 0, 1, 10), (1, 10, 0, 0)],
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("one requester's exchange"), "{e}");
    }

    #[test]
    fn an_unknown_exchange_mode_is_refused() {
        let e = exchange_graph("sideways", &[], false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("`exchange` is `near`, `far` or `none`"), "{e}");
    }
}
