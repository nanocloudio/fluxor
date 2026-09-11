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
        assert!(format!("{e:?}").contains("placed on node `bench`"), "got: {e:?}");
        let cfg = json!({"modules": [{"name": "a"}], "wiring": [{"from": "a.out", "to": "a.in"}]});
        refuse_wiring_to_remote(&cfg).unwrap();
    }
}
