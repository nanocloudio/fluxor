//! How deep a module's calls into module providers go.
//!
//! A module provider runs in its caller's frame, on its caller's core and
//! stack: a `provider_call` enters the kernel, which calls the provider's
//! `module_provider_dispatch` right there, and that provider may call its
//! own providers the same way. So what a module needs of the stack it steps
//! on is its own depth plus, for the deepest provider it can reach, one
//! kernel hop and that provider's whole chain. The composer admits that sum
//! (`check_stack_budget`), not the module's own figure alone.
//!
//! What a module reaches: the providers of every `[[resources]]` claim its
//! configuration exercises (`active_when_params`; a claim conditioned with
//! `when` counts, since only the module's schema resolves it), and the peer
//! of every port it binds as an edge contract's client (`contract =
//! "storage.block"`). A claim whose contract several instances provide
//! (volumes, routed by a selector) reaches the deepest of them.

use std::collections::HashMap;

use serde_json::Value;

use crate::manifest::Manifest;

/// The kernel's own frames on one hop, from a module's `provider_call` to
/// the provider's `module_provider_dispatch`: the syscall entry, the
/// provider table's routing and the gateway's argument checks. Measured on
/// the RP images (`kernel_stack_bound.py --root syscall_provider_call`,
/// handlers not followed: 1,192 B on RP2350, 1,224 B on RP2040, 2026-11-25)
/// and rounded up to 64 B. Every target is admitted with this one figure;
/// the hosted and aarch64 stacks it is small beside are not the ones it
/// binds.
pub const PROVIDER_HOP_BYTES: u64 = 1280;

/// One provider on a chain: the instance and the contract it was reached
/// through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    pub instance: String,
    pub contract: String,
}

/// The deepest provider chain under one caller: the bytes it adds to the
/// caller's own depth (each hop's [`PROVIDER_HOP_BYTES`] and each
/// provider's own depth) and the hops, outermost first. Empty when the
/// caller reaches no module provider.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Chain {
    pub bytes: u64,
    pub hops: Vec<Hop>,
}

impl Chain {
    /// The chain as a reader follows it: `caller → p1 (contract) → …`.
    pub fn describe(&self, caller: &str) -> String {
        let mut s = caller.to_string();
        for h in &self.hops {
            s.push_str(&format!(" → {} ({})", h.instance, h.contract));
        }
        s
    }
}

/// `instance`'s module entry in `config`.
fn entry<'a>(config: &'a Value, instance: &str) -> Option<&'a Value> {
    config
        .get("modules")
        .and_then(Value::as_array)?
        .iter()
        .find(|m| m.get("name").and_then(Value::as_str) == Some(instance))
}

/// A param of `instance` as text, on the entry or under `params:`.
fn param(config: &Value, instance: &str, key: &str) -> Option<String> {
    let e = entry(config, instance)?;
    let v = e
        .get(key)
        .or_else(|| e.get("params").and_then(|p| p.get(key)))?;
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

fn provides(m: &Manifest, contract: &str) -> bool {
    m.provides
        .iter()
        .any(|p| p == contract || (p == "file.data" && contract == "fs"))
}

/// The module providers `instance` calls into directly, each with the
/// contract it reaches them through.
pub fn providers_called<S: std::hash::BuildHasher>(
    config: &Value,
    manifests: &HashMap<String, Manifest, S>,
    instance: &str,
) -> Vec<Hop> {
    let Some(m) = manifests.get(instance) else {
        return Vec::new();
    };
    let mut out: Vec<Hop> = Vec::new();
    let mut push = |h: Hop| {
        if h.instance != instance && !out.contains(&h) {
            out.push(h);
        }
    };
    for claim in &m.resources {
        if !claim.variants.is_empty()
            && !m
                .selected_variant
                .as_ref()
                .is_some_and(|v| claim.variants.contains(v))
        {
            continue;
        }
        if !claim.exercised_by(|p| param(config, instance, p)) {
            continue;
        }
        let contract = crate::manifest::contract_name_to_str(claim.device_class);
        let mut names: Vec<&String> = manifests.keys().collect();
        names.sort();
        for name in names {
            if provides(&manifests[name], contract) {
                push(Hop {
                    instance: name.clone(),
                    contract: contract.to_string(),
                });
            }
        }
    }
    // Edge contracts: the port's one peer serves it.
    let wiring = config.get("wiring").and_then(Value::as_array);
    for port in &m.ports {
        let (Some(contract), Some(pname)) = (port.contract.as_deref(), port.name.as_deref()) else {
            continue;
        };
        let here = format!("{instance}.{pname}");
        for w in wiring.into_iter().flatten() {
            let (Some(from), Some(to)) = (
                w.get("from").and_then(Value::as_str),
                w.get("to").and_then(Value::as_str),
            ) else {
                continue;
            };
            let peer = if to == here || to.starts_with(&format!("{here}[")) {
                from
            } else if from == here || from.starts_with(&format!("{here}[")) {
                to
            } else {
                continue;
            };
            let peer = peer.split(['.', '[']).next().unwrap_or(peer);
            if manifests.contains_key(peer) {
                push(Hop {
                    instance: peer.to_string(),
                    contract: contract.to_string(),
                });
            }
        }
    }
    out
}

/// The deepest chain of module providers under `instance`, each provider
/// counted at `stack_of(provider instance)` bytes. A provider reached again
/// along its own chain (a cycle) is not walked twice.
pub fn deepest_chain<S: std::hash::BuildHasher>(
    config: &Value,
    manifests: &HashMap<String, Manifest, S>,
    instance: &str,
    stack_of: &dyn Fn(&str) -> u64,
) -> Chain {
    let mut path = vec![instance.to_string()];
    walk(config, manifests, instance, stack_of, &mut path)
}

fn walk<S: std::hash::BuildHasher>(
    config: &Value,
    manifests: &HashMap<String, Manifest, S>,
    instance: &str,
    stack_of: &dyn Fn(&str) -> u64,
    path: &mut Vec<String>,
) -> Chain {
    let mut best = Chain::default();
    for hop in providers_called(config, manifests, instance) {
        if path.contains(&hop.instance) {
            continue;
        }
        path.push(hop.instance.clone());
        let below = walk(config, manifests, &hop.instance, stack_of, path);
        path.pop();
        let bytes = PROVIDER_HOP_BYTES + stack_of(&hop.instance) + below.bytes;
        if bytes > best.bytes {
            let mut hops = vec![hop];
            hops.extend(below.hops);
            best = Chain { bytes, hops };
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn manifest(toml: &str) -> Manifest {
        Manifest::from_toml_str_for_target(&format!("version = \"1.0.0\"\n{toml}"), None)
            .expect("manifest parses")
    }

    #[test]
    fn the_chain_follows_exercised_claims_and_edge_ports_to_the_deepest() {
        let mut m = HashMap::new();
        m.insert(
            "tls".to_string(),
            manifest(
                "[[resources]]\nrequires_contract = \"key_vault\"\naccess = \"write\"\n\
                 active_when_params = [\"key_file\"]\n",
            ),
        );
        m.insert(
            "vault".to_string(),
            manifest(
                "provides = [\"key_vault\"]\nprovider_contracts = [\"key_vault\"]\n\
                 [[ports]]\nname = \"blocks\"\ndirection = \"input\"\n\
                 content_type = \"OctetStream\"\nrequired = false\n\
                 contract = \"storage.block\"\n",
            ),
        );
        m.insert(
            "flash".to_string(),
            manifest(
                "provider_contracts = [\"storage.block\"]\n\
                 [[ports]]\nname = \"store\"\ndirection = \"output\"\n\
                 content_type = \"OctetStream\"\nserves = \"storage.block\"\n",
            ),
        );
        let stacks = |n: &str| match n {
            "tls" => 6000,
            "vault" => 3000,
            "flash" => 500,
            _ => 0,
        };
        let graph = |tls: Value| {
            json!({
                "modules": [tls, {"name": "vault"}, {"name": "flash"}],
                "wiring": [{"from": "flash.store", "to": "vault.blocks"}],
            })
        };
        // No identity: the claim is not exercised, no chain.
        let g = graph(json!({"name": "tls"}));
        assert_eq!(deepest_chain(&g, &m, "tls", &stacks), Chain::default());
        let g = graph(json!({"name": "tls", "key_file": "/k.der"}));
        let c = deepest_chain(&g, &m, "tls", &stacks);
        assert_eq!(c.bytes, 2 * PROVIDER_HOP_BYTES + 3000 + 500);
        assert_eq!(
            c.describe("tls"),
            "tls → vault (key_vault) → flash (storage.block)"
        );
        // The vault's own chain.
        let v = deepest_chain(&g, &m, "vault", &stacks);
        assert_eq!(v.bytes, PROVIDER_HOP_BYTES + 500);
    }
}
