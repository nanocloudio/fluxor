//! Declarative platform stack expansion.
//!
//! Reads `platform:` from user YAML, loads stack profiles from `stacks/*.toml`,
//! matches a variant against board/target metadata, and injects concrete
//! modules, wiring, params, and services into the config before the existing
//! config generation pipeline runs.
//!
//! See `.context/platform_stacks.md` for the full specification.

use std::collections::HashMap;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::target::TargetDescriptor;

// ============================================================================
// TOML data structures
// ============================================================================

#[derive(Deserialize)]
struct StackFile {
    stack: StackMeta,
    variant: Vec<StackVariant>,
}

#[derive(Deserialize)]
struct StackMeta {
    name: String,
    #[allow(dead_code)]
    provides: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct StackVariant {
    #[serde(rename = "match")]
    match_keys: HashMap<String, String>,
    #[serde(default)]
    modules: Vec<StackModule>,
    #[serde(default)]
    wiring: Vec<String>,
    service: Option<String>,
}

#[derive(Deserialize)]
struct StackModule {
    name: String,
    #[serde(default)]
    params: HashMap<String, String>,
}

// ============================================================================
// Public expansion entry point
// ============================================================================

/// Expand all `platform:` stacks into concrete modules, wiring, and services.
///
/// Must be called AFTER `resolve_target` (needs board_id/family) and AFTER
/// `translate_legacy_hardware_network`, but BEFORE config generation.
pub fn expand_platform_stacks(
    config: &mut Value,
    target: &TargetDescriptor,
    project_root: &std::path::Path,
) -> Result<Vec<String>> {
    let mut auto_added = Vec::new();

    let platform = match config.get("platform") {
        Some(p) => p.clone(),
        None => return Ok(auto_added),
    };
    let platform_map = match platform.as_object() {
        Some(m) => m.clone(),
        None => return Err(Error::Config("platform: must be a mapping".into())),
    };

    for (stack_name, user_fields) in &platform_map {
        let stack_file = load_stack(stack_name, project_root)?;
        let merged = merge_with_board_defaults(user_fields, stack_name, target);
        let variant = select_variant(&stack_file, &merged)?;
        let added = inject_variant(config, variant, &merged, &stack_file.stack)?;
        auto_added.extend(added);
    }

    // Remove platform: key so downstream code doesn't see it
    if let Some(obj) = config.as_object_mut() {
        obj.remove("platform");
    }

    Ok(auto_added)
}

// ============================================================================
// Stack loading
// ============================================================================

fn load_stack(name: &str, project_root: &std::path::Path) -> Result<StackFile> {
    let path = project_root.join("stacks").join(format!("{}.toml", name));
    let content = std::fs::read_to_string(&path).map_err(|e| {
        Error::Config(format!(
            "Unknown platform stack '{}' (no {}): {}",
            name,
            path.display(),
            e
        ))
    })?;
    toml::from_str(&content).map_err(|e| {
        Error::Config(format!("Failed to parse {}: {}", path.display(), e))
    })
}

// ============================================================================
// Board defaults merge
// ============================================================================

fn merge_with_board_defaults(
    user_fields: &Value,
    stack_name: &str,
    target: &TargetDescriptor,
) -> HashMap<String, String> {
    let mut merged: HashMap<String, String> = HashMap::new();

    // Start with board defaults
    if let Some(defaults) = target.platform_defaults.get(stack_name) {
        for (k, v) in defaults {
            merged.insert(k.clone(), v.clone());
        }
    }

    // Check if user overrides phy (clears board driver)
    let user_overrides_phy = user_fields
        .as_object()
        .map_or(false, |o| o.contains_key("phy"));

    // User fields override
    if let Some(obj) = user_fields.as_object() {
        for (k, v) in obj {
            let s = match v {
                Value::String(s) => s.clone(),
                Value::Bool(true) => "true".into(),
                Value::Bool(false) => "false".into(),
                Value::Number(n) => n.to_string(),
                _ => continue,
            };
            merged.insert(k.clone(), s);
        }
    }

    // If user set phy but not driver, clear the board default driver
    // (drivers are phy-specific — cyw43 is WiFi, not Ethernet)
    if user_overrides_phy
        && !user_fields
            .as_object()
            .map_or(false, |o| o.contains_key("driver"))
    {
        merged.remove("driver");
    }

    // Inject target metadata (available for matching but not user-set)
    if let Some(ref board) = target.board_id {
        merged.entry("board".into()).or_insert_with(|| board.clone());
    }
    merged
        .entry("family".into())
        .or_insert_with(|| target.family.clone());

    merged
}

// ============================================================================
// Variant matching
// ============================================================================

fn select_variant<'a>(
    stack: &'a StackFile,
    merged: &HashMap<String, String>,
) -> Result<&'a StackVariant> {
    let mut eligible: Vec<(&StackVariant, u32)> = Vec::new();

    for variant in &stack.variant {
        // Filter: every key in the match block must equal the merged config
        let all_match = variant.match_keys.iter().all(|(mk, mv)| {
            merged.get(mk).map_or(false, |v| v == mv)
        });
        if !all_match {
            continue;
        }

        // Score by specificity
        let score: u32 = variant
            .match_keys
            .keys()
            .map(|k| match k.as_str() {
                "board" => 3,
                "family" => 2,
                _ => 1, // phy, media, driver, etc.
            })
            .sum();

        eligible.push((variant, score));
    }

    if eligible.is_empty() {
        return Err(Error::Config(format!(
            "platform.{}: no matching variant for config {:?}",
            stack.stack.name, merged
        )));
    }

    eligible.sort_by(|a, b| b.1.cmp(&a.1));

    if eligible.len() > 1 && eligible[0].1 == eligible[1].1 {
        return Err(Error::Config(format!(
            "platform.{}: ambiguous — two variants tied at score {}",
            stack.stack.name, eligible[0].1
        )));
    }

    Ok(eligible[0].0)
}

// ============================================================================
// Injection
// ============================================================================

fn inject_variant(
    config: &mut Value,
    variant: &StackVariant,
    merged: &HashMap<String, String>,
    stack_meta: &StackMeta,
) -> Result<Vec<String>> {
    let mut added = Vec::new();

    // Collect existing module names for dedup
    let existing = collect_module_names(config);

    // Ensure arrays exist
    if config.get("modules").is_none() {
        config["modules"] = json!([]);
    }
    if config.get("wiring").is_none() {
        config["wiring"] = json!([]);
    }

    // Inject modules (prepend for lower IDs → earlier instantiation)
    let mut to_prepend = Vec::new();
    for sm in &variant.modules {
        if existing.contains(&sm.name) {
            continue;
        }

        let mut entry = serde_json::Map::new();
        entry.insert("name".into(), json!(&sm.name));

        // Map params: module_param_name <- source value.
        // Sources:
        //   "env:VAR_NAME" → read from environment variable
        //   literal string  → use as-is (number/bool coercion applied)
        for (module_key, source) in &sm.params {
            let val = if let Some(var_name) = source.strip_prefix("env:") {
                // Environment variable — skip if not set (module uses its default)
                match std::env::var(var_name) {
                    Ok(v) => v,
                    Err(_) => continue,
                }
            } else {
                source.clone()
            };
            let coerced = match val.as_str() {
                "true" => json!(1),
                "false" => json!(0),
                _ => {
                    if let Ok(n) = val.parse::<i64>() {
                        json!(n)
                    } else {
                        json!(val)
                    }
                }
            };
            entry.insert(module_key.clone(), coerced);
        }

        to_prepend.push(Value::Object(entry));
        added.push(sm.name.clone());
    }

    if let Some(arr) = config["modules"].as_array_mut() {
        for (i, entry) in to_prepend.into_iter().enumerate() {
            arr.insert(i, entry);
        }
    }

    // Inject wiring (prepend, dedup)
    let existing_edges = collect_existing_edges(config);
    let mut wiring_prepend = Vec::new();
    for edge_str in &variant.wiring {
        let (from, to) = parse_edge_str(edge_str)?;
        let key = format!("{}->{}", from, to);
        if !existing_edges.contains(&key) {
            wiring_prepend.push(json!({"from": from, "to": to}));
        }
    }
    if let Some(arr) = config["wiring"].as_array_mut() {
        for (i, edge) in wiring_prepend.into_iter().enumerate() {
            arr.insert(i, edge);
        }
    }

    // Service injection
    if let Some(ref svc) = variant.service {
        if svc == "host" {
            // Host-provided — skip service injection
        } else if let Some(ref provides) = stack_meta.provides {
            // Inject services.<capability> = <module>
            if config.get("services").is_none() {
                config["services"] = json!({});
            }
            if let Some(svc_map) = config["services"].as_object_mut() {
                for svc_name in provides {
                    svc_map
                        .entry(svc_name.clone())
                        .or_insert_with(|| json!(svc));
                }
            }
        }
    }

    Ok(added)
}

// ============================================================================
// Helpers
// ============================================================================

fn collect_module_names(config: &Value) -> Vec<String> {
    config
        .get("modules")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.get("name").and_then(|n| n.as_str()))
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn collect_existing_edges(config: &Value) -> Vec<String> {
    config
        .get("wiring")
        .and_then(|w| w.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| {
                    let from = e.get("from").and_then(|f| f.as_str())?;
                    let to = e.get("to").and_then(|t| t.as_str())?;
                    Some(format!("{}->{}", from, to))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_edge_str(s: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = s.split("->").map(|p| p.trim()).collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(Error::Config(format!(
            "Invalid wiring syntax '{}' — expected 'module.port -> module.port'",
            s
        )));
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}
