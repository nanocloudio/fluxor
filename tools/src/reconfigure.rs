//! Transition plan computation for live graph reconfigure.
//!
//! Computes the diff between two graph configs and classifies each module
//! as survive, drain, or terminate. Used by `fluxor diff` CLI command and
//! at runtime by the scheduler.

use std::collections::HashMap;
use std::path::Path;

use serde_json::Value;

use crate::hash::fnv1a_hash;

// ============================================================================
// Transition Plan Types
// ============================================================================

/// Classification of a module during live reconfigure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleAction {
    /// Module unchanged — continues running with state intact.
    Survive,
    /// Module changed but exports module_drain — graceful drain then replace.
    Drain,
    /// Module changed, no drain support — immediate termination in MIGRATING.
    Terminate,
    /// Module is new in the new config — instantiate during MIGRATING.
    Add,
    /// Module is removed in the new config — terminate.
    Remove,
}

impl ModuleAction {
    pub fn label(&self) -> &'static str {
        match self {
            ModuleAction::Survive => "survive",
            ModuleAction::Drain => "drain",
            ModuleAction::Terminate => "terminate",
            ModuleAction::Add => "add",
            ModuleAction::Remove => "remove",
        }
    }
}

/// Per-module transition plan entry.
#[derive(Debug, Clone)]
pub struct ModulePlanEntry {
    /// Module name (from config type field).
    pub name: String,
    /// Module id in the old config (None if new).
    pub old_id: Option<u8>,
    /// Module id in the new config (None if removed).
    pub new_id: Option<u8>,
    /// Transition action.
    pub action: ModuleAction,
    /// Whether the module binary exports module_drain.
    pub drain_capable: bool,
    /// Per-module drain timeout override (ms), 0 = use global.
    pub drain_timeout_ms: u32,
}

/// Complete transition plan for a live reconfigure.
#[derive(Debug, Clone)]
pub struct TransitionPlan {
    pub entries: Vec<ModulePlanEntry>,
    /// Global drain timeout in ms.
    pub drain_timeout_ms: u32,
    /// Reconfigure mode from config.
    pub mode: ReconfigureMode,
}

/// Reconfigure mode declared in config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconfigureMode {
    /// Full destructive reconfigure (existing behavior, default).
    Atomic,
    /// Live reconfigure with drain.
    Live,
}

impl TransitionPlan {
    pub fn survive_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.action == ModuleAction::Survive)
            .count()
    }

    pub fn drain_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.action == ModuleAction::Drain)
            .count()
    }

    pub fn terminate_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.action == ModuleAction::Terminate)
            .count()
    }

    pub fn add_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.action == ModuleAction::Add)
            .count()
    }

    pub fn remove_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.action == ModuleAction::Remove)
            .count()
    }
}

// ============================================================================
// Module Identity
// ============================================================================

/// Identity of a module for comparison across configs.
///
/// A module is "the same" if name_hash, config_hash, and wiring_hash all match.
#[derive(Debug, Clone)]
struct ModuleIdentity {
    name: String,
    id: u8,
    name_hash: u32,
    config_hash: u32,
    wiring_hash: u32,
}

/// Compute FNV-1a hash of a module's config params.
///
/// Hashes the module's parameters (everything except id, type, and drain config)
/// to detect config-only changes.
fn compute_config_hash(module: &Value) -> u32 {
    // Serialize the module value to a canonical string for hashing.
    // Exclude keys that don't affect module behavior: id, type, drain.
    let mut hasher_input = Vec::new();

    if let Some(obj) = module.as_object() {
        // Sort keys for deterministic hashing
        let mut keys: Vec<&String> = obj.keys().collect();
        keys.sort();

        for key in keys {
            // Skip identity/metadata keys that don't affect module config
            if key == "id" || key == "type" || key == "drain" {
                continue;
            }
            hasher_input.extend_from_slice(key.as_bytes());
            hasher_input.push(b'=');
            let val_str = obj[key].to_string();
            hasher_input.extend_from_slice(val_str.as_bytes());
            hasher_input.push(b';');
        }
    }

    fnv1a_hash(&hasher_input)
}

/// Compute wiring hash for a module from the wiring section.
///
/// Hashes all edges connected to this module (both as source and destination).
fn compute_wiring_hash(module_name: &str, wiring: &Value) -> u32 {
    let mut hasher_input = Vec::new();

    if let Some(wires) = wiring.as_array() {
        for wire in wires {
            let wire_str = wire.as_str().unwrap_or("");
            // Check if this module is mentioned in the wiring entry
            // Wiring format: "from.port -> to.port" or "from -> to"
            let parts: Vec<&str> = wire_str.split("->").map(|s| s.trim()).collect();
            if parts.len() == 2 {
                let from_module = parts[0].split('.').next().unwrap_or("");
                let to_module = parts[1].split('.').next().unwrap_or("");
                if from_module == module_name || to_module == module_name {
                    hasher_input.extend_from_slice(wire_str.as_bytes());
                    hasher_input.push(b'\n');
                }
            }
        }
    }

    fnv1a_hash(&hasher_input)
}

/// Extract module identities from a config.
fn extract_identities(config: &Value) -> Vec<ModuleIdentity> {
    let mut identities = Vec::new();

    let modules = match config.get("modules").and_then(|m| m.as_array()) {
        Some(m) => m,
        None => return identities,
    };

    let wiring = config
        .get("wiring")
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));

    for module in modules {
        let name = module
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("unknown")
            .to_string();
        let id = module.get("id").and_then(|i| i.as_u64()).unwrap_or(0) as u8;
        let name_hash = fnv1a_hash(name.as_bytes());
        let config_hash = compute_config_hash(module);
        let wiring_hash = compute_wiring_hash(&name, &wiring);

        identities.push(ModuleIdentity {
            name,
            id,
            name_hash,
            config_hash,
            wiring_hash,
        });
    }

    identities
}

/// Check if a module binary is drain-capable by checking the .fmod header flag.
fn is_drain_capable(module_name: &str, modules_dir: &Path) -> bool {
    let fmod_path = modules_dir.join(format!("{}.fmod", module_name));
    if !fmod_path.exists() {
        return false;
    }

    match std::fs::read(&fmod_path) {
        Ok(data) => {
            // Header flag byte is at offset 60 (reserved[0])
            // Bit 3 = drain_capable
            if data.len() > 60 {
                (data[60] & 0x08) != 0
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

// ============================================================================
// Plan Computation
// ============================================================================

/// Parse reconfigure settings from config.
fn parse_reconfigure_settings(config: &Value) -> (ReconfigureMode, u32) {
    let reconfig = config
        .get("reconfigure")
        .or_else(|| config.get("graph").and_then(|g| g.get("reconfigure")));

    let mode = reconfig
        .and_then(|r| r.get("mode"))
        .and_then(|m| m.as_str())
        .map(|m| match m {
            "live" => ReconfigureMode::Live,
            _ => ReconfigureMode::Atomic,
        })
        .unwrap_or(ReconfigureMode::Atomic);

    let drain_timeout = reconfig
        .and_then(|r| r.get("drain_timeout_ms").or_else(|| r.get("drain_timeout")))
        .and_then(|t| t.as_u64())
        .unwrap_or(5000) as u32;

    (mode, drain_timeout)
}

/// Parse per-module drain timeout from config.
fn parse_module_drain_timeout(module: &Value) -> u32 {
    module
        .get("drain")
        .and_then(|d| d.get("timeout"))
        .and_then(|t| t.as_u64())
        .unwrap_or(0) as u32
}

/// Parse per-module drain policy from config.
fn parse_module_drain_policy(module: &Value) -> Option<&str> {
    module
        .get("drain")
        .and_then(|d| d.get("policy"))
        .and_then(|p| p.as_str())
}

/// Compute a transition plan between two configs.
///
/// Classifies each module as survive, drain, terminate, add, or remove.
pub fn compute_transition_plan(
    old_config: &Value,
    new_config: &Value,
    modules_dir: &Path,
) -> TransitionPlan {
    let old_ids = extract_identities(old_config);
    let new_ids = extract_identities(new_config);
    let (mode, drain_timeout_ms) = parse_reconfigure_settings(new_config);

    // Build lookup by (name_hash, id) for old modules
    let old_by_id: HashMap<u8, &ModuleIdentity> = old_ids.iter().map(|m| (m.id, m)).collect();

    let new_by_id: HashMap<u8, &ModuleIdentity> = new_ids.iter().map(|m| (m.id, m)).collect();

    // Get new config modules for per-module settings
    let new_modules: Vec<&Value> = new_config
        .get("modules")
        .and_then(|m| m.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default();

    let new_module_by_id: HashMap<u8, &Value> = new_modules
        .iter()
        .filter_map(|m| {
            let id = m.get("id").and_then(|i| i.as_u64())? as u8;
            Some((id, *m))
        })
        .collect();

    let mut entries = Vec::new();

    // Process modules in new config
    for new_mod in &new_ids {
        if let Some(old_mod) = old_by_id.get(&new_mod.id) {
            // Module exists in both configs — check identity
            let same_binary = old_mod.name_hash == new_mod.name_hash;
            let same_config = old_mod.config_hash == new_mod.config_hash;
            let same_wiring = old_mod.wiring_hash == new_mod.wiring_hash;

            if same_binary && same_config && same_wiring {
                entries.push(ModulePlanEntry {
                    name: new_mod.name.clone(),
                    old_id: Some(old_mod.id),
                    new_id: Some(new_mod.id),
                    action: ModuleAction::Survive,
                    drain_capable: false,
                    drain_timeout_ms: 0,
                });
            } else {
                // Module changed — check if drain-capable
                let drain_capable = is_drain_capable(&new_mod.name, modules_dir);
                let policy = new_module_by_id
                    .get(&new_mod.id)
                    .and_then(|m| parse_module_drain_policy(m));
                let forced_immediate = policy == Some("immediate");
                let per_module_timeout = new_module_by_id
                    .get(&new_mod.id)
                    .map(|m| parse_module_drain_timeout(m))
                    .unwrap_or(0);

                let action = if drain_capable && !forced_immediate {
                    ModuleAction::Drain
                } else {
                    ModuleAction::Terminate
                };

                entries.push(ModulePlanEntry {
                    name: new_mod.name.clone(),
                    old_id: Some(old_mod.id),
                    new_id: Some(new_mod.id),
                    action,
                    drain_capable,
                    drain_timeout_ms: per_module_timeout,
                });
            }
        } else {
            // New module
            entries.push(ModulePlanEntry {
                name: new_mod.name.clone(),
                old_id: None,
                new_id: Some(new_mod.id),
                action: ModuleAction::Add,
                drain_capable: false,
                drain_timeout_ms: 0,
            });
        }
    }

    // Process removed modules (in old but not in new)
    for old_mod in &old_ids {
        if !new_by_id.contains_key(&old_mod.id) {
            let drain_capable = is_drain_capable(&old_mod.name, modules_dir);

            entries.push(ModulePlanEntry {
                name: old_mod.name.clone(),
                old_id: Some(old_mod.id),
                new_id: None,
                action: if drain_capable {
                    ModuleAction::Drain
                } else {
                    ModuleAction::Remove
                },
                drain_capable,
                drain_timeout_ms: 0,
            });
        }
    }

    // Sort entries by id for stable display
    entries.sort_by_key(|e| e.new_id.or(e.old_id).unwrap_or(255));

    TransitionPlan {
        entries,
        drain_timeout_ms,
        mode,
    }
}

/// Format transition plan for display.
pub fn format_plan(plan: &TransitionPlan) -> String {
    let mut out = String::new();

    // Header
    out.push_str(&format!(
        "Reconfigure mode: {}\n",
        match plan.mode {
            ReconfigureMode::Live => "live",
            ReconfigureMode::Atomic => "atomic",
        }
    ));
    out.push_str(&format!("Drain timeout: {}ms\n\n", plan.drain_timeout_ms));

    // Table header
    out.push_str(&format!(
        "{:<4}  {:<16}  {:<12}  {:<8}\n",
        "ID", "Module", "Action", "Drain"
    ));
    out.push_str(&format!(
        "{:<4}  {:<16}  {:<12}  {:<8}\n",
        "----", "----------------", "------------", "--------"
    ));

    // Entries
    for entry in &plan.entries {
        let id_str = entry
            .new_id
            .or(entry.old_id)
            .map(|id| format!("{}", id))
            .unwrap_or_else(|| "-".to_string());

        let drain_str = match entry.action {
            ModuleAction::Drain => {
                if entry.drain_timeout_ms > 0 {
                    format!("{}ms", entry.drain_timeout_ms)
                } else {
                    "graceful".to_string()
                }
            }
            ModuleAction::Survive => "n/a".to_string(),
            _ => if entry.drain_capable {
                "capable"
            } else {
                "none"
            }
            .to_string(),
        };

        out.push_str(&format!(
            "{:<4}  {:<16}  {:<12}  {:<8}\n",
            id_str,
            entry.name,
            entry.action.label(),
            drain_str
        ));
    }

    // Summary
    out.push_str(&format!(
        "\nSummary: {} survive, {} drain, {} terminate, {} add, {} remove\n",
        plan.survive_count(),
        plan.drain_count(),
        plan.terminate_count(),
        plan.add_count(),
        plan.remove_count(),
    ));

    out
}
