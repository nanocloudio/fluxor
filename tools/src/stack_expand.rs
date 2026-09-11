//! Declarative platform stack expansion.
//!
//! Reads `platform:` from user YAML, loads stack profiles from `stacks/*.toml`,
//! matches a variant against board/target metadata, and injects concrete
//! modules, wiring, params, and services into the config before the existing
//! config generation pipeline runs.
//!
//! Two kinds of injection blocks coexist in a stack file:
//!
//! - `[[variant]]` — **exclusive**. Exactly one is selected by specificity-
//!   scored match. This answers "which driver/phy shape does this board use?".
//! - `[[overlay]]` — **additive**. Each is evaluated independently; every
//!   overlay whose match predicate holds is applied on top of the variant.
//!   This answers "what optional capabilities does the user want layered on?"
//!   (debug netconsole, pcap sink, perf exporter, …).
//!
//! Param sources (per-module-param):
//!   `env:VAR`   — read from the environment; skip if unset
//!   `user:KEY`  — read from merged user platform fields; skip if unset
//!   `host:PATH` — read from `~/.config/fluxor/host.toml` (dotted path
//!                 like `debug.collector_ip`); skip if unset
//!   literal     — string used as-is (with number/bool coercion)
//!
//! Multiple sources can be chained with `|`; the first that resolves
//! wins. A trailing `|required` token turns "nothing resolved" into a
//! build-time error, so safety-critical params (e.g. `log_net`'s
//! `dst_ip`) can't silently fall back to a dangerous compile-time
//! default.
//! Example:  `dst_ip = "user:dst_ip|host:debug.collector_ip|required"`.
//!
//! See `.context/platform_stacks.md` for the full specification.

use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::target::TargetDescriptor;

// ============================================================================
// Host config — per-developer settings in ~/.config/fluxor/host.toml
// ============================================================================
//
// Supplies values that the `host:` source prefix reads. Loaded once
// per invocation and passed into `inject_injection`. A missing file
// is not an error — `host:` lookups just don't resolve, and
// `|required` catches the gap at build time.
//
// Schema (all fields optional — callers decide what's required by
// whether they add `|required` to the source chain):
//
//   [debug]
//   collector_ip   = "192.168.1.10"   # dst for log_net
//   collector_port = 6666             # optional, UDP destination port
//   bind_port      = 6667             # optional, local UDP source port

type HostConfig = toml::Value;

fn load_host_config() -> Result<HostConfig> {
    let path = host_config_path();
    match path.as_ref().and_then(|p| std::fs::read_to_string(p).ok()) {
        Some(raw) => {
            let v: toml::Value = toml::from_str(&raw).map_err(|e| {
                Error::Config(format!(
                    "{}: host config parse error: {}",
                    path.as_ref().unwrap().display(),
                    e
                ))
            })?;
            Ok(v)
        }
        None => Ok(toml::Value::Table(toml::value::Table::new())),
    }
}

fn host_config_path() -> Option<PathBuf> {
    let base = if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|s| !s.is_empty()) {
        Some(PathBuf::from(xdg))
    } else {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config"))
    };
    base.map(|b| b.join("fluxor").join("host.toml"))
}

/// Look up a dotted path like `debug.collector_ip` in the host config.
/// Returns the leaf value as a string if it exists and is a string,
/// integer, or boolean. Tables / arrays / missing keys all return None.
fn host_lookup(cfg: &HostConfig, dotted: &str) -> Option<String> {
    let mut cur = cfg;
    for part in dotted.split('.') {
        cur = cur.get(part)?;
    }
    match cur {
        toml::Value::String(s) => Some(s.clone()),
        toml::Value::Integer(i) => Some(i.to_string()),
        toml::Value::Boolean(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Resolve a pipe-chained source expression to a string, or None if
/// no source resolved. Returns `Err` when `|required` is present and
/// every other source failed — the error lists every source tried so
/// the operator can pick one to fix.
fn resolve_param_source(
    expr: &str,
    merged: &HashMap<String, String>,
    host: &HostConfig,
    module: &str,
    param: &str,
) -> Result<Option<String>> {
    let mut required = false;
    let mut tried: Vec<String> = Vec::new();
    for raw in expr.split('|') {
        let src = raw.trim();
        if src.is_empty() {
            continue;
        }
        if src == "required" {
            required = true;
            continue;
        }
        tried.push(src.to_string());
        if let Some(var_name) = src.strip_prefix("env:") {
            if let Ok(v) = std::env::var(var_name) {
                if !v.is_empty() {
                    return Ok(Some(v));
                }
            }
            continue;
        }
        if let Some(key) = src.strip_prefix("user:") {
            if let Some(v) = merged.get(key) {
                if !v.is_empty() {
                    return Ok(Some(v.clone()));
                }
            }
            continue;
        }
        if let Some(path) = src.strip_prefix("host:") {
            if let Some(v) = host_lookup(host, path) {
                if !v.is_empty() {
                    return Ok(Some(v));
                }
            }
            continue;
        }
        // Bare literal source — resolves unconditionally. Useful as a
        // terminal fallback: `"user:dst_ip|192.168.1.1"`.
        return Ok(Some(src.to_string()));
    }
    if required {
        let host_hint = host_config_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "~/.config/fluxor/host.toml".to_string());
        return Err(Error::Config(format!(
            "module '{module}' param '{param}' has no resolved source. \
             Tried (in order): [{}]. Set one of these sources — e.g. \
             add the matching field to {host_hint} for the host:* lookup, \
             export the env var, or override via YAML platform.{module}.*.",
            tried.join(", "),
        )));
    }
    Ok(None)
}

// ============================================================================
// TOML data structures
// ============================================================================

#[derive(Deserialize)]
struct StackFile {
    stack: StackMeta,
    #[serde(default)]
    variant: Vec<StackInjection>,
    #[serde(default)]
    overlay: Vec<StackInjection>,
}

#[derive(Deserialize)]
struct StackMeta {
    name: String,
    #[allow(
        dead_code,
        reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
    )]
    provides: Option<Vec<String>>,
}

/// A match-and-inject block. Shared by `[[variant]]` (exclusive) and
/// `[[overlay]]` (additive). The only difference between the two is
/// *how many* can fire: variants pick one by specificity score, overlays
/// fire independently whenever their match holds.
#[derive(Deserialize)]
struct StackInjection {
    #[serde(rename = "match")]
    match_keys: HashMap<String, String>,
    #[serde(default)]
    modules: Vec<StackModule>,
    #[serde(default)]
    wiring: Vec<String>,
    service: Option<String>,
    /// When true, this injection introduces an intentional bidirectional
    /// feedback pair (e.g. `debug: to: net` wires `ip.net_out -> log_net`
    /// AND `log_net.net_out -> ip.net_in`, a 2-cycle). The v1 scheduler
    /// rejects cyclic graphs unless `scheduler.accept_cycles` is set, so an
    /// injection that knowingly creates a feedback pair sets that flag on the
    /// expanded config — otherwise every `debug: to: net` graph is rejected
    /// at `prepare_graph` and boots with no working graph (the pi5 "low-module
    /// boot wedge" was this: small configs lacked an unrelated http<->ws cycle
    /// that would have set the flag for them).
    #[serde(default)]
    accept_cycles: bool,
}

#[derive(Deserialize)]
struct StackModule {
    name: String,
    /// Implementation selector. When present, the injected module entry
    /// gets a `type:` field; the graph instance keeps `name`. Used by
    /// stacks that map a logical name (e.g. `display`, `audio_out`) to
    /// the concrete driver for the chosen target. Absent means
    /// `type` falls back to `name` at config-generation time.
    #[serde(default, rename = "type")]
    type_name: Option<String>,
    /// `[[variant]]` selection for the injected instance, e.g. the
    /// otlp-http export's `http` client asking for the `exchange` build.
    #[serde(default)]
    variant: Option<String>,
    /// The stack needs its OWN instance of this type and cannot be
    /// satisfied by one the graph already carries — the default type-dedup
    /// (below) exists for infrastructure singletons like `ip`, and would
    /// otherwise SILENTLY skip this module and drop its wiring. With this
    /// set, a type collision is a hard config error naming the conflict,
    /// never a silent skip: fail-loud is the whole point (rfc
    /// observability_surface §12.7 — a graph that already serves `http`
    /// cannot also carry the exchange-variant client, because one image
    /// carries one build of a type).
    #[serde(default)]
    require_distinct: bool,
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

    // Members placed on another node (`modules[].node`) are lifted out of
    // the module list first, so every reader from here on — stack
    // injection included — sees only what this node instantiates.
    crate::config::lift_remote_members(config)?;

    let platform = match config.get("platform") {
        Some(p) => p.clone(),
        None => return Ok(auto_added),
    };
    let platform_map = match platform.as_object() {
        Some(m) => m.clone(),
        None => return Err(Error::Config("platform: must be a mapping".into())),
    };

    // Load ~/.config/fluxor/host.toml once per invocation. A missing
    // file is fine; `|required` catches gaps at injection time.
    let host = load_host_config()?;

    // Two-pass expansion. Pass 1 injects every stack's MODULES; we
    // accumulate `globally_skipped` across all passes. Pass 2 — once
    // every module that will exist has been added — injects every
    // stack's WIRING with full knowledge of which names were dropped
    // (and therefore which wires must be dropped along with them).
    //
    // Why split: `platform_map` iterates alphabetically (serde_json
    // is a BTreeMap), so `debug` runs before `net`. If we did
    // modules+wiring in one pass per stack, debug would add wires
    // referencing `ip` before net had a chance to add (or skip) it,
    // and the cross-stack dedup case (e.g. multilane skipping ip via
    // type-collision with ip_0/ip_1) would never propagate to debug's
    // wires. The single-pass design was the source of the multilane
    // dangling-wire bug.
    let mut globally_skipped: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Resolve each stack file + matching variants/overlays up front
    // so both passes iterate the same set in the same order.
    struct Resolved {
        stack_file: StackFile,
        merged: HashMap<String, String>,
    }
    let mut resolved: Vec<Resolved> = Vec::with_capacity(platform_map.len());
    for (stack_name, user_fields) in &platform_map {
        let stack_file = load_stack(stack_name, project_root)?;
        let merged = merge_with_board_defaults(user_fields, stack_name, target);
        let user_keys: Vec<String> = user_fields
            .as_object()
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default();
        check_overlay_keys_matched(&stack_file, &merged, &user_keys)?;
        resolved.push(Resolved { stack_file, merged });
    }

    // ── Pass 1: modules only ──
    for r in &resolved {
        if !r.stack_file.variant.is_empty() {
            let variant = select_variant(&r.stack_file, &r.merged)?;
            let added = inject_modules(
                config,
                variant,
                &r.merged,
                &host,
                &r.stack_file.stack,
                &mut globally_skipped,
            )?;
            auto_added.extend(added);
        }
        for overlay in &r.stack_file.overlay {
            if !injection_matches(&overlay.match_keys, &r.merged) {
                continue;
            }
            let added = inject_modules(
                config,
                overlay,
                &r.merged,
                &host,
                &r.stack_file.stack,
                &mut globally_skipped,
            )?;
            auto_added.extend(added);
        }
    }

    // ── Pass 2: wiring + services ──
    for r in &resolved {
        if !r.stack_file.variant.is_empty() {
            let variant = select_variant(&r.stack_file, &r.merged)?;
            inject_wiring_and_services(config, variant, &r.stack_file.stack, &globally_skipped)?;
        }
        for overlay in &r.stack_file.overlay {
            if !injection_matches(&overlay.match_keys, &r.merged) {
                continue;
            }
            inject_wiring_and_services(config, overlay, &r.stack_file.stack, &globally_skipped)?;
        }
    }

    // Remove platform: key so downstream code doesn't see it
    if let Some(obj) = config.as_object_mut() {
        obj.remove("platform");
    }

    // ── Digest injection: a graph that carries the `otel` export engine
    // gets the build-time id-table digest injected as its `table_digest`
    // param, so every FXTL batch envelope names the table it was built with
    // and the host collector can refuse a mismatch instead of resolving
    // wrong names. Computed over the EXPANDED module list (indices =
    // instantiation order) from the project's own `modules/` tree — the same
    // default the `fluxor id-table` exporter uses. An explicit user
    // `table_digest` wins.
    inject_id_table_digest(config, project_root);

    Ok(auto_added)
}

/// See the call site in [`expand_platform_stacks`]. Separate so the walkdir
/// cost is paid only when an `otel` entry exists.
fn inject_id_table_digest(config: &mut Value, project_root: &std::path::Path) {
    let has_otel = |entry: &Value| -> bool {
        let name = entry
            .as_str()
            .or_else(|| entry.get("name").and_then(|v| v.as_str()))
            .unwrap_or("");
        let ty = entry.get("type").and_then(|v| v.as_str()).unwrap_or(name);
        ty == "otel"
    };
    let any = config
        .get("modules")
        .and_then(|m| m.as_array())
        .is_some_and(|a| a.iter().any(has_otel));
    if !any {
        return;
    }
    let table = crate::observability::id_table_for_expanded_config(
        config,
        &crate::observability::id_table_roots(project_root),
    );
    let digest = table.digest();
    let bounds_hex = table.bounds_blob_hex();
    if let Some(arr) = config["modules"].as_array_mut() {
        for entry in arr.iter_mut() {
            if !has_otel(entry) {
                continue;
            }
            let Some(obj) = entry.as_object_mut() else {
                continue;
            };
            if obj.get("table_digest").is_none() {
                obj.insert("table_digest".into(), json!(digest));
            }
            // The on-device id-table slice: per-instrument histogram
            // bounds, so on-device OTLP encodings can emit histogram16 with
            // DECLARED ladders instead of skipping them.
            if let (Some(hex), None) = (&bounds_hex, obj.get("bounds")) {
                obj.insert("bounds".into(), json!(hex));
            }
        }
    }
}

// ============================================================================
// Stack loading
// ============================================================================

/// Walk `<root>/stacks/` and return every `*.toml` file stem.
/// Used by `load_stack`'s "did you mean…?" diagnostic when the
/// caller typo'd a stack name AND by `fluxor inspect` to render a
/// merged project+install view (the caller dedupes/annotates by
/// source).
pub fn list_available_stack_names(root: &std::path::Path) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root.join("stacks")) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().is_some_and(|ext| ext == "toml") {
                if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                    names.push(stem.to_string());
                }
            }
        }
    }
    names.sort();
    names
}

fn load_stack(name: &str, project_root: &std::path::Path) -> Result<StackFile> {
    // Layered lookup: project root first, then the install root
    // (when discovered). Lets an external user project override
    // individual stacks (`stacks/audio.toml`) while still reaching
    // the bundled defaults for everything else.
    let project_path = project_root.join("stacks").join(format!("{name}.toml"));
    let path = if project_path.exists() {
        project_path
    } else if let Some(install) = crate::project::install_root() {
        let install_path = install.path.join("stacks").join(format!("{name}.toml"));
        if install_path.exists() {
            install_path
        } else {
            // Both roots checked, neither has the stack. Surface
            // the *project* path in the error so the user knows
            // where to add the override — the install path is
            // immutable.
            project_path
        }
    } else {
        project_path
    };

    let content = std::fs::read_to_string(&path).map_err(|e| {
        // "Did you mean…?" hint via the same Levenshtein lookup
        // the target loader uses for typo'd target names. Pulls
        // the candidate list from both the project root and the
        // install root so a user override that *replaces* a
        // bundled stack still surfaces the bundled name as a
        // suggestion.
        let mut available = list_available_stack_names(project_root);
        if let Some(install) = crate::project::install_root() {
            if install.path != project_root {
                for n in list_available_stack_names(&install.path) {
                    if !available.contains(&n) {
                        available.push(n);
                    }
                }
            }
        }
        available.sort();
        let suggestion = crate::target::closest_match(name, &available, 3);
        let did_you_mean = match suggestion {
            Some(s) => format!(" Did you mean '{s}'?"),
            None => String::new(),
        };
        let available_str = if available.is_empty() {
            String::new()
        } else {
            format!(" Available stacks: {}.", available.join(", "))
        };
        Error::Config(format!(
            "Unknown platform stack '{name}' (no {}): {e}.{did_you_mean}{available_str}",
            path.display()
        ))
    })?;
    toml::from_str(&content)
        .map_err(|e| Error::Config(format!("Failed to parse {}: {}", path.display(), e)))
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
        .is_some_and(|o| o.contains_key("phy"));

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
            .is_some_and(|o| o.contains_key("driver") || o.contains_key("nic"))
    {
        merged.remove("driver");
        // Net boards declare the NIC as a hardware fact (`nic`), not a driver
        // name — same clearing rule (facts are phy-specific too).
        merged.remove("nic");
    }

    // Inject target metadata AUTHORITATIVELY. `board` / `family` / `silicon` are
    // derived facts about the resolved target, not user-tunable knobs — a
    // user-supplied value (whether a mistake or an attempt to force a mismatched
    // variant) is overwritten here so overlay/variant matching can't be steered
    // away from the real hardware. `insert` (not `entry().or_insert`) makes the
    // injected value win regardless of any earlier user field.
    if let Some(ref board) = target.board_id {
        merged.insert("board".into(), board.clone());
    }
    merged.insert("family".into(), target.family.clone());
    // `silicon` is the module-artefact silicon id. Descriptors carry the
    // silicon id directly (boards resolve through the registry), so no
    // aliasing is needed. Lets an overlay select a narrower set than
    // `family` when a module supports only some silicon within a family —
    // e.g. the OTLP exporter is rp2350-only and must not match rp2040
    // under `family="rp2"`.
    merged.insert("silicon".into(), target.id.clone());

    merged
}

// ============================================================================
// Variant matching
// ============================================================================

fn select_variant<'a>(
    stack: &'a StackFile,
    merged: &HashMap<String, String>,
) -> Result<&'a StackInjection> {
    let mut eligible: Vec<(&StackInjection, u32)> = Vec::new();

    for variant in &stack.variant {
        if !injection_matches(&variant.match_keys, merged) {
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

/// True iff every match-key is satisfied by `merged`.
///
/// A match value of `"*"` matches any present truthy value (non-empty,
/// not `"false"`, not `"0"`). Exact string match otherwise.
/// Is a stack field set to something meaningful? `""` / `"false"` / `"0"`
/// read as "not set" — what the `"*"` wildcard treats as absent, and what
/// `check_overlay_keys_matched` skips rather than demanding a match for.
/// One definition so the two cannot disagree about `debug: { observe: 0 }`.
fn field_is_set(v: &str) -> bool {
    !v.is_empty() && v != "false" && v != "0"
}

fn injection_matches(
    match_keys: &HashMap<String, String>,
    merged: &HashMap<String, String>,
) -> bool {
    match_keys.iter().all(|(k, expected)| {
        let actual = merged.get(k);
        if expected == "*" {
            actual.is_some_and(|v| field_is_set(v))
        } else {
            actual == Some(expected)
        }
    })
}

/// A user-supplied stack field whose only consumer is overlay match
/// predicates must actually select an overlay. Overlays match by exact
/// value so new kinds compose without colliding — the flip side is that
/// a stale or typo'd value matches nothing, and the path it names
/// (telemetry export, netconsole, …) silently never materializes while
/// validation still passes. Catch that here: for every user-written
/// field that appears in overlay match-sets (and in no variant's —
/// variant keys already hard-error via `select_variant`), at least one
/// overlay matching on it must fire.
///
/// Exemptions: the authoritative target facts (`board`/`family`/
/// `silicon`), which are injected over user values and legitimately
/// appear in predicates the user's other fields don't satisfy; and
/// explicit off-values, which [`field_is_set`] defines once for both
/// this check and wildcard matching.
fn check_overlay_keys_matched(
    stack: &StackFile,
    merged: &HashMap<String, String>,
    user_keys: &[String],
) -> Result<()> {
    for key in user_keys {
        if matches!(key.as_str(), "board" | "family" | "silicon") {
            continue;
        }
        if stack.variant.iter().any(|v| v.match_keys.contains_key(key)) {
            continue;
        }
        let overlays_with_key: Vec<&StackInjection> = stack
            .overlay
            .iter()
            .filter(|o| o.match_keys.contains_key(key))
            .collect();
        if overlays_with_key.is_empty() {
            continue;
        }
        let Some(value) = merged.get(key).filter(|v| field_is_set(v)) else {
            continue;
        };
        if overlays_with_key
            .iter()
            .any(|o| injection_matches(&o.match_keys, merged))
        {
            continue;
        }
        let mut accepted: Vec<&str> = overlays_with_key
            .iter()
            .filter_map(|o| o.match_keys.get(key))
            .map(String::as_str)
            .filter(|v| *v != "*")
            .collect();
        accepted.sort_unstable();
        accepted.dedup();
        let accepted_str = if accepted.is_empty() {
            "none on this target".to_string()
        } else {
            accepted.join(", ")
        };
        return Err(Error::Config(format!(
            "platform.{}.{key} = {value:?} selects no overlay on this target — \
             the graph would silently omit what it names. Accepted values \
             (subject to target match): {accepted_str}.",
            stack.stack.name,
        )));
    }
    Ok(())
}

// ============================================================================
// Injection
// ============================================================================

/// Single-shot injection (modules + wiring + services). Convenience
/// wrapper used by tests: runs `inject_modules` then immediately
/// `inject_wiring_and_services` against the same skip set. The real
/// expansion path in [`expand_platform_stacks`] interleaves the two
/// passes across stacks instead, so a later stack's wiring sees
/// modules an earlier stack hasn't added yet — but for single-stack
/// unit tests this shim has identical semantics.
#[cfg(test)]
fn inject_injection(
    config: &mut Value,
    variant: &StackInjection,
    merged: &HashMap<String, String>,
    host: &HostConfig,
    stack_meta: &StackMeta,
    globally_skipped: &mut std::collections::HashSet<String>,
) -> Result<Vec<String>> {
    let added = inject_modules(config, variant, merged, host, stack_meta, globally_skipped)?;
    inject_wiring_and_services(config, variant, stack_meta, globally_skipped)?;
    Ok(added)
}

/// Pass 1 of stack expansion: inject only this stack's modules.
/// Returns the names of modules actually added (after name and type
/// dedup). Skipped names go into `globally_skipped` so pass 2 wiring
/// dedup can recognize them across stack boundaries.
fn inject_modules(
    config: &mut Value,
    variant: &StackInjection,
    merged: &HashMap<String, String>,
    host: &HostConfig,
    _stack_meta: &StackMeta,
    globally_skipped: &mut std::collections::HashSet<String>,
) -> Result<Vec<String>> {
    let mut added = Vec::new();

    // Collect existing module names + types for dedup. Two distinct
    // dedup paths:
    //   * **by name** — the original behavior. A user yaml that re-
    //     declares a stack-named module overrides the default.
    //   * **by type** — when a stack module's effective type matches
    //     an existing user module's effective type (e.g. stack wants
    //     `{name:"ip", type:"ip"}` and the user has `ip_0`/`ip_1` with
    //     `type:ip`), skip the stack module. Catches the multilane-
    //     HTTPS shape where the user wants per-lane IP stacks driven
    //     by a custom demux and the auto-`ip` would otherwise be
    //     added unwired downstream. Wiring referring to the skipped
    //     name is dropped in pass 2 via `globally_skipped`.
    let existing = collect_module_names(config);
    let existing_types = collect_existing_types(config);

    // Ensure arrays exist
    if config.get("modules").is_none() {
        config["modules"] = json!([]);
    }
    if config.get("wiring").is_none() {
        config["wiring"] = json!([]);
    }

    // Inject modules (prepend for lower IDs → earlier instantiation).
    //
    // `globally_skipped` is the per-expansion accumulator threaded
    // through every stack injection so a later stack can recognize
    // names an earlier stack dropped. The wiring loop below drops any
    // edge whose endpoint references one of these names.
    let mut to_prepend = Vec::new();
    for sm in &variant.modules {
        if existing.contains(&sm.name) {
            // Name-based dedup. The user re-declared the stack's
            // module (same name) — their declaration wins; the stack
            // wiring still applies since the name is still valid.
            continue;
        }
        // Effective type = explicit `type:` if set, else module name.
        // Matches how the kernel config-gen path computes a module's
        // implementation selector.
        let effective_type = sm.type_name.as_deref().unwrap_or(&sm.name);
        if existing_types.iter().any(|t| t == effective_type) {
            if sm.require_distinct {
                // Same type, SAME variant → two instances of one build, which
                // is ordinary graph composition — inject alongside. Only a
                // variant mismatch is irreconcilable (one image carries one
                // build of a type — module_variants §4.3), and a silent skip
                // would silently kill the stack's feature, so that case is a
                // hard error naming the ways out.
                let existing_variant = config
                    .get("modules")
                    .and_then(|m| m.as_array())
                    .and_then(|arr| {
                        arr.iter().find(|e| {
                            let name = e
                                .as_str()
                                .or_else(|| e.get("name").and_then(|v| v.as_str()))
                                .unwrap_or("");
                            let ty = e.get("type").and_then(|v| v.as_str()).unwrap_or(name);
                            ty == effective_type
                        })
                    })
                    .and_then(|e| e.get("variant").and_then(|v| v.as_str()))
                    .map(str::to_string);
                if existing_variant.as_deref() != sm.variant.as_deref() {
                    return Err(Error::Config(format!(
                        "stack module '{}' needs its own '{}' instance (variant {}), but \
the graph already carries that type at a different variant ({}) — one image \
holds one build of a module type, so the two cannot coexist. Either align the \
existing '{}' module on the same variant, drop it, or use a different \
transport (e.g. `export_telemetry: udp` + fluxor-collect).",
                        sm.name,
                        effective_type,
                        sm.variant.as_deref().unwrap_or("<default>"),
                        existing_variant.as_deref().unwrap_or("<default>"),
                        effective_type,
                    )));
                }
                // fall through: inject a second instance of the same build.
            } else {
                // Type-based dedup. Some existing module already provides
                // this implementation; injecting another would create two
                // independent instances (e.g. parallel IP stacks) — almost
                // never what the user wants. Log the skip so it's obvious
                // why a stack-default module didn't appear in the final
                // graph, then suppress the module's wiring too.
                eprintln!(
                    "stack expansion: skipped module '{}' (type='{}') — existing module(s) already provide this type; wiring referencing '{}' will be dropped",
                    sm.name, effective_type, sm.name,
                );
                globally_skipped.insert(sm.name.clone());
                continue;
            }
        }

        let mut entry = serde_json::Map::new();
        entry.insert("name".into(), json!(&sm.name));
        if let Some(ref ty) = sm.type_name {
            entry.insert("type".into(), json!(ty));
        }
        if let Some(ref v) = sm.variant {
            entry.insert("variant".into(), json!(v));
        }

        // Map params: module_param_name <- pipe-chained source list.
        // See `resolve_param_source` for the grammar.
        //
        // Soft sources skip the param if nothing resolves, letting
        // the module's compile-time default apply. Hard sources
        // (`|required`) fail the build with a message pointing at the
        // missing field — use this for values where a default would
        // be unsafe (e.g. `log_net` dst_ip).
        for (module_key, source) in &sm.params {
            let resolved = resolve_param_source(source, merged, host, &sm.name, module_key)?;
            let Some(val) = resolved else {
                continue;
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

    Ok(added)
}

/// Pass 2 of stack expansion: add this stack's wiring + services. By
/// the time this runs every other stack's modules are already in
/// `config["modules"]` and `globally_skipped` is complete, so wires
/// whose endpoint was deduped away in pass 1 (by any stack) get
/// dropped here with a stderr note. Wires whose endpoint truly doesn't
/// exist anywhere fall through to structural validation, which owns
/// the file:line diagnostic for those.
fn inject_wiring_and_services(
    config: &mut Value,
    variant: &StackInjection,
    stack_meta: &StackMeta,
    globally_skipped: &std::collections::HashSet<String>,
) -> Result<()> {
    if config.get("wiring").is_none() {
        config["wiring"] = json!([]);
    }
    let existing_edges = collect_existing_edges(config);
    let mut wiring_prepend = Vec::new();
    for edge_str in &variant.wiring {
        let (from, to) = parse_edge_str(edge_str)?;
        let from_mod = endpoint_module(&from);
        let to_mod = endpoint_module(&to);
        if globally_skipped.contains(from_mod) {
            eprintln!(
                "stack expansion: dropped wiring '{edge_str}' — `from` module '{from_mod}' was skipped by earlier dedup",
            );
            continue;
        }
        if globally_skipped.contains(to_mod) {
            eprintln!(
                "stack expansion: dropped wiring '{edge_str}' — `to` module '{to_mod}' was skipped by earlier dedup",
            );
            continue;
        }
        let key = format!("{from}->{to}");
        if !existing_edges.contains(&key) {
            wiring_prepend.push(json!({"from": from, "to": to}));
        }
    }
    if let Some(arr) = config["wiring"].as_array_mut() {
        for (i, edge) in wiring_prepend.into_iter().enumerate() {
            arr.insert(i, edge);
        }
    }

    // Intentional feedback pair → opt the graph into cycle acceptance. Set
    // only when not already specified, so a user's explicit `accept_cycles:
    // false` (should they ever want it) isn't silently overridden — but in
    // practice this is what makes `debug: to: net` graphs boot at all.
    if variant.accept_cycles {
        if config.get("scheduler").is_none() {
            config["scheduler"] = json!({});
        }
        if let Some(sched) = config["scheduler"].as_object_mut() {
            sched
                .entry("accept_cycles".to_string())
                .or_insert_with(|| json!(true));
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

    Ok(())
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

/// Collect each existing module's effective type — `type:` field when
/// present, otherwise the module's `name:`. Used by stack expansion to
/// skip a stack-default module when the user already supplied one with
/// the same implementation (e.g. two `type:ip` modules + the stack
/// would have added a third).
fn collect_existing_types(config: &Value) -> Vec<String> {
    config
        .get("modules")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| {
                    e.get("type")
                        .and_then(|t| t.as_str())
                        .or_else(|| e.get("name").and_then(|n| n.as_str()))
                        .map(|s| s.to_string())
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Extract the module name from a wiring endpoint string. `"foo.bar"`
/// returns `"foo"`; a malformed endpoint with no `.` returns the
/// whole string (the wiring would fail validation elsewhere anyway —
/// this fallback just keeps the dedup loop infallible).
fn endpoint_module(endpoint: &str) -> &str {
    endpoint.split('.').next().unwrap_or(endpoint)
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
                    Some(format!("{from}->{to}"))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_edge_str(s: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = s.split("->").map(|p| p.trim()).collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(Error::Config(format!(
            "Invalid wiring syntax '{s}' — expected 'module.port -> module.port'"
        )));
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_injection(modules: Vec<StackModule>, wiring: Vec<&str>) -> StackInjection {
        StackInjection {
            match_keys: HashMap::new(),
            modules,
            wiring: wiring.into_iter().map(String::from).collect(),
            service: None,
            accept_cycles: false,
        }
    }

    fn make_module(name: &str, type_name: Option<&str>) -> StackModule {
        StackModule {
            name: name.to_string(),
            type_name: type_name.map(String::from),
            variant: None,
            require_distinct: false,
            params: HashMap::new(),
        }
    }

    fn empty_meta() -> StackMeta {
        StackMeta {
            name: "test".to_string(),
            provides: None,
        }
    }

    fn dummy_host() -> HostConfig {
        toml::Value::Table(toml::value::Table::new())
    }

    /// Modules in the resulting config — name + type pairs, in graph
    /// order. Type is `null` when the entry has no explicit `type:`
    /// (kernel config-gen defaults it to name).
    fn module_pairs(config: &Value) -> Vec<(String, Option<String>)> {
        config
            .get("modules")
            .and_then(|m| m.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| {
                        let name = e.get("name").and_then(|n| n.as_str())?;
                        let ty = e.get("type").and_then(|t| t.as_str()).map(String::from);
                        Some((name.to_string(), ty))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn edge_strings(config: &Value) -> Vec<String> {
        collect_existing_edges(config)
    }

    /// An overlay-reserved key with a value no overlay matches must be
    /// a hard error, not a silent no-op — the classic case is a stale
    /// `export_telemetry:` value that quietly drops the whole export
    /// path while validation passes.
    #[test]
    fn unmatched_overlay_key_value_is_a_hard_error() {
        let stack: StackFile = toml::from_str(
            r#"
            [stack]
            name = "debug"
            [[overlay]]
            match = { export_telemetry = "udp", family = "bcm" }
            [[overlay]]
            match = { export_telemetry = "uart", family = "bcm" }
            "#,
        )
        .unwrap();
        let merged: HashMap<String, String> = [
            ("export_telemetry".to_string(), "otlp".to_string()),
            ("family".to_string(), "bcm".to_string()),
        ]
        .into();
        let err = check_overlay_keys_matched(&stack, &merged, &["export_telemetry".to_string()])
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("otlp"), "names the bad value: {msg}");
        assert!(msg.contains("uart, udp"), "lists accepted values: {msg}");

        // The same value matching an overlay passes.
        let mut ok = merged.clone();
        ok.insert("export_telemetry".into(), "udp".into());
        check_overlay_keys_matched(&stack, &ok, &["export_telemetry".to_string()]).unwrap();

        // Explicit off-values are not errors.
        let mut off = merged.clone();
        off.insert("export_telemetry".into(), "false".into());
        check_overlay_keys_matched(&stack, &off, &["export_telemetry".to_string()]).unwrap();

        // A valid value on a target no overlay covers still errors —
        // the export path would silently vanish on that family.
        let mut wrong_family = merged.clone();
        wrong_family.insert("export_telemetry".into(), "udp".into());
        wrong_family.insert("family".into(), "wasm".into());
        check_overlay_keys_matched(&stack, &wrong_family, &["export_telemetry".to_string()])
            .unwrap_err();
    }

    /// Original name-based dedup: stack module whose name matches an
    /// existing user module is silently skipped. The user's version
    /// wins. Stack wiring referencing that name is still applied —
    /// the name is valid, the module exists post-injection.
    #[test]
    fn name_collision_skips_module_but_keeps_wiring() {
        let mut config = json!({
            "modules": [{ "name": "ip", "use_dhcp": "1" }],
            "wiring": [],
        });
        let injection = make_injection(
            vec![
                make_module("rp1_gem", None),
                make_module("conn_guard", None),
                make_module("ip", Some("ip")),
            ],
            vec![
                "rp1_gem.frames_rx -> conn_guard.frames_rx",
                "conn_guard.frames_tx -> ip.frames_rx",
            ],
        );
        let mut globally_skipped = std::collections::HashSet::new();
        let added = inject_injection(
            &mut config,
            &injection,
            &HashMap::new(),
            &dummy_host(),
            &empty_meta(),
            &mut globally_skipped,
        )
        .unwrap();
        assert_eq!(added, vec!["rp1_gem", "conn_guard"]);
        let pairs = module_pairs(&config);
        let names: Vec<&str> = pairs.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["rp1_gem", "conn_guard", "ip"]);
        // Wiring stays — the user's `ip` is still a valid endpoint.
        let edges = edge_strings(&config);
        assert!(edges.contains(&"rp1_gem.frames_rx->conn_guard.frames_rx".to_string()));
        assert!(edges.contains(&"conn_guard.frames_tx->ip.frames_rx".to_string()));
    }

    /// `debug: to: net` injects a `log_net <-> ip` feedback 2-cycle. An
    /// injection with `accept_cycles = true` must set
    /// `scheduler.accept_cycles` on the expanded config so `prepare_graph`
    /// doesn't reject the graph (the pi5 low-module boot wedge). A user's
    /// explicit value is preserved (`.or_insert`).
    #[test]
    fn accept_cycles_injection_sets_scheduler_flag() {
        let mut config = json!({
            "modules": [{ "name": "ip" }],
            "wiring": [],
        });
        let mut injection = make_injection(
            vec![make_module("log_net", None)],
            vec![
                "ip.net_out -> log_net.net_in",
                "log_net.net_out -> ip.net_in",
            ],
        );
        injection.accept_cycles = true;
        let mut globally_skipped = std::collections::HashSet::new();
        inject_injection(
            &mut config,
            &injection,
            &HashMap::new(),
            &dummy_host(),
            &empty_meta(),
            &mut globally_skipped,
        )
        .unwrap();
        assert_eq!(
            config["scheduler"]["accept_cycles"],
            json!(true),
            "debug:to:net feedback pair must auto-enable accept_cycles"
        );

        // An explicit user value wins over the auto-set.
        let mut config2 = json!({
            "scheduler": { "accept_cycles": false },
            "modules": [{ "name": "ip" }],
            "wiring": [],
        });
        let mut injection2 = make_injection(
            vec![make_module("log_net", None)],
            vec![
                "ip.net_out -> log_net.net_in",
                "log_net.net_out -> ip.net_in",
            ],
        );
        injection2.accept_cycles = true;
        let mut skipped2 = std::collections::HashSet::new();
        inject_injection(
            &mut config2,
            &injection2,
            &HashMap::new(),
            &dummy_host(),
            &empty_meta(),
            &mut skipped2,
        )
        .unwrap();
        assert_eq!(
            config2["scheduler"]["accept_cycles"],
            json!(false),
            "explicit user accept_cycles must be preserved"
        );
    }

    /// An injection WITHOUT `accept_cycles` must not add a scheduler block.
    #[test]
    fn no_accept_cycles_leaves_scheduler_absent() {
        let mut config = json!({ "modules": [], "wiring": [] });
        let injection = make_injection(vec![make_module("foo", None)], vec![]);
        let mut skipped = std::collections::HashSet::new();
        inject_injection(
            &mut config,
            &injection,
            &HashMap::new(),
            &dummy_host(),
            &empty_meta(),
            &mut skipped,
        )
        .unwrap();
        assert!(
            config.get("scheduler").is_none(),
            "non-cycle injection must not synthesize a scheduler block"
        );
    }

    /// Type-based dedup: the user has `ip_0` with explicit `type:ip`,
    /// and the stack wants to add a generic `{name:"ip", type:"ip"}`.
    /// Same implementation type already present — skip both the
    /// module AND any wiring that points to the auto-name. This is
    /// the multilane-HTTPS shape.
    #[test]
    fn type_collision_skips_module_and_referencing_wiring() {
        let mut config = json!({
            "modules": [
                { "name": "ip_0", "type": "ip" },
                { "name": "ip_1", "type": "ip" },
                { "name": "demux" },
            ],
            "wiring": [
                { "from": "rp1_gem.frames_rx", "to": "demux.frames_rx" },
            ],
        });
        let injection = make_injection(
            vec![
                make_module("rp1_gem", None),
                make_module("conn_guard", None),
                make_module("ip", Some("ip")),
            ],
            vec![
                "rp1_gem.frames_rx -> conn_guard.frames_rx",
                "conn_guard.frames_tx -> ip.frames_rx",
                "ip.frames_tx -> rp1_gem.frames_tx",
            ],
        );
        let mut globally_skipped = std::collections::HashSet::new();
        let added = inject_injection(
            &mut config,
            &injection,
            &HashMap::new(),
            &dummy_host(),
            &empty_meta(),
            &mut globally_skipped,
        )
        .unwrap();
        assert_eq!(
            added,
            vec!["rp1_gem", "conn_guard"],
            "rp1_gem + conn_guard added, ip dropped via type dedup"
        );
        let pairs = module_pairs(&config);
        let names: Vec<&str> = pairs.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            !names.contains(&"ip"),
            "auto-`ip` should be absent — type collision with ip_0/ip_1"
        );
        // The two wires that *reference* the dropped `ip` are dropped.
        // The pure conn_guard wire stays.
        let edges = edge_strings(&config);
        assert!(
            edges.contains(&"rp1_gem.frames_rx->conn_guard.frames_rx".to_string()),
            "conn_guard wiring should remain — both endpoints exist"
        );
        assert!(
            !edges.contains(&"conn_guard.frames_tx->ip.frames_rx".to_string()),
            "wiring to dropped ip must be skipped — would dangle otherwise"
        );
        assert!(
            !edges.contains(&"ip.frames_tx->rp1_gem.frames_tx".to_string()),
            "wiring from dropped ip must be skipped"
        );
    }

    /// Effective-type fallback: the user's module declared with just
    /// `name:` (no explicit `type:`) still de-dupes a stack module
    /// of the same name when matched by type (since type-when-absent
    /// = name).
    #[test]
    fn implicit_type_via_name_still_blocks_duplicate() {
        let mut config = json!({
            "modules": [{ "name": "ip" }],   // no explicit type; effective type = "ip"
            "wiring": [],
        });
        let injection = make_injection(
            vec![make_module("ip", Some("ip"))],
            vec!["conn_guard.frames_tx -> ip.frames_rx"],
        );
        let mut globally_skipped = std::collections::HashSet::new();
        let added = inject_injection(
            &mut config,
            &injection,
            &HashMap::new(),
            &dummy_host(),
            &empty_meta(),
            &mut globally_skipped,
        )
        .unwrap();
        // Name path catches this before type path, but the result is
        // the same — the auto-`ip` is not added a second time.
        assert!(added.is_empty(), "no new modules — collision handled");
        let pairs = module_pairs(&config);
        assert_eq!(pairs.len(), 1, "still exactly one ip module");
    }

    /// No collision → stack module is added and its wiring lands.
    /// Sanity check that the dedup paths don't reject normal usage.
    #[test]
    fn no_collision_adds_module_and_wiring() {
        let mut config = json!({
            "modules": [{ "name": "tls" }],
            "wiring": [],
        });
        let injection = make_injection(
            vec![make_module("ip", Some("ip"))],
            vec!["ip.net_out -> tls.cipher_in"],
        );
        let mut globally_skipped = std::collections::HashSet::new();
        let added = inject_injection(
            &mut config,
            &injection,
            &HashMap::new(),
            &dummy_host(),
            &empty_meta(),
            &mut globally_skipped,
        )
        .unwrap();
        assert_eq!(added, vec!["ip"]);
        let pairs = module_pairs(&config);
        let names: Vec<&str> = pairs.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"ip"));
        assert!(names.contains(&"tls"));
        let edges = edge_strings(&config);
        assert!(edges.contains(&"ip.net_out->tls.cipher_in".to_string()));
    }

    /// Cross-stack dangling wire: an earlier stack dropped `ip` via
    /// type dedup; a later stack's wiring references that name and
    /// must be dropped too via the shared `globally_skipped` set.
    /// Models the multilane HTTPS flow: `net` runs first, skips `ip`
    /// because `ip_0`/`ip_1` are present; `debug` runs second and
    /// would otherwise wire `log_net <-> ip`.
    #[test]
    fn cross_stack_dangling_wire_is_dropped() {
        let mut config = json!({
            "modules": [
                { "name": "ip_0", "type": "ip" },
                { "name": "ip_1", "type": "ip" },
            ],
            "wiring": [],
        });
        let mut globally_skipped = std::collections::HashSet::new();

        // Stack #1 ("net"): tries to add ip; skipped by type dedup.
        let net_injection = make_injection(
            vec![make_module("ip", Some("ip"))],
            vec!["conn_guard.frames_tx -> ip.frames_rx"],
        );
        inject_injection(
            &mut config,
            &net_injection,
            &HashMap::new(),
            &dummy_host(),
            &empty_meta(),
            &mut globally_skipped,
        )
        .unwrap();
        assert!(
            globally_skipped.contains("ip"),
            "first stack should record 'ip' as skipped"
        );

        // Stack #2 ("debug"): adds log_net + tries to wire it to `ip`.
        // The wires must be dropped because `ip` is in globally_skipped.
        let debug_injection = make_injection(
            vec![make_module("log_net", None)],
            vec![
                "ip.net_out -> log_net.net_in",
                "log_net.net_out -> ip.net_in",
            ],
        );
        let added = inject_injection(
            &mut config,
            &debug_injection,
            &HashMap::new(),
            &dummy_host(),
            &empty_meta(),
            &mut globally_skipped,
        )
        .unwrap();
        assert_eq!(added, vec!["log_net"], "log_net is still added");
        let edges = edge_strings(&config);
        assert!(
            !edges
                .iter()
                .any(|e| e.contains("ip.net_out") || e.contains("ip.net_in")),
            "wires referencing dropped `ip` must be skipped; got: {edges:?}"
        );
    }

    /// Inverse of the dangling case: a stack adds wiring referencing
    /// a module another stack will add *later* in the same expansion.
    /// Stacks process in alphabetical order, so `debug` runs before
    /// `net` — debug's `log_net <-> ip` wiring must survive until
    /// `net` injects `ip`. Single-lane HTTPS depends on this. With no
    /// type collisions, `globally_skipped` is empty and the wire
    /// remains in the graph.
    #[test]
    fn forward_reference_wiring_is_kept_when_target_added_later() {
        let mut config = json!({ "modules": [], "wiring": [] });
        let mut globally_skipped = std::collections::HashSet::new();

        // Stack #1 ("debug" — alphabetically first): adds log_net and
        // wires to `ip` which doesn't exist yet.
        let debug_injection = make_injection(
            vec![make_module("log_net", None)],
            vec![
                "ip.net_out -> log_net.net_in",
                "log_net.net_out -> ip.net_in",
            ],
        );
        inject_injection(
            &mut config,
            &debug_injection,
            &HashMap::new(),
            &dummy_host(),
            &empty_meta(),
            &mut globally_skipped,
        )
        .unwrap();
        let edges_after_debug = edge_strings(&config);
        assert!(
            edges_after_debug
                .iter()
                .any(|e| e == "ip.net_out->log_net.net_in"),
            "forward-referenced wire must survive — net stack will add ip next"
        );

        // Stack #2 ("net"): adds rp1_gem + conn_guard + ip.
        let net_injection = make_injection(
            vec![
                make_module("rp1_gem", None),
                make_module("conn_guard", None),
                make_module("ip", Some("ip")),
            ],
            vec![],
        );
        inject_injection(
            &mut config,
            &net_injection,
            &HashMap::new(),
            &dummy_host(),
            &empty_meta(),
            &mut globally_skipped,
        )
        .unwrap();
        let pairs = module_pairs(&config);
        let names: Vec<&str> = pairs.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"ip"));
        assert!(names.contains(&"log_net"));
        assert!(
            edge_strings(&config)
                .iter()
                .any(|e| e == "ip.net_out->log_net.net_in"),
            "wire must still be present after net adds ip"
        );
    }

    #[test]
    fn endpoint_module_extracts_name_before_dot() {
        assert_eq!(endpoint_module("ip.frames_rx"), "ip");
        assert_eq!(endpoint_module("conn_guard.frames_tx"), "conn_guard");
        // Malformed (no dot) — return whole string. The wiring would
        // fail later validation; the dedup loop just needs to not panic.
        assert_eq!(endpoint_module("noport"), "noport");
        // Empty endpoint — split returns one empty piece; preserved.
        assert_eq!(endpoint_module(""), "");
    }

    #[test]
    fn collect_existing_types_uses_explicit_type_or_falls_back_to_name() {
        let config = json!({
            "modules": [
                { "name": "ip_0", "type": "ip" },
                { "name": "tls" },
                { "name": "lane_a", "type": "http" },
            ],
        });
        let types = collect_existing_types(&config);
        assert_eq!(types, vec!["ip", "tls", "http"]);
    }

    fn project_root() -> std::path::PathBuf {
        // tools/ → project root.
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf()
    }

    /// `merge_with_board_defaults` injects a `silicon` key (the module-artefact
    /// silicon id) so an overlay can select a narrower set than `family`: rp2040
    /// and rp2350 are both `family="rp2"`, so a module that fits only the larger
    /// part needs `silicon` to exclude the smaller one.
    #[test]
    fn merged_injects_silicon_id_distinct_from_family() {
        let root = project_root();
        let rp2350 = crate::target::load_target("pico2w", &root).unwrap();
        let merged = merge_with_board_defaults(&json!({}), "debug", &rp2350);
        assert_eq!(merged.get("family"), Some(&"rp2".to_string()));
        assert_eq!(
            merged.get("silicon"),
            Some(&"rp2350".to_string()),
            "pico2w board resolves to the rp2350 silicon"
        );

        let rp2040 = crate::target::load_target("pico", &root).unwrap();
        let merged = merge_with_board_defaults(&json!({}), "debug", &rp2040);
        assert_eq!(merged.get("family"), Some(&"rp2".to_string()));
        assert_eq!(
            merged.get("silicon"),
            Some(&"rp2040".to_string()),
            "rp2040 stays distinct so a `silicon=rp2350` overlay skips it"
        );
    }

    /// A stack module marked `require_distinct` must fail LOUD on a type
    /// collision (a silent skip would silently kill the stack's feature),
    /// and its `variant:` selection must reach the injected entry.
    #[test]
    fn require_distinct_collision_is_a_hard_error_and_variant_propagates() {
        let toml = r#"
[stack]
name = "t"
[[variant]]
match = {}
modules = [
  { name = "cli_x", type = "widget", variant = "small", require_distinct = true },
]
wiring = []
"#;
        let stack: StackFile = toml::from_str(toml).expect("stack parses");
        let sm = &stack.variant[0].modules[0];
        assert!(sm.require_distinct);
        assert_eq!(sm.variant.as_deref(), Some("small"));

        // Injection with a colliding type present → hard error naming it.
        let mut config = json!({ "modules": [ { "name": "w0", "type": "widget" } ] });
        let mut skipped = std::collections::HashSet::new();
        let host: HostConfig = toml::Value::Table(Default::default());
        let err = inject_modules(
            &mut config,
            &stack.variant[0],
            &HashMap::new(),
            &host,
            &stack.stack,
            &mut skipped,
        )
        .expect_err("collision must refuse");
        assert!(
            err.to_string().contains("one build of a module type"),
            "{err}"
        );

        // Same type at the SAME variant: two instances of one build is
        // ordinary composition — the entry must inject alongside, not error.
        let mut config = json!({ "modules": [
            { "name": "w0", "type": "widget", "variant": "small" } ] });
        inject_modules(
            &mut config,
            &stack.variant[0],
            &HashMap::new(),
            &host,
            &stack.stack,
            &mut skipped,
        )
        .expect("same variant coexists");
        assert_eq!(config["modules"].as_array().unwrap().len(), 2);
        assert_eq!(config["modules"][1]["variant"], "small");

        // Without a collision the entry lands with its variant.
        let mut config = json!({ "modules": [] });
        inject_modules(
            &mut config,
            &stack.variant[0],
            &HashMap::new(),
            &host,
            &stack.stack,
            &mut skipped,
        )
        .expect("no collision");
        assert_eq!(config["modules"][0]["variant"], "small");
    }

    /// An expanded graph carrying `otel` gets the id-table digest
    /// injected as its `table_digest` param; a graph without otel is left
    /// untouched, and an explicit user value wins.
    #[test]
    fn otel_entries_get_table_digest_injected() {
        let tmp = std::env::temp_dir().join(format!("fx_digest_{}", std::process::id()));
        let _ = std::fs::create_dir_all(tmp.join("modules"));

        let mut with_otel = json!({ "modules": [
            { "name": "ip" },
            { "name": "otel", "flush_ms": 500 },
        ]});
        inject_id_table_digest(&mut with_otel, &tmp);
        let d = with_otel["modules"][1]["table_digest"]
            .as_u64()
            .expect("digest injected");
        assert!(d > 0, "FNV-1a32 of a real table is never 0");
        assert!(
            with_otel["modules"][0].get("table_digest").is_none(),
            "only otel entries carry the param"
        );

        // Deterministic: the same expanded config injects the same digest.
        let mut again = json!({ "modules": [
            { "name": "ip" },
            { "name": "otel", "flush_ms": 500 },
        ]});
        inject_id_table_digest(&mut again, &tmp);
        assert_eq!(again["modules"][1]["table_digest"].as_u64(), Some(d));

        // Explicit user value wins.
        let mut explicit = json!({ "modules": [
            { "name": "otel", "table_digest": 7 },
        ]});
        inject_id_table_digest(&mut explicit, &tmp);
        assert_eq!(explicit["modules"][0]["table_digest"].as_u64(), Some(7));

        // No otel → untouched.
        let mut none = json!({ "modules": [ { "name": "ip" } ]});
        inject_id_table_digest(&mut none, &tmp);
        assert!(none["modules"][0].get("table_digest").is_none());

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
