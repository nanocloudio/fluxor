/// Parse a port spec like "module.out[1]" or "module.ctrl" into (name, port_type, port_index).
/// port_type: 0=in, 1=out, 2=ctrl. port_index: 0-based.
/// Simple forms: "module" → (module, in, 0), "module.out" → (module, out, 0),
/// Indexed: "module.in[1]" → (module, in, 1), "module.out[1]" → (module, out, 1)
/// Load manifests for all modules referenced in the config.
///
/// Resolves module type aliases (e.g., `name: btn_melody, type: button` loads
/// `modules/button/manifest.toml` and stores it under key `btn_melody`).
/// Manifests live in the source `modules/` directory, not `target/modules/`.
/// Load manifests from both the standard fluxor module directories and
/// Extract the manifest-source search paths a config wants the build tool
/// to consult, in priority order. The returned list is the union of:
///
/// 1. Any explicit `module_search_paths: [..]` entries declared at the
///    top level of the YAML config. Each entry is resolved relative to
///    the config file's directory (so `module_search_paths:
///    [../../substrate/modules]` in `<app>/configs/*.yaml` points at
///    `substrate/modules` regardless of where the tool is invoked from).
///
/// 2. The implicit `<config-parent>/../modules` default (e.g.
///    `<app>/modules` for a config in `<app>/configs/*.yaml`).
///    Kept for backward compatibility; new graphs should prefer the
///    explicit `module_search_paths:` key so the substrate / app split
///    is visible at the config layer.
///
/// Both manifest discovery (`load_module_manifests_with_extra`) and
/// graph parsing should consult this list. Non-existent entries are
/// kept (the consumer skips them) so an env-specific path that's
/// missing doesn't silently shadow other entries.
pub fn extract_module_search_paths(
    config: &Value,
    config_path: &std::path::Path,
) -> Vec<std::path::PathBuf> {
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    let config_dir = config_path.parent().unwrap_or(std::path::Path::new("."));

    if let Some(arr) = config.get("module_search_paths").and_then(|v| v.as_array()) {
        for entry in arr {
            if let Some(s) = entry.as_str() {
                let joined = config_dir.join(s);
                let canon = joined.canonicalize().unwrap_or(joined);
                paths.push(canon);
            }
        }
    }

    if let Some(default) = config_path
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("modules"))
    {
        // Avoid duplicating the default if the YAML already pointed at
        // the same place.
        let canon = default.canonicalize().unwrap_or(default);
        if !paths.iter().any(|p| p == &canon) {
            paths.push(canon);
        }
    }

    // Append the project root's `modules/` and the install root's
    // `modules/` so external user projects see the bundled
    // modules in their search-path view. The manifest loader
    // (`load_module_manifests_with_extra`) already walks these
    // independently via `STANDARD_MODULE_SUBDIRS`; surfacing them
    // here keeps `inspect`'s module-search-paths listing and the
    // actual loader behaviour aligned.
    let project = crate::project::root();
    let project_modules = project.join("modules");
    let canon = project_modules.canonicalize().unwrap_or(project_modules);
    if !paths.iter().any(|p| p == &canon) {
        paths.push(canon);
    }
    if let Some(install) = crate::project::install_root() {
        if install.path != project {
            let install_modules = install.path.join("modules");
            let canon = install_modules.canonicalize().unwrap_or(install_modules);
            if !paths.iter().any(|p| p == &canon) {
                paths.push(canon);
            }
        }
    }

    paths
}

/// any additional search paths (e.g., relative to the config file).
/// Standard fluxor module subdirectories, relative to a root. Mirrors
/// `Manifest::from_source_tree` in `tools/src/manifest.rs`. Built-ins
/// live under `modules/platform/<platform>/<name>/`.
const STANDARD_MODULE_SUBDIRS: &[&str] = &[
    "modules/drivers",
    "modules/foundation",
    "modules/app",
    "modules/fixtures",
    "modules/platform/linux",
    "modules/platform/wasm",
    "modules/platform/qemu",
    "modules",
];

/// Build the prioritized list of module search roots. Order:
///   1. `<project_root>/<standard subdirs>` — user's overrides
///      first so a local module shadows the bundled one.
///   2. `<install_root>/<standard subdirs>` — bundled fallback
///      when the install root differs from the project root.
///   3. `<workspace member>/<standard subdirs>` — sibling checkouts,
///      last so they never shadow an in-tree module. Dev-only; see
///      `workspace::member_roots`.
///
/// Returns absolute paths in priority order. Non-existent entries
/// are kept (the manifest loader skips them) so a missing
/// per-platform directory doesn't silently shadow other entries.
fn standard_module_dirs() -> Vec<std::path::PathBuf> {
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    let project = crate::project::root();
    for sub in STANDARD_MODULE_SUBDIRS {
        dirs.push(project.join(sub));
    }
    if let Some(install) = crate::project::install_root() {
        if install.path != project {
            for sub in STANDARD_MODULE_SUBDIRS {
                let p = install.path.join(sub);
                if !dirs.contains(&p) {
                    dirs.push(p);
                }
            }
        }
    }
    // Sibling checkouts last, so an in-tree module always wins a name clash.
    // See `workspace::member_roots` for why this is a dev convenience and not
    // a resolution path anything shippable may rely on.
    for member in crate::workspace::member_roots(&project) {
        for sub in STANDARD_MODULE_SUBDIRS {
            let p = member.join(sub);
            if p.is_dir() && !dirs.contains(&p) {
                dirs.push(p);
            }
        }
    }
    dirs
}

/// Resolve a module `type_name` to the directory that contains its
/// `manifest.toml` + `src/` tree, honoring the documented search-path
/// priority order:
///
///   1. **`extra_dirs` first** — the caller-supplied list, typically
///      `extract_module_search_paths()`'s output (YAML
///      `module_search_paths` → `<config-parent>/../modules` →
///      project/install `modules/`). The YAML entry is *priority-
///      ordered*: an entry earlier in the list shadows a later one.
///   2. **`standard_module_dirs()`** — the bundled subtree layout
///      (`modules/drivers`, `modules/foundation`, ...) under the
///      project root, then the install root, then any workspace
///      member checkout.
///
/// Returns the first hit (`<dir>/<type_name>` whose directory
/// exists). Centralising the lookup keeps the manifest loader
/// (`load_module_manifests_with_extra`) and the ISR-tier NEON-lint
/// in `validate_isr_tier_admission` aligned: if a config-declared
/// `module_search_paths:` entry collides with a bundled module of
/// the same `type:` name, both readers must agree on which one
/// wins. Splitting the order between the two readers historically
/// admitted an ISR module that scanned the wrong source tree.
fn resolve_module_root(
    type_name: &str,
    extra_dirs: &[&std::path::Path],
) -> Option<std::path::PathBuf> {
    for extra in extra_dirs {
        let candidate = extra.join(type_name);
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    for dir in standard_module_dirs() {
        let candidate = dir.join(type_name);
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    None
}

/// Process-global "already warned" cache for malformed manifest
/// paths. `load_module_manifests_with_extra` runs multiple times
/// in a single `fluxor build --check` / `fluxor build` invocation
/// (presentation groups + the main pipeline + each scenario
/// component); without deduplication the same warning fires 3-4
/// times for a single broken manifest. The cache survives for the
/// process lifetime, which is the natural scope — a fresh
/// invocation re-emits the warnings.
fn warn_manifest_once(path: &std::path::Path, message: &str) {
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<std::collections::BTreeSet<std::path::PathBuf>>> = OnceLock::new();
    let lock = SEEN.get_or_init(|| Mutex::new(std::collections::BTreeSet::new()));
    let mut seen = match lock.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if seen.insert(path.to_path_buf()) {
        eprintln!("warning: {message}");
    }
}

fn warn_manifest_parse_error_once(path: &std::path::Path, err: &Error) {
    warn_manifest_once(
        path,
        &format!("manifest at {} failed to parse: {}", path.display(), err),
    );
}

pub fn load_module_manifests_with_extra(
    modules_config: &Value,
    extra_dirs: &[&std::path::Path],
    project_root: &std::path::Path,
) -> HashMap<String, Manifest> {
    load_module_manifests_with_extra_for_target(modules_config, extra_dirs, None, project_root)
}

/// Target-aware variant used by config generation. Capacity tables in module
/// manifests are deployment inputs, so resolving them without the silicon id
/// silently selects `default` even when the graph targets a larger host.
pub fn load_module_manifests_with_extra_for_target(
    modules_config: &Value,
    extra_dirs: &[&std::path::Path],
    target_silicon: Option<&str>,
    project_root: &std::path::Path,
) -> HashMap<String, Manifest> {
    let mut manifests = HashMap::new();
    let list = match modules_config.as_array() {
        Some(l) => l,
        None => return manifests,
    };

    // A pinned `[[artifact]]` module entry ships its `manifest.toml` in the same
    // content-addressed store artifact as its `.fmod` (symmetric to
    // `resolve_fmod`'s store fallback). Consult the pins FIRST and
    // authoritatively: a store-only sibling module has no source tree
    // here, and even when a stale copy sits on disk, resolving ports from
    // anything but the pinned artifact lets wiring validate against a port
    // surface the pinned bytes don't have. `None` when nothing is pinned —
    // the common case pays no store I/O.
    //
    // `project_root` is config-anchored by the caller (`root_for_config`),
    // never `project::root()`'s cwd fallback: a cross-project invocation
    // (`fluxor build --check ../other/x.yaml`) must read the CONFIG's
    // `fluxor.lock` — the same lock the `.fmod` resolver uses — or port
    // validation and fmod packaging consult different pins. Silicon-scoped
    // so wiring binds to the exact artifact being packaged.
    let store_manifests =
        crate::store_cli::lock_store_manifest_resolver(project_root, target_silicon, None);

    for module in list {
        let name = match module["name"].as_str() {
            Some(n) => n,
            None => continue,
        };
        let type_name = module["type"].as_str().unwrap_or(name);

        if let Some(resolver) = &store_manifests {
            match resolver(type_name) {
                crate::modules::ManifestPin::Resolved(toml) => {
                    match Manifest::from_toml_str_for_target(&toml, target_silicon) {
                        Ok(mut m) => {
                            if let Some(variant) = module["variant"].as_str() {
                                if let Err(e) = m.apply_variant(variant) {
                                    warn_manifest_once(
                                        std::path::Path::new(&format!("oci://{type_name}")),
                                        &format!(
                                            "module '{name}' (pinned artifact): {e}; its \
                                             manifest is omitted from wiring validation"
                                        ),
                                    );
                                    continue;
                                }
                            }
                            manifests.insert(name.to_string(), m);
                        }
                        Err(e) => warn_manifest_parse_error_once(
                            std::path::Path::new(&format!("oci://{type_name}")),
                            &e,
                        ),
                    }
                    // Pinned is authoritative — never fall through to disk.
                    continue;
                }
                // This loader is infallible by construction, so it can only
                // warn; enforcement lives in
                // `assert_pinned_manifests_resolvable`, which every strict
                // path (validate / config-gen / image build) calls before
                // loading. Reaching this arm therefore means an advisory
                // caller, where aborting would be wrong.
                crate::modules::ManifestPin::Failed(why) => {
                    warn_manifest_once(
                        std::path::Path::new(&format!("oci://{type_name}")),
                        &format!(
                            "module '{name}' is pinned in fluxor.lock but its manifest \
                             could not be resolved from the store: {why}"
                        ),
                    );
                    continue;
                }
                crate::modules::ManifestPin::NotPinned => {}
            }
        }

        // `resolve_module_root` walks `extra_dirs` first (the
        // YAML-declared `module_search_paths:` order), then the
        // standard bundled subdirs. An explicit YAML entry
        // shadowing a bundled module of the same type:name was
        // documented to win — searching standard first violated
        // that and could load the wrong `manifest.toml` for
        // ISR-tier admission.
        let Some(root) = resolve_module_root(type_name, extra_dirs) else {
            continue;
        };
        let manifest_path = root.join("manifest.toml");
        if !manifest_path.exists() {
            continue;
        }
        match Manifest::from_toml_for_target(&manifest_path, target_silicon) {
            Ok(mut m) => {
                // Variant-selected node (RFC module_variants): the
                // manifest wiring validates against is the VARIANT's —
                // omitted ports absent, so a YAML that wires a dropped
                // port fails loudly at config build (`resolve_port_spec`
                // finds no such port) instead of at runtime. An unknown
                // variant name only WARNS here (this loader is
                // infallible by design — see the NOTE below on
                // omission); the hard failure comes at fmod resolution
                // (`parse_modules_from_config_multi`), which names the
                // missing `<type>-<variant>.fmod` artifact.
                if let Some(variant) = module["variant"].as_str() {
                    if let Err(e) = m.apply_variant(variant) {
                        warn_manifest_once(
                            &manifest_path,
                            &format!(
                                "module '{name}' (manifest {}): {e}; its manifest is \
                                 omitted from wiring validation",
                                manifest_path.display()
                            ),
                        );
                        continue;
                    }
                }
                manifests.insert(name.to_string(), m);
            }
            Err(e) => {
                // Don't silently swallow the parse error — a
                // malformed manifest looks identical to a missing
                // one downstream ("no manifest found") and the
                // user has no idea why. Surface the path + error.
                // NOTE: a malformed manifest is OMITTED from the
                // map, which is indistinguishable from "no manifest"
                // to map lookups — so a gate that must NOT fail open
                // on a malformed manifest (e.g. the adaptive
                // timer-class gate in `validate_adaptive_tick`) has
                // to re-check manifest-file existence itself and
                // reject; it cannot rely on the omission alone.
                // Dedup'd across the process so re-entry from
                // multiple validators doesn't spam the same path.
                warn_manifest_parse_error_once(&manifest_path, &e);
            }
        }
    }
    manifests
}

/// Enforcement half of the pinned-manifest path: a module pinned in
/// `fluxor.lock` whose `manifest.toml` cannot be resolved and parsed from
/// the store (corrupt/missing blob, non-UTF-8 payload, unreadable store,
/// unreadable lockfile, ambiguous multi-target pin, malformed TOML, unknown
/// variant) is a HARD error naming the module, the pin and the cause. The
/// pin exists precisely to enforce that port surface, so a strict caller
/// must refuse rather than let the module drop out of wiring validation and
/// pass a graph nothing checked.
///
/// Separate from `load_module_manifests_*` on purpose: that loader returns a
/// map and cannot fail, so it warns and omits — right for advisory callers,
/// wrong for `fluxor build --check` / config generation / image build, which call
/// this first. `project_root` is config-anchored (see the loader's note); a
/// project with no pins resolves no resolver and this is a no-op.
pub fn assert_pinned_manifests_resolvable(
    modules_config: &Value,
    target_silicon: Option<&str>,
    project_root: &std::path::Path,
) -> Result<()> {
    let Some(list) = modules_config.as_array() else {
        return Ok(());
    };
    let Some(resolver) =
        crate::store_cli::lock_store_manifest_resolver(project_root, target_silicon, None)
    else {
        return Ok(());
    };
    for module in list {
        let Some(name) = module["name"].as_str() else {
            continue;
        };
        let type_name = module["type"].as_str().unwrap_or(name);
        let why = match resolver(type_name) {
            crate::modules::ManifestPin::NotPinned => continue,
            crate::modules::ManifestPin::Failed(why) => why,
            crate::modules::ManifestPin::Resolved(toml) => {
                match Manifest::from_toml_str_for_target(&toml, target_silicon) {
                    Ok(mut m) => match module["variant"].as_str() {
                        Some(variant) => match m.apply_variant(variant) {
                            Ok(()) => continue,
                            Err(e) => format!("{e}"),
                        },
                        None => continue,
                    },
                    Err(e) => format!("{e}"),
                }
            }
        };
        return Err(Error::Config(format!(
            "module '{name}' is pinned in fluxor.lock but its manifest could not be \
             resolved from the OCI store: {why}"
        )));
    }
    Ok(())
}

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

    // Named port — look up in manifest. A missing manifest at this
    // point is almost always one of: a typo in the module's name
    // (e.g. `sequencr.notes` when the module is declared as
    // `sequencer`), a typo in the `type:` field, a `.fmod` whose
    // source tree fluxor can't see (the project root is wrong, or
    // the install root needs to be set), or a built-in module
    // whose feature isn't compiled into the running fluxor binary.
    // Run a Levenshtein lookup against the declared module-name
    // list first — typo'd name is the single most common cause.
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
             \x20\x20- the module is a built-in whose feature isn't compiled into this \
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
    edges: &[(u8, u8, u8, u8, u8)],
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
    let mut covered_data: BTreeSet<(u8, u8)> = BTreeSet::new();
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
            // flags bit 0 = required (per `Manifest::from_toml` at
            // tools/src/manifest.rs line ~760). A non-required
            // input left unconnected is fine — module handles
            // empty input by design.
            if port.flags & 0x01 == 0 {
                continue;
            }
            if covered_data.contains(&(module_id as u8, port.index)) {
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

/// Per-edge capacity + rate-class validation.
///
/// Static mirror of the runtime `open_channels` enforcement, using
/// the manifests' static port capacities: for every FIFO edge, model
/// the ring the kernel will grant and check
///   1. producer `max_record` fits it (wedge exclusion — an
///      all-or-nothing write larger than the ring can never succeed);
///   2. no request exceeds the 2 MiB channel ceiling;
///   3. the edge's rate class is satisfiable on this profile at all;
///   4. class floor ≤ ring × nominal tick rate (a necessary-condition
///      screen for order-of-magnitude misprovisioning, NOT a proof of
///      sufficiency — module step logic is P3's business).
///
/// Edge class = per-edge `rate:` override, else the consumer port's
/// content-type default (`CONTENT_RATE_CLASS`), else the producer's.
/// Grouped (mailbox) edges are skipped — their capacity story is the
/// buffer-group max, validated by the runtime group pass.
fn validate_wiring_capacity(
    config: &Value,
    edges: &[(u8, u8, u8, u8, u8)],
    module_names: &[String],
    manifests: &HashMap<String, Manifest>,
    from_specs: &[String],
    to_specs: &[String],
    embedded_profile: bool,
) -> Result<()> {
    use fluxor_contracts::{rate_class_floor, RateClass};

    const MIN_CHAN_BYTES: u32 = 64;
    const MAX_CHAN_BYTES: u32 = 4 * 1024 * 1024;
    const DEFAULT_RING: u32 = 8192; // kernel default (abi CHANNEL_BUFFER_SIZE)

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
            continue; // mailbox/group-max semantics — runtime validates
        }
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

        // Model the runtime grant (mirror of open_channels).
        let prod_size = from_port.map(|p| p.buffer_size).unwrap_or(0);
        let cons_size = to_port_spec.map(|p| p.buffer_size).unwrap_or(0);
        let request = prod_size.max(cons_size).max(buffer_bytes);
        // (2) ceiling.
        if request > MAX_CHAN_BYTES {
            return Err(Error::Config(format!(
                "wiring[{i}] ({} → {}): requested buffer {} exceeds the channel \
                 ceiling {} — lower the request or split the stream.",
                from_specs[i], to_specs[i], request, MAX_CHAN_BYTES
            )));
        }
        let granted = if request == 0 {
            DEFAULT_RING
        } else {
            request
                .clamp(MIN_CHAN_BYTES, MAX_CHAN_BYTES)
                .next_power_of_two()
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
            return Err(Error::Config(format!(
                "wiring[{i}] ({} → {}): rate class '{}' needs ≥ {} B/s but the \
                 {}-byte ring at tick_us={} sustains at most {} B/s. Raise \
                 buffer_bytes or lower the edge's rate class.",
                from_specs[i],
                to_specs[i],
                class.as_str(),
                floor,
                granted,
                tick_us,
                ring_rate_ceiling
            )));
        }
    }
    Ok(())
}

fn validate_wiring_types(
    edges: &[(u8, u8, u8, u8, u8)],
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

/// The five session continuity classes (rfc_protocols.md §7.1,
/// `protocol_surfaces.md`). Distinct from the AV `continuity_policy`
/// enum above, which governs presentation-group cutover only.
const CONTINUITY_CLASSES: &[&str] = &[
    "reroutable",
    "drain_only",
    "resumable",
    "edge_anchored",
    "transport_migratable",
];

/// `transport_migratable` migration mechanisms (rfc_protocols.md §7.1).
const MIGRATION_MECHANISMS: &[&str] = &["native_primitive", "platform_replicated_state"];

/// AEAD classes for platform-replicated-state migration
/// (rfc_protocols.md §13.7.2).
const AEAD_CLASSES: &[&str] = &["on_wire_sequence", "implicit_counter", "unencrypted"];

/// Capabilities every platform-replicated-state `transport_migratable`
/// declaration must resolve somewhere in the graph (§9.2 / §13.7.6
/// R1–R5 as structure). Presence, not fault-correctness — R-invariants
/// are proven by test, the timing budget by measurement.
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

