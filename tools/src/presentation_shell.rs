//! Build-time validator for the `presentation.shell` /
//! `presentation.browser_overlay` descriptors (RFC browser_overlay §19
//! + Amendment A §A.7).
//!
//! Kept as a standalone, dependency-light module (only `serde_json`) so
//! it is unit-testable directly with synthetic configs — no module
//! tree, no `fluxor validate` subprocess. It returns a plain
//! `Result<(), String>` so it carries no coupling to the (dual-compiled)
//! crate error type; the `config.rs` pass maps the message into its
//! `Error::Config` via `.map_err(...)`.
//!
//! Absent blocks validate trivially: every scenario without a `shell:`
//! keeps its prior behaviour. When present, this enforces the
//! structural, control-kind, and media/parameter cross-reference rules
//! so a malformed descriptor fails at build time rather than rendering
//! an empty or write-only control in the browser. The control
//! vocabulary is kept in lock-step with the JS renderer
//! (`src/platform/wasm/host/browser_overlay_runtime.js`, pinned by
//! `tools/tests/browser_overlay_runtime_surface.rs`).

use serde_json::Value;

/// Canonical control kinds (RFC §7.3 + Amendment A: `select`/`checkbox`).
pub const CONTROL_KINDS: &[&str] = &[
    "button",
    "button_cluster",
    "dpad",
    "stick",
    "slider",
    "scrubber",
    "toggle",
    "checkbox",
    "menu",
    "select",
    "keyboard",
    "status",
];

/// Semantic placement groups (RFC §7.2).
pub const PLACEMENTS: &[&str] = &[
    "primary_start",
    "primary_end",
    "secondary",
    "drawer",
    "transient",
    "above_content",
    "debug",
];

/// Media profiles (RFC §16).
pub const MEDIA_PROFILES: &[&str] = &[
    "game",
    "music",
    "movie",
    "gallery",
    "spectator",
    "terminal",
    "custom",
];

/// Activity contexts (RFC §7.5).
pub const CONTEXTS: &[&str] = &["preview", "launching", "active", "background", "spectator"];

/// Validate `config.presentation.shell` / `.browser_overlay` if present.
/// `module_names` is the set of declared module instance names, used to
/// resolve `presentation.surfaces[].module`. Returns the violation
/// message on failure.
pub fn validate(config: &Value, module_names: &[String]) -> Result<(), String> {
    let presentation = match config.get("presentation") {
        Some(p) => p,
        None => return Ok(()),
    };
    let shell = match presentation.get("shell") {
        Some(s) => s,
        None => {
            // A browser_overlay without a shell is invalid (§5.5: the
            // overlay is the browser adapter *for* the shell).
            if presentation.get("browser_overlay").is_some() {
                return Err(
                    "presentation.browser_overlay present without presentation.shell".to_string(),
                );
            }
            return Ok(());
        }
    };

    // §18.6 / §19.1: version must be exactly 1.
    if shell.get("version").and_then(|v| v.as_u64()) != Some(1) {
        return Err("presentation.shell.version must be 1".to_string());
    }

    // §19.1: media_profile recognized (or `custom`); context recognized.
    let profile = shell
        .get("media_profile")
        .and_then(|v| v.as_str())
        .unwrap_or("custom");
    if !MEDIA_PROFILES.contains(&profile) {
        return Err(format!(
            "presentation.shell.media_profile `{profile}` is not recognized \
             (expected one of {MEDIA_PROFILES:?})"
        ));
    }
    if let Some(ctx) = shell.get("context").and_then(|v| v.as_str()) {
        if !CONTEXTS.contains(&ctx) {
            return Err(format!(
                "presentation.shell.context `{ctx}` is not recognized \
                 (expected one of {CONTEXTS:?})"
            ));
        }
    }

    // §19.1: surface ids unique; referenced modules resolve.
    if let Some(surfaces) = presentation.get("surfaces").and_then(|v| v.as_array()) {
        let mut seen_ids: Vec<&str> = Vec::new();
        for (i, surf) in surfaces.iter().enumerate() {
            if let Some(id) = surf.get("id").and_then(|v| v.as_str()) {
                if seen_ids.contains(&id) {
                    return Err(format!(
                        "presentation.surfaces: duplicate surface id `{id}`"
                    ));
                }
                seen_ids.push(id);
            }
            if let Some(m) = surf.get("module").and_then(|v| v.as_str()) {
                if !module_names.iter().any(|n| n == m) {
                    return Err(format!(
                        "presentation.surfaces[{i}]: module `{m}` is not declared in `modules:`"
                    ));
                }
            }
        }
    }

    // Declared list keys + presence of a status feed (free-form feed
    // names resolved at runtime by the activity coordinator).
    let declared_lists: Vec<&str> = shell
        .get("lists")
        .and_then(|v| v.as_object())
        .map(|o| o.keys().map(|k| k.as_str()).collect())
        .unwrap_or_default();
    let has_status_feed = shell
        .get("status_feed")
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    // controls: unique ids, recognized kinds/placements, per-kind reqs.
    let empty = Vec::new();
    let controls = shell
        .get("controls")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let mut seen_ctl_ids: Vec<String> = Vec::new();
    for (i, ctl) in controls.iter().enumerate() {
        validate_control(ctl, i, &mut seen_ctl_ids, &declared_lists, has_status_feed)?;
    }

    // browser_overlay: version must be 1 when present.
    if let Some(bo) = presentation.get("browser_overlay") {
        if bo.get("version").and_then(|v| v.as_u64()) != Some(1) {
            return Err("presentation.browser_overlay.version must be 1".to_string());
        }
    }

    Ok(())
}

/// Validate one shell control (§19.2, §19.4, Amendment A §A.7).
fn validate_control(
    ctl: &Value,
    idx: usize,
    seen_ids: &mut Vec<String>,
    declared_lists: &[&str],
    has_status_feed: bool,
) -> Result<(), String> {
    let id = ctl
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("presentation.shell.controls[{idx}]: missing `id`"))?;
    if seen_ids.iter().any(|s| s == id) {
        return Err(format!(
            "presentation.shell.controls: duplicate control id `{id}`"
        ));
    }
    seen_ids.push(id.to_string());

    let kind = ctl
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("control `{id}`: missing `kind`"))?;
    if !CONTROL_KINDS.contains(&kind) {
        return Err(format!(
            "control `{id}`: unknown kind `{kind}` (expected one of {CONTROL_KINDS:?})"
        ));
    }
    if let Some(p) = ctl.get("placement").and_then(|v| v.as_str()) {
        if !PLACEMENTS.contains(&p) {
            return Err(format!(
                "control `{id}`: unknown placement `{p}` (expected one of {PLACEMENTS:?})"
            ));
        }
    }

    let has_action = ctl.get("action").and_then(|v| v.as_str()).is_some();
    let has_control = ctl.get("control").and_then(|v| v.as_str()).is_some();
    let names_list = ctl.get("list").and_then(|v| v.as_str());
    let list_resolves = names_list
        .map(|l| declared_lists.contains(&l))
        .unwrap_or(false);

    match kind {
        "button" | "toggle" | "checkbox" => {
            if !has_action && !has_control {
                return Err(format!(
                    "control `{id}` ({kind}): needs an `action` (semantic) or `control` (raw)"
                ));
            }
        }
        // A scrubber renders position from status and seeks via an action.
        "scrubber" => {
            if !has_action {
                return Err(format!(
                    "control `{id}` (scrubber): requires a seek `action`"
                ));
            }
            if !has_status_feed {
                return Err(format!(
                    "control `{id}` (scrubber): requires a `status_feed` on the shell to render position"
                ));
            }
        }
        "slider" => {
            if !has_action {
                return Err(format!("control `{id}` (slider): requires an `action`"));
            }
        }
        // Menu / select are list-backed semantic controls.
        "menu" | "select" => {
            if !has_action {
                return Err(format!("control `{id}` ({kind}): requires an `action`"));
            }
            match names_list {
                None => {
                    return Err(format!(
                        "control `{id}` ({kind}): requires a `list` naming a declared `lists:` entry"
                    ))
                }
                Some(l) if !list_resolves => {
                    return Err(format!(
                        "control `{id}` ({kind}): `list: {l}` is not declared under the shell's `lists:`"
                    ))
                }
                _ => {}
            }
        }
        "dpad" => {
            let has_src = ctl
                .get("source")
                .and_then(|s| s.get("controls"))
                .and_then(|c| c.as_object())
                .map(|o| !o.is_empty())
                .unwrap_or(false);
            if !has_src {
                return Err(format!(
                    "control `{id}` (dpad): requires `source.controls` (up/down/left/right)"
                ));
            }
        }
        "keyboard" => {
            if ctl.get("keys").is_none() && ctl.get("layout").is_none() {
                return Err(format!(
                    "control `{id}` (keyboard): requires `keys` or `layout`"
                ));
            }
        }
        "status" => {
            if ctl.get("field").and_then(|v| v.as_str()).is_none() {
                return Err(format!("control `{id}` (status): requires a `field`"));
            }
        }
        // Containers: each child button needs an action or raw control.
        "button_cluster" => {
            if let Some(buttons) = ctl.get("buttons").and_then(|v| v.as_array()) {
                for b in buttons {
                    let semantic = b.get("action").and_then(|v| v.as_str()).is_some();
                    let raw = b.get("control").and_then(|v| v.as_str()).is_some();
                    if !semantic && !raw {
                        let bid = b.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                        return Err(format!(
                            "control `{id}` (button_cluster): button `{bid}` needs `action` or `control`"
                        ));
                    }
                }
            }
        }
        "stick" => {}
        _ => {}
    }
    Ok(())
}
