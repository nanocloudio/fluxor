//! Build-time validator for the `presentation.shell` /
//! `presentation.browser_overlay` descriptors (RFC browser_overlay §19,
//! §A.7).
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

/// Canonical control kinds (RFC §7.3, §A: `select`/`checkbox`).
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
    "list",
    "keyboard",
    "status",
];

/// Max byte length of a `bind_physical` name. MUST match the on-device legend
/// store `MAX_BTN_LEN` in `presentation_resolver` and `content_controls` — those
/// PIC modules truncate a longer bound name, which would diverge the host and
/// device legends, so the validator rejects names over this length.
pub const BIND_PHYSICAL_MAX: usize = 24;

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

/// Named superimposed-overlay regions (RFC §11.3 `overlay_regions`). MUST match
/// the `OVERLAY_REGION` map in `browser_overlay_runtime.js` (pinned by
/// `tools/tests/browser_overlay_runtime_surface.rs`) — an unknown name would
/// silently default to a corner at runtime, so the validator rejects it.
pub const OVERLAY_REGIONS: &[&str] = &[
    "left_third",
    "right_third",
    "center_third",
    "top_start",
    "top_end",
    "bottom_start",
    "bottom_end",
    "bottom_center",
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

// ── Control-intent metadata (rfc_adaptive_presentation.md §9) ──
// Optional per-control fields that drive the placement resolver. All are
// additive: a control omitting them keeps the existing chrome behaviour.

/// `plane_affinity`: ordered preference of render planes. `bound`/`hidden` are
/// resolver *outcomes*, not requestable affinities — a control reaches `bound`
/// via `bind_physical`, and `hidden` only under overflow.
pub const PLANES: &[&str] = &["chrome", "content"];

/// `priority`: governs drop order under overflow. `essential` is never hidden.
pub const PRIORITIES: &[&str] = &["essential", "standard", "optional"];

/// `min_size_class` / size-class vocabulary (mirrors input::surface_traits).
pub const SIZE_CLASSES: &[&str] = &["compact", "regular", "expanded"];

/// Input modalities a `suppress_if: modality.<name>` clause may name (mirrors
/// the input::surface_traits MODALITY_* bits).
pub const MODALITIES: &[&str] = &[
    "key",
    "pointer_fine",
    "pointer_coarse",
    "touch",
    "gamepad",
    "physical_buttons",
];

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

/// Validate one shell control (§19.2, §19.4, §A.7).
/// Validate the optional control-intent fields
/// (`rfc_adaptive_presentation.md` §9): `plane_affinity`, `priority`,
/// `min_size_class`, `suppress_if`, `bind_physical`, `overlay`,
/// `overlay_regions`. All are additive — a control omitting them is unchanged.
fn validate_intent(ctl: &Value, id: &str) -> Result<(), String> {
    if let Some(v) = ctl.get("plane_affinity") {
        let arr = v.as_array().ok_or_else(|| {
            format!("control `{id}`: `plane_affinity` must be an array of planes {PLANES:?}")
        })?;
        if arr.is_empty() {
            return Err(format!(
                "control `{id}`: `plane_affinity` must not be empty (a control with no \
                 eligible plane can never render)"
            ));
        }
        for p in arr {
            let p = p.as_str().ok_or_else(|| {
                format!("control `{id}`: `plane_affinity` entries must be strings {PLANES:?}")
            })?;
            if !PLANES.contains(&p) {
                return Err(format!(
                    "control `{id}`: unknown plane `{p}` in `plane_affinity` (expected one of {PLANES:?})"
                ));
            }
        }
    }
    if let Some(p) = ctl.get("priority") {
        let p = p
            .as_str()
            .ok_or_else(|| format!("control `{id}`: `priority` must be a string"))?;
        if !PRIORITIES.contains(&p) {
            return Err(format!(
                "control `{id}`: unknown priority `{p}` (expected one of {PRIORITIES:?})"
            ));
        }
    }
    if let Some(s) = ctl.get("min_size_class") {
        let s = s
            .as_str()
            .ok_or_else(|| format!("control `{id}`: `min_size_class` must be a string"))?;
        if !SIZE_CLASSES.contains(&s) {
            return Err(format!(
                "control `{id}`: unknown min_size_class `{s}` (expected one of {SIZE_CLASSES:?})"
            ));
        }
    }
    if let Some(s) = ctl.get("suppress_if") {
        let s = s
            .as_str()
            .ok_or_else(|| format!("control `{id}`: `suppress_if` must be a string"))?;
        let m = s.strip_prefix("modality.").ok_or_else(|| {
            format!("control `{id}`: `suppress_if` must be `modality.<name>` (got `{s}`)")
        })?;
        if !MODALITIES.contains(&m) {
            return Err(format!(
                "control `{id}`: unknown modality `{m}` in `suppress_if` (expected one of {MODALITIES:?})"
            ));
        }
    }
    if let Some(b) = ctl.get("bind_physical") {
        let b = b
            .as_str()
            .ok_or_else(|| format!("control `{id}`: `bind_physical` must be a string"))?;
        if b.is_empty() {
            return Err(format!(
                "control `{id}`: `bind_physical` must be a non-empty physical-control id"
            ));
        }
        // The on-device legend (presentation_resolver / content_controls
        // MAX_BTN_LEN) truncates a bound name to BIND_PHYSICAL_MAX bytes, while
        // the host overlay carries the full string. A longer name would render
        // a different legend on host vs device, and two names sharing a
        // BIND_PHYSICAL_MAX-byte prefix would collapse to the same on-device
        // legend. Reject at config time so the two implementations never diverge.
        if b.len() > BIND_PHYSICAL_MAX {
            return Err(format!(
                "control `{id}`: `bind_physical` is {} bytes; the on-device legend \
                 truncates bound names to {BIND_PHYSICAL_MAX}, so a longer name would \
                 render differently on host and device (and names sharing a \
                 {BIND_PHYSICAL_MAX}-byte prefix would collapse) — shorten it",
                b.len()
            ));
        }
    }
    if let Some(o) = ctl.get("overlay") {
        if !o.is_boolean() {
            return Err(format!("control `{id}`: `overlay` must be a boolean"));
        }
    }
    if let Some(v) = ctl.get("overlay_regions") {
        let arr = v
            .as_array()
            .ok_or_else(|| format!("control `{id}`: `overlay_regions` must be an array"))?;
        for r in arr {
            let name = r.as_str().ok_or_else(|| {
                format!("control `{id}`: `overlay_regions` entries must be strings")
            })?;
            if !OVERLAY_REGIONS.contains(&name) {
                return Err(format!(
                    "control `{id}`: `overlay_regions` entry `{name}` is not a known region \
                     (one of {OVERLAY_REGIONS:?}) — an unknown name renders at a default corner"
                ));
            }
        }
    }
    Ok(())
}

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

    validate_intent(ctl, id)?;

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
        // A `list` is the browsable, rich-row sibling of `select`. It is
        // feed-backed via a declared `list:` (RFC §17.3) OR carries an
        // inline `options:` array for static collections; at least one
        // must be present. Picking a row emits the selection `action`.
        "list" => {
            if !has_action {
                return Err(format!(
                    "control `{id}` (list): requires a selection `action`"
                ));
            }
            let has_options = ctl.get("options").map(|v| v.is_array()).unwrap_or(false);
            match names_list {
                Some(l) if !list_resolves => {
                    return Err(format!(
                        "control `{id}` (list): `list: {l}` is not declared under the shell's `lists:`"
                    ))
                }
                None if !has_options => {
                    return Err(format!(
                        "control `{id}` (list): requires a `list` (declared `lists:` entry) or an inline `options` array"
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
