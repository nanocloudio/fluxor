//! Placement resolver — the pure, deterministic core
//! (`.context/rfc_adaptive_presentation.md` §9/§10).
//!
//! `resolve(intents, surface)` maps each control's declared *intent* onto a
//! concrete *disposition* (chrome / content / bound / hidden) given the runtime
//! `SurfaceTraits`. It is a pure function — same inputs, same output — so it is
//! unit-tested here host-side with no browser and no device (RFC acceptance
//! criterion #4). This is the canonical reference implementation; the on-device
//! `presentation.resolver` PIC module mirrors this algorithm (with fixed-size
//! arrays instead of `Vec`), and the `resolve→hidden` build lint runs
//! this same function against a config's declared surfaces.
//!
//! Algorithm (RFC §10.2), strictly one-directional (surface in, layout out):
//!   1. **size filter** — a control below its `min_size_class` can't render.
//!   2. **physical binding** — a control with `bind_physical` claims a free
//!      hardware button (when the surface has physical buttons). The action is
//!      then reachable with zero drawn pixels.
//!   3. **suppression** — `suppress_if: modality.X` drops the control when X is
//!      present (e.g. hide the virtual pad when a real gamepad is attached).
//!   4. **plane selection** — walk `plane_affinity` for the first plane the
//!      surface supports; a chrome-less surface auto-extends a `[chrome]`-only
//!      control to `content` so it degrades to *drawn*, not *dropped*.
//!   5. **overflow** — controls are placed highest-priority-first; when a
//!      plane's capacity is exhausted the rest overflow to the other eligible
//!      plane, then drop **optional → standard**. An `essential` control is
//!      never `Hidden`: if it can't be placed or bound it is flagged
//!      `unplaceable` (a graph misconfiguration the lint reports).

use std::collections::BTreeMap;

// Modality bits — mirror input::surface_traits MODALITY_*.
pub const MODALITY_KEY: u16 = 0x0001;
pub const MODALITY_POINTER_FINE: u16 = 0x0002;
pub const MODALITY_POINTER_COARSE: u16 = 0x0004;
pub const MODALITY_TOUCH: u16 = 0x0008;
pub const MODALITY_GAMEPAD: u16 = 0x0010;
pub const MODALITY_PHYSICAL_BUTTONS: u16 = 0x0020;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Plane {
    Chrome,
    Content,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Disposition {
    Chrome,
    Content,
    Bound,
    Hidden,
}

/// Drop order: lower variants drop first under overflow. `Ord` is derived so
/// `Essential > Standard > Optional`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Priority {
    Optional,
    Standard,
    Essential,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum SizeClass {
    Compact,
    Regular,
    Expanded,
}

/// One control's declared intent (the resolver-relevant subset of a
/// `presentation.shell` control + its §9 metadata).
#[derive(Clone, Debug)]
pub struct ControlIntent {
    pub id: String,
    /// Ordered plane preference. Default `[Chrome]`.
    pub affinity: Vec<Plane>,
    pub priority: Priority,
    pub min_size_class: SizeClass,
    /// A named physical control to bind to when the surface has buttons.
    pub bind_physical: Option<String>,
    /// Drop the control when this modality bit is present.
    pub suppress_if: Option<u16>,
}

impl ControlIntent {
    /// A control with defaults: chrome-only, standard, no min size.
    pub fn new(id: &str) -> Self {
        ControlIntent {
            id: id.to_string(),
            affinity: vec![Plane::Chrome],
            priority: Priority::Standard,
            min_size_class: SizeClass::Compact,
            bind_physical: None,
            suppress_if: None,
        }
    }
}

/// The runtime surface the resolver places onto (the resolver-relevant subset of
/// `SurfaceTraits` + host policy). One-directional: never derived from
/// app-reported content geometry.
#[derive(Clone, Debug)]
pub struct Surface {
    pub size_class_w: SizeClass,
    pub modalities: u16,
    pub display_count: u8,
    /// Does the host provide a chrome region around the content? (Browser: yes;
    /// a panel where the app owns the whole framebuffer: no.)
    pub chrome_region: bool,
    /// Free physical buttons available to bind.
    pub physical_buttons: u8,
    /// Max controls a plane renders before overflow (host/profile policy).
    pub chrome_capacity: usize,
    pub content_capacity: usize,
}

impl Surface {
    fn has(&self, modality: u16) -> bool {
        self.modalities & modality != 0
    }
    fn chrome_eligible(&self) -> bool {
        self.chrome_region && self.display_count > 0
    }
    fn content_eligible(&self) -> bool {
        self.display_count > 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayoutEntry {
    pub id: String,
    pub disposition: Disposition,
    pub plane: Option<Plane>,
    pub physical_binding: Option<String>,
    /// True only for an `essential` control that could not be placed or bound on
    /// this surface — a misconfiguration the build lint reports.
    pub unplaceable: bool,
}

#[derive(Clone, Debug, Default)]
pub struct LayoutResolution {
    pub entries: Vec<LayoutEntry>,
    /// Physical-button → action(control id) map for `Bound` controls (the
    /// legend an audio-less / chrome-less surface still needs, RFC §14).
    pub legend: Vec<(String, String)>,
}

impl LayoutResolution {
    pub fn get(&self, id: &str) -> Option<&LayoutEntry> {
        self.entries.iter().find(|e| e.id == id)
    }
    pub fn disposition(&self, id: &str) -> Option<Disposition> {
        self.get(id).map(|e| e.disposition)
    }
}

/// Resolve a layout. Deterministic; preserves declaration order in `entries`.
pub fn resolve(intents: &[ControlIntent], surface: &Surface) -> LayoutResolution {
    let mut out = LayoutResolution::default();
    // Disposition keyed by id; assembled in declaration order at the end.
    let mut disp: BTreeMap<usize, LayoutEntry> = BTreeMap::new();
    let mut free_buttons = surface.physical_buttons;
    let mut chrome_used = 0usize;
    let mut content_used = 0usize;

    // ── Steps 1–3: per-control filters that don't compete for plane slots. ──
    // Indices that still need a plane after filtering.
    let mut need_plane: Vec<usize> = Vec::new();
    for (i, c) in intents.iter().enumerate() {
        let entry = |d: Disposition, plane, bind, unplaceable| LayoutEntry {
            id: c.id.clone(),
            disposition: d,
            plane,
            physical_binding: bind,
            unplaceable,
        };

        // 1. Below the surface's size class → can't render. essential still
        //    falls through to binding/overflow below; others hide here.
        if surface.size_class_w < c.min_size_class && c.priority != Priority::Essential {
            disp.insert(i, entry(Disposition::Hidden, None, None, false));
            continue;
        }
        // 2. Physical binding wins when a button is free.
        if let Some(btn) = &c.bind_physical {
            if surface.has(MODALITY_PHYSICAL_BUTTONS) && free_buttons > 0 {
                free_buttons -= 1;
                out.legend.push((btn.clone(), c.id.clone()));
                disp.insert(i, entry(Disposition::Bound, None, Some(btn.clone()), false));
                continue;
            }
        }
        // 3. Suppressed by a present modality.
        if let Some(m) = c.suppress_if {
            if surface.has(m) {
                disp.insert(i, entry(Disposition::Hidden, None, None, false));
                continue;
            }
        }
        need_plane.push(i);
    }

    // ── Steps 4–5: plane assignment, highest-priority-first so overflow drops
    //    low-priority controls. Stable by index within a priority. ──
    need_plane.sort_by(|&a, &b| {
        intents[b]
            .priority
            .cmp(&intents[a].priority)
            .then(a.cmp(&b))
    });

    for &i in &need_plane {
        let c = &intents[i];
        // Eligible planes in the control's preference order, auto-extending a
        // chrome-only control to content on a chrome-less-but-displayed surface.
        let mut prefs: Vec<Plane> = c
            .affinity
            .iter()
            .copied()
            .filter(|p| match p {
                Plane::Chrome => surface.chrome_eligible(),
                Plane::Content => surface.content_eligible(),
            })
            .collect();
        if prefs.is_empty()
            && c.affinity == [Plane::Chrome]
            && !surface.chrome_eligible()
            && surface.content_eligible()
        {
            prefs.push(Plane::Content); // auto-extend: drawn, not dropped
        }

        // Place into the first preferred plane that still has capacity.
        let mut placed: Option<Disposition> = None;
        for p in &prefs {
            match p {
                Plane::Chrome if chrome_used < surface.chrome_capacity => {
                    chrome_used += 1;
                    placed = Some(Disposition::Chrome);
                    break;
                }
                Plane::Content if content_used < surface.content_capacity => {
                    content_used += 1;
                    placed = Some(Disposition::Content);
                    break;
                }
                _ => {}
            }
        }

        let plane = placed.map(|d| match d {
            Disposition::Chrome => Plane::Chrome,
            _ => Plane::Content,
        });
        match placed {
            Some(d) => {
                disp.insert(
                    i,
                    LayoutEntry {
                        id: c.id.clone(),
                        disposition: d,
                        plane,
                        physical_binding: None,
                        unplaceable: false,
                    },
                );
            }
            None => {
                // No eligible plane. An explicit `bind_physical` would already
                // have claimed a button in step 2, so reaching here means the
                // control has no binding to fall back to. An `essential` control
                // is flagged `unplaceable` (a misconfiguration the lint reports:
                // declare a `bind_physical` for it on this surface) rather than
                // silently inventing an arbitrary binding; others simply hide.
                disp.insert(
                    i,
                    LayoutEntry {
                        id: c.id.clone(),
                        disposition: Disposition::Hidden,
                        plane: None,
                        physical_binding: None,
                        unplaceable: c.priority == Priority::Essential,
                    },
                );
            }
        }
    }

    out.entries = (0..intents.len()).filter_map(|i| disp.remove(&i)).collect();
    out
}

// ── Wire serialization (presentation.layout) ─────────────────────────
//
// The resolver's output crosses a channel to its consumers (the chrome
// adapter + the content module). Fixed, bounded, little-endian; control
// identity is the entry's *position* (declaration order, which `resolve`
// preserves), so the consumer matches entries to its own control list by
// index. The on-device `presentation.resolver` PIC module mirrors this exact
// byte layout (drift-guarded); these consts are the single source of truth.
//
//   Header (8 bytes):
//     [0]     msg_type      MSG_LAYOUT
//     [1]     entry_count   u8
//     [2]     legend_count  u8
//     [3]     pad
//     [4..8]  derived_epoch u32 LE   (the SurfaceTraits epoch resolved)
//   Entries (entry_count × 4 bytes), in declaration order:
//     [0]     disposition   DISP_*  (chrome/content/bound/hidden)
//     [1]     plane         PLANE_* (chrome/content/none)
//     [2]     flags         bit0 = unplaceable
//     [3]     legend_ref    index into the legend table, or 0xFF
//   Legend table (legend_count entries), each:
//     [0]            name_len u8
//     [name_len]     button name (UTF-8)

pub const MSG_LAYOUT: u8 = 0x01;
pub const LAYOUT_HEADER_LEN: usize = 8;

pub const DISP_CHROME: u8 = 0;
pub const DISP_CONTENT: u8 = 1;
pub const DISP_BOUND: u8 = 2;
pub const DISP_HIDDEN: u8 = 3;

pub const PLANE_CHROME: u8 = 0;
pub const PLANE_CONTENT: u8 = 1;
pub const PLANE_NONE: u8 = 0xFF;

pub const FLAG_UNPLACEABLE: u8 = 0x01;
pub const LEGEND_NONE: u8 = 0xFF;

fn disp_code(d: Disposition) -> u8 {
    match d {
        Disposition::Chrome => DISP_CHROME,
        Disposition::Content => DISP_CONTENT,
        Disposition::Bound => DISP_BOUND,
        Disposition::Hidden => DISP_HIDDEN,
    }
}

fn plane_code(p: Option<Plane>) -> u8 {
    match p {
        Some(Plane::Chrome) => PLANE_CHROME,
        Some(Plane::Content) => PLANE_CONTENT,
        None => PLANE_NONE,
    }
}

/// Encode a resolution to the `presentation.layout` wire record. `epoch` is the
/// `SurfaceTraits.epoch` this layout was resolved from (stamped so a consumer
/// can detect a stale layout — RFC §12).
pub fn encode(res: &LayoutResolution, epoch: u32) -> Vec<u8> {
    // The wire format counts entries, legend entries, and name lengths in single
    // bytes (`LEGEND_NONE` = 0xFF also reserves the top legend index). Clamp to
    // those ceilings and serialize EXACTLY what the (clamped) header advertises,
    // so the body can never desync — a u8 wrap of the count would otherwise make
    // a decoder read an empty/garbled layout. These caps are far above any real
    // shell's control count; truncation here means a malformed config, not a
    // runtime case.
    const MAX_ENTRIES: usize = u8::MAX as usize; // 255
    const MAX_LEGEND: usize = LEGEND_NONE as usize; // 255 distinct legend refs (0..=254)
    const MAX_NAME: usize = u8::MAX as usize; // 255

    let entries = &res.entries[..res.entries.len().min(MAX_ENTRIES)];

    // Button name → legend index (dedup; a button drives one control).
    let mut legend_names: Vec<&str> = Vec::new();

    let mut entry_bytes = Vec::with_capacity(entries.len() * 4);
    for e in entries {
        let legend_ref = match (&e.disposition, &e.physical_binding) {
            (Disposition::Bound, Some(name)) => {
                match legend_names.iter().position(|n| *n == name.as_str()) {
                    Some(i) => i as u8,
                    // New legend name: assign an index only while one is free
                    // (0..MAX_LEGEND). Beyond that, fall back to "no legend"
                    // rather than alias index 0xFF (= LEGEND_NONE).
                    None if legend_names.len() < MAX_LEGEND => {
                        legend_names.push(name.as_str());
                        (legend_names.len() - 1) as u8
                    }
                    None => LEGEND_NONE,
                }
            }
            _ => LEGEND_NONE,
        };
        let flags = if e.unplaceable { FLAG_UNPLACEABLE } else { 0 };
        entry_bytes.push(disp_code(e.disposition));
        entry_bytes.push(plane_code(e.plane));
        entry_bytes.push(flags);
        entry_bytes.push(legend_ref);
    }

    let mut buf = Vec::with_capacity(LAYOUT_HEADER_LEN + entry_bytes.len());
    buf.push(MSG_LAYOUT);
    buf.push(entries.len() as u8); // ≤ MAX_ENTRIES by construction
    buf.push(legend_names.len() as u8); // ≤ MAX_LEGEND by construction
    buf.push(0);
    buf.extend_from_slice(&epoch.to_le_bytes());
    buf.extend_from_slice(&entry_bytes);
    for name in &legend_names {
        let nb = name.as_bytes();
        let nb = &nb[..nb.len().min(MAX_NAME)];
        buf.push(nb.len() as u8);
        buf.extend_from_slice(nb);
    }
    buf
}

/// A decoded entry (identity is the position; the wire carries no id).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireEntry {
    pub disposition: Disposition,
    pub plane: Option<Plane>,
    pub unplaceable: bool,
    pub binding: Option<String>,
}

/// Decoded `presentation.layout` record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireLayout {
    pub epoch: u32,
    pub entries: Vec<WireEntry>,
}

/// Decode a `presentation.layout` record. Returns `None` on a malformed /
/// truncated buffer (a consumer drops it rather than trusting partial data).
pub fn decode(buf: &[u8]) -> Option<WireLayout> {
    if buf.len() < LAYOUT_HEADER_LEN || buf[0] != MSG_LAYOUT {
        return None;
    }
    let entry_count = buf[1] as usize;
    let legend_count = buf[2] as usize;
    let epoch = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);

    let entries_start = LAYOUT_HEADER_LEN;
    let entries_end = entries_start.checked_add(entry_count.checked_mul(4)?)?;
    if buf.len() < entries_end {
        return None;
    }

    // Decode the legend table first so entries can resolve their refs.
    let mut legend: Vec<String> = Vec::with_capacity(legend_count);
    let mut off = entries_end;
    for _ in 0..legend_count {
        let name_len = *buf.get(off)? as usize;
        off += 1;
        let name = buf.get(off..off.checked_add(name_len)?)?;
        legend.push(core::str::from_utf8(name).ok()?.to_string());
        off += name_len;
    }

    let mut entries = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let b = &buf[entries_start + i * 4..entries_start + i * 4 + 4];
        let disposition = match b[0] {
            DISP_CHROME => Disposition::Chrome,
            DISP_CONTENT => Disposition::Content,
            DISP_BOUND => Disposition::Bound,
            DISP_HIDDEN => Disposition::Hidden,
            _ => return None,
        };
        let plane = match b[1] {
            PLANE_CHROME => Some(Plane::Chrome),
            PLANE_CONTENT => Some(Plane::Content),
            PLANE_NONE => None,
            _ => return None,
        };
        let unplaceable = b[2] & FLAG_UNPLACEABLE != 0;
        let binding = if b[3] == LEGEND_NONE {
            None
        } else {
            Some(legend.get(b[3] as usize)?.clone())
        };
        entries.push(WireEntry {
            disposition,
            plane,
            unplaceable,
            binding,
        });
    }
    Some(WireLayout { epoch, entries })
}

// ── Build-time lint (resolve→hidden, rfc_adaptive_presentation.md §9) ──
//
// Runs the resolver against a config's declared surface and reports any
// `essential` control that cannot be surfaced there (`unplaceable`). This is
// the build-time guarantee that an essential action is always reachable — the
// thing that would otherwise only surface as a dead control at runtime. Opt-in
// via `fluxor lint presentation`; configs without a `presentation.shell` (or
// with no controls) are skipped.

use serde_json::Value;

fn modality_bit(s: &str) -> Option<u16> {
    match s.strip_prefix("modality.")? {
        "key" => Some(MODALITY_KEY),
        "pointer_fine" => Some(MODALITY_POINTER_FINE),
        "pointer_coarse" => Some(MODALITY_POINTER_COARSE),
        "touch" => Some(MODALITY_TOUCH),
        "gamepad" => Some(MODALITY_GAMEPAD),
        "physical_buttons" => Some(MODALITY_PHYSICAL_BUTTONS),
        _ => None,
    }
}

/// Map a `presentation.shell` control object to a `ControlIntent` (defaults
/// match the validator: chrome-only / standard / compact). Returns `None` for a
/// control without an `id` (the shell validator already rejects that).
fn intent_from_control(ctl: &Value) -> Option<ControlIntent> {
    let id = ctl.get("id")?.as_str()?.to_string();
    let affinity: Vec<Plane> = ctl
        .get("plane_affinity")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|p| match p.as_str() {
                    Some("chrome") => Some(Plane::Chrome),
                    Some("content") => Some(Plane::Content),
                    _ => None,
                })
                .collect()
        })
        .filter(|a: &Vec<Plane>| !a.is_empty())
        .unwrap_or_else(|| vec![Plane::Chrome]);
    let priority = match ctl.get("priority").and_then(|v| v.as_str()) {
        Some("essential") => Priority::Essential,
        Some("optional") => Priority::Optional,
        _ => Priority::Standard,
    };
    let min_size_class = match ctl.get("min_size_class").and_then(|v| v.as_str()) {
        Some("regular") => SizeClass::Regular,
        Some("expanded") => SizeClass::Expanded,
        _ => SizeClass::Compact,
    };
    let bind_physical = ctl
        .get("bind_physical")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let suppress_if = ctl
        .get("suppress_if")
        .and_then(|v| v.as_str())
        .and_then(modality_bit);
    Some(ControlIntent {
        id,
        affinity,
        priority,
        min_size_class,
        bind_physical,
        suppress_if,
    })
}

/// Find the named surface-trait authority module (by `type`, falling back to
/// `name`) in a config's `modules` array.
fn find_authority<'a>(config: &'a Value, ty: &str) -> Option<&'a Value> {
    config
        .get("modules")
        .and_then(|m| m.as_array())?
        .iter()
        .find(|m| {
            let t = m
                .get("type")
                .and_then(|t| t.as_str())
                .or_else(|| m.get("name").and_then(|n| n.as_str()));
            t == Some(ty)
        })
}

/// The physical-button names a `panel_surface_traits` authority declares (lower-
/// cased), if it lists them via a `buttons` array. `Some([])` is never returned;
/// `None` means the panel declared no names (so the lint can't validate them).
fn declared_buttons(panel: &Value) -> Option<Vec<String>> {
    let names: Vec<String> = panel
        .get("buttons")?
        .as_array()?
        .iter()
        .filter_map(|b| b.as_str().map(|s| s.to_ascii_lowercase()))
        .collect();
    (!names.is_empty()).then_some(names)
}

/// Derive the surface a config presents on. A `panel_surface_traits` authority
/// names a bare-metal panel (including the screenless `display_count = 0` case);
/// a `linux_surface_traits` authority names a Linux host — which, like the
/// panel, owns its framebuffer and has NO host chrome region (the chrome overlay
/// is a browser-only renderer), so chrome-affinity controls auto-extend to
/// content there. Absent either authority, assume a browser/host surface with
/// chrome. The non-browser cases are checked at the *compact* size class — the
/// smallest plausible viewport — so a control needing more room is caught.
pub fn surface_from_config(config: &Value) -> Surface {
    if let Some(m) = find_authority(config, "panel_surface_traits") {
        let display_count = m.get("display_count").and_then(|v| v.as_u64()).unwrap_or(1) as u8;
        let modalities = m
            .get("modalities")
            .and_then(|v| v.as_u64())
            .unwrap_or(MODALITY_PHYSICAL_BUTTONS as u64) as u16;
        // Free physical buttons: prefer the panel's own declaration (a `buttons`
        // name list, else a `physical_button_count`); only when the panel
        // declares neither do we fall back to "unbounded" (can't validate
        // undeclared hardware — declare `buttons` for strict count/name checks).
        let has_btn_modality = modalities & MODALITY_PHYSICAL_BUTTONS != 0;
        let physical_buttons = if !has_btn_modality {
            0
        } else if let Some(names) = declared_buttons(m) {
            names.len().min(u8::MAX as usize) as u8
        } else if let Some(n) = m.get("physical_button_count").and_then(|v| v.as_u64()) {
            n.min(u8::MAX as u64) as u8
        } else {
            u8::MAX
        };
        return Surface {
            size_class_w: SizeClass::Compact,
            modalities,
            display_count,
            // A bare-metal app owns the whole framebuffer — no host chrome.
            chrome_region: false,
            physical_buttons,
            chrome_capacity: 0,
            content_capacity: if display_count > 0 { 64 } else { 0 },
        };
    }
    if let Some(m) = find_authority(config, "linux_surface_traits") {
        let display_count = m.get("display_count").and_then(|v| v.as_u64()).unwrap_or(1) as u8;
        return Surface {
            size_class_w: SizeClass::Compact,
            // Linux host input paths (keyboard/pointer); scanned at runtime, but
            // for the lint assume the baseline present set.
            modalities: MODALITY_KEY | MODALITY_POINTER_FINE,
            display_count,
            // No host chrome overlay on Linux — the app owns its framebuffer.
            chrome_region: false,
            physical_buttons: 0,
            chrome_capacity: 0,
            content_capacity: if display_count > 0 { 64 } else { 0 },
        };
    }
    Surface {
        size_class_w: SizeClass::Compact,
        modalities: MODALITY_KEY | MODALITY_POINTER_FINE,
        display_count: 1,
        chrome_region: true,
        physical_buttons: 0,
        chrome_capacity: 64,
        content_capacity: 64,
    }
}

/// Lint a config's presentation shell against its surface. Returns one message
/// per `essential` control that cannot be surfaced. Empty = clean (including
/// configs with no shell / no controls).
pub fn lint_config(config: &Value) -> Vec<String> {
    let controls = match config
        .pointer("/presentation/shell/controls")
        .and_then(|c| c.as_array())
    {
        Some(c) if !c.is_empty() => c,
        _ => return Vec::new(),
    };
    let intents: Vec<ControlIntent> = controls.iter().filter_map(intent_from_control).collect();
    let surface = surface_from_config(config);
    let res = resolve(&intents, &surface);
    let mut msgs: Vec<String> = res
        .entries
        .iter()
        .filter(|e| e.unplaceable)
        .map(|e| {
            format!(
                "control `{}` is `essential` but cannot be surfaced on this config's target \
                 (no chrome/content plane available, and no `bind_physical`) — declare a \
                 `bind_physical`, lower its `priority`, or relax `min_size_class`",
                e.id
            )
        })
        .collect();

    // Physical-binding integrity. These are independent of plane placement: a
    // double-bound button or a binding to a non-existent button is a config
    // error even when the control would also render in a plane.
    let panel = find_authority(config, "panel_surface_traits");
    let names = panel.and_then(declared_buttons);
    let mut seen: Vec<String> = Vec::new();
    for c in &intents {
        let Some(btn) = &c.bind_physical else {
            continue;
        };
        let key = btn.to_ascii_lowercase();
        // Duplicate: two controls claim the same physical button.
        if seen.contains(&key) {
            msgs.push(format!(
                "physical button `{btn}` is bound by more than one control \
                 (`bind_physical` must be unique per button) — control `{}`",
                c.id
            ));
        } else {
            seen.push(key.clone());
        }
        // Unknown name: only checkable when the panel declares its `buttons`.
        if let Some(set) = &names {
            if !set.contains(&key) {
                msgs.push(format!(
                    "control `{}` binds physical button `{btn}`, which the panel does not \
                     declare in its `buttons` list — fix the name or add it to the panel",
                    c.id
                ));
            }
        }
    }
    msgs
}
