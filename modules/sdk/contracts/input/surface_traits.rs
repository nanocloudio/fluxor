// Contract: input::surface_traits — runtime environment-plane descriptor.
//
// Layer: contracts/input (public, stable).
//
// The host platform adapter (the "authority") publishes a snapshot of
// the *surface* the graph is presenting on: viewport geometry, derived
// orientation + size class, the input modalities currently present, and
// the audio output config. A module that wants to adapt to its
// environment wires an input port to this surface and reacts to each
// record; a module that ignores it keeps static-config behaviour, so the
// contract is purely additive.
//
// Producers (all greenfield as of this contract landing): the browser
// authority (wasm_browser_surface_traits, driven by resize /
// visualViewport / matchMedia('(pointer: coarse)') / getGamepads /
// AudioContext), the Linux display authority (linux_display geometry +
// evdev modality enumeration), and bare-metal panels (static board
// manifest declaration). Consumers read the same wire shape regardless
// of which authority is on the other end — the capability-surface model.
//
// The wire-record *shape* is modelled on input::gamepad's connection
// message but shares no code; this surface has its own producer,
// transport, and consumer.
//
// Frame format (fixed 24 bytes, 4-byte aligned for cheap channel reads):
//   [msg_type:       u8]      MSG_TRAITS
//   [orientation:    u8]      ORIENT_*
//   [size_class_w:   u8]      SIZE_*
//   [size_class_h:   u8]      SIZE_*
//   [viewport_w_px:  u16 LE]  usable content width
//   [viewport_h_px:  u16 LE]  usable content height
//   [modalities:     u16 LE]  MODALITY_* bitmask
//   [gamepad_count:  u8]      attached gamepads, 0..MAX
//   [audio_channels: u8]      0 none, 1 mono, 2 stereo, 6 = 5.1
//   [audio_rate_hz:  u32 LE]  output sample rate, 0 if no audio sink
//   [epoch:          u32 LE]  monotonic; bumps once per coalesced change
//   [authority:      u8]      AUTHORITY_*
//   [display_count:  u8]      attached displays; 0 = headless (audio-only,
//                             e.g. an rp2350 + I2S speaker). When 0, the
//                             geometry/orientation/size-class fields are
//                             meaningless and a consumer drives UI by audio +
//                             physical controls only.
//   [pad:            u8 * 2]
//
// See `.context/rfc_surface_traits.md`.

/// Total record size in bytes. Fixed-width so consumers can stride
/// channel reads without parsing.
pub const EVENT_SIZE: usize = 24;

// ── Downstream: authority → consumer ─────────────────────────────────

/// Surface-state snapshot. The authority emits one record at startup
/// (so a freshly-wired consumer has a baseline) and one per coalesced
/// change thereafter, each with a fresh `epoch`.
pub const MSG_TRAITS: u8 = 0x01;

// ── Orientation (record.orientation) ─────────────────────────────────

pub const ORIENT_PORTRAIT: u8 = 0;
pub const ORIENT_LANDSCAPE: u8 = 1;

// ── Size class (record.size_class_w / size_class_h) ──────────────────
// Coarse buckets — the "trait" an adaptive consumer keys on, so layout
// does not depend on exact pixels. Derived from viewport geometry with
// hysteresis (see `size_class_for`).

pub const SIZE_COMPACT: u8 = 0;
pub const SIZE_REGULAR: u8 = 1;
pub const SIZE_EXPANDED: u8 = 2;

// ── Modality bitfield (record.modalities) ────────────────────────────
// Which input modalities are currently present on the surface. The
// authority sets a bit when the modality is usable; it clears on
// detach (hot-plug). Bits 6 (ir_remote) and 7 (voice) are reserved.

pub const MODALITY_KEY: u16 = 0x0001;
pub const MODALITY_POINTER_FINE: u16 = 0x0002; // mouse / stylus
pub const MODALITY_POINTER_COARSE: u16 = 0x0004; // coarse pointer
pub const MODALITY_TOUCH: u16 = 0x0008;
pub const MODALITY_GAMEPAD: u16 = 0x0010;
pub const MODALITY_PHYSICAL_BUTTONS: u16 = 0x0020;

// ── Authority provenance (record.authority) ──────────────────────────

pub const AUTHORITY_BROWSER: u8 = 0;
pub const AUTHORITY_LINUX: u8 = 1;
pub const AUTHORITY_PANEL: u8 = 2;

// ── Display presence (record.display_count) ──────────────────────────
// 0 = headless (no display at all — audio-only device like an rp2350 + I2S
// speaker; geometry/orientation/size-class are meaningless). 1 = single
// display. 2+ = multihead (per-head resolution not reported).
pub const DISPLAY_HEADLESS: u8 = 0;

// ── Size-class thresholds (px) with hysteresis ───────────────────────
// Single source of truth for every authority. The browser shim mirrors
// these constants in JS; the Linux / panel authorities call
// `size_class_for` directly. Hysteresis prevents a viewport hovering on
// a breakpoint from thrashing the class (and thus the epoch) every
// frame: a wider band must be crossed to *enter* the larger class than
// to *leave* it. The 900px expanded entry mirrors the existing
// `computeOrientation` desktop breakpoint in browser_overlay_runtime.js.

pub const COMPACT_ENTER_PX: u16 = 580; // shrink below this → compact
pub const REGULAR_ENTER_PX: u16 = 600; // grow to/above this → regular
pub const EXPANDED_LEAVE_PX: u16 = 880; // shrink below this → regular
pub const EXPANDED_ENTER_PX: u16 = 900; // grow to/above this → expanded

/// Resolve the size class for `px`, given the previously published
/// class `prev` (one of `SIZE_*`). Pure + deterministic, with the
/// hysteresis bands above. Pass `SIZE_REGULAR` as `prev` for a
/// cold start.
pub fn size_class_for(px: u16, prev: u8) -> u8 {
    match prev {
        SIZE_EXPANDED => {
            if px < EXPANDED_LEAVE_PX {
                if px < COMPACT_ENTER_PX {
                    SIZE_COMPACT
                } else {
                    SIZE_REGULAR
                }
            } else {
                SIZE_EXPANDED
            }
        }
        SIZE_COMPACT => {
            if px >= EXPANDED_ENTER_PX {
                SIZE_EXPANDED
            } else if px >= REGULAR_ENTER_PX {
                SIZE_REGULAR
            } else {
                SIZE_COMPACT
            }
        }
        // SIZE_REGULAR and any out-of-range prior value.
        _ => {
            if px >= EXPANDED_ENTER_PX {
                SIZE_EXPANDED
            } else if px < COMPACT_ENTER_PX {
                SIZE_COMPACT
            } else {
                SIZE_REGULAR
            }
        }
    }
}

/// Derive orientation from viewport geometry. Square counts as
/// landscape (matches the `w >= h` convention in the browser overlay).
pub fn orientation_for(w: u16, h: u16) -> u8 {
    if w >= h {
        ORIENT_LANDSCAPE
    } else {
        ORIENT_PORTRAIT
    }
}
