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
// Producers: the browser authority (wasm_browser_surface_traits, driven by
// resize / visualViewport / matchMedia / getGamepads / AudioContext), the
// Linux display authority (linux_display geometry + evdev modality
// enumeration), and bare-metal panels (static board manifest declaration).
// Consumers read the same wire shape regardless of which authority is on
// the other end — the capability-surface model.
//
// Record (fixed 24 bytes, little-endian, 4-byte aligned for cheap channel
// reads):
//
//   [0]       msg_type        MSG_TRAITS
//   [1]       orientation     ORIENT_*
//   [2]       size_class_w    SIZE_*
//   [3]       size_class_h    SIZE_*
//   [4..6]    viewport_w_px   u16  usable content width, logical pixels
//   [6..8]    viewport_h_px   u16  usable content height
//   [8..10]   modalities      u16  MODALITY_* bitmask
//   [10]      gamepad_count   attached gamepads
//   [11]      audio_channels  0 none, 1 mono, 2 stereo, 6 = 5.1
//   [12..16]  audio_rate_hz   u32  output sample rate, 0 if no audio sink
//   [16..20]  epoch           u32  monotonic; bumps once per coalesced change
//   [20]      authority       AUTHORITY_*
//   [21]      display_count   attached displays; 0 = headless (audio-only).
//                             When 0, the geometry, orientation and
//                             size-class fields are meaningless and a
//                             consumer drives UI by audio and physical
//                             controls only.
//   [22]      dpr_eighths     surface pixels per logical pixel, in eighths:
//                             8 = 1x, 12 = 1.5x, 18 = 2.25x; 0 = unreported
//   [23]      0               must be zero
//
// TWO PIXEL SPACES. Logical pixels are `viewport_w_px` / `viewport_h_px`
// (CSS pixels in a browser); size classes and layout key on these. Surface
// pixels are the pixels of the raster presented on the surface; pointer
// positions and accessibility bounds are in them. `dpr_eighths` tells a
// producer how many surface pixels to render per logical pixel for its
// raster to be presented 1:1: render at `viewport × dpr_eighths / 8`. A
// change of `dpr_eighths` bumps `epoch` under the same coalescing as a
// resize. A consumer reading 0 keeps its configured ratio.

/// Total record size in bytes. Fixed-width so consumers can stride
/// channel reads without parsing.
pub const EVENT_SIZE: usize = 24;

/// Byte offsets of the record's fields.
pub const OFF_MSG_TYPE: usize = 0;
pub const OFF_ORIENTATION: usize = 1;
pub const OFF_SIZE_CLASS_W: usize = 2;
pub const OFF_SIZE_CLASS_H: usize = 3;
pub const OFF_VIEWPORT_W_PX: usize = 4;
pub const OFF_VIEWPORT_H_PX: usize = 6;
pub const OFF_MODALITIES: usize = 8;
pub const OFF_GAMEPAD_COUNT: usize = 10;
pub const OFF_AUDIO_CHANNELS: usize = 11;
pub const OFF_AUDIO_RATE_HZ: usize = 12;
pub const OFF_EPOCH: usize = 16;
pub const OFF_AUTHORITY: usize = 20;
pub const OFF_DISPLAY_COUNT: usize = 21;
pub const OFF_DPR_EIGHTHS: usize = 22;
pub const OFF_RESERVED: usize = 23;

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

// ── Device pixel ratio (record.dpr_eighths) ──────────────────────────

/// The authority reports no ratio.
pub const DPR_UNREPORTED: u8 = 0;
/// One surface pixel per logical pixel.
pub const DPR_1X: u8 = 8;

/// The `dpr_eighths` value for a ratio given in thousandths (1.5x is
/// 1500): the nearest eighth, halves up, clamped to `1..=255`. A reported
/// ratio is never 0, which means unreported.
pub const fn dpr_eighths_for(ratio_milli: u32) -> u8 {
    let eighths = (ratio_milli as u64 * 8 + 500) / 1000;
    if eighths < 1 {
        1
    } else if eighths > 255 {
        255
    } else {
        eighths as u8
    }
}

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

/// One surface-traits record, by field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Traits {
    pub orientation: u8,
    pub size_class_w: u8,
    pub size_class_h: u8,
    pub viewport_w_px: u16,
    pub viewport_h_px: u16,
    pub modalities: u16,
    pub gamepad_count: u8,
    pub audio_channels: u8,
    pub audio_rate_hz: u32,
    pub epoch: u32,
    pub authority: u8,
    pub display_count: u8,
    /// Surface pixels per logical pixel in eighths; `DPR_UNREPORTED` when
    /// the authority reports none.
    pub dpr_eighths: u8,
}

/// Read a record. `None` for a message type other than `MSG_TRAITS` or a
/// non-zero reserved byte.
pub const fn decode(b: &[u8; EVENT_SIZE]) -> Option<Traits> {
    if b[OFF_MSG_TYPE] != MSG_TRAITS || b[OFF_RESERVED] != 0 {
        return None;
    }
    Some(Traits {
        orientation: b[OFF_ORIENTATION],
        size_class_w: b[OFF_SIZE_CLASS_W],
        size_class_h: b[OFF_SIZE_CLASS_H],
        viewport_w_px: u16::from_le_bytes([b[OFF_VIEWPORT_W_PX], b[OFF_VIEWPORT_W_PX + 1]]),
        viewport_h_px: u16::from_le_bytes([b[OFF_VIEWPORT_H_PX], b[OFF_VIEWPORT_H_PX + 1]]),
        modalities: u16::from_le_bytes([b[OFF_MODALITIES], b[OFF_MODALITIES + 1]]),
        gamepad_count: b[OFF_GAMEPAD_COUNT],
        audio_channels: b[OFF_AUDIO_CHANNELS],
        audio_rate_hz: u32::from_le_bytes([
            b[OFF_AUDIO_RATE_HZ],
            b[OFF_AUDIO_RATE_HZ + 1],
            b[OFF_AUDIO_RATE_HZ + 2],
            b[OFF_AUDIO_RATE_HZ + 3],
        ]),
        epoch: u32::from_le_bytes([
            b[OFF_EPOCH],
            b[OFF_EPOCH + 1],
            b[OFF_EPOCH + 2],
            b[OFF_EPOCH + 3],
        ]),
        authority: b[OFF_AUTHORITY],
        display_count: b[OFF_DISPLAY_COUNT],
        dpr_eighths: b[OFF_DPR_EIGHTHS],
    })
}

/// The record for `traits`.
pub const fn encode(traits: &Traits) -> [u8; EVENT_SIZE] {
    let vw = traits.viewport_w_px.to_le_bytes();
    let vh = traits.viewport_h_px.to_le_bytes();
    let m = traits.modalities.to_le_bytes();
    let r = traits.audio_rate_hz.to_le_bytes();
    let e = traits.epoch.to_le_bytes();
    [
        MSG_TRAITS,
        traits.orientation,
        traits.size_class_w,
        traits.size_class_h,
        vw[0],
        vw[1],
        vh[0],
        vh[1],
        m[0],
        m[1],
        traits.gamepad_count,
        traits.audio_channels,
        r[0],
        r[1],
        r[2],
        r[3],
        e[0],
        e[1],
        e[2],
        e[3],
        traits.authority,
        traits.display_count,
        traits.dpr_eighths,
        0,
    ]
}

const _: () = assert!(OFF_MSG_TYPE == 0);
const _: () = assert!(OFF_MSG_TYPE + 1 == OFF_ORIENTATION);
const _: () = assert!(OFF_ORIENTATION + 1 == OFF_SIZE_CLASS_W);
const _: () = assert!(OFF_SIZE_CLASS_W + 1 == OFF_SIZE_CLASS_H);
const _: () = assert!(OFF_SIZE_CLASS_H + 1 == OFF_VIEWPORT_W_PX);
const _: () = assert!(OFF_VIEWPORT_W_PX + 2 == OFF_VIEWPORT_H_PX);
const _: () = assert!(OFF_VIEWPORT_H_PX + 2 == OFF_MODALITIES);
const _: () = assert!(OFF_MODALITIES + 2 == OFF_GAMEPAD_COUNT);
const _: () = assert!(OFF_GAMEPAD_COUNT + 1 == OFF_AUDIO_CHANNELS);
const _: () = assert!(OFF_AUDIO_CHANNELS + 1 == OFF_AUDIO_RATE_HZ);
const _: () = assert!(OFF_AUDIO_RATE_HZ + 4 == OFF_EPOCH);
const _: () = assert!(OFF_EPOCH + 4 == OFF_AUTHORITY);
const _: () = assert!(OFF_AUTHORITY + 1 == OFF_DISPLAY_COUNT);
const _: () = assert!(OFF_DISPLAY_COUNT + 1 == OFF_DPR_EIGHTHS);
const _: () = assert!(OFF_DPR_EIGHTHS + 1 == OFF_RESERVED);
const _: () = assert!(OFF_RESERVED + 1 == EVENT_SIZE);
