// Contract: input::pointer — Pointer event surface.
//
// Layer: contracts/input (public, stable).
//
// Wire shape modelled on the W3C Pointer Events spec: unified
// surface for mouse, touch, and stylus input. Producers include
// the browser DOM (wasm_browser_pointer), Linux libinput
// (linux_input_evdev_pointer), and touchscreen drivers on RP /
// CM5 silicon. Pointer-mapped overlay transformers
// (touch_gamepad_overlay, touch_keyboard_overlay) CONSUME this
// contract and emit something else.
//
// Frame format (fixed 16 bytes):
//   [msg_type: u8] [pointer_id: u8] [event_kind: u8] [buttons: u8]
//   [modifiers: u8] [pad: u8] [pressure: u16 LE]
//   [x: i16 LE] [y: i16 LE]
//   [pad: u32 LE]
//
// Coordinates are device-pixel integers. Sub-pixel precision is
// out of scope today; if needed, a future MSG_HIRES variant can
// add float deltas.

/// Total event size in bytes. Fixed-width for stride reads.
pub const EVENT_SIZE: usize = 16;

// ── Downstream: producer → consumer ──────────────────────────────────

/// Pointer state event. Producers emit on every relevant DOM /
/// device transition: down, up, move, cancel, enter/leave (a
/// pointer crossing a graph-defined region boundary).
pub const MSG_EVENT: u8 = 0x01;

// ── Event kinds (msg.event_kind byte) ────────────────────────────────

pub const KIND_DOWN: u8   = 1;
pub const KIND_UP: u8     = 2;
pub const KIND_MOVE: u8   = 3;
pub const KIND_CANCEL: u8 = 4;
pub const KIND_ENTER: u8  = 5;
pub const KIND_LEAVE: u8  = 6;

// ── Button bitfield (msg.buttons) ────────────────────────────────────

pub const BTN_PRIMARY: u8   = 0x01;  // left mouse, primary touch contact
pub const BTN_SECONDARY: u8 = 0x02;  // right mouse, two-finger touch
pub const BTN_TERTIARY: u8  = 0x04;  // middle mouse
pub const BTN_BACK: u8      = 0x08;
pub const BTN_FORWARD: u8   = 0x10;

// ── Modifier bitfield (msg.modifiers) ────────────────────────────────

pub const MOD_SHIFT: u8 = 0x01;
pub const MOD_CTRL: u8  = 0x02;
pub const MOD_ALT: u8   = 0x04;
pub const MOD_META: u8  = 0x08;

/// Pressure scale: 0..1023 corresponds to W3C 0.0..1.0. Producers
/// that don't report pressure (regular mouse) emit 511 for "down"
/// events and 0 for "up".
pub const PRESSURE_MAX: u16 = 1023;
pub const PRESSURE_DEFAULT: u16 = 511;
