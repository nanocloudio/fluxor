// Contract: input::gamepad — Gamepad event surface.
//
// Layer: contracts/input (public, stable).
//
// Wire shape modelled on the W3C Gamepad API: up to 16 digital
// buttons + up to 4 analog axes per device, plus connection
// metadata. Producers include hardware USB-HID gamepads (pico2w,
// cm5), Linux libinput / evdev, the browser's Gamepad API
// (wasm_browser_gamepad), and pointer-mapped overlay transformers
// (wasm_browser_touch_gamepad_overlay).
//
// Consumers (games, emulators, UI input handlers) read from any
// channel with this contract — same wire shape regardless of which
// producer is on the other end. That's the whole point of the
// capability-surface model.
//
// Frame format (uniform per opcode for cheap dispatch):
//   [msg_type: u8] [pad: u8] [pad: u16 LE] [payload: 12 bytes]
//
// Total event = 16 bytes. Aligned to 4-byte boundary for cheap
// channel reads. Padding lets future opcodes grow without bumping
// the framing.

/// Total event size in bytes including header. Fixed-width so
/// consumers can stride channel reads without parsing.
pub const EVENT_SIZE: usize = 16;

// ── Downstream: producer → consumer ──────────────────────────────────

/// Full gamepad state snapshot. Producers emit at any cadence; the
/// canonical pattern is one snapshot per producer step when state
/// has changed, plus an idle snapshot every ~16ms so consumers can
/// distinguish "held button" from "stale channel".
///
/// Payload (12 bytes):
///   [gamepad_id:    u8]      slot, 0..MAX_GAMEPADS-1
///   [connected:     u8]      1 = connected, 0 = disconnected
///   [button_bits:   u16 LE]  bit i = button[i] pressed (W3C ordering)
///   [axis_lx:       i16 LE]  left stick X,    -32768..32767
///   [axis_ly:       i16 LE]  left stick Y
///   [axis_rx:       i16 LE]  right stick X
///   [axis_ry:       i16 LE]  right stick Y
pub const MSG_STATE: u8 = 0x01;

/// Connection change. Sent immediately on attach/detach in addition
/// to whatever MSG_STATE the producer would emit on the next tick.
///
/// Payload (12 bytes):
///   [gamepad_id:    u8]
///   [connected:     u8]      1 = newly attached, 0 = detached
///   [mapping:       u8]      W3C "mapping" enum: 0 = standard, 1 = legacy
///   [pad:           u8]
///   [vendor_id:     u16 LE]  USB VID, or 0 for browser-virtualised
///   [product_id:    u16 LE]  USB PID, or 0 ditto
///   [pad:           u32 LE]
pub const MSG_CONNECTION: u8 = 0x02;

// ── Upstream: consumer → producer ────────────────────────────────────

/// Rumble / haptic effect. Optional capability; producers MAY ignore
/// (e.g. USB-HID without force feedback, browsers on Safari).
///
/// Payload (12 bytes):
///   [gamepad_id:    u8]
///   [effect_kind:   u8]      0 = stop, 1 = dual-rumble
///   [duration_ms:   u16 LE]  effect length, 0..65535
///   [strong:        u8]      0..255, low-frequency motor amplitude
///   [weak:          u8]      0..255, high-frequency motor amplitude
///   [pad:           u8 * 6]
pub const CMD_RUMBLE: u8 = 0x80;

// ── W3C standard button mapping ──────────────────────────────────────
// Bit positions in MSG_STATE.button_bits. Matches the W3C "standard"
// mapping byte-for-byte so wasm_browser_gamepad can blit the
// browser's button array directly.

pub const BTN_A: u8           = 0;   // bottom face button
pub const BTN_B: u8           = 1;   // right face button
pub const BTN_X: u8           = 2;   // left face button
pub const BTN_Y: u8           = 3;   // top face button
pub const BTN_L1: u8          = 4;   // left shoulder
pub const BTN_R1: u8          = 5;   // right shoulder
pub const BTN_L2: u8          = 6;   // left trigger (digital threshold)
pub const BTN_R2: u8          = 7;   // right trigger (digital threshold)
pub const BTN_SELECT: u8      = 8;   // back / select
pub const BTN_START: u8       = 9;   // start / pause
pub const BTN_L3: u8          = 10;  // left stick click
pub const BTN_R3: u8          = 11;  // right stick click
pub const BTN_DPAD_UP: u8     = 12;
pub const BTN_DPAD_DOWN: u8   = 13;
pub const BTN_DPAD_LEFT: u8   = 14;
pub const BTN_DPAD_RIGHT: u8  = 15;

// ── Producer capacity ────────────────────────────────────────────────

/// Maximum gamepad slots per producer. Matches the Web Gamepad API's
/// `navigator.getGamepads()` ceiling and is plenty for hardware
/// targets — USB-HID can drive 4 simultaneous devices comfortably,
/// the rest of the slots are headroom for hot-plug churn.
pub const MAX_GAMEPADS: usize = 4;

// ── Mapping kinds (MSG_CONNECTION.mapping) ───────────────────────────

pub const MAPPING_STANDARD: u8 = 0;
pub const MAPPING_LEGACY: u8   = 1;
