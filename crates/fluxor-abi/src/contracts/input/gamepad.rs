// Contract: input::gamepad — Gamepad event surface.
//
// Layer: contracts/input (public, stable).
//
// Wire shape modelled on the W3C Gamepad API: up to 16 digital
// buttons + up to 4 analog axes per device, plus connection
// metadata. Producers include hardware USB-HID gamepads (pico2w,
// pi5), Linux libinput / evdev, the browser's Gamepad API
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

/// Byte offsets shared by every record: the message type, and the slot the
/// record is about, which is the first payload byte of each.
pub const OFF_MSG_TYPE: usize = 0;
pub const OFF_GAMEPAD_ID: usize = 4;
/// Byte offsets of the `MSG_STATE` and `MSG_CONNECTION` payload fields.
pub const OFF_CONNECTED: usize = 5;
pub const OFF_BUTTON_BITS: usize = 6;
pub const OFF_AXIS_LX: usize = 8;
pub const OFF_AXIS_LY: usize = 10;
pub const OFF_AXIS_RX: usize = 12;
pub const OFF_AXIS_RY: usize = 14;
pub const OFF_MAPPING: usize = 6;
pub const OFF_VENDOR_ID: usize = 8;
pub const OFF_PRODUCT_ID: usize = 10;
/// Byte offsets of the `CMD_RUMBLE` payload fields.
pub const OFF_EFFECT_KIND: usize = 5;
pub const OFF_DURATION_MS: usize = 6;
pub const OFF_STRONG: usize = 8;
pub const OFF_WEAK: usize = 9;

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

pub const BTN_A: u8 = 0; // bottom face button
pub const BTN_B: u8 = 1; // right face button
pub const BTN_X: u8 = 2; // left face button
pub const BTN_Y: u8 = 3; // top face button
pub const BTN_L1: u8 = 4; // left shoulder
pub const BTN_R1: u8 = 5; // right shoulder
pub const BTN_L2: u8 = 6; // left trigger (digital threshold)
pub const BTN_R2: u8 = 7; // right trigger (digital threshold)
pub const BTN_SELECT: u8 = 8; // back / select
pub const BTN_START: u8 = 9; // start / pause
pub const BTN_L3: u8 = 10; // left stick click
pub const BTN_R3: u8 = 11; // right stick click
pub const BTN_DPAD_UP: u8 = 12;
pub const BTN_DPAD_DOWN: u8 = 13;
pub const BTN_DPAD_LEFT: u8 = 14;
pub const BTN_DPAD_RIGHT: u8 = 15;

// ── Producer capacity ────────────────────────────────────────────────

/// Maximum gamepad slots per producer. Matches the Web Gamepad API's
/// `navigator.getGamepads()` ceiling and is plenty for hardware
/// targets — USB-HID can drive 4 simultaneous devices comfortably,
/// the rest of the slots are headroom for hot-plug churn.
pub const MAX_GAMEPADS: usize = 4;

// ── Mapping kinds (MSG_CONNECTION.mapping) ───────────────────────────

pub const MAPPING_STANDARD: u8 = 0;
pub const MAPPING_LEGACY: u8 = 1;

// ── Records by field ─────────────────────────────────────────────────

/// One record, by field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// `MSG_STATE`: a slot's buttons and axes.
    State {
        gamepad_id: u8,
        connected: bool,
        button_bits: u16,
        axis_lx: i16,
        axis_ly: i16,
        axis_rx: i16,
        axis_ry: i16,
    },
    /// `MSG_CONNECTION`: a slot attached or detached.
    Connection {
        gamepad_id: u8,
        connected: bool,
        mapping: u8,
        vendor_id: u16,
        product_id: u16,
    },
    /// `CMD_RUMBLE`: a haptic effect for a slot.
    Rumble {
        gamepad_id: u8,
        effect_kind: u8,
        duration_ms: u16,
        strong: u8,
        weak: u8,
    },
}

const fn u16_at(b: &[u8; EVENT_SIZE], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

const fn i16_at(b: &[u8; EVENT_SIZE], at: usize) -> i16 {
    i16::from_le_bytes([b[at], b[at + 1]])
}

/// Read a record. `None` for a message type this contract does not
/// allocate, or a slot at or past `MAX_GAMEPADS`.
pub const fn decode(b: &[u8; EVENT_SIZE]) -> Option<Event> {
    let gamepad_id = b[OFF_GAMEPAD_ID];
    if gamepad_id as usize >= MAX_GAMEPADS {
        return None;
    }
    match b[OFF_MSG_TYPE] {
        MSG_STATE => Some(Event::State {
            gamepad_id,
            connected: b[OFF_CONNECTED] != 0,
            button_bits: u16_at(b, OFF_BUTTON_BITS),
            axis_lx: i16_at(b, OFF_AXIS_LX),
            axis_ly: i16_at(b, OFF_AXIS_LY),
            axis_rx: i16_at(b, OFF_AXIS_RX),
            axis_ry: i16_at(b, OFF_AXIS_RY),
        }),
        MSG_CONNECTION => Some(Event::Connection {
            gamepad_id,
            connected: b[OFF_CONNECTED] != 0,
            mapping: b[OFF_MAPPING],
            vendor_id: u16_at(b, OFF_VENDOR_ID),
            product_id: u16_at(b, OFF_PRODUCT_ID),
        }),
        CMD_RUMBLE => Some(Event::Rumble {
            gamepad_id,
            effect_kind: b[OFF_EFFECT_KIND],
            duration_ms: u16_at(b, OFF_DURATION_MS),
            strong: b[OFF_STRONG],
            weak: b[OFF_WEAK],
        }),
        _ => None,
    }
}

const _: () = assert!(OFF_GAMEPAD_ID + 1 == OFF_CONNECTED);
const _: () = assert!(OFF_CONNECTED + 1 == OFF_BUTTON_BITS);
const _: () = assert!(OFF_BUTTON_BITS + 2 == OFF_AXIS_LX);
const _: () = assert!(OFF_AXIS_LX + 2 == OFF_AXIS_LY);
const _: () = assert!(OFF_AXIS_LY + 2 == OFF_AXIS_RX);
const _: () = assert!(OFF_AXIS_RX + 2 == OFF_AXIS_RY);
const _: () = assert!(OFF_AXIS_RY + 2 == EVENT_SIZE);
const _: () = assert!(OFF_CONNECTED + 1 == OFF_MAPPING);
const _: () = assert!(OFF_MAPPING + 2 == OFF_VENDOR_ID);
const _: () = assert!(OFF_VENDOR_ID + 2 == OFF_PRODUCT_ID);
const _: () = assert!(OFF_GAMEPAD_ID + 1 == OFF_EFFECT_KIND);
const _: () = assert!(OFF_EFFECT_KIND + 1 == OFF_DURATION_MS);
const _: () = assert!(OFF_DURATION_MS + 2 == OFF_STRONG);
const _: () = assert!(OFF_STRONG + 1 == OFF_WEAK);
