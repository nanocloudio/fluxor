// Contract: input::pointer — Pointer event surface.
//
// Layer: contracts/input (public, stable).
//
// Wire shape modelled on the W3C Pointer Events spec: unified
// surface for mouse, touch, and stylus input. Producers include
// the browser DOM (wasm_browser_pointer), Linux evdev (linux_pointer),
// a host window, and touchscreen drivers. Pointer-mapped overlay
// transformers (touch_gamepad_overlay, touch_keyboard_overlay) CONSUME
// this contract and emit something else.
//
// Record (fixed 16 bytes, little-endian):
//
//   [0]       msg_type    MSG_EVENT
//   [1]       pointer_id
//   [2]       event_kind  KIND_*
//   [3]       buttons     BTN_* bits held, for every kind
//   [4]       modifiers   MOD_* bits
//   [5]       wheel_unit  WHEEL_PIXELS | WHEEL_DETENTS (0 unless KIND_WHEEL)
//   [6..8]    pressure    u16
//   [8..10]   x           i16  pointer position, surface pixels
//   [10..12]  y           i16
//   [12..14]  dx          i16  horizontal wheel delta (0 unless KIND_WHEEL)
//   [14..16]  dy          i16  vertical wheel delta
//
// SURFACE PIXELS are the pixels of the raster presented on the surface,
// whatever its size; `x`, `y` and pixel wheel deltas are in them.
//
// WHEEL. `WHEEL_PIXELS` deltas are eighths of a surface pixel (a trackpad's
// smooth scroll); `WHEEL_DETENTS` deltas are 1/120 detent, the unit of USB
// HID high-resolution wheels, and the consumer turns a detent into its own
// line step. Signs follow the W3C `WheelEvent`: positive `dy` scrolls toward
// the end (content moves up), positive `dx` toward the right. A producer
// sends at most one wheel record per pointer per unit per frame or pass,
// summing deltas and carrying the last position; a sum past `i16` is split
// into further records, never clamped.

/// Total event size in bytes. Fixed-width for stride reads.
pub const EVENT_SIZE: usize = 16;

/// Byte offsets of the record's fields.
pub const OFF_MSG_TYPE: usize = 0;
pub const OFF_POINTER_ID: usize = 1;
pub const OFF_EVENT_KIND: usize = 2;
pub const OFF_BUTTONS: usize = 3;
pub const OFF_MODIFIERS: usize = 4;
pub const OFF_WHEEL_UNIT: usize = 5;
pub const OFF_PRESSURE: usize = 6;
pub const OFF_X: usize = 8;
pub const OFF_Y: usize = 10;
pub const OFF_DX: usize = 12;
pub const OFF_DY: usize = 14;

// ── Downstream: producer → consumer ──────────────────────────────────

/// Pointer state event. Producers emit on every relevant DOM /
/// device transition: down, up, move, cancel, enter/leave (a
/// pointer crossing a graph-defined region boundary).
pub const MSG_EVENT: u8 = 0x01;

// ── Event kinds (msg.event_kind byte) ────────────────────────────────

pub const KIND_DOWN: u8 = 1;
pub const KIND_UP: u8 = 2;
pub const KIND_MOVE: u8 = 3;
pub const KIND_CANCEL: u8 = 4;
pub const KIND_ENTER: u8 = 5;
pub const KIND_LEAVE: u8 = 6;
/// Relative motion (pointer-lock / captured-mouse): `x`/`y` carry signed
/// per-event deltas instead of absolute coordinates. Producers emit this
/// while a lock is active (e.g. browser Pointer Lock API); consumers that
/// implement FPS-style look should prefer it over KIND_MOVE deltas.
pub const KIND_MOVE_REL: u8 = 7;
/// Wheel or scroll: `wheel_unit`, `dx` and `dy` carry the motion; `x`/`y`
/// are the pointer's position as for any event.
pub const KIND_WHEEL: u8 = 8;

// ── Wheel units (msg.wheel_unit, KIND_WHEEL only) ────────────────────

/// Deltas in eighths of a surface pixel.
pub const WHEEL_PIXELS: u8 = 0;
/// Deltas in 1/120 detent.
pub const WHEEL_DETENTS: u8 = 1;
/// Wheel delta units in one surface pixel (`WHEEL_PIXELS`).
pub const WHEEL_UNITS_PER_PIXEL: i16 = 8;
/// Wheel delta units in one detent (`WHEEL_DETENTS`).
pub const WHEEL_UNITS_PER_DETENT: i16 = 120;

// ── Button bitfield (msg.buttons) ────────────────────────────────────

pub const BTN_PRIMARY: u8 = 0x01; // left mouse, primary touch contact
pub const BTN_SECONDARY: u8 = 0x02; // right mouse, two-finger touch
pub const BTN_TERTIARY: u8 = 0x04; // middle mouse
pub const BTN_BACK: u8 = 0x08;
pub const BTN_FORWARD: u8 = 0x10;

// ── Modifier bitfield (msg.modifiers) ────────────────────────────────

pub const MOD_SHIFT: u8 = 0x01;
pub const MOD_CTRL: u8 = 0x02;
pub const MOD_ALT: u8 = 0x04;
pub const MOD_META: u8 = 0x08;

/// Pressure scale: 0..1023 corresponds to W3C 0.0..1.0. Producers
/// that don't report pressure (regular mouse) emit 511 for "down"
/// events and 0 for "up".
pub const PRESSURE_MAX: u16 = 1023;
pub const PRESSURE_DEFAULT: u16 = 511;

/// One pointer record, by field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub pointer_id: u8,
    pub kind: u8,
    pub buttons: u8,
    pub modifiers: u8,
    /// `WHEEL_*`; zero unless `kind` is `KIND_WHEEL`.
    pub wheel_unit: u8,
    pub pressure: u16,
    pub x: i16,
    pub y: i16,
    /// Wheel deltas; zero unless `kind` is `KIND_WHEEL`.
    pub dx: i16,
    pub dy: i16,
}

const fn i16_at(b: &[u8; EVENT_SIZE], at: usize) -> i16 {
    i16::from_le_bytes([b[at], b[at + 1]])
}

/// Whether `event`'s wheel fields are ones this contract admits: a known
/// unit on a wheel record, and none of them set on any other kind.
const fn wheel_fields_valid(event: &Event) -> bool {
    if event.kind == KIND_WHEEL {
        matches!(event.wheel_unit, WHEEL_PIXELS | WHEEL_DETENTS)
    } else {
        event.wheel_unit == 0 && event.dx == 0 && event.dy == 0
    }
}

/// Read a record. `None` for a message type other than `MSG_EVENT`, a wheel
/// record with an unknown unit, or any other kind carrying a wheel unit or
/// delta.
pub const fn decode(b: &[u8; EVENT_SIZE]) -> Option<Event> {
    if b[OFF_MSG_TYPE] != MSG_EVENT {
        return None;
    }
    let event = Event {
        pointer_id: b[OFF_POINTER_ID],
        kind: b[OFF_EVENT_KIND],
        buttons: b[OFF_BUTTONS],
        modifiers: b[OFF_MODIFIERS],
        wheel_unit: b[OFF_WHEEL_UNIT],
        pressure: u16::from_le_bytes([b[OFF_PRESSURE], b[OFF_PRESSURE + 1]]),
        x: i16_at(b, OFF_X),
        y: i16_at(b, OFF_Y),
        dx: i16_at(b, OFF_DX),
        dy: i16_at(b, OFF_DY),
    };
    if wheel_fields_valid(&event) {
        Some(event)
    } else {
        None
    }
}

/// The record for `event`, or `None` when its wheel fields are ones `decode`
/// refuses.
pub const fn encode(event: &Event) -> Option<[u8; EVENT_SIZE]> {
    if !wheel_fields_valid(event) {
        return None;
    }
    let p = event.pressure.to_le_bytes();
    let x = event.x.to_le_bytes();
    let y = event.y.to_le_bytes();
    let dx = event.dx.to_le_bytes();
    let dy = event.dy.to_le_bytes();
    Some([
        MSG_EVENT,
        event.pointer_id,
        event.kind,
        event.buttons,
        event.modifiers,
        event.wheel_unit,
        p[0],
        p[1],
        x[0],
        x[1],
        y[0],
        y[1],
        dx[0],
        dx[1],
        dy[0],
        dy[1],
    ])
}

const _: () = assert!(OFF_MSG_TYPE == 0);
const _: () = assert!(OFF_MSG_TYPE + 1 == OFF_POINTER_ID);
const _: () = assert!(OFF_POINTER_ID + 1 == OFF_EVENT_KIND);
const _: () = assert!(OFF_EVENT_KIND + 1 == OFF_BUTTONS);
const _: () = assert!(OFF_BUTTONS + 1 == OFF_MODIFIERS);
const _: () = assert!(OFF_MODIFIERS + 1 == OFF_WHEEL_UNIT);
const _: () = assert!(OFF_WHEEL_UNIT + 1 == OFF_PRESSURE);
const _: () = assert!(OFF_PRESSURE + 2 == OFF_X);
const _: () = assert!(OFF_X + 2 == OFF_Y);
const _: () = assert!(OFF_Y + 2 == OFF_DX);
const _: () = assert!(OFF_DX + 2 == OFF_DY);
const _: () = assert!(OFF_DY + 2 == EVENT_SIZE);
