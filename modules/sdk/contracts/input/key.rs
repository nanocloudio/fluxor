// Contract: input::key — Keyboard event surface.
//
// Layer: contracts/input (public, stable).
//
// Wire shape modelled on the W3C UIEvents `KeyboardEvent` spec:
// physical-key + logical-key + modifier reporting on a single
// channel. Producers include browser DOM (wasm_browser_keyboard),
// Linux libinput keyboard (linux_input_evdev_keyboard), and any
// hardware-side scan-code reader (matrix encoder on rp2350,
// USB-HID-keyboard pass-through).
//
// Frame format (fixed 8 bytes — narrower than gamepad/pointer
// because key events carry less data and benefit from higher
// throughput):
//   [msg_type: u8] [event_kind: u8] [modifiers: u8] [repeat: u8]
//   [key_code: u16 LE] [scan_code: u16 LE]
//
// `key_code` is the W3C `KeyboardEvent.keyCode` (logical key after
// keymap). `scan_code` is the physical scan code (USB HID usage,
// or evdev keycode). Sub-spec details aside, the rule of thumb is:
// games / emulators care about scan_code (physical layout-
// independent); terminals / text editors care about key_code.

/// Total event size in bytes.
pub const EVENT_SIZE: usize = 8;

// ── Downstream: producer → consumer ──────────────────────────────────

/// Key state transition. Producers emit on KeyDown / KeyUp;
/// autorepeat-generated KeyDowns set the `repeat` byte to 1.
pub const MSG_EVENT: u8 = 0x01;

// ── Event kinds (msg.event_kind byte) ────────────────────────────────

pub const KIND_DOWN: u8 = 1;
pub const KIND_UP: u8   = 2;

// ── Modifier bitfield (msg.modifiers) ────────────────────────────────
// Same numeric layout as input::pointer::MOD_* so a single
// modifier-state byte can be shared if a transformer fuses
// pointer + key state.

pub const MOD_SHIFT: u8 = 0x01;
pub const MOD_CTRL: u8  = 0x02;
pub const MOD_ALT: u8   = 0x04;
pub const MOD_META: u8  = 0x08;
