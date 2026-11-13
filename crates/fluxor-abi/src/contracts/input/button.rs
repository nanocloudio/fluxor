// Contract: input::button — Single-button raw event surface.
//
// Layer: contracts/input (public, stable).
//
// Wire shape: one byte per debounced state transition.
//   0x01 = pressed
//   0x00 = released
//
// Producers (one canonical driver per platform — all expose the
// same byte shape so downstream consumers are platform-agnostic):
//
//   rp boards:
//     * `modules/drivers/flash_rp`     — BOOTSEL (QSPI sideband)
//     * `modules/foundation/button`    — external GPIO switch
//
//   wasm:
//     * `wasm_browser_button` built-in — DOM tap on player surface
//
//   future (bcm2712 via RP1, linux via evdev, etc.) — same contract
//
// Consumers:
//
//   * `modules/foundation/gesture`     — click counting + long-press
//                                        detection; emits FMP commands.
//                                        Single shared module; per-graph
//                                        params remap the click/double/
//                                        triple/long verbs to taste.
//   * direct downstream (rare)         — a state-only sink that just
//                                        wants pressed/released bits.
//
// The wire format is deliberately minimal so the timing logic lives in
// exactly one place (`gesture`). Producers must NOT emit duplicate
// bytes — only debounced transitions — so consumers can treat every
// byte as a state-change event and use their own clock for dwell
// reasoning.
//
// Wire type on the manifest is `OctetStream` (universal-compatible),
// not a typed surface, so existing FmpMessage / OctetStream sinks can
// also tap a button stream when that's useful.

/// Total event size in bytes. Fixed-width 1; one byte per debounced
/// transition.
pub const EVENT_SIZE: usize = 1;

/// State byte: button is currently pressed.
pub const STATE_PRESSED: u8 = 0x01;

/// State byte: button is currently released.
pub const STATE_RELEASED: u8 = 0x00;
