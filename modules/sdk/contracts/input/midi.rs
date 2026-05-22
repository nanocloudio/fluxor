// Contract: input::midi — MIDI event surface.
//
// Layer: contracts/input (public, stable).
//
// Wire shape modelled on the Web MIDI API + standard MIDI 1.0
// channel-voice messages, pre-decoded so downstream consumers do
// not need to bit-twiddle MIDI status bytes. Producers include
// browser Web MIDI (`wasm_browser_midi_in`), Linux ALSA seq
// (`linux_alsa_midi`), and class-compliant USB-MIDI hosts on
// rp2350 and cm5 (`usb_midi_host`). Symmetric output drivers
// (`wasm_browser_midi_out`, `linux_alsa_midi` in `out` mode,
// `usb_midi_host` device-out) consume the same wire shape.
//
// Frame format (fixed 4 bytes — covers every MIDI 1.0 channel-
// voice message; SysEx is reserved for a separate streaming
// contract and is not handled here):
//   [event_kind: u8] [channel: u8] [data1: u8] [data2: u8]
//
// `channel` is the 1-based MIDI channel (1..=16); the bit-packed
// 0-based form in the original status byte is decoded by the
// producer. `data1` and `data2` carry the message payload per
// `event_kind`. Unused bytes (e.g. ProgramChange's data2) are
// zero.
//
// Timestamps live on the carrying edge / clock domain, not in the
// wire bytes — matches `input::key` and Fluxor's broader rule that
// timing is a runtime property, not a payload property.

/// Total event size in bytes.
pub const EVENT_SIZE: usize = 4;

// ── Event kinds (frame.event_kind) ──────────────────────────────────
//
// Numerically chosen to be distinct from the raw MIDI status nibble
// so a fused byte stream cannot accidentally be misread. The
// producer decodes the status byte into a kind + channel pair.

pub const KIND_NOTE_OFF: u8         = 0x01;
pub const KIND_NOTE_ON: u8          = 0x02;
pub const KIND_POLY_PRESSURE: u8    = 0x03;
pub const KIND_CONTROL_CHANGE: u8   = 0x04;
pub const KIND_PROGRAM_CHANGE: u8   = 0x05;
pub const KIND_CHANNEL_PRESSURE: u8 = 0x06;
pub const KIND_PITCH_BEND: u8       = 0x07;

// ── Payload conventions ─────────────────────────────────────────────
//
// NoteOn / NoteOff:
//   data1 = note number (0..=127)
//   data2 = velocity   (0..=127); NoteOn with velocity 0 is
//           normalised to NoteOff by the producer.
//
// PolyPressure:
//   data1 = note number
//   data2 = pressure  (0..=127)
//
// ControlChange:
//   data1 = controller number (0..=127)
//   data2 = controller value  (0..=127)
//   14-bit CC pairs (MSB / LSB pattern) are forwarded as two
//   separate CC events; coalescing is the consumer's choice.
//
// ProgramChange:
//   data1 = program number (0..=127)
//   data2 = 0 (reserved)
//
// ChannelPressure:
//   data1 = pressure (0..=127)
//   data2 = 0 (reserved)
//
// PitchBend:
//   data1 = LSB (0..=127)
//   data2 = MSB (0..=127)
//   14-bit value = (data2 << 7) | data1; centre = 0x2000.

// ── Channel range ───────────────────────────────────────────────────
//
// Channel 10 (`MIDI_CHANNEL_DRUMS`) is the General MIDI drum kit
// channel and is named here so app-layer routers can match it
// symbolically rather than with a magic number.

pub const MIDI_CHANNEL_MIN: u8 = 1;
pub const MIDI_CHANNEL_MAX: u8 = 16;
pub const MIDI_CHANNEL_DRUMS: u8 = 10;
