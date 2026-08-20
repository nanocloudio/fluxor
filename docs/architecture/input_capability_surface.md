# Input Capability Surface

Fluxor's input architecture rests on two layered concepts:

1. a **surface family** — typed channel content the graph carries, one
   content type per input class;
2. a **role discipline** — sources emit source-domain events, mapper
   modules own application meaning, and consumers read the resolved
   surface only.

This document is the input peer of `av_capability_surface.md`,
`protocol_surfaces.md`, and `monitor-protocol.md`. The guiding rule is
the one stated in `vision.md`: a button is not a GPIO pin, a keyboard
is not a Bluetooth peripheral. Input providers describe what happened
on a labelled control; application meaning belongs in mapper modules
or graph configuration.

---

## 1. Canonical surface family

Source: `contracts/src/lib.rs` (`CONTENT_TYPES`).

Input pipelines move data on channels typed by `content_type`. One
content type exists per input class, so a consumer reads the same wire
shape regardless of which producer is on the other end:

| Surface             | Domain                                       | Typical producers                                              |
|---------------------|----------------------------------------------|----------------------------------------------------------------|
| `KeyEvents`         | Keyboard transitions (logical + physical key) | `wasm_browser_keyboard`, hardware scan-code readers            |
| `PointerEvents`     | Unified mouse / touch / stylus events        | `wasm_browser_pointer`, `linux_pointer`, touchscreen drivers   |
| `GamepadEvents`     | Gamepad state snapshots                      | `wasm_browser_gamepad`, `wasm_browser_touch_gamepad_overlay`   |
| `MidiEvents`        | Pre-decoded MIDI 1.0 channel-voice events    | `wasm_browser_midi_in`, `linux_alsa_midi`                      |
| `OctetStream` (button wire) | Debounced single-button transitions  | `foundation/button`, `flash_rp` (BOOTSEL), `wasm_browser_button` |
| `FmpMessage`        | Semantic commands after mapping              | `foundation/gesture`, `wasm_browser_action`                    |
| `SurfaceTraits`     | Environment-plane snapshots (viewport, modality, audio config) | `wasm_browser_surface_traits`, `linux_surface_traits` |
| `InputBinaryState`  | Keyboard-state snapshots on a single port    | `wasm_browser_dom_input`                                       |
| `InputEvent`        | Legacy generic input surface                 | `gt911` touch driver                                           |
| `GestureMatch`      | Recognised gesture pattern                   | gesture recognisers                                            |

Wiring edges that mismatch surfaces fail the build with a content-type
mismatch from `tools/src/config/manifest.rs::validate_wiring_types`.
The surface ID table is `CONTENT_TYPES` in `contracts/src/lib.rs`,
re-exported through `tools/src/manifest.rs`.

New graphs wire the per-class surfaces; `InputEvent` stays in the
table because reordering or removing `CONTENT_TYPES` entries is a
wire-format break.

---

## 2. Payload contracts

Source: `modules/sdk/contracts/input/`. Each file is the wire contract
its producers and consumers both include, so the two cannot drift.

### `KeyEvents` — `modules/sdk/contracts/input/key.rs`

Fixed 8-byte frame modelled on the W3C UIEvents `KeyboardEvent` spec:

```text
[msg_type: u8] [event_kind: u8] [modifiers: u8] [repeat: u8]
[key_code: u16 LE] [scan_code: u16 LE]
```

`key_code` is the logical key after keymap; `scan_code` is the
physical code (USB HID usage or evdev keycode). Games and emulators
key on `scan_code` (layout-independent); terminals and text editors
key on `key_code`. Autorepeat-generated key-downs set the `repeat`
byte.

### `PointerEvents` — `modules/sdk/contracts/input/pointer.rs`

Fixed 16-byte frame modelled on the W3C Pointer Events spec: one
unified surface for mouse, touch, and stylus.

```text
[msg_type: u8] [pointer_id: u8] [event_kind: u8] [buttons: u8]
[modifiers: u8] [pad: u8] [pressure: u16 LE]
[x: i16 LE] [y: i16 LE] [pad: u32 LE]
```

Event kinds: down, up, move, cancel, enter, leave. Coordinates are
device-pixel integers. `pointer_id` lets multiple pointers coexist on
one channel.

### `GamepadEvents` — `modules/sdk/contracts/input/gamepad.rs`

Fixed 16-byte frame modelled on the W3C Gamepad API: up to 16 digital
buttons plus up to 4 analogue axes per device, delivered as full state
snapshots. The canonical producer pattern is one snapshot per step
when state has changed, plus an idle snapshot roughly every 16 ms so
consumers can distinguish a held button from a stale channel.

### `MidiEvents` — `modules/sdk/contracts/input/midi.rs`

Fixed 4-byte frame carrying pre-decoded MIDI 1.0 channel-voice
messages: `[event_kind, channel, data1, data2]`. Producers include
browser Web MIDI, Linux ALSA seq, and class-compliant USB-MIDI hosts;
symmetric output drivers consume the same shape.

### Button wire — `modules/sdk/contracts/input/button.rs`

One byte per debounced state transition (`0x01` pressed, `0x00`
released), carried on `OctetStream` so untyped sinks can also tap a
button stream. Producers emit only debounced transitions, never
duplicates, so the timing logic (click counting, long-press dwell)
lives in exactly one place: `modules/foundation/gesture`.

### Action wire — `modules/sdk/contracts/input/action.rs`

A pure conduit for application-chosen semantic verbs. A control
carries an opaque action id string (`next`, `prev`, `toggle`, or any
app-specific verb); the producer hashes it with FNV-1a32 and emits the
hash as the FMP command type. Only the hash travels on the wire; the
consumer matches the same hash of the same string, so the two sides
agree without a shared vocabulary table. Fluxor carries no verb
vocabulary of its own.

### `SurfaceTraits` — `modules/sdk/contracts/input/surface_traits.rs`

Fixed 24-byte environment-plane record: viewport geometry, derived
orientation and size class, present input modalities, and audio output
config. Published by the host platform authority
(`wasm_browser_surface_traits`, `linux_surface_traits`, static board
declarations on bare metal); a module that wants to adapt to its
surface wires an input port to it. Modules that ignore it keep
static-config behaviour, so the contract is additive.

---

## 3. Capability declarations

Source: `contracts/src/vocabulary.rs` (`CAPABILITY_NAMES`), enforced
at manifest parse time in `tools/src/manifest.rs` (case-insensitive
match, canonicalised to lowercase).

The registry's input-side names:

- `input.mapper` — module translates source-domain input into another
  input surface or semantic commands
- `input.gamepad` — gamepad source
- `input.virtual` — software-synthesised source (no physical sensor)
- `input.remote` — source delivered over a transport from another peer
- `midi.input` / `midi.output` — MIDI drivers, paired with the
  `MidiEvents` content type

Capability names express role intent; the per-port `content_type`
declarations express data shape. Most input modules are matched by
content type alone and declare no capability names.

---

## 4. Roles

Three input roles sit above the surface family:

- **Source** — captures source-domain events or state and encodes no
  application semantics. A button driver emits debounced transitions;
  it does not emit `play` or `pause`. Per-platform drivers expose the
  same wire shape (`wasm_browser_keyboard` and a hardware scan-code
  reader both emit `KeyEvents`), so downstream modules are
  platform-agnostic.
- **Mapper** — translates source-domain input into consumer-domain
  input or semantic commands, and owns all timing and binding
  knowledge. `modules/foundation/gesture` consumes button bytes and
  emits FMP commands (`next`, `prev`, `toggle`, `select`,
  `long_press`, `on`, `off`, remappable per graph);
  `wasm_browser_touch_gamepad_overlay` consumes `PointerEvents` and
  emits `GamepadEvents`.
- **Consumer** — executes semantic commands or consumes mapped state,
  without depending on whether input was physical, virtual, local, or
  remote.

Sources and mappers are replaceable; application modules consume the
resolved surface only.

### Safety boundary

Fluxor's graph-scheduled input path is not a substitute for
hardware-rated safety interlocks. A graph-level emergency-stop binding
is appropriate for application-logic stop behaviour (release motors,
surface a fault, refuse new commands). A safety-rated stop guarantee
(IEC 61508 / ISO 13849 SIL or category ratings) must be enforced in
hardware or by a safety-rated subsystem outside the graph. Carrying
the signal on these surfaces is fine; relying on them as the only
enforcement path is not.

---

## Related documentation

- `architecture/av_capability_surface.md` — AV peer of this document.
- `architecture/capability_surface.md` — capability matching and
  content-type resolution.
- `architecture/events.md` — kernel-level event signalling that
  hardware-facing input modules build on.
- `architecture/browser_capability_surface.md` — how browser DOM
  events map onto these surfaces.
- `guides/input_system.md`, `guides/input_gestures.md` — guide-level
  treatment of the source / gesture / action layering.
