# Input Capability Surface

Fluxor's input architecture rests on three layered concepts:

1. a **surface family** — typed channel content the graph carries;
2. a small set of **irreducible primitives** plus a single rule for how
   sources address them;
3. a **capability vocabulary** — manifest-level role declarations — and
   **interaction groups** — validated topologies that bind sources, mappers,
   and consumers under one focus / capture / latency policy.

This document is the input peer of `av_capability_surface.md`,
`protocol_surfaces.md`, and `monitor-protocol.md`. The guiding rule is
the same one stated in `vision.md`: a button is not a GPIO pin, a
keyboard is not a Bluetooth peripheral. Input providers describe what
happened on a labeled control. Application meaning belongs in mapper
modules or graph configuration.

---

## 1. Canonical Surface Family

Input pipelines move data on channels typed by `content_type`:

| Surface              | Domain                                                | Typical producers / consumers                                       |
|----------------------|-------------------------------------------------------|---------------------------------------------------------------------|
| `InputBinaryEvent`   | Labeled binary edges                                  | GPIO button, web button, MQTT toggle, footswitch, e-stop, IoT button |
| `InputBinaryState`   | Labeled binary state set                              | virtual control panel, controller snapshot, appliance face          |
| `InputScalarEvent`   | Labeled scalar change or delta                        | knob, slider, trigger, throttle, encoder delta, ADC channel         |
| `InputScalarState`   | Labeled scalar state set                              | gamepad axes, mixer faders, jog controls, environmental sensor pack |
| `InputVectorEvent`   | Multi-axis sample with semantic linkage between axes  | IMU, accelerometer, joystick stick, head pose, gyro                 |
| `InputVectorState`   | Snapshot of one or more vector controls               | full-pose tracker, robot kinematic state, multi-axis sensor cluster |
| `InputKeyEvent`      | Symbolic key edges with key space and modifiers       | USB / BT HID keyboard, on-screen keyboard, browser-delivered keys   |
| `InputText`          | Text after layout / IME / paste / speech composition  | keyboard text path, on-screen keyboard, voice transcript, scanner   |
| `InputPointerEvent`  | One labeled point with motion, buttons, wheel, pressure | mouse, trackpad, stylus, browser-delivered pointer, eye tracker     |
| `InputTouchEvent`    | Touch contacts with lifecycle and geometry            | capacitive / resistive touch, multitouch trackpad, browser touch    |
| `InputGesture`       | Recognized pattern semantics                          | gesture recognizer, dwell-pointer recognizer, voice intent          |
| `InputAction`        | Bound semantic command after policy mapping           | action mapper, menu bindings, transport controls, automation        |

Codec-tagged variants may be introduced where the source identity must
travel in `content_type` itself: `InputHidReport`, `InputMidiMessage`,
`InputDmxFrame`. They are source-domain surfaces, not application
actions, and they carry the same semantics as the generic surfaces
above plus a transport identity.

Profile-level surfaces such as `InputGamepadEvent` / `InputGamepadState`
are convenience rollups over the irreducible primitives. A gamepad is
mostly binary state plus scalar state plus optional vector state. The
profile surface keeps games and emulators free of cross-control timing
glue without claiming gamepads are primitive. The same pattern applies
to keyboards (binary edges with a symbolic key space) and touchscreens
(touch contacts plus surface-local geometry).

### Where this is enforced

Wiring edges that mismatch surfaces fail the build with a content-type
mismatch from `tools/src/config.rs::validate_wiring_types`. The surface
ID table is `tools/src/manifest.rs::CONTENT_TYPES`, mirrored for
decoded-config rendering. Capability resolution is described in
`capability_surface.md`; this document defines the input vocabulary
that resolution operates on.

This surface covers any inbound signal that drives behavior. The
same source — a thermostat, an IMU — may also feed observability;
the split is consumer intent, not source hardware, and no separate
primitive is needed.

---

## 2. Irreducible Primitives

The surface family above factors into eight primitives. Sources of
wildly different shape (a GPIO pin, an MQTT message, a REST POST, a
keyboard key, a BLE remote, a touch region, a BOOTSEL pin, an IoT
dash button) all reduce to one of these — they differ only in their
**identity namespace**, not in their primitive shape.

### Binary Control

A labeled on / off transition or current state.

Examples of producing sources, all of which reduce to the same
primitive:

- physical GPIO pin with debouncing
- platform-synthesized pin such as a board BOOTSEL pin exposed at a
  reserved virtual pin id
- reed switch, hall sensor, limit switch, lid sensor, tamper switch
- foot pedal, kill switch, e-stop
- touchscreen virtual button region
- on-screen software button in a host UI
- browser-delivered button click
- HTTP POST to a bound REST path
- MQTT message on a bound topic
- IoT push button (Dash-style, BLE button, Zigbee button)
- card / RFID / NFC tap completion edge
- single-switch accessibility input
- voice wake-word edge before transcription

A keyboard key is a binary control with an identity in a symbolic key
namespace plus modifiers. It is broken out as `InputKeyEvent` because
keyboard layout, modifiers, repeat, and IME composition are real
machinery that other binary sources do not need.

### Scalar Control

A bounded analog value or delta on a labeled axis, with a declared
unit and range.

Examples:

- analog axis, trigger, slider, knob, throttle, jog wheel
- ADC channel, potentiometer, photoresistor, force-sensitive resistor
- rotary encoder delta
- environmental sensor reading: temperature, humidity, pressure,
  ambient light, particulate, CO₂
- battery voltage, current draw, fuel level
- network-delivered scalar setpoint (REST PUT, MQTT publish carrying
  a numeric value)
- MIDI continuous controller value
- pressure or force from a stylus or capacitive surface

### Vector Control

A semantically-linked multi-axis sample where the axes must be observed
together. Two or three independent scalar controls observed at the same
sample point are not the same as a vector — interleaved scalar updates
break the linkage.

Examples:

- IMU triple (accelerometer, gyro, magnetometer)
- joystick stick as a coupled (x, y) pair
- head, hand, or body pose from a 6-DoF tracker
- gaze direction from an eye tracker
- robot end-effector pose
- skeleton joint frame from a depth camera

A consumer that only needs independent axes can subscribe to the
scalar surface. A consumer that needs atomic axis linkage subscribes
to the vector surface. Mappers translate between forms.

### Symbolic Text

Composed text after keyboard layout, IME composition, paste, voice
transcription, or on-screen keyboard. Text is not a sequence of key
events; key events and text are different surfaces.

Examples:

- typed text under a layout and IME
- pasted text from a clipboard
- transcribed speech from a recognizer
- scanned barcode, magstripe read, RFID UID rendered as text
- form-field auto-fill from a credential manager
- chat / voice-assistant text from a remote channel

### Pointer

One directed point with motion, buttons, wheel, pressure, tilt, and a
declared coordinate space. A pointer carries a `pointer_id` so multiple
pointers (host + remote, mouse + dwell pointer + eye tracker) can
coexist.

Examples:

- mouse, trackpad, trackball
- stylus / pen with pressure and tilt
- absolute pointer such as a touchscreen single contact projected
  through pointer abstraction
- dwell pointer or eye tracker driving a pointer
- remote-desktop or browser-delivered pointer
- light-gun / IR pointer

### Touch Contact Set

One or more labeled contact points with a lifecycle (`start`, `move`,
`end`, `cancel`) and per-contact geometry (`major`, `minor`, pressure).

Examples:

- capacitive or resistive touchscreen
- multitouch trackpad
- pressure-sensitive surface
- browser-delivered touch contacts
- floor / mat sensor with multiple contact zones

A single contact may be projected into the pointer surface; a contact
set may be projected into binary regions (touch button) or gestures.
These projections are mapper concerns, not primitives.

### Derived Gesture

A recognized pattern over binary, scalar, vector, pointer, or touch
input: click, double-click, long-press, dwell, swipe, pinch, rotate,
shake, tap-and-hold, multi-tap rhythm, voice intent, head nod.

Gesture is derived. It is never a source-level primitive. The gesture
recognizer is a mapper module.

### Bound Action

A semantic command after policy mapping: `pause`, `select`, `jump`,
`menu_back`, `confirm`, `enter_service_mode`, `fire`, `coin`. Actions
should not leak physical source names. The action consumer does not
know whether the source was a touchscreen, a keyboard, a remote
session, or an automation script.

Action is the only surface in this list that is fully consumer-domain;
the others are all source- or surface-domain.

---

## 3. Identity Namespaces

Every binary, scalar, vector, key, and pointer surface carries a
`source_id` plus a per-control identifier. The identifier lives in a
declared **namespace** so binding tables and mappers can target controls
across heterogeneous sources without source-type sniffing.

| Namespace          | Identifier shape                | Examples                                          |
|--------------------|---------------------------------|---------------------------------------------------|
| `gpio`             | platform pin number             | `gpio.21`, `gpio.0xFF` (reserved virtual pin)     |
| `hid.usage`        | HID usage page + usage          | `hid.usage.0x07.0x04` (keyboard A)                |
| `key.symbolic`     | symbolic key name               | `key.symbolic.ArrowUp`, `key.symbolic.Escape`     |
| `pointer.button`   | pointer button index            | `pointer.button.0`, `pointer.button.2`            |
| `gamepad.control`  | profile control name            | `gamepad.control.south`, `gamepad.control.left_x` |
| `touch.region`     | declared touch region id        | `touch.region.transport_play`                     |
| `mqtt.topic`       | MQTT topic                      | `mqtt.topic.home/light/toggle`                    |
| `http.route`       | HTTP method + path              | `http.route.POST./api/play`                       |
| `midi`             | port + channel + control        | `midi.port0.ch1.cc7`                              |
| `dmx`              | universe + channel              | `dmx.u1.ch12`                                     |
| `sensor`           | logical sensor channel          | `sensor.cabin_temp`, `sensor.imu0.accel`          |
| `scheduled`        | timer or cron name              | `scheduled.morning_routine`                       |
| `automation`       | automation script identifier    | `automation.test_macro_3`                         |
| `virtual`          | software-synthesized control    | `virtual.confirm_overlay`, `virtual.dpad_up`      |
| `remote`           | wrapped namespace from a peer   | `remote.<peer>.<inner-namespace>.<id>`            |

Namespaces are declarative, not hardcoded. The list above enumerates
common ones. New sources may introduce new namespaces; the only
requirement is that the namespace is declared on the source so mappers
can match against it.

The `remote` namespace wraps another namespace to preserve source
identity across a transport. A browser-delivered keypress arriving over
a remote channel might surface as `remote.host42.key.symbolic.ArrowUp`,
which a mapper can rewrite, gate by focus policy, or translate into a
local binding without losing the original identity for audit.

Platform-specific synthesized sources (a board BOOTSEL exposed at a
reserved virtual pin id, a watchdog-derived health pulse) live in the
namespace that best reflects how the consumer addresses them, not the
namespace of the underlying mechanism. A BOOTSEL pin exposed as
virtual GPIO `0xFF` belongs in the `gpio` namespace because that is
how application configs target it.

---

## 4. Event vs State

Both event and state surfaces are needed and the choice is workload-
driven, not stylistic.

- **Event surfaces** preserve edges, deltas, text, contact lifecycle,
  and gesture lifecycle. An e-stop edge or a UI button click must
  never be coalesced.
- **State surfaces** preserve current control state at a sampling
  boundary. A frame-paced game does not want every gamepad axis edge;
  it wants the latest snapshot.

A mapper may consume events and emit state, or consume state and emit
actions. It may also coalesce high-rate state on an explicit policy.
It must not coalesce edges or text without an explicit declaration in
its manifest.

For games and emulators the clean target is:

```text
keyboard / virtual buttons / hid gamepad / browser
  -> InputKeyEvent + InputBinaryState + InputScalarState
  -> platform_input_mapper
  -> machine-specific input matrix
  -> emulator core
```

For an embedded appliance:

```text
front-panel buttons / rotary encoder / touchscreen
  -> InputBinaryEvent + InputScalarEvent + InputTouchEvent
  -> appliance_panel_mapper
  -> InputAction
  -> controller modules
```

For a robot or vehicle jog:

```text
joystick / footswitch / e-stop / web operator panel
  -> InputVectorState + InputBinaryEvent + InputScalarState
  -> jog_mapper
  -> motion_controller
```

---

## 5. Capability Declarations

Modules declare input-side capabilities via the manifest top-level
field, matched case-insensitively at parse time and canonicalized to
lowercase, matching AV capability behavior.

```toml
capabilities = ["input.key_event", "input.gamepad", "input.virtual"]
```

The whitelist covers two tiers plus two composition modifiers.
Hardware-facing names describe what the source *is*; service-level
names describe what data shape the source *provides*. A virtual
on-screen gamepad declares `input.gamepad` (role) and
`input.gamepad_state` (data shape) plus the `input.virtual` modifier.

### Hardware-facing

- `input.gpio_button` — physical binary input from a digital pin
- `input.keyboard` — keyboard / HID key source
- `input.mouse` — pointer source with buttons and wheel
- `input.stylus` — pointer source with pressure and tilt
- `input.touch` — touch contact source
- `input.gamepad` — gamepad / joystick source
- `input.rotary` — encoder / knob source
- `input.analog` — single-axis ADC / slider / trigger source
- `input.imu` — accelerometer / gyro / magnetometer source
- `input.tracker` — multi-axis pose tracker (head, hand, body, gaze)
- `input.hid` — generic HID report source
- `input.midi` — MIDI source
- `input.dmx` — DMX source
- `input.scanner` — barcode / RFID / NFC / magstripe source
- `input.sensor` — environmental or platform sensor source
- `input.iot` — network-delivered IoT button or remote
- `input.network` — REST / MQTT / webhook input source
- `input.automation` — scripted, scheduled, or replay input source

### Composition modifiers

- `input.virtual` — software-synthesized source (no physical sensor)
- `input.remote` — source delivered over a transport from another peer

A browser-delivered key source declares `input.keyboard` plus
`input.virtual` plus `input.remote`. A scripted test fixture declares
`input.automation` plus `input.virtual`. A wired-on-PCB BOOTSEL pin
declares `input.gpio_button` only.

### Service-level

- `input.binary_event`
- `input.binary_state`
- `input.scalar_event`
- `input.scalar_state`
- `input.vector_event`
- `input.vector_state`
- `input.key_event`
- `input.text`
- `input.pointer_event`
- `input.touch_event`
- `input.gamepad_event`
- `input.gamepad_state`
- `input.gesture`
- `input.action`
- `input.mapper`
- `input.coordinator`

---

## 6. Payload Contracts

Exact binary structs live with the module SDK contracts. Every input
surface preserves these baseline fields:

- `source_id` — module-stable identifier of the producing source
- `seq` — monotonic sequence number within `source_id`
- `timestamp` — sample or event time on the source's clock
- `namespace` — identity namespace (see §3)
- per-surface identifier (`control_id`, `key_code`, `pointer_id`,
  `contact_id`, `axis_id`, `action_id`)

Per-surface additions follow.

### `InputBinaryEvent`

`control_id`, `state` (`pressed`, `released`, optionally `repeat`).

Use for any labeled binary edge: GPIO buttons, web buttons, foot
pedals, e-stops, MQTT toggles, REST POSTs, IoT buttons, NFC taps.

### `InputBinaryState`

`controls` bitset or `control_id -> state` map. Use when the consumer
only wants the latest state per tick or frame.

### `InputScalarEvent`

`control_id`, `value`, `unit`, `range_min`, `range_max`, `delta`.

`unit` may be normalized 0..1, raw ADC counts, degrees, detents,
percent, or a domain-specific unit declared on the source's manifest
(`celsius`, `lux`, `rpm`, `hpa`).

### `InputScalarState`

`control_id -> value` map plus per-control unit and range metadata, or
a profile name that fixes those.

### `InputVectorEvent` / `InputVectorState`

`control_id`, `axes` (typed numeric tuple), `axis_units`, `frame_id`
(coordinate frame for pose / orientation data). Vector surfaces must
carry their coordinate frame; a pose update is meaningless without it.

### `InputKeyEvent`

`key_code`, `key_space`, `state`, `modifiers`, `repeat`.

A DOM `KeyA`, USB HID usage `0x07.0x04`, ASCII `a`, and an emulated
platform key `A` are not the same value. `key_space` declares which
namespace the `key_code` lives in; mappers translate between spaces.

### `InputText`

`text`, `composition_state`. IME composition, paste, speech, and
on-screen keyboards belong here, not on the key surface.

### `InputPointerEvent`

`pointer_id`, `phase` (`move`, `down`, `up`, `cancel`, `wheel`), `x`,
`y`, `coordinate_space`, `buttons`, `wheel_delta`, `pressure`, `tilt`.

`coordinate_space` must declare its frame: screen pixels, normalized
0..1, logical UI units, or surface-local pixels. Mixing frames is a
mapper bug, not a consumer bug.

### `InputTouchEvent`

`contact_id`, `phase` (`start`, `move`, `end`, `cancel`), `x`, `y`,
`coordinate_space`, `pressure`, `major`, `minor`.

### `InputGesture`

`gesture_id`, `phase` (`begin`, `update`, `end`, `cancel`), `value`
(scalar or vector for continuous gestures such as pinch / rotate /
swipe), `source_set` (which sources contributed).

### `InputAction`

`action_id`, `value` (binary or scalar — `pause` is binary,
`adjust_volume` is scalar). Actions are post-policy: the consumer
sees a semantic command stripped of source identity. Source
identity travels in a sideband for audit, replay, and policy
diagnostics — kept alongside the payload, not inside it, so
consumers stay source-neutral.

---

## 7. Interaction Groups

Input needs routing policy more than timing-group policy. Configs
declare optional interaction groups:

```yaml
interaction_groups:
  - id: player1
    target: game_runtime
    focus_policy: exclusive          # exclusive | shared | broadcast
    capture_policy: pointer_capture  # none | pointer_capture | sticky
    latency_budget_ms: 20
    repeat_policy: source            # source | mapper | disabled
    members:
      - keyboard
      - browser_gamepad
      - touch_overlay
```

### Validator rules

- `id` must be unique across the config.
- `target` must resolve to a known module.
- Every `member` must resolve to a known module that declares at least
  one `input.*` capability.
- The target or an intermediate mapper must consume the relevant input
  content type.
- `focus_policy` ∈ `{exclusive, shared, broadcast}`.
- `capture_policy` ∈ `{none, pointer_capture, sticky}`.
- `repeat_policy` ∈ `{source, mapper, disabled}`.
- `latency_budget_ms` must be an unsigned integer and ≤ 10 000.

Interaction groups compose naturally. A game runtime can have a
`player1` group with keyboard plus gamepad plus touch overlay; an
appliance can have an `operator` group with front-panel buttons plus a
rotary plus a touchscreen plus a remote service panel; a robot can
have a `pilot` group with joystick plus e-stop plus web operator
console where the e-stop preempts every other member regardless of
focus policy.

---

## 8. Roles

Four input roles sit above the surface family.

- **Source** — captures source-domain events or state. Sources do not
  encode application semantics. A GPIO button source emits binary
  edges with a `gpio.<pin>` identifier; it does not emit `play` or
  `pause`.
- **Mapper** — translates source-domain input to consumer-domain input
  or semantic actions. Mappers own machine-specific knowledge: which
  `key.symbolic.ArrowUp` becomes which platform key matrix bit, which
  long-press of which front-panel button enters service mode, which
  gesture means `next_track`.
- **Coordinator** — decides which target receives input under focus
  and capture policy. Optional for solo single-source configurations.
- **Consumer** — executes semantic commands or consumes mapped state.
  Consumers do not depend on whether input was physical, virtual,
  local, or remote.

Sources, mappers, and coordinators are replaceable. Application
modules consume the resolved surface only.

### Common mappers

- `binary_gesture_mapper`: `InputBinaryEvent` -> `InputGesture`
- `gesture_action_mapper`: `InputGesture` -> `InputAction`
- `key_action_mapper`: `InputKeyEvent` -> `InputAction`
- `touch_binary_mapper`: `InputTouchEvent` -> `InputBinaryEvent` (region buttons)
- `scalar_action_mapper`: `InputScalarEvent` / `InputScalarState` -> `InputAction`
- `gamepad_action_mapper`: `InputGamepadState` -> `InputAction`
- `vector_motion_mapper`: `InputVectorState` -> motion / pose commands
- `emulator_input_mapper`: host input -> machine-specific matrix / pad
- `panel_mapper`: buttons / touch / scalar controls -> appliance actions
- `automation_mapper`: scripted / scheduled events -> any of the above

A typical retro-platform mapper expresses itself as a binding table
that targets identifier namespaces directly:

```yaml
bindings:
  up:
    from:
      - key.symbolic.ArrowUp
      - gamepad.control.dpad_up
      - touch.region.overlay_up
    to: platform.control.up
  fire:
    from:
      - key.symbolic.Space
      - gamepad.control.south
      - touch.region.overlay_fire
    to: platform.control.fire
```

A POV hat or gamepad d-pad on the source side can land in the binding
table in one of two equivalent forms — four binary controls
(`gamepad.control.dpad_up` etc.) or a coupled scalar pair
(`gamepad.control.dpad_x` / `dpad_y` with values in `{-1, 0, +1}`).
The mapper picks the form the consumer needs. Hat is a wire encoding,
not a primitive.

An appliance mapper looks structurally identical:

```yaml
bindings:
  confirm:
    from:
      - gpio.4
      - touch.region.soft_ok
      - mqtt.topic.appliance/confirm
    to: action.confirm
  setpoint_delta:
    from:
      - sensor.knob_delta
      - touch.region.slider
      - http.route.PUT./setpoint
    to: action.adjust_temperature
  service_mode:
    from:
      - gpio.4.long_press
      - remote.support.combo
    to: action.enter_service_mode
```

The consumer modules in both cases see only `action.*`. Source variety
is fully absorbed by the binding table, which is the only place that
needs to know about identifier namespaces.

---

## 9. Telemetry

`MON_INPUT` is reserved for input source, mapper, and coordinator
emitters and follows the same line-format conventions as
`MON_PRESENTATION` and `MON_SESSION` in `monitor-protocol.md`:
space-separated `key=value` pairs after a tag, forward-compatible
field set.

High-level events:

- `source_active`, `source_inactive`
- `focus_acquired`, `focus_released`
- `capture_start`, `capture_end`
- `binding_active`, `binding_inactive`
- `event_dropped`, `state_coalesced`
- `latency_report`
- `mapper_error`

```text
MON_INPUT mod=12 event=binding_active group=player1 binding=fire source=touch_overlay
MON_INPUT mod=13 event=latency_report group=player1 p50_ms=4 p95_ms=11
```

`group=` follows the interaction-group `id` so a single grep can
follow one group across every emitter.

---

## 10. Validation Scenarios

The surface should remain stable across these scenarios. They are
chosen to span the full breadth of source variety.

### Game / emulator
Physical keyboard, browser keyboard, USB gamepad, touchscreen virtual
buttons, and a remote pad over a transport all feed the same player
mapper. The game consumes a state snapshot at frame cadence.
Platform-specific control matrices live in the mapper.

Required primitives: binary state, scalar state, vector state, key
events, virtual sources, remote sources.

### Industrial / appliance front panel
Physical buttons, a rotary encoder, a touch panel, and a remote
service panel all control the same menu. Long-press and combination
gestures are recognized without putting appliance policy into the
GPIO or touch driver. Setpoints can come from a knob, a slider, or a
remote write.

Required primitives: binary events, scalar events, touch events,
gestures, actions, network sources.

### IoT remote control
A wall button, a phone web UI, a BLE remote, and a cloud automation
all issue the same semantic action. Audit logs preserve source
identity. The control path is independent of telemetry and media
streams.

Required primitives: binary events, network sources, remote sources,
actions, identity namespaces.

### Kiosk / maintenance console
A touchscreen provides soft buttons, pointer / touch input, and text
entry. A hardware keyboard provides text input on demand. Focus
policy keeps maintenance input from leaking into the public UI.

Required primitives: touch events, pointer events, text input, key
events, interaction groups, capture policy.

### Robot / vehicle jog control
A joystick, gamepad, touchscreen pad, vector-only IMU controller, or
remote operator console can control motion. Axis state is sampled at
control-loop cadence. Emergency stop is a binary edge that must not
be coalesced or preempted.

> **Safety boundary.** Fluxor's graph-scheduled input path is not a
> substitute for hardware-rated safety interlocks. A graph-level
> e-stop binding is appropriate for application-logic stop behavior
> (release motors, exit motion mode, surface a fault, refuse new
> commands). The safety-rated stop guarantee — the one that has to
> meet IEC 61508 / ISO 13849 SIL or category ratings — must be
> enforced in hardware or by a safety-rated subsystem outside the
> graph. The same applies to kill switches, light curtains, two-hand
> controls, door interlocks, and any other safety-classified input.
> Carrying the signal on this surface is fine; relying on this
> surface as the only enforcement path is not.

Required primitives: vector state, scalar state, binary events,
interaction groups, latency telemetry.

### Smart-home / media control
Buttons, voice commands, gestures, IMU shake, remote UI, and
automation scripts all map to transport actions. The target consumes
semantic commands, not source-specific events.

Required primitives: gestures, text or voice intent, binary events,
vector events, scheduled / automation sources, actions.

### Accessibility / assistive input
A single switch, dwell pointer, eye-tracking pointer, head-pose
controller, voice command, or adaptive controller can operate the
same UI as a touchscreen or keyboard. Scanning, repeat, and dwell
windows live in a mapper or coordinator, not in the driver.

Required primitives: binary events, pointer events, vector events,
gestures, actions, interaction groups.

### Sensor-driven control
Temperature, ambient light, occupancy, and CO₂ sensors drive HVAC,
lighting, or notification logic alongside operator buttons. Sensor
events look like any other scalar source to consumers.

Required primitives: scalar events, scalar state, vector state,
binary events, actions.

### Music / instrument control
A drum kit of pads (binary edges with velocity) feeds a sampler; a
MIDI keyboard feeds a synth; CC sliders feed mix automation; foot
switches arm transport. Consumers see the same surfaces a touchscreen
overlay would produce.

Required primitives: binary events with velocity (binary + scalar
pair), scalar events, key events, gestures.

### Scanner / credential / form entry
A barcode scanner, RFID reader, magnetic stripe reader, keyboard
wedge, or on-screen keyboard all enter operator or asset identifiers.
Consumers receive text or domain actions, not transport-specific HID
reports. Source identity is preserved for audit.

Required primitives: text input, key events, binary events, actions,
identity namespaces.

### Multi-operator / remote assist
A local panel and a remote support session may both be present. Focus
and capture policy decide who controls the target. High-priority
local controls (e-stop, override) preempt remote input.

Required primitives: interaction groups, focus policy, capture
policy, remote sources, identity namespaces, latency telemetry.

### Scripted / automated input
Test fixtures, scheduled routines, gesture replay, and automation
macros drive the same surfaces a human operator would. The system
under test cannot tell the difference, which is the point.

Required primitives: any of the above, all reachable from the
`automation` and `scheduled` namespaces.

---

## 11. Scope

This page covers the input surface family, the irreducible primitives,
the identity namespace model, the capability vocabulary, the
`interaction_groups` schema and validator, the mapper / source /
coordinator / consumer roles, and the telemetry line format.

The following adjacent concerns live elsewhere or are not surfaced
through these contracts:

- **HID parsing tables, keyboard layout databases, and IME
  implementations** — driver and mapper internals.
- **Browser DOM compatibility shims** — implementation detail of
  whichever module bridges a browser to these surfaces. The surfaces
  themselves carry no DOM-specific concept.
- **Game- or appliance-specific binding defaults** — belong in mapper
  modules or graph configs, not in this surface.
- **Transport framing for remote input** — the remote-channel layer
  carries these surfaces but does not erase them, mirroring the AV
  and protocol-surface treatment.
- **Haptic / rumble feedback** — output, not input. The output peer
  surface is tracked separately; the input surface does not own its
  inverse.
- **Runtime focus / capture enforcement** — the validator gates
  manifest-level capability declarations and group structure. Live
  focus arbitration is a coordinator-module concern.
- **Hardware safety interlocks** — e-stops, kill switches, light
  curtains, two-hand controls, door interlocks, and any other
  safety-rated input must be enforced at the hardware layer or by a
  safety-rated subsystem. These surfaces can carry the signal for
  application logic, but the safety guarantee does not come from
  graph scheduling.

## Related documentation

- `architecture/av_capability_surface.md` — AV peer of this document.
- `architecture/capability_surface.md` — capability matching, content
  types, hardware-domain expansion; hosts the `input.*` capability
  names defined here.
- `architecture/protocol_surfaces.md` — protocol substrate that
  carries `input.remote` and network-namespace sources.
- `architecture/monitor-protocol.md` — `MON_*` line format conventions
  shared with `MON_INPUT`.
- `architecture/events.md` — kernel-level event signaling that
  hardware-facing input modules build on.
- `guides/input_system.md`, `guides/input_gestures.md` — guide-level
  treatment of the source / gesture / action layering.
