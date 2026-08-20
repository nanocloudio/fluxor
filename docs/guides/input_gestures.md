# Input and gestures

Raw input signals become semantic control actions in three layers, each an
ordinary module connected by graph wiring:

- input drivers report raw interactions
- the gesture module converts patterns into commands
- application modules act on the commands

This separation keeps control behaviour reusable across boards: the same
application graph works whether the button is a GPIO switch, the BOOTSEL
button, or a browser tap.

Source: `modules/foundation/gesture/`, `modules/drivers/button/`,
`modules/sdk/contracts/input/button.rs`.

## The raw button contract

Every platform's button driver speaks the same wire shape: one byte per
debounced state transition, `0x01` pressed, `0x00` released. Producers
include `button` (an external GPIO switch, rp boards), `flash_rp` (the
BOOTSEL button, read via the QSPI sideband rather than GPIO) and the
browser button driver on wasm. Because the byte shape is identical,
downstream consumers are platform-agnostic.

The GPIO `button` driver takes its pin number, active level and pull
configuration from module parameters and emits transitions on its output
channel; it encodes no application semantics.

## The gesture module

`gesture` consumes raw transitions on its `raw` input port, performs click
counting and long-press detection, and emits FMP command messages on its
`commands` control port. Commands are FNV-1a hashes of command names, so a
command is a compact fixed-size message rather than a string.

Pattern-to-command mapping and timing windows are configuration:

```yaml
- name: gesture
  params:
    click: toggle           # single click
    double_click: next
    triple_click: prev
    long_press: long_press
    multi_click_ms: 500     # click-chain window (ms)
    long_press_ms: 1000     # hold threshold (ms)
```

The defaults are the mapping shown above. The module's manifest declares
the command vocabulary it can emit: `next`, `prev`, `toggle`, `select`,
`long_press`, `on`, `off`.

Gesture recognition and command emission live entirely inside modules.
Consumers react to command messages on control channels; there is no
kernel-side action registry or dispatch table.

## Layer responsibilities

- **Input modules**: source-specific edge and state capture. No
  application semantics.
- **Gesture module**: timing and pattern recognition, command emission. No
  domain side effects.
- **Targets**: domain behaviour (playback, selection, toggles, mode
  changes).

Keeping control channels independent from bulk data channels prevents
control jitter under data-plane load.

## Integration patterns

- playback control: button -> gesture -> bank/transport modules
- UI navigation: touch or button -> gesture -> display controller
- system control: BOOTSEL input -> gesture -> a foundation module

## Design guidance

- Prefer semantic command names (`toggle`, `next`) over source-specific
  events; the binding from pattern to command belongs in configuration.
- Keep debounce and timing windows explicit in parameters so behaviour is
  deterministic for a given pattern window.
- Emit status updates where user feedback is required.

## Related documentation

- [input_system.md](input_system.md) — the input architecture end to end
- [music_player.md](music_player.md) — a complete consumer of gesture commands
- [../architecture/events.md](../architecture/events.md) — event objects and wake semantics
