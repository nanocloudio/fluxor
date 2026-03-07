# Input and Gestures

This guide defines how raw input signals become semantic control actions in
Fluxor graphs.

## Architectural Intent

Keep hardware sensing, gesture interpretation, and application policy as
separate layers.

- input drivers report raw interactions
- gesture modules convert patterns into commands
- application modules execute behavior

This separation keeps control behavior reusable across boards and workloads.

## Reference Flow

```text
button/touch/bootsel -> gesture -> target modules
```

Target modules include bank, transport controls, display/navigation, and service
control paths.

## Layer Responsibilities

- **Input modules**: source-specific edge/state capture
- **Gesture modules**: timing/pattern recognition and command emission
- **Targets**: domain behavior (playback, selection, toggles, mode changes)

Input modules should not encode application semantics. Gesture modules should not
contain domain-side effects.

## Command Plane Principles

- Commands are small, explicit messages.
- Gesture output should be deterministic for a given pattern window.
- Control channels should remain independent from bulk data channels.

Current message shape:

- Raw input modules usually emit byte transitions (`0x01` pressed, `0x00` released).
- Gesture modules convert those transitions into semantic command messages on
  control channels (for example `toggle`, `next`, `prev`, `long_press` mappings).

This improves responsiveness and prevents control jitter under data-plane load.

## Configuration Model

Configuration typically binds:

- input source identity
- gesture pattern mapping
- target module/control port

Gesture defaults should be treated as baseline behavior; project-specific policy
belongs in configuration.

Legacy note: previous input-action docs described kernel-side action dispatch.
Current behavior keeps gesture recognition and command emission inside modules,
with consumers reacting to command channels.

## Integration Patterns

Common patterns:

- playback control: input -> gesture -> bank/transport
- UI navigation: touch/button -> gesture -> display controller
- system control: bootsel/diagnostic input -> gesture -> service module

## Design Guidance

- Prefer semantic command names over source-specific events.
- Keep debounce and timing windows explicit and testable.
- Emit status updates where user feedback is required.

## Related Documentation

- `docs/guides/input_system.md`
- `docs/guides/music_player.md`
- `docs/architecture/events.md`
