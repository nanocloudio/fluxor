# Input System

The input system provides the architecture for turning hardware interactions
into stable, routable control actions.

## Goal

Provide a uniform control surface across heterogeneous input sources without
embedding board-specific behavior into application modules.

## System Model

```text
hardware input -> input module -> gesture/mapper -> action consumers
```

The system emphasizes contract stability: modules consume actions, not electrical
signal details.

Implementation pattern:

```text
button/touch/bootsel module -> raw channel bytes -> gesture module -> FMP command messages -> target modules
```

Input modules emit raw byte transitions on data channels. Gesture
modules consume those transitions and emit FMP command messages on
control channels. Target modules read the FMP messages and act on
them. The kernel has no concept of "actions" — control flow is
ordinary module-to-module channel traffic.

## Core Principles

- input capture is source-specific
- action semantics are source-agnostic
- bindings and policies are configuration-driven
- control flow is decoupled from stream/data flow

This model allows the same application graph to work with different physical
control hardware.

## Action Abstraction

Actions are compact command values with well-defined meaning at the consumer
boundary.

Benefits:

- low transport overhead
- simple fan-out to multiple consumers
- predictable handling under backpressure

## Binding Model

Bindings connect actions to target capabilities through configuration.

Typical binding choices:

- transport controls (play/pause/next/prev)
- selection/navigation
- mode toggles
- service operations

The binding layer owns policy, keeping input and application modules reusable.

In current modules, gesture mappings are typically configured as command hashes
(`click`, `double_click`, `long_press`, etc.) and emitted on a control channel.

## Event Integration

Input modules may use event objects and scheduler wake semantics for low-latency
reaction to hardware changes.

See `docs/architecture/events.md` for the event architecture.

Special case: the board user button is available as virtual pin `0xFF` in the
GPIO request-input path, allowing BOOTSEL-style input without board-specific
logic in application modules.

## Design Guidance

- keep action vocabulary stable and semantic
- avoid hard-coding target-specific logic in input modules
- ensure gesture/action modules have deterministic timing windows
- separate immediate input feedback from domain-side actions when needed

## Related Documentation

- `docs/guides/input_gestures.md`
- `docs/architecture/events.md`
- `docs/architecture/abi_layers.md`
