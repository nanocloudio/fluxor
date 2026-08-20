# Input system

The input system turns hardware interactions into stable, routable control
actions without embedding board-specific behaviour in application modules.

Source: `modules/sdk/contracts/input/`, `modules/foundation/gesture/`,
`modules/drivers/button/`.

## System model

```text
button/touch/bootsel module -> raw channel bytes -> gesture module -> FMP command messages -> target modules
```

Input modules emit raw byte transitions on data channels. The gesture
module consumes those transitions and emits FMP command messages on
control channels. Target modules read the FMP messages and act on them.
The kernel has no concept of "actions": control flow is ordinary
module-to-module channel traffic.

The contract layer under `modules/sdk/contracts/input/` fixes the wire
shapes: button transitions, pointer, key, gamepad, MIDI and surface-traits
records each have one stable contract, and every platform's driver for a
given source produces the same shape. Modules therefore consume actions,
not electrical signal details.

## Core principles

- input capture is source-specific
- action semantics are source-agnostic
- bindings and timing policy are configuration-driven
- control flow is decoupled from stream and data flow

The same application graph works with different physical control hardware:
only the input driver at the front of the chain changes.

## Action abstraction

Actions are compact command values: FNV-1a hashes of command names carried
in fixed-size FMP messages. This keeps transport overhead low, makes
fan-out to multiple consumers cheap, and gives predictable behaviour under
backpressure.

## Binding model

Bindings connect gesture patterns to commands through module parameters
(`click`, `double_click`, `triple_click`, `long_press`), and commands to
targets through graph wiring. Typical binding choices:

- transport controls (play/pause/next/prev)
- selection and navigation
- mode toggles
- service operations

The binding layer owns policy, keeping input and application modules
reusable. [input_gestures.md](input_gestures.md) documents the gesture
module's parameters and command vocabulary.

## Event integration

Input drivers use event objects and scheduler wake semantics for
low-latency reaction to hardware changes: the `gt911` touch driver, for
example, binds an event to the controller's interrupt line rather than
polling. See [../architecture/events.md](../architecture/events.md).

The BOOTSEL button on rp boards is read by the `flash_rp` driver through
the QSPI sideband, not through GPIO; it emits the same raw transition
contract as a GPIO button, so downstream modules cannot tell the
difference.

## Design guidance

- keep the action vocabulary stable and semantic
- avoid hard-coding target-specific logic in input modules
- keep gesture timing windows explicit so recognition is deterministic
- separate immediate input feedback from domain-side actions when needed

## Related documentation

- [input_gestures.md](input_gestures.md) — the gesture layer in detail
- [../architecture/events.md](../architecture/events.md) — event architecture
- [../architecture/input_capability_surface.md](../architecture/input_capability_surface.md) — the input capability surface
- [../architecture/abi_layers.md](../architecture/abi_layers.md) — contract layering
