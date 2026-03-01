# Displays Guide

This guide describes the display architecture in Fluxor, including panel output,
initialization, and touch integration.

## Scope

Display pipelines in Fluxor are built from driver modules and rendering/data
modules connected by explicit graph wiring.

Typical responsibilities:

- panel transport and timing
- pixel stream formatting
- optional touch input path
- UI/control integration via status and event channels

## Architectural Model

```text
image/source -> decode/format -> display driver -> panel
                               
 touch driver -----------------> control/event modules
```

Display output and touch input are independent planes that can be composed in
one graph.

## Panel Configuration

Panel behavior is declared in configuration and applied by the display driver
module. This includes:

- resolution and orientation
- transport/pin mapping
- panel timing and initialization profile
- backlight control policy

Keeping panel identity declarative allows one driver family to support multiple
boards and displays.

## Initialization Strategy

Panel bring-up uses profile-driven init sequences rather than hard-coded board
logic in the kernel path.

This keeps driver behavior portable and simplifies support for additional panel
variants.

## Pixel Pipeline Contracts

Display pipelines should define clear contracts for:

- pixel format and ordering
- frame or region update semantics
- expected buffer ownership model (copy vs zero-copy)

Upstream decode/format stages should normalize content into the driver's expected
input contract.

## Touch Integration

Touch controllers are modeled as input producers that emit normalized touch data
for gesture or UI modules.

Recommended pattern:

- touch driver emits contact/state events
- transform/gesture layer interprets policy
- application modules consume semantic actions

Coordinate transform policy (rotation, mirroring, axis mapping) should remain
explicit in configuration.

## Performance Guidance

- Avoid unnecessary full-frame copies when region updates are sufficient.
- Keep transport/backlight concerns inside display driver boundaries.
- Use buffer sizing consistent with target frame cadence and memory budget.

## Related Documentation

- `docs/architecture/pipeline.md`
- `docs/guides/input_gestures.md`
- module-local docs under `modules/st7701s/` and `modules/gt911/`
