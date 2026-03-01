# Asset Banks

Asset banks provide a uniform way to package, index, and navigate reusable media
or control assets in Fluxor graphs.

## Purpose

Banks decouple content selection from content consumption.

- Producers expose indexed assets as a stream.
- Consumers process only the selected asset payload.
- Control modules change selection through commands, not rewiring.

This model keeps playback, sequencing, and UI flows deterministic while allowing
runtime navigation.

## Architectural Model

```text
storage -> filesystem -> bank -> consumer
                         ^
                         |
                      control
```

Typical consumers include decoders, synthesizers, display modules, and effect
chains. The bank remains responsible for index selection and policy; downstream
modules remain content-focused.

## Core Concepts

- **Bank**: Logical collection of assets.
- **Cursor**: Current selection state (index + mode policy).
- **Entry**: Metadata describing one asset.
- **Locator**: Source location for reading payload bytes.

These contracts make the same control-plane behavior reusable across different
asset types.

## Selection and Control

Bank control is command-oriented.

- next/previous selection
- explicit index selection
- play/pause style control for stream-backed assets

The control source is typically gesture or UI modules, but the protocol is
agnostic to input origin.

## Modes and Progression Policy

Banks define progression policy independently of content format.

- **Once**: advance until the final entry, then hold
- **Loop**: wrap to index 0 after the final entry

This policy is evaluated on explicit commands and end-of-stream transitions.

## Data and Status Planes

Banks usually expose two outbound planes:

- **Data plane**: selected asset stream for consumers
- **Status plane**: current selection state for UI/telemetry

Separating these planes keeps display updates and media transport independent
under backpressure.

## Configuration Surface

Bank configuration typically defines:

- entry count or catalog source
- initial index
- progression mode
- optional metadata behavior for status reporting

The exact parameter encoding is module-local; architecture-level behavior is the
same across bank-backed pipelines.

## Integration Patterns

Common patterns in Fluxor:

- music player: `fat32 -> bank -> decoder -> i2s`
- instrument/tone sets: `bank -> synth`
- image galleries: `bank -> image decode -> display`

In each case, wiring remains stable while control changes only the selected
asset.

## Design Guidance

- Keep bank modules policy-focused (selection + progression), not format-heavy.
- Keep downstream modules stateless across asset boundaries when possible.
- Emit status updates on selection changes so UI modules stay synchronized.
- Treat end-of-stream as a first-class signal in bank state transitions.

## Related Documentation

- `docs/guides/music_player.md`
- `docs/guides/audio.md`
- `docs/architecture/pipeline.md`
