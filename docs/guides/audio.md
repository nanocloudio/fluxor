# Audio Guide

This guide describes the architecture of audio pipelines in Fluxor.

## Scope

Fluxor audio pipelines are module graphs that separate:

- source acquisition
- format/decode/transform stages
- hardware output

The same graph model supports file playback, synthesis, network audio, and
hybrid chains.

## Reference Pipeline

```text
source -> bank/decoder/format -> mixer/effects -> i2s
```

Not every pipeline uses every stage. Pipelines are assembled from required
functional blocks and board capabilities.

## Architectural Roles

- **Sources**: produce encoded or raw audio streams.
- **Transformers**: decode, convert, resample, mix, or shape audio.
- **Sinks**: consume PCM and drive output hardware.

Control inputs (gestures, network commands, UI events) run in a separate plane
and should not be coupled to PCM transport timing.

## Timing and Backpressure

Audio correctness depends on explicit backpressure contracts.

- Producers should only advance timeline when downstream accepts data.
- Transformers should avoid consuming input they cannot eventually emit.
- Sinks should handle starvation deterministically and report it.

See `docs/architecture/timing.md` for runtime timing rules.

## Format Boundaries

Pipelines should keep boundaries explicit:

- encoded stream boundaries (file/network)
- decoded PCM boundaries
- frame-size and sample-rate expectations per edge

This reduces drift, avoids partial-state bugs across track switches, and keeps
module contracts stable.

## Switching and Reset Semantics

When changing tracks or sources, use clean cutover semantics:

1. signal stream end to downstream decode/format stages
2. flush stale bytes in transit
3. seek/select new source
4. restart decode/transform from initial detect/parse state

This avoids mixed-stream artifacts and partial-frame carryover.

## Composition Patterns

Common Fluxor audio patterns:

- file playback: `sd -> fat32 -> bank -> decoder -> i2s`
- generated audio: `sequencer/control -> synth -> i2s`
- mixed inputs: `source A + source B -> mixer -> i2s`
- network ingest: `net -> protocol/decoder -> format -> i2s`

## Configuration Guidance

- Treat sample rate and channel layout as graph-level contracts.
- Keep control-rate channels small and atomic.
- Use mailbox or larger buffers for bulk audio frame movement when required.
- Keep module params declarative; avoid embedding policy in firmware code paths.

## Validation Checklist

- no drift under sustained backpressure
- deterministic behavior at source boundaries
- predictable startup and switch latency
- explicit handling of end-of-stream and starvation

## Related Documentation

- `docs/guides/music_player.md`
- `docs/guides/midi.md`
- `docs/architecture/pipeline.md`
- `docs/architecture/timing.md`
