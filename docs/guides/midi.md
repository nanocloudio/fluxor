# MIDI and Synthesis

This guide describes how Fluxor composes MIDI event handling and synthesis into
real-time audio graphs.

## Scope

Fluxor treats MIDI as control-plane data that drives synthesis or playback
modules, with PCM generation and output handled in the audio data plane.

## Reference Pipeline

```text
midi source -> midi parser/player -> synth/tone modules -> i2s
```

Asset-backed MIDI playback and live control inputs can share the same synthesis
and output stages.

## Architectural Roles

- **MIDI sources**: file-backed or live event producers
- **MIDI processors**: parse, schedule, and normalize events
- **Synthesis modules**: generate PCM from note/control state
- **Audio sinks**: output PCM through I2S or equivalent hardware drivers

## Event Semantics

MIDI events should be handled as timestamped control intents, not as raw byte
streams at every downstream boundary.

Normalization at the processor boundary keeps synthesis modules focused on voice
state and rendering.

## Voice and Timing Model

For predictable musical behavior:

- maintain explicit note-on/note-off lifecycle per voice
- apply controller changes through deterministic update rules
- align event timing with monotonic runtime clocks

Backpressure in the audio path should not silently skew control intent timing.

## Asset Integration

When MIDI data is bank-backed, selection policy remains in the bank/control
layer while MIDI processing stays format-focused.

This keeps track navigation and playback policy separate from synthesis logic.

## Configuration Guidance

- define source type and event policy explicitly
- keep synthesis parameters declarative
- separate transport control bindings from synthesis configuration

## Related Documentation

- `docs/guides/audio.md`
- `docs/guides/asset_banks.md`
- module-local docs under `modules/synth/` and `modules/sequencer/`
