# MIDI

Fluxor treats MIDI as control-plane data: event streams that drive
synthesis or playback modules, with PCM generation and output handled
in the audio data plane ([audio.md](audio.md)). Fluxor provides the
MIDI transport surface; the synthesis and sequencing modules that
consume it (synths, sequencers, MIDI routers) live in the grove
repository.

Source: `stacks/midi.toml`, `modules/sdk/contracts/input/midi.rs`,
`modules/foundation/usb_midi_host/`,
`modules/platform/linux/linux_alsa_midi/`,
`modules/platform/wasm/wasm_browser_midi_in/` and
`wasm_browser_midi_out/`.

## Transport surface

A graph requests MIDI transport declaratively; the `midi` platform
stack resolves the per-target driver:

```yaml
platform:
  midi: { direction: in }   # in | out | duplex
```

Every variant exchanges the `input::midi` contract on its `events`
ports: pre-decoded 4-byte channel-voice messages, carried on channels
with content type `MidiEvents`. The per-target drivers are:

- `linux_alsa_midi` on the Linux host: an ALSA sequencer client.
  `mode` follows the requested direction; `port_filter` matches an
  ALSA `client:port` name (empty selects the first available match);
  `client_name` names the client.
- `wasm_browser_midi_in` / `wasm_browser_midi_out` in the browser,
  over the Web MIDI API.
- `usb_midi_host` on pico2w, picow, and pi5: a class-compliant
  USB-MIDI host exposing a device's virtual cables as one logical
  port.

Status: the stack's shape and vocabulary are final, but every variant
currently resolves to a stub. Configs load and run cleanly (stubs
drain their inputs so producers do not backpressure, and log a STUB
marker on instantiation); real MIDI activity awaits each platform's
integration.

## Event handling

Handle MIDI events as timestamped control intents, not as raw byte
streams at every downstream boundary. Normalising at the processor
boundary keeps synthesis modules focused on voice state and
rendering:

- maintain an explicit note-on/note-off lifecycle per voice
- apply controller changes through deterministic update rules
- align event timing with the monotonic runtime clock

Backpressure in the audio path must not silently skew control-intent
timing; keep the MIDI control plane on its own channels rather than
coupling it to PCM transport.

## Asset-backed playback

For file-backed MIDI, an asset bank supplies track selection and
progression policy while the MIDI processing stage stays
format-focused ([asset_banks.md](asset_banks.md)). Bank-backed
playback and live input can share the same synthesis and output
stages.

## Related documentation

- [audio.md](audio.md)
- [asset_banks.md](asset_banks.md)
- [../architecture/input_capability_surface.md](../architecture/input_capability_surface.md)
