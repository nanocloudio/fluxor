# `midi_echo/` — MIDI surface demo (STUB)

Loops every `input::midi` 4-byte frame back from input to output port.
Exists to demonstrate the MIDI capability surface end-to-end: wiring,
manifest resolution, stack lookup, builtin loading.

**Status: stub.** Today the driver modules (`linux_alsa_midi`,
`wasm_browser_midi_in/out`, `usb_midi_host`) are placeholders that
register cleanly and drain their input channels so wired producers
don't backpressure — but no MIDI events actually flow. Each STUB
log marker fires at instantiation; see each module's `mod.rs` for
the implementation gap.

When the real drivers land, this example becomes a working echo
validator.

## Targets

- `linux.yaml` — ALSA seq client (mode: duplex)
- `wasm.yaml` — Web MIDI API (in + out as separate modules)
- `pico2w.yaml` — USB-MIDI class-compliant host (mode: duplex)

## Run

```sh
fluxor run examples/midi_echo/linux.yaml
# Watch logs for "[linux_alsa_midi] STUB" lines
```

## Related

- The wire contract lives at
  [`modules/sdk/contracts/input/midi.rs`](../../modules/sdk/contracts/input/midi.rs)
  (4-byte channel-voice frames).
- Stack resolution: [`stacks/midi.toml`](../../stacks/midi.toml).
