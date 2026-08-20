# Audio

Fluxor audio pipelines are module graphs that separate source
acquisition, decode and format conversion, and hardware output. The
same graph model covers file playback, synthesis, network audio, and
hybrid chains.

Source: `modules/foundation/format/`, `modules/drivers/i2s_pio/`,
`modules/platform/linux/linux_audio/`,
`modules/platform/wasm/wasm_browser_audio/`.

## Reference pipeline

```text
source -> bank/codec/format -> sink
```

Not every pipeline uses every stage; graphs are assembled from the
blocks a target's hardware and content require.

## Stages

**Sources** produce encoded or raw audio bytes:

- `fs_bank` and `object_bank` stream stored assets
  ([asset_banks.md](asset_banks.md))
- `mic_pio` captures from an I2S MEMS microphone through PIO on
  RP2350
- network modules deliver encoded streams over TCP, QUIC, or datagram
  transports

**Transformers** turn bytes into the PCM a sink accepts:

- codec modules decode compressed formats; they live in the spectra
  repository and splice into the graph between a source's byte stream
  and the PCM stages
- `format` normalises raw input: 8-bit unsigned or 16-bit signed,
  mono or stereo, resampled to the target rate via fixed-point linear
  interpolation. Parameters: `input_rate`, `output_rate`,
  `input_bits`, `input_channels`, `dither`.
- mixing and effects modules live in the grove repository

**Sinks** consume `AudioSample` PCM and drive output. A graph can
name a concrete driver, or request the `audio` platform stack
(`platform.audio:` in the YAML, defined in `stacks/audio.toml`),
which provides a logical `audio_out` sink and picks the driver for
the target so the same graph runs on hardware DACs and the host:

- `i2s_pio` drives an I2S DAC through PIO on RP2350
  (`data_pin`, `clock_base`, `sample_rate`)
- `linux_audio` runs on the Linux host; its `mode` selects `wav` or
  `raw` file capture, `null` (drain), or live `playback` through the
  host audio device, where the sink can also act as the presentation
  clock. Playback mode requires a `fluxor-linux` binary built with
  the `host-playback` feature; `fluxor build` rejects it otherwise.
- `wasm_browser_audio` plays through the browser's audio output

## Timing and backpressure

Audio correctness depends on the channel backpressure contracts:

- producers advance their timeline only when downstream accepts data
- transformers avoid consuming input they cannot eventually emit
- sinks handle starvation deterministically and report it

[../architecture/timing.md](../architecture/timing.md) covers the
runtime timing rules.

## Format boundaries

Keep boundaries explicit per edge: where the encoded stream ends,
where decoded PCM begins, and what frame size and sample rate each
edge carries. Treat sample rate and channel layout as graph-level
contracts rather than per-module assumptions; this avoids drift and
partial-frame carry-over across track switches.

## Switching and reset

When changing tracks or sources, cut over cleanly: end the current
stream toward the decode stages, flush stale bytes in transit, select
the new source, and let decode restart from its initial detect state.
The asset banks provide this boundary behaviour when they switch
entries ([asset_banks.md](asset_banks.md)).

## Composition patterns

- file playback: `sd -> fat32`-backed bank `-> codec -> i2s_pio`
- generated audio: control modules `-> synthesis (grove) -> sink`
- mixed inputs: two sources `-> mixer (grove) -> sink`
- network ingest: transport `-> codec -> format -> sink`

## Related documentation

- [music_player.md](music_player.md)
- [midi.md](midi.md)
- [../architecture/pipeline.md](../architecture/pipeline.md)
- [../architecture/timing.md](../architecture/timing.md)
