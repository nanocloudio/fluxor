# linux_audio

Linux-only built-in audio sink. Consumes signed-16-bit little-endian
PCM (interleaved stereo by default) on its `audio` input and either
captures to a file, discards, or plays through the host audio device.

## Modes

| Mode       | Behaviour                                                                              | Build                          |
|------------|----------------------------------------------------------------------------------------|--------------------------------|
| `wav`      | append samples to a WAV file at `<path>`; header refreshed periodically                | always                         |
| `raw`      | append little-endian PCM samples directly to `<path>` (no header)                      | always                         |
| `null`     | drain and discard — useful for backpressure tests                                      | always                         |
| `playback` | stream samples to the host audio device via CPAL (ALSA on Linux)                       | `--features host-playback`     |

Build interactive support:

```
cargo build --release --bin fluxor-linux \
  --no-default-features --features host-playback \
  --target aarch64-unknown-linux-gnu
```

`fluxor build` rejects `mode = "playback"` when the local
`fluxor-linux` binary lacks `host-playback`, naming the exact `cargo
build` invocation that adds the feature.

The playback queue is capped at ~250 ms of audio. If the producer
outruns the device, oldest samples are dropped and a rate-limited
underrun warning is logged.

## Configuration

Configured via `[[params]]` in [manifest.toml](manifest.toml):

| Param         | Type | Default                          | Meaning                                                           |
|---------------|------|----------------------------------|-------------------------------------------------------------------|
| `mode`        | enum | `wav` (or stack default)         | `wav`, `raw`, `null`, or `playback`                               |
| `path`        | str  | `./target/host-audio/out.wav`    | output path (used in `wav`/`raw` modes)                           |
| `sample_rate` | u32  | 48000 (range 8000..=192000)      | sample rate (WAV header / device config)                          |
| `channels`    | u8   | 2 (range 1..=8)                  | channel count (WAV header / device config)                        |

```yaml
modules:
  - name: audio_out
    type: linux_audio
    mode: wav
    path: ./target/host-audio/out.wav
    sample_rate: 48000
    channels: 2
```

The parent directory of `path` is created on demand.

When wired through the `audio` platform stack
([stacks/audio.toml](../../../../stacks/audio.toml)) the module instance
is named `audio_out` and its params come from `platform.audio.*` in
the YAML.

## WAV file finalization

The WAV header carries total sample-data length. Since the graph runs
indefinitely, the header is written with placeholder lengths on first
write and the file is left in a state that most players accept (we
update the header lengths in place every `flush_interval` writes —
default ~1 second of audio). On graceful teardown the final lengths
are written; if the process dies abruptly, the file remains playable
up to the last flush boundary.
