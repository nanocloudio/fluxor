# `audio_player/` — codec-driven audio playback

Decode WAV / MP3 / AAC from a file source and play through each
platform's native audio sink. Same overall graph shape as
[`image_viewer/`](../image_viewer/) — just substitutes the audio
sink for the display sink:

```
<button driver> → gesture → bank.commands
                              │
                              ▼
                       bank.stream → codec → <audio sink>
```

The unified PIC codec auto-detects WAV / MP3 / AAC from the byte
stream. Single-click toggles play/pause, double-click skips to next
track, long-press loops the bank.

## Targets

- `linux.yaml` — linux producer streaming to a browser player (split)
- `wasm.yaml` — pure-wasm; entire kernel runs in the browser
- `wasm-thin.yaml` — thin browser half of the linux / cm5 split
- `cm5-split.yaml` — Pi 5 producer + browser player
- `pico2w.yaml` — bare-metal pico2w with SD-FAT32 bank → I²S DAC
- `pico2w-inline.yaml` — pico2w with audio baked into the bundle
- `picow.yaml` — same shape on Pi Pico W

## Run

```sh
# Pure-wasm
fluxor run examples/audio_player/wasm.yaml
# open http://localhost:9876/, tap to play

# pico2w with SD card
make firmware TARGET=pico2w && make modules TARGET=rp2350
make flash CONFIG=examples/audio_player/pico2w.yaml
# drop audio files into /audio/ on the SD card, press BOOTSEL
```

## Related

- [`synth/`](../synth/) for **synthesized** audio (no codec, voice
  presets cycled via button).
- [`drums/`](../drums/) for TR-808-style synthesized percussion.
- [`../test_harness/{linux,wasm}/audio_*`](../test_harness/linux/) —
  codec coverage fixtures (one YAML per format × platform).
