# Example pipelines

This guide cross-references the canonical end-to-end examples in
`examples/`. The same playback graphs appear in four variants per
family, with **identical interaction models** but different
deployment targets. Use this page to pick the variant that matches
your hardware.

## Two playback families

Fluxor ships two canonical playback families:

| Family         | Source data       | Decoded form          | Sink           | Repo path                       |
| -------------- | ----------------- | --------------------- | -------------- | ------------------------------- |
| `image_viewer` | PNG/JPEG/GIF/BMP  | RGB565 frames          | `st7701s` LCD / `<canvas>` | see table below |
| `audio_player` | WAV/MP3/AAC       | signed 16-bit PCM      | `i2s_pio` DAC / WebAudio   | see table below |

Both families share the same module-graph shape:

```
storage  ──→  bank  ──→  codec  ──→  sink
              ↑
        navigation events  (single-button / BOOTSEL / mouse click)
```

`bank` enumerates the source directory (`dir:` + `formats:` params,
runtime-scanned via the FS contract's `FS_OPENDIR` + `FS_READDIR`
opcodes), cycles through entries on FMP commands, and opens each
file via `FS_OPEN` against the configured FS provider.

## Variant matrix

Each family has four variants. The interaction model is the same in
every column; only the deployment target changes.

### image_viewer

> single click → next image, double click → previous image

| Variant         | Target            | Source                          | Sink                          | Config                                                       |
| --------------- | ----------------- | ------------------------------- | ----------------------------- | ------------------------------------------------------------ |
| inline          | `rp2350` (lcd-4)  | two BMPs baked into config       | ST7701S 480×480 RGB parallel  | [`examples/waveshare-lcd4/image_viewer_inline.yaml`](../../examples/waveshare-lcd4/image_viewer_inline.yaml) |
| canonical SD    | `rp2350` (lcd-4)  | SPI SD card, `/images/*`         | ST7701S 480×480 RGB parallel  | [`examples/waveshare-lcd4/image_viewer.yaml`](../../examples/waveshare-lcd4/image_viewer.yaml) |
| split           | `cm5` + browser   | NVMe FAT32, `/images/*` on pi5   | browser `<canvas>` via WS     | [`examples/cm5/image_viewer.yaml`](../../examples/cm5/image_viewer.yaml) |
| full browser    | `wasm`            | `host_browser_fetch` over HTTP   | browser `<canvas>`            | [`examples/wasm/image_viewer.yaml`](../../examples/wasm/image_viewer.yaml) + [`viewer.html`](../../examples/wasm/viewer.html) |

### audio_player

> single click → toggle play/pause, double click → next track

| Variant         | Target           | Source                           | Sink                          | Config                                                       |
| --------------- | ---------------- | -------------------------------- | ----------------------------- | ------------------------------------------------------------ |
| inline          | `rp2350` (pico2w)| four sequence presets baked in   | I²S DAC                       | [`examples/pico2w/audio_player_inline.yaml`](../../examples/pico2w/audio_player_inline.yaml) |
| canonical SD    | `rp2350` (pico2w)| SPI SD card, `/audio/*`          | I²S DAC                       | [`examples/pico2w/audio_player.yaml`](../../examples/pico2w/audio_player.yaml) |
| split           | `cm5` + browser  | NVMe FAT32, `/audio/*` on pi5    | browser WebAudio via WS       | [`examples/cm5/audio_player_split.yaml`](../../examples/cm5/audio_player_split.yaml) |
| full browser    | `wasm`           | `host_browser_fetch` over HTTP   | browser WebAudio              | [`examples/wasm/audio_player.yaml`](../../examples/wasm/audio_player.yaml) + [`player.html`](../../examples/wasm/player.html) |

## Pipeline diagrams

### Bare-metal SD canonical (rp2350)

```
sd ──→ fat32 ──→ bank ──→ codec ──→ st7701s   (image_viewer)
sd ──→ fat32 ──→ bank ──→ codec ──→ mixer ──→ i2s_pio   (audio_player)
                  ↑
   button | flash_rp.events  ──→  gesture (audio only)  ──→  bank.commands
```

### Split deployment (pi5 decodes, browser renders)

```
nvme ──→ fat32 ──→ bank ──→ codec ──→ ws_stream ──→ http (ws fan-out)
                                                         │
                                                         ▼ /ws
                                                    browser <canvas>
                                                    browser WebAudio
```

The browser fetches `/`/`/api/list` from the same http listener, and
the wasm-free host page (a static HTML file served via `fs_path:`)
manages the WebSocket reception, fragment reassembly, and rendering.

### Full browser (wasm)

```
host_browser_fetch ──→ codec ──→ wasm_browser_canvas   (image_viewer)
host_browser_fetch ──→ codec ──→ wasm_browser_audio    (audio_player)
```

The host HTML (`viewer.html` / `player.html`) provides the playlist
and reboots the wasm kernel with a new URL on each navigation —
until a `host_browser_fs` provider lands, the wasm-side `bank` cannot
enumerate a browser-side directory, so cycling happens in JS.

### Inline (no storage)

```
flash_rp.stream  ──→ bank ──→ codec ──→ st7701s        (image_viewer)
gesture (synth bank) ──→ sequencer ──→ synth ──→ i2s   (audio_player)
   ↑
flash_rp.events / button.raw ──→ navigation
```

## Related guides

- [audio.md](audio.md) — audio pipeline architecture
- [codec_porting.md](codec_porting.md) — porting new audio codecs to the unified module
- [displays.md](displays.md) — display panel drivers
- [asset_banks.md](asset_banks.md) — `bank` module navigation semantics
- [input_gestures.md](input_gestures.md) — single/double/triple click mapping to FMP verbs

## Running the variants

Embedded targets (`rp2350` waveshare-lcd4, `pico2w`) and self-hosting
targets (`linux`, `qemu-virt`) build and run as a single Fluxor
graph today — `fluxor run <yaml>` for linux/qemu, `make firmware`
then flash for embedded.

The **WASM** and **split** variants need an HTTP origin to host the
browser side, which is a separate Fluxor graph. The declarative
answer is the deployment-scenario primitive proposed in
[`../../.context/rfc_deployment_scenarios.md`](../../.context/rfc_deployment_scenarios.md)
— a `*.scenario.yaml` that names the participating component graphs
and how they bind to each other, run by `fluxor run <scenario>`.
That RFC unifies the wasm-hosting and split-orchestration cases
into one primitive and removes every shell/Python wrapper currently
needed to coordinate them.

Until scenarios land, run wasm bundles by building them
(`fluxor build <yaml> -o target/wasm/<name>.wasm`) and serving the
output next to the host HTML page from any static HTTP server.
