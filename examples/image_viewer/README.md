# `image_viewer/` — codec + bank + display pipeline

Decode JPEG / PNG / BMP / GIF images and present them on each
platform's native display surface. Same overall graph shape across
every target:

```
<button driver> → gesture → bank.commands
                              │
                              ▼
                       bank.stream → codec → <display sink>
```

Only the button driver and display sink differ per platform. The
codec auto-detects all four image formats from the byte stream.

## Targets

- `linux.yaml` — linux producer streaming to a browser viewer (split)
- `wasm.yaml` — pure-wasm; entire kernel runs in the browser tab
- `wasm-thin.yaml` — thin browser side of the linux/cm5 split
- `cm5.yaml` — Pi 5 producer + browser viewer
- `waveshare-lcd4.yaml` — pico2w + Waveshare 4" LCD (single board)
- `waveshare-lcd4-inline.yaml` — inline-bytes variant (test fixture
  with bytes baked into the YAML)

## Gallery

`assets/test.jpg` and `assets/test2.jpg` are bundled here for the
wasm bundle. Other variants pull additional spirals from
`../test_harness/assets/` (the shared codec-coverage set).

## Run

```sh
fluxor run examples/image_viewer/wasm.yaml
# open http://localhost:9876/ in a browser; tap to cycle images
```

## Related

- [`audio_player/`](../audio_player/) — same graph shape for audio
- [`../test_harness/wasm/image_*`](../test_harness/wasm/) — codec-coverage
  fixtures (one YAML per format).
