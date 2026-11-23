# host_image_codec

Linux-only native module. Reads a complete encoded image (JPEG, PNG, BMP,
GIF) from its `encoded` input, decodes via the `image` crate, resizes
to the target dimensions, and sends the picture on `pixels` as one
`VideoRaster` record: the region header of a whole-surface frame
(`abi::contracts::video_raster`), then the RGB565 pixels.

Pairs with `linux_display` so a hosted graph can show real images
without a board-side image codec module.

```yaml
modules:
  - name: asset
    type: host_asset_source
    path: assets/test.jpg
  - name: codec
    type: host_image_codec
    width: 480
    height: 480
    scale_mode: fit
wiring:
  - from: asset.stream
    to:   codec.encoded
  - from: codec.pixels
    to:   display.pixels
```

## Build

```
cargo build --release --bin fluxor-linux \
  --no-default-features --features host-image \
  --target aarch64-unknown-linux-gnu
```

Combined with `host-window` for a viewable window:

```
cargo build --release --bin fluxor-linux \
  --no-default-features --features host-image,host-window \
  --target aarch64-unknown-linux-gnu
```

`fluxor build` rejects YAML that declares
`type = "host_image_codec"` when the local `fluxor-linux` binary
lacks `host-image`, naming the exact `cargo build` invocation that
adds the feature.

## Configuration

Configured via `[[params]]` in [manifest.toml](manifest.toml):

| Param        | Type | Default                     | Meaning                                                                             |
|--------------|------|-----------------------------|-------------------------------------------------------------------------------------|
| `width`      | u32  | 480 (range 1..=4096)        | output frame width in pixels                                                        |
| `height`     | u32  | 480 (range 1..=4096)        | output frame height in pixels                                                       |
| `scale_mode` | enum | `fit`                       | `fit` preserves aspect with black letterbox; `stretch` fills the target dimensions  |
| `max_bytes`  | u32  | 4194304 (range 1024..=64M)  | hard cap on encoded input size before the codec gives up                            |

The record states its own surface, so the downstream display takes the
picture's extent from the stream.

## Behaviour

- Reads encoded bytes incrementally from the channel into an internal
  buffer. Decode happens once an EOF signal is received from upstream
  (channel drained for ≥ N consecutive ticks).
- Sends one frame for each image it reads, then waits for the next.
- Decode failures log once and emit nothing.
