# linux_display

Linux-only built-in display sink. Consumes RGB565 frames (row-major,
`width × height × 2` bytes per frame) on its `pixels` input and either
writes them as PPM files, blits them through a host window, or
discards them.

## Modes

| Mode     | Behaviour                                                                  | Build                       |
|----------|----------------------------------------------------------------------------|-----------------------------|
| `file`   | write each frame to `<path>` with `%04d` substituted from a counter        | always                      |
| `null`   | accumulate and discard — useful for performance / backpressure tests       | always                      |
| `window` | open a winit + softbuffer window and blit each frame                       | `--features host-window`    |

Build interactive support:

```
cargo build --release --bin fluxor-linux \
  --no-default-features --features host-window \
  --target aarch64-unknown-linux-gnu
```

`fluxor build` rejects `mode = "window"` when the local
`fluxor-linux` binary lacks `host-window`, naming the exact `cargo
build` invocation that adds the feature.

## Configuration

Configured via `[[params]]` in [manifest.toml](manifest.toml):

| Param    | Type | Default                                  | Meaning                                                       |
|----------|------|------------------------------------------|---------------------------------------------------------------|
| `mode`   | enum | `file` (or stack default)                | `file`, `null`, or `window`                                   |
| `path`   | str  | `./target/host-display/frame_%04d.ppm`   | PPM path template (used in `file` mode)                       |
| `width`  | u32  | 480 (range 1..=4096)                     | frame width in pixels                                         |
| `height` | u32  | 480 (range 1..=4096)                     | frame height in pixels                                        |
| `scale`  | u32  | 1 (range 1..=16)                         | integer pixel scale for `window` mode                         |

```yaml
modules:
  - name: display
    type: linux_display
    mode: file
    path: ./target/host-display/frame_%04d.ppm
    width: 480
    height: 480
```

`%04d` in the path is replaced with a zero-padded sequence number.
A path with no `%d` overwrites a single file (useful for "current
frame" preview in tools that re-read on change).

The parent directory of `path` is created on demand.

When wired through the `display` platform stack
([stacks/display.toml](../../../../stacks/display.toml)) the module
instance is named `display` and its params come from
`platform.display.*` in the YAML.

## Pixel format

v1 consumes RGB565, row-major. Each frame is exactly
`width × height × 2` bytes. The PPM is written as P6 binary RGB888 —
RGB565 is expanded per-pixel.

Producers that emit row chunks are accumulated in a scratch buffer
until a full frame's worth has arrived. Producers that emit more than
one frame's worth in a single message are split at frame boundaries.
