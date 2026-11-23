# linux_display

Linux-only native display sink with frame memory. Consumes `VideoRaster`
records on its `pixels` input and either writes each presented frame as a
PPM file, shows it in a host window, or discards it. In window mode it is
also the window's input source: pointer, key and text records leave on its
`pointer`, `keys` and `text` outputs.

## Modes

| Mode     | Behaviour                                                                  | Build                       |
|----------|----------------------------------------------------------------------------|-----------------------------|
| `file`   | write each presented frame to `<path>` with `%04d` substituted from a counter | always                   |
| `null`   | take the stream and present nothing: for performance and backpressure tests | always                     |
| `window` | open a host window, show each frame, and send the window's input           | `--features host-window`    |

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
| `width`  | u32  | 480 (range 1..=4096)                     | the window's first width, in surface pixels                   |
| `height` | u32  | 480 (range 1..=4096)                     | the window's first height, in surface pixels                  |
| `scale`  | u32  | 1 (range 1..=16)                         | window pixels per surface pixel, each way, in `window` mode   |

The stream states its surface: `width` and `height` size the window until
the first frame arrives, and the window then takes the extent of the
surface in the stream.

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

## The stream

Every record on `pixels` is a 20-byte region header and that region's
pixels (`abi::contracts::video_raster`): the surface's extent, the pixel
format (RGB565 or RGBA8), a rectangle on the surface and two flags. The
display takes surfaces up to 4096 x 4096.

- A frame is one or more regions; the one flagged last ends it. The display
  holds the picture and presents at that region, so a frame of several
  regions appears whole: file mode writes one PPM a frame, never a partial
  one.
- A damage frame changes only its regions; the rest of the picture stays. A
  frame without the damage flag tiles the whole surface top to bottom.
- A record the contract refuses (a damaged header, a region outside its
  surface, a broken tiling, a surface past 4096 on an axis) is counted and
  logged, its frame is abandoned, the picture stays as last presented, and
  the stream is scanned forward for the next header of the surface in use.
- The alpha of an RGBA8 region is not kept: nothing lies behind the picture.

The PPM is written as P6 binary RGB888.

## Window input

In `window` mode the display sends what the window reports. Positions and
pixel wheel deltas are in surface pixels: window pixels divided by `scale`.

| Port      | Content type    | Records |
|-----------|-----------------|---------|
| `pointer` | `PointerEvents` | move, down, up, enter and leave for the mouse (pointer 0) and for touch contacts; wheel records, a line scroll in 1/120 detent and a smooth scroll in eighths of a surface pixel, positive toward the end and the right |
| `keys`    | `KeyEvents`     | key down and up with modifiers; `key_code` the logical key, `scan_code` the evdev code |
| `text`    | `TextEvents`    | text a key press typed, and an input method's composition and result |

A key record is flagged `KEY_TEXT` only when that key press sent a COMMIT
on `text`: text with no control character while neither Ctrl nor Meta is
held. Backspace, Enter, arrows and shortcuts arrive unflagged and are the
application's to act on. While an input method is composing, keys send no
record.

Records wait in three bounded queues of 64. A record a full channel
refuses is offered again on the next step; a queue that is itself full
drops its oldest record.

### Input method

Wire the application's `AccessibilityTree` output to the optional `tree`
input and the window allows its input method while the tree's focused node
is editable, placed at that node's bounds, and turns it off otherwise.
Without `tree`, text is what key presses type.

```yaml
wiring:
  - from: app.pixels
    to:   display.pixels
  - from: app.tree
    to:   display.tree
  - from: display.pointer
    to:   app.pointer
  - from: display.keys
    to:   app.keys
  - from: display.text
    to:   app.text
```
