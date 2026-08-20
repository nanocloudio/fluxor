# Displays

A display pipeline is ordinary graph wiring: producer modules emit pixel
data on a channel, and a panel driver module scans it out to the hardware.
Touch input, where the panel has it, is a separate input plane handled by
its own driver module. This guide describes both, using the in-tree panel
drivers as the reference.

Source: `modules/drivers/st7701s/`, `modules/drivers/gt911/`,
`modules/foundation/panel_surface_traits/`.

## Pipeline shape

```text
image/source -> decode/format -> panel driver -> panel
touch driver -> gesture/UI modules
```

The panel driver is a paced sink: it owns the display refresh timeline. In
the capability model it declares `video.raster`, `video.scanout`,
`display.scanout` and `presentation.clock`, so a display group that
contains one panel driver has its presentation clock without further
configuration. Upstream decode or format stages normalise content into the
driver's input contract; the driver consumes `VideoRaster` records on its
`pixels` input port.

## The ST7701S panel driver

`st7701s` drives ST7701S-based RGB parallel panels on rp2350 boards. It is
board-agnostic: pin assignments and PIO block selection come from module
parameters, so one driver supports different board layouts without code
changes.

Bring-up runs a reset pulse, writes the panel's register initialisation
sequence over bit-banged 9-bit SPI, then configures four PIO state
machines across two PIO blocks (hsync/vsync on the sync PIO, data-enable
and RGB on the data PIO) and starts DMA-fed scan-out. Frame timing is
generated entirely by the PIO hardware; the CPU only feeds pixel data into
the RGB state machine's FIFO. The backlight is enabled once the first
frame has loaded, so the panel never shows uninitialised memory.

Geometry is parameterised (`width`, `height`, both defaulting to 480); the
register initialisation sequence itself is compiled into the driver.

## Touch: the GT911 driver

`gt911` drives GT911 five-point capacitive touch controllers over I2C,
with configurable pin assignments. It selects the controller's I2C
address during the reset sequence, verifies the product ID, then binds an
event to the controller's interrupt line. On each interrupt it reads the
active touch points and writes one `TouchEvent` record per contact to its
`touch` output port (`InputEvent` content type).

Downstream interpretation (tap, gesture, UI navigation) is the consumer's
job; the driver reports contacts, not semantics. See
[input_gestures.md](input_gestures.md) for the interpretation layer.

## Declaring the surface

Fixed-function panels have a statically known viewport and input modality
set. The `panel_surface_traits` module emits one surface-traits record
describing the configured geometry, orientation and modalities, so an
application reacts to a buttoned panel the same way it reacts to a
browser window. A screenless device (display count zero) is described the
same way: the record then advertises an audio-only surface with physical
buttons.

## Design guidance

- Keep coordinate transform policy (rotation, mirroring, axis mapping)
  explicit in configuration rather than implicit in a consumer.
- Keep transport and backlight concerns inside the panel driver; upstream
  stages deal only in pixel formats.
- Prefer region updates over full-frame copies where the content allows.

## Related documentation

- [../architecture/pipeline.md](../architecture/pipeline.md) — pipeline and channel model
- [input_gestures.md](input_gestures.md) — turning input events into commands
- module READMEs under `modules/drivers/st7701s/` and `modules/drivers/gt911/`
