# Displays

A display is ordinary graph wiring: a producer sends a draw list or pixels
on a channel, and a panel driver shows them. Touch, where the panel has it,
is a separate input plane with its own driver. This guide describes both,
with the in-tree panel drivers as the reference.

Source: `modules/drivers/st7701s/`, `modules/drivers/gt911/`,
`modules/foundation/draw_raster/`, `modules/foundation/panel_surface_traits/`,
`crates/fluxor-sdk/src/video/raster/`.

## Pipeline shape

```text
application ──VideoDraw──▶ panel driver ──▶ panel
picture     ──VideoRaster─▶ panel driver (a surface the draw list places)

touch driver ──▶ gesture / UI modules
```

An application that draws its own interface sends a draw list
(`VideoDraw`: rectangles, rounded rectangles, borders, pixmaps, glyph runs;
see [av_capability_surface.md](../architecture/av_capability_surface.md)).
A panel driver that rasterises the list itself needs no framebuffer: it
keeps the last committed frame's records and draws them again every
refresh. A picture another producer draws (a decoded image, a video frame)
arrives as `VideoRaster` on its own edge, and a `SURFACE` record of the draw
list places it.

The panel driver owns the refresh timeline. It declares `video.draw`,
`video.raster`, `video.scanout`, `display.scanout` and `presentation.clock`,
so a display group with one panel driver has its presentation clock with
nothing more configured.

On a target whose display takes pixels (`linux_display`,
`wasm_browser_canvas`), `draw_raster` stands between the two: the same
rasteriser as a module, a draw list in and region rasters out. A draw list
gives the same pixels through either.

## The ST7701S panel driver

`st7701s` drives an ST7701S RGB-parallel panel from an RP2350.

| Port | Content type | |
|---|---|---|
| `draw` | `VideoDraw` | The draw list. The last committed frame is retained and drawn again every refresh. Every frame's damage is the whole surface. |
| `surface0` | `VideoRaster` | A raster a `SURFACE` record places, held whole at its own resolution. With no `draw` edge the driver shows it scaled to the panel. |

### Bands and the ring

The driver draws a refresh a band at a time: `band_rows` rows (default 16)
into one scratch band of three bytes a pixel, converted to RGB565 into a
slot of a ring of `ring_rows / band_rows` slots (default three). A DMA scan
list (`platform_dma_fd` `LIST_START`) sends one entry a band to the PIO
state machine that puts pixels on the pins: from a ring slot when the
driver armed the entry in time, and as one fill colour when it did not.
Four PIO state machines make HSYNC, VSYNC, DE and the pixel clock and never
stop. No software sits in the panel's timing.

A band can be armed until the scan is two entries short of it: the entry
being sent and the one after it are the scan's. The driver draws ahead of
the scan by up to the ring, and a slot is free again once its band has been
sent.

A new frame takes effect whole, at the first band of the first refresh
drawn after its `COMMIT`; a refresh never shows parts of two frames. Until
a frame has committed the panel is black.

### Refresh rate

`refresh_mhz` (default 60000) is the graph's choice. The driver reads the
system clock and sets the sync divider, in steps of 1/256, to the nearest
rate; a frame of `width × height` active pixels is
`(2 × width + 61) × (height + 29)` sync cycles. It refuses to construct at
a rate whose pixel clock is above `pclk_max_khz` (default 18000) or an
eighth of the system clock, which is what the pixel state machine needs.

For 480 × 480 on a 150 MHz system clock:

| `refresh_mhz` | Achieved | Divider | Pixel clock | 16-row band | Budget, system cycles a pixel |
|---|---|---|---|---|---|
| 60000 | 59.98 Hz | 4 + 208/256 | 15.6 MHz | 524 µs | 10.9 |
| 45000 | 45.00 Hz | 6 + 106/256 | 11.7 MHz | 699 µs | 14.5 |
| 40000 | 40.01 Hz | 7 + 55/256 | 10.4 MHz | 786 µs | 16.3 |

The budget is the whole of one core over a refresh, for everything a pixel
costs: walking the records, coverage, compositing and the RGB565
conversion.

### A band that is not drawn in time

A band whose entry is still fill when the scan loads it is an underrun.
The panel shows `underrun_rgb565` (default black) on those rows for that
refresh, the `underruns` counter moves, and nothing else happens: sync, the
porches and the pixel clock do not move, and an underrun is never a fault.

The driver does not chase the scan. When the scan catches it, it resumes at
the first band it can still finish (two past the one being sent, and one
further for each band period a band has been costing), and the bands
between go out as fill. So a frame that costs more than the budget shows a
share of its bands every refresh, in step with the scan, instead of
falling a refresh behind.

Two things blank bands that the driver drew in time:

- **The start.** The list starts on its first entry with the second next,
  so the first two bands of the first refresh are fill. The driver's
  `underruns` leaves those two out.
- **A flash write.** The kernel holds interrupts for a flash erase or
  program, so it first returns every armed entry of every list to fill:
  the panel shows fill for the length of the write instead of a slot a
  refresh old. Afterwards the driver arms bands as before and the picture
  is whole within one refresh. The bands a write blanked are counted in
  `underruns`; while a write lasts longer than a refresh, the scan's
  position, and with it `refreshes`, `underruns` and the measured rate,
  stand still for the whole refreshes that pass.

### Heavy frames

What a frame costs depends on what it draws. Counted on a Cortex-M33 model
for a 480 × 480 surface, drawing and conversion together, in instructions
per surface pixel:

| Frame | Instructions a pixel |
|---|---|
| Black, or one opaque background | 4.4 to 4.8 |
| A background, a rounded rectangle and a line of glyphs | 6.6 |
| 32 opaque rounded rectangles | 12.7 |
| A translucent fill of the whole surface | 17.8 |
| A background and 20 filled 48-pixel icons (path resources) | 20.7 |
| A background and a filled disc across the surface (a path) | 22.9 |
| A background and an 8-pixel stroke of that disc | 39.2 |
| A background and the 20 icons stroked a pixel wide | 63.3 |
| A background, 32 rounded rectangles, 32 borders and 400 glyphs | 30.6 |
| 1,800 a8 glyphs | 32.7 |
| A document of 721 records | 41.4 |

Paths cost by their edges more than by their area. On the same model,
with the default `path_bytes`:

| Path | Instructions |
|---|---|
| A covered pixel of a large fill (the disc) | 25 (17 with a whole band of cells) |
| A covered pixel of a 48-pixel filled icon | about 230 |
| A covered pixel of a large stroke (the 8-pixel ring) | about 600 (390 with a whole band of cells) |
| A covered pixel of a hairline-thin stroked icon | about 1,200 |
| Flattening a 256-segment circle again for a band it crosses | about 29,000 |
| Flattening a 48-pixel icon again for a band it crosses, and its edges | about 40,000 |
| Stroking a 48-pixel icon's outline again for a band it crosses | about 150,000 |

A path is flattened again in every band, and every strip of `path_bytes`,
it crosses; a curve whose control points all miss the strip is not.
For a small icon that is about a quarter of what it costs; the rest is
its edges, row by row. So on one core of the RP2350 a frame of 20 filled
icons over a background, about 4.8 million instructions, draws at about
20 refreshes a second, and the same icons stroked at about 7: give a
picture of icons the band cache, which brings a refresh that shows it
again back to a few instructions a pixel. A shape as wide as the panel
draws faster with `path_bytes` holding a whole band (30,720 at 480
wide), since it is then flattened once a band.

A cycle is not an instruction: allow about one and a half cycles for each,
more for code running from flash with a cold cache. By that measure the
first two rows are inside the 40 Hz budget; a panel of cards and text is
not, on one core, and shows part of its bands each refresh.

### The band cache

A picture that stays up for more than one refresh need not be drawn every
refresh. With `cache_bytes` set, from a picture's second refresh each band
the driver draws is also kept, as the RGB565 bytes it sent, encoded as runs
of one colour and literal pixels, while it fits; a kept band is copied into
its slot instead of being drawn, byte for byte what drawing it gives. A
`COMMIT`, or a new raster on `surface0`, drops every kept band, so a
picture's first refresh is always drawn, and a stream that commits a frame
every refresh keeps nothing and costs what it costs without a cache.

On the same Cortex-M33 model, the 480 × 480 panel of cards and text above
(30 instructions a pixel to draw) costs 3.9 a pixel from the cache, and
encoding it, once, 17.6. It keeps in 69,408 bytes of its 460,800 bytes of
RGB565; its largest band takes 3,112 bytes. `cache_bytes` holds a table of
four bytes a band and then the bands: one that does not hold a picture's
bands keeps the ones that fit, in scan order, and draws the rest.

Read it from the telemetry, or from the status line `status_s` turns on:

```text
[st7701s] measured_mhz=40006 refreshes=400 underruns=0 cached_bands=30 cache_used=69408 late_frames=0 render_us_per_band=… band_us=786
```

| Counter | Meaning |
|---|---|
| `refresh_mhz` | The rate the sync divider gives (telemetry). `measured_mhz` in the status line is the rate the scan ran at since the last line, from bands sent. |
| `refreshes` | Refreshes scanned. |
| `underruns` | Bands that went out as fill after the driver could have armed them. |
| `cached_bands`, `cache_used` | Bands of the picture shown that the cache holds, and the bytes they take (status line). |
| `late_frames` | Committed frames that waited more than one refresh to show. |
| `render_us_per_band` | The mean time the driver spent on a band over the last refresh, drawing and conversion. |

- `render_us_per_band` below `band_us` with `underruns` still: the content
  fits. The ratio is the share of its core the panel takes.
- `render_us_per_band` above `band_us`: the content does not fit. About
  `band_us / render_us_per_band` of the bands show each refresh and
  `underruns` rises by the rest, `refreshes × bands × (1 − share)`.
- `underruns` rising in bursts with `render_us_per_band` below `band_us`:
  something else held the driver's core for longer than the ring covers
  (about `ring_rows / band_rows − 2` band periods), or a flash write ran.

To fit a frame: give it a band cache if it stays up, lower `refresh_mhz`,
give the driver a core to itself,
draw fewer translucent and glyph-dense pixels, or keep text in glyph packs
the node image holds (`pack0` to `pack3`), which cost no resource memory
and no transfer.

### Memory

One heap block, sized by the params (`heap_per_param` in the manifest), and
the instance state:

| Part | Size | Default (480 × 480) |
|---|---|---|
| Ring | `ring_rows` × 960 | 46,080 |
| Scratch band | `band_rows` × 1,440 | 23,040 |
| Retained frames (two) | `frame_bytes` × 2 | 16,384 |
| Defined resources | `resource_bytes` | 16,384 |
| Read buffer | `record_bytes` | 1,024 |
| `surface0` (two buffers) | `surface_bytes` × 2 | 0 |
| Band cache | `cache_bytes` | 0 |
| Path cells | `path_bytes` | 7,680 |
| State | | about 6,400 |
| **Total** | | **about 117,100** |

The ring and scratch factors are for a row of 480 pixels, the widest the
driver takes. The smallest useful instance, bands of 8 rows with a ring of
24, two 4 KiB frames, every resource a `RES_REF` and path cells for one
row, takes 45,696 bytes of heap. The kernel keeps one table of 64 list entries for every scan list of
the node: a panel's bands (`height / band_rows`, at least three) must fit
what the table has free, or the scan fails to start and the log says so.

Path cells are the only memory a path costs beyond its resource bytes:
one `i32` a pixel of the rows a path is drawn through at a time. A path
is drawn as many rows at a time as `path_bytes` holds at the columns it
reaches, flattened again for each such strip, so the default's four rows
of a full-width path, or 40 rows of a 48-pixel icon, cost nothing in
memory whatever the path's size or its number of segments. `path_bytes`
must hold one row of `width`.

A frame larger than `frame_bytes`, more defined resource bytes than
`resource_bytes`, or a record larger than `record_bytes` is a stream fault:
the driver logs it with the byte offset, keeps showing the retained frame,
and skips to the next `STREAM`.

### Pins

The PIO programs fix the shape of a layout; the params place it:

- 16 data pins in a row from `data0_pin`, one RGB565 pixel a pixel clock;
- `de_pin`, `vsync_pin`, `hsync_pin`, `pclk_pin` in a row, in that order;
- all 20 inside GPIO 0-31, or all inside GPIO 16-47: the driver sets the
  PIO blocks' GPIO base from them;
- `cs_pin`, `sck_pin`, `sda_pin` (the 9-bit register SPI), `rst_pin` and
  `bl_pin` (active low; 255 for no backlight pin) anywhere;
- `pio_sync` and `pio_data`: two different PIO blocks.

Anything else is refused at construction with the reason.

| | Waveshare RP2350-Touch-LCD-4 (the defaults) | A 30-pin RP2350A board with a wireless chip |
|---|---|---|
| Data | 24-39 | 2-17 |
| DE, VSYNC, HSYNC, PCLK | 20, 21, 22, 23 | 18, 19, 20, 21 |
| Register SPI: CS, SCK, SDA | 18, 2, 3 | 22, 26, 27 |
| Reset | 19 | 28 |
| Backlight | 40 | none (255) |
| GPIO base | 16 | 0 |

The backlight comes on when the scan starts. `mirror_x` (default 1)
reverses the panel's source scan direction.

### Placement and edges

Give the driver a `poll` domain on a core of its own (domain 1 on RP2350):
it then draws without regard to a tick.

```yaml
execution:
  domains:
    - name: main
    - name: scan
      exec: poll

modules:
  - name: app
    domain: main
  - name: st7701s
    domain: scan
    params:
      refresh_mhz: 40000

wiring:
  - from: app.draw
    to: st7701s.draw
```

In a `tick` domain the tick must be shorter than the scan takes over
`ring_rows − band_rows` rows (1,048 µs at the 60 Hz defaults), and the
domain's other modules must leave the core the time a refresh costs; on a
shared core that means a lower `refresh_mhz`.

The `draw` edge needs nothing stated: the port asks for the `transaction`
rate class, since a frame is a few kilobytes that arrive when the picture
changes. An edge into `surface0` on an RP target must state its class:
`VideoRaster` edges are `video` class unless told otherwise, and RP buffer
arenas host no `video`-class ring.

```yaml
wiring:
  - from: decoder.pixels
    to: st7701s.surface0
    rate: transaction
```

Set `surface_bytes` to the largest surface the input will carry, in its own
format (a 240 × 240 RGB565 picture: 115,200); the driver keeps two.

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

- Send a draw list where the content is drawn (interfaces, text, charts)
  and a raster where it is a picture; a draw list costs kilobytes where a
  framebuffer costs hundreds.
- Keep coordinate transform policy (rotation, mirroring, axis mapping)
  explicit in configuration rather than implicit in a consumer.
- Keep transport and backlight concerns inside the panel driver.
- Choose the refresh rate for the content: a rate the frame fits shows
  every band; a higher one shows fill.

## Related documentation

- [../architecture/av_capability_surface.md](../architecture/av_capability_surface.md) — the draw list and raster contracts, and their facts
- [../architecture/pipeline.md](../architecture/pipeline.md) — pipeline and channel model
- [../architecture/concurrency.md](../architecture/concurrency.md) — domains and cores
- [input_gestures.md](input_gestures.md) — turning input events into commands
- module READMEs under `modules/drivers/st7701s/` and `modules/drivers/gt911/`
