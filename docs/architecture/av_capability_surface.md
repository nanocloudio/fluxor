# AV Capability Surface

Fluxor's audio/video architecture rests on three layered concepts:

1. a **surface family** — typed channel content the graph carries;
2. a **capability vocabulary** — manifest-level role declarations;
3. **presentation groups** — validated topologies that bind sinks under
   one timing authority.

This document is the AV peer of `protocol_surfaces.md` (net) and
`monitor-protocol.md` (telemetry).

---

## 1. Canonical surface family

Source: `contracts/src/lib.rs` (`CONTENT_TYPES`).

AV pipelines move data on channels typed by `content_type`:

| Surface         | Carries                             | Typical producers / consumers                             |
|-----------------|-------------------------------------|-----------------------------------------------------------|
| `AudioSample`   | Decoded audio samples               | tone/sample sources, mixers; `i2s_pio`, `linux_audio`, `wasm_browser_audio` (sinks) |
| `AudioEncoded`  | Encoded audio access units          | re-encode, RTP / VoIP, storage paths                      |
| `VideoEncoded`  | Encoded video access units          | hardware decode, transcoders, broadcast packagers         |
| `VideoDraw`     | Retained / replayable draw lists    | UI / layout, dashboards, remote-desktop UI (sources); `st7701s`, `draw_raster` (consumers) |
| `VideoRaster`   | Raw pixel frames / regions          | image codecs, `draw_raster`, `wasm_browser_display_capture` (sources); `linux_display`, `wasm_browser_canvas` (sinks); `st7701s` and `draw_raster` (surfaces a draw list places) |
| `VideoScanout`  | Present-ready frames to a paced sink| compositor → HDMI / DSI sink, page-flip, vsync handoff    |
| `MediaMuxed`    | Deliberate AV / timing / container  | recording, broadcast packaging, MP4 / TS streams          |

Codec identity is not part of the surface family: a `content_type`
names a substitution surface, not a codec enumeration, so there are no
per-codec variants of the encoded surfaces. Codec identity travels
in-band, in the stream's own `STREAM` record (§1.1), and a port that
can carry only some codecs declares which as a stream fact (§2.1). See
the vocabulary admission test in `abi_layers.md`.

### 1.1 The encoded record stream

Source: `crates/fluxor-abi/src/contracts/encoded.rs` (`abi::contracts::encoded`).

`AudioEncoded` and `VideoEncoded` carry one record stream:

| Record | Layout (little-endian) |
|---|---|
| `STREAM` | `[1][codec u8][packing u8][channels u8][clock_rate u32][config_len u32][config]` |
| `UNIT` | `[2][flags u8][len u32][pts i64][pts_minus_dts i32][payload]` |
| `END` | `[3]` |

- **The stream describes itself.** Codec, packing, clock rate, channel
  count and codec configuration (AudioSpecificConfig, avcC/hvcC,
  OpusHead) arrive in `STREAM` before the first unit. A `STREAM` after
  units starts the next stream; `END` closes one and tells a decoder to
  flush.
- **Codec and packing bytes** are positions in
  `contracts::vocabulary::CODECS` (`pcmu aac mp3 opus h264 h265 vp8 pcma`) and
  `PACKINGS` (`raw framed annexb length_prefixed`). Packing is declared,
  never converted; `stream_is_valid` states which codec takes which
  packing and what configuration it requires.
- **Units may be fragmented.** An access unit is one or more `UNIT`
  records chained by `CONTINUES`, so a keyframe larger than a ring still
  crosses it. `KEY` and `DISCONTINUITY` sit on the first fragment;
  `TRUNCATED` on the last marks a unit that lost data and must be
  discarded.
- **Time** is `pts` in ticks at `clock_rate`, signed; decode time is
  `pts - pts_minus_dts`. Units arrive in decode order. Ticks are never
  normalised, which would cost a 64-bit division the 32-bit PIC targets
  cannot link.
- **Reading.** Both types are `Streamed`: a write is whole, a read is any
  split. A consumer keeps a carry buffer, calls `parse` until it answers
  `NeedMore`, and admits each record through `Sequence`. The composer
  refuses fan-in onto an encoded input, since a merge interleaves two
  record streams beyond recovery.

### 1.2 The draw list

Source: `crates/fluxor-abi/src/contracts/video_draw.rs` (`abi::contracts::video_draw`).

`VideoDraw` carries a draw list: an application that draws its own
interface sends drawing records, and a consumer rasterises them. A
consumer may retain the last committed frame's records and replay
them, a few kilobytes standing in for a framebuffer.

Every record is `[kind u8][flags u8][len u16]` and `len` payload bytes,
little-endian. Geometry is `i32` fixed point in 1/64 of a device pixel;
colours are sRGB `[r][g][b][a]`, not premultiplied.

| Group | Records |
|---|---|
| Stream control | `STREAM` (surface extent, band height, nesting depth, resource limits, the producer's generation), `END` |
| Resources | `RES_DEF` and `RES_DATA` (a glyph strike, a pixmap or a path, usable once whole and its SHA-256 matches), `RES_DROP`, `RES_REF` (bytes the consumer already holds, found by digest: a glyph pack or strike, a path or a path pack) |
| Frames and bands | `FRAME` (generation, revision, damage), `BAND`, `COMMIT` |
| Paint state | `SAVE`, `RESTORE`, `CLIP_RECT`, `CLIP_RRECT`, `TRANSLATE`, `CURRENT_COLOR` |
| Drawing | `FILL_RECT`, `FILL_RRECT`, `BORDER`, `PIXMAP`, `GLYPHS`, `SURFACE`, `FILL_PATH`, `STROKE_PATH` |

- **Frames.** Records from `FRAME` to `COMMIT` are one frame, composited
  in stream order. `damage` is the region the frame repaints.
- **Bands.** A stream with a band height is banded: inside a frame every
  drawing record sits in a `BAND`, bands cover the damage rows top to
  bottom, and the paint state resets at each. A consumer that holds one
  band of pixels, such as a panel driver scanning out, draws such a
  stream without holding a frame.
- **`SURFACE`** places the latest committed frame of one of the
  consumer's raster inputs under or among the drawing: an interface
  over a picture another producer draws. The raster arrives on its own
  edge at its own pace, and a consumer that retains the frame's records
  redraws them when that picture changes.
- **Paths.** A path is a resource: its bounding box, its command count
  and its worst-case flattened segment count, then `MOVE`, `LINE`,
  `QUAD`, `CUBIC` and `CLOSE` commands in `i32` fixed point. It is sent
  once (or held by the consumer, alone or in a path pack) and drawn by
  `FILL_PATH` (non-zero or even-odd) and `STROKE_PATH` (width, miter,
  round or bevel joins, butt, round or square caps, a miter limit) any
  number of times. Each drawing record places the path with a 2×2
  matrix in 16.16 fixed point and a translation, so one definition is
  sharp at every device pixel ratio, rotated or skewed. The consumer
  flattens curves after the transform, in device pixels, to within 3/64
  of a pixel, and strokes with the pen carried through the matrix, as
  SVG does. Coverage is the signed area each segment leaves in each
  pixel, the method font rasterisers use, in integers; the contract's
  header comment states every step, and the conformance vectors pin it.
  An icon or a gauge face costs a few bytes a frame to draw again: a
  row of icons is one path resource each and one record each a frame.
- **The current colour.** `CURRENT_COLOR` sets a colour in the paint
  state (opaque black at `FRAME` and every `BAND`, saved and restored
  with the rest). Flag `0x01` on `FILL_RECT`, `FILL_RRECT`, `BORDER`
  (all four sides), `GLYPHS`, `FILL_PATH` or `STROKE_PATH` paints in it,
  so a retained frame changes the colour of every flagged record with
  one record, and an icon takes the colour of where it is drawn.
- **Faults.** A record out of place, a value out of range, a resource
  that cannot be used or resolved, or a limit of the consumer exceeded
  is a stream fault: the consumer discards the frame in progress, keeps
  its last committed output, logs the fault and its offset, and skips to
  the next `STREAM`. `video_draw::Sequence` holds the rules, so every
  consumer refuses the same streams.

The reference rasteriser is library code (`fluxor_sdk::video::raster`):
integer arithmetic of stated width and no floating point, so one stream
gives the same bytes on every target. Its consumers:

| Module | Draws into | Retains | Takes |
|---|---|---|---|
| `st7701s` (`draw`) | the panel, a band of `band_rows` rows at a time, again every refresh | two frames of `frame_bytes`; the frame shown changes whole at a refresh | every operation; damage `full`; one surface (`surface0`); paths of up to 1,024 commands and 8,192 segments; `refresh_mhz` is its param ([displays.md](../guides/displays.md)) |
| `draw_raster` (`draw`) | region rasters on `pixels`, a band at a time, when a frame commits or a surface changes | two frames of `frame_bytes`; its consumer holds the pixels | every operation; damage `full`; two surfaces; paths of up to 4,096 commands and 16,384 segments |

Paths are drawn through a strip of cells, four bytes a pixel, that each
consumer sizes with its `path_bytes` param: as many rows of a path at a
time as fit at the columns it reaches. That is the only memory a path
takes beyond its resource bytes; `path_commands` and `path_edges` bound
the time one costs.

`video.draw` facts, declared under a port's `[ports.facts]`:

| Fact | Values | Edge rule |
|---|---|---|
| `ops` | `fill_rect fill_rrect border pixmap glyphs clip_rect clip_rrect translate surface res_ref fill_path stroke_path current_color` | producer ⊆ consumer |
| `pixmap_formats` | `rgba8 rgb565` | producer ⊆ consumer |
| `glyph_formats` | `a1 a8` | producer ⊆ consumer |
| `max_depth`, `max_resources`, `resource_bytes` | u32 | producer ≤ consumer |
| `frame_bytes` | u32 | producer's largest frame ≤ what the consumer retains; a consumer declaring 0 retains nothing |
| `band_rows` | u32 | when the consumer's `frame_bytes` is 0, the producer is banded in bands no taller than the consumer's |
| `damage` | `full partial` | producer ⊆ consumer; a consumer that replays retained records takes `full` only |
| `atomic` | `yes no` | producer ⊆ consumer; a producer that needs a frame shown whole declares `yes` |
| `refresh_mhz` | u32 | consumer ≤ producer: the refresh a consumer scans at against the band rate the producer sustains |
| `surfaces` | u32 | raster inputs the producer's `SURFACE` records name ≤ the consumer's |
| `path_commands`, `path_edges` | u32 | the most commands, and flattened segments (`edges`), of a producer's paths ≤ the consumer's; a path past the consumer's is a fault when it would become usable |

### 1.3 Region rasters

Source: `crates/fluxor-abi/src/contracts/video_raster.rs` (`abi::contracts::video_raster`).

Every record on a `VideoRaster` edge is a 20-byte header and then a
region's pixels. There is no other form: the header is the stream's own
statement of its format and geometry, and the port facts are the
build-time check on top of it.

```text
[0..4]    magic      the contract's MAGIC
[4..6]    surface_w  u16   the whole surface's extent
[6..8]    surface_h  u16
[8]       format     u8    rgb565 0, rgba8 1 (positions in RASTER_FORMATS)
[9]       flags      u8    LAST 0x01, DAMAGE 0x02; other bits zero
[10..12]  x          u16   the region's top-left
[12..14]  y          u16
[14..16]  w          u16   the region's extent, at least 1
[16..18]  h          u16
[18..20]  0          u16
[20..]    pixels     w x h x bytes per pixel, rows top to bottom
```

- **Frames.** The region flagged `LAST` ends a frame. A consumer with
  frame memory presents there, so a frame of several regions appears
  whole.
- **Damage frames and tiling frames.** With `DAMAGE` on every region,
  each updates a retained surface and pixels outside the frame's regions
  keep their content. With it on none, the regions tile the whole
  surface top to bottom in full-width bands; a whole frame in one region
  is the simplest case. One frame does not mix the two.
- **A new surface.** A change of extent or format at a frame's start is
  a new surface: the consumer reallocates, or refuses one past what it
  declared. Inside a frame it is a fault.
- **Faults.** A region outside its surface, an empty region, an unknown
  format or flag, a non-zero reserved word, a surface past the
  consumer's extent, a broken tiling or a surface change inside a frame:
  the consumer discards the record, counts it, keeps its last presented
  picture, and scans forward for the next header of the surface in use.
  `Header::decode` and `Frames` hold the rules; no producer or consumer
  indexes the header's bytes.
- **Reading.** The content type is `Streamed`: a region of a large frame
  is bigger than a small target's ring, and the header states the
  record's length.

`video.raster` facts:

| Fact | Values | Edge rule |
|---|---|---|
| `formats` | `rgb565 rgba8` | producer ⊆ consumer |
| `regions` | `damage bands` | producer ⊆ consumer |
| `width`, `height` | u32 | the producer's largest surface ≤ what the consumer accepts |

| Module | Role | Regions |
|---|---|---|
| `draw_raster` | producer | damage regions, a band at a time |
| `wasm_browser_image_codec`, `host_image_codec` | producer | one whole-surface region a decoded picture |
| `wasm_browser_display_capture` | producer | one whole-surface region a captured frame |
| `wasm_browser_canvas` | consumer | both kinds, RGB565 and RGBA8, up to its `width` x `height` |
| `linux_display` | consumer | both kinds, RGB565 and RGBA8, up to 4096 x 4096; file mode writes one PPM a presented frame |
| `draw_raster` (`surface0`, `surface1`) | consumer | both kinds, held whole for `SURFACE` records |
| `st7701s` (`surface0`) | consumer | both kinds, RGB565 and RGBA8, held whole up to `surface_bytes` for `SURFACE` records; shown scaled to the panel when `draw` is not wired. On an RP target the edge states its rate class (`rate: transaction`) |

### Where this is enforced

Wiring edges that mismatch surfaces fail the build with a content-type
mismatch error from `tools/src/config/manifest.rs::validate_wiring_types`.
The surface-ID table is `CONTENT_TYPES` in `contracts/src/lib.rs`, a
positional table whose IDs become the on-wire `content_type` byte; it
is re-exported through `tools/src/manifest.rs` so manifest parsing and
decoded-config rendering share one table.

---

## 2. Capability declarations

Source: `contracts/src/vocabulary.rs` (`CAPABILITY_NAMES`), enforced at
manifest parse time in `tools/src/manifest.rs`.

Modules declare AV-side capabilities via the manifest top-level field:

```toml
capabilities = ["video.scanout", "display.scanout", "presentation.clock"]
```

The registry covers two kinds of name. Hardware-facing names describe what the
sink *is*; service-level names describe what data shape the sink
*accepts*. A paced display sink declares both: `display.scanout`
(hardware role) and `video.scanout` (carries the VideoScanout content
type). The validator's `multihead` rule consults `display.scanout`;
content-type wiring matches against `video.scanout`.

### Hardware-facing

- `display.scanout` — paced display output with frame-boundary present
- `display.multihead` — more than one coordinated display output
- `display.scanout.protected` — scanout path for rights-managed content
- `display.capture` — produces frames of a display owned elsewhere (a
  shared screen, window, or tab), as opposed to *being* one
- `video.decode` / `video.encode` — hardware-assisted decode/encode endpoints
- `video.decode.protected` — protected decode path
- `audio.output.protected` — protected audio output path
- `audio.output.rate_trim` — sink can perform fine drift correction
- `gpu.render` — render / submit capability for GPU-backed paths
- `gpu.compute` — compute-dispatch capability for GPU-backed paths
- `presentation.clock` — sink or device can act as a group clock authority

### Service-level

- `audio.sample`, `audio.encoded`
- `video.encoded`, `video.draw`, `video.raster`, `video.scanout`
- `media.muxed`, `media.path.protected`
- `presentation.group`

The same registry also carries the input, MIDI, and transport
capability names; those are documented in
`input_capability_surface.md` and `protocol_surfaces.md`.

### 2.1 Stream facts on encoded ports

`audio.encoded` and `video.encoded` carry facts that describe the stream
on ONE port, so they are declared on the port, never in the module's
`[capability_facts]` (which refuses them): a transcoder takes AAC on one
port and emits Opus on another.

```toml
[[ports]]
name = "audio_in"
direction = "input"
content_type = "AudioEncoded"

[ports.facts]
codec = ["pcmu", "opus"]
packing = "raw"
```

| Fact | `audio.encoded` | `video.encoded` | Edge rule |
|---|---|---|---|
| `codec` | audio codecs | video codecs | producer ⊆ consumer |
| `packing` | `raw`, `framed` | `raw`, `annexb`, `length_prefixed` | producer ⊆ consumer |
| `clock_rate` | u32 | u32 | equal |
| `channels` | u32 | — | equal |
| `max_payload` | u32 | u32 | producer ≤ consumer |

Checked by `tools/src/config/validate.rs::validate_port_facts` on every
edge where both ends declare the fact; a fact one end leaves out is
unconstrained there. Every numeric fact has one rule, by name
(`vocabulary::NUMERIC_FACT_RULES`): equal, a ceiling (producer ≤
consumer), or a floor (consumer ≤ producer, as `video.draw`'s
`refresh_mhz`: a consumer's refresh against the rate the producer
sustains). A rule that reads two facts is named beside the table
(`CROSS_FACT_RULES`) and judged on every edge of its capability:
`video.draw`'s banding rule refuses a consumer that retains no frame
(`frame_bytes = 0`) any producer that is not banded in bands within the
consumer's `band_rows`, whether or not the producer declares `band_rows`.

A numeric fact may take its value from one of the module's integer
params instead of stating it:

```toml
[ports.facts]
refresh_mhz = { param = "refresh_mhz" }
```

The composer reads it per instance: what the graph sets for that param,
or the param's default. Subset rather than intersection: a demuxer that may
emit MP3 must not bind an AAC-only decoder. The runtime truth is still
the `STREAM` record — a port that carries whatever a file holds declares
no `codec` fact and validates in-band.

Capability names are matched case-insensitively at parse time and
canonicalised to lowercase in the parsed manifest. They are not
serialised into the binary `.fmod`: capabilities are compile-time
metadata for the validator and live alongside, but distinct from, the
per-port `content_type` declarations. Capabilities express role
intent; content types express data shape per edge.

---

## 3. Presentation groups

Source: `tools/src/config/validate.rs` (`validate_presentation_groups`).

A presentation group binds one or more sinks under one timing authority.
Configs declare them under the optional top-level YAML block:

```yaml
presentation_groups:
  - id: living_room
    clock_authority: hdmi_audio
    members: [hdmi_audio, lcd_panel]
    latency_budget_ms: 40
    skew_budget_ms: 8
    cutover_policy: boundary_cut          # boundary_cut | resumable | anchor_preserved
    continuity_policy: drain              # drain | anchor_preserved
    mirror_policy: independent            # independent | strict_mirror | partition (optional)
    protected: false                      # demand protected decode/output end-to-end
    multihead: false                      # require >=2 display.scanout members
```

### Validator rules

Invoked from both `fluxor build` and `fluxor build --check`.

- `id` is required and must be unique across the config.
- `members` is required and must be a non-empty list of strings; each
  member must resolve to a known module name. Non-string entries fail
  with an indexed type error.
- `clock_authority` is required, must be one of `members`, and that
  module's manifest must declare
  `capabilities = ["presentation.clock", ...]`.
- `cutover_policy` ∈ `{boundary_cut, resumable, anchor_preserved}`.
- `continuity_policy` ∈ `{drain, anchor_preserved}`.
- `mirror_policy` ∈ `{independent, strict_mirror, partition}`.
- If `protected: true`:
  - every audio member must declare `audio.output.protected`;
  - every video member must declare `display.scanout.protected` or
    `video.decode.protected`.
- If `multihead: true`, at least two members must declare
  `display.scanout`.
- `latency_budget_ms` / `skew_budget_ms` must be unsigned integers and
  ≤ 10 000.

### Worked example

A solo speaker group on Pico 2 W. Drop this block at the top level of
any YAML config that wires `i2s_pio` as the audio sink:

```yaml
presentation_groups:
  - id: speaker
    clock_authority: i2s_pio
    members: [i2s_pio]
    cutover_policy: boundary_cut
    continuity_policy: drain
```

`i2s_pio`'s manifest declares
`capabilities = ["audio.sample", "presentation.clock"]`, so the
validator accepts it as the timing authority.

---

## 4. Roles

Four AV roles sit above the surface family:

- **Clock authority** — owns the group timeline; audio sinks realise
  this role by exposing `StreamTime`
  (`crates/fluxor-abi/src/contracts/stream_clock.rs`). Examples: `i2s_pio`
  (rp2350), `linux_audio` in `playback` mode, `wasm_browser_audio`
  (browser AudioWorklet sink).
- **Presentation anchor** — owns the stable attachment to a sink or sink
  group. Stays up while backend workers move.
- **Composition / codec worker** — movable, replaceable: decode, encode,
  resample, mix, scale, composite, draw → raster.
- **Group coordinator** — manages multi-member policy: membership,
  leader selection, drift correction, degraded-mode behaviour.

Anchors and coordinators are not required for solo single-sink groups.

---

## 5. Scope

This page covers the surface family, the capability vocabulary, and the
`presentation_groups` schema and validator. The following adjacent concerns live elsewhere or are not
surfaced through these contracts:

- **Typed payload metadata** — per-buffer side-channel data on decoded
  surfaces (pixel format, stride, colourspace, damage, present epoch,
  fence) travels on whatever shape the producing module defines on its
  channel. There is no separate metadata sideband. Encoded streams carry
  their description in-band (§1.1).
- **Remote AV transport** — moving any of these surfaces across a
  remote channel is the remote-channel layer's concern; transports
  carry but do not erase these contracts.
- **Presentation telemetry** — no presentation-group monitor line is
  defined.
- **Display `StreamTime`** — audio sinks expose `StreamTime`; display
  sinks do not.
- **Presentation anchors and group coordinators** — the role
  definitions are above; concrete modules that fill those roles for
  multi-sink and remote groups are not part of this surface.
- **Runtime protected-path enforcement** — the validator gates
  manifest-level capability declarations. Trusted decode, locked
  scanout buffers, and capture denial are runtime concerns.
