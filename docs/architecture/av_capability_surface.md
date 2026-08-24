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

| Surface         | Domain                              | Typical producers / consumers                             |
|-----------------|-------------------------------------|-----------------------------------------------------------|
| `AudioSample`   | Decoded sample-domain audio         | tone/sample sources, mixers; `i2s_pio`, `linux_audio`, `wasm_browser_audio` (sinks) |
| `AudioEncoded`  | Codec-domain audio access units     | re-encode, RTP / VoIP, storage paths                      |
| `VideoEncoded`  | Codec-domain video access units     | hardware decode, transcoders, broadcast packagers         |
| `VideoDraw`     | Retained / replayable draw lists    | UI / layout, browser, dashboard, remote-desktop UI        |
| `VideoRaster`   | Pixel-domain frames / regions       | image codecs, `wasm_browser_display_capture` (sources); `st7701s`, `linux_display`, `wasm_browser_canvas` (sinks) |
| `VideoScanout`  | Present-ready frames to a paced sink| compositor → HDMI / DSI sink, page-flip, vsync handoff    |
| `MediaMuxed`    | Deliberate AV / timing / container  | recording, broadcast packaging, MP4 / TS streams          |

Codec identity is not part of the surface family: a `content_type`
names a substitution surface, not a codec enumeration, so there are no
per-codec variants of the encoded surfaces. Codec identity travels
in-band (encoded access units and container formats are
self-describing) or as a capability fact on the wiring edge. See the
vocabulary admission test in `abi_layers.md`.

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

The registry covers two tiers. Hardware-facing names describe what the
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
  (`modules/sdk/contracts/stream_clock.rs`). Examples: `i2s_pio`
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

## 5. Telemetry

The `MON_PRESENTATION` text-line format is specified in
`monitor-protocol.md` and reserved for AV emitters. Status: design
target, not wired — no module emits these lines yet. High-level events:

- `group_active`, `member_joined`, `member_left`
- `epoch_advance`, `anchor_rebind`
- `clock_lost`, `clock_recovered`
- `latency_report`, `skew_report`
- `underflow`, `overflow`, `missed_present`
- `degraded_mode`

The format is forward-compatible: unknown event names and unknown keys
are ignored, so new transitions can be added without breaking older
monitor builds. Operator pattern: grep
`MON_PRESENTATION ... group=<id>` to follow one group across all
emitters.

---

## 6. Scope

This page covers the surface family, the capability vocabulary, the
`presentation_groups` schema and validator, and the telemetry line
format. The following adjacent concerns live elsewhere or are not
surfaced through these contracts:

- **Typed payload metadata** — per-buffer side-channel data (sample
  rate, channel layout, pixel format, stride, colourspace, damage,
  present epoch, fence) travels on whatever shape the producing module
  defines on its channel. There is no separate metadata sideband.
- **Remote AV transport** — moving any of these surfaces across a
  remote channel is the remote-channel layer's concern; transports
  carry but do not erase these contracts.
- **`MON_PRESENTATION` emitters** — the format here is the wire
  contract. Live emission belongs to clock-authority, anchor, and
  coordinator modules.
- **Display `StreamTime`** — audio sinks expose `StreamTime`; display
  sinks do not.
- **Presentation anchors and group coordinators** — the role
  definitions are above; concrete modules that fill those roles for
  multi-sink and remote groups are not part of this surface.
- **Runtime protected-path enforcement** — the validator gates
  manifest-level capability declarations. Trusted decode, locked
  scanout buffers, and capture denial are runtime concerns.
