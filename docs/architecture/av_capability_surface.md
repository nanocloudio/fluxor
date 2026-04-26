# AV Capability Surface

Fluxor's audio/video architecture rests on three layered concepts:

1. a **surface family** — typed channel content the graph carries;
2. a **capability vocabulary** — manifest-level role declarations;
3. **presentation groups** — validated topologies that bind sinks under
   one timing authority.

This document is the in-tree reference. It is the AV peer of
`protocol_surfaces.md` (net) and `monitor-protocol.md` (telemetry).

---

## 1. Canonical surface family

AV pipelines move data on channels typed by `content_type`:

| Surface         | Domain                              | Typical producers / consumers                           |
|-----------------|-------------------------------------|---------------------------------------------------------|
| `AudioSample`   | Decoded sample-domain audio         | `synth`, `mixer`, `i2s_pio` (sink), `linux_audio`       |
| `AudioEncoded`  | Codec-domain audio access units     | re-encode, RTP / VoIP, storage paths                    |
| `VideoEncoded`  | Codec-domain video access units     | hw decode, transcoders, broadcast packagers             |
| `VideoDraw`     | Retained / replayable draw lists    | UI / layout, browser, dashboard, remote-desktop UI      |
| `VideoRaster`   | Pixel-domain frames / regions       | `host_image_codec`, `codec.pixels`, `st7701s` (sink)    |
| `VideoScanout`  | Present-ready frames to a paced sink| compositor → HDMI / DSI sink, page-flip, vsync handoff  |
| `MediaMuxed`    | Deliberate AV / timing / container  | recording, broadcast packaging, MP4 / TS streams        |

`AudioOpus`, `AudioMp3`, `AudioAac`, `ImageJpeg`, `ImagePng` exist as
codec-tagged variants of the generic encoded surfaces so codec identity
can travel in `content_type` itself without a sideband channel.

The capture-side sibling, `VideoSensorRaw`, is a source-only surface
covered by the capture-side architecture and is not part of this page.

### Where this is enforced

Wiring edges that mismatch surfaces fail the build with a content-type
mismatch error from `tools/src/config.rs::validate_wiring_types`. The
surface-ID table is `tools/src/manifest.rs::CONTENT_TYPES` — a
positional table whose IDs become the on-wire `content_type` byte;
`tools/src/config.rs` mirrors it for decoded-config rendering.

---

## 2. Capability declarations

Modules declare AV-side capabilities via the manifest top-level field:

```toml
capabilities = ["video.scanout", "display.scanout", "presentation.clock"]
```

The whitelist enforced by `tools/src/manifest.rs::AV_CAPABILITY_NAMES`
covers two tiers. Hardware-facing names describe what the sink *is*;
service-level names describe what data shape the sink *accepts*. A
paced display sink declares both: `display.scanout` (hardware role)
and `video.scanout` (carries the VideoScanout content type). The
validator's `multihead` rule consults `display.scanout`; content-type
wiring matches against `video.scanout`.

### Hardware-facing

- `display.scanout` — paced display output with frame-boundary present
- `display.multihead` — more than one coordinated display output
- `display.protected_scanout` — scanout path for rights-managed content
- `video.decode` / `video.encode` — hw-assisted (en|de)code endpoints
- `video.protected_decode` — protected decode path
- `audio.protected_out` — protected audio output path
- `audio.rate_trim` — sink can perform fine drift correction
- `gpu.render` — render / submit capability for GPU-backed paths
- `presentation.clock` — sink or device can act as a group clock authority

### Service-level

- `audio.sample`, `audio.encoded`
- `video.encoded`, `video.draw`, `video.raster`, `video.scanout`
- `media.muxed`, `media.protected_path`
- `presentation.group`

Capability names are matched case-insensitively at parse time and
canonicalized to lowercase in the parsed manifest. They are *not*
serialized into the binary `.fmod` — capabilities are compile-time
metadata for the validator and live alongside, but distinct from, the
per-port `content_type` declarations: capabilities express role intent,
content types express data shape per edge.

---

## 3. Presentation groups

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

Implemented in `tools/src/config.rs::validate_presentation_groups` and
invoked from both `fluxor build` and `fluxor validate`.

- `id` must be unique across the config.
- `clock_authority` must be one of `members`, must resolve to a known
  module, and that module's manifest must declare
  `capabilities = ["presentation.clock", ...]`.
- Every entry in `members` must be a string and must resolve to a known
  module name. Non-string entries fail with an indexed type error.
- `cutover_policy` ∈ `{boundary_cut, resumable, anchor_preserved}`.
- `continuity_policy` ∈ `{drain, anchor_preserved}`.
- `mirror_policy` ∈ `{independent, strict_mirror, partition}`.
- If `protected: true`:
  - every audio member must declare `audio.protected_out`;
  - every video member must declare `display.protected_scanout` or
    `video.protected_decode`.
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

- **Clock authority** — owns the group timeline and exposes `StreamTime`.
  Examples: `i2s_pio` (rp2350), `linux_audio` in `playback` mode,
  `st7701s` (DSI panel scanout), HDMI scanout engine.
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
`monitor-protocol.md` and reserved for AV emitters. High-level events:

- `group_active`, `member_joined`, `member_left`
- `epoch_advance`, `anchor_rebind`
- `clock_lost`, `clock_recovered`
- `latency_report`, `skew_report`
- `underflow`, `overflow`, `missed_present`
- `degraded_mode`

The format is forward-compatible — unknown event names and unknown keys
are ignored — so new transitions can be added without breaking older
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
  rate, channel layout, pixel format, stride, colorspace, damage,
  present epoch, fence) travels on whatever shape the producing module
  defines on its channel. There is no separate metadata sideband.
- **Remote AV transport** — moving any of these surfaces across a
  remote channel is the remote-channel layer's concern; transports
  carry but do not erase these contracts.
- **`MON_PRESENTATION` emitters** — the format here is the wire
  contract. Live emission belongs to clock-authority, anchor, and
  coordinator modules.
- **Display `StreamTime`** — audio sinks expose `StreamTime`; display
  sinks do not yet.
- **Presentation anchors and group coordinators** — the role
  definitions are above; concrete modules that fill those roles for
  multi-sink and remote groups are not part of this surface.
- **Runtime protected-path enforcement** — the validator gates
  manifest-level capability declarations. Trusted decode, locked
  scanout buffers, and capture denial are runtime concerns.
