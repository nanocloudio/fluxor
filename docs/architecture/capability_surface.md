# Capability Surface Architecture

This document describes how hardware capabilities, module services, and application
requirements compose into validated, auto-wired graphs. It unifies the treatment
of networking, audio, display, storage, and connectivity under a single model.

## Scope

This architecture defines:

- Per-module capability declarations in `manifest.toml`
- Named ports and typed wiring
- Content-type validation during config compilation
- Hardware-domain expansion into concrete driver and foundation module graphs
- Auto-wiring via capability resolution

## The Problem

A static HTTP file server needs sockets. Sockets need a TCP/IP stack. A TCP/IP
stack needs ethernet frames. Ethernet frames need a hardware driver. But the
chain between "I need sockets" and the physical hardware varies wildly:

| Hardware | Module Chain | Count |
|----------|-------------|-------|
| cyw43 (WiFi, raw frames) | cyw43 + wifi + ip | 3 |
| enc28j60 (Ethernet, raw frames) | enc28j60 + ip | 2 |
| ch9120 (Ethernet, TCP/IP offload) | ch9120 | 1 |

The http_server module is identical in all three cases. It speaks the
`contracts/net/net_proto` framing over a channel and never touches
Ethernet frames or drivers. But the YAML config must wire completely
different module stacks depending on which board you're building for.

The same problem appears across every hardware domain:

- A synth outputs PCM. It doesn't care if PCM reaches a speaker via I2S, PDM,
  PWM, DAC, or Bluetooth A2DP.
- A photo viewer needs a display. It doesn't care if it's e-paper over SPI or
  an LCD over parallel bus.
- An MP3 player needs file data. It doesn't care if files are on local SD or
  fetched over HTTP.

## Design Principle: Locality Transparency

The module channel abstraction already makes local and remote resources
interchangeable at the data level. A module reading from a channel doesn't
know whether the bytes came from a local SD card, an HTTP GET, an NFS mount,
or an MQTT subscription. Channels are the same regardless of transport.

The capability surface makes this explicit and validatable. A module that
requires `file.data` can be satisfied by:

- `fat32` reading from local SD via SPI
- `http` fetching from a remote server via TCP socket
- `nfs_client` mounting a remote filesystem
- `mesh_bridge` proxying file data from another device

Similarly, a module that provides `audio.sample` can feed:

- `i2s` driving a local DAC via PIO
- `rtp` streaming over UDP to a remote speaker
- `bluetooth_a2dp` streaming to wireless headphones
- `mpeg_ts` muxing into an MPEG-2 transport stream

The capability model doesn't distinguish local from remote. It matches
providers to consumers by content type. The transport is an implementation
detail hidden inside modules and wiring.

This means the wiring of modules within one device is architecturally
identical to having them connect across devices. A display connected by
SPI and a display streamed via MPEG-2 transport both consume `VideoDraw`.
A file on local SD and a file on a network share both provide `file.data`.

## Architecture Overview

```
+----------------------------------------------------------------+
|                    Application Modules                          |
|        (http_server, mqtt, synth, photo_viewer, game)          |
|                                                                |
|     requires: [transport.stream] [audio.sample] [display.scanout]  |
+----------------------------------------------------------------+
                              |
                   Capability Resolution
                    (config tool, build time)
                              |
+----------------------------------------------------------------+
|                    Foundation Modules                           |
|             (ip, fat32, mp3_decoder, ble_stack)                |
|                                                                |
|     provides: [transport.stream]  requires: [net.frame]         |
|     provides: [file.data]         requires: [storage.block]     |
|     provides: [audio.sample]      requires: [audio.encoded]     |
+----------------------------------------------------------------+
                              |
                   Capability Resolution
                              |
+----------------------------------------------------------------+
|                    Driver Modules                               |
|          (cyw43, enc28j60, ch9120, sd, i2s, epaper)           |
|                                                                |
|        provides: [net.frame.wifi]                              |
|        provides: [net.frame.ethernet]                          |
|        provides: [transport.stream]  (ch9120: TCP/IP offload)  |
|        provides: [storage.block]                               |
|        provides: [audio.output]                                |
|        provides: [display.scanout]                             |
+----------------------------------------------------------------+
                              |
                      hardware: section
                       (board config)
```

Resolution happens at build time in the config tool. The kernel is unchanged.

## The Hardware Section

Drivers move from `modules:` to `hardware:`. The hardware section is the
board support declaration — it describes the physical platform independent
of the application.

```yaml
hardware:
  network:
    type: wifi
    driver: cyw43
    ssid: "${WIFI_SSID}"
    password: "${WIFI_PASSWORD}"
    security: wpa3

  audio:
    out:
      type: i2s
      data_pin: 28
      bclk_pin: 26
      lrclk_pin: 27
      sample_rate: 44100
    in:
      type: i2s
      data_pin: 22
      bclk_pin: 18
      lrclk_pin: 19
      sample_rate: 16000

  display:
    type: lcd
    driver: ili9341
    spi_bus: 0
    cs_pin: 5
    dc_pin: 6
    width: 320
    height: 240
    touch:
      driver: xpt2046
      cs_pin: 8
      irq_pin: 9

  storage:
    type: sd
    spi_bus: 0
    cs_pin: 17

  bluetooth:
    driver: cyw43
    profiles: [a2dp_sink, ble]
```

Each hardware subsection declares a physical capability. The config tool
resolves these into modules and wiring at build time.

### Subsection Types

| Subsection | Drivers | Provides |
|------------|---------|----------|
| `network` | cyw43, enc28j60, ch9120, rp1_gem, e810 | `net.frame.*`, `platform_nic_ring`, or `transport.stream` |
| `audio.out` | i2s, pdm, pwm, dac, bluetooth_a2dp | `audio.output` |
| `audio.in` | i2s, pdm, adc | `audio.capture` |
| `display` | epaper (ssd1680), oled (ssd1306), lcd (ili9341, st7789) | `display.scanout` (+ `max_refresh_hz` fact) |
| `display.touch` | xpt2046, ft6236, gt911 | `input.touch` |
| `storage` | sd, flash, eeprom | `storage.block` |
| `bluetooth` | cyw43, esp32 | `bluetooth.*` |

### Multi-Capability Chips

Some chips provide multiple capabilities. cyw43 provides WiFi frames and
Bluetooth. The CH9120 provides a stream transport directly. A chip appearing
in multiple hardware subsections is loaded once as a single module:

```yaml
hardware:
  network:
    type: wifi
    driver: cyw43           # loaded once
    ssid: "..."
  bluetooth:
    driver: cyw43           # same physical chip
    profiles: [a2dp_sink]
  audio:
    out:
      type: bluetooth_a2dp
      driver: cyw43         # audio routed through BT
```

The config tool deduplicates: one cyw43.fmod in the firmware, one module
instance at runtime. Different hardware subsections wire to different ports
on the same module.

## Manifest Fields

Current module manifests use separate fields for four different concerns:

- top-level `provides = [...]` for service names used by provider-chain
  validation
- top-level `capabilities = [...]` for presentation, audio, MIDI, and
  similar module capabilities
- `[[resources]].requires_contract = "..."` for kernel/provider contracts
  such as GPIO, SPI, PIO, channel, FS, timer, and platform DMA
- `[requires]` for target CPU features such as FPU, NEON, or MMU

Examples:

```toml
# modules/drivers/cyw43/manifest.toml
[[resources]]
requires_contract = "pio"
access = "exclusive"

[[resources]]
requires_contract = "gpio"
access = "write"

# modules/drivers/i2s_pio/manifest.toml
capabilities = ["audio.sample", "presentation.clock"]

[[resources]]
requires_contract = "pio"
access = "exclusive"

# Service-provider modules may additionally declare:
provides = ["example.service"]

# Target-feature gating uses:
[requires]
fpu = true
```

### Wildcard Matching

A requirement of `"net.frame"` matches any `net.frame.*` provider
(`net.frame.wifi`, `net.frame.ethernet`). This is how the IP module works with
any frame source without listing every possible driver.

Matching rules:
- Exact match: `"transport.stream"` matches `"transport.stream"`
- Prefix match: `"net.frame"` matches `"net.frame.wifi"`, `"net.frame.ethernet"`
- No reverse: `"net.frame.wifi"` does NOT match `"net.frame"` (a WiFi-specific
  module can't run on a generic frame provider)

## Port Content Types

Ports gain a `content_type` field that describes what data flows through them.
This enables auto-wiring and type-checked connections.

```toml
# synth/manifest.toml
[[ports]]
direction = "output"
content_type = "AudioSample"

# mp3_decoder/manifest.toml
[[ports]]
direction = "input"
content_type = "AudioEncoded"

[[ports]]
direction = "output"
content_type = "AudioSample"

# i2s/manifest.toml
[[ports]]
direction = "input"
content_type = "AudioSample"

# fat32/manifest.toml
[[ports]]
direction = "input"
content_type = "storage.block"

[[ports]]
direction = "output"
content_type = "file.data"

# sd/manifest.toml
[[ports]]
direction = "output"
content_type = "storage.block"

# epaper/manifest.toml
[[ports]]
direction = "input"
content_type = "VideoDraw"
```

### Content Type Registry

Content types describe the data format flowing through channels. They use
a hierarchical naming scheme matching the capability taxonomy.

Content-type identifiers are `UpperCamelCase` and resolve to a positional
wire byte (`contracts/src/lib.rs::CONTENT_TYPES`). The four storage surfaces
are the deliberate exception: they keep their dotted lowercase spelling, which
doubles as their semantic-surface and provider-contract name.

| Content Type | Description | Example Providers |
|-------------|-------------|-------------------|
| `AudioSample` | Raw PCM samples (interleaved stereo) | synth, mp3_decoder, mic_source |
| `AudioEncoded` | Compressed audio (MP3, AAC, WAV) | file reader, http client |
| `AudioMp3` | Specifically MP3 | file reader with MP3 files |
| `VideoDraw` | Drawing commands or framebuffer | photo viewer, UI renderer |
| `PointerEvents` | Pointer / touch coordinates and gestures | xpt2046, ft6236 |
| `storage.block` | Raw block I/O (512-byte sectors) | sd, flash |
| `file.data` | File byte stream | fat32, littlefs, http, nfs |
| `storage.namespace` | Directory-like name-keyed addressing (lookup, list, rename, delete, subscribe) | fat32, linux_fs, replicated namespace adapters |
| `storage.object` | Whole-blob byte-addressed put / get / range_get / head | content-addressed stores, replicated object stores, HTTP-backed adapters |
| `EthernetFrame` | Raw ethernet frames | cyw43, enc28j60, ip |
| `FmpMessage` | FMP messages (next/prev/toggle) | button, gesture, bank |
| `NetProto` | Unified TCP/UDP framing (`[msg_type][len][payload]`) | ip, tls, ch9120 |

The richer per-surface protocol envelopes — `NetStreamCmdV1`,
`NetStreamEvtV1`, `NetDatagramTxV1`, `NetDatagramRxV1`, `NetPacketV1`,
`NetMuxCmdV1`, `NetMuxEvtV1`, `NetSessionCtrlV1` — are appended to the wire
table as their implementations land. They correspond one-to-one with the
protocol surfaces defined in `architecture/protocol_surfaces.md`; the concrete
envelopes live under `modules/sdk/contracts/net/`. The existing TLV format
described in `architecture/network.md` is `NetProto`, the shipped compact
Stream Surface v1.

These correspond to the content types in the mesh event system
(see `architecture/mesh.md`), ensuring on-device channels and cross-device
mesh events use the same type identifiers.

## Display Capability and Refresh Facts

All display hardware provides one role capability, `display.scanout`. What
distinguishes e-paper from an LCD is not a separate capability tier but a
capability fact — chiefly `max_refresh_hz`. Touch is a separate input
capability (`input.touch`), even when the panel is physically integrated with
the display.

| Hardware | display.scanout | max_refresh_hz | input.touch |
|----------|:---:|:---:|:---:|
| e-paper (ssd1680) | Y | ~1 | |
| OLED (ssd1306) | Y | 60 | |
| LCD (ili9341) | Y | 60 | |
| LCD + touch (ili9341 + xpt2046) | Y | 60 | Y |

Application modules bind `display.scanout` and, when they need motion,
constrain the refresh fact:

| Application | Requirement | Works On |
|-------------|-------------------|----------|
| Weather station | `display.scanout` | All displays |
| Photo frame | `display.scanout` | All displays |
| Video player | `display.scanout` + `max_refresh_hz >= 30` | OLED, LCD |
| Game | `display.scanout` + `max_refresh_hz >= 30` + `input.touch` | LCD with touch only |
| Dashboard | `display.scanout` | All displays |

The config tool validates at build time:

```
hardware:
  display:
    type: epaper
    driver: ssd1680

modules:
  - name: game

Error: 'game' requires display.scanout with max_refresh_hz >= 30 but
       hardware.display (epaper/ssd1680) provides max_refresh_hz ~1.
       Compatible hardware: lcd/ili9341, lcd/st7789, oled/ssd1306.
```

## Capability Resolution

The config tool resolves the dependency graph at build time. This is
analogous to a package manager resolving dependencies — but for hardware
capabilities instead of software libraries.

### Resolution Algorithm

```
1. Collect all `requires` from user-declared modules
     http_server -> {transport.stream}
     synth -> {audio.sample} (provides, not requires)
     game -> {display.scanout (max_refresh_hz >= 30), input.touch}

2. Collect all `provides` from hardware: section
     hardware.network (wifi/cyw43) -> {net.frame.wifi}
     hardware.audio.out (i2s) -> {audio.output}
     hardware.display (lcd/ili9341) -> {display.scanout (max_refresh_hz 60)}
     hardware.display.touch (xpt2046) -> {input.touch}

3. For each unsatisfied requirement, find a provider chain:
     transport.stream <- ip (provides transport.stream, requires net.frame)
                      <- cyw43 (provides net.frame.wifi, from hardware)
     display.scanout <- ili9341 (from hardware)
     input.touch <- xpt2046 (from hardware)

4. For net.frame.wifi, also resolve link management:
     net.link.wifi <- wifi module (requires net.frame.wifi)

5. Emit resolved module list + infrastructure wiring:
     Auto-added: cyw43, wifi, ip, ili9341, xpt2046, i2s
     Auto-wired: cyw43<->ip frames, wifi<->cyw43 ctrl,
                 synth->i2s, etc.
```

### Auto-Wiring Rules

To keep behavior predictable and debuggable:

1. **Always auto-wire hardware infrastructure**: storage driver to filesystem,
   frame driver to IP stack, `AudioSample` to audio output. These are the
   "plumbing" connections that every application needs.

2. **Auto-wire when unambiguous**: if exactly one unconnected output port
   has content_type `AudioSample` and exactly one unconnected input port
   expects `AudioSample`, wire them.

3. **Error when ambiguous**: if both synth and mp3_decoder output
   `AudioSample` and i2s needs `AudioSample`, the config tool reports:
   ```
   Error: Ambiguous auto-wire for 'AudioSample' into i2s.in.
          Multiple providers: synth.out, mp3_decoder.out.
          Add explicit wiring to resolve.
   ```

4. **Never override explicit wiring**: user-declared wiring always takes
   priority over auto-wiring. If the user wires `synth.out -> effects.in`,
   the auto-wirer doesn't also try to wire `synth.out -> i2s.in`.

5. **Validate all connections**: even explicit wiring is checked against
   content types. Connecting `synth.out(AudioSample)` to `fat32.in(storage.block)`
   produces a type mismatch warning.

### What Gets Auto-Wired vs What Stays Explicit

| Category | Auto-Wired | Example |
|----------|-----------|---------|
| Hardware infrastructure | Yes | sd -> fat32, cyw43 <-> ip, AudioSample -> i2s |
| Driver control sidebands | Yes | wifi <-> cyw43 ctrl/status |
| Application data flow | No | bank -> mp3_decoder, button -> gesture |
| Application control flow | No | gesture -> bank.ctrl |

The principle: infrastructure plumbing is auto-wired. Application logic
is explicit. Users control their application graph; the tool handles the
platform substrate.

## Examples

### Static HTTP File Server

WiFi board:
```yaml
hardware:
  network:
    type: wifi
    driver: cyw43
    ssid: "${WIFI_SSID}"
    password: "${WIFI_PASSWORD}"
    security: wpa3
  storage:
    type: sd
    spi_bus: 0
    cs_pin: 17

modules:
  - name: fat32
  - name: http_server
    port: 80

wiring:
  - from: fat32.files
    to: http_server.variables
  - from: http_server.file_ctrl
    to: fat32.seek
```

Same app on CH9120 Ethernet — only hardware changes:
```yaml
hardware:
  network:
    type: ethernet
    driver: ch9120
    ip: "192.168.1.42"
    gateway: "192.168.1.1"
  storage:
    type: sd
    spi_bus: 0
    cs_pin: 17

modules:
  - name: fat32
  - name: http_server
    port: 80

wiring:
  - from: fat32.files
    to: http_server.variables
  - from: http_server.file_ctrl
    to: fat32.seek
```

Same app on enc28j60 — still just hardware:
```yaml
hardware:
  network:
    type: ethernet
    driver: enc28j60
    spi_bus: 1
    cs_pin: 9
  storage:
    type: sd
    spi_bus: 0
    cs_pin: 17

modules:
  - name: fat32
  - name: http_server
    port: 80

wiring:
  - from: fat32.files
    to: http_server.variables
  - from: http_server.file_ctrl
    to: fat32.seek
```

The `modules:` and `wiring:` sections are identical across all three boards.

### Resolved module graphs

The config tool resolves these hardware sections into different module
stacks, all providing the same `transport.stream` capability to http_server:

**WiFi (cyw43):**
```
Auto-added: cyw43, wifi, ip, sd
Auto-wired: sd.out -> fat32.in
            cyw43.out -> ip.in
            ip.out -> cyw43.in
            wifi.out -> cyw43.ctrl
            cyw43.out[3] -> wifi.in
```

**Ethernet (enc28j60):**
```
Auto-added: enc28j60, ip, sd
Auto-wired: sd.out -> fat32.in
            enc28j60.out -> ip.in
            ip.out -> enc28j60.in
```

**Ethernet (ch9120):**
```
Auto-added: ch9120, sd
Auto-wired: sd.out -> fat32.in
```

### Music Player

```yaml
hardware:
  audio:
    out:
      type: i2s
      data_pin: 28
      bclk_pin: 26
      lrclk_pin: 27
  storage:
    type: sd
    spi_bus: 0
    cs_pin: 17

modules:
  - name: fat32
  - name: mp3_decoder
  - name: bank
  - name: button
    pin: 14
  - name: gesture

wiring:
  - from: button.out
    to: gesture.in
  - from: gesture.out
    to: bank.ctrl
  - from: fat32.out
    to: bank.in
  - from: bank.out
    to: mp3_decoder.in
```

Auto-resolved:
```
Auto-added: sd, i2s
Auto-wired: sd.out -> fat32.in
            mp3_decoder.out(AudioSample) -> i2s.in(AudioSample)
```

Same player with PWM audio — one hardware line changes:
```yaml
hardware:
  audio:
    out:
      type: pwm
      pin: 15
  # ... rest identical
```

Same player streaming over Bluetooth A2DP:
```yaml
hardware:
  audio:
    out:
      type: bluetooth_a2dp
      driver: cyw43
  bluetooth:
    driver: cyw43
  # ... rest identical
```

The mp3_decoder still outputs `AudioSample`. The Bluetooth A2DP module
consumes `AudioSample` exactly like i2s does.

### Synthesizer with Effects

```yaml
hardware:
  audio:
    out:
      type: i2s
      data_pin: 28
      bclk_pin: 26
      lrclk_pin: 27

modules:
  - name: sequencer
  - name: synth
  - name: effects

wiring:
  - from: sequencer.out
    to: synth.in
  - from: synth.out
    to: effects.in

data:
  melody_a:
    type: sequence
    notes: [60, 62, 64, 65, 67, 69, 71, 72]
    note_length: 200
```

Auto-resolved:
```
Auto-added: i2s
Auto-wired: effects.out(AudioSample) -> i2s.in(AudioSample)
```

The auto-wirer sees that `effects.out` provides `AudioSample` and `i2s.in`
requires `AudioSample`, with no other `AudioSample` providers having unconnected
outputs. Unambiguous, so it wires automatically.

### Network File Player (Locality Transparency)

```yaml
hardware:
  network:
    type: wifi
    driver: cyw43
    ssid: "..."
    password: "..."
  audio:
    out:
      type: i2s
      data_pin: 28
      bclk_pin: 26
      lrclk_pin: 27

modules:
  - name: http
    host_ip: "192.168.1.100"
    port: 80
    path: "/music/song.mp3"
  - name: mp3_decoder

wiring:
  - from: http.out
    to: mp3_decoder.in
```

Same pipeline as the SD-based music player, but `file.data` comes from
HTTP instead of fat32. mp3_decoder doesn't know or care. The channel
carries bytes either way.

### MPEG-2 Transport Stream (Remote Display)

A module that renders frames locally can also stream them:

```yaml
hardware:
  network:
    type: wifi
    driver: cyw43
    ssid: "..."
    password: "..."

modules:
  - name: renderer
  - name: mpeg2_ts
    dest_ip: "192.168.1.200"
    dest_port: 5004

wiring:
  - from: renderer.out
    to: mpeg2_ts.in
```

The renderer provides `VideoDraw` on its output. When wired to a local
display driver, pixels go to SPI. When wired to mpeg2_ts, the same pixels
get packetized into MPEG-2 transport and sent over UDP. The renderer module
is unchanged.

### Weather Station on E-Paper

```yaml
hardware:
  display:
    type: epaper
    driver: ssd1680
    spi_bus: 0
    cs_pin: 5
    dc_pin: 6
    busy_pin: 7
    width: 296
    height: 128
  network:
    type: wifi
    driver: cyw43
    ssid: "..."
    password: "..."

modules:
  - name: weather_station
    update_interval: 3600
    api_url: "http://api.weather.com/..."
```

Auto-resolved:
```
Auto-added: cyw43, wifi, ip, ssd1680
Auto-wired: cyw43<->ip, wifi<->cyw43
            weather_station.out(VideoDraw) -> ssd1680.in(VideoDraw)
```

Validated: weather_station requires `display.scanout`, ssd1680 provides it.

### Game on LCD with Touch

```yaml
hardware:
  display:
    type: lcd
    driver: ili9341
    spi_bus: 0
    cs_pin: 5
    dc_pin: 6
    width: 320
    height: 240
    touch:
      driver: xpt2046
      cs_pin: 8
      irq_pin: 9

modules:
  - name: game
```

Auto-resolved:
```
Auto-added: ili9341, xpt2046
Auto-wired: game.out(VideoDraw) -> ili9341.in(VideoDraw)
            xpt2046.out(PointerEvents) -> game.in(PointerEvents)
```

Validated: game requires `display.scanout` (with `max_refresh_hz >= 30`) and
`input.touch`. ili9341 provides `display.scanout` at 60 Hz, xpt2046 provides
`input.touch`.

If the user tried this on e-paper:
```
Error: 'game' requires display.scanout with max_refresh_hz >= 30 but
       hardware.display (epaper/ssd1680) provides max_refresh_hz ~1.
```

## Capability Taxonomy

### Hardware Capabilities (from hardware: section)

```
net.frame.wifi      — raw WiFi ethernet frames (cyw43, esp32)
net.frame.ethernet  — raw wired ethernet frames (enc28j60, rp1_gem, e810)
bluetooth.ble       — Bluetooth Low Energy (cyw43, esp32)
bluetooth.a2dp      — Bluetooth audio streaming (cyw43)
audio.output        — physical audio output (i2s, pdm, pwm, dac, bt_a2dp)
audio.capture       — physical audio input (i2s_in, pdm_in, adc)
display.scanout     — paced display output (epaper, oled, lcd);
                      the max_refresh_hz fact distinguishes static from motion
input.touch         — touch input (xpt2046, ft6236, gt911)
storage.block       — raw block I/O (sd, flash, eeprom)
pio                 — programmable I/O (RP2350 PIO peripheral)
spi                 — SPI bus access
i2c                 — I2C bus access
gpio                — GPIO pin access
uart                — UART serial access
```

### Service Capabilities (from module manifests)

```
transport.stream    — byte-stream transport (provided by ip, ch9120, linux_net)
net.link.wifi       — WiFi connection management (provided by wifi)
file.data           — file byte stream (provided by fat32, littlefs, http)
storage.namespace   — directory-like name-keyed surface (provided by fat32, linux_fs, namespace adapters)
storage.object      — whole-blob byte-addressed surface (provided by content-addressed and replicated object adapters)
audio.sample        — raw PCM audio samples (provided by synth, decoder, mic)
audio.encoded       — compressed audio stream (provided by file reader, http)
video.draw          — drawing commands / framebuffer (provided by renderer)
input.touch         — touch coordinates, carried as PointerEvents (provided by touch driver)
selection           — item selection (project-local provides name, e.g. bank)
replication.state_machine — replicated commit log + apply pipeline
                      (committed-entry stream, snapshot install/export,
                      apply reset) (provided by clustor)
```

`replication.state_machine` names the apply-pipeline / state-machine
surface a consumer attaches to for replicated commit-and-apply: a
per-entry committed stream, an early "accepted into WAL, here's its
index" echo, a quorum-durability notice, bidirectional snapshot
install/export callbacks, and an apply-pipeline reset signal. It sits
one layer above the storage read/write/durability surfaces — the
early-ack echo, snapshot callbacks for apply-derived state, and the
reset signal have no equivalent in the `storage.namespace` + `event.log`
pattern (see `storage_capability_surface.md` §4), which correctly stays
at the storage layer. The full seven-primitive contract lives with its
single current provider, clustor, at
`../clustor/docs/architecture/substrate_capability_surface.md`; only the
surface name is canonicalized here. A consumer requires it by name
through the same string-matched capability resolution as any other
service capability (the resolver wires it to whichever module provides
it) — not through the `[requires]` table, which carries typed CPU/board
features. This gives the surface a documented home should a second
provider (a single-node WAL stand-in or a managed-Raft service) ever
ship.

### Storage Capability Surfaces

Storage capability is decomposed into four canonical surfaces plus
one orthogonal axis. The full architecture is in
`storage_capability_surface.md`; the names belong in this taxonomy:

```
storage.block       — raw block I/O (512-byte sectors). Drivers
                      (sd, flash, nvme) provide; filesystems consume.
file.data           — byte-stream file access (open, read, seek,
                      stat, write, fsync). fat32 / linux_fs / http
                      provide; player / viewer modules consume.
storage.namespace   — name-keyed directory surface (lookup, stat,
                      list, rename, delete, subscribe(prefix)).
                      fat32 provides readonly; write-capable adapters
                      can provide the full surface.
storage.object      — whole-blob byte-addressed surface (put, get,
                      head, range_get, delete). Multipart upload
                      composes via the event.log pattern rather
                      than living in the surface itself.
```

The orthogonal axis is `contracts::fence::Fence` — every storage op
that completes successfully returns the strongest fence it actually
achieved: `Volatile`, `LocalDurable { device_id }`,
`ReplicatedDurable { source, commit_index, epoch, quorum, witness }`,
`ContentHashed { algorithm, digest }`,
`RevisionMonotone { source, revision }`,
`ViewConsistent { source, revision }`. Source-tagged variants make
revision and commit_index comparisons honest — revision 10 of
namespace A does not dominate revision 5 of namespace B because the
sources differ. `ReplicatedDurable.commit_index` carries the
monotone log position within an epoch, and `witness` equality
distinguishes forks at the same `(source, epoch, commit_index)`.
Providers may share a surface name and differ in fence strength;
the fence is what makes substitution honest. See
`storage_capability_surface.md` for the full rationale and the
leased-`Handle` contract.

The `event.log` content-type pattern (not a surface) reuses these
primitives: a `storage.namespace` entry resolves to an Event stream
with monotone per-source sequence (mesh.md §5) and the appropriate
fence (`ReplicatedDurable` for cluster-committed entries). Local WALs,
replicated commit logs, and generic append logs all reduce to this
pattern without a separate capability surface.

### Protocol Surface Capabilities

Transport surfaces are capabilities, one per surface defined in
`architecture/protocol_surfaces.md`:

```
transport.packet                 — packet-preserving network surface
transport.stream                 — byte-stream transport endpoint
transport.stream.tcp             — TCP byte-stream transport
transport.stream.secure          — secured byte-stream transport (post-TLS)
transport.datagram               — datagram transport endpoint
transport.datagram.udp           — UDP datagram transport
transport.datagram.secure        — secured datagram transport (post-DTLS)
transport.mux                    — multiplexed session transport
transport.mux.quic               — QUIC transport
security.tls13.stream            — TLS 1.3 stream security layer
security.dtls13.datagram         — DTLS 1.3 datagram security layer
```

The `net_proto` contract — the compact TCP/UDP multiplexed framing, content
type `NetProto` — is exposed through `transport.stream` and
`transport.datagram`. A module depends on the explicit transport surface it
actually uses.

### Continuity Role Capabilities

Architectural roles from `architecture/protocol_surfaces.md`:

```
transport.anchor.stream          — stable stream-facing transport anchor
transport.anchor.stream.secure   — stable secure stream-facing transport anchor
transport.anchor.datagram        — stable datagram-facing anchor
transport.anchor.mux             — stable multiplexed-session anchor
session.worker                   — movable session / application worker
session.directory                — placement and continuity metadata service
session.resume                   — resumable session state support
session.handoff                  — opaque export / import handoff support
```

These are manifest-level capability names. They do not consume bits in
the `required_caps` device-class mask; they participate in the same
string-matched capability resolution as `file.data` or `audio.sample`.

### Capability Inheritance

Capabilities form a hierarchy. A requirement for a parent capability is
satisfied by any child:

```
net.frame           — matches net.frame.wifi, net.frame.ethernet
bluetooth           — matches bluetooth.ble, bluetooth.a2dp
audio.encoded       — matches audio.encoded.mp3, audio.encoded.aac
transport.stream    — matches transport.stream.tcp, transport.stream.secure
transport.datagram  — matches transport.datagram.udp, transport.datagram.secure
transport.mux       — matches transport.mux.quic
```

`display.scanout` does not graduate by name — every display provides it, and
the `max_refresh_hz` fact (not a child capability) is what a motion consumer
constrains.

The reverse does NOT hold. A module requiring `net.frame.wifi` specifically
cannot be satisfied by `net.frame.ethernet`, and a module requiring
`transport.stream.secure` is not satisfied by plain `transport.stream`.

**Security is orthogonal.** `transport.stream` is not equivalent to
`transport.stream.secure`. `tls` upgrades plain stream to secure stream;
`dtls` upgrades plain datagram to secure datagram. Secure anchors may
be expressed either as composed stacks (`tls` in front of
`transport.anchor.stream`) or as explicit secure-anchor capabilities
(`transport.anchor.stream.secure`) where that makes graph validation
clearer.

**Selection policy.** Transport insertion and continuity role insertion
must be explicit. The resolver may auto-wire infrastructure where
unambiguous, but it must not silently insert TLS/DTLS, silently invent
anchors, or silently treat `resumable` as `edge_anchored`. Continuity
behaviour is policy, not incidental broad matching.

## Relationship to Architecture

### Network Architecture (network.md)

`network.md` describes the frame provider vs transport provider
distinction. This document generalizes that pattern: frame providers and
transport providers are both instances of the capability model. The `provides`
field in manifests formalizes that contract.

The NetIF contract (frame channels between drivers and IP) becomes an
auto-wired infrastructure connection resolved from the hardware section.

### Protocol Surfaces (protocol_surfaces.md)

`protocol_surfaces.md` defines the four protocol surfaces (stream,
datagram, packet, multiplexed session), the five session continuity
classes, and the anchor / worker / directory roles. The `transport.*`,
`session.*`, and `net.*` names in this document are the capability and
content-type vocabulary that protocol_surfaces.md relies on. Continuity
classes are declared in graph configs and validated against the
capabilities declared here.

### Mesh Architecture (mesh.md)

The mesh content types (`audio/pcm`, `application/cbor`, etc.) align with
the port content types in this document. On-device channels and cross-device
mesh events use the same type identifiers, reinforcing locality transparency.

Mesh objects declare `accepts` and `emits` content types. Module manifests
declare port `content_type`. These are the same concept at different scales:
ports are intra-device, mesh bindings are inter-device.

### HAL Architecture (hal_architecture.md)

The HAL provides kernel-level primitives (GPIO, SPI, PIO, I2C). The
hardware section in this document builds on top of these — declaring which
primitives a driver needs. A driver that requires `spi` and `gpio` uses
the HAL's SPI and GPIO primitives at runtime.

### Pipeline Architecture (pipeline.md)

The graph runner, channel types, and module execution model remain the runtime
execution substrate. Capability resolution adds modules and wiring edges before
the runner sees it. From the runner's perspective, auto-added modules are
no different from user-declared ones.

## Implementation

Capability resolution runs in the `fluxor` config tool at build time.
The runtime executes the resolved graph; the kernel itself has no
knowledge of capabilities or content types.

### Manifest Schema

`manifest.toml` for each module declares service providers, presentation
or media capabilities, hardware contracts, and target CPU requirements
with separate fields:

```toml
provides = ["example.service"]
capabilities = ["audio.sample", "presentation.clock"]

[[resources]]
requires_contract = "pio"
access = "exclusive"

[requires]
fpu = true
```

Modules without these fields participate only in explicit wiring and
the capabilities inferred from their ports and stack expansion.

### Port Content Types

Ports in `manifest.toml` declare their `content_type`:

```toml
[[ports]]
name = "out"
direction = "output"
content_type = "AudioSample"
```

The config tool uses content types for validation and for unambiguous
auto-wiring matching.

### Hardware Section

The config schema's `hardware:` section maps to a built-in lookup table
of driver bundles. Each (subsection, driver) pair resolves to a module
list and a wiring template:

```
(wifi, cyw43)        → modules: [cyw43, ip]
                       wiring:  [cyw43.frames_rx → ip.frames_rx,
                                 ip.frames_tx   → cyw43.frames_tx]

(ethernet, enc28j60) → modules: [enc28j60, ip]
                       wiring:  [enc28j60.frames_rx → ip.frames_rx,
                                 ip.frames_tx       → enc28j60.frames_tx]

(ethernet, ch9120)   → modules: [ch9120]
                       wiring:  []   (ch9120 speaks net_proto directly)

(audio.out, i2s)     → modules: [i2s]
                       wiring:  [i2s gets the auto-wired AudioSample input]

(display, ili9341)   → modules: [ili9341]
                       wiring:  [ili9341 gets the auto-wired VideoDraw input]
```

The hardware section is the board support declaration: it describes the
physical platform independently of the application. Two configs that
target different boards but share the same `modules:` and `wiring:`
sections produce two different resolved graphs from the same application
description.

### Resolution Algorithm

The config tool walks the capability graph:

1. Collect every module's `provides`, `capabilities`, `[[resources]]`,
   and `[requires]` fields from manifests
2. Collect hardware section providers from the lookup table
3. For each unsatisfied `requires`, find a provider chain through service
   modules (e.g. `transport.stream` ← `ip` ← `net.frame.wifi` ← hardware section)
4. Auto-add intermediate modules (the `ip` module if a transport consumer
   needs frames-from-driver)
5. Auto-wire content-type matches where there is exactly one unconnected
   producer and one unconnected consumer of that type
6. Validate every connection (explicit or auto-wired) against content
   type and direction
7. Emit the resolved module list and full wiring as the binary config

### Auto-Wiring Rules

- **Always auto-wire hardware infrastructure**: storage driver to filesystem,
  frame driver to IP module, `AudioSample` output to audio output
- **Auto-wire when unambiguous**: exactly one unconnected producer and
  exactly one unconnected consumer of a given content type
- **Error when ambiguous**: multiple producers of `AudioSample` and one
  i2s consumer requires explicit user wiring to disambiguate
- **Never override explicit wiring**: user-declared wiring always wins
- **Validate all connections**: even explicit wiring is checked against
  content types

### Diagnostics

Resolution errors are reported with the source location and a list of
candidates:

```
Error: 'game' requires display.scanout with max_refresh_hz >= 30 but
       hardware.display (epaper/ssd1680) provides max_refresh_hz ~1.
       Compatible hardware: lcd/ili9341, lcd/st7789, oled/ssd1306.

Error: Ambiguous auto-wire for 'AudioSample' into i2s.in.
       Multiple unconnected providers: synth.out, mp3_decoder.out.
       Add explicit wiring to resolve.
```

### External Modules

External modules declare capabilities and content types in the same
`manifest.toml` schema as first-party modules. New content types are
not restricted to the platform — any string value is valid, and modules
that share a string match without coordination. The content type registry
in this document lists the well-known types used by the first-party
module set; external modules can extend it freely.
