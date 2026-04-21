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

Similarly, a module that provides `audio.pcm` can feed:

- `i2s` driving a local DAC via PIO
- `rtp` streaming over UDP to a remote speaker
- `bluetooth_a2dp` streaming to wireless headphones
- `mpeg_ts` muxing into an MPEG-2 transport stream

The capability model doesn't distinguish local from remote. It matches
providers to consumers by content type. The transport is an implementation
detail hidden inside modules and wiring.

This means the wiring of modules within one device is architecturally
identical to having them connect across devices. A display connected by
SPI and a display streamed via MPEG-2 transport both consume `display.draw`.
A file on local SD and a file on a network share both provide `file.data`.

## Architecture Overview

```
+----------------------------------------------------------------+
|                    Application Modules                          |
|        (http_server, mqtt, synth, photo_viewer, game)          |
|                                                                |
|        requires: [socket]  [audio.pcm]  [display.still]       |
+----------------------------------------------------------------+
                              |
                   Capability Resolution
                    (config tool, build time)
                              |
+----------------------------------------------------------------+
|                    Foundation Modules                           |
|             (ip, fat32, mp3_decoder, ble_stack)                |
|                                                                |
|        provides: [socket]        requires: [frame]             |
|        provides: [file.data]     requires: [storage.block]     |
|        provides: [audio.pcm]     requires: [audio.encoded]     |
+----------------------------------------------------------------+
                              |
                   Capability Resolution
                              |
+----------------------------------------------------------------+
|                    Driver Modules                               |
|          (cyw43, enc28j60, ch9120, sd, i2s, epaper)           |
|                                                                |
|        provides: [frame.wifi]                                  |
|        provides: [frame.ethernet]                              |
|        provides: [socket]          (ch9120: TCP/IP offload)    |
|        provides: [storage.block]                               |
|        provides: [audio.out]                                   |
|        provides: [display.still]                               |
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
| `network` | cyw43, enc28j60, w5500, ch9120 | `frame.*` or `socket` |
| `audio.out` | i2s, pdm, pwm, dac, bluetooth_a2dp | `audio.out` |
| `audio.in` | i2s, pdm, adc | `audio.in` |
| `display` | epaper (ssd1680), oled (ssd1306), lcd (ili9341, st7789) | `display.*` |
| `display.touch` | xpt2046, ft6236, gt911 | `display.touch` |
| `storage` | sd, flash, eeprom | `storage.block` |
| `bluetooth` | cyw43, esp32 | `bluetooth.*` |

### Multi-Capability Chips

Some chips provide multiple capabilities. cyw43 provides WiFi frames and
Bluetooth. The CH9120 provides sockets directly. A chip appearing in
multiple hardware subsections is loaded once as a single module:

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

## Manifest Extensions

Module manifests gain a `[capabilities]` section declaring what the module
provides and requires:

```toml
# cyw43/manifest.toml
[capabilities]
provides = ["frame.wifi", "bluetooth.ble", "bluetooth.a2dp"]
requires = ["pio", "gpio"]

# enc28j60/manifest.toml
[capabilities]
provides = ["frame.ethernet"]
requires = ["spi", "gpio"]

# ch9120/manifest.toml
[capabilities]
provides = ["socket"]
requires = ["uart"]

# ip/manifest.toml
[capabilities]
provides = ["socket"]
requires = ["frame"]

# wifi/manifest.toml
[capabilities]
provides = ["link.wifi"]
requires = ["frame.wifi"]

# i2s/manifest.toml
[capabilities]
provides = ["audio.out"]
requires = ["pio"]

# epaper_ssd1680/manifest.toml
[capabilities]
provides = ["display.still"]
requires = ["spi", "gpio"]

# lcd_ili9341/manifest.toml
[capabilities]
provides = ["display.still", "display.video"]
requires = ["spi", "gpio"]

# xpt2046/manifest.toml
[capabilities]
provides = ["display.touch"]
requires = ["spi", "gpio"]

# fat32/manifest.toml
[capabilities]
provides = ["file.data"]
requires = ["storage.block"]

# sd/manifest.toml
[capabilities]
provides = ["storage.block"]
requires = ["spi", "gpio"]

# mp3_decoder/manifest.toml
[capabilities]
provides = ["audio.pcm"]
requires = ["audio.encoded"]

# http_server/manifest.toml
[capabilities]
requires = ["socket"]

# mqtt/manifest.toml
[capabilities]
requires = ["socket"]

# synth/manifest.toml
[capabilities]
provides = ["audio.pcm"]

# weather_station/manifest.toml
[capabilities]
requires = ["display.still"]

# game/manifest.toml
[capabilities]
requires = ["display.video", "display.touch"]
```

### Wildcard Matching

A requirement of `"frame"` matches any `frame.*` provider (`frame.wifi`,
`frame.ethernet`). This is how the IP module works with any frame source
without listing every possible driver.

Matching rules:
- Exact match: `"socket"` matches `"socket"`
- Prefix match: `"frame"` matches `"frame.wifi"`, `"frame.ethernet"`
- No reverse: `"frame.wifi"` does NOT match `"frame"` (a WiFi-specific
  module can't run on a generic frame provider)

## Port Content Types

Ports gain a `content_type` field that describes what data flows through them.
This enables auto-wiring and type-checked connections.

```toml
# synth/manifest.toml
[[ports]]
direction = "output"
content_type = "audio.pcm"

# mp3_decoder/manifest.toml
[[ports]]
direction = "input"
content_type = "audio.encoded"

[[ports]]
direction = "output"
content_type = "audio.pcm"

# i2s/manifest.toml
[[ports]]
direction = "input"
content_type = "audio.pcm"

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
content_type = "display.draw"
```

### Content Type Registry

Content types describe the data format flowing through channels. They use
a hierarchical naming scheme matching the capability taxonomy.

| Content Type | Description | Example Providers |
|-------------|-------------|-------------------|
| `audio.pcm` | Raw PCM samples (interleaved stereo) | synth, mp3_decoder, mic_source |
| `audio.encoded` | Compressed audio (MP3, AAC, WAV) | file reader, http client |
| `audio.encoded.mp3` | Specifically MP3 | file reader with MP3 files |
| `display.draw` | Drawing commands or framebuffer | photo viewer, UI renderer |
| `display.touch_event` | Touch coordinates and gestures | xpt2046, ft6236 |
| `storage.block` | Raw block I/O (512-byte sectors) | sd, flash |
| `file.data` | File byte stream | fat32, littlefs, http, nfs |
| `frame.ethernet` | Raw ethernet frames | cyw43, enc28j60, ip |
| `control.fmp` | FMP messages (next/prev/toggle) | button, gesture, bank |

These correspond to the content types in the mesh event system
(see `architecture/mesh.md`), ensuring on-device channels and cross-device
mesh events use the same type identifiers.

## Graduated Display Capabilities

Display hardware provides different capability levels. The capability model
captures this as graduated sets:

| Hardware | display.still | display.video | display.touch |
|----------|:---:|:---:|:---:|
| e-paper (ssd1680) | Y | | |
| OLED (ssd1306) | Y | Y | |
| LCD (ili9341) | Y | Y | |
| LCD + touch (ili9341 + xpt2046) | Y | Y | Y |

Application modules declare their minimum requirements:

| Application | Minimum Requirement | Works On |
|-------------|-------------------|----------|
| Weather station | `display.still` | All displays |
| Photo frame | `display.still` | All displays |
| Video player | `display.video` | OLED, LCD |
| Game | `display.video` + `display.touch` | LCD with touch only |
| Dashboard | `display.still` | All displays |

The config tool validates at build time:

```
hardware:
  display:
    type: epaper
    driver: ssd1680

modules:
  - name: game

Error: 'game' requires 'display.video' but hardware provides only
       'display.still' (epaper/ssd1680).
       Compatible hardware: lcd/ili9341, lcd/st7789, oled/ssd1306.
```

## Capability Resolution

The config tool resolves the dependency graph at build time. This is
analogous to a package manager resolving dependencies — but for hardware
capabilities instead of software libraries.

### Resolution Algorithm

```
1. Collect all `requires` from user-declared modules
     http_server -> {socket}
     synth -> {audio.pcm} (provides, not requires)
     game -> {display.video, display.touch}

2. Collect all `provides` from hardware: section
     hardware.network (wifi/cyw43) -> {frame.wifi}
     hardware.audio.out (i2s) -> {audio.out}
     hardware.display (lcd/ili9341) -> {display.still, display.video}
     hardware.display.touch (xpt2046) -> {display.touch}

3. For each unsatisfied requirement, find a provider chain:
     socket <- ip (provides socket, requires frame)
             <- cyw43 (provides frame.wifi, from hardware)
     display.video <- ili9341 (from hardware)
     display.touch <- xpt2046 (from hardware)

4. For frame.wifi, also resolve link management:
     link.wifi <- wifi module (requires frame.wifi)

5. Emit resolved module list + infrastructure wiring:
     Auto-added: cyw43, wifi, ip, ili9341, xpt2046, i2s
     Auto-wired: cyw43<->ip frames, wifi<->cyw43 ctrl,
                 synth->i2s, etc.
```

### Auto-Wiring Rules

To keep behavior predictable and debuggable:

1. **Always auto-wire hardware infrastructure**: storage driver to filesystem,
   frame driver to IP stack, audio.pcm to audio output. These are the
   "plumbing" connections that every application needs.

2. **Auto-wire when unambiguous**: if exactly one unconnected output port
   has content_type `audio.pcm` and exactly one unconnected input port
   expects `audio.pcm`, wire them.

3. **Error when ambiguous**: if both synth and mp3_decoder output
   `audio.pcm` and i2s needs `audio.pcm`, the config tool reports:
   ```
   Error: Ambiguous auto-wire for 'audio.pcm' into i2s.in.
          Multiple providers: synth.out, mp3_decoder.out.
          Add explicit wiring to resolve.
   ```

4. **Never override explicit wiring**: user-declared wiring always takes
   priority over auto-wiring. If the user wires `synth.out -> effects.in`,
   the auto-wirer doesn't also try to wire `synth.out -> i2s.in`.

5. **Validate all connections**: even explicit wiring is checked against
   content types. Connecting `synth.out(audio.pcm)` to `fat32.in(storage.block)`
   produces a type mismatch warning.

### What Gets Auto-Wired vs What Stays Explicit

| Category | Auto-Wired | Example |
|----------|-----------|---------|
| Hardware infrastructure | Yes | sd -> fat32, cyw43 <-> ip, pcm -> i2s |
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
stacks, all providing the same `socket` capability to http_server:

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
            mp3_decoder.out(audio.pcm) -> i2s.in(audio.pcm)
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

The mp3_decoder still outputs `audio.pcm`. The Bluetooth A2DP module
consumes `audio.pcm` exactly like i2s does.

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
Auto-wired: effects.out(audio.pcm) -> i2s.in(audio.pcm)
```

The auto-wirer sees that `effects.out` provides `audio.pcm` and `i2s.in`
requires `audio.pcm`, with no other audio.pcm providers having unconnected
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

The renderer provides `display.draw` on its output. When wired to a local
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
            weather_station.out(display.draw) -> ssd1680.in(display.draw)
```

Validated: weather_station requires `display.still`, ssd1680 provides it.

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
Auto-wired: game.out(display.draw) -> ili9341.in(display.draw)
            xpt2046.out(display.touch_event) -> game.in(display.touch_event)
```

Validated: game requires `display.video` and `display.touch`. ili9341
provides `display.video`, xpt2046 provides `display.touch`.

If the user tried this on e-paper:
```
Error: 'game' requires 'display.video' but hardware.display (epaper/ssd1680)
       only provides 'display.still'.
```

## Capability Taxonomy

### Hardware Capabilities (from hardware: section)

```
frame.wifi          — raw WiFi ethernet frames (cyw43, esp32)
frame.ethernet      — raw wired ethernet frames (enc28j60, w5500)
bluetooth.ble       — Bluetooth Low Energy (cyw43, esp32)
bluetooth.a2dp      — Bluetooth audio streaming (cyw43)
audio.out           — physical audio output (i2s, pdm, pwm, dac, bt_a2dp)
audio.in            — physical audio input (i2s_in, pdm_in, adc)
display.still       — static image rendering (epaper, oled, lcd)
display.video       — frame-rate rendering (oled, lcd)
display.touch       — touch input (xpt2046, ft6236, gt911)
storage.block       — raw block I/O (sd, flash, eeprom)
pio                 — programmable I/O (RP2350 PIO peripheral)
spi                 — SPI bus access
i2c                 — I2C bus access
gpio                — GPIO pin access
uart                — UART serial access
```

### Service Capabilities (from module manifests)

```
socket              — TCP/UDP networking (provided by ip, ch9120, w5500)
link.wifi           — WiFi connection management (provided by wifi)
file.data           — file byte stream (provided by fat32, littlefs, http)
audio.pcm           — raw PCM audio samples (provided by synth, decoder, mic)
audio.encoded       — compressed audio stream (provided by file reader, http)
display.draw        — drawing commands / framebuffer (provided by renderer)
display.touch_event — touch coordinates (provided by touch driver)
selection           — item selection (provided by bank)
```

### Capability Inheritance

Capabilities form a hierarchy. A requirement for a parent capability is
satisfied by any child:

```
frame               — matches frame.wifi, frame.ethernet
bluetooth           — matches bluetooth.ble, bluetooth.a2dp
audio.encoded       — matches audio.encoded.mp3, audio.encoded.aac
display             — matches display.still, display.video
```

The reverse does NOT hold. A module requiring `frame.wifi` specifically
cannot be satisfied by `frame.ethernet`.

## Relationship to Architecture

### Network Architecture (network.md)

`network.md` describes the frame provider vs socket provider
distinction. This document generalizes that pattern: frame providers and
socket providers are both instances of the capability model. The `provides`
field in manifests formalizes that contract.

The NetIF contract (frame channels between drivers and IP) becomes an
auto-wired infrastructure connection resolved from the hardware section.

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

`manifest.toml` for each module declares what it provides and requires:

```toml
[capabilities]
provides = ["audio.pcm"]
requires = ["socket"]
```

Modules without the section have empty `provides`/`requires` lists and
participate only in explicit wiring.

### Port Content Types

Ports in `manifest.toml` declare their `content_type`:

```toml
[[ports]]
name = "out"
direction = "output"
content_type = "audio.pcm"
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
                       wiring:  [i2s gets the auto-wired audio.pcm input]

(display, ili9341)   → modules: [ili9341]
                       wiring:  [ili9341 gets the auto-wired display.draw input]
```

The hardware section is the board support declaration: it describes the
physical platform independently of the application. Two configs that
target different boards but share the same `modules:` and `wiring:`
sections produce two different resolved graphs from the same application
description.

### Resolution Algorithm

The config tool walks the capability graph:

1. Collect every module's `provides` and `requires` from manifests
2. Collect hardware section providers from the lookup table
3. For each unsatisfied `requires`, find a provider chain through service
   modules (e.g. `socket` ← `ip` ← `frame.wifi` ← hardware section)
4. Auto-add intermediate modules (the `ip` module if a socket consumer
   needs frames-from-driver)
5. Auto-wire content-type matches where there is exactly one unconnected
   producer and one unconnected consumer of that type
6. Validate every connection (explicit or auto-wired) against content
   type and direction
7. Emit the resolved module list and full wiring as the binary config

### Auto-Wiring Rules

- **Always auto-wire hardware infrastructure**: storage driver to filesystem,
  frame driver to IP module, audio.pcm output to audio output
- **Auto-wire when unambiguous**: exactly one unconnected producer and
  exactly one unconnected consumer of a given content type
- **Error when ambiguous**: multiple producers of `audio.pcm` and one
  i2s consumer requires explicit user wiring to disambiguate
- **Never override explicit wiring**: user-declared wiring always wins
- **Validate all connections**: even explicit wiring is checked against
  content types

### Diagnostics

Resolution errors are reported with the source location and a list of
candidates:

```
Error: 'game' requires 'display.video' but hardware.display (epaper/ssd1680)
       only provides 'display.still'.
       Compatible hardware: lcd/ili9341, lcd/st7789, oled/ssd1306.

Error: Ambiguous auto-wire for 'audio.pcm' into i2s.in.
       Multiple unconnected providers: synth.out, mp3_decoder.out.
       Add explicit wiring to resolve.
```

### Marketplace Modules

Modules loaded from a marketplace declare their capabilities and content
types in the same `manifest.toml` schema as first-party modules. New
content types are not restricted to the platform — any string value is
valid, and modules that share a string match without coordination. The
content type registry in this document lists the well-known types used
by the first-party module set; third-party modules can extend it freely.
