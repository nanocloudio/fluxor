# WASM Browser Host

The browser host runs the WASM platform target inside a browser tab.
The platform itself is host-agnostic (`wasm_platform.md`); this doc is
normative only for browser hosts. It defines the host page that loads
a `.wasm` bundle and drives the kernel, the browser-specific host
imports above the kernel-uniform set, the catalogue of host-provided
built-in modules, and the storage, audio, and lifecycle behaviour of
the browser embedding.

Everything host-side lives in `src/platform/wasm/host/`; the
kernel-side halves of the built-ins live in `src/platform/wasm/`.

---

## 1. Position in the architecture

```
Fluxor application graph (target-agnostic)
      |
      | AudioSample / VideoRaster / KeyEvents / PointerEvents / OctetStream / ...
      v
WASM kernel + modules (one .wasm bundle, per wasm_platform.md)
      |
      | kernel-uniform host imports (time, log, random, instantiate, invoke)
      | + browser-specific host imports (this doc §3)
      v
browser host page + shims (runtime.html, host_shims.js)
      |
      | WebAudio AudioWorklet / WebGPU / Canvas 2D / WebSocket / fetch / OPFS / DOM events
      v
browser platform APIs
```

Everything from the kernel up is binary-identical across hosts; only
the host layer changes.

---

## 2. Host page and bootstrap

Source: `src/platform/wasm/host/runtime.html`,
`src/platform/wasm/host/host_shims.js`,
`src/platform/wasm/host/fluxor-worker.js`.

`runtime.html` is the single generic shell. It:

1. fetches `/scenario.json` to learn what to render, and composes a
   DOM layout from its `presentation:` block (canvas / player /
   terminal surfaces);
2. loads `/fluxor.wasm` and instantiates it with the import object
   built by `host_shims.js`;
3. calls `kernel_init()`, then pumps `kernel_step()` from a
   `requestAnimationFrame` loop in bounded synchronous bursts, so a
   busy graph cannot starve the page's own event handling.

`host_shims.js` implements every `extern "C"` import the kernel
declares (the kernel-uniform set plus the browser capability imports
in §3) and the child-module syscall bridge that forwards
`env.channel_*` / `env.provider_*` imports of instantiated modules to
the kernel's exports. The invariant is one-to-one: every wasm-side
extern has a matching `host_*` shim entry, and a missing entry fails
instantiation with a `LinkError` naming the import.

The `fluxor` CLI's scenario synthesiser serves the pieces as static
routes on the synthesised host whenever a component targets wasm:

| Route             | Source                                    |
|-------------------|-------------------------------------------|
| `/`               | `src/platform/wasm/host/runtime.html`     |
| `/host_shims.js`  | `src/platform/wasm/host/host_shims.js`    |
| `/fluxor.wasm`    | `target/wasm/<bundle>.wasm`               |
| `/scenario.json`  | synthesised inline body                   |

### Worker mode

With `?worker=1` on the page URL, the kernel runs off the main thread:
`fluxor-worker.js` loads `host_shims.js` inside a Web Worker (with a
minimal `window` / `document` stub) and runs `kernel_init` plus the
step pump there. The page keeps the `AudioContext` and input capture;
the canvas is transferred to the worker as an `OffscreenCanvas`, so
WebGPU present happens worker-side. PCM crosses to the page by
`postMessage`, and the page pushes the live audio-clock lead back to
the worker on a ~10 ms timer so the audio-paced sink keeps draining as
the clock advances. This keeps a CPU-bound core from monopolising the
page: audio scheduling, GPU promise completion, presentation, and
input stay live on the main thread.

---

## 3. Browser-specific host imports

Source: extern declarations in `src/platform/wasm/*.rs`,
implementations in `src/platform/wasm/host/host_shims.js`.

In addition to the kernel-uniform imports (`wasm_platform.md` §6), the
browser host provides one import group per capability. Each built-in
module's step function calls its group directly; each import lives in
the kernel-side file of the module that uses it, so adding a
capability is one Rust file with one extern block plus one shim
implementation.

```text
// Raster present (canvas built-in) — RGB565 pixel buffer.
host_canvas_present(ptr, len, width: u32, height: u32)

// Realtime audio sink (AudioWorklet ring).
host_audio_play(ptr, len, sample_rate: u32, channels: u32)
host_audio_ready() -> i32       // renderer can consume PCM now
host_audio_lead_us() -> u64     // exact ring fill, from the render thread

// Audio-clock StreamTime snapshot (24-byte record).
host_stream_time(buf, len) -> i32

// Input event queues, one pop import per source class.
host_input_pop(buf, len) -> i32            // dom_input (keyboard snapshots)
host_keyboard_pop(buf, len) -> i32         // KeyEvents records
host_pointer_pop(buf, len) -> i32          // PointerEvents records
host_gamepad_pop(buf, len) -> i32          // GamepadEvents records
host_button_pop(buf, len) -> i32           // debounced button bytes
host_action_pop(buf, len) -> i32           // FNV-hashed action records
host_surface_traits_pop(buf, len) -> i32   // SurfaceTraits records

// WebSocket transport.
host_ws_open(url_ptr, url_len) -> i32      // handle; opens asynchronously
host_ws_send(handle, data, len) -> i32     // bytes accepted (0 until open)
host_ws_recv(handle, buf, len) -> i32      // bytes written

// HTTP fetch transport. Backs the `host_browser_fetch` channel source
// and the wasm FS provider (§5).
host_fetch_open(url_ptr, url_len) -> i32
host_fetch_recv(handle, buf, len) -> i32
host_fetch_size(handle) -> i32             // four-state, see below
host_fetch_close(handle) -> i32

// storage.object provider (§5).
host_object_head / host_object_range_open / host_object_recv /
host_object_close / host_object_put

// storage.namespace provider (§5).
host_ns_stat / host_ns_list

// Image decode (createImageBitmap + OffscreenCanvas).
host_image_decode_open / host_image_decode_url /
host_image_decode_size / host_image_decode_recv /
host_image_decode_close

// Generic GPU surfaces (§4.4). One adapter and one device serve both.
host_gpu_raster_*                          // pipelines, buffers, passes, draw, frame
host_gpu_service_*                         // the GPU contract's device half

// Camera capture and decoded-scan display.
host_camera_frame(buf, len) -> i32         // [w:u16][h:u16][luma w*h] frames
host_scan_result(ptr, len)

// Kernel-log scrollback widget.
host_terminal_emit(ptr, len)
```

URLs handed to the fetch imports resolve relative to the page origin;
the `asset://` scheme is served from the bundle's baked-in asset
section without a network request.

`host_fetch_size` is a four-state code. The wasm FS provider
(`src/platform/wasm/fs.rs`) translates it into `FS_STAT` semantics,
which in turn drives length-aware HTTP serving:

| Return | Meaning                                                  | FS_STAT  | HTTP commits |
|--------|----------------------------------------------------------|----------|--------------|
| `>= 0` | Content-Length received                                  | `OK`     | `200 OK` with `Content-Length`          |
| `-1`   | Headers received, no Content-Length (chunked / unknown)  | `ENOSYS` | streaming `200 OK` (body ends on close) |
| `-2`   | Hard failure — `fetch()` rejected or response not OK     | `ENODEV` | `502 Bad Gateway`                       |
| `-3`   | Headers not yet received (`fetch()` promise unresolved)  | `EAGAIN` | keep polling; never commit on this state |

The four-way split lets an HTTP server wait for an outcome before
committing a response code, so a slow `fetch()` failure surfaces as
`502` rather than a truncated `200 OK`.

---

## 4. Built-in module catalogue

Built-ins are declared in YAML like modules on any other target and
registered at `kernel_init` through the scheduler's builtin-module
path. Each has a manifest under `modules/platform/wasm/<name>/` and a
kernel-side step function in `src/platform/wasm/`.

Input sources (one per class, per `input_capability_surface.md`):

| Module | Output port → content type | Notes |
|--------|----------------------------|-------|
| `wasm_browser_keyboard` | `events` → `KeyEvents` | DOM `KeyboardEvent` → 8-byte key records |
| `wasm_browser_pointer`  | `events` → `PointerEvents` | mouse / touch / stylus, unified |
| `wasm_browser_gamepad`  | `events` → `GamepadEvents` | Gamepad API state snapshots |
| `wasm_browser_button`   | `raw` → `OctetStream` | debounced tap transitions on the player surface |
| `wasm_browser_action`   | `commands` → `FmpMessage` | overlay controls → FNV-hashed semantic commands |
| `wasm_browser_dom_input`| `events` → `InputBinaryState` | keyboard-state snapshots on a single port |
| `wasm_browser_surface_traits` | `events` → `SurfaceTraits` | viewport / modality / audio-config authority |
| `wasm_browser_midi_in` / `wasm_browser_midi_out` | `events` ↔ `MidiEvents` | Web MIDI. Status: stub, not functional |

Two further modules sit alongside the sources rather than in the
output-port table: `wasm_browser_surface_traits_probe` is a demo
consumer with a single input port `events` (`SurfaceTraits`) that logs
decoded records, and `wasm_browser_touch_gamepad_overlay` is a
transformer that consumes `PointerEvents` on its input port `events_in`
and emits `GamepadEvents` on its output port `events_out`.

Media, transport, and diagnostics:

| Module | Ports | Notes |
|--------|-------|-------|
| `wasm_browser_audio`    | `audio` in (`AudioSample`) | §4.1 |
| `wasm_browser_canvas`   | `pixels` in (`VideoRaster`) | §4.2 |
| `wasm_browser_image_codec` | `encoded` in (`OctetStream`) → `pixels` out (`VideoRaster`) | §4.3 |
| `wasm_browser_gpu`      | `commands` in (`OctetStream`) | §4.4 |
| `wasm_browser_compute`  | `commands` in (`GpuCommand`), `outcomes` out (`GpuOutcome`) | §4.4 |
| `wasm_browser_websocket`| `tx` in / `rx` out (`OctetStream`) | §4.5 |
| `wasm_browser_ws_source`| `bytes` out (`VideoRaster`) | §4.5 |
| `host_browser_fetch`    | `bytes` out (`OctetStream`) | §4.6 |
| `wasm_browser_camera`   | `frames` out (`OctetStream`) | luma frames from `getUserMedia`, for a downstream decoder |
| `wasm_browser_display_capture` | `pixels` out (`VideoRaster`) | `SRF1` RGB565 frames of a surface the person chose to share, from `getDisplayMedia`; §4.7 |
| `wasm_browser_scan_out` | `result` in (`OctetStream`) | surfaces a decoded byte result (e.g. a scanned token) in the page |
| `wasm_browser_terminal` | none | drains the kernel log ring (`LOG_RING_DRAIN`) into a DOM scrollback via `host_terminal_emit`; the wasm analogue of UART logging |
| `wasm_browser_video_codec` | `encoded` in (`OctetStream`) | Status: manifest declared, not registered; design target for WebCodecs decode |

### 4.1 `wasm_browser_audio` — AudioWorklet PCM sink

Source: `src/platform/wasm/audio.rs`; scheduler in `host_shims.js`.

Params: `sample_rate` (u32, required), `channels` (u8, default 1),
`lead_ms` (u8, default 120).

The shim registers a `pcm-ring` `AudioWorkletProcessor` that maintains
a ring of PCM frames and reads one quantum per `process()` call; on
underrun it emits silence and freezes its read cursor so content and
any frame cursor stay synchronised. The module forwards signed-16-bit
PCM blocks via `host_audio_play`, but only until the ring holds about
`lead_ms` of audio, then holds — leaving PCM in the input channel so
backpressure propagates upstream and the whole pipeline is paced by
the audio clock. `host_audio_ready` gates pre-unlock delivery, and
`host_audio_lead_us` reports the exact ring fill from the render
thread.

In a non-secure context (plain-HTTP LAN address), where the
AudioWorklet API is unavailable, the shim falls back to a
`ScriptProcessorNode` driving the same ring, preserving the identical
clock-locked contract.

The sink declares `capabilities = ["audio.sample",
"presentation.clock"]`; the wasm StreamTime provider
(`src/platform/wasm/stream_time.rs`) exposes the played-frame clock
through `provider_query(-1, STREAM_TIME)`, so producers and presenters
share one authoritative A/V clock exactly as with the Linux and
rp2350 audio sinks.

### 4.2 `wasm_browser_canvas` — raster sink

Source: `src/platform/wasm/canvas.rs`.

Params: `width` (u16, required), `height` (u16, required), `header`
(u16, default 0). Pixel format is RGB565 little-endian, the same as
`st7701s` and `linux_display`. The shim converts to RGBA in JS and
presents with Canvas 2D `putImageData`. The module declares
`capabilities = ["video.raster", "display.scanout",
"presentation.clock"]`.

### 4.3 `wasm_browser_image_codec` — encoded image → RGB565

Source: `src/platform/wasm/image_codec.rs`.

The wasm analogue of the Linux host image codec: `encoded` bytes in,
RGB565 `VideoRaster` out, with the decode delegated to the browser via
`createImageBitmap` plus an `OffscreenCanvas`. Params: `width`,
`height` (required), `max_bytes` (default 16 MiB).

### 4.4 `wasm_browser_gpu` / `wasm_browser_compute` — generic GPU surfaces

Source: `src/platform/wasm/gpu.rs`, `src/platform/wasm/gpu_compute.rs`.

Backend-agnostic GPU drivers. Neither holds application knowledge: no
shaders, no vertex or pixel semantics. The application ships its
shaders as data and describes the work as a command stream.

- **Raster** (`wasm_browser_gpu`, `capabilities = ["gpu.render",
  "display.scanout"]`) → `host_gpu_raster_*`: app-supplied render
  pipelines (WGSL), vertex / index / uniform buffers (single-shot or
  streamed), draw calls, and frame lifecycle, presenting to a canvas.
  The command byte layout is documented in the module doc-comment in
  `src/platform/wasm/gpu.rs`. Present timing is the application's
  decision — pace it on the audio `STREAM_TIME` clock for A/V sync.
- **Compute** (`wasm_browser_compute`, `capabilities =
  ["gpu.compute"]`) → `host_gpu_service_*`: the generic GPU contract
  (`docs/architecture/gpu_contract.md`) — program packs, buffers and
  bounded views, dependency-ordered submissions, fences, structured
  outcomes and readback. Validation, handles, sealing, residency,
  output commit and epochs are the shared cores; the JavaScript half
  owns device objects and nothing else.

Both draw from **one adapter and one device** for the whole page.
WebGPU resources belong to the device that created them, so a second
device would be a disjoint resource world: a buffer a compute shader
wrote could not be bound as raster geometry without a CPU round trip at
every hand-off. Sharing a device does not merge the surfaces'
capabilities or oblige either to own a swapchain — it only makes the
hand-off expressible.

The browser backend is WebGPU. The compute surface's contract is the
same one the native (`linux_gpu`) and replay (`gpu_replay`)
providers implement, so a graph wired to it runs unchanged on any of
them, shipping the program pack the target accepts. Domain-specific
GPU pipelines (a console rasteriser, a scientific kernel) are
applications that consume these surfaces; they live out of tree.

### 4.5 WebSocket built-ins

Source: `src/platform/wasm/websocket.rs`,
`src/platform/wasm/ws_source.rs`.

`wasm_browser_websocket` is a bidirectional raw byte transport:
`tx` / `rx` `OctetStream` ports, `url` param, backed by
`host_ws_open` / `host_ws_send` / `host_ws_recv`. Each direction owns
a fixed-size retry buffer, so no bytes are dropped under backpressure:
an unsent tail drains before new input is pulled. The handle opens
asynchronously; neither direction progresses until the handshake
completes. Stream-surface semantics live in modules layered above (a
stream framing module feeding `foundation/remote_channel`), the same
way `tls` wraps `net_proto` byte streams.

`wasm_browser_ws_source` is the receive-only "thin viewer" variant:
it emits incoming binary messages on a `VideoRaster` output, so an
upstream peer can decode images and push RGB565 frames to a browser
canvas over `/ws`. Swapping the decoder between the browser
(`wasm_browser_image_codec`) and an upstream device is purely a
graph-wiring change; the canvas and wire shape are identical.

### 4.6 `host_browser_fetch` — HTTP fetch source

Source: `src/platform/wasm/fetch.rs`.

Streams one URL's response body into a `bytes` output port via
`host_fetch_open` / `host_fetch_recv`. The `host_*` prefix marks it as
a host-provided capability in the same family as the Linux host
built-ins. One in-flight request per module instance; for parallel
fetches, instantiate one module per URL.

### 4.7 `wasm_browser_display_capture` — shared-surface source

Source: `src/platform/wasm/display_capture.rs`.

The peer of §4.2: that module presents pixels this host owns, this one
produces pixels it does not — the screen, window, or tab the person
picked in the browser's own share dialog. `getDisplayMedia` is the only
API for it, so capture is JS and the graph side is a pump.

Params: `width` / `height` (u16, required) and `header` (u16, default
1). The dimensions are the *backing* size, not the shared size: the
person choosing what to share decides the geometry and may change it
mid-session, so frames carry an `SRF1` header
(`sector/modules/common/sector_raster.rs`) and the buffer bounds what a
frame may claim. Larger surfaces are scaled to fit rather than refused.

Frames are RGB565-LE, so `capture.pixels -> display.pixels` resolves
against `linux_display`, `st7701s`, and `wasm_browser_canvas` with no
converter; `header = 0` drops the header for a consumer that has no
header mode and a capture that is known to be fixed-size.

Ending is one-way. When the person stops sharing — through the
browser's UI, which the page never sees otherwise — the current frame
finishes and the module latches. It does not pull again, because
pulling again means a fresh picker.

---

## 5. Storage providers

The browser host implements the platform storage contracts as
providers, not graph modules; any module that speaks the contracts
works on wasm unchanged.

### FS provider — `src/platform/wasm/fs.rs`

Fronts `fetch()` behind the FS contract (`FS_OPEN` / `FS_READ` /
`FS_STAT` / `FS_CLOSE`), the wasm equivalent of `fat32` over NVMe on
bare metal. `FS_OPEN` returns a slot immediately with the fetch in
flight; `FS_READ` maps the shim's four-state return to bytes / EAGAIN
/ EOF / error; `FS_STAT` maps `host_fetch_size` per the §3 table.
`FS_SEEK`, `FS_WRITE`, and `FS_FSYNC` return `ENOSYS`; the streaming
fetch model has no equivalent.

### `storage.object` provider — `src/platform/wasm/object.rs`

Adds the bounded-range reads that demand-paging needs, plus a write
tier:

- **Read tier.** `HEAD` / `RANGE_GET` over `fetch()` with byte
  ranges, serving shipped, immutable content from the page origin and
  the in-bundle `asset://` map.
- **Write tier.** `PUT` stages the blob in the shim's in-memory
  object store, so an immediately following `GET` / `HEAD` /
  `RANGE_GET` of the same key sees it, and persists it in the
  background to OPFS (Origin Private File System), with an IndexedDB
  fallback where OPFS is unavailable (insecure contexts, older
  browsers). The store is re-hydrated from persistent storage at
  boot, so a key written in a prior session reads back after a
  reload. This is what lets user-written data (save states, imported
  assets) survive in the browser.

Reads consult the written store before falling through to `fetch()`.
Durability is best-effort: the per-handle fence stays `Volatile`,
matching the browser quota model (origin storage may be evicted) and
the endpoint surface's best-effort cache role.

### `storage.namespace` provider — `src/platform/wasm/namespace.rs`

The browser has no `readdir`, so directory-style discovery derives a
tree from the same flat key space the object tier writes. `/` is the
hierarchy separator over the union of the written object store and a
fetched manifest of shipped content (`manifestUrl`, default
`fluxor-manifest.json`: a JSON array of `{key, size, mtime?, etag?}`).
A key `saves/tetris` makes `LIST("")` yield `saves` (namespace) and
`LIST("saves/")` yield `tetris` (object); a consumer scans here, then
fetches each hit via `storage.object` on the same key.

`LIST` / `STAT` answer synchronously from the in-memory union index:
a scanner treats a negative `LIST` as end-of-listing, so these never
return `EAGAIN`. The index hydrates asynchronously at boot and mutates
synchronously on object `PUT`; a scan that races boot sees a smaller
tree, never a stall. `LIST` pages via an integer cursor; `STAT`
returns size, mtime, kind, and an etag (a stable FNV hash synthesised
per key for written entries, or the manifest-supplied etag for shipped
content).

`modules/foundation/object_bank` composes the two surfaces into a
storage-backed asset bank: enumerate a prefix via `storage.namespace`
`LIST`, stream each entry via `storage.object` `GET` / `RANGE_GET`.
Wired as `button → gesture → object_bank → codec → audio_out`, a
browser plays media from a user-populatable library (imported through
the object write tier, or listed in `fluxor-manifest.json`) rather
than only bundle-baked `asset://` tracks.

---

## 6. Audio unlock and lifecycle

Browsers refuse to start an `AudioContext` without a user gesture.
The shim's policy:

- Before unlock, the audio sink's PCM stays backpressured upstream
  (`host_audio_ready` reports not-ready), rather than being consumed
  and discarded.
- Any qualifying gesture on the page (`pointerdown`, `pointerup`,
  `click`, `keydown`, `touchstart`, `touchend`) resumes the context;
  queued PCM then flushes.
- The shim listens for context `statechange` and re-issues `resume()`
  whenever the context reports suspended or interrupted after having
  run, so recovery after an interruption (a WebKit behaviour) does
  not need a fresh gesture where the platform allows it.

Camera access (`wasm_browser_camera`) requests `getUserMedia` lazily
on the first frame pull and simply produces no frames until the user
grants it.

Display capture (`wasm_browser_display_capture`) requests
`getDisplayMedia` the same way, and differs in what happens after: the
person chooses *what* is shared in the browser's own picker, and can
stop it at any time from the browser's own UI. A refusal and a stop are
both reported once as ended, and the shim does not call
`getDisplayMedia` again — re-calling it would re-open the picker, which
is asking someone for a screen they just took back. A new capture is a
new module instance.

---

## 7. Validation

A browser-host integration is healthy when:

- The same `<config>.wasm` runs with no rebuild wherever the host
  imports are provided; only the host layer differs.
- Application modules upstream of `wasm_browser_*` built-ins consume
  native AV / input / control content types; nothing knows it is a
  browser.
- Audio scheduling is implemented once in the shim's worklet ring; no
  application code touches WebAudio.
- Input identity is preserved end-to-end; the input built-ins emit
  source-domain records with no application mapping.
- Every kernel-side wasm extern has a matching `host_*` shim entry.
- Adding a new built-in requires a kernel-side step function, a
  manifest, and a shim implementation, with no kernel-ABI or
  platform-doc changes.

---

## 8. Related documentation

- `wasm_platform.md` — the platform target this host
  runs. Owns the module envelope, bundle format, kernel-uniform host
  imports, and tick model.
- `av_capability_surface.md` — surfaces
  `wasm_browser_audio` and `wasm_browser_canvas` consume.
- `input_capability_surface.md` — surfaces the input
  built-ins produce, and their record shapes.
- `storage_capability_surface.md` — the storage surfaces
  the §5 providers implement.
- `protocol_surfaces.md` — protocol substrate the
  WebSocket built-ins feed.
- `browser_capability_surface.md` — the browser as a
  pure-JS endpoint, without a WASM kernel.
- `endpoint_capability_surface.md` — the generic
  endpoint surface that path follows.
