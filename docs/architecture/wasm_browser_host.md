# WASM Browser Host

The browser host runs the WASM platform target inside a browser tab.
The platform itself is host-agnostic ([wasm_platform.md](wasm_platform.md)); this doc is
normative only for browser hosts. It defines the host page that loads
a `.wasm` bundle and drives the kernel, the browser-specific host
imports above the kernel-uniform set, the catalogue of host-provided
native modules, and the storage, audio, and lifecycle behaviour of
the browser embedding.

Everything host-side lives in `src/platform/wasm/host/`; the
kernel-side halves of the native modules live in `src/platform/wasm/`.

---

## 1. Position in the architecture

```
Fluxor node graph (target-agnostic)
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

1. fetches `scenario.json`, beside the page, to learn what to render,
   and composes a DOM layout from its `presentation:` block (canvas /
   player / terminal surfaces);
2. loads `fluxor.wasm` and instantiates it with the import object
   built by `host_shims.js`;
3. calls `kernel_init()`, then calls `kernel_step()` from a
   `requestAnimationFrame` loop in bounded synchronous bursts, so a
   busy graph cannot starve the page's own event handling.

`host_shims.js` implements every `extern "C"` import the kernel
declares (the kernel-uniform set plus the browser capability imports
in §3) and the child-module syscall bridge that forwards
`env.channel_*` / `env.provider_*` imports of instantiated modules to
the kernel's exports. The invariant is one-to-one: every wasm-side
extern has a matching `host_*` shim entry, and a missing entry fails
instantiation with a `LinkError` naming the import.

A child module has its own linear memory, so the bridge copies every
span through kernel scratch and back, and zero-copy channel lends answer
`ENOTSUP` across it ([wasm_platform.md §6](wasm_platform.md#6-host-import-surface)).

### Serving

`fluxor run` on a scenario with a `host:` block (a `kind: scenario` file,
or a graph's inline `scenario:` block) writes every file the browser
fetches into one document root, `target/scenarios/<name>/root` under the
scenario's project, and runs a Linux host graph that serves it. Under each
`serve:` binding's `prefix` (the root itself for `/`; a `serve:` names a
wasm component) the root holds:

| File                   | Content                                                    |
|------------------------|------------------------------------------------------------|
| `index.html`           | `runtime.html` with the overlay renderer inlined, or a link to the component's `host_page` |
| `fluxor.wasm`          | a link to the component's bundle, `target/wasm/<graph>.wasm` |
| `host_shims.js`        | `src/platform/wasm/host/host_shims.js`                     |
| `fluxor-worker.js`     | `src/platform/wasm/host/fluxor-worker.js`                  |
| `scenario.json`        | the scenario name, bundle URL, playlist and `presentation:` |
| `fluxor-manifest.json` | with a `list:` binding: one `{ key, size, mtime, etag }` per listed file |
| `<path>/`              | each `list:` binding's directory, linked at its `path` (default `/api/list`) |

A manifest key is `<path>/<relpath>` without a leading `/`: the file's URL
relative to the page, so the kernel fetching a key, and the shell's
playlist, resolve it under whichever prefix serves the page. The shell
sets the document's base to that prefix, so `/viewer` and `/viewer/`
resolve alike. The playlist is the keys under the first `list:` binding's
path, so the server needs no listing handler. Two `serve:` bindings need
distinct prefixes, and nothing is placed through a linked directory: a
prefix or path that would land in one is refused.

The host graph is:

```yaml
target: linux
platform:
  net: {}
scheduler:
  accept_cycles: true              # the net_in/net_out pair is a 2-cycle
include:
  - stack: "@file_server"
    as: web
    params:
      port: 9876                   # the scenario's host.port
      root: /abs/path/target/scenarios/<name>/root
wiring:
  - from: linux_net.net_out
    to: web.net_in
  - from: web.net_out
    to: linux_net.net_in
```

`@file_server` is a bound name ([stacks.md](stacks.md#bound-names)): the
project the scenario belongs to binds it to a stack, its own or a
published one, under `[uses.stacks]`; Fluxor ships no default. A stack fits when it
meets this interface:

| Item | Kind | Meaning |
|---|---|---|
| `port` | param, `integer` | TCP port to listen on |
| `root` | param, `string` | absolute path of a directory; a GET for `/p` serves `root/p`, following symbolic links; a path naming a directory serves its `index.html`; the content type comes from the extension (`.wasm` as `application/wasm`) |
| `net_in`, `net_out` | exports, `NetProto` | the connection to the platform `net` stack |

A provider may declare more params, each with a default, and more
exports. `fluxor run --print-synthesised` prints the host graph and writes
the root without a binding; `--validate-only` and a run expand the
include, so an unbound name is refused there, naming the line to add.

### Worker mode

With `#worker` in the page URL (or a `worker` query parameter, where the
server answers a path with a query), the kernel runs off the main thread:
`fluxor-worker.js` loads `host_shims.js` inside a Web Worker (with a
minimal `window` / `document` stub) and runs `kernel_init` plus the
`kernel_step` loop there. The page keeps the `AudioContext` and input capture;
the canvas is transferred to the worker as an `OffscreenCanvas`, so
WebGPU present and the 2D canvas sink (§4.2) paint worker-side. The
accessibility mirror (§4.8) is DOM and stays on the page: the worker
posts it each checked batch. PCM crosses to the page by
`postMessage`, and the page pushes the live audio-clock lead back to
the worker on a ~10 ms timer so the audio-paced sink keeps draining as
the clock advances. This keeps a CPU-bound core from monopolising the
page: audio scheduling, GPU promise completion, presentation, and
input stay live on the main thread.

Input is captured on the page in either mode, into one queue per input
class (`__fluxor_<class>_queue`: keyboard, pointer, button, gamepad, action,
surface traits, and the mirror's text edits and accessibility actions) plus
the `wasm_browser_dom_input` queue, and each is drained by its `host_*_pop`
import where the kernel steps. In worker mode the page posts every
non-empty queue to the worker in one `input` message on a ~16 ms timer
(`postInputBatch` in `host_shims.js`), and the worker appends the records
to its own queues in the order they were captured.

A graph need not hold the module that drains a class, so every queue has a
cap, on the page and in the worker: past it a queue loses its oldest
records. The kernel-side sources lose nothing they have taken: a record
the output channel refuses is held and written first on the next step.

Gamepads have no events for state, so the page polls
`navigator.getGamepads()` once per animation frame (`installGamepadPoller`)
and queues `GamepadEvents` records only when a pad changes: a connection
record then a state snapshot on attach, a state snapshot on any button or
axis change, and a connection record then a released snapshot on detach.
Indices past the contract's four slots are not reported. A presentation
overlay may also draw pads on the page; one slot table,
`__fluxor_gamepad_slots`, keeps the two apart. A drawn pad holds the slot
its shell declares. A pad the browser reports takes the slot of its own
`Gamepad.index` when nobody holds it, else the lowest free slot, and moves
when a drawn pad claims the one it had.

---

## 3. Browser-specific host imports

Source: extern declarations in `src/platform/wasm/*.rs`,
implementations in `src/platform/wasm/host/host_shims.js`.

In addition to the kernel-uniform imports ([wasm_platform.md §6](wasm_platform.md#6-host-import-surface)), the
browser host provides one import group per capability. Each native module
module's step function calls its group directly; each import lives in
the kernel-side file of the module that uses it, so adding a
capability is one Rust file with one extern block plus one shim
implementation.

```text
// Raster present (canvas native module): one region of a frame, as pixels
// and a rectangle. format 0 = RGB565, 1 = RGBA8; flags 1 = the region opens
// a frame, 2 = it completes one.
host_canvas_present(ptr, len, width: u32, height: u32, format: u32,
                    x: u32, y: u32, surface_w: u32, surface_h: u32, flags: u32)

// Realtime audio sink (AudioWorklet ring).
host_audio_play(ptr, len, sample_rate: u32, channels: u32)
host_audio_ready() -> i32       // renderer can consume PCM now
host_audio_lead_us() -> u64     // exact ring fill, from the render thread

// Audio-clock StreamTime snapshot (24-byte record); 1 once started, else 0.
host_stream_time(out) -> i32

// Input event queues, one pop import per source class.
host_input_pop(buf, len) -> i32            // dom_input (keyboard snapshots)
host_keyboard_pop(buf, len) -> i32         // KeyEvents records
host_pointer_pop(buf, len) -> i32          // PointerEvents records
host_gamepad_pop(buf, len) -> i32          // GamepadEvents records
host_button_pop(buf, len) -> i32           // debounced button bytes
host_action_pop(buf, len) -> i32           // FNV-hashed action records
host_surface_traits_pop(buf, len) -> i32   // SurfaceTraits records

// Accessibility mirror and its text field (§4.8).
host_a11y_open(tree_wired: u32)            // mirror a tree, or text only
host_a11y_stage(ptr, len)                  // one checked tree record
host_a11y_commit(apply: u32)               // apply the staged batch, or drop it
host_a11y_action_pop(buf, len) -> i32      // AccessibilityActions records
host_a11y_text_pop(buf, len) -> i32        // text edits, by field

// WebSocket transport (byte tunnel).
host_ws_open(url_ptr, url_len) -> i32      // handle; opens asynchronously
host_ws_send(handle, data, len) -> i32     // bytes accepted (0 until open)
host_ws_recv(handle, buf, len) -> i32      // bytes written

// Addressed WebSocket links (§4.5): message boundaries and opcodes kept,
// link events reported rather than inferred.
host_ws_link_open(origin, origin_len, path, path_len) -> i32
host_ws_link_event(handle) -> i32          // 0, or (kind << 16) | code
host_ws_link_send(handle, opcode, data, len) -> i32
host_ws_link_next(handle) -> i32           // -1, or (opcode << 24) | remaining
host_ws_link_recv(handle, buf, len) -> i32 // bytes of the oldest message
host_ws_link_close(handle, code) -> i32    // 0 = let go of an ended link

// HTTP exchange (§4.6): one fetch() per request, status and head kept.
host_http_open(method, method_len, origin, origin_len, path, path_len,
               headers, headers_len, body, body_len) -> i32
host_http_status(handle) -> i32            // -3 pending, -2 failed, else code
host_http_head(handle, buf, len) -> i32    // CRLF field lines, whole or -2
host_http_recv(handle, buf, len) -> i32    // bytes; 0 pending; -1 end; -2 failed
host_http_close(handle) -> i32

// HTTP fetch transport. Backs the `host_browser_fetch` channel source
// and the wasm FS provider (§5).
host_fetch_open(url_ptr, url_len) -> i32
host_fetch_recv(handle, buf, len) -> i32
host_fetch_size(handle) -> i32             // four-state, see below
host_fetch_write(handle, buf, len) -> i32  // stage bytes; published as one file at close
host_fetch_close(handle) -> i32

// storage.object provider (§5).
host_object_head / host_object_range_open / host_object_recv /
host_object_close / host_object_put / host_object_delete

// storage.namespace provider (§5).
host_ns_stat / host_ns_list

// Image decode (createImageBitmap + OffscreenCanvas): the
// wasm_browser_image_codec native module and the image_decode provider (§5).
host_image_decode_open / host_image_decode_object /
host_image_decode_size / host_image_decode_recv /
host_image_decode_close

// Generic GPU surfaces (§4.4). One adapter and one device serve both.
host_gpu_raster_*                          // pipelines, buffers, passes, draw, frame
host_gpu_service_*                         // the GPU contract's device half

// Camera capture and decoded-scan display.
host_camera_frame(buf, len) -> i32         // [w:u16][h:u16][luma w*h] frames
host_scan_result(ptr, len)

// Shared-surface capture (§4.7): RGB565 pixels into buf and the frame's
// width and height into extent; pixel bytes written, 0 none yet, negative =
// ended.
host_display_frame(buf, len, extent) -> i32

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

## 4. Native module catalogue

Native modules are declared in YAML like modules on any other target. Each
is a native module: a manifest under `modules/platform/wasm/<name>/` and
a vtable in `src/platform/wasm/` that the platform registers at
`kernel_init`.

Input sources (one per class, per [input_capability_surface.md](input_capability_surface.md)):

| Module | Output port → content type | Notes |
|--------|----------------------------|-------|
| `wasm_browser_keyboard` | `events` → `KeyEvents` | DOM `KeyboardEvent` → 8-byte key records; §4.9 |
| `wasm_browser_pointer`  | `events` → `PointerEvents` | mouse / touch / stylus, unified, and the wheel; §4.9 |
| `wasm_browser_gamepad`  | `events` → `GamepadEvents` | Gamepad API state snapshots |
| `wasm_browser_button`   | `raw` → `OctetStream` | debounced tap transitions on the player surface |
| `wasm_browser_action`   | `commands` → `FmpMessage` | overlay controls → FNV-hashed semantic commands |
| `wasm_browser_dom_input`| `events` → `InputBinaryState` | keyboard-state snapshots on a single port |
| `wasm_browser_surface_traits` | `events` → `SurfaceTraits` | viewport / device-pixel-ratio / modality / audio-config authority; §4.9 |
| `wasm_browser_accessibility` | `tree` in (`AccessibilityTree`), `actions` out (`AccessibilityActions`), `text` out (`TextEvents`) | the DOM mirror of a drawn UI and its text field; §4.8 |
| `wasm_browser_midi_in` / `wasm_browser_midi_out` | `events` ↔ `MidiEvents` | registered stubs: `midi_in` emits nothing, `midi_out` drains and discards its input; Web MIDI is not wired |

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
| `wasm_browser_gpu`      | `commands` in (`OctetStream`); params `width`, `height` (default 800 × 600) | §4.4 |
| `wasm_browser_compute`  | `commands` in (`GpuCommand`), `outcomes` out (`GpuOutcome`) | §4.4 |
| `wasm_browser_websocket`| `tx` in / `rx` out (`OctetStream`) | §4.5 |
| `wasm_browser_ws_source`| `bytes` out (`VideoRaster`) | §4.5 |
| `wasm_browser_ws`       | `open_in` in, `ws_in` in (`WsFrame`), `ws_out` out (`WsFrame`), `event_out` out | §4.5 |
| `host_browser_fetch`    | `bytes` out (`OctetStream`) | §4.6 |
| `wasm_browser_http`     | `request_in` in (`ExchangeRequest`), `response_out` out (`ExchangeResponse`) | §4.6 |
| `wasm_browser_camera`   | `frames` out (`OctetStream`) | luma frames from `getUserMedia`, for a downstream decoder |
| `wasm_browser_display_capture` | `pixels` out (`VideoRaster`) | RGB565 frames of a surface the person chose to share, from `getDisplayMedia`; §4.7 |
| `wasm_browser_scan_out` | `result` in (`OctetStream`) | surfaces a decoded byte result (e.g. a scanned token) in the page |
| `wasm_browser_terminal` | none | drains the kernel log ring (`LOG_RING_DRAIN`) into a DOM scrollback via `host_terminal_emit`; the wasm analogue of UART logging |
| `wasm_browser_video_codec` | `encoded` in (`OctetStream`) | a manifest only: no module is registered under the name, so a graph naming it does not load |

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

Params: `width` (u16, required), `height` (u16, required): the largest
surface the canvas accepts, which sizes its buffer. The stream states
its own surface. Every record on `pixels` is the region header of the
`VideoRaster` contract
(`crates/fluxor-abi/src/contracts/video_raster.rs`, 20 bytes) and that
region's pixels, in RGB565 or RGBA8 as the header says (alpha carried
and ignored); there is no headerless form. The canvas element takes the
extent of the surface in the stream.

The header has one definition. The module reads and checks it and hands
the shim plain pixels and a rectangle; no host file parses or writes
it.

- A frame's regions are staged and painted together at the region
  flagged `LAST`, so a frame of several regions appears whole.
- A frame whose regions carry `DAMAGE` changes only those rectangles;
  the rest of the canvas keeps its picture. A frame without it tiles
  the whole surface top to bottom (one region is the common case).
- A record the contract refuses (a region outside its surface, an
  unknown format or flag, a surface past `width` × `height`, a broken
  tiling, a surface change inside a frame) is counted and skipped. The
  frame it belonged to is abandoned, the canvas keeps what it last
  showed, and the stream is scanned forward for the next header of the
  surface in use.

The port declares the facts `formats = [rgb565, rgba8]` and
`regions = [damage, bands]`, so a producer that declares what it sends
is checked against them when the graph is composed. The shim converts
to RGBA in JS and paints with Canvas 2D `putImageData`. The module
declares `capabilities = ["video.raster", "display.scanout",
"presentation.clock"]`.

### 4.3 `wasm_browser_image_codec` — encoded image → RGB565

Source: `src/platform/wasm/image_codec.rs`.

The wasm analogue of the Linux host image codec: `encoded` bytes in,
`VideoRaster` out, with the decode delegated to the browser via
`createImageBitmap` plus an `OffscreenCanvas`. Each image goes out as
one region record covering the whole `width` × `height` surface in
RGB565; the module writes the header. Params: `width`, `height`
(required), `max_bytes` (default 16 MiB).

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
- **Contract** (`wasm_browser_compute`, `capabilities =
  ["gpu.compute", "gpu.render"]`) → `host_gpu_service_*`: the generic
  GPU contract ([gpu_contract.md](gpu_contract.md)) — program packs,
  buffers, textures and bounded views, compute and raster pipelines,
  dependency-ordered submissions, fences, structured outcomes,
  readback and device reset. Validation, handles, sealing, residency,
  output commit and epochs are the shared cores; the JavaScript half
  owns device objects and nothing else.

Both draw from **one adapter and one device** for the whole page.
WebGPU resources belong to the device that created them, so a second
device would be a disjoint resource world: a buffer a compute shader
wrote could not be bound as raster geometry without a CPU round trip at
every hand-off. Sharing a device does not merge the surfaces'
capabilities or oblige either to own a swapchain — it only makes the
hand-off expressible.

Sharing a device also shares its end. When the device is lost, or a
contract reset destroys it, every surface on the page sees the same
loss: the contract provider reports it as a new epoch and opens a
successor; the raster surface initialises again, and refuses commands
naming pipelines, targets or buffers until the app sends them again.

The browser backend is WebGPU. The compute surface's contract is the
same one the native (`linux_gpu`) and replay (`gpu_replay`)
providers implement, so a graph wired to it runs unchanged on any of
them, shipping the program pack the target accepts. Application-specific
GPU pipelines (a console rasteriser, a scientific kernel) are
applications that consume these surfaces; they live out of tree.

### 4.5 WebSocket native modules

Source: `src/platform/wasm/websocket.rs`,
`src/platform/wasm/ws_source.rs`.

`wasm_browser_websocket` is a bidirectional raw byte transport:
`tx` / `rx` `OctetStream` ports, `url` param, backed by
`host_ws_open` / `host_ws_send` / `host_ws_recv`. Each direction owns
a fixed-size retry buffer, so no bytes are dropped under backpressure:
an unsent tail drains before new input is pulled. The handle opens
asynchronously; neither direction progresses until the handshake
completes. Stream-surface semantics live in modules layered above it,
the same way `tls` wraps `net_proto` byte streams. It is not a
remote-channel transport: a remote channel needs a session with a
beginning, an end and an authenticated peer, which a raw byte stream
does not carry.

`wasm_browser_ws_source` is the receive-only "thin viewer" variant:
it emits incoming binary messages on a `VideoRaster` output, so an
upstream peer can decode images and push RGB565 frames to a browser
canvas over `/ws`. Swapping the decoder between the browser
(`wasm_browser_image_codec`) and an upstream device is purely a
graph-wiring change; the canvas and wire shape are identical.

`wasm_browser_ws` (`src/platform/wasm/ws.rs`) is the addressed
connector: the same four ports, records and link count
(`ws_control::WS_LINKS`) a socket-backed WebSocket connector offers, so
a consumer holding several links moves between the two by wiring
alone. `open_in` carries `ws_control` open records (which link, which
path), `ws_in` / `ws_out` carry `WsFrame` envelopes whose `conn` field
is the link index, and `event_out` carries `ws_control` events: a link
opened, ended with a close code, or never opened. A path names the
resource; the `origin` param names where (empty means the page's
origin over `ws:` or `wss:` to match how the page was served), and a
path carrying its own scheme or host is answered FAILED. A browser
sends and receives whole messages, so fragments arriving on `ws_in`
are assembled until their final frame and sent as one, and a received
message longer than one envelope leaves as fragments whose last
carries `fin`. Backed by `host_ws_link_*`, which keeps message
boundaries and opcodes and reports a close only after every message
that preceded it has been taken.

### 4.6 `host_browser_fetch` — HTTP fetch source

Source: `src/platform/wasm/fetch.rs`.

Streams one URL's response body into a `bytes` output port via
`host_fetch_open` / `host_fetch_recv`. The `host_*` prefix marks it as
a host-provided capability in the same family as the Linux host
native modules. One in-flight request per module instance; for parallel
fetches, instantiate one module per URL.

`wasm_browser_http` (`src/platform/wasm/http.rs`) is the browser as an
HTTP exchange provider: a provider of the exchange contract
([exchange.md](exchange.md)) speaking its HTTP binding and declaring
`stream.ordered_ack.exchange`, answering with the same records and
statuses a socket-backed HTTP client does, so a
requester moves between the two by wiring alone. Request records arrive
on `request_in`; each request is collected whole (`fetch()` takes its
body in one piece, up to `PAYLOAD_MAX`), and the page's `fetch()`
performs it. The answer leaves on `response_out` under the request's
exchange id: a response HEAD with the status as its detail, the
response's header fields (the content type among them) as meta and the
first body bytes, then BODY
records as the rest arrives, never past the requester's credit.

A request's target is a path and the `origin` param names where (empty
means the page's origin); a request may name its authority in a `host`
header, which must match a set origin and is dialled over https when
none is set. A target with its own scheme or host, anything but a call
with a method (a publish, a CONNECT or an upgrade), a broadcast, or a
header value that would split its line is answered 400; a request
past what it collects 413; more exchanges at once than it holds 503; a
fetch that fails before the response head, or a head too large for one
record, 502. A fetch that fails after the head aborts the exchange; an
ABORT from the requester cancels the fetch. Redirects are followed. One
exchange is performed at a time; a graph that wants concurrency
instantiates more. Backed by `host_http_*`, kept apart from the fetch
imports because those serve the written store and the asset bank ahead
of the network and discard the status.

### 4.7 `wasm_browser_display_capture` — shared-surface source

Source: `src/platform/wasm/display_capture.rs`.

The peer of §4.2: that module presents pixels this host owns, this one
produces pixels it does not — the screen, window, or tab the person
picked in the browser's own share dialog. `getDisplayMedia` is the only
API for it, so capture is JS and the graph side is a pump.

Params: `width` / `height` (u16, required). The dimensions are the
*backing* size, not the shared size: the person choosing what to share
decides the extent and may change it mid-session, so each frame is one
region record whose header (§4.2) states the surface that arrived, and
the buffer bounds what a frame may be. Larger surfaces are scaled to
fit rather than refused. The shim hands over pixels and their extent;
the module writes the header. The module declares `capabilities =
["video.raster", "display.capture"]`.

Frames are RGB565, so `capture.pixels -> display.pixels` resolves
against any raster display that takes RGB565, `wasm_browser_canvas`
among them, with no converter.

Ending is one-way. When the person stops sharing — through the
browser's UI, which the page never sees otherwise — the current frame
finishes and the module latches. It does not pull again, because
pulling again means a fresh picker.

### 4.8 `wasm_browser_accessibility` — the mirror of a drawn UI

Source: `src/platform/wasm/accessibility.rs`; the mirror in
`host_shims.js` (`createAccessibilityMirror`).

An application that draws its own controls into a raster is opaque to
assistive technology and to the platform's text machinery. It publishes
an accessibility tree (`AccessibilityTree`,
`crates/fluxor-abi/src/contracts/accessibility.rs`); this module mirrors
the tree into the page and reports back what was done to it.

| Port | Content type | Carries |
|------|--------------|---------|
| `tree` in | `AccessibilityTree` | the application's nodes, in batches ended by `APPLY` |
| `actions` out | `AccessibilityActions` | `ACTIVATE`, `FOCUS`, `SET_VALUE`, `RESYNC` |
| `text` out | `TextEvents` | `COMMIT`, `COMPOSE`, `DELETE`, `SELECT` from the mirror's text fields |

**Batches are all or nothing.** The module parses every record and
checks every batch before the page is touched: a node whose parent is
not in the tree, a cycle, more nodes than the port's `max_nodes` fact
(1,024), a string past its limit, text that is not UTF-8, an unknown
role or a secret carrying a value rejects the whole batch. The page
keeps the tree it showed, the reason is logged, and the module sends
`RESYNC` on `actions`; it then ignores batches until one opens with
`TREE`. It sends `RESYNC` at its start too. A checked batch is applied
in one synchronous pass, so the page never shows part of one.

**Where.** One subtree inside the display surface element, laid over
its canvas, with `translate="no"`. An element's CSS bounds are its
node's bounds ÷ 64 × (the canvas's shown width ÷ its raster width): the
inverse of the pointer mapping (§4.9), recomputed on every presented
frame and every resize. Bounds keep magnifiers, touch exploration and
the input method's window on the drawn control.

**Elements.** A node is a `<div>` with its ARIA role, states, name and
description, and takes no pointer events. It is never a native button
or link: a native button turns Enter and Space into a click, which
would activate the control a second time beside the key record, and a
link carries no URL. An editable node is an `<input>` or `<textarea>`;
a slider or spinbutton is a native range or number input, which is what
some screen readers adjust. Those take pointer events, so a tap focuses
them natively and a phone raises its keyboard; the event still reaches
the surface's pointer listeners, so the application sees the same tap.
Elements are transparent, never `opacity: 0` or `visibility: hidden`,
which assistive technology may skip; the application draws its own
focus ring.

**Focus.** The application's focused node is the mirror's one tab stop,
so Tab from page chrome enters there. A `FOCUS` record moves DOM focus
only when focus is already in the mirror or on the page body: the
application never takes focus from page chrome. A focus change the
mirror did not cause is a `FOCUS` action, with `NO_NODE` when focus
leaves the surface.

**Actions.** A click on a mirrored control (assistive technology's
"press") is `ACTIVATE`; a value set on a native range is `SET_VALUE`,
and the element waits for the application's echo. Keys are never
actions: every key reaches the application as a key record.

**Text.** A mirror text field is controlled: the application owns its
value and selection, and the element changes only by echo of the tree,
except while an input method composes.

- A `beforeinput` outside a composition is stopped and translated. An
  insert (typing, autocorrect, paste, drop, a line break) is a `SELECT`
  when the element's selection is not where the application last put
  it, then `COMMIT`; text past 1,024 bytes is split at scalar
  boundaries with `CONTINUES` on all but the last. A deletion is
  `DELETE`, measured on the value in grapheme clusters, words or lines
  as the input type says, in scalar values. Undo and redo are stopped
  and not translated: the key reaches the application unflagged.
- A composition is reported from its composition events alone:
  `COMPOSE START`, a `COMPOSE` per update with the input method's
  highlighted range, `COMPOSE END`, then `COMMIT` when it produced
  text. The `beforeinput` types a composition raises are never
  translated; one browser sends `insertFromComposition` after
  `compositionend`, and translating it would commit the text twice.
  An echo that arrives mid-composition waits for its end.
- A change the browser makes that cannot be stopped is undone at the
  `input` event that follows; an `input` with no `beforeinput` before
  it (autofill) replaces the whole value.
- A selection the user moves is `SELECT`; the mirror's own echo is not.

Offsets on the wire are Unicode scalar values; the mirror converts from
the DOM's UTF-16 units.

With `tree` unwired the mirror is one text field over the surface,
focused by the first tap on it, and its records carry `NO_TARGET` and
no offsets.

**Secrets.** A secret node carries no value, and none enters the page.
Its element is a password field holding one bullet per scalar of the
length the node states, so offsets and deletion work. What the user
types, pastes or autofills into it goes to the application on `text`
and is never left in the DOM.

**What the page can see.** The mirror puts the application's names,
values and descriptions into the page DOM, where the browser's
extensions can read them; that is what makes them reachable. Text
reaches only the module wired to `text`. Application strings enter the
page through `textContent`, `value` and `setAttribute` with attribute
names from fixed tables, never as markup and never as a URL, so a
module cannot inject script or navigation through its tree.

**Worker mode.** The module runs where the kernel steps and the mirror
where the DOM is. The worker posts `{ type: 'a11y', open }` once and
`{ type: 'a11y', bytes }` per applied batch; the mirror's actions and
text edits return through the `accessibility_action` and `text` input
queues.

### 4.9 Pointer, wheel, keys and device pixel ratio

Two pixel spaces are in play. *Logical pixels* are the viewport's (CSS
pixels); size classes key on them. *Surface pixels* are the pixels of
the raster a surface presents: its canvas's own `width` × `height`,
whatever size the page shows it at. Pointer positions, pixel wheel
deltas and accessibility bounds are all in surface pixels, through one
mapping (`surfaceGeometry` in `host_shims.js`). A canvas whose control
was transferred to a worker keeps the attributes it left with, so in
worker mode the page takes the raster's extent from each frame the
worker reports showing.

**Device pixel ratio.** `wasm_browser_surface_traits` reports
`dpr_eighths`: `devicePixelRatio` in eighths, to the nearest eighth,
within 1..=255 (a reported ratio is never 0, which means unreported). A
producer renders at viewport × `dpr_eighths` ÷ 8 for its raster to be
presented 1:1. A window moved to a screen of another density, or a
page zoom, fires no `resize`, so the publisher also listens on a
`resolution` media query for the ratio in force and arms one for the
next ratio each time it fires; a ratio change bumps the epoch like a
resize.

**Wheel.** A `wheel` listener on each display surface, not passive so
it can keep the page from scrolling, queues `KIND_WHEEL` pointer
records (`installWheel`). CSS-pixel deltas become `WHEEL_PIXELS` in
eighths of a surface pixel; line deltas become `WHEEL_DETENTS` at
three lines a detent; a page is the surface's height. At most one
record per unit goes out per animation frame, the deltas summed and
the last position carried; a sum past one record is split, never
clamped. A wheel event with Ctrl held is the browser's zoom and a
trackpad's pinch: it is neither forwarded nor stopped, and reaches the
application as a ratio change.

**Keys.** The keyboard producer (`installKeyboard`) posts each key
record one task after its keydown. The browser raises the `beforeinput`
a key causes inside the keydown's own task, so by then the mirror has
said whether its text field translated it; such a key carries
`KEY_TEXT`, and the application does not apply it a second time. A
keydown an input method owns produces no key record. A held key is
reported once. Outside the mirror the page stops Enter, Shift, Space
and the arrows from scrolling or activating page chrome; in a mirror
text field those must type, so there the caret and focus keys are
stopped instead (arrows, Home, End, PageUp, PageDown, Tab, Ctrl/Meta+A)
and reach the application as plain keys.

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
`FS_WRITE` stages its `data` against the handle and publishes the bytes
as one file at `FS_CLOSE`, in the persistent layer `storage.object` reads.
`FS_SEEK` and `FS_FSYNC` return `ENOSYS`; the streaming fetch model has no
equivalent.

### `storage.object` provider — `src/platform/wasm/object.rs`

Adds the bounded-range reads that demand-paging needs, plus a write
layer:

- **Read layer.** `HEAD` / `RANGE_GET` over `fetch()` with byte
  ranges, serving shipped, immutable content from the page origin and
  the in-bundle `asset://` map.
- **Write layer.** `PUT` stages the blob in the shim's in-memory
  object store, so an immediately following `GET` / `HEAD` /
  `RANGE_GET` of the same key sees it, and persists it in the
  background to OPFS (Origin Private File System), with an IndexedDB
  fallback where OPFS is unavailable (insecure contexts, older
  browsers). The store is re-hydrated from persistent storage at
  boot, so a key written in a prior session reads back after a
  reload. This is what lets user-written data (save states, imported
  assets) survive in the browser. `DELETE` removes a key from this layer
  only (`host_object_delete`); a key served by the read layer is not the
  provider's to delete.

`LIST` answers `ENOSYS`: the read layer falls through to `fetch()` against
the page origin, which cannot be enumerated, and a listing of the written
layer alone would omit objects `GET` serves. Enumeration is the
`storage.namespace` provider's.

Reads consult the written store before falling through to `fetch()`.
Durability is best-effort: the per-handle fence stays `Volatile`,
matching the browser quota model (origin storage may be evicted) and
the endpoint surface's best-effort cache role.

### `storage.namespace` provider — `src/platform/wasm/namespace.rs`

The browser has no `readdir`, so directory-style discovery derives a
tree from the same flat key space the object layer writes. `/` is the
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
tree, never a stall. `LIST` pages by name: the cursor is the last name
the page returned, in UTF-8 byte order, and a write behind it never shifts
the next page; `STAT`
returns size, mtime, kind, and an etag (a stable FNV hash synthesised
per key for written entries, or the manifest-supplied etag for shipped
content).

### `image_decode` provider — `src/platform/wasm/image_decode.rs`

`DECODE` names a byte range of an object by its key. The shim reads that
range the way the `storage.object` provider reads a key (the written store,
then `asset://`, then a ranged `fetch()` of the origin), decodes it with
`createImageBitmap`, scales it to the requested size on an
`OffscreenCanvas` and packs it as RGB565. The encoded bytes never enter
wasm memory. `RECV` answers `EAGAIN` until the pixels exist, then drains
them; a missing or short range, or bytes the browser cannot decode, is
`EIO`.

`modules/foundation/object_bank` composes the two surfaces into a
storage-backed asset bank: enumerate a prefix via `storage.namespace`
`LIST`, stream each entry via `storage.object` `GET` / `RANGE_GET`.
Wired as `button → gesture → object_bank → codec → audio_out`, a
browser plays media from a user-populatable library (imported through
the object write layer, or listed in `fluxor-manifest.json`) rather
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
- Application modules upstream of `wasm_browser_*` native modules consume
  native AV / input / control content types; nothing knows it is a
  browser.
- Audio scheduling is implemented once in the shim's worklet ring; no
  application code touches WebAudio.
- Input identity is preserved end-to-end; the input native modules emit
  source-side records with no application mapping.
- The host's own copies of contract values (the mirror's role table and
  record constants, the key and wheel constants) equal the contract's:
  each is declared on a line naming the contract constant it stands
  for, and `fluxor ci` compares them.
- `fluxor ci` has no browser. The `wasm-host-shims (node)` phase drives
  the real host files against a small DOM; a screen reader, an input
  method and a phone keyboard are checked by hand.
- Every kernel-side wasm extern has a matching `host_*` shim entry,
  and the shims behave as the native modules above rely on when driven from
  a fake linear memory under `node` — the `wasm-host-shims (node)`
  phase of `fluxor ci`, which reports itself skipped rather than
  passed when no `node` is on the path.
- A native module is a kernel-side half, a manifest, and a shim
  implementation; adding one changes neither the kernel ABI nor the
  platform contract.

---

## 8. Related documentation

- [wasm_platform.md](wasm_platform.md) — the platform target this host
  runs. Owns the module envelope, wasm bundle format, kernel-uniform
  host imports, and how the host drives the kernel.
- [av_capability_surface.md](av_capability_surface.md) — surfaces
  `wasm_browser_audio` and `wasm_browser_canvas` consume.
- [input_capability_surface.md](input_capability_surface.md) — surfaces
  the input native modules produce, and their record shapes.
- [storage_capability_surface.md](storage_capability_surface.md) — the
  storage surfaces the §5 providers implement.
- [protocol_surfaces.md](protocol_surfaces.md) — protocol substrate the
  WebSocket native modules feed.
- [browser_capability_surface.md](browser_capability_surface.md) — the
  browser as a pure-JS endpoint, without a WASM kernel.
- [endpoint_capability_surface.md](endpoint_capability_surface.md) — the
  generic endpoint surface that path follows.
