# WASM Browser Host

The browser host runs the WASM platform target inside a browser tab.
It is one of several host environments for the WASM target — peers
include `wasm_wasmtime_host` (standalone CLI) and edge runtime hosts.
The platform itself is host-agnostic; this doc is normative only for
browser hosts.

This document is the browser-host peer of `wasm_platform.md`. It
defines the bootstrap shim, the host-import surface specific to
browsers, the catalogue of host-provided built-in modules, and the
binding strategy each built-in uses (WebAudio AudioWorklet, WebGPU,
WebSocket, DOM input, OPFS / IndexedDB).

---

## 1. Scope

This host doc defines:

- the bootstrap shim that loads `<config>.wasm` and drives the kernel
- the browser-specific host imports above the kernel-uniform set
- the catalogue of built-in modules the browser host provides
- the prescribed binding for each built-in (`AudioWorklet` for audio,
  `WebGPU` with `WebGL2` and `Canvas2D` fallbacks for raster, and so
  on)
- audio unlock, background-throttling, permission, and tab-lifecycle
  policy
- the page-facing API the shim exposes

It does not define:

- the platform target, module envelope, bundle format, kernel tick
  semantics, or kernel-uniform host imports — those belong to
  `wasm_platform.md`
- a JavaScript framework or bundler — the shim ships as a single ESM
  file alongside the `.wasm`
- application profile code — application-specific JS belongs in app
  profiles, not in this host shim
- the endpoint surface — see `endpoint_capability_surface.md` for
  hosts that don't run a WASM kernel

---

## 2. Position in the Architecture

```
Fluxor application graph (target-agnostic)
      |
      | AudioSample / AudioEncoded / VideoRaster / VideoDraw / Input* / WsFrame / ...
      v
WASM kernel + modules (one .wasm bundle, per wasm_platform.md)
      |
      | kernel-uniform host imports (time, log, instantiate, invoke)
      | + browser-specific host imports (this doc §4)
      v
browser host shim
      |
      | WebAudio AudioWorklet / WebGPU / WebSocket / DOM events / OPFS
      v
browser platform APIs
```

The shim is host-side code in JS. Below the shim is the browser. Above
the shim is the WASM kernel and the modules it loads. Everything from
the kernel up is binary-identical to the same `<config>.wasm` running
under wasmtime, edge, or any other WASM host — only the shim layer
changes.

---

## 3. Bootstrap Shim

The shim is a single ESM file `fluxor_browser_shim.js` (~250 lines).
It is loaded by a thin HTML page that points at a `.wasm` bundle and
provides DOM elements for the built-in modules to bind to (canvas,
audio context, status surface).

Page-facing API:

```js
import { Fluxor } from '/fluxor_browser_shim.js';

const fluxor = await Fluxor.boot('/<config>.wasm', {
  canvas:        document.getElementById('screen'),
  audioContext:  optional existing AudioContext,
  statusElement: document.getElementById('status'),
  onTelemetry:   line => console.debug(line),
});
fluxor.start();
```

`Fluxor.boot` does, in order:

1. `WebAssembly.instantiateStreaming(fetch(url), imports)` with the
   import object built from §4.
2. Reads the kernel's `EMBEDDED_MODULES_BLOB` and
   `EMBEDDED_CONFIG_BLOB` data segments by calling kernel exports
   `kernel_modules_blob_offset()` / `kernel_modules_blob_len()` and
   `kernel_config_blob_offset()` / `kernel_config_blob_len()`, then
   slices `kernel.exports.memory.buffer` at those offsets to read
   the bytes. (A `_capacity()` accessor for each blob exists too;
   the bundle tool uses it to size the rewrite, the shim doesn't
   need it.) Parses the modules.bin index.
3. Calls kernel `kernel_init()`, which walks the module index and
   for each module either:
   - **PIC-shaped wasm32 module**: kernel calls
     `host_instantiate_module(bytes_ptr, bytes_len, …)` to get a
     handle, then calls module exports via `host_invoke_module`.
   - **Built-in module**: kernel matches the module's `name_hash`
     against the registered built-ins (`wasm_browser_canvas`,
     `wasm_browser_audio`, `wasm_browser_dom_input`,
     `wasm_browser_websocket`, `host_browser_fetch`) and registers
     the corresponding `BuiltInModule` step function — the
     scheduler-uniform path used on every target. The step function
     calls the browser-specific host imports directly (§4).
4. Starts the tick loop: `requestAnimationFrame` calls
   `kernel_step()` and re-queues. An `AudioWorklet` triggers a
   second tick path on audio rate when a `wasm_browser_audio` module
   is present (§5).

The shim never reads or interprets surfaces directly. All
content-bearing work happens inside the `.wasm` bundle's modules. The
shim only routes host imports and drives the tick.

---

## 4. Browser-Specific Host Imports

In addition to the kernel-uniform imports defined in
`wasm_platform.md` §6, the browser host provides one direct import
per browser capability. Each built-in module's step function calls
its capability's import(s) directly. Each capability gets a small,
typed surface — the same shape Linux uses for per-built-in Rust
functions (`linux_audio_step`, `host_asset_source_step`, etc.).

```text
// Raster present (canvas built-in).
host_canvas_present(
    ptr:    *const u8,                // pixel buffer (RGB565 or RGBA8)
    len:    usize,
    width:  u32,
    height: u32,
)

// Realtime audio sink (AudioWorklet built-in).
host_audio_play(
    ptr:         *const u8,           // PCM samples, interleaved channels
    len:         usize,
    sample_rate: u32,
    channels:    u32,
)

// DOM input event queue (keyboard / pointer / touch).
host_input_pop(buf: *mut u8, len: usize) -> i32  // bytes-written or 0 if queue empty

// WebSocket transport.
host_ws_open(url_ptr: *const u8, url_len: usize) -> i32          // socket handle
host_ws_send(handle: i32, data: *const u8, len: usize) -> i32    // bytes accepted
host_ws_recv(handle: i32, buf: *mut u8, len: usize) -> i32       // bytes written

// HTTP fetch transport. Backs the `host_browser_fetch` channel
// source and the wasm-target FS provider (`src/platform/wasm/fs.rs`),
// which fronts FS_CONTRACT (FS_OPEN / FS_READ / FS_CLOSE) on top of
// `fetch()` so any module that uses the FS contract on bare-metal
// (media_loader, foundation/http file routes, …) works on wasm
// without channel plumbing for asset ingest.
host_fetch_open(url_ptr: *const u8, url_len: usize) -> i32       // request handle
host_fetch_recv(handle: i32, buf: *mut u8, len: usize) -> i32    // bytes written
host_fetch_size(handle: i32) -> i32                               // Content-Length four-state: see below
host_fetch_close(handle: i32) -> i32                              // 0 on success, idempotent on unknown handles

// Cryptographic random (delegates to crypto.getRandomValues).
host_csprng_fill(buf: *mut u8, len: usize) -> i32                // bytes written
```

`host_fetch_size` is a four-state code — its return drives the
wasm-target FS provider's `FS_STAT` translation, which in turn
drives length-aware HTTP serving (`HANDLER_FS_FILE`):

| Return | Meaning                                                       | FS_STAT  | HTTP commits |
|--------|---------------------------------------------------------------|----------|--------------|
| `>= 0` | Content-Length received                                       | `OK`     | `200 OK` with `Content-Length`             |
| `-1`   | Headers received, no Content-Length (chunked / unknown)       | `ENOSYS` | streaming `200 OK` (body ends on close)    |
| `-2`   | Hard failure — `fetch()` rejected, response status not OK     | `ENODEV` | `502 Bad Gateway`                          |
| `-3`   | Headers not yet received (`fetch()` promise unresolved)       | `EAGAIN` | keep polling — never commit on this state  |

The four-way split lets HTTP wait for an outcome before committing
a response code, so a slow `fetch()` failure surfaces as `502`
rather than a truncated `200 OK`. Polling is cheap (cached state,
no fetch progress) and idempotent.


Each import lives in the module file that uses it (file paths
follow the `BuiltInModule` registration sites under
`src/platform/wasm/{canvas,audio,dom_input,websocket,fetch,hal}.rs`).
A new capability is one file with one extern block plus one shim
implementation.

The shim provides implementations for the imports above as part of
the import object passed to `WebAssembly.instantiateStreaming`.
Built-in *modules* register through the kernel scheduler the same
way as on every target (`scheduler::store_builtin_module` +
`BuiltInModule::step`); the imports are the *capabilities* those
built-ins call into, not the modules themselves.

A host that cannot provide a capability (e.g. an embedded WebView
with no audio policy) omits the corresponding import from the
import object. Instantiation traps with a clear "missing import"
message at boot. Configs that don't reference the missing
capability are unaffected.

---

## 5. Built-in Module Catalogue

Built-ins are declared in YAML the same way as on every other target:

```yaml
- name: screen
  type: wasm_browser_canvas
  prefer: webgpu              # webgpu | webgl2 | canvas2d
- name: speaker
  type: wasm_browser_audio
  sample_rate: 44100
  channels: 2
- name: net
  type: wasm_browser_websocket
  url: "wss://example.com/ws"
- name: dom_input
  type: wasm_browser_dom_input
- name: assets
  type: host_browser_fetch
  url: "https://example.com/data.bin"
```

Each entry below lists its ports, params, prescribed binding, and
fallback chain. Sections marked **(planned)** describe capabilities
the architecture covers but that no built-in is registered for yet;
configs that reference those types fall through to the missing-module
path.

### 5.1 `wasm_browser_audio` — AudioWorklet PCM sink

| Port | Direction | Content type |
|------|-----------|--------------|
| `audio`      | input  | `AudioSample` |

| Param | Type | Notes |
|-------|------|-------|
| `sample_rate` | u32 | Required (TLV tag 10) |
| `channels`    | u8  | Default `1` (TLV tag 11) |

A `telemetry` output port emitting `MON_PRESENTATION` lines is
planned. Until that port is declared, telemetry rides over `host_log`.

**Prescribed binding: AudioWorklet.** The shim creates one
`AudioWorkletNode` at boot, registered with a worklet processor that
maintains a ring buffer of decoded PCM frames. The module's host glue
reads `AudioSample` blocks off the channel and pushes them into the
ring buffer.

Ring transport prefers `SharedArrayBuffer` (zero-copy across the
audio-thread boundary) and falls back to `postMessage`-batched
buffers when `SharedArrayBuffer` is unavailable
(`crossOriginIsolated === false`). The fallback is observable in
`MON_PRESENTATION` as a `latency_floor` raised by ~10–20 ms.

The worklet's `process()` pulls one quantum (128 frames) per call;
on underrun emits silence and a `MON_PRESENTATION underflow` line.
StreamTime is anchored to `audioContext.currentTime` — the kernel's
clock-authority machinery in `av_capability_surface.md` §4 sees this
sink as the authority for any group it joins.

**No fallback to plain `BufferSource` is supported.** AudioWorklet is
universally available in evergreen browsers and the cost of
maintaining a non-worklet path is not worth the small mobile-Safari
edge cases that remain. A page-level error message prompts the user
to update if the worklet is missing.

**Audio unlock**: the shim exposes a `fluxor.unlockAudio()` method
that calls `audioContext.resume()` from a user gesture. The first
call is mandatory before audio frames flow; subsequent gestures are
no-ops. Browser-history quirks (BFCache, freeze/resume) are handled
in §7.

### 5.2 `wasm_browser_canvas` — raster sink

| Port | Direction | Content type |
|------|-----------|--------------|
| `raster`     | input  | `VideoRaster` |

| Param | Type | Notes |
|-------|------|-------|
| `width`  | u16 | Required (TLV tag 10) |
| `height` | u16 | Required (TLV tag 11) |

Pixel format is RGB565 little-endian (same as `st7701s` and
`linux_display`). A `telemetry` output port emitting
`MON_PRESENTATION` lines and the `prefer:` capability-tier param
described below are planned; the shim uses a single
`host_canvas_present` import.

**Prescribed binding: WebGPU**, with progressive fallback.

The module's host glue runs a 3-tier capability detector at boot:

1. **WebGPU** — `navigator.gpu.requestAdapter()` succeeds. A minimal
   compute shader does pixel-format conversion (RGB565 / RGBA8 /
   YUV422 → display RGBA) and writes to a `GPUCanvasContext`. The
   `VideoRaster`'s declared format selects which shader variant runs.
   No per-pixel JS in the hot path.
2. **WebGL2** — when WebGPU is unavailable. A fragment shader does
   the same conversion against a `WebGL2RenderingContext`. Slightly
   higher per-frame overhead from the GL state; same architectural
   shape.
3. **Canvas2D** — when neither GPU path works. `createImageData`
   plus a JS pixel walk. Reserved for low-end / sandboxed embedded
   WebViews. Emits a `MON_PRESENTATION degraded_mode` telemetry
   line so operators know the path that landed.

The `prefer:` parameter forces a tier explicitly when the default
detection picks the wrong path (testing, fallback validation, locked
appliance kiosks).

Frame presentation runs inside the rAF tick. The module's `step`
reads at most one `VideoRaster` per tick into the active GPU/canvas
buffer, then schedules a present. Producer-side rate-limiting (e.g.
emulator running ahead of the display) is the producer's concern;
the canvas sink takes the most recent frame and discards stale ones,
emitting `missed_present` telemetry on each drop.

### 5.3 `wasm_browser_websocket` — byte-stream transport

| Port | Direction | Content type |
|------|-----------|--------------|
| `tx` | input  | `OctetStream` (raw bytes to send on the WebSocket) |
| `rx` | output | `OctetStream` (raw bytes received from the WebSocket) |

| Param | Type | Notes |
|-------|------|-------|
| `url` | string | WS URL to connect to (TLV tag 10) |

A raw byte transport. Stream-surface semantics (Stream Surface v1,
datagram, session_ctrl) live in modules layered above
(`foundation/ws_stream` → `foundation/remote_channel`), the same
way `tls` wraps `net_proto` byte streams. Consumers that want
NetStreamCmdV1 semantics run `wasm_browser_websocket → ws_stream →
remote_channel` and read from the top of the stack.

**Prescribed binding: WebSocket** opened from the host page via
`new WebSocket(url)`. The shim's `host_ws_open` / `host_ws_send` /
`host_ws_recv` imports move bytes between the module's channels and
the live socket.

A separate `wasm_browser_webtransport` built-in (planned) covers
QUIC-shaped `transport.mux` when the browser supports it; the
remote-channel code path picks whichever transport the peer
advertises.

### 5.4 `wasm_browser_dom_input` — input surface source

| Port | Direction | Content type |
|------|-----------|--------------|
| `events` | output | `InputBinaryState` |

Keyboard events are emitted as `InputBinaryState` snapshots on a
single port. The shim normalises DOM event quirks (focus / blur,
repeat, sticky keys) before queuing events for `host_input_pop`.
Output preserves source identity — no application mapping inside
this module. App-specific binding tables live in mapper modules
elsewhere in the graph (`input_capability_surface.md` §8).

Pointer / touch / gamepad sources are planned and will surface as
their own output ports (`pointer` / `touch` / `gamepad`, each with
its respective content type). Until the manifest declares them,
downstream filters can split a multi-modal stream by source-id off
the single `events` port.

The shim's `boot()` argument optionally takes a `captureRoot`
element; events outside it are ignored. Default is the document
root.

### 5.5 `host_browser_fetch` — HTTP fetch source

| Port | Direction | Content type |
|------|-----------|--------------|
| `bytes` | output | `OctetStream` (response body) |

| Param | Type | Notes |
|-------|------|-------|
| `url` | string | URL to fetch (TLV tag 10) |

**Prescribed binding: `fetch()` API.** The shim opens a request via
`host_fetch_open(url_ptr, url_len)`; the module's step function
drains response bytes through `host_fetch_recv` into the `bytes`
port. The `host_*` prefix matches `host_asset_index` on Linux —
the same fetch capability surfaces on non-browser hosts (e.g.
wasmtime wires `host_fetch_*` to libcurl). One in-flight request
per module instance; for parallel fetches, instantiate one module
per URL.

### 5.6 `wasm_browser_storage` — cache role (planned)

| Port | Direction | Content type |
|------|-----------|--------------|
| `read`     | input/output | OctetStream cache protocol |

**Prescribed binding: OPFS** (Origin Private File System) when the
browser supports it; falls back to **IndexedDB**. Quota is
origin-scoped and may be evicted; the cache contract is best-effort
per `endpoint_capability_surface.md` §4 (Cache role).

**Status — persistent `storage.object` write tier (landed).** The
generic cache-role *module* is still planned, but the OPFS binding it
prescribes is now realized at the contract level: the wasm
`storage.object` provider (`src/platform/wasm/object.rs`) gained a `PUT`
op backed by `host_object_put` in `host_shims.js`. This is the
write/persistence half the read-only `fetch()` tier could never provide
— it is what lets RFC 0009 save-state derivatives (and any imported
asset) survive in-browser. Semantics:

- **Synchronous acceptance, background durability.** `PUT` stages the
  blob in an in-memory `objStore` (so an immediately-following
  `GET`/`HEAD`/`RANGE_GET` of the same key sees it) and returns `0`; the
  OPFS file write happens in the background. The contract fence stays
  `Volatile` — origin storage may be evicted, matching §4's best-effort
  Cache role.
- **OPFS-first reads.** `HEAD`/`RANGE_GET` consult `objStore` before
  `fetch()`, so a written key reads back without a network round-trip.
  Unknown keys fall through to the read-only `fetch()`/`asset://` tier
  (shipped, immutable content) unchanged.
- **Boot hydration.** At startup the shim recursively walks OPFS into
  `objStore`, so a key written in a prior session reads back after a
  reload. Hosts without OPFS (older browsers, private mode) degrade to
  session-only writes; reads still serve from `fetch()`.

The binding is checked by the host-shim coverage guard
`tools/tests/wasm_host_shim_coverage.rs` (every wasm extern must have a
matching `host_*` shim), which runs in `make ci`. Behavior is
additionally exercised by `tests/host/wasm_object_opfs.test.js` (a Node
test with a mock OPFS). Both `tools/tests/` and `/tests/` are local-only
by repo policy (not tracked — see `.gitignore`), and there is no JS
runtime in `fluxor ci`, so neither file is committed nor gates the
published CI.

**Status — `storage.namespace` enumeration tier (landed).** The browser
has no POSIX `readdir`, so directory-style discovery (truffle's
`truffle_scanner`, any `requires_contract = "storage.namespace"`
consumer) had nothing to talk to on wasm. The wasm `storage.namespace`
provider (`src/platform/wasm/namespace.rs`, bindings `host_ns_stat` /
`host_ns_list`) closes that gap by deriving a directory tree from the
**same flat key space** the object tier writes:

- **One key space, two surfaces.** `/` is the hierarchy separator over
  the union of `objStore` (OPFS-backed user data) and a fetched
  **manifest** of shipped content (`manifestUrl`, default
  `fluxor-manifest.json` — a JSON array of `{key, size, mtime?, etag?}`).
  A key `saves/tetris` makes `LIST("")` yield `saves` (namespace) and
  `LIST("saves/")` yield `tetris` (object). A consumer scans here, then
  fetches each hit via `storage.object` `GET` on the *same key*.
- **Synchronous answers.** `LIST`/`STAT` resolve from the in-memory
  union index — the scanner treats a negative `LIST` as end-of-listing
  and does not retry, so these never return EAGAIN. The index is
  hydrated asynchronously (OPFS walk + manifest fetch) and mutated
  synchronously on object `PUT`; a scan that races boot sees a smaller
  tree, never a stall.
- **Paging + identity.** `LIST` pages via an integer cursor; `STAT`
  returns `[size][mtime][kind][etag]`, with a stable FNV etag
  synthesized per key for objStore entries (the scanner packs the etag
  as its 16-byte ObjectId) or the manifest-supplied etag for shipped
  content.

Binding checked by the same `wasm_host_shim_coverage.rs` guard (run in
`make ci`); behavior exercised by `tests/host/wasm_namespace.test.js`.
Both are local-only by repo policy (not tracked — see `.gitignore`).

**Putting the tiers together — the persistent-library player.** The
write tier, the namespace tier, and the existing codec/audio path
compose into a browser music library that survives reloads.
`modules/foundation/object_bank` is `foundation/bank` with its `fs`
backend swapped for `storage.namespace::LIST` (enumerate a prefix) +
`storage.object` `GET`/`RANGE_GET` (stream each entry) — identical
navigation/FMP/streaming machinery, storage-backed source. The example
graph `examples/audio_player/wasm-library.yaml` wires
`button → gesture → object_bank → codec → audio_out`, so a browser plays
WAV/MP3/AAC from a *user-populatable* library (imported via the
object-PUT tier, or listed in `fluxor-manifest.json`) instead of only
bundle-baked `asset://` tracks. The graph type-checks under `fluxor
validate` for the wasm target; the enumerate→stream protocol is
additionally exercised at the shim level by the local-only (uncommitted)
Node test
`tests/host/wasm_object_bank_flow.test.js`.

### 5.7 `wasm_browser_video_decode` — encoded media decode (planned)

| Port | Direction | Content type |
|------|-----------|--------------|
| `encoded` | input  | `VideoEncoded` |
| `pixels`  | output | `VideoRaster` |

**Prescribed binding: WebCodecs** for hardware-accelerated decode of
H.264/H.265/VP9/AV1 frames. Output is `VideoRaster` consumed by
`wasm_browser_canvas`. Optional: only present in graphs that need
codec-domain video.

### 5.8 `wasm_browser_media_element` — direct media playback (planned)

| Port | Direction | Content type |
|------|-----------|--------------|
| `control` | input  | `MediaUrl` instructions |

**Prescribed binding: `HTMLMediaElement`** with HTTP range URLs.
Used when the codec/container is natively playable and sync
constraints are loose — see `endpoint_capability_surface.md` §9
"Direct media" routing mode.

---

## 6. Audio Unlock and Lifecycle

Browsers require a user gesture before `AudioContext.resume()`. The
shim's policy:

- Until `fluxor.unlockAudio()` is called, the
  `wasm_browser_audio` module operates in *suspended* mode: it
  consumes input frames but writes silence to the worklet. No frames
  are dropped; the StreamTime advances normally.
- The first qualifying gesture (`pointerdown`, `keydown`,
  `touchstart`) anywhere on the page calls `unlockAudio()`
  automatically unless the page opts out via
  `Fluxor.boot({ manualAudioUnlock: true })`.
- After resume, suspended-mode silence stops; subsequent frames go
  to the worklet.

Once unlocked, audio stays unlocked across the page's lifetime. BFCache
restoration emits a fresh `pageshow` event; the shim re-validates
`audioContext.state === 'running'` and re-resumes if needed.

`document.visibilityState === 'hidden'` triggers a
`MON_PRESENTATION background_throttled` telemetry line. The kernel's
provider modules decide policy: a passive viewer might drain video
frames; a music streamer keeps audio flowing. The shim itself does
not silence audio on hidden — the browser may choose to throttle the
audio thread, but that is observable per-frame (`process()` calls
slow), not a policy decision the shim makes.

---

## 7. Permissions

Microphone, camera, gamepad, MIDI, XR, and persistent storage all
follow the Permissions API model. The shim requests on demand
(typically inside a built-in module's first `step` that needs the
permission) and surfaces the result as a capability downgrade rather
than a hard error:

- Granted → built-in proceeds.
- Denied → built-in emits `MON_INPUT capability_revoked` telemetry
  and ports declare themselves degraded. Mappers and consumers see
  the same "absent source" condition they would see for any
  unwired source.
- Prompt-required → the shim deferred the prompt to the next user
  gesture; emits a `MON_INPUT permission_pending` telemetry line in
  the meantime.

Permission state is checked at `kernel_init` and at every visibility
change so revocations are picked up.

---

## 8. Tab Lifecycle

Browser tabs go through more lifecycle states than native processes:

- `pageshow` / `pagehide` — visible / not-visible.
- `freeze` / `resume` — Chrome's tab freezing for background tabs.
- `unload` — terminal.
- BFCache — back/forward cache may restore a fully suspended tab.

The shim handles each by emitting a `Telemetry` message into the
kernel:

```text
MON_BROWSER lifecycle=pageshow|pagehide|freeze|resume|bfcache_restore|unload
```

The kernel and provider modules decide the response. A typical
WebSocket transport closes the connection on `freeze`, reconnects on
`resume`. Audio sinks pause on `freeze` (the AudioContext suspends
automatically anyway). The session-epoch mechanism in
`protocol_surfaces.md` lets remote channels detect a stale session
on resume and trigger a clean reconnect via `SessionCtrlV1`.

---

## 9. Threads and Workers

The MVP runs single-threaded on the main thread, with the
`AudioWorkletNode` as the only off-main-thread work. Reasoning:

- WASM threads require `SharedArrayBuffer`, which requires COOP/COEP
  headers. Many deployment paths (embedded WebViews, Cloudflare
  Pages defaults) don't set them.
- The kernel's scheduler is designed around `kernel_step()` returning
  bounded-work intervals. Single-threaded performance is sufficient
  for small graphs (~7-10 modules — e.g. one core, one audio sink, one
  raster sink, ~10 modules total).
- Web Worker fan-out is a future option that doesn't change the
  module ABI — workers run additional `kernel_step()`-equivalent
  loops over partitioned module sets.

When a workload demands threads, the upgrade path is:

1. Page sets COOP/COEP.
2. Shim detects `crossOriginIsolated === true`.
3. Kernel built with `wasm32-wasi-preview1-threads` (or successor).
4. Module memory becomes shared; channels become zero-copy.
5. Worker pool drives `kernel_step()` for partitioned subgraphs.

Until then, the shim produces clear telemetry when single-threaded
performance is the bottleneck so the upgrade is data-driven.

---

## 10. Validation

A browser-host integration is healthy when:

- The same `<config>.wasm` runs on the browser host and a wasmtime
  host with no rebuild — only the shim differs.
- Application modules upstream of `wasm_browser_*` built-ins consume
  native AV / input / control content types; nothing knows it's a
  browser.
- Audio scheduling is implemented once in the AudioWorklet binding
  inside `wasm_browser_audio`; no application code touches WebAudio.
- Raster present picks the highest-fidelity GPU path the browser
  supports and reports the chosen tier.
- Input identity is preserved end-to-end; `wasm_browser_dom_input`
  emits source-domain `Input*` events with no application mapping.
- Audio unlock and visibility transitions are observable as
  telemetry lines, not silently swallowed.
- Adding a new built-in (say, `wasm_browser_webxr` for pose input)
  requires writing a JS implementation and a `register_builtin`
  call in the shim; no kernel, module-ABI, or platform-doc changes.
- The shim file is small and audit-able — under ~500 lines of plain
  JS, no bundler.

---

## 11. Open Items

- **WebGPU shader library.** The format-conversion shaders for
  RGB565, RGBA8, YUV420, NV12 should be a small published library
  the canvas binding pulls from. Land alongside the first WebGPU
  build of `wasm_browser_canvas`.
- **AudioWorklet ring buffer crate.** A reusable
  `SharedArrayBuffer`-backed lock-free SPSC ring buffer for PCM —
  several of the host doc's built-ins want this shape (audio,
  encoded video). Worth extracting once two consumers exist.
- **Encoded video on canvas.** When `wasm_browser_video_decode` and
  `wasm_browser_canvas` are both present, the decode → present path
  should bypass system memory by handing `VideoFrame` objects
  directly to the canvas binding via `GPUExternalTexture`. Defer
  until a workload uses encoded video.
- **WebTransport.** Adds a `transport.mux` peer to the WebSocket
  binding. Land when an upstream peer offers `transport.mux` and
  the latency win is measurable.
- **Service Worker as a tick host.** Lets the WASM kernel survive a
  tab close. Speculative; revisit when a workload needs durable
  background presence (e.g. push-notification gateway endpoint
  living in the browser).

---

## 12. Related Documentation

- `architecture/wasm_platform.md` — the platform target this host
  refines. Owns module envelope, bundle format, kernel-uniform host
  imports, and tick model.
- `architecture/av_capability_surface.md` — content types
  `wasm_browser_audio` and `wasm_browser_canvas` consume.
- `architecture/input_capability_surface.md` — content types
  `wasm_browser_dom_input` produces.
- `architecture/protocol_surfaces.md` — stream-surface contract
  `wasm_browser_websocket` implements.
- `architecture/endpoint_capability_surface.md` — external endpoint
  surface for browsers that don't run a WASM kernel.
- `architecture/browser_capability_surface.md` — endpoint profile
  for the browser. Stays as the "no-WASM" path. Cross-referenced
  from `endpoint_capability_surface.md` §1a.
