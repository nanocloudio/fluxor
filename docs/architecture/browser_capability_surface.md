# Browser Capability Surface

The browser is a profile of the endpoint capability surface defined in
`endpoint_capability_surface.md`. This document specifies the
browser-specific bindings: which web platform APIs implement each
generic concept, and which browser constraints the runtime absorbs.

This document is normative only for browser endpoints. The shape of
an endpoint, its role decomposition, its session protocol, and its
audio routing modes are owned by the endpoint surface. A browser tab
that runs a WASM Fluxor kernel is a different thing entirely; see
`wasm_platform.md` and `wasm_browser_host.md`.

---

## 1. Scope

This profile defines:

- which web platform APIs realise each generic endpoint role
- the shipped browser runtime core (`endpoint_runtime.js`)
- browser constraints the runtime absorbs (audio unlock, background
  throttling, sandboxed storage)
- transport options a browser endpoint can speak
- module and asset naming for browser endpoints

It does not define:

- new media or input primitives (delegated to the AV / input surfaces)
- the endpoint role decomposition, session protocol, or audio routing
  modes (delegated to the endpoint surface)
- a JavaScript application framework

---

## 2. Web API realisation

Each generic endpoint surface concept maps to one or more web platform
APIs. The implementation column is browser-specific; the surface
column is not.

### AV surfaces

| Fluxor surface  | Browser implementation                                                |
|-----------------|-----------------------------------------------------------------------|
| `AudioSample`   | WebAudio PCM sink via an AudioWorklet for timed playback              |
| `AudioEncoded`  | WebCodecs, Media Source Extensions, WASM decoder, or pass-through     |
| `VideoRaster`   | Canvas, WebGL texture upload, ImageBitmap, or WebGPU texture          |
| `VideoDraw`     | DOM / canvas retained UI renderer or app-specific draw-list renderer  |
| `VideoEncoded`  | WebCodecs or Media Source Extensions                                  |
| `MediaMuxed`    | MediaElement, MSE, or recording / broadcast path                      |

### Input sources

Browser DOM events map onto the per-class input surfaces defined in
`input_capability_surface.md`:

| Browser source                    | Fluxor surface                        |
|-----------------------------------|---------------------------------------|
| DOM `KeyboardEvent`               | `KeyEvents`                           |
| `PointerEvent` (mouse / stylus / touch) | `PointerEvents`                 |
| `Gamepad` API                     | `GamepadEvents`                       |
| Web MIDI                          | `MidiEvents`                          |
| Page virtual button               | button wire (`OctetStream` transitions) |
| App-semantic overlay control      | action wire (FNV-hashed FMP command)  |
| Viewport / modality / audio state | `SurfaceTraits`                       |

### Audio routing modes

The four generic audio routing modes (endpoint surface §9) bind to web
APIs as follows:

| Mode             | Browser implementation                                              |
|------------------|---------------------------------------------------------------------|
| Direct media     | `HTMLMediaElement` with HTTP range URLs                             |
| Encoded timed    | WebCodecs decode, MSE buffered playback, or WASM decoder + WebAudio |
| PCM timed        | WebAudio with AudioWorklet jitter buffer                            |
| Control-only     | (no audio sink; audio routed elsewhere)                             |

---

## 3. Shipped runtime core

Source: `src/platform/wasm/host/endpoint_runtime.js`,
`src/platform/wasm/host/browser_surface.css`.

`endpoint_runtime.js` is the generic, reusable browser-endpoint
runtime for pure-JS endpoints: pages that talk to a Fluxor producer
over WebSocket without downloading a WASM kernel. It loads as a plain
`<script>` tag, attaches `window.BrowserSurface`, and owns the generic
mechanics:

- **Connection** — WebSocket connect and reconnect, packet dispatch
  over the `[kind | flags | reserved | payload_len]` envelope, with
  per-kind handler registration.
- **Audio** — lazy `AudioContext` creation, gesture-driven `unlock()`,
  and timed PCM scheduling. Browsers require the first `unlock()` to
  run inside a user gesture handler; PCM arriving before unlock queues
  and flushes after it.
- **Raster** — RGB565 raster sink helpers drawing into a page canvas.
- **Input** — input capture lifecycle and button binding
  (`createInput().bindButtons(...)`).
- **Touch shell** — `createPlayerShell()` composes a canvas-plus-
  controls layout (d-pad, face, menu, row control groups) and
  `applyTouchDefaults()` injects `browser_surface.css`, the
  system-neutral touch-UI primitive: iOS callout suppression,
  orientation-driven flex layout, base button visuals, themeable via
  CSS custom properties.

Profile-specific code (renderers, keymaps, wire encoders) lives next
to the application page that loads the runtime, as a
`<profile>_browser_profile.js` alongside the generic core. Sibling
projects carry their own profiles against this runtime.

---

## 4. Browser capability names

A browser endpoint advertises no capability names: the runtime detects no
host features on the producer's behalf, and a page is written for the graph
it talks to. Which web APIs a page uses (§2) is its profile script's
choice.

---

## 5. Browser constraints

Three web-platform facts shape every browser endpoint:

- **Audio unlock.** An `AudioContext` cannot start without a user
  gesture. The runtime's `unlock()` must be called from a gesture
  handler; until then audio routing is effectively control-only.
- **Background throttling.** When `document.visibilityState` is
  `hidden`, browsers may throttle timers and downgrade audio
  scheduling. A producer deciding whether to drain, pause, or switch
  delivery needs visibility transitions surfaced, not hidden.
- **Sandboxed storage.** Host-side cache storage (Cache Storage,
  IndexedDB, OPFS) is origin-scoped and may be evicted, so the cache
  role stays best-effort.

---

## 6. Transport fit

Browsers can speak the protocol surfaces in `protocol_surfaces.md`,
subject to web platform availability:

- **WebSocket** — stream-shaped record framing over an HTTP upgrade.
  Broadly available and the default first transport for browser
  endpoints; the runtime core connects over it, and a consuming HTTP
  gateway serves the upgrade on the Fluxor side.
- **WebTransport** — multiplexed-session and datagram surface over
  HTTP/3. The natural fit when migration, low-latency datagrams, or
  per-stream backpressure matter. Availability varies; not used by
  the shipped runtime.
- **HTTP range** — request / response. Used by direct-media routing,
  not by the session protocol itself.
- **Server-Sent Events** — one-way stream from server to browser.
  Acceptable for telemetry-only or observer-only endpoints; not
  suitable for control endpoints because there is no return channel.

The gateway is transport-agnostic above the session protocol; the
profile only determines which transports a browser can negotiate.

---

## 7. Module and asset naming

The naming convention follows the endpoint surface's module and
runtime naming rules:

- Fluxor-side gateway modules for this profile take the
  `browser_endpoint_*` prefix.
- The browser-side generic core is `endpoint_runtime.js`;
  browser-wide extensions layer on it rather than fork it.
- Application profiles use `<app>_browser_profile` for both module
  and asset naming.

The application profile is application-specific; the runtime core is
reusable across applications. Adding a new browser-facing application
produces a new profile, never a new copy of the runtime.

---

## 8. Validation

A browser endpoint integration is healthy when, in addition to the
generic endpoint validation rules:

- Audio unlock is implemented once in the runtime core, not per
  application page.
- Application code never reads DOM events directly; it reads only the
  normalised input surfaces.
- The page picks the highest-fidelity audio routing mode the browser
  supports, with documented fallback.
- Background-throttling transitions are reported, not silently
  dropped.
- The cache role is best-effort and never required for correctness.

A browser endpoint is one profile of the endpoint surface,
interchangeable with mobile, desktop, headset, or kiosk profiles from
the rest of the graph's point of view.

---

## 9. Related documentation

- [endpoint_capability_surface.md](endpoint_capability_surface.md) — generic endpoint
  surface this profile refines. Owns role decomposition, session
  protocol, audio routing modes, input policy, and validation.
- [av_capability_surface.md](av_capability_surface.md) — AV surface family the
  browser profile maps web APIs onto.
- [input_capability_surface.md](input_capability_surface.md) — input surface family
  the browser profile produces into.
- [protocol_surfaces.md](protocol_surfaces.md) — protocol substrate WebSocket
  and WebTransport ride on.
- [capability_surface.md](capability_surface.md) — capability matching and
  content types.
- [wasm_browser_host.md](wasm_browser_host.md) — the browser as a WASM kernel
  host rather than an endpoint.
