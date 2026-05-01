# Browser Capability Surface

The browser is a profile of the endpoint capability surface defined in
`endpoint_capability_surface.md`. This document specifies the
browser-specific bindings: which web platform APIs implement each
generic concept, which browser quirks the runtime must absorb, and
which capability names describe browser-specific platform features.

This document is normative only for browser endpoints. The shape of
an endpoint, its role decomposition, its session protocol, and its
audio routing modes are owned by the endpoint surface.

---

## 1. Scope

This profile defines:

- which web platform APIs realize each generic endpoint role
- browser-specific capability names under `browser.*`
- browser quirks the runtime must absorb (audio unlock, background
  throttling, DOM event quirks, blur / focus / repeat policy)
- transport options a browser endpoint can speak
- module and asset naming for browser endpoints

It does not define:

- new media or input primitives (delegated to AV / input surfaces)
- the endpoint role decomposition, session protocol, or audio routing
  modes (delegated to the endpoint surface)
- a JavaScript application framework
- a single module that hides every browser behavior

---

## 2. Web API Realization

Each generic endpoint surface concept maps to one or more web
platform APIs. The implementation column is browser-specific; the
surface column is not.

### AV surfaces

| Fluxor surface                          | Browser implementation                                                  |
|-----------------------------------------|-------------------------------------------------------------------------|
| `AudioSample`                           | WebAudio PCM sink, usually via an AudioWorklet for timed playback       |
| `AudioEncoded` / codec-tagged variants  | WebCodecs, Media Source Extensions, WASM decoder, or pass-through       |
| `VideoRaster`                           | Canvas, WebGL texture upload, ImageBitmap, or WebGPU texture            |
| `VideoDraw`                             | DOM / canvas retained UI renderer or app-specific draw-list renderer    |
| `VideoEncoded`                          | WebCodecs or Media Source Extensions                                    |
| `MediaMuxed`                            | MediaElement, MSE, or recording / broadcast path                        |

### Input sources

| Browser source            | Fluxor surface                                          |
|---------------------------|---------------------------------------------------------|
| DOM `KeyboardEvent`       | `InputKeyEvent`                                         |
| `PointerEvent` (mouse)    | `InputPointerEvent`                                     |
| `PointerEvent` (stylus)   | `InputPointerEvent` with pressure / tilt                |
| `TouchEvent` contacts     | `InputTouchEvent`                                       |
| `Gamepad` API             | `InputBinaryState` + `InputScalarState` (gamepad profile) |
| WebXR pose                | `InputVectorEvent` / `InputVectorState`                 |
| Form text / paste / IME   | `InputText`                                             |
| Page virtual control      | `InputBinaryState` / `InputScalarState`                 |
| App-semantic button       | `InputAction`                                           |

### Audio routing modes

The four generic audio routing modes (§9 of the endpoint surface) bind
to web APIs as follows:

| Mode             | Browser implementation                                              |
|------------------|---------------------------------------------------------------------|
| Direct media     | `HTMLMediaElement` with HTTP range URLs                             |
| Encoded timed    | WebCodecs decode, MSE buffered playback, or WASM decoder + WebAudio |
| PCM timed        | WebAudio with AudioWorklet jitter buffer                            |
| Control-only     | (no audio sink; audio routed elsewhere)                             |

---

## 3. Browser Capability Names

Generic role and routing-mode names live under `endpoint.*` in the
parent surface. Browser-specific *platform feature* names live here
and are advertised in the `<host>:` block of the capability
advertisement.

| Capability                 | Meaning                                                           |
|----------------------------|-------------------------------------------------------------------|
| `browser.media_element`    | Can play direct media URLs through `HTMLMediaElement`             |
| `browser.webaudio`         | Can play or process audio through WebAudio                        |
| `browser.audio_worklet`    | Can run a worklet-backed timed PCM sink                           |
| `browser.webcodecs`        | Can use WebCodecs for encoded media                               |
| `browser.mse`              | Can use Media Source Extensions                                   |
| `browser.canvas2d`         | Can render through Canvas 2D                                      |
| `browser.webgl`            | Can render through WebGL                                          |
| `browser.webgpu`           | Can render through WebGPU                                         |
| `browser.gamepad_api`      | Can capture gamepad input through the Gamepad API                 |
| `browser.webxr`            | Can capture pose / controller input through WebXR                 |
| `browser.websocket`        | Can connect via WebSocket                                         |
| `browser.webtransport`     | Can connect via WebTransport                                      |

Feature presence is detected by the runtime at startup and advertised
in the `Hello` / `Caps` exchange. The Fluxor-side gateway picks a
routing mode whose feature set is satisfied by the advertisement.

---

## 4. Browser Runtime Concerns

The generic endpoint runtime (§8 of the parent surface) absorbs most
host mechanics. The following are browser-specific and live in a
browser extension to that runtime.

- **Audio unlock.** `AudioContext` cannot start without a user
  gesture. The runtime intercepts the first qualifying gesture
  (`pointerdown`, `keydown`, `touchstart`) and resumes the context
  before scheduling any audio. Until then, audio routing falls back
  to control-only.
- **Background throttling.** When `document.visibilityState` is
  `hidden`, browsers may throttle timers and downgrade audio
  scheduling. The runtime emits `Telemetry` reports on visibility
  transitions so the gateway can decide whether to drain, pause, or
  switch to encoded-only delivery.
- **Sandboxed storage.** Cache role uses `Cache Storage`, IndexedDB,
  or `OPFS`. Quotas are origin-scoped and may be evicted; the cache
  contract must remain best-effort.
- **DOM event quirks.** Key repeat, focus / blur cleanup, pointer
  capture, composition events, and synthetic touch / pointer
  duplication are normalized inside the runtime so the gateway sees
  clean `InputKeyEvent` / `InputPointerEvent` / `InputTouchEvent`
  streams. Application code never sees the raw DOM.
- **Permissions.** Microphone, camera, gamepad, midi, and XR access
  follow the Permissions API model. The runtime requests on demand
  and surfaces denials as capability downgrades, not errors.
- **Tab lifecycle.** `pagehide` / `pageshow`, `freeze` / `resume`,
  and BFCache restoration are mapped to session epoch handling so
  reconnects after a suspended tab don't desynchronize.

The advertised constraints in the capability block reflect these
concerns:

```text
constraints:
  audio_unlock_required: true
  background_throttle_possible: true
  sandboxed_storage_only: true
```

---

## 5. Transport Fit

Browsers can speak any of the protocol surfaces in
`protocol_surfaces.md`, subject to web platform availability:

- **WebSocket** — stream-shaped record framing over an HTTP/1, /2, or
  /3 upgrade. Broadly available; the default first transport for new
  browser endpoints. Already exposed by `foundation/http`.
- **WebTransport** — multiplexed-session and datagram surface over
  HTTP/3. The natural fit when migration, low-latency datagrams, or
  per-stream backpressure matter. Availability varies.
- **HTTP range** — request / response. Used by direct-media routing,
  not by the session protocol itself.
- **Server-Sent Events** — one-way stream from server to browser.
  Acceptable for telemetry-only or observer-only endpoints; not
  suitable for control endpoints because there is no return channel.

The gateway is transport-agnostic above the session protocol; the
profile only determines which transports a browser can negotiate.

---

## 6. Module and Asset Naming

- Fluxor-side gateway: `browser_endpoint_gateway` (extends the
  generic gateway with browser-specific packetization where needed,
  for example PCM-block sizing tuned to AudioWorklet quanta).
- Browser-side runtime: `browser_endpoint_runtime.js` (extends the
  generic `endpoint_runtime.js` with the §4 concerns).
- Browser-side helpers may follow the pattern
  `browser_audio_sink.js`, `browser_input_source.js`,
  `browser_raster_sink.js`, `browser_draw_sink.js`.
- Application profiles: `<app>_browser_profile` for both module and
  asset naming.

The application profile is application-specific. The runtime and
gateway are reusable across applications. Adding a new
browser-facing application produces a new profile, never a new copy
of the runtime.

---

## 7. Validation

A browser endpoint integration is healthy when, in addition to the
generic endpoint validation rules:

- Audio unlock is implemented once in the browser runtime, not per
  application page.
- Application code never reads DOM events directly; it reads only
  normalized `Input*` surfaces.
- Feature detection picks the highest-fidelity audio routing mode the
  capability advertisement supports, with documented fallback.
- Background-throttling transitions are reported, not silently
  dropped.
- Cache role is best-effort and never required for correctness.

The browser should feel like one profile of the endpoint surface,
interchangeable with mobile, desktop, headset, or kiosk profiles to
the rest of the graph.

---

## 8. Related Documentation

- `architecture/endpoint_capability_surface.md` — generic endpoint
  surface this profile refines. Owns role decomposition, session
  protocol, audio routing modes, input policy, and validation.
- `architecture/av_capability_surface.md` — AV surface family the
  browser profile maps web APIs onto.
- `architecture/input_capability_surface.md` — input surface family
  the browser profile produces into.
- `architecture/protocol_surfaces.md` — protocol substrate WebSocket
  and WebTransport ride on.
- `architecture/capability_surface.md` — capability matching and
  content types; hosts both the `endpoint.*` and `browser.*`
  capability names.
