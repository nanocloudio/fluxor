# Endpoint Capability Surface

Fluxor's remote-endpoint architecture rests on three layered concepts:

1. a **role decomposition** — control, visual, audio, cache, session
   — that any external endpoint resolves into;
2. an **endpoint session protocol** — a transport-agnostic message
   envelope between a gateway module on the Fluxor side and a runtime
   library on the endpoint side;
3. a **profile pattern** — host-API-specific code lives in named
   profiles (browser, mobile app, desktop app, smart-display,
   headset, industrial console, voice-assistant device, peer Fluxor
   device) that compose with the generic surface defined here.

This document is the endpoint peer of `av_capability_surface.md`,
`input_capability_surface.md`, and `protocol_surfaces.md`.

An *endpoint* in this document means an external host that participates
in a Fluxor graph by producing or consuming typed surfaces over a
transport. It is not a module port. Browsers, mobile apps, desktop
apps, smart displays, head-mounted displays, kiosks, industrial HMI
consoles, voice-assistant screens, and other Fluxor devices acting as
presentation peers all reduce to this surface. Profiles describe
*what platform APIs* the endpoint has; the surface describes *what
graph-level role* it plays.

---

## 1. Scope

This architecture defines:

- endpoint role decomposition and capability declarations
- the boundary between Fluxor-native surfaces and endpoint-specific
  implementation code
- the endpoint session protocol layer above transports
- reusable endpoint-runtime responsibilities
- the split between generic endpoint code and host-specific profiles

It does not define:

- new media or input primitives — the AV and input surface families
  remain authoritative
- a particular UI framework, draw API, or scripting language
- a requirement on which transport an endpoint uses
- endpoint-hosted Fluxor module execution — that path is covered by
  remote channels (see §1a)
- a single module that hides every endpoint behavior

The goal is to stop recreating bespoke endpoint code for every
browser-, mobile-, kiosk-, or headset-facing application while
preserving Fluxor's native graph boundaries.

---

## 1a. Relationship to the Remote-Channel Surface

An external host joins a Fluxor graph through one of two co-equal
mechanisms:

- the **endpoint surface** (this document) — typed AV, input, and
  control surfaces cross into a host through the endpoint session
  protocol, translated host-side by an endpoint runtime. The host
  does not run Fluxor modules or the kernel.
- the **remote-channel surface** (`protocol_surfaces.md` §"Remote
  Channels and Placement") — module-to-module channels span nodes
  directly, with the same content-type contracts on either end. The
  host runs a Fluxor kernel and modules.

These are not preferred-and-fallback. They are different connection
classes selected by what the host can host. A bare-metal rp2350
joining a CM5 graph uses remote channels because it runs a kernel.
A DOM-only browser uses the endpoint surface because it does not. A
browser tab running a WASM Fluxor build is the same shape as the
rp2350 case — it joins via remote channels and the endpoint surface
does not apply. A mobile WebView, a kiosk shell, a smart-display
runtime, or any host that can present surfaces but cannot host a
kernel uses the endpoint surface and will continue to.

A consequence: hosts that *can* run a kernel but choose not to (e.g.
a WebView shell that ships only the endpoint runtime) get the
endpoint surface; hosts that *cannot* run one are not classed
differently. The dividing line is "where the modules execute," not
"is this a real peer."

The two surfaces share the AV, input, and protocol surface
families — they differ in whether channels span the boundary
(remote-channel) or whether typed messages do (endpoint).

---

## 2. Design Rule

External-facing code is divided into five layers, host-agnostic:

```text
Fluxor application graph
      |
      | AudioSample / AudioEncoded / VideoRaster / VideoDraw / Input*
      v
endpoint gateway module
      |
      | endpoint session protocol
      v
transport gateway
      |
      | stream / datagram / mux / record transport
      v
endpoint runtime library
      |
      | host platform APIs (audio, draw, input, network, storage)
      v
host platform
```

Only the top layer is application logic. Only the bottom layer is
host-specific platform code. The middle three layers are reusable
infrastructure that profile docs refine, not replace.

The transport at layer four is whichever protocol-surface the host
can speak (`transport.stream`, `transport.datagram`, `transport.mux`,
or a record-framing path such as WebSocket-shaped frames). Transport
choice is a profile concern; the layers above are not.

---

## 3. Relationship to Existing Surfaces

The endpoint surface composes with — never replaces — the AV, input,
and protocol surface families.

### AV surfaces

Endpoint visual and audio paths carry the AV surface family without
adding endpoint-specific surfaces. A pixel-rendering endpoint is a
`VideoRaster` sink; a PCM-receiving endpoint is an `AudioSample`
sink; an encoded-stream endpoint is an `AudioEncoded` /
`VideoEncoded` sink. The AV surface table in
`av_capability_surface.md` is authoritative; endpoint profiles only
declare which AV surfaces they accept and how they render them.

### Input surfaces

Endpoint input maps onto the input surface family in
`input_capability_surface.md`:

| Endpoint source       | Fluxor surface |
|-----------------------|----------------|
| keyboard              | `InputKeyEvent`                           |
| pointer / mouse       | `InputPointerEvent`                       |
| stylus                | `InputPointerEvent` with pressure / tilt  |
| touch contacts        | `InputTouchEvent`                         |
| gamepad / controller  | `InputBinaryState` + `InputScalarState` (or gamepad profile) |
| pose / IMU tracker    | `InputVectorEvent` / `InputVectorState`   |
| text / paste / IME    | `InputText`                               |
| voice transcript      | `InputText`                               |
| virtual control       | `InputBinaryState` / `InputScalarState`   |
| application command   | `InputAction`                             |

Application meaning belongs in mappers or profiles. Generic endpoint
code never decodes a key press into application state.

### Protocol surfaces

Endpoint connections ride the protocol surfaces in
`protocol_surfaces.md`:

- A duplex byte session is `transport.stream` (TCP, TLS-over-TCP).
- A datagram session is `transport.datagram` (UDP, DTLS).
- A multiplexed session is `transport.mux` (QUIC, HTTP/3).
- A record-framed session over a stream upgrade (WebSocket-shaped
  framing) is a stream-surface profile.

The endpoint design must remain transport-agnostic above the session
protocol. A profile declares which transports its host can speak.

---

## 4. Endpoint Roles

An endpoint may provide any subset of these roles. Roles compose; an
endpoint that produces input, presents visuals, and presents audio
declares all three.

### Control

Provides user intent from endpoint input:

- key, pointer, touch, gamepad, vector / pose, form, and virtual
  controls
- focus and capture policy
- input state coalescing
- sequence numbers for state snapshots
- optional action mapping for app-level commands

### Visual

Presents UI, video, or diagnostic state:

- raster frame display
- retained draw-list rendering
- app-specific 2D / 3D rendering hooks
- layout and control-surface rendering
- visual telemetry overlays

### Audio

Presents audio through host APIs:

- direct media playback through URLs or range fetches
- decoded PCM playback through host audio APIs
- encoded playback through host decoders or platform fallbacks
- jitter-buffered timed playback for synchronized output
- host-specific unlock and resume behavior

### Session

Maintains endpoint lifecycle:

- connect, disconnect, reconnect
- endpoint registration and capability advertisement
- session epoch handling
- transport fallback
- telemetry and diagnostics

### Cache

Optionally uses host-side storage:

- artwork cache
- decoded metadata cache
- offline media cache
- replay / repair cache for streamed media

Cache use is optional and must not be required for correctness unless
the application profile declares it.

---

## 5. Capability Vocabulary

Endpoint capabilities describe role surface and platform mechanics,
not application identity. Generic role-and-mechanic names live under
`endpoint.*`. Host-specific feature names live under `<host>.*` in
the corresponding profile document (`browser.*`, `mobile.*`,
`desktop.*`, `headset.*`, etc.).

Generic names:

| Capability             | Meaning |
|------------------------|---------|
| `endpoint`             | endpoint session provider                              |
| `endpoint.control`     | can produce endpoint-originated input surfaces         |
| `endpoint.visual`      | can present visual surfaces                            |
| `endpoint.audio`       | can present audio surfaces                             |
| `endpoint.cache`       | can provide host-side storage / cache                  |
| `endpoint.media_url`   | can play direct media URLs through host media APIs     |
| `endpoint.pcm_timed`   | can run a host timed PCM sink with stream-time scheduling |
| `endpoint.encoded`     | can decode encoded media on the host                   |
| `endpoint.muxed`       | can play container-muxed media on the host             |

The AV and input capability vocabularies remain the authoritative
role vocabulary for media and input shape. Endpoint capabilities
describe endpoint mechanics on top of them.

A profile-shaped capability advertisement, transport-neutral:

```text
EndpointCaps:
  endpoint_id: <opaque>
  profile: <profile-name>          # e.g. browser, mobile, desktop, headset
  roles:
    control
    visual
    audio
  input:
    key
    pointer
    touch
    action
  visual:
    video.raster
    video.draw
  audio:
    audio.sample
    audio.encoded
    media.muxed
  endpoint:
    media_url
    pcm_timed
    encoded
  <host>:                          # profile-specific feature flags
    <host>.<feature>
  constraints:
    audio_unlock_required: <bool>
    background_throttle_possible: <bool>
    sandboxed_storage_only: <bool>
```

The `<host>:` block is the only profile-specific section; everything
else is generic and validated against the vocabulary above.

---

## 6. Endpoint Gateway

The gateway is the Fluxor-native module boundary between application
surfaces and the endpoint session protocol.

Responsibilities:

- consume native AV / control / status surfaces
- packetize surfaces into endpoint session messages
- demultiplex endpoint input / control messages back into native
  surfaces
- preserve content-type identity and stream / session metadata
- enforce bounded buffering and backpressure policy
- expose telemetry counters for dropped, late, malformed, and blocked
  messages

Non-responsibilities:

- host UI layout
- host audio unlock or resume gestures
- host draw API specifics
- application key maps or control layout
- transport wire framing (delegated to the chosen
  `transport.stream` / `transport.datagram` / `transport.mux`
  module)

A single gateway can fan out to multiple endpoints over the same
session protocol. Profile-specific gateways exist when the profile
needs host-aware packetization (for example, a browser-specific
PCM-block sizing policy), but they are profiles of one gateway, not
parallel implementations.

---

## 7. Session Protocol

The session protocol is the stable boundary between the gateway and
the endpoint runtime. It is independent of the transport.

Message classes:

| Class                  | Direction        | Purpose |
|------------------------|------------------|---------|
| `Hello` / `Caps`       | both             | version and endpoint capability negotiation |
| `Attach` / `Detach`    | both             | bind endpoint roles to graph sessions       |
| `AudioSample`          | Fluxor → endpoint | decoded PCM blocks with timing metadata    |
| `AudioEncoded`         | Fluxor → endpoint | encoded access units or segments           |
| `MediaUrl`             | Fluxor → endpoint | direct URL / range playback instruction    |
| `VideoRaster`          | Fluxor → endpoint | pixel frames or damage regions             |
| `VideoDraw`            | Fluxor → endpoint | retained / replayable draw operations      |
| `Input*`               | endpoint → Fluxor | key, pointer, touch, vector, scalar, binary, action input |
| `Control`              | both             | application / session commands              |
| `Telemetry`            | both             | buffer, latency, underrun, error, feature reports |

Every media-bearing message carries enough metadata for the sink to
make deterministic scheduling decisions:

- session id
- stream id
- epoch
- sequence
- content type
- codec / config id when encoded
- StreamTime start and duration when timed
- payload length and integrity hint

Transport-level fragmentation never leaks into the application
message model. Stream chunks, datagram boundaries, and record frames
are transport details.

---

## 8. Endpoint Runtime

The endpoint runtime is shared host-side code (a JavaScript module,
a linked host library, a system service, a peer-Fluxor module)
loaded by applications running on the host. It owns the host mechanics that
otherwise get rewritten per application.

Generic responsibilities:

- endpoint connection and reconnect
- session protocol parse / build / dispatch
- capability advertisement
- feature detection and fallback paths for the host's audio, draw,
  decode, and storage APIs
- audio unlock / resume policy where the host requires it
- PCM queueing, lead management, underrun / overflow reporting
- timed PCM scheduling against the host audio clock where available
- direct media playback via the host's URL-based media API
- raster sink helpers
- draw-list renderer hooks
- key, pointer, touch, gamepad, vector, and virtual-control capture
  helpers
- visibility / background-throttling detection
- telemetry emission and local diagnostics
- structured error reporting

Application code provides profile descriptors:

- layout
- domain-specific controls
- domain-specific renderers
- binding tables
- branding or styling
- application-specific command vocabulary

The runtime should be usable by a minimal application surface with
only a root element (or equivalent) and a profile descriptor.

---

## 9. Audio Routing Modes

Endpoint audio needs explicit routing modes because the endpoint may
be a control surface, an audio sink, or both. The four modes below
are generic; each profile names which host APIs implement them.

### Direct media

Fluxor sends a `MediaUrl` or playlist instruction. The endpoint uses
the host's built-in media-playback API and direct URL fetches.

Use when:
- the endpoint is the only sink
- sync requirements are loose
- the codec / container is directly playable on the host
- low CPU on the coordinator matters

### Encoded timed

Fluxor sends encoded access units or segments with StreamTime
metadata. The endpoint decodes through host decoders (or a host-side
software fallback) and schedules output against a host timed sink.

Use when:
- the endpoint participates in synchronized playback
- compressed-first transport is required
- direct file access is unavailable or unsuitable

### PCM timed

Fluxor sends decoded `AudioSample` blocks with StreamTime metadata.
The endpoint schedules PCM through the host audio API.

Use when:
- the endpoint cannot decode the source codec
- server-side decode is already required
- latency / sync control matters more than bandwidth

PCM over the network is a fallback, not the default.

### Control-only

The endpoint receives visual, status, or control messages, but audio
is routed to another sink (a local audio output, a network speaker,
or a different endpoint). A control-surface endpoint must not imply
an audio sink.

This is a first-class mode and the validator must allow an endpoint
to declare it without declaring any audio capability.

---

## 10. Input Policy

Endpoint input preserves source identity until an explicit mapper or
profile translates it.

```text
host key / pointer / touch / gamepad / vector
      |
endpoint runtime capture helper
      |
endpoint session protocol Input*
      |
endpoint gateway
      |
InputKeyEvent / InputPointerEvent / InputTouchEvent / InputVectorEvent / InputAction
      |
mapper / focus policy / application consumer
```

Profiles may emit `InputAction` directly for controls that are
already semantic — a transport "play" button, a soft "confirm" key.
Raw key, pointer, touch, and pose sources stay raw unless the
profile explicitly declares a binding table.

Focus, capture, repeat, and blur cleanup are endpoint policy.
Application modules receive clean events or state, not host-API
quirks.

---

## 11. Profiles

A *profile* is the host-API-specific binding for this surface. A
profile document specifies:

- which host APIs implement each generic role
- profile-specific capability names under `<host>.*`
- host-specific runtime concerns that the generic runtime cannot
  abstract (audio unlock policy, sandboxed storage, background
  throttling, permission models, sleep / wake handling)
- transport options the host can speak
- module and asset naming for that profile

Existing profiles:

- `browser_capability_surface.md` — browser endpoints with web
  platform APIs (WebAudio, AudioWorklet, Canvas, WebGL / WebGPU,
  WebCodecs, Media Source Extensions, MediaElement, WebSocket,
  WebTransport, DOM input).

A profile is normative only for endpoints of its host type. The
shape of an endpoint, its role decomposition, and its session
protocol are owned by this document; profiles do not redefine them.

---

## 12. Module and Runtime Naming

Module and asset names should make the gateway / runtime / profile
boundary visible.

- Reusable Fluxor-side modules use `endpoint_*` for fully generic
  pieces (`endpoint_session_mux`) and `<host>_endpoint_*` for
  profile-specific pieces (`browser_endpoint_gateway`,
  `mobile_endpoint_gateway`, `desktop_endpoint_gateway`).
- Host-side runtime files mirror the same split:
  `endpoint_runtime.<ext>` (generic core) plus
  `<host>_endpoint_runtime.<ext>` (profile-specific extensions).
- Application profiles take their domain as a prefix and the host as
  a suffix: `<app>_<host>_profile`.

The application profile is application-specific. The runtime and
gateway are reusable across applications of the same host. The
generic core is reusable across hosts.

---

## 13. Validation

An endpoint integration is healthy when:

- Fluxor modules upstream of the gateway use native content types
  only.
- Transport mechanics are isolated from application modules.
- Audio unlock and PCM scheduling are implemented once per host
  profile, not per application.
- Input identity is preserved until a mapper or profile
  intentionally translates it.
- Audio, visual, and control roles can be enabled independently on
  the same endpoint.
- Transport fragmentation is hidden from application messages.
- Telemetry reports connection state, buffer lead, underruns, late
  packets, malformed messages, and feature fallback decisions.
- Direct media playback is preferred over streamed PCM when sync
  and codec constraints allow it.
- Adding a new application of the same host requires only a new
  profile descriptor — no new gateway, runtime, or session-protocol
  code.
- Adding a new host (mobile, headset, kiosk, peer device) requires
  a new profile document plus a new host-side runtime — but
  reuses the gateway, session protocol, role decomposition, and
  audio routing modes unchanged.

The endpoint should feel like another capability-bearing peer in
the graph, not a one-off external app attached to a side channel.

---

## 14. Related Documentation

- `architecture/av_capability_surface.md` — AV peer; hosts the
  audio / video surface family endpoints map onto.
- `architecture/input_capability_surface.md` — input peer; hosts the
  input surface family and identity-namespace model endpoints
  produce into.
- `architecture/protocol_surfaces.md` — protocol substrate that
  carries endpoint session traffic across stream, datagram, mux,
  and remote-channel transports.
- `architecture/capability_surface.md` — capability matching,
  content types, and hardware-domain expansion; hosts the
  `endpoint.*` capability names defined here.
- `architecture/monitor-protocol.md` — `MON_*` line-format
  conventions shared with endpoint telemetry.
- `architecture/browser_capability_surface.md` — browser profile of
  this surface.
