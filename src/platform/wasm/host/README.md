# `src/platform/wasm/host/` — the wasm runtime's host page + shims

This directory holds the **wasm runtime's user-facing surface** —
the HTML page that loads a `.wasm` bundle in a browser tab and the
JS shim that satisfies every `extern "C"` import the kernel
declares. They are part of the wasm *platform* in the same sense
that `fluxor-linux` (the linux runtime binary) is part of the linux
platform — generic, scenario-agnostic, and shared by every wasm
bundle.

## Files

- **`runtime.html`** — the single shell. Fetches `/scenario.json`
  to learn what to render, composes a DOM layout from the
  `presentation:` block (canvas / player / terminal surfaces),
  loads `/fluxor.wasm`, instantiates with the shim, and drives
  `kernel_init` + `kernel_step` in a `requestAnimationFrame`
  loop. Per-role navigation is built into the shell: a display
  surface advances on click and steps back on double-click; a player
  surface toggles play/pause on click and advances on double-click.

- **`host_shims.js`** — comprehensive JS implementation of every
  `extern "C"` import the wasm kernel declares (`host_now_us`,
  `host_log`, `host_panic`, `host_csprng_fill`, `host_fetch_*`,
  `host_audio_play`, `host_canvas_present`, `host_input_pop`,
  `host_ws_*`, `host_image_decode_*`, `host_instantiate_module` and
  the child-module syscall bridge). Every kernel-side extern fn has a
  matching shim entry; a missing one fails CI.

- **`endpoint_runtime.js`** — generic reusable browser-endpoint
  runtime (exposes `window.BrowserSurface`) described
  in `docs/architecture/browser_capability_surface.md` §8. Owns
  the generic mechanics: WebSocket connect + reconnect, packet
  dispatch over the `[kind|flags|reserved|payload_len]` envelope,
  audio unlock + PCM scheduling, RGB565 raster sink, input
  capture lifecycle, diagnostics. Profile-specific code
  (renderers, keymaps, wire encoders) lives next to the
  application page that loads it.

  Not loaded by `runtime.html` above — the wasm runtime carries
  its own kernel + shims and doesn't need the JS-side runtime.
  Used by **pure-JS browser endpoints** that talk to a fluxor
  producer over WebSocket without downloading a wasm kernel; such an
  endpoint carries its own `<profile>_browser_profile.js` alongside
  the generic `endpoint_runtime.js` core.

  On import it injects **`browser_surface.css`** and exposes the
  touch-surface factory (`BrowserSurface.createPlayerShell` /
  `applyTouchDefaults`) — see below.

- **`browser_surface.css`** — the system-neutral touch-UI primitive
  (iOS callout/loupe suppression, orientation-driven canvas+controls
  flex layout, base `.pad-button` visuals). Theme-able via six CSS
  custom properties (`--surface-bg`/`--surface-fg`/`--button-border`/
  `--button-active-bg`/`--canvas-bg`/`--canvas-aspect`). `endpoint_
  runtime.js` injects it on import (one-shot, idempotent) so player
  pages inherit a consistent touch UX without re-coding the reset +
  flex layout per system. System-specific bits (canvas aspect, which
  buttons exist, theme colors) are supplied by `createPlayerShell()`.
  `example.html` is a hand-written smoke page: open it locally and
  DevTools-rotate portrait↔landscape to see the orientation flip.

## How they get served

The scenario synthesiser auto-mounts both files as static routes on
the synthesised host whenever a component targets wasm:

| Route | Source |
|---|---|
| `/` | `src/platform/wasm/host/runtime.html` |
| `/host_shims.js` | `src/platform/wasm/host/host_shims.js` |
| `/fluxor.wasm` | `target/wasm/<bundle>.wasm` |
| `/scenario.json` | synthesised inline body (presentation block + playlist source) |
| `/api/list` | `list:` binding (dual-mode listing + file-serve) |

Five routes against the host profile's `MAX_ROUTES = 8`. Three slots
remain for routes that bindings inject onto the synthesised host (e.g.
extra `list:` bindings for separate galleries).

## Why this lives under `src/platform/wasm/`

The page and shim are the wasm runtime, not part of any one
application, so they live with the platform. A per-bundle page with
its own shim copy would drift from the kernel ABI. Every platform has
the same shape: one runtime, and graphs that are pure YAML manifests.

- **Linux**: `src/bin/fluxor-linux.rs` is the runtime.
- **RP / BCM**: the kernel firmware blob built by `make firmware`.
- **WASM**: `src/platform/wasm/host/*`.

No per-bundle HTML, no per-bundle JS. One runtime, infinitely many
graphs.

**Host extensions:** domain-specific host executors are NOT part of
`host_shims.js`. They ship as separately served scripts that call
`FluxorHostExt.register(name, factory)` at load; the shim's generic
capability entries delegate through the registry, loading the script
lazily on first use (`importScripts` in a Worker, `<script>` injection
on the page). The registry currently has no in-tree clients: app-domain
GPU work goes through the generic `wasm_browser_compute` provider instead
(pipelines, buffers and dispatch lists arrive as channel data, so no
host-side executor is needed).

## How `presentation:` drives layout

The wasm component graph's top-level `presentation:` block declares
which DOM surfaces to compose:

```yaml
target: wasm

presentation:
  layout: stacked
  surfaces:
    - { id: main, role: display, module: display }
    - { id: term, role: terminal, module: terminal, rows: 12 }

modules:
  - { name: display, type: wasm_browser_canvas, width: 960, height: 540 }
  - { name: terminal, type: wasm_browser_terminal, rows: 12 }
  ...
```

The shell creates a `<div class="surface" data-role="display">`
per surface; the `host_canvas_present` shim mounts its canvas
inside the display surface; `host_terminal_emit` writes into the
terminal surface. Per-role CSS handles spacing, borders,
and hit regions.

## Adding new surface roles

A new `role` (e.g. `gamepad-overlay`) needs:

1. CSS in `runtime.html` styling `.surface[data-role="..."]`.
2. (Optionally) a buildSurface() branch for any role-specific DOM.
3. A matching wasm-side module declaring `presentation: surface
   role` in its manifest so the scenario validator picks it up.

That's the full extension surface. No JS bundling, no new tooling.
