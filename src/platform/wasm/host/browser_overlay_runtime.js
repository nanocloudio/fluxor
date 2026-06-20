// browser_overlay_runtime.js — Fluxor generic browser-overlay renderer.
//
// Implements the renderer half of `.context/rfc_browser_overlay.md`
// §6.3 (`browser_overlay_runtime` + the input-normalizer seam). It
// turns a host-neutral `presentation.shell` descriptor (+ optional
// `presentation.browser_overlay` policy) into DOM controls, lays them
// out responsively around the content so persistent controls never
// obscure it, and normalizes every interaction into canonical Fluxor
// input through a caller-supplied `sinks` object.
//
// Ownership boundary (RFC §5.2): this file is GENERIC. It knows control
// *kinds* (button/dpad/stick/slider/scrubber/toggle/menu/select/
// checkbox/keyboard/status) and how to draw + normalize them. It does
// NOT know what any control *means* — no Spectrum keys, no "tap = next
// track", no ROM logic. Meaning lives in mapper modules / app profiles;
// "which controls" lives in the descriptor the activity authors;
// "show these now" is the `ShellSelection` the launcher (Truffle)
// publishes.
//
// Security (RFC §23): CSP-compatible — no eval, no inline handlers, all
// text via `textContent`. Untrusted labels/options are rendered as text
// and length-capped; list data never injects control definitions.
//
// Testability: every element is created through the injected `doc`
// factory (defaults to the global `document`), so the renderer runs
// under a hand-rolled fake DOM with no browser and no npm — see
// `tests/host/browser_overlay_runtime.test.js`.

(function (root) {
  'use strict';

  // ── Canonical gamepad bit indices (RFC §9.2 standard mapping) ──────
  const GAMEPAD_BIT = {
    south: 0, east: 1, west: 2, north: 3,
    l1: 4, r1: 5, l2: 6, r2: 7,
    select: 8, start: 9, l3: 10, r3: 11,
    dpad_up: 12, dpad_down: 13, dpad_left: 14, dpad_right: 15,
  };

  // Minimal symbolic-key → DOM keyCode map for raw `key.symbolic.*`
  // controls (virtual quick keys). Unknown names emit keyCode 0; a
  // richer table is the mapper's concern, not the shell's.
  const KEYCODE = {
    Enter: 13, Space: 32, Escape: 27,
    ArrowUp: 38, ArrowDown: 40, ArrowLeft: 37, ArrowRight: 39,
  };
  for (let d = 0; d <= 9; d++) KEYCODE[String(d)] = 48 + d;
  for (let c = 0; c < 26; c++) KEYCODE[String.fromCharCode(97 + c)] = 65 + c;

  const LABEL_MAX = 64; // untrusted-text cap (RFC §23.4)

  // Placement group → responsive browser zone, per orientation
  // (RFC §7.2). Persistent groups never map to `content`.
  const ZONE_BY_ORIENT = {
    portrait: {
      primary_start: 'below_start', primary_end: 'below_end',
      secondary: 'below_center', above_content: 'above',
      drawer: 'drawer', transient: 'transient', debug: 'debug',
    },
    landscape: {
      primary_start: 'left_rail', primary_end: 'right_rail',
      secondary: 'below_center', above_content: 'above',
      drawer: 'drawer', transient: 'transient', debug: 'debug',
    },
    desktop: {
      // Virtual gameplay controls hide on desktop (RFC §13.4); media
      // and setting controls remain in the compact below/above rows.
      primary_start: 'below_start', primary_end: 'below_end',
      secondary: 'below_center', above_content: 'above',
      drawer: 'drawer', transient: 'transient', debug: 'debug',
    },
  };

  function cap(s) {
    s = String(s == null ? '' : s);
    return s.length > LABEL_MAX ? s.slice(0, LABEL_MAX) : s;
  }

  // FNV-1a 32-bit — byte-identical to the kernel's
  // `abi::wire::fnv1a32` / `runtime.rs::fnv1a` (offset 0x811c9dc5,
  // prime 0x01000193). `Math.imul` does the 32-bit wrapping multiply
  // that a plain `*` would lose precision on. Action ids are ASCII, so
  // `charCodeAt` equals the UTF-8 byte the kernel hashes.
  function fnv1a32(str) {
    let h = 0x811c9dc5 | 0;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i) & 0xff;
      h = Math.imul(h, 0x01000193);
    }
    return h >>> 0;
  }

  function setBit(bits, name) {
    const b = GAMEPAD_BIT[name];
    return b === undefined ? bits : (bits | (1 << b)) & 0xffff;
  }
  function clearBit(bits, name) {
    const b = GAMEPAD_BIT[name];
    return b === undefined ? bits : (bits & ~(1 << b)) & 0xffff;
  }

  // Parse a raw control identity like `gamepad.control.dpad_up` or
  // `key.symbolic.Enter` into { ns, name }.
  function parseControl(id) {
    if (typeof id !== 'string') return null;
    if (id.startsWith('gamepad.control.')) {
      return { ns: 'gamepad', name: id.slice('gamepad.control.'.length) };
    }
    if (id.startsWith('key.symbolic.')) {
      return { ns: 'key', name: id.slice('key.symbolic.'.length) };
    }
    return { ns: 'raw', name: id };
  }

  // ── Generic sink factory (RFC §6.3 shared capture). The renderer
  //    calls these on every control interaction; `emit(record)` routes
  //    the *normalized* record wherever the host wants it. Both the
  //    full-WASM host (`makeHostSinks`, below) and the DOM-only endpoint
  //    runtime (`endpoint_runtime.js::mountOverlay`) build on this, so
  //    gamepad-bit accumulation + key/action encoding are identical in
  //    both modes. Record shapes:
  //      { class:'gamepad', id, buttonBits, axisLx, axisLy, axisRx, axisRy }
  //      { class:'key', name, keyCode, down }
  //      { class:'action', actionId, hash, value }
  function makeSinks(emit) {
    const pads = new Map(); // accumulated button/axis state per virtual pad
    function pad(id) {
      let p = pads.get(id);
      if (!p) { p = { buttonBits: 0, axisLx: 0, axisLy: 0, axisRx: 0, axisRy: 0 }; pads.set(id, p); }
      return p;
    }
    function emitPad(id) {
      const p = pad(id);
      emit({ class: 'gamepad', id, buttonBits: p.buttonBits,
        axisLx: p.axisLx, axisLy: p.axisLy, axisRx: p.axisRx, axisRy: p.axisRy });
    }
    return {
      gamepadButton(id, name, pressed) {
        const p = pad(id);
        p.buttonBits = pressed ? setBit(p.buttonBits, name) : clearBit(p.buttonBits, name);
        emitPad(id);
      },
      gamepadAxis(id, axes) {
        const p = pad(id);
        if ('lx' in axes) p.axisLx = axes.lx | 0;
        if ('ly' in axes) p.axisLy = axes.ly | 0;
        if ('rx' in axes) p.axisRx = axes.rx | 0;
        if ('ry' in axes) p.axisRy = axes.ry | 0;
        emitPad(id);
      },
      key(name, down) {
        emit({ class: 'key', name, keyCode: KEYCODE[name] || 0, down: !!down });
      },
      action(actionId, value) {
        // Pass the raw value through (number for transport/scrubber,
        // or an object like { parameter_id, option_id } for param
        // controls); each emit target coerces as it needs.
        emit({ class: 'action', actionId, hash: fnv1a32(actionId), value });
      },
    };
  }

  // ── Full-WASM host sinks: emit normalized records into the kernel
  //    host queues drained by host_shims.js (`__fluxor_*_queue`).
  //    Semantic actions also fire the optional `__fluxor_action` hook.
  function makeHostSinks(win) {
    win = win || root;
    const gpQ = win.__fluxor_gamepad_queue || (win.__fluxor_gamepad_queue = []);
    const kbQ = win.__fluxor_keyboard_queue || (win.__fluxor_keyboard_queue = []);
    const acQ = win.__fluxor_action_queue || (win.__fluxor_action_queue = []);
    return makeSinks((r) => {
      if (r.class === 'gamepad') {
        gpQ.push({ kind: 0x01, gamepadId: r.id, connected: 1, buttonBits: r.buttonBits,
          axisLx: r.axisLx, axisLy: r.axisLy, axisRx: r.axisRx, axisRy: r.axisRy });
      } else if (r.class === 'key') {
        kbQ.push({ kind: r.down ? 0x01 : 0x02, modifiers: 0, repeat: 0,
          keyCode: r.keyCode, scanCode: 0 });
      } else if (r.class === 'action') {
        // The kernel action queue carries an f32; non-numeric param
        // values (e.g. select option ids) coerce to 0 there but reach
        // the app-level hook intact.
        acQ.push({ hash: r.hash, value: typeof r.value === 'number' ? r.value : 0 });
        if (typeof win.__fluxor_action === 'function') win.__fluxor_action(r.actionId, r.value);
      }
    });
  }

  // ── Renderer ────────────────────────────────────────────────────────
  function mount(opts) {
    const doc = opts.doc || root.document;
    const shell = (opts.shell && opts.shell.controls) ? opts.shell : { controls: [] };
    const policy = opts.browser_overlay || {};
    const sinks = opts.sinks || makeHostSinks(opts.window || root);
    const el = (tag) => doc.createElement(tag);

    const rootEl = el('div');
    rootEl.className = 'fx-overlay';
    if (policy.immersive) rootEl.className += ' fx-immersive';

    // Inject scoped, CSP-clean stylesheet once per document.
    ensureStyles(doc);

    // Build the zone containers. `content` holds the media surface and
    // is never given persistent controls.
    const zones = {};
    for (const z of ['above', 'content', 'left_rail', 'right_rail',
      'below_start', 'below_center', 'below_end', 'transient', 'drawer', 'debug']) {
      const d = el('div');
      d.className = 'fx-zone fx-zone-' + z;
      d.dataset.zone = z;
      zones[z] = d;
      rootEl.appendChild(d);
    }

    // The content surface attaches under `content` if provided.
    if (opts.contentEl) zones.content.appendChild(opts.contentEl);

    const profile = (opts.shell && opts.shell.media_profile) || 'custom';
    rootEl.dataset.profile = profile;

    // Track active controls for lifecycle cleanup + status updates.
    const controls = [];
    const statusBound = []; // { field, update(value) }

    // `null` until the first relayout so the initial `setOrientation`
    // always fires `renderAll()` even when the computed orientation is
    // the nominal default.
    let orientation = null;
    // Current surface traits (size class + modality bitmask) the placement
    // resolver keys on; updated by `relayout`, consumed by `renderAll`.
    let curSizeClass = 1; // SIZE_REGULAR
    let curModalities = 1; // MODALITY_KEY
    function zoneFor(placement) {
      const map = ZONE_BY_ORIENT[orientation] || ZONE_BY_ORIENT.portrait;
      return map[placement] || 'below_center';
    }

    // Render each control into its placement's current zone.
    function renderAll() {
      // Clear non-content zones, then re-place controls.
      for (const k of Object.keys(zones)) {
        if (k === 'content') continue;
        while (zones[k].firstChild) zones[k].removeChild(zones[k].firstChild);
      }
      // The content zone holds the app canvas (never cleared), but prior
      // superimposed controls must be removed so they don't accumulate.
      if (zones.content) {
        for (const n of Array.from(zones.content.children)) {
          if (n.classList && n.classList.contains('fx-superimposed')) {
            zones.content.removeChild(n);
          }
        }
      }
      controls.length = 0;
      statusBound.length = 0;
      // Resolve the layout for the current surface. A `chrome`-disposition
      // control renders in its chrome zone; a `content`-disposition control is
      // normally drawn by the app (skipped here) — UNLESS it is superimposed
      // (`overlay`), in which case it overlays the content regardless of plane.
      // So the overlay check comes BEFORE the chrome gate, gated only on
      // `hidden` (shrink ladder / suppression). The RFC's canonical overlay
      // control uses `[content, chrome]` affinity → resolves to `content`, and
      // would be dropped if we gated on chrome first.
      const layout = resolveLayout(shell.controls, curSizeClass, curModalities);
      for (const spec of shell.controls) {
        const disp = spec.id ? layout.get(spec.id) : 'chrome';
        if (disp === 'hidden') continue;
        if (spec.overlay === true) {
          // Superimposed mode (RFC §11.3): overlay the control translucently
          // OVER live content at an app-declared `overlay_regions`, rather than
          // packing it into a chrome zone. The "controls never obscure content"
          // invariant is deliberately waived here (virtual gamepads on a game).
          const built = buildControl(spec);
          if (!built) continue;
          applyA11y(built.node, spec);
          built.node.classList.add('fx-superimposed');
          applyOverlayRegion(built.node, spec);
          zones.content.appendChild(built.node);
          controls.push(built);
          if (built.statusField) statusBound.push(built);
          continue;
        }
        // Non-overlay: only the chrome plane renders as DOM chrome.
        if (disp !== 'chrome') continue;
        const built = buildControl(spec);
        if (!built) continue;
        applyA11y(built.node, spec);
        const placement = spec.placement || defaultPlacement(profile, spec);
        const z = (placement === 'drawer') ? 'drawer' : zoneFor(placement);
        zones[z].appendChild(built.node);
        controls.push(built);
        if (built.statusField) statusBound.push(built);
      }
    }

    // Ensure every rendered control exposes an accessible name + role for the
    // a11y tree (RFC §13). Native <button>/<select>/<input> derive a name from
    // their text/options; div-based controls (dpad/stick/cluster/keyboard/status)
    // need an explicit role + aria-label so assistive tech can navigate them.
    function applyA11y(node, spec) {
      if (!node || !node.setAttribute) return;
      const name = cap((spec.a11y && spec.a11y.label) || spec.label || spec.id || '');
      if (name && !node.getAttribute('aria-label')) node.setAttribute('aria-label', name);
      const tag = (node.tagName || '').toUpperCase();
      const native = tag === 'BUTTON' || tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA';
      if (!native && !node.getAttribute('role')) {
        node.setAttribute('role', spec.kind === 'status' ? 'status' : 'group');
      }
    }

    // Named overlay regions (RFC §11.3 `overlay_regions`) → CSS placement within
    // the content zone. The validated schema is `overlay` boolean +
    // `overlay_regions` a list of region NAMES; the validator
    // (tools/src/presentation_shell.rs OVERLAY_REGIONS) accepts EXACTLY these
    // names, so an unknown region fails the build rather than silently
    // defaulting. Keep the two lists in lock-step (pinned by
    // tools/tests/browser_overlay_runtime_surface.rs).
    const OVERLAY_REGION = {
      // Edge thirds (the RFC canonical safe regions — e.g. a dpad in left_third).
      left_third: { left: '2%', top: '50%', transform: 'translateY(-50%)', width: '30%' },
      right_third: { right: '2%', top: '50%', transform: 'translateY(-50%)', width: '30%' },
      center_third: { left: '50%', top: '50%', transform: 'translate(-50%,-50%)', width: '30%' },
      // Corners + bottom-center.
      bottom_start: { left: '4%', bottom: '6%' },
      bottom_end: { right: '4%', bottom: '6%' },
      top_start: { left: '4%', top: '6%' },
      top_end: { right: '4%', top: '6%' },
      bottom_center: { left: '50%', bottom: '6%', transform: 'translateX(-50%)' },
    };

    // Position a superimposed control from its declared `overlay_regions` (first
    // named region; default bottom_start). Safe when the platform node has no
    // `style` (tests).
    function applyOverlayRegion(node, spec) {
      if (!node || !node.style) return;
      const names = Array.isArray(spec.overlay_regions) ? spec.overlay_regions : [];
      const region = (names.length && OVERLAY_REGION[names[0]]) || OVERLAY_REGION.bottom_start;
      for (const k of Object.keys(region)) node.style[k] = region[k];
    }

    function buildControl(spec) {
      switch (spec.kind) {
        case 'button': return buildButton(spec);
        case 'button_cluster': return buildCluster(spec);
        case 'dpad': return buildDpad(spec);
        case 'stick': return buildStick(spec);
        case 'slider': return buildSlider(spec);
        case 'scrubber': return buildScrubber(spec);
        case 'toggle': return buildToggle(spec);
        case 'checkbox': return buildCheckbox(spec);
        case 'menu': // a menu is a select backed by a media list
        case 'select': return buildSelect(spec);
        case 'list': return buildList(spec);
        case 'keyboard': return buildKeyboard(spec);
        case 'status': return buildStatus(spec);
        default: return null;
      }
    }

    // A button emits either a raw control (binary/gamepad/key) or a
    // semantic action, per RFC §10.2.
    function emitPress(spec, pressed) {
      if (spec.action) {
        if (pressed) sinks.action(spec.action, spec.value);
        return;
      }
      const c = parseControl(spec.control);
      if (!c) return;
      const padId = spec.player || 0;
      if (c.ns === 'gamepad') sinks.gamepadButton(padId, c.name, pressed);
      else if (c.ns === 'key') sinks.key(c.name, pressed);
    }

    function wirePress(node, spec) {
      const hold = (spec.behavior && spec.behavior.minimum_hold_ms) || 0;
      let downAt = 0;
      const down = (ev) => {
        if (ev && ev.preventDefault) ev.preventDefault();
        node.classList.add('fx-active');
        downAt = (root.performance && root.performance.now) ? root.performance.now() : 0;
        emitPress(spec, true);
      };
      const up = () => {
        node.classList.remove('fx-active');
        // minimum-hold: defer the release edge for frame-sampled
        // consumers (RFC §10.4). Best-effort; no timer in fake-DOM tests.
        const release = () => emitPress(spec, false);
        if (hold > 0 && root.setTimeout) {
          const now = (root.performance && root.performance.now) ? root.performance.now() : 0;
          const remain = Math.max(0, hold - (now - downAt));
          root.setTimeout(release, remain);
        } else {
          release();
        }
      };
      node.addEventListener('pointerdown', down);
      node.addEventListener('pointerup', up);
      node.addEventListener('pointercancel', up);
      node.addEventListener('pointerleave', up);
      return { release: () => emitPress(spec, false) };
    }

    function buildButton(spec) {
      const node = el('button');
      node.className = 'fx-ctl fx-button';
      node.dataset.id = spec.id;
      node.textContent = cap(spec.label || spec.id);
      if (spec.a11y && spec.a11y.label) node.setAttribute('aria-label', cap(spec.a11y.label));
      const w = wirePress(node, spec);
      return { node, spec, release: w.release };
    }

    function buildCluster(spec) {
      const node = el('div');
      node.className = 'fx-ctl fx-cluster';
      node.dataset.id = spec.id;
      const children = [];
      for (const b of spec.buttons || []) {
        const child = buildButton(Object.assign({ kind: 'button' }, b));
        node.appendChild(child.node);
        children.push(child);
      }
      return { node, spec, release: () => children.forEach((c) => c.release && c.release()) };
    }

    // Digital d-pad with diagonals + track-through (RFC §9.5). Active
    // directions are computed from the pointer offset within the pad.
    function buildDpad(spec) {
      const node = el('div');
      node.className = 'fx-ctl fx-dpad';
      node.dataset.id = spec.id;
      const ctrls = (spec.source && spec.source.controls) || {};
      const padId = spec.player || 0;
      const diagonals = !(spec.behavior && spec.behavior.diagonals === false);
      let active = { up: false, down: false, left: false, right: false };

      const set = (next) => {
        for (const dir of ['up', 'down', 'left', 'right']) {
          if (next[dir] === active[dir]) continue;
          const ctl = ctrls[dir];
          if (ctl) {
            const c = parseControl(ctl);
            if (c && c.ns === 'gamepad') sinks.gamepadButton(padId, c.name, next[dir]);
            else if (c && c.ns === 'key') sinks.key(c.name, next[dir]);
          }
          node.classList.toggle('fx-dir-' + dir, next[dir]);
        }
        active = next;
      };
      const clear = () => set({ up: false, down: false, left: false, right: false });

      const fromPoint = (ev) => {
        const r = node.getBoundingClientRect ? node.getBoundingClientRect()
          : { left: 0, top: 0, width: 1, height: 1 };
        const nx = ((ev.clientX || 0) - r.left) / (r.width || 1) - 0.5;
        const ny = ((ev.clientY || 0) - r.top) / (r.height || 1) - 0.5;
        const dead = 0.18;
        const next = { up: false, down: false, left: false, right: false };
        if (ny < -dead) next.up = true;
        if (ny > dead) next.down = true;
        if (nx < -dead) next.left = true;
        if (nx > dead) next.right = true;
        if (!diagonals) {
          // collapse to the dominant axis
          if (Math.abs(nx) > Math.abs(ny)) { next.up = next.down = false; }
          else { next.left = next.right = false; }
        }
        return next;
      };
      let tracking = false;
      node.addEventListener('pointerdown', (ev) => {
        if (ev.preventDefault) ev.preventDefault();
        tracking = true; set(fromPoint(ev));
      });
      node.addEventListener('pointermove', (ev) => { if (tracking) set(fromPoint(ev)); });
      node.addEventListener('pointerup', () => { tracking = false; clear(); });
      node.addEventListener('pointercancel', () => { tracking = false; clear(); });
      node.addEventListener('pointerleave', () => { if (tracking) { tracking = false; clear(); } });
      return { node, spec, release: clear };
    }

    function buildStick(spec) {
      const node = el('div');
      node.className = 'fx-ctl fx-stick';
      node.dataset.id = spec.id;
      const knob = el('div');
      knob.className = 'fx-stick-knob';
      node.appendChild(knob);
      const padId = spec.player || 0;
      const side = (spec.axis === 'right') ? 'r' : 'l';
      let tracking = false;
      const update = (ev) => {
        const r = node.getBoundingClientRect ? node.getBoundingClientRect()
          : { left: 0, top: 0, width: 1, height: 1 };
        let nx = ((ev.clientX || 0) - r.left) / (r.width || 1) * 2 - 1;
        let ny = ((ev.clientY || 0) - r.top) / (r.height || 1) * 2 - 1;
        nx = Math.max(-1, Math.min(1, nx));
        ny = Math.max(-1, Math.min(1, ny));
        const axes = {};
        axes[side + 'x'] = Math.round(nx * 32767);
        axes[side + 'y'] = Math.round(ny * 32767);
        sinks.gamepadAxis(padId, axes);
      };
      const center = () => {
        const axes = {}; axes[side + 'x'] = 0; axes[side + 'y'] = 0;
        sinks.gamepadAxis(padId, axes);
      };
      // Capture the pointer on press so move/up keep arriving even when
      // the drag goes past the stick's edge (sticks need full-deflection
      // drags outside their bounds). Without capture, a release outside
      // the element never delivers `pointerup`, stranding the last
      // nonzero axis until blur/pagehide cleanup. `pointerleave` is a
      // fallback for environments lacking pointer capture (and is
      // suppressed by the browser while a capture is active, so it does
      // not fight the captured drag).
      let pointerId = null;
      const end = () => {
        if (!tracking) return;
        tracking = false;
        if (node.releasePointerCapture && pointerId != null) {
          try { node.releasePointerCapture(pointerId); } catch (_) {}
        }
        pointerId = null;
        center();
      };
      node.addEventListener('pointerdown', (ev) => {
        tracking = true;
        pointerId = (ev.pointerId != null) ? ev.pointerId : null;
        if (node.setPointerCapture && pointerId != null) {
          try { node.setPointerCapture(pointerId); } catch (_) {}
        }
        update(ev);
      });
      node.addEventListener('pointermove', (ev) => { if (tracking) update(ev); });
      node.addEventListener('pointerup', end);
      node.addEventListener('pointercancel', end);
      node.addEventListener('pointerleave', () => {
        const captured = node.hasPointerCapture && pointerId != null
          && node.hasPointerCapture(pointerId);
        if (tracking && !captured) end();
      });
      return { node, spec, release: center };
    }

    // `emitOnInput` (default true) drives the slider live as the user
    // drags — correct for a volume slider. A scrubber opts out so it does
    // not flood seek actions per input event; it seeks on release only.
    function buildSlider(spec, options) {
      const emitOnInput = !(options && options.emitOnInput === false);
      const node = el('input');
      node.className = 'fx-ctl fx-slider';
      node.dataset.id = spec.id;
      node.setAttribute('type', 'range');
      node.setAttribute('min', '0');
      node.setAttribute('max', '1000');
      if (emitOnInput) {
        node.addEventListener('input', () => {
          const v = (Number(node.value) || 0) / 1000;
          if (spec.action) sinks.action(spec.action, v);
        });
      }
      return { node, spec, statusField: spec.status_field,
        update: (val) => { if (val != null) node.value = String(Math.round(val * 1000)); } };
    }

    function buildScrubber(spec) {
      // Seek on release only (RFC §16.2): suppress the slider's per-input
      // emitter so dragging the scrubber doesn't flood/duplicate seeks,
      // then emit a single seek action on `change`.
      const built = buildSlider(spec, { emitOnInput: false });
      built.node.classList.remove('fx-slider');
      built.node.classList.add('fx-scrubber');
      built.node.addEventListener('change', () => {
        const v = (Number(built.node.value) || 0) / 1000;
        if (spec.action) sinks.action(spec.action, v);
      });
      built.statusField = spec.status_field || 'position';
      built.update = (val, status) => {
        const dur = status && status.duration_ms ? status.duration_ms : 0;
        const pos = status && status.position_ms ? status.position_ms : (val || 0);
        built.node.value = dur > 0 ? String(Math.round((pos / dur) * 1000)) : '0';
      };
      return built;
    }

    function buildToggle(spec) {
      const node = el('button');
      node.className = 'fx-ctl fx-toggle';
      node.dataset.id = spec.id;
      node.textContent = cap(spec.label || spec.id);
      node.setAttribute('aria-pressed', 'false');
      let on = false;
      node.addEventListener('click', () => {
        on = !on;
        node.setAttribute('aria-pressed', on ? 'true' : 'false');
        node.classList.toggle('fx-on', on);
        if (spec.action) sinks.action(spec.action, on);
        else emitPress(spec, on);
      });
      return { node, spec, statusField: spec.status_field,
        update: (val) => { on = !!val; node.setAttribute('aria-pressed', on ? 'true' : 'false'); node.classList.toggle('fx-on', on); } };
    }

    // A setting checkbox — distinct from `toggle`: its
    // state is parameter state, echoed via ParameterStatus.
    function buildCheckbox(spec) {
      const node = el('label');
      node.className = 'fx-ctl fx-checkbox';
      node.dataset.id = spec.id;
      const box = el('input');
      box.setAttribute('type', 'checkbox');
      const text = el('span');
      text.textContent = cap(spec.label || spec.id);
      node.appendChild(box);
      node.appendChild(text);
      box.addEventListener('change', () => {
        if (spec.action) sinks.action(spec.action, { parameter_id: spec.parameter_id, value: !!box.checked });
      });
      return { node, spec, statusField: spec.parameter_id,
        update: (val) => { box.checked = !!val; } };
    }

    // A `select`/`menu` backed by a bounded option list (RFC §17.3 /
    // §A.3). Options come from `opts.lists[spec.list]`;
    // labels are untrusted text.
    function buildSelect(spec) {
      const node = el('select');
      node.className = 'fx-ctl fx-select';
      node.dataset.id = spec.id;
      if (spec.a11y && spec.a11y.label) node.setAttribute('aria-label', cap(spec.a11y.label));
      // `opts.lists[name]` MUST be a *resolved* option-row array. The
      // shell descriptor's `lists:` is only a name→feed declaration
      // (RFC §17.3); the host resolves each feed to a bounded snapshot
      // before mount. Guard defensively: a bare feed string (or any
      // non-array) would otherwise iterate per-character into junk
      // <option>s, so coerce anything that is not an array to empty and
      // fall back to an inline `spec.options` array only.
      let list = opts.lists && opts.lists[spec.list];
      if (!Array.isArray(list)) list = Array.isArray(spec.options) ? spec.options : [];
      for (const o of list) {
        if (!o || typeof o !== 'object') continue;
        const opt = el('option');
        opt.setAttribute('value', cap(o.id != null ? o.id : o.option_id));
        opt.textContent = cap(o.label);
        if (o.enabled === false) opt.setAttribute('disabled', 'true');
        node.appendChild(opt);
      }
      node.addEventListener('change', () => {
        const v = node.value;
        if (spec.action) sinks.action(spec.action, { parameter_id: spec.parameter_id, option_id: v });
      });
      return { node, spec, statusField: spec.parameter_id,
        update: (val) => { if (val != null) node.value = String(val); } };
    }

    // A browsable, selectable list view — the rich-row sibling of
    // `select` (which is a compact dropdown). Generic by construction:
    // rows are `{ id, label, sublabel?, badge?, selected?, enabled? }`
    // records carrying no domain meaning. Rows come from the resolved
    // feed snapshot `opts.lists[spec.list]` (RFC §17.3 — the shell's
    // `lists:` is a name→feed declaration the host resolves to a bounded
    // snapshot) with an inline `spec.options` fallback. Picking a row
    // emits the selection `action` with `{ item_id }`; the app decides
    // what that means (catalog launch, ROM select, save-state slot, …).
    // Feed-driven: when the status plane (`applyStatus`) pushes a fresh
    // row array on `spec.status_field`, the list re-renders, so a
    // coordinator can stream live catalog updates in. All label text is
    // untrusted → `cap()`-bounded, same as every other control.
    function buildList(spec) {
      const node = el('div');
      node.className = 'fx-ctl fx-list';
      node.dataset.id = spec.id;
      node.setAttribute('role', 'listbox');
      if (spec.a11y && spec.a11y.label) node.setAttribute('aria-label', cap(spec.a11y.label));

      function rows(src) {
        if (Array.isArray(src)) return src;
        const l = opts.lists && opts.lists[spec.list];
        if (Array.isArray(l)) return l;
        return Array.isArray(spec.options) ? spec.options : [];
      }
      function clearSelection() {
        const kids = node.childNodes || [];
        for (let i = 0; i < kids.length; i++) {
          if (kids[i].classList) kids[i].classList.remove('fx-list-row-selected');
        }
      }
      function render(src) {
        node.textContent = '';
        for (const o of rows(src)) {
          if (!o || typeof o !== 'object') continue;
          const id = o.id != null ? o.id : o.option_id;
          const row = el('button');
          row.className = 'fx-list-row' + (o.selected ? ' fx-list-row-selected' : '');
          row.setAttribute('role', 'option');
          row.dataset.itemId = cap(id);
          if (o.enabled === false) row.setAttribute('disabled', 'true');
          const title = el('span');
          title.className = 'fx-list-title';
          title.textContent = cap(o.label);
          row.appendChild(title);
          if (o.sublabel != null) {
            const sub = el('span');
            sub.className = 'fx-list-sub';
            sub.textContent = cap(o.sublabel);
            row.appendChild(sub);
          }
          if (o.badge != null) {
            const b = el('span');
            b.className = 'fx-list-badge';
            b.textContent = cap(o.badge);
            row.appendChild(b);
          }
          row.addEventListener('click', () => {
            if (o.enabled === false) return;
            clearSelection();
            row.classList.add('fx-list-row-selected');
            if (spec.action) sinks.action(spec.action, { item_id: id });
          });
          node.appendChild(row);
        }
      }
      render(null);
      return { node, spec, statusField: spec.status_field,
        update: (val) => { if (Array.isArray(val)) render(val); } };
    }

    // Virtual keyboard show/hide drawer (RFC §11.5). A machine keyboard
    // emits key identities; this builds a compact key grid that emits
    // `key.symbolic.*` transitions.
    function buildKeyboard(spec) {
      const node = el('div');
      node.className = 'fx-ctl fx-keyboard';
      node.dataset.id = spec.id;
      const keys = spec.keys || defaultKeyRow();
      for (const k of keys) {
        const kb = el('button');
        kb.className = 'fx-key';
        kb.textContent = cap(k.label || k.key);
        const sym = k.key;
        kb.addEventListener('pointerdown', (ev) => { if (ev.preventDefault) ev.preventDefault(); sinks.key(sym, true); kb.classList.add('fx-active'); });
        kb.addEventListener('pointerup', () => { sinks.key(sym, false); kb.classList.remove('fx-active'); });
        kb.addEventListener('pointercancel', () => { sinks.key(sym, false); kb.classList.remove('fx-active'); });
        node.appendChild(kb);
      }
      return { node, spec, release: () => {} };
    }

    function buildStatus(spec) {
      const node = el('div');
      node.className = 'fx-ctl fx-status';
      node.dataset.id = spec.id;
      node.textContent = '';
      return { node, spec, statusField: spec.field,
        update: (val) => { node.textContent = cap(val); } };
    }

    // ── Status plane: push bounded PresentationStatus snapshots in;
    //    controls bound to a field re-render. Untrusted strings capped.
    function applyStatus(status) {
      if (!status) return;
      for (const b of statusBound) {
        if (!b.update) continue;
        const field = b.statusField;
        const val = status[field];
        b.update(val, status);
      }
    }

    // ── Orientation / responsive layout. Persistent controls live in
    //    rails (landscape) or the below row (portrait), never `content`.
    function computeOrientation(w, h, coarse) {
      if (!coarse && w >= 900) return 'desktop';
      return (w >= h) ? 'landscape' : 'portrait';
    }
    function setOrientation(o) {
      if (o === orientation) return;
      orientation = o;
      rootEl.className = rootEl.className
        .replace(/\bfx-orient-\w+\b/g, '').trim() + ' fx-orient-' + o;
      renderAll();
    }

    function relayout(viewport) {
      const w = viewport ? viewport.width : (root.innerWidth || 0);
      const h = viewport ? viewport.height : (root.innerHeight || 0);
      const mq = (q) => !!(root.matchMedia && root.matchMedia(q).matches);
      const coarse = viewport ? !!viewport.coarse : mq('(pointer: coarse)');
      // Surface traits the resolver keys on.
      const sc = sizeClassFor(w, curSizeClass);
      let mods = 1; // MODALITY_KEY — a browser always has a key path
      if (viewport && viewport.modalities != null) {
        mods = viewport.modalities | 0;
      } else {
        if (viewport ? !!viewport.fine : mq('(pointer: fine)')) mods |= 2;
        if (coarse) mods |= 4;
        if (viewport ? !!viewport.touch
          : (('ontouchstart' in root) || ((root.navigator && root.navigator.maxTouchPoints | 0) > 0))) {
          mods |= 8;
        }
      }
      const traitsChanged = sc !== curSizeClass || mods !== curModalities;
      curSizeClass = sc;
      curModalities = mods;
      const o = computeOrientation(w, h, coarse);
      if (o !== orientation) {
        setOrientation(o); // re-renders
      } else if (traitsChanged) {
        renderAll(); // size class / modality crossed a threshold within one orientation
      }
    }

    // ── Lifecycle cleanup: release all held input on interruption
    //    (RFC §8.4 / §14.7).
    function releaseAll() {
      for (const c of controls) if (c.release) c.release();
    }

    // Initial layout + render. `orientation` is null, so this first
    // relayout always runs `renderAll()` via `setOrientation`.
    relayout(opts.viewport);

    if (opts.mountEl) opts.mountEl.appendChild(rootEl);

    // Browser wiring (skipped under the fake DOM in tests).
    if (!opts.noAutoWire && root.addEventListener) {
      const onResize = () => relayout();
      root.addEventListener('resize', onResize);
      if (root.visualViewport && root.visualViewport.addEventListener) {
        root.visualViewport.addEventListener('resize', onResize);
      }
      for (const evt of ['blur', 'visibilitychange', 'pagehide']) {
        root.addEventListener(evt, releaseAll);
      }
    }

    return {
      root: rootEl,
      zones,
      controls,
      get orientation() { return orientation; },
      relayout,
      applyStatus,
      releaseAll,
      setOrientation,
    };
  }

  function defaultPlacement(profile, spec) {
    if (spec.kind === 'dpad' || spec.kind === 'stick') return 'primary_start';
    if (spec.kind === 'button_cluster') return 'primary_end';
    if (spec.kind === 'select' || spec.kind === 'checkbox' || spec.kind === 'keyboard') return 'drawer';
    return 'secondary';
  }

  function defaultKeyRow() {
    const out = [];
    for (let d = 0; d <= 9; d++) out.push({ key: String(d), label: String(d) });
    out.push({ key: 'Enter', label: '⏎' });
    return out;
  }

  // Scoped stylesheet — injected once. Grid-based zones; persistent
  // controls reserve space around `content` so it is never obscured.
  function ensureStyles(doc) {
    if (!doc.getElementById) return;
    if (doc.getElementById('fx-overlay-style')) return;
    const style = doc.createElement('style');
    style.id = 'fx-overlay-style';
    style.textContent = OVERLAY_CSS;
    if (doc.head && doc.head.appendChild) doc.head.appendChild(style);
    else if (doc.body && doc.body.appendChild) doc.body.appendChild(style);
  }

  const OVERLAY_CSS = [
    '.fx-overlay{position:absolute;inset:0;display:grid;gap:8px;',
    'padding:env(safe-area-inset-top,0) env(safe-area-inset-right,0) env(safe-area-inset-bottom,0) env(safe-area-inset-left,0);',
    'box-sizing:border-box;}',
    '.fx-immersive{overflow:hidden;overscroll-behavior:none;}',
    // Control zones capture pointer events. The host mounts the overlay
    // root with `pointer-events:none` as a click-through baseline (so the
    // surface beneath still receives input) and `pointer-events` inherits,
    // so each control-bearing zone must re-assert `auto` or its controls
    // go dead. The content zone deliberately stays click-through.
    '.fx-zone{display:flex;align-items:center;justify-content:center;gap:8px;flex-wrap:wrap;pointer-events:auto;}',
    '.fx-zone-content{overflow:hidden;pointer-events:none;}',
    // Superimposed mode (RFC §11.3): a control overlaid translucently OVER live
    // content at its app-declared region. The content zone becomes the
    // positioning context; the control re-asserts pointer-events (the zone is
    // click-through) and sits above the content.
    '.fx-zone-content{position:relative;}',
    '.fx-superimposed{position:absolute;pointer-events:auto;opacity:0.82;z-index:3;}',
    '.fx-zone-transient{position:absolute;left:0;right:0;bottom:0;pointer-events:none;}',
    '.fx-zone-transient>*{pointer-events:auto;}',
    '.fx-zone-debug{display:none;}',
    // Portrait: content above, controls split below, drawer/above rows.
    '.fx-orient-portrait{grid-template-columns:1fr 1fr;',
    'grid-template-areas:"above above" "content content" "below_start below_end" "below_center below_center" "drawer drawer";',
    'grid-template-rows:auto 1fr auto auto auto;}',
    '.fx-orient-portrait .fx-zone-left_rail,.fx-orient-portrait .fx-zone-right_rail{display:none;}',
    // Landscape: rails flank content.
    '.fx-orient-landscape{grid-template-columns:auto 1fr auto;',
    'grid-template-areas:"above above above" "left_rail content right_rail" "below_center below_center below_center" "drawer drawer drawer";',
    'grid-template-rows:auto 1fr auto auto;}',
    '.fx-orient-landscape .fx-zone-below_start,.fx-orient-landscape .fx-zone-below_end{display:none;}',
    // Desktop: content centered. Virtual gameplay controls are hidden by the
    // resolver (resolveLayout's virtual-gameplay policy), not CSS.
    '.fx-orient-desktop{grid-template-columns:1fr;',
    'grid-template-areas:"above" "content" "below_center" "drawer";grid-template-rows:auto 1fr auto auto;}',
    '.fx-zone-above{grid-area:above;}.fx-zone-content{grid-area:content;}',
    '.fx-zone-left_rail{grid-area:left_rail;flex-direction:column;}',
    '.fx-zone-right_rail{grid-area:right_rail;flex-direction:column;}',
    '.fx-zone-below_start{grid-area:below_start;}.fx-zone-below_center{grid-area:below_center;}',
    '.fx-zone-below_end{grid-area:below_end;}.fx-zone-drawer{grid-area:drawer;}',
    // Controls — min 44px touch targets (RFC §22.2), no text select.
    '.fx-ctl{min-width:44px;min-height:44px;touch-action:none;user-select:none;pointer-events:auto;',
    '-webkit-user-select:none;-webkit-tap-highlight-color:transparent;}',
    '.fx-button,.fx-toggle,.fx-key{border-radius:8px;border:1px solid #444;background:#222;color:#eee;font:inherit;}',
    '.fx-active{background:#3a6;}.fx-on{background:#284;}',
    '.fx-dpad{width:140px;height:140px;position:relative;border-radius:12px;background:#1a1a1a;}',
    '.fx-stick{width:120px;height:120px;border-radius:50%;background:#1a1a1a;position:relative;}',
    '.fx-stick-knob{position:absolute;left:35%;top:35%;width:30%;height:30%;border-radius:50%;background:#555;}',
    '.fx-slider,.fx-scrubber{width:100%;}',
    '.fx-keyboard{display:flex;flex-wrap:wrap;gap:4px;}',
    // Browsable list view (the `list` control). Scrolls internally;
    // rows are full-width selectable buttons with title + optional
    // sublabel/badge. Selection highlight reuses the on-state accent.
    '.fx-list{display:flex;flex-direction:column;align-items:stretch;gap:4px;',
    'width:min(92vw,560px);max-height:100%;overflow-y:auto;padding:4px;box-sizing:border-box;}',
    '.fx-list-row{display:flex;flex-direction:column;align-items:flex-start;gap:2px;',
    'padding:8px 12px;border-radius:8px;border:1px solid #333;background:#1c1c1c;',
    'color:#eee;font:inherit;text-align:left;width:100%;box-sizing:border-box;cursor:pointer;}',
    '.fx-list-row:hover{background:#262626;}',
    '.fx-list-row-selected{background:#284;border-color:#3a6;}',
    '.fx-list-title{font-weight:600;}',
    '.fx-list-sub{font-size:0.82em;opacity:0.68;}',
    '.fx-list-badge{font-size:0.72em;opacity:0.6;align-self:flex-end;}',
  ].join('');

  // ── Surface Traits publisher (rfc_surface_traits.md) ──────────
  //
  // The browser is the trait *authority*: it owns viewport geometry,
  // orientation, the coarse size class, which input modalities are
  // present, and the audio config — and it is the only place that learns
  // when any of these change. This publisher lifts that state out of the
  // overlay's private CSS-reflow path and pushes it onto the kernel-bound
  // `__fluxor_surface_traits_queue`, where the `wasm_browser_surface_traits`
  // built-in drains it onto a `SurfaceTraits` channel. Runs independently
  // of whether the overlay is mounted — a chrome-less player still needs
  // traits.
  //
  // Coalescing: any number of raw events collapse into at most one record
  // per animation frame, and a record is only enqueued when the derived
  // traits actually changed (epoch bumps per change). Size classes carry
  // hysteresis so a viewport hovering on a breakpoint does not thrash.
  // Thresholds MUST match input::surface_traits.rs.

  const ST = {
    ORIENT_PORTRAIT: 0, ORIENT_LANDSCAPE: 1,
    SIZE_COMPACT: 0, SIZE_REGULAR: 1, SIZE_EXPANDED: 2,
    COMPACT_ENTER_PX: 580, REGULAR_ENTER_PX: 600,
    EXPANDED_LEAVE_PX: 880, EXPANDED_ENTER_PX: 900,
    MOD_KEY: 0x0001, MOD_POINTER_FINE: 0x0002, MOD_POINTER_COARSE: 0x0004,
    MOD_TOUCH: 0x0008, MOD_GAMEPAD: 0x0010, MOD_PHYSICAL_BUTTONS: 0x0020,
  };

  // Mirror of input::surface_traits::size_class_for — same hysteresis.
  function sizeClassFor(px, prev) {
    if (prev === ST.SIZE_EXPANDED) {
      if (px < ST.EXPANDED_LEAVE_PX) {
        return (px < ST.COMPACT_ENTER_PX) ? ST.SIZE_COMPACT : ST.SIZE_REGULAR;
      }
      return ST.SIZE_EXPANDED;
    }
    if (prev === ST.SIZE_COMPACT) {
      if (px >= ST.EXPANDED_ENTER_PX) return ST.SIZE_EXPANDED;
      if (px >= ST.REGULAR_ENTER_PX) return ST.SIZE_REGULAR;
      return ST.SIZE_COMPACT;
    }
    // SIZE_REGULAR / cold start.
    if (px >= ST.EXPANDED_ENTER_PX) return ST.SIZE_EXPANDED;
    if (px < ST.COMPACT_ENTER_PX) return ST.SIZE_COMPACT;
    return ST.SIZE_REGULAR;
  }

  // Modality name → bit (mirror input::surface_traits MODALITY_*).
  const MODALITY_BIT = {
    key: 1, pointer_fine: 2, pointer_coarse: 4, touch: 8, gamepad: 16, physical_buttons: 32,
  };
  const SIZECLASS_RANK = { compact: 0, regular: 1, expanded: 2 };

  // Virtual gameplay controls are pointless on a true mouse-and-keyboard
  // surface (fine pointer, no touch) — this was a hard-coded desktop CSS rule;
  // it is now resolver POLICY DATA so the browser and the on-device resolver
  // make the same call. A real gamepad is handled by a declared
  // `suppress_if: modality.gamepad`; this covers the no-pad desktop case.
  const VIRTUAL_GAMEPLAY_KIND = { dpad: 1, stick: 1, button_cluster: 1 };

  // Browser specialization of the placement resolver
  // (tools/src/presentation_resolver.rs). It returns a `presentation.layout`-
  // shaped result: a Map of control id → disposition ('chrome' | 'content' |
  // 'hidden'). A browser surface has both chrome and content eligible with
  // unbounded zones and no physical buttons, so `bound`/capacity-overflow can't
  // trigger and the resolve reduces to: size filter → suppression (declared +
  // the virtual-gameplay policy) → plane = first `plane_affinity` (default
  // chrome). `renderAll` builds only the `chrome`-disposition controls; the
  // shrink ladder is this driven by viewport size class.
  function resolveLayout(specs, sizeClassRank, modalities) {
    const layout = new Map();
    const has = (name) => (modalities & MODALITY_BIT[name]) !== 0;
    for (const spec of specs) {
      const id = spec.id;
      const min = SIZECLASS_RANK[spec.min_size_class] || 0;
      const essential = spec.priority === 'essential';
      // 1. Below the surface size class → hidden (essential ignores the floor).
      if (sizeClassRank < min && !essential) { layout.set(id, 'hidden'); continue; }
      // 2. Suppression: a declared `suppress_if: modality.X`, or the virtual-
      //    gameplay policy (fine pointer present, no touch → no virtual pad).
      let suppressed = false;
      const s = spec.suppress_if;
      if (typeof s === 'string' && s.indexOf('modality.') === 0) {
        const bit = MODALITY_BIT[s.slice('modality.'.length)];
        if (bit && (modalities & bit)) suppressed = true;
      }
      if (!suppressed && VIRTUAL_GAMEPLAY_KIND[spec.kind] && has('pointer_fine') && !has('touch')) {
        suppressed = true;
      }
      if (suppressed) { layout.set(id, 'hidden'); continue; }
      // 3. Plane = first eligible affinity (both eligible on a browser surface).
      const aff = Array.isArray(spec.plane_affinity)
        ? spec.plane_affinity.filter((p) => p === 'chrome' || p === 'content')
        : [];
      layout.set(id, aff.length ? aff[0] : 'chrome');
    }
    return layout;
  }

  function installSurfaceTraits(win, opts) {
    opts = opts || {};
    const w = win || (typeof window !== 'undefined' ? window : {});
    const queue = w.__fluxor_surface_traits_queue
      || (w.__fluxor_surface_traits_queue = []);
    // Previous size classes feed hysteresis; start neutral (regular).
    let prevW = ST.SIZE_REGULAR;
    let prevH = ST.SIZE_REGULAR;
    let lastKey = null;     // change-detection key (excludes epoch)
    let epoch = 0;
    let scheduled = false;

    function probe() {
      // Test override: opts.viewport = { width, height, coarse, fine,
      // touch, gamepads, audioChannels, audioRateHz, physicalButtons }.
      const v = opts.viewport;
      const vw = v ? (v.width | 0) : (w.innerWidth | 0);
      const vh = v ? (v.height | 0) : (w.innerHeight | 0);
      const mq = (q) => !!(w.matchMedia && w.matchMedia(q).matches);
      const coarse = v ? !!v.coarse : mq('(pointer: coarse)');
      const fine = v ? !!v.fine : mq('(pointer: fine)');
      const touch = v ? !!v.touch
        : (('ontouchstart' in w) || ((w.navigator && w.navigator.maxTouchPoints | 0) > 0));
      let pads = 0;
      if (v && typeof v.gamepads === 'number') {
        pads = v.gamepads | 0;
      } else if (w.navigator && w.navigator.getGamepads) {
        try {
          for (const g of w.navigator.getGamepads()) if (g && g.connected) pads++;
        } catch (_) { pads = 0; }
      }
      const audioCh = v ? (v.audioChannels | 0)
        : ((w.__fluxor_audio_traits && w.__fluxor_audio_traits.channels) | 0);
      const audioHz = v ? (v.audioRateHz >>> 0)
        : ((w.__fluxor_audio_traits && w.__fluxor_audio_traits.rateHz) >>> 0);
      const physBtns = v ? !!v.physicalButtons : false;
      return { vw, vh, coarse, fine, touch, pads, audioCh, audioHz, physBtns };
    }

    function recompute() {
      const p = probe();
      const orientation = (p.vw >= p.vh) ? ST.ORIENT_LANDSCAPE : ST.ORIENT_PORTRAIT;
      const scW = sizeClassFor(p.vw, prevW);
      const scH = sizeClassFor(p.vh, prevH);
      prevW = scW;
      prevH = scH;
      let modalities = ST.MOD_KEY; // a browser surface always has a keyboard path
      if (p.fine) modalities |= ST.MOD_POINTER_FINE;
      if (p.coarse) modalities |= ST.MOD_POINTER_COARSE;
      if (p.touch) modalities |= ST.MOD_TOUCH;
      if (p.pads > 0) modalities |= ST.MOD_GAMEPAD;
      if (p.physBtns) modalities |= ST.MOD_PHYSICAL_BUTTONS;

      const key = [orientation, scW, scH, p.vw, p.vh, modalities, p.pads,
        p.audioCh, p.audioHz].join(',');
      if (key === lastKey) return false;
      lastKey = key;
      epoch = (epoch + 1) >>> 0;
      queue.push({
        orientation, sizeClassW: scW, sizeClassH: scH,
        viewportW: p.vw, viewportH: p.vh, modalities,
        gamepadCount: p.pads, audioChannels: p.audioCh,
        audioRateHz: p.audioHz, displayCount: 1, epoch,
      });
      // The publisher is installed for every runtime, but only the
      // `wasm_browser_surface_traits` built-in drains the queue. A scenario
      // without that module never consumes, so an actively-resizing window
      // would grow the queue unbounded. Records are last-write-wins snapshots,
      // so cap the backlog and drop the oldest — a late-wired consumer still
      // gets the most recent state, and an unwired one stays bounded.
      const QUEUE_CAP = 64;
      while (queue.length > QUEUE_CAP) queue.shift();
      return true;
    }

    // Coalesce a burst of raw events into one recompute per frame.
    function schedule() {
      if (scheduled) return;
      scheduled = true;
      const raf = w.requestAnimationFrame
        ? (cb) => w.requestAnimationFrame(cb)
        : (cb) => setTimeout(cb, 16);
      raf(() => { scheduled = false; recompute(); });
    }

    let stop = () => {};
    if (!opts.noAutoWire && w.addEventListener) {
      const onChange = () => schedule();
      const listeners = [['resize', w]];
      w.addEventListener('resize', onChange);
      if (w.visualViewport && w.visualViewport.addEventListener) {
        w.visualViewport.addEventListener('resize', onChange);
        listeners.push(['resize', w.visualViewport]);
      }
      for (const evt of ['gamepadconnected', 'gamepaddisconnected', 'orientationchange']) {
        w.addEventListener(evt, onChange);
        listeners.push([evt, w]);
      }
      stop = () => { for (const [evt, tgt] of listeners) tgt.removeEventListener(evt, onChange); };
    }

    // Startup baseline so a freshly-wired consumer has a record immediately.
    recompute();
    return { recompute, schedule, stop, _sizeClassFor: sizeClassFor };
  }

  // Map a page-space pointer position into a surface's LOGICAL pixel space —
  // the raster a module renders + hit-tests in. When a canvas is mounted (any
  // raster-rendering module, e.g. content_controls), that is the canvas's own
  // rect + intrinsic width/height, so a 240×80 content panel yields panel-local
  // coords and a 960×540 display yields 960×540. Canvas-less surfaces (the
  // gamepad overlay, hit-tested against the canonical 960×540 region table) use
  // the element rect + a 960×540 fallback. Used by runtime.html's pointer
  // listeners; exported so it can be unit-tested without a live browser.
  function surfaceLocalCoords(el, clientX, clientY) {
    const isCanvas = el && el.tagName && el.tagName.toUpperCase() === 'CANVAS';
    const canvas = isCanvas
      ? el
      : (el && el.querySelector ? el.querySelector('canvas') : null);
    const target = canvas || el;
    const rect = target.getBoundingClientRect();
    const logicalW = (canvas && canvas.width) || 960;
    const logicalH = (canvas && canvas.height) || 540;
    const scaleX = logicalW / (rect.width || logicalW);
    const scaleY = logicalH / (rect.height || logicalH);
    return {
      x: Math.round((clientX - rect.left) * scaleX),
      y: Math.round((clientY - rect.top) * scaleY),
    };
  }

  const api = { mount, makeSinks, makeHostSinks, installSurfaceTraits, surfaceLocalCoords, sizeClassFor, GAMEPAD_BIT, parseControl, fnv1a32, _css: OVERLAY_CSS };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.FluxorOverlay = api;
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
