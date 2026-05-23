// Reusable browser-side runtime for Fluxor browser endpoints.
//
// Owns the generic mechanics described in
// docs/architecture/browser_capability_surface.md §8: connection +
// reconnect, packet dispatch over the [kind|flags|reserved|payload_len]
// envelope, audio unlock + PCM scheduling, raster sink helpers, input
// capture lifecycle, diagnostics. Profile-specific code (renderers,
// keymaps, wire encoders) lives next to the application page.
//
// Loads as a plain <script> tag (no bundler). Attaches BrowserSurface
// to window. The profile script must load after this one.

(function () {
  'use strict';

  const HEADER_LEN = 8;
  const RECONNECT_MS_DEFAULT = 750;
  const PCM_HEADER_LEN = 16;
  const PCM_LEAD_MIN = 0.06;
  const PCM_LEAD_MAX = 0.5;

  // ── Session ──────────────────────────────────────────────────────────
  // connect(url, { packetHandlers, onStatusChange, reconnectMs })
  //   packetHandlers: { [kindByte]: function(view, bytes) }
  //   onStatusChange: function(text) — connect/error/disconnect notices
  //   reconnectMs: backoff before retrying after onclose (default 750)
  //
  // Returns { send(buffer), close() }. The session reconnects forever
  // until close() is called.
  function connect(url, opts) {
    opts = opts || {};
    const onStatusChange = opts.onStatusChange || function () {};
    const packetHandlers = opts.packetHandlers || {};
    const reconnectMs = (opts.reconnectMs == null) ? RECONNECT_MS_DEFAULT : opts.reconnectMs;
    let ws = null;
    let closed = false;

    function open() {
      ws = new WebSocket(url);
      ws.binaryType = 'arraybuffer';
      ws.onopen = function () { onStatusChange('connected'); };
      ws.onerror = function () { onStatusChange('websocket error'); };
      ws.onclose = function (event) {
        onStatusChange(`disconnected ${event.code || ''}`.trim());
        if (!closed) setTimeout(open, reconnectMs);
      };
      ws.onmessage = function (event) {
        const bytes = new Uint8Array(event.data);
        if (bytes.length < HEADER_LEN) return;
        const view = new DataView(event.data);
        const kind = view.getUint8(0);
        const payloadLen = view.getUint32(4, true);
        if (payloadLen + HEADER_LEN !== bytes.length) return;
        const handler = packetHandlers[kind];
        if (handler) handler(view, bytes);
      };
    }

    function send(buffer) {
      if (!ws || ws.readyState !== WebSocket.OPEN) return false;
      ws.send(buffer);
      return true;
    }

    function close() {
      closed = true;
      if (ws) ws.close();
    }

    open();
    return { send, close };
  }

  // ── Audio ────────────────────────────────────────────────────────────
  // createAudio() → { unlock(), handlePcmPacket(view, bytes),
  //                   onStatusChange(fn) }
  //
  // PCM packet layout (after the 8-byte session envelope):
  //   start_frame  : u64 LE        bytes 0..8
  //   sample_rate  : u32 LE        bytes 8..12
  //   frames       : u16 LE        bytes 12..14
  //   channels     : u8            byte  14
  //   sample_bytes : u8            byte  15
  //   samples      : channels × frames × sample_bytes (interleaved S16)
  //
  // The audio context is created lazily on the first unlock(). Browsers
  // require unlock() to be called from a user gesture handler.
  function createAudio() {
    let context = null;
    let gain = null;
    let nextTime = 0;
    let pcmPackets = 0;
    let pcmBlocks = 0;
    let onStatus = function () {};

    function ensure() {
      if (context) return;
      const Cls = window.AudioContext || window.webkitAudioContext;
      if (!Cls) throw new Error('AudioContext unavailable');
      context = new Cls();
      gain = context.createGain();
      gain.gain.value = 1;
      gain.connect(context.destination);
    }

    async function unlock() {
      try {
        ensure();
        await context.resume();
        nextTime = Math.max(nextTime, context.currentTime + 0.04);
        onStatus(`audio ${context.state} waiting`);
      } catch (err) {
        onStatus(`audio failed ${err.name || err.message}`);
      }
    }

    function handlePcmPacket(view, bytes) {
      pcmPackets++;
      if (!context) {
        onStatus(`audio off pcm ${pcmPackets}`);
        return;
      }
      try {
        const offset = HEADER_LEN;
        const sampleRate = view.getUint32(offset + 8, true);
        const frames = view.getUint16(offset + 12, true);
        const channels = view.getUint8(offset + 14);
        const sampleBytes = view.getUint8(offset + 15);
        if (sampleBytes !== 2 || channels < 1) return;
        const buffer = context.createBuffer(1, frames, sampleRate);
        const channel = buffer.getChannelData(0);
        let pos = offset + PCM_HEADER_LEN;
        for (let frame = 0; frame < frames; frame++) {
          let mixed = 0;
          for (let ch = 0; ch < channels; ch++) {
            mixed += view.getInt16(pos, true) / 32768;
            pos += 2;
          }
          channel[frame] = mixed / channels;
        }
        pcmBlocks++;
        const now = context.currentTime;
        if (nextTime < now + PCM_LEAD_MIN) {
          nextTime = now + PCM_LEAD_MIN;
        } else if (nextTime > now + PCM_LEAD_MAX) {
          nextTime = now + PCM_LEAD_MIN;
        }
        const source = context.createBufferSource();
        source.buffer = buffer;
        source.connect(gain);
        source.start(nextTime);
        const lead = nextTime - now;
        nextTime += buffer.duration;
        onStatus(`${context.state} pcm=${pcmBlocks} lead=${lead.toFixed(2)} sr=${context.sampleRate}`);
      } catch (err) {
        onStatus(`audio error ${err.name}`);
      }
    }

    return {
      unlock,
      handlePcmPacket,
      onStatusChange: function (fn) { onStatus = fn || function () {}; },
    };
  }

  // ── Raster RGB565 sink ───────────────────────────────────────────────
  // createRasterRgb565(canvas) → function(view, bytes)
  //
  // RGB565 packet layout (after the 8-byte session envelope):
  //   start_frame : u32 LE         bytes 0..4
  //   width       : u16 LE         bytes 4..6
  //   height      : u16 LE         bytes 6..8
  //   pixels      : width × height × 2 bytes (LE 5-6-5)
  //
  // Resizes the canvas on the first frame and on every dimension change.
  function createRasterRgb565(canvas) {
    const ctx = canvas.getContext('2d', { alpha: false });
    let image = ctx.createImageData(canvas.width, canvas.height);
    return function (view, bytes) {
      const width = view.getUint16(HEADER_LEN + 4, true);
      const height = view.getUint16(HEADER_LEN + 6, true);
      if (width !== canvas.width || height !== canvas.height) {
        canvas.width = width;
        canvas.height = height;
        image = ctx.createImageData(canvas.width, canvas.height);
      }
      const pixels = HEADER_LEN + 8;
      for (let src = pixels, dst = 0; src + 1 < bytes.length; src += 2, dst += 4) {
        const v = bytes[src] | (bytes[src + 1] << 8);
        image.data[dst] = ((v >> 11) & 0x1f) * 255 / 31;
        image.data[dst + 1] = ((v >> 5) & 0x3f) * 255 / 63;
        image.data[dst + 2] = (v & 0x1f) * 255 / 31;
        image.data[dst + 3] = 255;
      }
      ctx.putImageData(image, 0, 0);
    };
  }

  // ── Input capture ────────────────────────────────────────────────────
  // createInput({ onChange, onFirstInput, interestingCodes, activeClass })
  //
  // Returns { pressedCodes: Set<string>, pressedControls: Set<string>,
  //           installKeyboard(), bindButtons(selector), bindDpad(el),
  //           setControl(name, pressed), clearAll() }
  //
  // The runtime only owns the state bookkeeping and DOM event plumbing.
  // The profile reads pressedCodes / pressedControls and encodes the
  // wire packet whenever onChange fires.
  //
  // interestingCodes is a Set<string> of DOM `code` values worth
  // capturing. Keys not in the set fall through to the page (allows
  // dev-tools shortcuts, refresh, etc).
  function createInput(opts) {
    opts = opts || {};
    const onChange = opts.onChange || function () {};
    const onFirstInput = opts.onFirstInput || function () {};
    const interestingCodes = opts.interestingCodes || null;
    const activeClass = opts.activeClass || 'active';
    const pressedCodes = new Set();
    const pressedControls = new Set();

    function isInteresting(code) {
      return !interestingCodes || interestingCodes.has(code);
    }

    function onKey(event, pressed) {
      if (!isInteresting(event.code)) return;
      event.preventDefault();
      if (pressed) {
        pressedCodes.add(event.code);
        onFirstInput();
      } else {
        pressedCodes.delete(event.code);
      }
      onChange();
    }

    function setControl(control, pressed) {
      if (pressed) pressedControls.add(control);
      else pressedControls.delete(control);
      document.querySelectorAll(`[data-control="${control}"]`).forEach(function (el) {
        el.classList.toggle(activeClass, pressed);
      });
      onChange();
    }

    function clearAll() {
      pressedCodes.clear();
      pressedControls.clear();
      document.querySelectorAll('.' + activeClass).forEach(function (el) {
        el.classList.remove(activeClass);
      });
      onChange();
    }

    function installKeyboard() {
      window.addEventListener('keydown', function (e) { onKey(e, true); });
      window.addEventListener('keyup', function (e) { onKey(e, false); });
      window.addEventListener('blur', clearAll);
    }

    function bindButtons(selector) {
      document.querySelectorAll(selector).forEach(function (button) {
        const control = button.dataset.control;
        if (!control) return;
        button.addEventListener('pointerdown', function (e) {
          e.preventDefault();
          button.setPointerCapture(e.pointerId);
          onFirstInput();
          setControl(control, true);
        });
        button.addEventListener('pointerup', function (e) {
          e.preventDefault();
          setControl(control, false);
        });
        button.addEventListener('pointercancel', function () { setControl(control, false); });
      });
    }

    function bindDpad(dpadEl, dpadControls) {
      const controls = dpadControls || ['up', 'down', 'left', 'right'];
      function controlsAt(event) {
        const rect = dpadEl.getBoundingClientRect();
        const x = event.clientX - rect.left;
        const y = event.clientY - rect.top;
        if (x < 0 || y < 0 || x >= rect.width || y >= rect.height) return [];
        const out = [];
        if (y < rect.height / 3) out.push('up');
        if (y >= rect.height * 2 / 3) out.push('down');
        if (x < rect.width / 3) out.push('left');
        if (x >= rect.width * 2 / 3) out.push('right');
        return out;
      }
      function update(event) {
        const next = new Set(controlsAt(event));
        for (const c of controls) setControl(c, next.has(c));
      }
      function clear() { for (const c of controls) setControl(c, false); }
      dpadEl.addEventListener('pointerdown', function (e) {
        e.preventDefault();
        dpadEl.setPointerCapture(e.pointerId);
        onFirstInput();
        update(e);
      });
      dpadEl.addEventListener('pointermove', function (e) {
        if (dpadEl.hasPointerCapture(e.pointerId)) {
          e.preventDefault();
          update(e);
        }
      });
      dpadEl.addEventListener('pointerup', function (e) { e.preventDefault(); clear(); });
      dpadEl.addEventListener('pointercancel', clear);
    }

    return {
      pressedCodes,
      pressedControls,
      installKeyboard,
      bindButtons,
      bindDpad,
      setControl,
      clearAll,
    };
  }

  // ── Diagnostics ──────────────────────────────────────────────────────
  // installDiagnostics(handler) — handler receives a one-line string for
  // each window.error / unhandledrejection. Profile decides where it
  // surfaces (status DOM, MON_BROWSER telemetry, etc).
  function installDiagnostics(handler) {
    handler = handler || function () {};
    window.addEventListener('error', function (event) {
      handler(`js error ${event.message || 'unknown'}`);
    });
    window.addEventListener('unhandledrejection', function (event) {
      const reason = event.reason;
      handler(`js rejection ${reason && (reason.name || reason.message) || 'unknown'}`);
    });
  }

  window.BrowserSurface = {
    HEADER_LEN,
    connect,
    createAudio,
    createRasterRgb565,
    createInput,
    installDiagnostics,
  };
})();
