// Fluxor wasm host-import shim — single source of truth for the
// JS-side functions the wasm kernel imports from `env`. Every
// `extern "C"` block under `src/platform/wasm/` (plus the universal
// ones in `src/platform/wasm.rs`) corresponds to a function here.
//
// The wasm kernel imports ALL host_* functions unconditionally at
// link time — every built-in is registered at boot, even when its
// graph YAML doesn't wire it. Missing any one of them causes
// `WebAssembly.instantiate` to throw "LinkError: import 'env.host_X'
// is not defined", so the host page must provide the full set.
//
// Usage:
//   <script src="/host_shims.js"></script>
//   <script type="module">
//     const setKernel = (k) => { /* called once kernel is instantiated */ };
//     const imports = window.fluxor.buildHostImports({
//       getKernel: () => kernel,                  // required
//       onLog: (level, msg) => console.log(...), // optional
//       onPanic: (msg) => stopLoop(),            // optional
//       onCanvasFrame: (w, h) => {},             // optional
//       canvasContainer: stage,                   // required for canvas
//       inputQueue: keyboardQueue,                // required for input
//     });
//     const { instance } = await WebAssembly.instantiate(bytes, imports);
//     kernel = instance;
//   </script>
//
// Coverage test in tools/tests/wasm_host_shim_coverage.rs scans this
// file plus every `src/platform/wasm/*.rs` extern block and asserts
// the shim mentions every imported name.

(function () {
  function buildHostImports(opts) {
    const o = opts || {};
    const getKernel = o.getKernel || (() => null);
    const onLog = o.onLog || ((_lvl, msg) => console.log('[wasm]', msg));
    const onPanic = o.onPanic || ((msg) => { throw new Error('wasm panic: ' + msg); });
    const onCanvasFrame = o.onCanvasFrame || (() => {});
    const canvasContainer = o.canvasContainer || null;
    const inputQueue = o.inputQueue || [];
    const fetchUrlOverride = o.fetchUrlOverride || null;
    // Asset bank: a Map<string, Uint8Array> of assets baked into the
    // wasm bundle via the `fluxor.assets` custom section. URLs of the
    // form `asset://<name>` are served from this map without hitting
    // window.fetch — the bundle is self-contained, no fluxor-linux /
    // gallery folder / HTTP origin required at runtime. Empty map by
    // default; the shell extracts it from WebAssembly.Module
    // .customSections before instantiating and passes it in here.
    const assetBank = (o.assetBank instanceof Map) ? o.assetBank : new Map();

    function kmem() { return new Uint8Array(getKernel().exports.memory.buffer); }
    function kview(p, l) { return new Uint8Array(getKernel().exports.memory.buffer, p, l); }
    function kstr(p, l) { return new TextDecoder().decode(kview(p, l)); }

    // ── universal kernel imports ─────────────────────────────────────
    const universal = {
      host_now_us: () => BigInt(Math.round(performance.now() * 1000)),

      host_csprng_fill: (ptr, len) => {
        if (!self.crypto || !self.crypto.getRandomValues) return -38;
        const dst = kview(ptr, len);
        const CHUNK = 65536;
        for (let off = 0; off < len; off += CHUNK) {
          self.crypto.getRandomValues(dst.subarray(off, Math.min(off + CHUNK, len)));
        }
        return 0;
      },

      host_log: (level, ptr, len) => {
        const tag = ['trace', 'debug', 'info', 'warn', 'error'][level] || ('lvl' + level);
        onLog(level, '[' + tag + '] ' + kstr(ptr, len));
      },

      host_panic: (ptr, len) => {
        const msg = kstr(ptr, len);
        onPanic(msg);
        throw new Error('wasm panic: ' + msg);
      },
    };

    // ── fetch shim (host_browser_fetch) ──────────────────────────────
    const fetches = new Map();
    let nextFetchHandle = 1;

    const fetchShim = {
      host_fetch_open: (urlPtr, urlLen) => {
        try {
          let url = kstr(urlPtr, urlLen);
          if (fetchUrlOverride) url = fetchUrlOverride(url);
          const handle = nextFetchHandle++;
          const entry = { reader: null, queue: [], eof: false, contentLength: -3, bytes: 0 };
          fetches.set(handle, entry);

          // `asset://<name>` — short-circuit window.fetch. Bytes
          // come from the bundle's `fluxor.assets` custom section,
          // pre-parsed into `assetBank` by the shell. The wasm
          // kernel sees the exact same API surface (open/recv/size/
          // close) regardless of whether the bytes flew over HTTP or
          // were embedded; the runtime contract is just URL bytes.
          if (url.startsWith('asset://')) {
            const name = url.slice('asset://'.length);
            const bytes = assetBank.get(name);
            if (!bytes) {
              entry.eof = true;
              entry.contentLength = -2;
              console.warn(`host_fetch: asset:// miss for "${name}"`);
              return handle;
            }
            entry.contentLength = bytes.byteLength;
            entry.queue.push(bytes);
            entry.bytes = bytes.byteLength;
            entry.eof = true;
            return handle;
          }

          fetch(url).then(async (resp) => {
            if (!resp.ok) {
              entry.eof = true;
              entry.contentLength = -2;
              console.warn(`host_fetch: HTTP ${resp.status} ${resp.statusText} for ${url}`);
              return;
            }
            const cl = resp.headers.get('content-length');
            entry.contentLength = cl ? parseInt(cl, 10) : -1;
            const reader = resp.body.getReader();
            entry.reader = reader;
            while (true) {
              const { done, value } = await reader.read();
              if (done) {
                entry.eof = true;
                break;
              }
              entry.queue.push(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
              entry.bytes += value.byteLength;
            }
          }).catch((err) => {
            entry.eof = true;
            entry.contentLength = -2;
            console.error(`host_fetch: ${err.message} for ${url}`);
          });
          return handle;
        } catch (err) {
          console.error(`host_fetch_open threw: ${err.message}`);
          return -1;
        }
      },
      host_fetch_recv: (handle, bufPtr, bufLen) => {
        const entry = fetches.get(handle);
        if (!entry) return -2;
        if (entry.queue.length === 0) return entry.eof ? -1 : 0;
        const chunk = entry.queue[0];
        const n = Math.min(chunk.length, bufLen);
        kview(bufPtr, n).set(chunk.subarray(0, n));
        if (n >= chunk.length) entry.queue.shift();
        else entry.queue[0] = chunk.subarray(n);
        return n;
      },
      host_fetch_size: (handle) => {
        const entry = fetches.get(handle);
        return entry ? entry.contentLength : -1;
      },
      host_fetch_close: (handle) => {
        const entry = fetches.get(handle);
        if (!entry) return 0;
        if (entry.reader && !entry.eof) {
          try { entry.reader.cancel().catch(() => {}); } catch (_) {}
        }
        fetches.delete(handle);
        return 0;
      },
    };

    // ── Legacy omnibus input drain (wasm_browser_dom_input) ──────────
    // Kept for graphs that still wire the old combined module. New
    // graphs use the per-class modules below.
    const inputShim = {
      host_input_pop: (bufPtr, bufLen) => {
        if (inputQueue.length === 0 || bufLen < 8) return 0;
        const ev = inputQueue.shift();
        const view = new DataView(getKernel().exports.memory.buffer, bufPtr, 8);
        view.setUint32(0, 0, true);
        view.setUint8(4, (ev.modifiers || 0) & 0xFF);
        view.setUint8(5, 0);
        view.setUint8(6, ev.keyCode & 0xFF);
        view.setUint8(7, (ev.keyCode >> 8) & 0xFF);
        return 8;
      },
    };

    // ── Per-class input drains (capability-surface model) ────────────
    //
    // Each maps a browser-native input source to the matching wire
    // shape from `modules/sdk/contracts/input/<class>.rs`. The
    // host-side queues are exposed as globals so producer code
    // (event listeners installed by the page, or gamepad polling
    // installed by the shell) can push records into them.
    //
    //   wasm_browser_keyboard  ←  __fluxor_keyboard_queue
    //                              { kind, modifiers, repeat, keyCode, scanCode }
    //   wasm_browser_pointer   ←  __fluxor_pointer_queue
    //                              { pointerId, kind, buttons, modifiers,
    //                                pressure, x, y }
    //   wasm_browser_gamepad   ←  __fluxor_gamepad_queue
    //                              { kind: 0x01|0x02, gamepadId, connected,
    //                                buttonBits, axisLx, axisLy, axisRx, axisRy }

    const keyboardQueue = window.__fluxor_keyboard_queue
      || (window.__fluxor_keyboard_queue = []);
    const keyboardShim = {
      host_keyboard_pop: (bufPtr, bufLen) => {
        if (keyboardQueue.length === 0 || bufLen < 8) return 0;
        const ev = keyboardQueue.shift();
        const view = new DataView(getKernel().exports.memory.buffer, bufPtr, 8);
        view.setUint8(0, 0x01);                  // MSG_EVENT
        view.setUint8(1, ev.kind & 0xFF);        // KIND_DOWN / KIND_UP
        view.setUint8(2, ev.modifiers & 0xFF);
        view.setUint8(3, ev.repeat ? 1 : 0);
        view.setUint16(4, ev.keyCode & 0xFFFF, true);
        view.setUint16(6, (ev.scanCode || 0) & 0xFFFF, true);
        return 8;
      },
    };

    const pointerQueue = window.__fluxor_pointer_queue
      || (window.__fluxor_pointer_queue = []);
    const pointerShim = {
      host_pointer_pop: (bufPtr, bufLen) => {
        if (pointerQueue.length === 0 || bufLen < 16) return 0;
        const ev = pointerQueue.shift();
        const view = new DataView(getKernel().exports.memory.buffer, bufPtr, 16);
        view.setUint8(0, 0x01);                  // MSG_EVENT
        view.setUint8(1, ev.pointerId & 0xFF);
        view.setUint8(2, ev.kind & 0xFF);
        view.setUint8(3, ev.buttons & 0xFF);
        view.setUint8(4, ev.modifiers & 0xFF);
        view.setUint8(5, 0);
        view.setUint16(6, ev.pressure & 0xFFFF, true);
        view.setInt16(8,  ev.x | 0, true);
        view.setInt16(10, ev.y | 0, true);
        view.setUint32(12, 0, true);
        return 16;
      },
    };

    // BUTTON capability driver — wasm equivalent of `flash_rp` on
    // rp boards. The runtime shell pushes one-byte transitions
    // (0x01=pressed, 0x00=released) into this queue whenever the
    // user taps an interactive surface; the wasm kernel drains via
    // `host_button_pop`. Downstream `gesture` does click counting +
    // FMP mapping — same chain every other platform uses.
    const buttonQueue = window.__fluxor_button_queue
      || (window.__fluxor_button_queue = []);
    const buttonShim = {
      host_button_pop: (bufPtr, bufLen) => {
        if (buttonQueue.length === 0 || bufLen < 1) return 0;
        const byte = buttonQueue.shift() & 0xFF;
        const view = new DataView(getKernel().exports.memory.buffer, bufPtr, 1);
        view.setUint8(0, byte);
        return 1;
      },
    };

    const gamepadQueue = window.__fluxor_gamepad_queue
      || (window.__fluxor_gamepad_queue = []);
    const gamepadShim = {
      host_gamepad_pop: (bufPtr, bufLen) => {
        if (gamepadQueue.length === 0 || bufLen < 16) return 0;
        const ev = gamepadQueue.shift();
        const view = new DataView(getKernel().exports.memory.buffer, bufPtr, 16);
        view.setUint8(0, ev.kind & 0xFF);        // MSG_STATE | MSG_CONNECTION
        view.setUint8(1, 0);
        view.setUint16(2, 0, true);
        view.setUint8(4, ev.gamepadId & 0xFF);
        view.setUint8(5, ev.connected ? 1 : 0);
        view.setUint16(6, ev.buttonBits & 0xFFFF, true);
        view.setInt16(8,  ev.axisLx | 0, true);
        view.setInt16(10, ev.axisLy | 0, true);
        view.setInt16(12, ev.axisRx | 0, true);
        view.setInt16(14, ev.axisRy | 0, true);
        return 16;
      },
    };

    // ── WebSocket (wasm_browser_websocket) ───────────────────────────
    const wsSockets = new Map();
    let nextWsHandle = 1;

    const wsShim = {
      host_ws_open: (urlPtr, urlLen) => {
        try {
          let url = kstr(urlPtr, urlLen);
          if (urlLen === 0 || url.length === 0) {
            console.warn('host_ws_open: empty URL');
            return -1;
          }
          // Resolve relative URLs against the page origin so a graph
          // can declare `url: /ws` and have it work regardless of
          // host / port at runtime (split scenarios on different
          // ports, qemu-virt port-forwards, future static-site
          // deployments, etc.). The `WebSocket` constructor itself
          // only accepts absolute ws:/wss: URLs.
          if (url.startsWith('/')) {
            const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            url = `${proto}//${window.location.host}${url}`;
          }
          const sock = new WebSocket(url);
          sock.binaryType = 'arraybuffer';
          const handle = nextWsHandle++;
          const entry = { socket: sock, rxQueue: [], open: false };
          wsSockets.set(handle, entry);
          sock.addEventListener('open',  () => { entry.open = true; });
          sock.addEventListener('close', () => { entry.open = false; });
          sock.addEventListener('error', () => {
            console.warn(`host_ws[${handle}]: connection failed (${url})`);
          });
          sock.addEventListener('message', (e) => {
            const data = e.data instanceof ArrayBuffer
              ? new Uint8Array(e.data)
              : new TextEncoder().encode(String(e.data));
            entry.rxQueue.push(data);
          });
          return handle;
        } catch (err) {
          console.error(`host_ws_open threw: ${err.message}`);
          return -1;
        }
      },
      host_ws_send: (handle, dataPtr, len) => {
        const entry = wsSockets.get(handle);
        if (!entry || !entry.open) {
          return 0;
        }
        const bytes = new Uint8Array(
          getKernel().exports.memory.buffer.slice(dataPtr, dataPtr + len)
        );
        try {
          entry.socket.send(bytes);
          return len;
        }
        catch (e) {
          console.error(`host_ws_send threw: ${e}`);
          return -1;
        }
      },
      host_ws_recv: (handle, bufPtr, bufLen) => {
        const entry = wsSockets.get(handle);
        if (!entry || entry.rxQueue.length === 0) return 0;
        const msg = entry.rxQueue[0];
        const n = Math.min(msg.length, bufLen);
        kview(bufPtr, n).set(msg.subarray(0, n));
        if (n >= msg.length) entry.rxQueue.shift();
        else entry.rxQueue[0] = msg.subarray(n);
        return n;
      },
    };

    // ── Audio sink (wasm_browser_audio) ──────────────────────────────
    // AudioContext is created lazily on the first `host_audio_play`
    // call and locked to the source sample rate.
    let audioCtx = null;
    let audioSchedTime = 0;
    function ensureAudio(sampleRate) {
      if (!audioCtx) {
        audioCtx = new (window.AudioContext || window.webkitAudioContext)({ sampleRate });
        audioSchedTime = audioCtx.currentTime;
      }
      return audioCtx;
    }
    // Per the browser autoplay policy, AudioContext starts
    // suspended until `resume()` is called inside a user-gesture
    // handler. The wasm pipeline's first PCM frames arrive several
    // ticks after the user's click, by which point the gesture
    // context is gone and `host_audio_play` silently drops them.
    // A one-shot document listener pre-creates and resumes the
    // context inside the first gesture, before any PCM is queued.
    function unlockAudioOnGesture() {
      const ctx = ensureAudio(44100);
      if (ctx.state === 'suspended') {
        ctx.resume().catch(() => {});
      }
      document.removeEventListener('pointerdown', unlockAudioOnGesture, true);
      document.removeEventListener('keydown',     unlockAudioOnGesture, true);
      document.removeEventListener('touchstart',  unlockAudioOnGesture, true);
    }
    document.addEventListener('pointerdown', unlockAudioOnGesture, true);
    document.addEventListener('keydown',     unlockAudioOnGesture, true);
    document.addEventListener('touchstart',  unlockAudioOnGesture, true);

    // Diagnostic counters (surfaced once per second through onLog).
    let audioPlayCalls = 0;
    let audioPlayBytesAccepted = 0;
    let audioPlayBytesDropped  = 0;
    let audioPlayLastSurfaced  = 0;
    let audioPeakAbs = 0;
    function surfaceAudioStats() {
      const now = performance.now();
      if ((now - audioPlayLastSurfaced) < 1000) return;
      audioPlayLastSurfaced = now;
      const ctxState = audioCtx ? audioCtx.state : 'no-ctx';
      const ctxRate  = audioCtx ? audioCtx.sampleRate : 0;
      onLog(2,
        `[audio] calls=${audioPlayCalls} bytes_played=${audioPlayBytesAccepted}` +
        ` bytes_dropped=${audioPlayBytesDropped} peak=${audioPeakAbs}` +
        ` ctx=${ctxState} hw_rate=${ctxRate}`);
      audioPeakAbs = 0;
    }

    const audioShim = {
      host_audio_play: (ptr, len, sampleRate, channels) => {
        audioPlayCalls++;
        const ctx = ensureAudio(sampleRate);
        if (ctx.state !== 'running') {
          audioPlayBytesDropped += len;
          surfaceAudioStats();
          return;
        }
        const i16 = new Int16Array(getKernel().exports.memory.buffer.slice(ptr, ptr + len));
        const ch = Math.max(1, channels | 0);
        const frames = Math.floor(i16.length / ch);
        if (!frames) return;
        const buf = ctx.createBuffer(ch, frames, sampleRate);
        for (let c = 0; c < ch; c++) {
          const f32 = buf.getChannelData(c);
          for (let f = 0; f < frames; f++) {
            const s = i16[f * ch + c];
            f32[f] = s / 32768;
            const abs = s < 0 ? -s : s;
            if (abs > audioPeakAbs) audioPeakAbs = abs;
          }
        }
        const src = ctx.createBufferSource();
        src.buffer = buf;
        src.connect(ctx.destination);
        const now = ctx.currentTime;
        if (audioSchedTime < now) audioSchedTime = now;
        src.start(audioSchedTime);
        audioSchedTime += frames / sampleRate;
        audioPlayBytesAccepted += len;
        surfaceAudioStats();
      },
    };

    // ── Canvas sink (wasm_browser_canvas) ────────────────────────────
    let canvasEl = null;
    let canvasCtx = null;
    let canvasImage = null;
    function ensureCanvas(w, h) {
      if (canvasEl && canvasEl.width === w && canvasEl.height === h) return;
      canvasEl = document.createElement('canvas');
      canvasEl.width = w; canvasEl.height = h;
      canvasEl.style.maxWidth = '100%';
      canvasEl.style.height = 'auto';
      if (canvasContainer) {
        canvasContainer.replaceChildren(canvasEl);
      } else {
        document.body.appendChild(canvasEl);
      }
      canvasCtx = canvasEl.getContext('2d');
      canvasImage = canvasCtx.createImageData(w, h);
    }
    // ── DOM scrollback terminal (wasm_browser_terminal) ──────────────
    //
    // Kernel log ring → `<pre>` widget. The terminal module calls
    // `host_terminal_emit(ptr, len)` with raw UTF-8 bytes drained
    // from the log ring; the shim appends them to the in-page
    // terminal surface (created by runtime.html when the
    // graph's presentation: block declares `role: terminal`).
    //
    // Multi-instance-safe: each terminal module instance shares the
    // same DOM widget (single per-page log surface). If a future
    // graph wires multiple terminals, the shim could honour an
    // explicit surface-id arg — for v1 a single widget is enough.
    const terminalShim = {
      host_terminal_emit: (ptr, len) => {
        if (len <= 0) return;
        const bytes = new Uint8Array(getKernel().exports.memory.buffer, ptr, len);
        const text = new TextDecoder('utf-8').decode(bytes);
        const surface = document.querySelector('[data-role="terminal"]');
        if (!surface) {
          // No terminal surface in DOM — fall back to console so the
          // bytes aren't silently dropped during boot before the
          // shell has composed surfaces.
          console.log('[terminal]', text);
          return;
        }
        // Append + autoscroll. Surface is a `<div>`; for line-by-line
        // styling future revs can split on '\n' and span each line.
        surface.appendChild(document.createTextNode(text));
        surface.scrollTop = surface.scrollHeight;
      },
    };

    const canvasShim = {
      host_canvas_present: (ptr, len, width, height) => {
        ensureCanvas(width, height);
        const src = kview(ptr, len);
        const dst = canvasImage.data;
        const pixels = width * height;
        for (let i = 0; i < pixels; i++) {
          const lo = src[i * 2];
          const hi = src[i * 2 + 1];
          const v = (hi << 8) | lo;
          const r = ((v >> 11) & 0x1F) * 255 / 31;
          const g = ((v >> 5) & 0x3F) * 255 / 63;
          const b = (v & 0x1F) * 255 / 31;
          const o = i * 4;
          dst[o] = r; dst[o + 1] = g; dst[o + 2] = b; dst[o + 3] = 255;
        }
        canvasCtx.putImageData(canvasImage, 0, 0);
        onCanvasFrame(width, height);
      },
    };

    // ── Image decode bridge (wasm_browser_image_codec) ───────────────
    const imageDecodes = new Map();
    let nextImageHandle = 1;
    const imageShim = {
      host_image_decode_open: (encPtr, encLen, width, height) => {
        try {
          const enc = new Uint8Array(
            getKernel().exports.memory.buffer.slice(encPtr, encPtr + encLen)
          );
          const handle = nextImageHandle++;
          const job = { state: 'pending', buf: null, pos: 0, error: null, width, height };
          imageDecodes.set(handle, job);
          const blob = new Blob([enc]);
          createImageBitmap(blob, { resizeWidth: width, resizeHeight: height,
                                    resizeQuality: 'high' })
            .then((bitmap) => {
              const off = new OffscreenCanvas(width, height);
              const ctx = off.getContext('2d');
              ctx.drawImage(bitmap, 0, 0);
              const img = ctx.getImageData(0, 0, width, height);
              const rgba = img.data;
              const out = new Uint8Array(width * height * 2);
              for (let i = 0, p = 0; i < rgba.length; i += 4, p += 2) {
                const r = rgba[i] >> 3;
                const g = rgba[i + 1] >> 2;
                const b = rgba[i + 2] >> 3;
                const v = (r << 11) | (g << 5) | b;
                out[p] = v & 0xFF;
                out[p + 1] = (v >> 8) & 0xFF;
              }
              job.buf = out;
              job.state = 'ready';
              bitmap.close();
            })
            .catch((err) => {
              job.state = 'error';
              job.error = err.message;
              console.error(`host_image_decode[${handle}] failed: ${err.message}`);
            });
          return handle;
        } catch (err) {
          console.error(`host_image_decode_open threw: ${err.message}`);
          return -1;
        }
      },
      host_image_decode_size: (handle) => {
        const job = imageDecodes.get(handle);
        if (!job) return -3;
        if (job.state === 'pending') return -1;
        if (job.state === 'error') return -2;
        return job.buf.length;
      },
      host_image_decode_recv: (handle, bufPtr, bufLen) => {
        const job = imageDecodes.get(handle);
        if (!job) return -3;
        if (job.state !== 'ready') return -1;
        const remaining = job.buf.length - job.pos;
        if (remaining === 0) return 0;
        const n = Math.min(remaining, bufLen);
        kview(bufPtr, n).set(job.buf.subarray(job.pos, job.pos + n));
        job.pos += n;
        return n;
      },
      host_image_decode_close: (handle) => imageDecodes.delete(handle) ? 0 : -1,
    };

    // ── Sub-module instantiation (host_instantiate_module, ...) ──────
    //
    // The wasm kernel exports a tiny set of PIC syscalls (channel_*,
    // provider_*, kernel_heap_alloc/free); sub-modules are linked
    // against those at instantiation. The shim bridges the
    // sub-module's linear memory and the kernel's linear memory by
    // allocating in the kernel's heap and copying through. Same
    // shape as the wasm_smoke / test_harness reference shims.
    const moduleInstances = new Map();
    let nextHandle = 1;

    const moduleShim = {
      host_instantiate_module: (bytesPtr, bytesLen, _impPtr, _impLen) => {
        try {
          const bytes = new Uint8Array(
            getKernel().exports.memory.buffer.slice(bytesPtr, bytesPtr + bytesLen)
          );
          const mod = new WebAssembly.Module(bytes);
          let childInst = null;
          const childMem = () => new Uint8Array(childInst.exports.memory.buffer);
          const childToKernel = (cp, len) => {
            if (!len) return 0;
            const k = getKernel().exports.kernel_heap_alloc(len);
            if (!k) return 0;
            kmem().set(childMem().subarray(cp, cp + len), k);
            return k;
          };
          const kernelToChild = (kp, cp, len) => {
            if (!len) return;
            childMem().set(kmem().subarray(kp, kp + len), cp);
          };
          const env = {
            channel_read: (h, p, l) => {
              const k = getKernel().exports.kernel_heap_alloc(l);
              if (!k) return -1;
              const n = getKernel().exports.channel_read(h, k, l);
              if (n > 0) kernelToChild(k, p, n);
              getKernel().exports.kernel_heap_free(k);
              return n;
            },
            channel_write: (h, p, l) => {
              const k = childToKernel(p, l);
              const n = getKernel().exports.channel_write(h, k, l);
              if (k) getKernel().exports.kernel_heap_free(k);
              return n;
            },
            channel_poll: (h, e) => getKernel().exports.channel_poll(h, e),
            channel_peek: (h, p, l) => {
              const k = getKernel().exports.kernel_heap_alloc(l);
              if (!k) return -1;
              const n = getKernel().exports.channel_peek(h, k, l);
              if (n > 0) kernelToChild(k, p, n);
              getKernel().exports.kernel_heap_free(k);
              return n;
            },
            provider_open: (c, op, p, l) => {
              const k = childToKernel(p, l);
              const r = getKernel().exports.provider_open(c, op, k, l);
              if (k) getKernel().exports.kernel_heap_free(k);
              return r;
            },
            provider_call: (h, op, p, l) => {
              const k = childToKernel(p, l);
              const r = getKernel().exports.provider_call(h, op, k, l);
              if (k && l > 0) kernelToChild(k, p, l);
              if (k) getKernel().exports.kernel_heap_free(k);
              return r;
            },
            provider_query: (h, key, p, l) => {
              if (l === 0 || p === 0) return getKernel().exports.provider_query(h, key, 0, 0);
              const k = getKernel().exports.kernel_heap_alloc(l);
              if (!k) return -1;
              const r = getKernel().exports.provider_query(h, key, k, l);
              if (r >= 0) kernelToChild(k, p, l);
              getKernel().exports.kernel_heap_free(k);
              return r;
            },
            provider_close: (h) => getKernel().exports.provider_close(h),
          };
          childInst = new WebAssembly.Instance(mod, { env });
          const handle = nextHandle++;
          moduleInstances.set(handle, childInst);
          return handle;
        } catch (_err) { return -1; }
      },
      host_invoke_module: (handle, namePtr, nameLen, argsPtr, argsLen, retPtr, retCap) => {
        const inst = moduleInstances.get(handle);
        if (!inst) return -2;
        const name = kstr(namePtr, nameLen);
        const fn = inst.exports[name];
        if (typeof fn !== 'function') return -3;
        const args = [];
        const argCount = (argsLen / 4) | 0;
        if (argCount > 0) {
          const view = new DataView(getKernel().exports.memory.buffer, argsPtr, argsLen);
          for (let i = 0; i < argCount; i++) args.push(view.getInt32(i * 4, true));
        }
        let result;
        try { result = fn.apply(null, args); }
        catch (_err) { return -4; }
        if (typeof result === 'number' && retCap >= 4) {
          new DataView(getKernel().exports.memory.buffer, retPtr, 4).setInt32(0, result | 0, true);
          return 4;
        }
        return 0;
      },
      host_module_export_exists: (handle, namePtr, nameLen) => {
        const inst = moduleInstances.get(handle);
        if (!inst) return -2;
        const name = kstr(namePtr, nameLen);
        return typeof inst.exports[name] === 'function' ? 1 : 0;
      },
      host_destroy_module: (handle) => moduleInstances.delete(handle) ? 0 : -1,
    };

    return {
      env: Object.assign(
        {},
        universal,
        fetchShim,
        inputShim,
        keyboardShim,
        pointerShim,
        buttonShim,
        gamepadShim,
        wsShim,
        audioShim,
        canvasShim,
        terminalShim,
        imageShim,
        moduleShim
      ),
    };
  }

  // ── Asset bank parser ─────────────────────────────────────────────
  //
  // Walks a `fluxor.assets` custom-section payload (as returned by
  // `WebAssembly.Module.customSections(module, "fluxor.assets")[0]`)
  // and returns a Map<name, Uint8Array> the runtime shell hands to
  // `buildHostImports({ assetBank })`.
  //
  // Section body layout (must match `tools/src/asset_bank.rs`):
  //   [4]  magic "FXAB"
  //   [4]  u32 LE format_version
  //   [4]  u32 LE asset_count
  //   per entry:
  //     [4]              u32 LE name_len
  //     [4]              u32 LE byte_len
  //     [name_len bytes] UTF-8 name
  //     [byte_len bytes] asset bytes
  //
  // Throws on malformed input rather than returning a partial map —
  // a half-decoded bank is worse than a clean "no bank" state.
  function parseAssetBank(sectionBuffer) {
    if (!sectionBuffer) return new Map();
    const bytes = sectionBuffer instanceof ArrayBuffer
      ? new Uint8Array(sectionBuffer)
      : new Uint8Array(sectionBuffer.buffer, sectionBuffer.byteOffset, sectionBuffer.byteLength);
    if (bytes.byteLength < 12) {
      throw new Error(`asset bank section too short (${bytes.byteLength} B)`);
    }
    const magic = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]);
    if (magic !== 'FXAB') {
      throw new Error(`asset bank magic mismatch: got "${magic}", want "FXAB"`);
    }
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const version = dv.getUint32(4, true);
    if (version !== 1) {
      throw new Error(`asset bank version ${version} unsupported (tool wants 1)`);
    }
    const count = dv.getUint32(8, true);
    let off = 12;
    const dec = new TextDecoder();
    const map = new Map();
    for (let i = 0; i < count; i++) {
      if (off + 8 > bytes.byteLength) {
        throw new Error(`asset bank truncated at entry ${i} header`);
      }
      const nameLen = dv.getUint32(off, true);     off += 4;
      const byteLen = dv.getUint32(off, true);     off += 4;
      if (off + nameLen + byteLen > bytes.byteLength) {
        throw new Error(`asset bank truncated at entry ${i} body (need ${nameLen}+${byteLen})`);
      }
      const name = dec.decode(bytes.subarray(off, off + nameLen));
      off += nameLen;
      // Slice to a fresh, contiguous Uint8Array so the underlying
      // bundle buffer can be released after instantiation without
      // freeing the asset payload that asset:// URLs serve from.
      const data = bytes.slice(off, off + byteLen);
      off += byteLen;
      if (map.has(name)) {
        throw new Error(`asset bank duplicate name "${name}"`);
      }
      map.set(name, data);
    }
    return map;
  }

  window.fluxor = window.fluxor || {};
  window.fluxor.buildHostImports = buildHostImports;
  window.fluxor.parseAssetBank = parseAssetBank;
})();
