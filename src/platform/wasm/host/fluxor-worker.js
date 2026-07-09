// Fluxor emulation Worker — runs the wasm kernel (kernel_init + the kernel_step
// pump) OFF the main thread, so a CPU-bound core (e.g. a console emulator at >95%
// CPU) no longer monopolises the page: audio scheduling, GPU promise completion,
// presentation and input all stay live on the main thread.
//
// The kernel's host imports run synchronously inside kernel_step, so they run
// HERE, in the Worker. That works because:
//   - WebGPU (compute + present) runs in a Worker, drawing into an
//     OffscreenCanvas transferred from the page (host_shims `offscreenSurface`).
//   - fetch / WebSocket / crypto / performance / OPFS all exist in Workers.
//   - audio has no AudioContext in a Worker, so host_audio_play / host_audio_lead_us
//     are overridden to postMessage PCM to the page (which schedules it) and to read
//     back a cached audio-clock lead.
//   - input + logs cross via postMessage.
//
// host_shims.js is reused unchanged except for the `offscreenSurface` opt — the few
// `window.`/`document.` references it makes are satisfied by the shims set up below
// (self.window = self + a minimal document stub) before it is imported.

// --- environment shims so the (DOM-assuming) host_shims.js loads in a Worker ---
self.window = self; // window.fluxor / window.__fluxor_*_queue / window.location -> self.*
const _noop = () => {};
// Minimal document: host_shims only creates throwaway <canvas> elements (the real
// present surface is the transferred OffscreenCanvas via offscreenSurface) and
// (un)registers audio-unlock listeners (a no-op here; the page unlocks audio).
self.document = {
  createElement: (tag) => {
    if (tag === 'canvas') { const c = new OffscreenCanvas(1, 1); try { c.style = {}; } catch (e) {} return c; }
    return { style: {}, appendChild: _noop, setAttribute: _noop };
  },
  querySelector: () => null,
  addEventListener: _noop,
  removeEventListener: _noop,
  body: { appendChild: _noop },
  head: { appendChild: _noop },
};

let kernel = null;
let inputQueue = [];
let cachedAudioLeadUs = 0n;   // updated from the page's audio scheduler
let cachedAudioCursor = -1;   // audio playback frame cursor (the A/V present master clock)
let cachedAudioReady = false; // page AudioContext running + worklet connected
let booted = false;

function mem() { return new Uint8Array(kernel.exports.memory.buffer); }

function workerErrorText(e) {
  if (!e) return '(no error object)';
  const name = e.name ? e.name + ': ' : '';
  const msg = e.message || String(e);
  return name + msg + (e.stack ? '\n' + e.stack : '');
}

// Errors from async WebGPU work and promise continuations do not pass through the
// synchronous kernel_step try/catch. Forward both Worker-global failure channels to
// the page before the Worker is terminated or the rejection disappears in devtools.
self.addEventListener('error', (e) => {
  postMessage({ type: 'panic', msg: '[worker] uncaught error: ' + workerErrorText(e.error || e) +
    (e.filename ? ' at ' + e.filename + ':' + e.lineno + ':' + e.colno : '') });
});
self.addEventListener('unhandledrejection', (e) => {
  postMessage({ type: 'panic', msg: '[worker] unhandled rejection: ' + workerErrorText(e.reason) });
});

self.onmessage = async (e) => {
  const m = e.data;
  if (m.type === 'input') {
    // Repopulate the queues host_shims' host_*_pop functions drain. Keyboard uses
    // the injected inputQueue; pointer/button use the self.__fluxor_*_queue globals
    // host_shims lazily creates (window === self here).
    if (m.keyboard && m.keyboard.length) inputQueue.push(...m.keyboard);
    if (m.pointer && m.pointer.length) (self.__fluxor_pointer_queue || (self.__fluxor_pointer_queue = [])).push(...m.pointer);
    if (m.button && m.button.length) (self.__fluxor_button_queue || (self.__fluxor_button_queue = [])).push(...m.button);
    return;
  }
  if (m.type === 'audio-lead') {
    cachedAudioLeadUs = BigInt(Math.max(0, Math.floor(m.leadUs || 0)));
    if (m.cursor != null) cachedAudioCursor = m.cursor;
    cachedAudioReady = !!m.ready;
    return;
  }
  if (m.type !== 'boot' || booted) return;
  booted = true;
  try {
    importScripts(m.shimsUrl);

    // Namespace-hydration gate (set synchronously by the onNamespaceReady
    // callback inside buildHostImports; awaited before the step loop).
    let namespaceReadyP = Promise.resolve();
    const imports = self.fluxor.buildHostImports({
      getKernel: () => kernel,
      onLog: (level, msg) => postMessage({ type: 'log', level, msg }),
      onPanic: (msg) => postMessage({ type: 'panic', msg }),
      onCanvasFrame: (w, h) => postMessage({ type: 'canvas-frame', w, h }),
      offscreenSurface: m.canvas,     // OffscreenCanvas for the GPU present
      fetchUrlOverride: (req) => m.assetUrl || req,
      assetBank: m.assetBank || new Map(),
      manifestUrl: m.manifestUrl,
      // Gate the step loop on namespace hydration (manifest + OPFS): the
      // `storage.namespace` LIST/STAT answer synchronously and treat an
      // empty LIST as end-of-listing, so a scanner that steps before the
      // manifest fetch lands reads an empty tree as complete and misses all
      // shipped content permanently. The main-thread runtime.html awaits
      // this; the Worker must too (it owns kernel_step) — else the index
      // races the first LIST. Captured here, awaited before `runPump()`.
      onNamespaceReady: (p) => { namespaceReadyP = p; },
      inputQueue,
    });

    // Audio has no AudioContext in a Worker: forward PCM to the page (which owns
    // the AudioContext) and read back the cached audio-clock lead for pacing.
    imports.env.host_audio_play = (ptr, len, sampleRate, channels) => {
      const src = new Uint8Array(kernel.exports.memory.buffer, ptr, len);
      const copy = new Uint8Array(len); copy.set(src); // detach for transfer
      postMessage({ type: 'audio', pcm: copy.buffer, sampleRate, channels }, [copy.buffer]);
      // The main-thread ring report comes back asynchronously. Consume local
      // transport credit now so repeated audio_step calls in one Worker burst stop
      // at the 120 ms lead target rather than flooding the MessagePort/ring.
      const frameBytes = Math.max(1, (channels | 0) * 2);
      const frames = Math.floor(len / frameBytes);
      if (sampleRate > 0 && frames > 0) {
        cachedAudioLeadUs += BigInt(Math.round(frames * 1000000 / sampleRate));
      }
    };
    imports.env.host_audio_ready = () => cachedAudioReady ? 1 : 0;
    imports.env.host_audio_lead_us = () => cachedAudioLeadUs;
    // Audio-clock StreamTime authority (provider_query(-1, STREAM_TIME)) — the same
    // 24-byte layout as the in-process host_stream_time, from the pushed cursor, so
    // the producer + presenter read ONE clock in worker mode too.
    imports.env.host_stream_time = (ptr) => {
      const started = cachedAudioCursor >= 0;
      const dv = new DataView(kernel.exports.memory.buffer, ptr, 24);
      dv.setBigUint64(0, started ? BigInt(cachedAudioCursor) : 0n, true);
      // queued = downstream audio backlog in 60Hz frames (see the in-process
      // writeStreamTime) — from the page-pushed lead, so the presenter's
      // newest-minus-queued pairing works identically in worker mode.
      const lead = Number(cachedAudioLeadUs);
      dv.setUint32(8, started && lead > 0 ? Math.round(lead / 16667) : 0, true);
      dv.setUint32(12, (60 << 16) >>> 0, true);
      dv.setBigUint64(16, started ? 1n : 0n, true);
      return started ? 1 : 0;
    };

    kernel = await WebAssembly.instantiate(m.module, imports);
    const initRet = kernel.exports.kernel_init();
    postMessage({ type: 'log', level: 2, msg: `[worker] kernel_init() -> ${initRet}` });
    // Wait for the namespace index (manifest + OPFS) to hydrate before the
    // first kernel_step, so a boot scanner's LIST sees the full shipped tree
    // instead of racing the fetch and reading it as empty.
    await namespaceReadyP;
    postMessage({ type: 'log', level: 2, msg: '[worker] namespace hydrated; starting pump' });
    runPump();
  } catch (err) {
    postMessage({ type: 'panic', msg: '[worker] boot failed: ' + (err && err.message || err) });
  }
};

// Time-budgeted cooperative pump (same shape as the main-thread fallback). Running
// in the Worker, a long burst no longer blocks the page; the yield between bursts
// lets the Worker process incoming input/audio-lead messages and flush postMessages.
function runPump() {
  const STEP_BUDGET_MS = 12; // a touch larger than main-thread: the Worker is dedicated
  const STEP_MAX = 256;
  const kStep = kernel.exports.kernel_step;
  let diagTicks = 0, diagBudgetBound = 0, diagBursts = 0, diagLast = performance.now();
  const ch = new MessageChannel();
  function pump() {
    const start = performance.now();
    let i = 0;
    for (; i < STEP_MAX; i++) {
      try { kStep(); diagTicks++; }
      catch (err) { postMessage({ type: 'panic', msg: '[worker] kernel_step trapped: ' + (err && err.message || err) }); return; }
      if (performance.now() - start >= STEP_BUDGET_MS) { i++; break; }
    }
    diagBursts++;
    if (i >= STEP_MAX || performance.now() - start >= STEP_BUDGET_MS) diagBudgetBound++;
    // (Present is driven by the app graph's modules — e.g. a PRESENT command
    // on the generic compute driver — paced on the audio clock fed here from
    // cachedAudioCursor; no present call needed in the pump.)
    const now = performance.now();
    if (now - diagLast >= 2000) {
      const dt = (now - diagLast) / 1000;
      postMessage({ type: 'perf', ticksPerSec: Math.round(diagTicks / dt), bursts: diagBursts, budgetBound: diagBudgetBound, budgetMs: STEP_BUDGET_MS, stepMax: STEP_MAX });
      diagTicks = 0; diagBursts = 0; diagBudgetBound = 0; diagLast = now;
    }
    ch.port2.postMessage(0);
  }
  ch.port1.onmessage = pump;
  ch.port2.postMessage(0);
}
