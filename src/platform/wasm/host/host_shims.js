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
  // ── AudioWorklet ring processor source ────────────────────────────────
  // Runs on the audio render thread. Owns a circular buffer of stereo PCM and
  // is CLOCK-LOCKED: process() emits exactly 128 frames/quantum at the context
  // rate. On underflow it emits silence but does NOT advance its read cursor —
  // so the next real samples play at the LIVE clock, never after a silence
  // backlog. That is what makes it drift-free: falling behind costs latency
  // (bounded by the ring depth), never accumulated delay. On overflow it drops
  // the OLDEST frames so latency stays bounded. PCM is fed in via the port; the
  // ring fill + under/overflow counters are reported back the same way.
  const PCM_RING_PROCESSOR_SRC = `
class PcmRing extends AudioWorkletProcessor {
  constructor() {
    super();
    this.CAP = 0;            // ring capacity in frames (sized on first data)
    this.ring = null;        // Float32Array, interleaved stereo (CAP*2)
    this.writeFrame = 0;     // total frames written (monotonic)
    this.readFrame = 0;      // fractional read cursor in source frames
    this.inRate = sampleRate;// source rate of fed PCM (== ctx rate in practice)
    this.under = 0;          // cumulative underflow frames (silence emitted)
    this.over = 0;           // cumulative overflow frames (dropped oldest)
    this.quantum = 0;
    this.REPORT_EVERY = 8;   // ~21ms at 128 frames/quantum/48k (tight pacing feedback)
    this.port.onmessage = (e) => this._push(e.data);
  }
  _ensure(rate) {
    if (this.ring) return;
    this.inRate = rate || sampleRate;
    // ~320ms capacity. LEAD_TARGET holds production near 120ms, leaving ~200ms
    // headroom for Worker/main-thread feedback jitter without adding latency.
    this.CAP = Math.max(2048, Math.ceil(this.inRate * 0.32));
    this.ring = new Float32Array(this.CAP * 2);
  }
  _push(m) {
    if (!m || !m.pcm) return;
    this._ensure(m.rate);
    const pcm = m.pcm;            // Float32 interleaved stereo
    const n = pcm.length >> 1;    // frames
    if (n <= 0) return;
    const CAP = this.CAP, ring = this.ring;
    // Bound latency: if this write would exceed capacity, drop the oldest.
    const held = this.writeFrame - Math.floor(this.readFrame);
    if (held + n > CAP) {
      const drop = held + n - CAP;
      this.readFrame += drop;
      this.over += drop;
    }
    const w = this.writeFrame;
    for (let f = 0; f < n; f++) {
      const idx = (((w + f) % CAP) + CAP) % CAP * 2;
      ring[idx]     = pcm[f * 2];
      ring[idx + 1] = pcm[f * 2 + 1];
    }
    this.writeFrame = w + n;
  }
  process(_inputs, outputs) {
    const out = outputs[0];
    const L = out[0], R = out[1] || null;
    const N = L.length, ring = this.ring, CAP = this.CAP;
    // Playback is locked to the hardware clock. Arrival rate is not a valid speed
    // signal because wasm_browser_audio deliberately stops arrivals at LEAD_TARGET;
    // feeding that throttled rate back into playback creates a self-sustaining
    // slowdown. If production genuinely falls behind, emit silence on underflow and
    // leave readFrame frozen so content and the video cursor remain synchronized.
    // Never use playback rate as an underflow-control mechanism. Doing so changes
    // pitch and duration, which is especially destructive for music. A producer
    // that misses real time must cause a measurable silence gap, not corrupted PCM.
    const step = ring ? (this.inRate / sampleRate) : 1;
    for (let i = 0; i < N; i++) {
      // avail < 1 -> underflow: emit silence, FREEZE the read cursor so the
      // next real sample plays at the current clock position (no backlog).
      if (!ring || (this.writeFrame - this.readFrame) < 1) {
        L[i] = 0; if (R) R[i] = 0; this.under++;
        continue;
      }
      const p = this.readFrame, i0 = Math.floor(p), frac = p - i0;
      const a = ((i0 % CAP) + CAP) % CAP * 2;
      const hasNext = (this.writeFrame - i0) > 1;
      const b = hasNext ? ((((i0 + 1) % CAP) + CAP) % CAP * 2) : a;
      L[i] = ring[a] + (ring[b] - ring[a]) * frac;
      if (R) R[i] = ring[a + 1] + (ring[b + 1] - ring[a + 1]) * frac;
      this.readFrame = p + step;
    }
    if (++this.quantum >= this.REPORT_EVERY) {
      this.quantum = 0;
      const fill = ring ? Math.max(0, this.writeFrame - this.readFrame) : 0;
      // consumed = readFrame = total CONTENT frames played; the main thread derives
      // the present cursor as consumed / (inRate/60) = emulated frames played.
      this.port.postMessage({ fill: fill, inRate: this.inRate, under: this.under,
        over: this.over, consumed: this.readFrame, playRate: 1 });
    }
    return true;
  }
}
registerProcessor('pcm-ring', PcmRing);
`;

  // ── ScriptProcessorNode fallback ring (NON-SECURE contexts) ──────────────
  // AudioWorklet is only exposed in a SECURE context (https:// or
  // http://localhost). Served over a plain-http LAN IP (e.g. a kiosk panel at
  // http://192.168.x.x) `ctx.audioWorklet` is undefined, so playback would be
  // silent. This is a byte-for-byte port of the PcmRing above (same clock-lock
  // + underflow-freeze, no resampling drift) that runs in the deprecated-but-
  // universally-available ScriptProcessorNode.onaudioprocess on the main
  // thread. `ctxRate` is the AudioContext sample rate (the render rate);
  // `inRate` is the fed-PCM rate, exactly as `sampleRate` vs `this.inRate` in
  // the worklet.
  class PcmRingJS {
    constructor(ctxRate) {
      this.ctxRate = ctxRate || 44100;
      this.CAP = 0; this.ring = null;
      this.writeFrame = 0; this.readFrame = 0;
      this.inRate = this.ctxRate;
      this.under = 0; this.over = 0;
    }
    _ensure(rate) {
      if (this.ring) return;
      this.inRate = rate || this.ctxRate;
      this.CAP = Math.max(2048, Math.ceil(this.inRate * 0.32));
      this.ring = new Float32Array(this.CAP * 2);
    }
    _push(m) {
      if (!m || !m.pcm) return;
      this._ensure(m.rate);
      const pcm = m.pcm, n = pcm.length >> 1;
      if (n <= 0) return;
      const CAP = this.CAP, ring = this.ring;
      const held = this.writeFrame - Math.floor(this.readFrame);
      if (held + n > CAP) { const drop = held + n - CAP; this.readFrame += drop; this.over += drop; }
      const w = this.writeFrame;
      for (let f = 0; f < n; f++) {
        const idx = (((w + f) % CAP) + CAP) % CAP * 2;
        ring[idx] = pcm[f * 2]; ring[idx + 1] = pcm[f * 2 + 1];
      }
      this.writeFrame = w + n;
    }
    // Fill output channels for one onaudioprocess block; identical semantics to
    // the worklet process() (silence + frozen read cursor on underflow).
    render(L, R, N) {
      const ring = this.ring, CAP = this.CAP;
      const step = ring ? (this.inRate / this.ctxRate) : 1;
      for (let i = 0; i < N; i++) {
        if (!ring || (this.writeFrame - this.readFrame) < 1) {
          L[i] = 0; if (R) R[i] = 0; this.under++; continue;
        }
        const p = this.readFrame, i0 = Math.floor(p), frac = p - i0;
        const a = ((i0 % CAP) + CAP) % CAP * 2;
        const hasNext = (this.writeFrame - i0) > 1;
        const b = hasNext ? ((((i0 + 1) % CAP) + CAP) % CAP * 2) : a;
        L[i] = ring[a] + (ring[b] - ring[a]) * frac;
        if (R) R[i] = ring[a + 1] + (ring[b + 1] - ring[a + 1]) * frac;
        this.readFrame = p + step;
      }
    }
    // Same shape as the worklet's port report so the scheduler's stats path is
    // identical for both backends.
    report() {
      const fill = this.ring ? Math.max(0, this.writeFrame - this.readFrame) : 0;
      return { fill, inRate: this.inRate, under: this.under, over: this.over,
               consumed: this.readFrame, playRate: 1 };
    }
  }

  // Clock-locked AudioWorklet ring scheduler (the wasm_browser_audio sink).
  // Locking playback to the audio clock keeps the producer in step; a
  // per-block scheduler could only insert silence to catch up, compounding into
  // seconds of drift.
  // The ring is shared by BOTH the in-process path (buildHostImports below) and
  // the Worker bridge (runtime.html runs the kernel off-thread and forwards PCM
  // to the page, which owns the AudioContext — a Worker has none). ALWAYS runs
  // on the main thread. `onLog(level, msg)` surfaces once-per-second stats. Do
  // NOT reintroduce a block scheduler or a deep buffer — the ring is shallow
  // (~40ms) and clock-locked, so it's low-latency AND drift-free.
  function createAudioScheduler(onLog) {
    onLog = onLog || (() => {});
    let audioCtx = null;
    let workletNode = null;       // the 'pcm-ring' AudioWorkletNode
    let workletInitStarted = false;
    let workletBlobUrl = null;
    // Race cushion only. The wasm sink now leaves canonical pre-gesture PCM in
    // Fluxor channels until ready()==true, so this must never become a second,
    // unbounded audio timeline in JavaScript.
    const pendingPcm = [];
    let pendingPcmFrames = 0;
    const PENDING_PCM_MS = 120;
    let unlockListenersInstalled = false;
    let waitingLogged = false;
    // Last ring report from the processor (frames + counters). Cached so leadUs()
    // and the stats line are cheap. Stays 0 until process() runs (ctx running);
    // host_audio_ready now keeps pre-gesture PCM backpressured upstream.
    let ringFillFrames = 0, ringInRate = 0;
    // Wall-clock stamp of the last ring report. leadUs() extrapolates
    // consumption since this stamp: reports arrive only every
    // REPORT_EVERY quanta (~21 ms) AND queue behind busy main-thread
    // work (a kernel step burst), so the raw cached fill chronically
    // OVERESTIMATES the ring. A sink pacing on the stale estimate
    // stops refilling while the real ring drains — measured as
    // deterministic ~20 ms silence gaps in a held note.
    let ringReportT = -1;
    let underCount = 0, overCount = 0, consumedFrames = 0, ringPlayRate = 1;
    let realtimeBaseFrames = 0, realtimeBaseT = -1;
    // Phase-0 audio perf: lowest ring fill (ms) seen since the last [audio] tick
    // (the underflow-risk dip) + under/over at the last tick (for per-window deltas).
    let audioLeadMinMs = Infinity, audioPrevUnder = 0, audioPrevOver = 0;
    function ensureAudio(sampleRate) {
      if (!audioCtx) {
        audioCtx = new (window.AudioContext || window.webkitAudioContext)({ sampleRate });
        // Safari/WebKit can drop the context to 'interrupted' (its audio session was
        // taken) or 'suspended' AFTER it was running. While interrupted the worklet's
        // process() does NOT fire — no audio drains, the frame cursor freezes (so
        // video races ahead), and the on/off cycling sounds gurgly. Auto-resume on
        // every state change so it recovers without needing a fresh user gesture.
        audioCtx.onstatechange = () => {
          if (!audioCtx || audioCtx.state === 'closed') return;
          if (audioCtx.state === 'running') {
            waitingLogged = false;
            removeUnlockListeners();
            flushPending();
          } else {
            // WebKit may require a new trusted gesture after an interruption.
            installUnlockListeners();
            audioCtx.resume().catch(() => {});
          }
        };
      }
      return audioCtx;
    }
    // Fold one ring report (from the worklet port OR the ScriptProcessor
    // fallback) into the scheduler's cached stats. Shared so both audio
    // backends drive the identical stats/backpressure/cursor path.
    function applyRingReport(s) {
      ringFillFrames = s.fill; ringInRate = s.inRate || 0;
      ringReportT = performance.now();
      underCount = s.under; overCount = s.over; consumedFrames = s.consumed;
      if (s.playRate) ringPlayRate = s.playRate;
      if (realtimeBaseT < 0) { realtimeBaseT = performance.now(); realtimeBaseFrames = s.consumed; }
      // Phase-0 audio perf: the backend reports far more often than the 1 s
      // [audio] tick, so sample the LOW tail here — a near-0 dip between ticks
      // is a hair from underflow that the instantaneous snapshot would miss.
      if (s.inRate) { const lm = s.fill / s.inRate * 1000; if (lm < audioLeadMinMs) audioLeadMinMs = lm; }
    }
    // ScriptProcessorNode fallback for a NON-SECURE context (no AudioWorklet).
    // Presents the same `{ port: { postMessage } }` + `connect` surface the
    // rest of the scheduler expects from an AudioWorkletNode, so `schedule`,
    // `flushPending`, `ready` and the stats line are all backend-agnostic. The
    // ring lives on the main thread and is pulled by onaudioprocess against the
    // context clock — the same drift-free, clock-locked contract as the worklet.
    function ensureScriptProcessor(ctx) {
      const BUF = 4096; // ~85ms/block at 48k; large enough to stay ahead of main-thread jitter
      let sp;
      try { sp = ctx.createScriptProcessor(BUF, 0, 2); }
      catch (e) { sp = ctx.createScriptProcessor(BUF, 1, 2); } // some UAs reject 0 inputs
      const ring = new PcmRingJS(ctx.sampleRate | 0);
      sp.onaudioprocess = (e) => {
        const out = e.outputBuffer;
        const L = out.getChannelData(0);
        const R = out.numberOfChannels > 1 ? out.getChannelData(1) : null;
        ring.render(L, R, L.length);
        applyRingReport(ring.report());
      };
      sp.connect(ctx.destination);
      // Node-like adapter: the scheduler only ever calls `.port.postMessage(msg)`
      // and `.connect()`; keep a ref to sp/ring so they're not GC'd.
      workletNode = { port: { postMessage: (msg) => ring._push(msg) },
                      connect: () => {}, _sp: sp, _ring: ring };
      onLog(2, '[audio] ScriptProcessor fallback ready (no AudioWorklet — non-secure context; ctx=' + ctx.state + ')');
      ctx.resume().catch(() => {});
      flushPending();
    }
    // Kick off the (async) worklet module load + node creation exactly once.
    // addModule works on a suspended context, so the node is ready by the time
    // the gesture resumes playback. PCM that arrives meanwhile queues, then flushes.
    function ensureWorklet(ctx) {
      if (workletInitStarted) return;
      workletInitStarted = true;
      // Non-secure context (plain-http LAN IP): no AudioWorklet → fall back to a
      // ScriptProcessorNode so audio still plays instead of being disabled.
      if (!ctx.audioWorklet) { ensureScriptProcessor(ctx); return; }
      workletBlobUrl = URL.createObjectURL(new Blob([PCM_RING_PROCESSOR_SRC], { type: 'application/javascript' }));
      ctx.audioWorklet.addModule(workletBlobUrl).then(() => {
        const node = new AudioWorkletNode(ctx, 'pcm-ring', { numberOfInputs: 0, numberOfOutputs: 1, outputChannelCount: [2] });
        node.addEventListener('processorerror', (e) => {
          onLog(3, '[audio] AudioWorklet processorerror: ' + ((e && e.message) || 'render processor failed'));
        });
        node.port.onmessage = (e) => applyRingReport(e.data);
        node.connect(ctx.destination);
        workletNode = node;
        onLog(2, '[audio] fixed-rate worklet ready (ctx=' + ctx.state + ', rate=1.00) — resuming');
        ctx.resume().catch(() => {}); // kick it in case it came up suspended/interrupted
        flushPending();
      }).catch((err) => { onLog(3, '[audio] worklet init failed: ' + (err && err.message || err)); });
    }
    const UNLOCK_EVENTS = ['pointerdown', 'pointerup', 'click', 'keydown', 'touchstart', 'touchend'];
    const hasDoc = (typeof document !== 'undefined');
    function installUnlockListeners() {
      if (!hasDoc || unlockListenersInstalled) return;
      for (const e of UNLOCK_EVENTS) document.addEventListener(e, unlockAudioOnGesture, true);
      unlockListenersInstalled = true;
    }
    function removeUnlockListeners() {
      if (!hasDoc || !unlockListenersInstalled) return;
      for (const e of UNLOCK_EVENTS) document.removeEventListener(e, unlockAudioOnGesture, true);
      unlockListenersInstalled = false;
    }
    function enqueuePending(msg) {
      const frames = msg.pcm.length >> 1;
      const maxFrames = Math.max(1, Math.ceil((msg.rate || 44100) * PENDING_PCM_MS / 1000));
      pendingPcm.push(msg);
      pendingPcmFrames += frames;
      while (pendingPcmFrames > maxFrames && pendingPcm.length > 1) {
        const old = pendingPcm.shift();
        pendingPcmFrames -= old.pcm.length >> 1;
      }
    }
    function flushPending() {
      if (!workletNode || !audioCtx || audioCtx.state !== 'running') return;
      for (const msg of pendingPcm) workletNode.port.postMessage(msg, [msg.pcm.buffer]);
      ringFillFrames += pendingPcmFrames;
      pendingPcm.length = 0;
      pendingPcmFrames = 0;
    }
    function unlockAudioOnGesture() {
      const ctx = ensureAudio(44100);
      ensureWorklet(ctx);
      if (ctx.state === 'running') { removeUnlockListeners(); flushPending(); return; }
      // Invoke resume synchronously in the trusted event task. Only completion is
      // asynchronous; Safari's autoplay policy depends on that distinction.
      ctx.resume().then(() => {
        if (ctx.state === 'running') { removeUnlockListeners(); flushPending(); }
      }).catch(() => {});
    }
    installUnlockListeners();
    // Eager bring-up: create the context + worklet NOW and try to resume. With
    // autoplay allowed (desktop with sound permission, kiosk, headless) the resume
    // succeeds without any gesture; where it's blocked the context just stays
    // suspended until the unlock listeners fire. This must NOT be lazy:
    // host_audio_ready() backpressures PCM upstream until ready()==true, so a
    // lazy "create the context on first host_audio_play" never fires. Without
    // this eager kick, ready() could never become true and the producer would
    // hold at the boot logo forever.
    if (typeof window !== 'undefined' && (window.AudioContext || window.webkitAudioContext)) {
      try { const ctx = ensureAudio(44100); ensureWorklet(ctx); ctx.resume().catch(() => {}); }
      catch (e) { onLog(3, '[audio] eager init failed: ' + ((e && e.message) || e)); }
    }
    let audioPlayCalls = 0, audioPlayBytesAccepted = 0, audioPlayLastSurfaced = 0, audioPeakAbs = 0;
    function surfaceAudioStats() {
      const now = performance.now();
      if ((now - audioPlayLastSurfaced) < 1000) return;
      audioPlayLastSurfaced = now;
      const ctxState = audioCtx ? audioCtx.state : 'no-ctx';
      const ctxRate = audioCtx ? (audioCtx.sampleRate | 0) : 0;
      const rate = ringInRate || ctxRate || 44100;
      const running = audioCtx && audioCtx.state === 'running';
      const ringMs = running ? (ringFillFrames / rate * 1000) : 0;
      // realtime = real frames consumed / (rate x wall). ~1.0 = producer keeps up.
      let realtime = 0;
      if (realtimeBaseT >= 0) {
        const wall = (now - realtimeBaseT) / 1000;
        if (wall > 0.05) realtime = (consumedFrames - realtimeBaseFrames) / (rate * wall);
      }
      // String concat (not `${}` template literals): host_shims.js is served as a
      // file whose `${` are env-escaped to `$${` and never collapsed, so template
      // interpolation here would print a stray `$` in this user-read diagnostic.
      // Per-window (this ~1 s tick) underflow/overflow deltas + the worst ring dip:
      // the actionable "new events since last tick" the cumulative counters hide.
      const dUnder = underCount - audioPrevUnder, dOver = overCount - audioPrevOver;
      audioPrevUnder = underCount; audioPrevOver = overCount;
      const leadMin = (audioLeadMinMs === Infinity) ? ringMs : audioLeadMinMs;
      audioLeadMinMs = Infinity;
      onLog(2,
        // Keep the historical field name for the existing realtime probes. It is
        // bytes accepted by this scheduler, not proof of hardware playback; cursor
        // and ctx carry that distinction.
        '[audio] calls=' + audioPlayCalls + ' bytes_played=' + audioPlayBytesAccepted +
        ' ring=' + ringMs.toFixed(0) + 'ms dip=' + leadMin.toFixed(0) + 'ms' +
        ' under=' + underCount + '(+' + dUnder + ') over=' + overCount + '(+' + dOver + ')' +
        ' realtime=' + realtime.toFixed(2) + ' playrate=' + ringPlayRate.toFixed(2) +
        ' cursor=' + Math.floor(consumedFrames / (rate / 60)) +
        ' peak=' + audioPeakAbs + ' ctx=' + ctxState + ' hw_rate=' + ctxRate);
      audioPeakAbs = 0;
    }
    return {
      // Schedule a block of interleaved Int16 PCM. `bytes` = the source byte count
      // for the stats (the in-process path passes the wasm byte length; the Worker
      // bridge can omit it). Converts to stereo-interleaved Float32 and hands it to
      // the ring processor — no AudioBufferSource, no running schedTime.
      schedule(i16, sampleRate, channels, bytes) {
        audioPlayCalls++;
        const ctx = ensureAudio(sampleRate);
        ensureWorklet(ctx);
        // A suspended context never resumes itself; the gesture-unlock handles it,
        // but resume() here is harmless (no-op when not allowed) and recovers if a
        // gesture already happened before the first PCM arrived.
        if (ctx.state !== 'running' && ctx.state !== 'closed') ctx.resume().catch(() => {});
        const len = bytes != null ? bytes : i16.byteLength;
        const ch = Math.max(1, channels | 0);
        const rateHz = ctx.sampleRate | 0;
        const prevAudio = window.__fluxor_audio_traits;
        if (!prevAudio || prevAudio.channels !== ch || prevAudio.rateHz !== rateHz) {
          window.__fluxor_audio_traits = { channels: ch, rateHz };
          if (window.__fluxor_surface_traits && window.__fluxor_surface_traits.schedule) window.__fluxor_surface_traits.schedule();
        }
        const frames = Math.floor(i16.length / ch);
        if (!frames) { surfaceAudioStats(); return; }
        // interleaved Int16 (any channel count) -> stereo-interleaved Float32
        const f32 = new Float32Array(frames * 2);
        for (let f = 0; f < frames; f++) {
          const sl = i16[f * ch];
          const sr = ch > 1 ? i16[f * ch + 1] : sl;
          f32[f * 2] = sl / 32768;
          f32[f * 2 + 1] = sr / 32768;
          const al = sl < 0 ? -sl : sl, ar = sr < 0 ? -sr : sr;
          if (al > audioPeakAbs) audioPeakAbs = al;
          if (ar > audioPeakAbs) audioPeakAbs = ar;
        }
        const msg = { pcm: f32, rate: sampleRate };
        if (workletNode && ctx.state === 'running') {
          workletNode.port.postMessage(msg, [f32.buffer]);
          // Port delivery and the worklet's fill report are asynchronous. Account
          // for this write immediately so host_audio_lead_us applies backpressure
          // within the same wasm scheduler burst instead of flooding a second of
          // retained startup PCM before the first report returns.
          ringFillFrames += frames;
        } else enqueuePending(msg);
        audioPlayBytesAccepted += len;
        surfaceAudioStats();
      },
      // The wasm sink uses this to distinguish an empty live ring from a browser
      // renderer that cannot consume anything yet. Returning false preserves PCM
      // upstream instead of silently throwing away the beginning of a stream.
      ready() {
        const ok = !!(audioCtx && audioCtx.state === 'running' && workletNode);
        if (!ok && !waitingLogged) {
          waitingLogged = true;
          onLog(2, '[audio] waiting for a tap to start/resume WebAudio');
        }
        return ok;
      },
      // Audio buffered in the ring (µs) — the kernel sink (wasm_browser_audio)
      // paces production to this so the pipeline locks to the audio clock. 0 until
      // the processor is up + running; ready() disambiguates unavailable from empty.
      leadUs() {
        if (!audioCtx || audioCtx.state !== 'running' || !workletNode) return 0n;
        const rate = ringInRate || (audioCtx.sampleRate | 0) || 44100;
        // Extrapolate consumption since the last worklet report — the
        // worklet drains `rate` content frames per wall second while
        // running. Without this the fill estimate is stale-high and
        // the sink starves the ring (see ringReportT above).
        let fill = ringFillFrames;
        if (ringReportT >= 0) {
          fill -= (performance.now() - ringReportT) / 1000 * rate;
        }
        const us = Math.round(fill / rate * 1_000_000);
        return BigInt(us > 0 ? us : 0);
      },
      // The master clock for the unified A/V present: emulated frames whose audio
      // has been PLAYED = content samples consumed / (rate/60). The video present
      // scheduler shows the frame at this index. Underflow silence does not
      // advance consumedFrames, so video remains aligned to audio content even when
      // the producer cannot sustain the hardware rate. -1 until audio is running.
      frameCursor() {
        if (!audioCtx || audioCtx.state !== 'running' || !workletNode) return -1;
        const rate = ringInRate || (audioCtx.sampleRate | 0) || 44100;
        return Math.floor(consumedFrames / (rate / 60));
      },
    };
  }

  // ── Host-extension registry ──
  // Domain-specific host executors
  // are NOT compiled into this shim: they ship as separately served scripts
  // that call FluxorHostExt.register(name, factory) at load, and the generic
  // capability entries delegate through it. factory(ctx) receives a shim-owned
  // context object (device/backend getters, kview, log) and returns the
  // extension's call surface. Idempotent across page + Worker load orders.
  const FluxorHostExt = globalThis.FluxorHostExt = globalThis.FluxorHostExt || {
    _factories: new Map(),
    register(name, factory) { this._factories.set(name, factory); },
    has(name) { return this._factories.has(name); },
    create(name, ctx) { const f = this._factories.get(name); return f ? f(ctx) : null; },
  };


  function buildHostImports(opts) {
    const o = opts || {};
    const getKernel = o.getKernel || (() => null);
    const onLog = o.onLog || ((_lvl, msg) => console.log('[wasm]', msg));
    const onPanic = o.onPanic || ((msg) => { throw new Error('wasm panic: ' + msg); });
    const onCanvasFrame = o.onCanvasFrame || (() => {});
    const canvasContainer = o.canvasContainer || null;
    // Worker mode: an OffscreenCanvas (transferControlToOffscreen'd from the main
    // thread) to render the GPU present into, since a Worker has no DOM. When
    // set, the present path uses it directly instead of creating a <canvas>.
    const offscreenSurface = o.offscreenSurface || null;
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
    // Write a 24-byte StreamTime { consumed_units u64, queued u32, rate_q16 u32,
    // t0_micros u64 } at `ptr` in kernel memory from the audio-clock `cursor`
    // (emulated-60Hz frames played; -1 until running). Shared by the in-process and
    // worker `host_stream_time` imports so provider_query(-1,STREAM_TIME) answers
    // identically in both modes. rate_q16 = 60<<16 (units are emulated frames);
    // t0_micros nonzero once started (the StreamTime "started" signal).
    function writeStreamTime(buffer, ptr, cursor, leadUs) {
      const started = cursor >= 0;
      const dv = new DataView(buffer, ptr, 24);
      dv.setBigUint64(0, started ? BigInt(cursor) : 0n, true);
      // queued: frames of audio buffered downstream AWAITING playback (the
      // worklet ring fill, in emulated-60Hz frame units). The A/V presenter
      // pairs "video now" with "audio at the speaker now" as newest - queued —
      // the live backlog IS the A/V offset, so this must be real, not 0.
      const lead = Number(leadUs || 0);
      dv.setUint32(8, started && lead > 0 ? Math.round(lead / 16667) : 0, true);
      dv.setUint32(12, (60 << 16) >>> 0, true);
      dv.setBigUint64(16, started ? 1n : 0n, true);
      return started ? 1 : 0;
    }

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
        const msg = kstr(ptr, len);
        onLog(level, '[' + tag + '] ' + msg);
        // Mirror info/warn/error module logs (e.g. an emulator core's frame /
        // record counts / OVERSIZE) to the console so they show in devtools while
        // profiling — the DOM overlay alone is invisible to the profiler.
        if (level >= 2) (level >= 4 ? console.error : level >= 3 ? console.warn : console.log)('[' + tag + '] ' + msg);
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
          const entry = { reader: null, queue: [], eof: false, contentLength: -3, bytes: 0, consumed: 0 };
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
            // Backpressure: cap the undelivered queue so a large
            // streamed asset never accumulates in tab memory faster
            // than the wasm consumer drains it. 32 MiB ≈ 3 s of a
            // UHD remux — enough to ride out scheduler jitter and
            // bitrate peaks without starving the decoder.
            const FETCH_QUEUE_MAX = 32 * 1024 * 1024;
            while (true) {
              while (entry.bytes - entry.consumed > FETCH_QUEUE_MAX) {
                await new Promise((r) => setTimeout(r, 50));
              }
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
        entry.consumed += n;
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

    // ── object shim (host_object_*, storage.object range reads) ──────
    // Backs the wasm `storage.object` provider (`src/platform/wasm/
    // object.rs`). Adds bounded `Range:` reads + `HEAD` metadata on top
    // of the same fetch model as `fetchShim`. `host_object_head` and
    // `host_object_range_open` are idempotent per identity so a
    // provider call that returns EAGAIN and retries re-finds the same
    // in-flight request instead of issuing a duplicate fetch.
    //
    // Read tier vs. write tier: `fetch()` + `asset://` are read-only and
    // serve shipped content. `host_object_put` adds the persistent write
    // tier (RFC 0009 save-states, imports) backed by OPFS. Writes land
    // synchronously in `objStore` (so an immediately-following read sees
    // them) and persist to OPFS in the background; `objStore` is also
    // hydrated from OPFS at boot. Reads consult `objStore` before
    // fetch(), so a PUT key reads back this session and across reloads.
    const objects = new Map(); // handle -> entry
    const headByKey = new Map(); // url -> handle
    const rangeByKey = new Map(); // `${url}\0${off}\0${len}` -> handle
    let nextObjectHandle = 1;

    // Persistent write tier: key -> Uint8Array. Source of truth for
    // reads of written/hydrated objects; OPFS is its durable backing.
    const objStore = new Map();

    // OPFS root directory handle (a promise that resolves to the handle,
    // or to null when the host has no OPFS — older browsers, Node tests
    // without a mock, private-mode quotas). All OPFS work awaits this and
    // no-ops on null, so the provider degrades to the fetch read tier.
    const opfsRootP = (typeof navigator !== 'undefined'
      && navigator.storage && typeof navigator.storage.getDirectory === 'function')
      ? Promise.resolve().then(() => navigator.storage.getDirectory()).catch((err) => {
          console.warn(`host_object: OPFS unavailable (${err && err.message}); writes are session-only`);
          return null;
        })
      : Promise.resolve(null);

    // IndexedDB fallback persistence tier. OPFS (`navigator.storage`) only
    // exists in SECURE contexts — over plain-http (a LAN-IP dev box, the
    // same constraint that forces the ScriptProcessor audio fallback) it is
    // absent entirely, so an OPFS-only write tier silently loses every blob
    // on refresh and warm-boot consumers (the shell's catalog projection)
    // cold-scan forever. IndexedDB works in insecure contexts and Workers.
    // OPFS is preferred when present; IDB enumeration (a key cursor) is
    // reliable, so it needs no side index.
    const idbOpenP = new Promise((resolve) => {
      if (typeof indexedDB === 'undefined') return resolve(null);
      try {
        const req = indexedDB.open('fluxor-objects', 1);
        req.onupgradeneeded = () => {
          try { req.result.createObjectStore('blobs'); } catch (_) { /* exists */ }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => resolve(null);
        req.onblocked = () => resolve(null);
      } catch (_) { resolve(null); }
    });
    const idbPersist = (key, bytes) => idbOpenP.then((db) => new Promise((resolve) => {
      if (!db) return resolve();
      try {
        const tx = db.transaction('blobs', 'readwrite');
        tx.objectStore('blobs').put(bytes, key);
        tx.oncomplete = () => resolve();
        tx.onerror = () => resolve();
        tx.onabort = () => resolve();
      } catch (_) { resolve(); }
    }));
    const idbHydrate = () => idbOpenP.then((db) => new Promise((resolve) => {
      if (!db) return resolve();
      try {
        const cur = db.transaction('blobs', 'readonly').objectStore('blobs').openCursor();
        cur.onsuccess = () => {
          const c = cur.result;
          if (!c) return resolve();
          try {
            const k = String(c.key);
            if (!objStore.has(k)) objStore.set(k, new Uint8Array(c.value));
          } catch (_) { /* skip entry */ }
          c.continue();
        };
        cur.onerror = () => resolve();
      } catch (_) { resolve(); }
    }));

    // Resolve `key` ("a/b/c.bin") to an OPFS file handle, creating the
    // intermediate directories when `create` is set. Returns null if OPFS
    // is absent, or (for create=false) if any path segment is missing.
    const opfsResolveFile = async (key, create) => {
      const root = await opfsRootP;
      if (!root) return null;
      const parts = key.split('/').filter((s) => s.length > 0);
      if (parts.length === 0) return null;
      let dir = root;
      try {
        for (let i = 0; i < parts.length - 1; i++) {
          dir = await dir.getDirectoryHandle(parts[i], { create: !!create });
        }
        return await dir.getFileHandle(parts[parts.length - 1], { create: !!create });
      } catch (_) {
        return null; // missing segment (read) or creation denied.
      }
    };

    // Key index for hydration. Directory ENUMERATION (`entries()`) is not
    // trustworthy across realms — Chromium's worker-side enumeration has
    // been observed returning `$`-mangled segment names for entries created
    // in the same realm (`foo/x` enumerates as `$foo/$x`), so a
    // hydrate that reconstructs keys from enumerated names silently stores
    // them under the wrong key and every later lookup misses. Name
    // RESOLUTION (`get{Directory,File}Handle(name)`) round-trips reliably,
    // so persistence maintains an explicit index of PUT keys at a fixed
    // path and hydration resolves each listed key by name.
    const OPFS_INDEX_KEY = 'fluxor-object-index.json';
    // Background-persist `bytes` for `key` to OPFS (+ index update).
    // Fire-and-forget but SEQUENTIALIZED: the synchronous PUT has already
    // populated `objStore`, so a failure here only costs durability, never
    // correctness this session; the chain keeps read-modify-write index
    // updates from racing each other.
    let opfsPersistChain = Promise.resolve();
    const opfsPersist = (key, bytes) => {
      opfsPersistChain = opfsPersistChain.then(async () => {
        const root = await opfsRootP;
        if (!root) { await idbPersist(key, bytes); return; }
        const fh = await opfsResolveFile(key, true);
        if (!fh) return;
        const w = await fh.createWritable();
        await w.write(bytes);
        await w.close();
        const idxFh = await opfsResolveFile(OPFS_INDEX_KEY, true);
        if (!idxFh) return;
        let keys = [];
        try {
          const j = JSON.parse(await (await idxFh.getFile()).text());
          if (Array.isArray(j)) keys = j.filter((k) => typeof k === 'string');
        } catch (_) { /* absent/garbled index — rebuild from this key */ }
        if (!keys.includes(key)) {
          keys.push(key);
          const wi = await idxFh.createWritable();
          await wi.write(JSON.stringify(keys));
          await wi.close();
        }
      }).catch((err) => {
        console.warn(`host_object: OPFS persist failed for "${key}": ${err && err.message}`);
      });
    };

    // At boot, load every persisted object into `objStore` so keys
    // written in a prior session read back. Best-effort + recursive.
    // Returns the hydration promise so the host can gate module startup
    // on a complete index (see `namespaceReady` below).
    const opfsHydrate = () => {
      return opfsRootP.then(async (root) => {
        if (!root) return;
        // Index-driven: resolve each persisted key BY NAME (see the
        // OPFS_INDEX_KEY comment — enumeration is not realm-stable).
        const idxFh = await opfsResolveFile(OPFS_INDEX_KEY, false);
        if (!idxFh) return; // nothing persisted yet
        let keys = [];
        try {
          const j = JSON.parse(await (await idxFh.getFile()).text());
          if (Array.isArray(j)) keys = j.filter((k) => typeof k === 'string');
        } catch (_) { return; }
        for (const key of keys) {
          try {
            const fh = await opfsResolveFile(key, false);
            if (!fh) continue;
            const buf = new Uint8Array(await (await fh.getFile()).arrayBuffer());
            if (!objStore.has(key)) objStore.set(key, buf);
          } catch (_) { /* skip unreadable entry */ }
        }
      }).catch(() => { /* no OPFS — skip */ });
    };
    const opfsHydrateP = Promise.allSettled([opfsHydrate(), idbHydrate()]).then(() => {});

    // ── namespace index (host_ns_*, storage.namespace enumeration) ───
    // Directory enumeration over the SAME flat key space the object tier
    // writes (`objStore`, OPFS-backed) unioned with a fetched manifest of
    // shipped, immutable content. `/` is the hierarchy separator, so a
    // key "saves/tetris" makes LIST("") yield "saves" (namespace) and
    // LIST("saves/") yield "tetris" (object). Backs src/platform/wasm/
    // namespace.rs; lets `storage.namespace` consumers (truffle's
    // scanner) walk a tree the browser has no POSIX readdir for.
    const manifestIndex = new Map(); // key -> { size, mtime, etag(string) }
    // 16-char etag-ObjectId form -> manifest key (see the alias comment in
    // the hydration loop below).
    const etagAlias = new Map();
    const manifestUrl = o.manifestUrl || 'fluxor-manifest.json';
    // Boot fetch of the shipped-content manifest: a JSON array of
    // { key, size, mtime?, etag? }. Absent/garbled → the namespace tier
    // serves objStore (user data) only. Returns its promise so startup can
    // wait for it.
    const manifestHydrateP = (function loadManifest() {
      if (typeof fetch !== 'function') return Promise.resolve();
      return Promise.resolve().then(() => fetch(manifestUrl))
        .then((resp) => (resp && resp.ok) ? resp.json() : null)
        .then((entries) => {
          if (!Array.isArray(entries)) return;
          for (const e of entries) {
            if (!e || typeof e.key !== 'string') continue;
            manifestIndex.set(e.key, {
              size: Number(e.size) || 0,
              mtime: Number(e.mtime) || 0,
              etag: typeof e.etag === 'string' ? e.etag : '',
            });
            // ObjectId alias: consumers that carry a 16-byte etag-packed
            // ObjectId (etag bytes truncated or zero-padded to 16) resolve it as a
            // storage.object KEY. Alias that exact 16-char form (including
            // NUL padding, which kstr preserves) back to the manifest path
            // so a dispatched handle loads the right bytes in-browser.
            if (typeof e.etag === 'string' && e.etag.length > 0) {
              const a = e.etag.length >= 16
                ? e.etag.slice(0, 16)
                : e.etag + '\0'.repeat(16 - e.etag.length);
              if (!etagAlias.has(a)) etagAlias.set(a, e.key);
            }
          }
        }).catch(() => { /* no manifest — objStore-only namespace */ });
    })();

    // Single namespace-readiness signal. The `storage.namespace` LIST/STAT
    // answers SYNCHRONOUSLY from these two in-memory sources and treats a
    // negative/empty LIST as end-of-listing (no EAGAIN), so a scanner that
    // runs before hydration would read a partial tree as complete and miss
    // shipped content permanently. The canonical runtime awaits this promise
    // before the kernel steps any module (see runtime.html), making the index
    // fully built by the time the first LIST can be issued. A host that omits
    // the callback keeps the old best-effort behavior (no behavioral change).
    const namespaceReady = Promise
      .allSettled([opfsHydrateP, manifestHydrateP])
      .then(() => {});
    if (typeof o.onNamespaceReady === 'function') {
      try { o.onNamespaceReady(namespaceReady); } catch (_) { /* ignore */ }
    }

    // Deterministic 16-byte object id for a key (FNV-1a, four seeded
    // 32-bit passes). Stable per key + high-entropy, which is what the
    // scanner's etag→ObjectId packing wants for objStore entries that
    // carry no server etag.
    const fnvEtag16 = (key) => {
      const bytes = new TextEncoder().encode(key);
      const out = new Uint8Array(16);
      for (let lane = 0; lane < 4; lane++) {
        let h = (0x811c9dc5 ^ (lane * 0x9e3779b1)) >>> 0;
        for (let i = 0; i < bytes.length; i++) {
          h = (h ^ bytes[i]) >>> 0;
          h = Math.imul(h, 0x01000193) >>> 0;
        }
        out[lane * 4] = h & 0xff;
        out[lane * 4 + 1] = (h >>> 8) & 0xff;
        out[lane * 4 + 2] = (h >>> 16) & 0xff;
        out[lane * 4 + 3] = (h >>> 24) & 0xff;
      }
      return out;
    };

    // A manifest etag string → 16 bytes (utf-8, truncated/zero-padded).
    const etagToBytes16 = (s) => {
      const b = new TextEncoder().encode(s);
      const out = new Uint8Array(16);
      out.set(b.subarray(0, 16));
      return out;
    };

    // Resolve a key against the union index:
    //   { kind:'object', size, mtime, etag:Uint8Array(16) } | a leaf
    //   { kind:'namespace' }   — a prefix that has children
    //   null                   — unknown
    const nsResolve = (key) => {
      const stored = objStore.get(key);
      if (stored !== undefined) {
        return { kind: 'object', size: stored.byteLength, mtime: 0, etag: fnvEtag16(key) };
      }
      const m = manifestIndex.get(key);
      if (m !== undefined) {
        return {
          kind: 'object', size: m.size, mtime: m.mtime,
          etag: m.etag ? etagToBytes16(m.etag) : fnvEtag16(key),
        };
      }
      const dirPrefix = key.endsWith('/') ? key : key + '/';
      for (const k of objStore.keys()) if (k.startsWith(dirPrefix)) return { kind: 'namespace' };
      for (const k of manifestIndex.keys()) if (k.startsWith(dirPrefix)) return { kind: 'namespace' };
      return null;
    };

    // Immediate children under `prefix`, deduped and name-sorted (stable
    // order so integer-cursor paging is deterministic). A name that is
    // both a leaf and a sub-prefix resolves to a namespace.
    const nsListChildren = (prefix) => {
      let pfx = prefix;
      if (pfx.length > 0 && !pfx.endsWith('/')) pfx = pfx + '/';
      const children = new Map(); // name -> 'object' | 'namespace'
      const consider = (key) => {
        if (!key.startsWith(pfx)) return;
        const rest = key.slice(pfx.length);
        if (rest.length === 0) return;
        const slash = rest.indexOf('/');
        if (slash === -1) {
          if (!children.has(rest)) children.set(rest, 'object');
        } else {
          children.set(rest.slice(0, slash), 'namespace'); // namespace wins
        }
      };
      for (const k of objStore.keys()) consider(k);
      for (const k of manifestIndex.keys()) consider(k);
      return [...children.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    };

    // Encode [size:u64 LE][mtime:u64 LE] into a fresh 16-byte view.
    const encodeMeta = (size, mtimeSec) => {
      const meta = new Uint8Array(16);
      const dv = new DataView(meta.buffer);
      dv.setBigUint64(0, BigInt(size >>> 0 === size ? size : Math.floor(size)), true);
      dv.setBigUint64(8, BigInt(Math.max(0, Math.floor(mtimeSec))), true);
      return meta;
    };

    const objectShim = {
      host_object_head: (keyPtr, keyLen) => {
        try {
          let rawKey = kstr(keyPtr, keyLen);
          if (!objStore.has(rawKey) && !manifestIndex.has(rawKey) && etagAlias.has(rawKey)) {
            rawKey = etagAlias.get(rawKey);
          }
          // Persistent write tier first: a PUT/hydrated key serves its
          // size from memory without a HEAD round-trip. Keyed by the raw
          // PUT key, before any fetch URL override.
          const stored = objStore.get(rawKey);
          if (stored !== undefined) {
            const handle = nextObjectHandle++;
            objects.set(handle, {
              reader: null, queue: [encodeMeta(stored.byteLength, 0)],
              eof: true, bytes: 0, isHead: true,
            });
            return handle;
          }
          let url = rawKey;
          if (fetchUrlOverride) url = fetchUrlOverride(url);
          const existing = headByKey.get(url);
          if (existing !== undefined) return existing;

          const handle = nextObjectHandle++;
          // A HEAD stream's queue carries exactly the 16-byte meta
          // record; `recv` drains it once ready.
          const entry = { reader: null, queue: [], eof: false, bytes: 0, isHead: true };
          objects.set(handle, entry);
          headByKey.set(url, handle);

          if (url.startsWith('asset://')) {
            const bytes = assetBank.get(url.slice('asset://'.length));
            if (!bytes) { entry.eof = true; return handle; }
            entry.queue.push(encodeMeta(bytes.byteLength, 0));
            entry.eof = true;
            return handle;
          }

          fetch(url, { method: 'HEAD' }).then((resp) => {
            if (!resp.ok) { entry.eof = true; return; }
            const cl = parseInt(resp.headers.get('content-length') || '0', 10) || 0;
            const lm = resp.headers.get('last-modified');
            const mtime = lm ? Math.floor(Date.parse(lm) / 1000) : 0;
            entry.queue.push(encodeMeta(cl, mtime));
            entry.eof = true;
          }).catch((err) => {
            entry.eof = true;
            console.error(`host_object_head: ${err.message} for ${url}`);
          });
          return handle;
        } catch (err) {
          console.error(`host_object_head threw: ${err.message}`);
          return -1;
        }
      },

      host_object_range_open: (keyPtr, keyLen, offset, length) => {
        try {
          let rawKey = kstr(keyPtr, keyLen);
          if (!objStore.has(rawKey) && !manifestIndex.has(rawKey) && etagAlias.has(rawKey)) {
            rawKey = etagAlias.get(rawKey);
          }
          const off = Number(offset);
          const len = Number(length);
          // Persistent write tier first: serve the window straight from
          // the in-memory blob (same windowing as the asset:// branch).
          const stored = objStore.get(rawKey);
          if (stored !== undefined) {
            const handle = nextObjectHandle++;
            const entry = { reader: null, queue: [], eof: true, bytes: 0, isHead: false };
            const end = Math.min(stored.byteLength, off + len);
            if (off < end) entry.queue.push(stored.subarray(off, end));
            objects.set(handle, entry);
            return handle;
          }
          let url = rawKey;
          if (fetchUrlOverride) url = fetchUrlOverride(url);
          const idKey = `${url}\0${off}\0${len}`;
          const existing = rangeByKey.get(idKey);
          if (existing !== undefined) return existing;

          const handle = nextObjectHandle++;
          const entry = { reader: null, queue: [], eof: false, bytes: 0, isHead: false, idKey };
          objects.set(handle, entry);
          rangeByKey.set(idKey, handle);

          if (url.startsWith('asset://')) {
            const bytes = assetBank.get(url.slice('asset://'.length));
            if (!bytes) { entry.eof = true; return handle; }
            const end = Math.min(bytes.byteLength, off + len);
            if (off < end) entry.queue.push(bytes.subarray(off, end));
            entry.eof = true;
            return handle;
          }

          // Inclusive end byte per RFC 9110 §14.1.
          const range = `bytes=${off}-${off + len - 1}`;
          fetch(url, { headers: { Range: range } }).then(async (resp) => {
            if (!resp.ok) { entry.eof = true; return; }
            // 206 Partial Content → body IS the requested window. 200 OK
            // → the server ignored `Range` and sent the whole object from
            // byte 0, so we must skip `off` bytes and cap at `len`
            // locally; otherwise a nonzero-offset read returns the wrong
            // bytes. `remaining` also caps 206 in case a server over-sends.
            let skip = resp.status === 206 ? 0 : off;
            let remaining = len;
            const reader = resp.body.getReader();
            entry.reader = reader;
            // Backpressure: cap the undelivered queue so a large
            // streamed asset never accumulates in tab memory faster
            // than the wasm consumer drains it. 32 MiB ≈ 3 s of a
            // UHD remux — enough to ride out scheduler jitter and
            // bitrate peaks without starving the decoder.
            const FETCH_QUEUE_MAX = 32 * 1024 * 1024;
            while (true) {
              while (entry.bytes - entry.consumed > FETCH_QUEUE_MAX) {
                await new Promise((r) => setTimeout(r, 50));
              }
              const { done, value } = await reader.read();
              if (done) { entry.eof = true; break; }
              let chunk = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
              if (skip > 0) {
                if (chunk.length <= skip) { skip -= chunk.length; continue; }
                chunk = chunk.subarray(skip);
                skip = 0;
              }
              if (chunk.length > remaining) chunk = chunk.subarray(0, remaining);
              if (chunk.length === 0) { entry.eof = true; break; }
              entry.queue.push(chunk);
              entry.bytes += chunk.length;
              remaining -= chunk.length;
              if (remaining <= 0) { entry.eof = true; try { reader.cancel().catch(() => {}); } catch (_) {} break; }
            }
          }).catch((err) => {
            entry.eof = true;
            console.error(`host_object_range_open: ${err.message} for ${url}`);
          });
          return handle;
        } catch (err) {
          console.error(`host_object_range_open threw: ${err.message}`);
          return -1;
        }
      },

      host_object_recv: (handle, bufPtr, bufLen) => {
        const entry = objects.get(handle);
        if (!entry) return -2;
        if (entry.queue.length === 0) return entry.eof ? -1 : 0;
        const chunk = entry.queue[0];
        const n = Math.min(chunk.length, bufLen);
        kview(bufPtr, n).set(chunk.subarray(0, n));
        if (n >= chunk.length) entry.queue.shift();
        else entry.queue[0] = chunk.subarray(n);
        entry.consumed += n;
        return n;
      },

      host_object_close: (handle) => {
        const entry = objects.get(handle);
        if (!entry) return 0;
        if (entry.reader && !entry.eof) {
          try { entry.reader.cancel().catch(() => {}); } catch (_) {}
        }
        // Drop idempotency index entries so a later request re-fetches.
        if (entry.isHead) {
          for (const [k, h] of headByKey) if (h === handle) { headByKey.delete(k); break; }
        } else if (entry.idKey !== undefined) {
          rangeByKey.delete(entry.idKey);
        }
        objects.delete(handle);
        return 0;
      },

      // Write tier (OPFS). Stage the bytes synchronously so a following
      // read sees them, then persist to OPFS in the background. Returns 0
      // on acceptance, -1 on a hard failure (e.g. memory read fault).
      host_object_put: (keyPtr, keyLen, bodyPtr, bodyLen) => {
        try {
          const key = kstr(keyPtr, keyLen);
          if (key.length === 0) return -1;
          // Copy out of wasm linear memory — the buffer is reused after
          // the call returns, and OPFS persistence reads it later.
          const body = kview(bodyPtr, bodyLen).slice();
          objStore.set(key, body);
          opfsPersist(key, body);
          return 0;
        } catch (err) {
          console.error(`host_object_put threw: ${err.message}`);
          return -1;
        }
      },
    };

    // storage.namespace host bindings — render the contract wire format
    // straight into the caller's buffer from the union index above.
    const NS_KIND_OBJECT = 0, NS_KIND_NAMESPACE = 1;
    const nsShim = {
      // STAT: [size:u64][mtime:u64][kind:u8][etag_len:u8][etag]. ENOENT
      // (-2) when the key names neither an object nor a populated prefix.
      host_ns_stat: (keyPtr, keyLen, outPtr, outCap) => {
        try {
          const res = nsResolve(kstr(keyPtr, keyLen));
          if (!res) return -2; // ENOENT
          const etag = res.kind === 'object' ? res.etag : new Uint8Array(0);
          const need = 8 + 8 + 1 + 1 + etag.length;
          if (outCap < need) return -22; // EINVAL — buffer too small
          const out = kview(outPtr, outCap);
          const dv = new DataView(out.buffer, out.byteOffset, 16);
          dv.setBigUint64(0, BigInt(res.size || 0), true);
          dv.setBigUint64(8, BigInt(res.mtime || 0), true);
          out[16] = res.kind === 'namespace' ? NS_KIND_NAMESPACE : NS_KIND_OBJECT;
          out[17] = etag.length;
          out.set(etag, 18);
          return need;
        } catch (err) {
          console.error(`host_ns_stat threw: ${err.message}`);
          return -22;
        }
      },

      // LIST one page: entries [name_len:u8][kind:u8][name] then a
      // trailing [0xFF][cursor_len:u8][cursor] record — a 4-byte LE
      // next-index when more remain, cursor_len=0 at end of listing.
      host_ns_list: (prefixPtr, prefixLen, cursorIdx, outPtr, outCap) => {
        try {
          const children = nsListChildren(kstr(prefixPtr, prefixLen));
          const out = kview(outPtr, outCap);
          let w = 0;
          let i = cursorIdx >>> 0;
          for (; i < children.length; i++) {
            const name = new TextEncoder().encode(children[i][0]);
            if (name.length > 255) continue; // unaddressable in [name_len:u8]
            const need = 2 + name.length;
            // Always leave room for the worst-case trailing cursor (6 B).
            if (w + need + 6 > outCap) break;
            out[w++] = name.length;
            out[w++] = children[i][1] === 'namespace' ? NS_KIND_NAMESPACE : NS_KIND_OBJECT;
            out.set(name, w); w += name.length;
          }
          // The trailing cursor record is MANDATORY — a caller parses it
          // to learn whether more pages remain. Out-of-range writes on a
          // too-small typed array are silent no-ops, so without an
          // explicit check we'd return a positive count over a buffer
          // that never actually received the trailer, leaving the caller
          // to parse stale/malformed bytes. Fail with EINVAL instead:
          //   - more entries remain but nothing fit (w === 0): the buffer
          //     can't even hold one entry + the 6-byte cursor, so the
          //     caller could never advance — reject rather than hand back
          //     an empty page that re-polls forever;
          //   - end-of-listing but no room for the 2-byte terminator.
          // (When the loop DID emit entries it already reserved 6 B.)
          const more = i < children.length;
          if (more) {
            if (w === 0 || w + 6 > outCap) return -22; // EINVAL — buffer too small to page
          } else if (w + 2 > outCap) {
            return -22; // EINVAL — no room for end-of-listing marker
          }
          out[w++] = 0xFF;
          if (more) {
            out[w++] = 4;
            out[w++] = i & 0xff; out[w++] = (i >>> 8) & 0xff;
            out[w++] = (i >>> 16) & 0xff; out[w++] = (i >>> 24) & 0xff;
          } else {
            out[w++] = 0; // end of listing
          }
          return w;
        } catch (err) {
          console.error(`host_ns_list threw: ${err.message}`);
          return -22;
        }
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

    // ACTION source — wasm_browser_action. The presentation-shell
    // overlay (browser_overlay_runtime.js) pushes one record per
    // activated media/transport/gallery control:
    //   { hash: fnv1a32(action_id), value: <number> }
    // `host_action_pop` serialises it as [hash:u32 LE][value:f32 LE]
    // (8 bytes); the built-in maps the hash to an FMP verb.
    const actionQueue = window.__fluxor_action_queue
      || (window.__fluxor_action_queue = []);
    const actionShim = {
      host_action_pop: (bufPtr, bufLen) => {
        if (actionQueue.length === 0 || bufLen < 8) return 0;
        const ev = actionQueue.shift();
        const view = new DataView(getKernel().exports.memory.buffer, bufPtr, 8);
        view.setUint32(0, (ev.hash >>> 0), true);
        view.setFloat32(4, Number(ev.value) || 0, true);
        return 8;
      },
    };

    // SURFACE TRAITS authority — wasm_browser_surface_traits. The browser
    // runtime publisher (installSurfaceTraits in browser_overlay_runtime.js)
    // coalesces resize / visualViewport / pointer-class / gamepad / audio
    // changes to at most one record per animation frame and pushes:
    //   { orientation, sizeClassW, sizeClassH, viewportW, viewportH,
    //     modalities, gamepadCount, audioChannels, audioRateHz, epoch }
    // `host_surface_traits_pop` serialises it to the 24-byte MSG_TRAITS
    // record (input::surface_traits.rs). authority = 0 (browser).
    const surfaceTraitsQueue = window.__fluxor_surface_traits_queue
      || (window.__fluxor_surface_traits_queue = []);
    const surfaceTraitsShim = {
      host_surface_traits_pop: (bufPtr, bufLen) => {
        if (surfaceTraitsQueue.length === 0 || bufLen < 24) return 0;
        const ev = surfaceTraitsQueue.shift();
        const view = new DataView(getKernel().exports.memory.buffer, bufPtr, 24);
        view.setUint8(0, 0x01);                          // MSG_TRAITS
        view.setUint8(1, ev.orientation & 0xFF);
        view.setUint8(2, ev.sizeClassW & 0xFF);
        view.setUint8(3, ev.sizeClassH & 0xFF);
        view.setUint16(4, ev.viewportW & 0xFFFF, true);
        view.setUint16(6, ev.viewportH & 0xFFFF, true);
        view.setUint16(8, ev.modalities & 0xFFFF, true);
        view.setUint8(10, ev.gamepadCount & 0xFF);
        view.setUint8(11, ev.audioChannels & 0xFF);
        view.setUint32(12, (ev.audioRateHz >>> 0), true);
        view.setUint32(16, (ev.epoch >>> 0), true);
        view.setUint8(20, 0);                            // AUTHORITY_BROWSER
        view.setUint8(21, (ev.displayCount == null ? 1 : ev.displayCount) & 0xFF); // a browser always has a display
        view.setUint8(22, (ev.dpr8 || 0) & 0xFF);        // pad[0] = devicePixelRatio ×8 (DPR-aware raster)
        view.setUint8(23, 0);
        return 24;
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

    // ── Audio sink (wasm_browser_audio) — delegates to the shared fixed-rate
    //    scheduler (createAudioScheduler, top of file). The Worker bridge reuses
    //    the SAME factory on the main thread so pacing never drifts between paths.
    const audioSched = createAudioScheduler(onLog);
    const audioShim = {
      host_audio_play: (ptr, len, sampleRate, channels) => {
        const i16 = new Int16Array(getKernel().exports.memory.buffer.slice(ptr, ptr + len));
        audioSched.schedule(i16, sampleRate, channels, len);
      },
      host_audio_ready: () => audioSched.ready() ? 1 : 0,
      host_audio_lead_us: () => audioSched.leadUs(),
      // Audio-clock StreamTime authority (24 bytes) for provider_query(-1,
      // STREAM_TIME). Producers and presenters all read this ONE clock.
      // consumed_units = emulated frames played (frameCursor).
      host_stream_time: (ptr) => writeStreamTime(getKernel().exports.memory.buffer, ptr, audioSched.frameCursor(), audioSched.leadUs()),
    };
    // Present pacing is the app graph's job (it reads StreamTime and decides
    // when to PRESENT) — no page rAF present loop.

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

    // ── Camera source bridge (wasm_browser_camera) ───────────────────
    // getUserMedia is the browser's only camera API, so capture is JS; the
    // decode is the qr_scan module in the graph. We start the stream lazily
    // on the first pull, draw each frame to a small offscreen canvas, and hand
    // the wasm side a luma frame framed as [w:u16 LE][h:u16 LE][luma w*h].
    const CAM_DIM = 160; // square capture; resolves a low-version token QR
    let camState = null; // { video, canvas, ctx, ready }
    function startCamera() {
      const video = document.createElement('video');
      video.autoplay = true; video.playsInline = true; video.muted = true;
      const canvas = document.createElement('canvas');
      canvas.width = CAM_DIM; canvas.height = CAM_DIM;
      const st = { video, canvas, ctx: canvas.getContext('2d', { willReadFrequently: true }), ready: false };
      camState = st;
      navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
        .then((stream) => { video.srcObject = stream; return video.play(); })
        .then(() => { st.ready = true; })
        .catch((err) => { console.error('[camera] getUserMedia:', err && err.message); });
    }
    const cameraShim = {
      host_camera_frame: (bufPtr, bufLen) => {
        if (!camState) { startCamera(); return 0; }
        const st = camState;
        if (!st.ready || !st.video.videoWidth) return 0;
        const need = 4 + CAM_DIM * CAM_DIM;
        if (bufLen < need) return 0;
        st.ctx.drawImage(st.video, 0, 0, CAM_DIM, CAM_DIM);
        const px = st.ctx.getImageData(0, 0, CAM_DIM, CAM_DIM).data;
        const out = kview(bufPtr, need);
        out[0] = CAM_DIM & 0xFF; out[1] = (CAM_DIM >> 8) & 0xFF;
        out[2] = CAM_DIM & 0xFF; out[3] = (CAM_DIM >> 8) & 0xFF;
        for (let i = 0; i < CAM_DIM * CAM_DIM; i++) {
          out[4 + i] = (px[i * 4] * 0.30 + px[i * 4 + 1] * 0.59 + px[i * 4 + 2] * 0.11) | 0;
        }
        return need;
      },
    };

    // ── Display capture bridge (wasm_browser_display_capture) ────────
    // getDisplayMedia is the browser's only display-capture API, so capture is
    // JS; everything downstream is the graph. We ask lazily on the first pull —
    // a share dialog at boot is a dialog with no context — draw each frame to an
    // offscreen canvas, and hand the wasm side an SRF1 RGB565 frame.
    //
    // The person stopping the share is reported once, as ENDED, and the stream
    // is not restarted. Re-calling getDisplayMedia would re-open the picker; a
    // page that did that after someone stopped sharing would be re-asking for a
    // screen they just took back.
    const DISPLAY_ENDED = -2;
    let dispState = null; // { video, canvas, ctx, ready, ended }
    function startDisplayCapture() {
      const video = document.createElement('video');
      video.autoplay = true; video.playsInline = true; video.muted = true;
      const canvas = document.createElement('canvas');
      const st = {
        video,
        canvas,
        ctx: canvas.getContext('2d', { willReadFrequently: true }),
        ready: false,
        ended: false,
      };
      dispState = st;
      if (!navigator.mediaDevices || !navigator.mediaDevices.getDisplayMedia) {
        st.ended = true; // no API here: report it as ended rather than as "starting" forever
        return;
      }
      navigator.mediaDevices.getDisplayMedia({ video: true, audio: false })
        .then((stream) => {
          // The browser's own "Stop sharing" ends the track without telling the
          // page anything else. This is the only notice we get, and it is the
          // notice the graph needs.
          stream.getVideoTracks().forEach((t) => { t.onended = () => { st.ended = true; }; });
          video.srcObject = stream;
          return video.play();
        })
        .then(() => { st.ready = true; })
        // A refusal is a decision, not a failure to retry: it ends the capture.
        .catch((err) => {
          st.ended = true;
          console.warn('[display-capture] getDisplayMedia:', err && err.message);
        });
    }
    const displayCaptureShim = {
      host_display_frame: (bufPtr, bufLen) => {
        if (!dispState) { startDisplayCapture(); return 0; }
        const st = dispState;
        if (st.ended) return DISPLAY_ENDED;
        if (!st.ready || !st.video.videoWidth) return 0;
        // The shared surface's own geometry, capped by what the graph sized its
        // buffer for. The SRF1 header says which it turned out to be, so a
        // consumer never has to guess.
        const room = Math.max(0, (bufLen - 10) >> 1);
        let w = st.video.videoWidth;
        let h = st.video.videoHeight;
        if (w * h > room) {
          const scale = Math.sqrt(room / (w * h));
          w = Math.max(1, Math.floor(w * scale));
          h = Math.max(1, Math.floor(h * scale));
        }
        if (w * h === 0 || 10 + w * h * 2 > bufLen) return 0;
        if (st.canvas.width !== w || st.canvas.height !== h) {
          st.canvas.width = w; st.canvas.height = h;
        }
        st.ctx.drawImage(st.video, 0, 0, w, h);
        const px = st.ctx.getImageData(0, 0, w, h).data;
        const out = kview(bufPtr, 10 + w * h * 2);
        out[0] = 0x53; out[1] = 0x52; out[2] = 0x46; out[3] = 0x31; // "SRF1"
        out[4] = w & 0xFF; out[5] = (w >> 8) & 0xFF;
        out[6] = h & 0xFF; out[7] = (h >> 8) & 0xFF;
        out[8] = 1; // FMT_RGB565 (sector/modules/common/sector_raster.rs)
        out[9] = 0;
        for (let i = 0, p = 10; i < w * h; i++, p += 2) {
          const o = i * 4;
          const v = ((px[o] >> 3) << 11) | ((px[o + 1] >> 2) << 5) | (px[o + 2] >> 3);
          out[p] = v & 0xFF;
          out[p + 1] = (v >> 8) & 0xFF;
        }
        return 10 + w * h * 2;
      },
    };

    // Result sink (wasm_browser_scan_out): stash the decoded token for the page.
    const scanOutShim = {
      host_scan_result: (ptr, len) => {
        const bytes = kview(ptr, len).slice();
        const text = new TextDecoder().decode(bytes);
        window.__fluxor_scan_result = text;
        if (typeof window.onScanResult === 'function') { try { window.onScanResult(text); } catch (e) {} }
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
        // Distinguish a failed decode (-2, terminal) from one still decoding
        // (-1, EAGAIN). The Rust img_recv maps -1 → EAGAIN, so collapsing the
        // error state into -1 would loop the caller forever on a dead job.
        if (job.state === 'error') return -2;
        if (job.state !== 'ready') return -1;
        const remaining = job.buf.length - job.pos;
        if (remaining === 0) return 0;
        const n = Math.min(remaining, bufLen);
        kview(bufPtr, n).set(job.buf.subarray(job.pos, job.pos + n));
        job.pos += n;
        return n;
      },
      host_image_decode_close: (handle) => imageDecodes.delete(handle) ? 0 : -1,

      // Range-fetch an embedded image (cover art lives inside an .m4a at a
      // byte offset) and decode it straight to a `width`×`height` RGB565
      // buffer in the browser — so a PIC module (truffle_shell) gets album
      // covers without pulling multi-MB encoded images into wasm or
      // touching an in-wasm JPEG/PNG decoder. Reuses the
      // `host_image_decode_recv/size/close` job machinery.
      host_image_decode_url: (urlPtr, urlLen, offset, length, width, height) => {
        try {
          const url = kstr(urlPtr, urlLen);
          const off = Number(offset);
          const len = Number(length);
          const handle = nextImageHandle++;
          const job = { state: 'pending', buf: null, pos: 0, error: null, width, height };
          imageDecodes.set(handle, job);
          // Range header built by string concat (NOT a `${}` template literal):
          // host_shims.js is served through env-substitution that escapes `${` to
          // `$${`, so a template here would emit a literal, malformed Range and the
          // server would fall back to a full-body 200 (the whole multi-MB track).
          fetch(url, { headers: { Range: 'bytes=' + off + '-' + (off + len - 1) } })
            .then((r) => r.arrayBuffer().then((ab) => ({ status: r.status, ab })))
            .then(({ status, ab }) => {
              let bytes = new Uint8Array(ab);
              // Server ignored `Range:` (200, whole body) → slice the cover
              // out; a 206 already carries exactly the requested range.
              if (status !== 206 && bytes.length > len) {
                bytes = bytes.subarray(off, off + len);
              }
              return createImageBitmap(new Blob([bytes]), {
                resizeWidth: width, resizeHeight: height, resizeQuality: 'high',
              });
            })
            .then((bitmap) => {
              const oc = new OffscreenCanvas(width, height);
              const ctx = oc.getContext('2d');
              ctx.drawImage(bitmap, 0, 0);
              const rgba = ctx.getImageData(0, 0, width, height).data;
              const out = new Uint8Array(width * height * 2);
              for (let i = 0, p = 0; i < rgba.length; i += 4, p += 2) {
                const r = rgba[i] >> 3, g = rgba[i + 1] >> 2, b = rgba[i + 2] >> 3;
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
              console.error('host_image_decode_url[' + handle + '] failed: ' + err.message);
            });
          return handle;
        } catch (err) {
          console.error(`host_image_decode_url threw: ${err.message}`);
          return -1;
        }
      },
    };

    // ── Sub-module instantiation (host_instantiate_module, ...) ──────
    //
    // The wasm kernel exports a tiny set of PIC syscalls (channel_*,
    // provider_*, kernel_heap_alloc/free); sub-modules are linked
    // against those at instantiation. The shim bridges the
    // sub-module's linear memory and the kernel's linear memory by
    // allocating in the kernel's heap and copying through. Same
    // shape as the test_harness reference shims.
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
              // storage.namespace LIST (op 0x1302) is special: its output
              // buffer + fence are passed as pointers EMBEDDED in the arg
              // blob (into the CHILD's memory), not as direct args. The
              // generic arg copy-back below can't follow embedded pointers,
              // so the provider's page would be written into kernel memory
              // at a child address and never reach the module (empty LIST).
              // Bridge them explicitly: alloc kernel scratch, rewrite the
              // embedded pointers to it, then copy the results back to the
              // child. Arg layout (see contracts/storage/namespace.rs LIST):
              //   [prefix_len u16][prefix][cursor_len u16][cursor]
              //   [out_buf u64][out_cap u32][fence_ptr u64][fence_cap u16]
              const NS_LIST_OP = 0x1302;
              if (op === NS_LIST_OP && p && l >= 26) {
                const cbuf = childMem();
                const cdv = new DataView(cbuf.buffer, cbuf.byteOffset + p, l);
                const prefixLen = cdv.getUint16(0, true);
                const cursorOff = 2 + prefixLen;
                if (cursorOff + 2 <= l) {
                  const cursorLen = cdv.getUint16(cursorOff, true);
                  const oOff = cursorOff + 2 + cursorLen; // start of out_buf
                  if (oOff + 22 <= l) {
                    const outBufChild = cdv.getUint32(oOff, true);       // u64 lo
                    const outCap = cdv.getUint32(oOff + 8, true);
                    const fenceChild = cdv.getUint32(oOff + 12, true);   // u64 lo
                    const fenceCap = cdv.getUint16(oOff + 20, true);
                    const k = childToKernel(p, l);
                    if (!k) return -1;
                    const outK = outCap ? getKernel().exports.kernel_heap_alloc(outCap) : 0;
                    const fenceK = fenceCap ? getKernel().exports.kernel_heap_alloc(fenceCap) : 0;
                    // Rewrite the embedded pointers in the kernel arg copy to
                    // point at the kernel scratch (both u64: set lo + zero hi).
                    const kbuf = kmem();
                    const kdv = new DataView(kbuf.buffer, kbuf.byteOffset + k, l);
                    kdv.setUint32(oOff, outK, true); kdv.setUint32(oOff + 4, 0, true);
                    kdv.setUint32(oOff + 12, fenceK, true); kdv.setUint32(oOff + 16, 0, true);
                    const r = getKernel().exports.provider_call(h, op, k, l);
                    if (r > 0 && outK && outBufChild) {
                      kernelToChild(outK, outBufChild, Math.min(r, outCap));
                    }
                    if (fenceK && fenceChild) kernelToChild(fenceK, fenceChild, fenceCap);
                    if (outK) getKernel().exports.kernel_heap_free(outK);
                    if (fenceK) getKernel().exports.kernel_heap_free(fenceK);
                    getKernel().exports.kernel_heap_free(k);
                    return r;
                  }
                }
              }
              // storage.object PUT (0x1420) embeds body_ptr + fence_out_ptr
              // (child addresses) in the arg. Unbridged, the provider would
              // read the body from an untranslated child address in KERNEL
              // memory (persisting garbage) and write the fence to a child
              // address in kernel memory (heap corruption). Copy the body
              // through kernel scratch and rewrite both pointers.
              // Arg: [key_len:u16][key][ct_len:u8][ct][body_ptr:u64]
              //      [body_len:u64][if_match_len:u8][if_match]
              //      [fence_ptr:u64][fence_cap:u16]
              const OBJ_PUT_OP = 0x1420, OBJ_RANGE_GET_OP = 0x1423;
              if (op === OBJ_PUT_OP && p && l >= 2) {
                // Service the PUT directly from child memory: the kernel
                // path would need the whole (multi-MB) body staged through
                // kernel heap scratch just to end up in THIS closure's
                // host_object_put anyway. Same semantics (objStore +
                // OPFS persist), zero kernel-heap pressure. The fence is
                // left zeroed (the fence buffer lives child-side and the
                // wasm store is LocalDurable-at-best anyway).
                try {
                  const cbuf = childMem();
                  const cdv = new DataView(cbuf.buffer, cbuf.byteOffset + p, l);
                  const keyLen = cdv.getUint16(0, true);
                  const ctOff = 2 + keyLen;
                  if (keyLen === 0 || ctOff + 1 > l) return -1;
                  const ctLen = cdv.getUint8(ctOff);
                  const bodyOff = ctOff + 1 + ctLen;
                  if (bodyOff + 17 > l) return -1;
                  const bodyChild = cdv.getUint32(bodyOff, true);          // u64 lo
                  const bodyLen = Number(cdv.getBigUint64(bodyOff + 8, true));
                  const ifLen = cdv.getUint8(bodyOff + 16);
                  if (ifLen !== 0) return -38;                             // ENOSYS, like the kernel
                  const key = new TextDecoder().decode(cbuf.subarray(p + 2, p + 2 + keyLen));
                  const body = cbuf.slice(bodyChild, bodyChild + bodyLen);
                  objStore.set(key, body);
                  opfsPersist(key, body);
                  return 0;
                } catch (err) {
                  console.error(`module OBJ_PUT bridge threw: ${err.message}`);
                  return -1;
                }
              }
              // storage.object RANGE_GET (0x1423) embeds out_ptr (child):
              // unbridged, the provider writes the window into kernel memory
              // at the child address — the module never sees the bytes AND
              // kernel memory is corrupted. Alloc kernel scratch, rewrite,
              // copy the read bytes back to the child.
              // Arg: [offset:u64][length:u32][out_ptr:u64]
              if (op === OBJ_RANGE_GET_OP && p && l >= 20) {
                const cbuf = childMem();
                const cdv = new DataView(cbuf.buffer, cbuf.byteOffset + p, l);
                const rgLen = cdv.getUint32(8, true);
                const outChild = cdv.getUint32(12, true);                 // u64 lo
                const k = childToKernel(p, l);
                if (!k) return -1;
                const outK = rgLen ? getKernel().exports.kernel_heap_alloc(rgLen) : 0;
                if (rgLen && !outK) { getKernel().exports.kernel_heap_free(k); return -1; }
                const kbuf = kmem();
                const kdv = new DataView(kbuf.buffer, kbuf.byteOffset + k, l);
                kdv.setUint32(12, outK, true); kdv.setUint32(16, 0, true);
                const r = getKernel().exports.provider_call(h, op, k, l);
                if (r > 0 && outK && outChild) kernelToChild(outK, outChild, Math.min(r, rgLen));
                if (outK) getKernel().exports.kernel_heap_free(outK);
                getKernel().exports.kernel_heap_free(k);
                return r;
              }
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

    // ── Generic GPU raster shim (wasm_browser_gpu) ───────────────────
    //
    // Backend driver for the generic 3D raster capability surface. Holds ZERO
    // application knowledge: the render pipeline (WGSL shader, vertex layout,
    // uniform size, depth/cull flags) arrives as data via
    // `host_gpu_raster_pipeline` — see gpu.rs for the descriptor wire format.
    // A Vulkan / bare-metal driver implements the same imports unchanged.
    //
    // State is managed in JS (device, pipeline, buffers) since WebGPU
    // objects can't be serialized to WASM memory. The module calls
    // host_gpu_raster_* imports which manipulate this JS-side state.
    let gpuDevice = null;
    let gpuContext = null;
    let gpuCanvas = null;
    let gpuFormat = null;
    // Slotted resources: pipelines and vertex buffers are
    // independent id spaces; DRAW names a (pipeline_id, buffer_slot) pair.
    //   pipeline entry: { pipeline, depth, stride, uniformBuffer, bindGroup }
    //   slot entry:     { vb, bytes, ib, indexCount, pendingVB, pendingTotal, pendingCursor }
    const gpuPipelines = new Map();
    const gpuSlots = new Map();
    // Offscreen render targets: app-created color textures the
    // scene renders into and post-process / reflection passes sample. Each holds
    //   { msaa, color, depth, view, colorView, w, h, matchCanvas, withDepth }
    // where `color` is the single-sample sampled texture the `msaa` companion
    // resolves into. Target id 0 is the swapchain (never in this map).
    const gpuTargets = new Map();
    let gpuLinearSampler = null;
    let gpuAnyDepth = false; // any registered pipeline declares depth
    const gpuSlot = (slot) => {
      let s = gpuSlots.get(slot);
      if (!s) {
        s = { vb: null, bytes: 0, ib: null, indexCount: 0,
              pendingVB: null, pendingTotal: 0, pendingCursor: 0,
              pendingIB: null, pendingITotal: 0, pendingICursor: 0 };
        gpuSlots.set(slot, s);
      }
      return s;
    };
    let gpuDepthTexture = null;
    // MSAA 4x: frames render into a multisampled color target that resolves
    // to the canvas at end of pass; depth matches the sample count and every
    // pipeline is created with multisample.count = GPU_MSAA.
    const GPU_MSAA = 4;
    let gpuMsaaTexture = null;
    let gpuEncoder = null;
    let gpuPass = null;
    let gpuInitialized = false;
    // Vsync throttle. The kernel pump free-runs (thousands of ticks/s), so an
    // unpaced producer can submit hundreds of frames per display refresh —
    // renders then land on canvas textures the compositor has already expired
    // and present as BLACK. Gate to one submitted frame per animation frame:
    // begin_frame refuses (-2) until the next rAF opens the window.
    let gpuFrameSubmittedThisVsync = false;
    (function gpuVsyncPump() {
      gpuFrameSubmittedThisVsync = false;
      requestAnimationFrame(gpuVsyncPump);
    })();
    // WebGPU init is asynchronous (adapter/device requests are Promises), but a
    // Wasm import is synchronous — so `host_gpu_raster_init` cannot await and return
    // the real result inline (the module would observe a coerced Promise and
    // "succeed" before the device exists). Instead init kicks off the async work
    // and records progress here; the module polls `host_gpu_raster_poll_init`.
    // Status: 0 = ready, 1 = pending, 2 = not started, <0 = error (-1 no WebGPU,
    // -2 no adapter, -3 init threw).
    const GPU_INIT_READY = 0;
    const GPU_INIT_PENDING = 1;
    const GPU_INIT_NOT_STARTED = 2;
    let gpuInitStatus = GPU_INIT_NOT_STARTED;
    let gpuWidth = 0;
    let gpuHeight = 0;

    // Descriptor attribute format codes → WebGPU vertex formats (gpu.rs contract)
    const GPU_ATTR_FORMATS = ['float32', 'float32x2', 'float32x3', 'float32x4', 'uint32', 'unorm8x4'];

    // (Re)build a pipeline's bind group from its uniform buffer plus any bound
    // sampled-texture views. A pipeline that declares texture units draws
    // nothing until every unit has been bound (bindGroup stays null).
    function gpuRebuildBindGroup(entry) {
      if (entry.uniformSize === 0 && entry.texCount === 0) { entry.bindGroup = null; return; }
      const entries = [];
      if (entry.uniformSize > 0 && entry.uniformBuffer) {
        entries.push({ binding: 0, resource: { buffer: entry.uniformBuffer } });
      }
      for (let i = 0; i < entry.texCount; i++) {
        if (!entry.boundViews[i]) { entry.bindGroup = null; return; } // not all units bound yet
        entries.push({ binding: 1 + 2 * i, resource: entry.boundViews[i] });
        entries.push({ binding: 2 + 2 * i, resource: gpuLinearSampler });
      }
      entry.bindGroup = gpuDevice.createBindGroup({ layout: entry.bindGroupLayout, entries });
    }

    // Create/replace offscreen render target `id`. `reqW/reqH` of 0 track the
    // canvas size (recreated on resize). Color is single-sample + sampleable;
    // the MSAA companion resolves into it so sampled output is already resolved.
    function gpuCreateTarget(id, reqW, reqH, withDepth) {
      const width = reqW > 0 ? reqW : gpuCanvas.width;
      const height = reqH > 0 ? reqH : gpuCanvas.height;
      const msaa = gpuDevice.createTexture({
        size: [width, height], format: gpuFormat, sampleCount: GPU_MSAA,
        usage: GPUTextureUsage.RENDER_ATTACHMENT,
      });
      const color = gpuDevice.createTexture({
        size: [width, height], format: gpuFormat, sampleCount: 1,
        usage: GPUTextureUsage.RENDER_ATTACHMENT | GPUTextureUsage.TEXTURE_BINDING,
      });
      const depth = withDepth ? gpuDevice.createTexture({
        size: [width, height], format: 'depth24plus', sampleCount: GPU_MSAA,
        usage: GPUTextureUsage.RENDER_ATTACHMENT,
      }) : null;
      gpuTargets.set(id, {
        msaa, color, depth,
        msaaView: msaa.createView(), colorView: color.createView(),
        depthView: depth ? depth.createView() : null,
        reqW, reqH, matchCanvas: (reqW === 0 || reqH === 0), withDepth,
      });
    }

    // Begin a render pass into `targetId` (0 = swapchain). Every pass renders
    // 4x MSAA and resolves — into the canvas for the swapchain, or into a
    // target's sampleable single-sample color texture otherwise. Depth is
    // attached only when requested AND available. Returns 0 or <0.
    function gpuOpenPass(targetId, r, g, b, withDepth) {
      let colorView, resolveView, depthView;
      if (targetId === 0) {
        colorView = gpuMsaaTexture.createView();
        resolveView = gpuContext.getCurrentTexture().createView();
        depthView = withDepth ? gpuDepthTexture.createView() : null;
      } else {
        const t = gpuTargets.get(targetId);
        if (!t) return -1;
        colorView = t.msaaView;
        resolveView = t.colorView;
        depthView = (withDepth && t.depthView) ? t.depthView : null;
      }
      gpuPass = gpuEncoder.beginRenderPass({
        colorAttachments: [{
          view: colorView, resolveTarget: resolveView,
          loadOp: 'clear', storeOp: 'store', clearValue: { r: r, g: g, b: b, a: 1.0 },
        }],
        depthStencilAttachment: depthView ? {
          view: depthView, depthLoadOp: 'clear', depthStoreOp: 'store', depthClearValue: 1.0,
        } : undefined,
      });
      return 0;
    }

    const webgpuShim = {
      // Initialize WebGPU device and context. Returns 0 on success, <0 on error.
      // Synchronous kick-off: starts the async init and returns PENDING (1).
      // The module MUST poll `host_gpu_raster_poll_init` until it returns READY (0)
      // or an error (<0) before calling any other host_gpu_raster_* function — a
      // Wasm import cannot await, so this can't return the real device status
      // inline. Idempotent: a second call while pending just returns PENDING.
      host_gpu_raster_init: () => {
        if (gpuInitialized) return GPU_INIT_READY;
        if (gpuInitStatus === GPU_INIT_PENDING) return GPU_INIT_PENDING;
        if (!navigator.gpu) {
          console.error('[webgpu] WebGPU not supported');
          console.error('[webgpu] isSecureContext:', window.isSecureContext);
          console.error('[webgpu] protocol:', window.location.protocol);
          console.error('[webgpu] userAgent:', navigator.userAgent);
          gpuInitStatus = -1;
          return -1;
        }
        gpuInitStatus = GPU_INIT_PENDING;
        (async () => {
        try {
          console.log('[webgpu] requesting adapter...');
          const adapter = await navigator.gpu.requestAdapter({ powerPreference: 'high-performance' });
          if (!adapter) {
            console.error('[webgpu] No adapter found');
            gpuInitStatus = -2;
            return;
          }
          console.log('[webgpu] adapter found, requesting device...');
          gpuDevice = await adapter.requestDevice();
          console.log('[webgpu] device acquired');
          gpuDevice.lost.then((info) => {
            console.error('[webgpu] Device lost (' + info.reason + '):', info.message);
            gpuInitialized = false;
            gpuInitStatus = GPU_INIT_NOT_STARTED;
          });
          gpuDevice.onuncapturederror = (e) => {
            console.error('[webgpu] uncaptured error:', e.error.message);
          };

          // Find or create canvas
          gpuCanvas = canvasContainer
            ? canvasContainer.querySelector('canvas') || document.createElement('canvas')
            : document.createElement('canvas');
          if (!gpuCanvas.parentElement && canvasContainer) {
            canvasContainer.appendChild(gpuCanvas);
          } else if (!gpuCanvas.parentElement) {
            document.body.appendChild(gpuCanvas);
          }
          gpuCanvas.width = gpuWidth || 800;
          gpuCanvas.height = gpuHeight || 600;

          gpuContext = gpuCanvas.getContext('webgpu');
          gpuFormat = navigator.gpu.getPreferredCanvasFormat();
          gpuContext.configure({
            device: gpuDevice,
            format: gpuFormat,
            alphaMode: 'opaque',
          });

          // Depth texture is created eagerly; whether a frame attaches it is
          // decided by the app's pipeline descriptor (depth flag).
          gpuMsaaTexture = gpuDevice.createTexture({
            size: [gpuCanvas.width, gpuCanvas.height],
            format: gpuFormat,
            sampleCount: GPU_MSAA,
            usage: GPUTextureUsage.RENDER_ATTACHMENT,
          });
          gpuDepthTexture = gpuDevice.createTexture({
            size: [gpuCanvas.width, gpuCanvas.height],
            format: 'depth24plus',
            sampleCount: GPU_MSAA,
            usage: GPUTextureUsage.RENDER_ATTACHMENT,
          });
          // One shared linear/clamp sampler for texture-sampling pipelines
          // (offscreen render targets read by post-process / reflection passes).
          gpuLinearSampler = gpuDevice.createSampler({
            magFilter: 'linear', minFilter: 'linear',
            addressModeU: 'clamp-to-edge', addressModeV: 'clamp-to-edge',
          });

          // No pipeline yet: it arrives from the app via host_gpu_raster_pipeline.
          gpuInitialized = true;
          gpuInitStatus = GPU_INIT_READY;
          console.log('[webgpu] Initialized', gpuCanvas.width, 'x', gpuCanvas.height);
        } catch (err) {
          console.error('[webgpu] Init failed:', err.message);
          gpuInitStatus = -3;
        }
        })();
        return GPU_INIT_PENDING;
      },

      // Create/replace render pipeline `id` from the app's descriptor blob
      // (little-endian; layout documented in gpu.rs):
      //   vertex_stride u32, attr_count u32,
      //   attrs: attr_count × { format u32, offset u32, location u32 },
      //   uniform_size u32,
      //   flags u32 (bit0 depth test, bit1 cull back, bit2 line-list,
      //              bit3 suppress depth write),
      //   shader_format u32, shader_len u32, shader bytes.
      host_gpu_raster_pipeline: (id, descPtr, descLen) => {
        if (!gpuInitialized || !gpuDevice) return -1;
        try {
          const view = new DataView(getKernel().exports.memory.buffer, descPtr, descLen);
          let off = 0;
          const stride = view.getUint32(off, true); off += 4;
          const attrCount = view.getUint32(off, true); off += 4;
          if (attrCount > 16) return -2;
          const attributes = [];
          for (let i = 0; i < attrCount; i++) {
            const fmt = view.getUint32(off, true); off += 4;
            const attrOff = view.getUint32(off, true); off += 4;
            const loc = view.getUint32(off, true); off += 4;
            const format = GPU_ATTR_FORMATS[fmt];
            if (!format) return -2;
            attributes.push({ shaderLocation: loc, offset: attrOff, format });
          }
          const uniformSize = view.getUint32(off, true); off += 4;
          const flags = view.getUint32(off, true); off += 4;
          const shaderFormat = view.getUint32(off, true); off += 4;
          const shaderLen = view.getUint32(off, true); off += 4;
          if (off + shaderLen > descLen) return -2;
          // This driver consumes WGSL (format 0) only. SPIR-V (1) and native
          // blobs (2+) are for the Vulkan / bare-metal drivers.
          if (shaderFormat !== 0) {
            console.error('[webgpu] unsupported shader_format ' + shaderFormat + ' (WebGPU driver takes WGSL=0)');
            return -4;
          }
          const wgsl = new TextDecoder().decode(kview(descPtr + off, shaderLen));

          const wantDepth = (flags & 1) !== 0;
          const cullBack = (flags & 2) !== 0;
          const lineList = (flags & 4) !== 0;
          const noDepthWrite = (flags & 8) !== 0;
          const wantBlend = (flags & 16) !== 0;        // bit4: alpha-over blend
          const texCount = (flags >> 8) & 0xF;         // bits8-11: sampled textures

          const module = gpuDevice.createShaderModule({ code: wgsl });
          // Shader/pipeline validation is DEFERRED in WebGPU: creation returns
          // an object even when compilation failed, and the error only surfaces
          // when the pipeline is first used. Report compile diagnostics
          // explicitly so a broken app shader is visible at creation.
          module.getCompilationInfo().then((info) => {
            for (const m of info.messages) {
              const line = '[webgpu] shader ' + m.type + ' @' + m.lineNum + ':' + m.linePos + ' — ' + m.message;
              if (m.type === 'error') console.error(line); else console.warn(line);
            }
          });
          // Bind group layout: uniform at binding 0 (if any), then each sampled
          // texture unit i as texture@(1+2i) + sampler@(2+2i). A post/reflection
          // shader declares the matching bindings; a plain scene shader sets
          // texCount=0 and gets the original uniform-only layout.
          const bglEntries = [];
          if (uniformSize > 0) {
            bglEntries.push({
              binding: 0,
              visibility: GPUShaderStage.VERTEX | GPUShaderStage.FRAGMENT,
              buffer: { type: 'uniform' },
            });
          }
          for (let i = 0; i < texCount; i++) {
            bglEntries.push({
              binding: 1 + 2 * i,
              visibility: GPUShaderStage.FRAGMENT,
              texture: { sampleType: 'float', viewDimension: '2d' },
            });
            bglEntries.push({
              binding: 2 + 2 * i,
              visibility: GPUShaderStage.FRAGMENT,
              sampler: { type: 'filtering' },
            });
          }
          const bindGroupLayout = gpuDevice.createBindGroupLayout({ entries: bglEntries });
          const desc = {
            layout: gpuDevice.createPipelineLayout({ bindGroupLayouts: [bindGroupLayout] }),
            vertex: {
              module,
              entryPoint: 'vs_main',
              // A vertexless pipeline (attr_count 0, e.g. a fullscreen post pass
              // that derives position from @builtin(vertex_index)) declares no
              // vertex buffers.
              buffers: attributes.length > 0 ? [{ arrayStride: stride, attributes }] : [],
            },
            fragment: {
              module,
              entryPoint: 'fs_main',
              targets: [{
                format: gpuFormat,
                ...(wantBlend ? { blend: {
                  color: { srcFactor: 'src-alpha', dstFactor: 'one-minus-src-alpha', operation: 'add' },
                  alpha: { srcFactor: 'one', dstFactor: 'one-minus-src-alpha', operation: 'add' },
                } } : {}),
              }],
            },
            primitive: {
              topology: lineList ? 'line-list' : 'triangle-list',
              cullMode: cullBack ? 'back' : 'none',
              frontFace: 'ccw',
            },
            multisample: { count: GPU_MSAA },
          };
          if (wantDepth) {
            desc.depthStencil = {
              format: 'depth24plus',
              // Overlays test against the scene but must not occlude it —
              // lessEqual so coincident overlay geometry passes.
              depthWriteEnabled: !noDepthWrite,
              depthCompare: noDepthWrite ? 'less-equal' : 'less',
            };
          }
          const entry = {
            pipeline: gpuDevice.createRenderPipeline(desc),
            depth: wantDepth,
            stride,
            // Never destroy() a possibly in-flight resource — a prior frame's
            // submit may still reference the old pipeline's uniform buffer.
            // Replacing the map entry drops the JS references; WebGPU keeps
            // them alive until their GPU work completes.
            uniformBuffer: null,
            bindGroup: null,
            bindGroupLayout,
            uniformSize,
            texCount,
            // Sampled-texture views bound via host_gpu_raster_bind_texture,
            // one per declared unit; the bind group is (re)built once every
            // unit is filled (a post pass draws nothing until then).
            boundViews: new Array(texCount).fill(null),
          };
          if (uniformSize > 0) {
            entry.uniformBuffer = gpuDevice.createBuffer({
              size: uniformSize,
              usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
            });
          }
          gpuRebuildBindGroup(entry);
          gpuPipelines.set(id, entry);
          gpuAnyDepth = [...gpuPipelines.values()].some((p) => p.depth);
          console.log('[webgpu] pipeline ' + id + ' created: stride=' + stride + ' attrs=' + attrCount +
            ' uniforms=' + uniformSize + 'B depth=' + wantDepth + ' cull=' + cullBack +
            (lineList ? ' lines' : '') + (noDepthWrite ? ' no-zwrite' : ''));
          return 0;
        } catch (e) {
          console.error('[webgpu] pipeline create failed:', e.message);
          return -3;
        }
      },

      // Poll WebGPU init status: 0 = ready, 1 = pending, 2 = not started,
      // <0 = error (-1 no WebGPU, -2 no adapter, -3 init threw). The module
      // calls `host_gpu_raster_init` once, then polls this until it is not PENDING.
      host_gpu_raster_poll_init: () => gpuInitStatus,

      // Resize canvas and recreate depth texture
      host_gpu_raster_resize: (width, height) => {
        if (!gpuInitialized || !gpuCanvas || !gpuDevice) return -1;
        gpuWidth = width;
        gpuHeight = height;
        gpuCanvas.width = width;
        gpuCanvas.height = height;
        // Old depth texture may be referenced by an in-flight frame — drop the
        // reference, don't destroy() (see the uniform-buffer note above).
        gpuMsaaTexture = gpuDevice.createTexture({
          size: [width, height],
          format: gpuFormat,
          sampleCount: GPU_MSAA,
          usage: GPUTextureUsage.RENDER_ATTACHMENT,
        });
        gpuDepthTexture = gpuDevice.createTexture({
          size: [width, height],
          format: 'depth24plus',
          sampleCount: GPU_MSAA,
          usage: GPUTextureUsage.RENDER_ATTACHMENT,
        });
        // Recreate canvas-tracking offscreen targets at the new size. A rebound
        // pipeline picks up the new colorView on its next bind_texture; apps
        // that keep a target bound should re-bind after a resize.
        for (const [id, t] of gpuTargets) {
          if (t.matchCanvas) gpuCreateTarget(id, t.reqW, t.reqH, t.withDepth);
        }
        return 0;
      },

      // Streamed vertex upload into a buffer slot: BEGIN allocates a staging
      // buffer; CHUNK appends; when the accumulated bytes reach the declared
      // total, the staging buffer atomically becomes the slot's active
      // buffer. Draws keep using the slot's previous geometry until then.
      host_gpu_raster_vertices_begin: (slot, totalLen) => {
        if (!gpuInitialized || !gpuDevice) return -1;
        const s = gpuSlot(slot);
        if (totalLen === 0) {
          // Empty mesh: swap in immediately (no CHUNK will follow)
          s.vb = null;
          s.bytes = 0;
          s.pendingVB = null;
          return 0;
        }
        s.pendingVB = gpuDevice.createBuffer({
          size: totalLen,
          usage: GPUBufferUsage.VERTEX | GPUBufferUsage.COPY_DST,
        });
        s.pendingTotal = totalLen;
        s.pendingCursor = 0;
        return 0;
      },
      host_gpu_raster_vertices_chunk: (slot, ptr, byteLen) => {
        const s = gpuSlots.get(slot);
        if (!s || !s.pendingVB) return -1;
        if (s.pendingCursor + byteLen > s.pendingTotal) {
          console.error('[webgpu] vertices_chunk overflow: slot=' + slot + ' cursor=' + s.pendingCursor +
            ' len=' + byteLen + ' total=' + s.pendingTotal);
          return -2;
        }
        try {
          gpuDevice.queue.writeBuffer(s.pendingVB, s.pendingCursor, kview(ptr, byteLen));
        } catch (e) {
          // A driver error must never propagate into the kernel step loop.
          console.error('[webgpu] vertices_chunk failed: slot=' + slot + ' cursor=' + s.pendingCursor +
            ' len=' + byteLen + ' total=' + s.pendingTotal + ' — ' + e.message);
          s.pendingVB = null;
          return -3;
        }
        s.pendingCursor += byteLen;
        if (s.pendingCursor >= s.pendingTotal) {
          // Swap in (drop the old reference — never destroy() an in-flight buffer)
          s.vb = s.pendingVB;
          s.bytes = s.pendingTotal;
          s.pendingVB = null;
          console.log('[webgpu] slot ' + slot + ' streamed upload complete: ' + s.bytes + ' bytes');
        }
        return 0;
      },

      // Single-shot vertex upload: replaces the slot's buffer. Layout is
      // opaque; vertex count derives at draw time from the pipeline's stride.
      host_gpu_raster_upload_vertices: (slot, ptr, byteLen) => {
        if (!gpuInitialized || !gpuDevice) return -1;
        try {
          const s = gpuSlot(slot);
          const data = kview(ptr, byteLen);
          // Replace, never destroy(): the old buffer may be in flight.
          s.vb = gpuDevice.createBuffer({
            size: byteLen,
            usage: GPUBufferUsage.VERTEX | GPUBufferUsage.COPY_DST,
          });
          gpuDevice.queue.writeBuffer(s.vb, 0, data);
          s.bytes = byteLen;
          return 0;
        } catch (e) {
          console.error('[webgpu] upload_vertices failed: slot=' + slot + ' len=' + byteLen + ' — ' + e.message);
          return -3;
        }
      },

      // Upload index data (u32 indices) for a slot
      host_gpu_raster_upload_indices: (slot, ptr, byteLen) => {
        if (!gpuInitialized || !gpuDevice) return -1;
        try {
          const s = gpuSlot(slot);
          const data = kview(ptr, byteLen);
          // Replace, never destroy(): the old buffer may be in flight.
          s.ib = gpuDevice.createBuffer({
            size: byteLen,
            usage: GPUBufferUsage.INDEX | GPUBufferUsage.COPY_DST,
          });
          gpuDevice.queue.writeBuffer(s.ib, 0, data);
          s.indexCount = (byteLen / 4) | 0;
          return s.indexCount;
        } catch (e) {
          console.error('[webgpu] upload_indices failed: slot=' + slot + ' len=' + byteLen + ' — ' + e.message);
          return -3;
        }
      },

      // Streamed index upload — same staging semantics as the vertex pair.
      host_gpu_raster_indices_begin: (slot, totalLen) => {
        if (!gpuInitialized || !gpuDevice) return -1;
        const s = gpuSlot(slot);
        if (totalLen === 0) {
          s.ib = null;
          s.indexCount = 0;
          s.pendingIB = null;
          return 0;
        }
        s.pendingIB = gpuDevice.createBuffer({
          size: totalLen,
          usage: GPUBufferUsage.INDEX | GPUBufferUsage.COPY_DST,
        });
        s.pendingITotal = totalLen;
        s.pendingICursor = 0;
        return 0;
      },
      host_gpu_raster_indices_chunk: (slot, ptr, byteLen) => {
        const s = gpuSlots.get(slot);
        if (!s || !s.pendingIB) return -1;
        if (s.pendingICursor + byteLen > s.pendingITotal) {
          console.error('[webgpu] indices_chunk overflow: slot=' + slot);
          return -2;
        }
        try {
          gpuDevice.queue.writeBuffer(s.pendingIB, s.pendingICursor, kview(ptr, byteLen));
        } catch (e) {
          console.error('[webgpu] indices_chunk failed: slot=' + slot + ' — ' + e.message);
          s.pendingIB = null;
          return -3;
        }
        s.pendingICursor += byteLen;
        if (s.pendingICursor >= s.pendingITotal) {
          s.ib = s.pendingIB;
          s.indexCount = (s.pendingITotal / 4) | 0;
          s.pendingIB = null;
        }
        return 0;
      },

      // Write bytes verbatim into pipeline `id`'s uniform buffer. The layout
      // is a contract between the app's shader and the app's producer module.
      host_gpu_raster_set_uniforms: (id, ptr, byteLen) => {
        const p = gpuPipelines.get(id);
        if (!gpuInitialized || !gpuDevice || !p || !p.uniformBuffer) return -1;
        try {
          const data = kview(ptr, Math.min(byteLen, p.uniformBuffer.size));
          gpuDevice.queue.writeBuffer(p.uniformBuffer, 0, data);
          return 0;
        } catch (e) {
          console.error('[webgpu] set_uniforms failed: id=' + id + ' len=' + byteLen + ' — ' + e.message);
          return -3;
        }
      },

      // Begin a frame (clear and start render pass). The depth attachment is
      // included when any registered pipeline declares depth — every pipeline
      // drawn in the pass must then declare a compatible depthStencil state
      // (that is the app's contract; overlays use the no-depth-write flag).
      host_gpu_raster_begin_frame: (r, g, b) => {
        if (!gpuInitialized || !gpuDevice || !gpuContext) {
          return -1;
        }
        if (gpuFrameSubmittedThisVsync) return -2; // one frame per refresh
        gpuEncoder = gpuDevice.createCommandEncoder();
        // Single-pass form: one swapchain pass, depth iff any pipeline uses it.
        return gpuOpenPass(0, r, g, b, gpuAnyDepth && !!gpuDepthTexture);
      },

      // Create/replace offscreen render target `id` (id 0 is the swapchain and
      // is rejected). `flags` bit0 = allocate a depth attachment. w/h of 0 track
      // the canvas size. Device state — safe to call outside a frame.
      host_gpu_raster_target: (id, w, h, flags) => {
        if (!gpuInitialized || !gpuDevice) return -1;
        if (id === 0) return -2;
        try {
          gpuCreateTarget(id >>> 0, w >>> 0, h >>> 0, (flags & 1) !== 0);
          return 0;
        } catch (e) {
          console.error('[webgpu] target create failed: id=' + id + ' — ' + e.message);
          return -3;
        }
      },

      // Begin a render pass into `targetId` (0 = swapchain) with a clear color.
      // `flags` bit0 = attach depth. The first begin_pass of a frame opens the
      // command encoder and takes the vsync gate (returns -2 if a frame was
      // already submitted this refresh); a later begin_pass auto-ends the
      // previous pass. This is the multi-pass entry point; begin_frame is the
      // single-pass form. Both are ended by end_frame.
      host_gpu_raster_begin_pass: (targetId, r, g, b, flags) => {
        if (!gpuInitialized || !gpuDevice || !gpuContext) return -1;
        if (!gpuEncoder) {
          if (gpuFrameSubmittedThisVsync) return -2;
          gpuEncoder = gpuDevice.createCommandEncoder();
        } else if (gpuPass) {
          gpuPass.end();
          gpuPass = null;
        }
        return gpuOpenPass(targetId >>> 0, r, g, b, (flags & 1) !== 0);
      },

      // Bind offscreen target `targetId`'s (resolved) color texture to sampled
      // unit `unit` of pipeline `pipelineId`. Rebuilds the pipeline's bind group;
      // the pipeline draws once all its declared units are bound. Device state.
      host_gpu_raster_bind_texture: (pipelineId, unit, targetId) => {
        const p = gpuPipelines.get(pipelineId);
        if (!p) return -1;
        if (unit >= p.texCount) return -2;
        const t = gpuTargets.get(targetId);
        if (!t) return -3;
        p.boundViews[unit] = t.colorView;
        try { gpuRebuildBindGroup(p); } catch (e) {
          console.error('[webgpu] bind_texture failed: ' + e.message); return -4;
        }
        return 0;
      },

      // Draw a vertexless pipeline (fullscreen post/reflection pass): no vertex
      // buffer, `count` vertices from @builtin(vertex_index) — 3 for a
      // fullscreen triangle. Skips if the pipeline's textures are not all bound.
      host_gpu_raster_draw_fullscreen: (id, count) => {
        if (!gpuPass) return -1;
        const p = gpuPipelines.get(id);
        if (!p) return 0;
        if (p.texCount > 0 && !p.bindGroup) return 0; // textures not all bound yet
        gpuPass.setPipeline(p.pipeline);
        if (p.bindGroup) gpuPass.setBindGroup(0, p.bindGroup);
        gpuPass.draw(count);
        return 0;
      },

      // Draw buffer-slot geometry with pipeline `id`. Pipeline and bind group
      // are set per draw so multiple (pipeline, slot) pairs can render within
      // one frame (e.g. world mesh then highlight overlay).
      host_gpu_raster_draw: (id, slot) => {
        if (!gpuPass) return -1;
        const p = gpuPipelines.get(id);
        const s = gpuSlots.get(slot);
        if (!p || !s || !s.vb || !s.bytes) return 0; // nothing to draw yet
        gpuPass.setPipeline(p.pipeline);
        if (p.bindGroup) gpuPass.setBindGroup(0, p.bindGroup);
        gpuPass.setVertexBuffer(0, s.vb);
        if (s.ib && s.indexCount > 0) {
          gpuPass.setIndexBuffer(s.ib, 'uint32');
          gpuPass.drawIndexed(s.indexCount);
        } else {
          const count = (s.bytes / p.stride) | 0;
          if (count > 0) gpuPass.draw(count);
        }
        return 0;
      },

      // End frame and present. Ends the open pass (if any) and submits the whole
      // encoder — so a multi-pass frame (scene target → post to swapchain)
      // presents all its passes in one submit.
      host_gpu_raster_end_frame: () => {
        if (!gpuDevice || !gpuEncoder) {
          return -1;
        }
        if (gpuPass) { gpuPass.end(); gpuPass = null; }
        gpuDevice.queue.submit([gpuEncoder.finish()]);
        gpuEncoder = null;
        gpuFrameSubmittedThisVsync = true;
        return 0;
      },

      // Get canvas dimensions
      host_gpu_raster_get_size: (outPtr) => {
        if (!gpuCanvas) return -1;
        const view = new DataView(getKernel().exports.memory.buffer, outPtr, 8);
        view.setUint32(0, gpuCanvas.width, true);
        view.setUint32(4, gpuCanvas.height, true);
        return 0;
      },
    };


    // ── Generic GPU compute surface (host_gpu_compute_*) ──────────────
    // Backend-agnostic GPGPU driver, the compute sibling of webgpuShim. The app
    // supplies compute shaders + buffers + dispatch lists as data; this shim
    // holds ZERO application knowledge (no baked pipelines, no pixel formats).
    // WebGPU backend today; a Vulkan or bare-metal driver implements the same
    // host_gpu_compute_* surface and the module above is unchanged.
    let cpDevice = null;
    let cpInitStatus = GPU_INIT_NOT_STARTED;
    const cpPipelines = new Map(); // id -> GPUComputePipeline
    const cpBuffers = new Map(); // id -> { buf, size }
    let cpCanvas = null, cpCtx = null, cpImage = null;
    let cpRead = null, cpReadN = 0, cpReadBusy = false;
    let cpRb = null; // pending readback: { staging, ready } (one outstanding)
    let cpPresentLogged = false, cpMapLogged = false;

    function cpEnsureCanvas(w, h) {
      if (cpCanvas && cpCanvas.width === w && cpCanvas.height === h) return;
      if (offscreenSurface) {
        // Worker mode: draw into the OffscreenCanvas transferred from the page —
        // the ONLY surface that composites here. A Worker's `document` is a stub,
        // so a `createElement('canvas')` would be detached and never visible.
        cpCanvas = offscreenSurface;
        if (cpCanvas.width !== w) cpCanvas.width = w;
        if (cpCanvas.height !== h) cpCanvas.height = h;
      } else {
        cpCanvas = document.createElement('canvas');
        cpCanvas.width = w; cpCanvas.height = h;
        cpCanvas.style.maxWidth = '100%';
        cpCanvas.style.height = 'auto';
        cpCanvas.style.imageRendering = 'pixelated';
        if (canvasContainer) canvasContainer.replaceChildren(cpCanvas);
        else document.body.appendChild(cpCanvas);
      }
      cpCtx = cpCanvas.getContext('2d');
      cpImage = cpCtx.createImageData(w, h);
    }

    const computeShim = {
      // Kick off async device acquire; returns PENDING. Module polls poll_init.
      host_gpu_compute_init: () => {
        if (cpDevice) return GPU_INIT_READY;
        if (cpInitStatus === GPU_INIT_PENDING) return GPU_INIT_PENDING;
        if (!navigator.gpu) { console.error('[compute] no WebGPU'); cpInitStatus = -1; return -1; }
        cpInitStatus = GPU_INIT_PENDING;
        (async () => {
          try {
            const adapter = await navigator.gpu.requestAdapter();
            if (!adapter) throw new Error('no adapter');
            cpDevice = await adapter.requestDevice();
            cpDevice.lost.then((info) => {
              console.error('[compute] device lost:', info.message);
              cpDevice = null; cpPipelines.clear(); cpBuffers.clear();
              cpRead = null; cpReadN = 0; cpReadBusy = false; cpRb = null;
              cpInitStatus = GPU_INIT_NOT_STARTED;
            });
            cpInitStatus = GPU_INIT_READY;
            console.log('[compute] ready (WebGPU compute)');
          } catch (e) { console.error('[compute] init failed:', e.message); cpInitStatus = -3; }
        })();
        return GPU_INIT_PENDING;
      },
      host_gpu_compute_poll_init: () => cpInitStatus,

      // Create/replace compute pipeline `id`. shader_fmt: 0=WGSL utf8,
      // 1=SPIR-V (a native backend's job — the browser takes WGSL only).
      host_gpu_compute_pipeline: (id, fmt, entryPtr, entryLen, shaderPtr, shaderLen) => {
        if (!cpDevice) return -1;
        if (fmt !== 0) { console.error('[compute] unsupported shader_fmt', fmt); return -2; }
        try {
          const entry = kstr(entryPtr, entryLen);
          const wgsl = kstr(shaderPtr, shaderLen);
          const module = cpDevice.createShaderModule({ code: wgsl });
          // ASYNC creation: a synchronous createComputePipeline stalls the
          // whole device timeline while the backend compiles (minutes for a
          // large kernel on a software adapter) — every later submit,
          // present readback and map queues behind it. Async keeps the
          // device live; DISPATCHes naming a still-compiling pipeline are
          // skipped (drop-until-ready is the app contract during init).
          cpPipelines.delete(id >>> 0);
          cpDevice.createComputePipelineAsync({ layout: 'auto', compute: { module, entryPoint: entry } })
            .then((pipeline) => {
              cpPipelines.set(id >>> 0, pipeline);
              console.log('[compute] pipeline', id, '(' + entry + ', ' + wgsl.length + ' B) ready');
            })
            .catch((e) => console.error('[compute] pipeline', id, '(' + entry + ') failed:', e.message));
          return 0;
        } catch (e) { console.error('[compute] pipeline', id, 'failed:', e.message); return -3; }
      },

      // Allocate buffer `id`. usage bitmask: 1=storage 2=uniform 4=copy-src
      // 8=copy-dst 16=map-read. COPY_DST is always set so UPLOAD_BUFFER works.
      host_gpu_compute_buffer: (id, size, usage) => {
        if (!cpDevice) return -1;
        try {
          let u = GPUBufferUsage.COPY_DST;
          if (usage & 1) u |= GPUBufferUsage.STORAGE;
          if (usage & 2) u |= GPUBufferUsage.UNIFORM;
          if (usage & 4) u |= GPUBufferUsage.COPY_SRC;
          if (usage & 16) u |= GPUBufferUsage.MAP_READ;
          const existing = cpBuffers.get(id >>> 0);
          if (existing) existing.buf.destroy();
          const buf = cpDevice.createBuffer({ size: Math.max(size >>> 0, 16), usage: u });
          cpBuffers.set(id >>> 0, { buf, size: size >>> 0 });
          return 0;
        } catch (e) { console.error('[compute] buffer', id, 'failed:', e.message); return -3; }
      },

      host_gpu_compute_upload: (id, offset, ptr, len) => {
        if (!cpDevice) return -1;
        const e = cpBuffers.get(id >>> 0);
        if (!e) return -1;
        // Copy out of wasm memory: writeBuffer needs a source that isn't a live
        // view onto the module's (movable) memory.
        const data = kview(ptr, len).slice();
        cpDevice.queue.writeBuffer(e.buf, offset >>> 0, data);
        return 0;
      },

      // Decode + execute the DISPATCH/COPY sub-command list in one encoder.
      host_gpu_compute_submit: (listPtr, listLen) => {
        if (!cpDevice) return -1;
        const view = kview(listPtr, listLen);
        const dv = new DataView(view.buffer, view.byteOffset, listLen);
        const enc = cpDevice.createCommandEncoder();
        let off = 0, pass = null;
        try {
          while (off < listLen) {
            const sub = dv.getUint8(off); off += 1;
            if (sub === 0x01) { // DISPATCH
              const pipeId = dv.getUint32(off, true); off += 4;
              const nbind = dv.getUint32(off, true); off += 4;
              const entries = [];
              for (let i = 0; i < nbind; i++) {
                const binding = dv.getUint32(off, true); off += 4;
                const bufId = dv.getUint32(off, true); off += 4;
                const be = cpBuffers.get(bufId >>> 0);
                if (be) entries.push({ binding, resource: { buffer: be.buf } });
              }
              const gx = dv.getUint32(off, true); off += 4;
              const gy = dv.getUint32(off, true); off += 4;
              const gz = dv.getUint32(off, true); off += 4;
              const pipe = cpPipelines.get(pipeId >>> 0);
              if (!pipe) continue; // unknown pipeline; framing already advanced
              const bg = cpDevice.createBindGroup({ layout: pipe.getBindGroupLayout(0), entries });
              if (!pass) pass = enc.beginComputePass();
              pass.setPipeline(pipe); pass.setBindGroup(0, bg);
              pass.dispatchWorkgroups(gx, gy, gz);
            } else if (sub === 0x02) { // COPY (outside any compute pass)
              const src = dv.getUint32(off, true); off += 4;
              const srcOff = dv.getUint32(off, true); off += 4;
              const dst = dv.getUint32(off, true); off += 4;
              const dstOff = dv.getUint32(off, true); off += 4;
              const len = dv.getUint32(off, true); off += 4;
              if (pass) { pass.end(); pass = null; }
              const s = cpBuffers.get(src >>> 0), d = cpBuffers.get(dst >>> 0);
              if (s && d) enc.copyBufferToBuffer(s.buf, srcOff >>> 0, d.buf, dstOff >>> 0, len >>> 0);
            } else { console.error('[compute] bad sub-op', sub, 'at', off - 1); break; }
          }
          if (pass) pass.end();
          cpDevice.queue.submit([enc.finish()]);
          return 0;
        } catch (e) { console.error('[compute] submit failed:', e.message); return -3; }
      },

      // Blit buffer `id` (w*h u32, r|g<<8|b<<16) to the canvas via readback.
      host_gpu_compute_present: (bufId, w, h) => {
        if (!cpDevice) return -1;
        const e = cpBuffers.get(bufId >>> 0);
        if (!cpPresentLogged) { cpPresentLogged = true; console.log('[compute] first present buf=' + bufId + ' ' + w + 'x' + h + (e ? '' : ' (UNKNOWN BUFFER)')); }
        if (!e) return -1;
        const n = (w >>> 0) * (h >>> 0);
        if (n === 0) return -1;
        if (cpReadBusy) return 0; // drop a frame while a readback is in flight
        if (!cpRead || cpReadN < n) {
          if (cpRead) cpRead.destroy();
          cpRead = cpDevice.createBuffer({ size: n * 4, usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST });
          cpReadN = n;
        }
        cpReadBusy = true;
        const enc = cpDevice.createCommandEncoder();
        enc.copyBufferToBuffer(e.buf, 0, cpRead, 0, n * 4);
        cpDevice.queue.submit([enc.finish()]);
        cpRead.mapAsync(GPUMapMode.READ, 0, n * 4).then(() => {
          const got = new Uint32Array(cpRead.getMappedRange(0, n * 4));
          if (!cpMapLogged) { cpMapLogged = true; console.log('[compute] first present mapped (' + w + 'x' + h + ')'); }
          cpEnsureCanvas(w, h);
          const dst = cpImage.data;
          for (let i = 0; i < n; i++) { const v = got[i]; const o = i * 4; dst[o] = v & 0xff; dst[o + 1] = (v >> 8) & 0xff; dst[o + 2] = (v >> 16) & 0xff; dst[o + 3] = 255; }
          cpCtx.putImageData(cpImage, 0, 0);
          cpRead.unmap();
          cpReadBusy = false;
        }).catch((err) => { console.error('[compute] present readback:', err.message); cpReadBusy = false; });
        return 0;
      },

      // Read `len` bytes from buffer `bufId` at `offset` back to the CPU. Async:
      // the first call kicks off copy+map and returns -1 (pending); a later call
      // with the mapped result copies into out_ptr and returns `len`. One
      // outstanding at a time (a new request while busy stays pending).
      host_gpu_compute_readback: (bufId, offset, outPtr, len) => {
        if (!cpDevice) return -1;
        len = len >>> 0;
        if (cpRb && cpRb.ready) {
          try {
            const src = new Uint8Array(cpRb.staging.getMappedRange(0, len));
            kview(outPtr, len).set(src.subarray(0, len));
          } catch (e) { console.error('[compute] readback copy:', e.message); }
          cpRb.staging.unmap();
          cpRb.staging.destroy();
          cpRb = null;
          return len;
        }
        if (cpRb) return -1; // in flight
        const e = cpBuffers.get(bufId >>> 0);
        if (!e || len === 0) return -1;
        const staging = cpDevice.createBuffer({ size: len, usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST });
        const enc = cpDevice.createCommandEncoder();
        enc.copyBufferToBuffer(e.buf, offset >>> 0, staging, 0, len);
        cpDevice.queue.submit([enc.finish()]);
        cpRb = { staging, ready: false };
        staging.mapAsync(GPUMapMode.READ, 0, len)
          .then(() => { if (cpRb) cpRb.ready = true; })
          .catch((err) => { console.error('[compute] readback map:', err.message); if (cpRb) { cpRb.staging.destroy(); cpRb = null; } });
        return -1;
      },
    };

    return {
      env: Object.assign(
        {},
        universal,
        fetchShim,
        objectShim,
        nsShim,
        inputShim,
        keyboardShim,
        pointerShim,
        buttonShim,
        gamepadShim,
        actionShim,
        surfaceTraitsShim,
        wsShim,
        audioShim,
        canvasShim,
        cameraShim,
        displayCaptureShim,
        scanOutShim,
        terminalShim,
        imageShim,
        moduleShim,
        webgpuShim,
        computeShim
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
  window.fluxor.createAudioScheduler = createAudioScheduler; // shared by the Worker bridge
})();
