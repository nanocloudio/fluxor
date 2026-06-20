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

    // Background-persist `bytes` for `key` to OPFS. Fire-and-forget: the
    // synchronous PUT has already populated `objStore`, so a failure here
    // only costs durability, never correctness this session.
    const opfsPersist = (key, bytes) => {
      opfsResolveFile(key, true).then(async (fh) => {
        if (!fh) return;
        const w = await fh.createWritable();
        await w.write(bytes);
        await w.close();
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
        if (!root || typeof root.entries !== 'function') return;
        const walk = async (dir, prefix) => {
          for await (const [name, handle] of dir.entries()) {
            const path = prefix ? `${prefix}/${name}` : name;
            if (handle.kind === 'directory') {
              await walk(handle, path);
            } else {
              try {
                const file = await handle.getFile();
                const buf = new Uint8Array(await file.arrayBuffer());
                if (!objStore.has(path)) objStore.set(path, buf);
              } catch (_) { /* skip unreadable entry */ }
            }
          }
        };
        await walk(root, '');
      }).catch(() => { /* no OPFS / iteration unsupported — skip */ });
    };
    const opfsHydrateP = opfsHydrate();

    // ── namespace index (host_ns_*, storage.namespace enumeration) ───
    // Directory enumeration over the SAME flat key space the object tier
    // writes (`objStore`, OPFS-backed) unioned with a fetched manifest of
    // shipped, immutable content. `/` is the hierarchy separator, so a
    // key "saves/tetris" makes LIST("") yield "saves" (namespace) and
    // LIST("saves/") yield "tetris" (object). Backs src/platform/wasm/
    // namespace.rs; lets `storage.namespace` consumers (truffle's
    // scanner) walk a tree the browser has no POSIX readdir for.
    const manifestIndex = new Map(); // key -> { size, mtime, etag(string) }
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
          const rawKey = kstr(keyPtr, keyLen);
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
          const rawKey = kstr(keyPtr, keyLen);
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
            while (true) {
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
        view.setUint8(22, 0);
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

    // ── Audio sink (wasm_browser_audio) ──────────────────────────────
    // AudioContext is created lazily on the first `host_audio_play`
    // call and locked to the source sample rate.
    let audioCtx = null;
    let audioSchedTime = 0;
    // Scheduling cushion. The kernel emits PCM in bursts (tied to the
    // requestAnimationFrame step loop), so blocks must be queued ahead of
    // the audio clock — otherwise any late block underruns and clicks.
    // With the producer rate fixed at the source (gb_core now paces at a
    // true 59.726 Hz and ships the APU's exact per-frame sample count),
    // this cushion only has to absorb short scheduling jitter — rAF
    // granularity and the odd GC pause — not a steady drift. ~120ms is
    // ample for that at a low latency. MAX_AHEAD caps the queue so a
    // transient burst can't grow latency without bound.
    const AUDIO_LOOKAHEAD = 0.12;
    const AUDIO_MAX_AHEAD = 0.4;
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
    const UNLOCK_EVENTS = ['pointerdown', 'pointerup', 'click', 'keydown', 'touchstart', 'touchend'];
    function removeUnlockListeners() {
      for (const e of UNLOCK_EVENTS) document.removeEventListener(e, unlockAudioOnGesture, true);
    }
    function unlockAudioOnGesture() {
      const ctx = ensureAudio(44100);
      if (ctx.state === 'running') { removeUnlockListeners(); return; }
      // resume() must run inside the gesture's call stack. Only stop
      // listening once it has actually taken effect — a single failed or
      // ignored attempt must NOT disarm the unlock, or audio stays dead
      // for the rest of the session (the original bug: listeners were
      // removed after the first gesture regardless of the outcome).
      ctx.resume().then(() => {
        if (ctx.state === 'running') removeUnlockListeners();
      }).catch(() => {});
    }
    for (const e of UNLOCK_EVENTS) document.addEventListener(e, unlockAudioOnGesture, true);

    // Diagnostic counters (surfaced once per second through onLog).
    let audioPlayCalls = 0;
    let audioPlayBytesAccepted = 0;
    let audioPlayBytesDropped  = 0;
    let audioPlayLastSurfaced  = 0;
    let audioPeakAbs = 0;
    let audioUnderruns = 0;
    function surfaceAudioStats() {
      const now = performance.now();
      if ((now - audioPlayLastSurfaced) < 1000) return;
      audioPlayLastSurfaced = now;
      const ctxState = audioCtx ? audioCtx.state : 'no-ctx';
      const ctxRate  = audioCtx ? audioCtx.sampleRate : 0;
      onLog(2,
        `[audio] calls=${audioPlayCalls} bytes_played=${audioPlayBytesAccepted}` +
        ` bytes_dropped=${audioPlayBytesDropped} underruns=${audioUnderruns}` +
        ` peak=${audioPeakAbs} ctx=${ctxState} hw_rate=${ctxRate}`);
      audioPeakAbs = 0;
    }

    const audioShim = {
      host_audio_play: (ptr, len, sampleRate, channels) => {
        audioPlayCalls++;
        const ctx = ensureAudio(sampleRate);
        if (ctx.state !== 'running') {
          // Context not resumed yet (autoplay policy). Re-attempt the
          // resume opportunistically — host_audio_play runs every frame,
          // so the moment a user gesture has happened this catches up
          // and starts playback instead of dropping forever.
          if (ctx.state === 'suspended') ctx.resume().catch(() => {});
          audioPlayBytesDropped += len;
          surfaceAudioStats();
          return;
        }
        const i16 = new Int16Array(getKernel().exports.memory.buffer.slice(ptr, ptr + len));
        const ch = Math.max(1, channels | 0);
        // Publish the live audio config to the Surface Traits authority
        // (rfc_surface_traits.md). The publisher reads this each recompute; on a
        // real change, nudge it to emit a fresh record. Guarded so this runs
        // once per config change, not every audio frame.
        const rateHz = ctx.sampleRate | 0;
        const prevAudio = window.__fluxor_audio_traits;
        if (!prevAudio || prevAudio.channels !== ch || prevAudio.rateHz !== rateHz) {
          window.__fluxor_audio_traits = { channels: ch, rateHz };
          if (window.__fluxor_surface_traits && window.__fluxor_surface_traits.schedule) {
            window.__fluxor_surface_traits.schedule();
          }
        }
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
        // Underrun: the queue drained to (or below) the clock since the
        // last block — a gap was emitted. Restart AHEAD of the clock so
        // the next blocks have a cushion again, instead of butting right
        // up against `now` (which underruns again on the next late block).
        if (audioSchedTime < now + 0.005) {
          audioSchedTime = now + AUDIO_LOOKAHEAD;
          audioUnderruns++;
        } else if (audioSchedTime > now + AUDIO_MAX_AHEAD) {
          // Producer running ahead of real time — let it ride; the queue
          // is bounded by how fast PCM actually arrives.
          audioSchedTime = now + AUDIO_MAX_AHEAD;
        }
        src.start(audioSchedTime);
        audioSchedTime += frames / sampleRate;
        audioPlayBytesAccepted += len;
        surfaceAudioStats();
      },
      // How much audio is currently queued ahead of the playback clock,
      // in microseconds (`audioSchedTime - currentTime`). The kernel sink
      // reads this to pace itself to the WebAudio clock: it forwards PCM
      // only until this lead reaches its target, then HOLDS — leaving the
      // rest in its input channel so back-pressure propagates upstream and
      // the pipeline is locked to real time instead of free-running at the
      // browser's frame rate (which overruns the scheduler and overlaps
      // blocks → garbled, uneven-tempo playback). Returns 0 until the
      // context is running, so pre-gesture frames still drain (and drop)
      // exactly as before.
      host_audio_lead_us: () => {
        if (!audioCtx || audioCtx.state !== 'running') return 0n;
        const lead = audioSchedTime - audioCtx.currentTime;
        return BigInt(lead > 0 ? Math.round(lead * 1_000_000) : 0);
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
          fetch(url, { headers: { Range: `bytes=${off}-${off + len - 1}` } })
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
              console.error(`host_image_decode_url[${handle}] failed: ${err.message}`);
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
