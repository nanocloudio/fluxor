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
    // Resume cushion after an underrun (seconds). A producer that keeps up
    // with the audio clock underruns only on isolated scheduling jitter, so
    // the cushion stays at the low-latency floor. A producer running BELOW
    // real time (e.g. the wasm N64 LLE core at ~25% of real time on a slow
    // host) drains the queue faster than it fills and underruns on every
    // reset; those underruns CLUSTER, and we then deepen the cushion so the
    // dropouts are FEWER and LONGER — one gap then a continuous stretch —
    // instead of a rapid stop/start chatter at the frame rate. The production
    // deficit fixes the total silence either way; this only trades gap
    // frequency for gap length (much less grating on a starved target) and
    // costs the healthy real-time case nothing — the cushion relaxes straight
    // back to the floor once underruns stop clustering.
    const AUDIO_CUSHION_MIN = 0.12; // low-latency floor (healthy producer)
    const AUDIO_CUSHION_MAX = 0.35; // deepest cushion under sustained starve
    const AUDIO_CLUSTER_WINDOW = 0.7; // underruns closer than this = starved
    const AUDIO_MAX_AHEAD = 0.4;
    let audioCushion = AUDIO_CUSHION_MIN;
    let audioPrevUnderrunT = -1;
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
      const lead = audioCtx && audioCtx.state === 'running'
        ? Math.max(0, audioSchedTime - audioCtx.currentTime) : 0;
      onLog(2,
        `[audio] calls=${audioPlayCalls} bytes_played=${audioPlayBytesAccepted}` +
        ` bytes_dropped=${audioPlayBytesDropped} underruns=${audioUnderruns}` +
        ` peak=${audioPeakAbs} ctx=${ctxState} hw_rate=${ctxRate}` +
        ` cushion=${audioCushion.toFixed(2)} lead=${lead.toFixed(2)}`);
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
          // Clustered underruns (closer together than CLUSTER_WINDOW) mean the
          // producer is below real time → grow the cushion toward its ceiling
          // so the next gap is longer but rarer. An isolated underrun (a one-off
          // GC / rAF stall on an otherwise real-time producer) relaxes it back
          // to the floor, keeping latency low once the producer recovers.
          if (audioPrevUnderrunT >= 0 && (now - audioPrevUnderrunT) < AUDIO_CLUSTER_WINDOW) {
            audioCushion = Math.min(AUDIO_CUSHION_MAX, audioCushion * 1.5 + 0.02);
          } else {
            audioCushion = AUDIO_CUSHION_MIN;
          }
          audioPrevUnderrunT = now;
          audioSchedTime = now + audioCushion;
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

    // ── WebGPU 3D rendering shim (wasm_browser_webgpu) ───────────────
    //
    // Provides WebGPU device/context access for 3D rendering modules.
    // The module sends vertex data and draw commands; the shim manages
    // the WebGPU pipeline and presents frames to a canvas surface.
    //
    // State is managed in JS (device, pipeline, buffers) since WebGPU
    // objects can't be serialized to WASM memory. The module calls
    // host_webgpu_* imports which manipulate this JS-side state.
    let gpuDevice = null;
    let gpuContext = null;
    let gpuCanvas = null;
    let gpuPipeline = null;
    let gpuDepthTexture = null;
    let gpuVertexBuffer = null;
    let gpuIndexBuffer = null;
    let gpuUniformBuffer = null;
    let gpuBindGroup = null;
    let gpuEncoder = null;
    let gpuPass = null;
    let gpuVertexCount = 0;
    let gpuIndexCount = 0;
    let gpuInitialized = false;
    // WebGPU init is asynchronous (adapter/device requests are Promises), but a
    // Wasm import is synchronous — so `host_webgpu_init` cannot await and return
    // the real result inline (the module would observe a coerced Promise and
    // "succeed" before the device exists). Instead init kicks off the async work
    // and records progress here; the module polls `host_webgpu_poll_init`.
    // Status: 0 = ready, 1 = pending, 2 = not started, <0 = error (-1 no WebGPU,
    // -2 no adapter, -3 init threw).
    const GPU_INIT_READY = 0;
    const GPU_INIT_PENDING = 1;
    const GPU_INIT_NOT_STARTED = 2;
    let gpuInitStatus = GPU_INIT_NOT_STARTED;
    let gpuWidth = 0;
    let gpuHeight = 0;

    // Basic vertex shader for 3D voxel rendering
    const gpuVertexShader = `
      struct Uniforms {
        viewProj: mat4x4<f32>,
        camPos: vec4<f32>,
        time: f32,
        fogDist: f32,
        _pad: vec2<f32>,
      };
      @group(0) @binding(0) var<uniform> uniforms: Uniforms;

      struct VertexInput {
        @location(0) position: vec3<f32>,
        @location(1) color: vec3<f32>,
        @location(2) normal: vec3<f32>,
      };

      struct VertexOutput {
        @builtin(position) clip_position: vec4<f32>,
        @location(0) color: vec3<f32>,
        @location(1) world_pos: vec3<f32>,
        @location(2) normal: vec3<f32>,
      };

      @vertex
      fn vs_main(in: VertexInput) -> VertexOutput {
        var out: VertexOutput;
        out.clip_position = uniforms.viewProj * vec4<f32>(in.position, 1.0);
        out.color = in.color;
        out.world_pos = in.position;
        out.normal = in.normal;
        return out;
      }
    `;

    const gpuFragmentShader = `
      struct Uniforms {
        viewProj: mat4x4<f32>,
        camPos: vec4<f32>,
        time: f32,
        fogDist: f32,
        _pad: vec2<f32>,
      };
      @group(0) @binding(0) var<uniform> uniforms: Uniforms;

      struct VertexOutput {
        @builtin(position) clip_position: vec4<f32>,
        @location(0) color: vec3<f32>,
        @location(1) world_pos: vec3<f32>,
        @location(2) normal: vec3<f32>,
      };

      @fragment
      fn fs_main(in: VertexOutput) -> @location(0) vec4<f32> {
        // Simple directional lighting
        let lightDir = normalize(vec3<f32>(0.5, 1.0, 0.3));
        let ambient = 0.4;
        let diffuse = max(dot(in.normal, lightDir), 0.0) * 0.6;
        let lit = in.color * (ambient + diffuse);

        // Distance fog
        let dist = length(in.world_pos - uniforms.camPos.xyz);
        let fogFactor = clamp(dist / uniforms.fogDist, 0.0, 1.0);
        let fogColor = vec3<f32>(0.6, 0.8, 1.0);
        let final = mix(lit, fogColor, fogFactor * fogFactor);

        return vec4<f32>(final, 1.0);
      }
    `;

    const webgpuShim = {
      // Initialize WebGPU device and context. Returns 0 on success, <0 on error.
      // Synchronous kick-off: starts the async init and returns PENDING (1).
      // The module MUST poll `host_webgpu_poll_init` until it returns READY (0)
      // or an error (<0) before calling any other host_webgpu_* function — a
      // Wasm import cannot await, so this can't return the real device status
      // inline. Idempotent: a second call while pending just returns PENDING.
      host_webgpu_init: () => {
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
            console.error('[webgpu] Device lost:', info.message);
            gpuInitialized = false;
            gpuInitStatus = GPU_INIT_NOT_STARTED;
          });

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
          const format = navigator.gpu.getPreferredCanvasFormat();
          gpuContext.configure({
            device: gpuDevice,
            format: format,
            alphaMode: 'opaque',
          });

          // Create render pipeline
          const vertexModule = gpuDevice.createShaderModule({ code: gpuVertexShader });
          const fragmentModule = gpuDevice.createShaderModule({ code: gpuFragmentShader });

          const bindGroupLayout = gpuDevice.createBindGroupLayout({
            entries: [{
              binding: 0,
              visibility: GPUShaderStage.VERTEX | GPUShaderStage.FRAGMENT,
              buffer: { type: 'uniform' },
            }],
          });

          gpuPipeline = gpuDevice.createRenderPipeline({
            layout: gpuDevice.createPipelineLayout({ bindGroupLayouts: [bindGroupLayout] }),
            vertex: {
              module: vertexModule,
              entryPoint: 'vs_main',
              buffers: [{
                arrayStride: 36, // 3*4 + 3*4 + 3*4 = 36 bytes per vertex
                attributes: [
                  { shaderLocation: 0, offset: 0, format: 'float32x3' },  // position
                  { shaderLocation: 1, offset: 12, format: 'float32x3' }, // color
                  { shaderLocation: 2, offset: 24, format: 'float32x3' }, // normal
                ],
              }],
            },
            fragment: {
              module: fragmentModule,
              entryPoint: 'fs_main',
              targets: [{ format: format }],
            },
            primitive: {
              topology: 'triangle-list',
              cullMode: 'back',
              frontFace: 'ccw',
            },
            depthStencil: {
              format: 'depth24plus',
              depthWriteEnabled: true,
              depthCompare: 'less',
            },
          });

          // Create uniform buffer (viewProj matrix + camera pos + time + fog)
          gpuUniformBuffer = gpuDevice.createBuffer({
            size: 96, // 64 (mat4) + 16 (vec4) + 4 (time) + 4 (fog) + 8 (pad)
            usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
          });

          gpuBindGroup = gpuDevice.createBindGroup({
            layout: bindGroupLayout,
            entries: [{ binding: 0, resource: { buffer: gpuUniformBuffer } }],
          });

          // Create depth texture
          gpuDepthTexture = gpuDevice.createTexture({
            size: [gpuCanvas.width, gpuCanvas.height],
            format: 'depth24plus',
            usage: GPUTextureUsage.RENDER_ATTACHMENT,
          });

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

      // Poll WebGPU init status: 0 = ready, 1 = pending, 2 = not started,
      // <0 = error (-1 no WebGPU, -2 no adapter, -3 init threw). The module
      // calls `host_webgpu_init` once, then polls this until it is not PENDING.
      host_webgpu_poll_init: () => gpuInitStatus,

      // Resize canvas and recreate depth texture
      host_webgpu_resize: (width, height) => {
        if (!gpuInitialized || !gpuCanvas || !gpuDevice) return -1;
        gpuWidth = width;
        gpuHeight = height;
        gpuCanvas.width = width;
        gpuCanvas.height = height;
        if (gpuDepthTexture) gpuDepthTexture.destroy();
        gpuDepthTexture = gpuDevice.createTexture({
          size: [width, height],
          format: 'depth24plus',
          usage: GPUTextureUsage.RENDER_ATTACHMENT,
        });
        return 0;
      },

      // Upload vertex data. Format: [x,y,z, r,g,b, nx,ny,nz] per vertex (9 floats = 36 bytes)
      host_webgpu_upload_vertices: (ptr, byteLen) => {
        if (!gpuInitialized || !gpuDevice) return -1;
        const data = kview(ptr, byteLen);
        if (gpuVertexBuffer) gpuVertexBuffer.destroy();
        gpuVertexBuffer = gpuDevice.createBuffer({
          size: byteLen,
          usage: GPUBufferUsage.VERTEX | GPUBufferUsage.COPY_DST,
        });
        gpuDevice.queue.writeBuffer(gpuVertexBuffer, 0, data);
        gpuVertexCount = (byteLen / 36) | 0;
        return gpuVertexCount;
      },

      // Upload index data (u32 indices)
      host_webgpu_upload_indices: (ptr, byteLen) => {
        if (!gpuInitialized || !gpuDevice) return -1;
        const data = kview(ptr, byteLen);
        if (gpuIndexBuffer) gpuIndexBuffer.destroy();
        gpuIndexBuffer = gpuDevice.createBuffer({
          size: byteLen,
          usage: GPUBufferUsage.INDEX | GPUBufferUsage.COPY_DST,
        });
        gpuDevice.queue.writeBuffer(gpuIndexBuffer, 0, data);
        gpuIndexCount = (byteLen / 4) | 0;
        return gpuIndexCount;
      },

      // Set camera uniforms: viewProj (16 floats), camPos (3 floats), time, fogDist
      host_webgpu_set_uniforms: (ptr, byteLen) => {
        if (!gpuInitialized || !gpuDevice || !gpuUniformBuffer) return -1;
        const data = kview(ptr, Math.min(byteLen, 96));
        gpuDevice.queue.writeBuffer(gpuUniformBuffer, 0, data);
        return 0;
      },

      // Begin a frame (clear and start render pass)
      host_webgpu_begin_frame: (r, g, b) => {
        if (!gpuInitialized || !gpuDevice || !gpuContext) return -1;
        const texture = gpuContext.getCurrentTexture();
        gpuEncoder = gpuDevice.createCommandEncoder();
        gpuPass = gpuEncoder.beginRenderPass({
          colorAttachments: [{
            view: texture.createView(),
            loadOp: 'clear',
            storeOp: 'store',
            clearValue: { r: r, g: g, b: b, a: 1.0 },
          }],
          depthStencilAttachment: {
            view: gpuDepthTexture.createView(),
            depthLoadOp: 'clear',
            depthStoreOp: 'store',
            depthClearValue: 1.0,
          },
        });
        gpuPass.setPipeline(gpuPipeline);
        gpuPass.setBindGroup(0, gpuBindGroup);
        return 0;
      },

      // Draw uploaded geometry
      host_webgpu_draw: () => {
        if (!gpuPass || !gpuVertexBuffer) return -1;
        gpuPass.setVertexBuffer(0, gpuVertexBuffer);
        if (gpuIndexBuffer && gpuIndexCount > 0) {
          gpuPass.setIndexBuffer(gpuIndexBuffer, 'uint32');
          gpuPass.drawIndexed(gpuIndexCount);
        } else if (gpuVertexCount > 0) {
          gpuPass.draw(gpuVertexCount);
        }
        return 0;
      },

      // End frame and present
      host_webgpu_end_frame: () => {
        if (!gpuPass || !gpuEncoder || !gpuDevice) return -1;
        gpuPass.end();
        gpuDevice.queue.submit([gpuEncoder.finish()]);
        gpuPass = null;
        gpuEncoder = null;
        return 0;
      },

      // Get canvas dimensions
      host_webgpu_get_size: (outPtr) => {
        if (!gpuCanvas) return -1;
        const view = new DataView(getKernel().exports.memory.buffer, outPtr, 8);
        view.setUint32(0, gpuCanvas.width, true);
        view.setUint32(4, gpuCanvas.height, true);
        return 0;
      },
    };

    // ── GPU compute/present surface (host_gpgpu_*) ───────────────────
    //
    // The WebGPU host driver implementing the backend-agnostic GPU
    // compute/present capability surface. It runs the FAITHFUL N64 pixel
    // pipeline as COMPUTE shaders (not the graphics pipeline — that would change
    // precision and break bit-exactness). The module side (wasm_gpu_vi, see
    // gpu_vi.rs) speaks only these imports; no GPU types cross the boundary. A
    // future Vulkan / bare-metal driver implements the same imports unchanged.
    //
    // Async model mirrors host_webgpu_init: init kicks off the async device
    // acquire and returns PENDING; the module polls host_gpgpu_poll_init. Work is
    // submit-then-signal — dispatch/present never block; guest timing stays
    // CPU-modeled.
    //
    // The compute shaders are host-owned, version-locked assets (bit-significant,
    // pinned to the software oracle). PIPE_VI_FILTER below is a VERBATIM copy of
    // the canonical, bit-exactness-gated shader at
    //   zedex/shaders/n64_vi_filter.wgsl
    // validated per-pixel against software Rdp::vi_scanout by
    //   zedex/scripts/n64-vi-gpu-check.py
    // The two copies MUST stay in sync; the gate runs the canonical copy.
    let ggDevice = null;
    let ggCanvas = null, ggCtx = null, ggImage = null;
    let ggInitStatus = GPU_INIT_NOT_STARTED;
    let ggViPipeline = null;
    const ggBuffers = { 0: null, 1: null, 2: null }; // pix, cov, params
    let ggOut = null, ggOutN = 0, ggRead = null, ggReadBusy = false;
    const PIPE_VI_FILTER = 1;

    const VI_FILTER_WGSL = `
// N64 VI scan-out filter + display resample — WebGPU COMPUTE port of the
// software reference 'Rdp::vi_scanout' (rdp/vi_scanout.rs) and the display
// linearise/resample 'N64Machine::render_vi_to_screen' (machine.rs). Both are
// faithful integer pipelines (angrylion 'vi_fetch_filter16'/'restore_filter16'/
// 'divot_filter', then the VI 2.10 x/y-scale scan-out window). Bit-exact to the
// software oracles; integer-only, u32 wraps (WGSL-defined), i32<->u32 via bitcast
// (reinterpret, matching Rust 'as'), top-justified 8-bit channels (5-bit << 3).
//
// Two entry points share one per-pixel filter ('vi_filter_px'):
//   * 'main'       — filter only, at CI resolution (gate vs vi_scanout).
//   * 'vi_display' — filter + resample to the display surface (gate vs
//                    render_vi_to_screen); the in-app present path.
// The divot stage needs the AA/restore-filtered horizontal neighbours; each
// thread recomputes the filter for its 3 columns — pure compute, no barrier.

struct Params {
  w: u32,           // 0  colour-image width in pixels
  h: u32,           // 1  filter height (CI rows the VI filters = SCREEN_HEIGHT)
  vi_control: u32,  // 2  aa_mode[9:8], divot[4], dither[16], pixel_type[1:0]
  ci_size: u32,     // 3  colour-image size code (2 = 16bpp)
  v_res: u32,       // 4  active output rows  (resolved; defaults applied CPU-side)
  y_off: u32,       // 5  Y_SCALE sub-pixel start (2.10)
  y_mul: u32,       // 6  Y_SCALE step          (2.10; resolved default 0x400)
  x_off: u32,       // 7  X_SCALE sub-pixel start (2.10)
  x_mul: u32,       // 8  X_SCALE step          (2.10; resolved default 0x200)
  screen_w: u32,    // 9  display surface width  (SCREEN_WIDTH)
  screen_h: u32,    // 10 display surface height (SCREEN_HEIGHT)
  origin_px: u32,   // 11 (VI_ORIGIN - base)/2: displayed buffer source-index offset
};

@group(0) @binding(0) var<uniform> P: Params;
@group(0) @binding(1) var<storage, read> pix: array<u32>;  // 5551 pixel value per texel
@group(0) @binding(2) var<storage, read> cov: array<u32>;  // coverage 0..=7 per texel
@group(0) @binding(3) var<storage, read_write> outp: array<u32>; // r | g<<8 | b<<16

fn px_at(idx: u32) -> u32 { return pix[idx] & 0xffffu; }
fn cvg_at(idx: u32) -> u32 { return cov[idx]; }

// angrylion RGBA16_R/G/B: top-justified 8-bit (5-bit channel << 3).
fn work(px: u32) -> vec3<u32> {
  return vec3<u32>((px >> 8u) & 0xf8u, (px >> 3u) & 0xf8u, (px << 2u) & 0xf8u);
}

// Penultimate (second) min and max of 'p[0..n]', matching 'video_max_optimized'.
fn penu(p: ptr<function, array<u32, 7>>, n: u32) -> vec2<u32> {
  var posmax: u32 = 0u;
  var posmin: u32 = 0u;
  var cpmax: u32 = (*p)[0];
  var cpmin: u32 = (*p)[0];
  var i: u32 = 1u;
  loop {
    if (i >= n) { break; }
    if ((*p)[i] > (*p)[posmax]) {
      cpmax = (*p)[posmax];
      posmax = i;
    } else if ((*p)[i] < (*p)[posmin]) {
      cpmin = (*p)[posmin];
      posmin = i;
    }
    i = i + 1u;
  }
  if (cpmax != (*p)[posmax]) {
    var j: u32 = posmax + 1u;
    loop {
      if (j >= n) { break; }
      if ((*p)[j] > cpmax) { cpmax = (*p)[j]; }
      j = j + 1u;
    }
  }
  if (cpmin != (*p)[posmin]) {
    var j: u32 = posmin + 1u;
    loop {
      if (j >= n) { break; }
      if ((*p)[j] < cpmin) { cpmin = (*p)[j]; }
      j = j + 1u;
    }
  }
  return vec2<u32>(cpmin, cpmax);
}

fn sgn(nv: u32, a: u32) -> i32 {
  if (nv > a) { return 1; }
  if (nv < a) { return -1; }
  return 0;
}

// video_filter16 per-channel blend toward the penultimate min/max.
fn aa_chan(c: u32, lo: u32, hi: u32, coeff: u32) -> u32 {
  let col: u32 = lo + hi - (c << 1u);           // u32 wrap
  return (((col * coeff + 4u) >> 3u) + c) & 0xffu;
}

// Stage 1+2: AA / restore-de-dither working value (vr,vg,vb) for pixel (x,y).
fn aa_restore(x: u32, y: u32) -> vec3<u32> {
  let w = P.w;
  let h = P.h;
  let idx = y * w + x;
  var col = work(px_at(idx));
  let cvg = cvg_at(idx);
  let interior_row = (y >= 1u) && (y + 1u < h);
  let interior = interior_row && (x >= 2u) && (x + 2u < w);
  let dither_en = ((P.vi_control >> 16u) & 1u) != 0u;

  if (cvg == 7u) {
    if (dither_en && interior) {
      let up = (y - 1u) * w;
      let dn = (y + 1u) * w;
      let row = y * w;
      var taps = array<u32, 8>(
        up + (x - 1u), up + x, up + (x + 1u),
        row + (x - 1u), row + (x + 1u),
        dn + (x - 1u), dn + x, dn + (x + 1u),
      );
      var ri: i32 = bitcast<i32>(col.r);
      var gi: i32 = bitcast<i32>(col.g);
      var bi: i32 = bitcast<i32>(col.b);
      let ar = (col.r >> 3u) & 0x1fu;
      let ag = (col.g >> 3u) & 0x1fu;
      let ab = (col.b >> 3u) & 0x1fu;
      var k: u32 = 0u;
      loop {
        if (k >= 8u) { break; }
        let np = px_at(taps[k]);
        ri = ri + sgn((np >> 11u) & 0x1fu, ar);
        gi = gi + sgn((np >> 6u) & 0x1fu, ag);
        bi = bi + sgn((np >> 1u) & 0x1fu, ab);
        k = k + 1u;
      }
      col = vec3<u32>(bitcast<u32>(ri) & 0xffu, bitcast<u32>(gi) & 0xffu, bitcast<u32>(bi) & 0xffu);
    }
  } else if (interior) {
    let up = (y - 1u) * w;
    let dn = (y + 1u) * w;
    let row = y * w;
    var rr = array<u32, 7>(col.r, col.r, col.r, col.r, col.r, col.r, col.r);
    var gg = array<u32, 7>(col.g, col.g, col.g, col.g, col.g, col.g, col.g);
    var bb = array<u32, 7>(col.b, col.b, col.b, col.b, col.b, col.b, col.b);
    var tidx = array<u32, 6>(
      up + (x - 1u), up + (x + 1u),
      row + (x - 2u), row + (x + 2u),
      dn + (x - 1u), dn + (x + 1u),
    );
    var n: u32 = 1u;
    var k: u32 = 0u;
    loop {
      if (k >= 6u) { break; }
      let nidx = tidx[k];
      if (cvg_at(nidx) == 7u) {
        let nc = work(px_at(nidx));
        rr[n] = nc.r;
        gg[n] = nc.g;
        bb[n] = nc.b;
        n = n + 1u;
      }
      k = k + 1u;
    }
    let coeff = 7u - cvg;
    let rlohi = penu(&rr, n);
    let glohi = penu(&gg, n);
    let blohi = penu(&bb, n);
    col = vec3<u32>(
      aa_chan(col.r, rlohi.x, rlohi.y, coeff),
      aa_chan(col.g, glohi.x, glohi.y, coeff),
      aa_chan(col.b, blohi.x, blohi.y, coeff),
    );
  }
  return col;
}

fn med(l: u32, c: u32, r: u32) -> u32 {
  if ((l >= c && r >= l) || (l >= r && c >= l)) { return l; }
  if ((r >= c && l >= r) || (r >= l && c >= r)) { return r; }
  return c;
}

// Full per-pixel VI filter (Stage 1+2 AA/restore + Stage 3 divot), with the
// global early-outs (non-16bpp / width-range / identity aa_mode 2/3 -> the
// top-justified passthrough). Pure function of (CI, coverage) at (x,y).
fn vi_filter_px(x: u32, y: u32) -> vec3<u32> {
  let aa_mode = (P.vi_control >> 8u) & 3u;
  if (P.ci_size != 2u || P.w < 5u || P.w > 1024u || aa_mode >= 2u) {
    return work(px_at(y * P.w + x));
  }
  var c = aa_restore(x, y);
  let divot_en = ((P.vi_control >> 4u) & 1u) != 0u;
  if (divot_en && x >= 1u && x + 1u < P.w) {
    let idx = y * P.w + x;
    let ca = cvg_at(idx);
    let la = cvg_at(idx - 1u);
    let ra = cvg_at(idx + 1u);
    if (!(ca == 7u && la == 7u && ra == 7u)) {
      let l = aa_restore(x - 1u, y);
      let r = aa_restore(x + 1u, y);
      c = vec3<u32>(med(l.r, c.r, r.r), med(l.g, c.g, r.g), med(l.b, c.b, r.b));
    }
  }
  return c;
}

// Filter only, at CI resolution. Gate: == software Rdp::vi_scanout.
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
  let i = gid.x;
  if (i >= P.w * P.h) { return; }
  let c = vi_filter_px(i % P.w, i / P.w);
  outp[i] = c.r | (c.g << 8u) | (c.b << 16u);
}

// Filter + display resample. Gate: == software render_vi_to_screen for the
// RGBA5551 (filtered) path. Per output pixel: map to the source colour image via
// the VI 2.10 x/y-scale + active window, then filter at that source location.
// (8888 framebuffers are left to the software path — the module falls back.)
@compute @workgroup_size(64)
fn vi_display(@builtin(global_invocation_id) gid: vec3<u32>) {
  let i = gid.x;
  let sw = P.screen_w;
  let sh = P.screen_h;
  if (i >= sw * sh) { return; }
  let xo = i % sw;
  let yo = i / sw;
  // src_y = (y_off + yo*y_mul) >> 10, signed (matches the i32 arithmetic).
  let src_y_s: i32 = (bitcast<i32>(P.y_off) + bitcast<i32>(yo) * bitcast<i32>(P.y_mul)) >> 10u;
  if (bitcast<i32>(yo) >= bitcast<i32>(P.v_res) || src_y_s < 0 || src_y_s >= bitcast<i32>(P.h)) {
    outp[i] = 0u; // VI blanking -> black
    return;
  }
  let pixel_type = P.vi_control & 3u;
  if (pixel_type != 2u) { outp[i] = 0u; return; } // GPU path is RGBA5551 only
  let src_y = u32(src_y_s);
  var src_x = (P.x_off + xo * 2u * P.x_mul) >> 10u;
  if (src_x > P.w - 1u) { src_x = P.w - 1u; }
  // VI_ORIGIN points into the buffer (base-relative); add its pixel offset to the
  // source index, exactly as render_vi_to_screen reads display_pixel(origin+idx*2).
  let base_idx = P.origin_px + src_y * P.w + src_x;
  let sy = base_idx / P.w;
  if (sy >= P.h) { outp[i] = 0u; return; }
  let c = vi_filter_px(base_idx % P.w, sy);
  outp[i] = c.r | (c.g << 8u) | (c.b << 16u);
}
`;

    // WebGL2 FALLBACK backend (browsers without WebGPU). WebGL2 has no compute,
    // so the same faithful integer VI filter+resample runs as a fullscreen-quad
    // FRAGMENT shader (shaders/n64_vi_filter.frag) — bit-exact to the WGSL/software
    // reference (validated by scripts/n64-vi-webgl-check.py). A SECOND host-driver
    // behind the identical host_gpgpu_* surface; the module is unchanged.
    let ggBackend = null;            // 'webgpu' | 'webgl2'
    let ggGl = null, ggGlProg = null, ggGlCanvas = null, ggGlVao = null;
    let ggGlTexPix = null, ggGlTexCov = null;
    const ggGlU = {};
    let ggGlPix = null, ggGlCov = null, ggGlParams = null; // staged uploads
    const VI_FILTER_VERT = `#version 300 es
void main(){ vec2 v[3]=vec2[3](vec2(-1.,-1.),vec2(3.,-1.),vec2(-1.,3.)); gl_Position=vec4(v[gl_VertexID],0.,1.); }`;
    const VI_FILTER_FRAG = `#version 300 es
// N64 VI scan-out filter + display resample — WebGL2 FALLBACK port of the WebGPU
// compute shader (shaders/n64_vi_filter.wgsl), for browsers without WebGPU. Same
// faithful integer pipeline as the software oracles (Rdp::vi_scanout +
// N64Machine::render_vi_to_screen). WebGL2 has no compute, so the filter runs as
// a fullscreen-quad FRAGMENT shader: one fragment = one output pixel, sampling the
// colour image / coverage as integer textures.
//
// FAITHFULNESS: integer-only. GLSL ES 3.00 'highp uint' ops wrap mod 2^32 (== WGSL
// u32); int<->uint conversions are bit-preserving for the in-range values used
// here, and the restore accumulator wraps via 'ri & 0xff' (a non-negative mask)
// rather than uint(negative). Bit-exact to the WGSL/software reference; only the
// final float->unorm8 canvas write is non-integer (the non-bit-significant blit).

precision highp int;
precision highp float;
precision highp usampler2D;

uniform uint uW;          // colour-image width
uniform uint uH;          // filter height (CI rows = SCREEN_HEIGHT)
uniform uint uViControl;  // aa_mode[9:8], divot[4], dither[16], pixel_type[1:0]
uniform uint uCiSize;     // 2 = 16bpp
uniform uint uVRes;       // active output rows (resolved)
uniform uint uYOff;       // Y_SCALE 2.10 (resolved)
uniform uint uYMul;
uniform uint uXOff;       // X_SCALE 2.10 (resolved)
uniform uint uXMul;
uniform uint uScreenW;
uniform uint uScreenH;
uniform uint uOriginPx;   // (VI_ORIGIN - base)/2: displayed buffer source-index offset
uniform usampler2D uPix;  // R16UI: 5551 pixel value per texel
uniform usampler2D uCov;  // R8UI:  coverage 0..=7 per texel

out vec4 fragColor;

uint pxAt(uint idx) {
  return texelFetch(uPix, ivec2(int(idx % uW), int(idx / uW)), 0).r & 0xffffu;
}
uint cvgAt(uint idx) {
  return texelFetch(uCov, ivec2(int(idx % uW), int(idx / uW)), 0).r;
}

uvec3 work(uint px) {
  return uvec3((px >> 8u) & 0xf8u, (px >> 3u) & 0xf8u, (px << 2u) & 0xf8u);
}

// Penultimate (second) min and max of p[0..n], matching video_max_optimized.
uvec2 penu(uint p[7], uint n) {
  uint posmax = 0u, posmin = 0u;
  uint cpmax = p[0], cpmin = p[0];
  for (uint i = 1u; i < n; i++) {
    if (p[i] > p[posmax]) { cpmax = p[posmax]; posmax = i; }
    else if (p[i] < p[posmin]) { cpmin = p[posmin]; posmin = i; }
  }
  if (cpmax != p[posmax]) {
    for (uint j = posmax + 1u; j < n; j++) { if (p[j] > cpmax) cpmax = p[j]; }
  }
  if (cpmin != p[posmin]) {
    for (uint j = posmin + 1u; j < n; j++) { if (p[j] < cpmin) cpmin = p[j]; }
  }
  return uvec2(cpmin, cpmax);
}

int sgn(uint nv, uint a) {
  if (nv > a) return 1;
  if (nv < a) return -1;
  return 0;
}

uint aaChan(uint c, uint lo, uint hi, uint coeff) {
  uint col = lo + hi - (c << 1u);
  return (((col * coeff + 4u) >> 3u) + c) & 0xffu;
}

// Stage 1+2: AA / restore-de-dither working value for pixel (x,y).
uvec3 aaRestore(uint x, uint y) {
  uint w = uW, h = uH;
  uint idx = y * w + x;
  uvec3 col = work(pxAt(idx));
  uint cvg = cvgAt(idx);
  bool interiorRow = (y >= 1u) && (y + 1u < h);
  bool interior = interiorRow && (x >= 2u) && (x + 2u < w);
  bool ditherEn = ((uViControl >> 16u) & 1u) != 0u;

  if (cvg == 7u) {
    if (ditherEn && interior) {
      uint up = (y - 1u) * w, dn = (y + 1u) * w, row = y * w;
      uint taps[8] = uint[8](
        up + (x - 1u), up + x, up + (x + 1u),
        row + (x - 1u), row + (x + 1u),
        dn + (x - 1u), dn + x, dn + (x + 1u));
      int ri = int(col.r), gi = int(col.g), bi = int(col.b);
      uint ar = (col.r >> 3u) & 0x1fu, ag = (col.g >> 3u) & 0x1fu, ab = (col.b >> 3u) & 0x1fu;
      for (uint k = 0u; k < 8u; k++) {
        uint np = pxAt(taps[k]);
        ri += sgn((np >> 11u) & 0x1fu, ar);
        gi += sgn((np >> 6u) & 0x1fu, ag);
        bi += sgn((np >> 1u) & 0x1fu, ab);
      }
      // (uint8_t) wrap via a non-negative mask (avoids uint(negative)).
      col = uvec3(uint(ri & 0xff), uint(gi & 0xff), uint(bi & 0xff));
    }
  } else if (interior) {
    uint up = (y - 1u) * w, dn = (y + 1u) * w, row = y * w;
    uint rr[7] = uint[7](col.r, col.r, col.r, col.r, col.r, col.r, col.r);
    uint gg[7] = uint[7](col.g, col.g, col.g, col.g, col.g, col.g, col.g);
    uint bb[7] = uint[7](col.b, col.b, col.b, col.b, col.b, col.b, col.b);
    uint tidx[6] = uint[6](
      up + (x - 1u), up + (x + 1u),
      row + (x - 2u), row + (x + 2u),
      dn + (x - 1u), dn + (x + 1u));
    uint n = 1u;
    for (uint k = 0u; k < 6u; k++) {
      uint nidx = tidx[k];
      if (cvgAt(nidx) == 7u) {
        uvec3 nc = work(pxAt(nidx));
        rr[n] = nc.r; gg[n] = nc.g; bb[n] = nc.b;
        n++;
      }
    }
    uint coeff = 7u - cvg;
    uvec2 rlohi = penu(rr, n);
    uvec2 glohi = penu(gg, n);
    uvec2 blohi = penu(bb, n);
    col = uvec3(
      aaChan(col.r, rlohi.x, rlohi.y, coeff),
      aaChan(col.g, glohi.x, glohi.y, coeff),
      aaChan(col.b, blohi.x, blohi.y, coeff));
  }
  return col;
}

uint med(uint l, uint c, uint r) {
  if ((l >= c && r >= l) || (l >= r && c >= l)) return l;
  if ((r >= c && l >= r) || (r >= l && c >= r)) return r;
  return c;
}

uvec3 viFilterPx(uint x, uint y) {
  uint aaMode = (uViControl >> 8u) & 3u;
  if (uCiSize != 2u || uW < 5u || uW > 1024u || aaMode >= 2u) {
    return work(pxAt(y * uW + x));
  }
  uvec3 c = aaRestore(x, y);
  bool divotEn = ((uViControl >> 4u) & 1u) != 0u;
  if (divotEn && x >= 1u && x + 1u < uW) {
    uint idx = y * uW + x;
    uint ca = cvgAt(idx), la = cvgAt(idx - 1u), ra = cvgAt(idx + 1u);
    if (!(ca == 7u && la == 7u && ra == 7u)) {
      uvec3 l = aaRestore(x - 1u, y);
      uvec3 r = aaRestore(x + 1u, y);
      c = uvec3(med(l.r, c.r, r.r), med(l.g, c.g, r.g), med(l.b, c.b, r.b));
    }
  }
  return c;
}

void main() {
  // Output pixel (top-left origin). gl_FragCoord.y is bottom-left, so flip to put
  // N64 row 0 at the top of the canvas.
  uint xo = uint(int(gl_FragCoord.x));
  uint yo = uScreenH - 1u - uint(int(gl_FragCoord.y));

  int srcYs = (int(uYOff) + int(yo) * int(uYMul)) >> 10;
  if (int(yo) >= int(uVRes) || srcYs < 0 || srcYs >= int(uH)) {
    fragColor = vec4(0.0, 0.0, 0.0, 1.0);
    return;
  }
  if ((uViControl & 3u) != 2u) { // RGBA5551 only
    fragColor = vec4(0.0, 0.0, 0.0, 1.0);
    return;
  }
  uint srcY = uint(srcYs);
  uint srcX = (uXOff + xo * 2u * uXMul) >> 10u;
  if (srcX > uW - 1u) srcX = uW - 1u;
  // VI_ORIGIN points into the buffer; add its pixel offset to the source index.
  uint baseIdx = uOriginPx + srcY * uW + srcX;
  uint sy = baseIdx / uW;
  if (sy >= uH) { fragColor = vec4(0.0, 0.0, 0.0, 1.0); return; }
  uvec3 c = viFilterPx(baseIdx % uW, sy);
  fragColor = vec4(float(c.r) / 255.0, float(c.g) / 255.0, float(c.b) / 255.0, 1.0);
}
`;

    function ggGlInit() {
      ggGlCanvas = document.createElement('canvas');
      ggGlCanvas.style.maxWidth = '100%';
      ggGlCanvas.style.height = 'auto';
      ggGlCanvas.style.imageRendering = 'pixelated';
      if (canvasContainer) canvasContainer.replaceChildren(ggGlCanvas);
      else document.body.appendChild(ggGlCanvas);
      const gl = ggGlCanvas.getContext('webgl2', { preserveDrawingBuffer: true });
      if (!gl) return false;
      const sh = (t, src) => { const o = gl.createShader(t); gl.shaderSource(o, src); gl.compileShader(o);
        if (!gl.getShaderParameter(o, gl.COMPILE_STATUS)) throw new Error('shader: ' + gl.getShaderInfoLog(o)); return o; };
      const prog = gl.createProgram();
      gl.attachShader(prog, sh(gl.VERTEX_SHADER, VI_FILTER_VERT));
      gl.attachShader(prog, sh(gl.FRAGMENT_SHADER, VI_FILTER_FRAG));
      gl.linkProgram(prog);
      if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) throw new Error('link: ' + gl.getProgramInfoLog(prog));
      gl.useProgram(prog);
      ['uW','uH','uViControl','uCiSize','uVRes','uYOff','uYMul','uXOff','uXMul','uScreenW','uScreenH','uOriginPx','uPix','uCov']
        .forEach(n => ggGlU[n] = gl.getUniformLocation(prog, n));
      ggGlVao = gl.createVertexArray(); gl.bindVertexArray(ggGlVao);
      ggGlTexPix = gl.createTexture(); ggGlTexCov = gl.createTexture();
      gl.uniform1i(ggGlU.uPix, 0); gl.uniform1i(ggGlU.uCov, 1);
      ggGl = gl; ggGlProg = prog;
      return true;
    }

    function ggGlRender() {
      if (!ggGl || !ggGlParams || !ggGlPix || !ggGlCov) return;
      const gl = ggGl, p = ggGlParams, w = p[0], h = p[1], sw = p[9], sh = p[10];
      ggGlCanvas.width = sw; ggGlCanvas.height = sh; gl.viewport(0, 0, sw, sh);
      gl.pixelStorei(gl.UNPACK_ALIGNMENT, 1);
      gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, ggGlTexPix);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.R16UI, w, h, 0, gl.RED_INTEGER, gl.UNSIGNED_SHORT, ggGlPix);
      gl.activeTexture(gl.TEXTURE1); gl.bindTexture(gl.TEXTURE_2D, ggGlTexCov);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.R8UI, w, h, 0, gl.RED_INTEGER, gl.UNSIGNED_BYTE, ggGlCov);
      gl.uniform1ui(ggGlU.uW, p[0]); gl.uniform1ui(ggGlU.uH, p[1]); gl.uniform1ui(ggGlU.uViControl, p[2]);
      gl.uniform1ui(ggGlU.uCiSize, p[3]); gl.uniform1ui(ggGlU.uVRes, p[4]); gl.uniform1ui(ggGlU.uYOff, p[5]);
      gl.uniform1ui(ggGlU.uYMul, p[6]); gl.uniform1ui(ggGlU.uXOff, p[7]); gl.uniform1ui(ggGlU.uXMul, p[8]);
      gl.uniform1ui(ggGlU.uScreenW, sw); gl.uniform1ui(ggGlU.uScreenH, sh); gl.uniform1ui(ggGlU.uOriginPx, p[11]);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    }

    function ggEnsureCanvas(w, h) {
      if (ggCanvas && ggCanvas.width === w && ggCanvas.height === h) return;
      ggCanvas = document.createElement('canvas');
      ggCanvas.width = w; ggCanvas.height = h;
      ggCanvas.style.maxWidth = '100%';
      ggCanvas.style.height = 'auto';
      ggCanvas.style.imageRendering = 'pixelated';
      if (canvasContainer) canvasContainer.replaceChildren(ggCanvas);
      else document.body.appendChild(ggCanvas);
      ggCtx = ggCanvas.getContext('2d');
      ggImage = ggCtx.createImageData(w, h);
    }

    const gpgpuShim = {
      // Kick off async device acquire; returns PENDING. Module polls poll_init.
      host_gpgpu_init: () => {
        if (ggBackend) return GPU_INIT_READY;
        if (ggInitStatus === GPU_INIT_PENDING) return GPU_INIT_PENDING;
        const tryWebgl2 = () => {
          try {
            if (ggGlInit()) { ggBackend = 'webgl2'; ggInitStatus = GPU_INIT_READY; console.log('[gpgpu] ready (WebGL2 fallback)'); return true; }
          } catch (e) { console.error('[gpgpu] webgl2 init failed:', e.message); }
          return false;
        };
        // `?gpu=webgl2` (or window.__FORCE_GPU_BACKEND) forces the WebGL2 path so
        // it can be exercised on a WebGPU-capable browser (Safari has no WebGPU).
        let forceGl = false;
        try { forceGl = (new URLSearchParams(location.search).get('gpu') === 'webgl2') || window.__FORCE_GPU_BACKEND === 'webgl2'; } catch (e) {}
        console.log('[gpgpu] init called: navigator.gpu=' + (!!navigator.gpu) + ' forceGl=' + forceGl);
        if (!navigator.gpu || forceGl) {
          // No WebGPU (or forced) — try the WebGL2 fallback (synchronous).
          if (tryWebgl2()) return GPU_INIT_READY;
          ggInitStatus = -1; return -1;
        }
        ggInitStatus = GPU_INIT_PENDING;
        (async () => {
          try {
            const adapter = await navigator.gpu.requestAdapter();
            if (!adapter) throw new Error('no adapter');
            ggDevice = await adapter.requestDevice();
            ggDevice.lost.then((info) => { console.error('[gpgpu] device lost:', info.message); ggDevice = null; ggBackend = null; ggInitStatus = GPU_INIT_NOT_STARTED; });
            const mod = ggDevice.createShaderModule({ code: VI_FILTER_WGSL });
            // The in-app VI path is filter + display resample in one pass.
            ggViPipeline = ggDevice.createComputePipeline({ layout: 'auto', compute: { module: mod, entryPoint: 'vi_display' } });
            ggBackend = 'webgpu';
            ggInitStatus = GPU_INIT_READY;
            console.log('[gpgpu] ready (VI display compute pipeline)');
          } catch (e) {
            // WebGPU unavailable/failed — fall back to the WebGL2 driver.
            console.warn('[gpgpu] WebGPU unavailable (' + e.message + '), trying WebGL2');
            if (!tryWebgl2()) ggInitStatus = -3;
          }
        })();
        return GPU_INIT_PENDING;
      },
      host_gpgpu_poll_init: () => ggInitStatus,

      // Upload/refresh an input buffer slot (0=pix, 1=cov, 2=params). pix/cov
      // arrive as packed planes (u16 / u8); we expand to u32 storage arrays the
      // shader indexes — the integer values are identical, so bit-exactness holds.
      host_gpgpu_buffer_update: (slot, ptr, len) => {
        const raw = kview(ptr, len);
        if (ggBackend === 'webgl2') {
          // Stage the planes for ggGlRender (uploaded as integer textures there).
          if (slot === 2) {
            ggGlParams = new Uint32Array(raw.buffer.slice(raw.byteOffset, raw.byteOffset + len));
          } else if (slot === 0) {
            // pix: RDRAM 5551 big-endian (hi,lo) -> value, into a R16UI texture.
            const np = len >> 1;
            const a = new Uint16Array(np);
            for (let i = 0; i < np; i++) a[i] = (raw[2 * i] << 8) | raw[2 * i + 1];
            ggGlPix = a;
          } else {
            ggGlCov = new Uint8Array(raw.subarray(0, len)); // copy out of wasm mem
          }
          return 0;
        }
        if (!ggDevice) return -1;
        let arr;
        if (slot === 2) {
          arr = new Uint32Array(raw.buffer.slice(raw.byteOffset, raw.byteOffset + len));
          // params (12 u32): [w,h,vi_control,ci_size, v_res,y_off,y_mul,x_off,
          // x_mul, screen_w,screen_h, _pad]. The vi_display pass outputs
          // screen_w*screen_h; size the output buffer here so it exists before
          // dispatch (which runs before present). Fall back to w*h for a
          // filter-only (16-byte) params block.
          const n = (arr.length >= 11) ? ((arr[9] | 0) * (arr[10] | 0)) : ((arr[0] | 0) * (arr[1] | 0));
          if (n > 0 && ggOutN !== n) {
            if (ggOut) ggOut.destroy();
            if (ggRead) ggRead.destroy();
            ggOut = ggDevice.createBuffer({ size: n * 4, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC });
            ggRead = ggDevice.createBuffer({ size: n * 4, usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST });
            ggOutN = n;
          }
        } else if (slot === 0) {
          // pix plane = the RDRAM 5551 colour image, big-endian per pixel
          // (hi,lo) — decode to the pixel value the shader indexes.
          const np = len >> 1;
          arr = new Uint32Array(np);
          for (let i = 0; i < np; i++) arr[i] = (raw[2 * i] << 8) | raw[2 * i + 1];
        } else {
          arr = Uint32Array.from(raw); // cov bytes -> u32
        }
        const want = arr.byteLength;
        let b = ggBuffers[slot];
        if (!b || b.size < want) {
          if (b) b.destroy();
          const usage = (slot === 2 ? GPUBufferUsage.UNIFORM : GPUBufferUsage.STORAGE) | GPUBufferUsage.COPY_DST;
          b = ggDevice.createBuffer({ size: Math.max(want, 16), usage });
          ggBuffers[slot] = b;
        }
        ggDevice.queue.writeBuffer(b, 0, arr);
        return 0;
      },

      // Record + submit a compute pass. Returns immediately (submit-then-signal).
      // ggOut is sized by the first present(); the first frame's dispatch (before
      // any present) is skipped here and recovers on the next frame.
      host_gpgpu_dispatch: (pipe, gx, gy, gz) => {
        if (pipe !== PIPE_VI_FILTER) return -1;
        if (ggBackend === 'webgl2') { ggGlRender(); return 0; } // renders to canvas
        if (!ggDevice) return -1;
        if (!ggBuffers[0] || !ggBuffers[1] || !ggBuffers[2] || !ggOut) return -1;
        const bg = ggDevice.createBindGroup({ layout: ggViPipeline.getBindGroupLayout(0), entries: [
          { binding: 0, resource: { buffer: ggBuffers[2] } },
          { binding: 1, resource: { buffer: ggBuffers[0] } },
          { binding: 2, resource: { buffer: ggBuffers[1] } },
          { binding: 3, resource: { buffer: ggOut } },
        ]});
        const enc = ggDevice.createCommandEncoder();
        const pass = enc.beginComputePass();
        pass.setPipeline(ggViPipeline); pass.setBindGroup(0, bg);
        pass.dispatchWorkgroups(gx, gy, gz); pass.end();
        ggDevice.queue.submit([enc.finish()]);
        return 0;
      },

      // Blit the compute output (r|g<<8|b<<16 per pixel) to the canvas. Async
      // readback present for the pilot (the blit is not bit-significant); a
      // production driver would sample the output buffer as a texture instead.
      host_gpgpu_present: (w, h) => {
        if (ggBackend === 'webgl2') return 0; // ggGlRender already drew to the canvas
        if (!ggDevice || !ggOut) return -1;
        const n = w * h;
        if (ggOutN !== n) return -1; // params/present size mismatch
        if (ggReadBusy) return 0; // drop frame while a readback is in flight
        ggReadBusy = true;
        const enc = ggDevice.createCommandEncoder();
        enc.copyBufferToBuffer(ggOut, 0, ggRead, 0, n * 4);
        ggDevice.queue.submit([enc.finish()]);
        ggRead.mapAsync(GPUMapMode.READ).then(() => {
          const got = new Uint32Array(ggRead.getMappedRange());
          ggEnsureCanvas(w, h);
          const dst = ggImage.data;
          for (let i = 0; i < n; i++) {
            const v = got[i]; const o = i * 4;
            dst[o] = v & 0xff; dst[o + 1] = (v >> 8) & 0xff; dst[o + 2] = (v >> 16) & 0xff; dst[o + 3] = 255;
          }
          ggCtx.putImageData(ggImage, 0, 0);
          ggRead.unmap();
          ggReadBusy = false;
        }).catch((e) => { console.error('[gpgpu] present readback:', e.message); ggReadBusy = false; });
        return 0;
      },

      host_gpgpu_poll_done: () => (ggBackend === 'webgl2' ? 0 : (ggReadBusy ? 1 : 0)),
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
        moduleShim,
        webgpuShim,
        gpgpuShim
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
