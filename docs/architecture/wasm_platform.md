# WASM Platform Target

The WASM target is one of Fluxor's supported platforms, alongside
`rp2350` (bare-metal silicon), `bcm2712` (Pi 5 / Linux user-process),
and `linux` (generic Linux user-process). The defining feature of WASM
is that one binary architecture runs on many host environments —
browsers, `wasmtime`, edge runtimes, embedded `wasmtime` linked into a
larger application — without the kernel or modules changing.

This document is the platform peer of the per-chip platform code under
`src/platform/<chip>/` and the platform-specific module trees under
`modules/sdk/platform/<chip>/`. It defines the WASM architecture model;
each host environment that runs the WASM target is the subject of its
own host doc (`wasm_browser_host.md`, `wasm_wasmtime_host.md`).

---

## 1. Scope

This doc defines:

- the WASM platform's place in the existing target table
- the module envelope (`.fmod`) and how WASM module bytes sit inside it
- the bundle format (`.wasm`) and how `fluxor build` produces it
- the kernel/module ↔ host import surface, including the two host
  imports that distinguish WASM from native PIC targets
- the scheduler tick model
- the build pipeline and its parallels with the existing targets

It does not define:

- a particular WASM host environment (deferred to host docs)
- new content types, capability vocabulary, presentation/interaction
  groups, or surface families — those remain authoritative across all
  targets
- a JavaScript framework, browser runtime profile, or endpoint surface
  protocol — those are separate concerns
- WASM Component Model bindings — core WASM is the contract; the
  Component Model is a tooling layer that may be added later

---

## 2. Platform Position

The platform-targets table grows by one row:

| Target    | Code architecture     | Module format | Bundle format |
|-----------|-----------------------|---------------|---------------|
| `rp2350`  | thumbv8m PIC ELF      | `.fmod`       | `.uf2`        |
| `bcm2712` | aarch64 PIC ELF       | `.fmod`       | `.img`        |
| `linux`   | aarch64 PIC ELF       | `.fmod`       | runtime-linked (`config.bin` + `modules.bin`) |
| `wasm`    | wasm32 module         | `.fmod`       | `.wasm`       |

Three rules carry across:

1. The graph YAML is target-agnostic. The same `config.yaml` builds
   for any target whose modules and platform support the declared
   capabilities.
2. The module envelope (`.fmod`) is identical across targets — same
   TLV parameter section, same manifest hash, same entry-point table
   shape. Only the *code payload inside* the envelope changes.
3. The `fluxor build` tool selects modules and packages them with the
   kernel into the target's bundle format.

The WASM target follows all three. There is no parallel envelope, no
parallel manifest, no parallel build tool. WASM is a target row; the
rest of the architecture handles it the way it handles any target.

---

## 3. Kernel and Module Code

Both the Fluxor kernel and every PIC module compile for
`wasm32-unknown-unknown` (no_std, no host imports beyond what this
doc defines). Outputs:

- `target/wasm/firmware.wasm` — the kernel as a single WASM module
- `target/wasm/modules/<name>.fmod` — each module's `.fmod` envelope,
  with a wasm32 module as its code payload

The wasm32 build is selected via Cargo target plus the `target_arch =
"wasm32"` `cfg` branch in `modules/sdk/runtime.rs`. That branch
substitutes the `SyscallTable` struct of fn pointers (used on PIC
targets) with WASM extern imports of the same names. Module source is
unchanged; the SDK runtime knows how to talk to the kernel for either
ABI shape.

---

## 4. Module Envelope

The `.fmod` envelope is unchanged from native targets:

```
[ magic | version | manifest_hash | exports_table | params_tlv | code_payload ]
```

Only `code_payload` differs across targets. For wasm:

- `code_payload` is the raw wasm32 module bytes for that module.
- `exports_table` records the WASM export names the loader needs:
  `module_state_size`, `module_init`, `module_new`, `module_step`.
  Same names as native targets; same calling convention semantics.

A module's wasm32 code does not contain its `.fmod` parameters or
manifest hash — those live in the envelope's `params_tlv` and
`manifest_hash` fields exactly as on rp2350. The envelope is the
target-agnostic packaging.

This means the existing `tools/src/manifest.rs` `.fmod` packing code,
the `modules.bin` layout, the cache lookup machinery, and every
existing graph-validation rule apply to WASM modules byte-for-byte.

---

## 5. Bundle Format

`fluxor build config.yaml` for `target: wasm` emits exactly one file:
`target/wasm/<config>.wasm`. That file is a self-contained
single-instance WASM bundle: kernel + selected modules + config TLV.

Layout:

```
WASM module (kernel.wasm), with:

  - standard sections: type, import, function, table, memory, export, code
  - imports:           the host import surface (§6)
  - exports:           kernel_step, kernel_init, kernel_query_*
  - data section:      a passive data segment containing modules.bin
                       (concatenated .fmods + index) at known
                       symbol address EMBEDDED_MODULES_BLOB
  - data section:      a passive data segment containing config.bin
                       (route table, wiring, params) at known symbol
                       address EMBEDDED_CONFIG_BLOB
```

The bundle tool's job is mechanical: take the kernel's compiled
`firmware.wasm`, locate the placeholder data segments
`EMBEDDED_MODULES_BLOB` and `EMBEDDED_CONFIG_BLOB` (allocated by the
kernel's Cargo build with size 0), and rewrite them with the actual
modules.bin and config.bin bytes. The output is a single `.wasm` file
the host instantiates.

The choice of *passive* data segments matters: they're materialised on
demand via `memory.init`, so the kernel can ask the engine to copy
them into linear memory at boot exactly once. Active data segments
work too but force the entire blob into memory before kernel init
runs; passive segments give the kernel control over placement.

The kernel boots by reading its own `EMBEDDED_MODULES_BLOB` symbol
address as a known offset into linear memory, parsing modules.bin
exactly the way `fluxor-linux` parses the on-disk modules.bin today,
and instantiating each module via the host imports below.

This mirrors how the rp2350 .uf2 trailer, the bcm2712 .img layout,
and the Linux runtime-linked config+modules pair embed the same
modules.bin in the same shape — just packaged for the target's
deployment medium.

---

## 6. Host Import Surface

The kernel imports a small fixed set of functions from the WASM host.
The set is identical across browser, wasmtime, edge, and any future
host. Hosts implement these functions in their native language (JS,
Rust, etc.) but expose the same names and signatures.

### Time and log

Mirror the existing platform-time and platform-log abstractions:

```text
host_now_us() -> u64
host_log(level: u32, ptr: *const u8, len: usize)
host_panic(ptr: *const u8, len: usize) -> !
```

Equivalent to `linux::Instant::now()` and `log::info!`/`log::warn!` on
the Linux target; equivalent to silicon timer and UART logging on
rp2350. Same role.

### Memory

WASM linear memory is the kernel's heap. `host_alloc` is **not** a
host import — the kernel manages its own linear memory via a
in-binary allocator (same as how rp2350 manages its own RAM). The host
only sets the memory's growth limit at instantiation time.

### Module instantiation — the WASM-specific addition

PIC ELF on native targets is loaded by the kernel itself: mmap, fix up
relocations, jump to the entry point. WASM modules cannot self-host
WASM modules — the engine has to do the instantiation. So the kernel
delegates back to the host:

```text
host_instantiate_module(
    bytes_ptr: *const u8,
    bytes_len: usize,
    imports_ptr: *const u8,
    imports_len: usize,
) -> i32           // module_handle, or negative errno

host_invoke_module(
    handle: i32,
    export_name_ptr: *const u8,    // UTF-8 export name in kernel memory
    export_name_len: usize,
    args_ptr: *const u8,           // packed i32 LE args (one per i32 param)
    args_len: usize,
    ret_ptr: *mut u8,              // host writes the return value here
    ret_cap: usize,
) -> i32                           // bytes written to ret_ptr, or negative errno

host_module_export_exists(
    handle: i32,
    export_name_ptr: *const u8,
    export_name_len: usize,
) -> i32                           // 1 if exported, 0 if absent, negative on bad handle

host_destroy_module(handle: i32) -> i32
```

Exports are addressed by name; the host owns the export table and
the kernel never sees indices. `host_module_export_exists` is the
quiet probe for optional exports — `host_invoke_module` against an
absent name is allowed to log and return an error, so callers use
the probe before invoking when the export is optional. Args are
packed as a sequence of i32 little-endian values, one per parameter.

`imports_ptr` / `imports_len` are reserved; the kernel passes
`(null, 0)`. The host wires the PIC-module syscall surface by name
under the `env` namespace:

```text
env.channel_read   →  kernel.exports.channel_read
env.channel_write  →  kernel.exports.channel_write
env.channel_poll   →  kernel.exports.channel_poll
env.provider_open  →  kernel.exports.provider_open
env.provider_call  →  kernel.exports.provider_call
env.provider_query →  kernel.exports.provider_query
env.provider_close →  kernel.exports.provider_close
```

Heap functions live module-side (each module's bump allocator
backed by `memory.grow` in its own linear memory), so they are not
in the import set.

These are the only WASM-specific imports. Everything else (channels,
heap, timer, capability dispatch) the modules see is the kernel's
exported syscall surface, identical to the `SyscallTable` on PIC
targets.

### Host environment imports

Beyond the kernel-uniform set above, each host adds a *small*
host-environment import set covering capabilities the WASM sandbox
cannot provide directly: realtime audio, raster output, network, DOM
input, persistent storage. Those imports are the subject of the
per-host docs and are implemented by built-in modules on the host
side, exactly the way `linux_audio` and `host_image_codec` are
built-in modules on the Linux target today.

---

## 7. Tick Driver

The kernel's scheduler runs as a single function:

```text
export kernel_step() -> u32      // returns hint: ms-until-next-useful-tick,
                                 // 0 means run again immediately
```

The host calls `kernel_step` in a loop appropriate to its environment:

- **Browser host**: typically `requestAnimationFrame` for ~60 Hz,
  optionally an `AudioWorklet` for sample-rate-paced ticks when the
  graph contains audio sinks.
- **Wasmtime host**: a busy loop with `std::thread::sleep` honoring
  the returned hint.
- **Edge runtime host**: typically request-driven; `kernel_step` runs
  for a bounded burst per request and the kernel's persistent state
  lives across requests via host-provided storage.

The kernel does not assume a specific tick rate. Modules already use
monotonic time for any timing-critical work
(`module_architecture.md` §3); same rule on WASM.

The host does not poke kernel internals between ticks. Every
externally-observable change happens inside `kernel_step`. This makes
the kernel's behavior identical regardless of which host drives it.

---

## 8. Build Pipeline

The Makefile gains one target row plus the corresponding cargo target
entries; otherwise the user-visible commands are unchanged:

```sh
make modules    TARGET=wasm    # → target/wasm/modules/*.fmod
make firmware   TARGET=wasm    # → target/wasm/firmware.wasm
fluxor build    config.yaml    # → target/wasm/<config>.wasm  (with target: wasm)
```

Symmetrical with:

```sh
make modules    TARGET=rp2350
make firmware   TARGET=rp2350
fluxor build    config.yaml    # → target/rp2350/uf2/<config>.uf2
```

Internally, `fluxor build` for `target: wasm`:

1. Reads `config.yaml`, resolves the module set, packs each module's
   parameters into its `.fmod` TLV section.
2. Concatenates the selected `.fmod` files into `modules.bin` (same
   layout as every other target).
3. Loads `target/wasm/firmware.wasm`, locates the
   `EMBEDDED_MODULES_BLOB` and `EMBEDDED_CONFIG_BLOB` placeholder
   passive data segments, and rewrites them with the actual blobs.
4. Writes the result to `target/wasm/<config>.wasm`.

The kernel's Cargo build allocates the placeholder segments at fixed
sizes large enough to hold the blob plus a small slack; the bundle
tool refuses to write a `.wasm` that overflows the placeholder and
prints the required size so the kernel can be rebuilt with a larger
segment. Same defensive pattern as the rp2350 `modules.bin` size
limit and the Linux config-arena cap.

A build for `target: wasm` does **not** require selecting a specific
host. The same `<config>.wasm` is given to a browser shim, a wasmtime
shim, or an edge-runtime shim unchanged. Hosts differ only in which
*built-in* modules they provide (audio, video, DOM input, network)
and in the tick driver. Those built-ins live in the host shim and are
mounted into the graph at scheduler init via the same builtin-module
mechanism `fluxor-linux` uses today.

---

## 9. Hosts at a Glance

The platform itself is host-agnostic. Each host's specific contract
(host-environment imports, built-in module set, audio/visibility
policy, sandbox quirks) lives in its own doc. Brief sketch:

| Host                   | Tick driver        | Built-in modules                                                                | Doc |
|------------------------|--------------------|---------------------------------------------------------------------------------|-----|
| Browser tab            | `requestAnimationFrame` + optional `AudioWorklet` | `wasm_browser_canvas`, `wasm_browser_audio`, `wasm_browser_dom_input`, `wasm_browser_websocket`, `host_browser_fetch` | `wasm_browser_host.md` |
| `wasmtime` standalone | tick loop with sleep | `wasm_wasmtime_net`, `wasm_wasmtime_audio` (cpal-backed), file storage          | `wasm_wasmtime_host.md` |
| Edge runtime           | request-driven     | host-specific HTTP / KV / queue / cache adapters                                | per-runtime doc                |

Every host's built-in modules speak the existing AV / input / protocol
surface families. A WASM-Fluxor instance running in any of these hosts
joins larger Fluxor graphs the way any other Fluxor peer does — via
remote channels (`protocol_surfaces.md`).

---

## 10. Relationship to the Endpoint Surface

WASM-Fluxor in a browser is **not** the endpoint surface. The endpoint
surface (`endpoint_capability_surface.md`) covers hosts that don't run
a kernel — the typed AV / input / control messages cross into a
non-Fluxor runtime. WASM-Fluxor in a browser runs the kernel; channels
span the boundary instead.

A browser tab can do either, both, or neither, independently:

- WASM-Fluxor only: the tab loads `<config>.wasm`, joins an upstream
  Fluxor graph via remote channels.
- Endpoint surface only: the tab loads the endpoint runtime + an app
  profile (e.g. zedex's setup today) and talks to upstream Fluxor over
  the endpoint session protocol.
- Both: a tab might host a WASM-Fluxor for compute peers while also
  running the endpoint runtime for a presentation surface in the same
  graph. They don't share state.

The choice is a deployment decision, not an architectural one. See
`endpoint_capability_surface.md` §1a.

---

## 11. Validation

A WASM platform integration is healthy when:

- `fluxor build` for `target: wasm` produces a single `.wasm` file
  that runs unchanged on at least two host environments (browser +
  wasmtime), with only host-shim differences.
- Every existing PIC module that doesn't depend on chip-specific
  hardware compiles for wasm32 with no source change beyond a
  `#[cfg]` switch in `modules/sdk/runtime.rs`.
- Modules instantiated via `host_instantiate_module` see the same
  `SyscallTable`-equivalent surface they see on rp2350 / bcm2712 /
  linux. No WASM-specific module logic.
- The `.fmod` envelope, `modules.bin` layout, manifest hash check,
  capability matching, content-type validation, and presentation /
  interaction group rules apply to WASM-bundled modules unchanged.
- A WASM-Fluxor peer joins an upstream native Fluxor peer via remote
  channels using only the kernel's existing remote-channel transport
  modules.
- Adding a new host environment (a new browser-WASM runtime, a new
  edge platform) requires writing a host shim plus the host-specific
  built-in modules, with no changes to the WASM kernel, the WASM
  module ABI, or the bundle format.

WASM should feel like one more row in the target table, not a parallel
universe. The tooling, documentation, and graph definitions for any
existing config should produce a working `.wasm` for any host where
the required capabilities are present.

---

## 12. Open Items

These are deferred but tracked here for visibility:

- **WASM threads and shared memory.** The threads proposal lets
  modules share linear memory and run on parallel workers. Enables
  zero-copy channels and concurrent module ticks. Requires
  `SharedArrayBuffer` (COOP/COEP) in browsers. Defer until a workload
  needs it.
- **Component Model.** Wraps core WASM modules in a typed-interface
  envelope. Useful when exposing a Fluxor module as a consumer of
  non-Fluxor WASM components (or vice versa). Not needed for
  Fluxor-internal use; revisit when component-model toolchains
  stabilise.
- **WASI.** WASI provides POSIX-shaped syscalls. Fluxor's kernel does
  not need them — `wasm32-unknown-unknown` plus the host imports here
  are sufficient. WASI may matter on standalone hosts that prefer it
  as the host import vocabulary; that's a host-doc concern, not a
  platform-doc concern.
- **Bundle signing.** The existing `modules.bin` manifest-hash field
  protects per-module integrity. Bundle-level signature (signing the
  whole `.wasm`) is a deployment-policy concern handled at the host
  layer (e.g. browser SRI, wasmtime signature verification).
- **Live module reload.** WASM hosts can instantiate new module
  versions without restarting the kernel. The reconfigure framework
  (`reconfigure.md`) already covers the in-graph drain/swap dance;
  WASM just changes the loader call from PIC mmap to
  `host_instantiate_module`. Land reconfigure on WASM as a follow-up
  when there's a use case.

---

## 13. Related Documentation

- `architecture/abi_layers.md` — kernel ABI layers; the
  `kernel_abi` layer is what WASM modules see via WASM imports the
  same way native modules see it via `SyscallTable`.
- `architecture/module_architecture.md` — module interface contract,
  identical across targets.
- `architecture/protocol_surfaces.md` — remote-channel surface that
  WASM-Fluxor peers use to join larger graphs.
- `architecture/endpoint_capability_surface.md` — sibling external-host
  surface for environments that don't run a kernel.
- `architecture/reconfigure.md` — drain / migrate phases that apply
  unchanged to WASM hosts.
- `architecture/wasm_browser_host.md` — browser host shim, built-in
  modules, audio unlock, background-throttle policy.
