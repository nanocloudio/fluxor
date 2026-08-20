# WASM Platform Target

The WASM target is one of Fluxor's supported platforms, alongside
`rp2350` (bare-metal silicon), `bcm2712` (Pi 5), and `linux` (generic
Linux user-process). Its defining feature is that one binary
architecture runs on any host environment that provides the fixed host
import surface, without the kernel or modules changing. The browser is
the host that exists today (`wasm_browser_host.md`); the import
surface is deliberately host-neutral so other embeddings (a standalone
WASM engine, an edge runtime) can implement the same contract.

This document is the platform peer of the per-chip platform code under
`src/platform/<chip>/`. It defines the WASM architecture model; host
specifics live in the per-host doc.

---

## 1. Scope

This doc defines:

- the WASM platform's place in the existing target table
- the module envelope (`.fmod`) and how WASM module bytes sit inside it
- the bundle format (`.wasm`) and how `fluxor build` produces it
- the kernel/module ↔ host import surface, including the host imports
  that distinguish WASM from native PIC targets
- the scheduler tick model
- the build pipeline and its parallels with the existing targets

It does not define:

- a particular WASM host environment (deferred to host docs)
- new content types, capability vocabulary, presentation groups, or
  surface families — those remain authoritative across all targets
- WASM Component Model bindings — core WASM is the contract

---

## 2. Platform position

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
   shape. Only the code payload inside the envelope changes.
3. The `fluxor build` tool selects modules and packages them with the
   kernel into the target's bundle format.

The WASM target follows all three. There is no parallel envelope, no
parallel manifest, no parallel build tool.

---

## 3. Kernel and module code

Source: `src/platform/wasm.rs`, `modules/sdk/runtime/wasm.rs`.

Both the Fluxor kernel and every PIC module compile for
`wasm32-unknown-unknown` (no_std, no host imports beyond what this doc
defines). Outputs:

- `target/wasm/firmware.wasm` — the kernel as a single WASM module
  (built with the `host-wasm` cargo feature)
- `target/fluxor/wasm/modules/<name>.fmod` — each module's `.fmod`
  envelope, with a wasm32 module as its code payload

The wasm32 build is selected via the Cargo target plus the
`target_arch = "wasm32"` branch of the module SDK runtime
(`modules/sdk/runtime/wasm.rs`, `modules/sdk/runtime/wasm_entry.rs`).
That branch substitutes the `SyscallTable` struct of fn pointers (used
on PIC targets) with WASM extern imports of the same names. Module
source is unchanged; the SDK runtime knows how to talk to the kernel
for either ABI shape.

---

## 4. Module envelope

The `.fmod` envelope is unchanged from native targets:

```
[ magic | version | manifest_hash | exports_table | params_tlv | code_payload ]
```

Only `code_payload` differs across targets: for wasm it is the raw
wasm32 module bytes for that module.

A module's wasm32 code exposes wasm-specific entry points that the
kernel invokes by export name through the host (§6):
`module_init_wasm` (no-arg init, replacing the pointer-argument native
entry), `module_step_wasm` (no-arg step), and the optional
`module_arena_size` probe. The kernel probes optional exports with
`host_module_export_exists` before invoking them.

A module's wasm32 code does not contain its `.fmod` parameters or
manifest hash — those live in the envelope's `params_tlv` and
`manifest_hash` fields exactly as on rp2350. The envelope is the
target-agnostic packaging, so the existing `.fmod` packing code, the
`modules.bin` layout, and every existing graph-validation rule apply
to WASM modules unchanged.

---

## 5. Bundle format

Source: `tools/src/wasm_bundle.rs`, blob placeholders in
`src/platform/wasm.rs`.

`fluxor build config.yaml` for `target: wasm` emits one file:
`target/wasm/<config>.wasm`. That file is a self-contained
single-instance bundle: kernel + selected modules + config.

The kernel's Cargo build emits two placeholder blob structs as
`#[no_mangle] pub static` data, each laid out as:

```text
[0..16]   magic     — 16-byte ASCII sentinel (FLUXOR_MOD_BLOB / FLUXOR_CFG_BLOB)
[16..20]  capacity  — u32 LE, bytes available in `data`
[20..24]  used_len  — u32 LE, zero in the placeholder
[24..32]  reserved
[32..N]   data      — capacity bytes, zero in the placeholder
```

The bundle tool locates each sentinel in the kernel `.wasm` (it must
occur exactly once), validates the header, and overwrites `used_len`
plus the payload bytes with the real `modules.bin` and `config.bin`.
It refuses to write a bundle that overflows a placeholder's capacity
and reports the required size, so the kernel can be rebuilt with a
larger placeholder. Graph-declared assets are appended as a
`fluxor.assets` custom section and served by the host through the
`asset://` scheme.

At boot the kernel reads its own blob statics from linear memory
(`used_len` via a volatile read, since the rewrite is invisible to the
compiler), parses `modules.bin` the same way the Linux runtime parses
its on-disk `modules.bin`, and instantiates each module via the host
imports below. Hosts can also locate the blobs through the exported
accessors `kernel_modules_blob_offset` / `_len` / `_capacity` and
`kernel_config_blob_offset` / `_len` / `_capacity`.

---

## 6. Host import surface

Source: `src/platform/wasm.rs`, `src/platform/wasm/hal.rs`.

The kernel imports a small fixed set of functions from the WASM host.
The set is host-neutral: hosts implement these functions in their own
language but expose the same names and signatures under the `env`
namespace.

### Time, log, random

```text
host_now_us() -> u64
host_log(level: u32, ptr: *const u8, len: usize)
host_panic(ptr: *const u8, len: usize) -> !
host_csprng_fill(buf: *mut u8, len: usize) -> i32
```

The time and log imports fill the role the platform timer and UART
logging fill on rp2350. `host_csprng_fill` fills a buffer with
cryptographically secure random bytes (browser hosts delegate to
`crypto.getRandomValues`); hosts that cannot provide a CSPRNG must
return a negative errno, because TLS and key generation treat this as
cryptographic entropy.

### Memory

WASM linear memory is the kernel's heap. There is no `host_alloc`
import — the kernel manages its own linear memory with an in-binary
allocator, the way rp2350 manages its own RAM. The host only sets the
memory's growth limit at instantiation time.

### Module instantiation — the WASM-specific addition

PIC ELF on native targets is loaded by the kernel itself: map, fix up
relocations, jump to the entry point. A WASM module cannot instantiate
other WASM modules (the engine has to do it), so the kernel delegates
back to the host:

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
    ret_ptr: *mut u8,              // host writes the i32 return value here
    ret_cap: usize,
) -> i32                           // bytes written to ret_ptr, or negative errno

host_module_export_exists(
    handle: i32,
    export_name_ptr: *const u8,
    export_name_len: usize,
) -> i32                           // 1 if exported, 0 if absent, negative on bad handle

host_destroy_module(handle: i32) -> i32
```

Exports are addressed by name; the host owns the export table and the
kernel never sees indices. `host_module_export_exists` is the quiet
probe for optional exports; callers use it before invoking when an
export is optional. Args are packed as a sequence of i32
little-endian values, one per parameter.

`imports_ptr` / `imports_len` are reserved; the kernel passes
`(null, 0)`. The host wires the module-side syscall surface by name
under the `env` namespace, forwarding each import to the kernel export
of the same name:

```text
env.channel_read   →  kernel.exports.channel_read
env.channel_write  →  kernel.exports.channel_write
env.channel_poll   →  kernel.exports.channel_poll
env.provider_open  →  kernel.exports.provider_open
env.provider_call  →  kernel.exports.provider_call
env.provider_query →  kernel.exports.provider_query
env.provider_close →  kernel.exports.provider_close
```

Heap functions live module-side (each module's allocator backed by
`memory.grow` in its own linear memory), so they are not in the
import set.

These are the only kernel-uniform imports. Everything else the
modules see is the kernel's exported syscall surface, identical to the
`SyscallTable` on PIC targets.

### Host environment imports

Beyond the kernel-uniform set, each host adds a host-environment
import set covering capabilities the WASM sandbox cannot provide
directly: realtime audio, raster output, network, input, persistent
storage. Those imports are the subject of the per-host doc and are
implemented by built-in modules on the host side, the way
`linux_audio` is a built-in module on the Linux target.

---

## 7. Tick driver

The kernel's scheduler runs as exported functions:

```text
kernel_init() -> i32
kernel_step() -> u32      // hint: ms until the next useful tick; 0 = run again immediately
```

The host calls `kernel_step` in a loop appropriate to its environment.
The browser host pumps it from `requestAnimationFrame` in bounded
synchronous bursts, optionally moving the whole pump into a Web
Worker; see `wasm_browser_host.md`.

The kernel does not assume a specific tick rate. Modules use monotonic
time for timing-critical work (`module_architecture.md`), the same
rule as every target. The host does not poke kernel internals between
ticks: every externally observable change happens inside
`kernel_step`, which keeps kernel behaviour identical regardless of
which host drives it.

---

## 8. Build pipeline

The user-visible commands parallel the other targets:

```sh
fluxor modules build --target wasm    # → target/fluxor/wasm/modules/*.fmod
make firmware   TARGET=wasm           # → target/wasm/firmware.wasm
fluxor build    config.yaml           # → target/wasm/<config>.wasm  (with target: wasm)
```

Internally, `fluxor build` for `target: wasm`:

1. Reads `config.yaml`, resolves the module set, packs each module's
   parameters into its `.fmod` TLV section.
2. Concatenates the selected `.fmod` files into `modules.bin` (same
   layout as every other target) and compiles the config to
   `config.bin`.
3. Loads `target/wasm/firmware.wasm`, rewrites the two blob
   placeholders in place (§5), and appends any declared assets.
4. Writes the result to `target/wasm/<config>.wasm`.

A build for `target: wasm` does not select a host. The same
`<config>.wasm` is handed to any host shim unchanged; hosts differ
only in which built-in modules they provide and in the tick driver.
Host built-ins are mounted into the graph at scheduler init via the
same builtin-module mechanism the Linux runtime uses.

---

## 9. Relationship to the endpoint surface

WASM-Fluxor in a browser is not the endpoint surface. The endpoint
surface (`endpoint_capability_surface.md`) covers hosts that don't run
a kernel — the typed AV / input / control messages cross into a
non-Fluxor runtime. WASM-Fluxor in a browser runs the kernel; channels
span the boundary instead.

A browser tab can do either, both, or neither, independently:

- WASM-Fluxor only: the tab loads `<config>.wasm` and joins an
  upstream Fluxor graph via remote channels.
- Endpoint surface only: the tab loads the endpoint runtime plus an
  app profile and talks to upstream Fluxor over the endpoint session
  protocol.
- Both: a tab hosts a WASM-Fluxor for compute while also running the
  endpoint runtime for a presentation surface in the same graph. They
  don't share state.

The choice is a deployment decision, not an architectural one. See
`endpoint_capability_surface.md` §1a.

---

## 10. Platform invariants

- `fluxor build` for `target: wasm` produces a single `.wasm` file;
  host differences live entirely in the host shim.
- A PIC module that doesn't depend on chip-specific hardware compiles
  for wasm32 with no source change beyond the SDK runtime's
  `target_arch` switch.
- Modules instantiated via `host_instantiate_module` see the same
  `SyscallTable`-equivalent surface they see on rp2350 / bcm2712 /
  linux.
- The `.fmod` envelope, `modules.bin` layout, manifest hash check,
  capability matching, content-type validation, and presentation-group
  rules apply to WASM-bundled modules unchanged.
- A WASM-Fluxor peer joins an upstream native Fluxor peer via remote
  channels using the kernel's existing remote-channel transport
  modules.
- Adding a new host environment requires a host shim plus
  host-specific built-in modules, with no changes to the WASM kernel,
  the module ABI, or the bundle format.

---

## 11. Open items

Status: design targets, not wired.

- **WASM threads and shared memory.** The threads proposal would allow
  zero-copy channels and concurrent module ticks; it requires
  `SharedArrayBuffer` (COOP/COEP) in browsers. Deferred until a
  workload needs it.
- **Component Model.** Useful when exposing a Fluxor module to
  non-Fluxor WASM components; not needed for Fluxor-internal use.
- **WASI.** The kernel does not need POSIX-shaped syscalls —
  `wasm32-unknown-unknown` plus the imports here are sufficient. WASI
  could matter as the import vocabulary on a standalone host; that is
  a host-doc concern.
- **Bundle signing.** The `modules.bin` manifest-hash field protects
  per-module integrity; whole-bundle signature is a deployment-policy
  concern at the host layer.
- **Live module reload.** WASM hosts can instantiate new module
  versions without restarting the kernel; the reconfigure framework
  (`reconfigure.md`) covers the in-graph drain/swap sequence, and on
  WASM the loader call is `host_instantiate_module` instead of a PIC
  map.

---

## 12. Related documentation

- `abi_layers.md` — kernel ABI layers; the `kernel_abi`
  layer is what WASM modules see via WASM imports the same way native
  modules see it via `SyscallTable`.
- `module_architecture.md` — module interface contract,
  identical across targets.
- `protocol_surfaces.md` — remote-channel surface that
  WASM-Fluxor peers use to join larger graphs.
- `endpoint_capability_surface.md` — external-host
  surface for environments that don't run a kernel.
- `reconfigure.md` — drain / migrate phases that apply
  unchanged to WASM hosts.
- `wasm_browser_host.md` — browser host page, shims, and
  built-in modules.
