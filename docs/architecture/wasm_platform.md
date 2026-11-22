# WASM Platform Target

The WASM target is one of Fluxor's platforms, alongside the bare-metal
silicon (`rp2040`, `rp2350`, `bcm2712`), `uefi`, and `linux` (a Linux
user process). One binary runs on any host environment that provides the
fixed host import surface, without the kernel or modules changing. The
browser is the host Fluxor ships ([wasm_browser_host.md](wasm_browser_host.md));
the import surface is host-neutral so other embeddings (a standalone
WASM engine, an edge runtime) can implement the same contract.

This document is the platform peer of the per-chip platform code under
`src/platform/<chip>/`. It defines the WASM architecture model; host
specifics live in the per-host doc.

---

## 1. Scope

This doc defines:

- the WASM platform's place among the targets
- how WASM module bytes sit inside the `.fmod` envelope
- the wasm bundle format (`.wasm`) and how `fluxor build` produces it
- the kernel/module ↔ host import surface, including the host imports
  that distinguish WASM from native PIC targets
- how the host drives the kernel
- the build pipeline

It does not define:

- a particular WASM host environment (each host has its own doc)
- content types, capability vocabulary, presentation groups, or
  surface families — those are shared by every target
- WASM Component Model bindings — core WASM is the contract

---

## 2. Platform position

| Target    | Module ABI            | Module format | Image format  |
|-----------|-----------------------|---------------|---------------|
| `rp2040`  | thumbv6m PIC ELF      | `.fmod`       | `.uf2`        |
| `rp2350`  | thumbv8m PIC ELF      | `.fmod`       | `.uf2`        |
| `bcm2712` | aarch64 PIC ELF       | `.fmod`       | `.img`        |
| `uefi`    | aarch64 PIC ELF       | `.fmod`       | `.img`        |
| `linux`   | aarch64 PIC ELF       | `.fmod`       | `node.img`    |
| `wasm`    | wasm32 module         | `.fmod`       | `.wasm`       |

Three rules carry across:

1. The graph YAML is target-agnostic. The same `config.yaml` builds
   for any target whose modules and platform support the declared
   capabilities.
2. The module envelope (`.fmod`) is identical across targets — same
   header, export table, params schema and signed manifest. Only the
   code inside the envelope changes.
3. The `fluxor build` tool selects modules and packages them with the
   kernel into the target's image format: a firmware image, a node
   image (`node.img`) on Linux, a wasm bundle on wasm.

The WASM target follows all three: one envelope, one manifest, one
build tool.

---

## 3. Kernel and module code

Source: `src/platform/wasm.rs`, `crates/fluxor-rt/src/wasm.rs`.

Both the Fluxor kernel and every PIC module compile for
`wasm32-unknown-unknown` (no_std, no host imports beyond what this doc
and the host docs define). Outputs:

- `target/wasm32-unknown-unknown/release/fluxor.wasm` — the kernel as a
  single WASM module (built with the `host-wasm` cargo feature). Fluxor
  publishes it as the runtime `fluxor.wasm` (`[project].runtimes`), so a
  consumer's `fluxor sync` installs the pinned kernel at the same path,
  matching the SDK its modules are built against. `make firmware
  TARGET=wasm` also copies it to `target/wasm/firmware.wasm`, like every
  firmware target, but the bundler reads the runtime path.
- `target/fluxor/wasm32/modules/<name>.fmod` — each module's `.fmod`
  envelope, with a wasm32 module as its code payload

The wasm32 build is selected via the Cargo target plus the
`target_arch = "wasm32"` branch of the module SDK runtime
(`crates/fluxor-rt/src/wasm.rs`, `crates/fluxor-rt/src/wasm_entry.rs`).
That branch substitutes the `SyscallTable` struct of fn pointers (used
on PIC targets) with WASM extern imports of the same names. Module
source is unchanged; the SDK runtime talks to the kernel in either
shape.

---

## 4. Module envelope

Source: `crates/fluxor-rt/src/wasm_entry.rs`, `src/platform/wasm/module_host.rs`.

The `.fmod` container is the same on every target
([module_architecture.md](module_architecture.md#binary-and-loader-contract));
for wasm its code section holds the module's wasm32 bytes. The module
table (`modules.bin`), the manifest and its signature, and every
graph-validation rule apply to WASM modules unchanged.

Each module ends its source with `fluxor_rt::wasm_entry!()`, which on
wasm32 emits the two entry points the kernel invokes by name through the
host (§6):

- `module_init_wasm(in_chan, out_chan, ctrl_chan, arena_size) -> i32` —
  the module's first input, output and control channel handles (-1 when
  undeclared; further ports are looked up by name), and the instance's
  heap arena (0: the module's own `MODULE_ARENA_BYTES`). It sizes the
  module's heap from `MODULE_STATE_BYTES` and the arena (a wasm payload
  carries no symbols for the packer to read), pulls the instance params
  through `MODULE_INSTANCE_PARAMS`, and calls the module's `module_init`
  and `module_new`. A negative return skips the module.
- `module_step_wasm() -> i32` — calls the module's `module_step`.

Each module runs as its own wasm instance with its own linear memory;
the kernel hosts it as a native module whose step invokes
`module_step_wasm`. Its heap is a bump allocator over `memory.grow` in
that memory, so heap calls never cross into the kernel.

---

## 5. Bundle format

Source: `tools/src/wasm_bundle.rs`, blob placeholders in
`src/platform/wasm.rs`.

`fluxor build config.yaml` for `target: wasm` emits one file, the wasm
bundle (by default `target/wasm/wasm/<config>.wasm`, under the config's
subdirectory when it has one; `-o` names another). It is self-contained:
kernel + selected modules + config.

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
plus the payload bytes with the real `modules.bin` (the module table)
and `config.bin` (the boot config).
It refuses to write a bundle that overflows a placeholder's capacity
and reports the required size. Graph-declared assets are appended as a
`fluxor.assets` custom section and served by the host through the
`asset://` scheme; a module param names one as `${asset:<name>}`, which a
wasm graph renders as `asset://<name>`. An asset may be built at build time
by a bound stack ([stacks.md](stacks.md#build-time-assets)).

At boot the kernel reads its own blob statics from linear memory
(`used_len` via a volatile read, since the rewrite is invisible to the
compiler), admits the module table and config the way every target
admits a graph, and instantiates each module through the host imports
below. Hosts can also locate the blobs through the exported
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
cryptographic entropy. A successful fill returns 0, not the byte count —
the value is propagated unchanged to callers that test it against 0.

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

host_destroy_module(handle: i32) -> i32
```

Exports are addressed by name; the host owns the export table and the
kernel never sees indices. Invoking an export the module does not have
is an error.

`imports_ptr` / `imports_len` are reserved; the kernel passes
`(null, 0)`. The host wires the module-side syscall surface by name
under the `env` namespace, forwarding each import to the kernel export
of the same name:

```text
env.channel_read    →  kernel.exports.channel_read
env.channel_write   →  kernel.exports.channel_write
env.channel_poll    →  kernel.exports.channel_poll
env.channel_peek    →  kernel.exports.channel_peek
env.channel_discard →  kernel.exports.channel_discard
env.provider_open   →  kernel.exports.provider_open
env.provider_call   →  kernel.exports.provider_call
env.provider_query  →  kernel.exports.provider_query
env.provider_close  →  kernel.exports.provider_close
```

The module and the kernel have separate linear memories, so the host
copies every pointer argument through kernel scratch
(`kernel_heap_alloc` / `kernel_heap_free`, kernel exports) and copies
the result back: both spans of a `provider_call` (`arg` and `data`), a
read's or peek's buffer, a query's answer. A zero-copy channel lend
names kernel memory the module cannot address, so `ACQUIRE_WRITE`,
`ACQUIRE_READ` and `ACQUIRE_INPLACE` answer `ENOTSUP` across the bridge
and the module uses `channel_read` / `channel_write`.

Heap functions live module-side (§4), so they are not in the import
set. Apart from the lend exception, a module sees the same surface as
the `SyscallTable` on PIC targets.

### Host environment imports

Beyond the kernel-uniform set, each host adds a host-environment
import set covering capabilities the WASM sandbox cannot provide
directly: realtime audio, raster output, network, input, persistent
storage. Those imports are the subject of the per-host doc and are
used by native modules: native modules (vtables the platform registers
at init) compiled into the kernel, the way `linux_audio` is a native module
module on the Linux target.

---

## 7. Driving the kernel

The kernel exports its entry points:

```text
kernel_init() -> i32      // 0, or a negative errno
kernel_step() -> u32      // one tick pass; a wait hint in ms (16, about 60 Hz)
```

`kernel_step` runs one pass of the pass engine, the same one RP and
Linux run ([scheduler.md](scheduler.md#passes)), so step outcomes, fault
transitions and step-period gating behave identically. The host calls it
in a loop appropriate to its environment; the browser host calls it from
`requestAnimationFrame` in bounded synchronous bursts, or from a Web
Worker ([wasm_browser_host.md](wasm_browser_host.md#worker-mode)).

The kernel does not assume a tick rate. Modules use monotonic time for
timing-critical work ([timing.md](timing.md)), as on every target. The
host does not poke kernel internals between calls: every externally
observable change happens inside `kernel_step`, which keeps kernel
behaviour identical regardless of which host drives it.

---

## 8. Build pipeline

The user-visible commands parallel the other targets:

```sh
fluxor modules build --target wasm    # → target/fluxor/wasm32/modules/*.fmod
make firmware   TARGET=wasm           # → target/wasm32-unknown-unknown/release/fluxor.wasm
                                      #   (fluxor sync installs it in other projects)
fluxor build    config.yaml           # → target/wasm/wasm/<config>.wasm  (with target: wasm)
```

Internally, `fluxor build` for `target: wasm`:

1. Reads `config.yaml`, resolves the module set and compiles the config,
   per-instance params included, to `config.bin`.
2. Writes the selected `.fmod` files into `modules.bin`, the module
   table every target uses.
3. Loads `target/wasm32-unknown-unknown/release/fluxor.wasm`, rewrites
   the two blob placeholders in place (§5), and appends any declared
   assets.
4. Writes the wasm bundle.

A build for `target: wasm` does not select a host. The same
`<config>.wasm` is handed to any host shim unchanged; hosts differ
only in which host-environment imports they answer and how they drive
`kernel_step`.

---

## 9. Relationship to the endpoint surface

WASM-Fluxor in a browser is not the endpoint surface. The endpoint
surface ([endpoint_capability_surface.md](endpoint_capability_surface.md)) covers hosts that don't run
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
[endpoint_capability_surface.md](endpoint_capability_surface.md#1a-relationship-to-the-remote-channel-surface).

---

## 10. Platform invariants

- `fluxor build` for `target: wasm` produces a single `.wasm` file;
  host differences live entirely in the host shim.
- A PIC module that doesn't depend on chip-specific hardware compiles
  for wasm32 with no source change beyond the SDK runtime's
  `target_arch` switch.
- Modules instantiated via `host_instantiate_module` see the same
  surface as the `SyscallTable` on native targets, less zero-copy
  lends (§6).
- The `.fmod` envelope, module table, manifest signature check,
  capability matching, content-type validation, and presentation-group
  rules apply to modules in a wasm bundle unchanged.
- A WASM-Fluxor peer joins an upstream native Fluxor peer through
  remote channels, using the same remote-channel transport modules.
- Adding a new host environment requires a host shim plus
  host-specific native modules, with no changes to the WASM kernel,
  the module ABI, or the bundle format.

---

## 11. Not supported

- **WASM threads and shared memory.** Every module instance and the
  kernel run on one thread; channels copy between linear memories.
- **Component Model and WASI.** Core WASM and the imports here are the
  whole contract; a standalone host that speaks WASI maps it onto these
  imports itself.
- **Whole-bundle signing.** Each module's manifest signature is checked
  as on every target; the wasm bundle as a whole is not signed.

---

## 12. Related documentation

- [abi_layers.md](abi_layers.md) — kernel ABI layers; WASM modules
  reach the `kernel_abi` layer through imports, native modules through
  `SyscallTable`.
- [module_architecture.md](module_architecture.md) — module interface
  contract, identical across targets.
- [protocol_surfaces.md](protocol_surfaces.md) — the remote-channel
  surface WASM-Fluxor peers use to join larger graphs.
- [endpoint_capability_surface.md](endpoint_capability_surface.md) —
  the surface for hosts that don't run a kernel.
- [reconfigure.md](reconfigure.md) — drain and swap phases, which apply
  unchanged to WASM hosts.
- [wasm_browser_host.md](wasm_browser_host.md) — browser host page,
  shims, and native modules.
