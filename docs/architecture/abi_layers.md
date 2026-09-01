# ABI Layers & Contracts

Every API the kernel exposes to a module belongs to exactly one of
five layers. Pick the right layer up front when adding a new API;
wrong layer = redraw before coding.

| Layer | Source | Who may reach it | Contents |
|-------|--------|------------------|----------|
| `kernel_abi` | `modules/sdk/abi/kernel_abi.rs` | Every module (implicit) | Primitives the kernel owns: `SyscallTable`, channel, timer, buffer, event, log, random, arena, poll/errno, query keys, BIND_IRQ, STREAM_TIME |
| `hal` | `modules/sdk/contracts/hal/*.rs` | Modules that claim the hardware contract in their manifest | Privileged hardware contracts — portable abstraction of peripherals (GPIO, SPI, I2C, PIO, UART, ADC, PWM, PCIe) |
| stable module contracts | `modules/sdk/contracts/` (net, storage, key_vault, workload, input, telemetry, …) | Any consumer module | Portable module-provided contracts. Channel-served protocols live here too. |
| `internal` | `modules/sdk/internal/*.rs`, `src/kernel/internal/*.rs` | Kernel and first-party orchestrator modules only | Kernel-private orchestration: bridge, fault monitor, reconfigure, flash raw, backing-provider registration, paged-arena registration, platform MMIO/DMA/PCIe. Not public; not an extension point. |
| `platform` | `modules/sdk/platform/{rp,bcm2712,linux}/*.rs`, `src/platform/*.rs` | Chip-specific drivers in `modules/drivers/`, plus the owning platform | Chip- and host-specific raw register bridges and layout constants. Not public; not portable. |

Adding a new chip is a new `platform/<chip>/*` tree plus its hardware
drivers — no changes to the upper layers. Keep new APIs in the narrowest
layer that can own them, and do not expose `internal` or `platform`
contracts to portable application modules.

## Kernel primitives — `kernel_abi`

Source: `modules/sdk/abi/kernel_abi.rs`.

Every PIC module receives a `SyscallTable` at init. It holds exactly:

- `channel_read` / `channel_write` / `channel_poll` — direct ring-buffer I/O
- `channel_peek` — copy from a FIFO channel head without advancing the read pointer (frame-aware consumers inspect a header before committing to consume)
- `heap_alloc` / `heap_free` / `heap_realloc` — per-module heap
- `provider_open` / `provider_call` / `provider_query` / `provider_close` — handle-scoped contract dispatch
- `provider_call_sel` — selector-routed provider call: the op names its
  target (e.g. a storage volume) inline via a selector string instead of
  a pre-opened handle, so policy modules can route per-op

Everything else goes through `provider_*`. The kernel tracks each
handle's bound contract and routes calls to the contract's vtable;
contracts can delegate further to a PIC provider module registered
through the loader.

`ABI_VERSION = 1`. There is no backwards-compatibility layer — every
module is built against the current shape.

## Contracts

Contract ids are 16-bit values in `src/kernel/module/provider.rs::contract`.
Each id corresponds to a contract file under `modules/sdk/contracts/`
that defines its opcodes, arg payloads, and response semantics.

### HAL contracts — portable hardware transport

| Contract | Id | Provider | Notes |
|----------|----|----------|-------|
| `HAL_GPIO` | `0x0001` | Kernel (RP) | Claim, set direction, drive level, watch edge |
| `HAL_SPI` | `0x0002` | PIC (`spi_pl022`) | Open with freq/mode/cs, async transfers |
| `HAL_I2C` | `0x0003` | PIC (`i2c_dw`) | Write / read / write-read with slave addr |
| `HAL_PIO` | `0x0004` | PIC (`pio_rp`) | Stream alloc, register bridge, cmd transfer |
| `HAL_UART` | `0x000D` | PIC (`uart_pl011`) | Open / configure / write / read / poll |
| `HAL_ADC` | `0x000E` | PIC (`adc_rp`) | Open / configure / read / poll |
| `HAL_PWM` | `0x000F` | PIC (`pwm_rp`) | Open / configure / set duty |

HAL contracts describe *what* the peripheral does, not *how* the chip
implements it. A PIC provider module owns the per-chip implementation;
portable consumer modules talk to the contract, not the chip.

### Kernel service contracts — always available

These contracts are implemented by the kernel itself. Every module
can reach them without declaring anything in its manifest.

| Contract | Id | Contents |
|----------|----|----------|
| `CHANNEL` | `0x0005` | `open`, `close`, `connect`, `bind`, `listen`, `accept`, `port`, `ioctl` |
| `TIMER` | `0x0006` | `millis`, `micros`, `create`, `set`, `cancel`, `destroy` |
| `BUFFER` | `0x000A` | Zero-copy slot acquisition for in-place writers |
| `EVENT` | `0x000B` | Signalable/pollable flags + IRQ binding |
| `KEY_VAULT` | `0x0010` | P-256 + Ed25519 slots — ECDH, sign, verify, generate; raw material stays backend-side. Backend is platform-overridable (see below). |

#### Kernel service backends — platform-overridable

A kernel service contract has one *default* implementation in
`src/kernel/`, and a platform may re-register the class dispatch and
vtable at platform boot with an alternate backend. The consumer-visible
surface never changes; backends differ only in what the contract's own
discovery opcodes report (for `KEY_VAULT`: `TIER` and `SUITE_QUERY`).

Current backends of `KEY_VAULT`:

| Backend | Source | TIER | Selection |
|---------|--------|------|-----------|
| Software (default) | `src/kernel/security/key_vault.rs` | `SOFTWARE` | Always available |
| PKCS#11 HSM (Linux) | `src/platform/linux/hsm_key_vault.rs` | `PROCESS_HW` | `FLUXOR_HSM_PKCS11_MODULE` env at platform boot |

Rules for adding a backend: it must sit behind an **existing** kernel
service contract (a backend never introduces opcodes consumers must
know about), it must advertise its honest discovery answers so consumers
can adapt, and it must be visible — a row in this table plus a
descriptor under `modules/platform/<platform>/<name>/` (manifest-only,
not graph-placeable) so the inventory of kernel-resident code stays
complete. A hardware token reached over a fluxor bus (e.g. a secure
element on I2C/SPI) is **not** a kernel backend — that is a PIC driver
module providing the contract.

### Stable module contracts — portable

Same shape as HAL contracts — a provider (PIC module, kernel, or
platform) implements the vtable, and consumers reach it through
`provider_*`. Consumers declare the contract in their manifest with
`requires_contract = "…"`.

| Contract | Id | Provider | Notes |
|----------|----|----------|-------|
| `FS` | `0x0009` | PIC (`fat32`, `linux_fs_dispatch`) | Filesystem dispatch: open/read/write/seek/stat/close. |
| `PLATFORM_NIC_RING` | `0x0007` | Kernel (platform) | NIC DMA ring management: `NIC_RING_CREATE` / `INFO` / `DESTROY`. Also requires `platform_raw` permission. |
| `PLATFORM_DMA` | `0x0008` | Kernel (platform) | Raw DMA channel allocation. Handle = channel number. Opcodes under `dma_raw::channel::*`. |
| `PLATFORM_DMA_FD` | `0x0011` | Kernel (platform) | Async DMA fd with ping-pong queuing. Handle = tagged fd. Opcodes under `dma_raw::fd::*`. Separate contract from `PLATFORM_DMA`; see the DMA section below. |
| `PCIE_DEVICE` | `0x0012` | Kernel (platform) | Handle-scoped PCIe device binding; also requires the `pcie_device` permission. |
| `STORAGE_NAMESPACE` | `0x0013` | PIC / platform | Directory-like name-keyed storage surface (opcode class 0x13xx). See [storage_capability_surface.md](storage_capability_surface.md). |
| `STORAGE_OBJECT` | `0x0014` | PIC / platform | Whole-blob byte-addressed storage surface (opcode class 0x14xx). See [storage_capability_surface.md](storage_capability_surface.md). |
| `USB_HOST` | `0x0015` | Kernel (platform) — scaffold only | Handle-scoped USB host controller binding, reserved but not yet implemented. |
| `WORKLOAD` | `0x001A` | Kernel (platform backends) | Platform-neutral isolated-workload surface (opcode class 0x1Axx): run an isolated workload with a declared capability envelope. |
| `STREAM_CLOCK` | `0x001C` | Kernel (platform) | Generic stream-clock capability (opcode class 0x1Cxx) answering the `STREAM_TIME` audio-clock query independently of PIO hardware. |

`FS` STAT output is 8 bytes, `[size:u32 LE, mtime:u32 LE]`. The
contract serves random-access file I/O; streaming workloads use channel
transport instead.

`PCIE_DEVICE` `BIND` takes a selector (board alias like `m2_primary` or
`@class=<name>`) and returns a handle; subsequent ops (`CFG_READ32` /
`WRITE32`, `BAR_MAP`, `MSI_ALLOC`, `INFO`) act on the handle. Board
topology lives in `src/platform/<chip>/pcie_aliases.rs`, not in driver
code.

`USB_HOST` opcodes (`BIND`, `OPEN_ENDPOINT`, `BULK_READ` / `WRITE`,
`INTERRUPT_POLL`, `RELEASE`) are reserved but not implemented;
`provider_open` returns `-ENOSYS` until a host-controller driver lands.
First declared consumer: `modules/foundation/usb_midi_host`.

`WORKLOAD` has two placement-resolved backends: an fmod-graph backend
(MPU/EL0 + owner/lease, bare metal) and a host-process backend
(namespaces/cgroups, Linux). It is gated by
`requires_contract = "workload"` and `platform_raw`.

`STREAM_CLOCK` is where hosts register a dedicated clock provider. On
bare-metal RP the clock is a property of the active PIO stream, so no
provider is registered and the query falls back to `HAL_PIO`.

`HOST_PROCESS` (`0x001B`) is host-scoped, not stable: Linux
host-process mechanics (exec, PTY, read, bundles), registered only by
the Linux platform, with semantic constants at
`abi::platform::linux::host_process`. Unregistered platforms return
`ENOSYS`, which doubles as discovery.

Plus channel-served protocols (no contract id — there's nothing to
dispatch, just message formats):

- `contracts/net/net_proto.rs` — TCP/UDP control-plane framing between IP and higher layers
- `contracts/net/peer_identity.rs` — what a TLS handshake established about
  the peer, with accessors. `tls` writes the record and every consumer reads
  it through this file, so the layout is declared once rather than counted at
  each call site
- `contracts/storage/graph_slot.rs` — OTA reconfigure FMP protocol
- `contracts/storage/runtime_params.rs` — per-module-scoped `STORE` / `DELETE` / `CLEAR_ALL`
- `contracts/storage/paged_arena.rs` — kernel-pager ↔ backing-store protocol

Networking has no kernel-side contract — all of it is channel-based.
Drivers (`cyw43`, `ch9120`, `rp1_gem`, `virtio_net`) exchange Ethernet
frames with the `ip` module over channels, and `ip` exchanges
`net_proto`-framed messages with consumers (`tls`, `http`, `mqtt`, …)
over channels. Netif state transitions propagate as
`MSG_NETIF_STATE` frames on dedicated `netif_state` ports.

### DMA: two distinct public contracts

DMA access is split across two separate contracts with disjoint
handle types. Drivers declare exactly the family (or families) they
need:

| Contract | Id | Opener → handle | Opcodes | Import path |
|----------|----|-----------------|---------|-------------|
| `PLATFORM_DMA` | `0x0008` | `channel::ALLOC` → raw DMA channel number | `ALLOC` / `FREE` / `START` / `BUSY` / `ABORT` | `abi::platform::rp::dma_raw::channel` |
| `PLATFORM_DMA_FD` | `0x0011` | `fd::CREATE` → FD_TAG_DMA-tagged fd | `CREATE` / `START` / `RESTART` / `QUEUE` / `FREE` | `abi::platform::rp::dma_raw::fd` |

Manifest:
```toml
[[resources]]
requires_contract = "platform_dma"       # raw channel family

[[resources]]
requires_contract = "platform_dma_fd"    # async fd family
```

A driver that needs only one family (`spi_pl022` — channels only;
`st7701s` — fds only) declares only that one. A driver that needs
both (`pio_rp` — channels for CMD transfers, fds for streams)
declares both.

The kernel registers separate vtable slots for each contract. Each
contract's dispatcher accepts only its own opcodes; passing a handle
or opcode from the other family routes through the wrong vtable and
fails at dispatch. On top of that, every handler validates the
incoming handle shape (`is_dma_channel_handle` and `is_dma_fd_handle`
in [`src/platform/rp/providers.rs`](../../src/platform/rp/providers.rs))
so a raw channel number passed to an fd op — or vice versa — returns
`EINVAL` at the kernel boundary, not an opaque failure downstream.

`required_caps` is a u64 bitmask in the module header at bytes 6..14,
so every contract id in 0..63 is expressible in the manifest bitmask —
neither DMA contract is infra-implicit and neither relies on a
special-case fallback.

## Internal orchestration — `internal` layer

Source: `modules/sdk/internal/`, `src/kernel/module/syscalls.rs`.

The `internal` layer is kernel-private. It holds orchestration
opcodes that are part of kernel plumbing, not a public extension
surface. First-party orchestrator modules declare exactly which
sub-surface they need via the manifest `permissions = [...]` list.

| Permission | Surface | Typical caller |
|------------|---------|----------------|
| `reconfigure` | Graph slot commit, boot counter, FMP routing | `reconfigure` |
| `flash_raw` | Flash ERASE, PROGRAM (bounded to declared sectors) | `flash_rp`, `graph_slot` |
| `backing_provider` | Paged-arena / backing-store registration, SMMU map | `flash_rp`, `nvme` |
| `platform_raw` | MMIO, NIC ring create, raw peripheral register bridges, workload spawn | `pwm_rp`, `nvme`, `e810`, `rp1_gem` |
| `monitor` | Fault monitor BIND / WAIT / ACK / REPORT / RAISE, step histograms | `reconfigure`, `monitor` |
| `bridge` | Cross-domain / cross-core dispatch | kernel-internal |
| `pcie_device` | Kernel-mediated PCIe device binding (narrower than raw MMIO) | `nvme`, `e810` |
| `dma` | DMA-buffer alloc and cache maintenance on those buffers | DMA-owning drivers |
| `observe` | Read-only telemetry-ring drain (`TLM_SUBSCRIBE` / `DRAIN` / `STATS`) | `observe` |

`check_privileged_internal_op` in
[`src/kernel/module/syscalls.rs`](../../src/kernel/module/syscalls.rs)
maps each privileged opcode to exactly one permission via
`privileged_op_permission` and enforces per-category access. A module
that declares only `flash_raw` cannot reach `platform_raw` opcodes —
over-privilege is structurally prevented.

**New modules should not land opcodes here.** If a new surface is
genuinely needed, it goes into `kernel_abi` (as a primitive every
module can reach) or gets its own contract id with a vtable and
manifest declaration. The `internal` layer is not an "add one more
opcode" shortcut.

### Manifest schema — permissions vs resources

Public contracts go under `[[resources]]`:

```toml
[[resources]]
requires_contract = "gpio"
access = "exclusive"
```

Non-contract permissions go in the top-level `permissions` list — not
inside `[[resources]]`:

```toml
version = "1.0.0"
permissions = ["reconfigure", "monitor"]

[[resources]]
requires_contract = "gpio"
access = "exclusive"
```

`[[resources]]` rejects `"internal"`, `"system"`, or any permission
name with a parser error. This keeps the two surfaces from collapsing
back into a single overloaded list.

### Manifest schema — built-in module params (`[[params]]`)

Built-in modules (those with `builtin = true`) declare their parameter
schema directly in `manifest.toml`:

```toml
version = "1.0.0"
hardware_targets = ["linux"]
builtin = true

[[ports]]
name = "pixels"
direction = "input"
content_type = "VideoRaster"

[[params]]
name = "mode"
type = "enum"
values = ["file", "null", "window"]
default = "file"

[[params]]
name = "width"
type = "u32"
default = 480
range = [1, 4096]

[[params]]
name = "path"
type = "str"
required = true
```

Param types: `u8`, `u16`, `u32`, `str`, `enum`. Tags are auto-assigned
in declaration order starting at 10, so declaration order is wire ABI:
reordering `[[params]]` shifts every wire-side tag. The manifest and
the matching tag constants in `src/platform/linux/<name>.rs` change
together or not at all.

Validation runs at config-build time (`fluxor build`):

- **Unknown param**: hard error with a "did you mean…" hint
  (Levenshtein-based). The packer's flattening rules are mirrored, so
  nested objects (`eq: { low_freq: 100 }`), the transparent
  `params: { ... }` wrapper, and `_envelope`/`_config`/`_settings`/
  `_params` suffix-stripping all resolve correctly.
- **Range**: `range = [min, max]` checks numeric YAML values;
  out-of-range values fail the build with the manifest's bounds.
- **Required**: `required = true` makes YAML omission a hard error —
  use this for params with no safe default (e.g.
  `host_asset_source.path`). Mutually exclusive with `default`.
- **Schema source-of-truth boundary**: `[[params]]` is rejected on
  non-builtin manifests at parse time. PIC modules carry their schema
  in the binary via `define_params!`; declaring it again in the
  manifest would create two sources of truth for the same wire layout.

The wire format is identical to `.fmod` modules — same TLV stream
(`[0xFE][0x01][len_lo][len_hi][tag][len][value]…`). The tool packs
manifest defaults explicitly so every declared param shows up in the
TLV; built-ins don't re-encode defaults in code.

#### Runtime feature cross-check

`fluxor build` (linux family) queries the local `fluxor-linux` binary
via `--print-features` and rejects YAML that asks for an optional
backend the binary doesn't provide. The binary reports every optional
backend it carries; the rows below are the subset a config can select,
and so the subset there is anything to cross-check:

| YAML                                | Required feature  |
|-------------------------------------|-------------------|
| `type = "host_image_codec"`         | `host-image`      |
| `linux_display.mode = "window"`     | `host-window`     |
| `linux_audio.mode = "playback"`     | `host-playback`   |

The error message names the exact `cargo build` invocation that adds
the missing feature.

`host-hsm` is reported but has no row: the PKCS#11 `key_vault` backend
is chosen by environment at platform boot, not by a config field, so
there is nothing in the YAML to check it against.

## Capacity profiles — `abi::config`

Source: `modules/sdk/abi/config.rs`.

Cross-cutting capacity tunables live in one Rust file, re-exported
through `abi::config::*` so the kernel and every PIC module read from
one source. The file is organised as three `profile_*` modules, exactly
one of which is selected at compile time via `cfg(target_arch)`:

| Profile | Selected for | Sample sizes |
|---|---|---|
| `profile_host` | `target_arch = "aarch64"` (Pi 5, Linux host, BCM2712 bare-metal) | `STATE_ARENA_SIZE = 96 MiB`, `BUFFER_ARENA_SIZE = 8 MiB`, `MAX_MODULES = 128`, http `MAX_CONCURRENT_CONNS = 256`, `ELASTIC_REGION_SIZE = 8 MiB` |
| `profile_wasm` | `target_arch = "wasm32"` | `STATE_ARENA_SIZE = 96 MiB`, `BUFFER_ARENA_SIZE = 8 MiB`, `MAX_MODULES = 48`, http `MAX_CONCURRENT_CONNS = 256`, `ELASTIC_REGION_SIZE = 2 MiB` |
| `profile_embedded` | anything else (`thumbv*`) | `STATE_ARENA_SIZE = 256 KiB`, `BUFFER_ARENA_SIZE = 64 KiB`, `MAX_MODULES = 32`, http `MAX_CONCURRENT_CONNS = 1`, `ELASTIC_REGION_SIZE = 0` |

On RP silicon the kernel's arena sizes are overridden per chip by the
silicon TOMLs (`targets/silicon/rp2040.toml`: 64 KiB state / 16 KiB
buffer; `targets/silicon/rp2350.toml`: 256 KiB / 32 KiB);
`profile_embedded`'s figures apply to thumbv targets with no TOML
override.

This is *not* a YAML overlay or a TOML-driven build artefact — it is a
Rust file the SDK compiles into both the kernel and every module.
`src/platform/{linux,wasm,bcm2712}/chip.rs` are thin `pub use` shims
that re-export these constants under the platform's `super::chip::*`
path. Only RP-family chips take chip constants from
`targets/silicon/rp2*.toml`: build.rs reads that file's `[kernel]`
section and emits `chip_generated.rs`, which `src/platform/rp/chip.rs`
`include!`s.

Cross-subsystem invariants are enforced at compile time at the bottom of
the same file, e.g. `http::MAX_CONCURRENT_CONNS <= ip::MAX_TCP_CONNS`.
Adding a tunable means adding it to every `profile_*` module; the
`pub use ...::*` re-export is wildcarded so no extra plumbing is
required at the call site.

`src/kernel/config.rs::MAX_MODULES` is a `pub use` re-export of
`abi::config::kernel::MAX_MODULES`, so the kernel's static module-slot
arrays match what the SDK promises. A compile-time assert catches
bumps that would outgrow the `u64` event-wake bitmap in
`kernel/event.rs`.

## Platform layer — not public

Chip-specific register bridges and layout constants (`platform::rp::*`,
`platform::bcm2712::*`, `platform::linux::*`). Only drivers under
`modules/drivers/` and the owning platform may reach these. They are
not portable, and there is no stability promise — a new chip port
rewrites this layer.

## Appendix — the 0x0Cxx opcode range

Kernel primitives (LOG_WRITE, HANDLE_POLL, ARENA_GET, RANDOM_FILL,
BIND_IRQ, STREAM_TIME, …) and internal orchestration opcodes share
the 0x0Cxx opcode namespace under the routing-only contract id
`0x000C`. This is a transport detail of the dispatch plumbing, not a
public contract category.

- Primitives in 0x0Cxx are documented in [`kernel_abi`](../../modules/sdk/abi/kernel_abi.rs).
- Orchestration opcodes in 0x0Cxx are documented in [`internal`](../../modules/sdk/internal).
- The opcode → permission mapping is authoritatively defined by
  `privileged_op_permission` in [`src/kernel/module/syscalls.rs`](../../src/kernel/module/syscalls.rs).
  New opcodes must be classified there explicitly; unknowns fall
  through to the strictest `platform_raw` bucket.
- The dispatch-bucket id `0x000C` is exposed in the kernel only as
  `contract::INTERNAL_DISPATCH_BUCKET` — a routing constant, not a
  public contract. `syscall_provider_open` **rejects** modules passing
  this id with `ENOSYS`. Modules that need ring/DMA handle allocation
  go through the first-class contracts in the stable-module-contracts
  table above (`PLATFORM_NIC_RING`, `PLATFORM_DMA`).

No new public API may land in 0x0Cxx unless it is promoted into
`kernel_abi` (implicit for every module) or given its own contract id
with a vtable. The long-term move is to split each orchestration
sub-surface into its own contract so the 0x0Cxx transport goes away
entirely.

## Provider registration

PIC provider modules (the HAL and FS providers above) export two
well-known functions:

```rust
#[no_mangle]
#[link_section = ".text.module_provides_contract"]
pub extern "C" fn module_provides_contract() -> u32 {
    0x000F  // the contract id this module provides
}

#[no_mangle]
#[link_section = ".text.module_provider_dispatch"]
pub unsafe extern "C" fn module_provider_dispatch(
    state: *mut u8, handle: i32, opcode: u32, arg: *mut u8, arg_len: usize,
) -> i32 { /* ... */ }
```

The loader resolves both after `module_new()` succeeds and calls
`provider::register_module_provider()`. There is no runtime
registration syscall — a module that doesn't export these is not a
provider. The loader's registration is whitelisted to the HAL
contracts, FS, and the storage namespace/object contracts
(`is_module_providable` in `src/kernel/module/provider.rs`); other
contract ids are rejected.

## Capabilities

Source: `src/kernel/module/syscalls.rs`.

Access control has two distinct gates, and both are enforced on every
`provider_*` call.

**Contract gate** — `check_contract_grant`:
1. **Capability tier** — `current_module_cap_class()` returns a tier
   (Service / Service+GPIO / Service+PIO / Full). Each tier has a
   bitmap of permitted contracts in `CAP_CONTRACT_MASK`.
2. **Manifest grants** — a module's `required_caps` bitmap grants
   access beyond the infra allow-list (CHANNEL, TIMER, BUFFER, EVENT,
   KEY_VAULT, plus the 0x0Cxx transport bucket). Contracts outside
   the allow-list that the module doesn't hold → `ENOSYS`.

**Permission gate** — `check_privileged_internal_op` in the same file:
every privileged opcode is classified into exactly one permission
category (see the internal-layer table above) by
`privileged_op_permission`. The module must carry the matching category
bit in its manifest's `permissions = [...]` list, or the call returns
`ENOSYS`. The only bypass is `CAP_FULL` (module_type = Protocol,
kernel-trusted).

There is no "`required_caps == 0` skips the check" shortcut. A module
that declares nothing gets nothing: no HAL contracts (tier mask
still applies), no privileged 0x0Cxx opcodes (permission gate
refuses). This is what forces over-privilege to be declared
explicitly rather than inherited by default.

## Module categories

In-repo modules live in one of four trees; app modules live in sibling
repositories. The tree enforces where a module is *allowed* to reach,
not what it *happens* to touch. `drivers/`, `foundation/`, and
`fixtures/` hold PIC modules loaded at runtime as `.fmod` artefacts;
`modules/platform/<platform>/` holds descriptors for built-ins compiled
directly into the kernel binary.

### Drivers — `modules/drivers/`

Touch hardware directly. Use HAL contracts (`HAL_SPI`, `HAL_PIO`, …)
or platform raw-register bridges. Named after what they drive
(`cyw43`, `ch9120`, `nvme`, `rp1_gem`, `st7701s`, `enc28j60`, …).
Platform-coupled by design; not expected to be portable.

Providers for HAL contracts also live here (`spi_pl022`, `i2c_dw`,
`pio_rp`, `uart_pl011`, `adc_rp`, `pwm_rp`, `flash_rp`).

### Foundation — `modules/foundation/`

Touch stable module contracts (FS, net_proto channels), kernel
primitives, and timers/events. No direct hardware.

Examples: `ip`, `tls`, `dns`, `fat32`, `wifi`, `quic`.

A small set of **first-party orchestrator modules** under this tree
(`reconfigure`, `graph_slot`, `ota_ingest`, `monitor`) also import
from `internal::*` and `platform::*` directly — these are the modules
that implement kernel orchestration in PIC form, so they sit at the
foundation layer by location but reach downward into layers normally
reserved for drivers. They are required to declare the matching
`permissions = [...]` entries in their manifest. Treat them as
kernel-adjacent, not as typical foundation modules: new foundation
modules must not take this shape.

### App — sibling repositories

Domain-specific compositions. Free to consume any foundation or
driver output over channels. App modules live in sibling
repositories (grove, spectra, wave), built against the Fluxor SDK
and loaded like any other PIC module. Examples: `codec`, `drum`,
`effects`, `mixer`, `sequencer`, `synth`.

### Fixtures — `modules/fixtures/`

Probes, load generators, and protocol-surface demonstration modules —
built and loaded exactly like foundation/app PIC modules, but not
part of the stable module vocabulary and never shipped in a product
graph. Examples: `load_gen`, `test_fault`, `tier2_probe`, the
`iso_*` EL0-isolation probes, the `nvme_*_probe` bring-up probes,
`synth_source`, and the `echo_anchor`/`echo_worker` continuity-role
demonstration pair. Keeping them out of `foundation/`
preserves that tree's stable-vocabulary property (shadowing a
foundation name is a build error; a fixture name carries no such
weight). Fixtures are not publishable via `fluxor publish`.

### Built-in — `modules/platform/<platform>/<name>/`

Manifest-only descriptors for kernel-resident built-ins — modules
whose Rust code is linked into the kernel binary rather than shipped
as a `.fmod`. Each subdirectory holds `manifest.toml` (read by the
config tool for validation and TLV packing) and `README.md`. The
implementation lives under `src/platform/<platform>/<name>.rs`.

The platform subdirectory makes the binding explicit:

| Subtree                 | Binding                                                                                  | Examples                                                |
|-------------------------|------------------------------------------------------------------------------------------|---------------------------------------------------------|
| `modules/platform/linux/` | Linux-host APIs (winit, CPAL/ALSA, libc syscalls) plus host-agnostic `std` built-ins   | `linux_net`, `linux_display`, `linux_audio`, `host_asset_source`, `host_image_codec` |
| `modules/platform/wasm/`  | Browser APIs (Canvas, WebAudio, DOM, fetch)                                            | `wasm_browser_canvas`, `wasm_browser_audio`, `wasm_browser_keyboard`, `host_browser_fetch` |

Built-in vs PIC is a **deployment** distinction: built-ins compile
into the kernel because their platform lacks a PIC loader (wasm) or
sits below it (Linux runtime sinks). Selection is orthogonal —
`stacks/*.toml` route logical surfaces (`display`, `audio`, `net`) to
either a PIC driver or a built-in via board/family/platform match
keys, with no per-stack-file knowledge of the deployment shape. The
multi-platform model is documented in
[wasm_platform.md](wasm_platform.md) and
[wasm_browser_host.md](wasm_browser_host.md).

Built-in manifests carry `builtin = true`. Their `[[params]]` schema
is read by the config tool and packed into the same TLV stream PIC
modules use; the kernel's deserialiser is identical for both kinds.
See "Manifest schema — built-in module params" above for the schema
language.

## What the kernel is

The kernel moves bytes, touches registers, and wakes ISRs. It does
not know what TCP is, what TLS is, what MQTT is, what HTTP is, or
what audio looks like. Every protocol, every domain, every piece of
application logic lives in a module.

### What may live in the kernel binary

Exactly three kinds of device- or service-shaped code are allowed to
compile into the kernel binary; everything else is a PIC module:

1. **Raw register/boot bridges** behind platform contracts —
   PCIe binding, DMA, NIC rings, GPIO, MMU/GIC/boot code in
   `src/platform/<chip>/`.
2. **Kernel service contract implementations** and their
   platform-overridable backends (CHANNEL, TIMER, BUFFER, EVENT,
   KEY_VAULT) — each backend documented in the backends table above
   with a descriptor under `modules/platform/<platform>/`.
3. **Built-in modules** — host-API drivers that are manifest-declared
   under `modules/platform/<platform>/<name>/` and therefore visible to
   the config tool and inventory.

Anything device-shaped in the binary that is not manifest-visible or
listed in the backends table is drift by construction — it bypasses
the mechanism that keeps kernel-resident drivers accountable.

## Vocabulary admission

Fluxor owns every shared naming and numeric namespace — `CONTENT_TYPES`
wire bytes, `CAPABILITY_NAMES`, `PROVIDER_CONTRACTS`, contract ids,
permission bits, fd tags. Centrality is what makes cross-repo wiring
and drift-guarding possible, so the tables stay here; the question is
only what earns an entry. Apply this two-question test to every
proposed name:

1. **Does the kernel or fluxor tooling need it to route, validate, or
   gate?** A wire byte the kernel routes by, a manifest name the config
   compiler validates, a contract id with a vtable, a permission bit —
   central, no debate.
2. **Is it a substitution point across repo boundaries?** Could a
   producer or consumer from a *different* sibling plausibly sit on
   either end of the edge? If yes — central: surfaces exist precisely
   so siblings interoperate without depending on each other. If the
   only parties that will ever speak it are a matched pair inside one
   sibling — it stays sibling-private, riding a generic envelope.

Fail both questions and the name does not land, however useful it is
to the sibling proposing it.

**Envelope vs. payload.** Central vocabulary names the envelope — the
generic, substitutable surface. The payload schema inside it is
sibling-owned. `EventTimelineVideo` / `EventTimelineAudio` are the
canonical example: the surface declares "frame-aligned event stream,
video/audio flavour" and receivers parse the sibling-defined inner
packet; the producer's domain identity never enters the table. The GPU
capabilities follow the same split (`gpu.render` / `gpu.compute` are
central; renderer-level semantics live in the sibling that owns them).
Any sibling that needs private semantics gets them this way — never by
minting a central name.

**No implementation enumerations.** A name must identify *what the
data is*, not *which implementation produced it*. Codec identity is
the standing example: encoded surfaces are the generic `AudioEncoded`
/ `VideoEncoded`, and codec identity travels in-band (access units and
containers are self-describing) or as a capability fact on the edge —
per-codec content types are rejected. The same reasoning bars
per-vendor, per-chip, or per-protocol-revision forks of any existing
surface; those are facts or in-band discriminants, not names.

**Review smell.** If evaluating a table addition requires
understanding one sibling's internals, the entry is in the wrong
place. A central name must be reviewable from its own definition:
what bytes flow, what substitutes for what, and what the kernel or
tooling does with it.

## Boundary rulings

Standing decisions on ABI vocabulary and surface placement. Code
comments may summarise these; this section is the authority. Each
ruling records the condition under which it reopens.

### POSIX vocabulary at the kernel boundary: retained

`fd` (tagged handle), `errno` (negative error code), poll flags, and
syscall terminology at the kernel/module boundary are retained
deliberately. They are universally understood OS primitives, not
orchestrator vocabulary; renaming them to invented equivalents
(handle/readiness/control-op) would churn the entire ABI and every
consumer for no architectural gain. Higher-level orchestration
vocabulary is native Fluxor (`owner`, `workload`, `lease`, `posture`,
`endpoint`, `drain`); Kubernetes vocabulary lives in nanocloud, which
translates at its boundary.

Reopens if: Fluxor grows a public API audience for whom POSIX
vocabulary actively misleads (e.g. an `fd` that stops behaving like a
handle table).

### Source organisation: domain directories

Every kernel and SDK source file lives under a domain directory; there
are no loose top-level implementation files. Domains are formed by
consolidating similar concerns into a small set of coherent
directories (kernel: `boot exec ipc mem module security sys workload`;
SDK: `abi contracts cores crypto internal platform runtime wire
assets`) — not one directory per file, and not flat-until-forced.
Named exceptions, each justified as an entry point or generated
artefact that other files path-mount: `modules/sdk/abi.rs` (the
assembler), `abi_surface.rs` / `abi_surface_srcpin.rs` (the pin
machinery, path-referenced by `tools/src/abi_pin.rs` — see
[abi_surface.md](abi_surface.md)), `runtime.rs` (the module-side
aggregator), `fence.rs` (a cross-cutting ABI value type at the `abi`
root).

A domain earns a new directory when a concern stops reading as one
of the existing domains — prefer widening an existing domain over
minting a new one.

### Host-process semantics live outside the stable native surface

The stable 0x1A workload contract carries only the native core
(CREATE / START / WAIT / portable SIGNAL / DESTROY / PAUSE / RESUME /
CAPS plus the Tier-1 header). Host-process mechanics — READ / EXEC /
TTY_* opcodes, SOURCE_BUNDLE, FD_TAG_PROC, and the process-executor
class — live in the host-scoped class
`abi::platform::linux::host_process` (0x1B), registered only by the
Linux platform; unregistered = `ENOSYS` = discovery. Workload-targeting
ops carry the tagged fd as an in-argument, since handle-tagged calls
route by tag→class. Retired 0x1A positions are not reused; CAPS bits
0..2 are reserved, and the stable caps define only the bit-0 native
source kind. The generic kernel carries no host vocabulary: the proc
fd-tag routes via the platform-registered `register_fd_tag_route`
table, and the kernel registry keeps class 0x0016 — the host-process
executor class position — and its fd tag 25 only as reserved numerics.

### Container isolation: generic primitive in fluxor, OCI policy in nanocloud

The isolation mechanism (`src/platform/linux/host_backend.rs`:
fork/unshare/cgroups/rootfs) needs host `std`, and nanocloud has no
std-native code — it is entirely no_std PIC modules run by
fluxor-linux, the only std host on a node. So the mechanism cannot be
a nanocloud module. Instead it stays in fluxor's Linux platform,
reduced to a generic isolation primitive that knows no OCI format:
`build_plan(argv, rootfs, isolate)` takes explicit parameters, cgroup
limits come solely from the portable `ResourceEnvelope`, and the
workload CREATE source section carries explicit spawn params
(`[isolate:u8][rootfs_len:u16][rootfs][argv NUL-sep]`) rather than a
bundle-directory path. Nanocloud owns the OCI→params mapping — the
policy half — mirroring how the nanocloud CLI is built: a PIC fmod
owning logic plus fluxor host built-ins for host facts.
