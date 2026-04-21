# ABI Layers & Contracts

Every API the kernel exposes to a module belongs to exactly one of
five layers. Pick the right layer up front when adding a new API;
wrong layer = redraw before coding.

| Layer | Source | Who may reach it | Contents |
|-------|--------|------------------|----------|
| `kernel_abi` | `modules/sdk/kernel_abi.rs` | Every module (implicit) | Primitives the kernel owns: `SyscallTable`, channel, timer, buffer, event, log, random, arena, poll/errno, query keys, BIND_IRQ, STREAM_TIME |
| `hal` | `modules/sdk/contracts/hal/*.rs` | Modules that claim the hardware contract in their manifest | Privileged hardware contracts — portable abstraction of peripherals (GPIO, SPI, I2C, PIO, UART, ADC, PWM) |
| stable module contracts | `modules/sdk/contracts/{net,storage,key_vault}/*.rs` | Any consumer module | Portable module-provided contracts. Channel-served protocols live here too. |
| `internal` | `modules/sdk/internal/*.rs`, `src/kernel/internal/*.rs` | Kernel and first-party orchestrator modules only | Kernel-private orchestration: bridge, fault monitor, reconfigure, flash raw, backing-provider registration, paged-arena registration, platform MMIO/DMA/PCIe. **Not public; not an extension point.** |
| `platform` | `modules/sdk/platform/{rp,bcm2712}/*.rs`, `src/platform/*.rs` | Chip-specific drivers in `modules/drivers/` only | Chip-specific raw register bridges and layout constants. **Not public; not portable.** |

Adding a new chip is a new `platform/<chip>/*` tree plus its hardware
drivers — no changes to the upper layers. The guardrails are spelled
out in [`.context/rfc_ipc_architecture.md`](../../.context/rfc_ipc_architecture.md) §1.1 and §8.1.

## Kernel primitives — `kernel_abi`

Every PIC module receives a `SyscallTable` at init. It holds exactly:

- `channel_read` / `channel_write` / `channel_poll` — direct ring-buffer I/O
- `heap_alloc` / `heap_free` / `heap_realloc` — per-module heap
- `provider_open` / `provider_call` / `provider_query` / `provider_close` — handle-scoped contract dispatch

Everything else goes through `provider_*`. The kernel tracks each
handle's bound contract and routes calls to the contract's vtable;
contracts can delegate further to a PIC provider module registered
through the loader.

`ABI_VERSION = 1`. There is no backwards-compatibility layer — every
module is built against the current shape.

## Contracts

Contract ids are 16-bit values in `src/kernel/provider.rs::contract`.
Each id corresponds to a contract file under `modules/sdk/contracts/*/`
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
| `KEY_VAULT` | `0x0010` | P-256 slots — ECDH, sign, verify; raw material stays kernel-side |

### Stable module contracts — portable, module-provided

Same shape as HAL contracts — a PIC module provides the implementation,
and consumers reach it through a vtable. Not hardware-specific.
Consumers declare the contract in their manifest with
`requires_contract = "…"`.

| Contract | Id | Provider | Notes |
|----------|----|----------|-------|
| `FS` | `0x0009` | PIC (`fat32`, `linux_fs_dispatch`) | Filesystem dispatch: open/read/write/seek/stat/close. STAT output: 8 bytes `[size:u32 LE, mtime:u32 LE]`. Random-access file I/O; streaming workloads use channel transport instead. |
| `PLATFORM_NIC_RING` | `0x0007` | Kernel (platform) | NIC DMA ring management: `NIC_RING_CREATE` / `INFO` / `DESTROY`. Also requires `platform_raw` permission. |
| `PLATFORM_DMA` | `0x0008` | Kernel (platform) | Raw DMA channel allocation. Handle = channel number. Opcodes under `dma_raw::channel::*`. Also requires `platform_raw` permission. |
| `PLATFORM_DMA_FD` | `0x0011` | Kernel (platform) | Async DMA fd with ping-pong queuing. Handle = tagged fd. Opcodes under `dma_raw::fd::*`. Separate contract from `PLATFORM_DMA`; drivers using both families (e.g. `pio_rp`) declare both in `[[resources]]`. Also requires `platform_raw` permission. |

Plus channel-served protocols (no contract id — there's nothing to
dispatch, just message formats):

- `contracts/net/net_proto.rs` — TCP/UDP control-plane framing between IP and higher layers
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
in [`src/platform/rp_providers.rs`](../../src/platform/rp_providers.rs))
so a raw channel number passed to an fd op — or vice versa — returns
`EINVAL` at the kernel boundary, not an opaque failure downstream.

`required_caps` is a u32 bitmask (ABI v3), so both bits 8 and 17 are
expressible in the manifest bitmask — neither contract is
infra-implicit and neither relies on a special-case fallback.

## Internal orchestration — `internal` layer

The `internal` layer is kernel-private. It holds orchestration
opcodes that are part of kernel plumbing, not a public extension
surface. First-party orchestrator modules declare exactly which
sub-surface they need via the manifest `permissions = [...]` list.

| Permission | Surface | Typical caller |
|------------|---------|----------------|
| `reconfigure` | Graph slot commit, boot counter, FMP routing | `reconfigure` |
| `flash_raw` | Flash ERASE, PROGRAM (bounded to declared sectors) | `flash_rp`, `graph_slot` |
| `backing_provider` | Paged-arena / backing-store registration | `flash_rp`, `nvme` |
| `platform_raw` | MMIO, DMA, PCIe, SMMU, NIC ring create, raw peripheral register bridges | `pwm_rp`, `nvme`, `e810`, `rp1_gem` |
| `monitor` | Fault monitor BIND / WAIT / ACK / REPORT / RAISE | `reconfigure`, `monitor` |
| `bridge` | Cross-domain / cross-core dispatch | kernel-internal |

`check_privileged_internal_op` in [`src/kernel/syscalls.rs`](../../src/kernel/syscalls.rs)
maps each 0x0Cxx opcode to exactly one permission and enforces per-category
access. A module that declares only `flash_raw` cannot reach `platform_raw`
opcodes — over-privilege is structurally prevented.

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

## Platform layer — not public

Chip-specific register bridges and layout constants (`platform::rp::*`,
`platform::bcm2712::*`). Only drivers under `modules/drivers/` may
reach these. They are not portable, and there is no stability
promise — a new chip port rewrites this layer.

## Appendix — the 0x0Cxx opcode range

Kernel primitives (LOG_WRITE, HANDLE_POLL, ARENA_GET, RANDOM_FILL,
BIND_IRQ, STREAM_TIME, …) and internal orchestration opcodes share
the 0x0Cxx opcode namespace under the routing-only contract id
`0x000C`. **This is a transport detail of the dispatch plumbing, not
a public contract category.**

- Primitives in 0x0Cxx are documented in [`kernel_abi`](../../modules/sdk/kernel_abi.rs).
- Orchestration opcodes in 0x0Cxx are documented in [`internal`](../../modules/sdk/internal).
- The opcode → permission mapping is authoritatively defined by
  `privileged_op_permission` in [`src/kernel/syscalls.rs`](../../src/kernel/syscalls.rs).
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
provider. The loader's registration is whitelisted to HAL contracts
and FS; other contract ids are rejected.

## Capabilities

Access control has two distinct gates, and both are enforced on every
`provider_*` call.

**Contract gate** — `check_contract_grant` in [`src/kernel/syscalls.rs`](../../src/kernel/syscalls.rs):
1. **Capability tier** — `current_module_cap_class()` returns a tier
   (Service / Service+GPIO / Service+PIO / Full). Each tier has a
   bitmap of permitted contracts in `CAP_CONTRACT_MASK`.
2. **Manifest grants** — a module's `required_caps` bitmap grants
   access beyond the infra allow-list (CHANNEL, TIMER, BUFFER, EVENT,
   KEY_VAULT, plus the 0x0Cxx transport bucket). Contracts outside
   the allow-list that the module doesn't hold → `ENOSYS`.

**Permission gate** — `check_privileged_internal_op` in the same file:
every privileged 0x0Cxx opcode is classified into exactly one
permission category (`reconfigure`, `flash_raw`, `backing_provider`,
`platform_raw`, `monitor`, `bridge`) by `privileged_op_permission`.
The module must carry the matching category bit in its manifest's
`permissions = [...]` list, or the call returns `ENOSYS`. The only
bypass is `CAP_FULL` (module_type = Protocol, kernel-trusted).

There is no "`required_caps == 0` skips the check" shortcut. A module
that declares nothing gets nothing: no HAL contracts (tier mask
still applies), no privileged 0x0Cxx opcodes (permission gate
refuses). This is what forces over-privilege to be declared
explicitly rather than inherited by default.

## Module categories

Modules live in one of three directories. The tree enforces where they
are *allowed* to reach, not what they *happen* to touch.

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

Examples: `ip`, `tls`, `http`, `mqtt`, `dns`, `fat32`, `wifi`.

A small set of **first-party orchestrator modules** under this tree
(`reconfigure`, `graph_slot`, `ota_ingest`, `monitor`) also import
from `internal::*` and `platform::*` directly — these are the modules
that implement kernel orchestration in PIC form, so they sit at the
foundation layer by location but reach downward into layers normally
reserved for drivers. They are required to declare the matching
`permissions = [...]` entries in their manifest. Treat them as
kernel-adjacent, not as typical foundation modules: new foundation
modules must not take this shape.

### App — `modules/app/`

Domain-specific compositions. Free to consume any foundation or
driver output over channels. Examples: `codec`, `drum`, `effects`,
`mixer`, `rtp`, `sequencer`, `synth`, `voip`.

## What the kernel is

The kernel moves bytes, touches registers, and wakes ISRs. It does
not know what TCP is, what TLS is, what MQTT is, what Raft is, or
what audio looks like. Every protocol, every domain, every piece of
application logic lives in a module.
