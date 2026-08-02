# HAL Architecture

The Hardware Abstraction Layer is the boundary between the Fluxor kernel
and the silicon it runs on. It exposes a small set of bus and timer
primitives to PIC modules through a stable syscall ABI. Everything above
those primitives — protocols, drivers for individual chips, application
logic — lives in modules.

## Design Principles

1. **HAL provides primitives, not protocols.** GPIO, SPI, I2C, PIO, UART,
   timers, DMA. Anything more specific (a TFT display controller, an
   audio DAC, a CAN bus chip) is a module that uses these primitives.
   The portable surface lives under
   `modules/sdk/contracts/hal/{gpio,spi,i2c,pio,uart,adc,pwm}.rs`;
   chip-specific raw register bridges live under
   `modules/sdk/platform/<chip>/*`.

2. **One stable contract surface across silicon.** The HAL contract
   opcodes are identical on RP2040, RP2350, BCM2712, and (planned)
   ESP32. The kernel implementation behind each opcode differs per
   silicon, but a PIC module never sees that difference. Adding a new
   chip is a new `platform/<chip>/*` tree plus HAL backings — it does
   not change the public ABI.

3. **No hidden state.** Pin assignments, bus configurations, and clock
   settings come from the config binary at boot. The kernel does not
   probe hardware or guess pin functions. The chip is brought up exactly
   as the config says, and modules acquire resources by name from the
   resulting registry.

4. **Async by default, blocking never.** Every long-running hardware
   operation has start/poll semantics. A module begins a transfer, the
   step returns, and a later step polls for completion. The kernel does
   not block any syscall waiting for hardware.

5. **Onboard hardware is just a module.** BOOTSEL, status LED, and
   on-package WiFi chips are PIC modules. They use the same syscall
   surface as anything else. The HAL has no special path for them.

## Architecture Overview

```
+--------------------------------------------------------------------+
|                            App Layer                               |
|     synth, mixer, voip, sequencer, codec, raft_engine, ...         |
|                          (PIC modules)                             |
+--------------------------------------------------------------------+
|                        Foundation Layer                            |
|        ip, fat32, http, dns, mqtt, tls, wifi, mesh, ...            |
|                          (PIC modules)                             |
+--------------------------------------------------------------------+
|                          Driver Layer                              |
|        cyw43, enc28j60, virtio_net, sd, st7701s, gt911, i2s ...    |
|                          (PIC modules)                             |
+--------------------------------------------------------------------+
                    Stable Syscall ABI (provider_open/call/query/close)
+--------------------------------------------------------------------+
|                            Kernel                                  |
|     scheduler  •  channels  •  events  •  loader  •  syscalls      |
+--------------------------------------------------------------------+
|                              HAL                                   |
|        gpio  •  spi  •  i2c  •  pio  •  uart  •  timer  •  dma     |
+--------------------------------------------------------------------+
|                            Silicon                                 |
|             RP2040  •  RP2350  •  BCM2712  •  Pi 5                  |
+--------------------------------------------------------------------+
```

The driver, service, and application layers are all PIC modules. The
boundary they cross is the syscall ABI exposed by the kernel. The HAL
sits beneath the kernel and is responsible for talking to the actual
hardware on each silicon target.

## Per-Silicon HAL Implementations

Each silicon target has its own HAL implementation under `src/platform/`:

| Target | Platform file | Runtime model |
|--------|--------------|---------------|
| RP2040 | `src/platform/rp.rs` | Embassy async (Cortex-M0+) |
| RP2350 | `src/platform/rp.rs` | Embassy async (Cortex-M33) |
| BCM2712 | `src/platform/bcm2712.rs` | Synchronous polling (Cortex-A76, EL1) |
| Pi 5 | `src/platform/bcm2712.rs` (board overlay) | Synchronous polling |

The two RP families share `rp.rs` because both run Embassy on a Cortex-M
core with the same peripheral families. The aarch64 targets share
`bcm2712.rs` because both run on the same SoC; pi5 is a board overlay
on top of the same chip support.

The kernel itself is mostly cfg-free. Per-silicon constants are generated
at build time from `targets/silicon/*.toml` into `chip_generated.rs`,
which the selected platform chip module includes. The vast majority of
kernel code calls into the chip module rather than scattering
`#[cfg(...)]` blocks across `syscalls.rs` or `scheduler/mod.rs`. See
[pin_allocation.md](pin_allocation.md) for the silicon TOML schema.

## Bus Primitives

### GPIO

Digital pin I/O. Modules acquire pins by number, configure direction and
pull, and set/get level. Edge detection is bound to event objects (see
[events.md](events.md)) so that modules can wake on a transition without
polling.

```rust
// Acquire a pin as an input with pull-up
let mut arg = [pin_number, GPIO_PULL_UP];
let handle = (sys.provider_open)(HAL_GPIO, gpio::SET_INPUT, arg.as_mut_ptr(), 2);

// Read the level
let level = (sys.provider_call)(handle, gpio::GET_LEVEL, null, 0);
```

The HAL on each target is responsible for the actual MMIO writes that
configure the pad and the SIO. The opcode and the calling convention are
identical across all targets.

### SPI

Word- and block-oriented SPI bus access. Bus configuration (pins,
frequency, mode) comes from the config; modules open a handle to a
configured bus and a CS pin, then issue transfers.

```rust
let mut spi = SpiOpenArgs { bus, cs_handle, freq_hz, mode };
let handle = (sys.provider_open)(HAL_SPI, spi::OPEN, &mut spi as *mut _ as *mut u8,
                            core::mem::size_of::<SpiOpenArgs>());
(sys.provider_call)(handle, spi::TRANSFER, transfer_args, args_len);
```

Async transfers use start/poll: the module starts a DMA-backed transfer,
the step returns, and a later step polls for completion. The HAL
implementation may use Embassy async tasks (RP) or polled DMA descriptors
(aarch64).

### I2C

Open / close / write / read / write_read with handle-based bus locking.
Bus configuration comes from the config; modules open handles to specific
device addresses on a configured bus.

### PIO

Programmable I/O state machines (RP2040, RP2350 only). The HAL exposes
two distinct services:

- **PIO stream**: double-buffered DMA streaming for protocols where the
  state machine consumes a continuous data feed (I2S audio, WS2812 LEDs,
  CYW43 gSPI bursts). The kernel manages the double-buffer flip and
  surfaces `StreamTime` for synchronization.

- **PIO command**: bidirectional transfers where the state machine sends
  a command and reads a response (gSPI for the cyw43 module, custom
  protocols).

PIO programs are compiled into the module that uses them — the HAL just
loads bytes into the instruction memory and starts the state machine.

On targets without PIO (BCM2712, Pi 5), modules that depend on PIO are
declared incompatible at config-validation time and the build fails with
a clear diagnostic.

### UART

Byte-stream serial I/O. Used by drivers for hardware that exposes a
serial command interface (for example the CH9120 TCP/IP offload chip)
and by the kernel itself for log output. Like SPI and I2C, UART buses
are declared in the config and brought up before module instantiation.

### Timers

Monotonic millisecond and microsecond clocks via `millis()`, `micros()`,
and `stream_time()`. Async delays use `timer_start` / `timer_poll`
sequences. The HAL on each silicon backs these with the chip's own
timer hardware.

### DMA

DMA channels are claimed by drivers that need them (PIO, SPI). The HAL
manages the channel pool per silicon — RP2040 has 12 channels, RP2350
has 12 + a separate "system DMA" controller, BCM2712 has its own DMA
engines. Modules see only the abstract `provider_call` operations on PIO and
SPI; the DMA wiring is hidden.

### Trust and platform metadata

Two HAL hooks front the security-relevant platform state so loader code
stays silicon-oblivious:

- `verify_integrity(&[u8], &[u8]) -> bool` — byte-compare of computed
  against stored hash. Every silicon ships a real comparison; the
  loader relies on it for module admission.
- `otp_read_signing_key(&mut [u8; 32]) -> bool` — returns the device
  root-of-trust Ed25519 pubkey. Pi 5 reads it from a build-time
  environment variable (`FLUXOR_SIGNING_PUBKEY_HEX`) baked into the
  image; silicon with a real OTP bank reads from fuses. False means
  "no key provisioned" — the `enforce_signatures` feature then blocks
  module load.

On BCM2712, `kernel::dtb::read_ethernet_mac()` walks the firmware-
provided flattened device tree for the `local-mac-address` property.
The rp1_gem driver calls this via a kernel-primitive syscall
(`GET_HW_ETHERNET_MAC`, `0x0C3D`) and programs the returned MAC into
the GEM's SA1 register. On silicon without DTB plumbing the syscall
returns `ENODEV`, and drivers fall back to a locally-administered
default.

## Syscall Table

The syscall table (`SyscallTable` in `modules/sdk/kernel_abi.rs`) is a
`#[repr(C)]` struct of function pointers passed to each module at
`module_init`. It is the only ABI surface PIC modules see.

The table contains exactly:

| Group | Functions |
|-------|----------|
| Channel I/O | `channel_read`, `channel_write`, `channel_poll` |
| Heap | `heap_alloc`, `heap_free`, `heap_realloc` |
| Provider dispatch | `provider_open`, `provider_call`, `provider_query`, `provider_close` |

Channel I/O and heap are hot-path typed syscalls. Everything else
routes through the four `provider_*` entries:

- `provider_open(contract, open_op, config, len)` returns a handle
  bound to that contract. The kernel tracks the handle → contract
  mapping in a per-scheduler-reset table.
- `provider_call(handle, op, arg, len)` routes through the bound
  contract's vtable. For handle=-1 global operations and untracked
  handles, the opcode's high byte carries the contract id and
  dispatch routes directly through the class chain.
- `provider_query(handle, key, out, len)` reads introspection state.
- `provider_close(handle)` invokes the contract's default close
  opcode (if any) and releases the tracking entry.

There is no `provider_call` surface. The `provider_*` quartet
is the complete dispatch API. See [abi_layers.md](abi_layers.md)
for the contract inventory and opcode namespace.

## What the Kernel Owns vs What Modules Own

The kernel owns:

- **Scheduling** — cooperative dispatch, deferred-ready chain,
  event-driven wake, fault recovery
- **Memory** — module state arenas, channel buffer arena, optional
  per-module heap, optional demand-paged arenas
- **IPC** — channels (FIFO and mailbox), buffer pool, event flags
- **Bus primitives** — GPIO, SPI, I2C, PIO, UART, timers, DMA
- **Loader** — module validation, code/rodata layout, syscall table
  injection
- **Provider dispatch** — `provider_call` routing to registered handlers
  for each device class

The kernel does not own:

- Any device protocol (not WiFi, not display init sequences, not SD
  card commands, not TCP)
- Any filesystem implementation
- Any audio format
- Any network protocol
- Application policy of any kind

The litmus test: **if a piece of code can be written as a cooperative
state machine that uses bus syscalls and channels, it lives in a module,
not in the kernel.** This is why CYW43 (a complex chip with a 230 KB
firmware blob, gSPI, frame queues, and association state machines) lives
entirely in `modules/drivers/cyw43/`. The kernel sees it as a module
that talks PIO and exchanges Ethernet frames over a channel.

## Module Examples

### Driver Module: WS2812 (RP2350)

The WS2812 driver compiles a small PIO program into a module, claims a
GPIO pin, configures the PIO stream service, and pushes 32-bit color
values:

```rust
// PIO program produces WS2812 timing from 24-bit GRB words
static WS2812_PROGRAM: [u16; 4] = [ /* compiled instructions */ ];

fn module_new(...) -> i32 {
    // Claim the pin
    let mut pin_arg = [pin, 0];
    (sys.provider_open)(HAL_GPIO, gpio::SET_OUTPUT, pin_arg.as_mut_ptr(), 2);

    // Allocate a PIO stream (provider_open tracks stream → HAL_PIO
    // so subsequent provider_call(stream, …) routes via the PIO vtable).
    let stream = (sys.provider_open)(HAL_PIO, pio::STREAM_ALLOC, null, 0);
    (sys.provider_call)(stream, pio::LOAD_PROGRAM,
                   WS2812_PROGRAM.as_ptr() as *mut u8,
                   WS2812_PROGRAM.len() * 2);

    // Configure clock divider, pin, and FIFO mode
    let mut cfg = PioConfig { /* ... */ };
    (sys.provider_call)(stream, pio::CONFIGURE, &mut cfg as *mut _ as *mut u8,
                   core::mem::size_of::<PioConfig>());
    0
}

fn module_step(state: *mut u8) -> i32 {
    // Read color values from input channel and push to PIO
    let n = (sys.channel_read)(in_chan, color_buf.as_mut_ptr(), buf_max);
    if n > 0 {
        (sys.provider_call)(stream, pio::PUSH, color_buf.as_ptr(), n as usize);
    }
    0
}
```

The same module would compile and run unchanged on RP2040 (Cortex-M0+),
RP2350 (Cortex-M33), or any future RP-family target. It would not run
on BCM2712 because BCM2712 has no PIO peripheral — and the config
validator catches this at build time, not at runtime.

### Driver Module: ST7701S display (RP2350 + BCM2712)

A more complex driver that uses SPI for control commands, PIO stream for
the pixel data path, GPIO for reset / DC pins, and a display init
sequence stored in the module's rodata. None of these things require
kernel knowledge of "displays" — the module composes bus primitives to
implement the panel-specific protocol. See `modules/drivers/st7701s/`.

### Foundation Module: FAT32

A pure foundation module that uses no hardware syscalls at all. Reads
a block-I/O channel from a storage driver, parses the FAT32 filesystem,
exposes a file-stream channel to consumers. Identical on every target
because it never touches a bus. See `modules/foundation/fat32/`.

## Zero-Footprint Drivers

If a config does not reference a peripheral, no code for that peripheral
exists in the firmware image. The build system only links module
binaries that the config actually instantiates. A weather-station config
that uses I2C for a sensor and SPI for an e-paper display has no PIO
code, no I2S code, no display init sequences for displays it does not
use. This makes the firmware footprint scale with the application, not
with the union of every supported peripheral.

## Benefits

1. **Clean separation.** The kernel has no protocol knowledge to maintain.
   Adding support for a new chip means writing one module, not modifying
   the kernel.

2. **Cross-target portability.** Foundation modules (FAT32, IP, MP3 decoder,
   HTTP server) compile and run unchanged on every silicon target. Only
   driver modules differ — and only because the underlying hardware
   differs.

3. **Testable.** A module can be tested by mocking the syscall table and
   feeding synthetic channel data. No hardware required.

4. **Small kernel.** The minimum kernel for a Pico is around 256 KB
   compiled, including Embassy and the chip support. Nothing in the
   kernel scales with the number of supported peripherals.

5. **Stable for third-party modules.** A module compiled against the
   syscall ABI can be loaded by any kernel build with the same ABI
   version, on any target. The pack tool stamps the ABI version into
   each `.fmod` file and the loader rejects mismatches.

## File Locations

| Component | Location |
|-----------|----------|
| Syscall table definition | `modules/sdk/abi.rs` |
| Syscall dispatch | `src/kernel/syscalls.rs` |
| Provider registry | `src/kernel/provider.rs` |
| Channel implementation | `src/kernel/channel.rs` |
| Buffer pool | `src/kernel/buffer_pool.rs` |
| Loader | `src/kernel/loader.rs` |
| Scheduler | `src/kernel/scheduler/mod.rs` |
| Chip abstraction | `src/platform/{rp,bcm2712,linux,wasm}/chip.rs` (+ generated `chip_generated.rs` where applicable) |
| RP HAL | `src/platform/rp.rs`, `src/platform/rp/*.rs` |
| BCM2712 HAL | `src/platform/bcm2712.rs`, `src/platform/bcm2712/*.rs` |
| Silicon definitions | `targets/silicon/*.toml` |
| Board definitions | `targets/boards/*.toml` |

## Boundary Decisions

Decisions on the kernel/platform/board boundary. Each carries its status:
`DECIDED` (an explicit operator decision) or `PROPOSED` (the implementer's
recommendation, recorded for review — not yet agreed policy). Code may already
follow a PROPOSED entry; that makes it current practice, not a settled rule.
Code comments may summarize these; this section is the authority. Execution
history for these decisions is tracked in `.context/boundary_ledger.md`.

### D-KERNEL-PLATFORM — the kernel's two platform seams

Status: **PROPOSED** (implementer).

The kernel reaches platform behavior through exactly two seams, and nothing
else:

1. **`HalOps`** (`kernel::sys::hal`) — the function-pointer table each platform
   installs at boot. All platform *behavior* the kernel invokes goes through
   it: timing, interrupts, step-guard, ISR tiers, SMP quiesce, and the module
   protection surface (`protection_*`, `protected_step`, stack canaries — MPU
   on Cortex-M, EL0 MMU on aarch64, direct dispatch elsewhere).
2. **`platform::chip`** — the cfg-selected per-target *constants* module
   (arena sizes, capacity ceilings). These size static arrays, so they must be
   compile-time constants; a cfg-selected constants module IS the compile-time
   half of the HAL. Not a boundary violation: rp2040 (264 KiB) and rp2350
   (520 KiB) cannot share one arena figure, so the sizes are inherently
   per-silicon and must be pulled at compile time. All kernel capacity reads
   go through `crate::kernel::config` — the ONLY kernel↔`platform::chip`
   reference — so this seam is a single audited surface.

The kernel branches on CAPABILITY, never chip identity. What were once
`cfg(feature = "chip-bcm2712")` sites are expressed as capability features a
chip feature turns on: `kernel-vm` (page-table VM + EL0 isolation), `smp`
(multi-core execution domains), `dtb` (device-tree boot). chip-bcm2712
provides all three and is today the only target that does, but a future
MMU-but-single-core (or MPU-but-multi-core) target flips only the capabilities
it has; no chip name appears in `src/kernel`.

Anything a kernel file wants from a platform beyond these two seams is a
boundary bug: add a `HalOps` op (behavior), a `chip` constant (fact via
`kernel::config`), or a capability feature (a `cfg` the kernel branches on).

### D-HW-TAXONOMY — hardware capability placement

Status: **DECIDED** (operator, 2026-08-01), superseding the implementer's
earlier "promote after a second chip implements it" proposal.

The principle: **a capability belongs in Fluxor's generic contract vocabulary
when its semantics are independent of a particular controller implementation.**
Platform namespaces contain controller-specific mechanisms and escape hatches.
Boards declare topology and availability. Explicit drivers consume the
capabilities and expose typed module surfaces. Implementation count is NOT the
test — availability can be target-specific while the vocabulary stays generic.

Applied:

- **PCIe** — device access is generic vocabulary: the `pcie_device` contract
  (handles, config space, BARs, interrupts, device info) lives at
  `abi::contracts::hal::pcie_device` (id 0x0012). BCM2712 root-complex control
  (outbound windows, MSI controller, SMMU mechanics) stays platform, split by
  concern into `pcie_config`/`nic_ring`/`smmu`/`msi`. Board PCIe topology and
  aliases (`m2_primary`, `rp1`) are board facts, generated from the board TOML
  `[platform.pcie]`. Promoting the platform config/BAR ops into the generic
  `contracts/hal/pcie` opcode *class* would be a deliberate wire renumber and
  is operator-gated; the residual platform ops (dev_idx pre-open enumeration,
  PCIE_RESCAN slow-link-train bring-up) are controller semantics and stay
  platform by this section's own principle.
- **PIO** — RP PIO instruction-engine mechanics (16-bit programs, wrap
  targets, side-set, state-machine pin config), FIFO streaming, and the
  associated DMA belong under `platform::rp::pio`; RP drivers (cyw43, i2s_pio,
  mic_pio) consume them. The one truly platform-independent piece — the
  audio/media clock query — is the portable `contracts::stream_clock`
  capability (class 0x001C); linux/wasm register a real STREAM_CLOCK provider.
  `STREAM_TIME` remains on RP only as the PIO backend's per-stream clock (the
  kernel falls back to it when no STREAM_CLOCK provider is registered — on RP
  the clock genuinely IS the PIO stream).
- **DMA** — the portable channel-id surface (`peripherals.dma_channels`,
  `EdgeClass::DmaOwned`) is the vocabulary; raw register layouts stay
  per-family.
- **USB** — reserved kernel contract id + handle tag stand; the SDK contract
  is written when the first PIC module consumes it.

### D-BOARD-STACK — boards declare hardware facts; stacks select drivers

Status: **DECIDED** (operator, 2026-08-01). Executed for net, audio, display.

A board file declares hardware identity (`[platform.net] phy`, `nic =
"rp1-gem"|"virtio"|"cyw43"`; `[platform.audio] sink = "i2s"|"host"`;
`[platform.display] sink = "host"`), never a driver module name. The stack
owns the fact→driver mapping: its variants match on facts and name the driver
modules. No `driver` match keys exist in any stack; midi/pointer match on
`board`/`family`/`direction` facts.

## Related Documentation

- [abi_layers.md](abi_layers.md) — ABI layers, contract inventory, provider dispatch
- [pipeline.md](pipeline.md) — graph runner, channel mechanics, scheduler
- [events.md](events.md) — IRQ binding and interrupt-driven driver pattern
- [pin_allocation.md](pin_allocation.md) — config-driven pin and bus assignment
- [network.md](network.md) — networking stack built on bus primitives
