# Module Isolation

A module can be stepped with hardware between it and everything that is not
its own. This page describes what each protection level means, how a graph
asks for one, what the kernel enforces on each target, and what it does not
claim.

## Levels

| Level | Wire value (tag `0xF5`) | The module runs | Implemented on |
|---|---|---|---|
| `none` | 0 | privileged, called directly | every target |
| `guarded` | 1 | privileged, under the step guard | every target |
| `contained` | 2 | unprivileged: its own RAM and all of flash, nothing else | rp2040, rp2350 |
| `isolated` | 3 | unprivileged: its own RAM and its own code, nothing else | rp2040, rp2350, bcm2712 |

`contained` and `isolated` are the **gated** levels. A gated module reaches
the kernel only through the gateway, runs on a stack of its own, and is forced
out at its step deadline.

A requested level is a **floor**. The target provides the weakest level it
implements at or above the request, and the composer refuses a request above
everything it implements. For example, bcm2712 gives a `contained` request
`isolated`. The level a module asks for comes from, in order:
1. its own `protection:` key;
2. the graph's `protection:`;
3. the default for its trust tier (`default_trust_tier`).

The config carries the provided level, and the kernel enforces exactly that
level. The loader refuses a gated module whose protection domain it cannot
build; it never runs one privileged instead.

A signature sets a floor the graph cannot lower. On a kernel built with a
root signing key (`FLUXOR_SIGNING_PUBKEY_HEX`), a module that does not verify
against that key is loaded only at a gated level. A request for `none` or
`guarded` is refused at load. A kernel built without a key has no signature
state to enforce, and loads modules at the level the graph gives them.

## What a gated module can reach

| Memory | Access | Notes |
|---|---|---|
| Its code | read, execute | `contained` on an MPU target: all of XIP flash instead |
| Its private region | read, write, never execute | One allocation, laid out `[stack \| state \| heap]` |
| The gateway | read, execute | The veneer table it was handed as its `SyscallTable` |
| Its device window | read, write, device ordering | Only if the graph grants one (see below) |

Nothing else is mapped for it: kernel memory, other modules, channel buffers
and peripherals all fault. The fault is attributed to the module, reported as
`MON_FAULT … kind=4`, and handled by the module's fault policy. The kernel
and the module's siblings keep running.

The private region is shaped for the target's protection unit, so the planner
can always draw it as a single region:

| Model | Shape |
|---|---|
| PMSAv8 (rp2350) | 32-byte multiple, 32-byte aligned |
| PMSAv7 (rp2040) | a whole number of eighths of a power-of-two size, aligned to that size |
| Pages (bcm2712) | whole 4 KiB pages |

The region planner (`fluxor_contracts::isolation`) is shared by the composer
and the kernel. It plans exactly the spans it is given or refuses; it never
widens a region to make it fit.

## The gateway

Source: `src/kernel/module/gateway.rs`

A gated module's syscall table is a table of veneers. Each entry traps into
the kernel with its own op number: `svc #op; ret` on AArch64, `svc #op; bx lr`
on Thumb. The kernel decodes the op from the trap, never from a register the
module controls. Before dispatch it checks every call three ways:

| Check | Rule | Refusal |
|---|---|---|
| Pointers | Every buffer lies inside the caller's writable private region, or its readable code | `EFAULT` |
| Channels | Every channel handle is one of the caller's own ports | `EACCES` |
| Handles | Every provider handle is one the gateway minted for this caller | `EACCES` |

Provider opcodes pass through a default-deny rule table:
- The time, entropy, log, telemetry, report, event, arena and `storage.object`
  opcodes are listed, each with its direction and handle kind.
- An opcode the table does not name is refused with `EACCES`.
- A struct that carries pointers (the `storage.object` `PUT`, `HEAD`,
  `RANGE_GET`, `DELETE` and `LIST` requests) is copied into kernel memory,
  and every embedded pointer is checked before dispatch. The gateway copies
  at most 544 bytes of such a struct, sized to the largest `LIST` request: a
  prefix and a cursor of `STORAGE_KEY_MAX` (255) bytes each, so a gated caller can
  resume a listing at any key a provider holds.
- The `storage.object` ops a guarded store admits under a grant (`PUT`, `GET`,
  `HEAD`, `DELETE`, `LIST`) take either `-1` or a handle the gateway minted for
  the caller, never another module's grant. `PRESENT` carries no pointer, since
  its refusal is written into the request itself, so a gated caller can present
  the longest capability chain however far it runs past the struct copy.
- A channel ioctl is admitted only for the kernel's built-in commands and the
  `storage.block` requests. A block request's buffer is checked like any
  embedded pointer: private memory for a read, readable memory for a write.
  Any other command would reach a module-registered handler whose argument
  the gateway cannot see into, so it is refused. Every block command carries
  exactly its record's length, and a buffer lent by `SUBMIT` stays valid after
  the module is gone: see [Lent buffers](storage_capability_surface.md#11-storageblock-v1).
- Refusals are logged as `[gate] module M op N refused: <why>`, rate-limited.

Channel data is copied by the gateway, so a gated module has no view onto a
channel buffer. The composer therefore refuses a gated module on a zero-copy
(mailbox) edge.

## Admission

The composer admits against the target's `[isolation]` facts and refuses a
graph whose gated modules the kernel would refuse:

| Refused | Why |
|---|---|
| A level above everything the target implements | No backend enforces it |
| A permission that reaches past the gateway (`RECONFIGURE`, `FLASH_RAW`, `BACKING_PROVIDER`, `MONITOR`, `BRIDGE`, `PCIE_DEVICE`, `USB_HOST`, `PLATFORM_RAW`, `PLATFORM_DMA`) | The kernel would act on the module's behalf with authority it does not have |
| Providing a contract | Other modules' calls would run its code privileged |
| An interrupt-tier module (tier 1b, 2) | An ISR runs privileged with no gateway |
| An `isolated` module whose code the model cannot draw as one region | Use `contained` |
| More isolated modules than `isolated_slots` | The kernel's static table slots |
| A stack deeper than the target bounds | See [Stack depth](module_architecture.md#stack-depth) |

`fluxor build` prints each gated module's level and private region with the
state and stack budgets.

| Fact (`[isolation]`) | Meaning |
|---|---|
| `levels` | The gated levels this kernel implements |
| `region_model` | `pmsav8`, `pmsav7`, `pages` or `none` |
| `regions` | Protection regions per core; the RP kernel checks it against `MPU_TYPE` at boot |
| `stack_bound` | `limit-register`, `guard-region` or `guard-page` |
| `device_windows`, `device_ranges` | Whether windows are mapped, and the blocks they may be granted in |
| `isolated_stack_kb`, `isolated_slots` | bcm2712: the EL0 stack and how many modules can be isolated at once |
| `exception_frame_bytes` | What an exception pushes on a gated module's stack |

## Targets

| | rp2040 (Cortex-M0+) | rp2350 (Cortex-M33) | bcm2712 (Cortex-A76) |
|---|---|---|---|
| Mechanism | PMSAv7 MPU, thread unprivileged | PMSAv8 MPU, thread unprivileged | EL0 under a per-module page table and ASID |
| Regions per module | code, gateway, private (+ window) | code, gateway, private (+ window) | pages |
| Stack bound | the end of the private region (HardFault) | `PSPLIM` | an unmapped guard page under a 64 KiB stack |
| Forced out at deadline | PendSV from the step-guard alarm | PendSV from the step-guard alarm | lower-EL IRQ |
| Trap | SVC, PendSV and faults enter one trap; the kernel serves it in privileged thread mode | same | SVC from EL0; dispatch under the kernel's table with IRQs open |

On the RP kernel the module is launched, and resumed after every gateway
op, by an exception return onto a frame on its own stack: privilege is
dropped only by that return, never in thread mode, so no kernel instruction
runs unprivileged. The 256-byte gateway block in flash holds the veneers and
the table and nothing else. `init` and `new` run gated as well as `step`,
with a 50 ms construction deadline, so no module code ever runs privileged
at a gated level.

A deadline that passes while the kernel is serving a gateway op is honoured
before the module can resume, on both kernels: the RP trap records the
PendSV that reached the kernel path and finishes the entry as forced out at
the resume; the bcm2712 gateway makes the IRQ path's deadline check before
returning to EL0.

## Device windows

A gated driver can be granted its peripheral's registers, and nothing beside
them:

```yaml
modules:
  - name: my_driver
    protection: isolated
    device_window: pwm
```

- **Naming.** The window names a block from the target's `device_ranges`, an
  allowlist that defaults to deny. The same graph works on every die that
  lists the name. A block is listed only when no kernel driver touches it and
  it cannot master the bus.
- **Composer.** It checks that the module is gated, that the target maps
  windows, and that its model can draw the block exactly. It refuses two
  modules whose windows overlap.
- **Kernel.** It refuses a window outside every grantable block even if a
  config names one, then maps it: an MPU region with device attributes, or
  4 KiB Device pages that are EL0 read-write and never executable.
- **Module.** It reads its window's base and size from tag `0xFD` in its
  params (`device_window(params, len)` in the SDK).

On rp2350, ACCESSCTRL is a second layer under the MPU:
- At boot, every peripheral is made Secure-privileged only (`[gate]
  peripherals privileged-only: N`).
- A block's unprivileged bit is set again only while a gated module holds it
  as its window, and cleared when that module is released.
- An MPU mistake therefore still cannot reach a peripheral.

## Liveness

A gated module that never returns is forced out at its step deadline and
faulted.

On the RP kernel, a separate liveness watchdog guards against a board that
stops: for example, a privileged (`none`/`guarded`) module that never
returns, which would also stop USB.
- It is armed once the clocks are up. The boot and every graph build run
  under its longest timeout (about 8 s on rp2040 and 16 s on rp2350), and the
  main loop feeds it with a 4 s timeout.
- A reset it causes brings the board up in BOOTSEL, so the board can be
  reflashed over USB without anyone touching it.
- The stage the wedged boot reached is kept in a watchdog scratch register.
  The next boot reports it (`[boot] the previous boot wedged instantiating
  module N`), which no log can: a wedge before the main loop never pumps USB.
- Deliberate reboots disarm it first.

On bcm2712, each core's kernel stack sits above an unmapped 4 KiB guard page.
An overrun faults there, and core 0 reports `[fault] core=N
kind=kernel-stack-overflow`.

## What is not claimed

- **DMA.** A gated module cannot program DMA (`PLATFORM_DMA` is refused), and
  no bus master acts unprivileged on a module's behalf.
  - ACCESSCTRL's SRAM rules are not used: SRAM0–7 on rp2350 are word-striped
    across banks, so a bank boundary separates nothing.
  - A DMA path for gated modules would be bounded by the DMA's own MPU.
- **Code confidentiality under `contained`.** A contained module can read all
  of flash, including other modules' code.
- **Timing and cache side channels.**
- **TrustZone-M.** Not used: the rp2350 region budget does not need it, and
  it would apply to no other die.
