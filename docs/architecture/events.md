# Event System

Kernel-managed signalable/pollable notification objects for event-driven hardware drivers.

Source: `src/kernel/ipc/event.rs`

## Design Principles

1. **Pure mechanism** — no device semantics. Events are generic flags. The kernel has no knowledge of WiFi, sensors, or any device protocol.
2. **ISR-safe** — `event_signal_from_isr()` is bounded: one atomic store, one atomic RMW, one Signal. No allocation, no validation, no channel writes.
3. **Cooperative** — events trigger intra-tick module stepping. No preemption, no blocking, no priority inversion.
4. **Bounded pool** — event slots are a planned kernel table (32 by default), allocated atomically. No heap. See [limit_register.md](limit_register.md) for how the table is sized.

## Why Events Exist

A module that polls for a hardware change on every tick pays twice:

1. **Latency** — an edge that fires just after a tick pass is not seen until the next one.
2. **Wasted work** — a module waiting on hardware runs `module_step` on every tick even when nothing happened.

Events remove both: a signal latches the owning module's wake bit, a wake pass steps that module alone, and a wake ends the domain loop's sleep early for a sub-tick response.

## Architecture

```
Hardware edge
    |
    v
poll_gpio_edges()  ──>  doorbell_ring(doorbell)
                              |
                         sets signaled = true
                         latches the owner module's wake bit
                         wakes the scheduler
                              |
                              v
                    domain loop detects wake
                              |
                              v
                    wake pass (pass::run, PassKind::Wake) steps only affected modules
```

For ISR sources (DMA completion, timer expiry):

```
ISR context
    |
    v
event_signal_from_isr(handle)
    |
    sets signaled = true
    latches the owner module's wake bit
    wakes the scheduler  ──>  breaks the sleep early
                                      |
                                      v
                            wake pass runs immediately
```

## Event Lifecycle

### Create

```rust
// In module_new or module_step:
let evt = (sys.provider_call)(-1, event::CREATE, core::ptr::null_mut(), 0, core::ptr::null_mut(), 0);
// evt >= 0: event handle
// evt < 0: error (ENOSPC when the event table is full)
```

The event is owned by the currently executing module. When signaled, the scheduler knows which module to wake.

### Signal

```rust
// From the module that owns the event:
let rc = (sys.provider_call)(evt, event::SIGNAL, core::ptr::null_mut(), 0, core::ptr::null_mut(), 0);
```

Sets the signaled flag, latches the owning module's wake bit, and wakes the scheduler. The owning module is stepped by the wake pass that follows the current pass, before the domain loop sleeps. Every event op checks that the caller owns the event; an event handle names its slot at a generation, so a handle kept past `DESTROY` names nothing (`EBADF`). Another module, a provider or the platform signals a module through a doorbell instead (below).

### Poll

```rust
// In module_step, check if event fired:
let fired = (sys.provider_call)(evt, event::POLL, core::ptr::null_mut(), 0, core::ptr::null_mut(), 0);
// fired == 1: signaled (the poll clears it)
// fired == 0: not signaled
// fired < 0: error
```

Poll is atomic: it clears the signaled flag and returns the previous value. This prevents double-processing.

### Destroy

```rust
// In module cleanup:
let rc = (sys.provider_call)(evt, event::DESTROY, core::ptr::null_mut(), 0, core::ptr::null_mut(), 0);
```

Frees the slot and moves its generation, so the handle, and any IRQ still bound to it, names nothing: such an IRQ signals no event.

## IRQ Subscription

An event can be bound to a hardware interrupt line (`BIND_IRQ`, aarch64
targets with a GIC); a GPIO edge is watched through the GPIO contract's
doorbell instead (below).

### IRQ binding

```rust
// Bind the event to GIC IRQ 187 (example) so the kernel signals the event
// on fire. `ack` says how the kernel quiets the device behind the line
// first: `event::ack::NONE` leaves it to the driver, `VIRTIO_MMIO`
// acknowledges the machine's virtio-mmio transport on that line.
let mut args = [0u8; 5];
args[..4].copy_from_slice(&187u32.to_le_bytes());  // IRQ number
args[4] = event::ack::NONE;
let rc = (sys.provider_call)(evt, event::BIND_IRQ, args.as_mut_ptr(), 5, core::ptr::null_mut(), 0);
```

After binding, the kernel's interrupt handler signals the event whenever
the line fires, and the module polls the event rather than the device. The
line must be a shared peripheral interrupt (INTID 32 or above): an event
binding is serviced on core 0. An SGI or PPI, or an `ack` the machine has
no such device behind, is `EINVAL`.

GPIO edge-triggered wakes go through a doorbell: the GPIO contract's
`WATCH_EDGE` opcode on a claimed pin mints a watch handle that polls
`POLL_IN` once per edge.

### Doorbells

A provider signals the module that minted one of its handles through a
doorbell. An op the registry marks `signals` — `storage.namespace::SUBSCRIBE`,
`gpio::WATCH_EDGE`, `pcie_device::MSI_ALLOC` — mints a handle whose route
owns an event slot claimed for the minter. After the provider answers the op
with its own index, the kernel delivers `kernel::BIND_DOORBELL` to it (that
index as the handle, `[doorbell u32][contract u16][0 u16]` as `arg`); a
refusal closes the index and fails the op. The provider rings the doorbell
when its condition holds: platform code with `event::doorbell_ring`, which is
interrupt-safe, a module provider with `kernel::DOORBELL_RING` (`[doorbell
u32]`), which only the provider the doorbell was handed to may ring. The
minter is woken (`latch_module_wake`), and `HANDLE_POLL` on its handle
answers `POLL_IN` once per ring — the poll takes it. Closing the handle closes
the provider's index and frees the slot; the doorbell's generation moves, so
a ring after the close rings nothing.

### Constraints

- A GPIO edge watch needs the pin already claimed by the module (`gpio::CLAIM`); the watch is made on the claim's handle.
- There is no unbind opcode: `DESTROY` ends what the event receives, and a GPIO watch ends when its handle is closed.
- Every event op checks that the caller owns the event; a module's events are released with the module.

## Scheduler Wake Integration

Every loop drives one pass engine (`src/kernel/exec/scheduler/pass.rs`):
`pass::run(domain, kind)` steps one domain, either a full tick
(`PassKind::Tick`) or only the woken modules (`PassKind::Wake(&mask)`).
A single-core loop (RP, Linux, wasm) runs every domain in order through
`pass::tick_all()` and `pass::wake_all()`, then sleeps until the
deadline the tick pass returned or a wake, whichever comes first:

```rust
loop {
    // 1. Poll GPIO edges (signals events for bound pins)
    poll_gpio_edges();

    // 2. Tick pass over every domain; returns the merged sleep deadline
    let pass = pass::tick_all();

    // 3. Intra-tick wake: events latched during the tick pass
    pass::wake_all();

    // 4. Sleep for the pass's deadline_us (µs from now) OR until a wake
    SCHEDULER_WAKE.take();
    wait_for_wake(&SCHEDULER_WAKE, now_us() + pass.deadline_us, ...);

    // 5. Post-sleep wake: events from ISR during sleep
    pass::wake_all();
}
```

A domain loop on its own core does the same for its one domain:
`pass::run(d, PassKind::Tick)`, then `pass::take_domain_wakes(d)` and
`pass::run(d, PassKind::Wake(&woken))`. A domain loop takes only its own
domain's wake bits.

### Wake pass

`PassKind::Wake` runs the per-graph step of a tick pass for the woken
modules alone:
- Only steps modules whose bit is set in the wake mask, each once
- Bypasses the period gate (`step_period`) — an event-triggered step does
  not wait for the module's periodic due
- Preserves the domain's exec order (producer before consumer)
- Same fault, done and error handling as a tick pass
- The domain's step budget defers what does not fit
  (`MON_WAKE_BUDGET_DEFER`); a paused graph's wakes go to the deferred
  store

### Wake Timing

| Source | Latency | Mechanism |
|--------|---------|-----------|
| GPIO edge (software polled, RP) | Within one loop iteration | `poll_gpio_edges()` → `doorbell_ring()` → wake pass |
| Module signal or doorbell ring | Before the loop sleeps | the signal latches a wake → the wake pass after the tick pass |
| Bound IRQ | Sub-tick | interrupt → `event_signal_from_isr()` → the wake ends the sleep |

### Channel readiness and stream state

A channel handle polls through the same `HANDLE_POLL` (`channel_poll` on
the syscall table), from either end of the channel:

| Bit | Holds when |
|-----|------------|
| `IN` | a ring byte or a mailbox's READY record is buffered |
| `OUT` | a write fits now (a mailbox: its record is IDLE), or the reader is gone, when every write is committed and kept nowhere |
| `HUP` | the producer ended the stream (`channel::SET_HUP`), or retired (`producer_gone`) |
| `ERR` | the producer retired with an error |
| `WROTE` | anything was written since the last `channel::FLUSH` |

HUP has one source per meaning: the producer's statement, which a
`FLUSH` clears to start a new stream, and its retirement, which no flush
clears. ERR stays for the channel's life. HUP with WROTE is a stream that
ended; HUP without WROTE one that never started. A successful write on a
`wake: true` edge latches the consumer's wake bit, as an event signal
does, so data cuts an idle sleep short.

## ISR Safety Contract

`event_signal_from_isr()` contains exactly:

1. Handle lookup in the committed event table: the slot is live and its
   generation matches, or nothing is signalled (no owner check)
2. `slot.signaled.store(true, Release)` — one atomic store
3. A wake-latch RMW into the owner's wake word; if the owning module is
   paused, the wake is deferred and the scheduler wake suppressed
4. `hal::wake_scheduler()` — on RP this sets the scheduler wake latch and
   raises `SEV`, so a core parked in `WFE` returns and re-checks

No allocation, no table growth, no channel writes, no driver logic.

## GPIO Event Binding Model

GPIO edge watches on RP targets use software polling via
`poll_gpio_edges()`, once per loop iteration before the tick pass, which
rings each watch's doorbell. This model
is suitable for buttons, sensors, and most GPIO-driven peripherals.

It is also the model the RP platform commits to: `IO_IRQ_BANK0` is not
hooked, so GPIO edges are observed by the domain loop rather than by an
interrupt.

An interrupt source bound with `BIND_IRQ` signals through `event_signal_from_isr()` directly from interrupt context, giving it a sub-tick wake.

## Timers

A timer is a handle, and it wakes its owner the same way an event does.
`timer::CREATE` returns the timer's handle, `SET` arms it with a delay in
milliseconds, and `HANDLE_POLL` reports `POLL_IN` once it has fired. Every
timer op checks that the caller owns the timer. A module that wants to act in 5 ms arms a timer and waits on it; it
does not read the clock on a tick it does not control.

The kernel does two things with the armed timers of a domain each time it
decides how long to sleep:

- **Fire.** An expired timer latches its owner's wake bit exactly as
  `event_signal` would, once per arming, so a wake pass runs
  that module and it finds `POLL_IN`. The latch is what makes a fire an
  edge rather than a level — an expired-but-unread timer does not wake its
  owner again on every pass. `SET`, `CANCEL` and `DESTROY` clear it.
- **Bound the sleep.** The earliest armed timer that has not yet fired
  bounds the pacing deadline the adaptive mechanisms chose, down to the
  domain's worst-step floor and no further. So a module that arms 5 ms is
  stepped at ~5 ms even on an idle domain relaxed to a 50 ms backstop,
  while a heavy domain still never runs faster than its step budget admits.

Firing is domain-blind and the deadline is not: whichever domain notices an
expiry latches the owner's wake bit, but only the owner's own domain
shortens its sleep for it, so a sibling domain's short timer cannot drag
this one off its backstop.

`HANDLE_POLL` is a kernel primitive — a question about the handle rather
than a request to whatever provider the handle belongs to — so
`provider_call` routes it to the kernel ahead of the handle's contract, which
answers through its vtable's `poll` (the timer's deadline, the event's flag,
a signalling handle's doorbell).

## ABI

### Device Class

| Class | ID | Opcode Range |
|-------|----|-------------|
| Event | `0x04` | `0x0400-0x04FF` |

### Opcodes

| Opcode | Name | Args | Returns |
|--------|------|------|---------|
| `0x0400` | `CREATE` | handle=-1 | Event handle (>=0) or error |
| `0x0401` | `SIGNAL` | handle=event | 0 or error |
| `0x0402` | `POLL` | handle=event | 1 (was signaled), 0 (not), or error |
| `0x0403` | `DESTROY` | handle=event | 0 or error |
| `0x0451` | `BIND_IRQ` | handle=event, arg=[irq:u32 LE, ack:u8] (5B) | 0 or error |

### Error Codes

| Code | Name | When |
|------|------|------|
| `-28` | `ENOSPC` | No free event slots — an accounted capacity denial (`resource_ledger`, PSTATUS `POOL` records) |
| `-9` | `EBADF` | The handle names no live event of the caller's |
| `-22` | `EINVAL` | `BIND_IRQ`: an argument shorter than 5 bytes, an unknown `ack`, an SGI/PPI line, or an `ack` with no such device behind the line |
| `-12` | `ENOMEM` | `BIND_IRQ`: the interrupt controller's binding table is full |

## Driver Pattern: Event-Driven GPIO Module

A driver that waits on a GPIO edge claims the pin, watches its edge, and
polls the watch handle; the watch's doorbell wakes it. This is the pattern
of `modules/drivers/gt911` (its INT pin) and of any hardware driver that can
be written as a cooperative state machine with event notifications —
running entirely as a module with zero kernel knowledge of the device.

```rust
#[repr(C)]
struct ButtonState {
    syscalls: *const SyscallTable,
    out_chan: i32,
    pin_handle: i32,   // the pin's claim
    watch: i32,        // the edge watch: polls POLL_IN once per edge
    phase: u8,
}

const PH_WATCH: u8 = 0;
const PH_RUNNING: u8 = 1;

fn module_step(state: *mut u8) -> StepReturn {
    let s = unsafe { &mut *(state as *mut ButtonState) };
    let sys = unsafe { &*s.syscalls };

    match s.phase {
        PH_WATCH => {
            // Watch both edges of the claimed pin (claimed in module_new).
            let mut edge = [gpio::edge::BOTH];
            s.watch = unsafe {
                (sys.provider_call)(
                    s.pin_handle, gpio::WATCH_EDGE,
                    edge.as_mut_ptr(), 1,
                    core::ptr::null_mut(), 0,
                )
            };
            if s.watch < 0 { return StepReturn::error(s.watch); }
            s.phase = PH_RUNNING;
            StepReturn::Continue
        }
        PH_RUNNING => {
            // An edge since the last poll; the poll takes it.
            let ready = unsafe { dev_fd_poll(sys, s.watch, POLL_IN) };
            if ready > 0 && ready & POLL_IN as i32 != 0 {
                // read the level (gpio::GET_LEVEL), debounce, emit to out_chan
            }
            StepReturn::Continue
        }
        _ => StepReturn::error(errno::EINVAL),
    }
}
```

The module never runs in interrupt context. The doorbell latches its wake
when an edge is detected, the wake pass steps it, and it reads the pin level
and processes the change as a normal cooperative step.

## Litmus Test

> Any hardware driver that can be written as a cooperative state machine with event notifications can live entirely as a module, with zero kernel knowledge of the device's protocol.

The kernel provides:
- Bus primitives (GPIO, SPI, PIO) for hardware access
- Events for hardware-to-module notification
- Channels for module-to-module data flow
- Timers for time-based operations

The kernel does NOT provide:
- WiFi opcodes, netif types, association states
- Protocol logic, packet formats, device registers
- Any device-specific dispatch, or a sideband word beside a channel: what
  two modules tell each other travels in the contract they speak

## Implementation

| File | Description |
|------|-------------|
| `src/kernel/ipc/event.rs` | Event pool, create/signal/poll/destroy; IRQ binding stored per-event |
| `src/kernel/ipc/handle.rs` | Native handle resolution (`resolve_owned`) and `fd_poll` / `fd_poll_multi` |
| `src/kernel/ipc/timer.rs` | Timer slots and `timer_pump()` |
| `crates/fluxor-abi/registry/registry.toml` | The `event` contract (`0x04`) and its ops, re-exported as `kernel_abi::event::{CREATE,SIGNAL,POLL,DESTROY,BIND_IRQ}` |
| `crates/fluxor-abi/src/contracts/hal/gpio.rs` | `WATCH_EDGE` opcode for edge-triggered event wakes |
| `src/kernel/module/syscalls.rs` | Event contract dispatch |
| `src/platform/rp/io.rs` | `poll_gpio_edges()` and the per-pin edge watches (RP) |
| `src/arch/aarch64/gic.rs` | `irq_bind`: the `BIND_IRQ` line table (aarch64) |
| `src/kernel/exec/scheduler/pass.rs` | the pass engine: `pass::run` tick and wake passes, `take_domain_wakes()` |

## Limits

| Resource | Default | Notes |
|----------|---------|-------|
| Event slots | 32 | `MAX_EVENTS` in `src/kernel/ipc/event.rs`: the plan's `events` pool, sized at boot (a static table on wasm) |
| Timer slots | 16 | `MAX_TIMERS` in `src/kernel/ipc/timer.rs`: the plan's `timers` pool, sized at boot (a static table on wasm) |
| Modules (wake mask) | Sized to `MAX_MODULES` per target | `ModuleMask` of 64-bit words, one bit per module slot |
| GPIO edge watches | one watch handle per `WATCH_EDGE` on a claimed pin | closing the handle stops the detection |
