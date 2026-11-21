# Event System

Kernel-managed signalable/pollable notification objects for event-driven hardware drivers.

Source: `src/kernel/ipc/event.rs`

## Design Principles

1. **Pure mechanism** — no device semantics. Events are generic flags. The kernel has no knowledge of WiFi, sensors, or any device protocol.
2. **ISR-safe** — `event_signal_from_isr()` is bounded: one atomic store, one atomic RMW, one Signal. No allocation, no validation, no channel writes.
3. **Cooperative** — events trigger intra-tick module stepping. No preemption, no blocking, no priority inversion.
4. **Static pool** — 32 event slots, atomically allocated. No heap. Deterministic memory.

## Why Events Exist

Without events, modules poll for hardware changes every 1ms tick. This works but has two problems:

1. **Latency** — a GPIO edge that fires 0.5ms after a tick isn't seen until the next tick.
2. **Wasted work** — modules that are waiting for hardware run `step()` every tick even when nothing happened.

Events solve both: the scheduler only steps a module when its event fires, and a wake breaks out of the 1 ms sleep for sub-tick response.

## Architecture

```
Hardware edge
    |
    v
poll_gpio_edges()  ──>  doorbell_ring(doorbell)
                              |
                         sets signaled = true
                         sets EVENT_WAKE_PENDING bit for owner module
                         signals SCHEDULER_WAKE
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
    sets EVENT_WAKE_PENDING bit
    signals SCHEDULER_WAKE  ──>  breaks the sleep early
                                      |
                                      v
                            wake pass runs immediately
```

## Event Lifecycle

### Create

```rust
// In module_new or module_step:
let evt = (sys.provider_call)(-1, event::CREATE, core::ptr::null_mut(), 0);
// evt >= 0: event handle
// evt < 0: error (ENOSPC if pool exhausted)
```

The event is owned by the currently executing module. When signaled, the scheduler knows which module to wake.

### Signal

```rust
// From the module that owns the event:
let rc = (sys.provider_call)(evt, event::SIGNAL, core::ptr::null_mut(), 0);
```

Sets the signaled flag, marks the owning module for wake, and pokes `SCHEDULER_WAKE`. The owning module will be stepped in the same tick cycle (intra-tick wake). Every event op checks that the caller owns the event; an event handle names its slot at a generation, so a handle kept past `DESTROY` names nothing (`EBADF`). Another module, a provider or the platform signals a module through a doorbell instead (below).

### Poll

```rust
// In module_step, check if event fired:
let fired = (sys.provider_call)(evt, event::POLL, core::ptr::null_mut(), 0);
// fired == 1: was signaled (now cleared)
// fired == 0: not signaled
// fired < 0: error
```

Poll is atomic: it clears the signaled flag and returns the previous value. This prevents double-processing.

### Destroy

```rust
// In module cleanup:
let rc = (sys.provider_call)(evt, event::DESTROY, core::ptr::null_mut(), 0);
```

Unbinds any IRQ subscription, clears the slot.

## IRQ Subscription

Events can be bound to hardware IRQ sources. This document shows GPIO edge detection as the reference binding pattern.

### GPIO Edge Binding

```rust
// Bind event to GIC IRQ 187 (example) so the kernel signals the event
// on fire. `ack` says how the kernel quiets the device behind the line
// first: `event::ack::NONE` leaves it to the driver, `VIRTIO_MMIO`
// acknowledges the machine's virtio-mmio transport on that line.
let mut args = [0u8; 5];
args[..4].copy_from_slice(&187u32.to_le_bytes());  // IRQ number
args[4] = event::ack::NONE;
let rc = (sys.provider_call)(evt, event::BIND_IRQ, args.as_mut_ptr(), 5);
```

After binding, the kernel's ISR signals the event whenever the IRQ
fires. The module does not need to poll — just poll the event.

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

### Release

Destroying the event releases any IRQ binding. There is no separate
unsubscribe opcode.

```rust
(sys.provider_call)(evt, event::DESTROY, core::ptr::null_mut(), 0);
```

### Constraints

- For GPIO edge wakes, the pin must already be claimed by the module (via `provider_open(HAL_GPIO, gpio::CLAIM, ...)`)
- One event per IRQ source (returns `EBUSY` if already bound)
- One IRQ source per event (destroy the event and create a new one to re-bind)

### Lifecycle Hygiene

- Modules unsubscribe IRQ bindings before event destroy.
- Modules destroy all event handles during shutdown/reconfigure.
- Events remain the only scheduler wake mechanism for hardware-to-module notification paths.

## Scheduler Wake Integration

Every loop drives one pass engine (`src/kernel/exec/scheduler/pass.rs`):
`pass::run(domain, kind)` steps one domain, either a full tick
(`PassKind::Tick`) or only the woken modules (`PassKind::Wake(&mask)`).
A single-core loop (RP, Linux) runs every domain in order through
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

    // 4. Sleep until the pass deadline OR an event signal
    SCHEDULER_WAKE.take();
    wait_for_wake(&SCHEDULER_WAKE, now + pass.deadline_us, ...);

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
| GPIO edge (software polled) | Same tick cycle (~0-1ms) | `poll_gpio_edges()` → `event_signal()` → wake pass |
| Module-to-module signal | Same tick cycle | Module A signals → wake pass runs before sleep |
| ISR sources | Sub-tick | ISR → `event_signal_from_isr()` → `SCHEDULER_WAKE` breaks the sleep |

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

1. Bounds check (`handle < MAX_EVENTS`)
2. `slot.signaled.store(true, Release)` — one atomic store
3. A wake-latch RMW into the owner's `EVENT_WAKE_PENDING` word; if the
   owning module is paused, the wake is deferred and the doorbell
   suppressed
4. `hal::wake_scheduler()` — on RP this sets the scheduler wake latch and
   raises `SEV`, so a core parked in `WFE` returns and re-checks

No validation beyond bounds. No allocation. No channel writes. No driver logic. Called at most once per ISR entry (coalesced), not per-pin.

## GPIO Event Binding Model

GPIO edge watches on RP targets use software polling via
`poll_gpio_edges()` (same-tick-cycle response, ~1 ms worst case), which
rings each watch's doorbell. This model
is suitable for buttons, sensors, and most GPIO-driven peripherals.

It is also the model the RP platform commits to: `IO_IRQ_BANK0` is not
hooked, so GPIO edges are observed by the step loop rather than by an
interrupt.

For non-GPIO ISR sources (DMA completion, timer), `event_signal_from_isr()` works directly from ISR context, giving these sources a sub-tick wake.

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
| `-16` | `EBUSY` | Event already has an IRQ binding |
| `-19` | `ENODEV` | GPIO pin not claimed |
| `-22` | `EINVAL` | Invalid handle, edge value, or source |
| `-38` | `ENOSYS` | Unknown source_type |

## Driver Pattern: Event-Driven GPIO Module

This example shows a complete driver module that uses events for GPIO edge detection. This is the pattern for any hardware driver that can be written as a cooperative state machine with event notifications — running entirely as a module with zero kernel knowledge of the device.

```rust
#[repr(C)]
struct ButtonState {
    syscalls: *const SyscallTable,
    out_chan: i32,
    gpio_pin: u8,
    event_handle: i32,
    state: u8,
    debounce_timer: i32,
    last_level: u8,
}

const ST_INIT: u8 = 0;
const ST_CLAIM_PIN: u8 = 1;
const ST_CREATE_EVENT: u8 = 2;
const ST_SUBSCRIBE: u8 = 3;
const ST_RUNNING: u8 = 4;

fn module_step(state: *mut u8) -> StepReturn {
    let s = unsafe { &mut *(state as *mut ButtonState) };
    let sys = unsafe { &*s.syscalls };

    match s.state {
        ST_INIT => {
            // Claim GPIO pin as input with pull-up
            let rc = (sys.provider_call)(s.gpio_pin as i32, gpio::CLAIM, ...);
            if rc < 0 { return StepReturn::error(rc); }
            s.state = ST_CREATE_EVENT;
            StepReturn::Continue
        }
        ST_CREATE_EVENT => {
            // Create an event object
            let evt = (sys.provider_call)(-1, event::CREATE, core::ptr::null_mut(), 0);
            if evt < 0 { return StepReturn::error(evt); }
            s.event_handle = evt;
            s.state = ST_SUBSCRIBE;
            StepReturn::Continue
        }
        ST_SUBSCRIBE => {
            // Ask GPIO contract to signal our event on either edge of the pin.
            let args: [u8; 5] = [
                3, // edge: 1=rising, 2=falling, 3=both
                (s.event_handle as u32).to_le_bytes()[0],
                (s.event_handle as u32).to_le_bytes()[1],
                (s.event_handle as u32).to_le_bytes()[2],
                (s.event_handle as u32).to_le_bytes()[3],
            ];
            let rc = (sys.provider_call)(
                s.pin_handle, gpio::WATCH_EDGE,
                args.as_ptr() as *mut u8, 5,
            );
            if rc < 0 { return StepReturn::error(rc); }
            s.state = ST_RUNNING;
            StepReturn::Continue
        }
        ST_RUNNING => {
            // Poll event — only does work when GPIO edge detected
            let fired = (sys.provider_call)(
                s.event_handle, event::POLL,
                core::ptr::null_mut(), 0,
            );
            if fired == 1 {
                // Edge detected — read current level, emit control event
                let level = (sys.provider_call)(s.gpio_pin as i32, gpio::GET_LEVEL, ...);
                // ... debounce logic, emit to out_chan ...
            }
            StepReturn::Continue
        }
        _ => StepReturn::error(-1),
    }
}
```

The module never runs in interrupt context. The kernel signals its event when a GPIO edge is detected. The scheduler steps the module in the same tick cycle. The module reads the pin level and processes the change as a normal cooperative state machine step.

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
| `crates/fluxor-abi/src/kernel_abi.rs` | `event::{CREATE,SIGNAL,POLL,DESTROY,BIND_IRQ}` opcodes |
| `crates/fluxor-abi/src/contracts/hal/gpio.rs` | `WATCH_EDGE` opcode for edge-triggered event wakes |
| `src/kernel/module/syscalls.rs` | Event contract dispatch |
| `src/platform/rp/io.rs` | `poll_gpio_edges()` and the per-pin edge bindings (RP) |
| `src/kernel/exec/scheduler/pass.rs` | the pass engine: `pass::run` tick and wake passes, `take_domain_wakes()` |

## Limits

| Resource | Default | Notes |
|----------|---------|-------|
| Event slots | 32 | `MAX_EVENTS` in `src/kernel/ipc/event.rs` |
| Timer slots | 16 | `MAX_TIMERS` in `src/kernel/ipc/fd.rs` |
| Modules (wake mask) | Sized to `MAX_MODULES` per target | `ModuleMask` of 64-bit words, one bit per module slot |
| IRQ source types | GPIO (type 0) | Extensible per HAL |
| GPIO pins per binding | 1 event per pin, 1 pin per event | Enforced at `WATCH_EDGE` bind time |
