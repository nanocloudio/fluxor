# Event System

Kernel-managed signalable/pollable notification objects for event-driven hardware drivers.

## Design Principles

1. **Pure mechanism** — no domain semantics. Events are generic flags. The kernel has no knowledge of WiFi, sensors, or any device protocol.
2. **ISR-safe** — `event_signal_from_isr()` is bounded: one atomic store, one atomic RMW, one Signal. No allocation, no validation, no channel writes.
3. **Cooperative** — events trigger intra-tick module stepping. No preemption, no blocking, no priority inversion.
4. **Static pool** — 32 event slots, atomically allocated. No heap. Deterministic memory.

## Why Events Exist

Without events, modules poll for hardware changes every 1ms tick. This works but has two problems:

1. **Latency** — a GPIO edge that fires 0.5ms after a tick isn't seen until the next tick.
2. **Wasted work** — modules that are waiting for hardware run `step()` every tick even when nothing happened.

Events solve both: the scheduler only steps a module when its event fires, and the `select()` mechanism can break out of the 1ms sleep for sub-tick response.

## Architecture

```
Hardware edge
    |
    v
poll_gpio_edges()  ──>  event_signal(handle)
                              |
                         sets signaled = true
                         sets EVENT_WAKE_PENDING bit for owner module
                         signals SCHEDULER_WAKE
                              |
                              v
                    run_main_loop() detects wake
                              |
                              v
                    step_woken_modules() steps only affected modules
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
    signals SCHEDULER_WAKE  ──>  breaks select() sleep
                                      |
                                      v
                            step_woken_modules() runs immediately
```

## Event Lifecycle

### Create

```rust
// In module_new or module_step:
let evt = (sys.dev_call)(-1, dev_event::CREATE, core::ptr::null_mut(), 0);
// evt >= 0: event handle
// evt < 0: error (ENOMEM if pool exhausted)
```

The event is owned by the currently executing module. When signaled, the scheduler knows which module to wake.

### Signal

```rust
// From any module (e.g., module A signaling module B's event):
let rc = (sys.dev_call)(evt, dev_event::SIGNAL, core::ptr::null_mut(), 0);
```

Sets the signaled flag, marks the owning module for wake, and pokes `SCHEDULER_WAKE`. The owning module will be stepped in the same tick cycle (intra-tick wake).

### Poll

```rust
// In module_step, check if event fired:
let fired = (sys.dev_call)(evt, dev_event::POLL, core::ptr::null_mut(), 0);
// fired == 1: was signaled (now cleared)
// fired == 0: not signaled
// fired < 0: error
```

Poll is atomic: it clears the signaled flag and returns the previous value. This prevents double-processing.

### Destroy

```rust
// In module cleanup:
let rc = (sys.dev_call)(evt, dev_event::DESTROY, core::ptr::null_mut(), 0);
```

Unbinds any IRQ subscription, clears the slot.

## IRQ Subscription

Events can be bound to hardware IRQ sources. This document shows GPIO edge detection as the reference binding pattern.

### GPIO Edge Binding

```rust
// Subscribe event to GPIO pin 15, rising edge:
let args: [u8; 3] = [
    0,    // source_type: GPIO
    15,   // source_id: pin number
    1,    // edge: 1=rising, 2=falling, 3=both
];
let rc = (sys.dev_call)(evt, dev_event::IRQ_SUBSCRIBE, args.as_ptr() as *mut u8, 3);
```

After subscribing, the kernel's `poll_gpio_edges()` function automatically signals the event whenever the specified edge is detected on that pin. The module does not need to poll the GPIO pin itself — just poll the event.

### Unsubscribe

```rust
let rc = (sys.dev_call)(evt, dev_event::IRQ_UNSUBSCRIBE, core::ptr::null_mut(), 0);
```

### Constraints

- The GPIO pin must already be claimed by the module (via `dev_call(pin, dev_gpio::CLAIM, ...)`)
- One event per IRQ source (returns `EBUSY` if already bound)
- One IRQ source per event (call unsubscribe before re-subscribing to a different source)

### Lifecycle Hygiene

- Modules unsubscribe IRQ bindings before event destroy.
- Modules destroy all event handles during shutdown/reconfigure.
- Events remain the only scheduler wake mechanism for hardware-to-module notification paths.

## Scheduler Wake Integration

The main loop uses Embassy's `select()` to sleep efficiently:

```rust
loop {
    // 1. Poll GPIO edges (signals events for bound pins)
    poll_gpio_edges();

    // 2. Step all modules in topological order
    step_modules(modules, module_count);

    // 3. Intra-tick wake: events fired during step_modules
    let wake = take_wake_pending();
    if wake != 0 {
        step_woken_modules(modules, module_count, wake);
    }

    // 4. Sleep until 1ms tick OR event signal
    SCHEDULER_WAKE.reset();
    select(
        Timer::after(1ms),
        SCHEDULER_WAKE.wait(),
    ).await;

    // 5. Post-sleep wake: events from ISR during sleep
    let wake = take_wake_pending();
    if wake != 0 {
        step_woken_modules(modules, module_count, wake);
    }
}
```

### step_woken_modules

A lightweight variant of `step_modules` that:
- Only steps modules whose bit is set in `wake_bits`
- Bypasses frequency gating (`MODULE_STEP_PERIOD`) — event-triggered steps override period
- Preserves topological order (producer before consumer)
- Same done/error handling as the normal step path

### Wake Timing

| Source | Latency | Mechanism |
|--------|---------|-----------|
| GPIO edge (software polled) | Same tick cycle (~0-1ms) | `poll_gpio_edges()` → `event_signal()` → `step_woken_modules()` |
| Module-to-module signal | Same tick cycle | Module A signals → `step_woken_modules()` runs before sleep |
| ISR sources | Sub-tick | ISR → `event_signal_from_isr()` → `SCHEDULER_WAKE` breaks `select()` |

## ISR Safety Contract

`event_signal_from_isr()` contains exactly:

1. Bounds check (`handle < MAX_EVENTS`)
2. `slot.signaled.store(true, Release)` — one atomic store
3. `EVENT_WAKE_PENDING.fetch_or(1 << owner, Release)` — one atomic RMW
4. `SCHEDULER_WAKE.signal(())` — brief critical section via `CriticalSectionRawMutex`

No validation beyond bounds. No allocation. No channel writes. No driver logic. Called at most once per ISR entry (coalesced), not per-pin.

`SCHEDULER_WAKE` uses `Signal<CriticalSectionRawMutex, ()>`, which briefly disables interrupts on single-core Cortex-M33. This is the same mechanism Embassy uses for PIO DMA completion.

## GPIO Event Binding Model

Embassy-rp (0.9.0) registers `#[interrupt] fn IO_IRQ_BANK0()` when the `rt` feature is enabled. The `rt` feature is required for PIO and USB interrupt handlers. `BANK0_WAKERS` is `pub(crate)` and not accessible outside the embassy-rp crate.

GPIO event binding uses software polling via `poll_gpio_edges()` (same-tick-cycle response, ~1ms worst case). This model is suitable for buttons, sensors, and most GPIO-driven peripherals.

For non-GPIO ISR sources (DMA completion, timer), `event_signal_from_isr()` works directly from ISR context. The `select()` mechanism provides sub-tick wake for these sources.

## ABI

### Device Class

| Class | ID | Opcode Range |
|-------|----|-------------|
| Event | `0x0B` | `0x0B00-0x0BFF` |

### Opcodes

| Opcode | Name | Args | Returns |
|--------|------|------|---------|
| `0x0B00` | `CREATE` | handle=-1 | Event handle (>=0) or error |
| `0x0B01` | `SIGNAL` | handle=event | 0 or error |
| `0x0B02` | `POLL` | handle=event | 1 (was signaled), 0 (not), or error |
| `0x0B03` | `DESTROY` | handle=event | 0 or error |
| `0x0B10` | `IRQ_SUBSCRIBE` | handle=event, arg=[source_type, source_id, edge] | 0 or error |
| `0x0B11` | `IRQ_UNSUBSCRIBE` | handle=event | 0 or error |

### Error Codes

| Code | Name | When |
|------|------|------|
| `-12` | `ENOMEM` | No free event slots (pool exhausted) |
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

fn module_step(state: *mut u8) -> i32 {
    let s = unsafe { &mut *(state as *mut ButtonState) };
    let sys = unsafe { &*s.syscalls };

    match s.state {
        ST_INIT => {
            // Claim GPIO pin as input with pull-up
            let rc = (sys.dev_call)(s.gpio_pin as i32, dev_gpio::CLAIM, ...);
            if rc < 0 { return rc; }
            s.state = ST_CREATE_EVENT;
            0
        }
        ST_CREATE_EVENT => {
            // Create an event object
            let evt = (sys.dev_call)(-1, dev_event::CREATE, core::ptr::null_mut(), 0);
            if evt < 0 { return evt; }
            s.event_handle = evt;
            s.state = ST_SUBSCRIBE;
            0
        }
        ST_SUBSCRIBE => {
            // Bind event to GPIO pin, both edges
            let args: [u8; 3] = [0, s.gpio_pin, 3]; // GPIO, pin, both edges
            let rc = (sys.dev_call)(
                s.event_handle, dev_event::IRQ_SUBSCRIBE,
                args.as_ptr() as *mut u8, 3,
            );
            if rc < 0 { return rc; }
            s.state = ST_RUNNING;
            0
        }
        ST_RUNNING => {
            // Poll event — only does work when GPIO edge detected
            let fired = (sys.dev_call)(
                s.event_handle, dev_event::POLL,
                core::ptr::null_mut(), 0,
            );
            if fired == 1 {
                // Edge detected — read current level, emit control event
                let level = (sys.dev_call)(s.gpio_pin as i32, dev_gpio::GET_LEVEL, ...);
                // ... debounce logic, emit to out_chan ...
            }
            0 // Continue
        }
        _ => -1,
    }
}
```

The module never runs in interrupt context. The kernel signals its event when a GPIO edge is detected. The scheduler steps the module in the same tick cycle. The module reads the pin level and processes the change as a normal cooperative state machine step.

## Litmus Test

> Any hardware driver that can be written as a cooperative state machine with event notifications can live entirely as a module, with zero kernel knowledge of the device's domain.

The kernel provides:
- Bus primitives (GPIO, SPI, PIO) for hardware access
- Events for hardware-to-module notification
- Channels for module-to-module data flow
- Timers for time-based operations

The kernel does NOT provide:
- WiFi opcodes, netif types, association states
- Protocol logic, packet formats, device registers
- Any domain-specific dispatch or IOCTL

## Implementation

| File | Description |
|------|-------------|
| `src/kernel/event.rs` | Event pool (32 slots), create/signal/poll/destroy, IRQ subscribe/unsubscribe |
| `src/kernel/mod.rs` | Module declaration (`pub mod event`) |
| `src/abi.rs` | `dev_class::EVENT`, `dev_event` opcodes, `dev_gpio::SET_IRQ/POLL_IRQ` |
| `src/kernel/syscalls.rs` | EVENT class and GPIO IRQ dispatch in `dev_call` |
| `src/io/gpio.rs` | `GPIO_EVENT_BINDING`, modified `poll_gpio_edges()`, accessors |
| `src/kernel/scheduler.rs` | `select()` wake, `step_woken_modules()`, `current_module_index()` |

## Limits

| Resource | Default | Notes |
|----------|---------|-------|
| Event slots | 32 | `MAX_EVENTS` in `event.rs` |
| Modules (wake bitmask) | Sized to `MAX_MODULES` per target | u32 bitmask up to 32 modules; larger targets use a wider bitmask |
| IRQ source types | GPIO (type 0); extensible per HAL |
| GPIO pins per binding | 1 event per pin, 1 pin per event |
