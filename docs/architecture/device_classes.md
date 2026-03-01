# Device Classes

Syscalls are organized into device classes. Each class represents a category of kernel-provided primitive. This document describes the class system, the opcode namespace, and the generic `dev_call`/`dev_query` interface.

## Architecture

The kernel exposes primitives through **typed syscall families** (`spi_*`, `gpio_*`, `channel_*`, etc.). Each family maps to a **device class** with a reserved opcode range. The generic `dev_call` syscall dispatches to the same implementations via opcode lookup.

```
Module code
    |
    +-- Typed syscalls (primary API)
    |   spi_open(), gpio_get_level(), channel_read(), ...
    |   Zero overhead, compile-time clarity
    |
    +-- Generic syscall (ABI v3)
        dev_call(handle, opcode, arg, arg_len)
        Single entry point, stable ABI for marketplace modules
        |
        +-- Dispatches to same kernel implementations
```

Both paths call the same kernel functions. Typed syscalls are preferred for first-party modules. `dev_call` provides ABI stability for third-party/marketplace modules.

## Device Classes

### Bus Classes (hardware transport primitives)

| Class | ID | Opcode Range | Description |
|-------|----|-------------|-------------|
| GPIO | `0x01` | `0x0100-0x01FF` | Digital pin I/O |
| SPI | `0x02` | `0x0200-0x02FF` | SPI bus transactions |
| I2C | `0x03` | `0x0300-0x03FF` | I2C bus transactions |
| PIO | `0x04` | `0x0400-0x04FF` | Programmable I/O state machines |

Bus classes provide transport with no device knowledge. A module using SPI syscalls doesn't know what's on the other end of the bus.

### Infrastructure Classes (kernel services)

| Class | ID | Opcode Range | Description |
|-------|----|-------------|-------------|
| Channel | `0x05` | `0x0500-0x05FF` | Inter-module data pipes |
| Timer | `0x06` | `0x0600-0x06FF` | Monotonic timers |
| Buffer | `0x0A` | `0x0A00-0x0AFF` | Zero-copy buffer operations |
| Event | `0x0B` | `0x0B00-0x0BFF` | Signalable/pollable notification flags |
| System | `0x0C` | `0x0C00-0x0CFF` | Resource locks and flash sideband ops |

Infrastructure classes are kernel-provided services that all modules can use.

Events are the mechanism that enables hardware drivers to run entirely as modules without kernel knowledge of the device. A driver creates an event, binds it to an IRQ source, and polls the event in `step()`. The scheduler only wakes the owning module when its event fires. See `architecture/events.md` for details.

The System class provides exclusive resource locking and platform sideband operations. `RESOURCE_TRY_LOCK` / `RESOURCE_UNLOCK` guard critical resources like FLASH_XIP (exclusive flash/QSPI access). `FLASH_SIDEBAND` performs operations requiring exclusive flash access, such as reading the BOOTSEL button via the QSPI CS pin. The lock pool is bounded (4 slots) with non-blocking try semantics — modules receive `EBUSY` if a resource is already held.

### Contract Classes (driver-to-service boundaries)

| Class | ID | Opcode Range | Description |
|-------|----|-------------|-------------|
| NetIF | `0x07` | `0x0700-0x07FF` | Network interfaces (frames + control) |
| Socket | `0x08` | `0x0800-0x08FF` | TCP/UDP network sockets |
| FS | `0x09` | `0x0900-0x09FF` | Filesystem (VFS) |

Contract classes define the boundary between driver modules and service modules. A driver module *provides* a contract (e.g., a WiFi driver registers as a netif provider). A service module *consumes* a contract (e.g., an MQTT client uses sockets). The kernel routes between them.

NetIF, Socket, and FS are not "kernel networking" or "kernel filesystem" — they are contract interfaces that driver modules implement and service modules consume. The kernel's role is dispatch, not implementation.

### Cross-Class Operations

| Opcode | Name | Description |
|--------|------|-------------|
| `0x0001` | `GET_STATS` | Class-specific statistics |
| `0x0002` | `SET_POWER_STATE` | Power management (off/low/normal/high) |
| `0x0003` | `GET_POWER_STATE` | Query current power state |
| `0x0004` | `RESET` | Reset device to initial state |
| `0x0005` | `GET_INFO` | Device class, version, capabilities |

Every device class should respond to cross-class opcodes (or return `ENOSYS`).

## Module Tiers

The device class system defines a clear boundary between module types.

### Driver Modules

The lowest software component that directly touches the hardware interface the platform exposes. Use **bus class** syscalls or platform-specific hardware APIs to communicate with hardware, and register as providers of **contract class** interfaces.

- Named after what they drive (e.g., `enc28j60`, `cyw43`, `sd`, `button`)
- Platform-specific (depend on available hardware interfaces)
- Allowed to be ugly and non-portable — that's their job
- Examples:
  - `enc28j60` — uses SPI syscalls, registers as netif frame provider
  - `cyw43` — uses PIO syscalls (gSPI protocol), registers as netif frame provider
  - `esp_wifi` — calls vendor WiFi library, registers as netif frame provider
  - `sd` — uses SPI syscalls, provides block I/O
  - `button` — uses GPIO syscalls, emits control events
  - `flash` — uses System flash sideband (BOOTSEL), emits control events
  - `status_led` — uses GPIO syscalls, receives control commands
  - `i2s` — uses PIO syscalls, consumes audio frames

Fluxor does not require drivers to use bus primitives; it requires services not to. The ESP32 WiFi driver is a normal driver module whose hardware interface happens to be a vendor-defined call surface rather than SPI or PIO.

### Service Modules

Use only **infrastructure class** and **contract class** interfaces (channels, timers, netif, sockets, filesystem). No hardware access. Portable across all platforms.

- Named after what they do (e.g., `fat32`, `mqtt`, `synth`, `wifi`)
- Portable across all platforms
- Never know or care how the underlying contract is implemented
- Examples:
  - `ip` — TCP/UDP/IP stack (smoltcp), consumes netif frames, provides sockets
  - `wifi` — WiFi policy (association, reconnection), uses netif ioctls
  - `fat32` — filesystem, reads from block I/O channel
  - `mqtt` — MQTT client, uses sockets
  - `dhcp` — DHCP client, uses sockets or raw netif frames

## dev_call Interface

```c
// Generic device call
int dev_call(
    int handle,       // Device handle (-1 for open operations)
    uint32_t opcode,  // Class << 8 | operation
    void* arg,        // Opcode-specific argument buffer
    size_t arg_len    // Argument buffer length
);

// Device query
int dev_query(
    int handle,       // Device handle
    uint32_t key,     // Query key (see dev_query_key)
    void* out,        // Output buffer
    size_t out_len    // Output buffer length
);
```

### Usage Example

```rust
// All modules use dev_call (typed netif_* syscalls are deprecated stubs)
let mut if_type = [NETIF_WIFI];
let handle = (sys.dev_call)(-1, dev_netif::OPEN, if_type.as_mut_ptr(), 1);
let state = (sys.dev_call)(handle, dev_netif::STATE, core::ptr::null_mut(), 0);
```

## Kernel Scope

The kernel provides:

- **Scheduling** — cooperative async executor, module step() dispatch, event-driven wake
- **Memory** — allocation for module state, channel buffers
- **IPC** — channels, buffers, polling
- **Events** — signalable/pollable flags with IRQ binding for hardware notification
- **Timers** — monotonic timers, millisecond/microsecond queries
- **Bus primitives** — GPIO, SPI, I2C, PIO (hardware transport only)
- **Contract dispatch** — routing between netif/socket/fs providers and consumers
- **dev_call/dev_query** — generic device operation dispatch

The kernel does **not** provide:

- WiFi (driver modules: `cyw43`, `esp_wifi`)
- TCP/IP (service module: `ip` with smoltcp)
- Filesystem logic (service module: `fat32`)
- Application protocols (service modules: `mqtt`, `http`, `dhcp`)
- Any domain-specific knowledge

## Operational Model

The architecture uses:

1. Typed syscalls for common operations.
2. `dev_call` / `dev_query` for class-based device operations.
3. Provider dispatch for device-class contracts.
4. Cross-cutting services through shared query keys and opcodes.

## File Locations

| Component | Location |
|-----------|----------|
| Opcode constants | `src/abi.rs` (`dev_*` modules) |
| Device class IDs | `src/abi.rs` (`dev_class` module) |
| Cross-class opcodes | `src/abi.rs` (`dev_common` module) |
| Query keys | `src/abi.rs` (`dev_query_key` module) |
| dev_call implementation | `src/kernel/syscalls.rs` |
| Event subsystem | `src/kernel/event.rs` |
| Resource/flash sideband | `src/kernel/resource.rs` |
| DeviceInfo struct | `src/abi.rs` |
