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
| KeyVault | `0x10` | `0x1000-0x10FF` | Asymmetric-key slots; kernel-held key material |

Infrastructure classes are kernel-provided services that all modules can use.

Events are the mechanism that enables hardware drivers to run entirely as modules without kernel knowledge of the device. A driver creates an event, binds it to an IRQ source, and polls the event in `step()`. The scheduler only wakes the owning module when its event fires. See `architecture/events.md` for details.

The System class provides exclusive resource locking and platform sideband operations. `RESOURCE_TRY_LOCK` / `RESOURCE_UNLOCK` guard critical resources like FLASH_XIP (exclusive flash/QSPI access). `FLASH_SIDEBAND` performs operations requiring exclusive flash access, such as reading the BOOTSEL button via the QSPI CS pin. The lock pool is bounded (4 slots) with non-blocking try semantics — modules receive `EBUSY` if a resource is already held.

KeyVault is a kernel-managed asymmetric-key store. A module calls `STORE` with raw key material and receives an opaque `i32` handle; `ECDH`, `SIGN`, and `VERIFY` run P-256 directly in the kernel, and `DESTROY` zeroises the slot. The raw bytes never leave kernel static memory — TLS uses this to sign `CertificateVerify` without its own module arena ever seeing the private key after module_new. See `architecture/security.md` for the trust model.

### Bus Classes (continued)

| Class | ID | Opcode Range | Description |
|-------|----|-------------|-------------|
| UART | `0x0D` | `0x0D00-0x0DFF` | UART serial bus |
| ADC | `0x0E` | `0x0E00-0x0EFF` | Analog-to-digital conversion |
| PWM | `0x0F` | `0x0F00-0x0FFF` | Pulse-width modulation |

Like the other bus classes, these provide hardware transport with no
device knowledge. PWM is structured as a kernel raw register bridge plus
a PIC provider module that owns the per-pin slot logic — see
`modules/foundation/pwm_out/`.

### Contract Classes (filesystem dispatch)

| Class | ID | Opcode Range | Description |
|-------|----|-------------|-------------|
| FS | `0x09` | `0x0900-0x09FF` | Filesystem (VFS) dispatch |

The FS class is the only contract class still in active use. A
filesystem driver module (e.g., `fat32`) registers as the FS provider
for a particular storage backend, and consumer modules call
`dev_call(handle, dev_fs::OPEN, ...)` to access files. The kernel's
role is dispatch — it routes the call to the registered provider —
not filesystem implementation.

Networking does not use a contract class. All networking is
channel-based via the net_proto framing convention; the IP module is
a standalone PIC module that exchanges Ethernet frames with driver
modules over channels and net_proto frames with consumer modules over
channels. There is no `dev_socket` or `dev_netif` dispatch in the
hot path. See [network.md](network.md) for the full architecture.

### Cross-Class Operations

| Opcode | Name | Description |
|--------|------|-------------|
| `0x0001` | `GET_STATS` | Class-specific statistics |
| `0x0002` | `SET_POWER_STATE` | Power management (off/low/normal/high) |
| `0x0003` | `GET_POWER_STATE` | Query current power state |
| `0x0004` | `RESET` | Reset device to initial state |
| `0x0005` | `GET_INFO` | Device class, version, capabilities |

Every device class should respond to cross-class opcodes (or return `ENOSYS`).

## Module Categories

Modules are organized into three categories by directory. The device
class system defines which kinds of syscalls each category may use.

### Driver Modules (`modules/drivers/`)

The lowest software component that directly touches the hardware
interface the platform exposes. Use **bus class** syscalls or
platform-specific hardware APIs to communicate with hardware.

- Named after what they drive (e.g., `enc28j60`, `cyw43`, `sd`, `i2s`)
- Platform-specific (depend on available hardware interfaces)
- Allowed to be ugly and non-portable — that's their job
- Examples:
  - `enc28j60` — uses SPI syscalls, exchanges Ethernet frames with IP via channel
  - `cyw43` — uses PIO syscalls (gSPI protocol), exchanges Ethernet frames with IP via channel
  - `virtio_net` — uses MMIO, exchanges Ethernet frames with IP via channel
  - `sd` — uses SPI syscalls, provides block I/O on a channel
  - `i2s` — uses PIO syscalls, consumes audio frames from a channel
  - `st7701s` — uses SPI + PIO syscalls, consumes pixel data from a channel

Fluxor does not require drivers to use bus primitives; it requires
foundation modules not to. A vendor WiFi library exposed through a
function-call surface is still a driver module — driver-ness is about
what the module touches, not how.

### Foundation Modules

Use only **infrastructure class** and **contract class** interfaces
(channels, timers, events, FS dispatch). No hardware access. Portable
across all platforms.

- Named after what they do (e.g., `fat32`, `mqtt`, `ip`, `tls`)
- Live in `modules/foundation/`
- Portable across all platforms
- Never know what hardware is providing their inputs
- Examples:
  - `ip` — TCP/UDP/IP stack, exchanges Ethernet frames with a driver
    over a channel, exposes net_proto to consumer modules over channels
  - `fat32` — filesystem, reads from a block-I/O channel
  - `mqtt` — MQTT client, exchanges net_proto frames with the IP module
  - `http` — HTTP server/client, exchanges net_proto frames with IP or TLS
  - `tls` — TLS 1.3 transformer, sits between consumer modules and IP

### App Modules

Application-level modules that compose drivers and foundation modules
into a workload. Live in `modules/app/`. Examples include audio
synthesizers, codecs, sequencers, mixers, and distributed-systems
components like the Clustor consensus stack.

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
// Acquire a GPIO pin as an input with pull-up
let mut arg = [pin_number, GPIO_PULL_UP];
let handle = (sys.dev_call)(-1, dev_gpio::REQUEST_INPUT, arg.as_mut_ptr(), 2);

// Read the level
let level = (sys.dev_call)(handle, dev_gpio::GET_LEVEL, core::ptr::null_mut(), 0);
```

## Kernel Scope

The kernel provides:

- **Scheduling** — cooperative dispatch, deferred-ready chain, event-driven wake, fault recovery
- **Memory** — module state arenas, channel buffer arena, optional per-module heap, optional demand-paged arenas
- **IPC** — channels (FIFO and mailbox modes), buffer pool, polling
- **Events** — signalable/pollable flags with IRQ binding for hardware notification
- **Timers** — monotonic timers, millisecond/microsecond queries, `StreamTime`
- **Bus primitives** — GPIO, SPI, I2C, PIO, UART, ADC, PWM (hardware transport only)
- **FS dispatch** — routing FS opcodes to registered filesystem providers
- **`dev_call` / `dev_query`** — generic device operation dispatch

The kernel does **not** provide:

- TCP/IP, ARP, ICMP, or any network protocol (foundation module: `ip`)
- WiFi association, scan, or driver-specific opcodes (driver modules: `cyw43`, `enc28j60`, etc.)
- Filesystem implementation (foundation module: `fat32`)
- Application protocols (foundation modules: `mqtt`, `http`, `dns`, `tls`, ...)
- Audio formats, display protocols, or any domain-specific knowledge

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
