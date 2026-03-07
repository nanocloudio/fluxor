# Network Architecture

This document describes how networking is integrated into Fluxor.

## Design Principles

1. **Kernel provides contracts and plumbing, not protocol logic** - Bus primitives, channels/buffers, event/timer/scheduler services, plus netif/socket dispatch and slot management. No WiFi policy, no DHCP/DNS/TCP/IP protocol logic in kernel.
2. **All networking is PIC modules** - Drivers, IP stack, protocols, everything.
3. **NetIF is a contract** - The boundary between driver modules (frame providers) and the IP stack module. All drivers implement the same contract upward, regardless of hardware.
4. **Drivers are allowed to be ugly** - Platform-specific, non-portable, vendor-coupled. That's their job.
5. **Services never care** - A service module uses channels/sockets and never knows what hardware or driver is underneath.
6. **All async, no blocking** - Same polling model as everything else.

## Architecture Overview

```
+------------------------------------------------------------------+
|                     Application Layer                              |
|              (HTTP client, MQTT client, WebSocket)                 |
|                       [Service Modules]                            |
+------------------------------------------------------------------+
                              |
                          Channels
                              |
+------------------------------------------------------------------+
|                     IP Stack (smoltcp)                             |
|              TCP/UDP/IP, ARP, ICMP, DNS cache                     |
|                       [Service Module]                             |
+------------------------------------------------------------------+
                              |
                     NetIF contract (channels)
                              |
+------------------------------------------------------------------+
|                     Network Drivers                                |
|                       [Driver Modules]                             |
+------------------------------------------------------------------+
      |                    |                    |
+-----------+        +-----------+        +-----------+
|   WiFi    |        | Ethernet  |        | Ethernet  |
|  cyw43    |        | ENC28J60  |        |   W5500   |
| (PIO)     |        | (SPI)     |        |  (SPI)    |
+-----------+        +-----------+        +-----------+
 RP2350 only          Any platform        Any platform
```

On ESP32, `cyw43` is replaced by `esp_wifi` which calls the vendor WiFi library instead of PIO syscalls. Same netif contract upward.

Current ABI note: modules typically use `dev_call` opcode wrappers (for example in
`modules/pic_runtime.rs`) rather than older direct `netif_*`/`socket_*` syscall names.

## Network Drivers

Every network driver is a PIC module. "Driver" means the lowest software component that directly touches the hardware interface the platform exposes — not necessarily a bus.

### Frame Providers (e.g., ENC28J60, cyw43, esp_wifi)

Driver modules that send/receive raw Ethernet frames and register as netif providers.

- Module registers via `netif_register_frame(channel)`
- IP stack module (smoltcp) runs on top of frames
- Module sends frames to IP stack via channel
- Module receives frames from IP stack via channel

```
cyw43 Module (RP2350)              IP Stack Module
+---------------+                  +------------------+
| PIO gSPI      |  raw frames     |   smoltcp        |
| CYW43 proto   | <-------------> |   TCP/UDP/IP     |
| FW loading    |   via channel   |   ARP/ICMP       |
+---------------+                  +------------------+

esp_wifi Module (ESP32)            IP Stack Module
+---------------+                  +------------------+
| Vendor SDK    |  raw frames     |   smoltcp        |
| WiFi calls    | <-------------> |   TCP/UDP/IP     |
| IRQ handling  |   via channel   |   ARP/ICMP       |
+---------------+                  +------------------+

ENC28J60 Module                    IP Stack Module
+---------------+                  +------------------+
| SPI driver    |  raw frames     |   smoltcp        |
| MAC handling  | <-------------> |   TCP/UDP/IP     |
| Frame buffer  |   via channel   |   ARP/ICMP       |
+---------------+                  +------------------+
```

All three produce the same netif contract. The IP stack module doesn't know or care which driver is underneath.

### Socket Providers (e.g., W5500)

Driver modules with hardware TCP/UDP stack. These bypass the IP stack module entirely.

- Module registers via `netif_register_socket(channel)`
- Socket operations route directly to driver module
- Module handles TCP/UDP directly in hardware

```
W5500 Module                       Kernel
+---------------+                  +------------------+
| SPI driver    |  socket ops     |   Socket Router  |
| HW TCP/UDP    | <-------------> |   (passthrough)  |
| 8 HW sockets  |   via channel   |                  |
+---------------+                  +------------------+
```

## Network Interface States

```
Down -> Initializing -> NoLink -> Associating -> NoAddress -> Ready
                          ^                          |
                          +---------------------------+
```

| State | Value | Description |
|-------|-------|-------------|
| `Down` | 0 | Hardware not initialized |
| `Initializing` | 1 | Hardware init in progress (firmware loading) |
| `NoLink` | 2 | Ready but no link (WiFi: not associated) |
| `Associating` | 3 | Establishing link (WiFi: WPA handshake) |
| `NoAddress` | 4 | Link up, no IP address (DHCP in progress) |
| `Ready` | 5 | Fully operational with IP |
| `Error` | 255 | Fatal error |

## NetIF Contract

The netif contract is the interface between drivers and the IP stack.

### dev_call Interface

All netif operations use `dev_call` with opcodes from `dev_netif`:

```c
// Open/find interface by type (opaque u8, module-defined)
int handle = dev_call(-1, dev_netif::OPEN, &if_type, 1);

// Register frame provider: arg = [if_type(1), channel_le(4)]
dev_call(-1, dev_netif::REGISTER_FRAME, arg, 5);

// Register socket provider: arg = [if_type(1), channel_le(4)]
dev_call(-1, dev_netif::REGISTER_SOCKET, arg, 5);

// Get interface state (returns opaque u8)
int state = dev_call(handle, dev_netif::STATE, null, 0);

// Set interface state: arg = [state(1)]
dev_call(handle, dev_netif::IOCTL, arg, 1);  // cmd=1 (SET_STATE)

// Close interface
dev_call(handle, dev_netif::CLOSE, null, 0);
```

### IOCTL Commands

The kernel supports a single ioctl:

| Command | Value | Kernel Behavior | Description |
|---------|-------|-----------------|-------------|
| `SET_STATE` | 1 | Stores opaque u8 | Module signals state change |

All state values and their meanings are defined by modules, not the kernel.
WiFi-specific commands (100-199) are routed through the netif provider and
handled by driver modules (e.g. cyw43) — the kernel does not interpret them.

## Socket and Poll Contract

Socket operations are exposed through `dev_call` opcodes in the `dev_socket`
class (`src/abi.rs`) and dispatched by the socket provider (`src/kernel/syscalls.rs`).

Poll flags are stable ABI values:

| Flag | Value | Meaning |
|------|-------|---------|
| `POLL_IN` | `0x01` | Data available to read |
| `POLL_OUT` | `0x02` | Space available to write |
| `POLL_ERR` | `0x04` | Error condition |
| `POLL_HUP` | `0x08` | Hang-up / closed |
| `POLL_CONN` | `0x10` | Connect complete |

Error codes follow stable negative errno values from `src/abi.rs::errno`
(for example `EAGAIN=-11`, `EINVAL=-22`, `ENOSYS=-38`, `ENOTCONN=-107`).

## Data Structures

### Ipv4Config (module-side only)

The kernel does not parse or store this struct. The IP module uses it
internally and signals readiness via `dev_call(handle, IOCTL, [SET_STATE, READY])`.

```c
struct Ipv4Config {
    uint32_t address;   // Network byte order
    uint32_t netmask;
    uint32_t gateway;
};
```

### SocketAddr

```c
struct SocketAddr {
    uint32_t addr;      // IPv4 address, network byte order
    uint16_t port;      // Host byte order
    uint16_t _pad;
};
```

### WifiCredentials

```c
struct WifiCredentials {
    const char* ssid;
    size_t ssid_len;
    const char* password;
    size_t password_len;
};
```

### WifiScanEntry

```c
struct WifiScanEntry {
    uint8_t ssid[32];   // Null-padded
    uint8_t ssid_len;
    uint8_t bssid[6];   // MAC address
    int8_t rssi;        // Signal strength (dBm)
    uint8_t channel;
    uint8_t security;   // 0=Open, 2=WPA, 3=WPA2
};
```

## Module Examples

### WiFi Policy Module (Service)

```rust
// wifi.rs - WiFi association policy (portable service module)
// Uses dev_call for all netif operations. Doesn't know if the
// backing driver is cyw43, esp_wifi, or anything else.
fn module_step(state: *mut u8) -> i32 {
    let s = unsafe { &mut *(state as *mut WifiState) };
    let sys = unsafe { &*s.syscalls };

    match s.state {
        State::Init => {
            let mut if_type = [NETIF_WIFI];
            let handle = (sys.dev_call)(-1, dev_netif::OPEN, if_type.as_mut_ptr(), 1);
            if handle < 0 { return handle; }
            s.netif = handle;
            s.state = State::WaitReady;
        }
        State::WaitReady => {
            let state = (sys.dev_call)(s.netif, dev_netif::STATE, core::ptr::null_mut(), 0);
            if state == NETIF_NOLINK as i32 {
                let creds = WifiCredentials { ... };
                (sys.dev_call)(s.netif, dev_netif::IOCTL, &creds as *const _ as *mut u8, ...);
                s.state = State::Associating;
            }
        }
        State::Associating => {
            let state = (sys.dev_call)(s.netif, dev_netif::STATE, core::ptr::null_mut(), 0);
            if state == NETIF_NOADDRESS as i32 {
                s.state = State::Dhcp;
            }
        }
        // ... DHCP handling ...
    }
    0
}
```

### CYW43 Driver Module (RP2350-specific)

```rust
// cyw43.rs - WiFi frame provider via PIO gSPI (driver module)
// Platform-specific: uses PIO syscalls to talk to CYW43 chip.
// Registers as netif frame provider.
fn module_step(state: *mut u8) -> i32 {
    let s = unsafe { &mut *(state as *mut Cyw43State) };
    let sys = unsafe { &*s.syscalls };

    match s.phase {
        Phase::LoadFirmware => {
            // Multi-step firmware upload via PIO gSPI
            // ...
        }
        Phase::Running => {
            // Check for received frames from chip
            if cyw43_has_event(s) {
                let len = cyw43_read_frame(s, &mut s.rx_buf);
                (sys.channel_write)(s.netif_chan, s.rx_buf.as_ptr(), len);
            }

            // Check for frames to transmit
            let poll = (sys.channel_poll)(s.netif_chan, POLL_IN);
            if poll > 0 && (poll as u8 & POLL_IN) != 0 {
                let len = (sys.channel_read)(s.netif_chan, s.tx_buf.as_mut_ptr(), MTU);
                if len > 0 {
                    cyw43_send_frame(s, &s.tx_buf[..len as usize]);
                }
            }
        }
    }
    0
}
```

### ENC28J60 Driver Module

```rust
// enc28j60.rs - Ethernet frame provider via SPI (driver module)
fn module_step(state: *mut u8) -> i32 {
    let s = unsafe { &mut *(state as *mut Enc28State) };
    let sys = unsafe { &*s.syscalls };

    // Check for received frames
    if enc28_has_packet(s) {
        let len = enc28_read_packet(s, &mut s.rx_buf);
        (sys.channel_write)(s.netif_chan, s.rx_buf.as_ptr(), len);
    }

    // Check for frames to transmit
    let poll = (sys.channel_poll)(s.netif_chan, POLL_IN);
    if poll > 0 && (poll as u8 & POLL_IN) != 0 {
        let len = (sys.channel_read)(s.netif_chan, s.tx_buf.as_mut_ptr(), MTU);
        if len > 0 {
            enc28_send_packet(s, &s.tx_buf[..len as usize]);
        }
    }

    0
}
```

## What Stays in Kernel

The kernel provides only generic primitives:

1. **Scheduling** — cooperative async executor, module step() dispatch, event-driven wake
2. **Memory** — allocation for module state, channel buffers
3. **IPC** — channels, buffers, polling
4. **Timers** — monotonic timers
5. **Events** — signalable/pollable notification flags with IRQ binding (see `architecture/events.md`)
6. **Bus primitives** — GPIO, SPI, I2C, PIO (hardware transport only)
7. **Contract dispatch** — routing netif/socket operations between providers and consumers
8. **dev_call/dev_query** — generic device operation dispatch (ABI v3)

smoltcp (TCP/IP), netif state machines, and protocol policy live in PIC modules.
Kernel socket slot bookkeeping (`src/kernel/socket.rs`) is transport-neutral plumbing.

## What Lives in PIC Modules

Everything above bus primitives:

1. **Network Drivers** — cyw43 (PIO), esp_wifi (vendor SDK), ENC28J60 (SPI), W5500 (SPI)
2. **IP Stack** — smoltcp (TCP/UDP/IP, ARP, ICMP) — service module
3. **WiFi Policy** — association, reconnection, roaming — service module
4. **Protocol Helpers** — DHCP client, mDNS, NTP — service modules
5. **Application Protocols** — HTTP, WebSocket, MQTT, CoAP — service modules
6. **Higher-Level Services** — REST clients, cloud connectors — service modules

## File Locations

| Component | Location | Description |
|-----------|----------|-------------|
| NetIf registry | `src/kernel/net.rs` | Interface slot management, opaque state storage |
| NetIf provider | `src/kernel/syscalls.rs` | `dev_netif` dispatch via provider registry |
| Socket core plumbing | `src/kernel/socket.rs` | Socket slots, poll readiness, TX/RX buffers |
| NetIf/socket opcodes | `src/abi.rs` | `dev_netif` / `dev_socket` opcode namespaces |
| Runtime wrapper helpers | `modules/pic_runtime.rs` | `dev_socket_*`, `dev_channel_*`, `dev_netif_*` helpers |
| ENC28J60 driver | `modules/enc28j60/mod.rs` | Frame provider example |
| CYW43 driver | `modules/cyw43/mod.rs` | WiFi frame provider example |
| IP stack service | `modules/ip/mod.rs` | IP/socket provider service |
