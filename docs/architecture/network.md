# Network Architecture

Networking in Fluxor is built entirely from PIC modules connected by channels.
The kernel knows how to move bytes between modules; it does not know what TCP
is, what an IP address is, or what a TLS session looks like. Drivers, the IP
stack, TLS, DNS, HTTP, MQTT, and every other protocol live in modules and
talk to each other through the same channel mechanism that carries audio
samples or display pixels.

## Design Principles

1. **Channels are the only IPC.** Every byte that crosses a module boundary
   travels through a channel ring buffer. There is no separate "socket"
   syscall, no kernel-mediated handle table, no second poll system for
   networking. The same `channel_read` / `channel_write` / `channel_poll`
   primitives carry net_proto frames between consumer modules and the IP
   stack as carry audio samples between a decoder and I2S.

2. **Drivers exchange raw frames.** A network driver module receives bytes
   off the wire, packages them as Ethernet frames, and writes them to a
   channel. The IP module reads them. In the other direction, the IP module
   writes outbound frames to a channel and the driver puts them on the wire.

3. **Protocol state lives in modules.** TCP retransmission, ARP, ICMP,
   connection tracking, congestion control — all of it is internal to the
   IP module. The kernel cannot observe a TCP connection because the kernel
   does not have a concept of TCP. This makes the IP module replaceable:
   smoltcp on RP2350, a libc-socket bridge on Linux, a kernel-bypass
   driver on a server-class target, all expose the same channel surface.

4. **Consumer modules speak net_proto, not sockets.** HTTP, DNS, MQTT,
   VoIP, RTP, TLS, and Clustor modules each have a channel pair to the IP
   module. They send typed framed messages (`CMD_BIND`, `CMD_CONNECT`,
   `CMD_SEND`) and receive typed framed messages (`MSG_DATA`,
   `MSG_ACCEPTED`, `MSG_CLOSED`) over that channel pair. There is no
   shared socket handle table.

5. **TLS is a channel transformer.** TLS is not interception middleware
   sitting in front of a kernel socket. It is a normal PIC module with
   two pairs of net_proto channels: cleartext to HTTP, ciphertext to IP.
   It reads cleartext frames, wraps the payloads in TLS records, and
   forwards ciphertext frames in the other direction. HTTP and IP do not
   know TLS exists — the config either wires them directly or inserts TLS
   between them.

6. **No blocking, anywhere.** Every operation is non-blocking. Modules
   poll for readiness via `channel_poll` and step their state machines
   cooperatively. Hardware-facing operations on drivers use start/poll
   sequences. Backpressure propagates through channel fullness, not
   through credit counters or sleep loops.

## Architecture Overview

```
+------------------------------------------------------------------+
|                      Application Modules                         |
|       (HTTP, DNS, MQTT, VoIP, RTP, TLS, Clustor stack)           |
|                                                                  |
|  Each module has a channel pair to the IP module.                |
|  Frames carry the net_proto TLV protocol.                        |
+------------------------------------------------------------------+
                              |
                       net_proto channels
                              |
+------------------------------------------------------------------+
|                          IP Module                               |
|              TCP / UDP / IPv4 / ARP / ICMP / DHCP                |
|                                                                  |
|  Owns connection state, port table, conn_id allocation.          |
|  Reads net_proto frames from consumers, writes net_proto         |
|  frames back. Reads Ethernet frames from a driver, writes        |
|  Ethernet frames to it.                                          |
+------------------------------------------------------------------+
                              |
                      raw frame channels
                              |
+------------------------------------------------------------------+
|                       Network Drivers                            |
|                                                                  |
|  cyw43 (PIO gSPI)         enc28j60 (SPI)                         |
|  virtio_net (MMIO)        e810 (PCIe)                            |
|  linux_net (libc bridge)  ch9120 (UART)                          |
+------------------------------------------------------------------+
```

Every box in this diagram is a PIC module connected by `channel_write`/
`channel_read`. The kernel sits below this stack, providing the channels,
the bus primitives the drivers use to touch hardware, and nothing else.

## The net_proto Channel Protocol

`net_proto` is the framing convention used between the IP module and its
consumers. It is a TLV format:

```
[msg_type: u8] [len: u16 LE] [payload: len bytes]
```

The header is three bytes. `len` is the payload length, not the total frame
length. Reading a frame is always a two-step operation: read the 3-byte
header, then read exactly `len` bytes of payload. This prevents one
`channel_read` from accidentally consuming the next frame's header. The
SDK helper `net_read_frame` in `modules/sdk/runtime.rs` handles this.

### Upstream messages (consumer → IP)

| Type | Name | Payload | Meaning |
|------|------|---------|---------|
| `0x10` | `CMD_BIND` | port (u16) | Open a listener on a local port |
| `0x11` | `CMD_SEND` | conn_id (u8) + bytes | Send bytes on an established connection |
| `0x12` | `CMD_CONNECT` | dest_ip (u32) + dest_port (u16) | Initiate outbound connection |
| `0x13` | `CMD_CLOSE` | conn_id (u8) | Tear down a connection |

### Downstream messages (IP → consumer)

| Type | Name | Payload | Meaning |
|------|------|---------|---------|
| `0x01` | `MSG_ACCEPTED` | conn_id (u8) + peer info | Inbound connection established |
| `0x02` | `MSG_DATA` | conn_id (u8) + bytes | Received bytes on a connection |
| `0x03` | `MSG_CLOSED` | conn_id (u8) | Connection torn down |
| `0x04` | `MSG_BOUND` | port (u16) | Listener is ready |
| `0x05` | `MSG_CONNECTED` | conn_id (u8) | Outbound connection established |
| `0x06` | `MSG_ERROR` | code (i16) + conn_id (u8, optional) | Error |

### Connection identity

`conn_id: u8` is a per-IP-instance handle. The IP module allocates it when
a connection is opened and includes it in every downstream message. The
consumer echoes it back on `CMD_SEND` and `CMD_CLOSE`. 256 concurrent
connections per IP instance is sufficient for any practical workload —
HTTP serving thousands of clients runs many IP instances or scales the
type to u16 in a target-specific build.

The connection handle is module-local. It is not a kernel resource. The
kernel does not know what `conn_id 7` means or who owns it. Two consumer
modules attached to two different IP instances can both use `conn_id 7`
without conflict.

### Why two channels per consumer

Each consumer module has one **input** channel from the IP module (carrying
downstream messages) and one **output** channel to the IP module (carrying
upstream commands). The two-channel pattern means consumers and IP can
backpressure independently — a slow HTTP module doesn't block the IP
module's ability to receive frames from the driver, and a busy IP module
doesn't block HTTP from preparing the next request.

```yaml
wiring:
  - from: ip.http_data       # IP → HTTP (downstream messages)
    to: http.net_in
  - from: http.net_out       # HTTP → IP (upstream commands)
    to: ip.http_cmd
```

## Network Drivers

Every network driver is a PIC module. "Driver" means the lowest software
component that touches the hardware interface the platform exposes — not
necessarily a bus driver in the Linux sense.

A driver module has one input channel (outbound frames from IP) and one
output channel (inbound frames to IP). The frame format on those channels
is raw Ethernet (DIX or 802.3, with the 14-byte L2 header but without the
preamble or FCS — those belong to the wire/PHY).

```rust
// Generic shape of a driver step():
fn module_step(state: *mut u8) -> i32 {
    let s = unsafe { &mut *(state as *mut DriverState) };
    let sys = unsafe { &*s.syscalls };

    // 1. Move outbound frames from IP to the wire
    let mut buf = [0u8; MTU];
    let n = (sys.channel_read)(s.frames_in, buf.as_mut_ptr(), MTU);
    if n > 0 {
        hardware_send_frame(s, &buf[..n as usize]);
    }

    // 2. Move inbound frames from the wire to IP
    if hardware_has_frame(s) {
        let len = hardware_read_frame(s, &mut s.rx_buf);
        (sys.channel_write)(s.frames_out, s.rx_buf.as_ptr(), len);
    }

    0
}
```

Drivers are allowed to be ugly — they are platform-specific, vendor-coupled,
and may use bus syscalls in awkward ways to coax the right behavior out of
their hardware. That is their job. The frame interface upward is uniform.

### Frame channels are always Pipe channels

The kernel has exactly one channel implementation: a ring buffer. Frame
channels are sized large enough to hold a few full-sized frames (typically
4–8 KB). Drivers and the IP module exchange complete frames via
`channel_write` / `channel_read` — the ring buffer provides flow control
and the IP module's frame parser handles the boundaries.

For high-throughput targets (CM5, server-class), drivers and IP can use
the **mailbox mode** of channels for zero-copy frame handoff. The driver
acquires a buffer from the channel via `buffer_acquire_write`, the
hardware DMA fills it directly, and the IP module reads it via
`buffer_acquire_read` without copying. This is the same mailbox primitive
used for zero-copy audio buffers — see `pipeline.md` for the buffer state
machine.

### Currently shipping drivers

| Driver | Bus / Interface | Targets | Notes |
|--------|----------------|---------|-------|
| `cyw43` | PIO gSPI | RP2040, RP2350 (Pico W, Pico 2 W) | Onboard WiFi chip |
| `enc28j60` | SPI | Any | Discrete Ethernet PHY |
| `ch9120` | UART | Any | Hardware TCP/IP offload over UART |
| `virtio_net` | MMIO | aarch64 (QEMU virt, BCM2712) | Paravirtualized NIC |
| `e810` | PCIe | aarch64 (CM5, server) | Intel 800-series Ethernet |
| `linux_net` | libc TUN/socket | host-linux | Bridges Fluxor frames to Linux networking |

Each is a PIC module under `modules/drivers/`. None contain TCP, ARP, or
any IP-layer code. None know what an IP address is.

### What about ch9120 — hardware TCP/UDP offload?

The CH9120 chip implements TCP/IP in hardware. The driver module exposes
that hardware as a net_proto endpoint instead of an Ethernet frame
endpoint: it accepts `CMD_BIND` / `CMD_SEND` upstream and emits
`MSG_DATA` / `MSG_CLOSED` downstream, just like the IP module would.

In this configuration, **there is no IP module in the graph**. Consumer
modules wire directly to the ch9120 driver. The same HTTP module that
talks net_proto to the IP module on a Pico W talks net_proto to the
ch9120 driver on a CH9120 board, with no code change. The capability
surface (see `capability_surface.md`) determines which configuration to
emit based on the hardware section.

## The IP Module

The IP module (`modules/foundation/ip/mod.rs`) is a standalone PIC module
that owns the entire TCP/UDP/IPv4 stack. On constrained targets it uses
smoltcp; on Linux it bridges to libc sockets internally. Either way, the
upward interface is identical: net_proto frames over channels.

### Inputs and outputs

The IP module has:

- **One frame input** from a network driver (raw Ethernet frames in)
- **One frame output** to a network driver (raw Ethernet frames out)
- **N pairs of net_proto channels**, one pair per consumer module

The number of consumer pairs is determined at config time by the wiring.
A simple HTTP server might have a single pair; a graph with HTTP, DNS,
and MQTT has three pairs. Each consumer is assigned its own port-range
or owns specific ports declared in the config.

### Per-tick step

Each step the IP module:

1. Reads any pending frames from the driver input, parses them, advances
   TCP/UDP state machines, and queues outbound frames.
2. Writes outbound frames to the driver output until the channel fills.
3. For each consumer pair, reads any pending net_proto commands and
   handles them — `CMD_BIND` allocates a listener, `CMD_CONNECT` opens
   an outbound socket, `CMD_SEND` queues bytes for transmission,
   `CMD_CLOSE` tears down a connection.
4. For each connection with received data, writes `MSG_DATA` frames to
   the appropriate consumer's downstream channel.
5. For state transitions (connection established, connection closed),
   writes the corresponding notification.

The step is bounded — the module processes a fixed number of frames and
commands per tick to keep latency predictable. Backpressure on any
output channel causes that producer to skip the write and retry on the
next step; nothing blocks.

### Connection state

All connection state is private to the IP module's state arena:

- TCP control blocks (state, sequence numbers, retransmit timers, etc.)
- UDP socket bindings
- ARP cache
- Routing table (typically a single default route)
- Port allocation

None of this is visible to other modules or to the kernel. Other modules
see only the net_proto frames they receive on their downstream channel.

### Multiple IP instances

Nothing in the architecture prevents running two IP modules in the same
graph — for example, one bound to an Ethernet driver and another bound
to a WiFi driver. Each has its own connection table and its own consumer
channels. Consumer modules wire to whichever IP instance they belong to.

## TLS as a Channel Transformer

TLS is a normal PIC module with two pairs of net_proto channels:

```
HTTP <--clear_in/clear_out--> TLS <--cipher_in/cipher_out--> IP
```

It reads cleartext net_proto frames from HTTP, performs TLS record
encryption on the payloads, and writes ciphertext net_proto frames to
the IP module. In the other direction it decrypts incoming records and
forwards cleartext frames to HTTP. From HTTP's perspective, TLS *is* the
network: HTTP sends `CMD_SEND` frames to its output channel and reads
`MSG_DATA` frames from its input channel, exactly as it would when
connected directly to the IP module.

The TLS module owns the per-connection cipher state. It maps cleartext
`conn_id` values one-to-one with ciphertext `conn_id` values, so HTTP
can address connections without knowing whether they are encrypted.

```yaml
wiring:
  - from: http.net_out
    to: tls.clear_in
  - from: tls.clear_out
    to: http.net_in
  - from: tls.cipher_out
    to: ip.tls_cmd
  - from: ip.tls_data
    to: tls.cipher_in
```

To run HTTP without TLS, the same config wires HTTP directly to the IP
module:

```yaml
wiring:
  - from: http.net_out
    to: ip.http_cmd
  - from: ip.http_data
    to: http.net_in
```

No code change in HTTP. No "use TLS" flag. The graph topology is the
configuration.

## Consumer Modules

A consumer module is any module that wants to use the network. Examples
shipping today:

| Module | Role |
|--------|------|
| `http` | HTTP server / client (request parsing, header handling, body streaming) |
| `dns` | DNS resolver and authoritative server |
| `mqtt` | MQTT 3.1.1 client |
| `voip` | SIP signalling and RTP transport |
| `rtp` | RTP packet framing |
| `tls` | Channel-to-channel TLS 1.3 transformer |
| `mesh` | MQTT-bridged mesh transport |
| Clustor stack | `replicator`, `tls_stream`, `client_codec`, etc. |

Every one of these modules opens a channel pair to the IP (or TLS) module
in its config wiring and exchanges net_proto frames. None of them call a
"socket" syscall. None of them know what hardware is providing the network
underneath.

### Consumer pattern

```rust
// In module_step():
let mut buf = [0u8; FRAME_MAX];
let (msg_type, len) = net_read_frame(sys, s.net_in, buf.as_mut_ptr(), buf.len());

match msg_type {
    NET_MSG_ACCEPTED => {
        let conn_id = buf[NET_FRAME_HDR];
        // start handling new connection
    }
    NET_MSG_DATA => {
        let conn_id = buf[NET_FRAME_HDR];
        let payload = &buf[NET_FRAME_HDR + 1 .. NET_FRAME_HDR + len];
        // process received bytes
    }
    NET_MSG_CLOSED => {
        let conn_id = buf[NET_FRAME_HDR];
        // clean up connection state
    }
    _ => { /* no message this step */ }
}

// Send a response
let mut out = [0u8; FRAME_MAX];
let payload_len = build_response(&mut out[NET_FRAME_HDR + 1 ..], conn_id, response);
out[NET_FRAME_HDR] = conn_id;
net_write_frame(sys, s.net_out, NET_CMD_SEND, &out, payload_len + 1);
```

The two SDK helpers `net_read_frame` and `net_write_frame` are in
`modules/sdk/runtime.rs`. Reading is the two-step operation described
above; writing constructs the 3-byte header inline and emits the frame
with a single `channel_write`.

## State and Lifecycle

Network drivers and the IP module both go through an initialization
phase before the rest of the network stack can do useful work. The
scheduler integrates this through the **deferred-ready** mechanism:

- A module that needs initialization time exports `module_deferred_ready`
- The pack tool sets header flag bit 2 (`deferred_ready`) on the `.fmod`
- The scheduler tracks per-module ready state and gates downstream
  modules until upstream ready signals arrive
- When the module returns `StepOutcome::Ready` (3) from a step, its ready
  flag is set and downstream modules become eligible for execution

Both the cyw43 driver and the IP module use this. The cyw43 driver
needs to upload firmware to the chip and wait for it to boot. The IP
module waits for the driver to be ready before it tries to send any
frames. HTTP, DNS, and other consumers wait for the IP module to be
ready before they try to bind ports.

This produces a clean transitive readiness chain — from the perspective
of the HTTP module, "the network is ready" means everything between
the HTTP module and the wire has finished initialising, and the HTTP
module never observes a half-initialised state.

For runtime state changes (link drop, association loss, DHCP renewal),
drivers emit log entries and the IP module observes them via the same
frame channel — there is no separate "interface state" enum the kernel
tracks. State observation belongs to the modules that care.

## What Stays in the Kernel

The kernel provides only generic primitives:

1. **Scheduling** — cooperative async dispatch, deferred-ready chain,
   event-driven wake
2. **Memory** — module state arenas, channel buffer arena, optional
   per-module heap
3. **IPC** — channels (FIFO + mailbox modes), buffers
4. **Timers** — monotonic timers, microsecond-resolution clocks
5. **Events** — signalable flags with IRQ binding, scheduler wake
6. **Bus primitives** — GPIO, SPI, I2C, PIO, UART (transport only)

It does **not** provide:

- Sockets, netif registries, port tables, or any IP-layer concept
- WiFi association state, scan results, or driver-specific opcodes
- TCP, UDP, ICMP, ARP, DHCP, or any protocol logic
- Filesystem semantics, asset routing, or anything above bus transport

A module reading kernel symbols would find nothing networking-related
beyond `channel_*` syscalls. That is the entire architecture.

## Examples

### HTTP server on Pico 2 W (WiFi)

```yaml
hardware:
  network:
    type: wifi
    driver: cyw43
    ssid: "${WIFI_SSID}"
    password: "${WIFI_PASSWORD}"

modules:
  - name: http
    port: 80

wiring:
  # Driver ↔ IP frames (auto-wired from hardware section)
  - from: cyw43.frames_rx
    to: ip.frames_rx
  - from: ip.frames_tx
    to: cyw43.frames_tx
  # IP ↔ HTTP net_proto
  - from: ip.http_data
    to: http.net_in
  - from: http.net_out
    to: ip.http_cmd
```

### Same HTTP server on a CH9120 Ethernet board

```yaml
hardware:
  network:
    type: ethernet
    driver: ch9120

modules:
  - name: http
    port: 80

wiring:
  # No IP module — ch9120 speaks net_proto directly
  - from: ch9120.net_data
    to: http.net_in
  - from: http.net_out
    to: ch9120.net_cmd
```

The HTTP module is identical in both configurations.

### HTTPS server with TLS

```yaml
hardware:
  network:
    type: wifi
    driver: cyw43
    ssid: "${WIFI_SSID}"
    password: "${WIFI_PASSWORD}"

modules:
  - name: tls
    cert_path: "/certs/server.crt"
    key_path: "/certs/server.key"
  - name: http
    port: 443

wiring:
  # cyw43 ↔ IP frames (auto-wired)
  # IP ↔ TLS net_proto
  - from: ip.tls_data
    to: tls.cipher_in
  - from: tls.cipher_out
    to: ip.tls_cmd
  # TLS ↔ HTTP net_proto
  - from: tls.clear_out
    to: http.net_in
  - from: http.net_out
    to: tls.clear_in
```

### MQTT client + DNS resolver sharing one IP module

```yaml
hardware:
  network:
    type: wifi
    driver: cyw43

modules:
  - name: dns
  - name: mqtt
    broker: "mqtt.example.com"
    topic: "sensors/temp"

wiring:
  - from: ip.dns_data
    to: dns.net_in
  - from: dns.net_out
    to: ip.dns_cmd
  - from: ip.mqtt_data
    to: mqtt.net_in
  - from: mqtt.net_out
    to: ip.mqtt_cmd
```

One IP module instance, two consumer modules, two pairs of net_proto
channels. The IP module routes connections to the right consumer based
on which channel pair the connection was opened on.

## Related Documentation

- `architecture/pipeline.md` — channel mechanics, mailbox mode, scheduler
- `architecture/capability_surface.md` — hardware section, driver auto-wiring
- `architecture/events.md` — IRQ binding for interrupt-driven drivers
- `architecture/device_classes.md` — bus primitives drivers use to touch hardware
