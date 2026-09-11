# Network Architecture

Networking in Fluxor is built entirely from PIC modules connected by
channels. The kernel knows how to move bytes between modules; it does not
know what TCP is, what an IP address is, or what a TLS session looks like.
Drivers, the IP stack, TLS, DNS, HTTP, and every other protocol live in
modules and talk to each other through the same channel mechanism that
carries audio samples or display pixels.

This document describes the stream wire format and the module layering.
`protocol_surfaces.md` defines the wider protocol substrate: the stream,
datagram, packet, and multiplexed-session surfaces and the session
continuity classes above them. The `net_proto` TLV format described below
is the stream surface; datagram and packet traffic use the separate
contracts in `modules/sdk/contracts/net/datagram.rs` and
`modules/sdk/contracts/net/packet.rs`, which share the same 3-byte TLV
header and disjoint opcode ranges so one channel pair can carry several
contracts without ambiguity.

## Design Principles

1. **Channels are the only IPC.** Every byte that crosses a module
   boundary travels through a channel ring buffer. There is no separate
   "socket" syscall, no kernel-mediated handle table, no second poll
   system for networking. The same `channel_read` / `channel_write` /
   `channel_poll` primitives that carry audio samples between a decoder
   and I2S carry net_proto frames between consumer modules and the IP
   stack.

2. **Drivers exchange raw frames.** A network driver module receives
   bytes off the wire, packages them as Ethernet frames, and writes them
   to a channel. The IP module reads them. In the other direction, the
   IP module writes outbound frames to a channel and the driver puts
   them on the wire.

3. **Protocol state lives in modules.** TCP retransmission, ARP, ICMP,
   connection tracking: all of it is internal to the IP module. The
   kernel cannot observe a TCP connection because the kernel does not
   have a concept of TCP. This makes the network provider replaceable:
   the in-tree IP module on bare-metal targets, or the `linux_net`
   platform module bridging to host sockets on Linux, exposes the same
   channel surface.

4. **Consumer modules speak net_proto, not sockets.** HTTP, DNS, MQTT,
   and TLS modules exchange typed framed messages (`CMD_BIND`,
   `CMD_CONNECT`, `CMD_SEND` upstream; `MSG_DATA`, `MSG_ACCEPTED`,
   `MSG_CLOSED` downstream) over a channel pair. There is no shared
   socket handle table.

5. **TLS is a channel transformer.** TLS is not interception middleware
   sitting in front of a kernel socket. It is a normal PIC module with
   two pairs of net_proto channels: cleartext to HTTP, ciphertext to the
   IP module. HTTP and IP do not know TLS exists; the config either
   wires them directly or inserts TLS between them.

6. **No blocking, anywhere.** Every operation is non-blocking. Modules
   poll for readiness via `channel_poll` and step their state machines
   cooperatively. Hardware-facing operations on drivers use start/poll
   sequences. Backpressure propagates through channel fullness, not
   through credit counters or sleep loops.

## Architecture Overview

```
+------------------------------------------------------------------+
|                      Consumer Modules                            |
|                 (HTTP, DNS, MQTT, TLS, OTLP)                     |
|                                                                  |
|  Frames carry the net_proto / datagram / packet contracts.       |
+------------------------------------------------------------------+
                              |
                     net_in / net_out channels
                              |
+------------------------------------------------------------------+
|                     Network Provider                             |
|   IP module (bare metal): TCP / UDP / IPv4 / ARP / ICMP / DHCP   |
|   linux_net (hosted): bridge to host sockets                     |
|                                                                  |
|  Owns connection state, port table, conn_id allocation.          |
+------------------------------------------------------------------+
                              |
                    frames_rx / frames_tx channels
                              |
+------------------------------------------------------------------+
|                       Network Drivers                            |
|                                                                  |
|  cyw43 (PIO gSPI WiFi)     enc28j60 (SPI Ethernet)               |
|  rp1_gem (Pi 5 Ethernet)   virtio_net (MMIO)                     |
|  e810 (PCIe, skeleton)     ch9120 (UART TCP offload bridge)      |
+------------------------------------------------------------------+
```

Every box in this diagram is a PIC module connected by `channel_write` /
`channel_read`. The kernel sits below this stack, providing the channels,
the bus primitives the drivers use to touch hardware, and nothing else.

## The net_proto Channel Protocol (Stream Surface)

Source: `modules/sdk/contracts/net/net_proto.rs`.

`net_proto` is the framing convention between the network provider and
its stream consumers. It is stream-only: datagram traffic (DNS, RTP,
log_net) uses the `datagram` contract and packet-preserving flows (QUIC,
SRTP) use the `packet` contract, on the same channel pair, with disjoint
opcode ranges.

The TLV format is:

```
[msg_type: u8] [len: u16 LE] [payload: len bytes]
```

The header is three bytes. `len` is the payload length, not the total
frame length. Reading a frame is a two-step operation: read the 3-byte
header, then read exactly `len` bytes of payload, so one `channel_read`
never consumes the next frame's header. The SDK helpers `net_read_frame`
and `net_write_frame` in `modules/sdk/runtime/net.rs` implement this;
`net_read_frame_aligned` additionally discards an oversized payload tail
so the stream stays frame-aligned.

### Upstream messages (consumer → provider)

| Type | Name | Payload |
|------|------|---------|
| `0x10` | `CMD_BIND` | `[port: u16 LE]` — open a listener |
| `0x11` | `CMD_SEND` | `[conn_id: u16 LE][data…]` — send bytes on a connection |
| `0x12` | `CMD_CLOSE` | `[conn_id: u16 LE]` — tear down a connection |
| `0x13` | `CMD_CONNECT` | `[sock_type: u8][ip: u32 LE][port: u16 LE][requester_tag: u8?]` |

`CMD_CONNECT` accepts only `SOCK_TYPE_STREAM` (1); any other `sock_type`
fails with EINVAL. The trailing `requester_tag` is optional (the 7-byte
form means tag 0) and is echoed back in `MSG_CONNECTED`; see
§Fan-out and filtering.

The `data` portion of one `CMD_SEND` must not exceed `MAX_CMD_DATA`
(8192 bytes); a consumer with more bytes issues multiple `CMD_SEND`s and
the provider re-segments to MSS on the wire.

### Downstream messages (provider → consumer)

| Type | Name | Payload |
|------|------|---------|
| `0x01` | `MSG_ACCEPTED` | `[conn_id: u16 LE][local_port: u16 LE]` — inbound connection established |
| `0x02` | `MSG_DATA` | `[conn_id: u16 LE][data…]` — received bytes |
| `0x03` | `MSG_CLOSED` | `[conn_id: u16 LE]` — connection torn down |
| `0x04` | `MSG_BOUND` | `[conn_id: u16 LE][local_port: u16 LE]` — listener ready |
| `0x05` | `MSG_CONNECTED` | `[conn_id: u16 LE][requester_tag: u8]` — outbound connection established |
| `0x06` | `MSG_ERROR` | `[conn_id: u16 LE][errno: i8][requester_tag: u8?]` |
| `0x09` | `MSG_TRACE_CTX` | `[conn_id: u16 LE][trace_id: 16][parent_span_id: 8][trace_flags: u8]` |

Opcodes `0x07` and `0x08` are reserved: the IP module uses them
privately for `MSG_RETRANSMIT` (`[conn_id: u16 LE][from_seq: u32 LE]`)
and `MSG_ACK` (`[conn_id: u16 LE][acked_seq: u32 LE]`) on the same
channel. The IP module does not retain TCP payload for retransmission;
the consumer does, if it wants to. `MSG_ACK` lets the consumer truncate
its send buffer; `MSG_RETRANSMIT` fires on fast-retransmit or RTO and
asks the consumer to re-supply bytes from an absolute TCP sequence
number. The TLS module uses this to hold encrypted records until they
are acknowledged; see `security.md`.

The `data` portion of one `MSG_DATA` frame never exceeds
`MAX_DATA_FRAGMENT` (1460 bytes, one TCP MSS), so a consumer may size
its frame scratch to `FRAME_HDR + CONN_ID_LEN + MAX_DATA_FRAGMENT` and
be sure a whole frame always fits.

`MSG_TRACE_CTX` carries W3C trace context for a connection. The ingress
emits it right after `MSG_ACCEPTED`, and each forwarding stage (TLS)
re-emits it with its own span id so the next stage parents its span
correctly. It is best-effort (dropped if the channel is full) and a
stage that does not trace discards it like any unknown frame.

### Connection identity

`conn_id` is a `u16` LE per-provider-instance handle. The provider
allocates it when a connection is opened and includes it in every
downstream message; the consumer echoes it back on `CMD_SEND` and
`CMD_CLOSE`. The id space (65,535) exceeds any connection table a
supported target can back, so concurrency is bounded by the table, never
by the wire. `conn_id` 0 is a valid handle.

The connection handle is module-local, not a kernel resource. Two
consumers attached to two different provider instances can both hold
`conn_id 7` without conflict.

### Fan-out and filtering

The provider has a single net_proto pair: `net_in` (commands in) and
`net_out` (messages out). When several stream consumers share it, the
config fans `net_out` to each of them and every consumer filters:

- **Inbound connections** carry `local_port` in `MSG_ACCEPTED`; each
  consumer claims only connections accepted on the port it bound.
- **Outbound connections** are claimed by `requester_tag`: a consumer
  tags its `CMD_CONNECT` with its module index plus one (the
  `dev_requester_tag` encoding — the sentinel `REQUESTER_TAG_NONE` (0)
  therefore never collides with module index 0) and claims the
  `MSG_CONNECTED` or connect-phase `MSG_ERROR` echoing that tag. On a
  connect-phase failure `conn_id` is meaningless, so the failure must be
  matched on `requester_tag` alone.

A sole consumer may ignore both fields.

### Why two channels per consumer

Each consumer has one input channel (downstream messages) and one output
channel (upstream commands), so consumers and the provider backpressure
independently: a slow HTTP module does not block the provider's ability
to receive frames from the driver, and a busy provider does not block
HTTP from preparing the next request. Channel capacity on a wiring edge
is set with `buffer_bytes`.

```yaml
wiring:
  - from: ip.net_out       # provider → consumer (downstream messages)
    to: http.net_in
  - from: http.net_out     # consumer → provider (upstream commands)
    to: ip.net_in
```

## Network Drivers

Every network driver is a PIC module under `modules/drivers/`. "Driver"
means the lowest software component that touches the hardware interface
the platform exposes.

A frame driver has one input channel (outbound frames from IP, port
`frames_tx`) and one output channel (inbound frames to IP, port
`frames_rx`). The frame format is raw Ethernet (DIX or 802.3, with the
14-byte L2 header but without the preamble or FCS, which belong to the
wire/PHY). Drivers are allowed to be ugly: they are platform-specific
and vendor-coupled, and may use bus syscalls in awkward ways. The frame
interface upward is uniform.

| Driver | Bus / Interface | Targets | Notes |
|--------|----------------|---------|-------|
| `cyw43` | PIO gSPI | RP2040, RP2350 (Pico W, Pico 2 W) | Onboard WiFi; paired with the `wifi` control module |
| `rp1_gem` | RP1 GEM | Pi 5 | Onboard gigabit Ethernet |
| `enc28j60` | SPI | Any | Discrete Ethernet PHY |
| `virtio_net` | MMIO | aarch64 (QEMU virt) | Paravirtualised NIC |
| `e810` | PCIe | aarch64 server | Intel 800-series; skeleton, RX/TX poll stubbed |
| `ch9120` | UART | Any | Hardware TCP/IP offload; transparent byte bridge, see below |

None of the frame drivers contain TCP, ARP, or any IP-layer code.

On WiFi targets the `cyw43` driver handles the chip; the separate
`wifi` module (`modules/foundation/wifi/`) drives association over the
`wifi_ctrl` / `status` channel pair, with credentials supplied as module
params (`ssid`, `password`, `security`).

### Interface state

Drivers emit interface transitions as `MSG_NETIF_STATE` frames on a
dedicated `netif_state` output port, with a one-byte payload from the
`NETIF_STATE_*` values in `modules/sdk/runtime/consts.rs` (`DOWN`,
`NO_LINK`, `NO_ADDRESS`, `READY`, `ERROR`). Consumers that care (the
`wifi` module, for example) wire an input port of the same name. The
kernel tracks no interface state.

### Frame channels and mailbox mode

The kernel has exactly one channel implementation: a ring buffer.
Drivers and the IP module exchange complete frames via `channel_write` /
`channel_read`; the ring provides flow control and the IP module's
parser handles frame boundaries. For zero-copy handoff, channels also
have a mailbox mode: the producer acquires a buffer via
`buffer_acquire_write`, hardware DMA fills it directly, and the consumer
maps it via `buffer_acquire_read` without copying. This is the same
mailbox primitive used for zero-copy audio buffers; see `pipeline.md`
for the buffer state machine.

### ch9120: hardware TCP/IP offload

Source: `modules/drivers/ch9120/mod.rs`.

The CH9120 chip implements TCP/IP in hardware and presents a transparent
serial bridge: UART TX bytes go out on the network, network bytes arrive
on UART RX. The driver configures the chip (mode, addresses, ports) over
the CH9120 serial command protocol, then moves raw payload bytes between
its channel pair and the UART. It does not speak net_proto and carries a
single pre-configured connection; graphs using it wire an application
module directly to the driver's data channels. It emits `netif_state`
like the frame drivers.

## Admission Control: conn_guard

Source: `modules/foundation/conn_guard/mod.rs`.

Between the NIC driver and the IP module the Pi 5 network stack
(`stacks/net.toml`) inserts a stateless admission filter. It parses
Ethernet + IPv4 + TCP headers just far enough to identify pure SYNs and
rate-limits them per `(destination IPv4, source IPv4)` pair in a
fixed-size LRU table, so a flood aimed at one local address cannot
exhaust another workload's budget. Defaults: 32-entry table
(`rate_table_size`, 0 disables the guard), 16 SYNs
(`rate_limit_per_ip`) per 1000 ms window (`rate_window_ms`). Non-TCP,
non-SYN, and within-budget traffic passes through untouched.
`security.md` covers the threat model.

## The IP Module

Source: `modules/foundation/ip/mod.rs`.

The IP module is a standalone PIC module that owns the TCP/UDP/IPv4
stack on bare-metal targets. Its channels are:

- `frames_rx` (in[0]): raw Ethernet frames from the driver
- `frames_tx` (out[0]): raw Ethernet frames to the driver
- `net_in` (in[1]): net_proto / datagram commands from consumers
- `net_out` (out[1]): net_proto / datagram messages to consumers

### Supported profile

The stack implements a deliberately narrow IPv4 profile. These are
interoperability constraints, not gaps awaiting opportunistic patching:

- **IPv4 fragments are not reassembled.** Any packet carrying MF or a
  nonzero fragment offset is dropped before TCP or UDP sees it. A peer
  that must reach the node has to keep its datagrams inside the path
  MTU; the stack does not implement Path MTU Discovery either, so there
  is no ICMP "Fragmentation Needed" signal to observe.
- **One subnet, one default gateway.** An off-subnet destination with no
  configured gateway is unreachable and returns `ENETUNREACH`. There is
  no route table to populate and no on-link exception.
- **ARP mappings are created only by ARP.** Ordinary IPv4 traffic may
  refresh an existing mapping whose MAC is unchanged; installing a new
  mapping, or moving one to a different MAC, requires a correlated ARP
  reply. First contact with a new peer therefore costs one ARP round
  trip even when that peer has just sent traffic.
- **One transmit frame per datagram.** There is no transmit-side
  fragmentation: a UDP payload larger than the frame ceiling is refused
  with `EMSGSIZE` rather than truncated or split.

### Per-tick step

Each step the IP module:

1. Reads pending frames from `frames_rx`, parses them, advances TCP/UDP
   state machines, and queues outbound frames.
2. Writes outbound frames to `frames_tx` until the channel fills.
3. Reads pending commands from `net_in` and handles them: `CMD_BIND`
   allocates a listener, `CMD_CONNECT` opens an outbound socket,
   `CMD_SEND` queues bytes for transmission, `CMD_CLOSE` tears down a
   connection.
4. Writes `MSG_DATA` and state-transition notifications to `net_out`.

The step is bounded: the module processes a fixed number of frames and
commands per tick to keep latency predictable. Backpressure on any
output channel causes that producer to skip the write and retry on the
next step; nothing blocks.

### Connection state

All connection state is private to the IP module's state arena: TCP
control blocks, UDP socket bindings, the ARP cache, the routing table
(typically a single default route), and port allocation. Other modules
see only the frames they receive on their channels.

### Multiple instances

Nothing in the architecture prevents running two IP modules in one
graph, for example one bound to an Ethernet driver and another to a WiFi
driver. Each has its own connection table and its own channel pair, and
consumers wire to whichever instance they belong to.

### Table-sized work

Nothing on the ip module's step is allowed to grow with the connection
table. Lookups go through the hash indexes (`ip/index.rs`); the timer
sweep walks a slice proportional to the time elapsed in its 50 ms
window and never more than `SWEEP_SLICE_MAX` records in one step, so a
window owed after a stall is repaid over several steps rather than as
one multi-millisecond walk; a handshake held back by neighbour
resolution is remembered in a bounded list (`ARP_WAIT_MAX`) that an ARP
reply retries, with the sweep's per-tick retry covering a full list;
a slot is allocated by popping a free stack that every release pushes,
and when the stack is empty — the table is full — one bounded slice
(`ALLOC_SCAN_SLICE`) per step rebuilds it and the arrival is refused, so
a SYN flood at the ceiling never walks the table per SYN; loopback pairs
take their slots from the same allocator as accepted connections. The
step guard is what makes this a correctness rule rather than a
preference: a step that walks the whole table on a 65,536-record profile
ends the module. (Hardware pass: the first 65,535-connection rung on the
Pi 5 ended the board at ~63,000 connections — the free-slot cursor scan
degenerates to a full walk per SYN as the table fills.)

The same rule reaches the wiring around the module. A consumer port
shared by two readers — `debug: to: net` puts `log_net` beside the
application on `net_out` and `net_in` — is served by a kernel fan
(`_tee` on the way out, `_merge` on the way in), and what the fan moves
per step is then the ceiling on every accept, delivery and send. A fan
moves whole frames, up to `FAN_FRAMES_PER_STEP` of them per step, and
consumes nothing while any reader's ring is full, so every reader on a
fanned port must drain what it does not want (`log_net` discards up to
its own per-step budget) or the port stalls for all of them. Nor does
the module log per connection: the `[ip] hb` and `[ip] drop` lines carry
the counts, and a line per handshake at 8,192 handshakes a second is a
log storm through the same NIC the handshakes need.

## Hosted Linux: linux_net

Source: `modules/platform/linux/linux_net/`.

On the Linux target there is no IP module in the graph. The `linux_net`
platform module presents the same `net_in` / `net_out` net_proto surface
and bridges it to host sockets internally, so the same consumer modules
run unchanged. The Linux variant of `stacks/net.toml` instantiates it.

## TLS as a Channel Transformer

TLS (`modules/foundation/tls/`) is a normal PIC module with two pairs of
net_proto channels:

```
HTTP <--clear_in/clear_out--> TLS <--cipher_in/cipher_out--> IP
```

It reads cleartext net_proto frames from HTTP, performs TLS record
encryption on the payloads, and writes ciphertext net_proto frames to
the IP module; in the other direction it decrypts incoming records and
forwards cleartext frames to HTTP. From HTTP's perspective, TLS is the
network: HTTP sends `CMD_SEND` frames and reads `MSG_DATA` frames
exactly as it would when wired directly to the IP module. The TLS module
owns the per-connection cipher state and maps cleartext `conn_id` values
one-to-one with ciphertext `conn_id` values.

```yaml
wiring:
  - from: ip.net_out
    to: tls.cipher_in
  - from: tls.cipher_out
    to: ip.net_in
  - from: tls.clear_out
    to: http.net_in
  - from: http.net_out
    to: tls.clear_in
```

To run HTTP without TLS, the same config wires HTTP directly to the IP
module. No code change in HTTP, no "use TLS" flag: the graph topology is
the configuration.

## Consumer Modules

A consumer module is any module that uses the network:

| Module | Provided by | Role |
|--------|-------------|------|
| `http` | wave | HTTP server / client |
| `dns` | `modules/foundation/dns/` | DNS resolver and authoritative server |
| `mqtt_client` | quantum | MQTT 3.1.1 client |
| `tls` | `modules/foundation/tls/` | Channel-to-channel TLS 1.3 transformer |
| `log_net` | `modules/foundation/log_net/` | Log/netconsole emitter (datagram surface) |

Each opens a channel pair to the network provider (or to TLS) in its
config wiring and exchanges contract frames. None of them call a
"socket" syscall, and none know what hardware provides the network
underneath.

### DNS64 and authoritative update

Source: `modules/foundation/dns/mod.rs`; gates `tests/harness/tests/dns64.rs`,
`tests/harness/tests/dns_update.rs`; rigs `tests/host/dns64_stock_client.sh`,
`tests/host/dns_update_nsupdate.sh`.

Both are off unless their manifest parameter is set.

**DNS64** (`dns64_prefix`, RFC 6147 / RFC 6052, /96 only) is a
*non-validating* forwarding profile. A native AAAA answer is always relayed
as received. A forwarded AAAA whose answer is a complete, correlated
NOERROR/NODATA — never NXDOMAIN, an error rcode, a referral, a truncated or
a malformed answer — starts one follow-up A query for the terminal owner in
the same pending slot, in a second phase, against the deadline the query was
accepted with; the slot table never grows for it. CNAME chains are followed
under `MAX_CNAME_HOPS` / `MAX_CHAIN_BYTES` with loop detection, the chain is
preserved and only the terminal owner's A RRset is translated; a DNAME in
the answer is refused SERVFAIL. The synthesized TTL is `min(remaining A TTL,
negative-AAAA SOA minimum)`, or the remaining A TTL capped at 600 s without
a SOA, with the time spent resolving deducted. A locally configured A is
synthesized at the local TTL. Non-global IPv4 is excluded by default and
always under the well-known prefix `64:ff9b::/96`; a network-specific prefix
with an explicit `dns64_exclude` list translates exactly what the list
leaves. Each prefix/exclusion publication is a generation, and a query keeps
the generation it was accepted under.

The DNSSEC profile is the conservative one: a query with DO or CD set is
forwarded unchanged and never synthesized, so the caller's validation is
preserved; a synthesized answer clears AD and never carries an RRSIG. This
is not a validating DNS64 and does not claim one. There is no TCP surface in
the module, so a TC answer is relayed with TC set and the client retries
over TCP with its own resolver.

**Dynamic update** (`update_zone`, RFC 2136 with RFC 8945 TSIG) makes the
module the authoritative speaker for one zone, held as immutable
generations of at most `MAX_ZONE_RRS` records and served with AA. Every
UPDATE must carry an `hmac-sha256` TSIG under a key named in
`update_allow` (`"keyname=name-suffix,TYPE,..."`); the key is a vault
`HMAC_SHA256` key under the label `dns/tsig/<keyname>`, opened — never
generated — at construct, and the MAC is checked inside the vault. Unsigned
requests are REFUSED; a bad key, signature or time is NOTAUTH with the TSIG
error (BADKEY / BADSIG / BADTIME), and the time check reads the kernel's
trusted calendar clock under a `MAX_TSIG_FUDGE_S` window, failing closed
when the clock is untrusted (`[[requires_when]] time.wall`). All five RFC
2136 prerequisite forms are evaluated against the current generation; the
update section is prescanned, permission-checked against the key's
name-suffix and types, and applied to a candidate copy, so any refusal —
format, scope, permission, capacity — leaves the current generation as it
was. `update_durability` is mandatory: `volatile` acknowledges at once and
logs that the zone is lost on restart; `durable` commits the candidate
through the `fs` contract (temp → write → fsync → close → rename) before
acknowledging and recovers the last complete committed generation at
construct. A repeated authenticated transaction (same key and MAC) inside
`TXN_RETAIN_MS` is answered from the retained response. Messages are UDP,
at most 512 bytes.

## Platform Stack Expansion

Source: `stacks/net.toml`.

A config requests networking with a `platform` entry:

```yaml
platform:
  net: {}
```

The build tool selects a stack variant by board: `virtio_net` + `ip` on
QEMU virt, `cyw43` + `wifi` + `ip` on Pico W / Pico 2 W (WiFi
credentials from the `WIFI_SSID` / `WIFI_PASSWORD` / `WIFI_SECURITY`
environment), `rp1_gem` + `conn_guard` + `ip` on Pi 5, and `linux_net`
on Linux. The variant supplies the driver↔IP frame wiring; the app
config wires consumers to `ip.net_out` / `ip.net_in` (or `linux_net.*`
on Linux).

## Readiness and Lifecycle

Network drivers and the IP module need initialisation time before the
rest of the stack can work. The scheduler integrates this through the
deferred-ready mechanism:

- A module that needs initialisation time exports
  `module_deferred_ready`; the pack tool sets header flag bit 2
  (`deferred_ready`) on the `.fmod`.
- The scheduler gates downstream modules until upstream ready signals
  arrive; when a module returns `StepOutcome::Ready` (3) from a step,
  its ready flag is set and downstream modules become eligible.

The cyw43 driver uses this while it uploads firmware to the chip; the IP
module waits for the driver before sending frames; consumers wait for
the IP module before binding ports. From the HTTP module's perspective,
"the network is ready" means everything between it and the wire has
finished initialising, and it never observes a half-initialised state.

## What Stays in the Kernel

The kernel provides only generic primitives:

1. **Scheduling** — cooperative dispatch, deferred-ready chain,
   event-driven wake
2. **Memory** — module state arenas, channel buffer arena, optional
   per-module heap
3. **IPC** — channels (FIFO and mailbox modes), buffers
4. **Timers** — monotonic timers, microsecond-resolution clocks
5. **Events** — signalable flags with IRQ binding, scheduler wake
6. **Bus primitives** — GPIO, SPI, I2C, PIO, UART (transport only)

It does not provide sockets, netif registries, port tables, WiFi
association state, TCP/UDP/ICMP/ARP/DHCP logic, or anything else above
bus transport. A module reading kernel symbols finds nothing
networking-related beyond the `channel_*` syscalls.

## Related Documentation

- `protocol_surfaces.md` — protocol surfaces and continuity classes
- `pipeline.md` — channel mechanics, mailbox mode, scheduler
- `capability_surface.md` — capability names and stack selection
- `events.md` — IRQ binding for interrupt-driven drivers
- `abi_layers.md` — HAL contracts drivers use to touch hardware
- `security.md` — conn_guard, retransmit buffering, KEY_VAULT, trust
  model

## Emission Control

Contract: `modules/sdk/contracts/net/identity.rs` (`ADDR_ARM`,
`ADDR_FENCE`, the `addr_evt` events). Provider: `modules/foundation/ip`.

A secondary local address is installed by the address-control writer
(`ADDR_ADD`) and, from then on, is either **armed** — the stack sources
frames from it and answers ARP for it — or **fenced** — it does neither.
Every install mints an emission token (16 CSPRNG bytes mixed with the
kernel's boot incarnation, `BOOT_INCARNATION`) and returns it on
`addr_evt` (`MSG_ADDR_ADDED`); `ADDR_ARM` and `ADDR_FENCE` present that
token. A token from a previous install of the address, or from a previous
boot of the host, cannot match, which is what keeps a coordinator from a
previous life from re-enabling emission it no longer owns. An install is
armed unless the writer sets `install::DISARMED`, so a standby can hold an
address silently until it is told to speak; arming announces the address
with a gratuitous ARP.

The fence closes one gate, the hand-off to the driver ring in `send_frame`,
so it holds for every path that builds a frame: data, SYN-ACKs, RSTs, ARP
replies and the defence of the address against a competing claim (a fenced
address is not defended — its next owner may claim it). `MSG_ADDR_FENCED`
reports the cutoff index and what the boundary is worth. After closing
the gate the module asks the frame channel's reader — the NIC driver —
to drain, over the `tx_drain` channel ioctl (`net::identity::tx_drain`):
a driver that owns its transmit ring answers `EAGAIN` while any frame
handed over is unread on the channel or unused by the hardware, then `0`
with its completed transmit count, and the event goes out with
`cutoff::WIRE` and that count. The event is held while the driver drains,
bounded by `FENCE_WIRE_WAIT_MS`; past the wait, or on a channel whose
reader registers no handler, it goes out at once with
`cutoff::RING_HANDOFF` and the module's frame counter — what the ip module
can prove on its own, a frame already in the ring may still leave. The
rp1_gem driver answers the query (bcm2712); the hosted stack's wire is its
host kernel's and does not. The primary address is always armed and
cannot be fenced. Refused frames are counted (`fenced=` on the `[ip] drop`
line) so a fence that is doing its job is visible.

This is the `fence.enforceable` capability. The ip manifest declares
`cutoff = "ring_handoff"`, the floor it can promise everywhere; the
composer raises it to `wire` from the target facts
(`tools/src/target_facts.rs`, `nic_tx_drain`) where the driver drains on
request, which is what a strict continuity profile is admitted against.
IPv6 neighbour advertisement is not part of it: the stack is IPv4-only,
so there is no IPv6 address to announce or fence.

The same surface has a second kind of provider, the **out-of-band fence
agent** (`identity.rs` §Two providers, one surface). The ip module's fence
is what a host can prove about its own emission; an agent's fence is what
another host can prove about it, by cutting the whole failure domain from
outside — power, or the fabric port. It is therefore a member of the graph
placed on another node (`protocol_surfaces.md` §Remote Channels and
Placement), and it answers the same verbs: `ADDR_ADD` takes custody of the
host owning the address and mints a token, `ADDR_FENCE` cuts, and
`ADDR_ARM` restores.

`MSG_ADDR_FENCED` follows a cut only once the actuator has reported
success **and** the fenced host's hold-up has passed — a board goes on
running from what its supply holds after the relay opens, and a
coordinator that activated a standby on the relay's word would be
activating against a host still on the wire. It carries `cutoff::WIRE`,
the agent's own fence count as the cutoff index, and the custody
generation, which is the `fence_gen` a coordinator presents on
`CMD_SC_ACTIVATE`. An actuator that does not confirm is refused
`refusal::ACTUATOR`, leaving the host's state unknown and the standby
unactivated. The reference agent is `modules/fixtures/fence_agent/`: its
actuator is a command run on its own node through the `proc` executor,
by default the rig's power backend (`fluxor rig power off` / `on`), so a
fence at the bench is the plug opening. A `platform_replicated_state`
declaration needs both providers, and the agent's `cutoff = "wire"` counts
only from a placed member.

## Transport Continuity

Contract: `modules/sdk/contracts/net/session_ctrl.rs` §Transport
continuity. Providers: `modules/foundation/ip` (`continuity.rs`, TCP),
`modules/foundation/tls` (`continuity.rs`, the record layer),
`modules/foundation/quic` (`continuity.rs`, the mux). Each answers the
same command set on a `cont_in` / `cont_out` port pair: `PAIR_PREPARE`,
`CHECKPOINT_BEGIN / NEXT / COMMIT`, `DELTA_APPLY / DELTA_ACK`,
`QUIESCE_BEGIN / STATUS`, `CUT_EXPORT / CUT_IMPORT`, `EMISSION_ARM`,
`ACTIVATE`, `RETIRE`, `ABORT`, with every reply a `MSG_SC_CONTINUITY`
record. A failover coordinator drives the lifecycle and relays checkpoint
chunks and deltas between the primary's `cont_out` and the standby's
`cont_in`; the provider owns the codec, the buffers and the emission gate.
The coordinator is a role a deployment fills rather than a module Fluxor
ships: what is published here is the surface it drives.

A **checkpoint** is a canonical record, never a memory dump: for TCP the
tuple, sequence variables, windows, congestion and RTT state, timers as
remaining durations, and the reorder buffer (`TCP_RECORD_MAX`); for TLS
the epochs, record counters, partial inbound record, retained outbound
ciphertext and the secret set sealed by the vault under a labelled key;
for QUIC the packet-number spaces, streams, flow control, CIDs
(preserved verbatim) and the sealed secrets. Secrets never cross the
port in the clear — a standby whose vault holds the same labelled key
(`security.key_wrap`) opens them. A record is chunked with CRC32 and
bound by a SHA-256 manifest; the standby validates it whole in a shadow
slot (`MAX_TCP_SHADOWS`, `MAX_TLS_SHADOWS`, quic `MAX_SHADOW_SLOTS`) and
refuses gaps, conflicting duplicates, impossible relations and unknown
layouts before anything is mutated. Only synchronised connections and
established TLS 1.3 sessions are admitted; a handshake in progress is
refused `ABORT_UNSUPPORTED_STATE`.

Two **profiles**. `PROFILE_PLANNED`: deltas are asynchronous and the cut
at `CUT_EXPORT`, taken after `QUIESCE_BEGIN` closed the receive window
and drained what was in flight, is what makes the standby exact.
`PROFILE_CRASH_CONTINUOUS`: every externally visible transition waits
for its `DELTA_ACK` — the acknowledgement the TCP peer is shown never
runs ahead of the receive horizon the standby confirmed, a data segment,
FIN, TLS record or QUIC packet is not handed to the wire before its send
delta is confirmed, and a key update is a barrier. The wait is bounded
by the peer's window, never by a queue.

**Activation** turns a validated, armed shadow into the live connection
under a strictly higher epoch and a non-zero fence generation: timers
are converted from their remaining durations with the transfer age
charged, expired ones fire on the next sweep, congestion restarts
conservatively (window capped at the initial window, recovery cleared),
and the TCP side reports the live conn id the TLS side binds to. The old
anchor's `RETIRE` drops the connection silently — no FIN, no RST, no
consumer event — and zeroizes its secrets. The peer never sees the move.

What the ip and tls modules own here is the codec, the horizons and the
local gate; committed ownership epochs, reservations
(`CMD_SC_RESERVATION_GRANT` carries a grant to the quic packet-number
space) and the out-of-band fence belong to the `session.reservation`,
`durable.rpo_zero` and `fence.enforceable` providers a graph composes,
and admission (`capability_surface.md` §Continuity Validation) refuses a
graph that lacks them.

