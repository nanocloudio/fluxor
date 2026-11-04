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
   `CMD_CONNECT_TO`, `CMD_SEND` upstream; `MSG_DATA`, `MSG_ACCEPTED`,
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
frame length. A producer writes a frame with one `channel_write`, which
commits it whole or not at all. A consumer reads a frame whole or not at
all: it peeks the header, peeks the frame once every byte of it is
buffered, and consumes it with `channel_discard`. A frame still arriving
stays on the channel until it is complete, so a frame carried over a raw
byte-stream fan is never returned short, and a read never consumes the
next frame's header. A frame larger than the consumer's buffer, or than
the channel's ring, is discarded whole, now and as the rest of it arrives,
which keeps the stream aligned. The SDK helpers
`net_read_frame`, `net_read_frame_sized` and `net_write_frame` in
`modules/sdk/runtime/net.rs` implement this; the sized reader reports a
dropped frame's length so a consumer of a reliable stream can treat it
as a lost frame and reconnect, where the plain reader logs it.

### Upstream messages (consumer → provider)

| Type | Name | Payload |
|------|------|---------|
| `0x10` | `CMD_BIND` | `[port: u16 LE]` — open a listener |
| `0x11` | `CMD_SEND` | `[conn_id: u16 LE][data…]` — send bytes on a connection |
| `0x12` | `CMD_CLOSE` | `[conn_id: u16 LE]` — tear down a connection |
| `0x13` | `CMD_CONNECT` | reserved, unsupported — every provider answers `MSG_ERROR` ENOSYS on the requester tag |
| `0x14` | `CMD_CONNECT_TO` | `[sock_type: u8][af: u8][port: u16 LE][addr…][requester_tag: u16 LE?]` |
| `0x18` | `CMD_RESEND` | `[conn_id: u16 LE][seq: u32 LE][data…]` — retained bytes again at their own sequence numbers |
| `0x19` | `CMD_DELIVERED` | `[conn_id: u16 LE][consumer_cursor: u64 LE][in_bytes: u64 LE]` (`DELIVERED_LEN`) — the consumer has consumed the connection's first `in_bytes` clear bytes and stands at its cursor (opaque to the transport) there; kept with the byte and handed to a consumer that resumes the stream after a takeover (`MSG_RESUMED`), redelivery starting at that byte |

`CMD_CONNECT_TO` carries one of three address families: `AF_INET` (4,
`addr` is 4 bytes in network order), `AF_INET6` (6, 16 bytes), or
`AF_NAME` (1, `[len: u8][name: len bytes]` — a DNS name of 1..=253 ASCII
bytes, resolved by the provider). It accepts only `SOCK_TYPE_STREAM`
(1); any other `sock_type`, a malformed name, or a family the provider
does not serve fails with EINVAL on the requester tag, and a name that
does not resolve fails with ENOENT. The trailing `requester_tag` is
optional (absent means tag 0) and is echoed back in `MSG_CONNECTED`; see
§Fan-out and filtering. See §Connecting by name for the parameter that
feeds this record.

The `data` portion of one `CMD_SEND` must not exceed `MAX_CMD_DATA`
(8192 bytes); a consumer with more bytes issues multiple `CMD_SEND`s and
the provider re-segments to MSS on the wire.

### Downstream messages (provider → consumer)

| Type | Name | Payload |
|------|------|---------|
| `0x01` | `MSG_ACCEPTED` | `[conn_id: u16 LE][local_port: u16 LE]` — inbound connection established |
| `0x02` | `MSG_DATA` | `[conn_id: u16 LE][data…]` — received bytes |
| `0x03` | `MSG_CLOSED` | `[conn_id: u16 LE][kind: u8]` — `kind` 1 (`CLOSED_PEER_FIN`): the peer finished sending, the connection is still writable and its id held; 2 (`CLOSED_GONE`): the connection is gone (reset, aborted, timed out or released) |
| `0x04` | `MSG_BOUND` | `[conn_id: u16 LE][local_port: u16 LE]` — listener ready |
| `0x05` | `MSG_CONNECTED` | `[conn_id: u16 LE][requester_tag: u16 LE]` — outbound connection established |
| `0x06` | `MSG_ERROR` | `[conn_id: u16 LE][errno: i8][requester_tag: u16 LE?]` |
| `0x07` | `MSG_RETRANSMIT` | `[conn_id: u16 LE][from_seq: u32 LE]` — send retained bytes again from `from_seq` |
| `0x08` | `MSG_ACK` | `[conn_id: u16 LE][acked_seq: u32 LE][isn: u32 LE]` — the peer has everything before `acked_seq` |
| `0x09` | `MSG_TRACE_CTX` | `[conn_id: u16 LE][trace_id: 16][parent_span_id: 8][trace_flags: u8]` |
| `0x0A` | `MSG_PEER` | `[conn_id: u16 LE][family: u8][addr: 16][port: u16 LE]` — who is at the other end, sent once before the stream's first `MSG_DATA` |
| `0x0B` | `MSG_HORIZON` | `[conn_id: u16 LE][bytes_through: u64 LE]` — the consumer's clear bytes on the wire (under a crash-continuous pair, held by the standby first); from a record layer that opts in (`tls`'s `write_horizon`) |
| `0x0C` | `MSG_RESUMED` | `[conn_id: u16 LE][consumer_cursor: u64 LE][in_bytes: u64 LE][out_bytes: u64 LE]` (`RESUMED_LEN`) — the stream was resumed here by a continuity takeover: the predecessor consumer's last `CMD_DELIVERED` cursor and byte (both 0 when none was mirrored; redelivery starts at byte `in_bytes`) and its output horizon, after `MSG_PEER` and before any data |

A stage that numbers sessions (`tls`) appends `[generation: u16 LE]` to
`MSG_ACCEPTED` and `MSG_CONNECTED` (`put_session_generation`), and a
consumer that binds work to a session (`remote_channel`) reads it back
(`session_generation`), so it can tell a connection id's current session
from a closed one's. After the generation comes `[alpn_len: u8][alpn…]`,
the application protocol the stage negotiated (`put_session_alpn` /
`session_alpn`; length 0 for none): an HTTP client reads `h2` there and
runs HTTP/2 streams over the connection, `http/1.1` or nothing and it
speaks HTTP/1.1. `tls` configures what it offers (client) and selects from
in its own preference order (server) with `alpn` — a name or a list,
`h2,http/1.1` when unset (`http/1.1` under `alpn_h1_only`). A port-less
`MSG_ACCEPTED` (a sole consumer whose bind `tls` never saw) carries
neither.

`tls` holds a dial's `MSG_CONNECTED` until the handshake completes, so a
dial that never completes one is answered as a failed connect — a tagged
`MSG_ERROR` `ECONNREFUSED` — never a `MSG_CLOSED` under an id the
requester was not told. A client whose `identity_label` is not certified
yet (and so, under `trust_issuer`, has no anchor) does not dial: its
`CMD_CONNECT_TO` is answered `EAGAIN` on the requester's tag, and the
requester's backoff dials again. `MSG_PEER`'s
`family` is `AF_INET` (the address in the first four bytes, the rest zero)
or `AF_INET6`; for a dial to a service address it names that address, not
the backend it was translated to, and a stage that relabels connection ids
re-emits it under its own.

`MSG_RETRANSMIT`, `MSG_ACK`, `CMD_RESEND` and `CMD_DELIVERED` are SDK
constants (`net_proto.rs`, with `ack_parts` / `retransmit_parts` and the
payload lengths), shared by every stage rather than private to `ip` and
`tls`: any stage that
retains its own send bytes, or defers its delivery horizon to its consumer,
speaks them, and one that does not drops them as unknown opcodes. The IP
module does not retain TCP payload for retransmission;
the consumer does, if it wants to. `MSG_ACK` lets the consumer truncate
its send buffer; `MSG_RETRANSMIT` fires on fast-retransmit or RTO and
asks the consumer to re-supply bytes from an absolute TCP sequence
number. The TLS module uses this to hold encrypted records until they
are acknowledged; see `security.md`. `MSG_ACK` carries a third field,
`[isn: u32 LE]`, the sequence number of the stream's first byte (ISS + 1),
so a consumer that counted the bytes it handed down places them in
sequence space at the first report, whatever it sent before that report
reached it. `ip` reports from the segment that moves `SND.UNA`, straight
onto an idle channel (an acknowledgement is cumulative, so a report never
takes a place in the lane's event queue); one a full channel refused is
reported again by the timer sweep, and one is always queued ahead of a
`MSG_RETRANSMIT`. The consumer answers `MSG_RETRANSMIT` with `CMD_RESEND`
(0x18, `[conn_id: u16 LE][seq: u32 LE][data…]`): bytes it already handed
down, which `ip` sends again at their own sequence numbers — the part in
`[SND.UNA, SND.NXT)`, up to one segment — rather than allocating them as
new data. `MSG_RETRANSMIT` fires on duplicate ACKs (three, or with two or
three segments outstanding one fewer than outstanding — early retransmit,
RFC 5827, since `tls`'s 4 KiB window seldom has four out), on the RTO, and
on each partial acknowledgement in recovery (RFC 6582), so a burst the peer
dropped part of comes back hole by hole. The RTO is RFC 6298's, in
milliseconds of the module's clock: SRTT and RTTVAR from Karn-filtered
samples (a segment's send to the acknowledgement covering it), RTO = SRTT +
max(G, 4·RTTVAR) with G the 50 ms sweep window, one second before any
sample and never below it, doubled on each expiry up to sixty seconds. A
lost tail waits one RTO — a second on a fast path.

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

The table behind the handles has a ceiling (`MAX_TCP_CONNS`, the id
space on the host profile) and a lazily backed body (`ip/conn_arena.rs`).
The first 512 connections live inline in module state; when they are all
taken, the allocator asks the kernel elastic region for one more
256-connection chunk and hands out its lowest slot. A chunk, once
granted, is backed until the module is torn down, so a slot number once
valid stays valid, and every bound that drives or guards an access into
the table — a consumer's `conn_id`, the timer sweep, the free-slot scan —
is the backed length, never the ceiling. A chunk the region refuses is
counted and the arrival refused, exactly as a full table refuses it; the
periodic report carries the growth as `cgrow=<chunks granted>
cdeny=<chunks refused> cslots=<records backed>`. On the embedded
profiles the inline block is the whole table.

### Fan-out and filtering

The provider has a single net_proto pair: `net_in` (commands in) and
`net_out` (messages out). When several stream consumers share it, the
config fans `net_out` to each of them and every consumer filters:

- **Inbound connections** carry `local_port` in `MSG_ACCEPTED`; each
  consumer claims only connections accepted on the port it bound.
- **Outbound connections** are claimed by `requester_tag`: a consumer
  tags its `CMD_CONNECT_TO` with its module index plus one (the
  `dev_requester_tag` encoding — the sentinel `REQUESTER_TAG_NONE` (0)
  therefore never collides with module index 0) and claims the
  `MSG_CONNECTED` or connect-phase `MSG_ERROR` echoing that tag. On a
  connect-phase failure `conn_id` is meaningless, so the failure must be
  matched on `requester_tag` alone.

A sole consumer may ignore both fields.

### Connecting by name

A connection is opened to an authority, and the authority is one fact
that flows down the stack. The connector states `example.com:443`; the
`CMD_CONNECT_TO` record carries it; `tls`, which sits between the
connector and the network and forwards the record, reads the name off
it for SNI and the certificate check; the network provider resolves it,
because resolution is the network's job and every platform has one way
to do it. Nothing is written twice, so nothing can disagree.

The parameter rule: `authority` is the only address-bearing parameter a
connector takes. It is `host[:port]` — a DNS name, a dotted quad, or a
bracketed IPv6 literal — and the port lives inside it; when omitted, the
connector's protocol default applies. A server-mode instance keeps
`port`, because a bind is not an authority. `tls.verify_hostname` is the
one override: set it when the name to verify is not the one dialled (a
proxy, or a pinned host reached by address), and the build warns when it
differs from the authority wired into that `tls` instance so the
override is a stated decision. The build refuses any other
address-bearing key on a connector, and a `u32` parameter given a string
with a dot that is not a dotted quad — a host name on an address field —
is an error, never a hash.

The wire record is `CMD_CONNECT_TO` (0x14) in the table above:
`[sock_type][af][port][addr…][tag?]`, with `AF_INET`, `AF_INET6` and
`AF_NAME`. The SDK's `Target::parse` turns an authority into the target
and its port, recognising literals as literals, and `write_connect_to`
composes the record.

Who resolves: the provider that receives the record. `linux_net` calls
the host's `getaddrinfo` on a resolver thread and keeps a 60 s positive
cache; `ip` runs a stub resolver over UDP/53 against the `resolver`
parameter when set and otherwise the nameserver DHCP handed it. In the
browser there is no stream provider at all — the wasm host answers HTTP
requests as a provider of the exchange contract (`wasm_browser_http`,
`exchange.md`), and the browser resolves the URL's host. A
provider that cannot resolve answers an `AF_NAME` target with EINVAL,
and one with no IPv6 stack answers an `AF_INET6` literal the same way;
`ip` dials an `AF_INET6` literal from an IPv6 address of the dialler's
own — a workload's own, or for the node its first armed one no workload
owns (`ENETUNREACH` with none, or on a build without IPv6). An IPv4 literal is
the only target every provider dials.

Errors are synchronous or tagged, never a timeout: a name over 253 bytes,
a malformed record, or a family the provider does not serve is EINVAL at
the connect; a name that does not resolve is ENOENT on the requester
tag; the unsupported `CMD_CONNECT` (0x13) is ENOSYS. The `ip` stub resolver
holds names whole up to the contract's 253 bytes. A misconfigured graph
fails its first dial with a reason.

TLS names each session from the record it forwards. A name becomes the
SNI extension and is matched against the certificate's dNSName entries;
a literal sends no SNI and is matched against an iPAddress SAN. A
certificate that carries only a dNSName does not verify a session dialled
by address unless `verify_hostname` says which name to expect.

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
parser handles frame boundaries. Channels also have a mailbox mode, a
single message buffer handed from producer to consumer without a copy,
which the audio pipeline uses; see `pipeline.md` for its state machine.
The network drivers and the IP module use the ring.

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
  fragmentation: a UDP payload whose packet would pass the 1500-byte link
  MTU (1472 bytes over IPv4, 1452 over IPv6) is refused with `EMSGSIZE`
  rather than truncated, split or sent oversize.
- **IPv6: TCP and UDP through the one transport** (`v6t.rs`). An IPv6
  address the stack terminates — `ip6` (up to four), a `seam_v6` address a
  director disposes `LOCAL`, or an `ADDR_ADD` with `install::FAMILY6` — is a
  local-address slot whose IPv4 word is a stand-in from 240.0.0.0/8, and
  each IPv6 peer a peer entry with a stand-in from 241.0.0.0/8; the network
  header is translated statelessly at the edge both ways (RFC 7915's map for
  TCP and UDP, the transport checksum recomputed over the other family's
  pseudo-header, a zero UDP checksum refused over IPv6). So an IPv6
  connection is the same `TcpConn` — sequence space, timers, retransmission,
  emission fence, continuity — and a datagram endpoint sees an IPv6 peer as
  itself (`MSG_DG_RX_FROM` / `CMD_DG_SEND_TO` with `af = 6`); `MSG_PEER`
  reports `AF_INET6`. Stand-ins never leave the module: an IPv4 packet
  naming 240.0.0.0/7 is dropped first. IPv6 segments at 1440 bytes (a SYN's
  MSS clamped on the way out). A peer's link-layer address comes from the
  frame that introduced it or from a neighbour advertisement answering our
  solicitation (outbound dials, imported connections); only an override
  advertisement moves it, and never the router's. `gateway6` names the
  router every IPv6 peer is reached through (unset: on-link). Neighbour
  discovery is validated as RFC 4861 §7.1 asks (hop limit 255, code 0, the
  ICMPv6 checksum, a unicast target, well-formed options, no solicited
  advertisement to a group); a packet from a multicast, loopback or
  IPv4-mapped source, or to loopback, is refused before anything answers
  it. ICMPv6 beyond neighbour discovery and echo, extension headers and
  fragments are not delivered. IPv6 is served whether or not the IPv4 stack
  holds an address. `net.policy` tables name IPv4 addresses: while any
  table judges packets, an IPv6 flow it would judge — a stream, datagram or
  echo to a workload's IPv6 address — is dropped rather than judged under
  its stand-in. The 64-bit targets carry it; the small profiles keep their
  state arena, and refuse `ip6` and `gateway6`.

### Per-tick step

Each step the IP module:

1. Reads pending frames from `frames_rx`, parses them, advances TCP/UDP
   state machines, and queues outbound frames.
2. Writes outbound frames to `frames_tx` until the channel fills.
3. Reads pending commands from `net_in` and handles them: `CMD_BIND`
   allocates a listener, `CMD_CONNECT_TO` opens an outbound socket
   (resolving a name first),
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

### Receive windows

Every TCP connection delivers into the same consumer ring (`net_out`), so
receive windows are sized against that ring. After each delivery, and
from the timer sweep for a window that backpressure closed, the module
asks the kernel how many bytes the ring can take (`IOCTL_WRITABLE`) and
computes each connection's share: an equal part of that room among the
connections that received in the current or previous 50 ms epoch, less
1/16 for `MSG_DATA` framing, capped at `MAX_RCV_WND` (4 KiB on aarch64,
where that cap keeps the sum of windows inside the 32 KiB `frames_rx`
ring; 8 KiB elsewhere). A share under 536 bytes — one default-MSS
segment — is zero rather than a sliver (receiver-side silly window
avoidance). A channel with no ring to measure (a mailbox) is judged by
writability alone: writable offers the full cap, otherwise zero.

The share decides how far the right edge of the window (`RCV.NXT +
RCV.WND`) moves forward; it never moves the edge back (RFC 9293
§3.8.6.2.2). The window advertised is the larger of the share and what
is left of the previous window once the bytes delivered since are
subtracted, so data the peer sent under an earlier, larger window is
admitted even after other connections have filled the ring. The ring
itself is guarded at delivery: a segment it cannot take is not
acknowledged, `RCV.NXT` stays put, and the window closes to zero — the
one shrink a full ring forces — until the consumer drains. A continuity
quiesce closes the window the same way. The peer resends what was
refused. When the sweep reopens a closed
window it sends a window-update ACK at once, rather than leaving the peer
to discover it through its persist timer. A retransmit that straddles
`RCV.NXT` — some of its bytes already delivered — is trimmed to its new
bytes and processed (RFC 9293 §3.10.7.4) instead of dropped whole.

The periodic report carries these on one line:
`[ip] rx cktcp=<TCP checksum failures> trim=<straddling retransmits
trimmed> wupd=<window updates sent> sharers=<receivers in the last epoch>`.

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
ends the module. (Measured on a Pi 5: a free-slot cursor scan degenerates
to a full walk per SYN as the table fills, and the 65,535-connection rung
ended the board at ~63,000 connections.)

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

On the Linux target there is ordinarily no IP module in the graph. The
`linux_net` platform module presents the same `net_in` / `net_out`
net_proto surface and bridges it to host sockets internally, so the same
consumer modules run unchanged. The Linux variant of `stacks/net.toml`
instantiates it.

A graph that needs the stack itself — the transport-continuity surfaces
checkpoint connections `ip` owns, which a host socket is not — runs `ip`
over the `linux_eth` built-in instead: an Ethernet frame driver on a Linux
interface, either an `AF_PACKET` socket bound to an existing one (with no
address of its own, in a network namespace the runtime owns) or a TAP.

### Lanes for a workload staged at runtime

A subgraph staged by a `workload` CREATE (an fmod-graph source) joins the
network through lanes of its own rather than the fanned `net_out`. Its
FLXA names the provider as an endpoint, `Net(key)`: one edge from a module
into it (commands) and one edge out of it to a module (events) per key.
Each key becomes one lane.

A workload's `wiring:` is written as a graph's: ends are `module.port`
(resolved against the module's manifest; a bare `module` is its first
output in `from:`, its first input in `to:`), and the node's network is
the platform provider a base graph names — `linux_net` (or `ip`), which
the workload does not declare among its modules. `fluxor build` gives
every module wired to it a lane of its own (FLXA endpoint kind 3), keyed
in the order the wiring first names the module, and refuses a module
that is not wired to it exactly once each way — `linux_net.net_out` into
one of its inputs, one of its outputs into `linux_net.net_in`. The
network's other ports are not a workload's to reach. So a graph's
modules and wiring move under `workloads:` unchanged, but for the
platform's own entry:

```yaml
workloads:
  - modules:
      - name: front
        type: tls
      - name: link
        type: remote_channel
    wiring:
      - from: linux_net.net_out   # the lane's events (accepts, data) into tls
        to: front.cipher_in
      - from: front.cipher_out    # tls's net commands out to its lane
        to: linux_net.net_in
      - from: front.clear_out
        to: link.transport_in
      - from: link.transport_out
        to: front.clear_in
```

| Rule | Effect |
|---|---|
| Owner | Commands run as the workload's owner: binds are lease-gated as it, and what they open is stamped with it |
| Events | Every message about something the lane opened — accepts, data, closes, connect results — goes to the lane's events channel and nowhere else; a full lane back-pressures only its own sockets |
| Isolation | A lane sends on and closes only what it opened; the node's own lanes cannot touch a workload's connections either |
| Teardown | Freeing the owner detaches its lanes and closes everything they opened |

Two providers implement lanes. On Linux, `linux_net` is the provider (the
first instance in a graph); it serves the stream surface on a lane and
refuses the datagram surface (`EOPNOTSUPP`). On bare metal, `ip` is: it
claims the provider role from the kernel's workload backend
(`workload::NET_PROVIDE`) and takes each lane change the kernel queues for
it (`NET_LANE_TAKE`) before it touches any lane, so a channel the kernel
freed and handed on is never written by the lane that held it. `ip` serves
both surfaces on a lane:

- A bind lands as the lane's owner: on every address that owner holds,
  IPv4 and IPv6 alike, when it has any, on the node's shared addresses
  otherwise, never as an owner a command names. The kernel admits it (`NET_LANE_ADMIT`) by the gate a
  built-in provider applies — refused while the owner drains or is gone,
  and refused for a port the committed plan does not lease to it.
- A port another lane listens on at an overlapping address is
  `EADDRINUSE`, so no two lanes are offered the same connections.
- A workload that holds addresses sources only from them, per family: its
  IPv4 address for IPv4 (the node's primary for an IPv4 destination
  outside its cluster prefixes), its IPv6 address for IPv6. A family it
  holds no address of is refused `ENETUNREACH`, never sourced from the
  node's or another workload's address.
- Control frames wait in an event queue per lane (`lane_events`, default
  8, at least 4) and one of the node's own (`node_events`, default 32 on
  aarch64, at least 8), each drained to its own channel: a lane that stops
  reading holds up only its own frames, so the node's own events and its
  receive path never wait on it. A lane's command intake pauses while its
  queue has fewer than two slots free, and a connection whose accept
  cannot be announced on its lane (its `MSG_ACCEPTED` and peer report) is
  refused, as by a full accept backlog.
- When a lane detaches, `ip` resets what it opened, drops frames still
  queued for its events, and cancels the dials it parked on a lookup, so a
  lane that later takes the same channels or index inherits nothing.

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

A peer's close ends the session by default: its close_notify, or the FIN
`ip` reports as MSG_CLOSED (`CLOSED_PEER_FIN`), closes it and the consumer is
told MSG_CLOSED (`CLOSED_GONE`).
With `half_close` (param 22) each ends only the peer's direction (RFC 8446
§6.1): the consumer is told once, after everything the peer sent, and may
still send until its own CMD_CLOSE sends our close_notify; records after the
peer's close_notify are ignored. A connection that is gone (`CLOSED_GONE`)
ends the session under `half_close` too.

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
| `http` | an application package | HTTP server / client |
| `dns` | `modules/foundation/dns/` | DNS resolver and authoritative server |
| `mqtt_client` | quantum | MQTT 3.1.1 client |
| `tls` | `modules/foundation/tls/` | Channel-to-channel TLS 1.3 transformer |
| `log_net` | `modules/foundation/log_net/` | Log/netconsole emitter (datagram surface) |

Each opens a channel pair to the network provider (or to TLS) in its
config wiring and exchanges contract frames. None of them call a
"socket" syscall, and none know what hardware provides the network
underneath.

### DNS64 and authoritative update

Source: `modules/foundation/dns/mod.rs`.

Both are off unless their manifest parameter is set.

**DNS64** (`dns64_prefix`, RFC 6147 / RFC 6052) is a *non-validating*
forwarding profile. The prefix is any RFC 6052 §2.2 length — /32, /40, /48,
/56, /64 or /96, no bits past it, the `u` octet zero — and the IPv4 address
is embedded around the `u` octet exactly as the NAT64 translator embeds it
(`cores/nat.rs` `nat64_embed`), so the address a client is told and the one
the translator answers for are one. A native AAAA answer is relayed as
received, except that an AAAA in the IPv4-mapped range `::ffff:0:0/96` is
treated as absent (RFC 6147 §5.1.4's mandatory exclusion) and synthesized
over. A forwarded AAAA whose answer is a complete, correlated
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
always under the well-known prefix `64:ff9b::/96`, by the translator's own
test (`nat_v4_is_global`), so a client is never told an address the
translator refuses; a network-specific prefix
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

## Network Functions: NAT, Mirrors, Chains, Attachment Tunnels, Offload

The primitives a managed traffic fabric's packet paths are built from
(an egress gateway, a service-chain director, a private-service broker
and an offload gate), as SDK cores a module includes and decision-seam
dispositions `ip` honours. Apart from the seam's own modules
(`seam_shard`, `fwd_split`, `rescue_tunnel`), no module here wires the
cores into a translator, chain hop or tunnel end — those modules are the
consumer's.

- **NAT44 / NAT64** (`cores/nat.rs`). In-place NAT44 rewrite of a source or
  destination with RFC 1624 incremental checksums — the IPv4 header, TCP and
  UDP (a zero UDP checksum stays zero, a computed zero goes as 0xFFFF), the
  ICMP query identifier, and for a returning ICMP error the embedded
  packet's header, port and checksums with the outer ICMP checksum — so a
  packet that arrived with a bad checksum still has one — and NAT64
  translation (RFC 7915) both ways into a caller buffer: headers rebuilt,
  the TCP/UDP checksum carried across by its pseudo-header difference, a
  checksum-less UDP datagram given one (never zero) or refused by policy,
  ICMP/ICMPv6 informational and error types mapped by RFC 7915's tables with
  an error's embedded packet translated too and the whole error kept within
  1280 bytes (IPv6) or 576 (IPv4), Packet Too Big / Fragmentation Needed
  mapped with RFC 1191's plateaus (no lower than 1280) under both next-hop
  MTUs, Parameter Problem pointers mapped, TTL / hop limit decremented. An
  ICMP message whose checksum does not verify is refused (`Checksum`), never
  rewritten into a valid one. RFC 6052 embedding and extraction at every
  defined length, the well-known prefix refusing non-global IPv4 (this-
  network, RFC 1918, shared, loopback, link-local, 192.0.0.0/24,
  198.18.0.0/15, multicast, reserved). Fragments, IPv4 options, IPv6
  extension headers and other protocols are refused by name (`NatWhy`).
- **Tuple arena** (`cores/tuple_arena.rs`). Endpoint-independent mapping with
  address-and-port-dependent filtering (RFC 4787), so a return packet finds
  its tuple only from the remote it was bound to; the outside port space of
  each address cut into disjoint per-shard ranges, a flow's shard the hash of
  its inside endpoint, so shards never contend; a TCP binding opens only on
  a SYN (`NotSyn` otherwise) and idles out after `tcp_idle_ms` established,
  `tcp_transitory_ms` while opening or closing (RFC 5382's 2 h 4 min and
  4 min), both FINs or an RST → TIME-WAIT, UDP idle → hold; a port held live
  or retiring is never handed out, and reuse past the horizon advances its
  allocation generation — TCP's and UDP's separately — so a stale reference
  never matches; exhaustion names its binder (`PortsLive`, `PortsRetiring`,
  `Arena`); continuity import keeps a tuple's exact outside endpoint and
  generation, and refuses a duplicate.
- **Mirror copies** (`disposition::MIRROR` 5). The packet is delivered
  locally and one copy goes to the forward port as a forward record naming
  `MIRROR` and its arguments, within `ip`'s `packet_mirror_budget` (copies a
  second, a token bucket that deep; 0, the default, mirrors nothing). A copy
  the budget or the forward port cannot take is lost — never the original,
  and never held for — counted (`mirror_lost`) and reported
  (`MSG_PKT_MIRROR_LOST` 0x68, `[pkt_id][lost_total]`). `CMD_PKT_CLONE`
  remains for a director that wants the copy held for its own disposition.
- **Forward-and-copy** (`disposition::COPY` 0x80, OR'd into `TUNNEL`, `DSR`
  or `CHAIN`). A flow a director does not deliver locally is mirrored by
  one disposition: `[pkt_id][base | COPY][base args: 6][mirror args: 6]`.
  The frame is forwarded as the base disposition says (its record names the
  base, the flag clear) and one copy goes to the forward port as a record
  naming `MIRROR` and the mirror arguments, under the same budget, lost and
  reported as a `MIRROR`'s copy is. `COPY` on any other disposition, or
  without the second block, releases the packet as an unknown disposition.
- **IPv6 at the seam** (`seam_v6`, `MSG_PKT_DECIDE6` 0x69). A director
  deciding a v6 VIP needs its packets: with `seam_v6` naming up to four
  addresses (and the seam on), every TCP or UDP
  packet to one of them is checksummed over the RFC 8200 pseudo-header and
  described as `MSG_PKT_DECIDE6` — a message of its own, so an IPv4-only
  director sees nothing new — and held like an IPv4 one. Extension headers,
  fragments and other protocols are refused before the seam (`v6_refused`).
  The stack answers neighbour solicitation (a solicited, override
  advertisement with its MAC) and echo for those addresses. `TUNNEL`, `DSR`,
  `CHAIN` and forward-and-copy forward the frame whole; `REJECT` answers with
  an IPv6 RST or ICMPv6 port unreachable (quoting within the 1280-byte
  minimum MTU); `LOCAL` and `MIRROR` deliver a TCP or UDP packet to the
  stack's own transport (the seam address is a local IPv6 address,
  `v6t.rs`); anything else they release counted (`v6_no_local`).
- **RSS shards** (`seam_shard`). Up to four director shards behind one
  seam: each decision record goes to the shard a symmetric hash of its
  canonical tuple names — both directions of a flow, every packet of it,
  one shard, the software equivalent of a NIC's symmetric receive-side
  hash — its `rx_queue` byte set to the shard; `ip`'s later word on a
  packet (`CLONED`, `EXPIRED`, `MIRROR_LOST`) goes to the shard given it,
  also after that shard disposed of it, and a clone is the same shard's
  packet. The shards' dispositions merge back whole, the shards served in
  turn; one for a packet the shard was not given, or has already disposed
  of, is dropped and counted (`foreign`). A shard with no room holds the
  decision stream behind it, so order is kept and the back pressure
  reaches `ip`'s hold, whose deadline bounds it. A record longer than any
  the seam carries is skipped whole and counted (`oversize`).
- **The forward port shared** (`fwd_split`). The seam's forward records,
  split by disposition (COPY cleared) onto up to four frame-level modules
  (a chain hop, an attachment tunnel end, a rescue tunnel), whole and in
  order, back pressure reaching `ip`; a record no output names, or longer
  than an output's buffer, is dropped and counted.
- **The ingress cell's rescue tunnel** (`rescue_tunnel`,
  `cores/rescue_tunnel.rs`). A director that finds a flow's anchor on
  another host disposes `TUNNEL` `[anchor_id][flow_epoch]`; the ingress end
  seals the IP packet whole with the service, route generation, flow epoch,
  anchor and ingress host under the cell's key and a per-ingress-host
  sequence (HMAC-SHA256, 64-packet window) into UDP 4791 to the anchor's
  host over `ip`'s datagram surface (IPv4 or IPv6 fabric); the anchor end
  opens it only under the key, inside the window, for its service and an
  anchor it serves, and hands the inner packet (IPv4 or IPv6, its own
  length the header's) to its own `ip` as a frame (`frames_out` merged into
  `ip.frames_rx`). The header's interface and queue fields are 0: a forward
  record does not carry them. The ingress host's sequence starts at its
  wall-clock time (milliseconds, shifted left 20 bits), so a restarted
  ingress host carries on above its last run; without a real-time clock it
  starts at 1 and the anchor refuses it after a restart. The sealed
  datagram is the packet plus 70 bytes and `ip` neither fragments it nor
  sends more than one frame, so the fabric's frame must exceed the
  service's by that much (a datagram `ip` refuses is counted,
  `send_refused`).
  The cell's key is a param, or (`key_label`) an HMAC-SHA256 key
  provisioned in each host's vault, every tag the vault's and the key never
  in the module; the core takes the MAC as a function (`rt_seal_mac` /
  `rt_open_mac`), byte-identical to the keyed form. The anchor's host
  answers the client itself; the ingress host sends the client nothing for
  a tunnelled flow, only sealed UDP 4791 to the anchor, and a datagram that
  fails its tag or its window is refused and counted by reason.
- **A frame-level module beside `ip` on one NIC.** A chain hop or tunnel
  end that writes whole Ethernet frames wires its output to the NIC's
  `frames_tx` beside `ip.frames_tx`. That fan-in is the kernel's `_merge`,
  and since `EthernetFrame` edges carry `[len: u16 LE][frame]` the wiring
  gives it `FRAME_KIND_ETH`: it peeks each lane's length and moves one
  whole frame at a time, never one its output cannot hold, so sharing a
  NIC needs no module of its own. A fan into a port with no manifest of its
  own (the NIC, stdout) takes its framing from the producers only when every
  one that declares a framing declares the same (`agreed_frame_kind`);
  mixed producers — a `NetProto` port and an `OctetStream` one merged into
  stdout — make a byte fan that keeps each write whole, where a framed fan
  would read the stream as `NetProto` headers and stall for everyone. A frame-level module receives through the seam (its frames are
  forwarded to it), not through a tee of `frames_rx`, which would hand
  `ip` and it every frame.
- **Service chains** (`disposition::CHAIN` 6, `cores/chain_encap.rs`). The
  disposition hands the whole frame to the forward port for a chain hop; the
  encapsulation the hop writes names the chain, the generation the flow was
  pinned under, the stage, the pinned instance, the direction and the flow
  in canonical order (both directions one key), with a hop budget. Forward
  walks the stages up, reverse walks the same instances down; a hop refuses
  a header for another chain, generation, stage or instance — a fail-closed
  drop, never a re-selection.
- **Attachment tunnel** (`cores/attach_tunnel.rs`). A packet between a
  consumer's attachment anchor and a producer carries the attachment's
  context (consumer tenant, attachment id and generation, flow epoch) under
  an HMAC-SHA256 tag with the attachment's tunnel key — a vault DERIVE under
  the attachment and generation, so a revoked attachment's next generation
  is another key — and a 64-packet anti-replay window (RFC 4303 §3.4.3) per
  direction; one key serves both, so a window refuses the other direction's
  packets (one reflected back at its sender) before they touch it. The
  producer takes the context from the verified header alone. The tag may be
  made where the key is: `at_seal_mac` / `at_open_mac` take the MAC as a
  function (a vault `HMAC_SHA256` slot's `SIGN`), byte-identical to
  `at_seal` / `at_open` under the key.
- **Offload** (`contracts/net/offload.rs`). What a hardware flow-decision
  provider says and is told: its attested `(generation, digest)` and
  capabilities, each decision against the seam's `pkt_id` so the director
  can decide the same packet and compare, its counters, and the mode
  (off/shadow/active) the director sets. The gate that decides whether to
  believe it is the director's. Contract only: no provider exists; one
  **needs hardware**.

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
An IPv6 address (`ADDR_ADD` with `install::FAMILY6`) is armed, fenced and
removed by the same verbs and token: armed it answers neighbour
solicitation, sources packets and is announced by an unsolicited override
advertisement to all nodes (RFC 4861 §7.2.6, a moving VIP's new owner);
fenced it does none of these — the gate in `send_frame` covers IPv6 frames
by their source, and an advertisement by its target.

**The VIP authority's token** (`identity.rs` §The VIP authority's token). With `arm_authority` set, an install is disarmed
whatever it asks, and `ADDR_ARM` must carry the authority's emission token
after its install token (`[auth_len u16][auth]`). `ip` does not parse it: it
asks the authority it wires (`auth_req` out[7], `MSG_ARM_AUTH_CHECK` 0x7A
with the install generation and this host's boot incarnation) and arms only
on an accepting `ARM_AUTH_VERDICT` (0x7B, matched by address, generation and
the token's digest on `auth_rsp` in[5]). A refusal is `MSG_ADDR_REFUSED` with
`0x80 | code`; no token is `refusal::NO_AUTHORITY`; no verdict within
`ARM_AUTH_WAIT_MS` is `refusal::AUTHORITY`. Unwired, nothing arms. The
token is held nowhere and does not survive a restart. Per flow, the same
holds one level up: a moved connection's `ACTIVATE` emits only on the
authority's verdict on its per-flow token (`transport_continuity`,
`quic_continuity`).

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
`ACTIVATE`, `RETIRE`, `ABORT` (`CMD_SC_PAIR_PREPARE` 0x7A through
`CMD_SC_ABORT` 0x87), with every reply a `MSG_SC_CONTINUITY` (0x9A) record;
`CMD_SC_CUSTODY` (0x8A, `tls` and `quic`), `CMD_SC_RESERVATION_GRANT`
(0x88, `quic`) and `CMD_SC_TOMBSTONE` (0x89, `ip`) are answered where they
apply. A failover coordinator drives the lifecycle and relays checkpoint
chunks and deltas between the primary's `cont_out` and the standby's
`cont_in`; the provider owns the codec, the buffers and the emission gate.
The coordinator is a role a deployment fills rather than a module Fluxor
ships: what is published here is the surface it drives.

A **checkpoint** is a canonical record, never a memory dump: for TCP the
tuple, sequence variables, windows, congestion and RTT state, timers as
remaining durations, and the reorder buffer (`TCP_RECORD_MAX`); for TLS
the epochs, record counters, partial inbound record, retained outbound
ciphertext and the secret set sealed by the vault under the flow's
sealing key; for QUIC the packet-number spaces, streams, flow control, CIDs
(preserved verbatim) and the sealed secrets. Secrets never cross the
port in the clear. `tls` derives each flow's sealing key in its vault from a
continuity master (`tls-continuity-master`, a KDF key) for that flow and
ownership epoch, and a standby opens the secret set when its vault holds that
key: one derived from the same master (a deployment that distributes the
master), or — with no shared master — one moved to it by custody transfer
(`CMD_SC_CUSTODY`: the standby's vault attests a fresh recipient with
`ATTEST_KEY` over the transfer's challenge, signed by its custody identity
`tls-custody`; the primary's vault checks the evidence and its signature and
wraps the key to that recipient, bound to the composition it attests,
`KEY_WRAP`; the standby's vault unwraps it, `KEY_UNWRAP`). The key is in no
frame: what crosses is evidence and an `FXKW` blob only that recipient, in
that composition, opens. A CT_TLS record carries the epochs its sealed set
is at beside the record's own: a record up to 16 KeyUpdates past its seal
derives the secrets forward at import (RFC 8446 §7.2), as the primary
derived them, so a mirror never needs a newer secret sealed for it. A
record is chunked with CRC32 and bound by a SHA-256 manifest; the standby validates it whole in a shadow
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
by the peer's window, never by a queue, and by time: a horizon the standby
has not confirmed within `CONT_HORIZON_MS` (two seconds of wall clock) ends
the pair, the coordinator told before what the horizon held goes to the
peer. `tls` counts that budget in milliseconds, not steps — how many steps
a second holds depends on the graph's tick and load, and a budget in steps
would shrink as the scheduler sped up and abandon a healthy cross-host
pair whose mirror link is reconnecting. `quic` counts its strict horizon the
same way (`CONT_HORIZON_MS`, 2000 ms of `dev_millis`). Under it `tls` opens an inbound
record before mirroring it: its RECORD_IN carries the record's inner type
and its plaintext — a whole record's (2^14) on aarch64, up to 512 bytes on
the small targets (`[type][len u16][plain]` after the partial record; type
0xFF when not carried) — and the plaintext is held
undelivered until the delta is acknowledged. What the clear-side consumer
has consumed goes out as `DELTA_TLS_DELIVERED` (0x81, `[consumed u64]
[consumer_cursor u64][cursor_at u64]`): with the `tls` parameter
`delivery_ack` the consumer says so with `CMD_DELIVERED` (0x19, exactly
`[conn_id][consumer_cursor u64][in_bytes u64]`: it has consumed the
stream's first `in_bytes` clear bytes and stands at that cursor of its own
there), otherwise a delivery handed up counts as consumed. `tls` counts as
consumed only the records whose plaintext ends at or before `in_bytes` —
an acknowledgement still in flight while more records are handed up covers
none of them — and keeps the cursor with its byte (`cursor_at`). The cursor
is opaque to the transport: CT_TLS carries the latest with its byte and
the clear bytes of the consumed records (`[consumer_cursor:8][cursor_at:8]
[in_bytes:8]` after `out_bytes`), a strict shadow keeps the latest
mirrored, and the provider core carries them as `TsState::consumer_cursor`
/ `cursor_at` / `in_bytes` (the `DeliveryAck` delta `[cursor][consumer_cursor]
[cursor_at]`). At ACTIVATE the standby's `tls` tells its consumer
`MSG_RESUMED` (0x0C, `[conn_id][consumer_cursor u64][in_bytes u64]
[out_bytes u64]`, `out_bytes` in `MSG_HORIZON`'s numbering) after the
stream's `MSG_PEER` and before any of its data, and redelivers from exactly
byte `in_bytes`: the first delivery it holds is trimmed by what of it was
consumed, so an acknowledgement inside a record resumes inside it. The
consumer continues its predecessor's cursor and byte count exactly, also
after a crash with an acknowledgement in flight. While a strict pair's
consumer acknowledges, the primary opens the next record only while the
unconsumed ones with it stay fewer than the standby's eight and within its
`TCS_REDELIVER_MAX`; otherwise the record waits in the receive buffer and
the back-pressure reaches the TCP window. A consumer that cannot free room
(one message of its own spanning more records) is not waited on for ever:
after `CONT_HORIZON_MS` with no consumption the pair is abandoned and the
connection goes on unmirrored, counted as `redeliver_cap_abandoned`. A strict pair's relayed
`CONTINUITY{CHECKPOINT_COMMITTED}` also ends a quiesce — at `ip` the window
reopens with a window update — since from there the horizons, not a closed
window, keep the standby exact.

**A moved flow is never reset.** A segment for a tuple `ip` holds no
connection for is normally answered with RST. It is dropped silently
instead when the tuple is held as a shadow (the connection is arriving),
when `RETIRE` dropped it within the last five seconds (it has left), or
when an anchor has installed a tombstone for it: `CMD_SC_TOMBSTONE` (0x89,
`[flow_id][epoch][ttl_ms u32]`, at most 120 s), for a flow this host never
held but may be sent a stray segment of. A tombstone is answered
`CONTINUITY{RETIRED}`; with every slot holding a live one it is refused
`STATUS_NO_CAPACITY`, never evicted early. The peer's retransmission finds
the connection wherever it now lives.

**Activation** turns a validated, armed shadow into the live connection
under a strictly higher epoch and a non-zero fence generation: timers
are converted from their remaining durations with the transfer age
charged, expired ones fire on the next sweep, congestion restarts
conservatively (window capped at the initial window, recovery cleared),
and the TCP side reports the live conn id the TLS side binds to. `ip` keeps
a record of each activation — flow, epoch, connection slot and initial send
sequence — on the shadow slot it freed, until that slot is prepared again:
an `ABORT` naming the flow at the epoch it activated under, while the
connection in the slot is still the one activated, resets it (an RST to the
peer, its neighbour unpinned, the slot freed; `ABORTED` with `STATUS_OK`),
and any other `ABORT` for the flow is answered `STATUS_UNKNOWN_SESSION`
with nothing touched. A TCP record lands only on an address of the owner
it names (0 names none and takes the address's owner); another owner's is
refused `STATUS_CORRUPT`. The primary's
`RETIRE` drops the connection silently — no FIN, no RST, no
consumer event — and zeroizes its secrets. The peer never sees the move.

What the ip and tls modules own here is the codec, the horizons and the
local gate; committed ownership epochs, reservations
(`CMD_SC_RESERVATION_GRANT` carries a grant to the quic packet-number
space) and the out-of-band fence belong to the `session.reservation`,
`durable.rpo_zero` and `fence.enforceable` providers a graph composes,
and admission (`capability_surface.md` §Continuity Validation) refuses a
graph that lacks them.

### The anchor surface: `TRANSPORT_CONTINUITY`

Contract: `modules/sdk/contracts/net/transport_continuity.rs`. Provider:
`modules/sdk/cores/transport_continuity.rs` (`TcProvider`). This is the
single-flow surface an anchor outside the graph drives — one end of a
primary/standby pair per host, on the `tc_ctl` / `tc_evt` port pair —
rather than a coordinator speaking the per-layer surface above, and it
differs from that one in one deliberate way: a connection's TCP and TLS
halves are ONE canonical record (`TsState`, magic `WHTC`), so every mirror
delta is one atomic transition of both and "the standby holds the primary's
state" is a byte comparison. The bytes — record, chunks (`WHCC`), deltas
(`WHMD`), the provider frames and the cut — are fixed, and the canonical
encoding of a reference state is pinned by its SHA-256
(`tools/src/transport_continuity.rs`), so every implementation of the codec
is held to the same bytes. Every decoder is strict past
its digest: a version byte other than `TS_VERSION` / `MD_VERSION` (1), a
reserved bit or byte set, a length past its bound or a trailing byte is
refused by name (`CkptError`), so a state has exactly one encoding.

**The record** is sized to TLS 1.3's record limit, so a crash-continuous
pair over a stock peer keeps its protection for every record the peer may
send: a delivery holds a record's whole plaintext (2^14, `TS_DELIV_BYTES`,
eight at most), the receive buffer a whole protected record (16 704,
`TS_RECV_MAX`), the send buffer 32 KiB (`TS_SEND_MAX`, tiled by at most 32
outbound records), beside four out-of-order segments of up to 512 bytes;
an encoded checkpoint is at most 192 KiB (`TS_CKPT_MAX`). The header's flags
say which end opened the connection (`TS_FLAG_CLIENT`): a client session's
`client_*` is this host and `service_*` the remote server. An IPv4 address
is the first four bytes of its sixteen, the other twelve zero. Secrets
travel only as vault references, and the record holds the answer a peer's
KeyUpdate asked for (`key_update_owed`).

**Timers.** Beside the retransmission interval (`rto_ms`) and the idle
period (`idle_ms`) the record carries what remains of every timer the
connection runs — the retransmission timer, the idle close, the persist
timer (0 from `ip`, which leaves zero-window probing to its peer), the
CLOSE-WAIT bound, the CLOSING / LAST-ACK bound and TIME-WAIT — each 0 when
disarmed and at least `TS_TIMER_DUE` (1 ms: due) when armed, never past
`TS_TIMER_MAX_MS` (an hour), and armed only in the states that run it
(`ts_validate`). The transitions keep them as a stack does (`md_apply`):
data out starts the retransmission timer, an acknowledgement of new data
restarts or stops it (RFC 6298 §5), a payload byte restarts the idle close,
a state change stops what the new state does not run, and `ip`'s TIMERS at
each state change (`DELTA_TCP_TIMERS`, with six remainders) is a `Timers`
delta that sets the block — held by the bridge while the record has not yet
reached that state (the peer's FIN deferred behind the bytes before it).
A standby records when each remainder was current — its checkpoint's commit,
or the delta that last set it (`md_timers_set`) — and charges each the time
since before it imports the record (`ts_age_timers`); `ip` charges the rest
up to activation and fires an expired timer once, on its first sweep. So a
takeover resumes an RTO, an idle close, CLOSE-WAIT's FIN, LAST-ACK's give-up
and TIME-WAIT's end at what remained of them, late by at most the mirror's
latency — never restarted, never a whole interval late. A planned cut
compares the connection it re-exports with its checkpoint apart from the
remainders, which run down with the clock.

**The flow's end.** A connection that ends is no loss of its pairing.
`ip` tells the provider before it lets a mirrored connection go:
`DELTA_TCP_RESET` for a reset — the peer's, accepted on RFC 5961's rules in
every synchronised state, or ours, which it holds at the send horizon until
the standby has it, exactly as a FIN (an abortive `CMD_CLOSE`,
`net_proto::CLOSE_ABORT`, and a lane torn down) — and `DELTA_TCP_CLOSED` for
a completed close (LAST-ACK acknowledged, TIME-WAIT over, the closing bound
spent); with no room on `cont_out` the slot stays latched until there is.
`tls` ends a paired session that ends with its connection with
`CONTINUITY{ENDED}` (`CR_ENDED`; `END_RESET` for its consumer's abortive
close), not an abort. A reset is the `Reset` delta, after which the record
is terminal (`TsTcp::Reset`: it applies nothing more and never encodes). The
primary reports `tc_evt::ENDED` `[why][dir]` (`tc_end`) — ours once the
standby acknowledged the delta — and stops its pairing without an `ABORT`
STATUS; the standby that applies the `Reset` lets its `ip` shadow go, keeps
the flow's tombstone there (a straggler is dropped, never answered), reports
`ENDED` and refuses EMISSION_ARM, ACTIVATE and CUT_IMPORT with
`tc_end::REFUSED`; RETIRE or ABORT then lets either slot go. The halves
reach the provider on two ports, `ip`'s read first, so the flow's end can
overtake a `tls` delta sent before it — the record `tls` sealed just before
its consumer's abortive close, held at the horizon and never written. A
`tls` delta read once the record holds the end (our reset awaiting the
standby, the peer's reset, a completed close) is taken in its number and
not applied, and a RECORD_OUT waiting on a full outbound table is taken
then too: the end is reported as it is, never as a lost pairing. (`ip`'s
own stream is ordered, and its FIN cannot pass the records before it: `tls`
closes only after every record, and `ip` gates one transition at a
time.) A layer that
abandons its pairing names why — `ABORT_TXREC_CAP` (the record ceiling),
`ABORT_REDELIVER_CAP` (the redelivery caps), `ABORT_HORIZON_BUDGET` (an
unanswered horizon), `ABORT_MIRROR_LOST` — and the STATUS that ends the
pairing (`tcs_why::MIRROR | tcs_lost::LAYER`) carries the layer in its
value's second byte and the reason in the first.

**Chunks.** CHECKPOINT_BEGIN sends the encoded record as `WHCC` chunks of
16 KiB (`CKPT_CHUNK_PAYLOAD`, at most `CKPT_MAX_CHUNKS`), each naming the
checkpoint (its id, the flow, its epoch and mirror generation, the total
length) and carrying a running SHA-256 chain seeded under the domain
`wh-ckpt` with that identity. The standby verifies order and chain as they
arrive (`CkptVerifier`) and assembles into an inactive buffer, publishing
into its shadow only a whole record that decodes, validates and names the
identity its chunks named (`CkptAssembler`). A retry with the same bytes is
a duplicate; other bytes under an index already used, a broken chain or a
gap discard the assembly; a chunk of an older checkpoint than the last one
assembled is stale and ignored. Chunk arithmetic is shifts and masks
(`CKPT_CHUNK_SHIFT`): no division by a runtime value, so it links in a PIC
module on a core without a divide instruction.

**Deltas.** Each transition is a `WHMD` delta — its kind, the flow, epoch,
mirror generation and base checkpoint, a sequence number (1 after the
checkpoint), the previous delta's digest (the checkpoint's final chain
before the first) and a payload of up to 17 KiB (`MD_PAYLOAD_MAX`: a whole
protected record, or a record's whole plaintext, and their fields) — under a
SHA-256 digest with the domain `wh-delta`. `md_apply` is the deterministic
transition, applied through a scratch copy so a state changes only when the
result validates as a whole connection; `MdOrder` admits the next delta at
the standby, recognises a byte-identical retry within the last 32
(`MD_DUP_WINDOW`) and refuses a gap, a conflicting duplicate or a newer
history, which needs a full checkpoint. An inbound `KeyUpdate` ends
`[requested u8]`: the peer asked for ours, and the record owes the answer
until our own write rotation, through any later update that asks for none
(RFC 8446 §4.6.3).

**Pairing.** `PAIR_PREPARE` carries the null handle and `TcPair`, 47 bytes:
`[flow_id 16][flow_epoch u32][role u8][mode u8][transport u8]
[mirror_generation u64][service_id 16]`, each enum refused outside its
values. A primary pairs a connection it holds; a standby reserves an empty,
non-emitting shadow; the STATUS answer carries the handle it issues.

Operations arrive as `[op][len][payload]` frames carrying a
generation-checked handle the provider issued at `PAIR_PREPARE`:
`CHECKPOINT_BEGIN / NEXT / COMMIT`, `DELTA_APPLY / DELTA_ACK`,
`QUIESCE_BEGIN / STATUS`, `CUT_EXPORT / CUT_IMPORT`, `EMISSION_ARM`,
`ACTIVATE`, `RETIRE`, `ABORT`, `EMISSION_DISABLE` (the local
emission-disable hook; its STATUS value is the custody generation of the
cutoff) and `TOMBSTONE` (migrated-flow reset suppression, null handle),
numbered 2–16 in that order after `PAIR_PREPARE`'s 1; the custody
operations (17–19) and
`RESERVATION_GRANT` (20, QUIC only) follow below. Events go back as
`STATUS`, `CHUNK`, `DELTA`, `APPLIED`, `REJECTED`, `HORIZON`, `CUT` and
`CUSTODY` (0x81–0x88). A handle the provider no longer holds is refused
`STALE_HANDLE` before anything is mutated. A frame is at most
`TC_FRAME_MAX` bytes: a handle and a whole delta or chunk.

The provider is a pure core over two things it is handed. `TcRecords` is
the record layer over the key vault: it seals, opens, derives a KeyUpdate
in-vault and destroys retired epochs, and the record names secrets only by
`TsVaultRef`, so no field of any frame can carry a key. `TcTokenVerifier`
is the takeover authority's check of the per-flow emission token:
ACTIVATE refuses an unarmed shadow, a zero fence generation and an epoch
that is not strictly higher itself, then rebuilds the 48-byte token
(`TcFlowToken`, the ownership directory's token layout) from the command and
its own anchor id and enables emission only if the verifier accepts it.
Fluxor carries no authority's code: a host wires the provider to the
authority it trusts (the ownership directory's token check over its
replicated flow state and group seed). A standby derives a KeyUpdate's
secret in its vault before it applies the delta, and destroys it again if
the transition is refused.

Under `CrashContinuous` the gate (`MdGate`, a bounded journal of
`TC_GATE_J` unacknowledged deltas) holds the exposed ACK at the standby's
acknowledged RCV.NXT, emission at its acknowledged send end, deliveries
at its acknowledged delivery id and sealing at its installed write epoch
(the KeyUpdate barrier); a full journal closes the window and the
producer waits for credits. A delta is encoded before its transition is applied, so a
transition that could not be sent never changes the primary. A flow
`RETIRE` drops leaves a tombstone, so a late segment is dropped silently
instead of reset.

The core owns the state it checkpoints: a host feeds it segments and
records. It does not move keys between vaults or carry QUIC; the
`CUSTODY_ATTEST` / `CUSTODY_WRAP` / `CUSTODY_UNWRAP` operations (17–19, event
`CUSTODY` 0x88, `tc_custody`, `VAULT_TRANSFER`) are the module's below, over
`tls`'s vault. It reports exactly what it enforces
(`TC_PROVIDER_CAPS`: the TCP and TLS 1.3 codecs, the horizon gate,
import/arm/activate, emission disable, reset suppression) and nothing it
does not; `tc_cap::ALL` refuses a report with an unknown bit. The provider
is large — per flow slot a record, an assembler and the early-segment
buffer, plus a scratch state, a shadow and one encoded record — and a host
holds it in static state.

### `TRANSPORT_CONTINUITY` over `ip` and `tls`

Module: `modules/foundation/transport_continuity` (`TcStack`, in
`stack.rs`). The same surface, answered for a connection a graph's own
`ip` and `tls` hold rather than for state of the provider's own: the two
continuity surfaces relate as halves and whole. An anchor's operations
become per-layer commands on each module's `cont_in` / `cont_out` (wired
`ip.cont_out -> tc.ip_cont`, `tc.ip_ctl -> ip.cont_in`, and the same for
`tls`), and the canonical record is **composed** from the FXTC and CT_TLS
records the primary's modules export at the cut and **decomposed** into the
two the standby's import. No half's state is kept twice: the module holds a
flow's record only while it moves.

The map, field by field, is at the head of `stack.rs`. What it rests on:

- **Identity.** A flow is named by `ip`'s tuple identity (`[local_ip]
  [remote_ip][local_port][remote_port][0;4]`) on both hosts — what survives
  a VIP's connection moving — and `tls`'s by the connection id `ip` reports
  in a primary's `CR_PAIR_PREPARED` (`session_ctrl.rs`).
- **Send bytes.** `ip` holds none; `tls` retains the ciphertext it handed
  down, so `send[SND.UNA..SND.NXT)` and the outbound records tiling it come
  from `tls`'s retransmit window.
- **Keys.** The secret set stays sealed by `tls`'s vault under the flow's
  sealing key, bound by AAD to the session, the ownership epoch and the two
  epochs it was sealed at, the record sequences at the seal inside it as
  floors (in the CT_TLS record): a record may resume past them — a
  crash-continuous standby's, moved on by deltas, KeyUpdates included — and
  is refused below them. It travels as the *wrapped continuity object* —
  with the sealed epochs and the session identity the record names only by digest
  (ALPN, SNI, exporter context, peer-auth profile, and the peer block: the
  transport peer, a client session's requester tag and the peer identity) —
  on a custody path of its
  own (`key_out` / `key_in`); the record's `wrapped_digest` and vault
  references name it, and a standby holds the keys exactly when it holds
  that object and its vault the flow's sealing key.
- **Custody.** `CUSTODY_ATTEST` (standby, `[challenge]`) has its `tls`
  attest a fresh recipient key and answers `CUSTODY{EVIDENCE}`;
  `CUSTODY_WRAP` (primary, `[challenge][evidence]`) checks the evidence's
  shape and challenge (`TcCustodyEvidence::check`), asks the authority
  (`auth_req` `0xC4` `[flow][epoch][challenge][evidence]`, verdict `0xC5`
  `[flow][sha256(evidence)][verdict]`) and only on its verdict has `tls`'s
  vault verify the signature and wrap the flow's key to the recipient,
  answering `CUSTODY{WRAPPED}`; `CUSTODY_UNWRAP` (standby, once the wrapped
  object names the session) has `tls`'s vault unwrap it, kept for the flow
  until its shadow has imported with it. Whether the signer is the host the
  transfer was decided for is the authority's question — Fluxor carries no
  authority's code, as with the token verifier. Refusals are by name
  (`tc_custody::why`; `UNAUTHORIZED` with the authority's code).
- **Authority.** ACTIVATE's fail-closed checks are the core's; the token
  this module rebuilds for its own anchor goes to whatever authority the
  graph wires (`auth_req` / `auth_rsp`), and only its verdict activates.
  Unwired, nothing activates.
- **Every composition is decomposed again** and must give back what the
  modules exported; a state that would not is refused, by name
  (`tcs_why`), never moved approximately.

In: both roles' PAIR_PREPARE; the planned cut — QUIESCE, a checkpoint taken
once quiescent, CUT_EXPORT re-exporting both halves and holding only if
nothing moved; the standby's whole import (chunks, publish, ordered deltas
into the shadow, CUT_IMPORT, EMISSION_ARM importing both halves into silent
per-layer shadows); ACTIVATE (`ip` first, then `tls` bound to the
connection `ip` names; if `tls` refuses or does not answer after `ip` took
the connection, `ip` resets it with an ABORT at the new epoch and `tls`
lets go of its shadow, so no connection runs on unserved and the flow is no
longer armed); EMISSION_DISABLE, as the per-layer RETIRE of both
halves — `ip` holds nothing it could emit for the flow after it, and the
STATUS value is the custody generation of the cutoff; RETIRE; ABORT; and
`TOMBSTONE`, which is `ip`'s `CMD_SC_TOMBSTONE` (§A moved flow is never
reset, above).

Crash continuity: a `CrashContinuous` primary pairs both halves strict. Its
checkpoint is taken quiesced, then each half is told its checkpoint is held
— which turns its mirror on and ends its quiesce — and from then on each
per-layer delta becomes deltas on the primary's stream: `tls`'s
RECV_BYTES the `RxSegment` of what it holds past the record's receive buffer, its
RECORD_IN (with the plaintext) an `RxRecord`, its consumption a
`DeliveryAck`, its RECORD_OUT a `TxRecord`, its KEY_UPDATE a `KeyUpdate`
naming the next secret by reference into the wrapped object (none is sent;
the standby's `tls` derives it at import, and a write rotation stays `tls`'s
barrier until the standby holds it); `ip`'s ACKED a `PeerAck` and its
TIMERS a `Timers`, while `ip`'s RECV and SEND carry no bytes and wait on the
receive and emission horizons. Each delta is applied to the flow's record
and journaled in the horizon gate (`MdGate`, 32 deep), and a half's delta is
acknowledged to that half only when the gate covers it — so the ACK `ip`
shows, the segment it sends, the delivery `tls` makes and the record it
writes each wait for the standby's `DELTA_ACK` (answered `HORIZON`). The
standby applies the stream into its shadow and, after a crash, arms both
halves from it alone, its `ip` counting the whole send buffer sent so its RTO
resends what the peer never acknowledged. A transition the stream cannot
carry (KeyUpdates past what `tls` derives forward, plaintext `tls` did not
carry, a per-layer delta that contradicts the record, a gap, a half ending
its own pairing) ends the pairing — both halves ABORTed, an unsolicited
STATUS of op `ABORT` with reason `0x80 | tcs_lost` — and the connection runs
on unprotected.

A full table is not such a transition: it holds. Every fixed table or
buffer of the record a delta fills is one the halves keep their own within —
`session_ctrl`'s strict bounds (`STRICT_TX_RECORDS` 32 outbound records,
`STRICT_SEND_BYTES`, `STRICT_RECV_BYTES`, `STRICT_OOO_SEGS` ×
`STRICT_OOO_SEG`, `STRICT_DELIVERY_BYTES`), which the provider asserts equal
to the record's `TS_*` and `tls` and `ip` assert their own buffers within:

- `tls` holds its next outbound record while `STRICT_TX_RECORDS` records
  stand written-or-held and not wholly acknowledged by the peer's transport
  (its retransmit window since SND.UNA, and its horizon hold), the clear side
  waiting behind it; `ip`'s acknowledgement, sliding the window, releases it.
  A producer of many small records — MQTT acknowledgements pipelined faster
  than the peer acknowledges them — waits there instead of losing the pair.
  A peer that acknowledges nothing for `CONT_HORIZON_MS` while the ceiling
  holds has the pair abandoned (`[tls] continuity record ceiling held with
  no acknowledgement; mirror abandoned`, metric `txrec_cap_abandoned`), as
  the redelivery caps are.
- `tls` opens the next inbound record only once the consumption before it is
  mirrored, with `delivery_ack` or without it (without it a delivery is
  consumed when handed up), so the standby holds no more deliveries than the
  caps.
- The provider takes a half's next frame only while the gate has credits
  for what one frame becomes (`TCS_FRAME_DELTAS`, 2), the half's queue of
  deltas awaiting their horizon has room (`TCS_PEND`) and the anchor's event
  queue has room for them (`TCS_FRAME_EVT`); a `tls` record out only while
  the record's outbound table and send buffer have room — `ip`'s
  acknowledgement, arriving on the other port, frees it. A frame not taken
  stays on its port (`TcStack::layer_room`, counted `layer_holds`), and the
  half's own horizons and budgets carry the wait to the connection. The full
  journal, half queue and event queue keep their name (`tcs_lost::FULL`)
  only as a defensive invariant.
- `ip` offers a peer acknowledgement or a timer change its `cont_out`
  refused again each step (both cumulative), so the record never stays
  behind what the peer acknowledged.
- `tls` measures its `cont_out` ring at `module_new` and refuses a strict
  PAIR_PREPARE (`STATUS_NO_CAPACITY`, logged) when it holds less than a
  strict mirror may leave on it (`CONT_OUT_NEED`: `CONT_OUT_BUDGET`, one
  `CMD_SEND`'s held records and an owed KeyUpdate answer — within the 64 KiB
  the manifest asks for).

A bound reached anyway is named: `tcs_lost::BOUNDS` (reason `0x86`), its
STATUS value the delta's kind and the record's tables as they stood
(`tcs_bounds_detail`), not a divergence. Proven across two runtimes: 120
tiny records pipelined with the client's acknowledgements dropped hold the
primary at 32, the pair kept; a crash there, and the standby answers every
request byte-exactly.

Deliveries the standby owes its worker: a record's unconsumed deliveries
— handed to the primary's worker, never acknowledged by it (`delivery_ack`)
— cross in the CT_TLS record (`[deliv_count:1][deliv_len:4]` after the
sealed length, `deliv_count × [len:2][plaintext]` before the sealed set,
`delivered_in` the consumed cursor), up to four whole records' plaintext
(`TCS_REDELIVER_MAX`, eight entries at most); the standby's `tls` hands them
to its own worker, in order and before anything it opens itself, each
counted delivered as it goes. A primary's own export carries none (`tls`
keeps no plaintext it handed up), so what moves them is a mirror: a
crash-continuous standby's record, or a `tls` standby's own shadow, which
keeps each strict delivery from its RECORD_IN until DELTA_TLS_DELIVERED says
it was consumed (more than a record holds is refused `STATUS_NO_CAPACITY`,
ending the pair; a primary whose consumer acknowledges never sends more). More than `tls` hands again, or deliveries not following
the consumed cursor, are refused by name.

What a moved session's worker is told: what a session this host opened
would have told it. CT_TLS carries, after the peer-auth profile, the peer
block — the transport peer as `ip`'s MSG_PEER reported it
(`[family][addr:16][port:2]`, all zero when none was), a client session's
requester tag (`[tag:2]`, zero for an accepted one) and the peer identity
its `peer_identity` record carries (`[result][credential][flags:4]
[not_before:8][not_after:8][fp_len][fp:32][principal_len][principal:128]`,
zero-padded, held at import to the shapes a handshake produces). An
activated session emits the `peer_identity` record, then its held
MSG_ACCEPTED or MSG_CONNECTED (a client's on the carried requester tag),
then MSG_PEER, before any data. A standby whose peer-auth profile is not the
record's refuses it at commit (`STATUS_UNSUPPORTED`).

The answer to a KeyUpdate a crashed primary still owed: when the peer asks
for an update (`update_requested`), `tls`'s read rotation is mirrored with a
trailing `[owed:1]`, the inbound `KeyUpdate` delta carries it as
`[requested]`, the record holds `key_update_owed` until our own write
rotation, and CT_TLS carries it
as `key_update` bit 1. A `tls` activated from such a record sends its own
KeyUpdate before anything else (its clear side frozen until it has gone).

A half-closed connection: with `tls`'s `half_close`, the peer's
close_notify and its FIN (`ip`'s MSG_CLOSED `CLOSED_PEER_FIN`) end the peer's
direction only — the consumer is told once (MSG_CLOSED `CLOSED_PEER_FIN`, after
everything the peer sent) and
may still write until it closes; records after the peer's close_notify are
ignored (RFC 8446 §6.1). Such a session moves: `ip` exports CLOSE_WAIT (its
FIN one sequence number past what it delivered), CT_TLS carries the peer's
close_notify and FIN (`close_notify` bits 1 and 2), the record is
`CloseWait` with `fin_rcvd` and `close_notify_rcvd`, and a standby's `tls`
tells its own consumer, after the accept, that the peer is done. Under crash
continuity the peer's close_notify is an `RxRecord` and a `CloseNotify`, and
`ip`'s FIN a `Fin` the bridge defers until the record holds every byte
before it (`ip` reports the FIN before `tls` has those bytes); the ACK `ip`
shows for the FIN waits on the horizon past it. The `conn_sink` fixture
plays each of these services: `linger_ms` / `farewell` keep a half-closed
connection open and write to it before closing, `close_after` closes our
side once it has echoed that much, `echo_after` holds what it receives
unconsumed until that much has come (deliveries a standby owes),
`abort_after` resets the connection once it has echoed that much (an
abortive close), and `dial` makes it the client of a session it opens
(`tls` in client mode).

Our own close moves too. With continuity wired, a consumer's close keeps
the `tls` session `Closing`: its close_notify sealed through the ordinary
path (held under a strict horizon like any record, retained in the window),
mirrored (`DELTA_TLS_CLOSE_SENT` 0x82), and `CMD_CLOSE` to `ip` only after
every record before it, so the FIN follows them. CT_TLS `close_notify` bit 0
is our close_notify, bit 3 the transport close forwarded; FXTC carries
FIN-WAIT-1/2, CLOSING and LAST-ACK; the record is `FinWait1`, `FinWait2`,
`Closing` or `LastAck` with `close_notify_sent` and `fin_queued` while our
FIN is unacknowledged. Under crash continuity `ip`'s FIN-bearing SEND is a
`Fin` out and waits on the horizon past it. A standby activates such a
session closing — its consumer never told, its alert resent from the window
if `ip` asks, the transport close forwarded if the primary had not — and it
ends at `ip`'s MSG_CLOSED; a session that moves with its close_notify and
FIN in flight reaches the client whole, followed by a clean close from the
standby. TIME-WAIT moves too (FXTC state 7, the record's `TimeWait`): a
standby that takes it over answers the peer's retransmitted FIN and ends the
quiet period at what remained of it. A KeyUpdate that does not name the
object the standby holds is refused `DERIVE`. Quiescent means drained — nothing stashed below `ip`'s
send window, nothing held in `tls` — not nothing in flight: `tls`'s
retransmit window, anchored by `ip`'s `MSG_ACK` (above), holds exactly
`[SND.UNA, SND.NXT)`, so the cut carries the bytes in flight and the standby
resends them from the window it imports. Sessions move in ESTABLISHED,
CLOSE-WAIT, our own closing states and TIME-WAIT, over IPv4 and IPv6,
whichever end opened them.

A record crosses whole: an `RxRecord` delta is one record — it consumes
receive bytes and advances the read sequence by one — and carries its
plaintext as one delivery of up to `TS_DELIV_BYTES`, and a `TxRecord` one
whole record out. `tls`'s strict RECORD_IN carries a record's whole
plaintext where a whole record is received (aarch64; 512 bytes on the small
targets, where a longer record is not carried and the bridge ends the
pair).

Under a strict horizon `tls` holds every record it seals, in order: one
sealed while the retransmit window is full joins the hold behind the
records sealed before it rather than going ahead of them, and each held
record's RECORD_OUT names its own write sequence. A strict mirror stops
reading `cipher_in` while the deltas it has written and the standby has not
acknowledged, plus one more at its largest, could overrun `cont_out` — each
inbound segment's RECV_BYTES carries the partial record as it stands, up to
a whole protected record — since a delta the channel refuses ends the
pair.

A client session — one this host opened — is the record with
`TS_FLAG_CLIENT` set, composed with `client_*` this host's end and
`service_*` the server's, and decomposed back into `ip`'s
local end and `tls`'s client role, which activates telling its consumer
MSG_CONNECTED (with no requester tag: the standby's consumer did not dial
it).

IPv6 sessions move: `ip` exports an IPv6 connection as an FXTC record of
its IPv6 layout (the IPv4 record with both IPv4 address fields zero and the
two IPv6 addresses after the reorder slots), the record is `family` 6 with
the connection's own addresses, and the standby's `ip` imports it under its
own stand-ins, the peer's neighbour solicited at first send. The flow is
named `tc_flow_id_v6` (`0xF6` then the first fifteen bytes of a SHA-256 of
the tuple: the tuple does not fit sixteen bytes), which `ip` and the
contract compute alike, so the retired host's `ip` suppresses its reset for
the moved flow by the same name.

### QUIC under the anchor surface (`quic_continuity`)

Contract: `transport_continuity.rs`, its QUIC section. Module:
`modules/foundation/quic_continuity` (`qcs.rs`), for `TcTransport::Quic`
pairings, wired `quic.cont_out -> quic_cont`, `quic_ctl -> quic.cont_in`.
The canonical record is `WHQ1`: the anchor's view (both connection IDs, the
peer's path and family, the packet-number high-water, the largest received)
followed by `quic`'s own CT_QUIC record (magic `QKRC`) whole; a standby
refuses a header that disagrees with the record it carries.

Each crash-continuous transition is `MdKind::QuicDelta`, `quic`'s own
per-layer delta carried whole and numbered as `quic` numbers it. One that
cannot go out as exactly the next ends the pairing (an unsolicited STATUS of
op `ABORT`, reason `0x80 | qcs_lost`), since the anchor's DELTA_ACK of a
sequence is `quic`'s of that delta — so `quic`'s strict horizons (a packet
withheld until the standby holds it, an acknowledgement not shown before)
wait on the anchor's DELTA_ACK, and a crash standby arms from the stream
alone. ACTIVATE is refused unarmed, with no fence, or at an epoch not
strictly higher, and goes to `quic` only on the authority's verdict on the
per-flow token rebuilt for this provider's anchor. The activated `quic`
validates the client's path before trusting it (RFC 9000 §8.2: a
PATH_CHALLENGE, and at most three times what the path sent until it
answers; a validation that never completes ends the connection). The
checkpoint carries the connection's negotiated idle timeout and what was
left of its timer: the activated connection ends at that remainder unless
the client is heard first, and from then on runs the negotiated timeout —
never the standby's own `idle_timeout_ms`, which the client never saw.

The flow is `tc_flow_id_quic` of the server's connection ID, by which `quic`
binds an established connection at PAIR_PREPARE. The packet-number rule is
`quic`'s: a takeover resumes above every number the primary could have used
(its reservation's high-water, raised by every send delta). `quic` refuses
crash continuity on a connection whose packet numbers only it grants
itself, so the durable grant comes first: `RESERVATION_GRANT` (op 20,
`session_ctrl.rs`'s grant record) under the null handle on `tc_ctl`, or from
the authority on `auth_rsp` (`[0x14][len][grant]`, the grant naming its
flow), its block above everything the connection granted itself; the
connection is bound by its connection ID if no pairing has bound it yet.

With `cid_route_key` / `cid_route` every connection ID `quic` issues is a
19-byte routable ID (`cores/cid_route.rs`): a six-byte routing token
enciphered under the route key by a synthetic-IV construction over AES-128,
with a 64-bit tag and a fresh four-byte nonce. The keystream derives from
the tag, so a repeated nonce reveals only that two IDs share it, and any
ingress holding the key maps a packet to its anchor without a lookup — a
hint the anchor re-checks, never an authorization. `quic` holds peers
sixteen bytes wide (IPv4-mapped for IPv4) and runs over IPv6 on `ip`'s
datagram surface.

The QUIC continuity key is per flow, as `tls`'s is: `quic` derives it in its
vault from the `quic-continuity-master` KDF master under the label
`quic/continuity` and the flow, and it moves vault to vault by custody
(`CUSTODY_ATTEST` / `CUSTODY_WRAP` / `CUSTODY_UNWRAP`, ops 17–19, the
`quic-custody` signer attesting the destination's composition and the
challenge, the key wrapped to that destination only and opened on the
authority's verdict, `0xC4` / `0xC5` as for `transport_continuity`). No
master need be shared between hosts: each host's vault can make its own,
and the authority enrols each host's custody identity by its public half
(on Linux, `fluxor-linux vault-identity` opens or makes it in the host's
vault and prints its public half) before it accepts evidence that identity
signed.

The destination-bound key wrap is an SDK core (`cores/custody_wrap.rs`):
the kernel vault's `KEY_WRAP` and `KEY_UNWRAP` seal and open the `FXKW`
object with it (an HKDF-SHA256 KEK salted with the destination's
composition digest over the ECDH secret, ChaCha20-Poly1305 under it with
that digest as the associated data), so a peer or a harness holding the
same inputs computes the same bytes rather than a model of them.

### Between hosts: the remote channel

A standby is on another host, so everything a pair exchanges — chunks,
deltas and their acknowledgements, the cut, the wrapped continuity object,
custody evidence and the wrapped key — crosses between runtimes. Fluxor's
carrier for module-to-module frames between runtimes is `remote_channel`
(`modules/foundation/remote_channel`, `mesh.md`): local channels carried
record for record over authenticated transport sessions (a listener serves
up to `sessions` peers at once, one session each, named by the key
fingerprint its transport verified). With `resume`
it is also ordered and reliable across sessions:

- every record on every channel is numbered from 1 within the sender's
  incarnation (16 random bytes drawn at construction) and kept in a bounded
  retained window (`window`) until the receiver acknowledges it (`ACK`); a
  full window stops reading the channel's input, so back pressure reaches
  the producer;
- a session that ends takes nothing with it: the next one's `HELLO` says,
  per channel, the next record each end expects of the other's stream and
  whose stream it holds, and each end releases what the other has and sends
  the rest again from there — each record delivered once and in order across
  any number of reconnects;
- inside a session a numbered record must be exactly the next one expected:
  one the receiver already has is refused as a replay, one past it as a gap,
  and an acknowledgement of a record never sent, or behind one released,
  ends the session (`refuse::SEQUENCE`);
- a peer that names another incarnation than the one held has restarted and
  lost its streams: its streams start afresh, and what is retained for it is
  renumbered and sent again (at least once across a peer's restart);
- an idle session sends an acknowledgement every `keepalive_ms`, and one that
  hears nothing for three of those is ended and resumed by the next, so a
  link that died without a close on this end (a reset that reached only the
  other) cannot hold the one session for ever.

The transport authenticates: mutual `tls` (`peer_auth: ca_uri`) whose
identity is a P-256 key born in the host's vault (`identity_label`) and
certified at runtime (`identity_req` / `identity_cert`) under a URI naming
the host, from the enrolment authority the graph trusts; each end verifies
the other names the one peer it expects (`verify_uri`), and `remote_channel`
(`require_peer`) uses no session its transport did not bind. A host with
another authority's certificate (`unknown-ca`), or with this authority's
for another host (`name-mismatch`), gets no session.
`modules/fixtures/frame_split` hands each port of a graph whose frames
arrive multiplexed on one stream (a runtime's stdin) only the frames that
are its own.

An anchor provider on each host runs over a resumed channel between two
runtimes, with `transport_continuity` over this section's `ip` and `tls`
beneath each anchor: the planned move, the crash takeover and the custody
transfer all cross it, and under crash continuity a mirror link severed
while the client writes holds the records at the receive horizon through
the outage and the reconnect and leaves the pair intact.

Resume on the `mux` carrier: each channel is a stream of the QUIC session,
and every stream's `HELLO` carries the same resume trailer, fixed when the
session attached — applied once per stream, it is applied once, before any
record of the session goes — so a QUIC session that ends takes its streams
and what was on them with it and the next resumes each channel exactly as
on `net`. What a stream delivers proves the link to the keepalive as a
`net` segment does. A resumed session needs a new QUIC connection, which
`quic`'s client dials with `redial_ms` once its connection is gone; and the
connection must end when its peer is gone: `quic` restarts the idle timer
on every authenticated packet it receives, 1-RTT or long header, but on a
send only for the first ack-eliciting packet since one was received (RFC
9000 §10.1, so a PTO probe each interval does not keep a dead connection
alive); it advertises `idle_timeout_ms` (default 30 s; 0 none) and keeps
the smaller of it and the peer's (a zero one being none), raised at each
check to at least three times the current PTO (RFC 9000 §10.1, so a peer
advertising 1 ms does not end the connection before a probe could be
answered), and drops a write for a connection that has ended rather than
holding every command behind it. The probe timeout counts the peer's
`max_ack_delay` (25 ms when it sends none; 2^14 or more fails the
handshake) in the application-data space only (RFC 9002 §6.2.1). `quic`
advertises 25 ms, the step that receives a packet sending its
acknowledgement, or `CONT_MAX_ACK_DELAY_MS` (2025 ms) when its continuity
channel is wired, since a crash-continuous pairing withholds an
acknowledgement until the standby holds the packet, for at most
`CONT_HORIZON_MS`. Each acknowledgement reports how long its largest
packet waited, the hold included, at the default `ack_delay_exponent` of
3; the delay a peer reports, scaled by its exponent, comes off the RTT
sample in the application-data space as RFC 9002 §5.3 sets out — clamped
to its `max_ack_delay` once the handshake is confirmed, and only while the
sample stays at or above `min_rtt`. An ACK-only packet owes
no acknowledgement of its own (RFC 9000 §13.2.1), so two `quic`s never
answer each other's acknowledgements back and forth.

Resume does not run beside an exchange endpoint, and a peer that restarted
is not replay-checked (its streams are renumbered, so a record it had
received but not acknowledged is delivered again). A QUIC connection moves
under `TRANSPORT_CONTINUITY` through `quic_continuity` (above).
