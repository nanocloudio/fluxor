# ip Module

IP Stack Service Module

## Files

- `manifest.toml`
- `mod.rs`
- `arp.rs`
- `dhcp.rs`
- `eth.rs`
- `icmp.rs`
- `ipv4.rs`
- `tcp.rs`
- `udp.rs`
- `route.rs` — the `net.route` tables read with TAKE (segments, peer routes,
  held addresses), each entry's state reported with REPORT
- `flows.rs` — the datagram flow table (egress liveness, verdicts, service pins)
- `policy.rs` — packet policy enforced from `net.policy` tables
- `service.rs` — service translation (`net.policy` DNAT, `scope = local`)
- `held.rs` — held addresses realized from `net.route` HOLD
- `conn_arena.rs`, `index.rs`, `continuity.rs` — the connection table, the
  hashed indexes, transport continuity

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2040", "rp2350", "bcm2712"]

[[ports]]
name = "frames_rx"
direction = "input"
content_type = "EthernetFrame"
required = true

[[ports]]
name = "frames_tx"
direction = "output"
content_type = "EthernetFrame"
required = true
```

The optional ports — `net_in` / `net_out`, `addr_ctl` / `addr_evt`, the
pre-transport decision seam and the continuity pair — and the contracts it
declares (`workload`, `net_route`, `net_policy`) are described in
`manifest.toml`.

## Parameters

- `use_dhcp` — run the DHCP client (default 1).
- `expected_dhcp_server` — accept replies only from this server (0 = any).
- `trace_sample_permille` — ingress head-sampling rate.
- `dhcp_compat` — admit BOOTP replies and an ACK with no preceding OFFER
  (default 0 = strict). Both accept an address assignment the client cannot
  correlate to a selection it made.
- `static_ip`, `static_netmask`, `static_gateway` — the address to adopt
  when `use_dhcp=0`.
- `resolver` — the DNS server the node's own named dials are resolved at
  (default 0 = the server the DHCP lease supplied). A static-IP deployment
  that dials names sets it. A workload's dials use the name service its
  CREATE carried (`workload::resolver`), read with `NET_RESOLVER`.

Declared capacities — each sizes a table in the module heap at construction;
a graph declaring more than the default heap holds gives the instance
`heap.arena_bytes`, and construction otherwise refuses, naming the table.
Defaults are aarch64's, with the MCU-class figure after the slash:

- `lanes` (16 / 0) — workload lanes, stated to the kernel with
  `NET_PROVIDE`; `lane_endpoints` (16) — datagram endpoints per lane;
  `lane_pairs` (16) — same-node stream halves per lane; `lane_events` (8)
  and `node_events` (32 / 16) — each lane's own event queue and the node's.
- `max_peers` (0) — peer nodes (ARP table and peer routes); `max_segments`
  (4 / 0), `max_held` (0) — the `net.route` tables realized. Entries the
  node's tables hold past these are reported `refused(table_full)`.
- `max_dg_flows` (1024 / 4), `dg_flow_floor` (16 / 1 per lane),
  `dg_flow_idle_s` (30) — the datagram flow table; construction requires
  `max_dg_flows >= (lanes + 1) x dg_flow_floor`.
- `dns_cache` (8 / 2), `dns_pending` (4 / 2) — resolver entries per owner.
- `policy_tables` (comma-separated names), `policy_bytes` (8192 / 1024) —
  the `net.policy` tables this instance enforces and translates.

## Connecting by name

A consumer opens a stream with `CMD_CONNECT_TO` (`net_proto`, 0x14), whose
target carries an address family: `AF_INET` dials the literal at once,
`AF_INET6` is refused `EINVAL` (there is no IPv6 stack), and `AF_NAME` is
resolved here before the SYN goes out. The reserved `CMD_CONNECT` (0x13) is
unsupported and answered `MSG_ERROR ENOSYS` on its tag, with one log line naming
`CMD_CONNECT_TO`, so an emitter of it fails on its first dial.

The stub resolver is this module's: it owns the datagram path and the DHCP
lease's DNS server, so resolution needs no sibling module and no contract of
its own. One A query per name goes from an ephemeral port the resolver
allocates on first use and holds for the module's lifetime (reserved against
every later allocation), to `resolver` when set and otherwise to the lease's
server; replies are demuxed by that port ahead of the datagram endpoints, as
DHCP's are, and only from port 53 of that server. Two dials of one name in
flight share one query. A query unanswered after 3 s is sent once more with a
fresh CSPRNG-drawn id; a second silence, a negative answer (NXDOMAIN, an
error code, NOERROR with no A record), or no resolver to ask fails the dial
`ENOENT` on its requester tag. `EAGAIN` means every pending slot is taken,
or the CSPRNG had no id to give.

Answers are cached by TTL per owner — the node and each workload lane hold
their own `dns_cache` entries and `dns_pending` queries, so no owner joins
another's query or reads its answer — and a repeated dial pays no round
trip. A zero TTL is held for 60 s; others for 1..3600 s. Names are held
lowercased, whole up to the protocol's 253 bytes. A workload's queries go to
its own name service (translated when it is a service address, the backend
pinned for the lookup), from its own address when the server is inside its
cluster, under its search list; an answer is claimed only from the server
the query was pinned to, at the address it left from. The
`dns` module is a server; it does not resolve for siblings, and the wire
codec the two share is `sdk/contracts/net/dns_wire.rs`.

`CMD_DG_SEND_TO` takes the same `AF_NAME`: a cached name sends at once; a
name not in hand starts the lookup and the datagram is dropped without a
report, because a datagram sender retransmits and the next send finds the
answer. An address family other than `AF_INET` / `AF_NAME` is refused
`EAFNOSUPPORT`.

## Workload reachability

On bare metal this module is the node's network stack for its workloads,
and realizes what the node agent writes to the kernel:

- **`net.route` tables**, read with `TAKE` whenever their generation moves
  and reported entry by entry with `REPORT` (`route.rs`). A workload's
  address sources its traffic to its segment and the segment's cluster
  prefixes; anything else leaves from the node's address (a datagram from
  the endpoint's egress port, its replies admitted only on a live flow).
  Peer routes are realized when the peer is on the primary's link (direct
  carriage); held addresses in `deliver` mode become node addresses
  (`held.rs`). `announce`, forwarding between segments and translated
  egress are not offered here, and the kernel's CAPS say so.
- **`net.policy` tables** named by `policy_tables` (`policy.rs`): this
  module ATTACHes as their one enforcer and judges each flow's first packet
  with the shared evaluator — streams at connect and at an inbound SYN,
  datagrams when their flow begins (and per packet for an inbound datagram
  on no flow), echo requests to a workload. Traffic the node itself sends
  or terminates is not judged. A flow keeps its verdict for its lifetime.
- **Service translation** of `scope = local` DNAT records for the node's own
  traffic (`service.rs`): a dial, a datagram or a resolver query to a
  service address goes to one of its backends. A stream keeps its backend;
  a datagram flow re-picks when its backend leaves the set; a service with
  no backends refuses (`ECONNREFUSED`, `MSG_DG_ERROR`). Inbound translation
  for clients off the node is not offered (`DNAT_LOCAL` without `DNAT`).

## Supported profile

IPv4 fragments are dropped before L4 (no reassembler); off-subnet traffic
leaves by the longest matching peer route whose peer is on the link, else by
the configured gateway, and with neither is not sent; ARP mappings are
created only by a correlated
ARP reply; one transmit frame per datagram (`EMSGSIZE` past the ceiling).
See the module doc comment and `docs/architecture/network.md`.

Inbound TCP segments pass one admissibility gate before any state branch:
receive-window acceptability over the segment's full sequence extent,
RFC 5961 RST classification, and `SEG.ACK` range validation. Challenge ACKs
are rate-limited by a global and a per-connection bucket so the defence
cannot be used for reflection; suppressions are counted, not logged.

## Datagram endpoint identity

An `ep_id` is a slot index in the shared connection table, allocated from a
random offset and echoed by the consumer on every `CMD_DG_SEND_TO` /
`CMD_DG_CLOSE`. A command naming a slot that holds no live endpoint is
refused with `ENOTSOCK` and metered.

The bind identity is `(protocol, local_port, local_slot)` plus the owner
stamp. A repeated bind of the same identity by the same owner resolves to the
existing endpoint; a bind whose reachability overlaps one already held is
refused with `EADDRINUSE`. The same port at two distinct local addresses is
two endpoints.

`ep_id` is an index, not an authority. The graph model permits several
consumer modules to share this module's command channel — the kernel merges
them into one stream — and `channel_read` carries no producer identity, so an
index alone cannot say who sent a command. The owner tag is the authority:
`CMD_DG_BIND` records an `owner_tag` on the endpoint, `CMD_DG_SEND_TO` and
`CMD_DG_CLOSE` carry the tag they claim in a fixed position ahead of the
payload, and a command whose tag does not equal the endpoint's is refused with
`EPERM` and counted in `dg_ep_perm`. Liveness is decided first, so a released
handle still answers `ENOTSOCK`; a tag mismatch is only ever reported for a
slot that really holds an endpoint.

The tag a consumer presents is its own owner slot, read from the kernel
(`OWNER_TAG`, 0x0C4B — a module can only read its own). Every in-tree datagram
consumer reaches this surface through `sdk/cores/datagram_endpoint.rs`, which
stamps that slot on `CMD_DG_BIND` and presents it on every `CMD_DG_SEND_TO`.
It is the same axis, and the same value, that `NET_CMD_BIND` already carries
for TCP listeners.

The decoder is tolerant, and an absent tag decodes as tag 0. What remains
reachable by the untagged shape, exactly: owner slot 0 is `OWNER_SYSTEM`, so a
base-graph, host-owned module binds untagged and its endpoint is recorded with
`owner_tag = 0`. Such an endpoint accepts untagged send and close from any
consumer sharing the command channel — so host-owned consumers are not
separated from one another, and neither are two modules of the same workload.
What the tag separates is owners. A module of a `net=own` workload binds with
its workload's slot, and from that point an untagged command, or one bearing a
different tag, is `EPERM`. A tagged command does not reach a tag-0 endpoint
either — the presented tag must equal the recorded one, with no "any tag
matches 0" rule.

The tag is asserted by the consumer in the frame, not proved. The property is
"the consumer that bound this endpoint named this tag", not an unguessable
capability: tags are small owner-slot integers, and a module free to write
arbitrary bytes can name any of them. What bounds the assertion is bind
admission — a nonzero tag resolves to the `local_addrs` slot that owner owns,
and a bind naming an owner with no address on this host is refused `EACCES`.

## SYN resource defence

Passive open spends a connection slot per SYN only while half-open occupancy
is below `MAX_TCP_CONNS / 2`. Below that line behaviour is unchanged, SYN-ACK
retransmission included. At or above it the SYN is answered with a cookie ISS
— the ISN secret keyed over the four-tuple and a ~65.5 s epoch, the epoch's
low two bits carried in the cookie — and no slot is allocated; the returning
ACK's cookie is validated against the current or preceding epoch before the
RST path, and the connection is reconstructed from the ACK alone. There is no
SYN cache and nothing is swept.

The reconstruction is complete only because the stack negotiates no TCP
option: emitted headers are 20 bytes (`TCP_DATA_OFFSET_BYTE`, guarded by a
compile-time assertion), and a SYN that carries an option area is refused
rather than answered from a cookie. Counters `tcp_syn_cookie_{sent,ok,bad}`
and the option refusal print on the `[ip] cookie` line.

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
