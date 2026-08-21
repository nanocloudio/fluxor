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

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

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

## Parameters

- `use_dhcp` — run the DHCP client (default 1).
- `expected_dhcp_server` — accept replies only from this server (0 = any).
- `trace_sample_permille` — ingress head-sampling rate.
- `dhcp_compat` — admit BOOTP replies and an ACK with no preceding OFFER
  (default 0 = strict). Both accept an address assignment the client cannot
  correlate to a selection it made.

## Supported profile

IPv4 fragments are dropped before L4 (no reassembler); off-subnet traffic
requires a configured gateway; ARP mappings are created only by a correlated
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
- Last refreshed: 2026-08-21
