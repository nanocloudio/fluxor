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
them into one stream — and `channel_read` carries no producer identity, so a
consumer that guesses a live `ep_id` can act on another consumer's endpoint.
Closing that gap needs a requester tag on the datagram command opcodes, which
is a change to the `datagram` contract rather than to this module. Random
allocation and the `ENOTSOCK` refusal bound and expose the guess; they do not
prevent one.

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-08-20
