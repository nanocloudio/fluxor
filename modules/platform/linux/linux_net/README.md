# linux_net

The node's network on a Linux host. Bridges the stream surface contract
(`net_proto`) and the datagram surface to the host's TCP and UDP, serves
`net_route` and `net_policy`, and takes address control (`addr_ctl`). It is
the hosted-Linux counterpart of `rp1_gem` + `ip` on bare-metal Pi 5.

A host provider serves it, out of the runtime's process: the build makes a
`linux_net` instance a `host_lane` running `fluxor-provider-net` (beside
`fluxor-linux`, where `fluxor sync` puts a project's runtimes). Records
cross whole on shared rings, never as contract calls:

- every socket consumer is one of the provider's dynamic lanes: each
  `to: linux_net.net_in` edge of the node's graph a lane of its own under
  the node owner, keyed in wiring order, its events back to its producer;
  every edge marked `edge_class: merge` one shared lane (through a merge),
  its events to each `net_out` consumer that produces into no lane of its
  own (through a tee); and each lane a workload attaches (its
  `net_in`/`net_out` naming `linux_net`) under the workload's owner, added
  and removed with it. Lanes are drained in attach order, the node graph's
  first. Wiring that leaves a lane's events no one place to go is refused
  at build;
- `addr_ctl` / `addr_evt` are the one static pair, pair 0, which carries
  address control alone: socket traffic on a static pair is refused at
  build.

The runtime tells the provider, per lane, the owner its commands act for and
what that owner may claim (its admission, its authority, its grants under
the committed plan), and has it close every connection of an owner the
kernel frees before the release completes. The provider keeps
`CAP_NET_ADMIN`, `CAP_NET_RAW` and `CAP_NET_BIND_SERVICE` when the runtime
holds them, and nothing else.

It grants no stream sideband (`net_proto::flag`): `flags_granted` is 0 on
every `MSG_BOUND` / `MSG_ACCEPTED` / `MSG_CONNECTED`. The host's TCP keeps
its own copy of what is sent, so a stream is never offered `stream_retx`
and a record layer above it keeps no retransmission window; it emits no
trace context and serves no continuity cursors. An undefined flag bit is
refused `EINVAL`. A stream bind that fails is answered `MSG_ERROR` with no
connection and no tag; a datagram bind that fails, `MSG_DG_ERROR` on
endpoint 0xFF. A datagram endpoint, as a connection, belongs to the lane
its bind arrived on; a send or close from another lane is refused `EPERM`.
Both surfaces are served on every lane; an endpoint takes a connection slot
below 256, since its id is a byte.

Records: `net_out` writes at most 1483 bytes per frame (a `MSG_DATA` of
1460 bytes; a datagram of up to 1472 bytes of IPv4 payload — a larger one
is dropped and counted, never cut), and `net_in` accepts commands up to
49155 bytes.

```yaml
modules:
  - name: linux_net   # name fixed by the platform.net stack
  - name: my_anchor
    listen_port: 9000

wiring:
  - from: linux_net.net_out
    to: my_anchor.net_in
  - from: my_anchor.net_out
    to: linux_net.net_in
```

The `platform.net` stack injects this module when `target: linux` is
set, so most YAMLs do not name `linux_net` explicitly — they wire
`<anchor>.net_in` ↔ `<anchor>.net_out` against the stack-provided node.

## Configuration

| Param | Tag | Type | Default | Range | Meaning |
|---|---|---|---|---|---|
| `max_conns` | 10 | u32 | 128 | 2..=65535 | Connection slots (listeners, accepted clients and outbound connects share one table); the ceiling is the `u16` connection id `net_proto` carries |
| `write_buf_kib` | 11 | u32 | 128 | 1..=65536 | Per-connection unsent-byte backlog cap, KiB, grown as a send backs up and released with the slot |
| `listen_backlog` | 12 | u32 | 128 | 1..=65535 | `listen()` backlog |
| `lanes` | 13 | u8 | 32 | 0..=255 | Workload lanes served at once, to which the build adds the node graph's (255 together at most); 0 serves no workload |

A value outside its range is refused at build. Bind, connect and
close are runtime commands on a lane.

## Behaviour

- An idle slot holds no buffer. Commands stop being acted on — back-pressure
  on the lanes' rings, and through them on their producers — only while some
  connection's backlog is full, so a peer slow to read is buffered up to
  `write_buf_kib` without holding up the others.
- Listener sockets set `SO_REUSEADDR`, so a graph that crashes mid-run
  rebinds on the next start without waiting out `TIME_WAIT`.
- Sockets are non-blocking and level-triggered in one epoll set, which also
  wakes the provider; names resolve on a thread of its own through the
  host's resolver (`getaddrinfo`), answers cached for 60 s.
- Each instance is its own provider process with its own connection table;
  two `linux_net` instances share the host's ports.

## Source

The implementation is [hosts/linux/net](../../../../hosts/linux/net)
(`src/sockets.rs`, `src/serve.rs`); the build's rule is
`tools/src/config/host_provider.rs`. This directory holds the manifest the
build reads to validate the graph and to build the host lane; nothing here
is compiled.
