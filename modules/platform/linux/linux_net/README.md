# linux_net

Linux-only native network surface. Bridges the stream surface
contract (`net_proto`) to host TCP/UDP sockets via `libc`.

Implements the kernel-side dispatch for `CMD_BIND` / `CMD_CONNECT_TO` /
`CMD_SEND` / `CMD_CLOSE` and emits `MSG_BOUND` / `MSG_ACCEPTED` /
`MSG_DATA` / `MSG_CLOSED` / `MSG_ERROR` to anchor modules. It is the
hosted-Linux counterpart of `rp1_gem` + `ip` on bare-metal Pi 5.

It grants no stream sideband (`net_proto::flag`): `flags_granted` is 0 on
every `MSG_BOUND` / `MSG_ACCEPTED` / `MSG_CONNECTED`. The host's TCP keeps
its own copy of what is sent, so a stream is never offered `stream_retx`
and a record layer above it keeps no retransmission window; it emits no
trace context and serves no continuity cursors. An undefined flag bit is
refused `EINVAL`. A stream bind that fails is answered `MSG_ERROR` with no
connection and no tag; a datagram bind that fails, `MSG_DG_ERROR` on
endpoint 0xFF. A datagram endpoint belongs to the owner the kernel attests
for the lane its bind arrived on; a send or close from another owner's lane
is refused `EPERM`.

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

A value outside its range is refused at instantiation. Bind, connect and
close are runtime commands on `net_in`.

## Behaviour

- An idle slot holds no buffer. Commands stop being read — back-pressure
  on the shared upstream channel — only while some connection's backlog is
  full, so a peer slow to read is buffered up to `write_buf_kib` without
  holding up the others.
- Listener sockets set `SO_REUSEADDR`, so a graph that crashes mid-run
  rebinds on the next start without waiting out `TIME_WAIT`.
- Sockets are non-blocking: a receive with nothing to read is "no data
  this step", never a blocked domain loop.
- Each instance owns its connection table, held through the one
  state-arena word its manifest declares (`state_bytes_64 = 1`). Two
  `linux_net` instances in one process have independent tables but share
  the host's ports.

## Source

The implementation is [src/platform/linux/providers.rs](../../../../src/platform/linux/providers.rs).
This directory holds the manifest the build reads to validate the graph;
nothing here is compiled.
