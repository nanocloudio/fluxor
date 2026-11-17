# linux_net

Linux-only built-in network surface. Bridges the stream surface
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

This module has no `[[params]]`. Bind/connect/close commands flow as
runtime FMP messages on the `net_in` channel; nothing is set at
config-build time.

## Behaviour

- Up to 24 concurrent connections (TCP listeners + accepted clients +
  outbound connects, sharing one slot table).
- Listener sockets set `SO_REUSEADDR`, so a graph that crashes mid-run
  rebinds without `TIME_WAIT` waits on the next start.
- Accepted client sockets are non-blocking; a recv that returns
  `EAGAIN` becomes "no data this tick" rather than blocking the
  scheduler.
- Per-instance `Box<LinuxNetState>` — see
  `docs/architecture/abi_layers.md`'s built-in section for the boxed
  state pattern. Two `linux_net` modules in one process would still
  collide on OS listen ports (config-time concern), but their
  in-memory connection tables are independent.

## Source

Implementation lives in [src/platform/linux/providers.rs](../../../../src/platform/linux/providers.rs).
The directory you're reading is a manifest-only descriptor that the
config tool reads to validate wiring; nothing here gets compiled.
