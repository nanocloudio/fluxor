# linux_eth

Linux-only built-in Ethernet frame driver: the hosted runtime's counterpart
of `virtio_net` or `rp1_gem`, so `ip` runs its own TCP/IP stack on Linux
rather than `linux_net`'s host sockets. A graph needs that when it needs
the stack itself — the transport-continuity surfaces checkpoint
connections `ip` owns, and a host socket is not one.

```yaml
modules:
  - name: eth
    type: linux_eth
    ifname: eth0          # an interface in the runtime's network namespace
  - name: ip
    use_dhcp: 0
    static_ip: 172820737  # 10.77.9.1

wiring:
  - from: eth.frames_rx
    to: ip.frames_rx
  - from: ip.frames_tx
    to: eth.frames_tx
```

Frames cross both ports as `[len:u16 LE][frame]` records, the first out
being the MAC announcement `ip` waits for.

## Configuration

| Param | Tag | Type | Default | |
|---|---|---|---|---|
| `ifname` | 10 | str | required | The interface to drive. |
| `mac` | 11 | str | `""` | The stack's MAC (six hex octets); the interface's (`packet`) or one derived from `ifname` (`tap`) when unset. In `packet` mode the interface is not made promiscuous, so an override receives unicast only where the interface already accepts that address (a veth does; a hardware NIC filters it). |
| `mode` | 12 | enum | `packet` | `packet`: an `AF_PACKET` socket bound to an existing interface — a veth end with no address of its own, so the host kernel there answers nothing for the stack; needs `CAP_NET_RAW` in that namespace's user namespace. `tap`: a persistent TAP opened by name; needs access to `/dev/net/tun`. |

A packet socket reads frames as the wire carries them, so checksum offload
must be off on every link a frame crosses into it (`ethtool -K <if> tx off
rx off`); `ip` drops a segment whose checksum an offload never filled in.

A frame `frames_rx` has no room for is dropped and counted, as a NIC drops on
a full ring; so is a frame longer than 1518 bytes (no FCS, one VLAN tag)
either way, never truncated, and a transmit the interface refuses.

The interface is named by the boot graph: built-in modules are constructed
only from the runtime's own configuration, so `linux_eth` reaches what the
runtime process can — its network namespace and the capabilities it holds
there — and nothing a staged workload chooses. Its descriptor is
close-on-exec, so no host-process workload inherits it.

## Where it is used

A graph whose `ip` must own its connections — `transport_continuity` moving
a live TCP+TLS session between two runtimes, each `ip` over `linux_eth` on a
veth in an unprivileged network namespace of its own.
