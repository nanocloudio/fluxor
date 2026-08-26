# Foundation Modules Guide

This guide describes the foundation layer in Fluxor: the portable
modules that provide reusable domain capabilities (filesystem, network
protocol, network-plane hygiene, media control) without depending on
hardware bus specifics.

Source: `modules/foundation/`.

## Purpose

Driver modules provide hardware access. Foundation modules consume
contracts produced by drivers and expose higher-level domain interfaces
to app modules. App modules compose them into a workload.

## Architectural separation

```text
driver modules  →  contract interfaces  →  foundation modules  →  app modules
```

This separation is what makes foundation modules portable: the same
module runs on any board as long as a compatible driver is present. The
`ip` module that runs on a Pico W with the `cyw43` driver runs
unchanged on a Pi 5 with the `rp1_gem` driver, because both drivers
expose Ethernet frames over a channel and `ip` sits between them and
the application protocols.

## Foundation module characteristics

A Fluxor foundation module is:

- hardware-agnostic — uses no bus syscalls (no SPI, no PIO, no GPIO)
- contract-driven — communicates with the rest of the graph through
  channels and content types
- deterministic under backpressure
- explicit about control and data boundaries

Foundation modules do not assume board wiring or peripheral
implementation details. If a module needs to know which SPI bus its
data came from, it has crossed the line into being a driver.

## Common domains

The foundation layer covers:

- **Storage and filesystems** (`fat32`, `sd`, `mount`)
- **Networking** (`ip` — which includes the DHCP client — plus `dns`,
  `tls`, `quic`); application-protocol clients and servers (`http`,
  `mqtt`, …) live in sibling projects that consume them
- **Network-plane hygiene** (`conn_guard` for TCP-SYN connection-rate
  filtering, `demux` for 4-tuple hashed frame fan-out to replicated IP
  lanes, `conn_demux` for per-connection fan-out to parallel TLS
  lanes, `pkt_filter` for stateless rule-based filtering)
- **Media and session orchestration** (`format` for audio format
  conversion and resampling, control-plane bridges)

Each domain follows the same graph composition model and the same
scheduler semantics; there is no special-case API for any of these.

## Contract usage

Foundation modules consume infrastructure surfaces from the kernel and
contract surfaces from drivers:

- channels and buffers for data movement
- timers and events for coordination
- net_proto frames for networking (see [../architecture/network.md](../architecture/network.md))
- block I/O channels for storage
- filesystem (`FS`) contract for VFS-style access

See [../architecture/abi_layers.md](../architecture/abi_layers.md)
for the full contract inventory.

## Configuration model

Foundation module behaviour is configured declaratively in the graph YAML:

- endpoints and wiring
- policy modes and limits
- control bindings

This keeps foundation modules reusable and reduces firmware-level
branching. Two boards that need the same server with different backing
storage simply wire it differently; the module is the same `.fmod`
artefact in both.

## Lifecycle expectations

Foundation modules define clear behaviour for:

- initialisation readiness (export `module_deferred_ready` if
  downstream consumers must wait)
- transient upstream/downstream failure
- reset/reconfigure handling (export `module_drain` if in-flight work
  must complete cleanly)
- status emission for observability

## Design guidance

- keep foundation APIs narrow and explicit
- separate transport concerns from domain policy
- use status/control channels for observability and orchestration
- avoid leaking driver-specific details into consumer contracts

## Related documentation

- [../architecture/abi_layers.md](../architecture/abi_layers.md)
- [../architecture/pipeline.md](../architecture/pipeline.md)
- [../architecture/network.md](../architecture/network.md)
- [../architecture/module_architecture.md](../architecture/module_architecture.md)
- [../architecture/security.md](../architecture/security.md)
