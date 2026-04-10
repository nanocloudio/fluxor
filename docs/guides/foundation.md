# Foundation Modules Guide

This guide describes the foundation layer in Fluxor — the portable
modules that provide reusable domain capabilities (filesystem, network
protocol, application protocol, media control) without depending on
hardware bus specifics.

## Purpose

Driver modules provide hardware access. Foundation modules consume
contracts produced by drivers and expose higher-level domain interfaces
to app modules. App modules compose them into a workload.

## Architectural Separation

```text
driver modules  →  contract interfaces  →  foundation modules  →  app modules
```

This separation enables portability: the same foundation module can run
on any board as long as a compatible driver is present. The HTTP server
that runs on a Pico W with a `cyw43` driver runs unchanged on a CM5 with
a `virtio_net` driver, because both drivers expose Ethernet frames over
a channel and the IP foundation module sits between them and HTTP.

## Foundation Module Characteristics

A Fluxor foundation module should be:

- hardware-agnostic — uses no bus syscalls (no SPI, no PIO, no GPIO)
- contract-driven — communicates with the rest of the graph through
  channels and content types
- deterministic under backpressure
- explicit about control and data boundaries

Foundation modules should not assume board wiring or peripheral
implementation details. If a module needs to know which SPI bus its
data came from, it has crossed the line into being a driver.

## Common Domains

The foundation layer covers:

- **Storage and filesystems** (`fat32`)
- **Networking** (`ip`, `dns`, `dhcp`, `mqtt`, `http`, `tls`, `mesh`)
- **Protocol clients and servers** (`mqtt`, `http`, `dns`)
- **Media and session orchestration** (audio format normalization,
  control plane bridges)

Each domain follows the same graph composition model and the same
scheduler semantics — there is no special-case API for any of these.

## Contract Usage

Foundation modules consume infrastructure surfaces from the kernel and
contract surfaces from drivers:

- channels and buffers for data movement
- timers and events for coordination
- net_proto frames for networking (see [../architecture/network.md](../architecture/network.md))
- block I/O channels for storage
- filesystem (`dev_fs`) dispatch for VFS-style access

See [../architecture/device_classes.md](../architecture/device_classes.md)
for the full list of class-level contracts.

## Configuration Model

Foundation module behavior is configured declaratively in the graph YAML:

- endpoints and wiring
- policy modes and limits
- control bindings

This keeps foundation modules reusable and reduces firmware-level
branching. Two boards that need the same HTTP server with different
backing storage simply wire it differently — the HTTP module is the
same `.fmod` artifact in both.

## Lifecycle Expectations

Foundation modules should define clear behavior for:

- initialization readiness (use `module_deferred_ready` if downstream
  consumers must wait)
- transient upstream/downstream failure
- reset/reconfigure handling (use `module_drain` if in-flight work
  must complete cleanly)
- status emission for observability

## Design Guidance

- keep foundation APIs narrow and explicit
- separate transport concerns from domain policy
- use status/control channels for observability and orchestration
- avoid leaking driver-specific details into consumer contracts

## Related Documentation

- [../architecture/device_classes.md](../architecture/device_classes.md)
- [../architecture/pipeline.md](../architecture/pipeline.md)
- [../architecture/network.md](../architecture/network.md)
- [../architecture/module_architecture.md](../architecture/module_architecture.md)
