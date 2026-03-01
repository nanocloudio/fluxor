# Services Guide

This guide describes service-layer architecture in Fluxor.

## Purpose

Services provide reusable domain capabilities (filesystem, network protocol,
application protocol, media control) without direct dependence on hardware bus
specifics.

Driver modules provide hardware access. Service modules consume contracts.

## Architectural Separation

```text
driver modules -> contract interfaces -> service modules -> application modules
```

This separation enables portability: the same service module can run on
different boards as long as contract providers exist.

## Service Characteristics

A Fluxor service module should be:

- hardware-agnostic
- contract-driven
- deterministic under backpressure
- explicit about control and data boundaries

Services should not assume board wiring or peripheral implementation details.

## Common Service Domains

- storage and filesystem composition
- network stack and transport consumers
- protocol clients/servers
- media/session orchestration

Each domain follows the same graph composition model and scheduler semantics.

## Contract Usage

Services typically consume infrastructure and contract surfaces, including:

- channels/buffers for data movement
- timers/events for coordination
- contract interfaces for netif/socket/fs-style boundaries

See `docs/architecture/device_classes.md` for class-level contracts.

## Configuration Model

Service behavior is configured declaratively:

- endpoints and wiring
- policy modes and limits
- control bindings

This keeps service modules reusable and reduces firmware-level branching.

## Lifecycle Expectations

Services should define clear behavior for:

- initialization readiness
- transient upstream/downstream failure
- reset/reconfigure handling
- status emission for observability

## Design Guidance

- keep service APIs narrow and explicit
- separate transport concerns from domain policy
- use status/control channels for observability and orchestration
- avoid leaking provider-specific details into consumer contracts

## Related Documentation

- `docs/architecture/device_classes.md`
- `docs/architecture/pipeline.md`
- `docs/architecture/network.md`
