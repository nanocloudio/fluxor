# Network Boot

Fluxor devices can boot their application graph from the network. The
kernel and a minimal boot graph reside in local flash. The application
graph — modules, configuration, and assets — is fetched from a
deployment server at boot time. The device becomes a stateless compute
node whose behaviour is determined by what the network provides.

This is a composition of existing architectural primitives: remote
channels for transport, graph bundles for packaging, module signing
for trust, live graph reconfigure for the transition from boot graph
to application graph, and asset caching for incremental content
delivery.

The design is intentionally not PXE. Firmware still boots a local
kernel and a minimal boot graph. The network only supplies a signed
application graph bundle after the local trust root is already
running.

## Building Blocks

| Primitive | Role |
|---|---|
| Graph bundles | Package modules, configuration, and assets for a target. |
| Module signing | Verifies packed module hashes and Ed25519 signatures. |
| `modules/foundation/graph_slot/` | Staged graph-slot storage and promotion semantics. |
| `modules/foundation/ota_ingest/` | Ingests update data for staged deployment paths. |
| `modules/foundation/remote_channel/` | Fluxor-native channel transport between nodes. |
| `modules/foundation/reconfigure/` | Coordinates graph transition through the reconfigure path. |
| `architecture/security.md` | Trust profiles, signature handling, and KEY_VAULT usage. |

## Boot Flow

```text
Power on
  -> local kernel starts
  -> local boot graph starts network driver and transport modules
  -> boot graph discovers or contacts deployment server
  -> server selects a graph bundle for this device class and version
  -> device downloads bundle through remote channel or HTTP
  -> device verifies signature, hashes, target compatibility, and graph shape
  -> device stages bundle in graph_slot or volatile memory
  -> reconfigure promotes the application graph
  -> boot graph exits or remains as the fallback path
```

The boot graph is deliberately small: network driver, IP or host
transport, bundle fetch, validation, staging, and reconfigure trigger.
Application logic belongs in the loaded graph, not in the boot graph.

## Boot Image

A boot image is a local fallback image selected for the board being
provisioned. The person provisioning the device knows what network
hardware it has — they're holding the board — so the image carries
the right network driver for that board. The image includes:

- the target kernel and platform support
- the minimal boot graph
- the network driver or host transport for that board
- the trust root used to validate downloaded bundles
- enough configuration to find or discover the deployment server

Provisioning produces a complete boot image and writes it to the
board's primary boot storage. Pre-built boot images exist for the
common board/network-interface combinations.

## Bundle Fetch

Two transports cover the common cases:

- **Remote channel** for Fluxor-native deployments, where the server
  exposes a deployment endpoint over the channel fabric.
- **HTTP GET** for simple infrastructure, where the response body is a
  signed Fluxor bundle.

Both transports produce the same staging input: a byte stream
containing the signed graph bundle. Transport choice does not affect
validation or the runtime graph format.

## Validation

Before promotion, the boot graph rejects any bundle that fails:

- signature policy for the device trust profile
- per-module SHA-256 hash checks
- target and board compatibility checks
- manifest resource checks, including `[[resources]].requires_contract`
  and `[requires]` CPU-feature gating
- graph validation: ports, content types, resource limits, and wiring
- version or rollback policy

Validation reuses the same rules as the host build tool so a bundle
accepted by the device is not using a weaker schema than the one
accepted during local builds.

## Staging

Staging policy is target-specific:

- RP-class boards stage into reserved flash sectors when capacity
  permits.
- BCM2712/CM5-class targets stage into DRAM, NVMe, SD, or another
  board-selected backing store.
- Linux-hosted runs stage into the host filesystem.
- WASM-hosted deployments stage in the browser/host storage layer
  when the platform exposes one.

Promotion goes through the graph-slot/reconfigure path rather than
special-casing network boot in the kernel.

## Fallback

The local boot image is the recovery path. If download, validation,
instantiation, or first-tick health checks fail, the device remains on
or returns to the boot graph and reports the failure when transport is
available.

A failed application graph must not overwrite the local fallback image.
Updating the fallback image is a separate, higher-risk operation and
should require an explicit policy.

## Fleet Model

A deployment server can be any service that maps a device identity and
device class to a signed bundle. The server may also record boot
attempts, active versions, validation failures, and health telemetry,
but none of that changes the on-device graph model.

Typical server responsibilities:

- store graph bundles by target, board, version, and rollout channel
- authenticate device boot requests when the deployment requires it
- choose the bundle for the requesting device
- stream the bundle through remote channel or HTTP
- record success, failure, and rollback events

## Security Model

Network boot relies on the same trust chain as local packed firmware.
The network is not trusted. A transport can provide confidentiality and
server authentication, but bundle signatures and hashes are still the
authority for code and graph integrity.

Important properties:

- downloaded code is never executed before validation
- unsigned bundles are accepted only when the device policy allows them
- staged bundles must be bound to the target and board they were built for
- rollback policy must be explicit
- server compromise should not bypass the device trust root

See `security.md` for the loader trust profiles and signing model.

## Where It Fits

Network boot is one deployment shape for the same graph bundles used
by local flash, browser-hosted WASM, and Linux-hosted runs. The
bundle format, validation rules, signing model, and runtime graph
semantics are all shared. A device that boots its application graph
from the network and a device that boots the same graph from local
flash differ only in where the bytes came from — not in how they
execute.
