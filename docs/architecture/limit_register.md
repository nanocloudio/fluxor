# Limit register

The complete list of the system's deliberate hard ceilings. Two families:

- **Identifier widths** — wire/ABI commitments. The rule: no identifier
  space may become the binding limit before a memory pool does on any
  targeted deployment class. An id-shaped ceiling found in source but
  absent here is a bug.
- **Deliberate caps** — policy ceilings and sanity bounds that are meant
  to bind (or to catch runaway), with the reason recorded.

Each row names the defining `const` and its source file; the recorded
value is the aarch64/host profile's where a constant is per-profile.
The register and the source are kept in lockstep: editing a constant
means editing its row here in the same change.

## Identifier widths

| Id | Width | Ceiling | Symbol | Source | Value | Binds instead / notes |
|---|---|---|---|---|---|---|
| TCP/HTTP `conn_id` (net-proto wire) | u16 LE | 65535 | `MAX_TCP_CONNS` | modules/sdk/abi/config.rs | 256 | The id space does not bind — the connection table does. Raising the table past 256 first requires widening the datagram/packet `ep_id` (next row), which shares it |
| datagram/packet `ep_id` (DG/PKT wire) | u8 | 256 | — | modules/sdk/contracts/net/datagram.rs | — | Allocated from the TCP connection table, so `MAX_TCP_CONNS` = 256 exactly saturates this width; it is the binding id if the table grows |
| contract class (`required_caps` bitmask, fmod header) | u32 bit position | 32 | `MAX_CONTRACTS` | src/kernel/module/provider.rs | 32 | 28 of 32 positions assigned (including four reserved ids; excluding the kernel-internal dispatch bucket) (`STREAM_CLOCK` = 0x1C) — the tightest id headroom in the ABI; registration past the ceiling is refused EINVAL |
| permission category (fmod header) | u16 bitfield | 16 | — | src/kernel/module/loader.rs | — | 9 of 16 bits assigned (`observe` = bit 8); widening changes the module header layout |
| module index (exec_order, fault ids) | u8 | 256 | `MAX_MODULES` | modules/sdk/abi/config.rs | 128 | Deliberate keep at u8; reopen on multi-node density evidence. Dual asserts: `src/kernel/boot/config.rs`, `src/kernel/exec/scheduler/mod.rs` |
| channel buffer slot | i16 (−1 sentinel) | 32768 | `MAX_BUFFER_SLOTS` | src/kernel/ipc/buffer_pool.rs | 256 | The buffer arena binds first by orders of magnitude |
| owner slot | u16 | 65535 | `MAX_OWNERS` | src/kernel/workload/owner.rs | 64 | Memory/policy binds first; const-asserted ≤ `u16::MAX` |
| HTTP request path length | u16 | 65535 | `MAX_PATH` | modules/sdk/abi/config.rs | 200 | The wire field is u16; the 200-byte budget is pure memory policy |
| content-type position | u8 append-only | 256 | — | contracts/src/lib.rs | — | Vocabulary discipline; parallel tables are locked together by const asserts |

## Deliberate caps

| Cap | Symbol | Source | Value | Reason |
|---|---|---|---|---|
| Single module code segment | `MAX_MODULE_CODE_SIZE` | modules/sdk/abi/config.rs | 1048576 | Sanity bound: catches a corrupt or runaway blob, not a budget |
| Whole modules blob | `MAX_MODULES_BLOB_SIZE` | src/kernel/module/loader.rs | 8388608 | Sanity bound: a boot-image module table past this is refused at load |
| Boot config blob | `MAX_CONFIG_SIZE` | src/kernel/boot/config.rs | 262144 | Sanity bound on the packed config (32 KiB on RP/wasm profiles); an oversize blob is refused as `TooLarge` |
| OTA staging area (per A/B stage) | `STAGE_CAPACITY` | src/kernel/module/ota_stage.rs | 8388608 | Policy: a graph image larger than one stage is refused ENOSPC at stage write |
| Single channel ring | `MAX_CHAN_BYTES` | src/kernel/ipc/channel.rs | 4194304 | Sanity bound on one ring's share of the buffer arena |
| QUIC endpoint connections | `MAX_CONNS` | modules/foundation/quic/mod.rs | 2 | Policy: the endpoint is point-to-point by design |
| HTTP/2 streams per conn | `MAX_STREAMS` | modules/sdk/abi/config.rs | 4 | Policy: bounds per-connection stream state on every profile |
| HTTP route table | `MAX_ROUTES` | modules/sdk/abi/config.rs | 8 | Policy: a config declaring more routes is a compose-time error |
| Provider chain depth per contract | `MAX_CHAIN_DEPTH` | src/kernel/module/provider.rs | — | Policy, per-profile (3 RP2040 / 4 RP2350 / 8 aarch64-host); registration past the ceiling is refused EBUSY |
| KEY_VAULT key slots | `MAX_SLOTS` | src/kernel/security/key_vault.rs | 8 | Policy: generate/import with no free slot is refused ENOMEM |
| fat32 open files | `MAX_OPEN_FILES` | modules/foundation/fat32/mod.rs | 8 | Policy: an open past the table is refused ENFILE |
| mount open handles | `MAX_OPEN` | modules/foundation/mount/mod.rs | 64 | Policy: an open past the router table is refused ENFILE |
| OTA image layers | `MAX_LAYERS` | modules/foundation/ota_registry/mod.rs | 48 | Policy: sized to the 48-module fleet profile; a larger manifest is refused whole |
| SMMU DMA map table | `MAX_DMA_MAPS` | modules/foundation/smmu/mod.rs | 32 | Policy: a map past the translation table is refused ENOMEM before any MMIO write |
