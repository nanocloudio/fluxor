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
| contract class (`required_caps` bitmask, fmod header) | u64 bit position | 64 | `MAX_CONTRACTS` | src/kernel/module/provider.rs | 64 | One number for three roles: vtable index, opcode class byte, and bit position in the header's `required_caps`. Registration past the ceiling is refused EINVAL, and a dispatch id at or past it is refused ENOSYS by `check_contract_grant` before either capability gate |
| contract-class positions consumed | — | 64 | `CONTRACT_ID_POSITIONS_ASSIGNED` | tools/src/manifest.rs | 28 | Counts the four reserved ids, excludes the kernel-internal dispatch bucket. Highest allocated is `STREAM_CLOCK` = 0x1C, leaving 0x1D–0x3F (35 positions) free. The inventory is pinned by `tools/tests/contract_id_inventory.rs`, which also asserts the tools-side mirror `CONTRACT_ID_SPACE` equals `MAX_CONTRACTS` |
| permission category (fmod header) | u16 bitfield | 16 | — | src/kernel/module/loader.rs | — | 9 of 16 bits assigned (`observe` = bit 8); widening changes the module header layout |
| module index (exec_order, fault ids) | u8 | 256 | `MAX_MODULES` | modules/sdk/abi/config.rs | 192 | Deliberate keep at u8; the aarch64 profile sits at 192 of the 256 the width admits. Dual asserts: `src/kernel/boot/config.rs`, `src/kernel/exec/scheduler/mod.rs` |
| channel buffer slot | i16 (−1 sentinel) | 32768 | `MAX_BUFFER_SLOTS` | src/kernel/ipc/buffer_pool.rs | 256 | The buffer arena binds first by orders of magnitude |
| owner slot | u16 | 65535 | `MAX_OWNERS` | src/kernel/workload/owner.rs | 64 | Memory/policy binds first; const-asserted ≤ `u16::MAX` |
| HTTP request path length | u16 | 65535 | `MAX_PATH` | modules/sdk/abi/config.rs | 200 | The wire field is u16; the 200-byte budget is pure memory policy |
| content-type position | u8 append-only | 256 | — | contracts/src/lib.rs | — | Vocabulary discipline; parallel tables are locked together by const asserts |

## Deliberate caps

| Cap | Symbol | Source | Value | Reason |
|---|---|---|---|---|
| Ordered-ack record payload | `PAYLOAD_MAX` | modules/sdk/contracts/exchange.rs | 8192 | Policy: the one ceiling every provider of `stream.ordered_ack` derives from, so a producer has a number it can hold itself to. A per-provider ceiling is undiscoverable by the producer that must stay under it. A provider whose backend cannot take the full size declares the smaller number as its `max_payload` capability fact, which the build checks against the producer's own `max_payload` fact |
| Ordered-ack message key | `KEY_MAX` | modules/sdk/contracts/exchange.rs | 512 | Policy: a table or topic identifier plus a 256-byte natural key, with room for producers whose ordering unit is wider. The key is the ordering unit and is opaque to the provider |
| Ordered-ack publish frame | `PUBLISH_FRAME_MAX` | modules/sdk/contracts/exchange.rs | 8717 | Derived, not chosen: `PUBLISH_OVERHEAD + KEY_MAX + PAYLOAD_MAX` — what a `publish_in` port must take as one record and what a producer declares as `max_record`. Moves when any of its three parts moves, which is why it is checked rather than restated |
| Ordered-ack reply frame | `REPLY_FRAME_MAX` | modules/sdk/contracts/exchange.rs | 8717 | Derived, not chosen: `REPLY_OVERHEAD + KEY_MAX + PAYLOAD_MAX` — what a `reply_out` port must be able to emit as one record. Equal to `PUBLISH_FRAME_MAX` only because the two overheads happen to match; it is stated separately so a change to either frame moves only its own row |
| Single module code segment | `MAX_MODULE_CODE_SIZE` | modules/sdk/abi/config.rs | 1048576 | Sanity bound: catches a corrupt or runaway blob, not a budget |
| Whole modules blob | `MAX_MODULES_BLOB_SIZE` | src/kernel/module/loader.rs | 8388608 | Sanity bound: a boot-image module table past this is refused at load |
| Boot config blob | `MAX_CONFIG_SIZE` | src/kernel/boot/config.rs | 262144 | Sanity bound on the packed config (32 KiB on RP/wasm profiles); an oversize blob is refused as `TooLarge` |
| OTA staging area (per A/B stage) | `STAGE_CAPACITY` | src/kernel/module/ota_stage.rs | 8388608 | Policy: a graph image larger than one stage is refused ENOSPC at stage write |
| Single channel ring | `MAX_CHAN_BYTES` | src/kernel/ipc/channel.rs | 4194304 | Sanity bound on one ring's share of the buffer arena |
| QUIC endpoint connections | `MAX_CONNS` | modules/foundation/quic/mod.rs | 8 | Policy: ~20 KB of state per slot on a bcm2712-only module; a connection past the ceiling receives a stateless CONNECTION_REFUSED so it fails in one round trip rather than hanging, and a Closed slot recycles with a fresh ephemeral |
| HTTP/2 streams per conn | `MAX_STREAMS` | modules/sdk/abi/config.rs | 4 | Policy: bounds per-connection stream state on every profile |
| HTTP route table | `MAX_ROUTES` | modules/sdk/abi/config.rs | 8 | Policy: a config declaring more routes is a compose-time error |
| Provider chain depth per contract | `MAX_CHAIN_DEPTH` | src/kernel/module/provider.rs | — | Policy, per-profile (3 RP2040 / 4 RP2350 / 8 aarch64-host); registration past the ceiling is refused EBUSY |
| KEY_VAULT key slots | `MAX_SLOTS` | src/kernel/security/key_vault.rs | 8 | Policy: generate/import with no free slot is refused ENOMEM |
| fat32 open files | `MAX_OPEN_FILES` | modules/foundation/fat32/mod.rs | — | Policy, per-profile (32 aarch64 / 8 elsewhere): a multi-tenant node runs several independent consumers against one volume at once, where a microcontroller's consumer set is fixed and each handle costs a scratch buffer. An open past the table is refused ENFILE, with a log line naming the handles that hold it. The `max_open_per_owner` parameter adds a per-owner ceiling on top, refusing the owner that is over its share while the table still has room, so the failure lands on the workload at fault rather than on whoever asks next |
| fat32 directory-walk budget | `DIR_SCAN_BUDGET_SECTORS` | modules/foundation/fat32/mod.rs | 32 | Policy: directory sectors one `provider_call` reads before returning EAGAIN with its position saved. A directory with thousands of entries is not exotic — a WAL that segments per snapshot fills one — so an unbounded walk is a latent stall of every module sharing the lane, not a slow path |
| fat32 long-name length | `LFN_MAX_CHARS` | modules/foundation/fat32/mod.rs | 64 | Policy: the format allows 255, but a buffer for that is carried in the directory cursor and in every wanted-name argument, on a board whose whole module state is measured against a 256 KiB arena. A longer name is refused at creation, not clipped. Names longer than this that were written elsewhere are still preserved and retired correctly — preservation walks the companion run without decoding it, so only matching and generation are bounded |
| fat32 free-cluster scan | `FAT_SCAN_BUDGET_SECTORS` | modules/foundation/fat32/mod.rs | 32 | Policy: FAT sectors one `provider_call` reads looking for a free cluster before returning EAGAIN with its cursor saved. Matches `DIR_SCAN_BUDGET_SECTORS` for the same reason — a synchronous device read inside a dispatch is charged to the cooperative step budget, and the FAT of a large volume is far too big to walk in one |
| fat32 outstanding fences | `MAX_FENCES` | modules/foundation/fat32/mod.rs | — | Policy: equals `MAX_OPEN_FILES`. A fence table smaller than the handle table would let a consumer open a handle it cannot fence, which reads as a durability failure rather than a resource limit. `FSYNC_SUBMIT` past the table is refused EAGAIN (backpressure) |
| DNS pending forwarded queries | `MAX_PENDING` | modules/foundation/dns/mod.rs | 8 | Policy: with every slot live and unexpired, a new query is answered SERVFAIL rather than displacing accepted work |
| DNS configured host entries | `MAX_HOSTS` | modules/foundation/dns/mod.rs | 16 | Policy: `host=` parameters past the table are ignored at parse |
| DNS domain name length | `MAX_NAME_LEN` | modules/foundation/dns/mod.rs | 255 | The RFC 1035 full-name ceiling; a longer QNAME is refused at parse. Distinct from the 63-byte per-label ceiling (`MAX_LABEL_LEN`) |
| mount open handles | `MAX_OPEN` | modules/foundation/mount/mod.rs | 64 | Policy: an open past the router table is refused ENFILE |
| OTA image layers | `MAX_LAYERS` | modules/foundation/ota_registry/mod.rs | 48 | Policy: sized to the 48-module fleet profile; a larger manifest is refused whole |
| SMMU DMA map table | `MAX_DMA_MAPS` | modules/foundation/smmu/mod.rs | 32 | Policy: a map past the translation table is refused ENOMEM before any MMIO write |
