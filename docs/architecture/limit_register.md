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
| TCP/HTTP `conn_id` (net-proto wire) | u16 LE | 65535 | `MAX_TCP_CONNS` | modules/sdk/abi/config.rs | 65536 | The host table is exactly the id space (ids 0..65535); 256 on wasm, 16 on embedded. A record is ~2.2 KiB, most of it the bounded reorder buffer, so the host table is ~137 MiB and is the term `STATE_ARENA_SIZE` is sized around. Lookup is by hash index (`ip/index.rs`) whose removals close their holes and whose hash is seeded per instance, so a packet pays for the cluster it lands in rather than for the table — a miss included — and the timer sweep is sliced across its 50 ms window |
| datagram/packet `ep_id` (DG/PKT wire) | u8 | 256 | `MAX_DG_ENDPOINTS` | modules/sdk/abi/config.rs | 256 | Endpoints are allocated only from the first `MAX_DG_ENDPOINTS` connection slots, so the u8 id binds the endpoint count, not the table. TCP prefers the slots beyond that window and takes it only when the rest is full |
| local-address slot (`TcpConn::local_slot`) | u16 | 65535 | `MAX_LOCAL_ADDRS` | modules/sdk/abi/config.rs | 4096 | `0xFFFF` is the wildcard slot. Demux is by hash index; 8 on wasm and embedded |
| decision-seam hold (`pkt_id` slot) | u16 | 65535 | `MAX_PACKET_HOLD` | modules/sdk/abi/config.rs | 32 | One full frame per slot; an arrival past it is refused and counted, never displaces a held packet. 8 on wasm, 4 on embedded |
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
| Telemetry ring capacity | `CAPACITY` | src/kernel/sys/telemetry_ring.rs | 4096 | Policy, per target family (4 KiB on RP2040, 8 KiB on RP2350, 32 KiB on bcm2712/host). Records are denser than log text, so the ring sits below the log ring's split. A const assert holds it at or above one whole PSTATUS round — the scheduler emits a round as one uninterrupted burst, so a ring under that size drops the tail of *every* round and the high-index modules never report at all |
| Telemetry drain slots | `RING_CONSUMERS` | modules/sdk/contracts/telemetry.rs | 4 | Policy: the console exporter, one `otel` engine per export destination, and a spare. It is wire-visible — a `TLM_STATS` reply is `[head][dropped × RING_CONSUMERS]` — so a caller sizes its buffer from it and widening is an ABI change, not a tuning knob |
| Telemetry record | `TELEMETRY_MAX_RECORD` | src/kernel/exec/scheduler/module_types.rs | 144 | Derived, not chosen: the widest record kind, a 16-bucket histogram metric. The ring reserves atomically at this size and rejects anything larger whole, so a value below the true maximum silently bounces every wider emit at the syscall rather than failing loudly |
| Instrument dimension cardinality | `DIM_MAX_PRODUCT` | modules/sdk/contracts/telemetry.rs | 65534 | Policy: the product of one instrument's declared dimension domains, enforced at build so every composite index stays below the reserved `DIM_OTHER` (`0xFFFF`). Cardinality is a declared resource bound — an instrument that would exceed it shrinks a domain rather than discovering the ceiling at runtime |
| Single module code segment | `MAX_MODULE_CODE_SIZE` | modules/sdk/abi/config.rs | 1048576 | Sanity bound: catches a corrupt or runaway blob, not a budget |
| Whole modules blob | `MAX_MODULES_BLOB_SIZE` | src/kernel/module/loader.rs | 8388608 | Sanity bound: a boot-image module table past this is refused at load |
| Boot config blob | `MAX_CONFIG_SIZE` | src/kernel/boot/config.rs | 262144 | Sanity bound on the packed config (32 KiB on RP/wasm profiles); an oversize blob is refused as `TooLarge` |
| OTA staging area (per A/B stage) | `STAGE_CAPACITY` | src/kernel/module/ota_stage.rs | 8388608 | Policy: a graph image larger than one stage is refused ENOSPC at stage write |
| Module state arena | `STATE_ARENA_SIZE` | modules/sdk/abi/config.rs | 268435456 | Sized, not chosen: it must hold every module of the busiest graph at once. The `ip` connection table is the dominant term at ~137 MiB, and 256 MiB leaves ~117 MiB beside it — above the media-app host graph's 64 MiB peak. 256 KiB on embedded, where the whole envelope is different. Zero-initialised, so it costs kernel `.bss`, not image size. Exhaustion is refused at module load, not at the allocation that overruns |
| Single channel ring | `MAX_CHAN_BYTES` | src/kernel/ipc/channel.rs | 4194304 | Sanity bound on one ring's share of the buffer arena |
| QUIC endpoint connections | `MAX_CONNS` | modules/sdk/abi/config.rs | 64 | Policy: ~58 KiB of state per slot on a bcm2712-only module — ~3.6 MiB for the table, the dominant term in the module's footprint and paid resident, since the table is a field of the module state rather than an elastic pool. ~13 KiB of a slot is handshake scratch idle once the connection is established; the remaining ~45 KiB is state a live connection needs, so unlike the TLS ceiling this one is not mostly scratch. A connection past the ceiling receives a stateless CONNECTION_REFUSED so it fails in one round trip rather than hanging, and a Closed slot recycles with a fresh ephemeral |
| TLS sessions | `MAX_SESSIONS` | modules/sdk/abi/config.rs | 512 | Policy: the ceiling on concurrent TLS connections and so on HTTPS concurrency — an accept the tls module cannot seat is closed before http sees it. A seat is ~13 KiB, of which ~12 KiB is handshake scratch resident for the session's whole life; 512 seats are 63 granted chunks ≈ 7.9 MiB, drawn in 8-session chunks from the oversubscribable elastic region, so an idle stack pays only for the inline chunk. 4 inline on embedded. This bounds ONE instance and instances do not add up the way the number invites: a chunk asks ~104 KiB and rounds up to the 64 KiB grant quantum, so it takes 128 KiB, and the 16 MiB region holds 128 chunks — the same depth as the kernel's chunk table — for about 1,024 seats shared across every elastic pool on the host. Two saturated instances are already the region. Published in the profile so a consumer reads the envelope it has; `tls::MAX_SESSIONS <= ip::MAX_TCP_CONNS` is asserted at compile time |
| HTTP/2 streams per conn | `MAX_STREAMS` | modules/sdk/abi/config.rs | 4 | Policy: bounds per-connection stream state on every profile |
| HTTP route table | `MAX_ROUTES` | modules/sdk/abi/config.rs | 8 | Policy: a config declaring more routes is a compose-time error |
| Provider chain depth per contract | `MAX_CHAIN_DEPTH` | src/kernel/module/provider.rs | — | Policy, per-profile (3 RP2040 / 4 RP2350 / 8 aarch64-host); registration past the ceiling is refused EBUSY |
| KEY_VAULT key slots | `MAX_SLOTS` | src/kernel/security/key_vault.rs | 8 | Policy: generate/import with no free slot is refused ENOMEM |
| fat32 open files | `MAX_OPEN_FILES` | modules/foundation/fat32/mod.rs | — | Policy, per-profile (256 aarch64 / 8 elsewhere): a multi-tenant node runs several independent consumers against one volume at once, where a microcontroller's consumer set is fixed and each handle costs a scratch buffer. An open past the table is refused ENFILE, with a log line naming the handles that hold it. The `max_open_per_owner` parameter adds a per-owner ceiling on top, refusing the owner that is over its share while the table still has room, so the failure lands on the workload at fault rather than on whoever asks next |
| fat32 directory-walk budget | `DIR_SCAN_BUDGET_SECTORS` | modules/foundation/fat32/mod.rs | 32 | Policy: directory sectors one `provider_call` reads before returning EAGAIN with its position saved. A directory with thousands of entries is not exotic — a WAL that segments per snapshot fills one — so an unbounded walk is a latent stall of every module sharing the lane, not a slow path |
| fat32 long-name length | `LFN_MAX_CHARS` | modules/foundation/fat32/mod.rs | 64 | Policy: the format allows 255, but a buffer for that is carried in the directory cursor and in every wanted-name argument, on a board whose whole module state is measured against a 256 KiB arena. A longer name is refused at creation, not clipped. Names longer than this that were written elsewhere are still preserved and retired correctly — preservation walks the companion run without decoding it, so only matching and generation are bounded |
| fat32 free-cluster scan | `FAT_SCAN_BUDGET_SECTORS` | modules/foundation/fat32/mod.rs | 32 | Policy: FAT sectors one `provider_call` reads looking for a free cluster before returning EAGAIN with its cursor saved. Matches `DIR_SCAN_BUDGET_SECTORS` for the same reason — a synchronous device read inside a dispatch is charged to the cooperative step budget, and the FAT of a large volume is far too big to walk in one |
| fat32 outstanding fences | `MAX_FENCES` | modules/foundation/fat32/mod.rs | — | Policy: equals `MAX_OPEN_FILES`. A fence table smaller than the handle table would let a consumer open a handle it cannot fence, which reads as a durability failure rather than a resource limit. `FSYNC_SUBMIT` past the table is refused EAGAIN (backpressure) |
| DNS pending forwarded queries | `MAX_PENDING` | modules/foundation/dns/mod.rs | 8 | Policy: with every slot live and unexpired, a new query is answered SERVFAIL rather than displacing accepted work |
| DNS configured host entries | `MAX_HOSTS` | modules/foundation/dns/mod.rs | 16 | Policy: `host=` parameters past the table are ignored at parse |
| DNS domain name length | `MAX_NAME_LEN` | modules/foundation/dns/mod.rs | 255 | The RFC 1035 full-name ceiling; a longer QNAME is refused at parse. Distinct from the 63-byte per-label ceiling (`MAX_LABEL_LEN`) |
| DNS compression-pointer hops per name | `MAX_NAME_PTR_HOPS` | modules/foundation/dns/mod.rs | 16 | Sanity: pointers must also point backwards, so a cycle is refused by direction first; the hop bound is the second line. A name past it is malformed |
| DNS records examined per section | `MAX_SECTION_RRS` | modules/foundation/dns/mod.rs | 32 | Sanity: an upstream answer or UPDATE section claiming more is refused rather than walked |
| DNS64 alias hops | `MAX_CNAME_HOPS` | modules/foundation/dns/mod.rs | 4 | Policy: a CNAME chain past it is refused SERVFAIL; loops are detected within it |
| DNS64 alias-chain bytes per pending slot | `MAX_CHAIN_BYTES` | modules/foundation/dns/mod.rs | 384 | Policy: the re-encoded chain preserved into the synthesized answer; a chain that does not fit is refused SERVFAIL |
| DNS64 synthesized addresses per answer | `MAX_SYNTH_ADDRS` | modules/foundation/dns/mod.rs | 8 | Policy: A records of the terminal owner past it are not translated |
| DNS64 address exclusions | `MAX_DNS64_EXCLUDES` | modules/foundation/dns/mod.rs | 16 | Policy: `dns64_exclude` entries past the table are ignored at parse |
| DNS64 TTL without a negative SOA (seconds) | `DNS64_TTL_CAP_S` | modules/foundation/dns/mod.rs | 600 | RFC 6147 §5.1.7: the cap on the remaining A TTL when the AAAA NODATA carried no SOA |
| DNS zone records per generation | `MAX_ZONE_RRS` | modules/foundation/dns/mod.rs | — | Policy, per-profile (64 aarch64 / 16 elsewhere): an UPDATE whose candidate would exceed it is refused SERVFAIL whole |
| DNS UPDATE records per section | `MAX_UPDATE_RRS` | modules/foundation/dns/mod.rs | 32 | Policy: a prerequisite or update section claiming more is REFUSED before parsing (the 512-byte UDP message binds first) |
| DNS zone owner name | `MAX_ZONE_NAME` | modules/foundation/dns/mod.rs | 128 | Policy: an add whose dotted owner name does not fit is refused SERVFAIL |
| DNS zone RDATA | `MAX_ZONE_RDATA` | modules/foundation/dns/mod.rs | 128 | Policy: an add whose uncompressed RDATA does not fit is refused SERVFAIL |
| DNS TSIG keys admitted | `MAX_UPDATE_KEYS` | modules/foundation/dns/mod.rs | 4 | Policy: `update_allow` entries past the table are ignored at parse; each lists at most `MAX_ALLOW_TYPES` (8) record types |
| DNS TSIG signing window (seconds) | `MAX_TSIG_FUDGE_S` | modules/foundation/dns/mod.rs | 300 | Policy: the widest fudge honoured whatever the request asks (RFC 8945 §5.2.3); outside it is BADTIME |
| DNS retained update transactions | `MAX_TXN_CACHE` | modules/foundation/dns/mod.rs | 4 | Policy: a repeated authenticated transaction (same key and MAC) inside retention is answered from the cache; the oldest entry is displaced |
| DNS update-transaction retention (ms) | `TXN_RETAIN_MS` | modules/foundation/dns/mod.rs | 30000 | Policy: past retention a repeated transaction has its prerequisites evaluated anew |
| DNS zone-file commit writes | `MAX_COMMIT_WRITES` | modules/foundation/dns/mod.rs | 64 | Sanity: `WRITE` / `READ` calls per commit or recovery before the operation is refused as stalled |
| mount open handles | `MAX_OPEN` | modules/foundation/mount/mod.rs | 64 | Policy: an open past the router table is refused ENFILE |
| OTA image layers | `MAX_LAYERS` | modules/foundation/ota_registry/mod.rs | 48 | Policy: sized to the 48-module fleet profile; a larger manifest is refused whole |
| SMMU DMA map table | `MAX_DMA_MAPS` | modules/foundation/smmu/mod.rs | 32 | Policy: a map past the translation table is refused ENOMEM before any MMIO write |
| QUIC continuity shadow slots | `MAX_SHADOW_SLOTS` | modules/foundation/quic/continuity.rs | 2 | Policy: connections under CT_QUIC takeover at once, one per slot. Continuity is a control-plane event, not steady state, and each shadow stages a whole connection's worth of state; a PAIR_PREPARE past the free slots is refused `STATUS_NO_CAPACITY` |
| QUIC continuity checkpoint record | `CHECKPOINT_RECORD_MAX` | modules/foundation/quic/continuity.rs | 16384 | Sized, not chosen: holds the full serialized connection state — three bidi (1200+1500) and six uni (256+256) stream buffers, the retained last-emitted packet, the sealed secret set, and the fixed header, with headroom. A checkpoint whose `total_len` exceeds it is refused `STATUS_NO_CAPACITY` at CHECKPOINT_BEGIN and the shadow is discarded |
| ARP-wait handshake list | `ARP_WAIT_MAX` | modules/foundation/ip/mod.rs | 64 | Policy: handshakes remembered as waiting on neighbour resolution, so an ARP reply retries exactly those rather than walking the connection table. A full list only defers the retry to the timer sweep's next slice |
| GEM RX descriptors | `RX_DESC_COUNT` | modules/drivers/rp1_gem/mod.rs | 192 | Policy: the burst the Pi 5 MAC absorbs between two driver steps; a step drains the whole ring. The platform DMA arena holds 256 buffers shared with the 64 TX descriptors. Ring positions wrap at a multiple of the ring size (`rp1_gem/ring.rs`, pinned by `tests/harness/tests/gem_ring.rs`), so a size that does not divide 65,536 is safe |
| fan frames per step | `FAN_FRAMES_PER_STEP` | src/kernel/exec/scheduler/module_types.rs | 64 | Policy: whole frames a framed `_tee` or `_merge` moves in one step. A fan sits between a producer and its consumers, so this times the tick rate is the ceiling on every fanned port — `debug: to: net` fans the ip module's consumer ports, and every accept, delivery and send on that graph crosses one. Pinned by `tests/harness/tests/fan_throughput.rs` |
| free-slot rebuild slice | `ALLOC_SCAN_SLICE` | modules/foundation/ip/mod.rs | 256 | Policy: slots one step examines to rebuild the free stack when it is empty — the table is full, or a slot was released by a path that did not push it. Allocation is a pop; a SYN at the ceiling costs this slice once per step and is refused, never a walk of the table per SYN |
| timer-sweep slice | `SWEEP_SLICE_MAX` | modules/foundation/ip/mod.rs | 1024 | Policy: most connections one step of the sliced TCP timer sweep visits. The proportional slice visits a few hundred; after a stall the whole window is owed and this is the ceiling it meets — a full 65,536-record sweep in one step is a multi-millisecond, cache-missing step the guard would end the module for. The sweep lags a stall by at most 64 steps, and needs that many steps per 50 ms window to keep the timers on time: a tick of 780 µs or faster on the 65,536-record profile (the Pi 5 runs 100 µs) |
| TCP continuity shadow slots | `MAX_TCP_SHADOWS` | modules/sdk/abi/config.rs | 8 | Policy: connections a transport-continuity pair holds in flight on one ip instance — shadows staged for import plus flows being mirrored out. Each shadow is a connection record plus its checkpoint bytes, and takeover is a control-plane event, not steady state; a PAIR_PREPARE past the free slots is refused `STATUS_NO_CAPACITY`. 2 on wasm, 1 on embedded |
| fence wire wait | `FENCE_WIRE_WAIT_MS` | modules/foundation/ip/mod.rs | 500 | Policy: how long a fence holds its event for the driver's drain answer before reporting the ring hand-off instead. Longer than any transmit ring takes to empty at line rate; short enough that a coordinator waiting on the fence is not waiting on a hung driver |
| queued control frame | `NET_OUT_FRAME_MAX` | modules/foundation/ip/mod.rs | 9 | Sanity bound: the largest frame the fallback queue holds — header, a u16 connection id and a u32 sequence (`MSG_RETRANSMIT`, `MSG_ACK`). A larger frame is refused, never truncated |
| TLS continuity shadow slots | `MAX_TLS_SHADOWS` | modules/foundation/tls/continuity.rs | 2 | Policy: sessions under CT_TLS takeover at once on one instance, one per slot (1 on the embedded targets). A shadow is a staging record plus the decoded checkpoint — about twice `TLS_CKPT_RECORD_MAX`, resident in module state — and takeover is a control-plane event, not steady state; a PAIR_PREPARE past the free slots is refused `STATUS_NO_CAPACITY` |
| TLS continuity checkpoint record | `TLS_CKPT_RECORD_MAX` | modules/foundation/tls/continuity.rs | — | Derived, not chosen: the fixed header plus the whole partial-inbound buffer (`RECV_BUF_SIZE`), the whole retransmission window (`RETX_BUF_SIZE`) and the sealed secret set — about 21 KiB where the receive buffer is 16 KiB, about 9 KiB on the 4 KiB targets. A CHECKPOINT_BEGIN whose `total_len` exceeds it is refused `STATUS_NO_CAPACITY` before any byte moves; the record is never truncated |
| TLS strict-profile send hold | `TX_HOLD_SIZE` | modules/foundation/tls/continuity.rs | — | Derived, not chosen: every record one `CMD_SEND` (`MAX_CMD_DATA` bytes) can produce, since the clear-side frame is consumed whole and each of its records must wait for its own send horizon — six records of `WIRE_RECORD_MAX`, about 9.3 KiB per session, paid in every session slot whether or not it is mirrored. A producer that exceeds the contract's frame ceiling fills the hold and the session fails rather than the record being dropped |
| QUIC 1-RTT self-grant block | `LOCAL_PN_BLOCK` | modules/foundation/quic/connection.rs | 4096 | Policy: the send packet-number block a connection self-grants in local (non-durable) mode, refilled `LOCAL_PN_REFILL_LOW` (512) values ahead of exhaustion so the reservation never stalls a healthy sender. Matches the directory's smoke-path reserve size; in durable mode the directory chooses the block |
| declared step cost (`[execution] max_step_us`) | `STEP_BUDGET_DEFAULT_TICK_US` | tools/src/target_facts.rs | 1000 | Policy: the scheduler's default pass budget (`DEFAULT_TICK_US`, one tick) on every silicon; a manifest whose step cannot fit one default pass on a target it names is refused at parse. Per-target in shape so a slower part can publish a smaller budget |

## Machine-checked block

The tables above carry the reasoning; prose is not parseable, so the same
ceilings are restated here in the form `fluxor ci`'s `limit-register` phase
reads: `NAME | source path | right-hand side`. The right-hand side is
compared textually after whitespace normalisation, so a row records what the
source says rather than an evaluated number — `8 * 1024 * 1024` stays
`8 * 1024 * 1024`.

A constant declared once per `cfg` profile gets one row per profile, and the
gate compares the whole set: a profile added, removed, or retuned is drift.
Matching a single declaration would leave every profile the register does not
happen to quote free to move — the per-profile constants here span three
deployment classes, so that is most of them.

Editing a constant means editing its row. The gate also requires every name
here to appear in the prose above, so the two halves cannot diverge into two
registers, and reports ceiling-shaped constants in these files that no row
covers — which is what makes "an id-shaped ceiling found in source but absent
here is a bug" a measured number rather than a sentence.

```limit-register
MAX_TCP_CONNS | modules/sdk/abi/config.rs | 65536
MAX_TCP_CONNS | modules/sdk/abi/config.rs | 256
MAX_TCP_CONNS | modules/sdk/abi/config.rs | 16
MAX_DG_ENDPOINTS | modules/sdk/abi/config.rs | 256
MAX_DG_ENDPOINTS | modules/sdk/abi/config.rs | 16
MAX_LOCAL_ADDRS | modules/sdk/abi/config.rs | 4096
MAX_LOCAL_ADDRS | modules/sdk/abi/config.rs | 8
MAX_PACKET_HOLD | modules/sdk/abi/config.rs | 32
MAX_PACKET_HOLD | modules/sdk/abi/config.rs | 8
MAX_PACKET_HOLD | modules/sdk/abi/config.rs | 4
MAX_CONTRACTS | src/kernel/module/provider.rs | 64
CONTRACT_ID_POSITIONS_ASSIGNED | tools/src/manifest.rs | 28
MAX_MODULES | modules/sdk/abi/config.rs | 192
MAX_MODULES | modules/sdk/abi/config.rs | 48
MAX_MODULES | modules/sdk/abi/config.rs | 32
MAX_BUFFER_SLOTS | src/kernel/ipc/buffer_pool.rs | 256
MAX_OWNERS | src/kernel/workload/owner.rs | 64
MAX_OWNERS | src/kernel/workload/owner.rs | 1
MAX_PATH | modules/sdk/abi/config.rs | 200
MAX_PATH | modules/sdk/abi/config.rs | 32
PAYLOAD_MAX | modules/sdk/contracts/exchange.rs | 8192
KEY_MAX | modules/sdk/contracts/exchange.rs | 512
PUBLISH_FRAME_MAX | modules/sdk/contracts/exchange.rs | PUBLISH_OVERHEAD + KEY_MAX + PAYLOAD_MAX
REPLY_FRAME_MAX | modules/sdk/contracts/exchange.rs | REPLY_OVERHEAD + KEY_MAX + PAYLOAD_MAX
CAPACITY | src/kernel/sys/telemetry_ring.rs | 4096
CAPACITY | src/kernel/sys/telemetry_ring.rs | 8192
CAPACITY | src/kernel/sys/telemetry_ring.rs | 32768
RING_CONSUMERS | modules/sdk/contracts/telemetry.rs | 4
TELEMETRY_MAX_RECORD | src/kernel/exec/scheduler/module_types.rs | 144
DIM_MAX_PRODUCT | modules/sdk/contracts/telemetry.rs | 65534
MAX_MODULE_CODE_SIZE | modules/sdk/abi/config.rs | 1024 * 1024
MAX_MODULE_CODE_SIZE | modules/sdk/abi/config.rs | 384 * 1024
MAX_MODULES_BLOB_SIZE | src/kernel/module/loader.rs | 8 * 1024 * 1024
MAX_CONFIG_SIZE | src/kernel/boot/config.rs | 256 * 1024
MAX_CONFIG_SIZE | src/kernel/boot/config.rs | 32 * 1024
STAGE_CAPACITY | src/kernel/module/ota_stage.rs | 8 * 1024 * 1024
STATE_ARENA_SIZE | modules/sdk/abi/config.rs | 256 * 1024 * 1024
STATE_ARENA_SIZE | modules/sdk/abi/config.rs | 96 * 1024 * 1024
STATE_ARENA_SIZE | modules/sdk/abi/config.rs | 256 * 1024
MAX_CHAN_BYTES | src/kernel/ipc/channel.rs | 4 * 1024 * 1024
MAX_CONNS | modules/sdk/abi/config.rs | 64
MAX_CONNS | modules/sdk/abi/config.rs | 8
MAX_CONNS | modules/sdk/abi/config.rs | 2
MAX_SESSIONS | modules/sdk/abi/config.rs | 512
MAX_SESSIONS | modules/sdk/abi/config.rs | 64
MAX_SESSIONS | modules/sdk/abi/config.rs | 4
MAX_STREAMS | modules/sdk/abi/config.rs | 4
MAX_ROUTES | modules/sdk/abi/config.rs | 8
MAX_ROUTES | modules/sdk/abi/config.rs | 4
MAX_CHAIN_DEPTH | src/kernel/module/provider.rs | 3
MAX_CHAIN_DEPTH | src/kernel/module/provider.rs | 4
MAX_CHAIN_DEPTH | src/kernel/module/provider.rs | 8
MAX_SLOTS | src/kernel/security/key_vault.rs | 8
MAX_OPEN_FILES | modules/foundation/fat32/mod.rs | 256
MAX_OPEN_FILES | modules/foundation/fat32/mod.rs | 8
DIR_SCAN_BUDGET_SECTORS | modules/foundation/fat32/mod.rs | 32
LFN_MAX_CHARS | modules/foundation/fat32/mod.rs | 64
FAT_SCAN_BUDGET_SECTORS | modules/foundation/fat32/mod.rs | 32
MAX_FENCES | modules/foundation/fat32/mod.rs | MAX_OPEN_FILES
MAX_PENDING | modules/foundation/dns/mod.rs | 8
MAX_HOSTS | modules/foundation/dns/mod.rs | 16
MAX_NAME_LEN | modules/foundation/dns/mod.rs | 255
MAX_NAME_PTR_HOPS | modules/foundation/dns/mod.rs | 16
MAX_SECTION_RRS | modules/foundation/dns/mod.rs | 32
MAX_CNAME_HOPS | modules/foundation/dns/mod.rs | 4
MAX_CHAIN_BYTES | modules/foundation/dns/mod.rs | 384
MAX_SYNTH_ADDRS | modules/foundation/dns/mod.rs | 8
MAX_DNS64_EXCLUDES | modules/foundation/dns/mod.rs | 16
DNS64_TTL_CAP_S | modules/foundation/dns/mod.rs | 600
MAX_ZONE_RRS | modules/foundation/dns/mod.rs | 64
MAX_ZONE_RRS | modules/foundation/dns/mod.rs | 16
MAX_UPDATE_RRS | modules/foundation/dns/mod.rs | 32
MAX_ZONE_NAME | modules/foundation/dns/mod.rs | 128
MAX_ZONE_RDATA | modules/foundation/dns/mod.rs | 128
MAX_UPDATE_KEYS | modules/foundation/dns/mod.rs | 4
MAX_TSIG_FUDGE_S | modules/foundation/dns/mod.rs | 300
MAX_TXN_CACHE | modules/foundation/dns/mod.rs | 4
TXN_RETAIN_MS | modules/foundation/dns/mod.rs | 30000
MAX_COMMIT_WRITES | modules/foundation/dns/mod.rs | 64
MAX_OPEN | modules/foundation/mount/mod.rs | 64
MAX_LAYERS | modules/foundation/ota_registry/mod.rs | 48
MAX_DMA_MAPS | modules/foundation/smmu/mod.rs | 32
MAX_SHADOW_SLOTS | modules/foundation/quic/continuity.rs | 2
CHECKPOINT_RECORD_MAX | modules/foundation/quic/continuity.rs | 16384
ARP_WAIT_MAX | modules/foundation/ip/mod.rs | 64
RX_DESC_COUNT | modules/drivers/rp1_gem/mod.rs | 192
FAN_FRAMES_PER_STEP | src/kernel/exec/scheduler/module_types.rs | 64
ALLOC_SCAN_SLICE | modules/foundation/ip/mod.rs | 256
SWEEP_SLICE_MAX | modules/foundation/ip/mod.rs | 1024
MAX_TCP_SHADOWS | modules/sdk/abi/config.rs | 8
MAX_TCP_SHADOWS | modules/sdk/abi/config.rs | 2
MAX_TCP_SHADOWS | modules/sdk/abi/config.rs | 1
FENCE_WIRE_WAIT_MS | modules/foundation/ip/mod.rs | 500
NET_OUT_FRAME_MAX | modules/foundation/ip/mod.rs | 9
MAX_TLS_SHADOWS | modules/foundation/tls/continuity.rs | 2
MAX_TLS_SHADOWS | modules/foundation/tls/continuity.rs | 1
TLS_CKPT_RECORD_MAX | modules/foundation/tls/continuity.rs | CKPT_FIXED_LEN + RECV_BUF_SIZE + RETX_BUF_SIZE + TLS_SEALED_LEN
TX_HOLD_SIZE | modules/foundation/tls/continuity.rs | TX_HOLD_RECORDS * WIRE_RECORD_MAX
LOCAL_PN_BLOCK | modules/foundation/quic/connection.rs | 4096
STEP_BUDGET_DEFAULT_TICK_US | tools/src/target_facts.rs | 1000
```
