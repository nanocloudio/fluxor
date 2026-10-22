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

## Profiles

The deployment classes a per-profile ceiling can belong to. Each label names the
`cfg` predicate that selects it, and the gate derives every declaration's profile
by mapping the predicates that actually guard it — composing an enclosing
`mod profile_*`'s with the declaration's own — through this table.

Declared here rather than built into the gate because these are the project's own
deployment classes; a gate that invented the names would be asserting a
vocabulary nobody agreed to. A predicate with no label FAILS, so a new silicon or
feature split cannot arrive with its limits undescribed.

A row's profile field joins labels with `+` (`embedded+rp2040`), and `*` means the
declaration is unconditional.

```limit-register-profiles
host         | target_arch = "aarch64"
wasm         | target_arch = "wasm32"
embedded     | not(any(target_arch = "aarch64", target_arch = "wasm32"))
large-config | any(target_os = "linux", target_arch = "wasm32", target_arch = "aarch64")
small-config | not(any(target_os = "linux", target_arch = "wasm32", target_arch = "aarch64"))
rp2040       | fluxor_abi = "thumbv6m"
rp2350       | not(fluxor_abi = "thumbv6m")
multitenant  | feature = "multitenant"
linux-multitenant | all(feature = "multitenant", feature = "host-linux")
multitenant-non-linux | all(feature = "multitenant", not(feature = "host-linux"))
single-owner | not(feature = "multitenant")
chip-rp2040  | feature = "chip-rp2040"
rp           | feature = "rp"
non-rp       | not(feature = "rp")
rp-small     | any(feature = "chip-rp2040", feature = "chip-rp2350b")
kernel-vm    | feature = "kernel-vm"
no-kernel-vm | not(feature = "kernel-vm")
rp2350-chip  | all(feature = "rp", not(feature = "chip-rp2040"))
rsa-vault    | feature = "rsa-vault"
off-host     | not(target_arch = "aarch64")
linux        | feature = "host-linux"
non-linux    | not(feature = "host-linux")
bcm2712      | feature = "chip-bcm2712"
boot-sized   | any(feature = "host-linux", feature = "chip-bcm2712")
static-tables | not(any(feature = "host-linux", feature = "chip-bcm2712"))
wasm-kernel  | feature = "host-wasm"
rp-large     | all(not(target_arch = "aarch64"),not(feature = "chip-rp2040"),not(feature = "chip-rp2350b"),)
```

## Kernel capacity is not ABI

The kernel's own capacity — `STATE_ARENA_SIZE`, `BUFFER_ARENA_SIZE`,
`MAX_MODULE_CONFIG_SIZE` (RP only), `LOG_RING_CAPACITY`, `ELASTIC_REGION_SIZE`,
`HEAP_SEGMENTS`, `MAX_MODULES`, `MAX_BRIDGES`, `MAX_MODULE_CODE_SIZE` —
is stated in `src/kernel/config.rs`, one profile per kernel platform
(`profile_linux`, `profile_bcm2712`, `profile_wasm`, `profile_rp`; the RP
arenas come from the silicon TOML through `platform::chip`). It is never
restated under `modules/sdk` or `contracts/src`: those trees are hashed into
the ABI-surface digest, so a kernel size there turns raising it into an ABI
epoch and a workspace republish although no module reads it. Raising one of
these is a kernel rebuild and a row edit here — nothing more: the composer
reads the profiles as data (`tools/src/capacity.rs` embeds
`src/kernel/config.rs`), so its figures follow on the tools rebuild.

A module that needs a kernel figure asks at runtime — the module-slot count is
`internal::reconfigure::SLOT_CAPACITY` — or scales its own buffers by the SDK's
coarse `abi::config::TARGET_CLASS` (`TINY`, `SMALL`, `HOST`).
A tools gate (`kernel_capacity_gate`) fails if a kernel capacity constant
reappears in the srcpin's file set or in module source. Linux and bcm2712 are
separate profiles, so a hosted Linux kernel is not bound to a Pi 5's linker
regions; on bcm2712 `linker/memory-bcm2712.x` asserts the kernel's RAM ends
below the firmware's region at `0x2E00_0000`.

## Constraints

Values are only half of a resource envelope. `MAX_SESSIONS` being 512 and
`MAX_TCP_CONNS` being 65536 are both true, both checked above, and neither says
that the first must not exceed the second — so a tuning pass that lowered the
connection table below the session table would break an invariant no row covers.

These relations are exactly what gets missed when sizes are retuned per silicon,
because a retune moves many numbers at once and the constraint between two of
them is nobody's edit. Recording them here makes the couplings a list a reviewer
can read, and the gate checks each one is still ENFORCED — not merely still
described.

Two forms:

- `relation | <source path>` — the relation must be the CONDITION of an
  `assert!` in that file. Not its message: a coupling stated in an assert's
  failure text reads convincingly while enforcing nothing.
- `relation | derived` — for a relation no single compilation can see, where both
  sides are register rows named `NAME@path`. Two PIC modules on one channel
  cannot assert about each other's constants, so the check is that both sides
  have the same recorded right-hand side. Identical derivation is stronger than
  the inequality it stands in for.

```limit-constraints
tls::MAX_SESSIONS <= ip::MAX_TCP_CONNS | modules/sdk/abi/config.rs
http::MAX_CONCURRENT_CONNS <= ip::MAX_TCP_CONNS | modules/sdk/abi/config.rs
ip::MAX_DG_ENDPOINTS <= ip::MAX_TCP_CONNS | modules/sdk/abi/config.rs
ip::MAX_TCP_CONNS <= 65536 | modules/sdk/abi/config.rs
ip::MAX_LOCAL_ADDRS <= 4096 | modules/sdk/abi/config.rs
http::ARENA_WORKING_SET_CONNS <= http::MAX_CONCURRENT_CONNS | modules/sdk/abi/config.rs
tcp::MSS as usize + 14 + 20 + 20 <= MAX_FRAME_SIZE | modules/foundation/ip/mod.rs
MAX_PACKET_HOLD <= (1usize << abi::contracts::net::packet::PKT_SLOT_BITS) | modules/foundation/ip/mod.rs
CAPACITY >= PSTATUS_ROUND | src/kernel/sys/telemetry_ring.rs
```

## Identifier widths

| Id | Width | Ceiling | Symbol | Source | Value | Binds instead / notes |
|---|---|---|---|---|---|---|
| TCP/HTTP `conn_id` (net-proto wire) | u16 LE | 65535 | `MAX_TCP_CONNS` | modules/sdk/abi/config.rs | 65536 | The host table is exactly the id space (ids 0..65535); 256 on wasm, 8 on embedded. A record is ~2.2 KiB, most of it the bounded reorder buffer. The host table is backed lazily (`ip/conn_arena.rs`): the first 512 records live inline in module state (~1.1 MiB) and further records come in 256-record chunks from the kernel elastic region as connections arrive, so a slot number is bounded by the records backed, never by the ceiling, and the whole table is never committed. Lookup is by hash index (`ip/index.rs`) whose removals close their holes and whose hash is seeded per instance, so a packet pays for the cluster it lands in rather than for the table — a miss included — and the timer sweep is sliced across its 50 ms window |
| datagram/packet `ep_id` (DG/PKT wire) | u8 | 256 | `MAX_DG_ENDPOINTS` | modules/sdk/abi/config.rs | 256 | Endpoints are allocated only from the first `MAX_DG_ENDPOINTS` connection slots, so the u8 id binds the endpoint count, not the table. TCP prefers the slots beyond that window and takes it only when the rest is full |
| local-address slot (`TcpConn::local_slot`) | u16 | 65535 | `MAX_LOCAL_ADDRS` | modules/sdk/abi/config.rs | 4096 | `0xFFFF` is the wildcard slot. Demux is by hash index; 8 on wasm and embedded |
| decision-seam hold (`pkt_id` slot) | u16 | 65535 | `MAX_PACKET_HOLD` | modules/sdk/abi/config.rs | 32 | One full frame per slot; an arrival past it is refused and counted, never displaces a held packet. 8 on wasm, 4 on embedded |
| workload lane (`ip` provider, `workload::NET_PROVIDE`) | u8 | 255 | `LANE_CEILING` | src/kernel/workload/net_attach.rs | 255 | The provider states its lane capacity when it claims the role (`ip` param `lanes`), and the kernel sizes its lane tables to it — carved on bcm2712, allocated on Linux — keeping `max(previous, stated)` across rebuilds; an attach past it is `ENOSPC`. The `u8` lane id is the ceiling; the static profiles (wasm, RP) hold `STATIC_LANES` |
| contract class (`required_caps` bitmask, fmod header) | u64 bit position | 64 | `MAX_CONTRACTS` | src/kernel/module/provider.rs | 64 | One number for three roles: vtable index, opcode class byte, and bit position in the header's `required_caps`. Registration past the ceiling is refused EINVAL, and a dispatch id at or past it is refused ENOSYS by `check_contract_grant` before either capability gate |
| contract-class positions consumed | — | 64 | `CONTRACT_ID_POSITIONS_ASSIGNED` | tools/src/manifest.rs | 32 | Counts the four reserved ids, excludes the kernel-internal dispatch bucket. Highest allocated is `NET_ROUTE` = 0x20, leaving 0x21–0x3F (31 positions) free. The tools-side mirror of the space, `CONTRACT_ID_SPACE`, holds the same width as the kernel's `MAX_CONTRACTS`: an id outside it is unrepresentable in the header mask and unregisterable as a vtable |
| permission category (fmod header) | u16 bitfield | 16 | — | src/kernel/module/loader.rs | — | 9 of 16 bits assigned (`observe` = bit 8); widening changes the module header layout |
| module index (`ModuleId`: exec order, owners, fault ids, wire fields) | u16 | 65535 | `MAX_MODULES` | src/kernel/config.rs | 4096 | `0xFFFF` is `NO_MODULE`, the no-owner sentinel. On Linux this is the module-index DOMAIN, format-bound: the config blob carries a module id in 12 bits (low byte plus four spare bits of entry byte 9) and a `ModuleMask` holds one bit per index, while the scheduler's per-module tables are sized at boot from the graph — its modules, fans and resident workloads plus the `module_slots` reserve (`resource_ledger::plan`) — and grown a segment at a time by live adds; a plan past the domain is refused at boot naming `module_slots`. On bcm2712 and RP the same domain, with the tables sized from the plan within it (1024 on bcm2712, carved from the device tree's DRAM; 32 on RP, from the kernel's static pool); on wasm, the static table, 48. The telemetry ring holds one PSTATUS round of it. Kernel capacity, not ABI: modules read the live slot count at runtime (`internal::reconfigure::SLOT_CAPACITY`). Asserts: `src/kernel/boot/config.rs` and `src/kernel/config.rs` (fits the blob's 12 bits), `src/kernel/exec/scheduler/mod.rs` (below the sentinel) |
| channel buffer slot | i16 (−1 sentinel) | 32768 | `MAX_BUFFER_SLOTS` | src/kernel/ipc/buffer_pool.rs | — | Derived, not chosen: one slot per channel (`MAX_CHANNELS`), so the two cannot drift. `ChannelSlot.buffer_slot` holds a single id and every allocation takes its owning channel, so a slot past the channel table is unreachable and a pool short of it leaves the table's upper range unallocatable — `channel_open` refusing while slots are free. The buffer arena binds first by orders of magnitude |
| owner slot | u16 | 65535 | `MAX_OWNERS` | src/kernel/workload/owner.rs | 4096 | On Linux the owner-slot DOMAIN: the owner table and every per-owner table beside it (log rings — one 64 KiB ring allocated when its owner is created and freed with it —, code-pack regions, graph-workload slots, host-process sandboxes and workload slots) are sized at boot to the `owners` ceiling, the system slot plus the resident workloads plus the owner reserve (`resource_ledger::plan`, `size_kernel_tables`); a plan past the domain is refused at boot naming `owners`. The domain is bound by the host-process workload index, which shares the workload fd slot space with the graph backend's above `0x1000` (`GRAPH_SLOT_BASE`), not by the `u16` slot every wire field carries. 64 on bcm2712, the same domain, with the table carved from the device tree's DRAM. The default owner reserve (63) takes only what the domain leaves beside the system slot and the resident workloads, so a graph that fits the domain boots on the default; an explicit `capacity: { owners }` past it is refused (the composer runs the boot plan and refuses it at build). 1 single-tenant. Const-asserted ≤ `u16::MAX` |
| HTTP request path length | u16 | 65535 | `MAX_PATH` | modules/sdk/abi/config.rs | 200 | The wire field is u16; the 200-byte budget is pure memory policy |
| content-type position | u8 append-only | 256 | — | contracts/src/lib.rs | — | Vocabulary discipline; parallel tables are locked together by const asserts |

## Deliberate caps

| Cap | Symbol | Source | Value | Reason |
|---|---|---|---|---|
| Exchange record | `RECORD_MAX` | modules/sdk/contracts/exchange.rs | 8192 | Policy: the largest record either side of an exchange writes, and so one channel record — what an `ExchangeRequest` or `ExchangeResponse` port declares as `max_record`. A body of any size crosses as many records under credit, so this bounds a reader's buffer, never a request or an answer |
| Exchange collected body | `PAYLOAD_MAX` | modules/sdk/contracts/exchange.rs | 8192 | Policy: the largest body a provider that takes requests whole collects, and the one ceiling every provider of `stream.ordered_ack` derives from, so a requester has a number it can hold itself to. A per-provider ceiling is undiscoverable by the requester that must stay under it. A provider whose backend cannot take the full size declares the smaller number as its `max_payload` capability fact, which the build checks against the requester's own `max_payload` fact |
| Exchange ordering key | `KEY_MAX` | modules/sdk/contracts/exchange.rs | 512 | Policy: the largest `target` a publish carries — a table or topic identifier plus a 256-byte natural key, with room for requesters whose ordering unit is wider. The key is the ordering unit and is opaque to the provider |
| Telemetry ring capacity | `CAPACITY` | src/kernel/sys/telemetry_ring.rs | 4096 | Policy, per target family: 4 KiB on RP2040, 8 KiB on RP2350, and elsewhere one PSTATUS round rounded up to a power of two and never under 32 KiB (512 KiB on the 4096-index module domain of linux, 128 KiB on the 1024 module slots of bcm2712). A const assert holds it at or above one whole PSTATUS round — the scheduler emits a round as one uninterrupted burst, so a ring under that size drops the tail of *every* round and the high-index modules never report at all |
| Block buffers lent at once | `MAX_LENDS` | src/kernel/module/block_lend.rs | 128 | Policy: the kernel's ledger of buffers lent to `storage.block` sources, across every consumer. Deeper than any source's queue (nvme holds 8 per queue) so it only binds on a runaway consumer; a `SUBMIT` past it is `EAGAIN` before the source sees it |
| Torn-down modules awaiting their lends | `MAX_QUARANTINED` | src/kernel/module/block_lend.rs | 8 | Policy: modules torn down while a source still holds a buffer lent from them, whose memory is kept until the source returns it. Past it the memory stays lent and is not released (a leak, never a corruption) |
| Channels closed on a quarantine's behalf | `MAX_ADOPTED` | src/kernel/module/block_lend.rs | 16 | Policy: channels carrying a lend of a torn-down module, closed once the lends are back. Past it a channel stays open |
| Telemetry drain slots | `RING_CONSUMERS` | modules/sdk/contracts/telemetry.rs | 4 | Policy: the console exporter, one `otel` engine per export destination, and a spare. It is wire-visible — a `TLM_STATS` reply is `[head][dropped × RING_CONSUMERS]` — so a caller sizes its buffer from it and widening is an ABI change, not a tuning knob |
| Telemetry record | `TELEMETRY_MAX_RECORD` | src/kernel/exec/scheduler/module_types.rs | 144 | Derived, not chosen: the widest record kind, a 16-bucket histogram metric. The ring reserves atomically at this size and rejects anything larger whole, so a value below the true maximum silently bounces every wider emit at the syscall rather than failing loudly |
| Instrument dimension cardinality | `DIM_MAX_PRODUCT` | modules/sdk/contracts/telemetry.rs | 65534 | Policy: the product of one instrument's declared dimension domains, enforced at build so every composite index stays below the reserved `DIM_OTHER` (`0xFFFF`). Cardinality is a declared resource bound — an instrument that would exceed it shrinks a domain rather than discovering the ceiling at runtime |
| Single module code segment | `MAX_MODULE_CODE_SIZE` | src/kernel/config.rs | 1048576 | Sanity bound: catches a corrupt or runaway blob, not a budget; 393216 on RP2040. Code runs in place from flash on RP parts, so it is set by the part's flash; `module_code_kb` in the silicon TOML mirrors it and the packer refuses a module over it |
| Whole modules blob | `MAX_MODULES_BLOB_SIZE` | src/kernel/module/loader.rs | 8388608 | Sanity bound: a boot-image module table past this is refused at load |
| OTA staging area (per A/B stage) | `STAGE_CAPACITY` | src/kernel/module/ota_stage.rs | 8388608 | Policy: a graph image larger than one stage is refused ENOSPC at stage write |
| Module state arena | `STATE_ARENA_SIZE` | src/kernel/config.rs | 1073741824 | Policy: it must hold every module of the busiest graph at once, with headroom. A node hosts workload subgraphs beside its own graph in the same pool: a bare-metal node's control plane seats ~253 MiB, and one key-value workload's state worker asks 15-23 MiB. On bcm2712 this is the figure the graph builder plans against (a 2 GB Pi 5's DRAM above 1 GB, QEMU's upper GB at `-m 2G`); the arena itself is sized at boot from the device tree — the largest reservation-free DRAM zone above the boot image (above 1 GB on the Pi 5, clear of the firmware's top-of-first-GB reservation and the DTB and initramfs near 0x2E00_0000), less the kernel tables carved from its top — so a larger board gets a larger arena, all of its DRAM above the floor (the arena's free lists hold `usize` offsets, and an envelope's arena entry is exact bytes below 2 GiB and KiB past it, `resource::decode_entry`); the `ip` connection table holds its first 512 records inline (~1.1 MiB) and backs the rest from the elastic region, so no single module approaches the arena. On RP (240 KiB on rp2350, 64 KiB on rp2040, from the silicon TOML) it is the figure the composer admits a graph's module state against; the arena itself is what the kernel's static pool (`KERNEL_POOL_SIZE`) holds beside the graph's tables and buffer arena, at least this for every graph the composer admits, and a `capacity: { state_arena }` entry past it is refused at boot naming `state_arena`. It costs no image bytes and is never zeroed whole: on Linux a freed region is returned to zero as it is freed, so no allocation zeroes; on wasm and RP an allocation zeroes only what lies below the arena's clean mark; on bcm2712 a zeroed frontier advanced in the domains' slack (`ZERO_AHEAD_BYTES`) keeps zeroing off the module step. Exhaustion is refused at module load, not at the allocation that overruns |
| Single channel ring | `MAX_RING_BYTES` | src/kernel/ipc/ring_size.rs | 4194304 | Sanity bound on one ring's share of the buffer arena. A request above it is refused, never clamped — by the composer at build, the scheduler at graph preparation and `channel_open` at runtime, all from this one definition — since a producer sized for a ring it does not get wedges under load |
| QUIC endpoint connections | `MAX_CONNS` | modules/sdk/abi/config.rs | 64 | Policy: ~58 KiB of state per slot on a bcm2712-only module — ~3.6 MiB for the table, the dominant term in the module's footprint and paid resident, since the table is a field of the module state rather than an elastic pool. ~13 KiB of a slot is handshake scratch idle once the connection is established; the remaining ~45 KiB is state a live connection needs, so unlike the TLS ceiling this one is not mostly scratch. A connection past the ceiling receives a stateless CONNECTION_REFUSED so it fails in one round trip rather than hanging, and a Closed slot recycles with a fresh ephemeral |
| TLS sessions | `MAX_SESSIONS` | modules/sdk/abi/config.rs | 512 | Policy: the ceiling on concurrent TLS connections and so on HTTPS concurrency — an accept the tls module cannot seat is closed before http sees it. A seat is ~13 KiB, of which ~12 KiB is handshake scratch resident for the session's whole life; 512 seats are 63 granted chunks ≈ 7.9 MiB, drawn in 8-session chunks from the oversubscribable elastic region, so an idle stack pays only for the inline chunk. 1 inline on embedded: what the rp2350 arena holds beside the wifi stack. This bounds ONE instance and instances do not add up the way the number invites: a chunk asks ~104 KiB and rounds up to the 64 KiB grant quantum, so it takes 128 KiB, and the 16 MiB region holds 128 chunks — the same depth as the kernel's chunk table — for about 1,024 seats shared across every elastic pool on the host. Two saturated instances are already the region. Published in the profile so a consumer reads the envelope it has; `tls::MAX_SESSIONS <= ip::MAX_TCP_CONNS` is asserted at compile time |
| HTTP/2 streams per conn | `MAX_STREAMS` | modules/sdk/abi/config.rs | 4 | Policy: bounds per-connection stream state on every profile |
| HTTP route table | `MAX_ROUTES` | modules/sdk/abi/config.rs | 8 | Policy: a config declaring more routes is a compose-time error |
| Provider chain depth per contract | `MAX_CHAIN_DEPTH` | src/kernel/module/provider.rs | — | Policy, per-profile (3 RP2040 / 4 RP2350 / 8 aarch64-host); registration past the ceiling is refused EBUSY |
| Routed provider handles | `MAX_ROUTES` | src/kernel/module/provider.rs | — | Policy, per-profile (16 RP2040 / 32 RP2350 / 128 aarch64-host): handles minted through `provider_call_sel` that are open at once (one per file `mount` holds on a keyed volume, one per `file_block` image on `platform`). An open past it is closed at its provider and refused ENOMEM; at most 256, the width of the route index in the handle's slot |
| KEY_VAULT key slots | `MAX_SLOTS` | src/kernel/security/key_vault.rs | — | Policy, per-profile (64 aarch64 / 8 elsewhere): a slot is held per TLS session key, per mounted encrypted volume's data key, per attaching volume's recipient key, and per Clustor WAL or snapshot master key. Clustor segment subkeys are derived inside the operation that uses them and take no slot. Generate or import with no free slot is refused ENOMEM, and a consumer refuses its attach rather than falling back |
| PKCS#11 vault handles | `MAX_SLOTS` | src/platform/linux/hsm_key_vault.rs | 8 | Policy: token session objects one process holds through the Linux PKCS#11 backend. Separate from the kernel software vault's slots: each backend reports its own ceiling |
| Linux instance tag | `TAG_MAX` | src/platform/linux/instance.rs | 32 | Policy: the longest tag naming a runtime in the host registry. It rides whole in a link alias and in every policy-table name (`fx_<tag>_<name>`), both far longer, and is a file name in `/run/fluxor/`; 32 leaves room for a readable operator name or a digest |
| Linux link-name stem | `STEM_MAX` | src/platform/linux/instance.rs | 6 | Host fact: a link name has 15 characters (IFNAMSIZ less its NUL), and `fx` + stem + `w` + a two-digit sandbox slot must fit with room for a wider slot table. Two live tags may not share a stem (`EBUSY` at go-live), so the stem is what keeps their link names apart |
| Linux instance rule priorities | `RULE_PRIORITY_MAIN` | src/platform/linux/instance.rs | 32766 | Host fact: the host's `main` rule sits at 32766 and an instance's rule must come before it, so priorities are handed out from `RULE_PRIORITY_FIRST` (20000) up to it: 12766 live-or-uncollected instances on one host, then `ENOSPC` |
| KEY_VAULT RSA entries | `RSA_ENTRIES` | src/kernel/security/key_vault.rs | 2 | Policy: an RSA key is kilobytes of CRT material and Montgomery constants rather than the 64 bytes a slot carries, so RSA slots name one of two backend entries — an identity and its successor during a rotation. A third `STORE` is refused ENOMEM until one is destroyed. Behind the `rsa-vault` feature, about 22 KB of `.bss` with the signing job |
| RSA modulus width | `RSA_MODULUS_BITS_MAX` | modules/sdk/crypto/rsa.rs | 4096 | Policy: the widest key the core verifies or signs with. It sizes every buffer in the core and every job's step cost; no public issuer signs with more, and 8192 would double both for a key nothing presents |
| RSA public exponent width | `RSA_EXPONENT_BITS_MAX` | modules/sdk/crypto/rsa.rs | 32 | Policy: the exponent a public operation walks; 65537 needs 17 bits, and a key whose exponent is wider is refused rather than exponentiated at length |
| fat32 open files | `MAX_OPEN_FILES` | modules/foundation/fat32/mod.rs | — | Policy, per-profile (256 aarch64 / 8 elsewhere): a multi-tenant node runs several independent consumers against one volume at once, where a microcontroller's consumer set is fixed and each handle costs a scratch buffer. An open past the table is refused ENFILE, with a log line naming the handles that hold it. The `max_open_per_owner` parameter adds a per-owner ceiling on top, refusing the owner that is over its share while the table still has room, so the failure lands on the workload at fault rather than on whoever asks next |
| fat32 directory-walk budget | `DIR_SCAN_BUDGET_SECTORS` | modules/foundation/fat32/mod.rs | — | Policy, per-profile (32 aarch64 / 6 elsewhere, a quarter of `CACHE_SLOTS`): cached directory sectors one `provider_call` walks before returning EAGAIN with its position saved; a sector not cached parks the walk on it while its read lands. A walk pins the slots it touched for the rest of its call, so the budget leaves the rest of the cache to the commit that follows. A directory with thousands of entries is not exotic — a WAL that segments per snapshot fills one — so an unbounded walk is a latent stall of every module sharing the lane, not a slow path |
| fat32 long-name length | `LFN_MAX_CHARS` | modules/foundation/fat32/mod.rs | 64 | Policy: the format allows 255, but a buffer for that is carried in the directory cursor and in every wanted-name argument, on a board whose whole module state is measured against a 240 KiB arena. A longer name is refused at creation, not clipped. Names longer than this that were written elsewhere are still preserved and retired correctly — preservation walks the companion run without decoding it, so only matching and generation are bounded |
| fat32 free-cluster scan | `FAT_SCAN_BUDGET_SECTORS` | modules/foundation/fat32/mod.rs | 32 | Policy: FAT sectors one `provider_call` reads looking for a free cluster before returning EAGAIN with its cursor saved. Matches `DIR_SCAN_BUDGET_SECTORS` for the same reason — a synchronous device read inside a dispatch is charged to the cooperative step budget, and the FAT of a large volume is far too big to walk in one |
| fat32 walk time | `CALL_BUDGET_US` | modules/foundation/fat32/mod.rs | 400 | Policy: microseconds one `provider_call` or step spends walking a directory or the FAT before returning EAGAIN, alongside the two sector budgets. A sector count alone assumes a device speed, and one sector read costs from microseconds to milliseconds by device and power state. Every walk reads at least one sector per call, so a slow device still makes progress |
| fat32 outstanding fences | `MAX_FENCES` | modules/foundation/fat32/mod.rs | — | Policy: equals `MAX_OPEN_FILES`. A fence table smaller than the handle table would let a consumer open a handle it cannot fence, which reads as a durability failure rather than a resource limit. `FSYNC_SUBMIT` past the table is refused EAGAIN (backpressure) |
| fat32 sector cache | `CACHE_SLOTS` | modules/foundation/fat32/mod.rs | — | Policy, per-profile (128 aarch64 = 64 KiB / 24 elsewhere = 12 KiB): metadata sectors (FAT, directory, FSINFO, the rename intent record) held in memory. Every metadata read goes through it — a miss submits the read and the operation answers EAGAIN — and every metadata write lands in it, to be written back in epoch order. It must hold one call's working set: a walk's budget plus the largest commit (a rename's two directory sectors, their companions, the intent record twice, two FAT sectors and their copies) plus write-back not yet done. A slot it cannot find is a miss: the transaction aborts with nothing changed |
| fat32 taken operations | `FS_OP_SLOTS` | modules/foundation/fat32/mod.rs | 4 | Policy: operations answered EINPROGRESS and held at once (FSYNC_NAME, RENAME, TRUNCATE, PREALLOCATE; FSYNC is held per handle). A new one while all hold undecided operations is EAGAIN; an uncollected decision is dropped when a new one needs its slot |
| fat32 zero runs | `ZERO_RUN_SLOTS` | modules/foundation/fat32/mod.rs | 4 | Policy: sector ranges queued to be zeroed (a new directory cluster, a preallocated file's first sector), written from one zero buffer rather than through cache slots. A fifth before one completes is a miss: the operation answers EAGAIN |
| fat32 write-back window | `EPOCH_WINDOW` | modules/foundation/fat32/mod.rs | 56 | Policy: ordering epochs written but not yet behind the write-back at once. Below 64, so the durable-boundary bits never alias. Past it a new boundary is a miss (EAGAIN) until the device catches up |
| fat32 boundaries per transaction | `TX_BARRIER_MAX` | modules/foundation/fat32/mod.rs | 24 | Policy: ordering boundaries one transaction may close. Below `EPOCH_WINDOW`, so a transaction that misses on a full window always fits once the write-back drains and every transaction can commit. The largest real one (a rename that grows its directory) takes about a dozen; work that would need more — a large `clear_free_region` — runs as transactions of one FAT sector each. One that asked for more would be refused E2BIG, never retried for ever |
| fat32 taken-request argument | `OP_ARG_MAX` | modules/foundation/fat32/mod.rs | 512 | Policy: argument bytes a taken (EINPROGRESS) request keeps whole, so a re-ask is matched exactly and no request is ever handed another's decision. RENAME's two length-prefixed 254-byte paths fill it; a longer argument is refused E2BIG at once |
| nvme channel write pipeline | `MAX_INFLIGHT` | modules/drivers/nvme/mod.rs | — | Policy, per-profile (32 aarch64 / 8 elsewhere): writes in flight per I/O queue on the channel write path, each holding one 4 KiB DMA page. The command-id layout carries the slot in `CID_SLOT_BITS`, which moves with it |
| nvme block requests in flight | `V1_SLOTS` | modules/drivers/nvme/mod.rs | 16 | Policy: `storage.block` requests one namespace holds between `SUBMIT` and `REAP`, each with its own command id and 4 KiB DMA page. It is the `queue_depth` the source reports. They share I/O queue 0 with the channel pipeline, the bulk ring and the synchronous paths, and the sum stays below `IO_Q_ENTRIES` |
| nvme preflush flushes in flight | `V1_FLUSH_SLOTS` | modules/drivers/nvme/mod.rs | 4 | Policy: Flushes the `F_PREFLUSH` requests of one namespace can have outstanding at once, each its own command identifier. Past it a preflush request is `EAGAIN` before anything is submitted, so a retry never reuses an identifier still on the controller |
| nvme I/O queue pairs | `MAX_IO_QUEUES` | modules/drivers/nvme/mod.rs | 4 | Policy: submission/completion queue pairs created at bring-up; the channel write pipeline stripes across them and every other path runs on queue 0 |
| nvme blocks per command | `MAX_NLB` | modules/drivers/nvme/mod.rs | 8 | Sanity bound: one PRP1 page of 512-byte sectors, so no command needs a PRP list on the channel and synchronous paths |
| nvme pager bulk ring | `ASYNC_BULK_SLOTS` | modules/drivers/nvme/mod.rs | 8 | Policy: pager bulk commands in flight, each owning `MAX_BULK_PAGES` of contiguous DMA |
| nvme held completions | `HELD_MAX` | modules/drivers/nvme/mod.rs | 8 | Policy: completions a synchronous request takes off queue 0 and holds for their owner (a stream read's) to reach its own behind them; past it the request waits for the owner to consume them |
| nvme pager bulk transfer | `MAX_BULK_PAGES` | modules/drivers/nvme/mod.rs | 32 | Policy: 4 KiB pages one pager bulk command moves through its PRP list (128 KiB) |
| file_block requests in flight | `QUEUE_DEPTH` | modules/foundation/file_block/mod.rs | 8 | Policy: requests a `SUBMIT` has queued — waiting, running, or done and awaiting `REAP`; the queue depth the source reports. A `SUBMIT` past it is refused EAGAIN |
| file_block blocks per request | `MAX_BLOCKS` | modules/foundation/file_block/mod.rs | 64 | Policy: bounds the file I/O one request's resumable job moves |
| file_block image path | `PATH_CAP` | modules/foundation/file_block/mod.rs | 96 | Policy: the longest image path the `path` parameter holds; a longer one is truncated at parse and fails to open |
| file_block fs volume name | `VOLUME_CAP` | modules/foundation/file_block/mod.rs | 16 | Policy: the longest selector the `volume` parameter holds; a longer one is refused at open (EINVAL), never clipped into another provider's name |
| crypt_block authentication unit | `MAX_UNIT` | modules/foundation/crypt_block/mod.rs | 4096 | Policy: the largest authentication unit, which sizes the module's unit, ciphertext and journal-header scratch buffers |
| crypt_block lower block | `MAX_LOWER_BLOCK` | modules/foundation/crypt_block/mod.rs | 4096 | Policy: the largest lower logical block the metadata read-modify-write buffer holds; a larger lower device is refused at mount |
| crypt_block requests awaiting reap | `QUEUE_DEPTH` | modules/foundation/crypt_block/mod.rs | 8 | Policy: completions a `SUBMIT` queues for `REAP`; the queue depth the source reports |
| crypt_block journal records | `MAX_JOURNAL_RECORDS` | modules/foundation/crypt_block/mod.rs | 64 | Policy: journal records indexed in memory until they are home (half the largest journal). A full journal runs a flush cycle before the next write |
| crypt_block nonce reservation | `NONCE_STRIDE` | modules/foundation/crypt_block/mod.rs | 1048576 | Policy: nonce sequences reserved per superblock write. A restart abandons the unused rest of a range, so the stride trades superblock writes against wasted sequences out of 2^64 |
| crypt_block key label | `KEY_LABEL_CAP` | modules/foundation/crypt_block/mod.rs | 64 | Mirrors the vault's `MAX_LABEL` |
| crypt_block rotation batch | `MIGRATE_BATCH` | modules/foundation/crypt_block/mod.rs | 8 | Policy: units a data-key rotation re-seals, or metadata blocks its retirement scan reads, in one module step; bounds the rotation's share of a step while the volume stays mounted |
| crypt_block engine pump | `STEP_BUDGET` | modules/foundation/crypt_block/mod.rs | 4096 | Policy: lower requests and operation resumptions one pump of the lower-I/O engine runs before it yields to the next step. Above a whole upper request over a source that completes inline (a full journal cycle at one lower block per request), so `EXEC` over such a source still completes in its call; a format or erase of a large device spans steps |
| crypt_block operation nesting | `MAX_FRAMES` | modules/foundation/crypt_block/mod.rs | 5 | Implementation: resumable operations under way at once — a request, the unit write it makes, the journal cycle that write needs, the metadata write in that — with one to spare; a deeper call fails `EIO` rather than overrunning |
| nbd_serve chunks in flight | `MAX_SLOTS` | modules/foundation/nbd_serve/mod.rs | 8 | Policy: buffer slots, and so block requests one NBD client keeps in flight to the source; the `queue_depth` parameter and the source's reported depth can only lower it. Each slot is `SLOT_SIZE` of module state |
| nbd_serve chunk size | `SLOT_SIZE` | modules/foundation/nbd_serve/mod.rs | 16384 | Policy: the largest block request one NBD read or write is split into (lower when the source's `max_blocks` is). Larger NBD requests stream through the pool chunk by chunk; a source block larger than a slot is not published |
| nbd_serve NBD requests admitted | `MAX_REQUESTS` | modules/foundation/nbd_serve/mod.rs | 16 | Policy: NBD requests held between their header and their reply. A client past it is not read until one is answered, so TCP backpressure holds it |
| nbd_serve largest request | `MAX_REQUEST_BYTES` | modules/foundation/nbd_serve/mod.rs | 33554432 | Policy: ceiling on the `max_request` parameter, the NBD protocol's customary 32 MiB maximum payload. A read or write past `max_request` is refused EINVAL (a write's payload is drained, not buffered) |
| nbd_serve export name | `EXPORT_NAME_CAP` | modules/foundation/nbd_serve/mod.rs | 64 | Policy: the longest `export` parameter; a client naming anything else is refused |
| nbd_serve option payload | `OPT_BUF_SIZE` | modules/foundation/nbd_serve/mod.rs | 512 | Policy: the longest handshake option parsed; a longer one is drained and refused (`ERR_TOO_BIG`, or a close for `EXPORT_NAME`, which has no error reply) |
| nbd_serve reply frame | `OUT_DATA_MAX` | modules/foundation/nbd_serve/mod.rs | 4096 | Policy: reply bytes in one `CMD_SEND`; below `net_proto::MAX_CMD_DATA` and a sixteenth of the 64 KiB `net_out` buffer the manifest asks for |
| nbd_serve frames read per step | `STEP_FRAME_BUDGET` | modules/foundation/nbd_serve/mod.rs | 16 | Policy: transport frames (at most 1460 payload bytes each) one step parses, bounding the payload a step copies into slots |
| nbd_serve frames sent per step | `STEP_SEND_BUDGET` | modules/foundation/nbd_serve/mod.rs | 16 | Policy: reply frames one step writes |
| nbd_serve completions per step | `STEP_REAP_BUDGET` | modules/foundation/nbd_serve/mod.rs | 16 | Policy: completions one step reaps from the source; covers `MAX_SLOTS` twice |
| static-profile workload lanes | `STATIC_LANES` | src/kernel/workload/net_attach.rs | 16 | Policy: the lanes the kernel's static lane table holds where tables are not sized at boot (wasm); a provider stating more is refused `ENOSPC`. Linux and bcm2712 size the table to what the provider states (0 there: no static table), and so does RP, carving it from the kernel's static pool, where the figure is only the table type's unused compiled size |
| OTA registry authority | `MAX_AUTHORITY_LEN` | modules/foundation/ota_registry/mod.rs | 128 | Policy: the `host[:port]` the puller dials and sends as `Host:`. A longer one is refused at construction, naming the parameter — a truncated authority would dial a different registry |
| OTA directive record | `DIRECTIVE_RECORD_MAX` | modules/foundation/ota_registry/mod.rs | 256 | Policy: the longest signed directive record one frame carries, the counter, a tag of `MAX_TAG_LEN` and the signature with room to spare. A larger frame is dropped whole by the reader and never parsed |
| TLS/DTLS peer certificate | `MAX_CERT_LEN` | modules/foundation/tls/mod.rs | 2048 | Policy: the longest single certificate the module retains — each trust anchor, and the leaf inside a configured chain. An anchor past it refuses the instance rather than being stored truncated, because a truncated certificate is one that verifies nothing |
| TLS/DTLS presented chain | `MAX_CERT_CHAIN_BYTES` | modules/foundation/tls/mod.rs | 3072 | Policy: the leaf plus whatever issuers it needs to reach the peer's anchor, as concatenated DER. A bare leaf is the one-element case |
| TLS/DTLS identity key | `MAX_KEY_LEN` | modules/foundation/tls/mod.rs | 2400 | Policy: a PKCS#1 RSAPrivateKey of 4096 bits with its CRT fields is about 2.4 KB, and a PKCS#8 P-256 key is under 200 bytes, so this admits the largest identity the module signs with |
| TLS expected DNS identity | `MAX_EXPECTED_DNS` | modules/foundation/tls/mod.rs | 64 | Policy: a DNS name may be 253 octets, but this profile's names are service names in a configured deployment and the buffer is per-instance module state on targets that count kilobytes |
| TLS expected URI SAN | `MAX_EXPECTED_URI` | modules/foundation/tls/mod.rs | 256 | Policy: a SPIFFE ID is a trust domain plus a path and runs longer than a hostname, so it gets its own bound rather than borrowing the DNS one and silently truncating |
| DTLS client authority | `DTLS_AUTHORITY_MAX` | modules/foundation/tls/mod.rs | 64 | Policy: the `host[:port]` a DTLS client dials, held as text until construction judges it. Longer is refused with the parameter named, because a truncated authority is a different peer |
| DTLS peer sessions | `MAX_PEERS` | modules/foundation/tls/mod.rs | 4 | Policy: a peer carries its own handshake driver and reassembly buffer, ~29 KiB on a 32-bit core; 1 on embedded, where the arena holds one beside the stream session |
| DTLS datagram payload | `DGRAM_MAX` | modules/foundation/tls/mod.rs | 1500 | Policy: one link MTU, so a DTLS record the module emits never relies on IP fragmentation to arrive |
| DTLS retransmit flight | `MAX_FLIGHT_RECORDS` | modules/foundation/tls/mod.rs | 8 | Policy: a full TLS 1.3 server flight is at most 5 records (ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished); 8 gives headroom for HelloRetryRequest and certificate-request flows |
| TLS compatibility CCS per session | `MAX_COMPAT_CCS` | modules/foundation/tls/mod.rs | 2 | Policy: a TLS 1.3 peer sends at most one, immediately after its first flight, and the second is slack for a HelloRetryRequest exchange. Beyond that a ChangeCipherSpec stream is work an unauthenticated peer can ask for |
| TLS inbound record buffer | `RECV_BUF_SIZE` | modules/foundation/tls/mod.rs | 16704 | Policy: a client-mode session pulling bulk data must buffer one full 16 KiB record or no record ever decrypts. 4096 on the small-SRAM targets, whose deployments are server-side with small inbound records |
| TLS retransmission window | `RETX_BUF_SIZE` | modules/foundation/tls/mod.rs | 4096 | Policy: the encrypted frames TLS has written to `cipher_out`, retained so `MSG_RETRANSMIT` replays them without re-encryption |
| TLS inbound frames per step | `TLS_INBOUND_DRAIN_BUDGET` | modules/foundation/tls/mod.rs | 8 | Policy: deliberately below `ip`'s 32 RX budget. A larger drain lengthens every step, which costs the latency-bound paths — single-connection keepalive throughput is 1/latency and handshakes are round-trip bound — and buys nothing once the queue is cleared each tick |
| TLS cleartext passthroughs | `MAX_PASSTHROUGH` | modules/foundation/tls/mod.rs | — | Derived, not chosen: `MAX_SESSIONS`. A server-mode instance relays each backend dial its clear-side consumer makes raw, keyed by the dial's full u16 conn id, and each such dial serves a front connection that holds a session. The table is resident at 4 bytes an entry — 2 KiB at 512 on aarch64, 4 bytes at 1 embedded — where an exact bitmap of the id space would be 8 KiB per instance. A server-mode `CMD_CONNECT_TO` that finds it full is refused `ENOMEM` on its own tag before anything goes upstream, so a completion always finds a free entry; an entry ends on `MSG_CLOSED`, `CMD_CLOSE`, an established `MSG_ERROR`, or a new connection under its id |
| QUIC peer authority | `MAX_AUTHORITY` | modules/foundation/quic/mod.rs | — | Policy: `MAX_PEER_NAME` plus `:65535`. The instance keeps one peer authority; a longer one is refused at construction |
| QUIC peer name | `MAX_PEER_NAME` | modules/foundation/quic/mod.rs | 64 | Policy: the longest DNS name a QUIC peer may be dialled by, and the SNI and `dNSName` the handshake checks. The datagram surface carries up to 253 bytes; the module sizes this for the state budget and refuses rather than truncates, because a clipped name verifies against the wrong certificate |
| QUIC peer certificate | `MAX_CERT_LEN` | modules/foundation/quic/mod.rs | 1024 | Policy: the per-certificate ceiling for the configured leaf and each trust anchor. An anchor past it, or a ninth anchor, marks the table refused and the instance declines to construct |
| QUIC configured ALPN list | `MAX_ALPN_CFG` | modules/foundation/quic/mod.rs | 64 | Policy: the comma-separated protocol tokens a graph configures (`mqtt,h3`); 64 bytes holds several names with their separators |
| QUIC resumption tickets | `MAX_TICKETS` | modules/foundation/quic/mod.rs | 4 | Policy: the client-side ticket cache. Each entry is bound to the authority that issued it, so the table holds a handful of recently dialled peers and the oldest is displaced rather than grown |
| QUIC transparent stream read | `TRANSPARENT_READ_MAX` | modules/foundation/quic/mod.rs | 1200 | Policy: the most one read of the no-ALPN byte stream takes from `app_in`, one packet's worth. It is read only while the stream's send buffer has room for a whole read, so `app_in` backs up rather than losing bytes |
| DNS pending forwarded queries | `MAX_PENDING` | modules/foundation/dns/mod.rs | 8 | Policy: with every slot live and unexpired, a new query is answered SERVFAIL rather than displacing accepted work |
| DNS configured host entries | `MAX_HOSTS` | modules/foundation/dns/mod.rs | 16 | Policy: `host=` parameters past the table are ignored at parse |
| DNS upstream authority length | `UPSTREAM_AUTHORITY_MAX` | modules/foundation/dns/mod.rs | 64 | Policy: the `host[:port]` an encrypted upstream is dialled at; a longer value refuses construction rather than dialling a truncated authority |
| DoH endpoint path length | `UPSTREAM_PATH_MAX` | modules/foundation/dns/mod.rs | 64 | Policy: RFC 8484 makes the path server-specific, so it is configured; a longer one refuses construction |
| DNSSEC signed-form buffer | `DNSSEC_SIGNED_MAX` | modules/foundation/dns/mod.rs | 4096 | Derived: the RRSIG RDATA without its signature, plus the RRset in canonical form. An answer whose signed form exceeds it cannot be checked and is not claimed as checked |
| DNSSEC trust anchors | `MAX_ANCHORS` | modules/foundation/dns/mod.rs | 4 | Policy: `dnssec_anchor` entries past the table are dropped at parse. Only the first anchor for a zone is consulted, so the table sizes distinct zones, not keys per zone |
| DNSSEC anchor RDATA | `MAX_ANCHOR_RDATA` | modules/foundation/dns/mod.rs | 1028 | Policy: flags, protocol and algorithm plus the key itself — wide enough for the RSA moduli in use; a longer anchor is dropped at parse |
| DNS domain name length | `MAX_NAME_LEN` | modules/sdk/contracts/net/dns_wire.rs | 255 | The RFC 1035 full-name ceiling; a longer QNAME is refused at parse. Distinct from the 63-byte per-label ceiling (`MAX_LABEL_LEN`) |
| DNS compression-pointer hops per name | `MAX_NAME_PTR_HOPS` | modules/sdk/contracts/net/dns_wire.rs | 16 | Sanity: pointers must also point backwards, so a cycle is refused by direction first; the hop bound is the second line. A name past it is malformed |
| DNS records examined per section | `MAX_SECTION_RRS` | modules/sdk/contracts/net/dns_wire.rs | 32 | Sanity: an upstream answer or UPDATE section claiming more is refused rather than walked |
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
| DNS zone-file calls per step | `MAX_ZIO_CALLS_PER_STEP` | modules/foundation/dns/mod.rs | 64 | Sanity: `fs` calls one step issues for the zone commit or recovery step machine; a run of short counts resumes on the next step rather than monopolising this one |
| DNS durable-update response echo | `PEND_Q_MAX` | modules/foundation/dns/mod.rs | — | Derived: header + the longest wire name + type and class — the zone section an UPDATE's held response repeats while its commit is undecided; a longer one (unreachable after parsing) is answered SERVFAIL at once |
| mount open handles | `MAX_OPEN` | modules/foundation/mount/mod.rs | 64 | Policy: an open past the router table is refused ENFILE |
| OTA image layers | `MAX_LAYERS` | modules/foundation/ota_registry/mod.rs | 48 | Policy: sized to the 48-module fleet profile; a larger manifest is refused whole |
| SMMU DMA map table | `MAX_DMA_MAPS` | modules/foundation/smmu/mod.rs | 32 | Policy: a map past the translation table is refused ENOMEM before any MMIO write |
| QUIC continuity shadow slots | `MAX_SHADOW_SLOTS` | modules/foundation/quic/continuity.rs | 2 | Policy: connections under CT_QUIC takeover at once, one per slot. Continuity is a control-plane event, not steady state, and each shadow stages a whole connection's worth of state; a PAIR_PREPARE past the free slots is refused `STATUS_NO_CAPACITY` |
| QUIC continuity checkpoint record | `CHECKPOINT_RECORD_MAX` | modules/foundation/quic/continuity.rs | 49152 | Sized, not chosen: holds the full serialized connection state — six bidi (4096 send + 1500 receive) and nine uni (256+256) stream buffers, the 1-RTT CRYPTO send buffer, the retained last-emitted packet, the sealed secret set, and the fixed header, with headroom. A checkpoint whose `total_len` exceeds it is refused `STATUS_NO_CAPACITY` at CHECKPOINT_BEGIN and the shadow is discarded |
| ARP-wait handshake list | `ARP_WAIT_MAX` | modules/foundation/ip/mod.rs | 64 | Policy: handshakes remembered as waiting on neighbour resolution, so an ARP reply retries exactly those rather than walking the connection table. A full list only defers the retry to the timer sweep's next slice |
| GEM RX descriptors | `RX_DESC_COUNT` | modules/drivers/rp1_gem/mod.rs | 192 | Policy: the burst the Pi 5 MAC absorbs between two driver steps; a step drains the whole ring. The platform DMA arena holds 256 buffers shared with the 64 TX descriptors. The rings are walked with free-running `u16` positions under a `position % count` index, and those positions wrap at the largest multiple of the ring size a `u16` holds rather than at 65,536 (`rp1_gem/ring.rs`), so the index stays continuous across the wrap and a size that does not divide 65,536 is safe |
| fan frames per step | `FAN_FRAMES_PER_STEP` | src/kernel/exec/scheduler/module_types.rs | 64 | Policy: whole frames a framed `_tee` or `_merge` moves in one step. A fan sits between a producer and its consumers, so this times the tick rate is the ceiling on every fanned port — `debug: to: net` fans the ip module's consumer ports, and every accept, delivery and send on that graph crosses one |
| free-slot rebuild slice | `ALLOC_SCAN_SLICE` | modules/foundation/ip/mod.rs | 256 | Policy: slots one step examines to rebuild the free stack when it is empty — the table is full, or a slot was released by a path that did not push it. Allocation is a pop; a SYN at the ceiling costs this slice once per step and is refused, never a walk of the table per SYN |
| timer-sweep slice | `SWEEP_SLICE_MAX` | modules/foundation/ip/mod.rs | 1024 | Policy: most connections one step of the sliced TCP timer sweep visits. The proportional slice visits a few hundred; after a stall the whole window is owed and this is the ceiling it meets — a full 65,536-record sweep in one step is a multi-millisecond, cache-missing step the guard would end the module for. The sweep lags a stall by at most 64 steps, and needs that many steps per 50 ms window to keep the timers on time: a tick of 780 µs or faster on the 65,536-record profile (the Pi 5 runs 100 µs) |
| TCP continuity shadow slots | `MAX_TCP_SHADOWS` | modules/sdk/abi/config.rs | 8 | Policy: connections a transport-continuity pair holds in flight on one ip instance — shadows staged for import plus flows being mirrored out. Each shadow is a connection record plus its checkpoint bytes, and takeover is a control-plane event, not steady state; a PAIR_PREPARE past the free slots is refused `STATUS_NO_CAPACITY`. 2 on wasm, 1 on embedded |
| fence wire wait | `FENCE_WIRE_WAIT_MS` | modules/foundation/ip/mod.rs | 500 | Policy: how long a fence holds its event for the driver's drain answer before reporting the ring hand-off instead. Longer than any transmit ring takes to empty at line rate; short enough that a coordinator waiting on the fence is not waiting on a hung driver |
| queued control frame | `NET_OUT_FRAME_MAX` | modules/foundation/ip/mod.rs | — | Derived: the largest frame an event queue holds, the peer report (`MSG_PEER`: the header and `net_proto::PEER_LEN`, 24 bytes). A larger frame is refused, never truncated |
| TLS continuity shadow slots | `MAX_TLS_SHADOWS` | modules/foundation/tls/continuity.rs | 2 | Policy: sessions under CT_TLS takeover at once on one instance, one per slot (1 on wasm, 0 on the MCU-class targets, which hold no standby). A shadow is a staging record plus the decoded checkpoint — about twice `TLS_CKPT_RECORD_MAX`, resident in module state — and takeover is a control-plane event, not steady state; a PAIR_PREPARE past the free slots is refused `STATUS_NO_CAPACITY` |
| ISR bridge slots | `MAX_BRIDGES` | src/kernel/config.rs | 16 | Policy: edges that cross into an ISR-tier domain, one bridge slot each with its ring inline (~2 KiB of kernel static RAM per slot). An edge past the ceiling loses its ISR routing and the graph fails at setup rather than corrupting. 8 on RP, where the die's stack is what the slots would take |
| TLS continuity checkpoint record | `TLS_CKPT_RECORD_MAX` | modules/foundation/tls/continuity.rs | — | Derived, not chosen: the fixed header plus the whole partial-inbound buffer (`RECV_BUF_SIZE`), the whole retransmission window (`RETX_BUF_SIZE`) and the sealed secret set — about 21 KiB where the receive buffer is 16 KiB, about 9 KiB on the 4 KiB targets. A CHECKPOINT_BEGIN whose `total_len` exceeds it is refused `STATUS_NO_CAPACITY` before any byte moves; the record is never truncated |
| TLS strict-profile send hold | `TX_HOLD_SIZE` | modules/foundation/tls/continuity.rs | — | Derived, not chosen: every record one `CMD_SEND` (`MAX_CMD_DATA` bytes) can produce, since the clear-side frame is consumed whole and each of its records must wait for its own send horizon — six records of `WIRE_RECORD_MAX`, about 9.3 KiB per session, paid in every session slot whether or not it is mirrored. A producer that exceeds the contract's frame ceiling fills the hold and the session fails rather than the record being dropped |
| QUIC 1-RTT self-grant block | `LOCAL_PN_BLOCK` | modules/foundation/quic/connection.rs | 4096 | Policy: the send packet-number block a connection self-grants in local (non-durable) mode, refilled `LOCAL_PN_REFILL_LOW` (512) values ahead of exhaustion so the reservation never stalls a healthy sender. Matches the directory's smoke-path reserve size; in durable mode the directory chooses the block |
| declared step cost (`[execution] max_step_us`) | `STEP_BUDGET_DEFAULT_TICK_US` | tools/src/target_facts.rs | 1000 | Policy: the scheduler's default pass budget (`DEFAULT_TICK_US`, one tick) on every silicon; a manifest whose step cannot fit one default pass on a target it names is refused at parse. Per-target in shape so a slower part can publish a smaller budget |
| early-boot log ring | `LOG_RING_CAPACITY` | src/kernel/config.rs | 65536 | Sized to cover boot until a consumer reaches its transport, and NOT raised past it: the whole ring is replayed in one burst when the consumer attaches, and on the Pi 5 rig a 256 KiB ring outran the collector's socket buffer, losing the oldest datagrams — the exact ones the replay exists to deliver. Growing this needs a paced replay first. Then per-profile because the ring is static `.bss` charged against the whole SRAM: 16 KiB on wasm, 8 KiB on the RP parts (the smallest that still holds a whole boot until a host opens the USB console), where a host-class ring is a quarter of an RP2040's linker RAM region and an eighth of an RP2350's, and on both pushes `.bss` past that region once the state and buffer arenas are placed beside it. The RP kernels take the figure from their silicon TOML (`[kernel] log_ring_kb`), which `profile_rp` re-exports, so there is one figure. A full ring drops new records rather than overwriting unread ones, and counts the drops |
| Capability chain length | `MAX_CHAIN_LINKS` | modules/sdk/contracts/mesh/capability.rs | 8 | Policy: the root's grant plus seven delegations. Every link is one Ed25519 verification and a chain is verified on every presentation, so this is what one presentation can cost a verifier. A longer chain is refused (`ChainTooLong`), never truncated |
| Capability chain bytes | `MAX_CHAIN_BYTES` | modules/sdk/contracts/mesh/capability.rs | 1026 | Derived, not chosen: `CHAIN_HDR + MAX_CHAIN_LINKS * LINK_LEN` — the largest chain a receiver must be able to hold |
| Capability roots per verifier | `MAX_ROOTS` | modules/sdk/contracts/mesh/capability.rs | 2 | Policy: the deployment's root and its successor during a rotation; a chain signed by either verifies |
| Grants per session | `MAX_SESSION_GRANTS` | modules/sdk/contracts/mesh/capability.rs | 8 | Policy: the verified grants one session holds at once. A presentation past it is refused (`GRANTS_FULL`) until one is withdrawn; nothing is evicted, because an evicted grant is an operation that silently starts failing |
| Capability presentation payload | `PRESENT_MAX` | modules/sdk/contracts/mesh/capability.rs | 1030 | Derived, not chosen: the presentation id plus `MAX_CHAIN_BYTES` |
| Capability text form | `MAX_TEXT_LEN` | modules/sdk/contracts/mesh/capability.rs | 1375 | Derived, not chosen: the prefix plus unpadded base64url of `MAX_CHAIN_BYTES` — what an HTTP header carrying a chain must admit. Written as its value and held to that derivation by a const assert |
| Object LIST page | `LIST_PAGE_MAX` | modules/sdk/contracts/storage/object.rs | 1000 | Policy: entries one `storage.object` `LIST` call may return — S3's own `MaxKeys` ceiling, and the bound on one call's work. A request outside 1..=1000 is `EINVAL` |
| Storage key and entry name | `STORAGE_KEY_MAX` | modules/sdk/contracts/storage/handle.rs | 255 | Wire width: the `u8` `name_len` and trailing `cursor_len` of a `storage.namespace` LIST page, so it is also the longest key a store creates, the longest cursor on both listing surfaces (the cursor is the last name returned), the longest `storage.object` LIST prefix, and what the gateway's argument copy is sized to carry. A provider meeting a longer name in a range it lists refuses the page `EOVERFLOW` rather than skip it. One bound for one concept: the Linux and `bcm2712` key stores size their keys by it directly |
| Namespace path | `PATH_MAX` | modules/sdk/contracts/storage/namespace.rs | 1024 | Policy: the longest `storage.namespace` LIST prefix or LOOKUP path. A path is not a name: a directory-shaped provider's prefix is a host directory at any depth, while each name below it stays within `STORAGE_KEY_MAX`. Namespace ops are not walked by the gateway, so the bound costs no gated stack |
| Private regions per gated module | `MAX_PRIVATE` | src/kernel/module/gateway.rs | 3 | Sanity bound: state, heap and stack on an MMU target; one combined region on an MPU target. A pointer a gated module passes must lie in one of them |
| Gateway argument copy | `WALK_MAX` | src/kernel/module/gateway.rs | 544 | Derived, not chosen: the largest walked request, an object `LIST` with a prefix and a cursor of `STORAGE_KEY_MAX` bytes each (`REQUEST_FIXED_LEN + 2 * STORAGE_KEY_MAX`, rounded up to 16). Stack-resident per gated call |
| Remote channels per instance | `MAX_CHANNELS` | modules/foundation/remote_channel/wire.rs | 8 | Policy: each channel is a port pair, a reassembly region, a send state and on `quic` a stream; the manifest declares eight port pairs. A longer table is refused at construction |
| Remote-channel content-type name | `CT_NAME_MAX` | modules/foundation/remote_channel/wire.rs | 32 | Sanity bound: longer than any name in the content-type registry; a longer name in `channels` is refused |
| Remote-channel table frame | `HELLO_MAX` | modules/foundation/remote_channel/wire.rs | 302 | Derived, not chosen: the whole channel table at `MAX_CHANNELS` entries of `CT_NAME_MAX` names, and the exchange endpoint's side byte |
| Remote-channel record | `MAX_RECORD` | modules/foundation/remote_channel/mod.rs | 262144 | Policy: the largest record any channel may declare — one record is reassembled whole before delivery, so this is the largest allocation a peer can make the module hold. Above a large body record with its frame (loam's 128 KiB frames). 128 KiB on wasm, 16 KiB on embedded. A larger declaration is refused at construction; a larger record is refused and counted |
| Remote-channel reassembly | `REASSEMBLY_BYTES` | modules/foundation/remote_channel/mod.rs | 1048576 | Policy: every channel's reassembly ring (`max_record + 4`) and, on a `mailbox` channel, its two record stages must fit; a table that does not is refused at construction rather than shrunk. 256 KiB on wasm, 32 KiB on embedded |
| Remote-channel fragment (`net`) | `FRAGMENT_MAX` | modules/foundation/remote_channel/mod.rs | 4096 | Policy: record bytes in one frame on a shared stream — how long one channel holds the stream before the next channel's turn |
| Remote-channel open exchanges | `OPEN_EXCHANGES_MAX` | modules/foundation/remote_channel/mod.rs | — | Policy, per target class (`abi::config::TARGET_CLASS`): 256 on host-class targets, 32 on MCUs. The exchanges a far endpoint has handed its provider without a terminal record yet — the ones it ABORTs when the session ends. A request HEAD past it is answered `503`, marked RAISED, and never reaches the provider |
| Remote-channel fragment (`mux`) | `MUX_FRAGMENT_MAX` | modules/foundation/remote_channel/mod.rs | 1192 | Derived, not chosen: a whole frame fits one `CMD_MUX_STREAM_SEND` (`MUX_QUIC_STREAM_SEND_MAX` less the frame header and record length), held to that by a const assert |
| Graph parameters | `MAX_PARAMS` | tools/src/params.rs | 64 | Policy: parameters one graph, stack or bundle may declare. A graph needing more is being configured through its internals rather than its run surface; the bound also bounds the checks every launch makes |
| Parameter value | `MAX_PARAM_STRING_BYTES` | tools/src/params.rs | 4096 | Policy: the longest string value from `--param` or `--params`; content belongs in a file the value names |
| Parameter name | `MAX_PARAM_NAME_BYTES` | tools/src/params.rs | 64 | Sanity bound on a declared parameter name |
| Grant scope | `SCOPE_MAX` | modules/sdk/contracts/storage/object.rs | 255 | Derived, not chosen: a scope is a key prefix, so it is bounded as keys are (`STORAGE_KEY_MAX`), held equal by a const assert. A longer scope is refused at `PRESENT` |
| Grants on a guarded store | `DEFAULT_RESERVES` | src/kernel/config.rs | — | Policy, sized at boot (the `store_grants` pool, its default in `DEFAULT_RESERVES`): capability grants presented to the Linux store at once, the plan's `store_grants` ceiling (`DEFAULT_RESERVES`, or the envelope's entry). A presentation past it is `ENOMEM`, counted against the pool; none is evicted, because an evicted grant is a caller whose next operation silently starts failing |
| Staged streaming write | `STORE_STAGE_MAX` | src/platform/linux/store.rs | 67108864 | Policy: 64 MiB, the bytes one `PUT_STREAMED_*` write may stage before its commit. The store keeps objects in memory, so an open stream is the one place a caller can take the node's memory without committing anything; past it the write is `ENOSPC`. A provider for bulk objects stages to disk and carries no such bound |
| Streaming-write size hint | `STORE_STAGE_RESERVE_MAX` | src/platform/linux/store.rs | 1048576 | Policy: 1 MiB, the most a `PUT_STREAMED_OPEN` size hint may reserve up front. The hint is the caller's, so it is advice and not an allocation request; past this the staging buffer grows as the bytes arrive |

## Tables, arenas and budgets

Fixed-size tables and arenas whose size is a resource decision, and the
per-step budgets that keep one module's work from becoming another's
latency.

The Value column is the constant's first definition in its Source file,
as a bare integer, because that is what the gate compares against. A
constant declared once per profile therefore shows its host value here
and names the other profiles in its Reason — the full per-profile set is
in the machine-checked block below, one row each. A row whose value
cannot be evaluated from its own file reads `—` and says why.

| Cap | Symbol | Source | Value | Reason |
|---|---|---|---|---|
| Channel buffer arena | `BUFFER_ARENA_SIZE` | src/kernel/config.rs | 16777216 | Sized (host): a node's own graph plus the workload subgraphs it hosts, at 16–128 KiB per channel; the slack the node's graph leaves is what its workloads get. `fluxor build` and `fluxor build --check` add a graph's rings up by the rule the scheduler opens them by (`src/kernel/ipc/ring_size.rs`, mounted by the composer: each edge at the largest of its two ports' `buffer_size` and its `buffer_bytes`, rounded up to a power of two, 8 KiB where nothing sizes it; the edges joining fanned ports to their tees and merges; a mailbox group once for its mailbox-safe members; on bcm2712 a default consumer ring per cross-domain edge), print the largest rings, the total, its share of the arena and the slack, and refuse a graph that does not fit — this arena, or a lower `capacity: { buffer_arena }` envelope (on RP, which places the arena per graph, the entry is its size, larger or smaller) — naming its largest edges; the harness test `ring_demand` pins that sum to the arena `prepare_graph` uses. 8 MiB on wasm; the wasm arena is paged lazily by `memory.grow` so it costs nothing until used. 64 KiB on rp2350 and 16 KiB on rp2040, from the silicon TOML: there the default split of the kernel's static pool (`KERNEL_POOL_SIZE`), carved per graph at the plan's `buffer_arena` ceiling, so an envelope entry moves memory between it and the state arena and one past the pool is refused at boot naming `buffer_arena`. A workload admitted later whose rings do not fit is refused at its channel open |
| RP kernel pool | `KERNEL_POOL_SIZE` | src/kernel/config.rs | — | Sized (RP only), from `[kernel] kernel_pool_kb` in the silicon TOML: 344 KiB on rp2350, 112 KiB on rp2040 — what `ram_static_max_kb` holds beside the kernel's fixed statics (~112 KiB and ~96 KiB), less ~8 KiB of slack the static-RAM gate measures. One `.bss` pool each graph's plan splits at boot (`kernel::mem::carve::begin_plan` / `place_arenas`, arithmetic in `kernel::mem::pool_plan`): the tables the plan sizes off the top (a full 32-module, 128-channel graph's take ~33 KiB), the buffer arena at its ceiling below them, the state arena the rest. A plan the pool cannot hold is refused at boot naming the pool that did not fit; `build.rs` refuses a pool that cannot hold the two default arenas side by side |
| Tier B elastic region | `ELASTIC_REGION_SIZE` | src/kernel/config.rs | 16777216 | Policy: the oversubscribable region every elastic pool draws 64 KiB-quantum chunks from; 128 chunks on the host, which is the same depth as the kernel's chunk table. Zero on RP, where `ELASTIC_ALLOC` denies and elasticity compiles out; 2 MiB on wasm |
| RP override-merge buffer | `MAX_MODULE_CONFIG_SIZE` | src/kernel/config.rs | — | RP only, 16 KiB (rp2350) and 8 KiB (rp2040), from `[kernel] config_buffer_kb` in the silicon TOML, which `profile_rp` re-exports. Module params are borrowed from the config blob in place on every platform, so no profile bounds a module's params or the config's size: the blob's mapped length is the only bound (the file on Linux, the payload window below `.bss` on a RAM-loaded aarch64 image, the gap before the module blob on QEMU virt, the embedded blob on wasm, the graph slot or the flash below the slots on RP). This buffer is the only copy of params the kernel makes: the RP flash parameter store merges a module's stored overrides over its compiled params here, and only for a module that has an override. A merge that does not fit refuses the instance with a logged error; it is never truncated. Linux merges into a buffer grown to the merge |
| Module heap segments | `HEAP_SEGMENTS` | src/kernel/config.rs | 8 | Derived, not tuned: an elastic heap's first segment is `cap >> (HEAP_SEGMENTS - 1)` (at least the 64 KiB quantum) and every carve at least doubles what is committed, so eight carves reach any cap and the last slot takes what is left. Above 1 a module heap commits state-arena memory only as the module allocates, up to its cap (the type's declared arena, or the graph's per-instance `heap.arena_bytes`); growth past the cap, or past what the state arena holds, returns null, is counted (`grow_denied`) and logged. 8 on linux and bcm2712; 1 on wasm and RP, which commit every heap whole at instantiation as their state-arena budgets plan |
| Store read slots | `DEFAULT_RESERVES` | src/kernel/config.rs | — | Policy, sized at boot (the `store_reads` pool, its default in `DEFAULT_RESERVES`): `GET`-opened read slots on the Linux store at once, the plan's `store_reads` ceiling. A slot holds one value snapshot the caller drains by `RANGE_GET`, so the table bounds how many reads a node can have in flight; an open past it is `ENOMEM`, counted and named |
| Store streaming-write slots | `DEFAULT_RESERVES` | src/kernel/config.rs | — | Policy, sized at boot (the `store_writes` pool, its default in `DEFAULT_RESERVES`): `PUT_STREAMED_OPEN`-opened write slots at once, matched to the read slots and for the same reason — one slot per operation in flight; an open past it is `ENOMEM`, counted and named |
| Host-process sandboxes | `MAX_SANDBOXES` | src/platform/linux/host_backend.rs | 4096 | The sandbox-index DOMAIN; the table is sized at boot (the `sandboxes` pool). Every sandbox the Linux host-process backend holds is a workload with an owner, and a finished one is held until destroyed — an orchestrator keeps a terminated workload's status and logs for as long as the workload it belongs to exists — so the pool's derived part is the owner table's workload slots and its reserve (by default 64, `DEFAULT_RESERVES`) is headroom on top, taking by default only what this domain leaves beside the derived part; an explicit `capacity: { sandboxes }` past the domain is refused at boot, and the composer's boot plan names it. Slots are committed a segment at a time as spawns need them. The domain keeps `workload.rs`'s workload index (`MAX_WORKLOADS`, a table sized with this one) below the graph backend's slots and `fx<stem>w<idx>` inside IFNAMSIZ (const-asserted). A spawn past the ceiling is `ENOMEM`, counted against `sandboxes` |
| Host-process PTY sessions | `MAX_TTY_SESSIONS` | src/platform/linux/host_backend.rs | 4096 | The session-id DOMAIN; the table is sized at boot (the `tty_sessions` pool, by default 8): interactive terminals (an interactive exec, an attach) open at once across every sandbox of the Linux host-process backend, each a pseudo-terminal and a child pumped every step; a one-shot `EXEC` takes none. An open past the ceiling is `ENOMEM`, counted against `tty_sessions` |
| Workload user database read | `USER_DB_MAX` | src/platform/linux/host_backend.rs | 4194304 | Policy: the largest user or group database in a workload's root that the Linux host-process backend parses when it resolves an OCI user. A larger one is never read in part: resolution fails `E2BIG` with a `[host_process] … larger than 4194304 bytes` warning, for every user including `root` and the runtime's own identity. A database that cannot be read to its end fails with the read's errno and a warning. The database is parsed as bytes, line by line: a line that is not UTF-8 is skipped, the count logged, and the rest of the database resolves |
| Datagram reply-from addresses | `DG_REPLY_FROM_MAX` | src/platform/linux/providers.rs | 64 | Policy: peers a Linux datagram endpoint remembers the local arrival address of, so a reply to that peer leaves from the address it asked at rather than the one the route prefers (which the asker, and connection tracking for a translated service, would not take for the answer). Past it the longest-unheard peer is replaced, and a forgotten peer is answered from the route's preferred source |
| Linux host open files | `MAX_OPEN_FILES` | src/platform/linux/providers.rs | 256 | Policy: files and directory streams the Linux `fs` provider holds open at once for the whole node, sized for a replicated-state consumer's three handles a group beside everything else a node opens. An `OPEN`, `OPEN_CREATE` or `OPENDIR` past it, host or workload, is refused `ENOMEM` and the descriptor it opened is closed; a workload is held to `OWNER_MAX_OPEN_FILES` of the table. Const-asserted to fit the handle's 8 slot bits |
| Linux host path argument | `LINUX_FS_PATH_MAX` | src/platform/linux/providers.rs | 255 | Policy: the longest path the Linux `fs` provider accepts, one byte short of its 256-byte scratch so the path is passed to libc NUL-terminated. A longer path is refused `E2BIG` on a single-path op, host or workload, and a `LINK` or `RENAME` with either path longer is refused `EINVAL`; a path is never truncated |
| Linux host child processes | `MAX_PROCS` | src/platform/linux/providers.rs | 8 | Policy: dev-tool children `PROC_SPAWN` runs at once across the node; a spawn past it is refused `ENOMEM` before anything is started |
| Linux net connection-table ceiling | `LINUX_NET_MAX_CONNS_CAP` | src/platform/linux/providers.rs | 65535 | Policy: the largest `max_conns` the Linux `net` built-in takes (128 when the graph sets none), because `net_proto` carries the slot index as a `u16`; the smallest is 2 (`LINUX_NET_MAX_CONNS_MIN`). `fluxor build` refuses a value outside `[2, 65535]` from the built-in's manifest `range`, numeric strings and values past `u32` included. A value outside it that reaches instantiation is refused: the module is not loaded and `[inst] module N = linux_net refused: max_conns …` is logged; it is never adjusted. With every slot in use a listen or UDP bind is refused `ENOBUFS`, a dial `ENOMEM`, and an accepted connection is closed at once with a `[linux_net] connection table full` warning |
| Linux net command frame | `LINUX_NET_CMD_MAX` | src/platform/linux/providers.rs | 49152 | Policy: the largest command payload the Linux `net` built-in reads (its command scratch, several times `net_proto::MAX_CMD_DATA`), and the headroom its write backlog keeps: no command is read while a connection's backlog could not take one more frame of this size within `write_buf_kib`. A larger frame is drained from the lane, so the next frame parses from its header, logged, and answered `EMSGSIZE` in its requester's shape: `MSG_ERROR` on the tag of a `CMD_CONNECT_TO` (its last two bytes) or `CMD_CONNECT` (bytes 7..9); `MSG_BIND_REFUSED` for a bind, with `DG_MSG_ERROR` (endpoint 0xFF) for a datagram bind; `DG_MSG_ERROR` on the endpoint of a datagram send or close; `MSG_ERROR` on the connection of a `CMD_SEND` or `CMD_CLOSE`, and an oversized `CMD_SEND` then closes its connection (`MSG_CLOSED`), since the stream has lost bytes. A connection or endpoint the lane may not act on is left untouched and unnamed |
| Linux net queued control frames | `PENDING_CTRL_CAP` | src/platform/linux/providers.rs | 256 | Policy: control frames (`MSG_CONNECTED`, `MSG_CLOSED`, `MSG_ERROR`, `MSG_BOUND`, `MSG_ACCEPTED`, `MSG_PEER`, `MSG_BIND_REFUSED`, `DG_MSG_*` other than arrivals) held for one destination channel while it is full, flushed in order before each step. No queued frame is evicted. At the cap the destination's lanes pause: their commands stay in their command channels and their listeners' connections in the kernel's accept queue until the consumer reads, so a wedged consumer back-pressures its producer. Past the cap a queue grows only by what the lane's existing slots still owe (at most a connect result, a peer report and a close each) and so stays within `PENDING_CTRL_CAP + 2 + 3 × max_conns`; a frame refused there is counted (`ctrl_refused`) and logged at error |
| Linux net queued control frame | `CTRL_FRAME_MAX` | src/platform/linux/providers.rs | — | Derived: the largest frame a control-queue slot holds, the peer report (`MSG_PEER`: the 3-byte header and `net_proto::PEER_LEN`). Every control frame is checked against it at compile time, so none is too large to build or queue. Data is never queued: a datagram arrival that its channel cannot take, that would overtake a queued control frame, or that is larger than one frame carries (16373 bytes of data; a larger one is received cut and never delivered) is not delivered and is counted on its endpoint and per instance, with a warning at each power-of-two count |
| Linux net resolver cache | `DNS_CACHE_SLOTS` | src/platform/linux/providers.rs | 32 | Policy: names one Linux `net` instance keeps a resolved answer for, each for `DNS_CACHE_TTL` (60 s). A name past it evicts the entry soonest to expire, an expired one first, and the evicted name is resolved again on its next dial: past it a dial costs a lookup, never a failure |
| Linux net dial candidates | `MAX_DIAL_CANDIDATES` | src/platform/linux/providers.rs | 4 | Policy: addresses one name is dialled at. Every address `getaddrinfo` returns is taken, interleaved by family, then cut to four, so a host that answers several addresses of one family ahead of the other is dialled over both; the cache holds the same four. An address past them is never tried: when all four fail the dial ends in one `MSG_ERROR` carrying the last connect errno |
| Linux net accepts per step | `PER_TICK_ACCEPT_BUDGET` | src/platform/linux/providers.rs | 32 | Policy: connections accepted from one listener in one step, so a 32-client connect burst clears in one pass while no burst owns the step. A connection past it waits in the kernel's listen backlog and is accepted on a later step, the epoll set being level triggered |
| Workload open files | `OWNER_MAX_OPEN_FILES` | src/kernel/workload/storage.rs | 32 | Policy: files one workload holds open through its storage root at once, on every platform, so no workload can take the file table the node and every other workload open from; an open past it is `ENOMEM` |
| Workload store watches | `DEFAULT_RESERVES` | src/kernel/config.rs | — | Policy, sized at boot (the `owner_store_subs` pool, its default in `DEFAULT_RESERVES`): `SUBSCRIBE` watches one workload's own store holds at once (the envelope's entry, else the default). Each owner's store has handle tables of its own, sized for one tenant rather than the node; a watch past it is `ENOMEM`, counted and named |
| Workload store reads | `DEFAULT_RESERVES` | src/kernel/config.rs | — | Policy, sized at boot (the `owner_store_reads` pool, its default in `DEFAULT_RESERVES`): `GET` read slots one workload's own store holds open at once; a read past it is `ENOMEM` |
| Workload store streaming writes | `DEFAULT_RESERVES` | src/kernel/config.rs | — | Policy, sized at boot (the `owner_store_writes` pool, its default in `DEFAULT_RESERVES`): `PUT_STREAMED_OPEN` write slots one workload's own store holds at once; an open past it is `ENOMEM` |
| Workload staged streaming write | `OWNER_STAGE_MAX` | src/platform/linux/store.rs | 16777216 | Policy: 16 MiB, the bytes one of a workload's streamed writes may stage before its commit. Staged bytes are also charged to the owner's storage ledger, so its `storage_bytes` cap bounds them first when it is lower; past either the write is `ENOSPC` |
| HTTP concurrent connections | `MAX_CONCURRENT_CONNS` | modules/sdk/abi/config.rs | 256 | Policy: the http module's own table, below `MAX_TCP_CONNS`; an accept past it is closed before any request is read. The embedded 4 is sized against the 8-slot TCP table in that profile; the one-session TLS table beneath it bounds HTTPS. 4 on embedded. |
| HTTP per-connection receive buffer | `RECV_BUF_SIZE` | modules/sdk/abi/config.rs | 8192 | Policy: a whole request line, headers and a small body in one read; a request that does not fit is refused 431, not spilled 4096 on wasm, 2048 on embedded. |
| HTTP per-connection send buffer | `SEND_BUF_SIZE` | modules/sdk/abi/config.rs | 4100 | Policy, deliberately 4 KiB + 4: a WebSocket frame of exactly 4096 bytes of payload plus its header fits in one write, so the RFC 6455 fragmentation path is taken only by frames that genuinely exceed it |
| Dynamic routes | `MAX_DYN_ROUTES` | modules/sdk/abi/config.rs | 64 | Policy: the dynamic-route arena an ingress fills at runtime; a route past the ceiling is refused and counted in `http.routes.dropped` 8 on wasm and embedded. |
| Backends per route | `MAX_ROUTE_BACKENDS` | modules/sdk/abi/config.rs | 8 | Policy: an oversized backend set is truncated by weight order and the overflow is counted, so the route keeps serving from its heaviest members 4 on wasm and embedded. |
| Route filesystem path | `MAX_FS_PATH` | modules/sdk/abi/config.rs | 256 | Policy: host routes point into deep on-disk trees; embedded and wasm routes are short on-flash paths like `/web/INDEX.HTM`, and a longer path is refused at compose time 64 on wasm and embedded. |
| Body pool default | `DEFAULT_BODY_POOL_SIZE` | modules/sdk/abi/config.rs | 262144 | Policy: the request-body pool an http module gets when its config names none; a body that does not fit is refused 413. 32 KiB on wasm; on the RP parts 16 KiB (rp2350) and 4 KiB (rp2040), where the pool is charged against the same SRAM the state arena is |
| Fan-in/fan-out scratch | `FAN_BUF_SIZE` | src/kernel/exec/scheduler/module_types.rs | 32768 | Sized per target family: the per-domain static scratch a tee or merge stages each transfer in, not a ring — the channels on either side of a fan are ordinary rings from the buffer arena. A byte-stream fan moves at most this much per step; a frame or record larger than it cannot cross a fan. 32768 on aarch64 (bcm2712 and Linux on aarch64), 2048 on RP, 8192 elsewhere |
| Config graph edges | `MAX_GRAPH_EDGES` | src/kernel/boot/config.rs | — | Per profile. On Linux and bcm2712 the format's bound, 255 × 128 (a slot code is a byte of 128-edge units): the graph section is laid out for the graph it carries and byte 3 states its slot count, and the edge and channel tables are sized at boot from the edges plus the `channels` reserve. On wasm and RP their compiled `GRAPH_EDGES` (`SMALL_GRAPH_EDGES`), the one layout every blob for them carries |
| Static-profile graph edges | `GRAPH_EDGES` | src/kernel/config.rs | 128 | Policy: the wasm and RP profiles' edge slots; what their graph section holds, and so their channel-id domain. wasm's channel table is this static size; RP sizes its channel table from the plan within it, from the kernel's static pool. Linux and bcm2712 have none: they size them from the graph |
| Small-profile graph edges | `SMALL_GRAPH_EDGES` | src/kernel/boot/config.rs | 128 | Policy: wasm (48 module slots) and RP (32) keep 128 edges, so their static edge tables and config blobs stay small |
| Channels | `MAX_CHANNELS` | src/kernel/ipc/channel.rs | — | Derived, not chosen: the channel-id domain, one per edge slot, fan expansion included. The table itself is sized at boot on Linux, bcm2712 and RP (`channels` pool: the graph's edges and fans, twice each resident workload's edges and, on bcm2712, one per cross-domain edge, plus the reserve) — on Linux growing a segment at a time on a live open, up to its ceiling — and is the static table on wasm. Every ring graph preparation opens takes a slot, the consumer side of a bcm2712 cross-domain edge included, which the derived part counts (one per base-graph edge that crosses domains); `fluxor build` counts the rings against the plan. Not value-checked here: the gate evaluates a const against its own file and this one is written in terms of a symbol from another, so the row on `MAX_GRAPH_EDGES` is what holds the pair. |
| Hardware sections: SPI buses | `MAX_SPI_BUSES` | src/kernel/boot/config.rs | 2 | Policy: the packed hardware section carries fixed tables; a board declaring more buses of a kind is refused by the tools |
| Hardware sections: I2C buses | `MAX_I2C_BUSES` | src/kernel/boot/config.rs | 2 | Policy: the packed hardware section carries fixed tables; a board declaring more buses of a kind is refused by the tools |
| Hardware sections: UART buses | `MAX_UART_BUSES` | src/kernel/boot/config.rs | 2 | Policy: the packed hardware section carries fixed tables; a board declaring more buses of a kind is refused by the tools |
| Hardware sections: PIO instances | `MAX_PIO_CONFIGS` | src/kernel/boot/config.rs | 3 | Policy: RP2350B has three PIO blocks, the widest of the RP family |
| Hardware sections: GPIO pins | `MAX_GPIO_CONFIGS` | src/kernel/boot/config.rs | 8 | Policy: pins configured from the config blob; a driver claims the rest at runtime |
| Resident-workload section | `MAX_WORKLOAD_SECTION_BYTES` | src/kernel/boot/config.rs | 8192 | Sanity bound on a torn or hostile config tail; sized for a handful of workloads with room |
| Tick period ceiling | `TICK_BOUND_MAX` | src/kernel/boot/config.rs | 50000 | Policy: the longest tick (µs) a config may ask for; above it the adaptive tick has nothing left to adapt and a stuck graph looks like a slow one |
| Buffer-arena free-region list | `MAX_FREE_REGIONS` | src/kernel/ipc/buffer_pool.rs | 128 | Deliberate cap with a stated degradation: returned regions are kept coalesced, so the list holds one entry per gap in the arena, not per closed channel; a region returned while it is full is leaked (reported by `buffer_free_list_usage`) until the next `reset_buffer_arena` |
| State-arena free-region list | `MAX_FREE_REGIONS` | src/kernel/module/loader.rs | — | Sized at boot on Linux, bcm2712 and RP (`state_free_list` pool): a hole for every allocation the module slots can hold — state, arena and heap segments — so a free never finds it full. wasm's fixed list (`STATIC_POOLS`, 32) keeps its stated degradation: when it is full a freed region is leaked until the next full arena reset, counted against the pool |
| Isolated-image arena | `ISO_ARENA_SIZE` | src/kernel/module/loader.rs | 2097152 | Policy (`kernel-vm`): all isolated module state and heap of one image; exhaustion refuses the load |
| Tracked provider handles | `MAX_TRACKED` | src/kernel/module/provider.rs | — | Policy, sized at boot on Linux, bcm2712 and RP (`tracked_handles` pool, by default 128; on RP carved from the kernel's static pool), the static table on wasm (`STATIC_POOLS`): handle-to-owner bindings the kernel keeps for cross-owner checks on untagged handles (GPIO pins, DMA channels, HAL handles). A tagged handle's provider keeps its own slots and answers each to its opener, so it takes no entry. An open past the table is refused and counted, and the table is scanned on every provider call, so it is kept small on purpose |
| Kernel events | `MAX_EVENTS` | src/kernel/ipc/event.rs | — | Policy, sized at boot on Linux, bcm2712 and RP (`events` pool: no structural source, so its envelope entry, by default 32), the static table on wasm (32). Handles fit the tagged-fd slot field; a plan past it is refused at boot. A create past the ceiling is `ENOSPC`, counted |
| Timer fds | `MAX_TIMERS` | src/kernel/ipc/fd.rs | — | Policy, sized at boot on Linux, bcm2712 and RP (`timers` pool, by default 16), the static table on wasm (16). Handles fit the tagged-fd slot field; a plan past it is refused at boot. A create past the ceiling is `ENOSPC`, counted |
| `net.policy` tables | `MAX_TABLES` | src/kernel/net_policy.rs | — | Policy, sized at boot on Linux and bcm2712 (`net_policy_tables`, by default 8): a controller owns one; a REPLACE past the ceiling is `ENOSPC`, counted. 2 on wasm (`STATIC_POOLS`), by default none on RP (`DEFAULT_RESERVES`; an envelope entry carves them from the static pool). The enforcer bindings (ATTACH) are as many: one enforcer per table, an ATTACH past them `ENOSPC` |
| `net.policy` read retries | `READ_RETRIES` | src/kernel/net_policy.rs | 8 | Sanity bound: a READ that finds the store's sequence moving this many times answers `EAGAIN` and the enforcer keeps its previous copy (which then is not the stored generation, so the table's ENFORCED clears) |
| `net.policy` writer wait | `WRITER_SPINS` | src/kernel/net_policy.rs | 65536 | Sanity bound: spins a writer waits for the store's writer flag (held across one table copy) or for another REPLACE's platform apply, before answering `EAGAIN`; the caller retries |
| `net.route` segments | `MAX_SEGMENTS` | src/kernel/net_route.rs | — | Policy, sized at boot on Linux and bcm2712 (`net_route_segments`, by default 16: one per node is the common shape); none on wasm (`STATIC_POOLS`) and by default none on RP (`DEFAULT_RESERVES`). Across a rebuild the table keeps `max(previous, planned)`. A SEGMENTS replace past it is `ENOSPC`, counted |
| `net.route` peer routes | `MAX_PEERS` | src/kernel/net_route.rs | — | Policy, sized at boot on Linux and bcm2712 (`net_route_peers`, by default 256: one per other node); none on wasm, by default none on RP. A ROUTES replace past it is `ENOSPC`, counted |
| `net.route` held addresses | `MAX_HELD` | src/kernel/net_route.rs | — | Policy, sized at boot on Linux and bcm2712 (`net_route_held`, by default 256 service addresses); none on wasm, by default none on RP. A HOLD replace past it is `ENOSPC`, counted |
| `net.route` state-region wait | `STATE_SPINS` | src/kernel/net_route.rs | 65536 | Sanity bound: tries a SEGMENTS, ROUTES or HOLD replace waits for the entry-state region before answering `EAGAIN`; the caller retries. The region is held across a copy of the entry states and, where the platform realizes the tables itself, across asking it for each entry's state, which can wait on a realization in flight, so a hosted build yields between tries rather than spinning |
| `net.route` cluster prefixes per segment | `MAX_CLUSTER_PREFIXES` | modules/sdk/contracts/net/route.rs | 8 | Protocol maximum: the cluster prefix and its service range with room for a few more; a segment carrying more is malformed (`EINVAL`) |
| `net.policy` table rules | `MAX_TABLE_BYTES` | src/kernel/net_policy.rs | — | Policy, sized at boot on Linux and bcm2712 (`net_policy_table_bytes`, by default 8192: ~500 filter rules, or ~40 fully loaded services' DNAT with their backends); 2048 on wasm and by default on RP. A REPLACE of more is `ENOSPC` |
| Kernel pool defaults | `DEFAULT_RESERVES` | src/kernel/config.rs | — | Policy, the profile's data on Linux, bcm2712 and RP: each pool's live-add reserve when the config's envelope gives none (its size, for a pool the config cannot derive). Every table is sized at boot to derived + reserve (`resource_ledger::plan`) — on bcm2712 carved from the DRAM zone the device tree describes, on RP from the kernel's static pool (`kernel::mem::carve`); none of these is a ceiling. RP's derived reserves are slim (4 module slots, 16 channels: an MCU graph changes by a rebuild, which plans the pool again) and its arena entries are the default split, and an ask the platform cannot hold is refused at boot naming the pool. The composer reads this table (`tools/src/capacity.rs`) and runs the same plan at build (`capacity::check_boot_plan`), refusing a ceiling past a pool's index domain or static table by name and by how much; only what the platform's memory cannot hold is left to the boot |
| Kernel static pools | `STATIC_POOLS` | src/kernel/config.rs | — | Policy, the profile's data on wasm: the static size of every table the profile holds, the ceiling every boot plan must fit (refused at boot, naming the pool, past it). The composer reads this table as the profile's pool sizes (`tools/src/capacity.rs`). Linux, bcm2712 and RP state none |
| bcm2712 store subscriptions | `DEFAULT_RESERVES` | src/kernel/config.rs | — | Policy, sized at boot (the `store_subs` pool: what the graph's store consumers declare plus the reserve, by default 64) and carved from the device tree's DRAM zone: one subscription per watched prefix per module; a whole control plane asks ~95. A subscription past it is `ENOMEM` |
| bcm2712 store read slots | `DEFAULT_RESERVES` | src/kernel/config.rs | — | Policy, sized at boot (the `store_reads` pool, by default 32) and carved: `GET` read slots open at once on the bcm2712 store; an open past it is `ENOMEM` |
| bcm2712 store objects | `MAX_OBJECTS` | src/platform/bcm2712/store.rs | 512 | Policy: objects the bcm2712 control-plane store holds. No pool names them, so this is their size; the table (~2.2 MiB) is carved at boot from the device tree's DRAM zone rather than linked into `.bss`. A PUT past it is `ENOMEM`, never an eviction |
| bcm2712 store value | `MAX_VALUE` | src/platform/bcm2712/store.rs | 4096 | Policy: the largest value one bcm2712 store object holds, matching `store_effect`'s own |
| Cross-core channels | `MAX_CROSS_CHANNELS` | src/platform/bcm2712/multicore.rs | 256 | Format-bound: the ring-index DOMAIN, a `CrossDomainEdge` names its ring in a `u8`. The ring and cross-edge tables are sized from the graph when it is bridged (`size_cross`: one ring and one edge entry per edge whose endpoints are in different domains) and carved; a graph past the domain is refused at boot |
| Device-tree blob | `MAX_BLOB` | src/kernel/boot/dtb.rs | 2097152 | Sanity bound: a header claiming a larger tree is refused and the platform keeps its fixed map. A board's tree is ~80 KiB (the Pi 5's), QEMU's 1 MiB at most |
| Device-tree nesting | `MAX_DEPTH` | src/kernel/boot/dtb.rs | 16 | Sanity bound: node nesting the memory walk tracks (the Pi 5's tree nests 6 deep); a deeper tree is refused, not mis-read |
| Device-tree memory ranges | `MAX_MEMORY_RANGES` | src/kernel/boot/dtb.rs | 16 | Policy: `/memory` ranges kept (a board states one to a few, the Pi 5 two); past it the facts are marked incomplete and the fixed map is used |
| Device-tree reservations | `MAX_RESERVED_RANGES` | src/kernel/boot/dtb.rs | 32 | Policy: reservations kept — `/reserved-memory` children, the header block, the initramfs and the blob (the Pi 5 states about six). Past it the facts are marked incomplete and the fixed map is used, because a reservation dropped is memory the kernel would write over |
| Device-tree cell width | `MAX_CELLS` | src/kernel/boot/dtb.rs | 4 | Sanity bound: the widest `#address-cells` / `#size-cells` the memory walk reads (a PCI bus states three). A `/memory` or `/reserved-memory` `reg` under wider cells marks the facts incomplete and the platform keeps its fixed map (`[mem] src=FixedUnreadable`, with a `[mem] device tree facts incomplete` warning naming the reason); a `dma-ranges` window under wider cells is skipped, so it sets no DMA ceiling. A `/chosen` initramfs it cannot place (a bound wider than four cells, a non-zero cell above 64 bits, a length that is no whole number of cells, only one bound, or an end below its start) marks the facts incomplete the same way |
| Transient carve blocks | `RECYCLE_SLOTS` | src/kernel/mem/carve.rs | 16 | Policy: blocks the carve allocator keeps for reuse (the graph builder's scratch, the config's parse lists); graph preparation has a handful live at once. One given back to a full list replaces the smallest, which is leaked and counted (`[mem] leaked=`) |
| Zeroed frontier lead | `ZERO_AHEAD_BYTES` | src/kernel/config.rs | 67108864 | Policy (bcm2712): how far the state arena's zeroed frontier runs ahead of what the arena has handed out, cleared in the domains' slack and once before a graph first steps, so a heap growing on a step finds zeroed memory. A growth past it on one step zeroes the rest synchronously and counts it (`heap_zero_step_bytes`) |
| Zeroing claim | `ZERO_CHUNK_BYTES` | src/kernel/config.rs | 65536 | Policy (bcm2712): bytes one slack claim zeroes between clock reads (~10 us on a Cortex-A76): the unit of bounded work a domain donates |
| Execution domains (bcm2712) | `MAX_DOMAINS` | src/platform/bcm2712/multicore.rs | 4 | Hardware: one domain per Cortex-A76 core of the BCM2712 |
| Execution domains | `MAX_DOMAINS` | src/kernel/exec/scheduler/mod.rs | 4 | Format-bound: the config blob's graph section carries four domain-metadata entries |
| Scheduler module domain | `MAX_MODULES` | src/kernel/exec/scheduler/mod.rs | — | Derived, not chosen: the scheduler's name for `kernel::config::MAX_MODULES` (the module-index domain on Linux, the static table elsewhere). Not value-checked here: it is written in terms of the config's symbol, whose rows hold the value |
| Scheduler edge domain | `MAX_CHANNELS` | src/kernel/exec/scheduler/mod.rs | — | Derived, not chosen: the scheduler's name for `MAX_GRAPH_EDGES`, the edge-index domain the per-edge tables are typed by; the tables themselves are sized at boot on Linux |
| Burst re-steps | `MAX_BURST_STEPS` | src/kernel/exec/scheduler/mod.rs | 16384 | Policy: re-steps one module may take in a tick by answering `Burst`; each step is still bounded, and the per-domain budget cuts the pass short first |
| Drain ceiling | `MAX_DRAIN_MS` | src/kernel/exec/scheduler/mod.rs | 30000 | Policy: the longest a reconfigure's `Draining` phase may hold the graph before the kernel force-finalises what is left |
| Pre-tick drain modules | `MAX_PRE_TICK_PER_DOMAIN` | src/kernel/exec/scheduler/mod.rs | 4 | Policy: Tier 1c pre-tick modules per domain — a NIC RX drain and an ARP cache with headroom |
| Pre-tick budget | `MAX_PRE_TICK_BUDGET_US` | src/kernel/exec/scheduler/mod.rs | 5 | Policy: the combined µs every pre-tick module of a domain may take before the cooperative pass |
| Interned module names | `MAX_NAMES` | src/kernel/exec/scheduler/mod.rs | — | Derived, not chosen: one per module index (`MAX_MODULES`), since a graph cannot hold more distinct names |
| Interned name length | `MAX_NAME_LEN` | src/kernel/exec/scheduler/mod.rs | 32 | Policy: bytes of one interned module name |
| Secondary cores | `MAX_SECONDARY_CORES` | src/platform/bcm2712/multicore.rs | 3 | Hardware: the BCM2712's four Cortex-A76 cores, one the boot core |
| Cross-core ring depth | `RING_SLOTS` | src/platform/bcm2712/multicore.rs | 8 | Policy: slots in one cross-core SPSC ring |
| Cross-core slot | `SLOT_DATA_SIZE` | src/platform/bcm2712/multicore.rs | — | Derived, not chosen: one channel buffer (`CHANNEL_BUFFER_SIZE`) per cross-core ring slot |
| Cross-core DMA arena | `DMA_ARENA_SIZE` | src/platform/bcm2712/multicore.rs | 65536 | Policy: the uncached arena cross-core descriptors live in |
| Secondary-core stack | `CORE_STACK_SIZE` | src/platform/bcm2712/multicore.rs | 1048576 | Policy: each secondary core's kernel stack, matching the boot core's `kernel_stack_kb` |
| Secondary-core stack guard | `STACK_GUARD_SIZE` | src/platform/bcm2712/multicore.rs | 4096 | Hardware: one page, unmapped below each secondary stack |
| Provider vtables | `MAX_PROVIDERS` | src/kernel/module/provider.rs | 64 | Derived, not chosen: one vtable slot per contract id, so a contract registerable in one and not the other is impossible by construction |
| Contracts per provider module | `MAX_CONTRACTS_PER_PROVIDER` | src/kernel/module/loader.rs | 4 | Policy: the contracts one provider state may serve through `module_provides_contracts` (a store owning its objects and their namespace needs two); entries past it are not registered |
| Dynamic tag routes | `MAX_DYN_TAG_ROUTES` | src/kernel/module/provider.rs | 4 | Policy: keyed provider routes a policy module may add at runtime |
| Key material per vault slot | `MAX_KEY_BYTES` | src/kernel/security/key_vault.rs | 64 | Policy: a P-256 scalar is 32; the doubled width admits larger keying material without a header change |
| Vault label | `MAX_LABEL` | src/kernel/security/key_vault.rs | 64 | Policy, wire-visible: the label is how a module names a key; the contract's `MAX_LABEL` mirrors it |
| Persisted vault keys | `MAX_PERSISTED` | src/kernel/security/key_vault.rs | — | Policy, per-profile (64 aarch64 / 8 elsewhere), like the slot table: a Pi-class node persists a master per Clustor group, replica and key epoch, per locally encrypted volume, and its identities. With none free, persisting is refused and the consumer refuses its operation rather than holding an unpersisted key |
| One AEAD seal/open | `MAX_SEAL_BYTES` | src/kernel/security/key_vault.rs | 2048 | Policy: a resumption ticket or a checkpoint chunk in one call, never a bulk stream; a larger plaintext is refused EINVAL |
| Consumed share envelopes | `MAX_CONSUMED` | src/kernel/security/key_share.rs | 32 | Policy: anti-replay ids of the last envelopes a reconstruction used, refused EACCES if presented again. An attachment envelope's recipient is a fresh key destroyed after the attach, which stops replay to any other opener; the ring covers the recipient's own lifetime, which spans one attach |
| Parameter tag space | `PARAM_TAG_MAX` | tools/src/manifest.rs | 237 | Id width: a module parameter is addressed by a byte tag, and 0xEE–0xFF are reserved for kernel, protection and policy metadata (0xEE raw arena use, 0xEF an instance's heap cap, the voice-preset blobs, TLV magic and the terminator among them) |
| Transmit-side ethernet frame | `MAX_FRAME_SIZE` | modules/foundation/ip/mod.rs | 1536 | Policy: the frame ceiling every NIC driver and `ip` size their staging to — MTU plus headers, rounded to a 32-byte multiple. Every transmit-payload ceiling in `ip` derives from it |
| Listening TCP sockets | `MAX_LISTENERS` | modules/foundation/ip/mod.rs | — | Policy, per-profile (derived from `MAX_TCP_CONNS`): a SYN is matched against the listener list, never the whole table |
| `ip` workload lanes | `lanes` (param) | modules/foundation/ip/mod.rs | — | Declared input, default `LANES_DEFAULT` (16 on aarch64, none on MCU-class targets): the lanes `ip` holds and states to the kernel (`NET_PROVIDE`); sizes the lane table and the per-lane command stashes in the module heap. At most 255 (`LANE_CEILING`) |
| `ip` datagram endpoints per lane | `lane_endpoints` (param) | modules/foundation/ip/mod.rs | — | Declared input, default `LANE_ENDPOINTS_DEFAULT` (16): the quota one lane holds under the wire's 256 `ep_id`s; a bind past it is refused `EMFILE`, so one workload cannot take the ids the others need |
| `ip` ARP table | `max_peers` (param) | modules/foundation/ip/mod.rs | — | Declared input: the table is `max_peers` plus `ARP_SEGMENT_ENTRIES` (16, the gateway and the segment's own neighbours), in the module heap |
| `ip` resolver cache and queries | `dns_cache`, `dns_pending` (params) | modules/foundation/ip/mod.rs | — | Declared inputs, per owner (the node and each lane), default `DNS_CACHE_DEFAULT` / `DNS_PENDING_DEFAULT` (8 / 4 on aarch64, 2 / 2 elsewhere): each owner reads, joins and evicts only its own partition, sized for a search list's expansion. A query past an owner's partition is refused `EAGAIN` |
| `ip` held-address headroom | `max_held` (param) | modules/foundation/ip/mod.rs | — | Declared input: construction is refused unless the address table (`MAX_LOCAL_ADDRS`) holds the primary, one address per lane and `max_held` held addresses |
| `ip` default heap | `HEAP_DEFAULT_BYTES` | modules/foundation/ip/mod.rs | — | Policy: the heap cap `ip` asks for when the graph names none. Elastic on aarch64 (it commits what the declared tables touch), committed whole on MCU-class targets (4 KiB). A graph declaring more than it holds gives the instance `heap.arena_bytes`; construction otherwise refuses, naming the table |
| Outbound net queues | `node_events`, `lane_events` (params) | modules/foundation/ip/mod.rs | — | Declared inputs, default `NODE_EVENTS_DEFAULT` / `LANE_EVENTS_DEFAULT` (32 / 8; at least 8 / 4): control frames `ip` holds for a consumer that is not draining, in a queue per lane in the module heap, each lane's count kept on push and drain. The node's queue is the receive reserve — the receive loop stops reading the NIC when fewer than its headroom remain, so back-pressure reaches the wire — and a workload lane's fills only with its own events: an accept is announced only with room for `MSG_ACCEPTED` and its peer report, and is otherwise refused. Was one 32-slot queue shared four per lane, sixteen across lanes |
| `ip` fast-path pairs per lane | `lane_pairs` (param) | modules/foundation/ip/mod.rs | — | Declared input, default `LANE_PAIRS_DEFAULT` (16): same-node stream halves one lane holds; a dial past it is refused `ENOBUFS` |
| `ip` datagram flows | `max_dg_flows`, `dg_flow_floor`, `dg_flow_idle_s` (params) | modules/foundation/ip/flows.rs | — | Declared inputs, default `FLOWS_DEFAULT` / `FLOOR_DEFAULT` / `IDLE_DEFAULT_S` (1024 / 16 / 30 s on aarch64): the flow table and its 4× index in the module heap, each lane (the node's included) guaranteed its floor; construction refuses unless `max_dg_flows >= (lanes + 1) x floor`. A send at the floor with the shared part spent is refused `ENOBUFS`; inbound-only unanswered flows are evicted first, a live egress flow never |
| `ip` route tables | `max_segments` (param), `max_peers`, `max_held` | modules/foundation/ip/route.rs | — | Declared inputs, default `SEGMENTS_DEFAULT` (4): the TAKE buffer and the segments, peer routes and held addresses `ip` realizes. A table written past them answers TAKE `ERANGE`; the previous copy stays |
| `ip` packet-policy tables | `policy_tables`, `policy_bytes` (params) | modules/foundation/ip/policy.rs | — | Declared inputs, default `BYTES_DEFAULT` (8192 on aarch64): each named table held twice (a read lands whole in the spare) in the module heap, and the service index sized from them (`service.rs`, double-buffered). A table past `policy_bytes` keeps the previous copy in force and is reported not applied, so its `ENFORCED` is clear | Policy: frames `ip` holds for a consumer that is not draining; the receive loop stops reading the NIC when fewer than the headroom remain, so back-pressure reaches the wire instead of dropping on the floor |
| DNS record types per allow entry | `MAX_ALLOW_TYPES` | modules/foundation/dns/mod.rs | 8 | Policy: one `update_allow` entry lists the types a signer may update; more than eight is a policy written in the wrong place |
| fat32 enumeration | `MAX_FILES` | modules/foundation/fat32/mod.rs | 128 | Policy: entries one LIST returns; a larger directory is paged by the caller |
| fat32 unlink free-list | `UNLINK_FREE_SLOTS` | modules/foundation/fat32/mod.rs | 8 | Deliberate cap with a stated degradation: sized for WAL segment compaction retiring a handful of segments per snapshot; overflow degrades to orphaning clusters, which fsck reclaims |
| fat32 directory chain | `MAX_DIR_CLUSTERS` | modules/foundation/fat32/mod.rs | 65536 | Sanity bound: far past any real directory and far short of walking a cyclic chain for ever |
| fat32 resolved directories | `DIR_CACHE` | modules/foundation/fat32/mod.rs | 2 | Policy: directory components a path walk remembers, so a rename whose source and destination share a parent resolves both paths under a parent too long to walk in one call. Dropped when the parent's names change, when a rename is replayed and when the volume is formatted |
| fs_object store directory | `ROOT_MAX` | modules/foundation/fs_object/mod.rs | 96 | Policy: bytes of the `root` parameter; a longer one fails `module_new` rather than being cut to a different directory |
| fs_object read handles | `READS` | modules/foundation/fs_object/mod.rs | 8 | Policy: `GET` handles open at once, each an open file underneath; past it `GET` answers EBUSY |
| fs_object listing page | `PAGE_KEYS` | modules/foundation/fs_object/mod.rs | 16 | Policy: keys one `LIST` page carries, whatever `max_keys` asks; the cursor resumes after the last |
| fs_object headers per listing call | `SCAN_OPENS_PER_CALL` | modules/foundation/fs_object/mod.rs | 8 | Budget: object headers one listing call opens before it answers EAGAIN and resumes on the same request; a page costs an open per object in the store |
| fs_object write chunk | `WRITE_CHUNK` | modules/foundation/fs_object/mod.rs | 4096 | Budget: bytes one `PUT` ask writes to the filesystem |
| fs_object hash chunk | `HASH_CHUNK` | modules/foundation/fs_object/mod.rs | 4096 | Budget: body bytes one `PUT` ask hashes while it computes the etag |
| fs_object abandoned request | `SUPERSEDE_AFTER` | modules/foundation/fs_object/mod.rs | 64 | Policy: refusals of other requests (EBUSY for a write, EAGAIN for a listing) before the write or scan in flight counts as abandoned and is superseded, so a caller that stops asking cannot hold the store |
| object_exchange exchange slots | `EXCHANGE_SLOTS` | modules/foundation/object_exchange/mod.rs | — | Policy, per target class (`abi::config::TARGET_CLASS`): 16 on host-class targets, 2 on MCUs, where each slot's window-sized buffer is a large share of the state arena. A request HEAD past it is refused `503` at once, so a full table never holds back the exchanges it serves |
| object_exchange `if-match` entity tag | `ETAG_MAX` | modules/foundation/object_exchange/mod.rs | 32 | Policy: the longest entity tag a write's `if-match` may name, a SHA-256's width; a longer one is refused `400` rather than cut, since a cut tag names nothing |
| object_exchange records per step | `STEP_RECORD_BUDGET` | modules/foundation/object_exchange/mod.rs | 16 | Budget: request records one step reads and response records one step writes; the rest wait for the next step, never dropped |
| Mounts | `MAX_MOUNTS` | modules/foundation/mount/mod.rs | 8 | Policy: volumes one mount module routes; a backend registering past it fails EBUSY and its mounts resolve ENODEV |
| QUIC peer unidirectional stream credit | `PEER_UNI_CREDIT` | modules/foundation/quic/connection.rs | 6 | Policy, advertised as `initial_max_streams_uni` and re-granted as each finishes: HTTP/3's three critical streams with room for WebTransport's. The cumulative credit is held under the finished-stream window (64 past the lowest unfinished index) so a late frame for any index the peer may use is recognised; the stream holding the window's base ending releases it. A stream past the credit closes the connection with STREAM_LIMIT_ERROR |
| QUIC peer bidirectional stream credit | `PEER_BIDI_CREDIT` | modules/foundation/quic/connection.rs | 3 | Policy, advertised as `initial_max_streams_bidi`: as the unidirectional credit, its window included, lower because each bidirectional stream carries state in both directions |
| QUIC local unidirectional streams | `LOCAL_UNI_STREAMS` | modules/foundation/quic/connection.rs | 3 | Policy: streams of this kind the endpoint opens itself at once; an open past it is refused with `STATUS_NO_CAPACITY` |
| QUIC local bidirectional streams | `LOCAL_BIDI_STREAMS` | modules/foundation/quic/connection.rs | 3 | Policy: as the unidirectional share above |
| QUIC unidirectional stream table | `MAX_UNI_STREAMS` | modules/foundation/quic/connection.rs | 9 | Sized, not chosen: the peer's credit and the local share side by side, so a local open never takes a slot the peer was promised |
| QUIC bidirectional stream table | `MAX_BIDI_STREAMS` | modules/foundation/quic/connection.rs | 6 | Sized, not chosen: as the unidirectional table |
| QUIC connection IDs owed retirement | `RETIRE_QUEUE` | modules/foundation/quic/connection.rs | 4 | Sized, not chosen: at most two of the peer's IDs are active (`active_connection_id_limit` = 2) plus the one the previous path still uses, so no more than three can be owed at once |
| QUIC datagram frame ceiling | `QUIC_DGRAM_MAX` | modules/foundation/quic/connection.rs | 1500 | Policy: the wire layer caps a UDP datagram at one Ethernet MTU |
| QUIC sent-datagram ceiling | `QUIC_MAX_DATAGRAM_SIZE` | modules/foundation/quic/connection.rs | 1200 | Policy: what this endpoint will itself send, held under the MTU ceiling above so a datagram never depends on path discovery to arrive |
| QUIC bidirectional send buffer | `BIDI_SEND_BUF` | modules/foundation/quic/connection.rs | 4096 | Policy: each byte a bidirectional (or the transparent) stream sends is held until the peer acknowledges it, so a lost packet is sent again; the buffer bounds that stream's bytes in flight to a few packets per round trip. An application write with no room is held and the command channel backs up, never refused or truncated |
| QUIC unidirectional send buffer | `UNI_SEND_BUF` | modules/foundation/quic/connection.rs | 256 | Policy: as the bidirectional buffer, for a locally-opened unidirectional stream — typically a small control or metadata channel |
| SMMU stream ids | `MAX_STREAM_IDS` | modules/foundation/smmu/mod.rs | 8 | Policy: stream-id table entries one SMMU module programs; a device past it is refused |
| TLS checkpoint SNI | `CKPT_SNI_MAX` | modules/foundation/tls/continuity.rs | 64 | Policy, wire-visible in the checkpoint record: a session whose server name is longer is not checkpointable, and is refused rather than truncated |
| TLS checkpoint ALPN | `CKPT_ALPN_MAX` | modules/foundation/tls/continuity.rs | 16 | Policy, wire-visible in the checkpoint record: as the server-name ceiling above, for the negotiated protocol name |
| TLS continuity drain | `CONT_DRAIN_BUDGET` | modules/foundation/tls/continuity.rs | 8 | Policy: continuity frames drained per step, so a burst of deltas cannot take a step past the tick |

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
STATE_ARENA_SIZE | src/kernel/config.rs | 1024 * 1024 * 1024 | linux
STATE_ARENA_SIZE | src/kernel/config.rs | 1024 * 1024 * 1024 | bcm2712
STATE_ARENA_SIZE | src/kernel/config.rs | 96 * 1024 * 1024 | wasm-kernel
STATE_ARENA_SIZE | src/kernel/config.rs | crate::platform::chip::STATE_ARENA_SIZE | rp
BUFFER_ARENA_SIZE | src/kernel/config.rs | 16 * 1024 * 1024 | linux
BUFFER_ARENA_SIZE | src/kernel/config.rs | 16 * 1024 * 1024 | bcm2712
BUFFER_ARENA_SIZE | src/kernel/config.rs | 8 * 1024 * 1024 | wasm-kernel
BUFFER_ARENA_SIZE | src/kernel/config.rs | crate::platform::chip::BUFFER_ARENA_SIZE | rp
MAX_MODULE_CONFIG_SIZE | src/kernel/config.rs | crate::platform::chip::MAX_MODULE_CONFIG_SIZE | rp
KERNEL_POOL_SIZE | src/kernel/config.rs | crate::platform::chip::KERNEL_POOL_SIZE | rp
HEAP_SEGMENTS | src/kernel/config.rs | 8 | linux
HEAP_SEGMENTS | src/kernel/config.rs | 8 | bcm2712
HEAP_SEGMENTS | src/kernel/config.rs | 1 | wasm-kernel
HEAP_SEGMENTS | src/kernel/config.rs | 1 | rp
LOG_RING_CAPACITY | src/kernel/config.rs | 65536 | linux
LOG_RING_CAPACITY | src/kernel/config.rs | 65536 | bcm2712
LOG_RING_CAPACITY | src/kernel/config.rs | 16384 | wasm-kernel
LOG_RING_CAPACITY | src/kernel/config.rs | crate::platform::chip::LOG_RING_CAPACITY | rp
ELASTIC_REGION_SIZE | src/kernel/config.rs | 16 * 1024 * 1024 | linux
ELASTIC_REGION_SIZE | src/kernel/config.rs | 16 * 1024 * 1024 | bcm2712
ELASTIC_REGION_SIZE | src/kernel/config.rs | 2 * 1024 * 1024 | wasm-kernel
ELASTIC_REGION_SIZE | src/kernel/config.rs | 0 | rp
MAX_MODULES | src/kernel/config.rs | 4096 | linux
MAX_MODULES | src/kernel/config.rs | 1024 | bcm2712
MAX_MODULES | src/kernel/config.rs | 48 | wasm-kernel
MAX_MODULES | src/kernel/config.rs | 32 | rp
MAX_BRIDGES | src/kernel/config.rs | 16 | linux
MAX_BRIDGES | src/kernel/config.rs | 16 | bcm2712
MAX_BRIDGES | src/kernel/config.rs | 16 | wasm-kernel
MAX_BRIDGES | src/kernel/config.rs | 8 | rp
MAX_MODULE_CODE_SIZE | src/kernel/config.rs | 1024 * 1024 | linux
MAX_MODULE_CODE_SIZE | src/kernel/config.rs | 1024 * 1024 | bcm2712
MAX_MODULE_CODE_SIZE | src/kernel/config.rs | 1024 * 1024 | wasm-kernel
MAX_MODULE_CODE_SIZE | src/kernel/config.rs | 1024 * 1024 | rp+rp2350
MAX_MODULE_CODE_SIZE | src/kernel/config.rs | 384 * 1024 | rp+rp2040
MAX_TCP_CONNS | modules/sdk/abi/config.rs | 65536 | host
MAX_TCP_CONNS | modules/sdk/abi/config.rs | 256 | wasm
MAX_TCP_CONNS | modules/sdk/abi/config.rs | 8 | embedded+rp2350
MAX_TCP_CONNS | modules/sdk/abi/config.rs | 2 | embedded+rp2040
MAX_DG_ENDPOINTS | modules/sdk/abi/config.rs | 256 | host
MAX_DG_ENDPOINTS | modules/sdk/abi/config.rs | 256 | wasm
MAX_DG_ENDPOINTS | modules/sdk/abi/config.rs | 8 | embedded+rp2350
MAX_DG_ENDPOINTS | modules/sdk/abi/config.rs | 2 | embedded+rp2040
MAX_LOCAL_ADDRS | modules/sdk/abi/config.rs | 4096 | host
MAX_LOCAL_ADDRS | modules/sdk/abi/config.rs | 8 | wasm
MAX_LOCAL_ADDRS | modules/sdk/abi/config.rs | 8 | embedded
MAX_PACKET_HOLD | modules/sdk/abi/config.rs | 32 | host
MAX_PACKET_HOLD | modules/sdk/abi/config.rs | 8 | wasm
MAX_PACKET_HOLD | modules/sdk/abi/config.rs | 4 | embedded
LANE_CEILING | src/kernel/workload/net_attach.rs | 255 | *
STATIC_LANES | src/kernel/workload/net_attach.rs | 16 | static-tables
STATIC_LANES | src/kernel/workload/net_attach.rs | 0 | boot-sized
MAX_CONTRACTS | src/kernel/module/provider.rs | 64 | *
CONTRACT_ID_POSITIONS_ASSIGNED | tools/src/manifest.rs | 32 | *
MAX_BUFFER_SLOTS | src/kernel/ipc/buffer_pool.rs | MAX_CHANNELS | *
MAX_OWNERS | src/kernel/workload/owner.rs | 4096 | linux-multitenant
MAX_OWNERS | src/kernel/workload/owner.rs | 64 | multitenant-non-linux
MAX_OWNERS | src/kernel/workload/owner.rs | 1 | single-owner
MAX_PATH | modules/sdk/abi/config.rs | 200 | host
MAX_PATH | modules/sdk/abi/config.rs | 32 | wasm
MAX_PATH | modules/sdk/abi/config.rs | 32 | embedded
RECORD_MAX | modules/sdk/contracts/exchange.rs | 8192 | *
PAYLOAD_MAX | modules/sdk/contracts/exchange.rs | 8192 | *
KEY_MAX | modules/sdk/contracts/exchange.rs | 512 | *
CAPACITY | src/kernel/sys/telemetry_ring.rs | 4096 | chip-rp2040
CAPACITY | src/kernel/sys/telemetry_ring.rs | 8192 | rp2350-chip
CAPACITY | src/kernel/sys/telemetry_ring.rs | round_capacity(PSTATUS_ROUND) | non-rp
RING_CONSUMERS | modules/sdk/contracts/telemetry.rs | 4 | *
TELEMETRY_MAX_RECORD | src/kernel/exec/scheduler/module_types.rs | 144 | *
DIM_MAX_PRODUCT | modules/sdk/contracts/telemetry.rs | 65534 | *
MAX_MODULES_BLOB_SIZE | src/kernel/module/loader.rs | 8 * 1024 * 1024 | *
MAX_CONTRACTS_PER_PROVIDER | src/kernel/module/loader.rs | 4 | *
STAGE_CAPACITY | src/kernel/module/ota_stage.rs | 8 * 1024 * 1024 | *
MAX_RING_BYTES | src/kernel/ipc/ring_size.rs | 4 * 1024 * 1024 | *
MAX_CONNS | modules/sdk/abi/config.rs | 64 | host
MAX_CONNS | modules/sdk/abi/config.rs | 8 | wasm
MAX_CONNS | modules/sdk/abi/config.rs | 2 | embedded
MAX_SESSIONS | modules/sdk/abi/config.rs | 512 | host
MAX_SESSIONS | modules/sdk/abi/config.rs | 64 | wasm
MAX_SESSIONS | modules/sdk/abi/config.rs | 1 | embedded
MAX_STREAMS | modules/sdk/abi/config.rs | 4 | host
MAX_STREAMS | modules/sdk/abi/config.rs | 4 | wasm
MAX_STREAMS | modules/sdk/abi/config.rs | 4 | embedded
MAX_ROUTES | modules/sdk/abi/config.rs | 8 | host
MAX_ROUTES | modules/sdk/abi/config.rs | 4 | wasm
MAX_ROUTES | modules/sdk/abi/config.rs | 4 | embedded
MAX_CHAIN_DEPTH | src/kernel/module/provider.rs | 3 | chip-rp2040
MAX_CHAIN_DEPTH | src/kernel/module/provider.rs | 4 | rp2350-chip
MAX_CHAIN_DEPTH | src/kernel/module/provider.rs | 8 | non-rp
MAX_ROUTES | src/kernel/module/provider.rs | 16 | chip-rp2040
MAX_ROUTES | src/kernel/module/provider.rs | 32 | rp2350-chip
MAX_ROUTES | src/kernel/module/provider.rs | 128 | non-rp
MAX_SLOTS | src/kernel/security/key_vault.rs | 64 | host
MAX_SLOTS | src/kernel/security/key_vault.rs | 8 | off-host
MAX_SLOTS | src/platform/linux/hsm_key_vault.rs | 8 | *
TAG_MAX | src/platform/linux/instance.rs | 32 | *
STEM_MAX | src/platform/linux/instance.rs | 6 | *
RULE_PRIORITY_MAIN | src/platform/linux/instance.rs | 32766 | *
RSA_ENTRIES | src/kernel/security/key_vault.rs | 2 | rsa-vault
RSA_MODULUS_BITS_MAX | modules/sdk/crypto/rsa.rs | 4096 | *
RSA_EXPONENT_BITS_MAX | modules/sdk/crypto/rsa.rs | 32 | *
MAX_OPEN_FILES | modules/foundation/fat32/mod.rs | 256 | host
MAX_OPEN_FILES | modules/foundation/fat32/mod.rs | 8 | off-host
DIR_SCAN_BUDGET_SECTORS | modules/foundation/fat32/mod.rs | 32 | host
DIR_SCAN_BUDGET_SECTORS | modules/foundation/fat32/mod.rs | 6 | off-host
LFN_MAX_CHARS | modules/foundation/fat32/mod.rs | 64 | *
FAT_SCAN_BUDGET_SECTORS | modules/foundation/fat32/mod.rs | 32 | *
CALL_BUDGET_US | modules/foundation/fat32/mod.rs | 400 | *
MAX_FENCES | modules/foundation/fat32/mod.rs | MAX_OPEN_FILES | *
CACHE_SLOTS | modules/foundation/fat32/mod.rs | 128 | host
CACHE_SLOTS | modules/foundation/fat32/mod.rs | 24 | off-host
FS_OP_SLOTS | modules/foundation/fat32/mod.rs | 4 | *
ZERO_RUN_SLOTS | modules/foundation/fat32/mod.rs | 4 | *
EPOCH_WINDOW | modules/foundation/fat32/mod.rs | 56 | *
TX_BARRIER_MAX | modules/foundation/fat32/mod.rs | 24 | *
OP_ARG_MAX | modules/foundation/fat32/mod.rs | 512 | *
MAX_INFLIGHT | modules/drivers/nvme/mod.rs | 32 | host
MAX_INFLIGHT | modules/drivers/nvme/mod.rs | 8 | off-host
V1_SLOTS | modules/drivers/nvme/mod.rs | 16 | *
V1_FLUSH_SLOTS | modules/drivers/nvme/mod.rs | 4 | *
MAX_IO_QUEUES | modules/drivers/nvme/mod.rs | 4 | *
MAX_NLB | modules/drivers/nvme/mod.rs | 8 | *
ASYNC_BULK_SLOTS | modules/drivers/nvme/mod.rs | 8 | *
HELD_MAX | modules/drivers/nvme/mod.rs | 8 | *
MAX_BULK_PAGES | modules/drivers/nvme/mod.rs | 32 | *
QUEUE_DEPTH | modules/foundation/file_block/mod.rs | 8 | *
MAX_BLOCKS | modules/foundation/file_block/mod.rs | 64 | *
PATH_CAP | modules/foundation/file_block/mod.rs | 96 | *
VOLUME_CAP | modules/foundation/file_block/mod.rs | 16 | *
MAX_UNIT | modules/foundation/crypt_block/mod.rs | 4096 | *
MAX_LOWER_BLOCK | modules/foundation/crypt_block/mod.rs | 4096 | *
QUEUE_DEPTH | modules/foundation/crypt_block/mod.rs | 8 | *
MAX_JOURNAL_RECORDS | modules/foundation/crypt_block/mod.rs | 64 | *
NONCE_STRIDE | modules/foundation/crypt_block/mod.rs | 1 << 20 | *
KEY_LABEL_CAP | modules/foundation/crypt_block/mod.rs | 64 | *
MIGRATE_BATCH | modules/foundation/crypt_block/mod.rs | 8 | *
STEP_BUDGET | modules/foundation/crypt_block/mod.rs | 4096 | *
MAX_FRAMES | modules/foundation/crypt_block/mod.rs | 5 | *
MAX_SLOTS | modules/foundation/nbd_serve/mod.rs | 8 | *
SLOT_SIZE | modules/foundation/nbd_serve/mod.rs | 16384 | *
MAX_REQUESTS | modules/foundation/nbd_serve/mod.rs | 16 | *
MAX_REQUEST_BYTES | modules/foundation/nbd_serve/mod.rs | 32 << 20 | *
EXPORT_NAME_CAP | modules/foundation/nbd_serve/mod.rs | 64 | *
OPT_BUF_SIZE | modules/foundation/nbd_serve/mod.rs | 512 | *
OUT_DATA_MAX | modules/foundation/nbd_serve/mod.rs | 4096 | *
STEP_FRAME_BUDGET | modules/foundation/nbd_serve/mod.rs | 16 | *
STEP_SEND_BUDGET | modules/foundation/nbd_serve/mod.rs | 16 | *
STEP_REAP_BUDGET | modules/foundation/nbd_serve/mod.rs | 16 | *
MAX_AUTHORITY_LEN | modules/foundation/ota_registry/mod.rs | 128 | *
DIRECTIVE_RECORD_MAX | modules/foundation/ota_registry/mod.rs | 256 | *
MAX_CERT_LEN | modules/foundation/tls/mod.rs | 2048 | *
MAX_CERT_CHAIN_BYTES | modules/foundation/tls/mod.rs | 3072 | *
MAX_KEY_LEN | modules/foundation/tls/mod.rs | 2400 | *
MAX_EXPECTED_DNS | modules/foundation/tls/mod.rs | 64 | *
MAX_EXPECTED_URI | modules/foundation/tls/mod.rs | 256 | *
DTLS_AUTHORITY_MAX | modules/foundation/tls/mod.rs | 64 | *
MAX_PEERS | modules/foundation/tls/mod.rs | 4 | host
MAX_PEERS | modules/foundation/tls/mod.rs | 1 | off-host
DGRAM_MAX | modules/foundation/tls/mod.rs | 1500 | *
MAX_FLIGHT_RECORDS | modules/foundation/tls/mod.rs | 8 | *
MAX_COMPAT_CCS | modules/foundation/tls/mod.rs | 2 | *
RECV_BUF_SIZE | modules/foundation/tls/mod.rs | 16704 | host
RECV_BUF_SIZE | modules/foundation/tls/mod.rs | 4096 | off-host
RETX_BUF_SIZE | modules/foundation/tls/mod.rs | 4096 | *
TLS_INBOUND_DRAIN_BUDGET | modules/foundation/tls/mod.rs | 8 | *
MAX_PASSTHROUGH | modules/foundation/tls/mod.rs | MAX_SESSIONS | *
MAX_AUTHORITY | modules/foundation/quic/mod.rs | MAX_PEER_NAME + 6 | *
MAX_PEER_NAME | modules/foundation/quic/mod.rs | 64 | *
MAX_CERT_LEN | modules/foundation/quic/mod.rs | 1024 | *
MAX_ALPN_CFG | modules/foundation/quic/mod.rs | 64 | *
MAX_TICKETS | modules/foundation/quic/mod.rs | 4 | *
TRANSPARENT_READ_MAX | modules/foundation/quic/mod.rs | 1200 | *
MAX_PENDING | modules/foundation/dns/mod.rs | 8 | *
UPSTREAM_AUTHORITY_MAX | modules/foundation/dns/mod.rs | 64 | *
UPSTREAM_PATH_MAX | modules/foundation/dns/mod.rs | 64 | *
DNSSEC_SIGNED_MAX | modules/foundation/dns/mod.rs | 4096 | *
MAX_ANCHORS | modules/foundation/dns/mod.rs | 4 | *
MAX_ANCHOR_RDATA | modules/foundation/dns/mod.rs | 1028 | *
MAX_HOSTS | modules/foundation/dns/mod.rs | 16 | *
MAX_NAME_LEN | modules/sdk/contracts/net/dns_wire.rs | 255 | *
MAX_NAME_PTR_HOPS | modules/sdk/contracts/net/dns_wire.rs | 16 | *
MAX_SECTION_RRS | modules/sdk/contracts/net/dns_wire.rs | 32 | *
MAX_CNAME_HOPS | modules/foundation/dns/mod.rs | 4 | *
MAX_CHAIN_BYTES | modules/foundation/dns/mod.rs | 384 | *
MAX_SYNTH_ADDRS | modules/foundation/dns/mod.rs | 8 | *
MAX_DNS64_EXCLUDES | modules/foundation/dns/mod.rs | 16 | *
DNS64_TTL_CAP_S | modules/foundation/dns/mod.rs | 600 | *
MAX_ZONE_RRS | modules/foundation/dns/mod.rs | 64 | host
MAX_ZONE_RRS | modules/foundation/dns/mod.rs | 16 | off-host
MAX_UPDATE_RRS | modules/foundation/dns/mod.rs | 32 | *
MAX_ZONE_NAME | modules/foundation/dns/mod.rs | 128 | *
MAX_ZONE_RDATA | modules/foundation/dns/mod.rs | 128 | *
MAX_UPDATE_KEYS | modules/foundation/dns/mod.rs | 4 | *
MAX_TSIG_FUDGE_S | modules/foundation/dns/mod.rs | 300 | *
MAX_TXN_CACHE | modules/foundation/dns/mod.rs | 4 | *
TXN_RETAIN_MS | modules/foundation/dns/mod.rs | 30000 | *
MAX_ZIO_CALLS_PER_STEP | modules/foundation/dns/mod.rs | 64 | *
PEND_Q_MAX | modules/foundation/dns/mod.rs | DNS_HEADER_LEN + MAX_NAME_LEN + 1 + 4 | *
MAX_OPEN | modules/foundation/mount/mod.rs | 64 | *
MAX_LAYERS | modules/foundation/ota_registry/mod.rs | 48 | *
MAX_DMA_MAPS | modules/foundation/smmu/mod.rs | 32 | *
MAX_SHADOW_SLOTS | modules/foundation/quic/continuity.rs | 2 | *
CHECKPOINT_RECORD_MAX | modules/foundation/quic/continuity.rs | 49152 | *
ARP_WAIT_MAX | modules/foundation/ip/mod.rs | 64 | *
RX_DESC_COUNT | modules/drivers/rp1_gem/mod.rs | 192 | *
FAN_FRAMES_PER_STEP | src/kernel/exec/scheduler/module_types.rs | 64 | *
ALLOC_SCAN_SLICE | modules/foundation/ip/mod.rs | 256 | *
SWEEP_SLICE_MAX | modules/foundation/ip/mod.rs | 1024 | *
MAX_TCP_SHADOWS | modules/sdk/abi/config.rs | 8 | host
MAX_TCP_SHADOWS | modules/sdk/abi/config.rs | 2 | wasm
MAX_TCP_SHADOWS | modules/sdk/abi/config.rs | 1 | embedded
FENCE_WIRE_WAIT_MS | modules/foundation/ip/mod.rs | 500 | *
NET_OUT_FRAME_MAX | modules/foundation/ip/mod.rs | NET_FRAME_HDR + abi::contracts::net::net_proto::PEER_LEN | *
MAX_TLS_SHADOWS | modules/foundation/tls/continuity.rs | 2 | host
MAX_TLS_SHADOWS | modules/foundation/tls/continuity.rs | 1 | wasm
MAX_TLS_SHADOWS | modules/foundation/tls/continuity.rs | 0 | embedded
TLS_CKPT_RECORD_MAX | modules/foundation/tls/continuity.rs | CKPT_FIXED_LEN + RECV_BUF_SIZE + RETX_BUF_SIZE + TLS_SEALED_LEN | *
TX_HOLD_SIZE | modules/foundation/tls/continuity.rs | TX_HOLD_RECORDS * WIRE_RECORD_MAX | *
LOCAL_PN_BLOCK | modules/foundation/quic/connection.rs | 4096 | *
STEP_BUDGET_DEFAULT_TICK_US | tools/src/target_facts.rs | 1000 | *
MAX_FRAME_SIZE | modules/foundation/ip/mod.rs | 1536 | *
MAX_LISTENERS | modules/foundation/ip/mod.rs | if tcp::MAX_TCP_CONNS < 1024 { tcp::MAX_TCP_CONNS } else { 1024 } | *
MAX_ALLOW_TYPES | modules/foundation/dns/mod.rs | 8 | *
MAX_FILES | modules/foundation/fat32/mod.rs | 128 | *
UNLINK_FREE_SLOTS | modules/foundation/fat32/mod.rs | 8 | *
MAX_DIR_CLUSTERS | modules/foundation/fat32/mod.rs | 65_536 | *
DIR_CACHE | modules/foundation/fat32/mod.rs | 2 | *
ROOT_MAX | modules/foundation/fs_object/mod.rs | 96 | *
READS | modules/foundation/fs_object/mod.rs | 8 | *
PAGE_KEYS | modules/foundation/fs_object/mod.rs | 16 | *
SCAN_OPENS_PER_CALL | modules/foundation/fs_object/mod.rs | 8 | *
WRITE_CHUNK | modules/foundation/fs_object/mod.rs | 4096 | *
HASH_CHUNK | modules/foundation/fs_object/mod.rs | 4096 | *
SUPERSEDE_AFTER | modules/foundation/fs_object/mod.rs | 64 | *
EXCHANGE_SLOTS | modules/foundation/object_exchange/mod.rs | if abi::config::TARGET_CLASS == abi::config::target_class::HOST { 16 } else { 2 } | *
ETAG_MAX | modules/foundation/object_exchange/mod.rs | 32 | *
STEP_RECORD_BUDGET | modules/foundation/object_exchange/mod.rs | 16 | *
MAX_MOUNTS | modules/foundation/mount/mod.rs | 8 | *
PEER_UNI_CREDIT | modules/foundation/quic/connection.rs | 6 | *
PEER_BIDI_CREDIT | modules/foundation/quic/connection.rs | 3 | *
LOCAL_UNI_STREAMS | modules/foundation/quic/connection.rs | 3 | *
LOCAL_BIDI_STREAMS | modules/foundation/quic/connection.rs | 3 | *
MAX_UNI_STREAMS | modules/foundation/quic/connection.rs | PEER_UNI_CREDIT + LOCAL_UNI_STREAMS | *
MAX_BIDI_STREAMS | modules/foundation/quic/connection.rs | PEER_BIDI_CREDIT + LOCAL_BIDI_STREAMS | *
RETIRE_QUEUE | modules/foundation/quic/connection.rs | 4 | *
QUIC_DGRAM_MAX | modules/foundation/quic/connection.rs | 1500 | *
QUIC_MAX_DATAGRAM_SIZE | modules/foundation/quic/connection.rs | 1200 | *
BIDI_SEND_BUF | modules/foundation/quic/connection.rs | 4096 | *
UNI_SEND_BUF | modules/foundation/quic/connection.rs | 256 | *
MAX_STREAM_IDS | modules/foundation/smmu/mod.rs | 8 | *
CKPT_SNI_MAX | modules/foundation/tls/continuity.rs | 64 | *
CKPT_ALPN_MAX | modules/foundation/tls/continuity.rs | 16 | *
CONT_DRAIN_BUDGET | modules/foundation/tls/continuity.rs | 8 | *
MAX_CONCURRENT_CONNS | modules/sdk/abi/config.rs | 256 | host
MAX_CONCURRENT_CONNS | modules/sdk/abi/config.rs | 256 | wasm
MAX_CONCURRENT_CONNS | modules/sdk/abi/config.rs | 4 | embedded+rp2350
MAX_CONCURRENT_CONNS | modules/sdk/abi/config.rs | 1 | embedded+rp2040
RECV_BUF_SIZE | modules/sdk/abi/config.rs | 8192 | host
RECV_BUF_SIZE | modules/sdk/abi/config.rs | 4096 | wasm
RECV_BUF_SIZE | modules/sdk/abi/config.rs | 2048 | embedded
SEND_BUF_SIZE | modules/sdk/abi/config.rs | 4100 | host
SEND_BUF_SIZE | modules/sdk/abi/config.rs | 4100 | wasm
SEND_BUF_SIZE | modules/sdk/abi/config.rs | 4100 | embedded
MAX_DYN_ROUTES | modules/sdk/abi/config.rs | 64 | host
MAX_DYN_ROUTES | modules/sdk/abi/config.rs | 8 | wasm
MAX_DYN_ROUTES | modules/sdk/abi/config.rs | 8 | embedded
MAX_ROUTE_BACKENDS | modules/sdk/abi/config.rs | 8 | host
MAX_ROUTE_BACKENDS | modules/sdk/abi/config.rs | 4 | wasm
MAX_ROUTE_BACKENDS | modules/sdk/abi/config.rs | 4 | embedded
MAX_FS_PATH | modules/sdk/abi/config.rs | 256 | host
MAX_FS_PATH | modules/sdk/abi/config.rs | 64 | wasm
MAX_FS_PATH | modules/sdk/abi/config.rs | 64 | embedded
DEFAULT_BODY_POOL_SIZE | modules/sdk/abi/config.rs | 256 * 1024 | host
DEFAULT_BODY_POOL_SIZE | modules/sdk/abi/config.rs | 32 * 1024 | wasm
DEFAULT_BODY_POOL_SIZE | modules/sdk/abi/config.rs | 16 * 1024 | embedded+rp2350
DEFAULT_BODY_POOL_SIZE | modules/sdk/abi/config.rs | 4 * 1024 | embedded+rp2040
FAN_BUF_SIZE | src/kernel/exec/scheduler/module_types.rs | 32768 | host
FAN_BUF_SIZE | src/kernel/exec/scheduler/module_types.rs | 2048 | rp-small
FAN_BUF_SIZE | src/kernel/exec/scheduler/module_types.rs | 8192 | rp-large
MAX_GRAPH_EDGES | src/kernel/boot/config.rs | 255 * 128 | boot-sized
MAX_GRAPH_EDGES | src/kernel/boot/config.rs | crate::kernel::config::GRAPH_EDGES | static-tables
SMALL_GRAPH_EDGES | src/kernel/boot/config.rs | 128 | *
MAX_CHANNELS | src/kernel/ipc/channel.rs | MAX_GRAPH_EDGES | *
MAX_SPI_BUSES | src/kernel/boot/config.rs | 2 | *
MAX_I2C_BUSES | src/kernel/boot/config.rs | 2 | *
MAX_UART_BUSES | src/kernel/boot/config.rs | 2 | *
MAX_PIO_CONFIGS | src/kernel/boot/config.rs | 3 | *
MAX_GPIO_CONFIGS | src/kernel/boot/config.rs | 8 | *
MAX_WORKLOAD_SECTION_BYTES | src/kernel/boot/config.rs | 8 * 1024 | *
TICK_BOUND_MAX | src/kernel/boot/config.rs | 50_000 | *
MAX_FREE_REGIONS | src/kernel/ipc/buffer_pool.rs | 128 | *
MAX_FREE_REGIONS | src/kernel/module/loader.rs | crate::kernel::config::static_slots(crate::abi::contracts::resource::POOL_STATE_FREE_LIST) | *
ISO_ARENA_SIZE | src/kernel/module/loader.rs | 2 * 1024 * 1024 | kernel-vm
MAX_TRACKED | src/kernel/module/provider.rs | crate::kernel::config::static_slots(crate::abi::contracts::resource::POOL_TRACKED_HANDLES) | *
MAX_EVENTS | src/kernel/ipc/event.rs | crate::kernel::config::static_slots(crate::abi::contracts::resource::POOL_EVENTS) | *
MAX_TIMERS | src/kernel/ipc/fd.rs | crate::kernel::config::static_slots(crate::abi::contracts::resource::POOL_TIMERS) | *
MAX_TABLES | src/kernel/net_policy.rs | crate::kernel::config::static_slots(res::POOL_NET_POLICY_TABLES) | *
MAX_TABLE_BYTES | src/kernel/net_policy.rs | crate::kernel::config::static_slots(res::POOL_NET_POLICY_TABLE_BYTES) | *
MAX_SEGMENTS | src/kernel/net_route.rs | crate::kernel::config::static_slots(res::POOL_NET_ROUTE_SEGMENTS) | *
MAX_PEERS | src/kernel/net_route.rs | crate::kernel::config::static_slots(res::POOL_NET_ROUTE_PEERS) | *
MAX_HELD | src/kernel/net_route.rs | crate::kernel::config::static_slots(res::POOL_NET_ROUTE_HELD) | *
MAX_CLUSTER_PREFIXES | modules/sdk/contracts/net/route.rs | 8 | *
READ_RETRIES | src/kernel/net_policy.rs | 8 | *
WRITER_SPINS | src/kernel/net_policy.rs | 1 << 16 | *
STATE_SPINS | src/kernel/net_route.rs | 1 << 16 | *
DG_REPLY_FROM_MAX | src/platform/linux/providers.rs | 64 | *
MAX_OPEN_FILES | src/platform/linux/providers.rs | 256 | *
LINUX_FS_PATH_MAX | src/platform/linux/providers.rs | 255 | *
MAX_PROCS | src/platform/linux/providers.rs | 8 | *
LINUX_NET_MAX_CONNS_CAP | src/platform/linux/providers.rs | 65535 | *
LINUX_NET_CMD_MAX | src/platform/linux/providers.rs | 49152 | *
PENDING_CTRL_CAP | src/platform/linux/providers.rs | 256 | *
CTRL_FRAME_MAX | src/platform/linux/providers.rs | 3 + crate::abi::contracts::net::net_proto::PEER_LEN | *
DNS_CACHE_SLOTS | src/platform/linux/providers.rs | 32 | *
MAX_DIAL_CANDIDATES | src/platform/linux/providers.rs | 4 | *
PER_TICK_ACCEPT_BUDGET | src/platform/linux/providers.rs | 32 | *
MAX_OBJECTS | src/platform/bcm2712/store.rs | 512 | *
MAX_VALUE | src/platform/bcm2712/store.rs | 4096 | *
MAX_CROSS_CHANNELS | src/platform/bcm2712/multicore.rs | 256 | *
MAX_DOMAINS | src/platform/bcm2712/multicore.rs | 4 | *
MAX_DOMAINS | src/kernel/exec/scheduler/mod.rs | 4 | *
MAX_MODULES | src/kernel/exec/scheduler/mod.rs | CONFIG_MAX_MODULES | *
MAX_CHANNELS | src/kernel/exec/scheduler/mod.rs | MAX_GRAPH_EDGES | *
MAX_BURST_STEPS | src/kernel/exec/scheduler/mod.rs | 16384 | *
MAX_DRAIN_MS | src/kernel/exec/scheduler/mod.rs | 30_000 | *
MAX_PRE_TICK_PER_DOMAIN | src/kernel/exec/scheduler/mod.rs | 4 | *
MAX_PRE_TICK_BUDGET_US | src/kernel/exec/scheduler/mod.rs | 5 | *
MAX_NAMES | src/kernel/exec/scheduler/mod.rs | MAX_MODULES | *
MAX_NAME_LEN | src/kernel/exec/scheduler/mod.rs | 32 | *
MAX_SECONDARY_CORES | src/platform/bcm2712/multicore.rs | 3 | *
RING_SLOTS | src/platform/bcm2712/multicore.rs | 8 | *
SLOT_DATA_SIZE | src/platform/bcm2712/multicore.rs | crate::abi::CHANNEL_BUFFER_SIZE | *
DMA_ARENA_SIZE | src/platform/bcm2712/multicore.rs | 64 * 1024 | *
CORE_STACK_SIZE | src/platform/bcm2712/multicore.rs | 1024 * 1024 | *
STACK_GUARD_SIZE | src/platform/bcm2712/multicore.rs | 4096 | *
GRAPH_EDGES | src/kernel/config.rs | 128 | wasm-kernel
GRAPH_EDGES | src/kernel/config.rs | 128 | rp
MAX_BLOB | src/kernel/boot/dtb.rs | 2 * 1024 * 1024 | *
MAX_DEPTH | src/kernel/boot/dtb.rs | 16 | *
MAX_MEMORY_RANGES | src/kernel/boot/dtb.rs | 16 | *
MAX_RESERVED_RANGES | src/kernel/boot/dtb.rs | 32 | *
MAX_CELLS | src/kernel/boot/dtb.rs | 4 | *
RECYCLE_SLOTS | src/kernel/mem/carve.rs | 16 | *
ZERO_AHEAD_BYTES | src/kernel/config.rs | 64 * 1024 * 1024 | bcm2712
ZERO_CHUNK_BYTES | src/kernel/config.rs | 64 * 1024 | bcm2712
DEFAULT_RESERVES | src/kernel/config.rs | - | *
STATIC_POOLS | src/kernel/config.rs | - | *
MAX_PROVIDERS | src/kernel/module/provider.rs | MAX_CONTRACTS | *
MAX_DYN_TAG_ROUTES | src/kernel/module/provider.rs | 4 | *
MAX_KEY_BYTES | src/kernel/security/key_vault.rs | 64 | *
MAX_LABEL | src/kernel/security/key_vault.rs | 64 | *
MAX_PERSISTED | src/kernel/security/key_vault.rs | 64 | host
MAX_PERSISTED | src/kernel/security/key_vault.rs | 8 | off-host
MAX_SEAL_BYTES | src/kernel/security/key_vault.rs | 2048 | *
MAX_CONSUMED | src/kernel/security/key_share.rs | 32 | *
PARAM_TAG_MAX | tools/src/manifest.rs | 0xED | *
MAX_CHAIN_LINKS | modules/sdk/contracts/mesh/capability.rs | 8 | *
MAX_CHAIN_BYTES | modules/sdk/contracts/mesh/capability.rs | CHAIN_HDR + MAX_CHAIN_LINKS * LINK_LEN | *
MAX_ROOTS | modules/sdk/contracts/mesh/capability.rs | 2 | *
MAX_SESSION_GRANTS | modules/sdk/contracts/mesh/capability.rs | 8 | *
PRESENT_MAX | modules/sdk/contracts/mesh/capability.rs | 4 + MAX_CHAIN_BYTES | *
MAX_TEXT_LEN | modules/sdk/contracts/mesh/capability.rs | 1375 | *
LIST_PAGE_MAX | modules/sdk/contracts/storage/object.rs | 1000 | *
STORAGE_KEY_MAX | modules/sdk/contracts/storage/handle.rs | 255 | *
PATH_MAX | modules/sdk/contracts/storage/namespace.rs | 1024 | *
MAX_PRIVATE | src/kernel/module/gateway.rs | 3 | *
WALK_MAX | src/kernel/module/gateway.rs | 544 | *
MAX_CHANNELS | modules/foundation/remote_channel/wire.rs | 8 | *
CT_NAME_MAX | modules/foundation/remote_channel/wire.rs | 32 | *
HELLO_MAX | modules/foundation/remote_channel/wire.rs | 4 + 1 + MAX_CHANNELS * HELLO_ENTRY_LEN + 1 | *
MAX_RECORD | modules/foundation/remote_channel/mod.rs | 256 * 1024 | host
MAX_RECORD | modules/foundation/remote_channel/mod.rs | 128 * 1024 | wasm
MAX_RECORD | modules/foundation/remote_channel/mod.rs | 16 * 1024 | embedded
REASSEMBLY_BYTES | modules/foundation/remote_channel/mod.rs | 1024 * 1024 | host
REASSEMBLY_BYTES | modules/foundation/remote_channel/mod.rs | 256 * 1024 | wasm
REASSEMBLY_BYTES | modules/foundation/remote_channel/mod.rs | 32 * 1024 | embedded
FRAGMENT_MAX | modules/foundation/remote_channel/mod.rs | 4096 | *
MUX_FRAGMENT_MAX | modules/foundation/remote_channel/mod.rs | 1192 | *
OPEN_EXCHANGES_MAX | modules/foundation/remote_channel/mod.rs | if abi::config::TARGET_CLASS == abi::config::target_class::HOST { 256 } else { 32 } | *
MAX_PARAMS | tools/src/params.rs | 64 | *
MAX_PARAM_STRING_BYTES | tools/src/params.rs | 4096 | *
MAX_PARAM_NAME_BYTES | tools/src/params.rs | 64 | *
SCOPE_MAX | modules/sdk/contracts/storage/object.rs | 255 | *
STORE_STAGE_MAX | src/platform/linux/store.rs | 64 * 1024 * 1024 | *
STORE_STAGE_RESERVE_MAX | src/platform/linux/store.rs | 1024 * 1024 | *
OWNER_MAX_OPEN_FILES | src/kernel/workload/storage.rs | 32 | *
MAX_SANDBOXES | src/platform/linux/host_backend.rs | 4096 | *
MAX_TTY_SESSIONS | src/platform/linux/host_backend.rs | 4096 | *
USER_DB_MAX | src/platform/linux/host_backend.rs | 4 << 20 | *
OWNER_STAGE_MAX | src/platform/linux/store.rs | 16 * 1024 * 1024 | *
```

Constants in these files that are shaped like ceilings but are not
resource decisions — record layouts, scratch sized from a ceiling above,
protocol constants, mirrors of a registered symbol — are excluded from
the coverage report here, each with the reason it is not a row.

```limit-register-exempt
BODY_MAX | modules/sdk/contracts/exchange.rs | derived: one RECORD_MAX record less its 16-byte prefix
MAX_DG_ENDPOINTS | modules/foundation/ip/mod.rs | variant: the `small_table` override of the registered abi::config::ip ceiling, never above it — DHCP, a log or telemetry sink and one more, within that variant's four-slot table
CTRL_CAP | modules/foundation/nbd_serve/mod.rs | derived: the longest handshake answer, EXPORT_NAME's 134 bytes with the pad, or GO's two infos and ACK
INFO_BLOCK_SIZE | modules/foundation/nbd_serve/mod.rs | protocol: the NBD info type number for block-size constraints
NET_CMD_RECORD_CAPACITY | modules/foundation/tls/mod.rs | derived: the frame scratch less overhead, capped by net_proto MAX_CMD_DATA
CLEAR_CHUNK_MAX | modules/foundation/tls/mod.rs | derived: the record payload budget of NET_CMD_RECORD_CAPACITY
HS_FRAGMENT_MAX | modules/foundation/tls/mod.rs | derived: the same budget less the appended ChangeCipherSpec record
WIRE_RECORD_MAX | modules/foundation/tls/mod.rs | derived: equals NET_CMD_RECORD_CAPACITY; sizes the record staging buffers
NET_SCRATCH_SIZE | modules/foundation/tls/mod.rs | scratch: one net frame around one TLS record
MAX_KEY_LEN | modules/foundation/quic/mod.rs | mirror of the registered tls MAX_KEY_LEN, so a key_file shared between them packs identically
BLOCK_SIZE | modules/drivers/nvme/mod.rs | format: the 512-byte sector the channel stream moves
PAGER_WRITE_SLOTS | modules/drivers/nvme/mod.rs | derived: ASYNC_BULK_SLOTS * MAX_BULK_PAGES
REG_CAP | modules/drivers/nvme/mod.rs | register offset: controller capabilities
REQ_HDR_SIZE | modules/drivers/nvme/mod.rs | wire: the channel write-request header
SQE_SIZE | modules/drivers/nvme/mod.rs | format: the 64-byte NVMe submission entry, re-exported to the host-test controller model
CQE_SIZE | modules/drivers/nvme/mod.rs | format: the 16-byte NVMe completion entry, re-exported to the host-test controller model
IO_READ_BUDGET | modules/drivers/nvme/mod.rs | mirror of IO_READ_BUDGET_MS, a timeout and not a capacity, re-exported to the host-test controller model
PAGER_SUBMIT_BUDGET | modules/drivers/nvme/mod.rs | mirror of PAGER_SUBMIT_BUDGET_MS, a timeout and not a capacity, re-exported to the host-test controller model
MAX_HEADER | src/kernel/security/key_vault.rs | derived: the persisted-record header, magic through the longest label
MAX_BLOB_NAME | src/kernel/security/key_vault.rs | derived: the durable name, namespace and the longest label
PEER_MAX | src/kernel/security/key_share.rs | derived: an uncompressed P-256 point, the one encapsulation an envelope carries
MUX_DATA_MAX | modules/foundation/quic/mod.rs | derived: mux::MUX_QUIC_STREAM_RX_MAX, the contract's published bound
NET_BUF_SIZE | modules/foundation/quic/mod.rs | scratch: one net frame around one QUIC packet
ERR_STREAM_LIMIT | modules/foundation/quic/connection.rs | RFC 9000 §20.1 transport error code STREAM_LIMIT_ERROR, a protocol constant
ERR_CONNECTION_ID_LIMIT | modules/foundation/quic/connection.rs | RFC 9000 §20.1 transport error code CONNECTION_ID_LIMIT_ERROR, a protocol constant
STATE_ARENA_SIZE | src/kernel/module/loader.rs | mirror of the registered src/kernel/config.rs ceiling, re-exported for the loader
RSA_BYTES_MAX | modules/sdk/crypto/rsa.rs | derived: RSA_MODULUS_BITS_MAX in bytes
RSA_LIMBS_MAX | modules/sdk/crypto/rsa.rs | derived: RSA_MODULUS_BITS_MAX in limbs of the target's word
RSA_HALF_LIMBS_MAX | modules/sdk/crypto/rsa.rs | derived: a CRT prime is half the modulus
BUF_SIZE | modules/drivers/rp1_gem/mod.rs | DMA scratch sized by the ring, not a policy ceiling
MAX_FRAME | modules/drivers/rp1_gem/mod.rs | Ethernet frame size, a protocol constant (MTU + headers)
STATE_SIZE | modules/drivers/rp1_gem/mod.rs | size_of the driver state, not a ceiling
NET_BUF_SIZE | modules/foundation/dns/mod.rs | scratch: one net frame around one DNS packet
MAX_LABEL_LEN | modules/sdk/contracts/net/dns_wire.rs | RFC 1035 label length, a protocol constant
MAX_ZONE_PATH | modules/foundation/dns/mod.rs | path scratch for the committed-generation file name
ZONE_RECORD_MAX | modules/foundation/dns/mod.rs | derived from the registered zone name and rdata ceilings
MAX_ZONE_FILE | modules/foundation/dns/mod.rs | derived from ZONE_RECORD_MAX and the registered record count
MAX_VAULT_LABEL | modules/foundation/dns/mod.rs | mirror of key_vault::MAX_LABEL
MAC_INPUT_MAX | modules/foundation/dns/mod.rs | TSIG scratch derived from the packet and name ceilings
BLOCK_SIZE | modules/foundation/fat32/mod.rs | the FAT/SD sector size, a format constant
MAX_WRITE_NLB | modules/foundation/fat32/mod.rs | write chunking so a write fits any channel without hints, not a ceiling
DIR_ENTRY_SIZE | modules/foundation/fat32/mod.rs | on-disk directory entry size, a format constant
MAX_TX_FRAME_PAYLOAD | modules/foundation/ip/mod.rs | derived: MAX_FRAME_SIZE less the length prefix
DNS_NAME_CAP | modules/foundation/ip/mod.rs | protocol: the RFC 1035 presentation-form maximum, net_proto::MAX_NAME_LEN (253) — every name a dial carries is held whole; the resolver tables are bounded by their declared entry counts
MAX_UDP_TX_PAYLOAD | modules/foundation/ip/mod.rs | derived from MAX_TX_FRAME_PAYLOAD and the header lengths
MAX_TCP_TX_PAYLOAD | modules/foundation/ip/mod.rs | derived from MAX_TX_FRAME_PAYLOAD and the header lengths
MAX_ICMP_TX_LEN | modules/foundation/ip/mod.rs | derived from MAX_TX_FRAME_PAYLOAD and the header lengths
PENDING_CMD_BUF_SIZE | modules/foundation/ip/mod.rs | staging for a partially read command, sized to the largest command
CONN_INDEX_SIZE | modules/foundation/ip/mod.rs | derived: the hash index is twice MAX_TCP_CONNS
ADDR_INDEX_SIZE | modules/foundation/ip/mod.rs | derived: the hash index is four times MAX_LOCAL_ADDRS
EPHEMERAL_SCAN_MAX | modules/foundation/ip/mod.rs | derived: a port scan bounded by twice MAX_TCP_CONNS
PREFIX_MAX | modules/foundation/mount/mod.rs | control-message field width, bounded by its u8 length prefix
VOLUME_MAX | modules/foundation/mount/mod.rs | control-message field width, bounded by its u8 length prefix
PATH_MAX | modules/foundation/mount/mod.rs | path scratch for prefix rewriting
SCRATCH_MAX | modules/foundation/mount/mod.rs | derived from PATH_MAX: two length-prefixed paths of a RENAME / LINK
CTL_MSG_MAX | modules/foundation/mount/mod.rs | derived from the control-message field widths
NET_BUF_SIZE | modules/foundation/ota_registry/mod.rs | scratch: one MSG_DATA fragment plus its framing
HDR_BUF_SIZE | modules/foundation/ota_registry/mod.rs | HTTP response header accumulator scratch
MANIFEST_BUF_SIZE | modules/foundation/ota_registry/mod.rs | manifest accumulator scratch, sized to a 30-module graph
TX_BUF_SIZE | modules/foundation/ota_registry/mod.rs | request builder scratch
STAGE_ARG_SIZE | modules/foundation/ota_registry/mod.rs | derived: an OTA_STAGE_WRITE arg is an offset plus one fragment
MAX_HOST_LEN | modules/foundation/ota_registry/mod.rs | parameter string width
MAX_REPO_LEN | modules/foundation/ota_registry/mod.rs | parameter string width
MAX_TAG_LEN | modules/foundation/ota_registry/mod.rs | parameter string width
MAX_TICKET_LEN | modules/foundation/quic/connection.rs | scratch sized to the vault-sealed ticket the client echoes
MAX_RETRY_TOKEN_LEN | modules/foundation/quic/connection.rs | scratch sized to the retry token layout, rounded up
MAX_ALPN | modules/foundation/quic/connection.rs | protocol-name field width in the connection struct
MAX_DATAGRAM_SIZE | modules/foundation/quic/connection.rs | the congestion controller's datagram unit, mirroring QUIC_DGRAM_MAX
MAX_ACK_DELAY | modules/foundation/quic/connection.rs | the RFC 9000 default ack delay in ms, a protocol constant
TP_MAX_UDP_PAYLOAD_SIZE | modules/foundation/quic/connection.rs | transport-parameter wire id, named after the parameter
TP_ACTIVE_CONNECTION_ID_LIMIT | modules/foundation/quic/connection.rs | transport-parameter wire id, named after the parameter
TP_MAX_DATAGRAM_FRAME_SIZE | modules/foundation/quic/connection.rs | transport-parameter wire id, named after the parameter
CONT_SECRET_PT_MAX | modules/foundation/quic/continuity.rs | derived: the secret record's plaintext layout
MIRROR_DELTA_MAX | modules/foundation/quic/continuity.rs | derived: a delta header, a packet number and one packet
DELTA_PAYLOAD_MAX | modules/foundation/tls/continuity.rs | derived from RECV_BUF_SIZE and the delta header
CONT_SCRATCH_SIZE | modules/foundation/tls/continuity.rs | derived assembly scratch
REPLY_MAX | modules/foundation/tls/continuity.rs | derived reply assembly scratch
MAX_ID | modules/sdk/abi/config.rs | the highest vocabulary id, a marker rather than a cap
MAX_CONTENT_TYPE | modules/sdk/abi/config.rs | content-type string width
MAX_VARS | modules/sdk/abi/config.rs | template variable table, a tuning knob
MAX_VAR_VALUE | modules/sdk/abi/config.rs | template variable width, a tuning knob
MAX_CACHE | modules/sdk/abi/config.rs | template cache slots, a tuning knob
HEADER_SIZE | modules/sdk/contracts/telemetry.rs | record layout
METRIC_SCALAR_SIZE | modules/sdk/contracts/telemetry.rs | record layout
METRIC_HIST_SIZE | modules/sdk/contracts/telemetry.rs | record layout
METRIC_HIST16_SIZE | modules/sdk/contracts/telemetry.rs | record layout
SPAN_SIZE | modules/sdk/contracts/telemetry.rs | record layout
PSTATUS_STEP_SIZE | modules/sdk/contracts/telemetry.rs | record layout
PSTATUS_RES_SIZE | modules/sdk/contracts/telemetry.rs | record layout
PSTATUS_POOL_SIZE | modules/sdk/contracts/telemetry.rs | record layout
MAX_RECORD_SIZE | modules/sdk/contracts/telemetry.rs | mirror of TELEMETRY_MAX_RECORD, pinned by test
BATCH_HEADER_SIZE | modules/sdk/contracts/telemetry.rs | batch envelope layout
SPI_CONFIG_BIN_SIZE | src/kernel/boot/config.rs | packed hardware-section layout
I2C_CONFIG_BIN_SIZE | src/kernel/boot/config.rs | packed hardware-section layout
UART_CONFIG_BIN_SIZE | src/kernel/boot/config.rs | packed hardware-section layout
GPIO_CONFIG_BIN_SIZE | src/kernel/boot/config.rs | packed hardware-section layout
PIO_CONFIG_BIN_SIZE | src/kernel/boot/config.rs | packed hardware-section layout
GRAPH_EDGE_SIZE | src/kernel/boot/config.rs | packed graph-section layout
DOMAIN_META_ENTRY_SIZE | src/kernel/boot/config.rs | packed graph-section layout
DOMAIN_META_SIZE | src/kernel/boot/config.rs | packed graph-section layout
ADAPTIVE_POST_SIZE | src/kernel/boot/config.rs | packed graph-section layout
GRAPH_SLOTS_CODE | src/kernel/boot/config.rs | packed graph-section layout, derived from MAX_GRAPH_EDGES
MAX_SPANS | src/platform/bcm2712/memmap.rs | derived: the zone search keeps one span per device-tree memory range plus one per reservation (dtb MAX_MEMORY_RANGES + MAX_RESERVED_RANGES)
CHANNEL_SIZE | src/platform/bcm2712/multicore.rs | a peripheral's register-block stride, hardware layout
EVENT_HEADER_SIZE | src/platform/bcm2712/store.rs | mesh event record layout
HEADER_SIZE | src/kernel/boot/config.rs | config blob header layout
BUFFER_SIZE | src/kernel/ipc/buffer_pool.rs | mirror of CHANNEL_BUFFER_SIZE
BUFFER_ARENA_SIZE | src/kernel/ipc/buffer_pool.rs | mirror of the platform config's BUFFER_ARENA_SIZE
MODULE_STATE_SIZE | src/kernel/module/loader.rs | a parameter-name hash, not a size
MODULE_ARENA_SIZE | src/kernel/module/loader.rs | a parameter-name hash, not a size
STATE_CANARY_SIZE | src/kernel/module/loader.rs | canary layout
IMAGE_HEADER_SIZE | src/kernel/module/ota_stage.rs | staged-image header layout
MAX_SEALED | src/kernel/security/key_vault.rs | derived: MAX_KEY_BYTES plus the AEAD nonce and tag
MAX_ATTEST_RECORD | src/kernel/security/key_vault.rs | scratch derived from the host profile's table sizes
MAX_RECORD | src/kernel/sys/telemetry_ring.rs | mirror of TELEMETRY_MAX_RECORD
MANIFEST_HEADER_SIZE | tools/src/manifest.rs | manifest layout
SIGNATURE_BLOCK_SIZE | tools/src/manifest.rs | signature block layout
MAX_AUTHORITY_LEN | modules/foundation/remote_channel/mod.rs | holds the `authority` parameter as written; the provider's own name ceiling binds the dial
TABLE_TEXT_MAX | modules/foundation/remote_channel/mod.rs | holds the `channels` parameter text; MAX_CHANNELS and CT_NAME_MAX bind the table it parses to
EVENT_HEADER_SIZE | src/platform/linux/store.rs | protocol: the mesh event header's fixed length, not a ceiling
MAX_DATA_FRAGMENT | src/platform/linux/providers.rs | mirror of net_proto::MAX_DATA_FRAGMENT, the normative MSG_DATA payload, a protocol constant
KEY_MAX | modules/foundation/fs_object/mod.rs | mirror of the contract's STORAGE_KEY_MAX, the longest key a listing carries
CT_MAX | modules/foundation/fs_object/mod.rs | format: the content type's u8 length prefix
HDR_MAX | modules/foundation/fs_object/mod.rs | derived: the longest object header, from KEY_MAX and CT_MAX
PATH_MAX | modules/foundation/fs_object/mod.rs | derived: ROOT_MAX, a separator and an 8.3 name
NAME_MAX | modules/foundation/object_exchange/mod.rs | mirror of the contract's STORAGE_KEY_MAX, the longest object name
CT_MAX | modules/foundation/object_exchange/mod.rs | format: the content type's u8 length prefix
SCOPE_MAX | modules/foundation/object_exchange/mod.rs | mirror of the contract's grant::SCOPE_MAX, the longest scope a grant names
```
