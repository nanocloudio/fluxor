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
hosted       | any(target_os = "linux", target_arch = "wasm32")
bare         | not(any(target_os = "linux", target_arch = "wasm32"))
rp2040       | fluxor_silicon = "rp2040"
rp2350       | not(fluxor_silicon = "rp2040")
multitenant  | feature = "multitenant"
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
rp-large     | all(not(target_arch = "aarch64"),not(feature = "chip-rp2040"),not(feature = "chip-rp2350b"),)
```

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
| TCP/HTTP `conn_id` (net-proto wire) | u16 LE | 65535 | `MAX_TCP_CONNS` | modules/sdk/abi/config.rs | 65536 | The host table is exactly the id space (ids 0..65535); 256 on wasm, 8 on embedded. A record is ~2.2 KiB, most of it the bounded reorder buffer, so the host table is ~137 MiB and is the term `STATE_ARENA_SIZE` is sized around. Lookup is by hash index (`ip/index.rs`) whose removals close their holes and whose hash is seeded per instance, so a packet pays for the cluster it lands in rather than for the table — a miss included — and the timer sweep is sliced across its 50 ms window |
| datagram/packet `ep_id` (DG/PKT wire) | u8 | 256 | `MAX_DG_ENDPOINTS` | modules/sdk/abi/config.rs | 256 | Endpoints are allocated only from the first `MAX_DG_ENDPOINTS` connection slots, so the u8 id binds the endpoint count, not the table. TCP prefers the slots beyond that window and takes it only when the rest is full |
| local-address slot (`TcpConn::local_slot`) | u16 | 65535 | `MAX_LOCAL_ADDRS` | modules/sdk/abi/config.rs | 4096 | `0xFFFF` is the wildcard slot. Demux is by hash index; 8 on wasm and embedded |
| decision-seam hold (`pkt_id` slot) | u16 | 65535 | `MAX_PACKET_HOLD` | modules/sdk/abi/config.rs | 32 | One full frame per slot; an arrival past it is refused and counted, never displaces a held packet. 8 on wasm, 4 on embedded |
| resolver cache entry (`ip` stub resolver) | u8 (table index) | 255 | `MAX_DNS_CACHE` | modules/sdk/abi/config.rs | 32 | Names held with their address until the answer's TTL runs out; a full table replaces the entry nearest its expiry. One entry is a 64-byte name plus address and expiry (~76 B). 32 on wasm, 4 on embedded |
| resolver pending dial (`ip` stub resolver) | u8 (table index) | 255 | `MAX_DNS_PENDING` | modules/sdk/abi/config.rs | 8 | Dials parked on a name lookup in flight; two dials of one name share one entry's query. One past the table is refused `EAGAIN` until an answer or timeout frees an entry. 8 on wasm, 4 on embedded |
| contract class (`required_caps` bitmask, fmod header) | u64 bit position | 64 | `MAX_CONTRACTS` | src/kernel/module/provider.rs | 64 | One number for three roles: vtable index, opcode class byte, and bit position in the header's `required_caps`. Registration past the ceiling is refused EINVAL, and a dispatch id at or past it is refused ENOSYS by `check_contract_grant` before either capability gate |
| contract-class positions consumed | — | 64 | `CONTRACT_ID_POSITIONS_ASSIGNED` | tools/src/manifest.rs | 30 | Counts the four reserved ids, excludes the kernel-internal dispatch bucket. Highest allocated is `NET_POLICY` = 0x1E, leaving 0x1F–0x3F (33 positions) free. The tools-side mirror of the space, `CONTRACT_ID_SPACE`, holds the same width as the kernel's `MAX_CONTRACTS`: an id outside it is unrepresentable in the header mask and unregisterable as a vtable |
| permission category (fmod header) | u16 bitfield | 16 | — | src/kernel/module/loader.rs | — | 9 of 16 bits assigned (`observe` = bit 8); widening changes the module header layout |
| module index (exec_order, fault ids) | u8 | 256 | `MAX_MODULES` | modules/sdk/abi/config.rs | 255 | Deliberate keep at u8; the aarch64 profile sits at 255 — every slot the width admits except 0xFF, the no-module sentinel in the page pool, step guard and elastic allocator. Dual asserts: `src/kernel/boot/config.rs`, `src/kernel/exec/scheduler/mod.rs` |
| channel buffer slot | i16 (−1 sentinel) | 32768 | `MAX_BUFFER_SLOTS` | src/kernel/ipc/buffer_pool.rs | — | Derived, not chosen: one slot per channel (`MAX_CHANNELS`), so the two cannot drift. `ChannelSlot.buffer_slot` holds a single id and every allocation takes its owning channel, so a slot past the channel table is unreachable and a pool short of it leaves the table's upper range unallocatable — `channel_open` refusing while slots are free. The buffer arena binds first by orders of magnitude |
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
| Module state arena | `STATE_ARENA_SIZE` | modules/sdk/abi/config.rs | 268435456 | Sized, not chosen: it must hold every module of the busiest graph at once. The `ip` connection table is the dominant term at ~137 MiB, and 256 MiB leaves ~117 MiB beside it — above the media-app host graph's 64 MiB peak. 240 KiB on rp2350 and 64 KiB on rp2040, from the silicon TOML, where the whole envelope is different. Zero-initialised, so it costs kernel `.bss`, not image size. Exhaustion is refused at module load, not at the allocation that overruns |
| Single channel ring | `MAX_CHAN_BYTES` | src/kernel/ipc/channel.rs | 4194304 | Sanity bound on one ring's share of the buffer arena |
| QUIC endpoint connections | `MAX_CONNS` | modules/sdk/abi/config.rs | 64 | Policy: ~58 KiB of state per slot on a bcm2712-only module — ~3.6 MiB for the table, the dominant term in the module's footprint and paid resident, since the table is a field of the module state rather than an elastic pool. ~13 KiB of a slot is handshake scratch idle once the connection is established; the remaining ~45 KiB is state a live connection needs, so unlike the TLS ceiling this one is not mostly scratch. A connection past the ceiling receives a stateless CONNECTION_REFUSED so it fails in one round trip rather than hanging, and a Closed slot recycles with a fresh ephemeral |
| TLS sessions | `MAX_SESSIONS` | modules/sdk/abi/config.rs | 512 | Policy: the ceiling on concurrent TLS connections and so on HTTPS concurrency — an accept the tls module cannot seat is closed before http sees it. A seat is ~13 KiB, of which ~12 KiB is handshake scratch resident for the session's whole life; 512 seats are 63 granted chunks ≈ 7.9 MiB, drawn in 8-session chunks from the oversubscribable elastic region, so an idle stack pays only for the inline chunk. 1 inline on embedded: what the rp2350 arena holds beside the wifi stack. This bounds ONE instance and instances do not add up the way the number invites: a chunk asks ~104 KiB and rounds up to the 64 KiB grant quantum, so it takes 128 KiB, and the 16 MiB region holds 128 chunks — the same depth as the kernel's chunk table — for about 1,024 seats shared across every elastic pool on the host. Two saturated instances are already the region. Published in the profile so a consumer reads the envelope it has; `tls::MAX_SESSIONS <= ip::MAX_TCP_CONNS` is asserted at compile time |
| HTTP/2 streams per conn | `MAX_STREAMS` | modules/sdk/abi/config.rs | 4 | Policy: bounds per-connection stream state on every profile |
| HTTP route table | `MAX_ROUTES` | modules/sdk/abi/config.rs | 8 | Policy: a config declaring more routes is a compose-time error |
| Provider chain depth per contract | `MAX_CHAIN_DEPTH` | src/kernel/module/provider.rs | — | Policy, per-profile (3 RP2040 / 4 RP2350 / 8 aarch64-host); registration past the ceiling is refused EBUSY |
| KEY_VAULT key slots | `MAX_SLOTS` | src/kernel/security/key_vault.rs | 8 | Policy: generate/import with no free slot is refused ENOMEM |
| KEY_VAULT RSA entries | `RSA_ENTRIES` | src/kernel/security/key_vault.rs | 2 | Policy: an RSA key is kilobytes of CRT material and Montgomery constants rather than the 64 bytes a slot carries, so RSA slots name one of two backend entries — an identity and its successor during a rotation. A third `STORE` is refused ENOMEM until one is destroyed. Behind the `rsa-vault` feature, about 22 KB of `.bss` with the signing job |
| RSA modulus width | `RSA_MODULUS_BITS_MAX` | modules/sdk/crypto/rsa.rs | 4096 | Policy: the widest key the core verifies or signs with. It sizes every buffer in the core and every job's step cost; no public issuer signs with more, and 8192 would double both for a key nothing presents |
| RSA public exponent width | `RSA_EXPONENT_BITS_MAX` | modules/sdk/crypto/rsa.rs | 32 | Policy: the exponent a public operation walks; 65537 needs 17 bits, and a key whose exponent is wider is refused rather than exponentiated at length |
| fat32 open files | `MAX_OPEN_FILES` | modules/foundation/fat32/mod.rs | — | Policy, per-profile (256 aarch64 / 8 elsewhere): a multi-tenant node runs several independent consumers against one volume at once, where a microcontroller's consumer set is fixed and each handle costs a scratch buffer. An open past the table is refused ENFILE, with a log line naming the handles that hold it. The `max_open_per_owner` parameter adds a per-owner ceiling on top, refusing the owner that is over its share while the table still has room, so the failure lands on the workload at fault rather than on whoever asks next |
| fat32 directory-walk budget | `DIR_SCAN_BUDGET_SECTORS` | modules/foundation/fat32/mod.rs | 32 | Policy: directory sectors one `provider_call` reads before returning EAGAIN with its position saved. A directory with thousands of entries is not exotic — a WAL that segments per snapshot fills one — so an unbounded walk is a latent stall of every module sharing the lane, not a slow path |
| fat32 long-name length | `LFN_MAX_CHARS` | modules/foundation/fat32/mod.rs | 64 | Policy: the format allows 255, but a buffer for that is carried in the directory cursor and in every wanted-name argument, on a board whose whole module state is measured against a 240 KiB arena. A longer name is refused at creation, not clipped. Names longer than this that were written elsewhere are still preserved and retired correctly — preservation walks the companion run without decoding it, so only matching and generation are bounded |
| fat32 free-cluster scan | `FAT_SCAN_BUDGET_SECTORS` | modules/foundation/fat32/mod.rs | 32 | Policy: FAT sectors one `provider_call` reads looking for a free cluster before returning EAGAIN with its cursor saved. Matches `DIR_SCAN_BUDGET_SECTORS` for the same reason — a synchronous device read inside a dispatch is charged to the cooperative step budget, and the FAT of a large volume is far too big to walk in one |
| fat32 outstanding fences | `MAX_FENCES` | modules/foundation/fat32/mod.rs | — | Policy: equals `MAX_OPEN_FILES`. A fence table smaller than the handle table would let a consumer open a handle it cannot fence, which reads as a durability failure rather than a resource limit. `FSYNC_SUBMIT` past the table is refused EAGAIN (backpressure) |
| resolver name held | `DNS_NAME_CAP` | modules/foundation/ip/mod.rs | 64 | Policy: the longest name the stub resolver holds, in a cache entry and in a pending dial. It is what bounds those tables on an MCU-class profile, so a dial naming something longer is refused EINVAL rather than truncated to a name that resolves to somewhere else |
| OTA registry authority | `MAX_AUTHORITY_LEN` | modules/foundation/ota_registry/mod.rs | 128 | Policy: the `host[:port]` the puller dials and sends as `Host:`. A longer one is refused at construction, naming the parameter — a truncated authority would dial a different registry |
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
| QUIC peer authority | `MAX_AUTHORITY` | modules/foundation/quic/mod.rs | — | Policy: `MAX_PEER_NAME` plus `:65535`. The instance keeps one peer authority; a longer one is refused at construction |
| QUIC peer name | `MAX_PEER_NAME` | modules/foundation/quic/mod.rs | 64 | Policy: the longest DNS name a QUIC peer may be dialled by, and the SNI and `dNSName` the handshake checks. The datagram surface carries up to 253 bytes; the module sizes this for the state budget and refuses rather than truncates, because a clipped name verifies against the wrong certificate |
| QUIC peer certificate | `MAX_CERT_LEN` | modules/foundation/quic/mod.rs | 1024 | Policy: the per-certificate ceiling for the configured leaf and each trust anchor. An anchor past it, or a ninth anchor, marks the table refused and the instance declines to construct |
| QUIC configured ALPN list | `MAX_ALPN_CFG` | modules/foundation/quic/mod.rs | 64 | Policy: the comma-separated protocol tokens a graph configures (`mqtt,h3`); 64 bytes holds several names with their separators |
| QUIC resumption tickets | `MAX_TICKETS` | modules/foundation/quic/mod.rs | 4 | Policy: the client-side ticket cache. Each entry is bound to the authority that issued it, so the table holds a handful of recently dialled peers and the oldest is displaced rather than grown |
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
| DNS zone-file commit writes | `MAX_COMMIT_WRITES` | modules/foundation/dns/mod.rs | 64 | Sanity: `WRITE` / `READ` calls per commit or recovery before the operation is refused as stalled |
| mount open handles | `MAX_OPEN` | modules/foundation/mount/mod.rs | 64 | Policy: an open past the router table is refused ENFILE |
| OTA image layers | `MAX_LAYERS` | modules/foundation/ota_registry/mod.rs | 48 | Policy: sized to the 48-module fleet profile; a larger manifest is refused whole |
| SMMU DMA map table | `MAX_DMA_MAPS` | modules/foundation/smmu/mod.rs | 32 | Policy: a map past the translation table is refused ENOMEM before any MMIO write |
| QUIC continuity shadow slots | `MAX_SHADOW_SLOTS` | modules/foundation/quic/continuity.rs | 2 | Policy: connections under CT_QUIC takeover at once, one per slot. Continuity is a control-plane event, not steady state, and each shadow stages a whole connection's worth of state; a PAIR_PREPARE past the free slots is refused `STATUS_NO_CAPACITY` |
| QUIC continuity checkpoint record | `CHECKPOINT_RECORD_MAX` | modules/foundation/quic/continuity.rs | 16384 | Sized, not chosen: holds the full serialized connection state — three bidi (1200+1500) and six uni (256+256) stream buffers, the retained last-emitted packet, the sealed secret set, and the fixed header, with headroom. A checkpoint whose `total_len` exceeds it is refused `STATUS_NO_CAPACITY` at CHECKPOINT_BEGIN and the shadow is discarded |
| ARP-wait handshake list | `ARP_WAIT_MAX` | modules/foundation/ip/mod.rs | 64 | Policy: handshakes remembered as waiting on neighbour resolution, so an ARP reply retries exactly those rather than walking the connection table. A full list only defers the retry to the timer sweep's next slice |
| GEM RX descriptors | `RX_DESC_COUNT` | modules/drivers/rp1_gem/mod.rs | 192 | Policy: the burst the Pi 5 MAC absorbs between two driver steps; a step drains the whole ring. The platform DMA arena holds 256 buffers shared with the 64 TX descriptors. The rings are walked with free-running `u16` positions under a `position % count` index, and those positions wrap at the largest multiple of the ring size a `u16` holds rather than at 65,536 (`rp1_gem/ring.rs`), so the index stays continuous across the wrap and a size that does not divide 65,536 is safe |
| fan frames per step | `FAN_FRAMES_PER_STEP` | src/kernel/exec/scheduler/module_types.rs | 64 | Policy: whole frames a framed `_tee` or `_merge` moves in one step. A fan sits between a producer and its consumers, so this times the tick rate is the ceiling on every fanned port — `debug: to: net` fans the ip module's consumer ports, and every accept, delivery and send on that graph crosses one |
| free-slot rebuild slice | `ALLOC_SCAN_SLICE` | modules/foundation/ip/mod.rs | 256 | Policy: slots one step examines to rebuild the free stack when it is empty — the table is full, or a slot was released by a path that did not push it. Allocation is a pop; a SYN at the ceiling costs this slice once per step and is refused, never a walk of the table per SYN |
| timer-sweep slice | `SWEEP_SLICE_MAX` | modules/foundation/ip/mod.rs | 1024 | Policy: most connections one step of the sliced TCP timer sweep visits. The proportional slice visits a few hundred; after a stall the whole window is owed and this is the ceiling it meets — a full 65,536-record sweep in one step is a multi-millisecond, cache-missing step the guard would end the module for. The sweep lags a stall by at most 64 steps, and needs that many steps per 50 ms window to keep the timers on time: a tick of 780 µs or faster on the 65,536-record profile (the Pi 5 runs 100 µs) |
| TCP continuity shadow slots | `MAX_TCP_SHADOWS` | modules/sdk/abi/config.rs | 8 | Policy: connections a transport-continuity pair holds in flight on one ip instance — shadows staged for import plus flows being mirrored out. Each shadow is a connection record plus its checkpoint bytes, and takeover is a control-plane event, not steady state; a PAIR_PREPARE past the free slots is refused `STATUS_NO_CAPACITY`. 2 on wasm, 1 on embedded |
| fence wire wait | `FENCE_WIRE_WAIT_MS` | modules/foundation/ip/mod.rs | 500 | Policy: how long a fence holds its event for the driver's drain answer before reporting the ring hand-off instead. Longer than any transmit ring takes to empty at line rate; short enough that a coordinator waiting on the fence is not waiting on a hung driver |
| queued control frame | `NET_OUT_FRAME_MAX` | modules/foundation/ip/mod.rs | 9 | Sanity bound: the largest frame the fallback queue holds — header, a u16 connection id and a u32 sequence (`MSG_RETRANSMIT`, `MSG_ACK`). A larger frame is refused, never truncated |
| TLS continuity shadow slots | `MAX_TLS_SHADOWS` | modules/foundation/tls/continuity.rs | 2 | Policy: sessions under CT_TLS takeover at once on one instance, one per slot (1 on wasm, 0 on the MCU-class targets, which hold no standby). A shadow is a staging record plus the decoded checkpoint — about twice `TLS_CKPT_RECORD_MAX`, resident in module state — and takeover is a control-plane event, not steady state; a PAIR_PREPARE past the free slots is refused `STATUS_NO_CAPACITY` |
| ISR bridge slots | `MAX_BRIDGES` | modules/sdk/abi/config.rs | 16 | Policy: edges that cross into an ISR-tier domain, one bridge slot each with its ring inline (~2 KiB of kernel static RAM per slot). An edge past the ceiling loses its ISR routing and the graph fails at setup rather than corrupting. 8 on embedded, where the die's stack is what the slots would take |
| TLS continuity checkpoint record | `TLS_CKPT_RECORD_MAX` | modules/foundation/tls/continuity.rs | — | Derived, not chosen: the fixed header plus the whole partial-inbound buffer (`RECV_BUF_SIZE`), the whole retransmission window (`RETX_BUF_SIZE`) and the sealed secret set — about 21 KiB where the receive buffer is 16 KiB, about 9 KiB on the 4 KiB targets. A CHECKPOINT_BEGIN whose `total_len` exceeds it is refused `STATUS_NO_CAPACITY` before any byte moves; the record is never truncated |
| TLS strict-profile send hold | `TX_HOLD_SIZE` | modules/foundation/tls/continuity.rs | — | Derived, not chosen: every record one `CMD_SEND` (`MAX_CMD_DATA` bytes) can produce, since the clear-side frame is consumed whole and each of its records must wait for its own send horizon — six records of `WIRE_RECORD_MAX`, about 9.3 KiB per session, paid in every session slot whether or not it is mirrored. A producer that exceeds the contract's frame ceiling fills the hold and the session fails rather than the record being dropped |
| QUIC 1-RTT self-grant block | `LOCAL_PN_BLOCK` | modules/foundation/quic/connection.rs | 4096 | Policy: the send packet-number block a connection self-grants in local (non-durable) mode, refilled `LOCAL_PN_REFILL_LOW` (512) values ahead of exhaustion so the reservation never stalls a healthy sender. Matches the directory's smoke-path reserve size; in durable mode the directory chooses the block |
| declared step cost (`[execution] max_step_us`) | `STEP_BUDGET_DEFAULT_TICK_US` | tools/src/target_facts.rs | 1000 | Policy: the scheduler's default pass budget (`DEFAULT_TICK_US`, one tick) on every silicon; a manifest whose step cannot fit one default pass on a target it names is refused at parse. Per-target in shape so a slower part can publish a smaller budget |
| early-boot log ring | `LOG_RING_CAPACITY` | modules/sdk/abi/config.rs | 65536 | Sized to cover boot until a consumer reaches its transport, and NOT raised past it: the whole ring is replayed in one burst when the consumer attaches, and on the Pi 5 rig a 256 KiB ring outran the collector's socket buffer, losing the oldest datagrams — the exact ones the replay exists to deliver. Growing this needs a paced replay first. Then per-profile because the ring is static `.bss` charged against the whole SRAM: 16 KiB on wasm, 4 KiB on the RP parts, where a host-class ring is a quarter of an RP2040's linker RAM region and an eighth of an RP2350's, and on both pushes `.bss` past that region once the state and buffer arenas are placed beside it. The RP kernels take the figure from their silicon TOML (`[kernel] log_ring_kb`), and that figure and the embedded profile's constant must state the same size. A full ring drops new records rather than overwriting unread ones, and counts the drops |

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
| Channel buffer arena | `BUFFER_ARENA_SIZE` | modules/sdk/abi/config.rs | 8388608 | Sized: the largest host graph's channels at 16–64 KiB each under gigabit-class load; the wasm arena is paged lazily by `memory.grow` so it costs nothing until used. 64 KiB on embedded, where the whole envelope is different. Exhaustion refuses the channel open at compose time, never at runtime |
| Tier B elastic region | `ELASTIC_REGION_SIZE` | modules/sdk/abi/config.rs | 16777216 | Policy: the oversubscribable region every elastic pool draws 64 KiB-quantum chunks from; 128 chunks on the host, which is the same depth as the kernel's chunk table. Zero on MCU-class targets, where `ELASTIC_ALLOC` denies and elasticity compiles out 2 MiB on wasm. |
| Config arena | `CONFIG_ARENA_SIZE` | modules/sdk/abi/config.rs | 262144 | Sized against the largest per-module params section (~95 KiB for an http module on the host) with headroom for the rest of the graph. A packed config larger than this is refused at boot 32 KiB on wasm, 16 KiB on embedded. |
| One module's params section | `MAX_MODULE_CONFIG_SIZE` | modules/sdk/abi/config.rs | 262144 | Sanity bound on one module's slice of the config arena; kept in lockstep with the kernel's `MAX_MODULE_SECTION` and the CLI's params cap so the three refuse the same blob. 16 KiB on wasm; on the RP parts 16 KiB (rp2350) and 8 KiB (rp2040), taken from `[kernel] config_buffer_kb` in the silicon TOML, which the RP kernels generate their own copy from — the two must state the same size |
| Kernel module-section bound | `MAX_MODULE_SECTION` | src/kernel/boot/config.rs | 262144 | The kernel-side twin of `MAX_MODULE_CONFIG_SIZE` (linux + wasm / bare metal): a section past it is refused while parsing, before any module is instantiated. Registered separately so the pair cannot drift apart unnoticed 32 KiB on bare metal. |
| HTTP concurrent connections | `MAX_CONCURRENT_CONNS` | modules/sdk/abi/config.rs | 256 | Policy: the http module's own table, below `MAX_TCP_CONNS`; an accept past it is closed before any request is read. The embedded 4 is sized against the 8-slot TCP table in that profile; the one-session TLS table beneath it bounds HTTPS. 4 on embedded. |
| HTTP per-connection receive buffer | `RECV_BUF_SIZE` | modules/sdk/abi/config.rs | 8192 | Policy: a whole request line, headers and a small body in one read; a request that does not fit is refused 431, not spilled 4096 on wasm, 2048 on embedded. |
| HTTP per-connection send buffer | `SEND_BUF_SIZE` | modules/sdk/abi/config.rs | 4100 | Policy, deliberately 4 KiB + 4: a WebSocket frame of exactly 4096 bytes of payload plus its header fits in one write, so the RFC 6455 fragmentation path is taken only by frames that genuinely exceed it |
| Dynamic routes | `MAX_DYN_ROUTES` | modules/sdk/abi/config.rs | 64 | Policy: the dynamic-route arena an ingress fills at runtime; a route past the ceiling is refused and counted in `http.routes.dropped` 8 on wasm and embedded. |
| Backends per route | `MAX_ROUTE_BACKENDS` | modules/sdk/abi/config.rs | 8 | Policy: an oversized backend set is truncated by weight order and the overflow is counted, so the route keeps serving from its heaviest members 4 on wasm and embedded. |
| Route filesystem path | `MAX_FS_PATH` | modules/sdk/abi/config.rs | 256 | Policy: host routes point into deep on-disk trees; embedded and wasm routes are short on-flash paths like `/web/INDEX.HTM`, and a longer path is refused at compose time 64 on wasm and embedded. |
| Body pool default | `DEFAULT_BODY_POOL_SIZE` | modules/sdk/abi/config.rs | 262144 | Policy: the request-body pool an http module gets when its config names none; a body that does not fit is refused 413. 32 KiB on wasm; on the RP parts 16 KiB (rp2350) and 4 KiB (rp2040), where the pool is charged against the same SRAM the state arena is |
| Fan-in/fan-out buffer | `FAN_BUF_SIZE` | src/kernel/exec/scheduler/module_types.rs | 32768 | Sized per target family (aarch64 / RP / other): the ring behind each expanded fan edge, taken from the channel arena; a frame larger than it cannot cross a fan edge 2048 on RP, 8192 on other families. |
| Config graph edges | `MAX_GRAPH_EDGES` | src/kernel/boot/config.rs | — | Per profile, derived from `MAX_MODULES` so the two cannot drift: `HOST_GRAPH_EDGES` where the module ceiling passes 128, `SMALL_GRAPH_EDGES` elsewhere. Every channel table (`MAX_CHANNELS`) is sized from it. A graph with more edges is refused by the tools before it is packed |
| Host-profile graph edges | `HOST_GRAPH_EDGES` | src/kernel/boot/config.rs | 384 | Policy: a control plane whose controllers are params is a long chain of decision and connector nodes, one edge each, and cannot split across processes (the linux store is single-writer). The count passes a byte, so its HIGH byte rides graph-section byte 2, and byte 3 states the slot count the section was laid out for (`GRAPH_SLOTS_CODE`) |
| Small-profile graph edges | `SMALL_GRAPH_EDGES` | src/kernel/boot/config.rs | 128 | wasm32 and Cortex-M: unchanged, so their static tables and config blobs do not grow |
| Channels | `MAX_CHANNELS` | src/kernel/ipc/channel.rs | — | Derived, not chosen: one channel per edge, fan expansion included, so the two move together Not value-checked here: the gate evaluates a const against its own file and this one is written in terms of a symbol from another, so the row on `MAX_GRAPH_EDGES` is what holds the pair. |
| Hardware sections: SPI buses | `MAX_SPI_BUSES` | src/kernel/boot/config.rs | 2 | Policy: the packed hardware section carries fixed tables; a board declaring more buses of a kind is refused by the tools |
| Hardware sections: I2C buses | `MAX_I2C_BUSES` | src/kernel/boot/config.rs | 2 | Policy: the packed hardware section carries fixed tables; a board declaring more buses of a kind is refused by the tools |
| Hardware sections: UART buses | `MAX_UART_BUSES` | src/kernel/boot/config.rs | 2 | Policy: the packed hardware section carries fixed tables; a board declaring more buses of a kind is refused by the tools |
| Hardware sections: PIO instances | `MAX_PIO_CONFIGS` | src/kernel/boot/config.rs | 3 | Policy: RP2350B has three PIO blocks, the widest of the RP family |
| Hardware sections: GPIO pins | `MAX_GPIO_CONFIGS` | src/kernel/boot/config.rs | 8 | Policy: pins configured from the config blob; a driver claims the rest at runtime |
| Resident-workload section | `MAX_WORKLOAD_SECTION_BYTES` | src/kernel/boot/config.rs | 8192 | Sanity bound on a torn or hostile config tail; sized for a handful of workloads with room |
| Tick period ceiling | `TICK_BOUND_MAX` | src/kernel/boot/config.rs | 50000 | Policy: the longest tick (µs) a config may ask for; above it the adaptive tick has nothing left to adapt and a stuck graph looks like a slow one |
| Free-region list | `MAX_FREE_REGIONS` | src/kernel/module/loader.rs | 32 | Deliberate cap with a stated degradation: when the list is full a freed region is leaked until the next full arena reset, which is what a reconfigure does anyway |
| Isolated-image arena | `ISO_ARENA_SIZE` | src/kernel/module/loader.rs | 2097152 | Policy (`kernel-vm`): all isolated module state and heap of one image; exhaustion refuses the load |
| Tracked provider handles | `MAX_TRACKED` | src/kernel/module/provider.rs | 128 | Policy: handle-to-owner bindings the kernel keeps for cross-owner checks; an open past it is refused, and the table is scanned on every provider call, so it is kept small on purpose |
| Provider vtables | `MAX_PROVIDERS` | src/kernel/module/provider.rs | 64 | Derived, not chosen: one vtable slot per contract id, so a contract registerable in one and not the other is impossible by construction |
| Dynamic tag routes | `MAX_DYN_TAG_ROUTES` | src/kernel/module/provider.rs | 4 | Policy: keyed provider routes a policy module may add at runtime |
| Key material per vault slot | `MAX_KEY_BYTES` | src/kernel/security/key_vault.rs | 64 | Policy: a P-256 scalar is 32; the doubled width admits larger keying material without a header change |
| Vault label | `MAX_LABEL` | src/kernel/security/key_vault.rs | 64 | Policy, wire-visible: the label is how a module names a key; the contract's `MAX_LABEL` mirrors it |
| Persisted vault keys | `MAX_PERSISTED` | src/kernel/security/key_vault.rs | 8 | Policy: a deployment needing more persisted keys than this needs a real HSM, which is the tier the policy would already be asking for |
| One AEAD seal/open | `MAX_SEAL_BYTES` | src/kernel/security/key_vault.rs | 2048 | Policy: a resumption ticket or a checkpoint chunk in one call, never a bulk stream; a larger plaintext is refused EINVAL |
| Parameter tag space | `PARAM_TAG_MAX` | tools/src/manifest.rs | 239 | Id width: a module parameter is addressed by a byte tag, and 0xF0–0xFF are reserved for protection and policy metadata (voice-preset blobs, TLV magic, the terminator among them) |
| Transmit-side ethernet frame | `MAX_FRAME_SIZE` | modules/foundation/ip/mod.rs | 1536 | Policy: the frame ceiling every NIC driver and `ip` size their staging to — MTU plus headers, rounded to a 32-byte multiple. Every transmit-payload ceiling in `ip` derives from it |
| Listening TCP sockets | `MAX_LISTENERS` | modules/foundation/ip/mod.rs | — | Policy, per-profile (derived from `MAX_TCP_CONNS`): a SYN is matched against the listener list, never the whole table |
| Outbound net queue | `NET_OUT_QUEUE_SLOTS` | modules/foundation/ip/mod.rs | 32 | Policy: frames `ip` holds for a consumer that is not draining; the receive loop stops reading the NIC when fewer than the headroom remain, so back-pressure reaches the wire instead of dropping on the floor |
| DNS record types per allow entry | `MAX_ALLOW_TYPES` | modules/foundation/dns/mod.rs | 8 | Policy: one `update_allow` entry lists the types a signer may update; more than eight is a policy written in the wrong place |
| fat32 enumeration | `MAX_FILES` | modules/foundation/fat32/mod.rs | 128 | Policy: entries one LIST returns; a larger directory is paged by the caller |
| fat32 unlink free-list | `UNLINK_FREE_SLOTS` | modules/foundation/fat32/mod.rs | 8 | Deliberate cap with a stated degradation: sized for WAL segment compaction retiring a handful of segments per snapshot; overflow degrades to orphaning clusters, which fsck reclaims |
| fat32 directory chain | `MAX_DIR_CLUSTERS` | modules/foundation/fat32/mod.rs | 65536 | Sanity bound: far past any real directory and far short of walking a cyclic chain for ever |
| Mounts | `MAX_MOUNTS` | modules/foundation/mount/mod.rs | 8 | Policy: volumes one mount module routes; a backend registering past it fails EBUSY and its mounts resolve ENODEV |
| QUIC unidirectional streams per connection | `MAX_UNI_STREAMS` | modules/foundation/quic/connection.rs | 6 | Policy, advertised to the peer as a transport parameter: the stream state is a fixed table, so the advertised limit and the table are one number |
| QUIC bidirectional streams per connection | `MAX_BIDI_STREAMS` | modules/foundation/quic/connection.rs | 3 | Policy, advertised to the peer as a transport parameter: as the unidirectional ceiling above, and lower because each bidirectional stream carries state in both directions |
| QUIC datagram frame ceiling | `QUIC_DGRAM_MAX` | modules/foundation/quic/connection.rs | 1500 | Policy: the wire layer caps a UDP datagram at one Ethernet MTU |
| QUIC sent-datagram ceiling | `QUIC_MAX_DATAGRAM_SIZE` | modules/foundation/quic/connection.rs | 1200 | Policy: what this endpoint will itself send, held under the MTU ceiling above so a datagram never depends on path discovery to arrive |
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
LOG_RING_CAPACITY | modules/sdk/abi/config.rs | 65536 | host
LOG_RING_CAPACITY | modules/sdk/abi/config.rs | 16384 | wasm
LOG_RING_CAPACITY | modules/sdk/abi/config.rs | 4096 | embedded
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
MAX_DNS_CACHE | modules/sdk/abi/config.rs | 32 | host
MAX_DNS_CACHE | modules/sdk/abi/config.rs | 32 | wasm
MAX_DNS_CACHE | modules/sdk/abi/config.rs | 4 | embedded
MAX_DNS_PENDING | modules/sdk/abi/config.rs | 8 | host
MAX_DNS_PENDING | modules/sdk/abi/config.rs | 8 | wasm
MAX_DNS_PENDING | modules/sdk/abi/config.rs | 4 | embedded
MAX_CONTRACTS | src/kernel/module/provider.rs | 64 | *
CONTRACT_ID_POSITIONS_ASSIGNED | tools/src/manifest.rs | 30 | *
MAX_MODULES | modules/sdk/abi/config.rs | 255 | host
MAX_MODULES | modules/sdk/abi/config.rs | 48 | wasm
MAX_MODULES | modules/sdk/abi/config.rs | 32 | embedded
MAX_BRIDGES | modules/sdk/abi/config.rs | 16 | host
MAX_BRIDGES | modules/sdk/abi/config.rs | 16 | wasm
MAX_BRIDGES | modules/sdk/abi/config.rs | 8 | embedded
MAX_BUFFER_SLOTS | src/kernel/ipc/buffer_pool.rs | MAX_CHANNELS | *
MAX_OWNERS | src/kernel/workload/owner.rs | 64 | multitenant
MAX_OWNERS | src/kernel/workload/owner.rs | 1 | single-owner
MAX_PATH | modules/sdk/abi/config.rs | 200 | host
MAX_PATH | modules/sdk/abi/config.rs | 32 | wasm
MAX_PATH | modules/sdk/abi/config.rs | 32 | embedded
PAYLOAD_MAX | modules/sdk/contracts/exchange.rs | 8192 | *
KEY_MAX | modules/sdk/contracts/exchange.rs | 512 | *
PUBLISH_FRAME_MAX | modules/sdk/contracts/exchange.rs | PUBLISH_OVERHEAD + KEY_MAX + PAYLOAD_MAX | *
REPLY_FRAME_MAX | modules/sdk/contracts/exchange.rs | REPLY_OVERHEAD + KEY_MAX + PAYLOAD_MAX | *
CAPACITY | src/kernel/sys/telemetry_ring.rs | 4096 | chip-rp2040
CAPACITY | src/kernel/sys/telemetry_ring.rs | 8192 | rp2350-chip
CAPACITY | src/kernel/sys/telemetry_ring.rs | 32768 | non-rp
RING_CONSUMERS | modules/sdk/contracts/telemetry.rs | 4 | *
TELEMETRY_MAX_RECORD | src/kernel/exec/scheduler/module_types.rs | 144 | *
DIM_MAX_PRODUCT | modules/sdk/contracts/telemetry.rs | 65534 | *
MAX_MODULE_CODE_SIZE | modules/sdk/abi/config.rs | 1024 * 1024 | host
MAX_MODULE_CODE_SIZE | modules/sdk/abi/config.rs | 1024 * 1024 | wasm
MAX_MODULE_CODE_SIZE | modules/sdk/abi/config.rs | 384 * 1024 | embedded
MAX_MODULES_BLOB_SIZE | src/kernel/module/loader.rs | 8 * 1024 * 1024 | *
MAX_CONFIG_SIZE | src/kernel/boot/config.rs | 256 * 1024 | hosted
MAX_CONFIG_SIZE | src/kernel/boot/config.rs | 32 * 1024 | bare
STAGE_CAPACITY | src/kernel/module/ota_stage.rs | 8 * 1024 * 1024 | *
STATE_ARENA_SIZE | modules/sdk/abi/config.rs | 256 * 1024 * 1024 | host
STATE_ARENA_SIZE | modules/sdk/abi/config.rs | 96 * 1024 * 1024 | wasm
STATE_ARENA_SIZE | modules/sdk/abi/config.rs | 240 * 1024 | embedded+rp2350
STATE_ARENA_SIZE | modules/sdk/abi/config.rs | 64 * 1024 | embedded+rp2040
MAX_CHAN_BYTES | src/kernel/ipc/channel.rs | 4 * 1024 * 1024 | *
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
MAX_SLOTS | src/kernel/security/key_vault.rs | 8 | *
RSA_ENTRIES | src/kernel/security/key_vault.rs | 2 | rsa-vault
RSA_MODULUS_BITS_MAX | modules/sdk/crypto/rsa.rs | 4096 | *
RSA_EXPONENT_BITS_MAX | modules/sdk/crypto/rsa.rs | 32 | *
MAX_OPEN_FILES | modules/foundation/fat32/mod.rs | 256 | host
MAX_OPEN_FILES | modules/foundation/fat32/mod.rs | 8 | off-host
DIR_SCAN_BUDGET_SECTORS | modules/foundation/fat32/mod.rs | 32 | *
LFN_MAX_CHARS | modules/foundation/fat32/mod.rs | 64 | *
FAT_SCAN_BUDGET_SECTORS | modules/foundation/fat32/mod.rs | 32 | *
MAX_FENCES | modules/foundation/fat32/mod.rs | MAX_OPEN_FILES | *
DNS_NAME_CAP | modules/foundation/ip/mod.rs | 64 | *
MAX_AUTHORITY_LEN | modules/foundation/ota_registry/mod.rs | 128 | *
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
MAX_AUTHORITY | modules/foundation/quic/mod.rs | MAX_PEER_NAME + 6 | *
MAX_PEER_NAME | modules/foundation/quic/mod.rs | 64 | *
MAX_CERT_LEN | modules/foundation/quic/mod.rs | 1024 | *
MAX_ALPN_CFG | modules/foundation/quic/mod.rs | 64 | *
MAX_TICKETS | modules/foundation/quic/mod.rs | 4 | *
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
MAX_COMMIT_WRITES | modules/foundation/dns/mod.rs | 64 | *
MAX_OPEN | modules/foundation/mount/mod.rs | 64 | *
MAX_LAYERS | modules/foundation/ota_registry/mod.rs | 48 | *
MAX_DMA_MAPS | modules/foundation/smmu/mod.rs | 32 | *
MAX_SHADOW_SLOTS | modules/foundation/quic/continuity.rs | 2 | *
CHECKPOINT_RECORD_MAX | modules/foundation/quic/continuity.rs | 16384 | *
ARP_WAIT_MAX | modules/foundation/ip/mod.rs | 64 | *
RX_DESC_COUNT | modules/drivers/rp1_gem/mod.rs | 192 | *
FAN_FRAMES_PER_STEP | src/kernel/exec/scheduler/module_types.rs | 64 | *
ALLOC_SCAN_SLICE | modules/foundation/ip/mod.rs | 256 | *
SWEEP_SLICE_MAX | modules/foundation/ip/mod.rs | 1024 | *
MAX_TCP_SHADOWS | modules/sdk/abi/config.rs | 8 | host
MAX_TCP_SHADOWS | modules/sdk/abi/config.rs | 2 | wasm
MAX_TCP_SHADOWS | modules/sdk/abi/config.rs | 1 | embedded
FENCE_WIRE_WAIT_MS | modules/foundation/ip/mod.rs | 500 | *
NET_OUT_FRAME_MAX | modules/foundation/ip/mod.rs | 9 | *
MAX_TLS_SHADOWS | modules/foundation/tls/continuity.rs | 2 | host
MAX_TLS_SHADOWS | modules/foundation/tls/continuity.rs | 1 | wasm
MAX_TLS_SHADOWS | modules/foundation/tls/continuity.rs | 0 | embedded
TLS_CKPT_RECORD_MAX | modules/foundation/tls/continuity.rs | CKPT_FIXED_LEN + RECV_BUF_SIZE + RETX_BUF_SIZE + TLS_SEALED_LEN | *
TX_HOLD_SIZE | modules/foundation/tls/continuity.rs | TX_HOLD_RECORDS * WIRE_RECORD_MAX | *
LOCAL_PN_BLOCK | modules/foundation/quic/connection.rs | 4096 | *
STEP_BUDGET_DEFAULT_TICK_US | tools/src/target_facts.rs | 1000 | *
MAX_FRAME_SIZE | modules/foundation/ip/mod.rs | 1536 | *
MAX_LISTENERS | modules/foundation/ip/mod.rs | if tcp::MAX_TCP_CONNS < 1024 { tcp::MAX_TCP_CONNS } else { 1024 } | *
NET_OUT_QUEUE_SLOTS | modules/foundation/ip/mod.rs | 32 | *
MAX_ALLOW_TYPES | modules/foundation/dns/mod.rs | 8 | *
MAX_FILES | modules/foundation/fat32/mod.rs | 128 | *
UNLINK_FREE_SLOTS | modules/foundation/fat32/mod.rs | 8 | *
MAX_DIR_CLUSTERS | modules/foundation/fat32/mod.rs | 65_536 | *
MAX_MOUNTS | modules/foundation/mount/mod.rs | 8 | *
MAX_UNI_STREAMS | modules/foundation/quic/connection.rs | 6 | *
MAX_BIDI_STREAMS | modules/foundation/quic/connection.rs | 3 | *
QUIC_DGRAM_MAX | modules/foundation/quic/connection.rs | 1500 | *
QUIC_MAX_DATAGRAM_SIZE | modules/foundation/quic/connection.rs | 1200 | *
MAX_STREAM_IDS | modules/foundation/smmu/mod.rs | 8 | *
CKPT_SNI_MAX | modules/foundation/tls/continuity.rs | 64 | *
CKPT_ALPN_MAX | modules/foundation/tls/continuity.rs | 16 | *
CONT_DRAIN_BUDGET | modules/foundation/tls/continuity.rs | 8 | *
BUFFER_ARENA_SIZE | modules/sdk/abi/config.rs | 8 * 1024 * 1024 | host
BUFFER_ARENA_SIZE | modules/sdk/abi/config.rs | 8 * 1024 * 1024 | wasm
BUFFER_ARENA_SIZE | modules/sdk/abi/config.rs | 64 * 1024 | embedded+rp2350
BUFFER_ARENA_SIZE | modules/sdk/abi/config.rs | 16 * 1024 | embedded+rp2040
ELASTIC_REGION_SIZE | modules/sdk/abi/config.rs | 16 * 1024 * 1024 | host
ELASTIC_REGION_SIZE | modules/sdk/abi/config.rs | 2 * 1024 * 1024 | wasm
ELASTIC_REGION_SIZE | modules/sdk/abi/config.rs | 0 | embedded
CONFIG_ARENA_SIZE | modules/sdk/abi/config.rs | 256 * 1024 | host
CONFIG_ARENA_SIZE | modules/sdk/abi/config.rs | 32 * 1024 | wasm
CONFIG_ARENA_SIZE | modules/sdk/abi/config.rs | 16 * 1024 | embedded+rp2350
CONFIG_ARENA_SIZE | modules/sdk/abi/config.rs | 8 * 1024 | embedded+rp2040
MAX_MODULE_CONFIG_SIZE | modules/sdk/abi/config.rs | 256 * 1024 | host
MAX_MODULE_CONFIG_SIZE | modules/sdk/abi/config.rs | 16 * 1024 | wasm
MAX_MODULE_CONFIG_SIZE | modules/sdk/abi/config.rs | 16 * 1024 | embedded+rp2350
MAX_MODULE_CONFIG_SIZE | modules/sdk/abi/config.rs | 8 * 1024 | embedded+rp2040
MAX_MODULE_SECTION | src/kernel/boot/config.rs | 256 * 1024 | hosted
MAX_MODULE_SECTION | src/kernel/boot/config.rs | 32 * 1024 | bare
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
MAX_GRAPH_EDGES | src/kernel/boot/config.rs | if MAX_MODULES > 128 { HOST_GRAPH_EDGES } else { SMALL_GRAPH_EDGES } | *
HOST_GRAPH_EDGES | src/kernel/boot/config.rs | 384 | *
SMALL_GRAPH_EDGES | src/kernel/boot/config.rs | 128 | *
MAX_CHANNELS | src/kernel/ipc/channel.rs | MAX_GRAPH_EDGES | *
MAX_SPI_BUSES | src/kernel/boot/config.rs | 2 | *
MAX_I2C_BUSES | src/kernel/boot/config.rs | 2 | *
MAX_UART_BUSES | src/kernel/boot/config.rs | 2 | *
MAX_PIO_CONFIGS | src/kernel/boot/config.rs | 3 | *
MAX_GPIO_CONFIGS | src/kernel/boot/config.rs | 8 | *
MAX_WORKLOAD_SECTION_BYTES | src/kernel/boot/config.rs | 8 * 1024 | *
TICK_BOUND_MAX | src/kernel/boot/config.rs | 50_000 | *
MAX_FREE_REGIONS | src/kernel/module/loader.rs | 32 | *
ISO_ARENA_SIZE | src/kernel/module/loader.rs | 2 * 1024 * 1024 | kernel-vm
MAX_TRACKED | src/kernel/module/provider.rs | 128 | *
MAX_PROVIDERS | src/kernel/module/provider.rs | MAX_CONTRACTS | *
MAX_DYN_TAG_ROUTES | src/kernel/module/provider.rs | 4 | *
MAX_KEY_BYTES | src/kernel/security/key_vault.rs | 64 | *
MAX_LABEL | src/kernel/security/key_vault.rs | 64 | *
MAX_PERSISTED | src/kernel/security/key_vault.rs | 8 | *
MAX_SEAL_BYTES | src/kernel/security/key_vault.rs | 2048 | *
PARAM_TAG_MAX | tools/src/manifest.rs | 0xEF | *
```

Constants in these files that are shaped like ceilings but are not
resource decisions — record layouts, scratch sized from a ceiling above,
protocol constants, mirrors of a registered symbol — are retired from
the coverage report here, each with the reason it is not a row.

```limit-register-exempt
NET_CMD_RECORD_CAPACITY | modules/foundation/tls/mod.rs | derived: the frame scratch less overhead, capped by net_proto MAX_CMD_DATA
CLEAR_CHUNK_MAX | modules/foundation/tls/mod.rs | derived: the record payload budget of NET_CMD_RECORD_CAPACITY
HS_FRAGMENT_MAX | modules/foundation/tls/mod.rs | derived: the same budget less the appended ChangeCipherSpec record
WIRE_RECORD_MAX | modules/foundation/tls/mod.rs | derived: equals NET_CMD_RECORD_CAPACITY; sizes the record staging buffers
NET_SCRATCH_SIZE | modules/foundation/tls/mod.rs | scratch: one net frame around one TLS record
MAX_KEY_LEN | modules/foundation/quic/mod.rs | mirror of the registered tls MAX_KEY_LEN, so a key_file shared between them packs identically
MUX_DATA_MAX | modules/foundation/quic/mod.rs | derived: mux::MUX_QUIC_STREAM_RX_MAX, the contract's published bound
NET_BUF_SIZE | modules/foundation/quic/mod.rs | scratch: one net frame around one QUIC packet
STATE_ARENA_SIZE | src/kernel/module/loader.rs | mirror of the registered modules/sdk/abi/config.rs ceiling, re-exported for the loader
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
GRAPH_SECTION_SIZE | src/kernel/boot/config.rs | derived from MAX_GRAPH_EDGES and the layout sizes
GRAPH_SLOTS_CODE | src/kernel/boot/config.rs | packed graph-section layout, derived from MAX_GRAPH_EDGES
HEADER_SIZE | src/kernel/boot/config.rs | config blob header layout
CONFIG_ARENA_SIZE | src/kernel/boot/config.rs | mirror of the platform config's CONFIG_ARENA_SIZE
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
```
