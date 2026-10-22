// Resource-ledger registry.
//
// Every accounted capacity in the system is a *pool* with a stable u16 id.
// The kernel ledger (`kernel::sys::resource_ledger`) tracks
// `{cap, cur, peak, denials}` per pool and publishes them as PSTATUS `POOL`
// telemetry records (`telemetry::PSTATUS_POOL`); a denied request returns
// `errno::ENOSPC` and increments the pool's `denials` counter. Consumers
// (observe, otel, owner status) name pools from this registry.
//
// Units are per-pool: arena pools count bytes; table pools count slots.
// Ids are append-only — a pool id, once published, is never reused.

// ── Resource classes ───────────────────

/// R1: memory bytes/slots — the fungible class; pools grow with hardware.
pub const CLASS_MEMORY: u8 = 1;
/// R2: identifier-width ceilings — wire/ABI commitments, never expected to
/// bind before a `CLASS_MEMORY` pool does (see the limit register).
pub const CLASS_ID: u8 = 2;
/// R3: hardware units — datasheet-finite, declared per silicon.
pub const CLASS_UNIT: u8 = 3;

// ── Kernel pool ids ─────────────────────────────────────────────────
//
// The kernel's own accounted capacities. Ids 0x0001..=0x00FF are reserved
// for kernel pools; 0x0100.. is reserved for module-declared pools.

/// Per-module state arena (bytes; backs `loader::alloc_state`).
pub const POOL_STATE_ARENA: u16 = 0x0001;
/// Shared channel buffer-pool arena (bytes).
pub const POOL_BUFFER_ARENA: u16 = 0x0002;
/// Boot configuration (bytes): the module params the graph borrows from its
/// config blob in place, against the blob's mapped length. Observed, never
/// allocated from, so it is not sizable by a capacity envelope.
pub const POOL_CONFIG_ARENA: u16 = 0x0003;
/// Channel slot table (slots).
pub const POOL_CHANNELS: u16 = 0x0004;
/// Event slot table (slots).
pub const POOL_EVENTS: u16 = 0x0005;
/// Timer-fd slot table (slots).
pub const POOL_TIMERS: u16 = 0x0006;
/// Workload owner table (slots).
pub const POOL_OWNERS: u16 = 0x0007;
/// Scheduler module slot table (slots).
pub const POOL_MODULE_SLOTS: u16 = 0x0008;
/// Kernel elastic region (bytes) — Tier B chunk grants (`ELASTIC_ALLOC`).
pub const POOL_ELASTIC_REGION: u16 = 0x0009;
/// Control-plane store subscriptions (slots): one per watched prefix per
/// module. Derived from what the graph's store consumers declare.
pub const POOL_STORE_SUBS: u16 = 0x000A;
/// Control-plane store `GET` read slots open at once (slots).
pub const POOL_STORE_READS: u16 = 0x000B;
/// Control-plane store streamed writes open at once (slots).
pub const POOL_STORE_WRITES: u16 = 0x000C;
/// Capability grants presented to a guarded store at once (slots).
pub const POOL_STORE_GRANTS: u16 = 0x000D;
/// Host-process sandboxes held at once, finished ones included (slots).
pub const POOL_SANDBOXES: u16 = 0x000E;
/// Interactive terminal sessions open at once (slots).
pub const POOL_TTY_SESSIONS: u16 = 0x000F;
/// Provider handles the kernel tracks for teardown at once (slots).
pub const POOL_TRACKED_HANDLES: u16 = 0x0010;
/// State-arena free-list entries: the holes freed modules leave below the
/// bump mark (slots).
pub const POOL_STATE_FREE_LIST: u16 = 0x0011;
/// `net.policy` tables held at once (slots).
pub const POOL_NET_POLICY_TABLES: u16 = 0x0012;
/// Rule bytes one `net.policy` table holds (bytes).
pub const POOL_NET_POLICY_TABLE_BYTES: u16 = 0x0013;
/// Subscriptions one workload's own store holds (slots).
pub const POOL_OWNER_STORE_SUBS: u16 = 0x0014;
/// `GET` read slots one workload's own store holds (slots).
pub const POOL_OWNER_STORE_READS: u16 = 0x0015;
/// Streamed writes one workload's own store holds (slots).
pub const POOL_OWNER_STORE_WRITES: u16 = 0x0016;
/// `net.route` segments held at once (slots).
pub const POOL_NET_ROUTE_SEGMENTS: u16 = 0x0017;
/// `net.route` peer routes held at once (slots).
pub const POOL_NET_ROUTE_PEERS: u16 = 0x0018;
/// `net.route` held addresses at once (slots).
pub const POOL_NET_ROUTE_HELD: u16 = 0x0019;

/// Number of kernel pools — the ledger table size and the count of `POOL`
/// records in one PSTATUS round.
pub const KERNEL_POOL_COUNT: usize = 25;

/// First id of the module-declared pool range.
pub const POOL_MODULE_BASE: u16 = 0x0100;

/// Class of a kernel pool id. Every kernel pool is a memory pool; a pool of
/// another class takes an id of its own.
pub const fn kernel_pool_class(_pool: u16) -> u8 {
    CLASS_MEMORY
}

const _: () = assert!(KERNEL_POOL_COUNT == POOL_NET_ROUTE_HELD as usize);

/// An arena entry with this bit set is in KiB, not bytes. Arena sizes below
/// 2 GiB are written in exact bytes, so a byte-precise budget stays exact; a
/// larger one (a 16 GB board's state arena) is written in KiB, rounded up,
/// and reaches 2 TiB. Other pools' entries are plain counts.
pub const ENTRY_KIB: u32 = 1 << 31;

/// Whether `pool` is an arena, whose entries may carry [`ENTRY_KIB`].
pub const fn is_arena(pool: u16) -> bool {
    matches!(
        pool,
        POOL_STATE_ARENA | POOL_BUFFER_ARENA | POOL_ELASTIC_REGION
    )
}

/// The figure an envelope (or declared-demand) entry `n` states for `pool`:
/// bytes for an arena (KiB × 1024 when [`ENTRY_KIB`] is set), slots
/// otherwise.
pub const fn decode_entry(pool: u16, n: u32) -> u64 {
    if is_arena(pool) && n & ENTRY_KIB != 0 {
        ((n & !ENTRY_KIB) as u64) * 1024
    } else {
        n as u64
    }
}

// ── Tier B elastic-region chunk grants ─
//
// A module whose manifest pool supports Tier B grows it at runtime in
// whole chunks taken from the kernel's composer-reservable elastic
// region — module state and heap arenas are committed at load, so
// runtime elasticity has to come from a kernel-owned region.

/// Request a chunk from the kernel elastic region. handle = -1.
/// arg in: `[bytes u32 LE]`; the kernel rounds the grant up to the
/// elastic quantum. arg out (same buffer, ≥ 8 bytes): `[ptr u64 LE]`.
/// Returns the granted byte count (> 0), or `errno::ENOSPC` — an
/// accounted denial against `POOL_ELASTIC_REGION` (region exhausted,
/// chunk table full, or a zero-sized region on targets without one).
///
/// Grants are monotonic-to-teardown: there is no individual free; every
/// chunk a module holds is reclaimed when its owner is torn down.
/// EL0-isolated modules are denied: their page tables map state, heap and
/// channels only, and a grant lies outside all three.
pub const ELASTIC_ALLOC: u32 = 0x0C3F;

// ── Capacity-envelope config section ───
//
// The composer's per-deployment pool envelope, carried as a post-body
// config section (PAST the checksummed body: growing `body_size` hangs the
// bare-metal Pi 5 boot).
// Section layout, mirroring the resident-workload (FXPD) section's
// self-describing header:
//
//   [FXEV u32][section_len u32][crc16 u16][entry_count u16]
//   [entries: pool_id u16 LE + n u32 LE, ×entry_count]
//
// `crc16` covers `section[10..section_len]` (count + entries). The kernel
// sizes each table from the config it parses — module slots from the module
// and edge counts, channels from the edges, owners from the resident
// workloads, store subscriptions from what the graph's store consumers
// declare (the FXDM section below) — and an envelope entry is the pool's
// LIVE-ADD RESERVE on top of that: the pool's ceiling is derived + `n`. A
// pool with no structural source (events, timers, TTY sessions, …) is sized
// by its entry alone. `n` is decoded by `decode_entry`: exact bytes for an
// arena below 2 GiB, KiB past it (`ENTRY_KIB`, up to 2 TiB), the pool's own
// unit otherwise. Absent entry ⇒ the platform's default reserve. An ask the
// platform cannot hold (past a static table, past a format ceiling, or
// memory the host refuses) is refused at boot with the pool named; it is
// never clamped.
/// Envelope section magic: "FXEV".
pub const ENVELOPE_SECTION_MAGIC: u32 = 0x4658_4556;
/// One envelope entry: `pool_id u16 LE + n u32 LE`.
pub const ENVELOPE_ENTRY_SIZE: usize = 6;
/// Section header: magic + section_len + crc16 + entry_count.
pub const ENVELOPE_HEADER_SIZE: usize = 12;
/// Bounds a torn or hostile tail (more entries than pools can exist).
pub const MAX_ENVELOPE_ENTRIES: usize = 64;
/// Largest envelope section the kernel will read.
pub const MAX_ENVELOPE_SECTION_BYTES: usize =
    ENVELOPE_HEADER_SIZE + MAX_ENVELOPE_ENTRIES * ENVELOPE_ENTRY_SIZE;

// ── Declared-demand config section ─
//
// What the graph's modules declare they will ask of a kernel pool at run
// time, summed per pool by the composer from each module's manifest
// (`[capacities] store_subscriptions = n`, …). The kernel adds it to the
// pool's derived size, so a pool such as the store's subscription table is
// sized from the graph that boots rather than from a constant. Same shape as
// the envelope section, after it:
//
//   [FXDM u32][section_len u32][crc16 u16][entry_count u16]
//   [entries: pool_id u16 LE + n u32 LE, ×entry_count]

/// Declared-demand section magic: "FXDM".
pub const DEMAND_SECTION_MAGIC: u32 = 0x4658_444D;
