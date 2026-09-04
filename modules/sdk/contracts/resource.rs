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
/// Decoded boot-configuration arena (bytes).
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

/// Number of kernel pools — the ledger table size and the count of `POOL`
/// records in one PSTATUS round.
pub const KERNEL_POOL_COUNT: usize = 9;

/// First id of the module-declared pool range.
pub const POOL_MODULE_BASE: u16 = 0x0100;

/// Class of a kernel pool id (all kernel pools are R1 today; R3 unit
/// claims join the ledger with their own ids when instrumented).
pub const fn kernel_pool_class(_pool: u16) -> u8 {
    CLASS_MEMORY
}

const _: () = assert!(KERNEL_POOL_COUNT == POOL_ELASTIC_REGION as usize);

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
/// Grants are monotonic-to-teardown (§3.6 "shrink deferred"): there is
/// no individual free; every chunk a module holds is reclaimed when its
/// owner is torn down. EL0-isolated modules are denied (their page
/// tables map state/heap/channels only — mapping grants is future work).
pub const ELASTIC_ALLOC: u32 = 0x0C3F;

// ── Capacity-envelope config section ───
//
// The composer's per-deployment pool envelope, carried as a post-body
// config section (PAST the checksummed body — the rig-proven additive
// discipline; growing `body_size` hangs the bare-metal Pi 5 boot).
// Section layout, mirroring the resident-workload (FXPD) section's
// self-describing header:
//
//   [FXEV u32][section_len u32][crc16 u16][entry_count u16]
//   [entries: pool_id u16 LE + n u32 LE, ×entry_count]
//
// `crc16` covers `section[10..section_len]` (count + entries). Each entry
// sets the named pool's ENFORCED capacity for this deployment — always ≤
// the compiled static table/arena size; the kernel clamps and logs an
// entry that exceeds it. Absent section ⇒ static sizes rule (byte-identical
// boot for configs without a `capacity:` block).

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
