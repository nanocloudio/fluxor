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

// ── Resource classes ───────────────────

/// R1: memory bytes/slots — the fungible class; pools grow with hardware.
pub const CLASS_MEMORY: u8 = 1;
/// R2: identifier-width ceilings — wire/ABI commitments, never expected to
/// bind before a `CLASS_MEMORY` pool does (see the limit register).
pub const CLASS_ID: u8 = 2;
/// R3: hardware units — datasheet-finite, declared per silicon.
pub const CLASS_UNIT: u8 = 3;

// ── Pool ids ────────────────────────────────────────────────────────
//
// Declared in the registry (`registry::pool`): kernel pools are
// `1..=KERNEL_POOL_COUNT`, module-served pools `POOL_MODULE_BASE..`, each
// dense.

pub use super::super::registry::pool::{
    BUFFER_ARENA as POOL_BUFFER_ARENA, CHANNELS as POOL_CHANNELS,
    CONFIG_ARENA as POOL_CONFIG_ARENA, ELASTIC_REGION as POOL_ELASTIC_REGION,
    EVENTS as POOL_EVENTS, HANDLES as POOL_HANDLES, ISOLATED_SLOTS as POOL_ISOLATED_SLOTS,
    KERNEL_COUNT as KERNEL_POOL_COUNT, LENDS as POOL_LENDS, MODULE_BASE as POOL_MODULE_BASE,
    MODULE_COUNT as MODULE_POOL_COUNT, MODULE_SLOTS as POOL_MODULE_SLOTS, OWNERS as POOL_OWNERS,
    SANDBOXES as POOL_SANDBOXES, STATE_ARENA as POOL_STATE_ARENA,
    STATE_FREE_LIST as POOL_STATE_FREE_LIST, STORE_SUBS as POOL_STORE_SUBS, TIMERS as POOL_TIMERS,
    TTY_SESSIONS as POOL_TTY_SESSIONS,
};

/// Class of a kernel pool id. Every kernel pool is a memory pool; a pool of
/// another class takes an id of its own.
pub const fn kernel_pool_class(_pool: u16) -> u8 {
    CLASS_MEMORY
}

/// An arena entry with this bit set is in KiB, not bytes. Arena sizes below
/// 2 GiB are written in exact bytes, so a byte-precise budget stays exact; a
/// larger one (a 16 GB board's state arena) is written in KiB, rounded up,
/// and reaches 2 TiB. Other pools' entries are plain counts.
pub const ENTRY_KIB: u32 = 1 << 31;

/// Whether `pool` is an arena, whose entries may carry [`ENTRY_KIB`].
pub const fn is_arena(pool: u16) -> bool {
    super::super::registry::pool::is_arena(pool)
}

/// The figure an envelope (or declared-demand) entry `n` states for `pool`:
/// bytes for an arena (KiB × 1024 when [`ENTRY_KIB`] is set), slots
/// otherwise. The boot configuration carries these entries: an envelope
/// entry is the pool's live-add reserve on top of what the graph derives (or
/// the pool's whole size, for a pool the graph cannot derive), a demand entry
/// what the graph's modules declare they will ask of it.
pub const fn decode_entry(pool: u16, n: u32) -> u64 {
    if is_arena(pool) && n & ENTRY_KIB != 0 {
        ((n & !ENTRY_KIB) as u64) * 1024
    } else {
        n as u64
    }
}

// ── Elastic-region chunk grants ─
//
// A module whose manifest pool supports elastic-region grants grows it at runtime in
// whole chunks taken from the kernel's composer-reservable elastic
// region — module state and heap arenas are committed at load, so
// runtime elasticity has to come from a kernel-owned region.

/// Request a chunk from the kernel elastic region. handle = -1.
/// arg in: `[bytes u32 LE]`; the kernel rounds the grant up to the
/// elastic quantum. arg out (same buffer, 12 bytes):
/// `[addr u64 LE][len u32 LE]`, `len` the granted byte count.
/// Returns 0, or `errno::ENOSPC` — an
/// accounted denial against `POOL_ELASTIC_REGION` (region exhausted,
/// chunk table full, or a zero-sized region on targets without one).
///
/// Grants are monotonic-to-teardown: there is no individual free; every
/// chunk a module holds is reclaimed when its owner is torn down.
/// EL0-isolated modules are denied: their page tables map state, heap and
/// channels only, and a grant lies outside all three.
pub use super::super::registry::resource::ELASTIC_ALLOC;

// ── Module-provided pools ─
//
// A pool in the module range is served by module providers rather than a
// kernel table: the store's subscriptions, held by the graph's
// `storage.namespace` providers, whose heap the composer plans from the
// demand the graph declares. The ledger keeps no counters of its own: it
// PULLS the pool's
// in-use figure from that provider, and the provider tells it of each
// refusal, so the pool's `POOL` record reads the same whoever serves it.
//
// A provider opts in with a manifest fact,
//
//   samples_pool = true
//
// beside its `provider_contracts`. The loader reads it after the
// provider's registration succeeds; a module that registers no contract is
// refused, and one without the marker is never called with `POOL_SAMPLE`.

/// The kernel's question TO a provider: how much of `pool` is in use. The
/// ledger calls the marked provider's `module_provider_dispatch` with this
/// opcode once per pool it serves in each PSTATUS round (never from inside
/// a provider call, so the provider is not re-entered), on the scheduler
/// thread, in a provider frame.
///
/// `handle = -1`; `arg = [pool: u16 LE]`, `arg_len = 2`. The provider
/// answers the pool's in-use figure in the pool's own unit (`>= 0`), or a
/// negative errno when it cannot say — the ledger then reads the pool from
/// its kernel owner until a later round's answer. The handler must be
/// bounded: a count it keeps, not a walk.
pub use super::super::registry::resource::POOL_SAMPLE;

/// Byte length of the `POOL_SAMPLE` argument.
pub const POOL_SAMPLE_ARG_LEN: usize = 2;

/// Count a refusal against `pool`: the provider of a module-provided pool
/// refused a request for want of capacity (it answered the request `ENOMEM`,
/// as the store family does). `handle = -1`; `arg = [pool: u16 LE]`.
/// The ledger counts the denial and pushes the pool's `POOL` record, as for
/// its own refusals. Admitted only from the module currently registered as
/// the default (unkeyed) provider of the pool's contract
/// ([`module_provided_pool_contract`]): `EACCES` from any other caller,
/// `EINVAL` for a pool no module provides. Answers 0.
pub use super::super::registry::resource::LEDGER_DENY;

// ── Owner lines ─
//
// Each workload owner holds one ledger line per kind of thing it is charged
// for: `{used, cap}` in bytes, cap 0 = uncapped. The kernel charges the
// state and buffer lines itself as it places modules and channels. The
// storage line is charged by the module that roots the owner's storage (a
// provider registered `provider_scope = "workloads"`), for bytes it alone can
// measure; the kernel knows a cap and a count, never what a byte of storage
// is. An owner whose admission installed no storage line holds no storage:
// every charge against it is refused.

/// Module state the owner's modules hold (bytes).
pub const OWNER_LINE_STATE: u16 = 0;
/// Channel buffers the owner's edges hold (bytes).
pub const OWNER_LINE_BUFFER: u16 = 1;
/// Storage the owner holds through a workload-scoped provider (bytes).
pub const OWNER_LINE_STORAGE: u16 = 2;
/// Lines each owner holds.
pub const OWNER_LINE_COUNT: usize = 3;

/// Charge `bytes` to the owner of the module calling the provider:
/// `arg = [line u16][bytes u64][flags u8]`, all LE, `handle = -1`.
/// [`LEDGER_HELD`] charges bytes the owner already holds (found on media),
/// past its cap if need be: an owner over its cap can shrink but not grow.
///
/// Admitted only inside a provider frame of a module holding a workload-scoped
/// layer, for a caller acting with its own authority, and only for
/// [`OWNER_LINE_STORAGE`]: `EACCES` otherwise, and `EACCES` for an owner
/// with no storage line. `ENOSPC` past the cap. Answers 0. The charged owner
/// is never an argument: it is the frame's caller, so a provider charges
/// only an owner it is serving.
pub use super::super::registry::resource::LEDGER_CHARGE;

/// Give `bytes` back to the calling owner's line, under the rules of
/// [`LEDGER_CHARGE`]: `arg = [line u16][bytes u64]`. Saturating. Answers 0.
pub use super::super::registry::resource::LEDGER_RELEASE;

/// [`LEDGER_CHARGE`] flag: the bytes are already held; charge past the cap.
pub const LEDGER_HELD: u8 = 0x01;
/// Byte length of the [`LEDGER_CHARGE`] argument.
pub const LEDGER_CHARGE_ARG_LEN: usize = 11;
/// Byte length of the [`LEDGER_RELEASE`] argument.
pub const LEDGER_RELEASE_ARG_LEN: usize = 10;

/// The contract whose module provider serves `pool`, as a contract id
/// (`requires_contract` class byte), or `None` for a pool only the kernel
/// serves.
pub const fn module_provided_pool_contract(pool: u16) -> Option<u16> {
    super::super::registry::pool::served_by(pool)
}
