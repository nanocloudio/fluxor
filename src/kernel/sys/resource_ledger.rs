//! Kernel resource ledger — accounting and denial attribution for every
//! kernel-owned capacity pool.
//!
//! Pull-based by design: the ledger never keeps its own usage counters.
//! Each pool's `cur`/`cap` is sampled from the subsystem that owns the
//! allocation (`loader::arena_usage`, the channel/event/timer slot tables,
//! …), so the ledger cannot drift from the allocators it reports on. The
//! ledger owns only what the allocators don't: cumulative `denials` per
//! pool and the sampled high-water `peak`.
//!
//! Two surfaces:
//! - **Denial**: a capacity-refusal site calls [`deny`], which counts the
//!   refusal and pushes one immediate PSTATUS `POOL` record (when a
//!   telemetry consumer is subscribed). The site returns `errno::ENOSPC`
//!   to its caller — the accounted capacity denial, distinct from
//!   `ENOMEM` allocator failure.
//! - **Cadence**: [`emit_all`] publishes one `POOL` record per kernel pool
//!   in the scheduler's PSTATUS round (`sample_pstatus`), kernel-stamped.
//!
//! It also holds the **boot plan**: each pool's ceiling is what the config
//! derives for it (module and edge counts, resident workloads, declared
//! demand) plus its live-add reserve (the FXEV envelope entry, else the
//! profile's default, `kernel::config::DEFAULT_RESERVES`). The tables size
//! themselves to [`ceiling`]; a static profile's table must already hold it,
//! and a plan it cannot hold is refused at boot naming the pool
//! ([`refuse`]), never clamped.

use crate::abi::contracts::resource as res;
use crate::abi::contracts::telemetry as tlm;
use portable_atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

// Every figure is held in the pool's own unit (bytes for the arenas, slots
// for the tables) as a `u64`: an arena on a large machine is past 4 GiB. The
// `u32` surfaces below (`ceiling`, `plan_parts`, `stats`) are for the tables
// and saturate; the arenas read [`ceiling_bytes`] and [`enforced`].
static DENIALS: [AtomicU32; res::KERNEL_POOL_COUNT] =
    [const { AtomicU32::new(0) }; res::KERNEL_POOL_COUNT];
static PEAKS: [AtomicU64; res::KERNEL_POOL_COUNT] =
    [const { AtomicU64::new(0) }; res::KERNEL_POOL_COUNT];
/// Per-deployment reserve (or size) from the boot config's FXEV envelope
/// section, in the pool's own unit; meaningful where `HAS_ENTRY` is set.
static ENTRY: [AtomicU64; res::KERNEL_POOL_COUNT] =
    [const { AtomicU64::new(0) }; res::KERNEL_POOL_COUNT];
static HAS_ENTRY: [AtomicBool; res::KERNEL_POOL_COUNT] =
    [const { AtomicBool::new(false) }; res::KERNEL_POOL_COUNT];
/// What the graph's modules declare they will ask of each pool (FXDM).
static DECLARED: [AtomicU64; res::KERNEL_POOL_COUNT] =
    [const { AtomicU64::new(0) }; res::KERNEL_POOL_COUNT];
/// What the parsed config derives for each pool (module count, edges,
/// resident workloads), set by [`plan`].
static DERIVED: [AtomicU64; res::KERNEL_POOL_COUNT] =
    [const { AtomicU64::new(0) }; res::KERNEL_POOL_COUNT];
/// A plan has been made: before one, ceilings are the defaults alone.
static PLANNED: AtomicBool = AtomicBool::new(false);

/// Kernel pool ids are 1-based and contiguous (`resource` contract).
fn idx(pool: u16) -> Option<usize> {
    if pool >= 1 && (pool as usize) <= res::KERNEL_POOL_COUNT {
        Some(pool as usize - 1)
    } else {
        None
    }
}

/// The pool's name as a capacity envelope (`capacity:`) spells it.
pub fn pool_name(pool: u16) -> &'static str {
    match pool {
        res::POOL_STATE_ARENA => "state_arena",
        res::POOL_BUFFER_ARENA => "buffer_arena",
        res::POOL_CONFIG_ARENA => "config_arena",
        res::POOL_CHANNELS => "channels",
        res::POOL_EVENTS => "events",
        res::POOL_TIMERS => "timers",
        res::POOL_OWNERS => "owners",
        res::POOL_MODULE_SLOTS => "module_slots",
        res::POOL_ELASTIC_REGION => "elastic_region",
        res::POOL_STORE_SUBS => "store_subs",
        res::POOL_STORE_READS => "store_reads",
        res::POOL_STORE_WRITES => "store_writes",
        res::POOL_STORE_GRANTS => "store_grants",
        res::POOL_SANDBOXES => "sandboxes",
        res::POOL_TTY_SESSIONS => "tty_sessions",
        res::POOL_TRACKED_HANDLES => "tracked_handles",
        res::POOL_STATE_FREE_LIST => "state_free_list",
        res::POOL_NET_POLICY_TABLES => "net_policy_tables",
        res::POOL_NET_POLICY_TABLE_BYTES => "net_policy_table_bytes",
        res::POOL_OWNER_STORE_SUBS => "owner_store_subs",
        res::POOL_OWNER_STORE_READS => "owner_store_reads",
        res::POOL_OWNER_STORE_WRITES => "owner_store_writes",
        res::POOL_NET_ROUTE_SEGMENTS => "net_route_segments",
        res::POOL_NET_ROUTE_PEERS => "net_route_peers",
        res::POOL_NET_ROUTE_HELD => "net_route_held",
        _ => "unknown",
    }
}

/// Sample `cur` in the pool's own units from the owning subsystem.
fn sample_cur(pool: u16) -> u64 {
    match pool {
        res::POOL_STATE_ARENA => crate::kernel::module::loader::arena_usage().0 as u64,
        res::POOL_BUFFER_ARENA => crate::kernel::ipc::buffer_pool::arena_usage().0 as u64,
        // Module params are borrowed from the config blob in place, so the
        // pool reports the params the graph carries against the blob's
        // mapped length; nothing is allocated from it.
        res::POOL_CONFIG_ARENA => crate::kernel::boot::config::config_params_usage().0 as u64,
        res::POOL_CHANNELS => crate::kernel::ipc::channel::in_use_count() as u64,
        res::POOL_EVENTS => crate::kernel::ipc::event::in_use_count() as u64,
        res::POOL_TIMERS => crate::kernel::ipc::fd::timer_in_use_count() as u64,
        res::POOL_OWNERS => {
            crate::kernel::exec::scheduler::ownership::owners().active_workload_count() as u64
        }
        res::POOL_MODULE_SLOTS => crate::kernel::exec::scheduler::active_module_count() as u64,
        res::POOL_ELASTIC_REGION => crate::kernel::mem::elastic::region_usage().0 as u64,
        res::POOL_TRACKED_HANDLES => crate::kernel::module::provider::tracked_in_use() as u64,
        res::POOL_STATE_FREE_LIST => {
            crate::kernel::module::loader::state_free_list_usage().0 as u64
        }
        res::POOL_NET_ROUTE_SEGMENTS | res::POOL_NET_ROUTE_PEERS | res::POOL_NET_ROUTE_HELD => {
            crate::kernel::net_route::in_use(pool) as u64
        }
        #[cfg(feature = "host-linux")]
        res::POOL_STORE_SUBS
        | res::POOL_STORE_READS
        | res::POOL_STORE_WRITES
        | res::POOL_STORE_GRANTS => crate::platform::linux::store::pool_in_use(pool) as u64,
        #[cfg(feature = "chip-bcm2712")]
        res::POOL_STORE_SUBS | res::POOL_STORE_READS => {
            crate::platform::store::pool_in_use(pool) as u64
        }
        _ => 0,
    }
}

/// The pool's capacity where it is not a plan: the config blob's mapped
/// length for the config arena, which is observed and never allocated from,
/// and on bcm2712 the state arena the device tree's memory leaves.
fn observed_cap(pool: u16) -> Option<u64> {
    match pool {
        res::POOL_CONFIG_ARENA => Some(crate::kernel::boot::config::config_params_usage().1 as u64),
        // bcm2712's arena is what the device tree's zone holds after the
        // kernel's tables are carved from it, RP's what the static pool holds
        // beside the graph's tables and buffer arena — not the planning
        // figure.
        #[cfg(any(feature = "chip-bcm2712", feature = "rp"))]
        res::POOL_STATE_ARENA => Some(crate::kernel::module::loader::arena_cap() as u64),
        _ => None,
    }
}

fn update_peak(i: usize, cur: u64) -> u64 {
    let peak = PEAKS[i].load(Ordering::Relaxed).max(cur);
    PEAKS[i].store(peak, Ordering::Relaxed);
    peak
}

/// Install one envelope entry: the deployment's live-add reserve for `pool`
/// (its size, for a pool the config cannot derive), `n` as the entry encodes
/// it (`resource::decode_entry`: exact bytes for an arena below 2 GiB). Not
/// clamped: a reserve the platform cannot hold is refused when the plan is
/// made. Called from the boot-config FXEV section parse.
pub fn set_reserve(pool: u16, n: u32) {
    let Some(i) = idx(pool) else {
        log::warn!("[ledger] envelope names unknown pool {pool}; ignored");
        return;
    };
    ENTRY[i].store(res::decode_entry(pool, n), Ordering::Relaxed);
    HAS_ENTRY[i].store(true, Ordering::Relaxed);
}

/// Install one declared-demand entry (FXDM): what the graph's modules declare
/// they will ask of `pool`, added to its derived size (decoded as
/// [`set_reserve`] decodes).
pub fn set_declared(pool: u16, n: u32) {
    let Some(i) = idx(pool) else {
        log::warn!("[ledger] declared demand names unknown pool {pool}; ignored");
        return;
    };
    DECLARED[i].store(res::decode_entry(pool, n), Ordering::Relaxed);
}

/// Clear every envelope entry and declared demand — a config without them must
/// not inherit the previous deployment's. Called before the post-body parse.
pub fn reset_envelope() {
    for i in 0..res::KERNEL_POOL_COUNT {
        ENTRY[i].store(0, Ordering::Relaxed);
        HAS_ENTRY[i].store(false, Ordering::Relaxed);
        DECLARED[i].store(0, Ordering::Relaxed);
    }
}

/// Record what the parsed config derives for `pool` (the plan's structural
/// part; declared demand is added on top).
pub fn set_derived(pool: u16, n: u32) {
    if let Some(i) = idx(pool) {
        DERIVED[i].store(u64::from(n), Ordering::Relaxed);
        PLANNED.store(true, Ordering::Relaxed);
    }
}

/// `(derived, reserve)` of `pool`'s plan: what the config derives and
/// declares, and the reserve on top of it (saturating at `u32::MAX`: a
/// table's figure; an arena's is [`plan_parts_wide`]).
pub fn plan_parts(pool: u16) -> (u32, u32) {
    let (d, r) = plan_parts_wide(pool);
    (sat(d), sat(r))
}

fn sat(n: u64) -> u32 {
    n.min(u64::from(u32::MAX)) as u32
}

/// [`plan_parts`] in the pool's own unit, unsaturated.
pub fn plan_parts_wide(pool: u16) -> (u64, u64) {
    plan_parts_in(&crate::kernel::config::PROFILE, pool)
}

/// [`plan_parts_wide`] against `profile`'s pool tables rather than the
/// compiled profile's: the same plan, over what the config derived and the
/// envelope carries, for a profile this kernel was not built with.
pub fn plan_parts_in(profile: &crate::kernel::config::CapacityProfile, pool: u16) -> (u64, u64) {
    let Some(i) = idx(pool) else { return (0, 0) };
    let mut derived = DERIVED[i]
        .load(Ordering::Relaxed)
        .saturating_add(DECLARED[i].load(Ordering::Relaxed));
    // The system owner is structural in every graph, planned or not.
    if pool == res::POOL_OWNERS {
        derived = derived.max(1);
    }
    let reserve = if HAS_ENTRY[i].load(Ordering::Relaxed) {
        // The deployment's own figure, never clamped: one past the pool's
        // domain is refused at boot naming the pool.
        ENTRY[i].load(Ordering::Relaxed)
    } else {
        match profile.static_pool(pool) {
            // A static table without an envelope entry keeps every slot it
            // has: the reserve is whatever the derived part leaves.
            Some(n) => (n as u64).saturating_sub(derived),
            // The profile's default is headroom, not an ask: it takes what
            // the pool's index domain leaves beside the derived part, so a
            // graph that fits the domain boots on the defaults.
            None => {
                let default = profile.default_reserve(pool) as u64;
                match pool_domain(pool) {
                    Some(domain) => default.min(domain.saturating_sub(derived)),
                    None => default,
                }
            }
        }
    };
    (derived, reserve)
}

/// The index domain `pool`'s table is held within: what an index into it may
/// be at all, whatever the plan. A ceiling past it is refused at boot naming
/// the pool (`size_kernel_tables`). `None` for a pool bound only by the
/// memory the platform gives it.
pub fn pool_domain(pool: u16) -> Option<u64> {
    let n = match pool {
        res::POOL_MODULE_SLOTS => crate::kernel::config::MAX_MODULES,
        res::POOL_CHANNELS => crate::kernel::exec::scheduler::MAX_CHANNELS,
        res::POOL_OWNERS => crate::kernel::workload::owner::MAX_OWNERS,
        // Event and timer handles name their slot in a tagged fd's slot
        // field.
        res::POOL_EVENTS | res::POOL_TIMERS => crate::abi::kernel_abi::fd::SLOT_MASK as usize + 1,
        #[cfg(feature = "host-linux")]
        res::POOL_SANDBOXES => crate::platform::linux::host_backend::MAX_SANDBOXES,
        #[cfg(feature = "host-linux")]
        res::POOL_TTY_SESSIONS => crate::platform::linux::host_backend::MAX_TTY_SESSIONS,
        _ => return None,
    };
    Some(n as u64)
}

/// The pool's ceiling: derived + reserve. What its table is sized to, and
/// what an allocation is admitted against. A table's slot count; saturates
/// at `u32::MAX` (an arena reads [`ceiling_bytes`]).
pub fn ceiling(pool: u16) -> u32 {
    sat(ceiling_bytes(pool))
}

/// The pool's ceiling in its own unit, unsaturated: an arena's bytes.
pub fn ceiling_bytes(pool: u16) -> u64 {
    let (derived, reserve) = plan_parts_wide(pool);
    derived.saturating_add(reserve)
}

/// Log a boot plan the platform cannot hold, naming the pool, and count it.
/// The caller fails the boot.
pub fn refuse(pool: u16, why: &str) {
    refuse_in(&crate::kernel::config::PROFILE, pool, why);
}

/// [`refuse`], stating the plan `profile` makes.
fn refuse_in(profile: &crate::kernel::config::CapacityProfile, pool: u16, why: &str) {
    let (derived, reserve) = plan_parts_in(profile, pool);
    log::error!(
        "[capacity] pool '{}' refused at boot: ceiling {} (derived {derived} + reserve {reserve}) — \
         {why}",
        pool_name(pool),
        derived.saturating_add(reserve),
    );
    deny(pool);
}

/// A kernel table could not be sized to what the boot config asks; the
/// refusal has already been logged, naming the pool ([`refuse`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused;

/// Check that a static profile's table holds `pool`'s plan: what the config
/// derives and declares, plus the envelope entry when there is one (without
/// one the reserve is whatever the table leaves). `Err` has logged the
/// refusal ([`refuse`]). A profile that sizes the pool at boot has nothing to
/// check here.
pub fn check_static(pool: u16) -> Result<(), Refused> {
    check_static_in(&crate::kernel::config::PROFILE, pool)
}

/// [`check_static`] against `profile`'s tables: the check a kernel compiled
/// with that profile makes at boot, over the same plan.
pub fn check_static_in(
    profile: &crate::kernel::config::CapacityProfile,
    pool: u16,
) -> Result<(), Refused> {
    match profile.static_pool(pool) {
        Some(n) => {
            let (derived, reserve) = plan_parts_in(profile, pool);
            if derived.saturating_add(reserve) > n as u64 {
                refuse_in(profile, pool, "past this profile's static table");
                Err(Refused)
            } else {
                Ok(())
            }
        }
        None => Ok(()),
    }
}

/// Would usage `next_use` (in the pool's own units, AFTER the candidate
/// allocation) still be within the pool's ceiling? A table sized to its
/// ceiling enforces it itself; this is the check for allocation sites whose
/// storage is larger (a static table, an arena).
pub fn enforced_allows(pool: u16, next_use: impl Into<u64>) -> bool {
    if idx(pool).is_none() {
        return true;
    }
    next_use.into() <= ceiling_bytes(pool)
}

/// The deployment's envelope capacity for `pool` — `Some` only when the boot
/// config carried an envelope entry for it, so a refusal can say the
/// packaging, not the platform, is what bound.
pub fn enforced(pool: u16) -> Option<u64> {
    let i = idx(pool)?;
    if HAS_ENTRY[i].load(Ordering::Relaxed) {
        Some(ceiling_bytes(pool))
    } else {
        None
    }
}

/// Whether a boot plan has been made (a config parsed and derived).
pub fn planned() -> bool {
    PLANNED.load(Ordering::Relaxed)
}

/// Count a capacity refusal against `pool` and push one immediate `POOL`
/// record. The refusing site returns `errno::ENOSPC` to its caller.
pub fn deny(pool: u16) {
    let Some(i) = idx(pool) else { return };
    DENIALS[i].fetch_add(1, Ordering::Relaxed);
    if crate::kernel::sys::telemetry_ring::is_enabled() {
        emit_one(pool, crate::kernel::sys::hal::now_micros());
    }
}

/// The capacity a pool reports: its plan's ceiling, or what it observes.
fn report_cap(pool: u16) -> u64 {
    observed_cap(pool).unwrap_or_else(|| ceiling_bytes(pool))
}

/// `(cap, cur, peak, denials)` for one pool — observe/test surface, a
/// table's figures (saturating at `u32::MAX`; [`stats_wide`] for an arena).
/// `cap` is the pool's ceiling (derived + reserve).
pub fn stats(pool: u16) -> (u32, u32, u32, u32) {
    let (cap, cur, peak, denials) = stats_wide(pool);
    (sat(cap), sat(cur), sat(peak), denials)
}

/// [`stats`] in the pool's own unit, unsaturated.
pub fn stats_wide(pool: u16) -> (u64, u64, u64, u32) {
    let Some(i) = idx(pool) else {
        return (0, 0, 0, 0);
    };
    let cur = sample_cur(pool);
    let peak = update_peak(i, cur);
    (
        report_cap(pool),
        cur,
        peak,
        DENIALS[i].load(Ordering::Relaxed),
    )
}

fn emit_one(pool: u16, t_micros: u64) {
    let Some(i) = idx(pool) else { return };
    let cur = sample_cur(pool);
    let cap = report_cap(pool);
    let peak = update_peak(i, cur);
    let mut rec = [0u8; tlm::PSTATUS_POOL_SIZE];
    if let Some(n) = tlm::write_pstatus_pool(
        &mut rec,
        tlm::MODULE_KERNEL,
        t_micros,
        pool,
        res::kernel_pool_class(pool),
        cap,
        cur,
        peak,
        DENIALS[i].load(Ordering::Relaxed),
    ) {
        crate::kernel::sys::telemetry_ring::emit(tlm::MODULE_KERNEL, &rec[..n]);
    }
}

/// Publish one `POOL` record per kernel pool — called from the scheduler's
/// PSTATUS round; the caller has already checked ring subscription.
pub fn emit_all(t_micros: u64) {
    for pool in 1..=res::KERNEL_POOL_COUNT as u16 {
        emit_one(pool, t_micros);
    }
}

// ── Boot plan ──────────────────────────────────────────────────────────────

/// Tees and merges `prepare_graph` will insert: one per port that carries
/// two or more edges in the same direction. An upper bound — a fan a
/// multi-inbound or multi-outbound module keeps unfanned is still counted —
/// so the tables it sizes never come up short.
fn fan_count(config: &crate::kernel::boot::config::Config) -> usize {
    let n = config.edge_count as usize;
    // Keys: direction (bit 31) | module id (bits 5..16) | port key (bits 0..4:
    // the output port index, or the input port type and index).
    let mut keys = crate::scratch![0u32; 2 * crate::kernel::boot::config::MAX_GRAPH_EDGES, 2 * n];
    if keys.len() < 2 * n {
        // No scratch for the scan (logged where it was refused): every fan
        // takes at least two edges, so half the edges' endpoints bound them.
        return n;
    }
    let mut k = 0;
    for edge in config.graph_edges.iter().take(n).flatten() {
        let to_key = (u32::from(edge.to_port) << 4) | u32::from(edge.to_port_index);
        keys[k] = (u32::from(edge.from_id) << 5) | u32::from(edge.from_port_index);
        keys[k + 1] = (1 << 31) | (u32::from(edge.to_id) << 5) | to_key;
        k += 2;
    }
    let keys = &mut keys[..k];
    keys.sort_unstable();
    let mut fans = 0;
    let mut i = 0;
    while i < keys.len() {
        let mut j = i + 1;
        while j < keys.len() && keys[j] == keys[i] {
            j += 1;
        }
        if j - i >= 2 {
            fans += 1;
        }
        i = j;
    }
    fans
}

/// `(workloads, modules, edges)` the config's resident-workload section
/// (FXPD) will admit at boot: each workload is an owner, its modules take
/// module slots and its edges channels.
fn resident_demand(config: &crate::kernel::boot::config::Config) -> (usize, usize, usize) {
    let (ptr, len) = (
        config.resident_workload_section,
        config.resident_workload_section_len,
    );
    if ptr.is_null() || len < 12 {
        return (0, 0, 0);
    }
    // SAFETY: the parser validated the section (bounds and CRC) and it stays
    // mapped with the config blob.
    let s = unsafe { core::slice::from_raw_parts(ptr, len) };
    let count = u16::from_le_bytes([s[10], s[11]]) as usize;
    let (mut modules, mut edges) = (0, 0);
    let mut off = 12;
    for _ in 0..count {
        let Some(b) = s.get(off..off + 4) else { break };
        let blob_len = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
        // Frame: blob_len u32, flags u8, then the FLXA blob, whose header
        // carries module_count at byte 32 and edge_count at 33.
        if let Some(h) = s.get(off + 5..off + 5 + 34) {
            modules += h[32] as usize;
            edges += h[33] as usize;
        }
        off = off.saturating_add(5).saturating_add(blob_len);
    }
    (count, modules, edges)
}

/// Edges of the base graph that cross execution domains: their modules sit in
/// different domains, or the edge is marked cross-core. bcm2712 bridges each
/// with a consumer-side channel of its own beside the producer's
/// (`bridge_cross_domain_edges`). A tee or merge takes the domain of the
/// module it fans on, so fanning adds no crossing.
#[cfg(feature = "chip-bcm2712")]
fn cross_domain_edges(config: &crate::kernel::boot::config::Config) -> usize {
    use crate::kernel::boot::config::EdgeClass;
    let domain = |id: crate::kernel::exec::scheduler::ModuleId| {
        config.modules[id as usize].map(|m| m.domain_id)
    };
    config
        .graph_edges
        .iter()
        .take(config.edge_count as usize)
        .flatten()
        .filter(|e| e.edge_class == EdgeClass::CrossCore || domain(e.from_id) != domain(e.to_id))
        .count()
}

/// Derive every pool's structural size from `config`. A fan doubles as a
/// module and an edge; a resident workload's edges may each fan; on bcm2712 a
/// cross-domain edge takes a second channel, its consumer side.
pub fn plan(config: &crate::kernel::boot::config::Config) {
    let modules = config.modules.iter().flatten().count();
    let edges = config.edge_count as usize;
    let fans = fan_count(config);
    let (workloads, wl_modules, wl_edges) = resident_demand(config);
    let module_slots = modules + fans + wl_modules + wl_edges;
    #[cfg(feature = "chip-bcm2712")]
    let channels = edges + fans + 2 * wl_edges + cross_domain_edges(config);
    #[cfg(not(feature = "chip-bcm2712"))]
    let channels = edges + fans + 2 * wl_edges;
    set_derived(res::POOL_MODULE_SLOTS, module_slots as u32);
    set_derived(res::POOL_CHANNELS, channels as u32);
    set_derived(
        res::POOL_OWNERS,
        if cfg!(feature = "multitenant") {
            1 + workloads as u32
        } else {
            1
        },
    );
    // Holes below the bump mark number at most the live allocations plus
    // one, and a module holds its state, its arena and its heap segments. A
    // static profile's list is its fixed size, and a free past it is leaked
    // until the arena is reset.
    if crate::kernel::config::static_pool(res::POOL_STATE_FREE_LIST).is_none() {
        let per_module = 2 + crate::kernel::config::HEAP_SEGMENTS;
        set_derived(
            res::POOL_STATE_FREE_LIST,
            (ceiling(res::POOL_MODULE_SLOTS) as usize * per_module + 1) as u32,
        );
    }
}
