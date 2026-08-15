//! Kernel resource ledger — accounting and denial attribution for every
//! kernel-owned capacity pool (`rfc_resource_model.md` §6.1).
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

use crate::abi::contracts::resource as res;
use crate::abi::contracts::telemetry as tlm;
use portable_atomic::{AtomicU32, Ordering};

static DENIALS: [AtomicU32; res::KERNEL_POOL_COUNT] =
    [const { AtomicU32::new(0) }; res::KERNEL_POOL_COUNT];
static PEAKS: [AtomicU32; res::KERNEL_POOL_COUNT] =
    [const { AtomicU32::new(0) }; res::KERNEL_POOL_COUNT];
/// Per-deployment enforced capacities from the boot config's FXEV
/// envelope section (`rfc_resource_model.md` §3 Tier A). `0` = no
/// envelope entry — the compiled static size rules.
static ENFORCED: [AtomicU32; res::KERNEL_POOL_COUNT] =
    [const { AtomicU32::new(0) }; res::KERNEL_POOL_COUNT];

/// Kernel pool ids are 1-based and contiguous (`resource` contract).
fn idx(pool: u16) -> Option<usize> {
    if pool >= 1 && (pool as usize) <= res::KERNEL_POOL_COUNT {
        Some(pool as usize - 1)
    } else {
        None
    }
}

/// Sample `(cap, cur)` in the pool's own units from the owning subsystem.
fn sample(pool: u16) -> (u32, u32) {
    match pool {
        res::POOL_STATE_ARENA => {
            let (used, cap) = crate::kernel::module::loader::arena_usage();
            (cap as u32, used as u32)
        }
        res::POOL_BUFFER_ARENA => {
            let (used, cap) = crate::kernel::ipc::buffer_pool::arena_usage();
            (cap as u32, used as u32)
        }
        res::POOL_CONFIG_ARENA => {
            let (used, cap) = crate::kernel::boot::config::config_arena_usage();
            (cap as u32, used as u32)
        }
        res::POOL_CHANNELS => (
            crate::kernel::ipc::channel::MAX_CHANNELS as u32,
            crate::kernel::ipc::channel::in_use_count() as u32,
        ),
        res::POOL_EVENTS => (
            crate::kernel::ipc::event::MAX_EVENTS as u32,
            crate::kernel::ipc::event::in_use_count() as u32,
        ),
        res::POOL_TIMERS => (
            crate::kernel::ipc::fd::MAX_TIMERS as u32,
            crate::kernel::ipc::fd::timer_in_use_count() as u32,
        ),
        res::POOL_OWNERS => (
            crate::kernel::workload::owner::MAX_OWNERS as u32,
            crate::kernel::exec::scheduler::ownership::owners().active_workload_count() as u32,
        ),
        res::POOL_MODULE_SLOTS => (
            crate::kernel::exec::scheduler::MAX_MODULES as u32,
            crate::kernel::exec::scheduler::active_module_count() as u32,
        ),
        res::POOL_ELASTIC_REGION => {
            let (used, cap) = crate::kernel::mem::elastic::region_usage();
            (cap as u32, used as u32)
        }
        _ => (0, 0),
    }
}

fn update_peak(i: usize, cur: u32) -> u32 {
    let peak = PEAKS[i].load(Ordering::Relaxed).max(cur);
    PEAKS[i].store(peak, Ordering::Relaxed);
    peak
}

/// Install one envelope entry: the deployment's enforced capacity for
/// `pool`, clamped to the compiled static size (an entry above it is a
/// composer/kernel version skew — clamp and log rather than reject the
/// whole envelope). Called from the boot-config FXEV section parse.
pub fn set_enforced(pool: u16, n: u32) {
    let Some(i) = idx(pool) else {
        log::warn!("[ledger] envelope names unknown pool {pool}; ignored");
        return;
    };
    let (static_cap, _) = sample(pool);
    let eff = if n > static_cap {
        log::warn!(
            "[ledger] envelope pool {pool} n={n} exceeds compiled capacity {static_cap}; clamped"
        );
        static_cap
    } else {
        n
    };
    ENFORCED[i].store(eff, Ordering::Relaxed);
}

/// Clear every enforced capacity — a config without an envelope must not
/// inherit the previous deployment's. Called before the FXEV parse.
pub fn reset_enforced() {
    for e in &ENFORCED {
        e.store(0, Ordering::Relaxed);
    }
}

/// Would usage `next_use` (in the pool's own units, AFTER the candidate
/// allocation) still be within the deployment's enforced capacity?
/// `true` when no envelope entry exists — the static size then rules at
/// the owning table/arena itself.
pub fn enforced_allows(pool: u16, next_use: u32) -> bool {
    let Some(i) = idx(pool) else { return true };
    match ENFORCED[i].load(Ordering::Relaxed) {
        0 => true,
        cap => next_use <= cap,
    }
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

/// Effective capacity: the envelope's enforced value when set, else the
/// compiled static size.
fn effective_cap(i: usize, static_cap: u32) -> u32 {
    match ENFORCED[i].load(Ordering::Relaxed) {
        0 => static_cap,
        cap => cap,
    }
}

/// `(cap, cur, peak, denials)` for one pool — observe/test surface.
/// `cap` is the effective (envelope-enforced or static) capacity.
pub fn stats(pool: u16) -> (u32, u32, u32, u32) {
    let Some(i) = idx(pool) else {
        return (0, 0, 0, 0);
    };
    let (static_cap, cur) = sample(pool);
    let peak = update_peak(i, cur);
    (
        effective_cap(i, static_cap),
        cur,
        peak,
        DENIALS[i].load(Ordering::Relaxed),
    )
}

fn emit_one(pool: u16, t_micros: u64) {
    let Some(i) = idx(pool) else { return };
    let (static_cap, cur) = sample(pool);
    let cap = effective_cap(i, static_cap);
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
