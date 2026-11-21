//! The adaptive pacer: one [`Pacer`] per resident `(graph, domain)`, and the
//! merge of a domain's instances into the sleep its pass returns.
//!
//! An instance reads its graph's signals from the pass that just stepped it
//! (useful work, a burst, a wake, a due timer) and chooses the graph's next
//! deadline under the domain's adaptive flags:
//!
//! - flags `0`: the domain's nominal tick, nothing adaptive;
//! - (a) demand-driven idle (`ADAPTIVE_FLAG_IDLE`): an idle graph relaxes
//!   straight to `tick_max_us`, and the pass may skip it while it stays idle;
//! - (b) adaptive cadence (`ADAPTIVE_FLAG_CADENCE`): AIMD between the floor
//!   and `tick_max_us` on a discrete ladder (`tick_max >> level`), with
//!   run-length hysteresis, a minimum dwell and a deadband; the first busy
//!   passes after idle run at the floor (hot-start) so a request's return
//!   hops do not each wait out the ramp.
//!
//! The floor is `max(tick_min_us, worst_step × FLOOR_MARGIN)`, clamped to
//! `tick_max_us`: a shortened tick never leaves less budget than one heavy
//! step. A domain with one resident graph has one instance, which is the
//! domain's pacer.
//!
//! Instances live in a table with one entry per owner slot and domain, at
//! `slot * MAX_DOMAINS + domain`, sized at boot with the owner table. An
//! instance is touched only by its domain's loop, and by the resident-graph
//! index rebuild, which runs with the other domains parked.
use super::*;

/// Bit 0 of a domain's adaptive flags: (a) demand-driven idle.
pub const ADAPTIVE_FLAG_IDLE: u8 = 0x01;
/// Bit 1 of a domain's adaptive flags: (b) adaptive cadence.
pub const ADAPTIVE_FLAG_CADENCE: u8 = 0x02;

/// Floor margin: the pacer never drives the tick below `worst_step ×
/// FLOOR_MARGIN`, so the per-domain budget always fits one heavy step with
/// headroom for the rest of the pass.
const FLOOR_MARGIN: u32 = 2;
/// Consecutive busy passes before the cadence steps down (faster).
const PACER_BUSY_RUN_N: u16 = 2;
/// Consecutive idle passes before the cadence steps up (relaxes).
const PACER_IDLE_RUN_M: u16 = 4;
/// Least wall-clock dwell between cadence-level changes, µs. Below a
/// workload's burst inter-arrival the cadence would sawtooth.
const PACER_MIN_DWELL_US: u64 = 2_000;
/// Deepest ladder level (deadline = `tick_max >> level`, clamped to the
/// floor, which usually bites first).
const PACER_MAX_LEVEL: u8 = 12;
/// Deadband: the previous deadline is held unless a new one differs by more
/// than `last >> PACER_DEADBAND_SHIFT` (≈6 %), at least
/// `PACER_DEADBAND_MIN_US`, so worst-step measurement jitter does not dither
/// the cadence. Ladder steps (2×) and real floor moves clear it.
const PACER_DEADBAND_SHIFT: u32 = 4;
const PACER_DEADBAND_MIN_US: u32 = 16;
/// Hot-start window in passes: the bounded pipeline hop budget, so the first
/// request after idle converges at the floor.
const PACER_HOTSTART_PASSES: u8 = MAX_PIPELINE_PASSES as u8;

/// One `(graph, domain)` pacer instance.
#[derive(Clone, Copy)]
pub(crate) struct Pacer {
    pub(crate) active: bool,
    pub(crate) graph_slot: u16,
    pub(crate) generation: u32,
    pub(crate) domain: u8,
    /// Ladder level: 0 = `tick_max` (relaxed); higher = faster.
    level_idx: u8,
    busy_run: u16,
    idle_run: u16,
    /// `now_micros()` of the last level change (dwell gate).
    last_change_us: u64,
    /// Last applied ladder deadline (deadband, `MON_PACER_LEVEL`).
    last_reported_us: u32,
    init: bool,
    /// The last pass's signals: useful work, a burst, a wake.
    pub(crate) work: bool,
    pub(crate) burst: bool,
    pub(crate) wake: bool,
    was_idle: bool,
    hotstart: u8,
    /// In demand-driven idle, so `MON_PACER_IDLE_SLEEP` logs once per
    /// busy→idle transition.
    idle_reported: bool,
}

impl Pacer {
    pub(crate) const fn new() -> Self {
        Self {
            active: false,
            graph_slot: 0,
            generation: 0,
            domain: 0,
            level_idx: 0,
            busy_run: 0,
            idle_run: 0,
            last_change_us: 0,
            last_reported_us: 0,
            init: false,
            work: false,
            burst: false,
            wake: false,
            was_idle: false,
            hotstart: 0,
            idle_reported: false,
        }
    }

    /// Runnable: the last pass left work, a burst or a wake.
    pub(crate) fn runnable(&self) -> bool {
        self.work || self.burst || self.wake
    }

    /// Drive the ladder to fully relaxed: demand-driven idle bypasses the
    /// AIMD ladder, and without this the first busy pass after a long idle
    /// would jump back to the pre-idle cadence instead of ramping down.
    fn force_relaxed(&mut self, tick_max: u32, now: u64) {
        if self.level_idx != 0 || !self.init {
            self.last_change_us = now;
        }
        self.init = true;
        self.level_idx = 0;
        self.busy_run = 0;
        self.last_reported_us = tick_max;
    }

    /// One AIMD step: busy passes step the level down fast, idle passes step
    /// it up slowly, both gated on run length and dwell; the deadline is held
    /// inside the deadband.
    fn ladder(&mut self, idle: bool, b: &PacerBounds, now: u64) -> u32 {
        if !self.init {
            self.init = true;
            self.level_idx = 0;
            self.last_change_us = now;
        }
        if idle {
            self.idle_run = self.idle_run.saturating_add(1);
            self.busy_run = 0;
        } else {
            self.busy_run = self.busy_run.saturating_add(1);
            self.idle_run = 0;
        }
        let dwell_ok = now.wrapping_sub(self.last_change_us) >= PACER_MIN_DWELL_US;
        let old_idx = self.level_idx;
        if !idle && self.busy_run >= PACER_BUSY_RUN_N && dwell_ok {
            self.level_idx = (self.level_idx + 1).min(PACER_MAX_LEVEL);
            self.busy_run = 0;
        } else if idle && self.idle_run >= PACER_IDLE_RUN_M && dwell_ok {
            self.level_idx = self.level_idx.saturating_sub(1);
            self.idle_run = 0;
        }
        if self.level_idx != old_idx {
            self.last_change_us = now;
        }
        let raw = (b.tick_max_us >> self.level_idx.min(31))
            .max(b.floor_us)
            .min(b.tick_max_us);
        let last = self.last_reported_us;
        let band = (last >> PACER_DEADBAND_SHIFT).max(PACER_DEADBAND_MIN_US);
        let deadline = if last != 0 && raw.abs_diff(last) <= band {
            last
        } else {
            raw
        };
        if deadline != self.last_reported_us {
            self.last_reported_us = deadline;
            let d = self.domain;
            let reason = if idle { "cooldown" } else { "busy" };
            let pass = pass_count(d as usize);
            log::info!("MON_PACER_LEVEL domain={d} tick_us={deadline} reason={reason} tick={pass}");
            if b.floor_us > b.tick_min_us {
                log::info!(
                    "MON_PACER_FLOOR domain={d} floor_us={} worst_step_us={} tick={pass}",
                    b.floor_us,
                    domain_worst_step_us(d as usize)
                );
            }
        }
        deadline
    }

    /// The instance's next deadline (µs) from the signals last set.
    fn deadline(&mut self, b: &PacerBounds, now: u64) -> u32 {
        if b.flags == 0 {
            return b.nominal_us;
        }
        let idle = !self.runnable();
        let was_idle = self.was_idle;
        self.was_idle = idle;
        if idle {
            self.hotstart = 0;
        }
        if (b.flags & ADAPTIVE_FLAG_IDLE) != 0 {
            let reported = self.idle_reported;
            self.idle_reported = idle;
            if idle && !reported {
                log::info!(
                    "MON_PACER_IDLE_SLEEP domain={} backstop_us={} tick={}",
                    self.domain,
                    b.tick_max_us,
                    pass_count(self.domain as usize)
                );
            }
            if idle {
                if (b.flags & ADAPTIVE_FLAG_CADENCE) != 0 {
                    self.force_relaxed(b.tick_max_us, now);
                }
                return b.tick_max_us;
            }
        }
        if (b.flags & ADAPTIVE_FLAG_CADENCE) == 0 {
            // Idle-only: a busy pass keeps the nominal tick.
            return b.nominal_us;
        }
        if was_idle && !idle {
            self.hotstart = PACER_HOTSTART_PASSES;
            mon_hotstart(self.domain as usize, b.floor_us);
        }
        if self.hotstart > 0 {
            self.hotstart -= 1;
            // Drive the ladder toward the floor so the cadence stays tight
            // when the window ends.
            let _ = self.ladder(false, b, now);
            return b.floor_us;
        }
        self.ladder(idle, b, now)
    }
}

/// `MON_PACER_HOTSTART`, throttled per domain: a cooperative pipeline can
/// alternate idle and work at every boundary.
fn mon_hotstart(domain: usize, floor_us: u32) {
    if domain >= MAX_DOMAINS {
        return;
    }
    // SAFETY: this domain's loop is the caller; its record is its own.
    let d = unsafe { &mut (*core::ptr::addr_of_mut!(SCHED)).domains[domain] };
    if let Some(sup) = d.mon_throttle(MonLine::Hotstart) {
        log::info!(
            "MON_PACER_HOTSTART domain={domain} deadline_us={floor_us} passes={PACER_HOTSTART_PASSES} tick={} suppressed={sup}",
            d.passes()
        );
    }
}

/// A domain's pacing bounds, read once per pass.
#[derive(Clone, Copy, Debug)]
pub struct PacerBounds {
    /// Adaptive flags (`ADAPTIVE_FLAG_*`).
    pub flags: u8,
    /// The domain's nominal tick, µs.
    pub nominal_us: u32,
    pub tick_min_us: u32,
    pub tick_max_us: u32,
    /// The live floor (`pacer_domain_floor_us`).
    pub floor_us: u32,
}

/// `domain`'s pacing bounds now.
pub fn pacer_bounds(domain: usize) -> PacerBounds {
    PacerBounds {
        flags: domain_adaptive_flags(domain),
        nominal_us: domain_tick_us(domain),
        tick_min_us: domain_tick_min_us(domain),
        tick_max_us: domain_tick_max_us(domain),
        floor_us: pacer_domain_floor_us(domain),
    }
}

/// The pacer instances, one per owner slot and domain. The static profiles
/// hold the compiled owner table's slots.
pub(crate) static mut GRAPH_PACERS: crate::kernel::mem::table::Table<
    Pacer,
    { crate::kernel::workload::owner::OWNER_TABLE_SLOTS * MAX_DOMAINS },
> = crate::boot_table!(
    crate::kernel::workload::owner::OWNER_TABLE_SLOTS * MAX_DOMAINS,
    Pacer::new(),
    crate::abi::contracts::resource::POOL_OWNERS,
    MAX_DOMAINS
);

/// Size the pacer table for an owner table of `owners` slots: an instance
/// per slot and domain, all committed.
///
/// # Safety
/// As `Table::reserve`: graph preparation, with no pacer instance borrowed.
pub(crate) unsafe fn size_graph_pacers(
    owners: usize,
) -> Result<(), crate::kernel::mem::table::TableError> {
    let n = owners
        .checked_mul(MAX_DOMAINS)
        .ok_or(crate::kernel::mem::table::TableError::Ceiling)?;
    // SAFETY: the caller's contract.
    let t = unsafe { &*core::ptr::addr_of!(GRAPH_PACERS) };
    // SAFETY: the caller's contract.
    unsafe { t.reserve(n)? };
    t.grow(n)
}

/// The instance of `(graph_slot, domain)`, claimed on first use. A
/// generation mismatch (the owner slot was reused by a new graph) resets it,
/// so the new graph does not inherit the old one's heat. `None` only for a
/// key no resident graph can have.
fn graph_pacer(graph_slot: u16, generation: u32, domain: u8) -> Option<&'static mut Pacer> {
    if domain as usize >= MAX_DOMAINS {
        return None;
    }
    let i = (graph_slot as usize)
        .checked_mul(MAX_DOMAINS)?
        .checked_add(domain as usize)?;
    let gp = &raw mut GRAPH_PACERS;
    // SAFETY: instance `i` belongs to `domain`, whose loop is the caller;
    // no other core touches it (see the module doc).
    let p = unsafe { (&mut *gp).get_mut(i)? };
    if !p.active || p.generation != generation {
        *p = Pacer::new();
        p.active = true;
        p.graph_slot = graph_slot;
        p.generation = generation;
        p.domain = domain;
    }
    Some(p)
}

/// Set an instance's signals from the pass that just ran: useful work, a
/// burst, a wake taken or still latched. `false` for a key no resident graph
/// can have.
pub fn graph_pacer_set_signals(
    graph_slot: u16,
    generation: u32,
    domain: u8,
    work: bool,
    burst: bool,
    wake: bool,
) -> bool {
    let Some(p) = graph_pacer(graph_slot, generation, domain) else {
        return false;
    };
    p.work = work;
    p.burst = burst;
    p.wake = wake;
    true
}

/// Whether the instance's last pass left it runnable. Fail-closed: a key
/// without an instance is runnable.
pub(crate) fn graph_pacer_runnable(graph_slot: u16, generation: u32, domain: u8) -> bool {
    graph_pacer(graph_slot, generation, domain).is_none_or(|p| p.runnable())
}

/// The instance's next deadline (µs) under `bounds`.
pub fn graph_pacer_deadline(
    graph_slot: u16,
    generation: u32,
    domain: u8,
    bounds: &PacerBounds,
    now_us: u64,
) -> u32 {
    match graph_pacer(graph_slot, generation, domain) {
        Some(p) => p.deadline(bounds, now_us),
        None => bounds.tick_max_us,
    }
}

/// Reset every instance (reconfigure, test teardown).
pub fn graph_pacer_reset_all() {
    let gp = &raw mut GRAPH_PACERS;
    // SAFETY: scheduler-thread-exclusive; reconfigure or tests.
    let t = unsafe { &mut *gp };
    for p in t.iter_mut() {
        *p = Pacer::new();
    }
}

/// Release every instance whose key `live` does not name: its owner was
/// freed or its graph rebuilt, and a reused slot must start fresh.
pub(crate) fn graph_pacer_retain(live: impl Fn(u16, u32, u8) -> bool) {
    let gp = &raw mut GRAPH_PACERS;
    // SAFETY: the resident-graph rebuild, with the other domains parked.
    let t = unsafe { &mut *gp };
    for p in t.iter_mut() {
        if p.active && !live(p.graph_slot, p.generation, p.domain) {
            *p = Pacer::new();
        }
    }
}

/// The merge of a domain's instances into one sleep: the soonest deadline
/// among the runnable graphs (and the periodic, must-tick and backstop terms
/// the pass adds); with none runnable, the soonest relaxed deadline, so an
/// idle sibling relaxes without delaying a hot graph.
#[derive(Clone, Copy, Debug)]
pub struct DeadlineMerge {
    min_runnable: u32,
    min_backstop: u32,
    any_runnable: bool,
}

impl Default for DeadlineMerge {
    fn default() -> Self {
        Self::new()
    }
}

impl DeadlineMerge {
    pub const fn new() -> Self {
        Self {
            min_runnable: u32::MAX,
            min_backstop: u32::MAX,
            any_runnable: false,
        }
    }

    /// A graph's pacer deadline; `busy` when it was runnable.
    pub fn graph(&mut self, deadline_us: u32, busy: bool) {
        self.min_backstop = self.min_backstop.min(deadline_us);
        if busy {
            self.runnable(deadline_us);
        }
    }

    /// Something that must run within `us`.
    pub fn runnable(&mut self, us: u32) {
        self.any_runnable = true;
        self.min_runnable = self.min_runnable.min(us);
    }

    /// The merged sleep (µs) under `bounds`.
    pub fn finish(&self, bounds: &PacerBounds) -> u32 {
        if bounds.flags == 0 {
            bounds.nominal_us
        } else if self.any_runnable {
            self.min_runnable
        } else if self.min_backstop == u32::MAX {
            // No resident graph: nothing to step before the backstop.
            bounds.tick_max_us
        } else {
            self.min_backstop
        }
    }
}

/// Period most recently chosen for each domain's next pass. Zero means no
/// pacing decision since graph preparation; readers then take the nominal
/// cadence.
static PACER_CURRENT_PERIOD_US: [AtomicU32; MAX_DOMAINS] =
    [const { AtomicU32::new(0) }; MAX_DOMAINS];

/// Settle `domain`'s next sleep from the merged pacer deadline: service the
/// domain's fired timers (their owners' wake bits latch as an event's would)
/// and let its earliest armed timer shorten the sleep, down to the floor and
/// no further. Records the period the flow budgets are paced on.
pub(crate) fn settle_deadline(domain: usize, merged_us: u32, floor_us: u32) -> u32 {
    let mut deadline = merged_us;
    if let Some(ms) = crate::kernel::ipc::timer::timer_pump(domain as u8) {
        let bound = ms.saturating_mul(1000).max(floor_us);
        if bound < deadline {
            deadline = bound;
        }
    }
    let deadline = deadline.max(1);
    PACER_CURRENT_PERIOD_US[domain.min(MAX_DOMAINS - 1)].store(deadline, Ordering::Relaxed);
    deadline
}

/// Period currently governing per-step flow budgets for a domain.
pub fn pacer_current_period_us(domain_id: usize) -> u32 {
    let period = PACER_CURRENT_PERIOD_US[domain_id.min(MAX_DOMAINS - 1)].load(Ordering::Relaxed);
    if period == 0 {
        domain_tick_us(domain_id)
    } else {
        period
    }
}

/// The live floor (µs) for `domain_id`: `max(tick_min_us, worst_step ×
/// FLOOR_MARGIN)`, clamped to `tick_max_us`. No pacer deadline goes below
/// it, and a platform that clamps the armed deadline further (bcm2712's
/// software-wake latency clamp) must not arm below it either: reconcile as
/// `raw.min(clamp.max(pacer_domain_floor_us(d)))`.
pub fn pacer_domain_floor_us(domain_id: usize) -> u32 {
    let tick_max = domain_tick_max_us(domain_id);
    domain_tick_min_us(domain_id)
        .max(domain_worst_step_us(domain_id).saturating_mul(FLOOR_MARGIN))
        .min(tick_max)
}

/// Reset all pacing state for a (re)configured graph, so its first cadence
/// decision depends on the new graph alone. Single-threaded reconfigure.
pub(crate) fn pacer_reset_all() {
    for p in PACER_CURRENT_PERIOD_US.iter() {
        p.store(0, Ordering::Relaxed);
    }
    graph_pacer_reset_all();
}
