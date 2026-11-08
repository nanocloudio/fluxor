//! Execution domains on their own cores: the run loop each domain's core
//! enters, the bridges between domains, and the quiesce that parks every
//! other domain while the primary changes the graph.
//!
//! Domain `d` runs on the platform's `d`th core (the boot core runs domain 0).
//! The platform wakes its cores and enters [`run`] on each; everything that
//! decides what a pass does is here, so every platform with more than one
//! core steps a graph the same way. What differs is passed in as a
//! [`Platform`]: which domains have a core, and the housekeeping a platform
//! does after each pass and after a domain's modules step.
//!
//! Boot, on the primary: `prepare_graph`, then [`cross::bridge_edges`], then
//! [`instantiate`], then [`coreless_domain`] (a graph with a domain no core
//! runs is refused), then [`release`] (the secondaries enter their loops),
//! then [`run`] for domain 0.

pub mod cross;

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::arch::aarch64::{cpu, exception, timer};
use crate::kernel::boot::config::ModuleEntry;
use crate::kernel::exec::scheduler::{self, MAX_DOMAINS};

// ============================================================================
// The platform's part
// ============================================================================

/// How a domain's loop runs, from the domain's `exec_mode`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Cooperative, one pass per tick (the default).
    Cooperative,
    /// High-rate periodic: a pass per tick at the domain's own rate.
    HighRate,
    /// Polled-timer ISR: the domain's modules belong to the ISR tier.
    PolledIsr,
    /// IRQ-owned: the domain's modules run from their interrupt.
    IrqOwned,
    /// Poll mode: passes back to back while any module bursts.
    Poll,
}

impl Tier {
    fn of(domain_id: usize) -> Self {
        match scheduler::domain_exec_mode(domain_id) {
            1 => Tier::HighRate,
            2 => Tier::PolledIsr,
            3 => Tier::Poll,
            4 => Tier::IrqOwned,
            _ => Tier::Cooperative,
        }
    }
}

/// What a platform does around the shared loop.
pub struct Platform {
    /// Whether a core runs domain `domain_id`'s loop once the domain has
    /// modules (domains 1 and up; the boot core runs domain 0).
    pub has_core: fn(domain_id: usize) -> bool,
    /// After each pass of a domain's loop, on the domain's core: the console
    /// drain, periodic reports, the uptime limit.
    pub after_pass: fn(domain_id: usize, core_id: usize, tier: Tier),
    /// After a cooperative or high-rate domain has stepped its modules, on its
    /// core: work that must not race those steps.
    pub after_step: fn(domain_id: usize),
}

// ============================================================================
// Which domains run
// ============================================================================

/// Modules per domain in the graph last instantiated; a domain with any has a
/// core running its loop.
static MODULE_COUNT: [AtomicU32; MAX_DOMAINS] = [const { AtomicU32::new(0) }; MAX_DOMAINS];

/// Set by the primary once the graph is instantiated; the secondaries wait for
/// it before entering their loops.
static RELEASED: AtomicBool = AtomicBool::new(false);

/// Whether domain `domain_id` has modules, so a core runs its loop.
pub fn is_active(domain_id: usize) -> bool {
    domain_id < MAX_DOMAINS && MODULE_COUNT[domain_id].load(Ordering::Acquire) != 0
}

/// The highest domain with modules, plus one: the cores the graph needs.
pub fn domains_needed() -> usize {
    (0..MAX_DOMAINS)
        .rev()
        .find(|&d| is_active(d))
        .map_or(1, |d| d + 1)
}

/// Primary-only, once the graph is instantiated: let the secondaries enter
/// their loops.
pub fn release() {
    RELEASED.store(true, Ordering::Release);
    // SAFETY: DMB + SEV are architectural hints; no memory effects.
    unsafe { core::arch::asm!("dmb ish", "sev", options(nostack)) };
}

/// True once [`release`] has run.
pub fn released() -> bool {
    RELEASED.load(Ordering::Acquire)
}

/// The first domain with modules that no core of `platform` runs: its
/// modules would never step, so a graph that has one is refused.
pub fn coreless_domain(platform: &Platform) -> Option<usize> {
    (1..MAX_DOMAINS).find(|&d| is_active(d) && !(platform.has_core)(d))
}

/// Seed this core's tick at domain `domain_id`'s rate, which can be faster
/// (high-rate) or slower than the global tick. The timer handler reloads from
/// this core's slot, so the rate survives the first interrupt. Returns the
/// period in counter ticks, for the platform to arm.
pub fn seed_core_tick(domain_id: usize) -> u32 {
    let ticks = us_to_ticks(scheduler::domain_tick_us(domain_id));
    let slot = (cpu::current_core_id() as usize).min(exception::NEXT_DEADLINE_TICKS.len() - 1);
    exception::NEXT_DEADLINE_TICKS[slot].store(ticks, Ordering::Relaxed);
    ticks
}

fn us_to_ticks(us: u32) -> u32 {
    let freq = timer::timer_freq();
    if freq > 0 {
        (u64::from(us) * freq / 1_000_000) as u32
    } else {
        // The counter frequency could not be read: ~1 ms at 62.5 MHz.
        62_500
    }
}

// ============================================================================
// Instantiation
// ============================================================================

/// Why a graph was not instantiated.
#[derive(Debug)]
pub enum InstantiateError {
    /// The staged owner plan is invalid: running the graph would run it with
    /// ownership isolation off.
    OwnerPlan(crate::kernel::workload::owner_plan::PlanError),
    /// This many modules did not instantiate, so the graph would run with
    /// unwired ports.
    Modules(usize),
}

/// Instantiate every module of a prepared graph and record which domains run.
/// Shared by first boot and live rebuild; both call `prepare_graph` and
/// [`cross::bridge_edges`] first. Interrupts are masked throughout. Returns the
/// number of modules loaded.
pub fn instantiate(
    module_list: &[Option<ModuleEntry>],
    module_count: usize,
) -> Result<usize, InstantiateError> {
    let guard = crate::kernel::sys::guard::KernelGuard::acquire();

    // Ownership must be live before any provider handle is opened (see
    // `bare_metal::apply_owner_plan`).
    crate::kernel::exec::bare_metal::apply_owner_plan().map_err(InstantiateError::OwnerPlan)?;

    // SAFETY: the scheduler's thread, during instantiation.
    let (loader_ref, sched) = unsafe { (scheduler::static_loader(), scheduler::sched_mut()) };
    let budget = crate::kernel::exec::bare_metal::PendingBudget::default();
    let mut loaded = 0usize;
    let mut failed = 0usize;
    for (index, slot) in module_list.iter().enumerate().take(module_count) {
        let Some(entry) = slot else { continue };
        if entry.domain_id as usize >= MAX_DOMAINS {
            log::error!("[inst] module {index} names domain {}", entry.domain_id);
            failed += 1;
            continue;
        }
        scheduler::set_current_module(index);
        match scheduler::instantiate_one_module(
            loader_ref,
            entry,
            index,
            index,
            &mut sched.edges,
            &mut sched.modules,
            &mut sched.ports,
        ) {
            scheduler::InstantiateResult::Done => loaded += 1,
            scheduler::InstantiateResult::Pending(mut pending) => {
                let mut polls = 0u32;
                loop {
                    // SAFETY: allocated by the call above; polled here until done.
                    match unsafe { pending.try_complete() } {
                        Ok(Some(module)) => {
                            scheduler::store_dynamic_module(index, module);
                            loaded += 1;
                            break;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            e.log("module");
                            failed += 1;
                            break;
                        }
                    }
                    polls += 1;
                    if budget.exhausted(polls) {
                        log::error!("[inst] module {index} pending timeout");
                        failed += 1;
                        break;
                    }
                    wait_ms(1);
                }
            }
            scheduler::InstantiateResult::Error(e) => {
                log::error!("[inst] module {index} failed rc={e}");
                failed += 1;
            }
        }
    }
    scheduler::set_active_module_count(module_count);
    // SAFETY: a read of the installed config, on the scheduler's thread.
    let cfg = unsafe { scheduler::static_config() };
    scheduler::log_dma_owned_edges_from_config(&cfg.graph_edges);

    // The modules of a polled-timer ISR domain go to the ISR-tier dispatcher.
    let isr_registered = scheduler::register_isr_tier_modules_from_graph();
    if isr_registered > 0 {
        log::info!("[isr] Tier 1b admitted {isr_registered} module(s)");
    }

    for (d, count) in MODULE_COUNT.iter().enumerate() {
        let n = scheduler::domain_module_count(d);
        count.store(n as u32, Ordering::Release);
        if n == 0 {
            continue;
        }
        let mut order = [0u16; 32];
        let shown = n.min(order.len());
        for (k, slot) in order.iter_mut().enumerate().take(shown) {
            *slot = scheduler::domain_exec_order_at(d, k).unwrap_or(usize::MAX) as u16;
        }
        log::info!("[domain] {d}: {n} modules, order: {:?}", &order[..shown]);
    }
    drop(guard);

    // A module that did not instantiate leaves its ports unwired, so the graph
    // that would run is not the graph that was asked for.
    if failed > 0 && crate::kernel::exec::bare_metal::instantiation_is_fail_closed() {
        return Err(InstantiateError::Modules(failed));
    }
    // Before the first step: clear the state arena's zeroed frontier its full
    // distance ahead, so the first heap growth on a step finds zeroed memory.
    crate::kernel::module::loader::prime_frontier();
    Ok(loaded)
}

fn wait_ms(ms: u64) {
    let until = timer::read_timer_count_64() + ms * timer::timer_freq() / 1000;
    while timer::read_timer_count_64() < until {
        core::hint::spin_loop();
    }
}

// ============================================================================
// Quiesce
// ============================================================================
//
// The primary parks every other domain's core at its pass boundary, outside
// any step, while it changes global scheduler state (a graph rebuild, a live
// add or removal), and releases them after.
//
// A quiesce is a generation: `QUIESCE_GEN` is odd while one is in flight, and
// each request and each release advances it. A core parks by recording the
// generation it parked in (`PARKED_IN`) and waits for the generation to move.
// The primary waits for every core that has entered its loop (`IN_LOOP`) to
// record the current generation. Recording the generation, not a count, keeps
// a core that is still leaving one quiesce from being taken as parked in the
// next. A core enters its loop by setting its `IN_LOOP` bit and then reading
// the generation, and the primary requests by advancing the generation and
// then reading `IN_LOOP`, all sequentially consistent: either the primary
// waits for that core, or the core sees the request and parks anyway.
//
// The primary domain never parks.

/// Bit `d` set once domain `d`'s core has entered its loop, which it never
/// leaves.
static IN_LOOP: AtomicU32 = AtomicU32::new(0);
/// Odd while a quiesce is in flight.
static QUIESCE_GEN: AtomicU32 = AtomicU32::new(0);
/// The generation each domain's core last parked in (0, which is even, before
/// its first).
static PARKED_IN: [AtomicU32; MAX_DOMAINS] = [const { AtomicU32::new(0) }; MAX_DOMAINS];

/// Primary-only. Ask every other domain's core to park at its next pass
/// boundary. Paired with [`release_quiesce`].
pub fn request_quiesce() {
    QUIESCE_GEN.fetch_add(1, Ordering::SeqCst);
    // SAFETY: DMB + SEV are architectural hints; no memory effects.
    unsafe { core::arch::asm!("dmb ish", "sev", options(nostack)) };
}

/// Pass-boundary hook: a no-op on the primary domain and when no quiesce is
/// in flight; otherwise the core records the generation and waits in WFE
/// until [`release_quiesce`] advances it.
fn park_if_requested(domain_id: usize) {
    if domain_id == 0 {
        return;
    }
    let generation = QUIESCE_GEN.load(Ordering::SeqCst);
    if generation & 1 == 0 {
        return;
    }
    PARKED_IN[domain_id].store(generation, Ordering::Release);
    while QUIESCE_GEN.load(Ordering::Acquire) == generation {
        // SAFETY: WFE is a hint to wait until the next event.
        unsafe { core::arch::asm!("wfe", options(nostack)) };
    }
}

/// Primary-only, after [`request_quiesce`]: spin until every other domain's
/// core in its loop has parked.
pub fn wait_parked() {
    let generation = QUIESCE_GEN.load(Ordering::Relaxed);
    loop {
        let in_loop = IN_LOOP.load(Ordering::SeqCst);
        let parked = (1..MAX_DOMAINS)
            .filter(|&d| in_loop & (1 << d) != 0)
            .all(|d| PARKED_IN[d].load(Ordering::Acquire) == generation);
        if parked {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Primary-only. Release the parked cores. Pairs with [`request_quiesce`].
pub fn release_quiesce() {
    QUIESCE_GEN.fetch_add(1, Ordering::SeqCst);
    // SAFETY: DMB + SEV are architectural hints; no memory effects.
    unsafe { core::arch::asm!("dmb ish", "sev", options(nostack)) };
}

/// Park every other domain for a structural change (the `HalOps` seam):
/// `false`, and nothing parked, before [`release`], when no other core runs.
pub fn quiesce_peers() -> bool {
    if !released() {
        return false;
    }
    request_quiesce();
    wait_parked();
    true
}

// ============================================================================
// Live rebuild
// ============================================================================

/// Serve a pending live rebuild, on the primary domain. Called from every
/// domain loop so the rebuild runs whatever the primary's tier. No-op off
/// domain 0.
///
/// On a pending request: quiesce the other domains, reload the config and
/// rebuild the graph in place, bridges included. The old graph is gone once
/// `prepare_graph` starts; a rebuild that cannot finish leaves the graph idle,
/// never partly built. A parked loop resumes in the tier it was entered in
/// and re-reads the module tables each pass, but not its exec mode, so a
/// graph that moves a domain to another tier needs a reboot.
fn poll_rebuild(domain_id: usize, platform: &Platform) {
    if domain_id != 0 {
        return;
    }

    // Test hook (feature `test-plan`): once, well after netconsole bring-up,
    // report the owner-table occupancy. The boot `apply_staged()` installs the
    // embedded plan's owner before the net is up (so its own log predates the
    // netconsole); this late report makes that boot-applied ownership observable
    // over the netconsole. Expect "active workloads = 1".
    #[cfg(feature = "test-plan")]
    {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        let t = exception::CORE_TICKS[0].load(Ordering::Relaxed);
        if t >= 180_000 && !REPORTED.swap(true, Ordering::Relaxed) {
            let n = scheduler::owners().active_workload_count();
            log::info!("[test] owner table active workloads = {n}");
        }
    }

    // Test hook (feature `test-rebuild`): one-shot rebuild after a fixed number
    // of timer ticks (~47 s at 9.5 kHz: long past DHCP and netconsole bring-up)
    // so the bridge can be observed on hardware. Absent from normal builds.
    #[cfg(feature = "test-rebuild")]
    {
        static FIRED: AtomicBool = AtomicBool::new(false);
        let t = exception::CORE_TICKS[0].load(Ordering::Relaxed);
        if t >= 450_000 && !FIRED.swap(true, Ordering::Relaxed) {
            log::warn!("[test] one-shot rebuild trigger at tick {t}");
            // SAFETY: null/0 = reload current STATIC_CONFIG sentinel.
            unsafe { scheduler::request_rebuild(core::ptr::null(), 0) };
        }
    }

    if scheduler::take_rebuild_request().is_none() {
        return;
    }
    request_quiesce();
    wait_parked();
    log::warn!("[reconfigure] other domains parked; rebuilding");
    // The bridges are reset so `cross::bridge_edges` registers from a clean
    // table, as at boot; `prepare_graph` reopens the channels they join.
    // SAFETY: every other domain is parked; a parked core neither walks the
    // edge table nor touches a ring.
    unsafe { cross::reset_cross_state() };
    match rebuild(platform) {
        Ok((n, bridges)) => {
            let domains = (0..MAX_DOMAINS).filter(|&d| is_active(d)).count();
            log::warn!(
                "[reconfigure] rebuilt graph: {n} modules, {domains} domain(s), \
                 {bridges} cross-domain bridge(s)"
            );
        }
        Err(why) => {
            scheduler::hold_idle();
            log::error!("[reconfigure] {why}; graph left idle");
        }
    }
    scheduler::set_reconfigure_phase(scheduler::ReconfigurePhase::Running);
    release_quiesce();
}

/// Prepare, bridge and instantiate the installed config, with every other
/// domain parked: `(modules loaded, bridges)`, or why it could not.
fn rebuild(platform: &Platform) -> Result<(usize, usize), &'static str> {
    let (module_list, module_count) =
        scheduler::prepare_graph().map_err(|_| "graph preparation failed")?;
    let bridges = cross::bridge_edges()?;
    let loaded = instantiate(&module_list, module_count).map_err(|why| match why {
        InstantiateError::OwnerPlan(_) => "the staged owner plan is invalid",
        InstantiateError::Modules(_) => "modules failed to instantiate",
    })?;
    if coreless_domain(platform).is_some() {
        return Err("a domain with modules has no core to run it");
    }
    // As at boot: owner accounting and the contract-readiness gate.
    scheduler::finalize_instantiation_accounting();
    Ok((loaded, bridges))
}

// ============================================================================
// Pacing
// ============================================================================

/// Per-domain loop metrics, read and written only by the core running that
/// domain's loop.
struct DomainMetrics {
    /// High-rate: passes whose step work exceeded half the tick.
    slow_passes: u32,
    /// Poll mode: passes.
    poll_steps: u32,
    /// Poll mode: passes in which no module burst.
    poll_idle: u32,
    /// Poll mode: WFE count.
    wfe_count: u32,
    /// Worst pass duration in counter ticks (for deadline margin).
    worst_step_ticks: u32,
}

impl DomainMetrics {
    const fn new() -> Self {
        Self {
            slow_passes: 0,
            poll_steps: 0,
            poll_idle: 0,
            wfe_count: 0,
            worst_step_ticks: 0,
        }
    }
}

static mut DOMAIN_METRICS: [DomainMetrics; MAX_DOMAINS] =
    [const { DomainMetrics::new() }; MAX_DOMAINS];

/// Passes each domain's loop has run (every tier but poll mode, which counts
/// its own); read from any core.
static PASSES: [AtomicU32; MAX_DOMAINS] = [const { AtomicU32::new(0) }; MAX_DOMAINS];

/// Domain `domain_id`'s pass count, for diagnostics on another core.
pub fn domain_ticks(domain_id: usize) -> u32 {
    PASSES
        .get(domain_id)
        .map_or(0, |p| p.load(Ordering::Relaxed))
}

/// Count a pass of domain `domain_id`'s loop: the count it now stands at.
fn count_pass(domain_id: usize) -> u32 {
    PASSES[domain_id]
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1)
}

/// Counter ticks each domain's core spent in its passes, from waking to the
/// end of the pass (cooperative and high-rate loops), so a reader can tell a
/// core that is saturated from one that is waiting.
static BUSY_TICKS: [AtomicU64; MAX_DOMAINS] = [const { AtomicU64::new(0) }; MAX_DOMAINS];

/// Counter ticks domain `domain_id`'s core has spent in its passes since boot.
pub fn busy_ticks(domain_id: usize) -> u64 {
    BUSY_TICKS
        .get(domain_id)
        .map_or(0, |b| b.load(Ordering::Relaxed))
}

fn count_busy(domain_id: usize, since: u64) {
    BUSY_TICKS[domain_id].fetch_add(
        timer::read_timer_count_64().wrapping_sub(since),
        Ordering::Relaxed,
    );
}

/// This core's interrupt count, read before a pass so [`await_tick`] can tell
/// whether an interrupt was taken during it.
fn core_interrupts(core_id: usize) -> u32 {
    exception::CORE_INTERRUPTS[core_id.min(exception::MAX_CORES - 1)].load(Ordering::Relaxed)
}

/// Sleep until the interrupt the next pass answers. An interrupt taken DURING
/// a pass is already handled when the pass ends, so the WFI that follows
/// would not return for it: a tick that fired mid-pass (a pass longer than
/// the period) would lose its pass and idle the core for a whole period with
/// work queued, and a device interrupt would leave the data it announced
/// until the next tick. Either way the next pass runs at once instead. A
/// pass therefore follows only an interrupt, so a loaded domain runs back to
/// back and an idle one still sleeps.
fn await_tick(core_id: usize, interrupts_before_pass: u32) {
    if core_interrupts(core_id) == interrupts_before_pass {
        // SAFETY: WFI halts the core until the next interrupt; hint-only.
        unsafe { core::arch::asm!("wfi") };
    }
}

/// The software-wake latency bound on an adaptive domain's relaxed deadline.
///
/// The cooperative loop idles on WFI, broken only by an interrupt. A device
/// interrupt breaks it at once, but a cross-domain or software wake only sets
/// `EVENT_WAKE_PENDING`; it raises no interrupt unless the platform's
/// `wake_scheduler` sends a wake SGI, so it may wait for the next timer fire.
/// Clamping a relaxed deadline bounds that wait. The clamp only bites when the
/// pacer relaxes past it (an idle domain widening toward `tick_max_us`); busy
/// passes return at most the nominal tick, and fixed-tick domains are never
/// clamped. It trades idle wakeups against worst-case software-wake latency.
const IDLE_DEADLINE_CLAMP_US: u32 = 4_000;

/// Most-relaxed deadline (µs) domain 0 armed since the last
/// [`take_domain0_max_deadline_us`]: a sampling-robust witness that the pacer
/// reached a relaxed cadence, where a point sample taken on a busy reporting
/// pass reads low.
static DOMAIN0_MAX_DEADLINE_US: AtomicU32 = AtomicU32::new(0);

/// Read and reset [`DOMAIN0_MAX_DEADLINE_US`].
pub fn take_domain0_max_deadline_us() -> u32 {
    DOMAIN0_MAX_DEADLINE_US.swap(0, Ordering::Relaxed)
}

/// The next deadline (µs) each domain's last step chose (the resident-graph
/// merge, or the single-graph pacer); written by [`domain_step_all`] before
/// [`arm_next_deadline`] reads it in the same pass.
static DOMAIN_RUNNER_DEADLINE_US: [AtomicU32; MAX_DOMAINS] =
    [const { AtomicU32::new(0) }; MAX_DOMAINS];

/// Arm this core's next deadline from the pass just finished: the pacer's
/// chosen period, converted to counter ticks, into this core's
/// `NEXT_DEADLINE_TICKS` slot, which the timer handler reloads on its next
/// fire (so the period takes effect one period later, acceptable for a cadence
/// pacer). A fixed domain (`adaptive_flags == 0`) gets its fixed
/// `domain_tick_us` back, so its cadence is a plain fixed tick.
fn arm_next_deadline(domain_id: usize, core_id: usize) {
    let raw_us = DOMAIN_RUNNER_DEADLINE_US[domain_id].load(Ordering::Relaxed);
    let next_us = if scheduler::domain_adaptive_flags(domain_id) != 0 {
        // The clamp must not undercut the pacer's floor (`max(tick_min_us,
        // worst_step × MARGIN)`): arming below it would run the domain faster
        // than its worst-step budget admits. A domain whose floor is above
        // the clamp gets its floor; its own cadence bounds its latency.
        let floor = scheduler::pacer_domain_floor_us(domain_id);
        raw_us.min(IDLE_DEADLINE_CLAMP_US.max(floor))
    } else {
        raw_us
    };
    if domain_id == 0 {
        DOMAIN0_MAX_DEADLINE_US.fetch_max(next_us, Ordering::Relaxed);
    }
    let slot = core_id.min(exception::NEXT_DEADLINE_TICKS.len() - 1);
    exception::NEXT_DEADLINE_TICKS[slot].store(us_to_ticks(next_us), Ordering::Relaxed);
}

// ============================================================================
// The run loop
// ============================================================================

/// Run domain `domain_id`'s loop on this core. Never returns. The primary
/// enters it for domain 0 once the graph is released; each secondary for its
/// own domain after [`released`].
pub fn run(domain_id: usize, platform: &'static Platform) -> ! {
    let tier = Tier::of(domain_id);
    let core_id = cpu::current_core_id() as usize;
    let metrics = |d: usize| {
        // SAFETY: domain `d`'s metrics are touched only by the core running
        // its loop, which is this one.
        unsafe { &mut (*core::ptr::addr_of_mut!(DOMAIN_METRICS))[d] }
    };
    if domain_id != 0 {
        // From here the primary's quiesce waits for this core to park.
        IN_LOOP.fetch_or(1 << domain_id, Ordering::SeqCst);
    }

    match tier {
        Tier::HighRate => {
            log::info!(
                "[domain] {} core={} tier=1a tick_us={}",
                domain_id,
                core_id,
                scheduler::domain_tick_us(domain_id)
            );
            let mut interrupts_before_pass = core_interrupts(core_id);
            loop {
                await_tick(core_id, interrupts_before_pass);
                park_if_requested(domain_id);
                let woke = timer::read_timer_count_64();
                interrupts_before_pass = core_interrupts(core_id);
                let t0 = timer::read_timer_count();
                domain_step_all(domain_id, platform);
                cross::pump(domain_id);
                let elapsed = timer::read_timer_count().wrapping_sub(t0);
                (platform.after_pass)(domain_id, core_id, tier);
                let passes = count_pass(domain_id);
                scheduler::maybe_emit_alive(u64::from(passes), Some(domain_id));
                poll_rebuild(domain_id, platform);
                let m = metrics(domain_id);
                if elapsed > m.worst_step_ticks {
                    m.worst_step_ticks = elapsed;
                }
                if elapsed > us_to_ticks(scheduler::domain_tick_us(domain_id)) / 2 {
                    m.slow_passes += 1;
                }
                // Every ~10 s at the domain's rate.
                let report_interval = 10_000_000 / scheduler::domain_tick_us(domain_id).max(1);
                if passes.is_multiple_of(report_interval.max(1)) {
                    log::info!(
                        "[tier1a] d={} ticks={} slow={} worst={}cyc",
                        domain_id,
                        passes,
                        m.slow_passes,
                        m.worst_step_ticks
                    );
                }
                arm_next_deadline(domain_id, core_id);
                count_busy(domain_id, woke);
            }
        }
        Tier::Poll => {
            log::info!("[domain] {domain_id} core={core_id} tier=3 poll-mode");
            loop {
                park_if_requested(domain_id);
                // SAFETY: this domain's modules, stepped on its own core.
                let sched = unsafe { scheduler::sched_mut() };
                let (_result, any_burst) =
                    scheduler::step_domain_modules_poll(&mut sched.modules, domain_id);
                cross::pump(domain_id);
                (platform.after_pass)(domain_id, core_id, tier);
                let m = metrics(domain_id);
                m.poll_steps += 1;
                scheduler::maybe_emit_alive(u64::from(m.poll_steps), Some(domain_id));
                poll_rebuild(domain_id, platform);
                let m = metrics(domain_id);
                if !any_burst {
                    m.poll_idle += 1;
                    m.wfe_count += 1;
                    // SAFETY: WFE halts the core until an event; hint-only.
                    unsafe { core::arch::asm!("wfe") };
                }
                // Every ~1M passes.
                if m.poll_steps & 0xFFFFF == 0 {
                    log::info!(
                        "[tier3] d={} polls={} idle={}% wfe={}",
                        domain_id,
                        m.poll_steps,
                        m.poll_idle * 100 / m.poll_steps.max(1),
                        m.wfe_count
                    );
                }
            }
        }
        // The domain's modules were handed to the ISR-tier dispatcher at
        // instantiation; the loop fires it when its period has elapsed and
        // still pumps, so a cooperative sibling can deliver work into it.
        Tier::PolledIsr => {
            log::info!(
                "[domain] {} core={} tier=1b period_us={}",
                domain_id,
                core_id,
                scheduler::domain_tick_us(domain_id)
            );
            loop {
                park_if_requested(domain_id);
                crate::kernel::exec::isr_tier::poll_tier1b();
                cross::pump(domain_id);
                (platform.after_pass)(domain_id, core_id, tier);
                // SAFETY: WFE halts the core until an event arrives; the poll
                // above is non-blocking.
                unsafe { core::arch::asm!("wfe") };
                let passes = count_pass(domain_id);
                scheduler::maybe_emit_alive(u64::from(passes), Some(domain_id));
                poll_rebuild(domain_id, platform);
                if passes.is_multiple_of(1_000_000) {
                    log::info!(
                        "[tier1b] d={} polls={} ticks={}",
                        domain_id,
                        passes,
                        crate::kernel::exec::isr_tier::tier1b_ticks(),
                    );
                }
            }
        }
        // Each module is bound to its interrupt at instantiation and runs from
        // it; the core stays in WFI to take that interrupt with least latency,
        // and between interrupts does what every domain core owes: pumping,
        // the rebuild bridge, parking for a reconfigure.
        Tier::IrqOwned => {
            log::info!("[domain] {domain_id} core={core_id} tier=2 irq-owned");
            loop {
                // SAFETY: WFI halts the core until its interrupt; the
                // trampoline runs in interrupt context.
                unsafe { core::arch::asm!("wfi") };
                park_if_requested(domain_id);
                cross::pump(domain_id);
                (platform.after_pass)(domain_id, core_id, tier);
                let passes = count_pass(domain_id);
                scheduler::maybe_emit_alive(u64::from(passes), Some(domain_id));
                poll_rebuild(domain_id, platform);
                if passes.is_multiple_of(1_000_000) {
                    log::info!(
                        "[tier2] d={domain_id} wakes={} irqs={}",
                        passes,
                        crate::kernel::exec::isr_tier::tier2_dispatch_count(),
                    );
                }
            }
        }
        Tier::Cooperative => {
            let mut interrupts_before_pass = core_interrupts(core_id);
            loop {
                await_tick(core_id, interrupts_before_pass);
                park_if_requested(domain_id);
                let woke = timer::read_timer_count_64();
                interrupts_before_pass = core_interrupts(core_id);
                let tick = exception::CORE_TICKS[core_id.min(exception::MAX_CORES - 1)]
                    .load(Ordering::Relaxed);
                // Tier-2 silicon validation: from core 0, periodically send SGI 15
                // to core 1, the interrupt its Tier-2 module owns. Build flag only.
                #[cfg(feature = "test_tier2_sgi")]
                if core_id == 0 && tick.is_multiple_of(2000) {
                    // SAFETY: a single write to the distributor mapped at boot.
                    unsafe { crate::arch::aarch64::gic::send_sgi(1, 15) };
                }
                domain_step_all(domain_id, platform);
                cross::pump(domain_id);
                // With no core of its own, a polled-timer ISR domain is fired from
                // here.
                crate::kernel::exec::isr_tier::poll_tier1b();
                (platform.after_pass)(domain_id, core_id, tier);
                count_pass(domain_id);
                scheduler::maybe_emit_alive(u64::from(tick), Some(domain_id));
                poll_rebuild(domain_id, platform);
                arm_next_deadline(domain_id, core_id);
                count_busy(domain_id, woke);
            }
        }
    }
}

/// Step every module of `domain_id` through the shared per-domain scheduler
/// path (the `step_one_module` body every platform uses), so period gating,
/// upstream-ready gating, `Done`, the fault state machine and `Burst` behave
/// as they do on every other platform. With more than one resident graph in
/// the domain, each owner steps independently and the merged deadline comes
/// back.
fn domain_step_all(domain_id: usize, platform: &Platform) {
    // SAFETY: this domain's modules, stepped on its own core.
    let sched = unsafe { scheduler::sched_mut() };
    let (_result, deadline_us) =
        scheduler::step_resident_graphs_domain(&mut sched.modules, domain_id);
    (platform.after_step)(domain_id);
    DOMAIN_RUNNER_DEADLINE_US[domain_id].store(deadline_us, Ordering::Relaxed);
}
