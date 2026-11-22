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
use crate::kernel::exec::irq;
use crate::kernel::exec::scheduler::{self, MAX_DOMAINS};
use fluxor_contracts::boot_config::ExecMode;

// ============================================================================
// The platform's part
// ============================================================================

/// What a platform does around the shared loop.
pub struct Platform {
    /// Whether a core runs domain `domain_id`'s loop once the domain has
    /// modules (domains 1 and up; the boot core runs domain 0).
    pub has_core: fn(domain_id: usize) -> bool,
    /// After each pass of a domain's loop, on the domain's core: the console
    /// drain, periodic reports, the uptime limit.
    pub after_pass: fn(domain_id: usize, core_id: usize, mode: ExecMode),
    /// After a `tick` domain has stepped its modules, on its core: work that
    /// must not race those steps.
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
    cpu::signal_cores();
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
/// (a domain `tick_us`) or slower than the global tick. The timer handler reloads from
/// this core's slot, so the rate survives the first interrupt. Returns the
/// period in counter ticks, for the platform to arm.
pub fn seed_core_tick(domain_id: usize) -> u32 {
    let ticks = timer::us_to_ticks(scheduler::domain_tick_us(domain_id));
    let slot = (cpu::current_core_id() as usize).min(exception::NEXT_DEADLINE_TICKS.len() - 1);
    exception::NEXT_DEADLINE_TICKS[slot].store(ticks, Ordering::Relaxed);
    ticks
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
    /// The graph was refused with this errno: a module did not instantiate,
    /// so the graph would run with unwired ports.
    Refused(i32),
}

/// Instantiate the graph `prepare_graph` staged (`scheduler::instantiate_graph`)
/// and record which domains run. Shared by first boot and live rebuild; both
/// call `prepare_graph` and [`cross::bridge_edges`] first. Interrupts are
/// masked throughout. Returns the number of modules.
pub fn instantiate(staged: scheduler::splice::StagedAdd) -> Result<usize, InstantiateError> {
    let guard = crate::kernel::sys::guard::KernelGuard::acquire();

    // Ownership must be live before any provider handle is opened (see
    // `bare_metal::apply_owner_plan`).
    if let Err(e) = crate::kernel::exec::bare_metal::apply_owner_plan() {
        scheduler::splice::abandon(staged);
        return Err(InstantiateError::OwnerPlan(e));
    }
    let loaded = scheduler::instantiate_graph(staged, &mut || wait_ms(1), &mut |_| {})
        .map_err(InstantiateError::Refused)?;

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
    cpu::signal_cores();
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
        cpu::wait_for_event();
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
    cpu::signal_cores();
}

/// Park every other domain for a structural change (the `HalOps` seam):
/// `false`, and nothing newly parked, before [`release`], when no other core
/// runs, and when the domains are already parked by an outer quiesce (a
/// rebuild), whose holder releases them.
pub fn quiesce_peers() -> bool {
    if !released() || QUIESCE_GEN.load(Ordering::SeqCst) & 1 == 1 {
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
/// domain loop so the rebuild runs whatever the primary's execution mode.
/// No-op off domain 0.
///
/// On a pending request: quiesce the other domains, reload the config and
/// rebuild the graph in place, bridges included. The old graph is gone once
/// `prepare_graph` starts; a rebuild that cannot finish leaves the graph idle,
/// never partly built. A parked loop resumes in the execution mode it was
/// entered in and re-reads the module tables each pass, but not its mode, so
/// a graph that moves a domain to another mode needs a reboot.
fn poll_rebuild(domain_id: usize, platform: &Platform) {
    if domain_id != 0 {
        return;
    }

    if !scheduler::take_rebuild_request() {
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
    let staged = scheduler::prepare_graph().map_err(|_| "graph preparation failed")?;
    let bridges = match cross::bridge_edges() {
        Ok(n) => n,
        Err(why) => {
            scheduler::splice::abandon(staged);
            return Err(why);
        }
    };
    let loaded = instantiate(staged).map_err(|why| match why {
        InstantiateError::OwnerPlan(_) => "the staged owner plan is invalid",
        InstantiateError::Refused(_) => "a module failed to instantiate",
    })?;
    if coreless_domain(platform).is_some() {
        return Err("a domain with modules has no core to run it");
    }
    scheduler::log_arena_usage();
    Ok((loaded, bridges))
}

// ============================================================================
// Pacing
// ============================================================================

/// Per-domain loop metrics, read and written only by the core running that
/// domain's loop.
struct DomainMetrics {
    /// Tick mode: passes whose step work exceeded half the domain's tick.
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

/// Counter ticks each domain's core spent in its passes, from waking to the
/// end of the pass (the `tick` loop), so a reader can tell a
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
        cpu::wait_for_interrupt();
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

/// The next deadline (µs) each domain's last tick pass chose (the resident-graph
/// merge, or the single-graph pacer); written by [`run_domain_passes`] before
/// [`arm_next_deadline`] reads it in the same pass.
static DOMAIN_LOOP_DEADLINE_US: [AtomicU32; MAX_DOMAINS] =
    [const { AtomicU32::new(0) }; MAX_DOMAINS];

/// Arm this core's next deadline from the pass just finished: the pacer's
/// chosen period, converted to counter ticks, into this core's
/// `NEXT_DEADLINE_TICKS` slot, which the timer handler reloads on its next
/// fire (so the period takes effect one period later, acceptable for a cadence
/// pacer). A fixed domain (`adaptive_flags == 0`) gets its fixed
/// `domain_tick_us` back, so its cadence is a plain fixed tick.
fn arm_next_deadline(domain_id: usize, core_id: usize) {
    let raw_us = DOMAIN_LOOP_DEADLINE_US[domain_id].load(Ordering::Relaxed);
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
    exception::NEXT_DEADLINE_TICKS[slot].store(timer::us_to_ticks(next_us), Ordering::Relaxed);
}

// ============================================================================
// The run loop
// ============================================================================

/// Run domain `domain_id`'s loop on this core. Never returns. The primary
/// enters it for domain 0 once the graph is released; each secondary for its
/// own domain after [`released`].
pub fn run(domain_id: usize, platform: &'static Platform) -> ! {
    let mode = scheduler::domain_exec_mode(domain_id);
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

    match mode {
        ExecMode::Tick => {
            log::info!(
                "[domain] {} core={} exec=tick tick_us={}",
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
                run_domain_passes(domain_id, platform);
                cross::pump(domain_id);
                let elapsed = timer::read_timer_count().wrapping_sub(t0);
                // With no core of its own, a polled `timer` domain is fired
                // from here.
                crate::kernel::exec::timer::poll();
                (platform.after_pass)(domain_id, core_id, mode);
                let passes = scheduler::pass_count(domain_id);
                scheduler::maybe_emit_alive(u64::from(passes), Some(domain_id));
                poll_rebuild(domain_id, platform);
                let tick_us = scheduler::domain_tick_us(domain_id);
                let m = metrics(domain_id);
                if elapsed > m.worst_step_ticks {
                    m.worst_step_ticks = elapsed;
                }
                if elapsed > timer::us_to_ticks(tick_us) / 2 {
                    m.slow_passes += 1;
                }
                // Every ~10 s at the domain's rate.
                let report_interval = 10_000_000 / tick_us.max(1);
                if passes.is_multiple_of(report_interval.max(1)) {
                    log::info!(
                        "[tick] d={} passes={} slow={} worst={}cyc",
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
        ExecMode::Poll => {
            log::info!("[domain] {domain_id} core={core_id} exec=poll");
            loop {
                park_if_requested(domain_id);
                let any_burst = scheduler::pass::run(domain_id, scheduler::PassKind::Tick).burst;
                cross::pump(domain_id);
                (platform.after_pass)(domain_id, core_id, mode);
                let m = metrics(domain_id);
                m.poll_steps += 1;
                scheduler::maybe_emit_alive(u64::from(m.poll_steps), Some(domain_id));
                poll_rebuild(domain_id, platform);
                let m = metrics(domain_id);
                if !any_burst {
                    m.poll_idle += 1;
                    m.wfe_count += 1;
                    cpu::wait_for_event();
                }
                // Every ~1M passes.
                if m.poll_steps & 0xFFFFF == 0 {
                    log::info!(
                        "[poll] d={} passes={} idle={}% wfe={}",
                        domain_id,
                        m.poll_steps,
                        m.poll_idle * 100 / m.poll_steps.max(1),
                        m.wfe_count
                    );
                }
            }
        }
        // The domain's modules were handed to the `timer` dispatcher at
        // instantiation; the loop fires it when its period has elapsed and
        // still pumps, so a cooperative sibling can deliver work into it.
        ExecMode::Timer => {
            log::info!(
                "[domain] {} core={} exec=timer period_us={}",
                domain_id,
                core_id,
                scheduler::domain_tick_us(domain_id)
            );
            loop {
                park_if_requested(domain_id);
                crate::kernel::exec::timer::poll();
                // The domain's pass: the faults its modules latched.
                let _ = scheduler::pass::run(domain_id, scheduler::PassKind::Tick);
                cross::pump(domain_id);
                (platform.after_pass)(domain_id, core_id, mode);
                // The poll above is non-blocking.
                cpu::wait_for_event();
                let passes = scheduler::pass_count(domain_id);
                scheduler::maybe_emit_alive(u64::from(passes), Some(domain_id));
                poll_rebuild(domain_id, platform);
                if passes.is_multiple_of(1_000_000) {
                    log::info!(
                        "[timer] d={} passes={} ticks={}",
                        domain_id,
                        passes,
                        crate::kernel::exec::timer::ticks(),
                    );
                }
            }
        }
        // Each module is bound to its interrupt at instantiation and runs from
        // it; the core stays in WFI to take that interrupt with least latency,
        // and between interrupts does what every domain core owes: pumping,
        // the rebuild bridge, parking for a reconfigure.
        ExecMode::Irq => {
            log::info!("[domain] {domain_id} core={core_id} exec=irq");
            loop {
                // The trampoline runs in interrupt context.
                cpu::wait_for_interrupt();
                park_if_requested(domain_id);
                // The domain's pass: the faults its modules latched.
                let _ = scheduler::pass::run(domain_id, scheduler::PassKind::Tick);
                cross::pump(domain_id);
                (platform.after_pass)(domain_id, core_id, mode);
                let passes = scheduler::pass_count(domain_id);
                scheduler::maybe_emit_alive(u64::from(passes), Some(domain_id));
                poll_rebuild(domain_id, platform);
                if passes.is_multiple_of(1_000_000) {
                    log::info!(
                        "[irq] d={domain_id} wakes={} irqs={}",
                        passes,
                        irq::dispatch_count(),
                    );
                }
            }
        }
    }
}

/// Run `domain_id`'s tick pass (`pass::run`), then its latched wakes, and
/// publish the pass's deadline for the core's timer.
fn run_domain_passes(domain_id: usize, platform: &Platform) {
    let pass = scheduler::pass::run(domain_id, scheduler::PassKind::Tick);
    let woken = scheduler::pass::take_domain_wakes(domain_id);
    if !woken.is_empty() {
        let _ = scheduler::pass::run(domain_id, scheduler::PassKind::Wake(&woken));
    }
    (platform.after_step)(domain_id);
    DOMAIN_LOOP_DEADLINE_US[domain_id].store(pass.deadline_us, Ordering::Relaxed);
}
