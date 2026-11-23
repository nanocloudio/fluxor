//! The shared domain loop of a kernel that runs domains on more than one
//! core: the platform seam, which domains run, instantiation, the quiesce
//! entry points, the live rebuild, pacing and the loop itself.

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};
use portable_atomic::AtomicU64;

use super::quiesce::{self, STEP, STRUCTURAL};
use super::{core_domains, cross, domain_core};
use crate::kernel::exec::irq;
use crate::kernel::exec::scheduler::{self, MAX_DOMAINS};
use fluxor_contracts::boot_config::ExecMode;

// ============================================================================
// The platform's part
// ============================================================================

/// What a platform supplies to the shared loop: how its cores wait, wake and
/// park, and what it does around a pass.
pub struct Platform {
    /// The core this is called on.
    pub core_id: fn() -> usize,
    /// Make this core's earlier stores visible to the other cores and end
    /// every core's wait for an event.
    pub signal: fn(),
    /// Wait for an event: a [`Platform::signal`], an interrupt taken on this
    /// core, or nothing at all. The caller re-checks what it waits for.
    pub wait_event: fn(),
    /// Wait for an interrupt taken on this core. May return early.
    pub wait_interrupt: fn(),
    /// Park this core for a quiesce (see [`quiesce::ParkWait`]).
    pub park: quiesce::ParkWait,
    /// A free-running counter, for durations.
    pub counter: fn() -> u64,
    /// Microseconds as ticks of [`Platform::counter`].
    pub us_to_ticks: fn(us: u32) -> u32,
    /// Interrupts core `core_id` has taken, read on that core: [`run`] tells
    /// from it whether one arrived during a pass.
    pub interrupts: fn(core_id: usize) -> u32,
    /// Set the period of core `core_id`'s tick, on that core: the interrupt
    /// a `tick` domain's loop waits for.
    pub set_tick: fn(core_id: usize, period_us: u32),
    /// Whether a core runs domain `domain_id`'s loop once the domain has
    /// modules (domains 1 and up; the boot core runs domain 0).
    pub has_core: fn(domain_id: usize) -> bool,
    /// After each pass of a domain's loop, on the domain's core, with the
    /// passes the loop has made: the console drain, periodic reports, the
    /// uptime limit, and on the core that runs domain 0 from this loop,
    /// [`primary_upkeep`].
    pub after_pass: fn(domain_id: usize, core_id: usize, mode: ExecMode, passes: u32),
    /// After a `tick` domain has stepped its modules, on its core: work that
    /// must not race those steps.
    pub after_step: fn(domain_id: usize),
}

/// The platform [`install`] named; null before it.
static PLATFORM: AtomicPtr<Platform> = AtomicPtr::new(core::ptr::null_mut());

/// Name the platform the shared loop runs on. Primary-only, at boot, before
/// any other function here.
pub fn install(platform: &'static Platform) {
    PLATFORM.store(
        platform as *const Platform as *mut Platform,
        Ordering::Release,
    );
}

fn platform() -> Option<&'static Platform> {
    // SAFETY: null or the `&'static Platform` `install` stored.
    unsafe { PLATFORM.load(Ordering::Acquire).as_ref() }
}

/// End every core's wait for an event (the platform's `signal`).
pub fn signal() {
    if let Some(p) = platform() {
        (p.signal)();
    }
}

/// The core this is called on; 0 before [`install`].
pub fn core_id() -> usize {
    platform().map_or(0, |p| (p.core_id)())
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

/// Whether domain `domain_id` has modules, so its core's loop passes over it.
pub fn is_active(domain_id: usize) -> bool {
    domain_id < MAX_DOMAINS && MODULE_COUNT[domain_id].load(Ordering::Acquire) != 0
}

/// The highest domain with modules, plus one.
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
    signal();
}

/// True once [`release`] has run.
pub fn released() -> bool {
    RELEASED.load(Ordering::Acquire)
}

/// The first domain with modules that no core of `platform` runs: its
/// modules would never step, so a graph that has one is refused. A domain
/// the target maps to core 0 runs on the boot core's loop.
pub fn coreless_domain(platform: &Platform) -> Option<usize> {
    (1..MAX_DOMAINS).find(|&d| is_active(d) && domain_core(d) != 0 && !(platform.has_core)(d))
}

/// Seed this core's tick at domain `domain_id`'s rate, which can be faster
/// (a domain `tick_us`) or slower than the global tick. The platform keeps
/// the period (`set_tick`), so the rate survives the first interrupt.
/// Returns the period in counter ticks, for the platform to arm.
pub fn seed_core_tick(domain_id: usize, platform: &Platform) -> u32 {
    let period_us = scheduler::domain_tick_us(domain_id);
    (platform.set_tick)((platform.core_id)(), period_us);
    (platform.us_to_ticks)(period_us)
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
pub fn instantiate(
    staged: scheduler::splice::StagedAdd,
    platform: &Platform,
) -> Result<usize, InstantiateError> {
    let guard = crate::kernel::sys::guard::KernelGuard::acquire();

    // Ownership must be live before any provider handle is opened (see
    // `bare_metal::apply_owner_plan`).
    if let Err(e) = crate::kernel::exec::bare_metal::apply_owner_plan() {
        scheduler::splice::abandon(staged);
        return Err(InstantiateError::OwnerPlan(e));
    }
    let loaded = scheduler::instantiate_graph(staged, &mut || wait_ms(1, platform), &mut |_| {})
        .map_err(InstantiateError::Refused)?;
    record_module_counts();
    drop(guard);

    // Before the first step: clear the state arena's zeroed frontier its full
    // distance ahead, so the first heap growth on a step finds zeroed memory.
    crate::kernel::module::loader::prime_frontier();
    Ok(loaded)
}

/// Record which domains the instantiated graph gave modules, and log each
/// one's order. Primary-only, after a graph is instantiated and before
/// [`release`] or the end of the quiesce it was rebuilt under.
pub fn record_module_counts() {
    for (d, count) in MODULE_COUNT.iter().enumerate() {
        let n = scheduler::domain_module_count(d);
        count.store(n as u32, Ordering::Release);
        if n == 0 {
            continue;
        }
        log::info!(
            "[domain] {d} core={}: {n} modules, order: {}",
            domain_core(d),
            Order {
                domain: d,
                shown: n.min(32)
            }
        );
    }
}

/// The first `shown` modules of a domain's order, as `[a, b, c]`.
struct Order {
    domain: usize,
    shown: usize,
}

impl core::fmt::Display for Order {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[")?;
        for k in 0..self.shown {
            let module = scheduler::domain_exec_order_at(self.domain, k).unwrap_or(usize::MAX);
            if k != 0 {
                f.write_str(", ")?;
            }
            write!(f, "{}", module as u16)?;
        }
        f.write_str("]")
    }
}

fn wait_ms(ms: u32, platform: &Platform) {
    let until = (platform.counter)() + u64::from((platform.us_to_ticks)(ms * 1000));
    while (platform.counter)() < until {
        core::hint::spin_loop();
    }
}

// ============================================================================
// Quiesce
// ============================================================================
//
// The primary parks every other core at its pass boundary, outside any step,
// while it changes global scheduler state (a graph rebuild, a live add or
// removal), and releases them after ([`quiesce::STRUCTURAL`]). A parked core
// parks every domain it runs. The protocol and its proof are in [`quiesce`].

/// Primary-only. Ask every other core to park at its next pass boundary.
/// Paired with [`release_quiesce`].
pub fn request_quiesce() {
    STRUCTURAL.request();
    signal();
}

/// Pass-boundary hook: a no-op on core 0 and when no quiesce is in flight;
/// otherwise the core parks until the quiesce is released. A step quiesce is
/// honoured here too, so a core whose domain has nothing to step still
/// parks for it.
fn park_if_requested(core_id: usize, platform: &Platform) {
    STRUCTURAL.park_if_requested(core_id, platform.park);
    STEP.park_if_requested(core_id, platform.park);
}

/// The primary's own pass boundary, for a platform whose core 0 runs a loop
/// of its own over its domains: pump the bridges of every domain core 0
/// runs.
pub fn pump_core(core_id: usize) {
    let mine = core_domains(core_id);
    for d in (0..MAX_DOMAINS).filter(|&d| mine & (1 << d) != 0 && is_active(d)) {
        cross::pump(d);
    }
}

/// Primary-only, after [`request_quiesce`]: spin until every other core in
/// its loop has parked.
pub fn wait_parked() {
    STRUCTURAL.wait_parked();
}

/// [`wait_parked`], calling `waiting` on every turn of the spin: for a
/// platform that must notice, while it waits, a core that will never park
/// (one that has stopped on a fault).
pub fn wait_parked_watching(mut waiting: impl FnMut()) {
    while !STRUCTURAL.all_parked() {
        waiting();
        core::hint::spin_loop();
    }
}

/// Primary-only. Release the parked cores. Pairs with [`request_quiesce`].
pub fn release_quiesce() {
    STRUCTURAL.release();
    signal();
}

/// Park every other core for a structural change (the `HalOps` seam):
/// `false`, and nothing newly parked, before [`release`], when no other core
/// runs, and when the cores are already parked by an outer quiesce (a
/// rebuild), whose holder releases them.
pub fn quiesce_peers() -> bool {
    quiesce_peers_watching(|| {})
}

/// [`quiesce_peers`], calling `waiting` on every turn of the wait (see
/// [`wait_parked_watching`]).
pub fn quiesce_peers_watching(waiting: impl FnMut()) -> bool {
    if !released() || STRUCTURAL.requested() {
        return false;
    }
    request_quiesce();
    wait_parked_watching(waiting);
    true
}

/// Whether core `core_id` has entered its domain loop.
pub fn in_loop(core_id: usize) -> bool {
    STRUCTURAL.in_loop(core_id)
}

/// Between two module steps, on any core: park if the primary has asked for
/// a step quiesce ([`quiesce::STEP`]). One atomic load when it has not.
#[inline]
pub fn step_boundary() {
    if !STEP.requested() {
        return;
    }
    if let Some(p) = platform() {
        STEP.park_if_requested((p.core_id)(), p.park);
    }
}

/// A core did not reach a park point before the wait for it gave up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotParked;

/// Primary-only. Park every other core between module steps, waiting until
/// `expired` gives up. `Ok(true)`: the cores are parked and the caller ends
/// with [`release_step_quiesce`]. `Ok(false)`: no other core is in a loop,
/// or every one is already parked by a structural quiesce in flight, and
/// there is nothing to release. `Err(NotParked)`: a core did not park in
/// time; the request is withdrawn.
pub fn step_quiesce(expired: impl FnMut() -> bool) -> Result<bool, NotParked> {
    if (1..quiesce::MAX_CORES)
        .filter(|&c| STRUCTURAL.in_loop(c))
        .all(|c| STRUCTURAL.parked(c))
    {
        return Ok(false);
    }
    STEP.request();
    signal();
    if STEP.wait_parked_until(expired) {
        Ok(true)
    } else {
        release_step_quiesce();
        Err(NotParked)
    }
}

/// Primary-only. Release the cores [`step_quiesce`] parked.
pub fn release_step_quiesce() {
    STEP.release();
    signal();
}

/// Step quiesces taken since boot, over every core.
pub fn step_parks() -> u32 {
    STEP.parks()
}

// ============================================================================
// Live rebuild
// ============================================================================

/// What the core that runs domain 0 from the shared loop owes after each of
/// that domain's passes, whatever its execution mode: the scheduler's
/// heartbeat line and a pending live rebuild. A platform whose boot core
/// runs [`run`] calls this from its `after_pass`; one whose boot core runs a
/// loop of its own serves both there.
pub fn primary_upkeep(domain_id: usize, passes: u32, platform: &Platform) {
    scheduler::maybe_emit_alive(u64::from(passes), Some(domain_id));
    poll_rebuild(domain_id, platform);
}

/// Serve a pending live rebuild, on the primary domain. No-op off domain 0.
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
    let loaded = instantiate(staged, platform).map_err(|why| match why {
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
        .map_or(0, |b| b.load(portable_atomic::Ordering::Relaxed))
}

fn count_busy(domain_id: usize, since: u64, platform: &Platform) {
    BUSY_TICKS[domain_id].fetch_add(
        (platform.counter)().wrapping_sub(since),
        portable_atomic::Ordering::Relaxed,
    );
}

/// Sleep until the interrupt the next pass answers. An interrupt taken DURING
/// a pass is already handled when the pass ends, so the WFI that follows
/// would not return for it: a tick that fired mid-pass (a pass longer than
/// the period) would lose its pass and idle the core for a whole period with
/// work queued, and a device interrupt would leave the data it announced
/// until the next tick. Either way the next pass runs at once instead. A
/// pass therefore follows only an interrupt, so a loaded domain runs back to
/// back and an idle one still sleeps.
fn await_tick(core_id: usize, interrupts_before_pass: u32, platform: &Platform) {
    if (platform.interrupts)(core_id) == interrupts_before_pass {
        (platform.wait_interrupt)();
    }
}

/// The software-wake latency bound on an adaptive domain's relaxed deadline.
///
/// The cooperative loop idles waiting for an interrupt. A device interrupt
/// ends the wait at once, but a cross-domain or software wake only sets
/// `EVENT_WAKE_PENDING`; it raises no interrupt unless the platform's
/// `wake_scheduler` sends one, so it may wait for the next timer fire.
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
/// chosen period becomes the core's tick period (`set_tick`), which the
/// platform's tick takes up on its next fire (so the period takes effect one
/// period later, acceptable for a cadence pacer). A fixed domain
/// (`adaptive_flags == 0`) gets its fixed `domain_tick_us` back, so its
/// cadence is a plain fixed tick.
fn arm_next_deadline(domain_id: usize, core_id: usize, platform: &Platform) {
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
    (platform.set_tick)(core_id, next_us);
}

// ============================================================================
// The run loop
// ============================================================================

/// Run domain `domain_id`'s loop on this core, the core the target maps the
/// domain to. Never returns. The primary enters it for domain 0 once the
/// graph is released; each secondary for its own domain after [`released`].
pub fn run(domain_id: usize, platform: &'static Platform) -> ! {
    let mode = scheduler::domain_exec_mode(domain_id);
    let core_id = (platform.core_id)();
    let metrics = |d: usize| {
        // SAFETY: domain `d`'s metrics are touched only by the core running
        // its loop, which is this one.
        unsafe { &mut (*core::ptr::addr_of_mut!(DOMAIN_METRICS))[d] }
    };
    // From here the primary's quiesces wait for this core to park.
    STRUCTURAL.enter_loop(core_id);
    STEP.enter_loop(core_id);

    match mode {
        ExecMode::Tick => {
            log::info!(
                "[domain] {} core={} exec=tick tick_us={}",
                domain_id,
                core_id,
                scheduler::domain_tick_us(domain_id)
            );
            let mut interrupts_before_pass = (platform.interrupts)(core_id);
            loop {
                await_tick(core_id, interrupts_before_pass, platform);
                park_if_requested(core_id, platform);
                let woke = (platform.counter)();
                interrupts_before_pass = (platform.interrupts)(core_id);
                run_domain_passes(domain_id, platform);
                cross::pump(domain_id);
                let elapsed = (platform.counter)().wrapping_sub(woke) as u32;
                // With no core of its own, a polled `timer` domain is fired
                // from here.
                crate::kernel::exec::timer::poll();
                let passes = scheduler::pass_count(domain_id);
                (platform.after_pass)(domain_id, core_id, mode, passes);
                let tick_us = scheduler::domain_tick_us(domain_id);
                let m = metrics(domain_id);
                if elapsed > m.worst_step_ticks {
                    m.worst_step_ticks = elapsed;
                }
                if elapsed > (platform.us_to_ticks)(tick_us) / 2 {
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
                arm_next_deadline(domain_id, core_id, platform);
                count_busy(domain_id, woke, platform);
            }
        }
        ExecMode::Poll => {
            log::info!("[domain] {domain_id} core={core_id} exec=poll");
            loop {
                park_if_requested(core_id, platform);
                let any_burst = scheduler::pass::run(domain_id, scheduler::PassKind::Tick).burst;
                cross::pump(domain_id);
                let m = metrics(domain_id);
                m.poll_steps += 1;
                (platform.after_pass)(domain_id, core_id, mode, m.poll_steps);
                let m = metrics(domain_id);
                if !any_burst {
                    m.poll_idle += 1;
                    m.wfe_count += 1;
                    (platform.wait_event)();
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
                park_if_requested(core_id, platform);
                crate::kernel::exec::timer::poll();
                // The domain's pass: the faults its modules latched.
                let _ = scheduler::pass::run(domain_id, scheduler::PassKind::Tick);
                cross::pump(domain_id);
                let passes = scheduler::pass_count(domain_id);
                (platform.after_pass)(domain_id, core_id, mode, passes);
                // The poll above is non-blocking.
                (platform.wait_event)();
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
                (platform.wait_interrupt)();
                park_if_requested(core_id, platform);
                // The domain's pass: the faults its modules latched.
                let _ = scheduler::pass::run(domain_id, scheduler::PassKind::Tick);
                cross::pump(domain_id);
                let passes = scheduler::pass_count(domain_id);
                (platform.after_pass)(domain_id, core_id, mode, passes);
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
