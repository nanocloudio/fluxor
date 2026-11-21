//! The pass engine: one function steps a domain's modules for one tick, and
//! the same function steps woken modules between ticks. Every platform loop
//! calls [`run`] (a single-core loop through [`tick_all`] and [`wake_all`]),
//! so a graph behaves the same whether it is the only resident graph or one
//! of many, admitted at boot or live, on any target.
//!
//! A tick pass ([`PassKind::Tick`]), in order:
//! 1. the pass count; the interrupt-mode fault latch; the drain ceiling;
//! 2. one walk building the active count and the not-ready and must-tick
//!    sets; the readiness starvation sweep (domain 0);
//! 3. the budget reset, the worst-step decay, the attribution reset;
//! 4. the pre-pass slot, once;
//! 5. each resident graph of the domain: its pause, its wakes, whether it is
//!    runnable, and the bounded multi-pass over the domain's order filtered
//!    to the graph;
//! 6. the post-tick flush, the bridge pump, the lend pump, the slack
//!    donation;
//! 7. the deadline merge over the graphs' pacers, bounded by the domain's
//!    armed timers.
//!
//! A wake pass ([`PassKind::Wake`]) is step 5 for the woken modules alone,
//! each once, with the domain's budget deferring what does not fit.
use super::*;
use fault::{self, FaultKind};

/// What a pass does: a full domain tick, or the woken modules in the mask.
#[derive(Clone, Copy)]
pub enum PassKind<'a> {
    Tick,
    Wake(&'a ModuleMask),
}

/// A pass's outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PassResult {
    /// `Done` once no module of the graph is active.
    pub result: StepResult,
    /// The domain's next sleep, µs (a tick pass; a wake pass returns the
    /// nominal tick).
    pub deadline_us: u32,
    /// A graph ended the pass with a module still bursting: work is pending
    /// (a poll-mode domain spins rather than waiting for an event).
    pub burst: bool,
}

/// Tick passes `domain` has run: the domain's clock for fault records and
/// monitor lines.
pub fn pass_count(domain: usize) -> u32 {
    if domain >= MAX_DOMAINS {
        return 0;
    }
    // SAFETY: an atomic read of the domain's own record.
    unsafe { (*core::ptr::addr_of!(SCHED)).domains[domain].passes() }
}

/// Take `domain`'s latched wake bits (never another domain's).
pub fn take_domain_wakes(domain: usize) -> ModuleMask {
    if domain >= MAX_DOMAINS {
        return ModuleMask::new();
    }
    // SAFETY: scheduler-thread read of this domain's mask.
    let mask = unsafe { (*core::ptr::addr_of!(SCHED)).domains[domain].module_mask };
    crate::kernel::ipc::event::take_wake_in_mask(&mask)
}

/// A single-core loop's tick: [`run`] over every domain, in order. The
/// result is `Done` only when every domain's is; the deadline is the
/// soonest.
pub fn tick_all() -> PassResult {
    let mut out = PassResult {
        result: StepResult::Done,
        deadline_us: u32::MAX,
        burst: false,
    };
    for d in 0..domain_count() {
        let r = run(d, PassKind::Tick);
        if r.result != StepResult::Done {
            out.result = r.result;
        }
        out.deadline_us = out.deadline_us.min(r.deadline_us);
        out.burst |= r.burst;
    }
    if out.deadline_us == u32::MAX {
        out.deadline_us = domain_tick_us(0);
    }
    out
}

/// A single-core loop's wake drain: each domain's latched wakes, stepped by
/// [`run`]. Returns whether any were taken.
pub fn wake_all() -> bool {
    let mut any = false;
    for d in 0..domain_count() {
        let woken = take_domain_wakes(d);
        if !woken.is_empty() {
            any = true;
            let _ = run(d, PassKind::Wake(&woken));
        }
    }
    any
}

/// Per-pass scratch threaded through the graph walk.
struct PassCtx {
    not_ready: ModuleMask,
    must_tick: ModuleMask,
    active_count: usize,
    overrun_logged: bool,
    deferred: u32,
}

/// Step `domain` once: a tick, or the woken modules.
pub fn run(domain: usize, kind: PassKind<'_>) -> PassResult {
    if domain >= MAX_DOMAINS {
        return PassResult {
            result: StepResult::Done,
            deadline_us: domain_tick_us(0),
            burst: false,
        };
    }
    // SAFETY: scheduler-thread context: this domain's loop is the sole
    // stepper of its modules (its own core on bcm2712).
    let sched = unsafe { &mut *core::ptr::addr_of_mut!(SCHED) };
    // SAFETY: as above; the module table is stepped through this view.
    let modules: &mut [ModuleSlot] = unsafe { &mut (*core::ptr::addr_of_mut!(SCHED)).modules };
    let nominal = domain_tick_us(domain);
    let idle = PassResult {
        result: StepResult::Done,
        deadline_us: nominal,
        burst: false,
    };
    if sched.prepare_in_progress {
        return idle;
    }
    let tick = matches!(kind, PassKind::Tick);
    let count = sched.active_module_count;

    // ── 1. Pass count, interrupt-mode faults, drain ceiling ─────────────
    if tick {
        sched.domains[domain]
            .pass_count
            .fetch_add(1, Ordering::Relaxed);
        if domain == 0 {
            // Lines whose `irq` module ended go on the primary.
            fault::retire_isr_lines();
        }
        if sched.domains[domain].exec_mode.is_interrupt() {
            // An interrupt-mode domain's modules run from their interrupt;
            // its pass owes only the faults they latched.
            let mut active = (0..count).filter(|&i| !sched.finished[i]).count();
            fault::drain_isr_faults(sched, modules, domain, &mut active);
            return PassResult {
                result: if active == 0 {
                    StepResult::Done
                } else {
                    StepResult::Continue
                },
                ..idle
            };
        }
        if fault::enforce_drain_timeout(sched, modules, count) {
            return idle;
        }
    } else if sched.domains[domain].exec_mode.is_interrupt() {
        return idle;
    }

    // ── 2. One walk: active, not-ready, must-tick ────────────────────────
    let mut cx = PassCtx {
        not_ready: ModuleMask::new(),
        must_tick: ModuleMask::new(),
        active_count: 0,
        overrun_logged: false,
        deferred: 0,
    };
    for i in 0..count {
        if !sched.ready[i] {
            cx.not_ready.set(i);
        }
        if sched.finished[i] {
            continue;
        }
        cx.active_count += 1;
        let initialising = sched.deferred_ready[i] && !sched.ready[i];
        let recovering = matches!(
            sched.fault_info[i].state,
            FaultState::Faulted | FaultState::Recovering
        );
        if initialising || recovering {
            cx.must_tick.set(i);
        }
    }

    // Busy reported by the pre-pass slot, credited to the graphs owning it.
    let mut pre_busy = false;
    if tick {
        if domain == 0 {
            readiness_starvation_sweep(sched, modules, count, &cx.not_ready);
        }
        // ── 3. Budget reset, worst-step decay, attribution reset ────────
        let ds = &mut sched.domains[domain];
        ds.budget_consumed_us = 0;
        let w = ds.worst_step_us;
        if w > 0 {
            ds.worst_step_us = w - (w >> WORST_STEP_DECAY_SHIFT).max(1);
        }
        for i in 0..count {
            if sched.domain_id[i] as usize == domain {
                sched.pass_module_us[i] = 0;
                sched.pass_module_steps[i] = 0;
            }
        }
        // ── 4. Pre-tick slot, once ───────────────────────────────────────
        let ds = &sched.domains[domain];
        ds.pacer_work.store(false, Ordering::Relaxed);
        ds.pacer_burst.store(false, Ordering::Relaxed);
        step_domain_pre_pass(modules, sched, domain, &cx.not_ready, &mut cx.active_count);
        let ds = &sched.domains[domain];
        pre_busy = ds.pacer_work.load(Ordering::Relaxed) || ds.pacer_burst.load(Ordering::Relaxed);
    }
    let mut pre_pass_mask = ModuleMask::new();
    if pre_busy {
        let ds = &sched.domains[domain];
        for &m in ds.pre_pass_order.iter().take(ds.pre_pass_count as usize) {
            pre_pass_mask.set(m as usize);
        }
    }

    // ── 5. Each resident graph of the domain ─────────────────────────────
    let bounds = pacer_bounds(domain);
    let idle_skip = (bounds.flags & ADAPTIVE_FLAG_IDLE) != 0;
    let now = crate::kernel::sys::hal::now_micros();
    let mut merge = DeadlineMerge::new();
    let mut pending_burst = false;

    for gi in 0..resident_graph_count() {
        // A snapshot of this domain's own entry: another domain's loop may
        // be writing its own.
        let Some(e) = resident_graph(gi) else {
            continue;
        };
        if e.domain as usize != domain {
            continue;
        }
        let paused = crate::kernel::ipc::event::paused_owners_present()
            && owner_graph_paused(sched, e.slot, e.generation);

        if let PassKind::Wake(sel) = kind {
            let mut woken = *sel;
            woken.and_assign(&e.mask);
            if woken.is_empty() {
                continue;
            }
            if paused {
                crate::kernel::ipc::event::defer_masked_wakes(&woken);
                continue;
            }
            let _ = step_graph(modules, sched, &mut cx, &e, domain, &woken, true);
            continue;
        }

        if paused {
            // Wakes that latched before the pause was visible go to the
            // deferred store, so they do not hold the domain out of idle.
            let stragglers = crate::kernel::ipc::event::take_wake_in_mask(&e.mask);
            crate::kernel::ipc::event::defer_masked_wakes(&stragglers);
            continue;
        }
        let mut woken = crate::kernel::ipc::event::take_wake_in_mask(&e.mask);
        let wake = !woken.is_empty();
        let is_system = e.slot == 0;

        // The graph's periodic modules: any due now, and the soonest not.
        let mut any_due = false;
        let mut min_due_us = u32::MAX;
        for idx in e.periodic_mask.iter_set() {
            let nd = sched.module_next_due_us[idx];
            if nd == 0 || now >= nd {
                any_due = true;
            } else {
                min_due_us = min_due_us
                    .min(nd.saturating_sub(now).min(u64::from(bounds.tick_max_us)) as u32);
            }
        }

        let prior_runnable = graph_pacer_runnable(e.slot, e.generation, domain as u8);
        let must_tick = e.mask.intersects(&cx.must_tick);
        let backstop_due = !is_system
            && !e.idle_safe
            && (e.backstop_next_due_us == 0 || now >= e.backstop_next_due_us);
        let base_runnable = is_system
            || !idle_skip
            || !e.primed
            || prior_runnable
            || wake
            || any_due
            || must_tick
            || backstop_due;
        // An otherwise-idle graph with readable bytes on an inbound edge from
        // another graph is runnable now, its consumers stepped as woken.
        let mut inbound = ModuleMask::new();
        let inbound_ready = !base_runnable && graph_inbound_readable(sched, &e.mask, &mut inbound);
        if inbound_ready {
            log::debug!(
                "MON_GRAPH_INBOUND slot={} gen={} domain={domain}",
                e.slot,
                e.generation
            );
            woken.or_assign(&inbound);
        }
        let runnable = base_runnable || inbound_ready;

        let mut backstop = e.backstop_next_due_us;
        let (mut work, burst, last_burst) = if runnable {
            let r = step_graph(modules, sched, &mut cx, &e, domain, &woken, false);
            if !is_system && !e.idle_safe {
                backstop = now.wrapping_add(u64::from(bounds.tick_max_us));
            }
            mark_graph_stepped(gi, backstop);
            for idx in e.periodic_mask.iter_set() {
                let nd = sched.module_next_due_us[idx];
                if nd > now {
                    min_due_us = min_due_us
                        .min(nd.saturating_sub(now).min(u64::from(bounds.tick_max_us)) as u32);
                }
            }
            r
        } else {
            (false, false, false)
        };
        if pre_busy && e.mask.intersects(&pre_pass_mask) {
            work = true;
        }
        pending_burst |= last_burst;
        // A wake still latched after the walk keeps the graph busy.
        let wake_after = crate::kernel::ipc::event::wake_pending_in_mask(&e.mask);
        let wake_signal = wake || wake_after;
        graph_pacer_set_signals(e.slot, e.generation, domain as u8, work, burst, wake_signal);
        let busy = work || burst || wake_signal;
        log_pacer_line(gi, now, busy, runnable, e.slot, e.generation, domain);

        // ── 7 (per graph). Its pacer, its periodic, must-tick and
        // backstop terms.
        let d = graph_pacer_deadline(e.slot, e.generation, domain as u8, &bounds, now);
        merge.graph(d, busy);
        if min_due_us != u32::MAX {
            merge.runnable(min_due_us);
        }
        if must_tick {
            merge.runnable(bounds.nominal_us);
        }
        if !is_system && !e.idle_safe {
            merge.runnable(
                backstop
                    .saturating_sub(now)
                    .min(u64::from(bounds.tick_max_us)) as u32,
            );
        }
    }

    if !tick {
        let result = if cx.active_count == 0 {
            StepResult::Done
        } else {
            StepResult::Continue
        };
        if cx.deferred > 0 {
            if let Some(sup) = sched.domains[domain].mon_throttle(MonLine::WakeDefer) {
                log::info!(
                    "MON_WAKE_BUDGET_DEFER domain={domain} count={} suppressed={sup}",
                    cx.deferred
                );
            }
        }
        return PassResult {
            result,
            deadline_us: nominal,
            burst: pending_burst,
        };
    }

    // ── 6. Post-tick flush, bridge pump, lend pump, slack donation ────────
    step_domain_post_tick_flush(modules, sched, domain, &mut cx.active_count);
    if sched.bridge_count > 0 {
        pump_isr_bridges();
    }
    crate::kernel::ipc::lend::pump();
    let limit = u64::from(sched.domains[domain].budget_limit_us);
    if limit > 0 {
        crate::kernel::module::loader::zero_in_slack(
            limit.saturating_sub(sched.domains[domain].budget_consumed_us),
        );
    }

    // ── 7. Deadline merge, bounded by the domain's armed timers ───────────
    let deadline_us = settle_deadline(domain, merge.finish(&bounds), bounds.floor_us);
    PassResult {
        result: if cx.active_count == 0 {
            StepResult::Done
        } else {
            StepResult::Continue
        },
        deadline_us,
        burst: pending_burst,
    }
}

/// Step one resident graph's modules in `domain`: the domain's order rotated
/// by its offset, filtered to the graph. A tick (`wake_only == false`) runs
/// the bounded multi-pass; a wake pass steps the woken modules once,
/// deferring those the domain's budget cannot take. Returns the graph's
/// `(work, burst, burst in its last sub-pass)`.
fn step_graph(
    modules: &mut [ModuleSlot],
    sched: &mut SchedulerState,
    cx: &mut PassCtx,
    e: &ResidentGraph,
    domain: usize,
    woken: &ModuleMask,
    wake_only: bool,
) -> (bool, bool, bool) {
    {
        let ds = &sched.domains[domain];
        ds.pacer_work.store(false, Ordering::Relaxed);
        ds.pacer_burst.store(false, Ordering::Relaxed);
    }
    let count = sched.active_module_count;
    let n = sched.domains[domain].module_count as usize;
    let offset = if n > 0 && !wake_only {
        (sched.domains[domain].exec_offset as usize) % n
    } else {
        0
    };
    let mut tick_pass = 0u32;
    let mut last_burst;
    loop {
        sched.domains[domain]
            .burst_seen
            .store(false, Ordering::Relaxed);
        let pass_start_us = sched.domains[domain].budget_consumed_us;
        let mut hard_break = false;
        for i in 0..n {
            let pos = (i + offset) % n;
            let module_idx = sched.domain_exec_order[domain][pos] as usize;
            if module_idx >= count || !e.mask.test(module_idx) {
                continue;
            }
            let event_wake = woken.test(module_idx);
            if wake_only {
                if !event_wake {
                    continue;
                }
                if domain_budget_exhausted(sched, domain) {
                    crate::kernel::ipc::event::relatch_module_wake(module_idx);
                    cx.deferred += 1;
                    continue;
                }
            }
            step_one_module(
                modules,
                sched,
                module_idx,
                &cx.not_ready,
                &mut cx.active_count,
                event_wake,
            );
            if wake_only {
                continue;
            }
            let soft = domain_budget_exhausted(sched, domain);
            let hard = soft && domain_budget_hard_overrun(sched, domain);
            if soft && !cx.overrun_logged {
                record_domain_budget_overrun(sched, domain, module_idx);
                let ds = &mut sched.domains[domain];
                ds.exec_offset = ds.exec_offset.wrapping_add(1);
                cx.overrun_logged = true;
            }
            if hard {
                hard_break = true;
                break;
            }
        }
        last_burst = sched.domains[domain].burst_seen.load(Ordering::Relaxed);
        if wake_only {
            break;
        }
        tick_pass += 1;
        if hard_break || tick_pass >= MAX_PIPELINE_PASSES {
            break;
        }
        if !domain_budget_admits_repass(sched, domain, pass_start_us) {
            break;
        }
        // Device input that arrived during the pass: the node graph owns
        // the pre-pass slot's refill hooks.
        let refilled = e.slot == 0
            && step_domain_pipeline_refill(modules, sched, domain, &mut cx.active_count);
        if !last_burst && !refilled && !forced_pass_pending(tick_pass) {
            break;
        }
    }
    let ds = &sched.domains[domain];
    (
        ds.pacer_work.load(Ordering::Relaxed),
        ds.pacer_burst.load(Ordering::Relaxed),
        last_burst,
    )
}

/// Has `domain` consumed more than its budget in the current pass? A limit
/// of 0 disables the check.
#[inline]
pub(crate) fn domain_budget_exhausted(sched: &SchedulerState, domain_id: usize) -> bool {
    let Some(ds) = sched.domains.get(domain_id) else {
        return false;
    };
    let limit = u64::from(ds.budget_limit_us);
    limit != 0 && ds.budget_consumed_us > limit
}

/// Multiplier above the per-domain budget at which the pass breaks rather
/// than logging the overrun: runaway-loop protection. A soft overrun lets
/// the pass finish so downstream modules (the NIC drain) still tick.
const BUDGET_HARD_BREAK_MULTIPLIER: u64 = 10;

/// Max sub-passes over a graph within one tick. One sub-pass moves data one
/// hop along the order, so a request's return path (against the order)
/// would otherwise wait a tick per hop; re-running while a module bursts
/// lets a round trip finish in one tick. Idle ticks burst nothing and take
/// one sub-pass; the budget bounds the busy case.
pub(crate) const MAX_PIPELINE_PASSES: u32 = 12;

/// Whether `domain` can afford another sub-pass: one costs about what the
/// last did, and starting it with less left overruns by construction.
/// `pass_start_us` is the consumption when the last sub-pass began.
#[inline]
pub(crate) fn domain_budget_admits_repass(
    sched: &SchedulerState,
    domain_id: usize,
    pass_start_us: u64,
) -> bool {
    let Some(ds) = sched.domains.get(domain_id) else {
        return true;
    };
    let limit = u64::from(ds.budget_limit_us);
    if limit == 0 {
        return true;
    }
    let last_pass = ds.budget_consumed_us.saturating_sub(pass_start_us);
    ds.budget_consumed_us.saturating_add(last_pass) <= limit
}

#[inline]
pub(crate) fn domain_budget_hard_overrun(sched: &SchedulerState, domain_id: usize) -> bool {
    let Some(ds) = sched.domains.get(domain_id) else {
        return false;
    };
    let limit = u64::from(ds.budget_limit_us);
    limit != 0 && ds.budget_consumed_us > limit.saturating_mul(BUDGET_HARD_BREAK_MULTIPLIER)
}

/// Count a budget overrun and log `MON_BUDGET_OVERRUN`, naming the three
/// modules of the domain that consumed the most of the pass
/// (`index:µs/steps`) and the one whose step closed it.
pub(crate) fn record_domain_budget_overrun(
    sched: &mut SchedulerState,
    domain_id: usize,
    last_module_idx: usize,
) {
    let ds = &mut sched.domains[domain_id];
    ds.budget_overruns = ds.budget_overruns.saturating_add(1);
    let Some(sup) = ds.mon_throttle(MonLine::BudgetOverrun) else {
        return;
    };
    const TOP: usize = 3;
    let mut top = [(u32::MAX, 0u32, 0u16); TOP];
    for i in 0..module_slots() {
        let us = sched.pass_module_us[i];
        if us == 0 || sched.domain_id[i] as usize != domain_id {
            continue;
        }
        let entry = (i as u32, us, sched.pass_module_steps[i]);
        for slot in 0..TOP {
            if top[slot].0 == u32::MAX || us > top[slot].1 {
                top.copy_within(slot..TOP - 1, slot + 1);
                top[slot] = entry;
                break;
            }
        }
    }
    let cell = |t: (u32, u32, u16)| {
        if t.0 == u32::MAX {
            (0u32, 0u32, 0u16)
        } else {
            t
        }
    };
    let (a, b, c) = (cell(top[0]), cell(top[1]), cell(top[2]));
    let ds = &sched.domains[domain_id];
    log::warn!(
        "MON_BUDGET_OVERRUN domain={} consumed_us={} limit_us={} \
         last_mod={} top={}:{}/{},{}:{}/{},{}:{}/{} overrun_count={} tick={} suppressed={}",
        domain_id,
        ds.budget_consumed_us,
        ds.budget_limit_us,
        last_module_idx,
        a.0,
        a.1,
        a.2,
        b.0,
        b.1,
        b.2,
        c.0,
        c.1,
        c.2,
        ds.budget_overruns,
        ds.passes(),
        sup,
    );
}

/// Budget overruns of `domain_id` since boot.
pub fn domain_budget_overruns(domain_id: usize) -> u32 {
    // SAFETY: scheduler-thread read.
    unsafe { (*core::ptr::addr_of!(SCHED)).domains.get(domain_id) }.map_or(0, |d| d.budget_overruns)
}

/// Pre-tick budget overruns of `domain_id` since boot.
pub fn domain_pre_pass_overruns(domain_id: usize) -> u32 {
    // SAFETY: scheduler-thread read.
    unsafe { (*core::ptr::addr_of!(SCHED)).domains.get(domain_id) }
        .map_or(0, |d| d.pre_pass_overruns)
}

/// Pre-tick modules assigned to `domain_id`.
pub fn domain_pre_pass_count(domain_id: usize) -> usize {
    // SAFETY: scheduler-thread read.
    unsafe { (*core::ptr::addr_of!(SCHED)).domains.get(domain_id) }
        .map_or(0, |d| d.pre_pass_count as usize)
}

/// The pre-pass module at `pos` in `domain_id`'s slot.
pub fn domain_pre_pass_at(domain_id: usize, pos: usize) -> Option<usize> {
    // SAFETY: scheduler-thread read.
    let d = unsafe { (*core::ptr::addr_of!(SCHED)).domains.get(domain_id) }?;
    if pos >= d.pre_pass_count as usize || pos >= MAX_PRE_PASS_PER_DOMAIN {
        return None;
    }
    Some(d.pre_pass_order[pos] as usize)
}

/// µs `domain_id` consumed in its most recent pass.
pub fn domain_budget_us_consumed(domain_id: usize) -> u64 {
    // SAFETY: scheduler-thread read.
    unsafe { (*core::ptr::addr_of!(SCHED)).domains.get(domain_id) }
        .map_or(0, |d| d.budget_consumed_us)
}

/// Test-facing setter: a domain's budget limit without `prepare_graph`;
/// `0` disables it.
pub fn set_domain_budget_us_limit(domain_id: usize, limit_us: u32) {
    // SAFETY: scheduler-thread mutation.
    if let Some(d) = unsafe { (*core::ptr::addr_of_mut!(SCHED)).domains.get_mut(domain_id) } {
        d.budget_limit_us = limit_us;
    }
}

/// Whether a module of `domain_id` reported useful work during the current
/// graph's walk (the pacer's work signal).
pub fn domain_pacer_work_pending(domain_id: usize) -> bool {
    // SAFETY: an atomic read.
    unsafe {
        (*core::ptr::addr_of!(SCHED))
            .domains
            .get(domain_id.min(MAX_DOMAINS - 1))
    }
    .is_some_and(|d| d.pacer_work.load(Ordering::Relaxed))
}

/// Test-only: clear the work signal (a pass clears it per graph walk).
pub fn clear_domain_pacer_work_for_test(domain_id: usize) {
    // SAFETY: an atomic write.
    if let Some(d) = unsafe {
        (*core::ptr::addr_of!(SCHED))
            .domains
            .get(domain_id.min(MAX_DOMAINS - 1))
    } {
        d.pacer_work.store(false, Ordering::Relaxed);
    }
}

/// Run `domain_id`'s pre-pass slot: each module once, the slot as a whole
/// capped at the domain's pre-pass budget (past it the rest wait for the next
/// pass, and `MON_PRE_PASS_OVERRUN` is logged). Its cost is taken back out
/// of the domain's accumulator so the order starts with the whole budget.
fn step_domain_pre_pass(
    modules: &mut [ModuleSlot],
    sched: &mut SchedulerState,
    domain_id: usize,
    not_ready: &ModuleMask,
    active_count: &mut usize,
) {
    let n = sched.domains[domain_id].pre_pass_count as usize;
    if n == 0 {
        return;
    }
    let active_module_count = sched.active_module_count;
    let baseline = sched.domains[domain_id].budget_consumed_us;
    let budget = sched.pre_pass_budget_us(domain_id);
    for pos in 0..n.min(MAX_PRE_PASS_PER_DOMAIN) {
        let module_idx = sched.domains[domain_id].pre_pass_order[pos] as usize;
        if module_idx >= active_module_count {
            continue;
        }
        // The slot is domain-global, not per graph: a paused owner's module
        // is skipped here.
        if crate::kernel::ipc::event::paused_owners_present()
            && crate::kernel::ipc::event::module_wake_masked(module_idx)
        {
            continue;
        }
        step_one_module(modules, sched, module_idx, not_ready, active_count, false);
        let ds = &mut sched.domains[domain_id];
        let used = ds.budget_consumed_us.saturating_sub(baseline);
        if used > budget {
            ds.pre_pass_overruns = ds.pre_pass_overruns.saturating_add(1);
            log::warn!(
                "MON_PRE_PASS_OVERRUN domain={} elapsed_us={} budget_us={} last_mod={} tick={}",
                domain_id,
                used,
                budget,
                module_idx,
                ds.passes(),
            );
            break;
        }
    }
    sched.domains[domain_id].budget_consumed_us = baseline;
}

/// Which hook of a pre-pass module to run.
#[derive(Clone, Copy)]
enum PrePassHook {
    Refill,
    Flush,
}

/// Run a pre-pass module's `hook` under the step guard; a fault takes the
/// module's policy. Returns whether a refill admitted new work.
fn run_pre_pass_hook(
    modules: &mut [ModuleSlot],
    sched: &mut SchedulerState,
    module_idx: usize,
    hook: PrePassHook,
    active_count: &mut usize,
) -> bool {
    set_current_module(module_idx);
    // SAFETY: debug-only volatile write to a scalar static.
    unsafe {
        core::ptr::write_volatile(&raw mut DBG_STEP_MODULE, module_idx as ModuleId);
    }
    step_guard::arm(sched.fault_info[module_idx].effective_deadline_us());
    let result = match (modules[module_idx].as_module_mut(), hook) {
        (Some(m), PrePassHook::Refill) => m.pipeline_refill(),
        (Some(m), PrePassHook::Flush) => m.post_tick_flush().map(|()| false),
        (None, _) => Ok(false),
    };
    let (timed_out, protection) = end_step_guard();
    let mut admitted = false;
    let context = match hook {
        PrePassHook::Refill => " (pipeline-refill)",
        PrePassHook::Flush => " (post-tick-flush)",
    };
    if timed_out {
        fault::fault(
            sched,
            modules,
            module_idx,
            FaultKind::Timeout,
            active_count,
            "",
        );
    } else if protection {
        fault::fault(
            sched,
            modules,
            module_idx,
            FaultKind::Protection,
            active_count,
            "",
        );
    } else {
        match result {
            Ok(work) => admitted = work,
            Err(rc) => fault::fault(
                sched,
                modules,
                module_idx,
                FaultKind::Error(rc),
                active_count,
                context,
            ),
        }
    }
    set_current_module(MAX_MODULES);
    admitted
}

/// Whether pre-pass module `module_idx` may run a hook now.
fn pre_pass_hook_eligible(sched: &SchedulerState, module_idx: usize) -> bool {
    module_idx < sched.active_module_count
        && !sched.finished[module_idx]
        && sched.ready[module_idx]
        && sched.fault_info[module_idx].state == FaultState::Running
}

/// Run the pre-pass modules' device-input refill hooks between sub-passes.
/// A hook that admitted new work earns another sub-pass. Distinct from
/// `module_step`, so a refill cannot repeat link maintenance, TX or timers.
fn step_domain_pipeline_refill(
    modules: &mut [ModuleSlot],
    sched: &mut SchedulerState,
    domain_id: usize,
    active_count: &mut usize,
) -> bool {
    let n = sched.domains[domain_id].pre_pass_count as usize;
    let budget = sched.pre_pass_budget_us(domain_id);
    let t0 = crate::kernel::sys::hal::now_micros();
    let mut admitted = false;
    for pos in 0..n.min(MAX_PRE_PASS_PER_DOMAIN) {
        let module_idx = sched.domains[domain_id].pre_pass_order[pos] as usize;
        if !pre_pass_hook_eligible(sched, module_idx)
            || (crate::kernel::ipc::event::paused_owners_present()
                && crate::kernel::ipc::event::module_wake_masked(module_idx))
        {
            continue;
        }
        admitted |= run_pre_pass_hook(
            modules,
            sched,
            module_idx,
            PrePassHook::Refill,
            active_count,
        );
        if crate::kernel::sys::hal::now_micros().wrapping_sub(t0) > budget {
            break;
        }
    }
    admitted
}

/// Run the pre-pass modules' output-only flush hooks after the graphs: what
/// the pass produced ships this tick without re-running an RX drain.
fn step_domain_post_tick_flush(
    modules: &mut [ModuleSlot],
    sched: &mut SchedulerState,
    domain_id: usize,
    active_count: &mut usize,
) {
    let n = sched.domains[domain_id].pre_pass_count as usize;
    let budget = sched.pre_pass_budget_us(domain_id);
    let t0 = crate::kernel::sys::hal::now_micros();
    for pos in 0..n.min(MAX_PRE_PASS_PER_DOMAIN) {
        let module_idx = sched.domains[domain_id].pre_pass_order[pos] as usize;
        if !pre_pass_hook_eligible(sched, module_idx) {
            continue;
        }
        run_pre_pass_hook(modules, sched, module_idx, PrePassHook::Flush, active_count);
        let used = crate::kernel::sys::hal::now_micros().wrapping_sub(t0);
        if used > budget {
            log::warn!(
                "MON_POST_TICK_FLUSH_OVERRUN domain={domain_id} elapsed_us={used} budget_us={budget} last_mod={module_idx} tick={}",
                sched.domains[domain_id].passes()
            );
            break;
        }
    }
}

/// How long the readiness gate may hold a module before it is reported:
/// longer than a network's normal bring-up (a Wi-Fi association and a DHCP
/// lease hold everything after `ip`).
const STARVATION_REPORT_MS: u64 = 30_000;
/// How often [`readiness_starvation_sweep`] looks.
const STARVATION_SWEEP_MS: u64 = 1_000;

/// Report, once per hold, a module the readiness gate has held for a whole
/// [`STARVATION_REPORT_MS`] window, naming an upstream module it waits on.
///
/// The gate skips a non-deferred module while any module upstream of it has
/// not reported Ready, silently: a deferred module that never reports Ready
/// holds everything after it for ever. The modules held when a window opens
/// are its suspects; a suspect seen unheld at any sweep leaves them, and one
/// still held when the window closes is reported, so a report means a hold
/// of between one and two windows. Observable as
/// `ModuleStateSnapshot::readiness_starved`.
fn readiness_starvation_sweep(
    sched: &mut SchedulerState,
    modules: &[ModuleSlot],
    count: usize,
    not_ready: &ModuleMask,
) {
    let now = crate::kernel::sys::hal::now_millis();
    if now.wrapping_sub(sched.starvation_sweep_ms) < STARVATION_SWEEP_MS {
        return;
    }
    sched.starvation_sweep_ms = now;
    let window_over = now.wrapping_sub(sched.starvation_window_ms) >= STARVATION_REPORT_MS;
    let mut held_now = ModuleMask::new();
    for m in 0..count {
        let held = !not_ready.is_empty()
            && !sched.finished[m]
            && !sched.deferred_ready[m]
            && sched.upstream_mask[m].intersects(not_ready);
        if !held {
            sched.starvation_suspect.clear(m);
            sched.starvation_reported.clear(m);
            continue;
        }
        held_now.set(m);
        if !window_over || !sched.starvation_suspect.test(m) || sched.starvation_reported.test(m) {
            continue;
        }
        sched.starvation_reported.set(m);
        let mut waits = sched.upstream_mask[m];
        waits.and_assign(not_ready);
        let held_name = modules.get(m).map_or("?", |s| s.type_name());
        let wait_name = waits
            .iter_set()
            .next()
            .and_then(|u| modules.get(u))
            .map_or("?", |s| s.type_name());
        log::warn!(
            "[ready] {held_name} not stepped for at least {}s: waiting on {wait_name}, which \
             has not reported Ready",
            STARVATION_REPORT_MS / 1000
        );
    }
    if window_over {
        sched.starvation_suspect = held_now;
        sched.starvation_window_ms = now;
    }
}

/// End a guarded call: the deadline check (before the disarm: the
/// cooperative guard records a timeout only while armed), both guard flags
/// cleared so neither lingers into the next step, then the disarm (a
/// hardware alarm stays live until told otherwise). Returns `(timed out,
/// protection fault)`.
fn end_step_guard() -> (bool, bool) {
    step_guard::post_step_check();
    let timed_out = step_guard::check_and_clear_timeout();
    let protection = step_guard::check_and_clear_mpu_fault();
    step_guard::disarm();
    (timed_out, protection)
}

/// Whether periodic module `module_idx` is due now, anchoring its schedule
/// on its first pass: the first due falls `period - phase - 1` nominal ticks
/// out, so a phase staggers modules of one period.
fn periodic_due(sched: &mut SchedulerState, module_idx: usize, now: u64) -> bool {
    let nd = sched.module_next_due_us[module_idx];
    if nd != 0 {
        return now >= nd;
    }
    let period = u64::from(sched.step_period[module_idx]);
    let phase = u64::from(sched.step_phase[module_idx]).min(period - 1);
    let nominal = u64::from(domain_tick_us(sched.domain_id[module_idx] as usize));
    let first = now.wrapping_add((period - 1 - phase) * nominal).max(1);
    sched.module_next_due_us[module_idx] = first;
    now >= first
}

/// Advance a periodic module's schedule past `now` by its own period
/// (`step_period × nominal tick`), resynchronising after a long stall
/// rather than catching up in a storm.
fn advance_periodic(sched: &mut SchedulerState, module_idx: usize, now: u64) {
    let nominal = u64::from(domain_tick_us(sched.domain_id[module_idx] as usize));
    let period = u64::from(sched.step_period[module_idx])
        .saturating_mul(nominal)
        .max(1);
    let mut nd = sched.module_next_due_us[module_idx];
    for _ in 0..64 {
        if nd > now {
            break;
        }
        nd = nd.wrapping_add(period);
    }
    if nd <= now {
        nd = now.wrapping_add(period);
    }
    sched.module_next_due_us[module_idx] = nd;
}

/// The one per-module step body: the fault machine, the period and
/// readiness gates, the step under the guard, every outcome, the burst
/// re-steps, and the charge to the domain's budget.
///
/// `event_wake` bypasses the period gate (the event is the trigger) and
/// keeps every other rule. `active_count` is decremented when the module
/// finalizes.
pub(crate) fn step_one_module(
    modules: &mut [ModuleSlot],
    sched: &mut SchedulerState,
    module_idx: usize,
    not_ready: &ModuleMask,
    active_count: &mut usize,
    event_wake: bool,
) {
    if sched.finished[module_idx] {
        return;
    }
    // Interrupt-mode modules run from their timer or IRQ, never from a pass.
    let domain = sched.domain_id[module_idx] as usize;
    if domain < MAX_DOMAINS && sched.domains[domain].exec_mode.is_interrupt() {
        return;
    }
    // Recovery runs ahead of the period and readiness gates.
    if fault::advance(sched, modules, module_idx, active_count) {
        return;
    }

    // A periodic module steps when its own wall-clock due arrives; the due
    // moves on only when it actually steps, so a readiness veto keeps the
    // slot.
    let periodic = !event_wake && sched.step_period[module_idx] > 1;
    let now = crate::kernel::sys::hal::now_micros();
    if periodic && !periodic_due(sched, module_idx, now) {
        return;
    }

    // Readiness gate: a non-deferred module waits while any upstream module
    // has not reported Ready. Deferred (infrastructure) modules step freely
    // to reach Ready.
    if !not_ready.is_empty()
        && !sched.deferred_ready[module_idx]
        && sched.upstream_mask[module_idx].intersects(not_ready)
    {
        sched.inactive_for_ticks[module_idx] =
            sched.inactive_for_ticks[module_idx].saturating_add(1);
        return;
    }

    let Some(m) = modules[module_idx].as_module_mut() else {
        return;
    };
    if periodic {
        advance_periodic(sched, module_idx, now);
    }
    sched.inactive_for_ticks[module_idx] = 0;
    set_current_module(module_idx);
    // SAFETY: DBG_STEP_MODULE is a diagnostic with one writer per core's
    // pass; the fault handler reads it with `read_volatile`.
    unsafe {
        core::ptr::write_volatile(&raw mut DBG_STEP_MODULE, module_idx as ModuleId);
    }

    let deadline = sched.fault_info[module_idx].effective_deadline_us();
    step_guard::arm(deadline);
    // The whole step's wall clock, burst re-steps included, is what the
    // domain's budget is charged.
    let module_t0 = crate::kernel::sys::hal::now_micros();
    crate::kernel::sys::hal::stack_fence_arm(m.stack_bytes());
    let outcome = as_module_step(|| m.step());
    note_stack_fence(module_idx);
    record_step_time(
        module_idx,
        (crate::kernel::sys::hal::now_micros() - module_t0) as u32,
    );

    match outcome {
        Ok(StepOutcome::Continue) => {
            let (timed_out, protection) = end_step_guard();
            // A step finalizes at most once; the timeout wins.
            if timed_out {
                fault::fault(
                    sched,
                    modules,
                    module_idx,
                    FaultKind::Timeout,
                    active_count,
                    "",
                );
            } else if protection {
                fault::fault(
                    sched,
                    modules,
                    module_idx,
                    FaultKind::Protection,
                    active_count,
                    "",
                );
            }
        }
        Ok(StepOutcome::Ready) => {
            let (_, protection) = end_step_guard();
            if protection {
                fault::fault(
                    sched,
                    modules,
                    module_idx,
                    FaultKind::Protection,
                    active_count,
                    "",
                );
            } else if !sched.ready[module_idx] {
                sched.ready[module_idx] = true;
                log::info!("{}: ready", modules[module_idx].type_name());
            }
        }
        Ok(StepOutcome::Done) => {
            let _ = end_step_guard();
            finalize_module(module_idx, None, modules[module_idx].type_name(), "");
            *active_count -= 1;
        }
        Ok(StepOutcome::Burst) => {
            step_burst(
                modules,
                sched,
                module_idx,
                deadline,
                module_t0,
                active_count,
            );
        }
        Err(rc) => {
            let (_, protection) = end_step_guard();
            // An EL0 abort returns Continue through the protection flag; an
            // error with the flag also set is one fault, not two.
            let kind = if protection {
                FaultKind::Protection
            } else {
                FaultKind::Error(rc)
            };
            fault::fault(sched, modules, module_idx, kind, active_count, "");
        }
    }

    set_current_module(MAX_MODULES);

    let elapsed = crate::kernel::sys::hal::now_micros().wrapping_sub(module_t0);
    let Some(ds) = sched.domains.get_mut(domain) else {
        return;
    };
    ds.budget_consumed_us = ds.budget_consumed_us.saturating_add(elapsed);
    let e = elapsed.min(u64::from(u32::MAX)) as u32;
    if e > ds.worst_step_us {
        ds.worst_step_us = e;
    }
    if elapsed > MOD_STEP_HEAVY_US {
        if let Some(sup) = ds.mon_throttle(MonLine::HeavyStep) {
            log::warn!(
                "MON_HEAVY_STEP module={} domain={} elapsed_us={} tick={} suppressed={}",
                module_idx,
                domain,
                elapsed,
                ds.passes(),
                sup,
            );
        }
    }
    sched.pass_module_us[module_idx] = sched.pass_module_us[module_idx].saturating_add(e);
    sched.pass_module_steps[module_idx] = sched.pass_module_steps[module_idx].saturating_add(1);
}

/// A step returned `Burst`: re-step the module while it keeps bursting, up
/// to `MAX_BURST_STEPS`, under the burst deadline and within the domain's
/// budget. Each re-step is recorded as a step.
fn step_burst(
    modules: &mut [ModuleSlot],
    sched: &mut SchedulerState,
    module_idx: usize,
    deadline: u32,
    module_t0: u64,
    active_count: &mut usize,
) {
    let domain = sched.domain_id[module_idx] as usize;
    if let Some(ds) = sched.domains.get(domain) {
        ds.burst_seen.store(true, Ordering::Relaxed);
        ds.pacer_burst.store(true, Ordering::Relaxed);
    }
    step_guard::disarm();
    let burst_deadline = sched.fault_info[module_idx]
        .explicit_burst_deadline_us()
        .unwrap_or_else(|| deadline.saturating_mul(step_guard::BURST_MULTIPLIER));
    step_guard::arm(burst_deadline);

    // Set once the burst ended the module's step (finalized or faulted), so
    // the closing guard check does not take a second fault.
    let mut ended = false;
    for _ in 0..MAX_BURST_STEPS {
        if step_guard::is_timed_out() {
            step_guard::disarm();
            step_guard::check_and_clear_timeout();
            fault::fault(
                sched,
                modules,
                module_idx,
                FaultKind::Timeout,
                active_count,
                "",
            );
            ended = true;
            break;
        }
        // A bursting module must not eat its siblings' budget: the
        // accumulator plus this step so far, against the limit.
        if let Some(ds) = sched.domains.get_mut(domain) {
            let limit = u64::from(ds.budget_limit_us);
            if limit > 0 {
                let elapsed_now = crate::kernel::sys::hal::now_micros().wrapping_sub(module_t0);
                if ds.budget_consumed_us.saturating_add(elapsed_now) > limit {
                    if let Some(sup) = ds.mon_throttle(MonLine::BurstAbort) {
                        log::warn!(
                            "MON_BURST_BUDGET_ABORT module={} domain={} \
                             elapsed_us={} consumed_us={} limit_us={} suppressed={}",
                            module_idx,
                            domain,
                            elapsed_now,
                            ds.budget_consumed_us,
                            limit,
                            sup,
                        );
                    }
                    break;
                }
            }
        }
        let Some(m) = modules[module_idx].as_module_mut() else {
            break;
        };
        let t0 = crate::kernel::sys::hal::now_micros();
        let outcome = as_module_step(|| m.step());
        note_stack_fence(module_idx);
        record_step_time(
            module_idx,
            (crate::kernel::sys::hal::now_micros() - t0) as u32,
        );
        match outcome {
            Ok(StepOutcome::Burst) => continue,
            Ok(StepOutcome::Continue) => break,
            Ok(StepOutcome::Ready) => {
                if !sched.ready[module_idx] {
                    sched.ready[module_idx] = true;
                    log::info!("{}: ready", modules[module_idx].type_name());
                }
                break;
            }
            Ok(StepOutcome::Done) => {
                finalize_module(
                    module_idx,
                    None,
                    modules[module_idx].type_name(),
                    " (burst)",
                );
                *active_count -= 1;
                ended = true;
                break;
            }
            Err(rc) => {
                fault::fault(
                    sched,
                    modules,
                    module_idx,
                    FaultKind::Error(rc),
                    active_count,
                    " (burst)",
                );
                ended = true;
                break;
            }
        }
    }
    let (timed_out, protection) = end_step_guard();
    if ended {
        return;
    }
    if timed_out {
        fault::fault(
            sched,
            modules,
            module_idx,
            FaultKind::Timeout,
            active_count,
            "",
        );
    } else if protection {
        fault::fault(
            sched,
            modules,
            module_idx,
            FaultKind::Protection,
            active_count,
            "",
        );
    }
}

/// A step over this (µs) logs `MON_HEAVY_STEP`; quiet on the fast path.
const MOD_STEP_HEAVY_US: u64 = 50;

/// Burst re-steps per module per step: each one bounded, so a compute-heavy
/// module does several chunks a tick and stays cooperative.
const MAX_BURST_STEPS: usize = 16384;

/// Check the stack fence after a module call. A broken fence means the
/// module and the kernel under it went deeper than the composer admitted:
/// a protection fault on the module that was running, reported once.
fn note_stack_fence(module_idx: usize) {
    if !crate::kernel::sys::hal::stack_fence_intact() {
        log::error!("[stack] module {module_idx} ran past its admitted stack");
        crate::kernel::sys::hal::stack_fence_arm(0);
        step_guard::record_mpu_fault(module_idx);
    }
}

/// Least sub-passes per tick, whatever modules return. 1 is the baseline:
/// only a `Burst` earns a re-pass. Raising it forces the first K
/// unconditionally, so a reply path against the order finishes within the
/// tick without any module opting in; fairness-neutral (every module steps
/// K times), and the budget still bounds it.
static FORCED_PIPELINE_PASSES: AtomicU32 = AtomicU32::new(1);

/// Whether a sub-pass is owed to the forced count.
#[inline]
fn forced_pass_pending(tick_pass: u32) -> bool {
    tick_pass < FORCED_PIPELINE_PASSES.load(Ordering::Relaxed)
}

/// Set the forced sub-pass count, clamped to `[1, MAX_PIPELINE_PASSES]`.
pub fn set_forced_pipeline_passes(n: u32) {
    FORCED_PIPELINE_PASSES.store(n.clamp(1, MAX_PIPELINE_PASSES), Ordering::Relaxed);
}

/// `StepEffect` codes reported via `REPORT_STEP_EFFECT`. Values are
/// wire-stable (module SDK ↔ kernel).
pub mod step_effect {
    /// No useful work; no known runnable backlog.
    pub const IDLE: u8 = 0;
    /// Blocked on external/device/peer progress — does NOT heat the pacer.
    pub const WAITING: u8 = 1;
    /// Useful work happened; no immediate same-module re-step.
    pub const WORK_DONE: u8 = 2;
    /// More local work can progress, but fairness says yield — heats the
    /// pacer, no immediate re-step.
    pub const RUNNABLE_BACKLOG: u8 = 3;
    /// Useful work and immediate re-step is productive (mirror of the `Burst`
    /// return; reporting it here also heats the pacer).
    pub const BURST: u8 = 4;
}

/// Record a module's `StepEffect`: `WorkDone`/`RunnableBacklog`/`Burst` mark
/// its domain busy for the pacer (heat only: a re-step still takes a `Burst`
/// return); `Idle`/`Waiting` do nothing, so a blocked module does not pin
/// the pacer hot.
pub fn report_step_effect(module_idx: usize, effect: u8) {
    if module_idx >= module_slots() || effect < step_effect::WORK_DONE {
        return;
    }
    // SAFETY: scheduler-thread read of the module's domain; an atomic store.
    unsafe {
        let sched = &*core::ptr::addr_of!(SCHED);
        if let Some(d) = sched.domains.get(sched.domain_id[module_idx] as usize) {
            d.pacer_work.store(true, Ordering::Relaxed);
        }
    }
}
