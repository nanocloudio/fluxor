//! Scheduler responsibility module (real module boundary; parent statics and
//! helpers reach us via `super`). Per-domain pacing and CPU-budget accounting.
#![allow(
    unused_imports,
    reason = "the flat scheduler namespace is glob-imported; each module uses a subset"
)]
use super::*;

/// Whether a module in `domain_id` reported useful work this outer tick (the
/// pacer's work signal). Read by the pacer's busy rule and exposed for observability /
/// conformance tests. Resets once per outer tick.
pub fn domain_pacer_work_pending(domain_id: usize) -> bool {
    PACER_WORK_TICK
        .get(domain_id.min(MAX_DOMAINS - 1))
        .map(|b| b.load(Ordering::Relaxed))
        .unwrap_or(false)
}

/// Test-only: clear the per-domain work-tick accumulator (production resets it
/// once per outer tick at the top of `step_modules` / `step_domain_modules`).
pub fn clear_domain_pacer_work_for_test(domain_id: usize) {
    if let Some(b) = PACER_WORK_TICK.get(domain_id.min(MAX_DOMAINS - 1)) {
        b.store(false, Ordering::Relaxed);
    }
}

/// Variant of [`step_domain_modules`] for platforms running a
/// continuous-poll execution tier (e.g. BCM2712 Tier 3): runs one full
/// pass through the domain's modules via the shared `step_one_module`
/// body, then returns `(StepResult, burst_seen)` where `burst_seen`
/// indicates whether any module returned `StepOutcome::Burst` during
/// the pass. Poll-mode callers use that bit to decide whether to spin
/// (more work pending) or WFE (idle).
pub fn step_domain_modules_poll(
    modules: &mut [ModuleSlot; MAX_MODULES],
    domain_id: usize,
) -> (StepResult, bool) {
    if domain_id >= MAX_DOMAINS {
        return (step_domain_modules(modules, domain_id), false);
    }
    BURST_SEEN_THIS_PASS[domain_id].store(false, Ordering::Relaxed);
    let result = step_domain_modules(modules, domain_id);
    let burst = BURST_SEEN_THIS_PASS[domain_id].swap(false, Ordering::Relaxed);
    (result, burst)
}

/// Has the given domain consumed more than its tick budget in the
/// current pass? Called between modules in `step_modules` /
/// `step_domain_modules` to enforce the per-domain budget; returns
/// `true` once the cumulative `m.step()` wall-clock for this pass
/// exceeds `domain_budget_us_limit`. A `limit == 0` disables the
/// check (no budget configured — e.g. host-test or pre-`prepare_graph`
/// callers).
#[inline]
pub(crate) fn domain_budget_exhausted(sched: &SchedulerState, domain_id: usize) -> bool {
    if domain_id >= MAX_DOMAINS {
        return false;
    }
    let limit = sched.domain_budget_us_limit[domain_id] as u64;
    if limit == 0 {
        return false;
    }
    sched.domain_budget_us_consumed[domain_id] > limit
}

/// Multiplier above the per-domain budget at which the scheduler
/// breaks the pass rather than just logging the overrun. Reserved
/// for runaway-loop protection; soft overruns let the pass finish
/// so downstream modules (e.g. the NIC drain) still tick.
const BUDGET_HARD_BREAK_MULTIPLIER: u64 = 10;

/// Max times the per-domain exec rotation is re-run within a single tick.
///
/// One pass moves data one hop along `exec_order`, so a request's RETURN
/// path (http→tls→ip, against topological order) would otherwise wait a full
/// tick per hop — the dominant per-request latency (≈ pipeline-depth × tick_us).
/// Re-running the pass while any module still reports `Burst` (pending work)
/// lets a full ip→tls→http→tls→ip round-trip complete in one tick. Idle ticks
/// burst nothing → exactly one pass, so the low-load cost is unchanged; the
/// per-domain budget caps the busy case. Bounded so a perpetually-bursting
/// module can't spin the tick.
pub(crate) const MAX_PIPELINE_PASSES: u32 = 12;

/// Whether a domain can afford another pipeline pass this tick.
///
/// A pass is re-run while modules report backlog, and a re-run costs about
/// what the pass before it did. Starting one with less than that left
/// overruns the budget by construction: the overrun is then charged to
/// whichever module closed the pass, but the cause was admitting the pass.
/// So a pass is admitted only when another of the same cost still fits.
/// `pass_start_us` is the domain's consumption when the pass just finished
/// began.
#[inline]
pub(crate) fn domain_budget_admits_repass(
    sched: &SchedulerState,
    domain_id: usize,
    pass_start_us: u64,
) -> bool {
    if domain_id >= MAX_DOMAINS {
        return true;
    }
    let limit = sched.domain_budget_us_limit[domain_id] as u64;
    if limit == 0 {
        return true;
    }
    let consumed = sched.domain_budget_us_consumed[domain_id];
    let last_pass = consumed.saturating_sub(pass_start_us);
    consumed.saturating_add(last_pass) <= limit
}

#[inline]
pub(crate) fn domain_budget_hard_overrun(sched: &SchedulerState, domain_id: usize) -> bool {
    if domain_id >= MAX_DOMAINS {
        return false;
    }
    let limit = sched.domain_budget_us_limit[domain_id] as u64;
    if limit == 0 {
        return false;
    }
    sched.domain_budget_us_consumed[domain_id] > limit.saturating_mul(BUDGET_HARD_BREAK_MULTIPLIER)
}

/// Record a per-domain budget-overrun event: increment the counter
/// and emit a `MON_BUDGET_OVERRUN` log line over the same monitor
/// transport the fault ring uses. Reusing the existing transport
/// means operators see budget overruns alongside faults without a
/// second pipe to subscribe to. `last_module_idx` names the module
/// whose step closed the pass over budget, for triage — it isn't
/// faulted (its `StepOutcome` was honoured), it's just the last
/// observable step before the overrun fired.
pub(crate) fn record_domain_budget_overrun(
    sched: &mut SchedulerState,
    domain_id: usize,
    last_module_idx: usize,
) {
    sched.domain_budget_overruns[domain_id] =
        sched.domain_budget_overruns[domain_id].saturating_add(1);
    // SAFETY: scheduler-thread only; throttle via raw static ptrs.
    if let Some(sup) = unsafe {
        mon_throttle(
            core::ptr::addr_of_mut!(MON_OVERRUN_LAST),
            core::ptr::addr_of_mut!(MON_OVERRUN_SUP),
        )
    } {
        // The three modules of this domain that consumed the most of the
        // pass, as `index:µs/steps`.
        const TOP: usize = 3;
        let mut top = [(u32::MAX, 0u32, 0u16); TOP];
        for i in 0..MAX_MODULES {
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
        log::warn!(
            "MON_BUDGET_OVERRUN domain={} consumed_us={} limit_us={} \
             last_mod={} top={}:{}/{},{}:{}/{},{}:{}/{} overrun_count={} tick={} suppressed={}",
            domain_id,
            sched.domain_budget_us_consumed[domain_id],
            sched.domain_budget_us_limit[domain_id],
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
            sched.domain_budget_overruns[domain_id],
            // SAFETY: DBG_TICK aligned u32 read.
            unsafe { DBG_TICK },
            sup,
        );
    }
}

/// Diagnostic accessor — total budget-overrun count for `domain_id`
/// since boot. Returns 0 for invalid `domain_id`.
pub fn domain_budget_overruns(domain_id: usize) -> u32 {
    if domain_id >= MAX_DOMAINS {
        return 0;
    }
    // SAFETY: scheduler-thread read; domain_id bounded.
    unsafe { SCHED.domain_budget_overruns[domain_id] }
}

/// Diagnostic accessor — cumulative count of Tier 1c pre-tick budget
/// overruns for `domain_id` since boot (one increment per pass where
/// the combined pre-tick budget `MAX_PRE_TICK_BUDGET_US` was
/// exceeded). Returns 0 for invalid `domain_id`.
pub fn domain_pre_tick_overruns(domain_id: usize) -> u32 {
    if domain_id >= MAX_DOMAINS {
        return 0;
    }
    // SAFETY: scheduler-thread read; domain_id bounded.
    unsafe { SCHED.domain_pre_tick_overruns[domain_id] }
}

/// Diagnostic accessor — number of Tier 1c pre-tick modules
/// currently assigned to `domain_id`. Returns 0 for invalid
/// `domain_id`. Used by `tools/tests/scheduler_pre_tick_slot.rs`
/// (the pre-tick slot drift guard) to confirm `pre_tick_drain` modules
/// route to the pre-tick list and not to `domain_exec_order`.
pub fn domain_pre_tick_count(domain_id: usize) -> usize {
    if domain_id >= MAX_DOMAINS {
        return 0;
    }
    // SAFETY: scheduler-thread read; domain_id bounded.
    unsafe { SCHED.domain_pre_tick_count[domain_id] as usize }
}

/// Diagnostic accessor — Tier 1c pre-tick module index at `pos`
/// within `domain_id`. Returns `None` for invalid `domain_id` or
/// `pos` past the populated count. Used by the pre-tick slot drift guard.
pub fn domain_pre_tick_at(domain_id: usize, pos: usize) -> Option<usize> {
    if domain_id >= MAX_DOMAINS {
        return None;
    }
    // SAFETY: scheduler-thread read; domain_id bounded.
    let count = unsafe { SCHED.domain_pre_tick_count[domain_id] as usize };
    if pos >= count || pos >= MAX_PRE_TICK_PER_DOMAIN {
        return None;
    }
    // SAFETY: as above, bounded by MAX_PRE_TICK_PER_DOMAIN.
    Some(unsafe { SCHED.domain_pre_tick_order[domain_id][pos] as usize })
}

/// Diagnostic accessor — microseconds consumed by `domain_id` in the
/// most recent pass. Reset at the top of every pass; reading after
/// the pass returns the cumulative time. Returns 0 for invalid
/// `domain_id`.
pub fn domain_budget_us_consumed(domain_id: usize) -> u64 {
    if domain_id >= MAX_DOMAINS {
        return 0;
    }
    // SAFETY: scheduler-thread read; domain_id bounded.
    unsafe { SCHED.domain_budget_us_consumed[domain_id] }
}

/// Test-facing setter — overrides the budget limit for a domain
/// without going through `prepare_graph`. Conformance tests use this
/// to plant a tight budget against a controllable workload. Passing
/// `limit_us == 0` disables enforcement.
pub fn set_domain_budget_us_limit(domain_id: usize, limit_us: u32) {
    if domain_id >= MAX_DOMAINS {
        return;
    }
    // SAFETY: scheduler-thread mutation; domain_id bounded.
    unsafe {
        SCHED.domain_budget_us_limit[domain_id] = limit_us;
    }
}

pub fn step_domain_modules(
    modules: &mut [ModuleSlot; MAX_MODULES],
    domain_id: usize,
) -> StepResult {
    if domain_id >= MAX_DOMAINS {
        return StepResult::Done;
    }
    // Reset the pacer's per-tick busy accumulator once for the whole outer tick
    // (before any sub-pass or pre-tick step). `BURST_SEEN_THIS_PASS` is reset
    // per sub-pass for drain-detection and can't serve the pacer's "tick busy?".
    PACER_BURST_TICK[domain_id].store(false, Ordering::Relaxed);
    // Useful-work signal: same per-tick reset cadence.
    PACER_WORK_TICK[domain_id].store(false, Ordering::Relaxed);
    // SAFETY: scheduler-thread context — multi-domain platform's caller
    // (BCM2712 core pump) is the sole stepper for this domain.
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };
    // Transaction marker — see `step_modules`.
    if sched.prepare_in_progress {
        return StepResult::Done;
    }

    // Advance the canonical tick. Multi-domain platforms (BCM2712)
    // never call `step_modules`, so the tick advance has to happen
    // here too — otherwise `DBG_TICK` stays at zero forever and the
    // drain timeout (and every other tick-relative check) never
    // fires. Only domain 0 increments to keep one canonical advance
    // per platform-tick under the BCM convention of "one
    // `step_domain_modules` call per core per platform-tick";
    // sibling-domain cores observe the same `DBG_TICK` value within
    // a platform tick. Multi-core races on `DBG_TICK++` already exist
    // on event-wake paths; this doesn't make them worse.
    if domain_id == 0 {
        // SAFETY: domain 0 is the canonical tick advancer; the
        // race with event-wake paths is documented above.
        unsafe {
            DBG_TICK = DBG_TICK.wrapping_add(1);
        }
    }

    // Drain timeout ceiling — same wall-clock check as `step_modules`.
    let count = sched.active_module_count;
    if enforce_drain_timeout(sched, modules, count) {
        return StepResult::Done;
    }

    // Recompute active_count and not_ready once per tick (cheap; same
    // as `step_modules`). active_count is global; a domain-only count
    // would need per-domain `finished[]` tracking// per the design memo.
    let mut active_count: usize = 0;
    for i in 0..count {
        if !sched.finished[i] {
            active_count += 1;
        }
    }
    let mut not_ready = ModuleMask::new();
    for i in 0..count {
        if !sched.ready[i] {
            not_ready.set(i);
        }
    }

    // Reset the per-pass budget accumulator before stepping any
    // modules. `step_one_module` adds elapsed wall-clock here; the
    // loop below cuts the pass only on a hard overrun, advancing
    // the cyclic shift on soft overruns so operators see them
    // without losing the rest of the pass.
    sched.domain_budget_us_consumed[domain_id] = 0;
    for i in 0..sched.active_module_count {
        if sched.domain_id[i] as usize == domain_id {
            sched.pass_module_us[i] = 0;
            sched.pass_module_steps[i] = 0;
        }
    }
    // Decay this domain's adaptive-tick floor worst-step peak-hold once per pass
    // so a stale spike ages out; step_one_module re-raises it to the live worst.
    // `max(v >> shift, 1)` for non-zero v — a pure `v >> 8` stalls at 0 once
    // v < 256, leaving a sub-256 µs spike to pin the floor (and tick_min) forever.
    let w = sched.domain_worst_step_us[domain_id];
    if w > 0 {
        sched.domain_worst_step_us[domain_id] = w - (w >> WORST_STEP_DECAY_SHIFT).max(1);
    }
    let mut overrun_logged_this_pass = false;

    // Tier 1c pre-pass drain — runs `domain_pre_tick_order[d]`
    // modules before the regular exec_order rotation, capped at
    // `MAX_PRE_TICK_BUDGET_US` combined. Pre-tick costs are
    // snapshot-restored against the regular accumulator inside
    // the helper.
    step_domain_pre_tick(modules, sched, domain_id, &not_ready, &mut active_count);

    let n = sched.domain_module_count[domain_id] as usize;
    // Rotate the per-domain exec_order start by
    // `domain_exec_order_offset[domain_id]`. Each domain's offset
    // advances independently on its own budget overrun so a burster
    // in one domain doesn't permanently starve later positions in
    // that same domain's exec_order.
    let dom_offset = if n > 0 {
        (sched.domain_exec_order_offset[domain_id] as usize) % n
    } else {
        0
    };
    // Bounded multi-pass within the tick (see `MAX_PIPELINE_PASSES`). Re-run
    // the exec rotation while any module still reports `Burst` and the domain
    // budget isn't spent, so a request's forward AND return path flow in one
    // tick instead of one hop per tick. The budget accumulates across passes
    // (reset once above), so the existing soft/hard overrun guards bound the
    // busy case exactly as a single pass would.
    let mut tick_pass = 0u32;
    let mut hard_break = false;
    loop {
        BURST_SEEN_THIS_PASS[domain_id].store(false, Ordering::Relaxed);
        let pass_start_us = sched.domain_budget_us_consumed[domain_id];
        for pos in 0..n {
            let rotated = if n > 0 { (pos + dom_offset) % n } else { pos };
            let module_idx = sched.domain_exec_order[domain_id][rotated] as usize;
            if module_idx >= count {
                continue;
            }
            step_one_module(
                modules,
                sched,
                module_idx,
                &not_ready,
                &mut active_count,
                false,
            );

            // Soft overrun: log once + advance the cyclic shift, keep
            // running. Hard overrun (`break`) is runaway-loop protection.
            let soft = domain_budget_exhausted(sched, domain_id);
            let hard = soft && domain_budget_hard_overrun(sched, domain_id);
            if soft && !overrun_logged_this_pass {
                record_domain_budget_overrun(sched, domain_id, module_idx);
                sched.domain_exec_order_offset[domain_id] =
                    sched.domain_exec_order_offset[domain_id].wrapping_add(1);
                overrun_logged_this_pass = true;
            }
            if hard {
                hard_break = true;
                break;
            }
        }
        tick_pass += 1;
        if hard_break || tick_pass >= MAX_PIPELINE_PASSES {
            break;
        }
        // Another pass would not fit the tick budget: let the next tick
        // continue draining.
        if !domain_budget_admits_repass(sched, domain_id, pass_start_us) {
            break;
        }
        let refilled = step_domain_pipeline_refill(modules, sched, domain_id, &mut active_count);
        // No module backlog and no newly-admitted device input → drained.
        // A forced pass overrides this exit only: the budget breaks above
        // still apply, so K forced passes are bounded as one pass is.
        if !BURST_SEEN_THIS_PASS[domain_id].load(Ordering::Relaxed)
            && !refilled
            && !super::stepping::forced_pass_pending(tick_pass)
        {
            break;
        }
    }

    // Ship output produced by this graph pass without re-running RX/input.
    step_domain_post_tick_flush(modules, sched, domain_id, &mut active_count);

    // Drain cooperative⇄ISR bridges after the domain finishes its
    // exec_order rotation. Mirrors the pump call in `step_modules`.
    pump_isr_bridges();

    if active_count == 0 {
        StepResult::Done
    } else {
        StepResult::Continue
    }
}

/// Run the Tier 1c pre-tick slot for `domain_id`. Walks
/// `domain_pre_tick_order[domain_id]` and steps each entry through
/// `step_one_module`, honouring the combined budget cap
/// `MAX_PRE_TICK_BUDGET_US`. When the cap is exceeded, emits
/// `MON_PRE_TICK_OVERRUN`, bumps `domain_pre_tick_overruns[d]`, and
/// stops iterating — remaining pre-tick modules wait until the next
/// pass.
///
/// Pre-tick costs are charged into `domain_budget_us_consumed` as a
/// side effect of `step_one_module`; this helper snapshots the
/// accumulator before iterating and restores it on return so the
/// regular `domain_exec_order` rotation that follows starts with a
/// fresh budget.
#[inline]
pub(crate) fn step_domain_pre_tick(
    modules: &mut [ModuleSlot; MAX_MODULES],
    sched: &mut SchedulerState,
    domain_id: usize,
    not_ready: &ModuleMask,
    active_count: &mut usize,
) {
    if domain_id >= MAX_DOMAINS {
        return;
    }
    let n = sched.domain_pre_tick_count[domain_id] as usize;
    if n == 0 {
        return;
    }
    let active_module_count = sched.active_module_count;
    let baseline = sched.domain_budget_us_consumed[domain_id];
    let budget = MAX_PRE_TICK_BUDGET_US as u64;
    for pos in 0..n.min(MAX_PRE_TICK_PER_DOMAIN) {
        let module_idx = sched.domain_pre_tick_order[domain_id][pos] as usize;
        if module_idx >= active_module_count {
            continue;
        }
        // Pause guard: pre-tick drain is domain-global (not per-graph),
        // so a paused owner's Tier-1c module must be skipped here explicitly.
        // Default-off: one relaxed load when nothing is paused.
        if crate::kernel::ipc::event::paused_owners_present()
            && crate::kernel::ipc::event::module_wake_masked(module_idx)
        {
            continue;
        }
        step_one_module(modules, sched, module_idx, not_ready, active_count, false);
        let used = sched.domain_budget_us_consumed[domain_id].saturating_sub(baseline);
        if used > budget {
            sched.domain_pre_tick_overruns[domain_id] =
                sched.domain_pre_tick_overruns[domain_id].saturating_add(1);
            log::warn!(
                "MON_PRE_TICK_OVERRUN domain={} elapsed_us={} budget_us={} last_mod={} tick={}",
                domain_id,
                used,
                MAX_PRE_TICK_BUDGET_US,
                module_idx,
                // SAFETY: DBG_TICK is an aligned u32 read.
                unsafe { DBG_TICK },
            );
            break;
        }
    }
    // Subtract pre-tick costs back out so the regular exec_order
    // accounting starts at `baseline` for the rest of the pass.
    sched.domain_budget_us_consumed[domain_id] = baseline;
}

/// Run optional device-input refill hooks between bounded graph passes.
/// A positive hook result means it admitted new work and another pass can make
/// progress. The hook is separate from `module_step`, so input refill cannot
/// repeat link maintenance, TX, timers, or other pre-tick side effects.
#[inline]
pub(crate) fn step_domain_pipeline_refill(
    modules: &mut [ModuleSlot; MAX_MODULES],
    sched: &mut SchedulerState,
    domain_id: usize,
    active_count: &mut usize,
) -> bool {
    if domain_id >= MAX_DOMAINS {
        return false;
    }
    let n = sched.domain_pre_tick_count[domain_id] as usize;
    if n == 0 {
        return false;
    }
    let active_module_count = sched.active_module_count;
    let refill_t0 = crate::kernel::sys::hal::now_micros();
    let mut admitted = false;
    for pos in 0..n.min(MAX_PRE_TICK_PER_DOMAIN) {
        let module_idx = sched.domain_pre_tick_order[domain_id][pos] as usize;
        if module_idx >= active_module_count
            || sched.finished[module_idx]
            || !sched.ready[module_idx]
            || sched.fault_info[module_idx].state != FaultState::Running
        {
            continue;
        }
        // Pause guard — same rationale as `step_domain_pre_tick`.
        if crate::kernel::ipc::event::paused_owners_present()
            && crate::kernel::ipc::event::module_wake_masked(module_idx)
        {
            continue;
        }

        set_current_module(module_idx);
        // SAFETY: debug-only volatile write to a scalar static; scheduler-thread only.
        unsafe {
            core::ptr::write_volatile(&raw mut DBG_STEP_MODULE, module_idx as u8);
        }
        let deadline = sched.fault_info[module_idx].effective_deadline_us();
        step_guard::arm(deadline);
        let result = match modules[module_idx].as_module_mut() {
            Some(m) => m.pipeline_refill(),
            None => Ok(false),
        };
        step_guard::post_step_check();
        let timed_out = step_guard::check_and_clear_timeout();
        let mpu = step_guard::check_and_clear_mpu_fault();
        if timed_out {
            handle_step_timeout(sched, modules, module_idx, active_count);
        } else if mpu {
            handle_mpu_fault(sched, modules, module_idx, active_count);
        } else {
            match result {
                Ok(work) => admitted |= work,
                Err(rc) => handle_step_error(
                    sched,
                    modules,
                    module_idx,
                    rc,
                    active_count,
                    " (pipeline-refill)",
                ),
            }
        }
        set_current_module(MAX_MODULES);

        if crate::kernel::sys::hal::now_micros().wrapping_sub(refill_t0)
            > MAX_PRE_TICK_BUDGET_US as u64
        {
            break;
        }
    }
    admitted
}

/// Run the optional output-only hook on Tier 1c modules after graph execution.
/// This is deliberately a distinct ABI entrypoint from `module_step`: the
/// scheduler must never repeat an RX drain merely to make newly-produced TX
/// visible in the same outer tick.
#[inline]
pub(crate) fn step_domain_post_tick_flush(
    modules: &mut [ModuleSlot; MAX_MODULES],
    sched: &mut SchedulerState,
    domain_id: usize,
    active_count: &mut usize,
) {
    if domain_id >= MAX_DOMAINS {
        return;
    }
    let n = sched.domain_pre_tick_count[domain_id] as usize;
    if n == 0 {
        return;
    }
    let active_module_count = sched.active_module_count;
    let flush_t0 = crate::kernel::sys::hal::now_micros();
    for pos in 0..n.min(MAX_PRE_TICK_PER_DOMAIN) {
        let module_idx = sched.domain_pre_tick_order[domain_id][pos] as usize;
        if module_idx >= active_module_count
            || sched.finished[module_idx]
            || !sched.ready[module_idx]
            || sched.fault_info[module_idx].state != FaultState::Running
        {
            continue;
        }

        set_current_module(module_idx);
        // SAFETY: debug-only volatile write to a scalar static; scheduler-thread only.
        unsafe {
            core::ptr::write_volatile(&raw mut DBG_STEP_MODULE, module_idx as u8);
        }
        let deadline = sched.fault_info[module_idx].effective_deadline_us();
        step_guard::arm(deadline);
        let result = match modules[module_idx].as_module_mut() {
            Some(m) => m.post_tick_flush(),
            None => Ok(()),
        };
        step_guard::post_step_check();
        let timed_out = step_guard::check_and_clear_timeout();
        let mpu = step_guard::check_and_clear_mpu_fault();
        if timed_out {
            handle_step_timeout(sched, modules, module_idx, active_count);
        } else if mpu {
            handle_mpu_fault(sched, modules, module_idx, active_count);
        } else if let Err(rc) = result {
            handle_step_error(
                sched,
                modules,
                module_idx,
                rc,
                active_count,
                " (post-tick-flush)",
            );
        }
        set_current_module(MAX_MODULES);

        let used = crate::kernel::sys::hal::now_micros().wrapping_sub(flush_t0);
        if used > MAX_PRE_TICK_BUDGET_US as u64 {
            // SAFETY: debug-only read of a scalar static; scheduler-thread only.
            let dbg_tick = unsafe { DBG_TICK };
            log::warn!(
                "MON_POST_TICK_FLUSH_OVERRUN domain={domain_id} elapsed_us={used} budget_us={MAX_PRE_TICK_BUDGET_US} last_mod={module_idx} tick={dbg_tick}"
            );
            break;
        }
    }
}

/// Per-module step body shared between `step_modules` (flat,
/// single-domain), `step_domain_modules` (per-domain), and
/// `step_woken_modules` (event wake). Encapsulates the full
/// `StepOutcome` handling — period gating, ready gating, fault state
/// machine, burst loop, finalisation — so every caller gets identical
/// semantics.
///
/// `event_wake = true` bypasses step-period gating (an event overrides
/// the per-module period) but keeps every other invariant: upstream-
/// ready gating, fault transitions, step-time recording, step-guard
/// arm/disarm, stack-canary check, and burst MPU-fault handling all
/// fire identically. `active_count` is decremented on finalisation.
///
/// Caller passes its current `active_count`; this function decrements
/// it when a module finalises (Done / terminate / fault-without-restart).
#[inline]
pub(crate) fn step_one_module(
    modules: &mut [ModuleSlot; MAX_MODULES],
    sched: &mut SchedulerState,
    module_idx: usize,
    not_ready: &ModuleMask,
    active_count: &mut usize,
    event_wake: bool,
) {
    // Skip already finished modules
    if sched.finished[module_idx] {
        return;
    }

    // Skip ISR-tier modules. Tier 1b (`exec_mode == 2`) and Tier 2
    // (`exec_mode == 4`) modules run from a timer-ISR or hardware IRQ
    // handler — not from the cooperative `step_modules` loop. Stepping
    // them here would double-execute their work (once cooperatively
    // and once from the ISR) and would also break the ISR-only
    // assumption that no `provider_call`/heap-allocation is on the
    // call stack at module entry. The build-time validator in
    // `tools/src/config.rs::validate_isr_tier_admission` already
    // rejects ISR-tier modules without the `isr_safe` flag; the
    // runtime skip here is defense in depth for hand-rolled binaries.
    let domain = sched.domain_id[module_idx] as usize;
    if domain < MAX_DOMAINS && is_isr_tier_exec_mode(sched.domain_exec_mode[domain]) {
        return;
    }

    // Handle the fault-state machine BEFORE the period/readiness
    // gates. A module raised into `Faulted` by an out-of-step caller
    // (notably `heap_alloc` with `alloc_failure_policy = "fault"`)
    // must run its policy on the next tick regardless of declared
    // period or upstream-readiness gates — those gates govern
    // *normal* step scheduling, not recovery. A module with
    // `step_period = 16` and a hung upstream would otherwise sit
    // Faulted for tens or hundreds of ticks holding handles and
    // channels.
    //
    // The Faulted branch routes through restart-or-finalize via
    // the existing helpers; the Terminated/Recovering branches
    // early-return so the period gate's counter advancement doesn't
    // fire against a dead module.
    let fault_state_early = sched.fault_info[module_idx].state;
    if fault_state_early == FaultState::Faulted {
        // Quarantine must be checked BEFORE draining the restart
        // backoff. `raise_module_fault` arms `restart_backoff_ms`
        // (default 100 ticks) for Restart-policy modules, and
        // `QUARANTINE_WINDOW_MS` is also 100 ms (≈ 100 ticks at the
        // 1 ms default). Draining backoff first would let a
        // Restart-policy module spend the full window decrementing
        // while its partner's `last_fault_ms` ages past the edge of
        // the window, and quarantine would silently miss the co-fault.
        //
        // The check is cheap (`apply_quarantine` returns immediately
        // when no partner has faulted within the window) and
        // idempotent (re-checking after both modules are finished
        // is a no-op via the `finished[partner]` guard). Quarantine
        // also outranks `FaultPolicy::Restart` per the documented
        // contract.
        let pre_finished = sched.finished[module_idx];
        apply_quarantine(sched, modules, module_idx, active_count);
        if sched.finished[module_idx] && !pre_finished {
            return;
        }
        // Backoff drain happens AFTER quarantine. Restart modules
        // wait for backoff; Skip modules (backoff=0) fall through
        // to the can_restart check immediately.
        if sched.fault_info[module_idx].backoff_remaining > 0 {
            sched.fault_info[module_idx].backoff_remaining -= 1;
            return;
        }
        if sched.fault_info[module_idx].can_restart() {
            handle_module_restart(sched, modules, module_idx);
            return;
        } else {
            sched.fault_info[module_idx].state = FaultState::Terminated;
            finalize_module(
                module_idx,
                Some(-110),
                modules[module_idx].type_name(),
                " (terminated)",
            );
            *active_count -= 1;
            return;
        }
    } else if fault_state_early == FaultState::Terminated
        || fault_state_early == FaultState::Recovering
    {
        return;
    }

    // Step frequency gating: skip if counter hasn't reached period.
    // `step_period` is measured in scheduler ticks (NOT milliseconds);
    // wall-clock cadence is `step_period * domain_tick_us`.
    // Event-wake bypasses the period — the event is the trigger.
    //
    // The counter is advanced here but **not** reset until the module
    // actually executes (just before `m.step()` below). Resetting on
    // the period boundary regardless of whether the step fires would
    // lose the slot when the readiness or fault gate vetoes: the
    // module would have to wait another full `period` ticks before
    // becoming eligible again, even though it was *ready to run* on
    // this tick. Keeping the counter saturated at `period` until the
    // step lands preserves the slot across veto, matching the
    // declared cadence under bursty upstream readiness.
    if !event_wake {
        let period = sched.step_period[module_idx];
        if period > 0 {
            let next = sched.step_counter[module_idx].saturating_add(1);
            sched.step_counter[module_idx] = if next >= period { period } else { next };
            if sched.step_counter[module_idx] < period {
                return;
            }
            // counter stays at `period` until the step fires; reset is
            // performed at the call site below.
        }
    }

    // Note: we intentionally step ALL non-finished modules every tick.
    // Stateful generators (e.g. synth) produce continuous output from
    // internal state, not just in response to input data. Gating on
    // input readiness starves audio pipelines.

    // Ready-signal gating: skip if any upstream module hasn't signaled Ready.
    // Deferred-ready modules (infrastructure) are exempt while initializing —
    // they must step freely to reach Ready even if upstream peers aren't ready.
    // Only non-deferred (application) modules are gated by upstream readiness.
    if !not_ready.is_empty()
        && !sched.deferred_ready[module_idx]
        && sched.upstream_mask[module_idx].intersects(not_ready)
    {
        // Count consecutive ticks the readiness gate veto'd this
        // module. Cleared once the module actually steps below. A
        // non-zero value on a steady-state module indicates a dead
        // upstream edge — the diagnostic surfaces via
        // `ModuleStateSnapshot::inactive_for_ticks`.
        sched.inactive_for_ticks[module_idx] =
            sched.inactive_for_ticks[module_idx].saturating_add(1);
        return;
    }

    // Defensive duplicate fault-state check. The early up-front
    // check handles every transition; only modules in `Running`
    // (or a recovering state that just woke) reach this point. This
    // arm fires only if `state` flipped between the early check and
    // here — currently impossible in single-domain single-thread,
    // but cheap to keep for forward-compat with cross-core setters.
    let fault_state = sched.fault_info[module_idx].state;
    if fault_state == FaultState::Faulted {
        if sched.fault_info[module_idx].backoff_remaining > 0 {
            sched.fault_info[module_idx].backoff_remaining -= 1;
            return;
        }
        if sched.fault_info[module_idx].can_restart() {
            handle_module_restart(sched, modules, module_idx);
            return;
        } else {
            sched.fault_info[module_idx].state = FaultState::Terminated;
            finalize_module(
                module_idx,
                Some(-110),
                modules[module_idx].type_name(),
                " (terminated)",
            );
            *active_count -= 1;
            return;
        }
    } else if fault_state == FaultState::Terminated || fault_state == FaultState::Recovering {
        return;
    }

    if let Some(m) = modules[module_idx].as_module_mut() {
        // Step is committed for this tick — reset the period counter
        // (it was held at `period` across veto cycles; clearing here
        // restarts the period count for the next cadence boundary).
        // Event-wake bypasses the period gate entirely and leaves the
        // counter alone so the natural cadence resumes once events stop.
        if !event_wake && sched.step_period[module_idx] > 0 {
            sched.step_counter[module_idx] = 0;
        }
        // An actual step is about to fire — reset the readiness-veto
        // counter. A non-zero value never persists past a successful
        // step; it only accumulates while the gate keeps rejecting.
        sched.inactive_for_ticks[module_idx] = 0;
        // Set current_module so channel_port works during module_step
        set_current_module(module_idx);
        // Track for HardFault diagnosis
        // SAFETY: DBG_STEP_MODULE is a u8 diagnostic — single writer
        // (this scheduler thread); the fault handler reads it via
        // `read_volatile`.
        unsafe {
            core::ptr::write_volatile(&raw mut DBG_STEP_MODULE, module_idx as u8);
        }

        // Arm step guard timer
        let deadline = sched.fault_info[module_idx].effective_deadline_us();
        step_guard::arm(deadline);
        let step_t0 = crate::kernel::sys::hal::now_micros();
        // `module_t0` is the *whole-step* wall-clock anchor for the
        // per-domain budget accumulator. Distinct from `step_t0`
        // (which times the individual `step()` call recorded into the
        // histogram) because Burst's re-step loop should count toward
        // the domain budget too — every iteration of the loop is real
        // wall-clock the domain owes.
        let module_t0 = step_t0;

        // Every step is recorded, whatever it returned.
        //
        // Recording only one outcome would make a module that is not
        // being stepped and a module being stepped but answering
        // something other than `Continue` produce the identical record —
        // none — and telling those two apart is the reading this
        // histogram exists to support.
        let outcome = m.step();
        record_step_time(
            module_idx,
            (crate::kernel::sys::hal::now_micros() - step_t0) as u32,
        );

        match outcome {
            Ok(StepOutcome::Continue) => {
                // Run the post-step deadline check BEFORE disarming. The BCM
                // (cooperative) guard's `post_step_check` early-returns when the
                // guard is already disarmed, so the previous `disarm()`-first
                // order silently dropped every over-deadline step; `post_step_check`
                // both records the timeout AND disarms.
                step_guard::post_step_check();
                // A single step finalizes AT MOST ONCE. A timeout, an MPU/EL0
                // protection fault, and a stack-canary overflow each
                // terminate/quarantine the module and decrement `active_count`;
                // running more than one for the same step double-counts (and can
                // stop a healthy sibling). Clear both guard flags unconditionally
                // (so neither lingers into the next step), then finalize once —
                // timeout takes precedence, MPU and canary collapse into one fault.
                let timed_out = step_guard::check_and_clear_timeout();
                let mpu = step_guard::check_and_clear_mpu_fault();
                let canary_violated = !crate::kernel::sys::hal::stack_canary_check();
                if canary_violated {
                    log::error!("[mpu] module {module_idx} stack canary violated");
                    crate::kernel::sys::hal::stack_canary_reinit();
                }
                if timed_out {
                    handle_step_timeout(sched, modules, module_idx, active_count);
                } else if mpu || canary_violated {
                    handle_mpu_fault(sched, modules, module_idx, active_count);
                }
            }
            Ok(StepOutcome::Ready) => {
                step_guard::disarm();
                if !sched.ready[module_idx] {
                    sched.ready[module_idx] = true;
                    log::info!("{}: ready", modules[module_idx].type_name());
                }
            }
            Ok(StepOutcome::Done) => {
                step_guard::disarm();
                finalize_module(module_idx, None, modules[module_idx].type_name(), "");
                *active_count -= 1;
            }
            Ok(StepOutcome::Burst) => {
                // Record that this pass saw a Burst — poll-mode callers
                // (`step_domain_modules_poll`) read this to decide
                // whether to spin or WFE. Set the bursting module's OWN
                // domain slot so a concurrent sibling-core pass can't be
                // confused by it.
                let burst_domain = sched.domain_id[module_idx] as usize;
                if burst_domain < MAX_DOMAINS {
                    BURST_SEEN_THIS_PASS[burst_domain].store(true, Ordering::Relaxed);
                    // Outer-tick accumulator for the pacer — never cleared
                    // mid-tick, so a flush-then-drain tick still reads busy.
                    PACER_BURST_TICK[burst_domain].store(true, Ordering::Relaxed);
                }
                // Keep timer armed for entire burst with extended deadline
                step_guard::disarm();
                // If the manifest declared an explicit burst deadline,
                // use it as-is. Otherwise fall back to the implicit
                // `deadline * BURST_MULTIPLIER` ceiling so modules
                // without a declared burst window still get one.
                let burst_deadline = sched.fault_info[module_idx]
                    .explicit_burst_deadline_us()
                    .unwrap_or_else(|| deadline.saturating_mul(step_guard::BURST_MULTIPLIER));
                step_guard::arm(burst_deadline);

                for _ in 0..MAX_BURST_STEPS {
                    // Check timeout between burst iterations
                    if step_guard::is_timed_out() {
                        step_guard::disarm();
                        step_guard::check_and_clear_timeout();
                        handle_step_timeout(sched, modules, module_idx, active_count);
                        break;
                    }
                    // Per-iteration domain-budget check: a single
                    // bursting module must not eat the entire tick's
                    // budget for siblings. The accumulator at this
                    // point reflects every module *before* this one in
                    // the pass; adding the elapsed-so-far for this
                    // step is the closest projection we have without
                    // committing the time twice. When the projection
                    // crosses the limit, abort the burst cleanly:
                    // disarm the guard and break — the module is left
                    // in its current state (no fault, no `Ready` flip)
                    // so the next pass picks up where it left off.
                    {
                        let d = sched.domain_id[module_idx] as usize;
                        if d < MAX_DOMAINS {
                            let limit = sched.domain_budget_us_limit[d] as u64;
                            if limit > 0 {
                                let elapsed_now =
                                    crate::kernel::sys::hal::now_micros().wrapping_sub(module_t0);
                                let projected =
                                    sched.domain_budget_us_consumed[d].saturating_add(elapsed_now);
                                if projected > limit {
                                    // SAFETY: scheduler-thread only.
                                    if let Some(sup) = unsafe {
                                        mon_throttle(
                                            core::ptr::addr_of_mut!(MON_BURST_LAST),
                                            core::ptr::addr_of_mut!(MON_BURST_SUP),
                                        )
                                    } {
                                        log::warn!(
                                            "MON_BURST_BUDGET_ABORT module={} domain={} \
                                             elapsed_us={} consumed_us={} limit_us={} suppressed={}",
                                            module_idx,
                                            d,
                                            elapsed_now,
                                            sched.domain_budget_us_consumed[d],
                                            limit,
                                            sup,
                                        );
                                    }
                                    step_guard::disarm();
                                    break;
                                }
                            }
                        }
                    }
                    if let Some(m) = modules[module_idx].as_module_mut() {
                        // Each burst iteration is another step, and is
                        // recorded as one — the histogram counts steps
                        // the scheduler performed, not passes it made.
                        let burst_t0 = crate::kernel::sys::hal::now_micros();
                        let burst_outcome = m.step();
                        record_step_time(
                            module_idx,
                            (crate::kernel::sys::hal::now_micros() - burst_t0) as u32,
                        );
                        match burst_outcome {
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
                                break;
                            }
                            Err(rc) => {
                                handle_step_error(
                                    sched,
                                    modules,
                                    module_idx,
                                    rc,
                                    active_count,
                                    " (burst)",
                                );
                                break;
                            }
                        }
                    } else {
                        break;
                    }
                }
                // Post-check before disarm (see the Continue arm) so an
                // over-deadline burst is actually recorded; finalize at most once.
                step_guard::post_step_check();
                let timed_out = step_guard::check_and_clear_timeout();
                let mpu = step_guard::check_and_clear_mpu_fault();
                if timed_out {
                    handle_step_timeout(sched, modules, module_idx, active_count);
                } else if mpu {
                    handle_mpu_fault(sched, modules, module_idx, active_count);
                }
            }
            Err(rc) => {
                step_guard::disarm();
                // A returned error and a pending MPU fault must not BOTH finalize
                // the same step (each terminates + decrements active_count). The
                // EL0 abort path already returns Continue (handled via the MPU
                // flag above), so reaching here with a pending MPU fault is a
                // genuine double-signal — handle the step error XOR the MPU fault.
                let mpu = step_guard::check_and_clear_mpu_fault();
                if mpu {
                    handle_mpu_fault(sched, modules, module_idx, active_count);
                } else {
                    handle_step_error(sched, modules, module_idx, rc, active_count, "");
                }
            }
        }

        // Module call complete — drop module context so scheduler /
        // platform logs emitted between steps attribute to the system
        // owner, not to whichever module happened to run last. The
        // MAX_MODULES sentinel maps to OWNER_SYSTEM in `module_owner`
        // (and short-circuits the contract-grant gate), matching the
        // reconfigure reset path.
        set_current_module(MAX_MODULES);

        // Accumulate wall-clock spent on this module (any outcome,
        // including Burst loops and faults) into the owning domain's
        // budget. The accumulator is reset by the caller at the top
        // of each pass; the per-domain pass loop checks the limit
        // after this function returns and breaks the iteration if
        // exceeded. now_micros uses the same monotonic source as
        // step_t0, so wraparound matches step-time recording.
        let elapsed = crate::kernel::sys::hal::now_micros().wrapping_sub(module_t0);
        let d = sched.domain_id[module_idx] as usize;
        if d < MAX_DOMAINS {
            sched.domain_budget_us_consumed[d] =
                sched.domain_budget_us_consumed[d].saturating_add(elapsed);
            // Peak-hold the per-domain worst single-step (µs) for the
            // adaptive-tick floor. Decayed once per pass (see the per-pass
            // budget reset) so it relaxes after a spike — a decaying peak-hold,
            // not a monotonic max. u32 µs is ample: a step over ~4 ms
            // already trips the budget at any sane tick.
            let e = elapsed.min(u32::MAX as u64) as u32;
            if e > sched.domain_worst_step_us[d] {
                sched.domain_worst_step_us[d] = e;
            }
            sched.pass_module_us[module_idx] = sched.pass_module_us[module_idx].saturating_add(e);
            sched.pass_module_steps[module_idx] =
                sched.pass_module_steps[module_idx].saturating_add(1);
        }
        // Name the module that actually consumed the time — the
        // overrun line names whichever finished *last*, which is a
        // poor proxy for cause.
        if elapsed > MOD_STEP_HEAVY_US {
            // SAFETY: scheduler-thread only; throttle via raw static ptrs.
            if let Some(sup) = unsafe {
                mon_throttle(
                    core::ptr::addr_of_mut!(MON_HEAVY_LAST),
                    core::ptr::addr_of_mut!(MON_HEAVY_SUP),
                )
            } {
                log::warn!(
                    "MON_HEAVY_STEP module={} domain={} elapsed_us={} tick={} suppressed={}",
                    module_idx,
                    d,
                    elapsed,
                    // SAFETY: DBG_TICK is an aligned u32 read; the scheduler
                    // is the only writer.
                    unsafe { DBG_TICK },
                    sup,
                );
            }
        }
    }
}

/// Threshold (µs) above which a single module-step emits
/// `MON_HEAVY_STEP`. Sized to stay quiet on the fast path.
const MOD_STEP_HEAVY_US: u64 = 50;

/// Step only modules whose bit is set in `wake_bits`. Walks the
/// topological execution order so producer modules still run before
/// their consumers within a single wake pass, then delegates each
/// per-module step to `step_one_module` with `event_wake = true`.
/// Event-wake bypasses step-period gating but inherits every other
/// scheduler invariant — upstream-ready gating, fault state machine,
/// step-time recording, step-guard arm/disarm, stack-canary check,
/// burst MPU-fault handling — from the shared body.
pub fn step_woken_modules(
    modules: &mut [ModuleSlot; MAX_MODULES],
    count: usize,
    wake_bits: &ModuleMask,
) {
    // SAFETY: scheduler thread is the sole stepper.
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };
    // Transaction marker — drop event wakes targeting a graph
    // mid-build. The event reappears once the consumer remounts.
    if sched.prepare_in_progress {
        return;
    }

    // Compute current readiness mask once per wake pass, matching the
    // flat/domain stepping paths.
    let mut not_ready = ModuleMask::new();
    for i in 0..count {
        if !sched.ready[i] {
            not_ready.set(i);
        }
    }
    let mut active_count: usize = 0;
    for i in 0..count {
        if !sched.finished[i] {
            active_count += 1;
        }
    }

    let exec_count = sched.exec_order_count;
    let n = if exec_count > 0 { exec_count } else { count };
    let mut deferred: u32 = 0;
    for order_pos in 0..n {
        let module_idx = if exec_count > 0 {
            sched.exec_order[order_pos] as usize
        } else {
            order_pos
        };
        if module_idx >= count {
            continue;
        }
        if !wake_bits.test(module_idx) {
            continue;
        }
        // Pause guard: a wake bit that escaped the pause-time sweep
        // (latched between the mask write and the sweep, then taken by a
        // GLOBAL `take_wake_pending` drain — the Linux/rp platform loops)
        // must not step a paused owner's module; defer it so `owner_resume`
        // re-latches it. Default-off: one relaxed load when nothing is
        // paused.
        if crate::kernel::ipc::event::paused_owners_present()
            && crate::kernel::ipc::event::module_wake_masked(module_idx)
        {
            crate::kernel::ipc::event::defer_masked_wake(module_idx);
            continue;
        }
        // Budget bound on the woken path: woken steps are charged to the
        // domain accumulators like pass steps, and the limit must bind
        // here too — wake-on-write makes wakes data-driven, so without
        // this bound one hot flagged edge steps its consumer unboundedly
        // between ticks, bypassing the fairness rotation. Enforce the
        // same soft limit the pass loop uses: an over-budget domain
        // defers the remaining woken steps to the next pass by
        // re-latching their bits (level-triggered — nothing is lost, the
        // backstop semantics). An out-of-range domain id is fail-open
        // (never deferred), matching the accounting path in
        // `step_one_module`, which skips charging such modules — clamping
        // it to a real domain would defer them against a budget they
        // never consume from.
        let domain = sched.domain_id[module_idx] as usize;
        if domain_budget_exhausted(sched, domain) {
            crate::kernel::ipc::event::relatch_module_wake(module_idx);
            deferred += 1;
            continue;
        }
        step_one_module(
            modules,
            sched,
            module_idx,
            &not_ready,
            &mut active_count,
            true,
        );
    }
    if deferred > 0 {
        // Same throttle as the other per-step budget monitors: on a
        // coarse-timer host (wasm `now_micros` floor ~1-2 ms) every step
        // trips the domain budget, so an unthrottled line here would emit
        // once per wake drain, every tick, for as long as a wake is
        // latched. The deferral itself is unthrottled — only the log line
        // coalesces, carrying the suppressed-window count.
        // SAFETY: scheduler-thread only; throttle via raw static ptrs.
        if let Some(sup) = unsafe {
            mon_throttle(
                core::ptr::addr_of_mut!(MON_WAKE_DEFER_LAST),
                core::ptr::addr_of_mut!(MON_WAKE_DEFER_SUP),
            )
        } {
            log::info!("MON_WAKE_BUDGET_DEFER count={deferred} suppressed={sup}");
        }
    }
}
