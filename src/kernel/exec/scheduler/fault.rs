//! The module fault machine: what a timeout, a returned error or a
//! protection fault does to a module under its `FaultPolicy`, the restart
//! after its backoff, the quarantine of paired modules, and the drain
//! ceiling on a reconfigure.
//!
//! Kernel time windows here are wall-clock (`hal::now_millis()`): a window
//! counted in passes would stretch and shrink with the adaptive tick and stop
//! while a domain idles.
use super::*;
use crate::kernel::exec::interrupt::{self, IsrOutcome};
use crate::kernel::exec::irq;
use crate::kernel::exec::step_guard::PostedFault;
use portable_atomic::{AtomicU32, Ordering};

/// What went wrong with a module's step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FaultKind {
    /// The step ran past its deadline.
    Timeout,
    /// The step (or a step hook) returned an error.
    Error(i32),
    /// A protection fault: an EL0 abort, or a broken stack fence.
    Protection,
}

/// Where in a pass a module's fault was taken: what its log line says after
/// the error code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FaultSite {
    /// The module's step.
    Step,
    /// A burst re-step.
    Burst,
    /// The pipeline-refill hook.
    Refill,
    /// The post-tick-flush hook.
    Flush,
}

impl FaultSite {
    fn suffix(self) -> &'static str {
        match self {
            FaultSite::Step => "",
            FaultSite::Burst => " (burst)",
            FaultSite::Refill => " (pipeline-refill)",
            FaultSite::Flush => " (post-tick-flush)",
        }
    }
}

impl FaultKind {
    fn wire(self) -> u8 {
        match self {
            FaultKind::Timeout => fault_type::TIMEOUT,
            FaultKind::Error(_) => fault_type::STEP_ERROR,
            FaultKind::Protection => fault_type::MPU_FAULT,
        }
    }

    /// The code the module is finalized with when it does not restart.
    fn rc(self) -> i32 {
        match self {
            FaultKind::Timeout => -110,
            FaultKind::Error(rc) => rc,
            FaultKind::Protection => -14,
        }
    }
}

/// Wall-clock window (ms) within which an upstream module's fault is taken
/// as the cause of a downstream one: tight enough to ignore unrelated
/// faults, wide enough to catch a pipeline's hop (rarely more than a tick or
/// two).
const CASCADE_WINDOW_MS: u64 = 4;

/// The upstream module that faulted most recently within
/// [`CASCADE_WINDOW_MS`] of `now_ms`, or `NO_MODULE`.
fn detect_caused_by(sched: &SchedulerState, module_idx: usize, now_ms: u64) -> ModuleId {
    let mask = sched.upstream_mask[module_idx];
    let mut best = NO_MODULE;
    let mut best_elapsed = CASCADE_WINDOW_MS + 1;
    for i in mask.iter_set() {
        let fi = &sched.fault_info[i];
        if fi.fault_count == 0 {
            continue;
        }
        let elapsed = now_ms.wrapping_sub(fi.last_fault_ms);
        if elapsed <= CASCADE_WINDOW_MS && elapsed < best_elapsed {
            best = i as ModuleId;
            best_elapsed = elapsed;
        }
    }
    best
}

/// Whether `domain`'s own core leaves a module's fault work to the primary:
/// every domain a core other than 0 runs. Finalizing, restarting and
/// terminating a module change tables every domain reads and run through
/// provider release hooks, so they are done on the primary, with the other
/// cores parked ([`apply_posted`]); a kernel with one core does them where
/// the fault is taken.
#[inline]
fn posts_to_primary(domain: usize) -> bool {
    #[cfg(all(feature = "smp", target_os = "none"))]
    {
        crate::kernel::exec::domains::domain_core(domain) != 0
    }
    #[cfg(not(all(feature = "smp", target_os = "none")))]
    {
        let _ = domain;
        false
    }
}

/// Set once a module has something posted; the primary's pass looks only
/// then.
static ANY_POSTED: portable_atomic::AtomicBool = portable_atomic::AtomicBool::new(false);

/// Leave `what` on `module_idx` for the primary.
fn post(sched: &mut SchedulerState, module_idx: usize, what: PostedFault, rc: i32) {
    if sched.fault_info[module_idx].post(what, rc) {
        ANY_POSTED.store(true, Ordering::Release);
        crate::kernel::sys::hal::wake_scheduler();
    }
}

/// The primary domain's half of the fault work of modules on other cores:
/// with every other core parked, do to each module what its core posted.
/// One relaxed load when nothing is posted.
pub(crate) fn apply_posted(sched: &mut SchedulerState, modules: &mut [ModuleSlot]) {
    if !ANY_POSTED.swap(false, Ordering::AcqRel) {
        return;
    }
    let parked = crate::kernel::sys::hal::smp_quiesce_peers();
    let count = sched.active_module_count;
    let mut active = (0..count).filter(|&i| !sched.finished[i]).count();
    for idx in 0..count {
        let (what, rc) = sched.fault_info[idx].take_posted();
        if what == PostedFault::None || sched.finished[idx] {
            continue;
        }
        // One of three things, each called from one place.
        let fault = |kind, site| Some((kind, site));
        let as_fault = match what {
            PostedFault::Timeout => fault(FaultKind::Timeout, FaultSite::Step),
            PostedFault::Protection => fault(FaultKind::Protection, FaultSite::Step),
            PostedFault::Error => fault(FaultKind::Error(rc), FaultSite::Step),
            PostedFault::ErrorInBurst => fault(FaultKind::Error(rc), FaultSite::Burst),
            PostedFault::ErrorInRefill => fault(FaultKind::Error(rc), FaultSite::Refill),
            PostedFault::ErrorInFlush => fault(FaultKind::Error(rc), FaultSite::Flush),
            PostedFault::None
            | PostedFault::Done
            | PostedFault::DoneInBurst
            | PostedFault::Advance => None,
        };
        if let Some((kind, site)) = as_fault {
            fault_now(sched, modules, idx, kind, &mut active, site);
        } else if what == PostedFault::Advance {
            let _ = advance_now(sched, modules, idx, &mut active);
        } else {
            finish(modules, idx, what == PostedFault::DoneInBurst);
        }
        // An interrupt-mode module is not stepped by a pass: its domain's
        // pass drives a `Faulted` one's backoff, and its line goes once it
        // has ended.
        let domain = sched.domain_id[idx] as usize;
        if domain < MAX_DOMAINS && sched.domains[domain].exec_mode.is_interrupt() {
            if sched.fault_info[idx].state == FaultState::Faulted {
                ISR_FAULTED_DOMAINS.fetch_or(1 << domain, Ordering::Relaxed);
            }
            if sched.finished[idx] {
                if let Some(irq) = super::module_irq(idx) {
                    retire_line(irq);
                }
            }
        }
    }
    if parked {
        crate::kernel::sys::hal::smp_release_peers();
    }
}

/// A module's step returned `Done`: finalize it, or leave that to the
/// primary when the module's core is not the primary.
pub(crate) fn done(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot],
    module_idx: usize,
    active_count: &mut usize,
    in_burst: bool,
) {
    if posts_to_primary(sched.domain_id[module_idx] as usize) {
        let what = if in_burst {
            PostedFault::DoneInBurst
        } else {
            PostedFault::Done
        };
        post(sched, module_idx, what, 0);
        return;
    }
    finish(modules, module_idx, in_burst);
    *active_count -= 1;
}

/// Finalize a module whose step returned `Done`.
#[inline(never)]
fn finish(modules: &mut [ModuleSlot], module_idx: usize, in_burst: bool) {
    let site = if in_burst {
        FaultSite::Burst
    } else {
        FaultSite::Step
    };
    finalize_module(
        module_idx,
        None,
        modules[module_idx].type_name(),
        site.suffix(),
    );
}

/// Take a fault on `module_idx`: on the primary's core at once
/// ([`fault_now`]); on any other, posted for the primary.
#[inline(never)]
pub(crate) fn fault(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot],
    module_idx: usize,
    kind: FaultKind,
    active_count: &mut usize,
    site: FaultSite,
) {
    if posts_to_primary(sched.domain_id[module_idx] as usize) {
        let (what, rc) = match (kind, site) {
            (FaultKind::Timeout, _) => (PostedFault::Timeout, 0),
            (FaultKind::Protection, _) => (PostedFault::Protection, 0),
            (FaultKind::Error(rc), FaultSite::Step) => (PostedFault::Error, rc),
            (FaultKind::Error(rc), FaultSite::Burst) => (PostedFault::ErrorInBurst, rc),
            (FaultKind::Error(rc), FaultSite::Refill) => (PostedFault::ErrorInRefill, rc),
            (FaultKind::Error(rc), FaultSite::Flush) => (PostedFault::ErrorInFlush, rc),
        };
        post(sched, module_idx, what, rc);
        return;
    }
    fault_now(sched, modules, module_idx, kind, active_count, site);
}

/// Take a fault on `module_idx`: record it (counters, `MON_FAULT`, the fault
/// ring), then apply its policy. `Tolerate` records a timeout and nothing
/// more: a step stalled behind a device flush is late work, not a runaway. A
/// module that may restart moves to `Faulted` with its backoff; any other is
/// terminated and finalized. Then the quarantine pairing.
#[inline(never)]
fn fault_now(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot],
    module_idx: usize,
    kind: FaultKind,
    active_count: &mut usize,
    site: FaultSite,
) {
    let now_ms = crate::kernel::sys::hal::now_millis();
    let domain = sched.domain_id[module_idx] as usize;
    let pass = pass_count(domain);
    let caused_by = detect_caused_by(sched, module_idx, now_ms);
    let name = modules[module_idx].type_name();
    let fi = &mut sched.fault_info[module_idx];
    fi.record_fault(kind.wire(), pass);
    match kind {
        FaultKind::Timeout => log::warn!(
            "[guard] module {module_idx} ({name}) step timeout (fault #{})",
            fi.fault_count
        ),
        FaultKind::Protection => log::warn!(
            "[mpu] module {module_idx} ({name}) protection fault (fault #{})",
            fi.fault_count
        ),
        FaultKind::Error(rc) if fi.can_restart() => log::warn!(
            "[guard] module {module_idx} ({name}) error rc={rc} — will restart (fault #{})",
            fi.fault_count
        ),
        FaultKind::Error(_) => {}
    }
    step_guard::push_fault(FaultRecord {
        module_idx: module_idx as ModuleId,
        fault_kind: kind.wire(),
        caused_by,
        tick: pass,
        fault_count: fi.fault_count,
        restart_count: fi.restart_count,
    });

    if kind == FaultKind::Timeout && fi.policy == FaultPolicy::Tolerate {
        return;
    }
    if fi.can_restart() {
        fi.state = FaultState::Faulted;
        fi.restart_not_before_ms = now_ms.saturating_add(u64::from(fi.effective_backoff_ms()));
    } else {
        fi.state = FaultState::Terminated;
        let suffix = match kind {
            FaultKind::Timeout => " (timeout terminated)",
            FaultKind::Protection => " (mpu terminated)",
            FaultKind::Error(_) => site.suffix(),
        };
        finalize_module(module_idx, Some(kind.rc()), name, suffix);
        *active_count -= 1;
    }
    apply_quarantine(sched, modules, module_idx, active_count);
}

/// Whether `module_idx` must not step, running its policy if it is
/// `Faulted`: on the primary's core at once ([`advance_now`]); on any other
/// the policy is posted for the primary. A module with anything posted does
/// not step until the primary has taken it.
pub(crate) fn advance(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot],
    module_idx: usize,
    active_count: &mut usize,
) -> bool {
    if posts_to_primary(sched.domain_id[module_idx] as usize) {
        if sched.fault_info[module_idx].posted != PostedFault::None {
            return true;
        }
        return match sched.fault_info[module_idx].state {
            FaultState::Running => false,
            FaultState::Terminated | FaultState::Recovering => true,
            FaultState::Faulted => {
                // Posted once the backoff has passed, so the primary parks
                // the other cores for the restart or the termination and
                // not on every pass of the wait. The quarantine pairing was
                // applied when the fault was taken, and is again when the
                // partner faults.
                let now_ms = crate::kernel::sys::hal::now_millis();
                if now_ms >= sched.fault_info[module_idx].restart_not_before_ms {
                    post(sched, module_idx, PostedFault::Advance, 0);
                }
                true
            }
        };
    }
    advance_now(sched, modules, module_idx, active_count)
}

/// Run a `Faulted` module's policy: quarantine first (a co-faulted partner
/// outranks recovery), then, once its backoff has passed, restart it or
/// terminate it. A module in `Terminated` or `Recovering` does nothing.
/// Returns `true` when the module is not `Running` and so must not step.
/// Runs ahead of the period and readiness gates: those govern normal
/// stepping, not recovery.
fn advance_now(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot],
    module_idx: usize,
    active_count: &mut usize,
) -> bool {
    match sched.fault_info[module_idx].state {
        FaultState::Running => false,
        FaultState::Terminated | FaultState::Recovering => true,
        FaultState::Faulted => {
            // Quarantine before the backoff: a backoff as long as the
            // quarantine window would let the partner's fault age out of it.
            let was_finished = sched.finished[module_idx];
            apply_quarantine(sched, modules, module_idx, active_count);
            if sched.finished[module_idx] && !was_finished {
                return true;
            }
            let now_ms = crate::kernel::sys::hal::now_millis();
            if now_ms < sched.fault_info[module_idx].restart_not_before_ms {
                return true;
            }
            let restarted =
                sched.fault_info[module_idx].can_restart() && restart(sched, modules, module_idx);
            if !restarted {
                sched.fault_info[module_idx].state = FaultState::Terminated;
                finalize_module(
                    module_idx,
                    Some(-110),
                    modules[module_idx].type_name(),
                    " (terminated)",
                );
                *active_count -= 1;
            }
            true
        }
    }
}

/// Resume a faulted module on the state it had.
///
/// 1. `syscalls::release_module_handles` releases everything the module
///    registered or opened: events, timers, platform handles (DMA among
///    them), provider layers, and the mailbox records it held lent.
/// 2. Every connected channel (in / out / ctrl) is flushed.
/// 3. If the module was `deferred_ready`, its ready bit is reset.
/// 4. An interrupt-mode module is registered with its dispatcher again
///    (`setup::register_isr_module`, the bring-up path): its slot, and for
///    an `irq` module its line unmasked (its binding stayed).
/// 5. Fault state moves back to `Running`; `finished[idx]` is cleared.
///
/// Returns `false` when an interrupt-mode module could not be registered
/// again; it stays `Recovering` and the caller terminates it.
///
/// This is not a re-instantiation. State memory is not zeroed and
/// `module_new` is not run again, so the module resumes with the state it
/// faulted in, minus every resource that state may name. That is safe only
/// for a module that holds nothing across steps, which is why the composer
/// requires its manifest to attest `resume_after_fault` and refuses the
/// policy outright to a module that provides a contract or surface (nothing
/// registers its layer or handlers again). A module whose invariants do not
/// survive being re-stepped uses `FaultPolicy::Skip`, and the operator
/// drains and reloads it.
pub(crate) fn restart(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot],
    module_idx: usize,
) -> bool {
    sched.fault_info[module_idx].state = FaultState::Recovering;
    sched.fault_info[module_idx].restart_count += 1;
    log::info!(
        "[guard] restarting module {} ({}) (restart #{})",
        module_idx,
        modules[module_idx].type_name(),
        sched.fault_info[module_idx].restart_count
    );

    syscalls::release_module_handles(module_idx as ModuleId);

    let ports = &sched.ports[module_idx];
    for i in 0..ports.in_count as usize {
        if ports.in_chans[i] >= 0 {
            channel::channel_flush(ports.in_chans[i]);
        }
    }
    for i in 0..ports.out_count as usize {
        if ports.out_chans[i] >= 0 {
            channel::channel_flush(ports.out_chans[i]);
        }
    }
    for i in 0..ports.ctrl_count as usize {
        if ports.ctrl_chans[i] >= 0 {
            channel::channel_flush(ports.ctrl_chans[i]);
        }
    }

    if sched.deferred_ready[module_idx] {
        sched.ready[module_idx] = false;
    }

    // Outstanding telemetry snapshots taken before the restart refer to the
    // pre-restart occupancy.
    sched.slot_generation[module_idx] = sched.slot_generation[module_idx].wrapping_add(1);

    let domain = sched.domain_id[module_idx] as usize;
    if domain < MAX_DOMAINS
        && sched.domains[domain].exec_mode.is_interrupt()
        && super::setup::register_isr_module(sched, modules, module_idx, false).is_none()
    {
        return false;
    }

    sched.fault_info[module_idx].state = FaultState::Running;
    sched.finished[module_idx] = false;
    true
}

/// Wall-clock window (ms) within which a paired-module fault co-incidence
/// triggers quarantine: if module A faults and its declared
/// `quarantine_partner` B has also faulted within it, both are terminated
/// whatever their own policy. Comfortable for two halves of a TLS handshake
/// going wrong together, tight enough that unrelated faults do not
/// cross-trigger.
const QUARANTINE_WINDOW_MS: u64 = 100;

/// Terminate `module_idx` together with every module paired with it that
/// also faulted within [`QUARANTINE_WINDOW_MS`]: its declared partner, and
/// any module that declared it as partner (an unreciprocated declaration
/// counts). Idempotent; a finished module is skipped.
pub(crate) fn apply_quarantine(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot],
    module_idx: usize,
    active_count: &mut usize,
) {
    let now_ms = crate::kernel::sys::hal::now_millis();
    let recent = |fi: &ModuleFaultInfo| {
        fi.fault_count > 0 && now_ms.wrapping_sub(fi.last_fault_ms) <= QUARANTINE_WINDOW_MS
    };
    let mut targets = ModuleMask::new();
    let forward = sched.fault_info[module_idx].quarantine_partner as usize;
    if forward < module_slots()
        && forward != module_idx
        && !sched.finished[forward]
        && recent(&sched.fault_info[forward])
    {
        targets.set(forward);
    }
    // A bounded walk over every slot, only when a module faults.
    for i in 0..module_slots() {
        if i == module_idx
            || sched.finished[i]
            || sched.fault_info[i].quarantine_partner as usize != module_idx
        {
            continue;
        }
        if recent(&sched.fault_info[i]) {
            targets.set(i);
        }
    }
    if targets.is_empty() {
        return;
    }
    let target_count = targets.iter_set().count();
    log::warn!(
        "MON_QUARANTINE module={module_idx} partner_count={target_count} now_ms={now_ms} window_ms={QUARANTINE_WINDOW_MS}",
    );
    targets.set(module_idx);
    for idx in targets.iter_set() {
        if idx < module_slots() && !sched.finished[idx] {
            sched.fault_info[idx].state = FaultState::Terminated;
            finalize_module(idx, Some(-111), modules[idx].type_name(), " (quarantined)");
            *active_count -= 1;
        }
    }
}

/// Hard kernel ceiling on a `Draining` phase (ms). The reconfigure module
/// owns the drain and decides when each module has finished its in-flight
/// work, but a hung drain could hold the graph for ever: past this ceiling
/// every unfinished module is terminated (`MON_DRAIN_FORCED`) and the phase
/// returns to `Running`.
const MAX_DRAIN_MS: u64 = 30_000;

/// Enforce [`MAX_DRAIN_MS`]. Returns `true` when it fired: every active
/// module went through `finalize_module` (consumers see the channels close,
/// owned handles are released) and the pass ends.
pub(crate) fn enforce_drain_timeout(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot],
    count: usize,
) -> bool {
    if sched.reconfigure_phase != ReconfigurePhase::Draining {
        return false;
    }
    let start = sched.drain_started_ms;
    let now_ms = crate::kernel::sys::hal::now_millis();
    if start == u64::MAX || now_ms.wrapping_sub(start) <= MAX_DRAIN_MS {
        return false;
    }
    let surviving = (0..count).filter(|i| !sched.finished[*i]).count();
    log::warn!(
        "MON_DRAIN_FORCED ms_elapsed={} ceiling_ms={} — force-terminating \
         {} still-running modules",
        now_ms.wrapping_sub(start),
        MAX_DRAIN_MS,
        surviving,
    );
    for (i, slot) in modules.iter().enumerate().take(count) {
        if !sched.finished[i] {
            sched.fault_info[i].state = FaultState::Terminated;
            finalize_module(i, Some(-110), slot.type_name(), " (drain timeout)");
        }
    }
    sched.reconfigure_phase = ReconfigurePhase::Running;
    sched.drain_started_ms = u64::MAX;
    true
}

/// Record a fault raised outside the module's step result (a heap
/// allocation failure under `alloc_failure_policy = "fault"`) and mark the
/// module `Faulted`, leaving the policy to its next pass: the caller's step
/// frame may still be on the stack, so nothing is finalized or released
/// here. A module that may restart gets its backoff; any other is finalized
/// by `advance` on its next pass.
pub(crate) fn raise(sched: &mut SchedulerState, module_idx: usize, fault_kind: u8) {
    let now_ms = crate::kernel::sys::hal::now_millis();
    let pass = pass_count(sched.domain_id[module_idx] as usize);
    let caused_by = detect_caused_by(sched, module_idx, now_ms);
    let fi = &mut sched.fault_info[module_idx];
    fi.record_fault(fault_kind, pass);
    step_guard::push_fault(FaultRecord {
        module_idx: module_idx as ModuleId,
        fault_kind,
        caused_by,
        tick: pass,
        fault_count: fi.fault_count,
        restart_count: fi.restart_count,
    });
    if fi.state == FaultState::Running {
        fi.state = FaultState::Faulted;
        fi.restart_not_before_ms = if fi.can_restart() {
            now_ms.saturating_add(u64::from(fi.effective_backoff_ms()))
        } else {
            0
        };
    }
}

/// Domains (bit per domain) holding an interrupt-mode module in `Faulted`:
/// their pass drives its backoff and restart, since no pass steps it.
static ISR_FAULTED_DOMAINS: AtomicU32 = AtomicU32::new(0);

/// Lines whose `irq` module has ended, for the primary domain to retire
/// (`u32::MAX`: none). The dispatcher masked each when the outcome latched;
/// the binding goes on the primary, with every other domain parked
/// ([`retire_isr_lines`]).
static RETIRING: [AtomicU32; irq::MAX_IRQ_MODULES] =
    [const { AtomicU32::new(u32::MAX) }; irq::MAX_IRQ_MODULES];
static RETIRE_PENDING: portable_atomic::AtomicBool = portable_atomic::AtomicBool::new(false);

/// Queue `irq` for [`retire_isr_lines`].
fn retire_line(irq: u16) {
    for r in RETIRING.iter() {
        if r.compare_exchange(
            u32::MAX,
            u32::from(irq),
            Ordering::AcqRel,
            Ordering::Relaxed,
        )
        .is_ok()
        {
            break;
        }
    }
    RETIRE_PENDING.store(true, Ordering::Release);
}

/// The primary domain's half of an ended `irq` module: drop the binding of
/// every line queued since the last pass (`hal::irq_unbind`), with every
/// other domain parked. One relaxed load when nothing is queued.
pub(crate) fn retire_isr_lines() {
    if !RETIRE_PENDING.swap(false, Ordering::AcqRel) {
        return;
    }
    let parked = crate::kernel::sys::hal::smp_quiesce_peers();
    for r in RETIRING.iter() {
        let irq = r.swap(u32::MAX, Ordering::AcqRel);
        if irq != u32::MAX {
            let _ = crate::kernel::sys::hal::irq_unbind(irq);
        }
    }
    if parked {
        crate::kernel::sys::hal::smp_release_peers();
    }
}

/// Take the outcomes `domain`'s interrupt-mode modules latched in interrupt
/// context (`interrupt::take_faults`) and apply them on this, the domain's
/// own, core: `Done` finalizes the module; an error is [`fault`] with
/// `Error(rc)`; a budget overrun is [`fault`] with `Timeout`. Then every
/// `Faulted` interrupt-mode module of the domain is [`advance`]d: its
/// restart re-registers it and unmasks its line, or it is terminated. An
/// `irq` module that ends has its line queued for the primary to retire
/// ([`retire_isr_lines`]). One relaxed load when nothing is latched or
/// faulted.
pub(crate) fn drain_isr_faults(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot],
    domain: usize,
    active_count: &mut usize,
) {
    let bit = 1u32 << domain;
    let faults = interrupt::take_faults(|m| {
        let m = m as usize;
        m < module_slots() && sched.domain_id[m] as usize == domain
    });
    for f in faults.iter() {
        let idx = f.module_index as usize;
        if sched.finished[idx] {
            continue;
        }
        match f.outcome {
            IsrOutcome::Done => done(sched, modules, idx, active_count, false),
            IsrOutcome::Error(rc) => {
                fault(
                    sched,
                    modules,
                    idx,
                    FaultKind::Error(rc),
                    active_count,
                    FaultSite::Step,
                );
            }
            IsrOutcome::Overrun => {
                fault(
                    sched,
                    modules,
                    idx,
                    FaultKind::Timeout,
                    active_count,
                    FaultSite::Step,
                );
            }
        }
        if sched.fault_info[idx].state == FaultState::Faulted {
            ISR_FAULTED_DOMAINS.fetch_or(bit, Ordering::Relaxed);
        }
        if let (true, Some(irq)) = (sched.finished[idx], f.irq) {
            retire_line(irq);
        }
    }

    if ISR_FAULTED_DOMAINS.load(Ordering::Relaxed) & bit == 0 {
        return;
    }
    let mut still_faulted = false;
    for i in 0..sched.active_module_count {
        if sched.domain_id[i] as usize != domain
            || sched.finished[i]
            || sched.fault_info[i].state != FaultState::Faulted
        {
            continue;
        }
        advance(sched, modules, i, active_count);
        still_faulted |= sched.fault_info[i].state == FaultState::Faulted;
        if sched.finished[i] {
            if let Some(irq) = super::module_irq(i) {
                retire_line(irq);
            }
        }
    }
    if !still_faulted {
        ISR_FAULTED_DOMAINS.fetch_and(!bit, Ordering::Relaxed);
    }
}
