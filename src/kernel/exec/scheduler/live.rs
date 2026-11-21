//! Owner lifecycle on a running graph: tearing an owner down, pausing and
//! resuming it, and the step budget a graph's module declares. Adding an
//! owner is the splice (`scheduler::splice`).
//!
//! [`free_owner`] stops the owner's modules (one-shot drain then terminate),
//! closes its edges, reclaims its state and revokes the handle (the
//! generation guard in [`crate::kernel::workload::owner`] rejects it
//! thereafter). Surviving modules keep their slot, state and schedule
//! position: the freed owner's entries are compacted out of the execution
//! order, never re-sorted.

use super::{module_slots, Edge, ModuleId, ModuleSlot, SchedulerState, SCHED};
use crate::kernel::exec::step_guard::{FaultPolicy, BURST_MULTIPLIER, DEFAULT_STEP_DEADLINE_US};
use crate::kernel::workload::owner::{OwnerHandle, OwnerState, OWNER_NODE};

/// A module's step budget as its graph declares it (`step_deadline_us`,
/// `step_deadline_burst_us`, `fault_policy`), carried by the composed graph's
/// module record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepBudget {
    /// Step deadline in microseconds; `0` is the node's default
    /// (`DEFAULT_STEP_DEADLINE_US`).
    pub deadline_us: u32,
    /// Burst re-step deadline in microseconds; `0` is
    /// `deadline × BURST_MULTIPLIER`.
    pub burst_us: u32,
    /// What an overrun or step error does. A workload is admitted only a
    /// policy confined to the faulting module
    /// ([`FaultPolicy::confined_to_module`]).
    pub policy: FaultPolicy,
}

impl StepBudget {
    /// No declaration: the node's default deadline, the multiplier burst,
    /// `Skip`. What a module gets when its graph says nothing.
    pub const NODE_DEFAULT: StepBudget = StepBudget {
        deadline_us: 0,
        burst_us: 0,
        policy: FaultPolicy::Skip,
    };

    /// Whether the budget declares a deadline of either kind. An undeclared
    /// budget runs on the node's defaults and is never measured against the
    /// ceiling, as a node-graph module that declares none is not.
    pub const fn declares_deadline(&self) -> bool {
        self.deadline_us != 0 || self.burst_us != 0
    }

    /// The burst deadline the budget runs under: the declared one, else the
    /// declared (or default) step deadline × `BURST_MULTIPLIER` — the figure
    /// the burst path uses at run time.
    pub const fn effective_burst_us(&self) -> u32 {
        if self.burst_us != 0 {
            self.burst_us
        } else {
            let d = if self.deadline_us != 0 {
                self.deadline_us
            } else {
                DEFAULT_STEP_DEADLINE_US
            };
            d.saturating_mul(BURST_MULTIPLIER)
        }
    }
}

/// Absolute ceiling on any declared deadline, step or burst, in
/// microseconds. Mirrors the build's `HARD_BURST_CAP_US`: no module can
/// authorise stalling the scheduler longer than this.
pub const STEP_BUDGET_HARD_CAP_US: u32 = 100_000;

/// The burst ceiling, in domain ticks: a declared deadline fits in this many
/// of the domain's ticks. Mirrors the build's `16 × domain tick_us` rule.
pub const STEP_BUDGET_TICKS: u32 = 16;

/// The longest deadline, step or burst, a module in `domain_id` may declare
/// on this node: `STEP_BUDGET_TICKS` of the domain's shortest tick (its
/// `tick_min_us` when the domain runs adaptive cadence, else its tick),
/// never above [`STEP_BUDGET_HARD_CAP_US`]. The figures are the node's, not
/// the ones the subgraph's author built against.
pub fn step_budget_ceiling_us(domain_id: u8) -> u32 {
    let d = domain_id as usize;
    let tick = if super::domain_adaptive_flags(d) & super::ADAPTIVE_FLAG_CADENCE != 0 {
        super::domain_tick_min_us(d)
    } else {
        super::domain_tick_us(d)
    };
    let tick = if tick == 0 { super::tick_us() } else { tick };
    tick.saturating_mul(STEP_BUDGET_TICKS)
        .min(STEP_BUDGET_HARD_CAP_US)
}

/// Why a declared step budget was not admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetRefusal {
    /// The policy reaches past the faulting module (`Restart`).
    Policy,
    /// The step deadline is above the domain's ceiling.
    Deadline { ceiling_us: u32 },
    /// The effective burst deadline is above the domain's ceiling.
    Burst { ceiling_us: u32 },
}

/// Admit `b` for a module of a workload in `domain_id`, bounded by the
/// node's policy: a policy confined to the module, and a step and burst
/// deadline each within [`step_budget_ceiling_us`]. Refuses rather than
/// clamps, as the build refuses a node graph's over-ceiling deadline — a
/// module silently given less time than its graph declared would fault for
/// a budget nobody chose.
pub fn admit_step_budget(b: &StepBudget, domain_id: u8) -> Result<(), BudgetRefusal> {
    if !b.policy.confined_to_module() {
        return Err(BudgetRefusal::Policy);
    }
    if !b.declares_deadline() {
        return Ok(());
    }
    let ceiling_us = step_budget_ceiling_us(domain_id);
    if b.deadline_us > ceiling_us {
        return Err(BudgetRefusal::Deadline { ceiling_us });
    }
    if b.effective_burst_us() > ceiling_us {
        return Err(BudgetRefusal::Burst { ceiling_us });
    }
    Ok(())
}

/// The module staging the next subgraph, for `Endpoint::Caller`.
static mut CALLER: Option<usize> = None;

/// Name the module on whose behalf the next splice stages a graph,
/// so `Endpoint::Caller` resolves to it; `None` after the add.
pub fn set_caller(slot: Option<usize>) {
    // SAFETY: scheduler thread only, like the add it brackets.
    unsafe { *core::ptr::addr_of_mut!(CALLER) = slot };
}

pub(crate) fn caller() -> Option<usize> {
    // SAFETY: as `set_caller`.
    unsafe { *core::ptr::addr_of!(CALLER) }
}

/// Why `free_owner` failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FreeError {
    /// The handle names the node owner, which cannot be freed.
    NotWorkload,
    /// The handle is unknown or its generation no longer matches (already
    /// freed / reused) — the fail-closed path.
    StaleHandle,
    /// The owner is still being added (`Reserved`): the add that staged it
    /// publishes it or rolls it back, and nothing else frees it — freeing it
    /// underneath the add would leave the add placing modules for an owner
    /// that is gone.
    Staged,
}

impl FreeError {
    pub fn code(self) -> i32 {
        match self {
            FreeError::NotWorkload => -1,
            FreeError::StaleHandle => -2,
            FreeError::Staged => -3,
        }
    }
}

/// Why `owner_pause` / `owner_resume` failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PauseError {
    /// The handle names the node owner, which can never be paused.
    NotWorkload,
    /// Unknown handle or stale generation (already freed / reused).
    StaleHandle,
    /// The owner is in a state the verb does not apply to (`Reserved`,
    /// `Draining`, `Revoked`) — pause is Active↔Paused only; a draining
    /// owner is past the point of reversibility.
    BadState,
}

impl PauseError {
    pub fn code(self) -> i32 {
        match self {
            PauseError::NotWorkload => -1,
            PauseError::StaleHandle => -2,
            PauseError::BadState => -3,
        }
    }
}

/// Borrow the scheduler state. Single-threaded scheduler context; callers must
/// not hold the returned reference across a call that re-derives `SCHED`.
#[inline]
fn sched() -> &'static mut SchedulerState {
    // SAFETY: scheduler-thread-exclusive; mirrors `sched_mut()`.
    unsafe { &mut *core::ptr::addr_of_mut!(SCHED) }
}

// On a multi-domain kernel (the `smp` feature) every peer domain core is
// parked while an owner is torn down, and the affected domains' dispatch
// tables are reprojected from the compacted flat order.

/// Bit `d` set ⇒ a module in the mutation touches domain `d`. Bounded by
/// `scheduler::MAX_DOMAINS` (≤ 32, so a `u32` mask is always sufficient).
#[inline]
fn domain_bit(domain_id: u8) -> u32 {
    1u32 << (domain_id as usize).min(super::MAX_DOMAINS - 1)
}

/// Park every peer domain core for a live schedule mutation, returning `true`
/// iff a quiesce was actually taken (so the caller must release it). At runtime
/// on domain cores this is the `request_quiesce`/`wait_parked` park-all-secondaries
/// pattern (`kernel::exec::domains`); before the domains are released and on
/// single-domain hosts it is a no-op — the mutation runs single-threaded.
///
/// **Invariant:** primary-core-only. `request_quiesce` is defined for domain 0;
/// the runtime callers (the splice and `free_owner`) must run on the primary
/// domain's scheduler context (the metal `workload` provider dispatches on the
/// node graph, which lives on domain 0).
#[inline]
fn quiesce_peers() -> bool {
    crate::kernel::sys::hal::smp_quiesce_peers()
}

/// Release a quiesce taken by [`quiesce_peers`]. No-op when `parked` is false.
#[inline]
fn release_peers(parked: bool) {
    if parked {
        crate::kernel::sys::hal::smp_release_peers();
    }
}

// ============================================================================
// free_owner
// ============================================================================

/// Free `handle`: stop its modules, close its edges, reclaim its state, and
/// revoke the handle. Synchronous and idempotent against a stale handle.
///
/// One-shot drain only: `module_drain` is invoked once (a best-effort
/// stop-intake/flush) and the module is then terminated. Multi-tick graceful
/// drain is the reconfigure module's cross-tick policy, layered on top by
/// driving the owner's modules to `Done` *before* calling `free_owner`.
pub fn free_owner(handle: OwnerHandle) -> Result<(), FreeError> {
    if handle.is_system() {
        return Err(FreeError::NotWorkload);
    }
    let state = match sched().owners.lookup(handle) {
        Some(e) if e.state == OwnerState::Reserved => return Err(FreeError::Staged),
        Some(e) => e.state,
        None => return Err(FreeError::StaleHandle),
    };
    // Tell subscribed providers first, while the owner handle still resolves
    // and every provider module is still live and steppable. A provider that
    // holds resources on this owner's behalf (scratch objects, open files)
    // reclaims them here; after this point the handle's generation moves and
    // a provider belonging to this owner's own graph is torn down below.
    // Delivered from here rather than from the platform drain driver so the
    // paths that bypass it — the workload verbs (KILL/DESTROY), `FREE_OWNER`
    // and admission rollback — are covered by the same edge.
    crate::kernel::module::provider::notify_owner_released(handle);
    // Its net lanes go before its channels close, and the provider closes
    // every endpoint they opened.
    // SAFETY: scheduler thread, before the owner's channels close.
    unsafe { crate::kernel::workload::net_attach::detach(handle) };
    // Which module slots belong to this owner, and which domains they occupy —
    // captured up front (pure reads) BEFORE any mutation, because the
    // per-domain unsplice below needs the freed owner's domain set, and
    // step 4 clears each module's `domain_id`.
    let mut owned = crate::kernel::workload::bitmask::ModuleMask::new();
    let mut owned_count = 0usize;
    let mut affected: u32 = 0;
    for i in 0..module_slots() {
        if matches!(sched().modules[i], ModuleSlot::Empty) {
            continue;
        }
        if super::module_owner(i) == handle {
            owned.set(i);
            owned_count += 1;
            affected |= domain_bit(sched().domain_id[i]);
        }
    }
    let is_owned = |i: usize| i < module_slots() && owned.test(i);

    // Park every peer domain core for the teardown: the drain, the
    // unsplice from each domain's order, edge close, state free and reindex
    // are the mutations a concurrently-stepping peer core must never
    // observe half applied. No-op wrapper on single-domain hosts and at boot.
    let parked = quiesce_peers();

    if state == OwnerState::Paused {
        // Freeing a paused owner: drop its wake masking first so the
        // paused-owner count and mask bits can't outlive the owner. The
        // deferred wakes are discarded — the modules are being torn down.
        let mask = owned_module_mask(handle);
        let _ = crate::kernel::ipc::event::unpause_mask_modules(&mask);
    }
    sched().owners.begin_drain(handle);

    // 1. Stop modules: one-shot drain (if exported), then mark finished so the
    //    scheduler skips them immediately.
    {
        let s = sched();
        for i in 0..module_slots() {
            if !is_owned(i) {
                continue;
            }
            if let ModuleSlot::Dynamic(ref m) = s.modules[i] {
                // SAFETY: module is live and about to be torn down; drain runs
                // on its owning (scheduler) core. The caller (a workload
                // manager's KILL or DESTROY) gets its own context back.
                let _ = super::with_module_context(i, || unsafe { m.call_drain() });
            }
            s.finished[i] = true;
        }
    }

    // 2. Unsplice from each domain's order BEFORE freeing state, so a
    //    racing step can never reach a freed slot. Stable compaction.
    super::unsplice_from_orders(&owned, affected);

    // 3. Close the owner's edges and compact the edges array. Nothing
    //    references edges by array index, and channel handles are unchanged by
    //    the shift, so surviving owners are untouched. `channel_close` resets
    //    the slot, which also clears any wake-on-write `wake_module` binding —
    //    a reused channel slot can never latch wakes for a freed module index.
    {
        let s = sched();
        let mut w = 0usize;
        for r in 0..s.edge_count {
            let edge = s.edges[r];
            let from_owned = is_owned(edge.from_module);
            let to_owned = is_owned(edge.to_module);
            if edge.tap && edge.tap_source >= 0 && (from_owned || to_owned) {
                // Either end going stops the mirror.
                crate::kernel::ipc::channel::channel_set_mirror(edge.tap_source, -1);
            }
            if edge.tap && from_owned && !to_owned {
                // The TAPPED module went; its observer lives on. End the tap's
                // stream (the observer completes by EOF) and keep the edge —
                // and its channel, which the observer still reads — until the
                // observer's own owner is freed.
                crate::kernel::ipc::channel::channel_producer_gone(edge.channel, false);
                let mut kept = edge;
                kept.tap_source = -1;
                s.edges[w] = kept;
                w += 1;
                continue;
            }
            if from_owned || to_owned {
                if edge.channel >= 0 {
                    super::splice::release_ring(&edge);
                    crate::kernel::module::syscalls::channel_close(edge.channel);
                }
                continue;
            }
            if w != r {
                s.edges[w] = s.edges[r];
            }
            w += 1;
        }
        for i in w..s.edge_count {
            s.edges[i] = Edge::simple(0, 0);
        }
        s.edge_count = w;
    }

    // 4. Free state and clear each owned slot.
    {
        let s = sched();
        for i in 0..module_slots() {
            if !is_owned(i) {
                continue;
            }
            // A live-added module may hold events, timers and platform handles,
            // mailbox lends, and a contract-provider layer (e.g. a
            // mounted volume backend). Release them before its state is freed,
            // or a later dispatch would call into freed code. Boot modules
            // reach this through the finish path; the live-splice teardown
            // does it explicitly.
            crate::kernel::module::syscalls::release_module_handles(i as ModuleId);
            // Memory, isolation region and per-slot bookkeeping, as one
            // teardown. A module with buffers lent to a block source keeps its
            // memory until they are back.
            super::free_module_state(i);
            s.slot_generation[i] = s.slot_generation[i].wrapping_add(1);
            s.type_hash[i] = 0;
            super::set_module_owner(i, OWNER_NODE);
        }
        s.active_module_count = s.active_module_count.saturating_sub(owned_count);
    }

    // The affected domains' wake masks, over the survivors only: after the
    // state free, so freed slots are `Empty`.
    super::refresh_domains(affected);

    // 5. Revoke the handle. The generation guard now rejects it.
    sched().owners.free(handle);
    // The owner's own modules' code, when it brought a pack: nothing of the
    // owner runs any more (its modules are unspliced, their handles and
    // provider layers released), and a module whose state is quarantined
    // for a lend keeps only that state.
    crate::kernel::workload::code_pack::release_owner(handle.slot);
    // Drop the freed owner from the resident-graph index. A later slot reuse
    // bumps the generation, so its pacer instance resets and the re-added
    // entry is re-primed.
    super::rebuild_resident_graph_index();
    // Teardown complete — release the parked peer cores (no-op if none).
    release_peers(parked);
    Ok(())
}

// ============================================================================
// owner_pause / owner_resume
// ============================================================================
//
// The metal PAUSE verb: a reversible quiesce built from exactly the two
// primitives drain is built from — admission close (the
// `authorize_admit` gate, closed by the `Paused` owner state) and
// per-owner wake masking (`event::pause_mask_modules`) — plus the re-latch
// path `owner_resume` owns. Deliberately weaker than drain: no
// `module_drain`, no channel-empty requirement, no deadline. In-flight
// steps complete naturally (pause runs on the scheduler thread between
// steps — there is no preemption to suppress); from the next pass
// the pass's runnable predicate treats the owner's graphs as not-runnable
// regardless of readable inbound data, and inbound writes simply buffer in
// the owner's channels: deferred, not refused, because channel rings are
// lossless and bounded, so buffering IS the deferral; producers see normal
// backpressure when the ring fills.

/// The owner's stamped module set. Bounded scan; scheduler-thread only.
fn owned_module_mask(handle: OwnerHandle) -> crate::kernel::workload::bitmask::ModuleMask {
    let s = sched();
    let mut mask = crate::kernel::workload::bitmask::ModuleMask::new();
    for i in 0..module_slots() {
        if !matches!(s.modules[i], ModuleSlot::Empty) && super::module_owner(i) == handle {
            mask.set(i);
        }
    }
    mask
}

/// Pause `handle`: close admission and mask its wake sources so its graphs
/// stop being stepped. Idempotent (pause of a paused owner is a no-op).
/// The node owner is refused. Scheduler-thread only (same access class
/// as the splice and `free_owner`).
pub fn owner_pause(handle: OwnerHandle) -> Result<(), PauseError> {
    if handle.is_system() {
        return Err(PauseError::NotWorkload);
    }
    let state = match sched().owners.lookup(handle) {
        Some(e) => e.state,
        None => return Err(PauseError::StaleHandle),
    };
    match state {
        OwnerState::Paused => return Ok(()), // idempotent
        OwnerState::Active => {}
        _ => return Err(PauseError::BadState),
    }
    let mask = owned_module_mask(handle);
    // Mask-then-check (lost-wakeup discipline): divert NEW wakes first,
    // then sweep bits that latched before the mask was visible. A signal
    // racing the sweep lands in EVENT_WAKE_PENDING and is deferred by the
    // the domain loop's per-pass straggler sweep / the woken-step guard.
    crate::kernel::ipc::event::pause_mask_modules(&mask);
    let latched = crate::kernel::ipc::event::take_wake_in_mask(&mask);
    crate::kernel::ipc::event::defer_masked_wakes(&latched);
    // State last: the domain loop skips on `Paused`, admission closes via
    // `authorize_admit` (the same gate, reversible).
    sched().owners.set_state(handle, OwnerState::Paused);
    Ok(())
}

/// Resume `handle`: reopen admission and re-latch every wake that arrived
/// while paused, so deferred producers/timers are serviced on the next
/// pass — a module with masked-arrived data steps exactly once with
/// `event_wake = true`, as if the wake had just fired. Idempotent (resume
/// of an Active owner is a no-op).
pub fn owner_resume(handle: OwnerHandle) -> Result<(), PauseError> {
    if handle.is_system() {
        return Err(PauseError::NotWorkload);
    }
    let state = match sched().owners.lookup(handle) {
        Some(e) => e.state,
        None => return Err(PauseError::StaleHandle),
    };
    match state {
        OwnerState::Active => return Ok(()), // idempotent
        OwnerState::Paused => {}
        _ => return Err(PauseError::BadState),
    }
    sched().owners.set_state(handle, OwnerState::Active);
    let mask = owned_module_mask(handle);
    // Unmask-then-drain: after the mask clears, new wakes latch normally;
    // the returned set is everything that was diverted while masked. Both
    // orders of a racing signal deliver — none are lost, a duplicate
    // event-wake step is benign (level-triggered semantics).
    let deferred = crate::kernel::ipc::event::unpause_mask_modules(&mask);
    if !deferred.is_empty() {
        for idx in deferred.iter_set() {
            crate::kernel::ipc::event::relatch_module_wake(idx);
        }
        crate::kernel::sys::hal::wake_scheduler();
    }
    Ok(())
}

/// Decode `[slot:u16 LE, generation:u32 LE]` and free that owner.
pub fn free_owner_encoded(arg: &[u8]) -> i32 {
    match decode_owner_handle(arg) {
        Some(h) => match free_owner(h) {
            Ok(()) => 0,
            Err(e) => e.code(),
        },
        None => crate::kernel::sys::errno::EINVAL,
    }
}

/// Decode `[slot:u16 LE, generation:u32 LE]` and pause that owner
/// (`reconfigure::OWNER_PAUSE`). Same handle record as `FREE_OWNER`.
pub fn owner_pause_encoded(arg: &[u8]) -> i32 {
    match decode_owner_handle(arg) {
        Some(h) => match owner_pause(h) {
            Ok(()) => 0,
            Err(e) => e.code(),
        },
        None => crate::kernel::sys::errno::EINVAL,
    }
}

/// Decode `[slot:u16 LE, generation:u32 LE]` and resume that owner
/// (`reconfigure::OWNER_RESUME`).
pub fn owner_resume_encoded(arg: &[u8]) -> i32 {
    match decode_owner_handle(arg) {
        Some(h) => match owner_resume(h) {
            Ok(()) => 0,
            Err(e) => e.code(),
        },
        None => crate::kernel::sys::errno::EINVAL,
    }
}

/// Shared `[slot:u16 LE, generation:u32 LE]` handle decode.
fn decode_owner_handle(arg: &[u8]) -> Option<OwnerHandle> {
    let b = arg.get(..6)?;
    Some(OwnerHandle {
        slot: u16::from_le_bytes([b[0], b[1]]),
        generation: u32::from_le_bytes([b[2], b[3], b[4], b[5]]),
    })
}
