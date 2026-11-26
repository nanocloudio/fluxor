//! Scheduler responsibility module (real module boundary; parent statics and
//! helpers reach us via `super`).
use super::*;

// ============================================================================
// Workload ownership
// ============================================================================

/// Shared reference to the workload owner table.
#[inline]
pub fn owners() -> &'static OwnerTable {
    // The raw pointer is bound to a local first so we never form a reference to
    // the `static mut` (`static_mut_refs`) nor inline-deref an address-of
    // (`deref_addrof`).
    let p = &raw const SCHED;
    // SAFETY: scheduler-thread read of the static owner table.
    unsafe { &(*p).owners }
}

/// Mutable reference to the workload owner table. Scheduler-thread only.
#[inline]
pub fn owners_mut() -> &'static mut OwnerTable {
    // Raw pointer bound to a local first (see `owners`) to avoid both the
    // `static_mut_refs` and `deref_addrof` lints.
    let p = &raw mut SCHED;
    // SAFETY: scheduler-thread-exclusive mutation of the static owner table.
    unsafe { &mut (*p).owners }
}

/// Owner handle stamped on module `module_idx`.
#[inline]
pub fn module_owner(module_idx: usize) -> OwnerHandle {
    if module_idx >= module_slots() {
        return OWNER_NODE;
    }
    // SAFETY: scheduler-thread read; module_idx bounded above.
    unsafe { SCHED.module_owner[module_idx] }
}

/// Stamp module `module_idx` with `owner`.
#[inline]
pub fn set_module_owner(module_idx: usize, owner: OwnerHandle) {
    if module_idx < module_slots() {
        // SAFETY: scheduler-thread-exclusive mutation; module_idx bounded.
        unsafe {
            SCHED.module_owner[module_idx] = owner;
        }
    }
}

/// Authorize `caller` to touch a resource owned by module `target_idx`.
/// Returns true when the target is node-owned or the same owner.
#[inline]
pub fn authorize_module_access(caller: OwnerHandle, target_idx: usize) -> bool {
    crate::kernel::workload::owner::same_or_node(caller, module_owner(target_idx))
}

/// Owner of the currently-executing module (the syscall caller).
#[inline]
pub fn caller_owner() -> OwnerHandle {
    // Before the platform is up no module runs: the caller is the kernel.
    if !crate::kernel::sys::hal::is_initialised() {
        return OWNER_NODE;
    }
    module_owner(current_module_index())
}

/// The authority the currently-executing module acts with: the node owner
/// for the node and for an owner admitted with the node's authority, its own
/// owner otherwise. What it reaches is decided by this; what it holds is
/// stamped with [`caller_owner`].
#[inline]
pub fn caller_authority() -> OwnerHandle {
    owners().authority_of(caller_owner())
}

/// Whether module N has returned StepOutcome::Done.
pub fn module_is_finished(module_idx: usize) -> bool {
    if module_idx >= module_slots() {
        return false;
    }
    // SAFETY: scheduler-thread read; module_idx bounded.
    unsafe { SCHED.finished[module_idx] }
}

/// One resident owner's live runtime aggregate: the per-MODULE fault/finish
/// state of its plan-assigned module range folded into per-owner counts
/// — an owner-status store keyed by owner UID. This is the kernel half of
/// the per-workload status surface: only the kernel knows
/// the slot→module mapping, so the aggregation happens here and consumers
/// (the node runtime's status writer, `fluxor agent status`) never see
/// module indices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerLiveStatus {
    pub owner_uid: [u8; 16],
    pub slot: u16,
    pub generation: u32,
    /// Modules stamped with this owner (0 until the graph instantiates).
    pub modules_total: u16,
    /// Stamped modules whose slot actually holds an instantiated module.
    /// `< modules_total` means instantiation partially failed (the platform
    /// logs and continues on a per-module error) — the workload must not be
    /// reported Running.
    pub modules_loaded: u16,
    /// Modules that returned `StepOutcome::Done` cleanly (not via fault
    /// termination).
    pub modules_finished: u16,
    /// Modules permanently terminated by the fault state machine.
    pub modules_terminated: u16,
    /// Modules currently `Faulted`/`Recovering` — an internal retry in
    /// flight. Telemetry-grade unreadiness, NOT an aggregate restart.
    pub modules_recovering: u16,
    /// `fault_type::*` of the most recent fault among this owner's
    /// terminated modules (`fault_type::NONE` when none terminated).
    pub last_fault_kind: u8,
    /// When that fault happened (the fault record's `last_fault_ms`), 0 when
    /// none terminated.
    pub last_fault_ms: u64,
    /// Owner lifecycle state: [`OWNER_STATE_ACTIVE`], [`OWNER_STATE_DRAINING`]
    /// or [`OWNER_STATE_PAUSED`].
    pub owner_state: u8,
}

/// `owner_state` code: the owner is running normally.
pub const OWNER_STATE_ACTIVE: u8 = 0;
/// `owner_state` code: the owner is draining before revocation.
pub const OWNER_STATE_DRAINING: u8 = 1;
/// `owner_state` code: the owner is paused (reversible quiesce). Not
/// terminal; `owner_resume` returns it to [`OWNER_STATE_ACTIVE`].
pub const OWNER_STATE_PAUSED: u8 = 2;

impl OwnerLiveStatus {
    pub const EMPTY: OwnerLiveStatus = OwnerLiveStatus {
        owner_uid: [0; 16],
        slot: 0,
        generation: 0,
        modules_total: 0,
        modules_loaded: 0,
        modules_finished: 0,
        modules_terminated: 0,
        modules_recovering: 0,
        last_fault_kind: fault_type::NONE,
        last_fault_ms: 0,
        owner_state: OWNER_STATE_ACTIVE,
    };
}

/// The live status of one owner, its modules folded in;
/// `None` for a free slot or a stale handle. Scheduler-thread only.
pub fn owner_live_status(handle: OwnerHandle) -> Option<OwnerLiveStatus> {
    // SAFETY: scheduler-thread read of the static owner table + fault state.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    if handle.is_node() {
        return None;
    }
    let mut rec = owner_record(sched, handle.slot as usize)?;
    if rec.generation != handle.generation {
        return None;
    }
    for idx in 0..module_slots() {
        if module_owner(idx) == handle {
            fold_module(sched, &mut rec, idx);
        }
    }
    Some(rec)
}

/// The record for owner slot `slot` before any module is folded in; `None`
/// for a free slot.
fn owner_record(sched: &SchedulerState, slot: usize) -> Option<OwnerLiveStatus> {
    let e = sched.owners.entry_at(slot)?;
    let owner_state = match e.state {
        crate::kernel::workload::owner::OwnerState::Free => return None,
        crate::kernel::workload::owner::OwnerState::Draining => OWNER_STATE_DRAINING,
        crate::kernel::workload::owner::OwnerState::Paused => OWNER_STATE_PAUSED,
        _ => OWNER_STATE_ACTIVE,
    };
    Some(OwnerLiveStatus {
        owner_uid: e.owner_uid,
        slot: slot as u16,
        generation: e.generation,
        owner_state,
        ..OwnerLiveStatus::EMPTY
    })
}

/// Fold module `idx`'s load, finish and fault state into its owner's record.
fn fold_module(sched: &SchedulerState, rec: &mut OwnerLiveStatus, idx: usize) {
    rec.modules_total += 1;
    if !matches!(sched.modules[idx], ModuleSlot::Empty) {
        rec.modules_loaded += 1;
    }
    let fi = &sched.fault_info[idx];
    match fi.state {
        FaultState::Terminated => {
            rec.modules_terminated += 1;
            if fi.last_fault_ms >= rec.last_fault_ms {
                rec.last_fault_ms = fi.last_fault_ms;
                rec.last_fault_kind = fi.last_fault_type;
            }
        }
        FaultState::Faulted | FaultState::Recovering => {
            rec.modules_recovering += 1;
        }
        FaultState::Running => {
            if sched.finished[idx] {
                rec.modules_finished += 1;
            }
        }
    }
}

/// Is a draining owner's subgraph quiescent? Two structural
/// conditions:
///
/// * every module the owner stamps ran to its natural end (`StepOutcome::Done`)
///   or terminal fault state, and
/// * every graph channel touching an owned module is EMPTY — FIFO bytes and the
///   mailbox-mode branch both (`channel_has_pending` covers the pending frame
///   the byte-count accessor reports as 0).
///
/// Remaining narrowing: owner-timer/latched-wake emptiness arrives with the
/// full admission-gate build-out; a steady-state module that never finishes
/// drains by deadline, which is correct and observable. An owner stamping no
/// modules is trivially quiescent. Scheduler thread only.
pub fn owner_modules_quiescent(handle: OwnerHandle) -> bool {
    // SAFETY: scheduler-thread read of the static module/fault/edge tables.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    let mut owned = ModuleMask::new();
    for idx in 0..module_slots() {
        if module_owner(idx) != handle {
            continue;
        }
        owned.set(idx);
        if matches!(sched.modules[idx], ModuleSlot::Empty) {
            continue;
        }
        let terminal = matches!(sched.fault_info[idx].state, FaultState::Terminated);
        if !sched.finished[idx] && !terminal {
            return false;
        }
    }
    // In-flight frames: revoking now would drop a queued input; wait for the
    // pipeline to run dry (the deadline bounds a pipeline that never does).
    for edge in sched.edges.iter().take(sched.edge_count) {
        let touches_owner = (edge.from_module < module_slots() && owned.test(edge.from_module))
            || (edge.to_module < module_slots() && owned.test(edge.to_module));
        if touches_owner && crate::kernel::ipc::channel::channel_has_pending(edge.channel) {
            return false;
        }
    }
    true
}

/// Owner of the module that PRODUCES into channel `ch` — the carried-
/// attribution source for provider modules that serve multiple owners over
/// per-edge lanes (`linux_net` stamps each bind
/// with its commanding lane's owner). `OWNER_NODE` when no edge produces
/// into the channel or the producer is node-owned. Scheduler thread only,
/// resolved at instantiation (after plan apply) and re-resolved on rebuild.
pub fn channel_producer_owner(ch: i32) -> OwnerHandle {
    if ch < 0 {
        return crate::kernel::workload::owner::OWNER_NODE;
    }
    // SAFETY: scheduler-thread read of the static edge table.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    for edge in sched.edges.iter().take(sched.edge_count) {
        if edge.channel == ch && edge.from_module < module_slots() {
            return module_owner(edge.from_module);
        }
    }
    crate::kernel::workload::owner::OWNER_NODE
}

/// `channel::FACTS` for `caller`: the owner slot of the module that writes
/// channel `ch` and the channel's edge flags (`facts::RETAINS_SEND` when
/// the edge it is carries it), or `None` when `caller` is not an end of it.
pub fn channel_facts(ch: i32, caller: usize) -> Option<(u16, u8)> {
    use crate::abi::kernel_abi::channel::facts;
    if ch < 0 {
        return None;
    }
    // SAFETY: scheduler-thread read of the static edge table.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    let edge = sched.edges.iter().take(sched.edge_count).find(|e| {
        (e.channel == ch || e.consumer_channel == ch)
            && (e.from_module == caller || e.to_module == caller)
    })?;
    let flags = if edge.retains_send {
        facts::RETAINS_SEND
    } else {
        0
    };
    Some((channel_producer_owner(edge.channel).slot, flags))
}

/// Owner attribution for a module: `(owner_uid, slot, generation)`, or `None` if
/// the module is node-owned or its owner stamp is stale (slot reused at a
/// newer generation): a stale stamp attributes to nobody. Used by
/// the Linux log tee to attribute an on-step log record to its owner. Scheduler
/// thread only.
pub fn module_owner_attribution(module_idx: usize) -> Option<([u8; 16], u16, u32)> {
    let handle = module_owner(module_idx);
    if handle.is_node() {
        return None;
    }
    // SAFETY: scheduler-thread read of the static owner table.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    let e = sched.owners.entry_at(handle.slot as usize)?;
    if e.generation != handle.generation {
        return None; // stale stamp: module belongs to the slot's previous owner
    }
    Some((e.owner_uid, handle.slot, handle.generation))
}

/// Test-only: force module `idx`'s fault state so status-aggregation tests
/// can stage `Terminated`/`Recovering` modules without driving the full
/// step-guard fault path (which requires a running step loop).
#[doc(hidden)]
pub fn force_module_fault_state_for_test(module_idx: usize, state: FaultState, fault_kind: u8) {
    if module_idx >= module_slots() {
        return;
    }
    // SAFETY: single-threaded test context; module_idx bounded.
    unsafe {
        let p = &raw mut SCHED;
        (&mut (*p).fault_info)[module_idx].state = state;
        (&mut (*p).fault_info)[module_idx].last_fault_type = fault_kind;
    }
}

/// Test-only: force module `idx`'s `finished` flag (StepOutcome::Done).
#[doc(hidden)]
pub fn force_module_finished_for_test(module_idx: usize, finished: bool) {
    if module_idx >= module_slots() {
        return;
    }
    // SAFETY: single-threaded test context; module_idx bounded.
    unsafe {
        let p = &raw mut SCHED;
        (&mut (*p).finished)[module_idx] = finished;
    }
}

/// Request a graph rebuild from the boot configuration. The per-platform
/// domain loop consumes the request after its pass returns.
pub fn request_rebuild() {
    // SAFETY: scheduler-thread mutation; the domain loop consumes the request
    // before it re-enters `prepare_graph`.
    unsafe {
        let p = &raw mut SCHED;
        (*p).rebuild_request = true;
    }
}

/// Consume the pending rebuild request: whether one was made.
pub fn take_rebuild_request() -> bool {
    // SAFETY: scheduler-thread mutation; single consumer (domain loop).
    unsafe {
        let p = &raw mut SCHED;
        core::mem::take(&mut (*p).rebuild_request)
    }
}

/// Tear down a single module: take its memory (state buffer, heap arena,
/// elastic chunks and, on a protection-unit target, its private region) back
/// to the loader, drop its isolation region, and clear its slot, port
/// assignments, hints, drain flags and finished state so the slot can be
/// reused.
///
/// The caller has already released what the module registered or opened
/// (`release_module_handles`) and unspliced it from the execution order. A
/// module whose lent memory is still borrowed is **quarantined**: its memory
/// and slot are kept until every borrow is returned (see `ipc::lend`), and
/// everything else is torn down at once.
pub fn free_module_state(module_idx: usize) {
    if module_idx >= module_slots() {
        return;
    }
    // SAFETY: teardown context — the scheduler thread is the sole mutator.
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };

    // A gated module on an MPU target owns one private region — its stack,
    // state and heap — which goes back to the pool whole; its state and heap
    // are not freed on their own as well.
    #[cfg(feature = "kernel-mpu")]
    let private = crate::kernel::module::gateway::regions(module_idx)
        .filter(|(_, stack, p)| stack.len != 0 && p[0].base == stack.base)
        .map(|(_, _, p)| (p[0].base as *mut u8, p[0].len));
    #[cfg(not(feature = "kernel-mpu"))]
    let private: Option<(*mut u8, usize)> = None;

    // The heap arena (from the manifest, if any) and the state buffer the
    // instance holds; a native instance releases what it built first.
    let arena = core::mem::replace(&mut sched.arenas[module_idx], ArenaInfo::empty());
    let state = sched.modules[module_idx].take_state_range();
    // An elastic heap records a null arena (its cap is what the owner was
    // charged) and owns the segments it carved; they go with the rest.
    let memory = crate::kernel::module::loader::ModuleMemory::new(
        state,
        (arena.ptr, arena.size as usize),
        private,
    )
    .with_heap(crate::kernel::mem::heap::detach_module_heap(module_idx));
    if crate::kernel::ipc::lend::lent_out(module_idx) {
        crate::kernel::ipc::lend::quarantine(module_idx, memory);
    } else {
        // Elastic-region chunks the module grew into: teardown IS the reclaim
        // path — release them before the slot is reused.
        crate::kernel::mem::elastic::reclaim_module(module_idx as ModuleId);
        // SAFETY: the module is unspliced and never stepped again, and no
        // provider holds a borrow of its memory.
        unsafe { memory.release() };
    }

    // A gated module's isolation region goes with it: its slot, tables and
    // stack, and every handle the gateway minted for it.
    if crate::kernel::module::gateway::is_registered(module_idx) {
        crate::kernel::sys::hal::protection_release_module(module_idx);
        crate::kernel::module::gateway::release(module_idx);
    }
    sched.protection[module_idx] = fluxor_contracts::isolation::Level::Privileged;
    sched.device_window[module_idx] = (0, 0);

    // Reset per-module scheduler bookkeeping so reuse is clean.
    sched.ports[module_idx] = ModulePorts::empty();
    sched.port_caps[module_idx] = PortCapacities::NONE;
    sched.finished[module_idx] = false;
    sched.ready[module_idx] = true;
    sched.deferred_ready[module_idx] = false;
    sched.mailbox_safe[module_idx] = false;
    sched.in_place_writer[module_idx] = false;
    sched.upstream_mask[module_idx] = ModuleMask::EMPTY;
    sched.starvation_suspect.clear(module_idx);
    sched.starvation_reported.clear(module_idx);
    sched.step_period[module_idx] = 0;
    sched.step_phase[module_idx] = 0;
    sched.module_next_due_us[module_idx] = 0;
    sched.module_code_base[module_idx] = 0;
    sched.module_code_size[module_idx] = 0;
}
