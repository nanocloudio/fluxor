//! Scheduler responsibility module (real module boundary; parent statics and
//! helpers reach us via `super`).
#![allow(
    unused_imports,
    reason = "the flat scheduler namespace is glob-imported; each module uses a subset"
)]
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

/// Owner handle stamped on module `module_idx`. On single-tenant builds there
/// is no per-module owner array; every module is the system owner.
#[inline]
pub fn module_owner(module_idx: usize) -> OwnerHandle {
    #[cfg(feature = "multitenant")]
    {
        if module_idx >= MAX_MODULES {
            return OWNER_SYSTEM;
        }
        // SAFETY: scheduler-thread read; module_idx bounded above.
        unsafe { SCHED.module_owner[module_idx] }
    }
    #[cfg(not(feature = "multitenant"))]
    {
        let _ = module_idx;
        OWNER_SYSTEM
    }
}

/// Stamp module `module_idx` with `owner`. No-op on single-tenant builds.
#[inline]
pub fn set_module_owner(module_idx: usize, owner: OwnerHandle) {
    #[cfg(feature = "multitenant")]
    {
        if module_idx < MAX_MODULES {
            // SAFETY: scheduler-thread-exclusive mutation; module_idx bounded.
            unsafe {
                SCHED.module_owner[module_idx] = owner;
            }
        }
    }
    #[cfg(not(feature = "multitenant"))]
    {
        let _ = (module_idx, owner);
    }
}

/// Authorize `caller` to touch a resource owned by module `target_idx`. Returns
/// true when the target is system-owned or the same owner (rfc_k8s.md §14).
/// Compile-time `true` on single-tenant builds.
#[inline]
pub fn authorize_module_access(caller: OwnerHandle, target_idx: usize) -> bool {
    crate::kernel::workload::owner::same_or_system(caller, module_owner(target_idx))
}

/// Owner of the currently-executing module (the syscall caller). On
/// single-tenant builds this is always the system owner.
#[inline]
pub fn caller_owner() -> OwnerHandle {
    module_owner(current_module_index())
}

/// Whether module N has returned StepOutcome::Done.
pub fn module_is_finished(module_idx: usize) -> bool {
    if module_idx >= MAX_MODULES {
        return false;
    }
    // SAFETY: scheduler-thread read; module_idx bounded.
    unsafe { SCHED.finished[module_idx] }
}

/// One resident owner's live runtime aggregate: the per-MODULE fault/finish
/// state of its plan-assigned module range folded into per-owner counts
/// (rfc_k8s.md §18.2 — "a Fluxor owner-status store keyed by owner UID"). This
/// is the kernel half of the per-workload status surface: only the kernel knows
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
    /// Owner lifecycle state: [`OWNER_STATE_ACTIVE`] or [`OWNER_STATE_DRAINING`]
    /// (rfc_owner_drain_and_logs.md §3.7). `Active` until the drain driver flips
    /// it.
    pub owner_state: u8,
    /// Wall-clock second at which a drain forfeits its grace, or 0 when not
    /// draining. Set by the drain driver.
    pub drain_deadline_unix: u64,
    /// Seconds remaining in the drain window, or 0 when not draining.
    pub drain_remaining_secs: u32,
}

/// `owner_state` code: the owner is running normally.
pub const OWNER_STATE_ACTIVE: u8 = 0;
/// `owner_state` code: the owner is draining before revocation.
pub const OWNER_STATE_DRAINING: u8 = 1;
/// `owner_state` code: the owner is paused (reversible quiesce,
/// rfc_workload_lifecycle.md §3.2). Not terminal; `owner_resume` returns
/// it to [`OWNER_STATE_ACTIVE`].
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
        owner_state: OWNER_STATE_ACTIVE,
        drain_deadline_unix: 0,
        drain_remaining_secs: 0,
    };
}

/// Snapshot the live per-owner runtime status: every non-free workload slot,
/// with the fault/finish state of its stamped module range aggregated in.
/// Writes into `out` and returns the record count. Allocation-free;
/// scheduler-thread only (same access class as `module_fault_state`).
///
/// On single-tenant builds (`MAX_OWNERS == 1`) there are no workload slots
/// and this always returns 0.
pub fn owner_live_snapshot(out: &mut [OwnerLiveStatus; MAX_OWNERS]) -> usize {
    // SAFETY: scheduler-thread read of the static owner table + fault state.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    let mut count = 0usize;
    // Empty range on single-tenant (MAX_OWNERS == 1) builds — returns 0, per the doc above.
    #[allow(
        clippy::reversed_empty_ranges,
        reason = "empty by design when MAX_OWNERS == 1 (single-tenant)"
    )]
    for slot in 1..MAX_OWNERS {
        let Some(e) = sched.owners.entry_at(slot) else {
            continue;
        };
        if matches!(e.state, crate::kernel::workload::owner::OwnerState::Free) {
            continue;
        }
        let owner_state = match e.state {
            crate::kernel::workload::owner::OwnerState::Draining => OWNER_STATE_DRAINING,
            crate::kernel::workload::owner::OwnerState::Paused => OWNER_STATE_PAUSED,
            _ => OWNER_STATE_ACTIVE,
        };
        out[count] = OwnerLiveStatus {
            owner_uid: e.owner_uid,
            slot: slot as u16,
            generation: e.generation,
            owner_state,
            ..OwnerLiveStatus::EMPTY
        };
        count += 1;
    }
    // Fold each module's state into its owning record. A stale stamp (owner
    // slot reused at a newer generation) attributes to nobody — the module
    // belongs to the previous occupant, not the current one.
    let mut last_fault_ms = [0u64; MAX_OWNERS];
    for idx in 0..MAX_MODULES {
        let owner = module_owner(idx);
        if owner.is_system() {
            continue;
        }
        let Some(pos) = out[..count]
            .iter()
            .position(|r| r.slot == owner.slot && r.generation == owner.generation)
        else {
            continue;
        };
        let rec = &mut out[pos];
        rec.modules_total += 1;
        if !matches!(sched.modules[idx], ModuleSlot::Empty) {
            rec.modules_loaded += 1;
        }
        let fi = &sched.fault_info[idx];
        match fi.state {
            FaultState::Terminated => {
                rec.modules_terminated += 1;
                if fi.last_fault_ms >= last_fault_ms[pos] {
                    last_fault_ms[pos] = fi.last_fault_ms;
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
    count
}

/// Is a draining owner's subgraph quiescent (rfc_owner_drain_and_logs.md §3.1)?
/// Two structural conditions:
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
    let mut owned = [false; MAX_MODULES];
    for (idx, is_owned) in owned.iter_mut().enumerate() {
        if module_owner(idx) != handle {
            continue;
        }
        *is_owned = true;
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
        let touches_owner = (edge.from_module < MAX_MODULES && owned[edge.from_module])
            || (edge.to_module < MAX_MODULES && owned[edge.to_module]);
        if touches_owner && crate::kernel::ipc::channel::channel_has_pending(edge.channel) {
            return false;
        }
    }
    true
}

/// Owner of the module that PRODUCES into channel `ch` — the carried-
/// attribution source for provider modules that serve multiple owners over
/// per-edge lanes (rfc_endpoint_lease.md §4.1: `linux_net` stamps each bind
/// with its commanding lane's owner). `OWNER_SYSTEM` when no edge produces
/// into the channel or the producer is system-owned. Scheduler thread only,
/// resolved at instantiation (after plan apply) and re-resolved on rebuild.
pub fn channel_producer_owner(ch: i32) -> OwnerHandle {
    if ch < 0 {
        return crate::kernel::workload::owner::OWNER_SYSTEM;
    }
    // SAFETY: scheduler-thread read of the static edge table.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    for edge in sched.edges.iter().take(sched.edge_count) {
        if edge.channel == ch && edge.from_module < MAX_MODULES {
            return module_owner(edge.from_module);
        }
    }
    crate::kernel::workload::owner::OWNER_SYSTEM
}

/// Owner attribution for a module: `(owner_uid, slot, generation)`, or `None` if
/// the module is system-owned or its owner stamp is stale (slot reused at a
/// newer generation). Mirrors `owner_live_snapshot`'s stale-stamp rule. Used by
/// the Linux log tee to attribute an on-step log record to its owner. Scheduler
/// thread only.
pub fn module_owner_attribution(module_idx: usize) -> Option<([u8; 16], u16, u32)> {
    let handle = module_owner(module_idx);
    if handle.is_system() {
        return None;
    }
    // SAFETY: scheduler-thread read of the static owner table.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    let e = sched.owners.entry_at(handle.slot as usize)?;
    if e.generation != handle.generation {
        return None; // stale stamp: module belongs to the slot's previous tenant
    }
    Some((e.owner_uid, handle.slot, handle.generation))
}

/// Test-only: force module `idx`'s fault state so status-aggregation tests
/// can stage `Terminated`/`Recovering` modules without driving the full
/// step-guard fault path (which requires a running step loop).
#[doc(hidden)]
pub fn force_module_fault_state_for_test(module_idx: usize, state: FaultState, fault_kind: u8) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: single-threaded test context; module_idx bounded.
    unsafe {
        let p = &raw mut SCHED;
        (*p).fault_info[module_idx].state = state;
        (*p).fault_info[module_idx].last_fault_type = fault_kind;
    }
}

/// Test-only: force module `idx`'s slot occupied (Dummy) or empty, so
/// status-aggregation tests can stage loaded vs failed-instantiate modules.
#[doc(hidden)]
pub fn force_module_loaded_for_test(module_idx: usize, loaded: bool) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: single-threaded test context; module_idx bounded.
    unsafe {
        let p = &raw mut SCHED;
        (*p).modules[module_idx] = if loaded {
            ModuleSlot::Dummy(DummyModule)
        } else {
            ModuleSlot::Empty
        };
    }
}

/// Test-only: force module `idx`'s `finished` flag (StepOutcome::Done).
#[doc(hidden)]
pub fn force_module_finished_for_test(module_idx: usize, finished: bool) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: single-threaded test context; module_idx bounded.
    unsafe {
        let p = &raw mut SCHED;
        (*p).finished[module_idx] = finished;
    }
}

/// Request a graph rebuild. The per-platform main loop consumes the request
/// after `step_modules` returns.
///
/// # Safety
/// The caller must ensure `config_ptr..config_ptr+config_len` remains valid
/// until the main loop consumes the request. A null pointer with zero length
/// signals "reload current STATIC_CONFIG".
pub unsafe fn request_rebuild(config_ptr: *const u8, config_len: usize) {
    // SAFETY: caller upholds `# Safety` invariant (pointer validity); the
    // request is consumed before the main loop re-enters `prepare_graph`.
    unsafe {
        let p = &raw mut SCHED;
        (*p).rebuild_request = Some((config_ptr, config_len));
    }
}

/// Consume the pending rebuild request, if any.
pub fn take_rebuild_request() -> Option<(*const u8, usize)> {
    // SAFETY: scheduler-thread mutation; single consumer (main loop).
    unsafe {
        let p = &raw mut SCHED;
        (*p).rebuild_request.take()
    }
}

/// Tear down a single module: release its module heap arena, then its
/// state buffer, back to the loader pool. Clears the slot, port
/// assignments, hints, drain flags, and finished state so the slot can
/// be reused.
///
/// Intended for use by the graph-rebuild path when only some modules
/// need to be replaced. Not called by the atomic reconfigure path,
/// which uses `reset_state_arena` to drop everything at once.
pub fn free_module_state(module_idx: usize) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: graph-rebuild context — scheduler thread is the sole mutator.
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };

    // Elastic-region chunks the module grew into (`rfc_resource_model.md`
    // §3.6): teardown IS the reclaim path — release them before the slot
    // is reused.
    crate::kernel::mem::elastic::reclaim_module(module_idx as u8);

    // Heap arena (from module_arena_size export, if any).
    let arena = sched.arenas[module_idx];
    if !arena.ptr.is_null() && arena.size > 0 {
        // SAFETY: `(arena.ptr, arena.size)` was returned by
        // `loader::alloc_state(size)` during instantiation.
        unsafe {
            crate::kernel::module::loader::free_state_range(arena.ptr, arena.size as usize);
        }
    }
    sched.arenas[module_idx] = ArenaInfo::empty();

    // State buffer lives inside the DynamicModule; consume the slot.
    let slot = core::mem::replace(&mut sched.modules[module_idx], ModuleSlot::Empty);
    if let ModuleSlot::Dynamic(m) = slot {
        // SAFETY: `m` is the just-replaced slot; no other reference is live.
        unsafe {
            m.free();
        }
    }

    // Reset per-module scheduler bookkeeping so reuse is clean.
    sched.ports[module_idx] = ModulePorts::empty();
    sched.hints[module_idx] = ModuleHints::empty();
    sched.finished[module_idx] = false;
    sched.ready[module_idx] = true;
    sched.deferred_ready[module_idx] = false;
    sched.mailbox_safe[module_idx] = false;
    sched.in_place_writer[module_idx] = false;
    sched.upstream_mask[module_idx] = ModuleMask::EMPTY;
    sched.step_period[module_idx] = 0;
    sched.step_counter[module_idx] = 0;
    sched.module_code_base[module_idx] = 0;
    sched.module_code_size[module_idx] = 0;
    sched.module_export_table[module_idx] = core::ptr::null();
    sched.module_export_count[module_idx] = 0;
}
