//! Kernel-side decode + apply of the bounded binary device-graph plan. The
//! kernel consumes a validated, bounded binary plan; it parses no orchestrator
//! objects, OCI manifests or YAML.
//!
//! The plan's format and its one codec are `fluxor_contracts::owner_plan`
//! (FLXP), which the composer encodes with. Decoding is `no_std` and
//! allocation-free on every target: a decoded plan is a view over the bytes
//! it verified, its records read from them when asked. The codec fails closed
//! on bad magic, an unknown, repeated or missing section, a length overrun,
//! an over-cap count, or a digest mismatch; this module adds the checks that
//! need the running kernel (slot range, duplicate slot, module-range overlap
//! and bounds, rollback).
//!
//! `apply` installs each owner at its plan-assigned slot/generation and stamps
//! the owner onto its module range, so provider enforcement and per-owner
//! accounting hold for a composed multi-workload graph. Every module is the system
//! owner until a plan is applied.

use fluxor_contracts::owner_plan as codec;
pub use fluxor_contracts::owner_plan::{Assignment, Grant, Plan, Revocation};

use crate::abi::contracts::workload::owners;
use crate::kernel::workload::owner::{OwnerHandle, OwnerState, MAX_OWNERS};

/// At most one assignment per owner slot: the owner-slot range. A slot past
/// the live owner table is refused when the plan is validated.
pub const MAX_PLAN_ASSIGNMENTS: usize = MAX_OWNERS;

/// Why a staged plan was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanError {
    /// The codec refused the bytes (framing, limits, digest).
    Codec(codec::PlanError),
    /// A slot is the node owner's slot (0) or beyond the owner table.
    SlotOutOfRange,
    /// Two assignments claim the same owner slot.
    DuplicateSlot,
    /// Two assignments' module ranges overlap (both would own a module).
    OverlappingModules,
    /// A module range extends past the module table.
    ModuleRangeOutOfRange,
    /// The plan's generation is older than the last applied plan (rollback).
    GenerationRollback,
}

impl core::fmt::Display for PlanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Codec(e) => f.write_str(e.kind()),
            Self::SlotOutOfRange => {
                write!(f, "slot is the node owner's slot or past the owner table")
            }
            Self::DuplicateSlot => write!(f, "two assignments claim one slot"),
            Self::OverlappingModules => write!(f, "two assignments' module ranges overlap"),
            Self::ModuleRangeOutOfRange => write!(f, "module range past the module table"),
            Self::GenerationRollback => write!(f, "generation older than the last applied plan"),
        }
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use crate::kernel::security::crypto::sha256::Sha256;
    let mut h = Sha256::new();
    h.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Decode and verify a bounded binary plan. Fails closed on any inconsistency.
///
/// # Errors
/// The codec's refusal, or the first assignment that does not fit the
/// running owner and module tables.
pub fn decode(bytes: &[u8]) -> Result<Plan<'_>, PlanError> {
    let plan = codec::decode(bytes, MAX_PLAN_ASSIGNMENTS, sha256).map_err(PlanError::Codec)?;
    // Semantic validation: framing + digest prove the bytes are intact, not
    // that the plan is coherent. The kernel does not trust the composer's
    // promise of unique slots / non-overlapping ranges — a corrupt or hostile
    // plan is rejected here rather than applied (a partial apply would leave
    // modules with stale handles or the node owner, silently disabling
    // isolation). Validate assignments AND revocations under one rule set: a
    // draining owner still occupies its slot and module range, so revocations
    // participate in the same duplicate/overlap checks.
    let records = || {
        plan.assignments()
            .chain(plan.revocations().map(|r| r.assignment))
    };
    for (i, a) in records().enumerate() {
        // Slot 0 is the node owner (reserved); slot must be a real workload
        // slot within the owner table.
        if a.slot == 0 || a.slot as usize >= crate::kernel::exec::scheduler::owners().slot_count() {
            return Err(PlanError::SlotOutOfRange);
        }
        // The module range must lie within the module table.
        let a_end = a.module_base as usize + a.module_count as usize;
        if a_end > crate::kernel::exec::scheduler::module_slots() {
            return Err(PlanError::ModuleRangeOutOfRange);
        }
        for prev in records().take(i) {
            if a.slot == prev.slot {
                return Err(PlanError::DuplicateSlot);
            }
            // Overlapping module ranges → two owners would claim the same module.
            let p_base = prev.module_base as usize;
            let p_end = p_base + prev.module_count as usize;
            if a.module_count > 0
                && prev.module_count > 0
                && (a.module_base as usize) < p_end
                && p_base < a_end
            {
                return Err(PlanError::OverlappingModules);
            }
        }
    }
    Ok(plan)
}

/// Apply a decoded plan to the running owner table: install each owner at its
/// plan-assigned slot/generation and stamp the owner onto its module range.
/// Returns the number of owners installed.
pub fn apply(plan: &Plan<'_>) -> usize {
    let table = crate::kernel::exec::scheduler::owners_mut();
    // The plan is authoritative for residency: revoke owners not re-installed
    // below so a removed workload's slot fails closed (generations preserved).
    table.reset_workloads();
    let mut installed = 0usize;
    for a in plan.assignments() {
        // Install with the plan's admitted caps (cap 0 = unlimited); per-owner
        // accounting is charged against these.
        if let Some(handle) =
            table.install(a.slot, a.generation, a.owner_uid, a.state_cap, a.buffer_cap)
        {
            installed += 1;
            // `install` reset the owner's log ring iff this is a genuinely
            // new owner on the slot; a same-triple reinstall (every routine
            // rebuild) keeps the ring and its seq counter.
            let base = a.module_base as usize;
            let end = base.saturating_add(a.module_count as usize);
            for idx in base..end {
                crate::kernel::exec::scheduler::set_module_owner(idx, handle);
            }
        }
    }
    // The owners the plan did not bring back are gone, and their rings.
    table.release_free_rings();
    // A revoked owner this kernel did not free by a drain — the reset just
    // dropped it mid-drain, or this kernel never held it — keeps the outcome
    // it already has or is recorded forfeited.
    for rev in plan.revocations() {
        let (slot, generation) = (rev.assignment.slot, rev.assignment.generation);
        let decided = table
            .entry_at(slot as usize)
            .is_some_and(|e| e.generation == generation && e.drain != owners::DRAIN_NONE);
        if !decided {
            table.record_drain(slot, generation, owners::DRAIN_FORFEITED, 0);
        }
    }
    installed
}

// ============================================================================
// Staged-plan delivery (node-agent stages a plan; the
// platform applies it BEFORE instantiation so module_new sees workload ownership,
// and RE-applies the retained plan on every rebuild since prepare_graph resets
// every module to the node owner)
// ============================================================================

/// Pending staged plan `(ptr, len)`, set by the node agent / platform before the
/// graph is instantiated and consumed once by `apply_staged`. Its bytes stay
/// valid for the run: the plan applied from them is retained as a view over
/// them.
static mut STAGED_PLAN: Option<(*const u8, usize)> = None;

/// Generation of the last successfully-applied plan; a staged plan older than
/// this is rejected as a rollback. 0 = none applied yet.
static mut LAST_APPLIED_GENERATION: u64 = 0;

/// Digest of the last successfully-applied plan: all zero until one is.
static mut LAST_APPLIED_DIGEST: [u8; 32] = [0; 32];

/// The bytes of the last successfully-applied plan, retained so a graph
/// rebuild (which runs `prepare_graph`, resetting every module to the node
/// owner) can RE-apply it without a fresh staged blob, and `OWNER_GRANTS`
/// can answer from it (`endpoints::owner_grants`). `None` until the first
/// plan is applied. The staged bytes live for the run ([`set_staged_plan`]);
/// the plan is read from them as a view ([`retained`]).
static mut RETAINED_PLAN: Option<(*const u8, usize)> = None;

/// The retained plan, as a view over its bytes. They were decoded, verified
/// and checked when the plan was applied, so the carried digest stands in
/// for hashing them again.
fn retained() -> Option<Plan<'static>> {
    // SAFETY: scheduler-thread read of a scalar pair.
    let (ptr, len) = unsafe { *core::ptr::addr_of!(RETAINED_PLAN) }?;
    // SAFETY: `set_staged_plan`'s caller keeps the bytes valid for the run.
    let bytes: &'static [u8] = unsafe { core::slice::from_raw_parts(ptr, len) };
    let carried: [u8; 32] = bytes.get(len.checked_sub(32)?..)?.try_into().ok()?;
    codec::decode(bytes, MAX_PLAN_ASSIGNMENTS, |_| carried).ok()
}

/// Generation of the last successfully-applied plan (0 = none yet). Lets the
/// platform's owner-status writer stamp which plan generation the live state
/// it reports came from.
pub fn last_applied_generation() -> u64 {
    let p = &raw const LAST_APPLIED_GENERATION;
    // SAFETY: scheduler-thread read (same access class as apply_staged).
    unsafe { *p }
}

/// Digest of the last successfully-applied plan (all zero = none yet), the
/// value its body hashed to when it was decoded. Lets the owner-status writer
/// say exactly which plan the live state it reports came from.
pub fn last_applied_digest() -> [u8; 32] {
    let p = &raw const LAST_APPLIED_DIGEST;
    // SAFETY: scheduler-thread read (same access class as apply_staged).
    unsafe { *p }
}

/// Stage a binary plan to be applied at the next `apply_staged`.
///
/// # Safety
/// `ptr..ptr+len` must remain valid and unchanged for the rest of the run: the
/// plan applied from it is retained, and read from these bytes on every
/// rebuild.
pub unsafe fn set_staged_plan(ptr: *const u8, len: usize) {
    let p = &raw mut STAGED_PLAN;
    *p = Some((ptr, len));
}

/// The bytes the retained (last applied) plan is a view over, so a platform
/// that owns its staged buffers keeps them while the kernel reads them.
pub fn retained_plan_bytes() -> Option<*const u8> {
    // SAFETY: scheduler-thread read of a scalar.
    unsafe { *core::ptr::addr_of!(RETAINED_PLAN) }.map(|(p, _)| p)
}

/// Test-only: clear all staged/retained plan state so a test starts from a
/// clean slate (the retained plan + last-applied generation are process-global).
#[doc(hidden)]
pub fn reset_staged_plan_for_test() {
    let sp = &raw mut STAGED_PLAN;
    let lg = &raw mut LAST_APPLIED_GENERATION;
    let ld = &raw mut LAST_APPLIED_DIGEST;
    let rp = &raw mut RETAINED_PLAN;
    // SAFETY: single-threaded test / scheduler-thread accessor.
    unsafe {
        *sp = None;
        *lg = 0;
        *ld = [0; 32];
        *rp = None;
    }
}

/// Consume the pending staged plan, if any.
fn take_staged_plan() -> Option<(*const u8, usize)> {
    // SAFETY: scheduler-thread (boot/rebuild) single consumer.
    unsafe {
        let p = &raw mut STAGED_PLAN;
        (*p).take()
    }
}

/// Owner `(slot, generation)`'s grant records in the retained plan, written
/// into `out` from 0: the bytes they take, which may exceed `out` (then only
/// the records that fit are written whole). 0 when no plan is retained: a
/// plan grants nothing it does not carry. Scheduler thread only.
pub fn plan_grants(slot: u16, generation: u32, out: &mut [u8]) -> usize {
    retained().map_or(0, |plan| plan.owner_grants(slot, generation, out))
}

/// Whether the retained plan grants `(kind, bytes)` to an owner other than
/// `(slot, generation)`. Scheduler thread only.
pub fn plan_grants_elsewhere(slot: u16, generation: u32, kind: u16, bytes: &[u8]) -> bool {
    retained().is_some_and(|plan| {
        plan.grants().any(|g| {
            (g.slot, g.generation) != (slot, generation) && g.kind == kind && g.bytes == bytes
        })
    })
}

/// Attempt to apply the staged plan as a **pure-drain delta** — the one plan
/// shape a removal generation produces: every staged assignment is
/// byte-identical to a retained one, every retained assignment either
/// survives or moved verbatim into the staged revocation section, and every
/// retained revocation whose owner is still installed is carried forward
/// verbatim. Then no rebuild is needed: co-resident owners are untouched,
/// and each newly revoked owner is flipped to `Draining` in place (admission
/// closes; its modules keep stepping until the platform's drain driver frees
/// it at quiescence or deadline).
///
/// Returns `Some(n)`, the drains begun (0 when every revocation names an
/// already-gone owner), after consuming the staged plan and updating the
/// retained-plan bookkeeping — the caller must NOT rebuild. [`drain_tick`]
/// frees each at quiescence or its deadline.
/// Returns `None` — leaving the staged plan in place for the ordinary
/// `apply_staged` rebuild path — when there is no staged plan, no retained
/// plan (boot), a decode/rollback failure (the rebuild path reports it), or a
/// structural change.
pub fn try_apply_drain_delta() -> Option<usize> {
    // Peek without consuming: an ineligible plan must stay staged for the
    // rebuild path.
    // SAFETY: scheduler-thread single accessor.
    let (ptr, len) = unsafe {
        let p = &raw const STAGED_PLAN;
        (*p)?
    };
    let retained = retained()?;

    // SAFETY: `set_staged_plan`'s caller upheld the validity contract: the
    // bytes live for the run.
    let bytes: &'static [u8] = unsafe { core::slice::from_raw_parts(ptr, len) };
    let Ok(plan) = decode(bytes) else {
        return None; // rebuild path surfaces the decode error
    };
    // SAFETY: scheduler-thread single accessor; scalar read by value.
    let last = unsafe { LAST_APPLIED_GENERATION };
    if plan.generation < last {
        return None; // rebuild path surfaces the rollback rejection
    }

    // Delta-eligible? Every staged assignment must exist verbatim in the
    // retained plan (no additions, no mutations)…
    for a in plan.assignments() {
        if !retained.assignments().any(|r| r == a) {
            return None;
        }
    }
    // …and every retained assignment either survives verbatim or departed into
    // the staged revocation section verbatim.
    for r in retained.assignments() {
        let survives = plan.assignments().any(|a| a == r);
        let revoked = plan.revocations().any(|rev| rev.assignment == r);
        if !survives && !revoked {
            return None;
        }
    }
    // …and every retained revocation whose owner is still installed must be
    // carried forward verbatim. The retained revocation states the drain's
    // deadline and keeps its outcome readable (`owners`), so a plan may drop
    // it only once [`drain_tick`] has freed the owner.
    {
        let table = crate::kernel::exec::scheduler::owners_mut();
        for rev in retained.revocations() {
            let handle = crate::kernel::workload::owner::OwnerHandle {
                slot: rev.assignment.slot,
                generation: rev.assignment.generation,
            };
            if table.lookup(handle).is_some() && !plan.revocations().any(|r| r == rev) {
                return None;
            }
        }
    }

    // Eligible: consume the staged plan and apply the delta in place.
    let _ = take_staged_plan();
    let armed = begin_revocation_drains(&plan);

    let generation = plan.generation;
    // SAFETY: scheduler-thread single accessor; retain for rebuild re-apply.
    // Direct static assignment forms no reference.
    unsafe {
        LAST_APPLIED_GENERATION = generation;
        LAST_APPLIED_DIGEST = plan.digest;
        RETAINED_PLAN = Some((ptr, len));
    }
    log::info!("[owner] drain delta applied: {armed} drains armed (gen {generation})");
    Some(armed)
}

/// `begin_drain` every still-installed owner named in `plan`'s revocation
/// section; the count begun. An already-revoked / never-installed owner is a
/// no-op, and `begin_drain` is idempotent for an already-Draining owner. The
/// deadline is the revocation's own, so a replayed record never resets the
/// clock.
fn begin_revocation_drains(plan: &Plan<'_>) -> usize {
    let table = crate::kernel::exec::scheduler::owners_mut();
    let mut begun = 0;
    for rev in plan.revocations() {
        let handle = OwnerHandle {
            slot: rev.assignment.slot,
            generation: rev.assignment.generation,
        };
        if table.lookup(handle).is_some() && table.begin_drain(handle) {
            begun += 1;
        }
    }
    begun
}

/// Begin drains for the staged plan's revocations without consuming it or
/// requiring delta-eligibility. The structural rebuild path calls this: a plan
/// that adds or changes owners is not a pure-drain delta, but any owner it
/// revokes stops admitting before the rebuild, whose apply then records it
/// forfeited (the rebuild's `reset_workloads` drops it). The staged plan
/// stays in place for `apply_staged`. The count begun.
pub fn begin_staged_revocation_drains() -> usize {
    // SAFETY: scheduler-thread single accessor; scalar read by value.
    let Some((ptr, len)) = (unsafe { STAGED_PLAN }) else {
        return 0;
    };
    // SAFETY: `set_staged_plan`'s caller upheld the validity contract.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    let Ok(plan) = decode(bytes) else {
        return 0;
    };
    // A rollback is rejected by the rebuild's `apply_staged`; do not arm drains
    // for a plan that will not be applied.
    // SAFETY: scheduler-thread single accessor; scalar read by value.
    let last = unsafe { LAST_APPLIED_GENERATION };
    if plan.generation < last {
        return 0;
    }
    begin_revocation_drains(&plan)
}

/// Drive every drain the retained plan's revocations state: an owner still
/// draining is freed (`scheduler::free_owner`: drain hooks, stop, unsplice,
/// close edges, reclaim, revoke) once every module it stamps ended and its
/// edges ran dry, or once `now_unix` reaches the revocation's
/// `deadline_unix`, and how it ended is recorded on its slot for
/// [`owners_answer`]. `now_unix` is the platform's wall clock: the kernel
/// keeps none. Returns how many owners were freed. Scheduler thread only.
pub fn drain_tick(now_unix: u64) -> usize {
    let Some(plan) = retained() else {
        return 0;
    };
    let mut freed = 0;
    for rev in plan.revocations() {
        let handle = OwnerHandle {
            slot: rev.assignment.slot,
            generation: rev.assignment.generation,
        };
        let draining = crate::kernel::exec::scheduler::owners()
            .lookup(handle)
            .is_some_and(|e| matches!(e.state, OwnerState::Draining));
        if !draining {
            continue;
        }
        let quiescent = crate::kernel::exec::scheduler::owner_modules_quiescent(handle);
        if !quiescent && now_unix < rev.deadline_unix {
            continue;
        }
        // `free_owner`'s release edge closes what the owner holds of the
        // platform before it returns, so a reader never sees the outcome
        // below while the owner still runs anything.
        if let Err(e) = crate::kernel::exec::scheduler::free_owner(handle) {
            log::warn!(
                "[drain] free_owner slot {} gen {}: {e:?}",
                handle.slot,
                handle.generation
            );
        }
        let outcome = if quiescent {
            owners::DRAIN_QUIESCED
        } else {
            owners::DRAIN_DEADLINE_PASSED
        };
        crate::kernel::exec::scheduler::owners_mut().record_drain(
            handle.slot,
            handle.generation,
            outcome,
            now_unix,
        );
        log::info!(
            "[drain] owner slot {} gen {} revoked ({})",
            handle.slot,
            handle.generation,
            if quiescent {
                "quiesced"
            } else {
                "deadline exceeded"
            }
        );
        freed += 1;
    }
    freed
}

/// `workload::OWNERS`: the node's owner facts into `out` — every workload
/// owner the table holds, then every freed owner whose revocation the
/// retained plan still lists, by slot (`workload::owners` has the layout).
/// Returns the answer's length, `ERANGE` when `out` cannot hold it.
/// Scheduler thread only.
pub fn owners_answer(out: &mut [u8]) -> i32 {
    use crate::kernel::sys::errno;
    let plan = retained();
    let revocation_of = |slot: u16, generation: u32| {
        plan.as_ref().and_then(|p| {
            p.revocations()
                .find(|r| r.assignment.slot == slot && r.assignment.generation == generation)
        })
    };
    let table = crate::kernel::exec::scheduler::owners();
    let mut count: usize = 0;
    let mut at = owners::HEADER_LEN;
    for slot in 1..table.slot_count() {
        let Some(e) = table.entry_at(slot) else {
            continue;
        };
        let handle = OwnerHandle {
            slot: slot as u16,
            generation: e.generation,
        };
        let rev = revocation_of(handle.slot, handle.generation);
        let mut rec = owners::Record {
            uid: e.owner_uid,
            slot: handle.slot,
            generation: e.generation,
            activations: e.activations,
            drain: e.drain,
            drained_at: e.drained_at,
            drain_deadline: rev.map_or(0, |r| r.deadline_unix),
            ..owners::Record::default()
        };
        match crate::kernel::exec::scheduler::owner_live_status(handle) {
            Some(live) => {
                rec.state = match e.state {
                    OwnerState::Draining => owners::STATE_DRAINING,
                    OwnerState::Paused => owners::STATE_PAUSED,
                    _ => owners::STATE_ACTIVE,
                };
                rec.modules = live.modules_total;
                rec.loaded = live.modules_loaded;
                rec.finished = live.modules_finished;
                rec.terminated = live.modules_terminated;
                rec.recovering = live.modules_recovering;
                rec.fault_kind = live.last_fault_kind;
                rec.fault_ms = live.last_fault_ms;
            }
            None => {
                // Freed: listed while the plan lists its revocation.
                let Some(r) = rev else {
                    continue;
                };
                if e.drain == owners::DRAIN_NONE {
                    continue;
                }
                rec.state = owners::STATE_GONE;
                rec.uid = r.assignment.owner_uid;
            }
        }
        if let Some(b) = out.get_mut(at..at + owners::RECORD_LEN) {
            rec.write(b);
        }
        count += 1;
        at += owners::RECORD_LEN;
    }
    let need = owners::HEADER_LEN + count * owners::RECORD_LEN;
    if out.len() < need {
        return errno::ERANGE;
    }
    owners::write_head(
        out,
        count as u16,
        last_applied_generation(),
        &last_applied_digest(),
    );
    need as i32
}

/// Establish plan ownership for the graph. Called by the platform BEFORE module
/// instantiation (so `module_new`'s provider handles are recorded under the
/// module's workload owner, not the node owner) and again on every rebuild.
///
/// - A newly-staged plan (a plan-file update) is decoded, validated,
///   rollback-checked, applied, and RETAINED.
/// - With no newly-staged plan but a retained one, it is RE-applied: a rebuild
///   ran `prepare_graph`, which reset every module to the node owner, so
///   isolation must be re-established. An ordinary rebuild must NOT drop
///   ownership.
/// - With nothing ever staged, returns `Ok(0)` — the legitimate no-plan case.
///
/// Returns `Err` only when a staged plan is invalid. The platform MUST fail
/// closed on `Err`: a corrupt/rolled-back plan must reject the graph, never fall
/// back to running it node-owned, which would silently disable multi-owner
/// enforcement.
pub fn apply_staged() -> Result<usize, PlanError> {
    let Some((ptr, len)) = take_staged_plan() else {
        // No newly-staged plan: re-apply the retained one so a rebuild does not
        // drop isolation (prepare_graph reset ownership). None ⇒ no plan ever.
        return Ok(match retained() {
            Some(plan) => apply(&plan),
            None => 0,
        });
    };
    // SAFETY: caller of `set_staged_plan` upheld the validity contract: the
    // bytes live for the run.
    let bytes: &'static [u8] = unsafe { core::slice::from_raw_parts(ptr, len) };
    let plan = decode(bytes).inspect_err(|e| {
        log::error!("[owner] staged plan invalid: {e}");
    })?;
    // Reject a rollback to an older plan generation. Re-applying the SAME
    // generation is allowed (idempotent rebuild); only a strictly-older plan is
    // a rollback.
    let last_ptr = &raw const LAST_APPLIED_GENERATION;
    // SAFETY: scheduler-thread (boot/rebuild) single accessor.
    let last = unsafe { *last_ptr };
    if plan.generation < last {
        log::error!(
            "[owner] staged plan generation {} < last applied {last}; rejected",
            plan.generation
        );
        return Err(PlanError::GenerationRollback);
    }
    let generation = plan.generation;
    let n = apply(&plan);
    let last_mut = &raw mut LAST_APPLIED_GENERATION;
    let digest_mut = &raw mut LAST_APPLIED_DIGEST;
    let retained = &raw mut RETAINED_PLAN;
    // SAFETY: scheduler-thread single accessor. Retain the plan for rebuild
    // re-application.
    unsafe {
        *last_mut = generation;
        *digest_mut = plan.digest;
        *retained = Some((ptr, len));
    }
    log::info!("[owner] applied staged plan: {n} owners (gen {generation})");
    Ok(n)
}
