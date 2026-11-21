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
pub use fluxor_contracts::owner_plan::{Assignment, Lease, Plan, Revocation};

use crate::kernel::workload::owner::MAX_OWNERS;

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

/// The last successfully-applied plan, retained so a graph rebuild (which runs
/// `prepare_graph`, resetting every module to the node owner) can RE-apply it
/// without a fresh staged blob. `None` until the first plan is applied. A view
/// over the staged bytes, which live for the run ([`set_staged_plan`]).
static mut RETAINED_PLAN: Option<Plan<'static>> = None;

/// The staged bytes [`RETAINED_PLAN`] is a view over.
static mut RETAINED_BYTES: *const u8 = core::ptr::null();

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
    let p = unsafe { *core::ptr::addr_of!(RETAINED_BYTES) };
    (!p.is_null()).then_some(p)
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
        *core::ptr::addr_of_mut!(RETAINED_BYTES) = core::ptr::null();
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

/// Hand each of the retained plan's revocations to `f`. The platform uses
/// this at boot to synthesize drain-timeout-by-restart terminal records for
/// owners that were mid-drain when the previous process died — they are
/// absent from the assignment section, so nothing re-instantiates them; the
/// record is the only trace.
pub fn retained_revocations(mut f: impl FnMut(Revocation)) {
    let retained = &raw const RETAINED_PLAN;
    // SAFETY: scheduler-thread read.
    if let Some(plan) = unsafe { &*retained } {
        plan.revocations().for_each(&mut f);
    }
}

/// Bind-gate verdict for `(slot, generation, protocol, port)` against the
/// retained plan's lease grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseGate {
    /// No enforcement: no plan is retained, or the bind is an ephemeral port-0
    /// source. A retained plan that simply grants nothing still enforces — it
    /// refuses undeclared nonzero binds.
    Ungated,
    /// The bind matches a granted lease.
    Granted,
    /// The plan is lease-aware and no grant covers this bind.
    Refused,
}

/// Consult the retained plan's grants for a bind by owner `(slot, generation)`.
/// Scheduler thread only.
pub fn lease_gate(slot: u16, generation: u32, protocol: u8, port: u16) -> LeaseGate {
    // Port 0 is an ephemeral-source bind ("give me any port"), not an
    // endpoint claim: it exports nothing, can collide with nothing, and no
    // lease could name it. Gating it would break every module that opens an
    // outbound datagram endpoint (e.g. dns upstream forwarding) the moment
    // ANY admitted workload on the node declares an export. Admission
    // (Draining refusal) still applies upstream of this gate.
    if port == 0 {
        return LeaseGate::Ungated;
    }
    let retained = &raw const RETAINED_PLAN;
    // SAFETY: scheduler-thread read.
    let Some(plan) = (unsafe { (*retained).as_ref() }) else {
        return LeaseGate::Ungated;
    };
    // A retained plan is lease-aware; enforcement is mandatory. An owner may
    // bind only a nonzero port it was granted — every other nonzero bind is
    // refused, whether or not the plan grants any endpoints at all.
    if plan.leases().any(|l| {
        l.slot == slot && l.generation == generation && l.protocol == protocol && l.port == port
    }) {
        LeaseGate::Granted
    } else {
        LeaseGate::Refused
    }
}

/// One drain to arm: the platform converts `deadline_unix` to its own clock
/// and drives quiescence/deadline against it (the kernel never reads wall
/// clock).
#[derive(Clone, Copy)]
pub struct DrainArm {
    pub owner_uid: [u8; 16],
    pub slot: u16,
    pub generation: u32,
    pub grace_secs: u16,
    pub deadline_unix: u64,
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
/// Returns `Some(n)`, the drains handed to `arm` (0 when every revocation
/// names an already-gone owner), after consuming the staged plan and updating
/// the retained-plan bookkeeping — the caller must NOT rebuild.
/// Returns `None` — leaving the staged plan in place for the ordinary
/// `apply_staged` rebuild path — when there is no staged plan, no retained
/// plan (boot), a decode/rollback failure (the rebuild path reports it), or a
/// structural change.
pub fn try_apply_drain_delta(arm: impl FnMut(DrainArm)) -> Option<usize> {
    // Peek without consuming: an ineligible plan must stay staged for the
    // rebuild path.
    // SAFETY: scheduler-thread single accessor.
    let (ptr, len) = unsafe {
        let p = &raw const STAGED_PLAN;
        (*p)?
    };
    let retained_ptr = &raw const RETAINED_PLAN;
    // SAFETY: scheduler-thread single accessor.
    let retained = unsafe { (*retained_ptr).as_ref()? };

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
    // carried forward verbatim. The retained revocation is the only DURABLE
    // trace of the pending drain terminal — restart synthesis reads it
    // to report a drain forfeited by a process death — so a plan may drop it
    // only once the drain driver has freed the owner.
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
    let armed = arm_revocations(&plan, arm);

    let generation = plan.generation;
    // SAFETY: scheduler-thread single accessor; retain for rebuild re-apply.
    // Direct static assignment forms no reference.
    unsafe {
        LAST_APPLIED_GENERATION = generation;
        LAST_APPLIED_DIGEST = plan.digest;
        RETAINED_PLAN = Some(plan);
        *core::ptr::addr_of_mut!(RETAINED_BYTES) = ptr;
    }
    log::info!("[owner] drain delta applied: {armed} drains armed (gen {generation})");
    Some(armed)
}

/// `begin_drain` every still-installed owner named in `plan`'s revocation
/// section and hand each its drain arm; the count armed. An already-revoked /
/// never-installed owner is a no-op; `begin_drain` is idempotent for an
/// already-Draining owner, and the platform re-arms with the record's original
/// deadline, so a replayed record never resets the clock.
fn arm_revocations(plan: &Plan<'_>, mut arm: impl FnMut(DrainArm)) -> usize {
    let table = crate::kernel::exec::scheduler::owners_mut();
    let mut armed = 0;
    for rev in plan.revocations() {
        let handle = crate::kernel::workload::owner::OwnerHandle {
            slot: rev.assignment.slot,
            generation: rev.assignment.generation,
        };
        if table.lookup(handle).is_some() && table.begin_drain(handle) {
            arm(DrainArm {
                owner_uid: rev.assignment.owner_uid,
                slot: rev.assignment.slot,
                generation: rev.assignment.generation,
                grace_secs: rev.grace_secs,
                deadline_unix: rev.deadline_unix,
            });
            armed += 1;
        }
    }
    armed
}

/// Arm drains for the staged plan's revocations without consuming it or
/// requiring delta-eligibility. The structural rebuild path calls this: a plan
/// that adds or changes owners is not a pure-drain delta, but any owner it
/// revokes must still drain — `begin_drain` plus a terminal record — rather than
/// being dropped untracked by the rebuild's `reset_workloads`. The staged plan
/// stays in place for `apply_staged`; the arms handed to `arm` outlive the
/// table reset, so the drain driver finalises each freed owner. The count
/// armed.
pub fn arm_staged_revocation_drains(arm: impl FnMut(DrainArm)) -> usize {
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
    arm_revocations(&plan, arm)
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
        let retained = &raw const RETAINED_PLAN;
        // SAFETY: scheduler-thread (boot/rebuild) single accessor.
        return Ok(match unsafe { &*retained } {
            Some(plan) => apply(plan),
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
        *retained = Some(plan);
        *core::ptr::addr_of_mut!(RETAINED_BYTES) = ptr;
    }
    log::info!("[owner] applied staged plan: {n} owners (gen {generation})");
    Ok(n)
}
