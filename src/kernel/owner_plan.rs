//! Kernel-side decode + apply of the bounded binary device-graph plan
//! (rfc_k8s.md §11: "the kernel consumes a validated bounded binary plan; it
//! does not parse Kubernetes objects, OCI manifests, or arbitrary YAML").
//!
//! This is the kernel half of the host composer's wire format
//! (`tools/src/compose.rs::encode_plan`). The two MUST stay in lockstep: same
//! magic, version, and fixed-width record layout. Decoding is `no_std` and
//! allocation-free — assignments land in a fixed array bounded by the owner
//! table — and fails closed on bad magic/version, length overrun, over-cap
//! count, or digest mismatch.
//!
//! `apply` installs each owner at its plan-assigned slot/generation and stamps
//! the owner onto its module range, so provider enforcement and per-owner
//! accounting hold for a composed multi-Pod graph. Every module is the system
//! owner until a plan is applied.

use sha2::{Digest, Sha256};

use crate::kernel::owner::MAX_OWNERS;

/// Plan magic: "FLXP". Matches `tools/src/compose.rs::PLAN_MAGIC`.
const PLAN_MAGIC: u32 = 0x464C_5850;
/// On-wire plan format version.
const PLAN_VERSION: u16 = 1;
/// Header: magic(4) + version(2) + reserved(2).
const PLAN_HEADER_LEN: usize = 8;
/// Per-assignment record: pod_uid(16)+slot(2)+gen(4)+mod_base(2)+mod_count(2)
/// +edge_base(2)+edge_count(2).
const ASSIGN_REC_LEN: usize = 16 + 2 + 4 + 2 + 2 + 2 + 2 + 4 + 4;
/// At most one assignment per owner slot.
pub const MAX_PLAN_ASSIGNMENTS: usize = MAX_OWNERS;

/// One decoded owner placement.
#[derive(Clone, Copy)]
pub struct PlanAssignment {
    pub pod_uid: [u8; 16],
    pub slot: u16,
    pub generation: u32,
    pub module_base: u16,
    pub module_count: u16,
    pub edge_base: u16,
    pub edge_count: u16,
    pub state_cap: u32,
    pub buffer_cap: u32,
}

impl PlanAssignment {
    const EMPTY: PlanAssignment = PlanAssignment {
        pod_uid: [0; 16],
        slot: 0,
        generation: 0,
        module_base: 0,
        module_count: 0,
        edge_base: 0,
        edge_count: 0,
        state_cap: 0,
        buffer_cap: 0,
    };
}

/// A decoded, digest-verified plan. Allocation-free.
pub struct DecodedPlan {
    pub generation: u64,
    count: usize,
    assignments: [PlanAssignment; MAX_PLAN_ASSIGNMENTS],
}

impl DecodedPlan {
    /// The valid assignment slice.
    pub fn assignments(&self) -> &[PlanAssignment] {
        &self.assignments[..self.count]
    }
}

/// Why decoding a binary plan failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanError {
    BadMagic,
    BadVersion,
    Truncated,
    TooManyAssignments,
    DigestMismatch,
    TrailingBytes,
    /// A slot is the system slot (0) or beyond the owner table.
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

fn be_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn be_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[0..8]);
    u64::from_be_bytes(a)
}

/// Decode and verify a bounded binary plan. Fails closed on any inconsistency.
pub fn decode(bytes: &[u8]) -> Result<DecodedPlan, PlanError> {
    if bytes.len() < PLAN_HEADER_LEN + 12 + 32 {
        return Err(PlanError::Truncated);
    }
    if be_u32(&bytes[0..4]) != PLAN_MAGIC {
        return Err(PlanError::BadMagic);
    }
    if be_u16(&bytes[4..6]) != PLAN_VERSION {
        return Err(PlanError::BadVersion);
    }
    let body = &bytes[PLAN_HEADER_LEN..];
    let generation = be_u64(&body[0..8]);
    let count = be_u32(&body[8..12]) as usize;
    if count > MAX_PLAN_ASSIGNMENTS {
        return Err(PlanError::TooManyAssignments);
    }
    let body_len = 12 + count * ASSIGN_REC_LEN;
    let expected_total = PLAN_HEADER_LEN + body_len + 32;
    if bytes.len() < expected_total {
        return Err(PlanError::Truncated);
    }
    if bytes.len() > expected_total {
        return Err(PlanError::TrailingBytes);
    }
    // Verify the digest over the body before trusting any field.
    let mut hasher = Sha256::new();
    hasher.update(&body[..body_len]);
    let computed = hasher.finalize();
    if computed.as_slice() != &bytes[PLAN_HEADER_LEN + body_len..] {
        return Err(PlanError::DigestMismatch);
    }
    let mut assignments = [PlanAssignment::EMPTY; MAX_PLAN_ASSIGNMENTS];
    for (i, a) in assignments.iter_mut().enumerate().take(count) {
        let r = &body[12 + i * ASSIGN_REC_LEN..12 + (i + 1) * ASSIGN_REC_LEN];
        let mut pod_uid = [0u8; 16];
        pod_uid.copy_from_slice(&r[0..16]);
        *a = PlanAssignment {
            pod_uid,
            slot: be_u16(&r[16..18]),
            generation: be_u32(&r[18..22]),
            module_base: be_u16(&r[22..24]),
            module_count: be_u16(&r[24..26]),
            edge_base: be_u16(&r[26..28]),
            edge_count: be_u16(&r[28..30]),
            state_cap: be_u32(&r[30..34]),
            buffer_cap: be_u32(&r[34..38]),
        };
    }
    // Semantic validation: framing + digest prove the bytes are intact, not that
    // the plan is coherent. The kernel does not trust the composer's promise of
    // unique slots / non-overlapping ranges — a corrupt or hostile plan is
    // rejected here rather than applied (a partial apply would leave modules with
    // stale handles or the system owner, silently disabling isolation).
    for i in 0..count {
        let a = &assignments[i];
        // Slot 0 is the system owner (reserved); slot must be a real workload
        // slot within the owner table.
        if a.slot == 0 || a.slot as usize >= MAX_OWNERS {
            return Err(PlanError::SlotOutOfRange);
        }
        // The module range must lie within the module table.
        let a_end = a.module_base as usize + a.module_count as usize;
        if a_end > crate::kernel::scheduler::MAX_MODULES {
            return Err(PlanError::ModuleRangeOutOfRange);
        }
        for a_prev in assignments.iter().take(i) {
            if a.slot == a_prev.slot {
                return Err(PlanError::DuplicateSlot);
            }
            // Overlapping module ranges → two owners would claim the same module.
            let p_base = a_prev.module_base as usize;
            let p_end = p_base + a_prev.module_count as usize;
            if a.module_count > 0
                && a_prev.module_count > 0
                && (a.module_base as usize) < p_end
                && p_base < a_end
            {
                return Err(PlanError::OverlappingModules);
            }
        }
    }
    Ok(DecodedPlan {
        generation,
        count,
        assignments,
    })
}

/// Apply a decoded plan to the running owner table: install each owner at its
/// plan-assigned slot/generation and stamp the owner onto its module range.
/// Returns the number of owners installed. On single-tenant builds the install
/// is a no-op (only the system slot exists), so this is inert there.
pub fn apply(plan: &DecodedPlan) -> usize {
    let table = crate::kernel::scheduler::owners_mut();
    // The plan is authoritative for residency: revoke owners not re-installed
    // below so a removed pod's slot fails closed (generations preserved).
    table.reset_workloads();
    let mut installed = 0usize;
    for a in plan.assignments() {
        // Install with the plan's admitted caps (cap 0 = unlimited); per-owner
        // accounting is charged against these.
        if let Some(handle) =
            table.install(a.slot, a.generation, a.pod_uid, a.state_cap, a.buffer_cap)
        {
            installed += 1;
            let base = a.module_base as usize;
            let end = base.saturating_add(a.module_count as usize);
            for idx in base..end {
                crate::kernel::scheduler::set_module_owner(idx, handle);
            }
        }
    }
    installed
}

// ============================================================================
// Staged-plan delivery (rfc_k8s.md §11, §12 — node-agent stages a plan; the
// platform applies it BEFORE instantiation so module_new sees tenant ownership,
// and RE-applies the retained plan on every rebuild since prepare_graph resets
// every module to the system owner)
// ============================================================================

/// Pending staged plan `(ptr, len)`, set by the node agent / platform before the
/// graph is instantiated and consumed once by `apply_staged`.
static mut STAGED_PLAN: Option<(*const u8, usize)> = None;

/// Generation of the last successfully-applied plan; a staged plan older than
/// this is rejected as a rollback. 0 = none applied yet.
static mut LAST_APPLIED_GENERATION: u64 = 0;

/// The last successfully-applied plan, retained so a graph rebuild (which runs
/// `prepare_graph`, resetting every module to the system owner) can RE-apply it
/// without a fresh staged blob. `None` until the first plan is applied.
static mut RETAINED_PLAN: Option<DecodedPlan> = None;

/// Generation of the last successfully-applied plan (0 = none yet). Lets the
/// platform's owner-status writer stamp which plan generation the live state
/// it reports came from (rfc_k8s.md §17.2 join key).
pub fn last_applied_generation() -> u64 {
    let p = &raw const LAST_APPLIED_GENERATION;
    // SAFETY: scheduler-thread read (same access class as apply_staged).
    unsafe { *p }
}

/// Stage a binary plan to be applied at the next `apply_staged`.
///
/// # Safety
/// `ptr..ptr+len` must remain valid until `apply_staged` consumes it (i.e. until
/// just after module instantiation in the platform boot/rebuild path).
pub unsafe fn set_staged_plan(ptr: *const u8, len: usize) {
    let p = &raw mut STAGED_PLAN;
    *p = Some((ptr, len));
}

/// Test-only: clear all staged/retained plan state so a test starts from a
/// clean slate (the retained plan + last-applied generation are process-global).
#[doc(hidden)]
pub fn reset_staged_plan_for_test() {
    let sp = &raw mut STAGED_PLAN;
    let lg = &raw mut LAST_APPLIED_GENERATION;
    let rp = &raw mut RETAINED_PLAN;
    // SAFETY: single-threaded test / scheduler-thread accessor.
    unsafe {
        *sp = None;
        *lg = 0;
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

/// Establish plan ownership for the graph. Called by the platform BEFORE module
/// instantiation (so `module_new`'s provider handles are recorded under the
/// module's tenant owner, not the system owner) and again on every rebuild.
///
/// - A newly-staged plan (a plan-file update) is decoded, validated,
///   rollback-checked, applied, and RETAINED.
/// - With no newly-staged plan but a retained one, it is RE-applied: a rebuild
///   ran `prepare_graph`, which reset every module to the system owner, so
///   isolation must be re-established. An ordinary rebuild must NOT drop
///   ownership.
/// - With nothing ever staged, returns `Ok(0)` — the legitimate no-plan case.
///
/// Returns `Err` only when a staged plan is invalid. The platform MUST fail
/// closed on `Err`: a corrupt/rolled-back plan must reject the graph, never fall
/// back to running it system-owned, which would silently disable multi-tenant
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
    // SAFETY: caller of `set_staged_plan` upheld the validity contract.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    let plan = decode(bytes).inspect_err(|e| {
        log::error!("[owner] staged plan invalid: {e:?}");
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
    let retained = &raw mut RETAINED_PLAN;
    // SAFETY: scheduler-thread single accessor. Retain the plan for rebuild
    // re-application.
    unsafe {
        *last_mut = generation;
        *retained = Some(plan);
    }
    log::info!("[owner] applied staged plan: {n} owners (gen {generation})");
    Ok(n)
}
