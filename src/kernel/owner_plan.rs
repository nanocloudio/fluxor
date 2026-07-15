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

use crate::kernel::crypto::sha256::Sha256;

use crate::kernel::owner::MAX_OWNERS;

/// Plan magic: "FLXP". Matches `tools/src/compose.rs::PLAN_MAGIC`.
/// `#[doc(hidden)] pub` so the golden-format harness tests can hand-build
/// plan bytes off the same constant the encoder pins to.
#[doc(hidden)]
pub const PLAN_MAGIC: u32 = 0x464C_5850;
/// On-wire plan format version. `#[doc(hidden)] pub` for the golden-format tests.
#[doc(hidden)]
pub const PLAN_VERSION: u16 = 1;
/// Header: magic(4) + version(2) + reserved(2).
const PLAN_HEADER_LEN: usize = 8;
/// Per-assignment record: pod_uid(16)+slot(2)+gen(4)+mod_base(2)+mod_count(2)
/// +edge_base(2)+edge_count(2).
const ASSIGN_REC_LEN: usize = 16 + 2 + 4 + 2 + 2 + 2 + 2 + 4 + 4;
/// Per-revocation record: an assignment record verbatim + grace_secs(2) +
/// deadline_unix(8) (rfc_owner_drain_and_logs.md §3.2). The revocation section
/// is present only when non-empty.
const REVOKE_REC_LEN: usize = ASSIGN_REC_LEN + 2 + 8;
/// Per-lease record: slot(2) + generation(4) + protocol(1) + port(2)
/// (rfc_endpoint_lease.md §5.1).
const LEASE_REC_LEN: usize = 2 + 4 + 1 + 2;
/// Opens the lease section: an impossible revocation count, so the first u32
/// of the tail discriminates sections deterministically (48-byte revocation
/// and 9-byte lease records collide at 148 tail bytes under count-only
/// framing). Lives inside the digested body — integrity-protected.
/// `#[doc(hidden)] pub` for the golden-format tests.
#[doc(hidden)]
pub const LEASE_SECTION_MARKER: u32 = 0xFFFF_FFFF;
/// Decoder ceiling for the lease section (bounded-binary rule). Matches
/// `tools/src/compose.rs::MAX_PLAN_LEASES`.
pub const MAX_PLAN_LEASES: usize = 256;
/// At most one assignment per owner slot.
pub const MAX_PLAN_ASSIGNMENTS: usize = MAX_OWNERS;

/// One decoded owner placement.
#[derive(Clone, Copy, PartialEq, Eq)]
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

/// One decoded revocation: a departing owner's last assignment plus its drain
/// window (rfc_owner_drain_and_logs.md §3.2).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PlanRevocation {
    pub assignment: PlanAssignment,
    pub grace_secs: u16,
    pub deadline_unix: u64,
}

impl PlanRevocation {
    pub const EMPTY: PlanRevocation = PlanRevocation {
        assignment: PlanAssignment::EMPTY,
        grace_secs: 0,
        deadline_unix: 0,
    };
}

/// One granted endpoint lease: owner `(slot, generation)` may bind
/// `(protocol, port)` — 1 = tcp, 2 = udp (rfc_endpoint_lease.md §5.1).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PlanLease {
    pub slot: u16,
    pub generation: u32,
    pub protocol: u8,
    pub port: u16,
}

impl PlanLease {
    const EMPTY: PlanLease = PlanLease {
        slot: 0,
        generation: 0,
        protocol: 0,
        port: 0,
    };
}

/// A decoded, digest-verified plan. Allocation-free.
pub struct DecodedPlan {
    pub generation: u64,
    count: usize,
    assignments: [PlanAssignment; MAX_PLAN_ASSIGNMENTS],
    rev_count: usize,
    revocations: [PlanRevocation; MAX_PLAN_ASSIGNMENTS],
    lease_count: usize,
    leases: [PlanLease; MAX_PLAN_LEASES],
}

impl DecodedPlan {
    /// The valid assignment slice.
    pub fn assignments(&self) -> &[PlanAssignment] {
        &self.assignments[..self.count]
    }

    /// The valid revocation slice (usually empty).
    pub fn revocations(&self) -> &[PlanRevocation] {
        &self.revocations[..self.rev_count]
    }

    /// The valid lease slice, empty when the plan grants no endpoints.
    pub fn leases(&self) -> &[PlanLease] {
        &self.leases[..self.lease_count]
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
    let assign_len = 12 + count * ASSIGN_REC_LEN;
    let base_total = PLAN_HEADER_LEN + assign_len + 32;
    if bytes.len() < base_total {
        return Err(PlanError::Truncated);
    }
    // Tail grammar (rfc_endpoint_lease.md §5.1): [rev_section] [lease_section],
    // fixed order, each omitted when empty. The first u32 of the surplus
    // discriminates: LEASE_SECTION_MARKER opens a lease section; a valid count
    // opens the revocation section. Lengths validate, never discriminate.
    let mut tail_cursor = assign_len;
    let tail_end = bytes.len() - PLAN_HEADER_LEN - 32;
    let mut rev_count = 0usize;
    let mut lease_count = 0usize;
    if tail_cursor < tail_end {
        if tail_cursor + 4 > tail_end {
            return Err(PlanError::TrailingBytes);
        }
        let first = be_u32(&body[tail_cursor..tail_cursor + 4]);
        if first != LEASE_SECTION_MARKER {
            let rc = first as usize;
            if rc == 0 || rc > MAX_PLAN_ASSIGNMENTS {
                return Err(PlanError::TrailingBytes);
            }
            rev_count = rc;
            tail_cursor += 4 + rev_count * REVOKE_REC_LEN;
            if tail_cursor > tail_end {
                return Err(PlanError::Truncated);
            }
        }
    }
    if tail_cursor < tail_end {
        if tail_cursor + 8 > tail_end {
            return Err(PlanError::TrailingBytes);
        }
        if be_u32(&body[tail_cursor..tail_cursor + 4]) != LEASE_SECTION_MARKER {
            return Err(PlanError::TrailingBytes);
        }
        // Count 0 is valid — a plan that grants no endpoints; only an over-cap
        // count is rejected.
        let lc = be_u32(&body[tail_cursor + 4..tail_cursor + 8]) as usize;
        if lc > MAX_PLAN_LEASES {
            return Err(PlanError::TrailingBytes);
        }
        lease_count = lc;
        tail_cursor += 8 + lease_count * LEASE_REC_LEN;
    }
    let body_len = tail_cursor;
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
    fn read_assignment(r: &[u8]) -> PlanAssignment {
        let mut pod_uid = [0u8; 16];
        pod_uid.copy_from_slice(&r[0..16]);
        PlanAssignment {
            pod_uid,
            slot: be_u16(&r[16..18]),
            generation: be_u32(&r[18..22]),
            module_base: be_u16(&r[22..24]),
            module_count: be_u16(&r[24..26]),
            edge_base: be_u16(&r[26..28]),
            edge_count: be_u16(&r[28..30]),
            state_cap: be_u32(&r[30..34]),
            buffer_cap: be_u32(&r[34..38]),
        }
    }
    let mut assignments = [PlanAssignment::EMPTY; MAX_PLAN_ASSIGNMENTS];
    for (i, a) in assignments.iter_mut().enumerate().take(count) {
        *a = read_assignment(&body[12 + i * ASSIGN_REC_LEN..12 + (i + 1) * ASSIGN_REC_LEN]);
    }
    let mut revocations = [PlanRevocation::EMPTY; MAX_PLAN_ASSIGNMENTS];
    for (i, rev) in revocations.iter_mut().enumerate().take(rev_count) {
        let base = assign_len + 4 + i * REVOKE_REC_LEN;
        let r = &body[base..base + REVOKE_REC_LEN];
        *rev = PlanRevocation {
            assignment: read_assignment(&r[..ASSIGN_REC_LEN]),
            grace_secs: be_u16(&r[ASSIGN_REC_LEN..ASSIGN_REC_LEN + 2]),
            deadline_unix: be_u64(&r[ASSIGN_REC_LEN + 2..ASSIGN_REC_LEN + 10]),
        };
    }
    // Semantic validation: framing + digest prove the bytes are intact, not that
    // the plan is coherent. The kernel does not trust the composer's promise of
    // unique slots / non-overlapping ranges — a corrupt or hostile plan is
    // rejected here rather than applied (a partial apply would leave modules with
    // stale handles or the system owner, silently disabling isolation).
    // Validate assignments AND revocations under one rule set: a draining owner
    // still occupies its slot and module range (rfc_owner_drain_and_logs.md
    // §3.2), so revocations participate in the same duplicate/overlap checks.
    let record = |i: usize| -> &PlanAssignment {
        if i < count {
            &assignments[i]
        } else {
            &revocations[i - count].assignment
        }
    };
    let total = count + rev_count;
    for i in 0..total {
        let a = record(i);
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
        for j in 0..i {
            let a_prev = record(j);
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
    let mut leases = [PlanLease::EMPTY; MAX_PLAN_LEASES];
    let lease_base = assign_len
        + if rev_count > 0 {
            4 + rev_count * REVOKE_REC_LEN
        } else {
            0
        }
        + 8; // marker + count
    for (i, lease) in leases.iter_mut().enumerate().take(lease_count) {
        let r = &body[lease_base + i * LEASE_REC_LEN..lease_base + (i + 1) * LEASE_REC_LEN];
        *lease = PlanLease {
            slot: be_u16(&r[0..2]),
            generation: be_u32(&r[2..6]),
            protocol: r[6],
            port: be_u16(&r[7..9]),
        };
    }
    Ok(DecodedPlan {
        generation,
        count,
        assignments,
        rev_count,
        revocations,
        lease_count,
        leases,
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
            // Reset the owner's log ring iff this is a genuinely new tenant on the
            // slot; a same-triple reinstall (every routine rebuild) keeps the ring
            // and its seq counter (rfc_owner_drain_and_logs.md §4.3). The ring
            // module is host-linux-gated (see kernel/mod.rs).
            #[cfg(feature = "host-linux")]
            crate::kernel::owner_log::install_slot(a.slot as usize, a.pod_uid, a.generation);
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

/// Copy the retained plan's revocations into `out`, returning the count. The
/// platform uses this at boot to synthesize drain-timeout-by-restart terminal
/// records for owners that were mid-drain when the previous process died
/// (rfc_owner_drain_and_logs.md §3.6) — they are absent from the assignment
/// section, so nothing re-instantiates them; the record is the only trace.
pub fn retained_revocations(out: &mut [PlanRevocation; MAX_PLAN_ASSIGNMENTS]) -> usize {
    let retained = &raw const RETAINED_PLAN;
    // SAFETY: scheduler-thread read.
    match unsafe { &*retained } {
        Some(plan) => {
            let revs = plan.revocations();
            out[..revs.len()].copy_from_slice(revs);
            revs.len()
        }
        None => 0,
    }
}

/// Bind-gate verdict for `(slot, generation, protocol, port)` against the
/// retained plan's lease grants (rfc_endpoint_lease.md §5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseGate {
    /// No enforcement: no plan is retained, or the bind is an ephemeral port-0
    /// source. A retained plan that simply grants nothing still enforces — it
    /// refuses undeclared nonzero binds (rfc_endpoint_lease.md §5.1).
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
    let leases = plan.leases();
    if leases.iter().any(|l| {
        l.slot == slot && l.generation == generation && l.protocol == protocol && l.port == port
    }) {
        LeaseGate::Granted
    } else {
        LeaseGate::Refused
    }
}

/// One drain to arm: the platform converts `deadline_unix` to its own clock and
/// drives quiescence/deadline against it (the kernel never reads wall clock —
/// rfc_owner_drain_and_logs.md §3.6).
#[derive(Clone, Copy)]
pub struct DrainArm {
    pub pod_uid: [u8; 16],
    pub slot: u16,
    pub generation: u32,
    pub grace_secs: u16,
    pub deadline_unix: u64,
}

impl DrainArm {
    pub const EMPTY: DrainArm = DrainArm {
        pod_uid: [0; 16],
        slot: 0,
        generation: 0,
        grace_secs: 0,
        deadline_unix: 0,
    };
}

/// Drains armed by a delta apply. Fixed-size, allocation-free.
pub struct DrainDelta {
    pub count: usize,
    pub arms: [DrainArm; MAX_PLAN_ASSIGNMENTS],
}

/// Attempt to apply the staged plan as a **pure-drain delta** — the one plan
/// shape a removal generation produces (rfc_owner_drain_and_logs.md §3.4):
/// every staged assignment is byte-identical to a retained one, every
/// retained assignment either survives or moved verbatim into the staged
/// revocation section, and every retained revocation whose owner is still
/// installed is carried forward verbatim. Then no rebuild is needed:
/// co-resident owners are
/// untouched, and each newly revoked owner is flipped to `Draining` in place
/// (admission closes; its modules keep stepping until the platform's drain
/// driver frees it at quiescence or deadline).
///
/// Returns `Some(delta)` (possibly with `count == 0` drains when every
/// revocation names an already-gone owner) after consuming the staged plan and
/// updating the retained-plan bookkeeping — the caller must NOT rebuild.
/// Returns `None` — leaving the staged plan in place for the ordinary
/// `apply_staged` rebuild path — when there is no staged plan, no retained
/// plan (boot), a decode/rollback failure (the rebuild path reports it), or a
/// structural change.
pub fn try_apply_drain_delta() -> Option<DrainDelta> {
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

    // SAFETY: `set_staged_plan`'s caller upheld the validity contract.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
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
        if !retained.assignments().iter().any(|r| r == a) {
            return None;
        }
    }
    // …and every retained assignment either survives verbatim or departed into
    // the staged revocation section verbatim.
    for r in retained.assignments() {
        let survives = plan.assignments().iter().any(|a| a == r);
        let revoked = plan.revocations().iter().any(|rev| rev.assignment == *r);
        if !survives && !revoked {
            return None;
        }
    }
    // …and every retained revocation whose owner is still installed must be
    // carried forward verbatim. The retained revocation is the only DURABLE
    // trace of the pending drain terminal — restart synthesis (§3.6) reads it
    // to report a drain forfeited by a process death — so a plan may drop it
    // only once the drain driver has freed the owner.
    {
        let table = crate::kernel::scheduler::owners_mut();
        for rev in retained.revocations() {
            let handle = crate::kernel::owner::OwnerHandle {
                slot: rev.assignment.slot,
                generation: rev.assignment.generation,
            };
            if table.lookup(handle).is_some() && !plan.revocations().contains(rev) {
                return None;
            }
        }
    }

    // Eligible: consume the staged plan and apply the delta in place.
    let _ = take_staged_plan();
    let delta = arm_revocations(&plan);

    let generation = plan.generation;
    // SAFETY: scheduler-thread single accessor; retain for rebuild re-apply.
    // Direct static assignment forms no reference.
    unsafe {
        LAST_APPLIED_GENERATION = generation;
        RETAINED_PLAN = Some(plan);
    }
    log::info!(
        "[owner] drain delta applied: {} drains armed (gen {generation})",
        delta.count
    );
    Some(delta)
}

/// `begin_drain` every still-installed owner named in `plan`'s revocation
/// section and return their drain arms. An already-revoked / never-installed
/// owner is a no-op; `begin_drain` is idempotent for an already-Draining owner,
/// and the platform re-arms with the record's original deadline, so a replayed
/// record never resets the clock.
fn arm_revocations(plan: &DecodedPlan) -> DrainDelta {
    let mut delta = DrainDelta {
        count: 0,
        arms: [DrainArm::EMPTY; MAX_PLAN_ASSIGNMENTS],
    };
    let table = crate::kernel::scheduler::owners_mut();
    for rev in plan.revocations() {
        let handle = crate::kernel::owner::OwnerHandle {
            slot: rev.assignment.slot,
            generation: rev.assignment.generation,
        };
        if table.lookup(handle).is_some() && table.begin_drain(handle) {
            delta.arms[delta.count] = DrainArm {
                pod_uid: rev.assignment.pod_uid,
                slot: rev.assignment.slot,
                generation: rev.assignment.generation,
                grace_secs: rev.grace_secs,
                deadline_unix: rev.deadline_unix,
            };
            delta.count += 1;
        }
    }
    delta
}

/// Arm drains for the staged plan's revocations without consuming it or
/// requiring delta-eligibility. The structural rebuild path calls this: a plan
/// that adds or changes owners is not a pure-drain delta, but any owner it
/// revokes must still drain — `begin_drain` plus a terminal record — rather than
/// being dropped untracked by the rebuild's `reset_workloads`. The staged plan
/// stays in place for `apply_staged`; the returned arms outlive the table reset,
/// so the drain driver finalises each freed owner.
pub fn arm_staged_revocation_drains() -> DrainDelta {
    let empty = DrainDelta {
        count: 0,
        arms: [DrainArm::EMPTY; MAX_PLAN_ASSIGNMENTS],
    };
    // SAFETY: scheduler-thread single accessor; scalar read by value.
    let Some((ptr, len)) = (unsafe { STAGED_PLAN }) else {
        return empty;
    };
    // SAFETY: `set_staged_plan`'s caller upheld the validity contract.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    let Ok(plan) = decode(bytes) else {
        return empty;
    };
    // A rollback is rejected by the rebuild's `apply_staged`; do not arm drains
    // for a plan that will not be applied.
    // SAFETY: scheduler-thread single accessor; scalar read by value.
    let last = unsafe { LAST_APPLIED_GENERATION };
    if plan.generation < last {
        return empty;
    }
    arm_revocations(&plan)
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
