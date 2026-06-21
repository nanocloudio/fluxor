//! Deterministic device-graph composition and reservation
//! (rfc_k8s.md §6.7, §11).
//!
//! This is the trusted, host-side core of the node agent: it turns a
//! `DeviceDesiredState` plus the node's capacity facts and prior owner-table
//! snapshot into a `CompositionPlan` with deterministic owner-slot, generation,
//! and module/edge index assignments, and a content digest over the result.
//!
//! Determinism is a hard contract (rfc_k8s.md §11): identical
//! `(desired, capacity, snapshot)` inputs must produce a byte-identical plan
//! and the same `plan_digest`, so any node — or offline tooling — composes the
//! same answer. The rules enforced here:
//!   * pods are processed in ascending `pod_uid` order;
//!   * an already-resident pod keeps its slot and generation (handle preserved);
//!   * a new pod takes the lowest free slot; its generation is the slot's
//!     persistent counter + 1 (monotonic across reuse, so a stale handle from a
//!     deleted pod can never match);
//!   * module/edge index ranges are assigned contiguously in ascending slot
//!     order.
//!
//! Artifact resolution, signature verification, and graph expansion (the rest
//! of the §11 reconcile) layer on top of this module, which owns the
//! allocation/determinism and reservation invariants.

use sha2::{Digest, Sha256};

pub type PodUid = [u8; 16];
pub type Digest32 = [u8; 32];

/// Desired lifecycle of a pod.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DesiredPhase {
    Running,
    Stopped,
}

/// Measured runtime demand of a workload implementation (the signed resource
/// profile). Counts are per-pod.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceProfile {
    pub modules: u16,
    pub edges: u16,
    pub state_bytes: u32,
    pub buffer_bytes: u32,
    pub endpoints: u16,
    pub domains: u8,
}

/// One pod's desired state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PodDesired {
    pub pod_uid: PodUid,
    pub namespace: String,
    pub name: String,
    pub workload_digest: Digest32,
    pub config_generation: u64,
    pub desired_phase: DesiredPhase,
    pub profile: ResourceProfile,
}

/// Whole-device desired state (rfc_k8s.md §11).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceDesiredState {
    pub generation: u64,
    pub system_revision: u64,
    pub pods: Vec<PodDesired>,
}

/// Node capacity facts — mirrors the per-profile kernel limits the plan must
/// fit within. `max_owners` includes the system slot 0.
#[derive(Clone, Copy, Debug)]
pub struct NodeCapacity {
    pub max_owners: u16,
    pub max_modules: u16,
    pub max_edges: u16,
    pub state_bytes: u32,
    pub buffer_bytes: u32,
    pub max_endpoints: u16,
    pub max_domains: u8,
}

/// State of one owner slot in the prior owner table (rfc_k8s.md §11 input).
/// `generation` is the slot's persistent monotonic counter — it survives free,
/// so reuse always issues a strictly higher generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotState {
    pub occupant: Option<PodUid>,
    pub generation: u32,
}

impl SlotState {
    pub const EMPTY: SlotState = SlotState {
        occupant: None,
        generation: 0,
    };
}

/// Snapshot of the owner table, indexed by slot (slot 0 = system).
#[derive(Clone, Debug, Default)]
pub struct OwnerSnapshot {
    pub slots: Vec<SlotState>,
}

impl OwnerSnapshot {
    /// An empty snapshot sized for `max_owners` (only the system slot present).
    pub fn empty(max_owners: u16) -> Self {
        OwnerSnapshot {
            slots: vec![SlotState::EMPTY; max_owners as usize],
        }
    }

    fn slot_of(&self, uid: &PodUid) -> Option<u16> {
        self.slots
            .iter()
            .position(|s| s.occupant.as_ref() == Some(uid))
            .map(|i| i as u16)
    }

    fn generation_at(&self, slot: u16) -> u32 {
        self.slots
            .get(slot as usize)
            .map(|s| s.generation)
            .unwrap_or(0)
    }
}

/// One owner's placement in a composed plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerAssignment {
    pub pod_uid: PodUid,
    pub slot: u16,
    pub generation: u32,
    pub module_base: u16,
    pub module_count: u16,
    pub edge_base: u16,
    pub edge_count: u16,
}

/// A composed, validated device-graph plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompositionPlan {
    pub generation: u64,
    /// Assignments in ascending slot order.
    pub assignments: Vec<OwnerAssignment>,
    pub plan_digest: Digest32,
}

/// Why composition failed admission (rfc_k8s.md §12.1 static capacity).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComposeError {
    OwnerSlotsExhausted,
    ModulesExceeded,
    EdgesExceeded,
    StateBytesExceeded,
    BufferBytesExceeded,
    EndpointsExceeded,
    DomainsExceeded,
}

/// Compose a candidate device graph. Deterministic in `(desired, cap, prior)`.
pub fn compose(
    desired: &DeviceDesiredState,
    cap: &NodeCapacity,
    prior: &OwnerSnapshot,
) -> Result<CompositionPlan, ComposeError> {
    // 1. Only running pods are placed; sort by pod_uid for a stable order.
    let mut running: Vec<&PodDesired> = desired
        .pods
        .iter()
        .filter(|p| p.desired_phase == DesiredPhase::Running)
        .collect();
    running.sort_by(|a, b| a.pod_uid.cmp(&b.pod_uid));

    // 2. Assign owner slots. Resident pods keep their slot+generation; new pods
    //    take the lowest free slot with a bumped generation.
    let occupied_by_desired: Vec<u16> = running
        .iter()
        .filter_map(|p| prior.slot_of(&p.pod_uid))
        .collect();

    let mut next_free: u16 = 1; // slot 0 is the system owner
    let mut free_slot = |occupied: &[u16], cap: &NodeCapacity| -> Option<u16> {
        while (next_free as usize) < cap.max_owners as usize {
            let s = next_free;
            next_free += 1;
            if !occupied.contains(&s) {
                return Some(s);
            }
        }
        None
    };

    // (slot, generation) per running pod, in the running (uid-sorted) order.
    let mut placed: Vec<(u16, u32)> = Vec::with_capacity(running.len());
    for p in &running {
        if let Some(slot) = prior.slot_of(&p.pod_uid) {
            placed.push((slot, prior.generation_at(slot)));
        } else {
            let slot =
                free_slot(&occupied_by_desired, cap).ok_or(ComposeError::OwnerSlotsExhausted)?;
            placed.push((slot, prior.generation_at(slot).wrapping_add(1)));
        }
    }

    // 3. Order assignments by slot (stable graph layout), then lay out module
    //    and edge index ranges contiguously while checking aggregate capacity.
    let mut order: Vec<usize> = (0..running.len()).collect();
    order.sort_by_key(|&i| placed[i].0);

    let mut module_cursor: u32 = 0;
    let mut edge_cursor: u32 = 0;
    let mut total_state: u64 = 0;
    let mut total_buffer: u64 = 0;
    let mut total_endpoints: u32 = 0;
    let mut total_domains: u32 = 0;
    let mut assignments: Vec<OwnerAssignment> = Vec::with_capacity(order.len());

    for &i in &order {
        let p = running[i];
        let (slot, generation) = placed[i];

        module_cursor += p.profile.modules as u32;
        if module_cursor > cap.max_modules as u32 {
            return Err(ComposeError::ModulesExceeded);
        }
        edge_cursor += p.profile.edges as u32;
        if edge_cursor > cap.max_edges as u32 {
            return Err(ComposeError::EdgesExceeded);
        }
        total_state += p.profile.state_bytes as u64;
        if total_state > cap.state_bytes as u64 {
            return Err(ComposeError::StateBytesExceeded);
        }
        total_buffer += p.profile.buffer_bytes as u64;
        if total_buffer > cap.buffer_bytes as u64 {
            return Err(ComposeError::BufferBytesExceeded);
        }
        total_endpoints += p.profile.endpoints as u32;
        if total_endpoints > cap.max_endpoints as u32 {
            return Err(ComposeError::EndpointsExceeded);
        }
        total_domains += p.profile.domains as u32;
        if total_domains > cap.max_domains as u32 {
            return Err(ComposeError::DomainsExceeded);
        }

        assignments.push(OwnerAssignment {
            pod_uid: p.pod_uid,
            slot,
            generation,
            module_base: (module_cursor - p.profile.modules as u32) as u16,
            module_count: p.profile.modules,
            edge_base: (edge_cursor - p.profile.edges as u32) as u16,
            edge_count: p.profile.edges,
        });
    }

    let plan_digest = digest_plan(desired.generation, &assignments);
    Ok(CompositionPlan {
        generation: desired.generation,
        assignments,
        plan_digest,
    })
}

/// Per-assignment fixed record width in the canonical plan body:
/// pod_uid(16) + slot(2) + generation(4) + module_base(2) + module_count(2)
/// + edge_base(2) + edge_count(2).
const ASSIGN_REC_LEN: usize = 16 + 2 + 4 + 2 + 2 + 2 + 2;

/// Canonical, fixed-width big-endian serialization of a plan's payload
/// (generation + count + assignments). Stable across platforms, so the digest
/// over it — and the encoded plan — are reproducible. Shared by `digest_plan`
/// and `encode_plan`.
fn plan_body(generation: u64, assignments: &[OwnerAssignment]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(12 + assignments.len() * ASSIGN_REC_LEN);
    buf.extend_from_slice(&generation.to_be_bytes());
    buf.extend_from_slice(&(assignments.len() as u32).to_be_bytes());
    for a in assignments {
        buf.extend_from_slice(&a.pod_uid);
        buf.extend_from_slice(&a.slot.to_be_bytes());
        buf.extend_from_slice(&a.generation.to_be_bytes());
        buf.extend_from_slice(&a.module_base.to_be_bytes());
        buf.extend_from_slice(&a.module_count.to_be_bytes());
        buf.extend_from_slice(&a.edge_base.to_be_bytes());
        buf.extend_from_slice(&a.edge_count.to_be_bytes());
    }
    buf
}

fn sha256_of(bytes: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

/// Canonical content digest over a plan. Fixed-width big-endian encoding so the
/// bytes — and therefore the digest — are stable across platforms.
fn digest_plan(generation: u64, assignments: &[OwnerAssignment]) -> Digest32 {
    sha256_of(&plan_body(generation, assignments))
}

// ============================================================================
// Binary plan codec (rfc_k8s.md §11: "the kernel consumes a validated bounded
// binary plan; it does not parse Kubernetes objects, OCI manifests, or YAML")
// ============================================================================

/// Magic for an encoded device-graph plan: "FLXP".
const PLAN_MAGIC: u32 = 0x464C_5850;
/// On-wire plan format version.
const PLAN_VERSION: u16 = 1;
/// Fixed header: magic(4) + version(2) + reserved(2).
const PLAN_HEADER_LEN: usize = 8;
/// Hard ceiling on assignments in one bounded plan (matches the largest
/// per-profile owner table; the kernel rejects anything larger).
const MAX_PLAN_ASSIGNMENTS: usize = 256;

/// Why decoding a binary plan failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanDecodeError {
    BadMagic,
    BadVersion,
    Truncated,
    TooManyAssignments,
    DigestMismatch,
    TrailingBytes,
}

/// Encode a composed plan into the bounded binary form the kernel consumes:
/// `[header][body][sha256(body)]`. Deterministic — identical plans encode to
/// identical bytes.
pub fn encode_plan(plan: &CompositionPlan) -> Vec<u8> {
    let body = plan_body(plan.generation, &plan.assignments);
    let digest = sha256_of(&body);
    let mut out = Vec::with_capacity(PLAN_HEADER_LEN + body.len() + 32);
    out.extend_from_slice(&PLAN_MAGIC.to_be_bytes());
    out.extend_from_slice(&PLAN_VERSION.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // reserved
    out.extend_from_slice(&body);
    out.extend_from_slice(&digest);
    out
}

/// Decode and verify a binary plan. Validates magic/version, bounds every length
/// against the input, enforces `MAX_PLAN_ASSIGNMENTS`, and verifies the trailing
/// sha256 over the body so a tampered or truncated plan fails closed.
pub fn decode_plan(bytes: &[u8]) -> Result<CompositionPlan, PlanDecodeError> {
    if bytes.len() < PLAN_HEADER_LEN + 12 + 32 {
        return Err(PlanDecodeError::Truncated);
    }
    let magic = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
    if magic != PLAN_MAGIC {
        return Err(PlanDecodeError::BadMagic);
    }
    let version = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
    if version != PLAN_VERSION {
        return Err(PlanDecodeError::BadVersion);
    }
    let body = &bytes[PLAN_HEADER_LEN..];
    let generation = u64::from_be_bytes(body[0..8].try_into().unwrap());
    let count = u32::from_be_bytes(body[8..12].try_into().unwrap()) as usize;
    if count > MAX_PLAN_ASSIGNMENTS {
        return Err(PlanDecodeError::TooManyAssignments);
    }
    let body_len = 12 + count * ASSIGN_REC_LEN;
    let expected_total = PLAN_HEADER_LEN + body_len + 32;
    if bytes.len() < expected_total {
        return Err(PlanDecodeError::Truncated);
    }
    if bytes.len() > expected_total {
        return Err(PlanDecodeError::TrailingBytes);
    }
    // Verify the digest over the body before trusting any field.
    let digest = &bytes[PLAN_HEADER_LEN + body_len..];
    if sha256_of(&body[..body_len]) != digest {
        return Err(PlanDecodeError::DigestMismatch);
    }
    let mut assignments = Vec::with_capacity(count);
    for i in 0..count {
        let r = &body[12 + i * ASSIGN_REC_LEN..12 + (i + 1) * ASSIGN_REC_LEN];
        let mut pod_uid = [0u8; 16];
        pod_uid.copy_from_slice(&r[0..16]);
        assignments.push(OwnerAssignment {
            pod_uid,
            slot: u16::from_be_bytes(r[16..18].try_into().unwrap()),
            generation: u32::from_be_bytes(r[18..22].try_into().unwrap()),
            module_base: u16::from_be_bytes(r[22..24].try_into().unwrap()),
            module_count: u16::from_be_bytes(r[24..26].try_into().unwrap()),
            edge_base: u16::from_be_bytes(r[26..28].try_into().unwrap()),
            edge_count: u16::from_be_bytes(r[28..30].try_into().unwrap()),
        });
    }
    let mut plan_digest = [0u8; 32];
    plan_digest.copy_from_slice(digest);
    Ok(CompositionPlan {
        generation,
        assignments,
        plan_digest,
    })
}

// ============================================================================
// Reservation protocol (rfc_k8s.md §6.7, §12.4)
// ============================================================================

/// A single-use placement reservation. Bound to the pod, the workload and plan
/// digests, and the node epoch under which it was issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservationToken {
    pub pod_uid: PodUid,
    pub workload_digest: Digest32,
    pub plan_digest: Digest32,
    pub node_epoch: u64,
}

/// Why staging a reservation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReserveError {
    /// The token's node epoch no longer matches — issued before a crash/recover.
    StaleEpoch,
    /// The token was already consumed (single-use violation).
    AlreadyConsumed,
}

/// Tracks the node epoch and consumed tokens so each reservation stages exactly
/// once. A crash before commit is modelled by [`recover`](Self::recover), which
/// bumps the epoch and invalidates every outstanding token (rfc_k8s.md §12.4).
#[derive(Clone, Debug)]
pub struct Reservations {
    node_epoch: u64,
    consumed: Vec<(PodUid, u64)>,
}

impl Reservations {
    pub fn new(node_epoch: u64) -> Self {
        Reservations {
            node_epoch,
            consumed: Vec::new(),
        }
    }

    pub fn node_epoch(&self) -> u64 {
        self.node_epoch
    }

    /// Issue a reservation against the current epoch.
    pub fn reserve(
        &self,
        pod_uid: PodUid,
        workload_digest: Digest32,
        plan_digest: Digest32,
    ) -> ReservationToken {
        ReservationToken {
            pod_uid,
            workload_digest,
            plan_digest,
            node_epoch: self.node_epoch,
        }
    }

    /// Consume a reservation exactly once. Rejects a stale-epoch token (issued
    /// before a recover) and a double-consume.
    pub fn stage(&mut self, token: &ReservationToken) -> Result<(), ReserveError> {
        if token.node_epoch != self.node_epoch {
            return Err(ReserveError::StaleEpoch);
        }
        if self
            .consumed
            .iter()
            .any(|(uid, epoch)| *uid == token.pod_uid && *epoch == token.node_epoch)
        {
            return Err(ReserveError::AlreadyConsumed);
        }
        self.consumed.push((token.pod_uid, token.node_epoch));
        Ok(())
    }

    /// Recover after a crash before commit: a fresh epoch invalidates every
    /// outstanding token, so a spent-but-uncommitted reservation can never
    /// re-activate a candidate (rfc_k8s.md §12.4).
    pub fn recover(&mut self) {
        self.node_epoch = self.node_epoch.wrapping_add(1);
        self.consumed.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid(n: u8) -> PodUid {
        let mut u = [0u8; 16];
        u[0] = n;
        u
    }

    fn profile(modules: u16, edges: u16) -> ResourceProfile {
        ResourceProfile {
            modules,
            edges,
            state_bytes: 1024,
            buffer_bytes: 512,
            endpoints: 1,
            domains: 1,
        }
    }

    fn pod(n: u8, phase: DesiredPhase, p: ResourceProfile) -> PodDesired {
        PodDesired {
            pod_uid: uid(n),
            namespace: "default".into(),
            name: format!("pod-{n}"),
            workload_digest: [n; 32],
            config_generation: 1,
            desired_phase: phase,
            profile: p,
        }
    }

    fn cap() -> NodeCapacity {
        NodeCapacity {
            max_owners: 16,
            max_modules: 128,
            max_edges: 256,
            state_bytes: 1 << 20,
            buffer_bytes: 1 << 20,
            max_endpoints: 64,
            max_domains: 4,
        }
    }

    #[test]
    fn composition_is_deterministic_regardless_of_input_order() {
        let snap = OwnerSnapshot::empty(16);
        let a = pod(1, DesiredPhase::Running, profile(4, 6));
        let b = pod(2, DesiredPhase::Running, profile(8, 10));

        let s1 = DeviceDesiredState {
            generation: 7,
            system_revision: 1,
            pods: vec![a.clone(), b.clone()],
        };
        // same pods, reversed order
        let s2 = DeviceDesiredState {
            generation: 7,
            system_revision: 1,
            pods: vec![b, a],
        };

        let p1 = compose(&s1, &cap(), &snap).unwrap();
        let p2 = compose(&s2, &cap(), &snap).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(p1.plan_digest, p2.plan_digest);

        // pod 1 (lower uid) takes slot 1, module base 0; pod 2 slot 2.
        assert_eq!(p1.assignments[0].pod_uid, uid(1));
        assert_eq!(p1.assignments[0].slot, 1);
        assert_eq!(p1.assignments[0].module_base, 0);
        assert_eq!(p1.assignments[1].slot, 2);
        assert_eq!(p1.assignments[1].module_base, 4);
    }

    #[test]
    fn stopped_pods_are_not_placed() {
        let snap = OwnerSnapshot::empty(16);
        let ds = DeviceDesiredState {
            generation: 1,
            system_revision: 1,
            pods: vec![
                pod(1, DesiredPhase::Stopped, profile(4, 4)),
                pod(2, DesiredPhase::Running, profile(4, 4)),
            ],
        };
        let plan = compose(&ds, &cap(), &snap).unwrap();
        assert_eq!(plan.assignments.len(), 1);
        assert_eq!(plan.assignments[0].pod_uid, uid(2));
    }

    #[test]
    fn resident_pod_keeps_slot_new_pod_bumps_generation() {
        // pod 2 already resides in slot 1 at generation 5.
        let mut snap = OwnerSnapshot::empty(16);
        snap.slots[1] = SlotState {
            occupant: Some(uid(2)),
            generation: 5,
        };
        let ds = DeviceDesiredState {
            generation: 2,
            system_revision: 1,
            pods: vec![
                pod(2, DesiredPhase::Running, profile(4, 4)),
                pod(3, DesiredPhase::Running, profile(4, 4)),
            ],
        };
        let plan = compose(&ds, &cap(), &snap).unwrap();
        let a2 = plan
            .assignments
            .iter()
            .find(|a| a.pod_uid == uid(2))
            .unwrap();
        let a3 = plan
            .assignments
            .iter()
            .find(|a| a.pod_uid == uid(3))
            .unwrap();
        // resident pod 2 keeps slot 1 + generation 5
        assert_eq!((a2.slot, a2.generation), (1, 5));
        // new pod 3 takes the next free slot 2, generation 1 (fresh slot)
        assert_eq!((a3.slot, a3.generation), (2, 1));
    }

    #[test]
    fn reused_slot_generation_is_monotonic() {
        // slot 1 was used before (generation 9) and is now free.
        let mut snap = OwnerSnapshot::empty(16);
        snap.slots[1] = SlotState {
            occupant: None,
            generation: 9,
        };
        let ds = DeviceDesiredState {
            generation: 3,
            system_revision: 1,
            pods: vec![pod(7, DesiredPhase::Running, profile(4, 4))],
        };
        let plan = compose(&ds, &cap(), &snap).unwrap();
        assert_eq!(plan.assignments[0].slot, 1);
        assert_eq!(plan.assignments[0].generation, 10); // 9 + 1, never reused
    }

    #[test]
    fn capacity_overflow_is_rejected() {
        let snap = OwnerSnapshot::empty(16);
        let ds = DeviceDesiredState {
            generation: 1,
            system_revision: 1,
            pods: vec![pod(1, DesiredPhase::Running, profile(200, 4))],
        };
        assert_eq!(
            compose(&ds, &cap(), &snap),
            Err(ComposeError::ModulesExceeded)
        );
    }

    #[test]
    fn owner_slots_exhausted_is_rejected() {
        let small = NodeCapacity {
            max_owners: 2, // system + exactly one workload slot
            ..cap()
        };
        let snap = OwnerSnapshot::empty(2);
        let ds = DeviceDesiredState {
            generation: 1,
            system_revision: 1,
            pods: vec![
                pod(1, DesiredPhase::Running, profile(1, 1)),
                pod(2, DesiredPhase::Running, profile(1, 1)),
            ],
        };
        assert_eq!(
            compose(&ds, &small, &snap),
            Err(ComposeError::OwnerSlotsExhausted)
        );
    }

    #[test]
    fn reservation_is_single_use() {
        let mut r = Reservations::new(1);
        let t = r.reserve(uid(1), [1; 32], [2; 32]);
        assert!(r.stage(&t).is_ok());
        assert_eq!(r.stage(&t), Err(ReserveError::AlreadyConsumed));
    }

    #[test]
    fn recover_invalidates_outstanding_tokens() {
        let mut r = Reservations::new(1);
        let t = r.reserve(uid(1), [1; 32], [2; 32]);
        // crash before commit: recover bumps the epoch
        r.recover();
        assert_eq!(r.stage(&t), Err(ReserveError::StaleEpoch));
        // a fresh token under the new epoch stages fine
        let t2 = r.reserve(uid(1), [1; 32], [2; 32]);
        assert!(r.stage(&t2).is_ok());
    }

    // ── Binary plan codec ───────────────────────────────────────────────────

    fn sample_plan() -> CompositionPlan {
        let snap = OwnerSnapshot::empty(16);
        let ds = DeviceDesiredState {
            generation: 42,
            system_revision: 1,
            pods: vec![
                pod(1, DesiredPhase::Running, profile(4, 6)),
                pod(2, DesiredPhase::Running, profile(8, 10)),
            ],
        };
        compose(&ds, &cap(), &snap).unwrap()
    }

    #[test]
    fn encode_decode_round_trips() {
        let plan = sample_plan();
        let bytes = encode_plan(&plan);
        let decoded = decode_plan(&bytes).expect("decode");
        assert_eq!(decoded, plan);
        // decoded plan_digest matches the freshly composed one
        assert_eq!(decoded.plan_digest, plan.plan_digest);
    }

    #[test]
    fn encode_is_deterministic() {
        let plan = sample_plan();
        assert_eq!(encode_plan(&plan), encode_plan(&plan));
    }

    #[test]
    fn empty_plan_round_trips() {
        let plan = CompositionPlan {
            generation: 7,
            assignments: vec![],
            plan_digest: digest_plan(7, &[]),
        };
        assert_eq!(decode_plan(&encode_plan(&plan)).unwrap(), plan);
    }

    #[test]
    fn tampered_body_fails_digest() {
        let mut bytes = encode_plan(&sample_plan());
        // flip a byte inside the first assignment record (after the 12-byte
        // body prefix, which is after the 8-byte header).
        let idx = PLAN_HEADER_LEN + 12 + 4;
        bytes[idx] ^= 0xFF;
        assert_eq!(decode_plan(&bytes), Err(PlanDecodeError::DigestMismatch));
    }

    #[test]
    fn bad_magic_and_version_rejected() {
        let mut bytes = encode_plan(&sample_plan());
        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 0xFF;
        assert_eq!(decode_plan(&bad_magic), Err(PlanDecodeError::BadMagic));
        bytes[5] = 0xFF; // version low byte
        assert_eq!(decode_plan(&bytes), Err(PlanDecodeError::BadVersion));
    }

    #[test]
    fn truncated_and_trailing_rejected() {
        let bytes = encode_plan(&sample_plan());
        assert_eq!(
            decode_plan(&bytes[..bytes.len() - 1]),
            Err(PlanDecodeError::Truncated)
        );
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(decode_plan(&extra), Err(PlanDecodeError::TrailingBytes));
    }

    #[test]
    fn over_cap_count_rejected() {
        // Hand-craft a header claiming more assignments than the bound, so the
        // count check trips before any allocation.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PLAN_MAGIC.to_be_bytes());
        bytes.extend_from_slice(&PLAN_VERSION.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&7u64.to_be_bytes()); // generation
        bytes.extend_from_slice(&((MAX_PLAN_ASSIGNMENTS as u32 + 1).to_be_bytes()));
        bytes.extend_from_slice(&[0u8; 32]); // (bogus) digest area
        assert_eq!(
            decode_plan(&bytes),
            Err(PlanDecodeError::TooManyAssignments)
        );
    }
}
