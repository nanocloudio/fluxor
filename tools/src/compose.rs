//! Deterministic device-graph composition and reservation.
//!
//! This is the trusted, host-side core of the node agent: it turns a
//! `DeviceDesiredState` plus the node's capacity facts and prior owner-table
//! snapshot into a `CompositionPlan` with deterministic owner-slot, generation,
//! and module/edge index assignments, and a content digest over the result.
//!
//! Determinism is a hard contract: identical
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
//! of the reconcile) layer on top of this module, which owns the
//! allocation/determinism and reservation invariants.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type PodUid = [u8; 16];
pub type Digest32 = [u8; 32];

/// Desired lifecycle of a pod.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DesiredPhase {
    Running,
    Stopped,
}

/// Measured runtime demand of a workload implementation (the signed resource
/// profile). Counts are per-pod.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceProfile {
    pub modules: u16,
    pub edges: u16,
    pub state_bytes: u32,
    pub buffer_bytes: u32,
    pub endpoints: u16,
    pub domains: u8,
}

/// One declared network export of an admitted workload (mirrors the workload
/// manifest's `Export`, minus the name — the agent joins the runtime's bound
/// report against these). Persisted with the
/// desired pod; `#[serde(default)]` tolerates a desired pod that declares none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportDecl {
    pub protocol: String,
    pub port: u16,
}

/// One pod's desired state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PodDesired {
    pub pod_uid: PodUid,
    pub namespace: String,
    pub name: String,
    pub workload_digest: Digest32,
    pub config_generation: u64,
    pub desired_phase: DesiredPhase,
    pub profile: ResourceProfile,
    /// Declared exports from the admitted workload manifest (empty for
    /// flag-based commits with no bundle).
    #[serde(default)]
    pub exports: Vec<ExportDecl>,
}

/// Whole-device desired state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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

/// Node capacity for a named target profile. This is the single host-side
/// mirror of the kernel's per-profile limits; `capacity_mirrors_kernel_sources`
/// (below) textually extracts the kernel constants and fails when they drift.
///
/// `linux` and `pi5`/`bcm2712` share values because both compile the aarch64
/// `profile_host` block (`modules/sdk/config.rs`) with the `multitenant`
/// feature (`src/kernel/workload/owner.rs` MAX_OWNERS). `max_endpoints` is agent-level
/// admission policy — the kernel has no endpoint table constant yet.
pub fn capacity_for_profile(profile: &str) -> Option<NodeCapacity> {
    match profile {
        "linux" | "pi5" | "bcm2712" => Some(NodeCapacity {
            max_owners: 64, // owner.rs MAX_OWNERS (multitenant)
            // Taken from `capacity::kernel_max_modules`, not restated: two
            // copies of one kernel constant is how the composer comes to
            // admit a graph the kernel has no slots for.
            max_modules: crate::capacity::kernel_max_modules(profile) as u16,
            max_edges: 128,                 // kernel/config.rs MAX_GRAPH_EDGES
            state_bytes: 256 * 1024 * 1024, // profile_host STATE_ARENA_SIZE
            buffer_bytes: 8 * 1024 * 1024,  // profile_host BUFFER_ARENA_SIZE
            max_endpoints: 64,              // agent admission policy
            max_domains: 4,                 // scheduler MAX_DOMAINS
        }),
        // MCU silicon. Without a capacity row here, composition has no model
        // for an RP target: a graph is admitted blind and discovers its
        // sizing as a boot-time clamp-and-log (`capacity::kernel_pool_static_cap`
        // says so outright for the RP arenas). On a die whose whole state
        // arena is 64 KiB that is the difference between a build error and a
        // board that boots with modules missing.
        //
        // The arena figures come from `targets/silicon/<id>.toml` and are
        // mirrored here rather than read, because this function is pure and has
        // no repo path. `capacity_mirrors_silicon_tomls` (below) extracts them
        // textually and fails on drift — the same mitigation the host row uses
        // against the kernel constants.
        //
        // `max_owners: 1` is the system slot alone: multitenancy is an aarch64
        // feature, so there are no workload slots to hand out. `max_modules`
        // comes from `kernel_max_modules`, which already answers 32 for every
        // non-host target.
        "rp2040" | "pico" | "picow" => Some(NodeCapacity {
            max_owners: 1,
            max_modules: crate::capacity::kernel_max_modules(profile) as u16,
            max_edges: 128,
            state_bytes: 64 * 1024,  // rp2040.toml state_arena_kb
            buffer_bytes: 16 * 1024, // rp2040.toml buffer_arena_kb
            max_endpoints: 4,
            max_domains: 4,
        }),
        "rp2350" | "pico2w" | "waveshare-lcd4" => Some(NodeCapacity {
            max_owners: 1,
            max_modules: crate::capacity::kernel_max_modules(profile) as u16,
            max_edges: 128,
            state_bytes: 240 * 1024, // rp2350.toml state_arena_kb
            buffer_bytes: 64 * 1024, // rp2350.toml buffer_arena_kb
            max_endpoints: 8,
            max_domains: 4,
        }),
        _ => None,
    }
}

/// State of one owner slot in the prior owner table (an input to composition).
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

/// Snapshot of the owner table, indexed by slot (slot 0 = system), plus the
/// committed plan's records: prior assignments (so resident pods retain their
/// module/edge ranges verbatim across membership changes) and prior
/// revocations (carried forward until expiry).
#[derive(Clone, Debug, Default)]
pub struct OwnerSnapshot {
    pub slots: Vec<SlotState>,
    /// The committed plan's assignments (empty when nothing committed).
    pub assignments: Vec<OwnerAssignment>,
    /// The committed plan's still-listed revocations.
    pub revocations: Vec<PlanRevocation>,
}

impl OwnerSnapshot {
    /// An empty snapshot sized for `max_owners` (only the system slot present).
    pub fn empty(max_owners: u16) -> Self {
        OwnerSnapshot {
            slots: vec![SlotState::EMPTY; max_owners as usize],
            assignments: Vec::new(),
            revocations: Vec::new(),
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
    /// Admitted hard caps from the signed resource profile. The kernel installs
    /// these so per-owner state/buffer accounting is charged against them.
    pub state_cap: u32,
    pub buffer_cap: u32,
}

/// One departing owner: its last assignment record verbatim, plus the grace
/// window. Removal is ONE generation: the
/// record moves from the assignment section to the revocation section, carrying
/// `deadline_unix = wallclock_at_publish + grace_secs` stamped by the agent.
/// While live (deadline not yet passed + settle margin) it occupies its slot
/// and charges its resource footprint in admission; expiry frees both by the
/// calendar — no acknowledgement protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanRevocation {
    pub assignment: OwnerAssignment,
    pub grace_secs: u16,
    pub deadline_unix: u64,
}

/// Settle margin added to a revocation's deadline before the agent drops the
/// record on recompose — absorbs clock skew between agent invocations.
pub const REVOCATION_SETTLE_SECS: u64 = 5;

impl PlanRevocation {
    /// Still occupying its slot/ranges/capacity at `now`?
    pub fn live_at(&self, now_unix: u64) -> bool {
        now_unix <= self.deadline_unix.saturating_add(REVOCATION_SETTLE_SECS)
    }
}

/// A composed, validated device-graph plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompositionPlan {
    pub generation: u64,
    /// Assignments in ascending slot order.
    pub assignments: Vec<OwnerAssignment>,
    /// Owners departing under a drain window, in ascending slot order. Usually
    /// empty; the revocation section is omitted from the encoding when empty.
    pub revocations: Vec<PlanRevocation>,
    /// Granted endpoint leases, ordered by
    /// (slot, protocol, port), empty when the workload declares no exports. The
    /// lease section is always encoded — its presence marks the plan lease-aware
    /// and makes bind-gate enforcement mandatory.
    pub leases: Vec<PlanLease>,
    pub plan_digest: Digest32,
}

/// One granted endpoint lease: owner `(slot, generation)` may bind
/// `(protocol, port)`. Composed from the admitted
/// workload's declared exports; the runtime's bind gate enforces it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanLease {
    pub slot: u16,
    pub generation: u32,
    /// 1 = tcp, 2 = udp.
    pub protocol: u8,
    pub port: u16,
}

/// Protocol byte values for [`PlanLease::protocol`].
pub const LEASE_PROTO_TCP: u8 = 1;
pub const LEASE_PROTO_UDP: u8 = 2;

/// Map an export's protocol string to a lease protocol byte; `None` for
/// protocols the lease system does not cover (reported but not granted/gated).
pub fn lease_protocol(protocol: &str) -> Option<u8> {
    if protocol.eq_ignore_ascii_case("tcp") {
        Some(LEASE_PROTO_TCP)
    } else if protocol.eq_ignore_ascii_case("udp") {
        Some(LEASE_PROTO_UDP)
    } else {
        None
    }
}

/// Why composition failed admission against the node's static capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComposeError {
    OwnerSlotsExhausted,
    /// Two owners were granted the same (protocol, port), or a lease intersects
    /// the node's reserved-port set — caught at
    /// commit, before anything runs.
    EndpointConflict,
    ModulesExceeded,
    EdgesExceeded,
    StateBytesExceeded,
    BufferBytesExceeded,
    EndpointsExceeded,
    DomainsExceeded,
}

/// One occupied interval in an index space (module or edge).
type Interval = (u32, u32); // (base, count)

/// First-fit `count` into the space `[0, max)` avoiding `occupied` (sorted by
/// base). Returns the base, or None when no gap holds it (free-but-fragmented
/// space is reported honestly as exhaustion).
fn first_fit(occupied: &[Interval], count: u32, max: u32) -> Option<u32> {
    if count == 0 {
        return Some(0);
    }
    let mut cursor: u32 = 0;
    for &(base, len) in occupied {
        if base >= cursor && base - cursor >= count {
            return Some(cursor);
        }
        cursor = cursor.max(base + len);
    }
    if max >= cursor && max - cursor >= count {
        return Some(cursor);
    }
    None
}

fn insert_interval(occupied: &mut Vec<Interval>, base: u32, count: u32) {
    if count == 0 {
        return;
    }
    let pos = occupied.partition_point(|&(b, _)| b < base);
    occupied.insert(pos, (base, count));
}

/// Compose a candidate device graph. Deterministic in
/// `(desired, cap, prior, revoke_graces, now_unix)` — the clock is an input,
/// stamped by the agent at publish, never read here.
///
/// Revocation lifecycle: prior
/// revocations are carried forward until expiry; a prior occupant absent from
/// the new running set departs as a NEW revocation record (its last assignment
/// verbatim + `deadline_unix = now + grace`); live revocations occupy their
/// slot, hold their module/edge ranges, and charge state/buffer capacity.
/// Resident pods retain their prior ranges verbatim; new (or resized) pods are
/// placed first-fit into the gaps, so a removal generation leaves every
/// surviving assignment byte-identical.
pub fn compose(
    desired: &DeviceDesiredState,
    cap: &NodeCapacity,
    prior: &OwnerSnapshot,
    revoke_graces: &[(PodUid, u16)],
    now_unix: u64,
    reserved_ports: &[u16],
    system_modules: u16,
) -> Result<CompositionPlan, ComposeError> {
    // 1. Only running pods are placed; sort by pod_uid for a stable order.
    let mut running: Vec<&PodDesired> = desired
        .pods
        .iter()
        .filter(|p| p.desired_phase == DesiredPhase::Running)
        .collect();
    running.sort_by(|a, b| a.pod_uid.cmp(&b.pod_uid));

    // 2. Revocations: carry forward the prior plan's live records, then add one
    //    for each prior occupant departing in this generation.
    let mut revocations: Vec<PlanRevocation> = prior
        .revocations
        .iter()
        .filter(|r| r.live_at(now_unix))
        .copied()
        .collect();
    let prior_assignment_of = |uid: &PodUid| prior.assignments.iter().find(|a| &a.pod_uid == uid);
    for a in &prior.assignments {
        let still_running = running.iter().any(|p| p.pod_uid == a.pod_uid);
        let already_revoked = revocations
            .iter()
            .any(|r| r.assignment.slot == a.slot && r.assignment.generation == a.generation);
        if !still_running && !already_revoked {
            let grace = revoke_graces
                .iter()
                .find(|(uid, _)| uid == &a.pod_uid)
                .map(|(_, g)| *g)
                .unwrap_or(0);
            let rev = PlanRevocation {
                assignment: *a,
                grace_secs: grace,
                deadline_unix: now_unix.saturating_add(grace as u64),
            };
            if rev.live_at(now_unix) {
                revocations.push(rev);
            }
        }
    }
    revocations.sort_by_key(|r| r.assignment.slot);

    // 3. Assign owner slots. Resident pods keep their slot+generation; new pods
    //    take the lowest free slot (never one held by a live revocation) with a
    //    bumped generation.
    let mut occupied_slots: Vec<u16> = running
        .iter()
        .filter_map(|p| prior.slot_of(&p.pod_uid))
        .collect();
    occupied_slots.extend(revocations.iter().map(|r| r.assignment.slot));

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
            let slot = free_slot(&occupied_slots, cap).ok_or(ComposeError::OwnerSlotsExhausted)?;
            placed.push((slot, prior.generation_at(slot).wrapping_add(1)));
        }
    }

    // 4. Range layout: live revocations hold their ranges; resident pods
    //    whose profile still matches retain their prior ranges VERBATIM; new or
    //    resized pods first-fit into the gaps. Aggregate capacity charges
    //    running pods plus live revocations (the draining owner really is still
    //    holding modules/state/buffers).
    let mut module_occ: Vec<Interval> = Vec::new();
    let mut edge_occ: Vec<Interval> = Vec::new();
    // The node substrate's platform prefix:
    // platform stacks PREPEND their modules (linux_net et al. at the low
    // indices), so the ownable range starts past them. Occupied, never
    // charged — system modules belong to no workload.
    if system_modules > 0 {
        insert_interval(&mut module_occ, 0, system_modules as u32);
    }
    let mut total_state: u64 = 0;
    let mut total_buffer: u64 = 0;
    let mut total_modules: u32 = 0;
    let mut total_edges: u32 = 0;
    for r in &revocations {
        let a = &r.assignment;
        insert_interval(&mut module_occ, a.module_base as u32, a.module_count as u32);
        insert_interval(&mut edge_occ, a.edge_base as u32, a.edge_count as u32);
        total_modules += a.module_count as u32;
        total_edges += a.edge_count as u32;
        total_state += a.state_cap as u64;
        total_buffer += a.buffer_cap as u64;
    }

    // Retained residents first (their ranges are fixed), then the rest.
    let mut order: Vec<usize> = (0..running.len()).collect();
    order.sort_by_key(|&i| placed[i].0);

    struct Pending {
        idx: usize,
        retained: Option<(u16, u16)>, // (module_base, edge_base) kept verbatim
    }
    let mut pending: Vec<Pending> = Vec::with_capacity(order.len());
    for &i in &order {
        let p = running[i];
        let retained = prior_assignment_of(&p.pod_uid).and_then(|a| {
            (a.module_count == p.profile.modules && a.edge_count == p.profile.edges)
                .then_some((a.module_base, a.edge_base))
        });
        if let Some((mb, eb)) = retained {
            insert_interval(&mut module_occ, mb as u32, p.profile.modules as u32);
            insert_interval(&mut edge_occ, eb as u32, p.profile.edges as u32);
        }
        pending.push(Pending { idx: i, retained });
    }

    let mut total_endpoints: u32 = 0;
    let mut total_domains: u32 = 0;
    let mut assignments: Vec<OwnerAssignment> = Vec::with_capacity(order.len());
    let mut leases: Vec<PlanLease> = Vec::new();

    for pend in &pending {
        let p = running[pend.idx];
        let (slot, generation) = placed[pend.idx];

        total_modules += p.profile.modules as u32;
        if total_modules > cap.max_modules as u32 {
            return Err(ComposeError::ModulesExceeded);
        }
        total_edges += p.profile.edges as u32;
        if total_edges > cap.max_edges as u32 {
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

        let (module_base, edge_base) = match pend.retained {
            Some((mb, eb)) => (mb as u32, eb as u32),
            None => {
                let mb = first_fit(
                    &module_occ,
                    p.profile.modules as u32,
                    cap.max_modules as u32,
                )
                .ok_or(ComposeError::ModulesExceeded)?;
                let eb = first_fit(&edge_occ, p.profile.edges as u32, cap.max_edges as u32)
                    .ok_or(ComposeError::EdgesExceeded)?;
                insert_interval(&mut module_occ, mb, p.profile.modules as u32);
                insert_interval(&mut edge_occ, eb, p.profile.edges as u32);
                (mb, eb)
            }
        };

        assignments.push(OwnerAssignment {
            pod_uid: p.pod_uid,
            slot,
            generation,
            module_base: module_base as u16,
            module_count: p.profile.modules,
            edge_base: edge_base as u16,
            edge_count: p.profile.edges,
            state_cap: p.profile.state_bytes,
            buffer_cap: p.profile.buffer_bytes,
        });

        // Endpoint leases: one per declared
        // tcp/udp export, charged against the pod's admitted endpoint count;
        // duplicates across owners and reserved-port intersections are
        // admission-time errors — a bind race between co-resident pods (or
        // with the embedding host's own listeners) never reaches the node.
        // A DRAINING owner's ports are not in this set (revocation records
        // carry no exports); overlap with a drain window is refused at bind
        // time by the owner-aware fast path instead.
        let mut pod_leases = 0u32;
        for export in &p.exports {
            let Some(protocol) = lease_protocol(&export.protocol) else {
                continue; // non-tcp/udp exports are reported, not leased
            };
            pod_leases += 1;
            if pod_leases > p.profile.endpoints as u32 {
                return Err(ComposeError::EndpointsExceeded);
            }
            // Port 0 cannot be exported: the kernel's bind gate treats 0 as
            // an ephemeral-source bind and never matches it to a lease, so a
            // port-0 grant would silently never serve. Refuse the declaration.
            if export.port == 0 || reserved_ports.contains(&export.port) {
                return Err(ComposeError::EndpointConflict);
            }
            if leases
                .iter()
                .any(|l: &PlanLease| l.protocol == protocol && l.port == export.port)
            {
                return Err(ComposeError::EndpointConflict);
            }
            leases.push(PlanLease {
                slot,
                generation,
                protocol,
                port: export.port,
            });
        }
    }

    let plan_digest = digest_plan(desired.generation, &assignments, &revocations, &leases);
    Ok(CompositionPlan {
        generation: desired.generation,
        assignments,
        revocations,
        leases,
        plan_digest,
    })
}

/// Per-assignment fixed record width in the canonical plan body:
/// pod_uid(16) + slot(2) + generation(4) + module_base(2) + module_count(2)
/// + edge_base(2) + edge_count(2).
const ASSIGN_REC_LEN: usize = 16 + 2 + 4 + 2 + 2 + 2 + 2 + 4 + 4;

/// Per-revocation fixed record width: an assignment record verbatim plus
/// grace_secs(2) + deadline_unix(8).
const REVOKE_REC_LEN: usize = ASSIGN_REC_LEN + 2 + 8;
/// Per-lease fixed record width: slot(2) + generation(4) + protocol(1) + port(2).
const LEASE_REC_LEN: usize = 2 + 4 + 1 + 2;
/// Opens the lease section: an IMPOSSIBLE
/// revocation count (counts are capped at MAX_PLAN_ASSIGNMENTS), so the first
/// u32 of the tail deterministically discriminates the sections — no length
/// arithmetic is trusted for discrimination (48-byte revocation and 9-byte
/// lease records collide at e.g. 148 tail bytes). Lives inside the digested
/// body, unlike header bits, so it is integrity-protected.
const LEASE_SECTION_MARKER: u32 = 0xFFFF_FFFF;
/// Decoder ceiling for the lease section (bounded-binary rule).
pub const MAX_PLAN_LEASES: usize = 256;

fn push_assignment(buf: &mut Vec<u8>, a: &OwnerAssignment) {
    buf.extend_from_slice(&a.pod_uid);
    buf.extend_from_slice(&a.slot.to_be_bytes());
    buf.extend_from_slice(&a.generation.to_be_bytes());
    buf.extend_from_slice(&a.module_base.to_be_bytes());
    buf.extend_from_slice(&a.module_count.to_be_bytes());
    buf.extend_from_slice(&a.edge_base.to_be_bytes());
    buf.extend_from_slice(&a.edge_count.to_be_bytes());
    buf.extend_from_slice(&a.state_cap.to_be_bytes());
    buf.extend_from_slice(&a.buffer_cap.to_be_bytes());
}

/// Canonical, fixed-width big-endian serialization of a plan's payload
/// (generation + count + assignments [+ revocation section]). Stable across
/// platforms, so the digest over it — and the encoded plan — are reproducible.
/// Shared by `digest_plan` and `encode_plan`.
///
/// The revocation section (`rev_count(4)` + records) is appended only when
/// non-empty — a plan with no revocations, the overwhelmingly common case,
/// omits it entirely.
fn plan_body(
    generation: u64,
    assignments: &[OwnerAssignment],
    revocations: &[PlanRevocation],
    leases: &[PlanLease],
) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(
        12 + assignments.len() * ASSIGN_REC_LEN
            + if revocations.is_empty() {
                0
            } else {
                4 + revocations.len() * REVOKE_REC_LEN
            },
    );
    buf.extend_from_slice(&generation.to_be_bytes());
    buf.extend_from_slice(&(assignments.len() as u32).to_be_bytes());
    for a in assignments {
        push_assignment(&mut buf, a);
    }
    if !revocations.is_empty() {
        buf.extend_from_slice(&(revocations.len() as u32).to_be_bytes());
        for r in revocations {
            push_assignment(&mut buf, &r.assignment);
            buf.extend_from_slice(&r.grace_secs.to_be_bytes());
            buf.extend_from_slice(&r.deadline_unix.to_be_bytes());
        }
    }
    // Lease section: marker + count + records,
    // fixed order revocations-before-leases. The section is always emitted, even
    // with zero grants: its presence is the integrity-protected signal that the
    // plan is lease-aware, and the kernel bind gate enforces it mandatorily (an
    // owner may bind only a nonzero port it was granted).
    buf.extend_from_slice(&LEASE_SECTION_MARKER.to_be_bytes());
    buf.extend_from_slice(&(leases.len() as u32).to_be_bytes());
    for l in leases {
        buf.extend_from_slice(&l.slot.to_be_bytes());
        buf.extend_from_slice(&l.generation.to_be_bytes());
        buf.push(l.protocol);
        buf.extend_from_slice(&l.port.to_be_bytes());
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
/// bytes — and therefore the digest — are stable across platforms. Covers the
/// revocation section too: a tampered deadline fails the digest.
fn digest_plan(
    generation: u64,
    assignments: &[OwnerAssignment],
    revocations: &[PlanRevocation],
    leases: &[PlanLease],
) -> Digest32 {
    sha256_of(&plan_body(generation, assignments, revocations, leases))
}

// ============================================================================
// Binary plan codec. The kernel consumes a validated, bounded binary plan; it
// never parses Kubernetes objects, OCI manifests, or YAML.
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
    let body = plan_body(
        plan.generation,
        &plan.assignments,
        &plan.revocations,
        &plan.leases,
    );
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
    let assign_len = 12 + count * ASSIGN_REC_LEN;
    let base_total = PLAN_HEADER_LEN + assign_len + 32;
    if bytes.len() < base_total {
        return Err(PlanDecodeError::Truncated);
    }
    // Optional revocation section: present iff bytes remain between the
    // assignments and the digest (an empty revocation section is not encoded).
    // Tail grammar: [rev_section] [lease_section],
    // fixed order, each omitted when empty. The first u32 of the surplus
    // discriminates deterministically: LEASE_SECTION_MARKER (an impossible
    // revocation count) opens a lease section; a valid count (1..=cap) opens
    // the revocation section. Length equations validate, never discriminate.
    let mut cursor = assign_len; // offset into `body`
    let tail_end = bytes.len() - PLAN_HEADER_LEN - 32; // end of body incl. tail
    let read_u32_at = |off: usize| -> Option<u32> {
        body.get(off..off + 4)
            .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
    };
    let mut rev_count = 0usize;
    let mut lease_count = 0usize;
    if cursor < tail_end {
        let first = read_u32_at(cursor).ok_or(PlanDecodeError::Truncated)?;
        if first != LEASE_SECTION_MARKER {
            let rc = first as usize;
            if rc == 0 || rc > MAX_PLAN_ASSIGNMENTS {
                // An explicitly-empty section is not a valid encoding; treat
                // like trailing garbage, not a second spelling of "none".
                return Err(PlanDecodeError::TrailingBytes);
            }
            rev_count = rc;
            cursor += 4 + rev_count * REVOKE_REC_LEN;
            if cursor > tail_end {
                return Err(PlanDecodeError::Truncated);
            }
        }
    }
    if cursor < tail_end {
        let marker = read_u32_at(cursor).ok_or(PlanDecodeError::Truncated)?;
        if marker != LEASE_SECTION_MARKER {
            return Err(PlanDecodeError::TrailingBytes);
        }
        let lc = read_u32_at(cursor + 4).ok_or(PlanDecodeError::Truncated)? as usize;
        // Count 0 is valid — a plan that grants no endpoints; only an over-cap
        // count is rejected.
        if lc > MAX_PLAN_LEASES {
            return Err(PlanDecodeError::TrailingBytes);
        }
        lease_count = lc;
        cursor += 4 + 4 + lease_count * LEASE_REC_LEN;
    }
    let body_len = cursor;
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
    let read_assignment = |r: &[u8]| -> OwnerAssignment {
        let mut pod_uid = [0u8; 16];
        pod_uid.copy_from_slice(&r[0..16]);
        OwnerAssignment {
            pod_uid,
            slot: u16::from_be_bytes(r[16..18].try_into().unwrap()),
            generation: u32::from_be_bytes(r[18..22].try_into().unwrap()),
            module_base: u16::from_be_bytes(r[22..24].try_into().unwrap()),
            module_count: u16::from_be_bytes(r[24..26].try_into().unwrap()),
            edge_base: u16::from_be_bytes(r[26..28].try_into().unwrap()),
            edge_count: u16::from_be_bytes(r[28..30].try_into().unwrap()),
            state_cap: u32::from_be_bytes(r[30..34].try_into().unwrap()),
            buffer_cap: u32::from_be_bytes(r[34..38].try_into().unwrap()),
        }
    };
    let mut assignments = Vec::with_capacity(count);
    for i in 0..count {
        assignments.push(read_assignment(
            &body[12 + i * ASSIGN_REC_LEN..12 + (i + 1) * ASSIGN_REC_LEN],
        ));
    }
    let mut revocations = Vec::with_capacity(rev_count);
    for i in 0..rev_count {
        let base = assign_len + 4 + i * REVOKE_REC_LEN;
        let r = &body[base..base + REVOKE_REC_LEN];
        revocations.push(PlanRevocation {
            assignment: read_assignment(&r[..ASSIGN_REC_LEN]),
            grace_secs: u16::from_be_bytes(
                r[ASSIGN_REC_LEN..ASSIGN_REC_LEN + 2].try_into().unwrap(),
            ),
            deadline_unix: u64::from_be_bytes(
                r[ASSIGN_REC_LEN + 2..ASSIGN_REC_LEN + 10]
                    .try_into()
                    .unwrap(),
            ),
        });
    }
    let mut leases = Vec::with_capacity(lease_count);
    let lease_base = assign_len
        + if rev_count > 0 {
            4 + rev_count * REVOKE_REC_LEN
        } else {
            0
        }
        + 8; // marker + count
    for i in 0..lease_count {
        let base = lease_base + i * LEASE_REC_LEN;
        let r = &body[base..base + LEASE_REC_LEN];
        leases.push(PlanLease {
            slot: u16::from_be_bytes(r[0..2].try_into().unwrap()),
            generation: u32::from_be_bytes(r[2..6].try_into().unwrap()),
            protocol: r[6],
            port: u16::from_be_bytes(r[7..9].try_into().unwrap()),
        });
    }
    let mut plan_digest = [0u8; 32];
    plan_digest.copy_from_slice(digest);
    Ok(CompositionPlan {
        generation,
        assignments,
        revocations,
        leases,
        plan_digest,
    })
}

// ============================================================================
// Reservation protocol
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
    /// The token's node epoch does not match the node's current one — it was
    /// issued before a crash/recover.
    StaleEpoch,
    /// The token was already consumed (single-use violation).
    AlreadyConsumed,
}

/// Tracks the node epoch and consumed tokens so each reservation stages exactly
/// once. A crash before commit is modelled by [`recover`](Self::recover), which
/// bumps the epoch and invalidates every outstanding token.
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
    /// re-activate a candidate.
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
            exports: Vec::new(),
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

        let p1 = compose(&s1, &cap(), &snap, &[], 0, &[], 0).unwrap();
        let p2 = compose(&s2, &cap(), &snap, &[], 0, &[], 0).unwrap();
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
        let plan = compose(&ds, &cap(), &snap, &[], 0, &[], 0).unwrap();
        assert_eq!(plan.assignments.len(), 1);
        assert_eq!(plan.assignments[0].pod_uid, uid(2));
    }

    #[test]
    fn resident_workload_keeps_slot_new_pod_bumps_generation() {
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
        let plan = compose(&ds, &cap(), &snap, &[], 0, &[], 0).unwrap();
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
        let plan = compose(&ds, &cap(), &snap, &[], 0, &[], 0).unwrap();
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
            compose(&ds, &cap(), &snap, &[], 0, &[], 0),
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
            compose(&ds, &small, &snap, &[], 0, &[], 0),
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
        compose(&ds, &cap(), &snap, &[], 0, &[], 0).unwrap()
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
            revocations: vec![],
            leases: vec![],
            plan_digest: digest_plan(7, &[], &[], &[]),
        };
        assert_eq!(decode_plan(&encode_plan(&plan)).unwrap(), plan);
    }

    #[test]
    fn lease_section_round_trips_alone_with_revocations_and_never_misparses() {
        let lease = |slot: u16, port: u16| PlanLease {
            slot,
            generation: 1,
            protocol: LEASE_PROTO_TCP,
            port,
        };
        let base = sample_plan();

        // Lease-only plan round-trips (the marker discriminates the section;
        // pre-marker decoders would have misparsed this as revocations).
        let mut lease_only = base.clone();
        lease_only.leases = vec![lease(1, 8080), lease(2, 9090)];
        lease_only.plan_digest = digest_plan(
            lease_only.generation,
            &lease_only.assignments,
            &[],
            &lease_only.leases,
        );
        let decoded = decode_plan(&encode_plan(&lease_only)).unwrap();
        assert_eq!(decoded.leases, lease_only.leases);
        assert!(decoded.revocations.is_empty());

        // THE COLLISION PAIR: 3 revocations and 16
        // leases both occupy 148 tail bytes. Each decodes to its own section.
        let committed = sample_plan();
        let snap = snap_from(&committed, 16);
        let ds = DeviceDesiredState {
            generation: 43,
            system_revision: 1,
            pods: vec![],
        };
        // Build a plan with exactly 3 revocations via three graced removals.
        let mut with_revs = compose(
            &ds,
            &cap(),
            &snap,
            &[(uid(1), 60), (uid(2), 60)],
            1000,
            &[],
            0,
        )
        .unwrap();
        // Manufacture the third revocation by hand to hit exactly R=3.
        let mut third = with_revs.revocations[0];
        third.assignment.slot = 9;
        with_revs.revocations.push(third);
        with_revs.plan_digest = digest_plan(
            with_revs.generation,
            &with_revs.assignments,
            &with_revs.revocations,
            &[],
        );
        let mut sixteen_leases = base.clone();
        sixteen_leases.leases = (0..16).map(|i| lease(1, 7000 + i as u16)).collect();
        sixteen_leases.plan_digest = digest_plan(
            sixteen_leases.generation,
            &sixteen_leases.assignments,
            &[],
            &sixteen_leases.leases,
        );
        let rev_bytes = encode_plan(&with_revs);
        let lease_bytes = encode_plan(&sixteen_leases);
        // The ambiguity the marker removes: under count-only framing, a
        // 3-revocation tail and a 16-lease tail would both be 148 bytes —
        // undecidable by length. The marker adds 4 bytes to the lease section
        // precisely to make the first u32 discriminate instead.
        assert_eq!(
            4 + 3 * REVOKE_REC_LEN,
            4 + 16 * LEASE_REC_LEN,
            "the documented 148-byte collision (marker-less framing)"
        );
        // …and each decodes to the correct section.
        let r = decode_plan(&rev_bytes).unwrap();
        assert_eq!((r.revocations.len(), r.leases.len()), (3, 0));
        let l = decode_plan(&lease_bytes).unwrap();
        assert_eq!((l.revocations.len(), l.leases.len()), (0, 16));

        // Both sections together round-trip, order rev-then-lease.
        let mut both = with_revs.clone();
        both.leases = vec![lease(2, 8080)];
        both.plan_digest = digest_plan(
            both.generation,
            &both.assignments,
            &both.revocations,
            &both.leases,
        );
        let d = decode_plan(&encode_plan(&both)).unwrap();
        assert_eq!(d.revocations.len(), 3);
        assert_eq!(d.leases, both.leases);

        // Truncating inside the lease section fails closed.
        let bytes = encode_plan(&sixteen_leases);
        assert!(decode_plan(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn compose_grants_charges_and_conflicts_leases() {
        let exported_pod = |n: u8, port: u16, endpoints: u16| {
            let mut p = pod(n, DesiredPhase::Running, profile(4, 6));
            p.profile.endpoints = endpoints;
            p.exports = vec![ExportDecl {
                protocol: "TCP".into(),
                port,
            }];
            p
        };
        let snap = OwnerSnapshot::empty(16);

        // Grant: an export becomes a lease bound to the pod's (slot, gen).
        let ds = DeviceDesiredState {
            generation: 1,
            system_revision: 1,
            pods: vec![exported_pod(1, 8080, 1)],
        };
        let plan = compose(&ds, &cap(), &snap, &[], 0, &[], 0).unwrap();
        assert_eq!(plan.leases.len(), 1);
        assert_eq!(plan.leases[0].port, 8080);
        assert_eq!(plan.leases[0].slot, plan.assignments[0].slot);

        // Charge: more exports than admitted endpoints → EndpointsExceeded.
        let mut greedy = exported_pod(2, 7000, 1);
        greedy.exports.push(ExportDecl {
            protocol: "udp".into(),
            port: 7001,
        });
        let ds = DeviceDesiredState {
            generation: 1,
            system_revision: 1,
            pods: vec![greedy],
        };
        assert_eq!(
            compose(&ds, &cap(), &snap, &[], 0, &[], 0),
            Err(ComposeError::EndpointsExceeded)
        );

        // Conflict: two owners, same (protocol, port) → admission-time error.
        let ds = DeviceDesiredState {
            generation: 1,
            system_revision: 1,
            pods: vec![exported_pod(1, 8080, 1), exported_pod(2, 8080, 1)],
        };
        assert_eq!(
            compose(&ds, &cap(), &snap, &[], 0, &[], 0),
            Err(ComposeError::EndpointConflict)
        );

        // Reserved ports (the embedding host's own listeners) refuse the grant.
        let ds = DeviceDesiredState {
            generation: 1,
            system_revision: 1,
            pods: vec![exported_pod(1, 6443, 1)],
        };
        assert_eq!(
            compose(&ds, &cap(), &snap, &[], 0, &[6443], 0),
            Err(ComposeError::EndpointConflict)
        );

        // Port 0 cannot be exported: the kernel gate never matches a lease
        // to an ephemeral bind, so the grant could silently never serve.
        let ds = DeviceDesiredState {
            generation: 1,
            system_revision: 1,
            pods: vec![exported_pod(1, 0, 1)],
        };
        assert_eq!(
            compose(&ds, &cap(), &snap, &[], 0, &[], 0),
            Err(ComposeError::EndpointConflict)
        );
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

    /// A snapshot that carries the given plan as prior state (occupancy +
    /// retained ranges + revocations), the way `snapshot_from_committed` does.
    fn snap_from(plan: &CompositionPlan, max_owners: u16) -> OwnerSnapshot {
        let mut snap = OwnerSnapshot::empty(max_owners);
        for a in &plan.assignments {
            snap.slots[a.slot as usize].occupant = Some(a.pod_uid);
            snap.slots[a.slot as usize].generation = a.generation;
        }
        for r in &plan.revocations {
            let s = &mut snap.slots[r.assignment.slot as usize];
            s.generation = s.generation.max(r.assignment.generation);
        }
        snap.assignments = plan.assignments.clone();
        snap.revocations = plan.revocations.clone();
        snap
    }

    #[test]
    fn no_revocation_plan_has_the_canonical_layout_with_an_empty_lease_section() {
        // Canonical layout, hand-built: header + generation + count + assignment
        // records + [no revocation section] + lease section (marker + count 0) +
        // sha256(body). The revocation section is omitted when empty; the lease
        // section is always emitted, so a no-revocation, no-lease plan carries
        // the 8-byte empty section and nothing more.
        let plan = sample_plan();
        assert!(plan.revocations.is_empty() && plan.leases.is_empty());
        let mut expected = Vec::new();
        expected.extend_from_slice(&PLAN_MAGIC.to_be_bytes());
        expected.extend_from_slice(&PLAN_VERSION.to_be_bytes());
        expected.extend_from_slice(&0u16.to_be_bytes());
        let mut body = Vec::new();
        body.extend_from_slice(&plan.generation.to_be_bytes());
        body.extend_from_slice(&(plan.assignments.len() as u32).to_be_bytes());
        for a in &plan.assignments {
            push_assignment(&mut body, a);
        }
        // Always-present lease section: marker + count(0), no records.
        body.extend_from_slice(&LEASE_SECTION_MARKER.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        expected.extend_from_slice(&body);
        expected.extend_from_slice(&sha256_of(&body));
        assert_eq!(encode_plan(&plan), expected);
    }

    #[test]
    fn plan_with_revocations_round_trips_and_digest_guards_the_deadline() {
        let committed = sample_plan();
        let snap = snap_from(&committed, 16);
        // Remove pod 1 with a 30 s grace at t=1000.
        let ds = DeviceDesiredState {
            generation: 43,
            system_revision: 1,
            pods: vec![pod(2, DesiredPhase::Running, profile(8, 10))],
        };
        let plan = compose(&ds, &cap(), &snap, &[(uid(1), 30)], 1000, &[], 0).unwrap();
        assert_eq!(plan.assignments.len(), 1);
        assert_eq!(plan.revocations.len(), 1);
        let rev = &plan.revocations[0];
        assert_eq!(rev.assignment.pod_uid, uid(1));
        assert_eq!(rev.grace_secs, 30);
        assert_eq!(rev.deadline_unix, 1030);

        let bytes = encode_plan(&plan);
        assert_eq!(decode_plan(&bytes).unwrap(), plan);

        // Tampering with the stamped deadline fails the digest. deadline_unix is
        // the last field of the revocation record, which sits before the 8-byte
        // empty lease section and the 32-byte digest — structurally inert
        // (framing unchanged) but digest-covered.
        let mut tampered = bytes.clone();
        let deadline_last = tampered.len() - 32 - 8 - 1; // - digest - empty lease section
        tampered[deadline_last] ^= 0xFF;
        assert_eq!(decode_plan(&tampered), Err(PlanDecodeError::DigestMismatch));

        // Truncating inside the revocation section fails closed.
        assert!(decode_plan(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn removal_leaves_survivors_byte_identical_and_holds_the_departed_ranges() {
        let committed = sample_plan();
        let survivor = *committed
            .assignments
            .iter()
            .find(|a| a.pod_uid == uid(2))
            .unwrap();
        let departed = *committed
            .assignments
            .iter()
            .find(|a| a.pod_uid == uid(1))
            .unwrap();
        let snap = snap_from(&committed, 16);

        let ds = DeviceDesiredState {
            generation: 43,
            system_revision: 1,
            pods: vec![pod(2, DesiredPhase::Running, profile(8, 10))],
        };
        let plan = compose(&ds, &cap(), &snap, &[(uid(1), 60)], 1000, &[], 0).unwrap();
        // The survivor's record is BYTE-identical (slot, gen, ranges).
        assert_eq!(plan.assignments, vec![survivor]);
        // The departed owner's ranges are still held by its revocation.
        assert_eq!(plan.revocations[0].assignment, departed);

        // A new pod admitted during the drain first-fits AROUND the held
        // ranges — it must not overlap the draining owner's modules.
        let snap2 = snap_from(&plan, 16);
        let ds2 = DeviceDesiredState {
            generation: 44,
            system_revision: 1,
            pods: vec![
                pod(2, DesiredPhase::Running, profile(8, 10)),
                pod(3, DesiredPhase::Running, profile(4, 6)),
            ],
        };
        let plan2 = compose(&ds2, &cap(), &snap2, &[], 1001, &[], 0).unwrap();
        let newcomer = plan2
            .assignments
            .iter()
            .find(|a| a.pod_uid == uid(3))
            .unwrap();
        let dep_end = departed.module_base + departed.module_count;
        let new_end = newcomer.module_base + newcomer.module_count;
        assert!(
            new_end <= departed.module_base || newcomer.module_base >= dep_end,
            "newcomer {}..{} overlaps draining owner {}..{}",
            newcomer.module_base,
            new_end,
            departed.module_base,
            dep_end
        );
    }

    #[test]
    fn expired_revocation_frees_slot_ranges_and_capacity() {
        let committed = sample_plan();
        let departed = *committed
            .assignments
            .iter()
            .find(|a| a.pod_uid == uid(1))
            .unwrap();
        let snap = snap_from(&committed, 16);
        let ds = DeviceDesiredState {
            generation: 43,
            system_revision: 1,
            pods: vec![pod(2, DesiredPhase::Running, profile(8, 10))],
        };
        let plan = compose(&ds, &cap(), &snap, &[(uid(1), 10)], 1000, &[], 0).unwrap();
        assert_eq!(plan.revocations.len(), 1, "live during the window");

        // Recompose after deadline + settle: the record drops, and a new pod
        // may reuse the freed slot (post-expiry, at a bumped generation via the
        // high-water table — modeled here by the retained snapshot generation).
        let snap2 = snap_from(&plan, 16);
        let ds2 = DeviceDesiredState {
            generation: 44,
            system_revision: 1,
            pods: vec![
                pod(2, DesiredPhase::Running, profile(8, 10)),
                pod(3, DesiredPhase::Running, profile(4, 6)),
            ],
        };
        let expired_now = 1000 + 10 + REVOCATION_SETTLE_SECS + 1;
        let plan2 = compose(&ds2, &cap(), &snap2, &[], expired_now, &[], 0).unwrap();
        assert!(plan2.revocations.is_empty(), "expired record dropped");
        let newcomer = plan2
            .assignments
            .iter()
            .find(|a| a.pod_uid == uid(3))
            .unwrap();
        assert_eq!(newcomer.slot, departed.slot, "slot freed by the calendar");
        assert!(
            newcomer.generation > departed.generation,
            "reuse bumps past the departed occupant"
        );
    }

    #[test]
    fn revocations_charge_capacity_honestly() {
        // Node with room for exactly 12 modules. One 8-module pod committed.
        let mut small = cap();
        small.max_modules = 12;
        let snap0 = OwnerSnapshot::empty(16);
        let ds0 = DeviceDesiredState {
            generation: 1,
            system_revision: 1,
            pods: vec![pod(1, DesiredPhase::Running, profile(8, 4))],
        };
        let committed = compose(&ds0, &small, &snap0, &[], 0, &[], 0).unwrap();

        // Remove it with grace, and try to admit another 8-module pod during
        // the window: the draining owner still holds its 8 modules, so the
        // node honestly reports exhaustion.
        let snap = snap_from(&committed, 16);
        let ds = DeviceDesiredState {
            generation: 2,
            system_revision: 1,
            pods: vec![pod(2, DesiredPhase::Running, profile(8, 4))],
        };
        assert_eq!(
            compose(&ds, &small, &snap, &[(uid(1), 60)], 1000, &[], 0),
            Err(ComposeError::ModulesExceeded)
        );

        // The removal alone (no newcomer) commits fine; its snapshot carries the
        // live revocation forward. After expiry, recomposing with the newcomer
        // succeeds — capacity freed by the calendar, no acknowledgement.
        let ds_removed = DeviceDesiredState {
            generation: 2,
            system_revision: 1,
            pods: vec![],
        };
        let removal = compose(&ds_removed, &small, &snap, &[(uid(1), 60)], 1000, &[], 0).unwrap();
        assert_eq!(removal.revocations.len(), 1);
        let snap2 = snap_from(&removal, 16);
        let ds2 = DeviceDesiredState {
            generation: 3,
            system_revision: 1,
            pods: vec![pod(2, DesiredPhase::Running, profile(8, 4))],
        };
        assert_eq!(
            compose(&ds2, &small, &snap2, &[], 1000, &[], 0),
            Err(ComposeError::ModulesExceeded),
            "still exhausted during the window"
        );
        let expired = 1000 + 60 + REVOCATION_SETTLE_SECS + 1;
        assert!(compose(&ds2, &small, &snap2, &[], expired, &[], 0).is_ok());
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

    /// The MCU rows of `capacity_for_profile` mirror the silicon TOMLs. Those
    /// arena sizes are the kernel's actual budget on those dies, so a composer
    /// that admits against a stale copy admits graphs the arena cannot hold —
    /// and on a 64 KiB die the margin for that error is nil.
    #[test]
    fn capacity_mirrors_silicon_tomls() {
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for (silicon, expect_state_kb, expect_buffer_kb) in
            [("rp2040", 64u64, 16u64), ("rp2350", 240, 64)]
        {
            let toml =
                std::fs::read_to_string(repo.join(format!("targets/silicon/{silicon}.toml")))
                    .unwrap_or_else(|_| panic!("{silicon}: no silicon toml"));
            let kb = |key: &str| -> u64 {
                toml.lines()
                    .find(|l| l.trim_start().starts_with(key))
                    .unwrap_or_else(|| panic!("{silicon}: no {key}"))
                    .split('=')
                    .nth(1)
                    .expect("value")
                    .trim()
                    .parse()
                    .expect("integer")
            };
            assert_eq!(
                kb("state_arena_kb"),
                expect_state_kb,
                "{silicon} state_arena_kb moved; update capacity_for_profile"
            );
            assert_eq!(
                kb("buffer_arena_kb"),
                expect_buffer_kb,
                "{silicon} buffer_arena_kb moved; update capacity_for_profile"
            );
            let cap = capacity_for_profile(silicon)
                .unwrap_or_else(|| panic!("{silicon}: no composer capacity row"));
            assert_eq!(cap.state_bytes as u64, expect_state_kb * 1024);
            assert_eq!(cap.buffer_bytes as u64, expect_buffer_kb * 1024);
        }
    }

    /// Drift guard: `capacity_for_profile` mirrors kernel constants it cannot
    /// import (they live behind target cfgs). Textual extraction is the
    /// accepted pattern for cross-cfg drift guards in this repo (see the ABI
    /// wire-surface guards); when a kernel limit changes, this fails loudly
    /// and the mirror above is the single place to update.
    #[test]
    fn capacity_mirrors_kernel_sources() {
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let read = |p: &str| std::fs::read_to_string(repo.join(p)).expect(p);

        fn extract(src: &str, name: &str) -> u64 {
            let pat = format!("pub const {name}: usize = ");
            let start = src.find(&pat).unwrap_or_else(|| panic!("{name} not found"));
            let rest = &src[start + pat.len()..];
            let expr: String = rest[..rest.find(';').expect("terminator")].to_string();
            // Evaluate `A * B * C` integer products (the only shape used).
            expr.split('*')
                .map(|t| t.trim().parse::<u64>().expect("integer term"))
                .product()
        }

        let owner = read("src/kernel/workload/owner.rs");
        let sdk = read("modules/sdk/abi/config.rs");
        let kcfg = read("src/kernel/boot/config.rs");
        let sched = read("src/kernel/exec/scheduler/mod.rs");

        // All three per-profile MAX_MODULES values, in declaration order
        // (host, wasm, embedded) — pins `kernel_max_modules` too.
        use crate::capacity::kernel_max_modules;
        assert_eq!(
            kernel_max_modules("linux") as u64,
            extract_nth(&sdk, "MAX_MODULES", 1)
        );
        assert_eq!(
            kernel_max_modules("wasm") as u64,
            extract_nth(&sdk, "MAX_MODULES", 2)
        );
        assert_eq!(
            kernel_max_modules("rp2350") as u64,
            extract_nth(&sdk, "MAX_MODULES", 3)
        );

        let cap = capacity_for_profile("linux").expect("linux profile");
        // First MAX_OWNERS in owner.rs is the multitenant value.
        assert_eq!(cap.max_owners as u64, extract(&owner, "MAX_OWNERS"));
        // First profile block in sdk config.rs is profile_host (aarch64).
        assert_eq!(cap.max_modules as u64, extract(&sdk, "MAX_MODULES"));
        assert_eq!(cap.state_bytes as u64, extract(&sdk, "STATE_ARENA_SIZE"));
        assert_eq!(cap.buffer_bytes as u64, extract(&sdk, "BUFFER_ARENA_SIZE"));
        assert_eq!(cap.max_edges as u64, extract(&kcfg, "MAX_GRAPH_EDGES"));
        assert_eq!(cap.max_domains as u64, extract(&sched, "MAX_DOMAINS"));
        // pi5/bcm2712 alias the same aarch64 profile.
        for alias in ["pi5", "bcm2712"] {
            let c = capacity_for_profile(alias).expect(alias);
            assert_eq!(c.max_modules, cap.max_modules);
            assert_eq!(c.max_owners, cap.max_owners);
        }
        // The MCU rows exist but hand out no workload owner slots:
        // multitenancy is an aarch64 feature, so `max_owners` is the system
        // slot alone. Their arena figures are pinned against the silicon
        // TOMLs by `capacity_mirrors_silicon_tomls`; what belongs here is the
        // half that mirrors a kernel source — the embedded module ceiling
        // both dies share.
        for mcu in ["rp2040", "rp2350"] {
            let c = capacity_for_profile(mcu).unwrap_or_else(|| panic!("{mcu}: no capacity row"));
            assert_eq!(c.max_owners, 1, "{mcu} is single-tenant");
            assert_eq!(
                c.max_modules as u64,
                extract_nth(&sdk, "MAX_MODULES", 3),
                "{mcu} uses profile_embedded's module ceiling"
            );
        }
    }

    /// The `n`th (1-based) `pub const <name>: usize = …;` in `src`, its
    /// right-hand side evaluated as a product of integer terms.
    ///
    /// Per-profile constants are declared once each in host, wasm, embedded
    /// order, so the occurrence index selects the profile. Textual because
    /// the kernel cannot import a profile from behind its target cfg, which
    /// is the same reason these guards exist at all.
    fn extract_nth(src: &str, name: &str, n: usize) -> u64 {
        let pat = format!("pub const {name}: usize = ");
        let mut from = 0;
        for _ in 0..n {
            let at = src[from..]
                .find(&pat)
                .unwrap_or_else(|| panic!("{name} occurrence {n} not found"));
            from += at + pat.len();
        }
        let rest = &src[from..];
        rest[..rest.find(';').expect("terminator")]
            .split('*')
            .map(|t| t.trim().parse::<u64>().expect("integer term"))
            .product()
    }

    /// Drift guard: the RP kernels size their log ring from the silicon
    /// TOML (`[kernel] log_ring_kb` → `build.rs` → `chip_generated.rs`),
    /// while `profile_embedded` publishes the same ceiling to the SDK and
    /// composer. One number with two sources, so they are pinned to each
    /// other here.
    ///
    /// What it prevents: an RP target taking the host-class 64 KiB ring,
    /// which overflows `.bss` past the linker's RAM region on both parts
    /// and surfaces as a link error naming no constant.
    #[test]
    fn log_ring_toml_mirrors_embedded_profile() {
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let sdk =
            std::fs::read_to_string(repo.join("modules/sdk/abi/config.rs")).expect("sdk config");
        let embedded = extract_nth(&sdk, "LOG_RING_CAPACITY", 3);

        for silicon in ["rp2040", "rp2350"] {
            let toml =
                std::fs::read_to_string(repo.join(format!("targets/silicon/{silicon}.toml")))
                    .expect("silicon toml");
            let line = toml
                .lines()
                .find(|l| l.trim_start().starts_with("log_ring_kb"))
                .unwrap_or_else(|| panic!("{silicon}: no log_ring_kb"));
            let kb: u64 = line
                .split('=')
                .nth(1)
                .expect("value")
                .trim()
                .parse()
                .expect("integer");
            assert_eq!(
                kb * 1024,
                embedded,
                "{silicon} log_ring_kb ({kb} KiB) disagrees with \
                 profile_embedded LOG_RING_CAPACITY ({embedded} bytes)"
            );
            assert!(
                (kb * 1024).is_power_of_two(),
                "{silicon} log ring must be a power of two (MASK indexing)"
            );
        }
    }
}
