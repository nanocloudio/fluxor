//! Node-agent reconcile → stage → commit orchestration (rfc_k8s.md §6.7, §11,
//! §12), tying together composition, the binary plan codec, and the durable
//! generation store.
//!
//! `reconcile_and_commit` is the trusted host-side step that turns a desired
//! device state into a durably committed graph generation: compose the
//! deterministic plan, encode it to the bounded binary form the kernel consumes,
//! stage it (plan blob in the content-addressed store), verify, and atomically
//! commit. `load_committed_plan` reads it back — the same bytes a device fetches
//! to apply at boot. This is the real delivery path the `FLUXOR_PLAN` /
//! `test-plan` stand-ins emulate.

use sha2::{Digest, Sha256};

use crate::compose::{
    compose, decode_plan, encode_plan, ComposeError, CompositionPlan, DesiredPhase,
    DeviceDesiredState, NodeCapacity, OwnerSnapshot, PodDesired,
};
use crate::genstore::{GenStore, Storage, StoreError};

/// Why a reconcile failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentError {
    Compose(ComposeError),
    Store(StoreError),
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Compose the candidate plan for `desired`, encode it, and durably commit it as
/// generation `gen_id` in `store`. Returns the composed plan. Deterministic in
/// `(desired, cap, prior)`; the committed generation's plan blob lives in the
/// content-addressed store keyed by its sha256.
pub fn reconcile_and_commit<S: Storage>(
    store: &mut GenStore<S>,
    desired: &DeviceDesiredState,
    cap: &NodeCapacity,
    prior: &OwnerSnapshot,
    gen_id: u64,
) -> Result<CompositionPlan, AgentError> {
    let plan = stage_candidate(store, desired, cap, prior, gen_id)?;
    store.commit(gen_id).map_err(AgentError::Store)?;
    Ok(plan)
}

/// Compose + stage + verify a candidate generation WITHOUT committing (the
/// pointer is not flipped). Split out from `reconcile_and_commit` so the node
/// agent can order its own bookkeeping writes before the final commit — the
/// commit must be the last durable write so it never becomes visible ahead of a
/// failed bookkeeping write.
fn stage_candidate<S: Storage>(
    store: &mut GenStore<S>,
    desired: &DeviceDesiredState,
    cap: &NodeCapacity,
    prior: &OwnerSnapshot,
    gen_id: u64,
) -> Result<CompositionPlan, AgentError> {
    let plan = compose(desired, cap, prior).map_err(AgentError::Compose)?;
    let blob = encode_plan(&plan);
    let blob_digest = sha256(&blob);
    store
        .stage(gen_id, blob_digest, &[(blob_digest, blob)])
        .map_err(AgentError::Store)?;
    store
        .verify_and_mark_candidate(gen_id)
        .map_err(AgentError::Store)?;
    Ok(plan)
}

/// Load and decode the plan from the currently committed generation — the bytes
/// a device fetches to apply at boot. `None` if nothing is committed or the blob
/// is missing/undecodable.
pub fn load_committed_plan<S: Storage>(store: &GenStore<S>) -> Option<CompositionPlan> {
    let g = store.committed()?;
    let blob = store.read_artifact(&g.plan_digest)?;
    decode_plan(&blob).ok()
}

/// Publish the committed generation's plan blob to `path` (temp + atomic
/// rename), for a kernel that stages its plan from a file — the Linux runtime's
/// `FLUXOR_PLAN` delivery. Returns the number of bytes published, or `None`
/// when nothing is committed.
pub fn publish_committed_plan<S: Storage>(
    store: &GenStore<S>,
    path: &std::path::Path,
) -> std::io::Result<Option<usize>> {
    let Some(g) = store.committed() else {
        return Ok(None);
    };
    let Some(blob) = store.read_artifact(&g.plan_digest) else {
        return Ok(None);
    };
    let tmp = path.with_extension("plan.tmp");
    // Durability mirrors FsStorage::write: temp write + fsync(file) + atomic
    // rename + fsync(parent dir). Without the parent-dir fsync a power loss
    // after the data fsync can still lose the rename (the new directory entry),
    // so a command that reported success could publish nothing.
    std::fs::write(&tmp, &blob)?;
    std::fs::File::open(&tmp)?.sync_all()?;
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        // An empty parent means the CWD; skip rather than open "".
        if !parent.as_os_str().is_empty() {
            std::fs::File::open(parent)?.sync_all()?;
        }
    }
    Ok(Some(blob.len()))
}

/// Key under which the node's desired pod set persists in the store.
const DESIRED_KEY: &str = "desired.pods";
/// Key recording where the committed plan was last published (the
/// `FLUXOR_PLAN` file). The node runtime writes its live owner-status file
/// (`owner_status.json`) NEXT TO the plan it consumes, so this is how a later
/// `agent status` invocation — which only receives `--store` — locates the
/// runtime's status surface.
const PUBLISH_PATH_KEY: &str = "publish.path";
/// Key holding the per-slot high-water owner generation. Slot generations must
/// survive a slot going empty (rfc_k8s.md §11: reuse always issues a strictly
/// higher generation, so a deleted pod's stale handles can never match), and
/// the committed plan only records currently-occupied slots.
const SLOT_GENS_KEY: &str = "slot.generations";

fn load_slot_gens<S: Storage>(store: &GenStore<S>) -> Result<Vec<u32>, StoreError> {
    // Absent → first run (empty). Present but undecodable → hard error: silently
    // resetting the slot high-water would let a reused slot get a lower
    // generation, defeating the stale-handle guard. An I/O fault is likewise a
    // hard error — never "absent" — so a transient read failure cannot masquerade
    // as an empty high-water table.
    match store
        .storage
        .read(SLOT_GENS_KEY)
        .map_err(|_| StoreError::StorageIo)?
    {
        None => Ok(Vec::new()),
        Some(b) => serde_json::from_slice(&b).map_err(|_| StoreError::CorruptState),
    }
}

fn save_slot_gens<S: Storage>(store: &mut GenStore<S>, gens: &[u32]) -> Result<(), StoreError> {
    let bytes = serde_json::to_vec(gens).map_err(|_| StoreError::WriteFailed)?;
    store
        .storage
        .write(SLOT_GENS_KEY, &bytes)
        .map_err(|_| StoreError::WriteFailed)
}

fn load_desired<S: Storage>(store: &GenStore<S>) -> Result<Vec<PodDesired>, StoreError> {
    // Absent → first run (empty desired set). Present but undecodable → hard
    // error: silently treating corrupt state as an empty set would drop every
    // live pod on the next reconcile. An I/O fault is a hard error too — a
    // transient read failure must never look like "no pods desired".
    match store
        .storage
        .read(DESIRED_KEY)
        .map_err(|_| StoreError::StorageIo)?
    {
        None => Ok(Vec::new()),
        Some(b) => serde_json::from_slice(&b).map_err(|_| StoreError::CorruptState),
    }
}

fn save_desired<S: Storage>(
    store: &mut GenStore<S>,
    pods: &[PodDesired],
) -> Result<(), StoreError> {
    let bytes = serde_json::to_vec(pods).map_err(|_| StoreError::WriteFailed)?;
    store
        .storage
        .write(DESIRED_KEY, &bytes)
        .map_err(|_| StoreError::WriteFailed)
}

/// Owner snapshot derived from the committed plan: the plan IS the record of
/// which pod holds which slot at which generation (rfc_k8s.md §11 input), so
/// recomposition keeps resident pods' slots/generations stable.
fn snapshot_from_committed<S: Storage>(
    store: &GenStore<S>,
    max_owners: u16,
) -> Result<OwnerSnapshot, StoreError> {
    let mut snap = OwnerSnapshot::empty(max_owners);
    // Generations: high-water table (survives slots going empty)...
    for (i, gen) in load_slot_gens(store)?.into_iter().enumerate() {
        if let Some(slot) = snap.slots.get_mut(i) {
            slot.generation = gen;
        }
    }
    // ...occupancy: the committed plan.
    if let Some(plan) = load_committed_plan(store) {
        for a in &plan.assignments {
            if let Some(slot) = snap.slots.get_mut(a.slot as usize) {
                slot.occupant = Some(a.pod_uid);
                slot.generation = slot.generation.max(a.generation);
            }
        }
    }
    Ok(snap)
}

/// Remember where the committed plan was published so `agent status` can
/// find the runtime's `owner_status.json` beside it. Stored canonicalized —
/// status may run from a different working directory.
pub fn record_publish_path<S: Storage>(
    store: &mut GenStore<S>,
    path: &std::path::Path,
) -> Result<(), StoreError> {
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    store
        .storage
        .write(PUBLISH_PATH_KEY, canonical.to_string_lossy().as_bytes())
        .map_err(|_| StoreError::WriteFailed)
}

// ── Live runtime status (rfc_k8s.md §7.2 vocabulary) ────────────────────────
//
// These types mirror what the node runtime writes into `owner_status.json`.
// The reason/phase enums ARE the fixed §7.2 vocabulary: deserialization
// rejects anything outside the set, so a runtime emitting an unknown reason
// can never leak it into the orchestrator-facing JSON (nanocloud matches on
// these strings and rejects others).

/// Aggregate pod phase as observed by the live runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RuntimePhase {
    Activating,
    Running,
    Terminated,
}

/// §7.2 `state.terminated.reason` vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TerminatedReason {
    Completed,
    GraphNodeFault,
    ExternalProcessExited,
    LivenessFailure,
    Evicted,
    FluxorReservationInvalid,
}

/// §7.2 waiting reasons only the runtime can know (`FluxorStaging` /
/// `FluxorActivating` are inferred by the orchestrator from committed state
/// plus liveness and are deliberately absent here).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WaitingReason {
    FluxorReserving,
    ActivationBackOff,
}

/// Terminal aggregate state (present only when `phase == Terminated`).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TerminatedState {
    pub reason: TerminatedReason,
    /// 0 = Completed; non-zero = fault.
    pub exit_code: i32,
    /// Present when an external-process signal determined the termination.
    #[serde(default)]
    pub signal: Option<u8>,
    pub finished_at: String,
}

/// One pod's LIVE runtime status, §7.2-shaped. Joined into [`PodStatus`] by
/// pod UID; absent entirely when the runtime isn't up.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PodRuntimeStatus {
    pub phase: RuntimePhase,
    /// Aggregate readiness (`ContainersReady`).
    pub ready: bool,
    /// Aggregate startup complete.
    pub started: bool,
    /// Activation time (RFC 3339); present once Running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    /// AGGREGATE owner re-activations only — an internal module retry is
    /// module telemetry, never a Kubernetes container restart.
    pub restart_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminated: Option<TerminatedState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting_reason: Option<WaitingReason>,
}

/// On-disk shape of the runtime's `owner_status.json`.
#[derive(Debug, serde::Deserialize)]
struct RuntimeStatusFile {
    #[allow(dead_code, reason = "self-describing on-disk field")]
    version: u32,
    /// Writer's process id — liveness gate for the whole file.
    pid: u32,
    /// Writer's process start time (clock ticks since boot, field 22 of
    /// `/proc/<pid>/stat`). Together with `pid` this identifies THE writer
    /// process — a recycled PID has a different start time.
    pid_start_ticks: u64,
    /// Plan generation the live state was derived under. The join is scoped
    /// to it: after a new commit/publish, live state from the previous
    /// generation must not be attached to the new durable pod records.
    plan_generation: u64,
    pods: Vec<RuntimeStatusPod>,
}

#[derive(Debug, serde::Deserialize)]
struct RuntimeStatusPod {
    pod_uid_hex: String,
    /// Owner slot + generation — with the pod UID, the §17.2 join key. Both
    /// must match the committed assignment for the join to attach.
    slot: u16,
    owner_generation: u32,
    runtime: PodRuntimeStatus,
}

/// One pod's surfaced status: the owner-tagged join of the persisted desired
/// state and the committed plan (rfc_k8s.md §17.2 — pod UID + slot +
/// generation is the join key between orchestrator status and device
/// telemetry). `slot`/`owner_generation`/allocation fields are present only
/// when the pod is in the committed generation.
#[derive(Clone, Debug, serde::Serialize)]
pub struct PodStatus {
    pub pod_uid_hex: String,
    pub namespace: String,
    pub name: String,
    pub desired_phase: DesiredPhase,
    pub committed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_generation: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modules: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edges: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_cap: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buffer_cap: Option<u32>,
    /// LIVE per-pod runtime status (§7.2-shaped), joined from the runtime's
    /// `owner_status.json` by pod UID. Absent when the runtime isn't up —
    /// additive: existing consumers of the durable fields are unaffected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<PodRuntimeStatus>,
}

/// Whole-node status snapshot.
#[derive(Clone, Debug, serde::Serialize)]
pub struct NodeStatus {
    /// Committed generation id, `None` before the first commit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    /// ABI-surface digest of THIS tool build (hex) — the substrate surface
    /// new generations will be pinned to. The kernel deployed from the same
    /// tree computes the identical value (locked by
    /// `tests/harness/tests/abi_surface_digest.rs`).
    pub abi_surface: String,
    /// Pin recorded in the committed generation. When it differs from
    /// `abi_surface`, the committed graph predates an ABI-surface change:
    /// the orchestrator must restage/recommit before (or atomically with)
    /// rolling the substrate, or the device-side pin check will reject the
    /// generation at boot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed_abi_surface: Option<String>,
    pub pods: Vec<PodStatus>,
}

fn hex32(d: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in d {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Derive the node's per-pod status from the store: desired set joined with
/// the committed plan's owner assignments. Read-only; safe to run while the
/// runtime is live (the store is only ever appended by commit).
pub fn node_status<S: Storage>(store: &GenStore<S>) -> Result<NodeStatus, StoreError> {
    let desired = load_desired(store)?;
    let plan = load_committed_plan(store);
    let committed = store.committed();
    let generation = committed.as_ref().map(|g| g.id);
    let committed_abi_surface = committed.as_ref().map(|g| hex32(&g.abi_surface));
    let mut pods: Vec<PodStatus> = desired
        .iter()
        .map(|p| {
            let assignment = plan
                .as_ref()
                .and_then(|pl| pl.assignments.iter().find(|a| a.pod_uid == p.pod_uid));
            let mut hex = String::with_capacity(32);
            for b in &p.pod_uid {
                use std::fmt::Write;
                let _ = write!(hex, "{b:02x}");
            }
            PodStatus {
                pod_uid_hex: hex,
                namespace: p.namespace.clone(),
                name: p.name.clone(),
                desired_phase: p.desired_phase,
                committed: assignment.is_some(),
                slot: assignment.map(|a| a.slot),
                owner_generation: assignment.map(|a| a.generation),
                modules: assignment.map(|a| a.module_count),
                edges: assignment.map(|a| a.edge_count),
                state_cap: assignment.map(|a| a.state_cap),
                buffer_cap: assignment.map(|a| a.buffer_cap),
                runtime: None,
            }
        })
        .collect();
    pods.sort_by(|a, b| a.pod_uid_hex.cmp(&b.pod_uid_hex));
    Ok(NodeStatus {
        generation,
        abi_surface: hex32(&crate::hash::abi_surface_digest()),
        committed_abi_surface,
        pods,
    })
}

/// `node_status` plus the LIVE per-pod runtime join: read the runtime's
/// `owner_status.json` (located beside the plan file recorded by
/// [`record_publish_path`]) and attach each pod's §7.2-shaped `runtime`
/// object by the full §17.2 join key — pod UID + slot + owner generation,
/// scoped to the committed plan generation. Best-effort and fail-absent: a
/// missing/garbled/out-of-vocabulary file, a writer process that is no
/// longer alive (or is a recycled PID), a file from a different plan
/// generation, or a slot/generation mismatch yields the plain durable
/// status with no `runtime` objects — never an error and never stale live
/// state presented as current.
pub fn node_status_with_runtime<S: Storage>(store: &GenStore<S>) -> Result<NodeStatus, StoreError> {
    let mut st = node_status(store)?;
    if let Some(file) = read_runtime_status(store) {
        // Live state derived under a different plan generation (the runtime
        // hasn't rebuilt onto the new commit yet, or is behind a rollback)
        // must not be joined to the new durable records.
        if Some(file.plan_generation) == st.generation {
            for pod in &mut st.pods {
                if let Some(entry) = file.pods.iter().find(|p| {
                    p.pod_uid_hex == pod.pod_uid_hex
                        && Some(p.slot) == pod.slot
                        && Some(p.owner_generation) == pod.owner_generation
                }) {
                    pod.runtime = Some(entry.runtime.clone());
                }
            }
        }
    }
    Ok(st)
}

/// Load + vocabulary-validate + liveness-gate the runtime status file.
/// `None` on any failure (the pull-based contract: absent = runtime not up).
fn read_runtime_status<S: Storage>(store: &GenStore<S>) -> Option<RuntimeStatusFile> {
    let publish = String::from_utf8(store.storage.read(PUBLISH_PATH_KEY).ok()??).ok()?;
    let path = std::path::Path::new(&publish)
        .parent()?
        .join("owner_status.json");
    let text = std::fs::read_to_string(path).ok()?;
    // Strict parse: an unknown phase/reason string fails the enum and drops
    // the whole file — out-of-vocabulary values must not reach consumers.
    let file: RuntimeStatusFile = serde_json::from_str(&text).ok()?;
    if !writer_alive(file.pid, file.pid_start_ticks) {
        return None;
    }
    Some(file)
}

/// Is the status writer's process still alive AND the same process that
/// wrote the file? procfs check of pid + process start time, so a
/// recycled PID or a zombie is never mistaken for the writer. On a host
/// without /proc (non-Linux dev machine) the file is trusted as-is.
fn writer_alive(pid: u32, pid_start_ticks: u64) -> bool {
    if !std::path::Path::new("/proc").exists() {
        return true;
    }
    proc_start_ticks(pid) == Some(pid_start_ticks)
}

/// Start time of `pid` in clock ticks since boot — field 22 of
/// `/proc/<pid>/stat`, parsed from after the LAST `)` so a comm containing
/// spaces or parens cannot shift the fields. `None` when the process is gone
/// or a zombie (state `Z`: it has exited; anything it wrote is history).
fn proc_start_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail = &stat[stat.rfind(')')? + 1..];
    let mut fields = tail.split_whitespace();
    if fields.next()? == "Z" {
        return None;
    }
    // `state` was field 3; `starttime` is field 22.
    fields.nth(18)?.parse().ok()
}

/// Upsert `pod` into the node's persisted desired state and recompose ALL
/// running pods into the next generation (rfc_k8s.md §6.3: one device, one
/// composed graph). Resident pods keep their slots/generations via the
/// committed-plan snapshot. Returns the committed plan and its generation id.
pub fn upsert_pod_and_commit<S: Storage>(
    store: &mut GenStore<S>,
    pod: PodDesired,
    cap: &NodeCapacity,
) -> Result<(CompositionPlan, u64), AgentError> {
    let mut pods = load_desired(store).map_err(AgentError::Store)?;
    pods.retain(|p| p.pod_uid != pod.pod_uid);
    pods.push(pod);
    recompose(store, pods, cap)
}

/// Remove a pod from the desired state and recompose the remainder.
pub fn remove_pod_and_commit<S: Storage>(
    store: &mut GenStore<S>,
    pod_uid: [u8; 16],
    cap: &NodeCapacity,
) -> Result<(CompositionPlan, u64), AgentError> {
    let mut pods = load_desired(store).map_err(AgentError::Store)?;
    pods.retain(|p| p.pod_uid != pod_uid);
    recompose(store, pods, cap)
}

fn recompose<S: Storage>(
    store: &mut GenStore<S>,
    pods: Vec<PodDesired>,
    cap: &NodeCapacity,
) -> Result<(CompositionPlan, u64), AgentError> {
    let gen_id = store.committed().map(|g| g.id + 1).unwrap_or(1);
    let running: Vec<PodDesired> = pods
        .iter()
        .filter(|p| p.desired_phase == DesiredPhase::Running)
        .cloned()
        .collect();
    let desired = DeviceDesiredState {
        generation: gen_id,
        system_revision: 1,
        pods: running,
    };
    let prior = snapshot_from_committed(store, cap.max_owners).map_err(AgentError::Store)?;
    // Stage + verify the candidate WITHOUT committing yet.
    let plan = stage_candidate(store, &desired, cap, &prior, gen_id)?;
    // Persist the node bookkeeping (desired set + slot high-water generations)
    // BEFORE the commit. The commit (pointer flip) is the LAST durable write, so
    // a bookkeeping failure leaves nothing committed and the caller's error is
    // consistent with the unchanged prior generation — never "error returned but
    // a new generation is already live".
    save_desired(store, &pods).map_err(AgentError::Store)?;
    let mut gens = load_slot_gens(store).map_err(AgentError::Store)?;
    for a in &plan.assignments {
        let idx = a.slot as usize;
        if gens.len() <= idx {
            gens.resize(idx + 1, 0);
        }
        gens[idx] = gens[idx].max(a.generation);
    }
    save_slot_gens(store, &gens).map_err(AgentError::Store)?;
    store.commit(gen_id).map_err(AgentError::Store)?;
    Ok((plan, gen_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose::{DesiredPhase, PodDesired, ResourceProfile};
    use crate::genstore::MemStorage;

    fn uid(n: u8) -> [u8; 16] {
        let mut u = [0u8; 16];
        u[0] = n;
        u
    }

    fn pod(n: u8, modules: u16) -> PodDesired {
        PodDesired {
            pod_uid: uid(n),
            namespace: "default".into(),
            name: format!("pod-{n}"),
            workload_digest: [n; 32],
            config_generation: 1,
            desired_phase: DesiredPhase::Running,
            profile: ResourceProfile {
                modules,
                edges: 0,
                state_bytes: 4096,
                buffer_bytes: 2048,
                endpoints: 1,
                domains: 1,
            },
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

    fn desired(pods: Vec<PodDesired>) -> DeviceDesiredState {
        DeviceDesiredState {
            generation: 1,
            system_revision: 1,
            pods,
        }
    }

    #[test]
    fn reconcile_commits_and_round_trips_the_plan() {
        let mut store = GenStore::new(MemStorage::default());
        let ds = desired(vec![pod(1, 4), pod(2, 8)]);

        let plan = reconcile_and_commit(&mut store, &ds, &cap(), &OwnerSnapshot::empty(16), 1)
            .expect("reconcile");

        // A committed generation now exists, and the plan reloaded from the
        // store is byte-for-byte the composed plan (incl. caps from the profile).
        let loaded = load_committed_plan(&store).expect("load");
        assert_eq!(loaded, plan);
        assert_eq!(loaded.assignments.len(), 2);
        assert_eq!(loaded.assignments[0].state_cap, 4096);
        assert_eq!(loaded.assignments[0].buffer_cap, 2048);
    }

    #[test]
    fn second_reconcile_supersedes_first() {
        let mut store = GenStore::new(MemStorage::default());
        reconcile_and_commit(
            &mut store,
            &desired(vec![pod(1, 4)]),
            &cap(),
            &OwnerSnapshot::empty(16),
            1,
        )
        .unwrap();
        let plan2 = reconcile_and_commit(
            &mut store,
            &desired(vec![pod(1, 4), pod(3, 2)]),
            &cap(),
            &OwnerSnapshot::empty(16),
            2,
        )
        .unwrap();

        assert_eq!(store.committed().unwrap().id, 2);
        assert_eq!(load_committed_plan(&store).unwrap(), plan2);
        assert_eq!(plan2.assignments.len(), 2);
    }

    #[test]
    fn fs_store_survives_reopen_and_publishes_plan() {
        use crate::genstore::FsStorage;
        let dir = std::env::temp_dir().join(format!("fluxor-genstore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        // Commit into a directory-backed store...
        let plan = {
            let mut store = GenStore::new(FsStorage::open(&dir).unwrap());
            reconcile_and_commit(
                &mut store,
                &desired(vec![pod(1, 4)]),
                &cap(),
                &OwnerSnapshot::empty(16),
                1,
            )
            .unwrap()
        }; // store dropped — simulate process exit

        // ...reopen (fresh process) and the committed generation survives.
        let store = GenStore::new(FsStorage::open(&dir).unwrap());
        assert_eq!(store.committed().unwrap().id, 1);
        assert_eq!(load_committed_plan(&store).unwrap(), plan);

        // Publish for FLUXOR_PLAN delivery: the file's bytes decode to the
        // exact committed plan.
        let out = dir.join("current.plan");
        let n = publish_committed_plan(&store, &out).unwrap().unwrap();
        let bytes = std::fs::read(&out).unwrap();
        assert_eq!(bytes.len(), n);
        assert_eq!(decode_plan(&bytes).unwrap(), plan);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn upsert_recompose_keeps_resident_slots_stable() {
        let mut store = GenStore::new(MemStorage::default());
        // Pod A alone → slot 1, gen 1.
        let (p1, g1) = upsert_pod_and_commit(&mut store, pod(1, 4), &cap()).unwrap();
        assert_eq!(g1, 1);
        assert_eq!(p1.assignments[0].slot, 1);

        // Add pod B → BOTH pods in gen 2; A keeps slot 1 + owner generation.
        let (p2, g2) = upsert_pod_and_commit(&mut store, pod(2, 8), &cap()).unwrap();
        assert_eq!(g2, 2);
        assert_eq!(p2.assignments.len(), 2, "co-resident recompose");
        let a = p2.assignments.iter().find(|a| a.pod_uid == uid(1)).unwrap();
        let b = p2.assignments.iter().find(|a| a.pod_uid == uid(2)).unwrap();
        assert_eq!(
            (a.slot, a.generation),
            (p1.assignments[0].slot, p1.assignments[0].generation),
            "resident pod's slot/generation stable across recompose"
        );
        assert_eq!(b.slot, 2);

        // Remove A → gen 3 holds only B, still in slot 2.
        let (p3, g3) = remove_pod_and_commit(&mut store, uid(1), &cap()).unwrap();
        assert_eq!(g3, 3);
        assert_eq!(p3.assignments.len(), 1);
        assert_eq!(p3.assignments[0].slot, 2);

        // Re-add a pod → reuses slot 1 with a bumped owner generation (stale
        // handles from the removed pod can never match).
        let (p4, _) = upsert_pod_and_commit(&mut store, pod(3, 2), &cap()).unwrap();
        let c = p4.assignments.iter().find(|a| a.pod_uid == uid(3)).unwrap();
        assert_eq!(c.slot, 1);
        assert!(c.generation > a.generation);
    }

    #[test]
    fn capacity_overflow_propagates_without_committing() {
        let mut store = GenStore::new(MemStorage::default());
        // One pod needing more modules than the node has.
        let ds = desired(vec![pod(1, 200)]);
        let r = reconcile_and_commit(&mut store, &ds, &cap(), &OwnerSnapshot::empty(16), 1);
        assert!(matches!(
            r,
            Err(AgentError::Compose(ComposeError::ModulesExceeded))
        ));
        // nothing committed
        assert!(store.committed().is_none());
        assert!(load_committed_plan(&store).is_none());
    }

    #[test]
    fn corrupt_desired_state_is_a_hard_error() {
        let mut store = GenStore::new(MemStorage::default());
        // Commit a live pod so persisted desired state exists.
        upsert_pod_and_commit(&mut store, pod(1, 4), &cap()).unwrap();
        // Corrupt the persisted desired set.
        store.storage.write(DESIRED_KEY, b"not json").unwrap();
        // The next reconcile must ERROR — not silently drop the live pod by
        // treating corrupt state as an empty desired set.
        let r = upsert_pod_and_commit(&mut store, pod(2, 8), &cap());
        assert!(matches!(
            r,
            Err(AgentError::Store(StoreError::CorruptState))
        ));
        // The previously committed generation is untouched.
        assert_eq!(store.committed().unwrap().id, 1);
    }

    /// Storage that injects a fault on one specific key — a failed write and/or
    /// a failed read — to test commit ordering and read-fault handling.
    struct KeyFailStorage {
        inner: MemStorage,
        fail_write_key: Option<String>,
        fail_read_key: Option<String>,
    }
    impl KeyFailStorage {
        fn fail_write(key: &str) -> Self {
            KeyFailStorage {
                inner: MemStorage::default(),
                fail_write_key: Some(key.to_string()),
                fail_read_key: None,
            }
        }
    }
    impl Storage for KeyFailStorage {
        fn read(&self, key: &str) -> std::io::Result<Option<Vec<u8>>> {
            if self.fail_read_key.as_deref() == Some(key) {
                return Err(std::io::Error::other("injected read failure"));
            }
            self.inner.read(key)
        }
        fn write(&mut self, key: &str, bytes: &[u8]) -> std::io::Result<()> {
            if self.fail_write_key.as_deref() == Some(key) {
                Err(std::io::Error::other("injected write failure"))
            } else {
                self.inner.write(key, bytes)
            }
        }
        fn delete(&mut self, key: &str) {
            self.inner.delete(key);
        }
        fn keys(&self) -> Vec<String> {
            self.inner.keys()
        }
    }

    #[test]
    fn bookkeeping_write_failure_leaves_nothing_committed() {
        // The pointer flip (commit) is the LAST durable write. A bookkeeping
        // write (desired set) that fails BEFORE it must leave the store with no
        // new committed generation — never "error returned but generation live".
        let mut store = GenStore::new(KeyFailStorage::fail_write(DESIRED_KEY));
        let r = upsert_pod_and_commit(&mut store, pod(1, 4), &cap());
        assert!(matches!(r, Err(AgentError::Store(StoreError::WriteFailed))));
        assert!(
            store.committed().is_none(),
            "no generation committed when a pre-commit write failed"
        );
    }

    #[test]
    fn commit_write_failure_leaves_prior_generation_live() {
        // Failure DURING the commit itself (the pointer flip), not before it.
        // `recompose` stages + writes bookkeeping, then flips the pointer last;
        // if that flip fails the store must stay on the PRIOR committed
        // generation — never report success, never advance the pointer.
        let mut store = GenStore::new(KeyFailStorage::fail_write("ptr.a"));
        // No pointer exists yet, so the first commit targets ptr.a → it fails.
        let r = upsert_pod_and_commit(&mut store, pod(1, 4), &cap());
        assert!(matches!(r, Err(AgentError::Store(StoreError::WriteFailed))));
        assert!(
            store.committed().is_none(),
            "a failed pointer flip must leave nothing committed"
        );
    }

    #[test]
    fn read_fault_on_desired_state_is_not_treated_as_empty() {
        // A committed pod exists; a transient I/O fault reading the desired set
        // must be a hard error, NOT an empty set (which would drop the pod).
        let mut store = GenStore::new(KeyFailStorage {
            inner: MemStorage::default(),
            fail_write_key: None,
            fail_read_key: None,
        });
        upsert_pod_and_commit(&mut store, pod(1, 4), &cap()).unwrap();
        // Now make reads of the desired set fault.
        store.storage.fail_read_key = Some(DESIRED_KEY.to_string());
        let r = upsert_pod_and_commit(&mut store, pod(2, 8), &cap());
        assert!(matches!(r, Err(AgentError::Store(StoreError::StorageIo))));
        // The prior generation is untouched — the resident pod is not dropped.
        assert_eq!(store.committed().unwrap().id, 1);
    }

    /// Render a runtime-written `owner_status.json` body for one pod
    /// (mirrors the linux runtime writer's fixed emission), with every
    /// join-key field overridable so tests can stage mismatches.
    fn runtime_status_json_at(
        pid: u32,
        pid_start_ticks: u64,
        plan_generation: u64,
        uid_hex: &str,
        slot: u16,
        owner_generation: u32,
        runtime_body: &str,
    ) -> String {
        format!(
            "{{\"version\":1,\"pid\":{pid},\"pid_start_ticks\":{pid_start_ticks},\
             \"plan_generation\":{plan_generation},\
             \"written_at\":\"2026-07-07T00:00:00Z\",\"pods\":[\
             {{\"pod_uid_hex\":\"{uid_hex}\",\"slot\":{slot},\
             \"owner_generation\":{owner_generation},\
             \"runtime\":{runtime_body}}}]}}"
        )
    }

    /// [`runtime_status_json_at`] with every join-key field matching what
    /// [`store_with_published_pod`] commits (generation 1, slot 1, owner
    /// generation 1) and this test process as the live writer.
    fn runtime_status_json(pid: u32, uid_hex: &str, runtime_body: &str) -> String {
        let ticks = proc_start_ticks(std::process::id()).unwrap_or(0);
        runtime_status_json_at(pid, ticks, 1, uid_hex, 1, 1, runtime_body)
    }

    /// FsStorage-backed store in a fresh temp dir with pod 1 committed and
    /// the plan published + publish-path recorded (the full agent flow).
    fn store_with_published_pod(
        tag: &str,
    ) -> (GenStore<crate::genstore::FsStorage>, std::path::PathBuf) {
        use crate::genstore::FsStorage;
        let dir =
            std::env::temp_dir().join(format!("fluxor-agent-rt-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = GenStore::new(FsStorage::open(&dir).unwrap());
        upsert_pod_and_commit(&mut store, pod(1, 4), &cap()).unwrap();
        let publish = dir.join("current.plan");
        publish_committed_plan(&store, &publish).unwrap().unwrap();
        record_publish_path(&mut store, &publish).unwrap();
        (store, dir)
    }

    const UID1_HEX: &str = "01000000000000000000000000000000";

    #[test]
    fn status_joins_live_runtime_by_pod_uid() {
        let (store, dir) = store_with_published_pod("join");
        let rt = "{\"phase\":\"Terminated\",\"ready\":false,\"started\":false,\
                  \"restart_count\":2,\"started_at\":\"2026-07-07T00:00:01Z\",\
                  \"terminated\":{\"reason\":\"GraphNodeFault\",\"exit_code\":2,\
                  \"signal\":null,\"finished_at\":\"2026-07-07T00:00:02Z\"}}";
        std::fs::write(
            dir.join("owner_status.json"),
            runtime_status_json(std::process::id(), UID1_HEX, rt),
        )
        .unwrap();

        let st = node_status_with_runtime(&store).unwrap();
        let p = st.pods.iter().find(|p| p.pod_uid_hex == UID1_HEX).unwrap();
        let rt = p.runtime.as_ref().expect("runtime joined");
        assert_eq!(rt.phase, RuntimePhase::Terminated);
        assert_eq!(rt.restart_count, 2);
        let t = rt.terminated.as_ref().unwrap();
        assert_eq!(t.reason, TerminatedReason::GraphNodeFault);
        assert_eq!(t.exit_code, 2);
        assert_eq!(t.signal, None);

        // The JSON stays additive: durable fields unchanged, `runtime` is a
        // nested optional object with the exact §7.2 field names.
        let v = serde_json::to_value(&st).unwrap();
        let pj = &v["pods"][0];
        assert_eq!(pj["pod_uid_hex"], UID1_HEX);
        assert!(pj["committed"].as_bool().unwrap());
        assert_eq!(pj["runtime"]["phase"], "Terminated");
        assert_eq!(pj["runtime"]["terminated"]["reason"], "GraphNodeFault");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dead_writer_pid_means_runtime_absent() {
        let (store, dir) = store_with_published_pod("deadpid");
        let rt = "{\"phase\":\"Running\",\"ready\":true,\"started\":true,\"restart_count\":0}";
        // PID far above pid_max: the writer is gone; its file is history,
        // not live state.
        std::fs::write(
            dir.join("owner_status.json"),
            runtime_status_json(4_100_000, UID1_HEX, rt),
        )
        .unwrap();

        let st = node_status_with_runtime(&store).unwrap();
        assert!(st.pods[0].runtime.is_none(), "stale file not surfaced");

        // Existing consumers see no `runtime` key at all.
        let v = serde_json::to_value(&st).unwrap();
        assert!(v["pods"][0].get("runtime").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recycled_writer_pid_means_runtime_absent() {
        let (store, dir) = store_with_published_pod("recycled");
        let rt = "{\"phase\":\"Running\",\"ready\":true,\"started\":true,\"restart_count\":0}";
        // The writer's PID is alive (it's ours) but the recorded start time
        // belongs to a different, earlier process: the PID was recycled.
        let wrong_ticks = proc_start_ticks(std::process::id()).unwrap_or(0) + 1;
        std::fs::write(
            dir.join("owner_status.json"),
            runtime_status_json_at(std::process::id(), wrong_ticks, 1, UID1_HEX, 1, 1, rt),
        )
        .unwrap();

        let st = node_status_with_runtime(&store).unwrap();
        assert!(st.pods[0].runtime.is_none(), "recycled PID not trusted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_plan_generation_drops_the_runtime_join() {
        let (store, dir) = store_with_published_pod("stalegen");
        let rt = "{\"phase\":\"Running\",\"ready\":true,\"started\":true,\"restart_count\":0}";
        // Live state derived under a different plan generation (runtime not
        // yet rebuilt onto the current commit) must not attach to the new
        // durable records — same PID, same pod UID, wrong generation.
        let ticks = proc_start_ticks(std::process::id()).unwrap_or(0);
        std::fs::write(
            dir.join("owner_status.json"),
            runtime_status_json_at(std::process::id(), ticks, 999, UID1_HEX, 1, 1, rt),
        )
        .unwrap();

        let st = node_status_with_runtime(&store).unwrap();
        assert!(
            st.pods[0].runtime.is_none(),
            "cross-generation join refused"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn slot_or_owner_generation_mismatch_drops_the_runtime_join() {
        let rt = "{\"phase\":\"Running\",\"ready\":true,\"started\":true,\"restart_count\":0}";
        let ticks = proc_start_ticks(std::process::id()).unwrap_or(0);

        // Right pod UID, wrong slot.
        let (store, dir) = store_with_published_pod("wrongslot");
        std::fs::write(
            dir.join("owner_status.json"),
            runtime_status_json_at(std::process::id(), ticks, 1, UID1_HEX, 9, 1, rt),
        )
        .unwrap();
        let st = node_status_with_runtime(&store).unwrap();
        assert!(st.pods[0].runtime.is_none(), "slot mismatch refused");
        let _ = std::fs::remove_dir_all(&dir);

        // Right pod UID and slot, wrong owner generation.
        let (store, dir) = store_with_published_pod("wrongogen");
        std::fs::write(
            dir.join("owner_status.json"),
            runtime_status_json_at(std::process::id(), ticks, 1, UID1_HEX, 1, 9, rt),
        )
        .unwrap();
        let st = node_status_with_runtime(&store).unwrap();
        assert!(
            st.pods[0].runtime.is_none(),
            "owner-generation mismatch refused"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn out_of_vocabulary_reason_drops_the_runtime_join() {
        let (store, dir) = store_with_published_pod("vocab");
        let rt = "{\"phase\":\"Terminated\",\"ready\":false,\"started\":false,\
                  \"restart_count\":0,\"terminated\":{\"reason\":\"SomethingNew\",\
                  \"exit_code\":1,\"signal\":null,\"finished_at\":\"2026-07-07T00:00:02Z\"}}";
        std::fs::write(
            dir.join("owner_status.json"),
            runtime_status_json(std::process::id(), UID1_HEX, rt),
        )
        .unwrap();

        // §7.2: reasons outside the fixed set are never emitted — a file
        // carrying one fails strict parse and the join is dropped.
        let st = node_status_with_runtime(&store).unwrap();
        assert!(st.pods[0].runtime.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_status_file_or_publish_record_is_not_an_error() {
        // No publish path recorded at all (MemStorage, no publish).
        let mut store = GenStore::new(MemStorage::default());
        upsert_pod_and_commit(&mut store, pod(1, 4), &cap()).unwrap();
        let st = node_status_with_runtime(&store).unwrap();
        assert!(st.pods[0].runtime.is_none());

        // Publish recorded but no owner_status.json written yet.
        let (store, dir) = store_with_published_pod("nofile");
        let st = node_status_with_runtime(&store).unwrap();
        assert!(st.pods[0].runtime.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `node_status` surfaces the ABI-surface pin: matching pins report
    /// quietly; a committed generation pinned to a different surface (i.e.
    /// committed before an ABI change) is visible to the orchestrator so it
    /// restages before rolling the substrate.
    #[test]
    fn status_surfaces_abi_pin_and_mismatch() {
        let mut store = GenStore::new(MemStorage::default());
        let cap = cap();
        upsert_pod_and_commit(&mut store, pod(1, 1), &cap).expect("commit");

        let st = node_status(&store).expect("status");
        assert_eq!(st.committed_abi_surface.as_ref(), Some(&st.abi_surface));

        // Simulate a generation committed under an older surface: rewrite the
        // committed record's pin bytes (GEN_ABI_SURFACE_OFFSET per
        // genstore_wire).
        let gen_id = st.generation.unwrap();
        let key = format!("gen.{gen_id}");
        let mut rec = store.storage.read(&key).unwrap().unwrap();
        let off = crate::genstore::genstore_wire::GEN_ABI_SURFACE_OFFSET;
        for b in &mut rec[off..off + 32] {
            *b ^= 0xA5;
        }
        store.storage.write(&key, &rec).unwrap();

        let st2 = node_status(&store).expect("status after tamper");
        assert_ne!(st2.committed_abi_surface.as_ref(), Some(&st2.abi_surface));
    }
}
