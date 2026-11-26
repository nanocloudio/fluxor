//! Node-agent reconcile → stage → commit orchestration: the device-side control
//! loop that turns one node's desired workload set into a single durably committed
//! graph generation, tying together composition, the binary plan codec, and the
//! durable generation store.
//!
//! `reconcile_and_commit` is the trusted host-side step that turns a desired
//! device state into a durably committed graph generation: compose the
//! deterministic plan, encode it to the bounded binary form the kernel consumes,
//! stage it (plan blob in the content-addressed store), verify, and atomically
//! commit. `load_committed_plan` reads it back — the same bytes a device fetches
//! to apply at boot. This is the real delivery path the `FLUXOR_PLAN`
//! stand-in emulates.

use sha2::{Digest, Sha256};

use crate::compose::{
    compose, decode_plan, encode_plan, ComposeError, CompositionPlan, DesiredPhase,
    DeviceDesiredState, NodeCapacity, OwnerSnapshot, WorkloadDesired,
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
    let policy = load_node_policy(store).map_err(AgentError::Store)?;
    let plan = stage_candidate(
        store,
        desired,
        cap,
        prior,
        gen_id,
        &[],
        0,
        &policy.reserved_ports,
        policy.system_modules,
    )?;
    store.commit(gen_id).map_err(AgentError::Store)?;
    Ok(plan)
}

/// Compose + stage + verify a candidate generation WITHOUT committing (the
/// pointer is not flipped). Split out from `reconcile_and_commit` so the node
/// agent can order its own bookkeeping writes before the final commit — the
/// commit must be the last durable write so it never becomes visible ahead of a
/// failed bookkeeping write.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors compose()'s parameter list plus the staging identifiers; bundling them into a struct would add a type used at exactly one call site"
)]
fn stage_candidate<S: Storage>(
    store: &mut GenStore<S>,
    desired: &DeviceDesiredState,
    cap: &NodeCapacity,
    prior: &OwnerSnapshot,
    gen_id: u64,
    revoke_graces: &[([u8; 16], u16)],
    now_unix: u64,
    reserved_ports: &[u16],
    system_modules: u16,
) -> Result<CompositionPlan, AgentError> {
    let plan = compose(
        desired,
        cap,
        prior,
        revoke_graces,
        now_unix,
        reserved_ports,
        system_modules,
    )
    .map_err(AgentError::Compose)?;
    let blob = encode_plan(&plan).map_err(AgentError::Compose)?;
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

/// Key under which the node's desired workload set persists in the store.
const DESIRED_KEY: &str = "desired.workloads";
/// Key recording where the committed plan was last published (the
/// `FLUXOR_PLAN` file). The node runtime writes its owner facts file
/// (`abi::platform::linux::owner_facts`) NEXT TO the plan it consumes, so
/// this is how a later `agent status` invocation — which only receives
/// `--store` — locates them.
const PUBLISH_PATH_KEY: &str = "publish.path";
/// Key holding the per-slot high-water owner generation. Slot generations must
/// survive a slot going empty — reusing a slot must always issue a STRICTLY
/// higher owner generation, so a deleted workload's stale handles can never match —
/// and the committed plan only records currently-occupied slots.
const SLOT_GENS_KEY: &str = "slot.generations";
/// Key holding the node policy the orchestrator supplies out-of-band of any
/// one workload: today the reserved-port set that exported endpoints must not
/// intersect. It is node-scoped, never a per-workload manifest field, because the
/// ports it protects belong to the orchestrator itself. Persisted so EVERY recompose —
/// commit or remove, whoever triggers it — composes against the same policy.
const NODE_POLICY_KEY: &str = "node.policy";

/// Node-scoped composition policy. Additive by design: absent file or absent
/// field means the empty default, so agents upgraded in place keep composing.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NodePolicy {
    /// Host ports no owner export may claim (the orchestrator's own
    /// listeners). Compose refuses intersecting exports at admission with
    /// `ComposeError::EndpointConflict`.
    #[serde(default)]
    pub reserved_ports: Vec<u16>,
    /// The node substrate's platform-module prefix: platform stacks PREPEND
    /// their modules (linux_net et al.), so compiled indices [0, N) are
    /// system infrastructure and workload module ranges must start past them
    /// — the node's own system services are not ownable by a workload.
    /// 0 = no platform modules (a substrate
    /// whose module list is entirely ownable).
    #[serde(default)]
    pub system_modules: u16,
}

/// Load the node policy. Absent → default (no reservations). Present but
/// undecodable → hard error: silently composing without the reserved set
/// could grant a lease over the orchestrator's own listener. An I/O fault is
/// a hard error too, never "no policy".
pub fn load_node_policy<S: Storage>(store: &GenStore<S>) -> Result<NodePolicy, StoreError> {
    match store
        .storage
        .read(NODE_POLICY_KEY)
        .map_err(|_| StoreError::StorageIo)?
    {
        None => Ok(NodePolicy::default()),
        Some(b) => serde_json::from_slice(&b).map_err(|_| StoreError::CorruptState),
    }
}

/// Persist the node policy (whole-value replace).
pub fn save_node_policy<S: Storage>(
    store: &mut GenStore<S>,
    policy: &NodePolicy,
) -> Result<(), StoreError> {
    let bytes = serde_json::to_vec(policy).map_err(|_| StoreError::WriteFailed)?;
    store
        .storage
        .write(NODE_POLICY_KEY, &bytes)
        .map_err(|_| StoreError::WriteFailed)
}

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

/// The node's persisted desired workload set.
pub fn load_desired<S: Storage>(store: &GenStore<S>) -> Result<Vec<WorkloadDesired>, StoreError> {
    // Absent → first run (empty desired set). Present but undecodable → hard
    // error: silently treating corrupt state as an empty set would drop every
    // live workload on the next reconcile. An I/O fault is a hard error too — a
    // transient read failure must never look like "no workloads desired".
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
    workloads: &[WorkloadDesired],
) -> Result<(), StoreError> {
    let bytes = serde_json::to_vec(workloads).map_err(|_| StoreError::WriteFailed)?;
    store
        .storage
        .write(DESIRED_KEY, &bytes)
        .map_err(|_| StoreError::WriteFailed)
}

/// Owner snapshot derived from the committed plan: the plan IS the record of
/// which workload holds which slot at which generation — the input the next slot and
/// generation allocation is computed against — so recomposition keeps resident
/// workloads' slots/generations stable.
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
    // ...occupancy + retained ranges + live revocations: the committed plan.
    if let Some(plan) = load_committed_plan(store) {
        for a in &plan.assignments {
            if let Some(slot) = snap.slots.get_mut(a.slot as usize) {
                slot.occupant = Some(a.owner_uid);
                slot.generation = slot.generation.max(a.generation);
            }
        }
        // Revocation slots stay generation-guarded too: a reused slot must get
        // a strictly higher generation than the draining occupant's.
        for r in &plan.revocations {
            if let Some(slot) = snap.slots.get_mut(r.assignment.slot as usize) {
                slot.generation = slot.generation.max(r.assignment.generation);
            }
        }
        snap.assignments = plan.assignments;
        snap.revocations = plan.revocations;
    }
    Ok(snap)
}

/// Remember where the committed plan was published so `agent status` can
/// find the runtime's owner facts beside it. Stored canonicalized —
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

/// Directory the runtime writes its sidecars into — the owner facts file, the
/// network provider's bound-endpoint report and the per-owner `logs/` ring directory (one ring file per owner UID, named
/// `<owner_uid>.<slot>.<owner_generation>.ring`) — which is the parent of the
/// recorded publish path. `None` when nothing has been
/// published yet. Shared by `agent status` and `agent logs` so both resolve the
/// sidecars the same way.
pub fn published_sidecar_dir<S: Storage>(store: &GenStore<S>) -> Option<std::path::PathBuf> {
    let publish = String::from_utf8(store.storage.read(PUBLISH_PATH_KEY).ok()??).ok()?;
    Some(std::path::Path::new(&publish).parent()?.to_path_buf())
}

// ── Live runtime status (the closed workload-status vocabulary) ──────────────────
//
// `agent status` renders these from the kernel's owner facts
// (`workload::OWNERS`, which the runtime writes verbatim beside the plan):
// the phase, reasons, restart count and drain detail below are this agent's
// reading of those facts ([`render_runtime`]). The reason/phase enums ARE the
// closed vocabulary — the complete, fixed set of phase, terminated-reason and
// waiting-reason strings a workload status may carry, and nothing outside it
// is a valid value.

/// Aggregate workload phase as observed by the live runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RuntimePhase {
    Activating,
    Running,
    Terminated,
}

/// The closed `state.terminated.reason` vocabulary: the complete set of reasons
/// a terminated owner may report. Nothing outside these six is valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TerminatedReason {
    Completed,
    GraphNodeFault,
    ExternalProcessExited,
    LivenessFailure,
    Evicted,
    FluxorReservationInvalid,
}

/// The waiting reasons only the runtime can know (`FluxorStaging` /
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
    /// When it ended (RFC 3339), present when the facts carry a wall-clock
    /// time for it: a drain the runtime ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
}

/// One workload's LIVE runtime status, in the closed status vocabulary above. Joined
/// into [`WorkloadStatus`] by owner uid; absent entirely when the runtime isn't up.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct WorkloadRuntimeStatus {
    pub phase: RuntimePhase,
    /// Aggregate readiness (`ContainersReady`).
    pub ready: bool,
    /// Aggregate startup complete.
    pub started: bool,
    /// AGGREGATE owner re-activations only — each time the runtime
    /// instantiated the owner's modules again; an internal module retry is
    /// module telemetry, never an owner restart.
    pub restart_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminated: Option<TerminatedState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting_reason: Option<WaitingReason>,
    /// Owner lifecycle state; `Some("Draining")` during a graceful drain,
    /// `Some("Paused")` while paused, absent when running normally. A
    /// free-form string, not an enum, so a consumer that does not know a
    /// lifecycle state never trips over it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_state: Option<String>,
    /// Wall-clock second the drain forfeits its grace (present while draining).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_deadline_unix: Option<u64>,
    /// Seconds left in the drain window (present while draining).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_remaining_secs: Option<u32>,
    /// How a completed drain window closed (present on drained-owner
    /// terminal records).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain: Option<DrainDetail>,
}

/// Terminal drain detail: how a completed drain window closed. Independent
/// bool fields rather than an enum, so a drain outcome this reader does not
/// know about arrives as an unset field instead of failing the strict parse.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DrainDetail {
    /// The grace deadline lapsed before the owner reached quiescence.
    #[serde(default)]
    pub timed_out: bool,
    /// The drain did not run to its end in this runtime: a rebuild dropped
    /// the owner mid-drain, or the runtime started after it was revoked. The
    /// grace is simply lost.
    #[serde(default)]
    pub forfeited: bool,
}

/// One bound (protocol, port) pair from the network provider's report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundEndpoint {
    pub protocol: String,
    pub port: u16,
}

impl BoundEndpoint {
    /// The report's record, with its IP protocol number named.
    fn of(rec: &fluxor_abi::platform::linux::bound_endpoints::Record) -> BoundEndpoint {
        use fluxor_abi::contracts::net::net_proto::grant;
        BoundEndpoint {
            protocol: match rec.protocol {
                grant::PROTO_TCP => "tcp".to_string(),
                grant::PROTO_UDP => "udp".to_string(),
                n => n.to_string(),
            },
            port: rec.port,
        }
    }
}

/// The agent's declared⇄bound join for one endpoint: one entry per declared
/// export (`bound` = a matching listener is live) plus any observed bind that
/// no export declared (`declared: false`). An undeclared bind is reported, not
/// refused — the join surfaces the discrepancy, it does not police it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct EndpointStatus {
    pub protocol: String,
    pub port: u16,
    pub bound: bool,
    pub declared: bool,
}

/// Join a workload's declared exports with the bound report. Pure —
/// unit-tested without a store or runtime. Matching is case-insensitive on
/// protocol + numeric port equality.
pub fn join_endpoints(
    declared: &[crate::compose::ExportDecl],
    bound: &[BoundEndpoint],
) -> Vec<EndpointStatus> {
    let mut out: Vec<EndpointStatus> = declared
        .iter()
        .map(|d| EndpointStatus {
            protocol: d.protocol.to_ascii_lowercase(),
            port: d.port,
            bound: bound
                .iter()
                .any(|b| b.port == d.port && b.protocol.eq_ignore_ascii_case(&d.protocol)),
            declared: true,
        })
        .collect();
    for b in bound {
        let matches_declared = declared
            .iter()
            .any(|d| d.port == b.port && d.protocol.eq_ignore_ascii_case(&b.protocol));
        if !matches_declared {
            out.push(EndpointStatus {
                protocol: b.protocol.to_ascii_lowercase(),
                port: b.port,
                bound: true,
                declared: false,
            });
        }
    }
    out
}

/// The runtime's owner facts file, read: the process that wrote it and the
/// kernel's `OWNERS` answer.
struct OwnerFactsFile {
    /// Writer's process id — liveness gate for the whole file.
    pid: u32,
    /// Writer's process start time (clock ticks since boot, field 22 of
    /// `/proc/<pid>/stat`). Together with `pid` this identifies THE writer
    /// process — a recycled PID has a different start time.
    pid_start_ticks: u64,
    /// Plan generation the facts were read under. The join is scoped to it:
    /// after a new commit/publish, facts from the previous generation must
    /// not be attached to the new durable workload records.
    plan_generation: u64,
    /// Digest of the plan the kernel applied, as it verified it.
    plan_digest: [u8; 32],
    records: Vec<fluxor_abi::contracts::workload::owners::Record>,
}

/// Parse an owner facts file: its head, then the `OWNERS` answer. `None`
/// for a wrong magic, a short head or a malformed answer.
fn parse_owner_facts(bytes: &[u8]) -> Option<OwnerFactsFile> {
    use fluxor_abi::contracts::workload::owners;
    use fluxor_abi::platform::linux::owner_facts as file;
    let head = bytes.get(..file::HEAD_LEN)?;
    if head[..4] != file::MAGIC {
        return None;
    }
    let pid = u32::from_le_bytes(head[file::PID..file::PID + 4].try_into().ok()?);
    let pid_start_ticks = u64::from_le_bytes(
        head[file::PID_START_TICKS..file::PID_START_TICKS + 8]
            .try_into()
            .ok()?,
    );
    let answer = &bytes[file::HEAD_LEN..];
    let (count, len, plan_generation, plan_digest) = owners::read_head(answer)?;
    let records = (0..count)
        .map(|i| owners::Record::read(&answer[owners::HEADER_LEN + i * len..]))
        .collect::<Option<Vec<_>>>()?;
    Some(OwnerFactsFile {
        pid,
        pid_start_ticks,
        plan_generation,
        plan_digest,
        records,
    })
}

/// This agent's reading of one owner record, at wall-clock `now_unix`.
///
/// - A drained owner (`STATE_GONE`) is Terminated: `Completed` when it
///   quiesced, else `GraphNodeFault` with the drain-timeout fault code, and
///   its drain detail.
/// - A live owner with a terminated module is Terminated with the reason for
///   that fault kind (`LivenessFailure` for a step deadline, else
///   `GraphNodeFault`) and the kind as its exit code; one whose every module
///   ended cleanly is `Completed`, exit 0.
/// - Otherwise it is Running once every module it stamps is instantiated
///   (ready while none is being retried and it is not draining), and
///   Activating before — waiting in `ActivationBackOff` when it stamps
///   modules of which some failed to instantiate.
///
/// The restart count is its activations past the first.
pub fn render_runtime(
    rec: &fluxor_abi::contracts::workload::owners::Record,
    now_unix: u64,
) -> WorkloadRuntimeStatus {
    use fluxor_abi::contracts::workload::owners;
    let drain_timeout = i32::from(owners::FAULT_DRAIN_TIMEOUT);
    let step_timeout = owners::FAULT_TIMEOUT;
    let mut rt = WorkloadRuntimeStatus {
        phase: RuntimePhase::Activating,
        ready: false,
        started: false,
        restart_count: rec.activations.saturating_sub(1),
        terminated: None,
        waiting_reason: None,
        owner_state: None,
        drain_deadline_unix: None,
        drain_remaining_secs: None,
        drain: None,
    };
    if rec.state == owners::STATE_GONE {
        let quiesced = rec.drain == owners::DRAIN_QUIESCED;
        rt.phase = RuntimePhase::Terminated;
        rt.terminated = Some(TerminatedState {
            reason: if quiesced {
                TerminatedReason::Completed
            } else {
                TerminatedReason::GraphNodeFault
            },
            exit_code: if quiesced { 0 } else { drain_timeout },
            signal: None,
            finished_at: (rec.drained_at > 0).then(|| rfc3339_utc(rec.drained_at)),
        });
        rt.drain = Some(DrainDetail {
            timed_out: !quiesced,
            forfeited: rec.drain == owners::DRAIN_FORFEITED,
        });
        return rt;
    }
    let fully_loaded = rec.modules > 0 && rec.loaded >= rec.modules;
    if rec.terminated > 0 {
        rt.phase = RuntimePhase::Terminated;
        rt.terminated = Some(TerminatedState {
            reason: if rec.fault_kind == step_timeout {
                TerminatedReason::LivenessFailure
            } else {
                TerminatedReason::GraphNodeFault
            },
            exit_code: if rec.fault_kind == 0 {
                1
            } else {
                i32::from(rec.fault_kind)
            },
            signal: None,
            finished_at: None,
        });
    } else if fully_loaded && rec.finished == rec.modules {
        rt.phase = RuntimePhase::Terminated;
        rt.terminated = Some(TerminatedState {
            reason: TerminatedReason::Completed,
            exit_code: 0,
            signal: None,
            finished_at: None,
        });
    } else if fully_loaded {
        rt.phase = RuntimePhase::Running;
        rt.started = true;
        rt.ready = rec.recovering == 0 && rec.state != owners::STATE_DRAINING;
    } else if rec.modules > 0 {
        rt.waiting_reason = Some(WaitingReason::ActivationBackOff);
    }
    match rec.state {
        owners::STATE_DRAINING => {
            rt.owner_state = Some("Draining".to_string());
            if rec.drain_deadline > 0 {
                rt.drain_deadline_unix = Some(rec.drain_deadline);
                rt.drain_remaining_secs = Some(
                    u32::try_from(rec.drain_deadline.saturating_sub(now_unix)).unwrap_or(u32::MAX),
                );
            }
        }
        owners::STATE_PAUSED => rt.owner_state = Some("Paused".to_string()),
        _ => {}
    }
    rt
}

/// RFC 3339 UTC timestamp from unix seconds (Howard Hinnant's
/// civil-from-days).
pub fn rfc3339_utc(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    )
}

/// One workload's surfaced status: the owner-tagged join of the persisted desired
/// state and the committed plan. owner uid + owner slot + owner generation is
/// the join key between orchestrator-facing status and device telemetry; a
/// partial match is not a match. `slot`/`owner_generation`/allocation fields are present only
/// when the workload is in the committed generation.
#[derive(Clone, Debug, serde::Serialize)]
pub struct WorkloadStatus {
    pub owner_uid_hex: String,
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
    /// LIVE per-workload runtime status (in the closed status vocabulary),
    /// rendered from the runtime's owner facts joined by owner uid. Absent
    /// when the runtime isn't up — additive: existing consumers of the
    /// durable fields are unaffected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<WorkloadRuntimeStatus>,
    /// Declared⇄bound endpoint join ([`join_endpoints`]): present only while
    /// a live network provider reports its bound endpoints — no report means
    /// "unknown", never a claimed `bound: false`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<EndpointStatus>,
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
    /// Digest (hex) of the plan a live runtime reports having applied, present
    /// only when that runtime reports the committed generation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_plan_digest: Option<String>,
    pub workloads: Vec<WorkloadStatus>,
}

/// Derive the node's per-workload status from the store: desired set joined with
/// the committed plan's owner assignments. Read-only; safe to run while the
/// runtime is live (the store is only ever appended by commit).
pub fn node_status<S: Storage>(store: &GenStore<S>) -> Result<NodeStatus, StoreError> {
    let desired = load_desired(store)?;
    let plan = load_committed_plan(store);
    let committed = store.committed();
    let generation = committed.as_ref().map(|g| g.id);
    let committed_abi_surface = committed.as_ref().map(|g| crate::hash::hex(&g.abi_surface));
    let mut workloads: Vec<WorkloadStatus> = desired
        .iter()
        .map(|p| {
            let assignment = plan
                .as_ref()
                .and_then(|pl| pl.assignments.iter().find(|a| a.owner_uid == p.owner_uid));
            let mut hex = String::with_capacity(32);
            for b in &p.owner_uid {
                use std::fmt::Write;
                let _ = write!(hex, "{b:02x}");
            }
            WorkloadStatus {
                owner_uid_hex: hex,
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
                endpoints: Vec::new(),
            }
        })
        .collect();
    // Departing workloads stay observable for the whole drain window: a removed
    // workload is gone from desired state immediately, but its revocation record
    // rides the committed plan until retention lapses
    // until its retention lapses. Synthesize a row from each revocation whose
    // UID no longer has a desired row, so `status` keeps
    // showing the owner (and, via the runtime join, its Draining/Terminated
    // state) instead of the workload silently vanishing mid-drain. Namespace and
    // name left empty — the desired record that carried them is gone; the
    // owner uid is the orchestrator's join key.
    if let Some(pl) = plan.as_ref() {
        for rev in &pl.revocations {
            let a = &rev.assignment;
            let mut hex = String::with_capacity(32);
            for b in &a.owner_uid {
                use std::fmt::Write;
                let _ = write!(hex, "{b:02x}");
            }
            if workloads.iter().any(|p| p.owner_uid_hex == hex) {
                continue;
            }
            workloads.push(WorkloadStatus {
                owner_uid_hex: hex,
                namespace: String::new(),
                name: String::new(),
                desired_phase: DesiredPhase::Stopped,
                committed: true,
                slot: Some(a.slot),
                owner_generation: Some(a.generation),
                modules: Some(a.module_count),
                edges: Some(a.edge_count),
                state_cap: Some(a.state_cap),
                buffer_cap: Some(a.buffer_cap),
                runtime: None,
                endpoints: Vec::new(),
            });
        }
    }
    workloads.sort_by(|a, b| a.owner_uid_hex.cmp(&b.owner_uid_hex));
    Ok(NodeStatus {
        generation,
        abi_surface: crate::hash::hex(&crate::hash::abi_surface_digest()),
        committed_abi_surface,
        runtime_plan_digest: None,
        workloads,
    })
}

/// `node_status` plus the LIVE per-workload runtime join: read the runtime's
/// owner facts (located beside the plan file recorded by
/// [`record_publish_path`]) and attach each workload's rendered `runtime`
/// object ([`render_runtime`]) by the full join key — owner uid, owner slot
/// and owner generation, scoped to the committed plan generation. Best-effort
/// and fail-absent: a missing or malformed file, a writer process that is no
/// longer alive (or is a recycled PID), facts from a different plan
/// generation, or a slot/generation mismatch yields the plain durable status
/// with no `runtime` objects — never an error and never stale live state
/// presented as current.
pub fn node_status_with_runtime<S: Storage>(store: &GenStore<S>) -> Result<NodeStatus, StoreError> {
    let mut st = node_status(store)?;
    if let Some(bound) = read_bound_endpoints(store) {
        join_bound_endpoints(&mut st, &load_desired(store)?, &bound);
    }
    let Some(file) = read_owner_facts(store) else {
        return Ok(st);
    };
    // Live state read under a different plan generation (the runtime hasn't
    // rebuilt onto the new commit yet, or is behind a rollback) must not be
    // joined to the new durable records.
    if Some(file.plan_generation) != st.generation {
        return Ok(st);
    }
    st.runtime_plan_digest = Some(crate::hash::hex(&file.plan_digest));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for rec in &file.records {
        let uid_hex = crate::hash::hex(&rec.uid);
        let rt = render_runtime(rec, now);
        if let Some(workload) = st.workloads.iter_mut().find(|p| p.owner_uid_hex == uid_hex) {
            if Some(rec.slot) == workload.slot && Some(rec.generation) == workload.owner_generation
            {
                workload.runtime = Some(rt);
            }
            continue;
        }
        // An owner with no durable row left — a departed owner whose
        // revocation aged out of this agent's plan while the runtime still
        // lists it: a runtime-only row rather than a dropped terminal state.
        st.workloads.push(WorkloadStatus {
            owner_uid_hex: uid_hex,
            namespace: String::new(),
            name: String::new(),
            desired_phase: DesiredPhase::Stopped,
            committed: false,
            slot: Some(rec.slot),
            owner_generation: Some(rec.generation),
            modules: None,
            edges: None,
            state_cap: None,
            buffer_cap: None,
            runtime: Some(rt),
            endpoints: Vec::new(),
        });
    }
    st.workloads
        .sort_by(|a, b| a.owner_uid_hex.cmp(&b.owner_uid_hex));
    Ok(st)
}

/// Load + parse + liveness-gate the runtime's owner facts. `None` on any
/// failure (the pull-based contract: absent = runtime not up).
fn read_owner_facts<S: Storage>(store: &GenStore<S>) -> Option<OwnerFactsFile> {
    let path =
        published_sidecar_dir(store)?.join(fluxor_abi::platform::linux::owner_facts::FILE_NAME);
    let file = parse_owner_facts(&std::fs::read(path).ok()?)?;
    if !writer_alive(file.pid, file.pid_start_ticks) {
        return None;
    }
    Some(file)
}

/// Attach the declared⇄bound endpoint join to every workload the committed
/// plan places: a record is the workload's when its owner slot and owner
/// generation are the plan's for it (a slot reused by a later owner carries
/// a higher generation, so it never matches). The declared side is the
/// admitted exports. Records of no placed workload — the node's own — are
/// not shown.
fn join_bound_endpoints(
    st: &mut NodeStatus,
    desired: &[WorkloadDesired],
    bound: &[fluxor_abi::platform::linux::bound_endpoints::Record],
) {
    for workload in &mut st.workloads {
        let (Some(slot), Some(generation)) = (workload.slot, workload.owner_generation) else {
            continue;
        };
        let held: Vec<BoundEndpoint> = bound
            .iter()
            .filter(|r| r.owner_slot == slot && r.owner_generation == generation)
            .map(BoundEndpoint::of)
            .collect();
        let declared = desired
            .iter()
            .find(|d| crate::hash::hex(&d.owner_uid) == workload.owner_uid_hex)
            .map(|d| d.exports.as_slice())
            .unwrap_or(&[]);
        workload.endpoints = join_endpoints(declared, &held);
    }
}

/// Parse a bound-endpoint report: `(pid, pid_start_ticks, records)`. `None`
/// for a wrong magic, a short head or records past the end.
fn parse_bound_endpoints(
    bytes: &[u8],
) -> Option<(
    u32,
    u64,
    Vec<fluxor_abi::platform::linux::bound_endpoints::Record>,
)> {
    use fluxor_abi::platform::linux::bound_endpoints as file;
    let (pid, ticks, count, len) = file::read_head(bytes)?;
    let records = (0..count)
        .map(|i| file::Record::read(&bytes[file::HEAD_LEN + i * len..]))
        .collect::<Option<Vec<_>>>()?;
    Some((pid, ticks, records))
}

/// Load + parse + liveness-gate the network provider's bound-endpoint
/// report, beside the owner facts. `None` on any failure (absent = no
/// provider reporting).
fn read_bound_endpoints<S: Storage>(
    store: &GenStore<S>,
) -> Option<Vec<fluxor_abi::platform::linux::bound_endpoints::Record>> {
    let path =
        published_sidecar_dir(store)?.join(fluxor_abi::platform::linux::bound_endpoints::FILE_NAME);
    let (pid, ticks, records) = parse_bound_endpoints(&std::fs::read(path).ok()?)?;
    writer_alive(pid, ticks).then_some(records)
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
    // The field just consumed is field 3 (`state`); `starttime` is field 22.
    fields.nth(18)?.parse().ok()
}

/// What a package directory says of the workload once it has passed admission.
#[derive(Clone, Debug)]
pub struct ResolvedPackage {
    pub name: String,
    pub profile: crate::compose::ResourceProfile,
    /// The workload digest: the sha256 of the package's `workload.json`, which
    /// pins `resources.json` and `graph.yaml` by their own digests.
    pub workload_digest: [u8; 32],
    pub exports: Vec<crate::compose::ExportDecl>,
}

/// Verify an on-disk artifact's content hashes to the manifest's pinned digest.
/// A package whose artifact bytes don't match the declared digest is rejected —
/// modified artifacts must never be admitted.
fn verify_artifact(bytes: &[u8], declared: &str, what: &str) -> Result<(), String> {
    let actual = format!("sha256:{}", crate::hash::hex(&sha256(bytes)));
    if actual != declared {
        return Err(format!(
            "package {what}: content digest mismatch (manifest pins {declared}, artifact is {actual})"
        ));
    }
    Ok(())
}

/// Validate a package dir and extract the workload's resource profile + workload
/// digest from it. Admission-gates the manifest: a package that fails
/// validation, lacks a linux implementation, or whose artifacts don't match the
/// manifest's pinned digests is rejected before anything is committed. The
/// error is the diagnostic, verbatim.
///
/// This is the trust model of a manifest from a trusted source: the artifacts
/// (`resources.json`, `graph.yaml`) are verified against the digests it pins, so
/// a modified artifact fails. A signature over the manifest itself is not part
/// of this format.
pub fn resolve_package(dir: &std::path::Path) -> Result<ResolvedPackage, String> {
    use crate::workload::{
        parse_manifest, parse_resource_profile, select_implementation, validate,
    };

    let manifest_json = std::fs::read_to_string(dir.join("workload.json"))
        .map_err(|e| format!("package {}: workload.json: {e}", dir.display()))?;
    let manifest = parse_manifest(&manifest_json)?;
    let report = validate(&manifest);
    if !report.is_ok() {
        return Err(format!(
            "workload package '{}' failed validation: {}",
            manifest.name,
            report.errors.join("; ")
        ));
    }
    let imp = select_implementation(&manifest, "linux", "aarch64", 1).ok_or_else(|| {
        format!(
            "workload package '{}' has no linux/aarch64/abi-1 implementation",
            manifest.name
        )
    })?;

    // Verify the package's artifacts against the digests the manifest pins.
    let resources_json = std::fs::read(dir.join("resources.json"))
        .map_err(|e| format!("package {}: resources.json: {e}", dir.display()))?;
    verify_artifact(&resources_json, &imp.resources.digest, "resources.json")?;
    let graph_yaml = std::fs::read(dir.join("graph.yaml"))
        .map_err(|e| format!("package {}: graph.yaml: {e}", dir.display()))?;
    verify_artifact(&graph_yaml, &imp.graph.digest, "graph.yaml")?;

    let doc = parse_resource_profile(
        &String::from_utf8(resources_json)
            .map_err(|e| format!("package {}: resources.json: {e}", dir.display()))?,
    )?;

    // Declared exports travel with the desired workload so `agent status` can join
    // them against the runtime's report of what actually bound.
    let exports = manifest
        .contract
        .exports
        .iter()
        .map(|e| crate::compose::ExportDecl {
            protocol: e.protocol.clone(),
            port: e.port,
        })
        .collect();
    Ok(ResolvedPackage {
        name: manifest.name.clone(),
        profile: doc.to_compose(),
        workload_digest: sha256(manifest_json.as_bytes()),
        exports,
    })
}

/// Upsert `workload` into the node's persisted desired state and recompose ALL
/// running workloads into the next generation — one device runs exactly ONE
/// composed graph, so every resident workload is recomposed together, never patched
/// in individually. Resident workloads keep their slots/generations via the
/// committed-plan snapshot. Returns the committed plan and its generation id.
pub fn upsert_workload_and_commit<S: Storage>(
    store: &mut GenStore<S>,
    workload: WorkloadDesired,
    cap: &NodeCapacity,
) -> Result<(CompositionPlan, u64), AgentError> {
    let mut workloads = load_desired(store).map_err(AgentError::Store)?;
    workloads.retain(|p| p.owner_uid != workload.owner_uid);
    workloads.push(workload);
    recompose(store, workloads, cap, &[])
}

/// Remove a workload from the desired state and recompose the remainder. With a
/// non-zero `grace_secs` the departing workload leaves through a bounded drain
/// window: its revocation record (deadline = now + grace) rides the same single
/// generation, and the runtime drains-then-revokes against it.
/// `grace_secs == 0` revokes immediately —
/// the same code path, with an already-past deadline.
pub fn remove_workload_and_commit<S: Storage>(
    store: &mut GenStore<S>,
    owner_uid: [u8; 16],
    grace_secs: u16,
    cap: &NodeCapacity,
) -> Result<(CompositionPlan, u64), AgentError> {
    let mut workloads = load_desired(store).map_err(AgentError::Store)?;
    workloads.retain(|p| p.owner_uid != owner_uid);
    recompose(store, workloads, cap, &[(owner_uid, grace_secs)])
}

fn recompose<S: Storage>(
    store: &mut GenStore<S>,
    workloads: Vec<WorkloadDesired>,
    cap: &NodeCapacity,
    revoke_graces: &[([u8; 16], u16)],
) -> Result<(CompositionPlan, u64), AgentError> {
    let gen_id = store.committed().map(|g| g.id + 1).unwrap_or(1);
    let running: Vec<WorkloadDesired> = workloads
        .iter()
        .filter(|p| p.desired_phase == DesiredPhase::Running)
        .cloned()
        .collect();
    let desired = DeviceDesiredState {
        generation: gen_id,
        system_revision: 1,
        workloads: running,
    };
    let prior = snapshot_from_committed(store, cap.max_owners).map_err(AgentError::Store)?;
    let policy = load_node_policy(store).map_err(AgentError::Store)?;
    // Wall clock is consulted ONLY here, at publish: revocation deadlines are
    // stamped as absolute seconds into the plan; every later check
    // (agent expiry, runtime drain) evaluates the stamped value.
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Stage + verify the candidate WITHOUT committing yet.
    let plan = stage_candidate(
        store,
        &desired,
        cap,
        &prior,
        gen_id,
        revoke_graces,
        now_unix,
        &policy.reserved_ports,
        policy.system_modules,
    )?;
    // Persist the node bookkeeping (desired set + slot high-water generations)
    // BEFORE the commit. The commit (pointer flip) is the LAST durable write, so
    // a bookkeeping failure leaves nothing committed and the caller's error is
    // consistent with the unchanged prior generation — never "error returned but
    // a new generation is already live".
    save_desired(store, &workloads).map_err(AgentError::Store)?;
    let mut gens = load_slot_gens(store).map_err(AgentError::Store)?;
    let mut bump = |slot: u16, generation: u32| {
        let idx = slot as usize;
        if gens.len() <= idx {
            gens.resize(idx + 1, 0);
        }
        gens[idx] = gens[idx].max(generation);
    };
    for a in &plan.assignments {
        bump(a.slot, a.generation);
    }
    // A draining slot's generation is retained too, so post-expiry reuse always
    // bumps past the departed occupant.
    for r in &plan.revocations {
        bump(r.assignment.slot, r.assignment.generation);
    }
    save_slot_gens(store, &gens).map_err(AgentError::Store)?;
    store.commit(gen_id).map_err(AgentError::Store)?;
    Ok((plan, gen_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose::{DesiredPhase, ResourceProfile, WorkloadDesired};
    use crate::genstore::MemStorage;

    fn uid(n: u8) -> [u8; 16] {
        let mut u = [0u8; 16];
        u[0] = n;
        u
    }

    fn workload(n: u8, modules: u16) -> WorkloadDesired {
        WorkloadDesired {
            owner_uid: uid(n),
            namespace: "default".into(),
            name: format!("workload-{n}"),
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

    fn desired(workloads: Vec<WorkloadDesired>) -> DeviceDesiredState {
        DeviceDesiredState {
            generation: 1,
            system_revision: 1,
            workloads,
        }
    }

    #[test]
    fn reconcile_commits_and_round_trips_the_plan() {
        let mut store = GenStore::new(MemStorage::default());
        let ds = desired(vec![workload(1, 4), workload(2, 8)]);

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
            &desired(vec![workload(1, 4)]),
            &cap(),
            &OwnerSnapshot::empty(16),
            1,
        )
        .unwrap();
        let plan2 = reconcile_and_commit(
            &mut store,
            &desired(vec![workload(1, 4), workload(3, 2)]),
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
                &desired(vec![workload(1, 4)]),
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
    fn node_policy_reserved_ports_gate_every_recompose() {
        use crate::compose::ExportDecl;
        let mut store = GenStore::new(MemStorage::default());
        // No policy written → default (empty set): an exporting workload admits.
        assert_eq!(load_node_policy(&store).unwrap(), NodePolicy::default());
        let mut exporting = workload(1, 4);
        exporting.exports = vec![ExportDecl {
            protocol: "udp".into(),
            port: 53,
        }];
        upsert_workload_and_commit(&mut store, exporting.clone(), &cap()).unwrap();
        let (_, g) = remove_workload_and_commit(&mut store, uid(1), 0, &cap()).unwrap();

        // Reserve 53 → the SAME workload is now refused at admission, and the
        // failure leaves the committed generation untouched.
        save_node_policy(
            &mut store,
            &NodePolicy {
                reserved_ports: vec![6443, 53],
                ..NodePolicy::default()
            },
        )
        .unwrap();
        let err = upsert_workload_and_commit(&mut store, exporting, &cap()).unwrap_err();
        assert_eq!(err, AgentError::Compose(ComposeError::EndpointConflict));
        assert_eq!(store.committed().unwrap().id, g);

        // A non-intersecting export still admits under the policy.
        let mut ok = workload(2, 4);
        ok.exports = vec![ExportDecl {
            protocol: "tcp".into(),
            port: 8080,
        }];
        upsert_workload_and_commit(&mut store, ok, &cap()).unwrap();
    }

    #[test]
    fn node_policy_system_modules_offset_workload_ranges() {
        // A substrate whose platform stack prepends one module (linux_net at
        // compiled index 0): workload ranges must start past the prefix, and a
        // policy set AFTER a commit applies from the next recompose.
        let mut store = GenStore::new(MemStorage::default());
        save_node_policy(
            &mut store,
            &NodePolicy {
                system_modules: 1,
                ..NodePolicy::default()
            },
        )
        .unwrap();
        let (plan, _) = upsert_workload_and_commit(&mut store, workload(1, 2), &cap()).unwrap();
        assert_eq!(
            plan.assignments[0].module_base, 1,
            "range skips the platform prefix"
        );
        let (plan2, _) = upsert_workload_and_commit(&mut store, workload(2, 1), &cap()).unwrap();
        let b = plan2
            .assignments
            .iter()
            .find(|a| a.owner_uid == uid(2))
            .unwrap();
        assert_eq!(
            b.module_base, 3,
            "second workload first-fits after the first"
        );
    }

    #[test]
    fn upsert_recompose_keeps_resident_slots_stable() {
        let mut store = GenStore::new(MemStorage::default());
        // Workload A alone → slot 1, gen 1.
        let (p1, g1) = upsert_workload_and_commit(&mut store, workload(1, 4), &cap()).unwrap();
        assert_eq!(g1, 1);
        assert_eq!(p1.assignments[0].slot, 1);

        // Add workload B → BOTH workloads in gen 2; A keeps slot 1 + owner generation.
        let (p2, g2) = upsert_workload_and_commit(&mut store, workload(2, 8), &cap()).unwrap();
        assert_eq!(g2, 2);
        assert_eq!(p2.assignments.len(), 2, "co-resident recompose");
        let a = p2
            .assignments
            .iter()
            .find(|a| a.owner_uid == uid(1))
            .unwrap();
        let b = p2
            .assignments
            .iter()
            .find(|a| a.owner_uid == uid(2))
            .unwrap();
        assert_eq!(
            (a.slot, a.generation),
            (p1.assignments[0].slot, p1.assignments[0].generation),
            "resident workload's slot/generation stable across recompose"
        );
        assert_eq!(b.slot, 2);

        // Remove A → ONE generation: A moves to the revocation section (its
        // last assignment verbatim, deadline stamped), B untouched in slot 2
        // B's record is byte-identical.
        let (p3, g3) = remove_workload_and_commit(&mut store, uid(1), 0, &cap()).unwrap();
        assert_eq!(g3, 3);
        assert_eq!(p3.assignments.len(), 1);
        assert_eq!(p3.assignments[0].slot, 2);
        assert_eq!(p3.assignments[0], *b, "survivor untouched by removal");
        assert_eq!(p3.revocations.len(), 1);
        let rev = &p3.revocations[0];
        assert_eq!(rev.assignment.owner_uid, uid(1));
        assert_eq!(
            (rev.assignment.slot, rev.assignment.generation),
            (a.slot, a.generation)
        );
        assert_eq!(rev.grace_secs, 0);

        // Re-add during the drain window → the revocation still occupies slot 1,
        // so the new workload takes the next free slot with its own fresh identity —
        // a clean admission alongside the drain, never a resurrection.
        let (p4, _) = upsert_workload_and_commit(&mut store, workload(3, 2), &cap()).unwrap();
        let c = p4
            .assignments
            .iter()
            .find(|a| a.owner_uid == uid(3))
            .unwrap();
        assert_eq!(c.slot, 3, "drain window holds slot 1");
        // The revocation rides along until expiry.
        assert_eq!(p4.revocations.len(), 1);
        // Slot 1's high-water generation is retained: post-expiry reuse of the
        // slot must bump past the departed occupant.
        let gens = load_slot_gens(&store).unwrap();
        assert!(gens[1] >= a.generation);
    }

    #[test]
    fn capacity_overflow_propagates_without_committing() {
        let mut store = GenStore::new(MemStorage::default());
        // One workload needing more modules than the node has.
        let ds = desired(vec![workload(1, 200)]);
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
        // Commit a live workload so persisted desired state exists.
        upsert_workload_and_commit(&mut store, workload(1, 4), &cap()).unwrap();
        // Corrupt the persisted desired set.
        store.storage.write(DESIRED_KEY, b"not json").unwrap();
        // The next reconcile must ERROR — not silently drop the live workload by
        // treating corrupt state as an empty desired set.
        let r = upsert_workload_and_commit(&mut store, workload(2, 8), &cap());
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
        let r = upsert_workload_and_commit(&mut store, workload(1, 4), &cap());
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
        let r = upsert_workload_and_commit(&mut store, workload(1, 4), &cap());
        assert!(matches!(r, Err(AgentError::Store(StoreError::WriteFailed))));
        assert!(
            store.committed().is_none(),
            "a failed pointer flip must leave nothing committed"
        );
    }

    #[test]
    fn read_fault_on_desired_state_is_not_treated_as_empty() {
        // A committed workload exists; a transient I/O fault reading the desired set
        // must be a hard error, NOT an empty set (which would drop the workload).
        let mut store = GenStore::new(KeyFailStorage {
            inner: MemStorage::default(),
            fail_write_key: None,
            fail_read_key: None,
        });
        upsert_workload_and_commit(&mut store, workload(1, 4), &cap()).unwrap();
        // Now make reads of the desired set fault.
        store.storage.fail_read_key = Some(DESIRED_KEY.to_string());
        let r = upsert_workload_and_commit(&mut store, workload(2, 8), &cap());
        assert!(matches!(r, Err(AgentError::Store(StoreError::StorageIo))));
        // The prior generation is untouched — the resident workload is not dropped.
        assert_eq!(store.committed().unwrap().id, 1);
    }

    /// An owner facts file as the runtime writes it: the head naming
    /// `pid`/`pid_start_ticks`, then the kernel's `OWNERS` answer holding
    /// `records` under `plan_generation`.
    fn owner_facts_at(
        pid: u32,
        pid_start_ticks: u64,
        plan_generation: u64,
        records: &[fluxor_abi::contracts::workload::owners::Record],
    ) -> Vec<u8> {
        use fluxor_abi::contracts::workload::owners;
        use fluxor_abi::platform::linux::owner_facts as file;
        let mut b = vec![0u8; file::HEAD_LEN + owners::HEADER_LEN];
        b[..4].copy_from_slice(&file::MAGIC);
        b[file::PID..file::PID + 4].copy_from_slice(&pid.to_le_bytes());
        b[file::PID_START_TICKS..file::PID_START_TICKS + 8]
            .copy_from_slice(&pid_start_ticks.to_le_bytes());
        owners::write_head(
            &mut b[file::HEAD_LEN..],
            records.len() as u16,
            plan_generation,
            &[7; 32],
        );
        for r in records {
            let at = b.len();
            b.resize(at + owners::RECORD_LEN, 0);
            assert!(r.write(&mut b[at..]));
        }
        b
    }

    /// Workload 1's owner as [`store_with_published_workload`] commits it
    /// (slot 1, owner generation 1), running its four modules.
    fn running_owner() -> fluxor_abi::contracts::workload::owners::Record {
        fluxor_abi::contracts::workload::owners::Record {
            uid: uid(1),
            slot: 1,
            generation: 1,
            modules: 4,
            loaded: 4,
            activations: 1,
            ..Default::default()
        }
    }

    /// [`owner_facts_at`] under the committed plan generation (1), with
    /// this test process as the live writer.
    fn owner_facts(
        pid: u32,
        records: &[fluxor_abi::contracts::workload::owners::Record],
    ) -> Vec<u8> {
        let ticks = proc_start_ticks(std::process::id()).unwrap_or(0);
        owner_facts_at(pid, ticks, 1, records)
    }

    fn facts_path(dir: &std::path::Path) -> std::path::PathBuf {
        dir.join(fluxor_abi::platform::linux::owner_facts::FILE_NAME)
    }

    /// FsStorage-backed store in a fresh temp dir with workload 1 committed and
    /// the plan published + publish-path recorded (the full agent flow).
    fn store_with_published_workload(
        tag: &str,
    ) -> (GenStore<crate::genstore::FsStorage>, std::path::PathBuf) {
        store_with_published(tag, workload(1, 4))
    }

    /// [`store_with_published_workload`] committing `w`.
    fn store_with_published(
        tag: &str,
        w: WorkloadDesired,
    ) -> (GenStore<crate::genstore::FsStorage>, std::path::PathBuf) {
        use crate::genstore::FsStorage;
        let dir =
            std::env::temp_dir().join(format!("fluxor-agent-rt-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = GenStore::new(FsStorage::open(&dir).unwrap());
        upsert_workload_and_commit(&mut store, w, &cap()).unwrap();
        let publish = dir.join("current.plan");
        publish_committed_plan(&store, &publish).unwrap().unwrap();
        record_publish_path(&mut store, &publish).unwrap();
        (store, dir)
    }

    const UID1_HEX: &str = "01000000000000000000000000000000";

    /// The fixture is the runtime's file: what the reader parses back is
    /// exactly the records the kernel answered, under the writer's head.
    #[test]
    fn the_owner_facts_file_reads_back_as_written() {
        let rec = running_owner();
        let f = parse_owner_facts(&owner_facts_at(42, 9, 3, &[rec])).expect("parses");
        assert_eq!((f.pid, f.pid_start_ticks, f.plan_generation), (42, 9, 3));
        assert_eq!(f.plan_digest, [7; 32]);
        assert_eq!(f.records, vec![rec]);
        let mut bad = owner_facts_at(42, 9, 3, &[rec]);
        bad[0] ^= 1;
        assert!(parse_owner_facts(&bad).is_none(), "a wrong magic");
        let short = owner_facts_at(42, 9, 3, &[rec]);
        assert!(
            parse_owner_facts(&short[..short.len() - 1]).is_none(),
            "a record past the end"
        );
    }

    #[test]
    fn status_joins_live_runtime_by_owner_uid() {
        let (store, dir) = store_with_published_workload("join");
        let faulted = fluxor_abi::contracts::workload::owners::Record {
            terminated: 1,
            fault_kind: fluxor_abi::contracts::workload::owners::FAULT_STEP_ERROR,
            activations: 3,
            ..running_owner()
        };
        std::fs::write(
            facts_path(&dir),
            owner_facts(std::process::id(), &[faulted]),
        )
        .unwrap();

        let st = node_status_with_runtime(&store).unwrap();
        let p = st
            .workloads
            .iter()
            .find(|p| p.owner_uid_hex == UID1_HEX)
            .unwrap();
        let rt = p.runtime.as_ref().expect("runtime joined");
        assert_eq!(rt.phase, RuntimePhase::Terminated);
        assert_eq!(rt.restart_count, 2);
        let t = rt.terminated.as_ref().unwrap();
        assert_eq!(t.reason, TerminatedReason::GraphNodeFault);
        assert_eq!(t.exit_code, 2);
        assert_eq!(t.signal, None);
        assert_eq!(st.runtime_plan_digest.as_deref(), Some(&*"07".repeat(32)));

        // The JSON stays additive: durable fields unchanged, `runtime` is a
        // nested optional object with the exact status-vocabulary field names.
        let v = serde_json::to_value(&st).unwrap();
        let pj = &v["workloads"][0];
        assert_eq!(pj["owner_uid_hex"], UID1_HEX);
        assert!(pj["committed"].as_bool().unwrap());
        assert_eq!(pj["runtime"]["phase"], "Terminated");
        assert_eq!(pj["runtime"]["terminated"]["reason"], "GraphNodeFault");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One rendering per record, from the record alone: a fault in one
    /// owner terminates that owner only, with the reason its fault kind
    /// names; an internal retry is unreadiness, not a restart; a draining
    /// owner withdraws readiness while it keeps running; a clean end is
    /// Completed.
    #[test]
    fn a_record_renders_its_own_phase_and_reason() {
        use fluxor_abi::contracts::workload::owners::{self, Record};
        let r = |rec: Record| render_runtime(&rec, 100);
        let healthy = running_owner();
        let rt = r(healthy);
        assert_eq!(rt.phase, RuntimePhase::Running);
        assert!(rt.ready && rt.started);
        assert_eq!(rt.restart_count, 0);
        assert!(rt.owner_state.is_none() && rt.terminated.is_none());

        for (kind, reason) in [
            (owners::FAULT_TIMEOUT, TerminatedReason::LivenessFailure),
            (owners::FAULT_STEP_ERROR, TerminatedReason::GraphNodeFault),
            (owners::FAULT_MPU, TerminatedReason::GraphNodeFault),
        ] {
            let rt = r(Record {
                terminated: 1,
                fault_kind: kind,
                ..healthy
            });
            assert_eq!(rt.phase, RuntimePhase::Terminated);
            let t = rt.terminated.unwrap();
            assert_eq!((t.reason, t.exit_code), (reason, i32::from(kind)));
        }

        let rt = r(Record {
            recovering: 1,
            ..healthy
        });
        assert_eq!(rt.phase, RuntimePhase::Running);
        assert!(!rt.ready, "a module mid-retry is unready");
        assert_eq!(rt.restart_count, 0, "and not restarted");

        let rt = r(Record {
            finished: 4,
            ..healthy
        });
        let t = rt.terminated.unwrap();
        assert_eq!((t.reason, t.exit_code), (TerminatedReason::Completed, 0));

        let rt = r(Record {
            state: owners::STATE_DRAINING,
            drain_deadline: 112,
            ..healthy
        });
        assert_eq!(rt.phase, RuntimePhase::Running, "still serving");
        assert!(!rt.ready);
        assert_eq!(rt.owner_state.as_deref(), Some("Draining"));
        assert_eq!(rt.drain_deadline_unix, Some(112));
        assert_eq!(rt.drain_remaining_secs, Some(12));

        let rt = r(Record {
            state: owners::STATE_PAUSED,
            ..healthy
        });
        assert_eq!(rt.owner_state.as_deref(), Some("Paused"));
    }

    /// The restart count is the kernel's re-activations: each time it
    /// instantiated the owner's modules again.
    #[test]
    fn re_activations_are_the_restart_count() {
        let rt = render_runtime(
            &fluxor_abi::contracts::workload::owners::Record {
                activations: 3,
                ..running_owner()
            },
            0,
        );
        assert_eq!(rt.restart_count, 2);
    }

    /// An owner whose modules are not all instantiated is Activating: plainly
    /// before any is, in `ActivationBackOff` when some failed.
    #[test]
    fn an_owner_not_fully_instantiated_is_activating() {
        use fluxor_abi::contracts::workload::owners::Record;
        let rt = render_runtime(
            &Record {
                modules: 0,
                loaded: 0,
                ..running_owner()
            },
            0,
        );
        assert_eq!(rt.phase, RuntimePhase::Activating);
        assert!(!rt.started && rt.waiting_reason.is_none());
        let rt = render_runtime(
            &Record {
                loaded: 3,
                ..running_owner()
            },
            0,
        );
        assert_eq!(rt.phase, RuntimePhase::Activating);
        assert!(!rt.ready);
        assert_eq!(rt.waiting_reason, Some(WaitingReason::ActivationBackOff));
    }

    /// A drained owner is Terminated: Completed when it quiesced, a
    /// drain-timeout fault when its deadline passed or its drain was
    /// forfeited, with the time the runtime freed it when it did.
    #[test]
    fn a_drained_owner_renders_how_its_drain_ended() {
        use fluxor_abi::contracts::workload::owners::{self, Record};
        let gone = |drain, drained_at| {
            render_runtime(
                &Record {
                    state: owners::STATE_GONE,
                    drain,
                    drained_at,
                    ..running_owner()
                },
                0,
            )
        };
        let rt = gone(owners::DRAIN_QUIESCED, 200);
        let t = rt.terminated.unwrap();
        assert_eq!((t.reason, t.exit_code), (TerminatedReason::Completed, 0));
        assert_eq!(t.finished_at.as_deref(), Some("1970-01-01T00:03:20Z"));
        let d = rt.drain.unwrap();
        assert!(!d.timed_out && !d.forfeited);

        let rt = gone(owners::DRAIN_DEADLINE_PASSED, 200);
        let t = rt.terminated.unwrap();
        assert_eq!(t.reason, TerminatedReason::GraphNodeFault);
        assert_eq!(t.exit_code, i32::from(owners::FAULT_DRAIN_TIMEOUT));
        let d = rt.drain.unwrap();
        assert!(d.timed_out && !d.forfeited);

        let rt = gone(owners::DRAIN_FORFEITED, 0);
        assert!(rt.terminated.unwrap().finished_at.is_none());
        let d = rt.drain.unwrap();
        assert!(d.timed_out && d.forfeited);
    }

    #[test]
    fn rfc3339_matches_known_instants() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(951_827_696), "2000-02-29T12:34:56Z");
        assert_eq!(rfc3339_utc(1_783_275_045), "2026-07-05T18:10:45Z");
    }

    /// A bound-endpoint report as the network provider writes it.
    fn bound_report(
        pid: u32,
        pid_start_ticks: u64,
        records: &[fluxor_abi::platform::linux::bound_endpoints::Record],
    ) -> Vec<u8> {
        use fluxor_abi::platform::linux::bound_endpoints as file;
        let mut b = vec![0u8; file::HEAD_LEN + records.len() * file::RECORD_LEN];
        file::write_head(&mut b, pid, pid_start_ticks, records.len() as u16);
        for (k, r) in records.iter().enumerate() {
            r.write(&mut b[file::HEAD_LEN + k * file::RECORD_LEN..]);
        }
        b
    }

    fn bound_rec(
        owner_slot: u16,
        owner_generation: u32,
        protocol: u8,
        port: u16,
    ) -> fluxor_abi::platform::linux::bound_endpoints::Record {
        fluxor_abi::platform::linux::bound_endpoints::Record {
            owner_slot,
            owner_generation,
            protocol,
            port,
        }
    }

    #[test]
    fn the_bound_endpoints_file_reads_back_as_written() {
        let recs = [bound_rec(1, 1, 17, 5353), bound_rec(0, 0, 6, 80)];
        let (pid, ticks, back) = parse_bound_endpoints(&bound_report(42, 9, &recs)).unwrap();
        assert_eq!((pid, ticks), (42, 9));
        assert_eq!(back, recs.to_vec());
        let mut bad = bound_report(42, 9, &recs);
        bad[0] ^= 1;
        assert!(parse_bound_endpoints(&bad).is_none(), "a wrong magic");
        let short = bound_report(42, 9, &recs);
        assert!(
            parse_bound_endpoints(&short[..short.len() - 1]).is_none(),
            "a record past the end"
        );
    }

    /// The provider's report joins a placed workload by the committed
    /// plan's owner slot and generation, against what it declared: a
    /// declared export it holds is bound, one it does not is not, a bind it
    /// never declared is shown undeclared; the node's own endpoints and an
    /// earlier owner of the slot are no workload's.
    #[test]
    fn status_joins_bound_endpoints_by_the_plans_owner() {
        use crate::compose::ExportDecl;
        let mut w = workload(1, 4);
        w.profile.endpoints = 2;
        w.exports = vec![
            ExportDecl {
                protocol: "udp".into(),
                port: 15353,
            },
            ExportDecl {
                protocol: "tcp".into(),
                port: 8080,
            },
        ];
        let (store, dir) = store_with_published("endpoints", w);
        let ticks = proc_start_ticks(std::process::id()).unwrap_or(0);
        let path = dir.join(fluxor_abi::platform::linux::bound_endpoints::FILE_NAME);
        std::fs::write(
            &path,
            bound_report(
                std::process::id(),
                ticks,
                &[
                    bound_rec(1, 1, 17, 15353),
                    bound_rec(1, 1, 6, 9999),
                    bound_rec(0, 0, 6, 80),
                    bound_rec(1, 0, 6, 8080),
                ],
            ),
        )
        .unwrap();

        // No owner facts: the endpoints still join (they are the
        // provider's, not the runtime's).
        let st = node_status_with_runtime(&store).unwrap();
        assert!(st.workloads[0].runtime.is_none());
        let ep = |protocol: &str, port, bound, declared| EndpointStatus {
            protocol: protocol.into(),
            port,
            bound,
            declared,
        };
        assert_eq!(
            st.workloads[0].endpoints,
            vec![
                ep("udp", 15353, true, true),
                ep("tcp", 8080, false, true),
                ep("tcp", 9999, true, false),
            ]
        );
        let v = serde_json::to_value(&st).unwrap();
        let e = &v["workloads"][0]["endpoints"][0];
        assert_eq!(e["protocol"], "udp");
        assert_eq!(e["port"], 15353);
        assert_eq!(e["bound"], true);
        assert_eq!(e["declared"], true);

        // A report whose writer is gone says nothing: no `endpoints` key.
        std::fs::write(
            &path,
            bound_report(4_100_000, ticks, &[bound_rec(1, 1, 17, 15353)]),
        )
        .unwrap();
        let st = node_status_with_runtime(&store).unwrap();
        assert!(st.workloads[0].endpoints.is_empty());
        let v = serde_json::to_value(&st).unwrap();
        assert!(v["workloads"][0].get("endpoints").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dead_writer_pid_means_runtime_absent() {
        let (store, dir) = store_with_published_workload("deadpid");
        // PID far above pid_max: the writer is gone; its file is history,
        // not live state.
        std::fs::write(facts_path(&dir), owner_facts(4_100_000, &[running_owner()])).unwrap();

        let st = node_status_with_runtime(&store).unwrap();
        assert!(st.workloads[0].runtime.is_none(), "stale file not surfaced");

        // Existing consumers see no `runtime` key at all.
        let v = serde_json::to_value(&st).unwrap();
        assert!(v["workloads"][0].get("runtime").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recycled_writer_pid_means_runtime_absent() {
        let (store, dir) = store_with_published_workload("recycled");
        // The writer's PID is alive (it's ours) but the recorded start time
        // belongs to a different, earlier process: the PID was recycled.
        let wrong_ticks = proc_start_ticks(std::process::id()).unwrap_or(0) + 1;
        std::fs::write(
            facts_path(&dir),
            owner_facts_at(std::process::id(), wrong_ticks, 1, &[running_owner()]),
        )
        .unwrap();

        let st = node_status_with_runtime(&store).unwrap();
        assert!(
            st.workloads[0].runtime.is_none(),
            "recycled PID not trusted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_plan_generation_drops_the_runtime_join() {
        let (store, dir) = store_with_published_workload("stalegen");
        // Live state read under a different plan generation (runtime not
        // yet rebuilt onto the current commit) must not attach to the new
        // durable records — same PID, same owner uid, wrong generation.
        let ticks = proc_start_ticks(std::process::id()).unwrap_or(0);
        std::fs::write(
            facts_path(&dir),
            owner_facts_at(std::process::id(), ticks, 999, &[running_owner()]),
        )
        .unwrap();

        let st = node_status_with_runtime(&store).unwrap();
        assert!(
            st.workloads[0].runtime.is_none(),
            "cross-generation join refused"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn slot_or_owner_generation_mismatch_drops_the_runtime_join() {
        let ticks = proc_start_ticks(std::process::id()).unwrap_or(0);
        let at = |slot, generation| {
            let rec = fluxor_abi::contracts::workload::owners::Record {
                slot,
                generation,
                ..running_owner()
            };
            owner_facts_at(std::process::id(), ticks, 1, &[rec])
        };

        // Right owner uid, wrong slot.
        let (store, dir) = store_with_published_workload("wrongslot");
        std::fs::write(facts_path(&dir), at(9, 1)).unwrap();
        let st = node_status_with_runtime(&store).unwrap();
        assert!(st.workloads[0].runtime.is_none(), "slot mismatch refused");
        let _ = std::fs::remove_dir_all(&dir);

        // Right owner uid and slot, wrong owner generation.
        let (store, dir) = store_with_published_workload("wrongogen");
        std::fs::write(facts_path(&dir), at(1, 9)).unwrap();
        let st = node_status_with_runtime(&store).unwrap();
        assert!(
            st.workloads[0].runtime.is_none(),
            "owner-generation mismatch refused"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_status_file_or_publish_record_is_not_an_error() {
        // No publish path recorded at all (MemStorage, no publish).
        let mut store = GenStore::new(MemStorage::default());
        upsert_workload_and_commit(&mut store, workload(1, 4), &cap()).unwrap();
        let st = node_status_with_runtime(&store).unwrap();
        assert!(st.workloads[0].runtime.is_none());

        // Publish recorded but no owner facts written yet.
        let (store, dir) = store_with_published_workload("nofile");
        let st = node_status_with_runtime(&store).unwrap();
        assert!(st.workloads[0].runtime.is_none());
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
        upsert_workload_and_commit(&mut store, workload(1, 1), &cap).expect("commit");

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

#[cfg(test)]
mod endpoint_join_tests {
    use super::*;
    use crate::compose::ExportDecl;

    fn decl(protocol: &str, port: u16) -> ExportDecl {
        ExportDecl {
            protocol: protocol.into(),
            port,
        }
    }
    fn bound(protocol: &str, port: u16) -> BoundEndpoint {
        BoundEndpoint {
            protocol: protocol.into(),
            port,
        }
    }

    #[test]
    fn join_marks_declared_exports_bound_and_flags_undeclared_binds() {
        let declared = [decl("TCP", 8080), decl("udp", 5353)];
        // 8080 is live; 5353 never bound; 9999 bound but never declared.
        let live = [bound("tcp", 8080), bound("tcp", 9999)];
        let joined = join_endpoints(&declared, &live);
        assert_eq!(
            joined,
            vec![
                EndpointStatus {
                    protocol: "tcp".into(),
                    port: 8080,
                    bound: true,
                    declared: true
                },
                EndpointStatus {
                    protocol: "udp".into(),
                    port: 5353,
                    bound: false,
                    declared: true
                },
                EndpointStatus {
                    protocol: "tcp".into(),
                    port: 9999,
                    bound: true,
                    declared: false
                },
            ]
        );
    }

    #[test]
    fn join_distinguishes_same_port_different_protocol() {
        // A udp bind never satisfies a tcp declaration on the same port.
        let joined = join_endpoints(&[decl("tcp", 7000)], &[bound("udp", 7000)]);
        assert!(!joined[0].bound);
        assert!(joined.iter().any(|e| e.protocol == "udp" && !e.declared));
    }

    #[test]
    fn no_declarations_and_no_binds_yield_nothing() {
        assert!(join_endpoints(&[], &[]).is_empty());
    }

    #[test]
    fn report_protocol_numbers_read_as_names() {
        use fluxor_abi::platform::linux::bound_endpoints::Record;
        let of = |protocol| {
            BoundEndpoint::of(&Record {
                owner_slot: 1,
                owner_generation: 1,
                protocol,
                port: 53,
            })
            .protocol
        };
        assert_eq!(
            (of(6), of(17), of(132)),
            ("tcp".into(), "udp".into(), "132".into())
        );
    }
}
