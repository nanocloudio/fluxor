// Owner live-status writer — the runtime half of the per-owner status
// surface. The contract (record shape, closed reason vocabularies, join key,
// freshness and generation rules) is in
// `docs/architecture/owner_status.md`; this file documents only what the
// WRITER guarantees.
//
// In node-agent mode (FLUXOR_PLAN set) the runtime consumes the committed plan
// by file + mtime watch and symmetrically publishes `owner_status.json` next to
// it, atomically replaced whenever the derived state changes. The kernel has
// already folded modules into owners in `scheduler::owner_live_snapshot`, so
// nothing here re-derives an aggregate or exposes a slot→module mapping.
//
// Writer invariants:
//   - Values are drawn only from the closed vocabularies the reader enforces;
//     emitting anything else is a bug that fails the reader's parse rather
//     than reaching a consumer.
//   - Reasons this runtime can currently observe are `Completed`,
//     `GraphNodeFault` and `LivenessFailure`, plus the `ActivationBackOff`
//     waiting reason. The rest of the vocabulary belongs to paths that do not
//     exist here yet.
//   - `restart_count` counts AGGREGATE re-activations only: an owner observed
//     Terminated (or superseded by a new owner generation) that runs again. An
//     internal module retry (step-guard `Restart` policy) surfaces as transient
//     unreadiness, never as a restart.
//   - The file is replaced whole, via temp + fsync + rename + parent-dir fsync,
//     so a concurrent reader never sees a partial record.

/// One workload's tracked lifecycle latches, keyed by owner UID. The kernel
/// snapshot is instantaneous; phase transitions (activation time, terminal
/// reason, restart count) are latched here across snapshots.
use super::owner_drain::{drain_overlay_for_status, drain_terminal_pods_json};
use super::providers::linux_net_bound_endpoints;

pub struct OwnerTrack {
    restart_count: u32,
    /// Present once the aggregate has been observed Running.
    started_at_unix: Option<u64>,
    /// Owner generation at last observation; a bump is a re-activation.
    generation: u32,
    /// Latched terminal state: (reason, exit_code, finished_at).
    terminated: Option<(&'static str, i32, u64)>,
}

/// Writes `owner_status.json` next to the published plan. Created only in
/// node-agent mode; `tick()` is cheap when nothing changed (string compare).
pub struct OwnerStatusWriter {
    path: std::path::PathBuf,
    tracks: std::collections::HashMap<[u8; 16], OwnerTrack>,
    /// Per-workload carryover recovered from a previous runtime process's status
    /// file: restart count, and whether the workload had actually started there.
    /// A workload that STARTED under the previous process re-activates under this
    /// one — that first activation is a restart. One that never got past
    /// Activating (e.g. ActivationBackOff) hasn't restarted anything.
    pub seeded: std::collections::HashMap<String, SeededPod>,
    /// This process's start time (clock ticks since boot), written into the
    /// file so the reader can tell this writer from a recycled PID.
    pid_start_ticks: u64,
    /// Last emitted `(plan_generation, workloads payload)` — rewrite only on
    /// change. The generation is part of the key: the reader scopes its join
    /// to the committed generation, so a plan reload must rewrite the file
    /// even when the derived workload states are byte-identical.
    last_emit: Option<(u64, String)>,
}

impl OwnerStatusWriter {
    /// `plan_path` is the FLUXOR_PLAN file; the status file lives beside it.
    pub fn new(plan_path: &std::path::Path) -> Self {
        let dir = plan_path.parent().unwrap_or(std::path::Path::new("."));
        let path = dir.join("owner_status.json");
        let seeded = read_seed_restarts(&path);
        OwnerStatusWriter {
            path,
            tracks: std::collections::HashMap::new(),
            seeded,
            pid_start_ticks: proc_start_ticks(std::process::id()).unwrap_or(0),
            last_emit: None,
        }
    }

    /// Pods whose previous-process status file already carried a TERMINAL
    /// state (lowercase-hex UIDs). The boot-time drain-forfeit synthesis skips
    /// these — a persisted `Completed` is never rewritten as by-restart.
    pub fn seeded_terminated_uids(&self) -> std::collections::HashSet<String> {
        self.seeded
            .iter()
            .filter(|(_, seed)| seed.terminated)
            .map(|(uid, _)| uid.clone())
            .collect()
    }

    /// Snapshot the kernel's per-owner aggregates, roll the lifecycle
    /// latches forward, and atomically replace the status file if the
    /// derived state changed.
    pub fn tick(&mut self) {
        let mut recs = [crate::kernel::exec::scheduler::OwnerLiveStatus::EMPTY;
            crate::kernel::workload::owner::MAX_OWNERS];
        let n = crate::kernel::exec::scheduler::owner_live_snapshot(&mut recs);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Live drain deadlines live in the drain driver; the kernel snapshot
        // carries only owner_state. Overlay before deriving.
        drain_overlay_for_status(&mut recs[..n], now);
        // Bound network endpoints per owner: the runtime's RAW report — which
        // (protocol, port) pairs are actually listening, owner-attributed.
        // Declarations are the agent's business.
        let bound = linux_net_bound_endpoints()
            .into_iter()
            .map(|(owner, proto, port)| (owner.slot, owner.generation, proto, port))
            .collect::<Vec<_>>();
        let mut pods_json =
            derive_pods_json(&recs[..n], &mut self.tracks, &self.seeded, now, &bound);
        // Drained-and-revoked owners are gone from the live snapshot; their
        // terminal records ride alongside until retention lapses.
        for entry in drain_terminal_pods_json() {
            if !pods_json.is_empty() {
                pods_json.push(',');
            }
            pods_json.push_str("\n    ");
            pods_json.push_str(&entry);
        }
        let plan_generation = crate::kernel::workload::owner_plan::last_applied_generation();
        if self
            .last_emit
            .as_ref()
            .is_some_and(|(g, p)| *g == plan_generation && *p == pods_json)
        {
            return;
        }
        let body = format!(
            "{{\n  \"version\": 1,\n  \"pid\": {},\n  \"pid_start_ticks\": {},\n  \
             \"plan_generation\": {plan_generation},\n  \
             \"written_at\": \"{}\",\n  \"workloads\": [{}\n  ]\n}}\n",
            std::process::id(),
            self.pid_start_ticks,
            rfc3339_utc(now),
            pods_json,
        );
        match write_atomic(&self.path, body.as_bytes()) {
            Ok(()) => {
                self.last_emit = Some((plan_generation, pods_json));
            }
            Err(e) => {
                // Non-fatal: the runtime must keep stepping even when the
                // status volume misbehaves; retry on the next change.
                log::warn!(
                    "[owner] status write to {} failed: {e}",
                    self.path.display()
                );
            }
        }
    }
}

/// Map a module fault kind (`step_guard::fault_type`) to the fixed §7.2
/// `state.terminated.reason`. A step-deadline `TIMEOUT` is the runtime's
/// liveness enforcement detecting a non-responsive module → `LivenessFailure`;
/// a step error, hard/MPU fault, or drain timeout is a graph-node fault →
/// `GraphNodeFault`. Reasons that need signals this snapshot does not carry
/// (`ExternalProcessExited`, `Evicted`, `FluxorReservationInvalid`) are not
/// emitted here — the reader enforces the full §7.2 set.
fn terminated_reason_for_fault(kind: u8) -> &'static str {
    use crate::kernel::exec::step_guard::fault_type;
    match kind {
        fault_type::TIMEOUT => "LivenessFailure",
        _ => "GraphNodeFault",
    }
}

/// Roll the per-workload latches forward against the instantaneous kernel
/// snapshot and render the `workloads` array body. Pure of I/O and clock —
/// unit-testable.
#[allow(
    clippy::implicit_hasher,
    reason = "internal platform surface; callers only ever pass std's default hasher"
)]
pub fn derive_pods_json(
    recs: &[crate::kernel::exec::scheduler::OwnerLiveStatus],
    tracks: &mut std::collections::HashMap<[u8; 16], OwnerTrack>,
    seeded: &std::collections::HashMap<String, SeededPod>,
    now_unix: u64,
    bound_endpoints: &[(u16, u32, u8, u16)], // (slot, generation, protocol, port)
) -> String {
    use std::fmt::Write;
    let mut entries: Vec<String> = Vec::with_capacity(recs.len());
    for rec in recs {
        let uid_hex: String = rec.owner_uid.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        let track = tracks.entry(rec.owner_uid).or_insert_with(|| OwnerTrack {
            restart_count: seeded.get(&uid_hex).map_or(0, |s| s.restart_count),
            started_at_unix: None,
            generation: rec.generation,
            terminated: None,
        });

        // A bumped owner generation supersedes the previous activation.
        if rec.generation != track.generation {
            if track.started_at_unix.is_some() {
                track.restart_count += 1;
            }
            track.generation = rec.generation;
            track.started_at_unix = None;
            track.terminated = None;
        }

        // Instantaneous aggregate phase from the kernel counts. A stamped
        // module whose slot never instantiated (platform logs the error and
        // continues) keeps the aggregate out of Running: `modules_loaded <
        // modules_total` is a partially-activated workload, not a healthy one.
        let fully_loaded = rec.modules_total > 0 && rec.modules_loaded >= rec.modules_total;
        let any_terminated = rec.modules_terminated > 0;
        let all_finished = fully_loaded && rec.modules_finished == rec.modules_total;

        if fully_loaded && !any_terminated {
            if track.terminated.take().is_some() {
                // Was terminal, runs again: the graph was rebuilt and the
                // owner re-activated (plan reload). Aggregate restart.
                track.restart_count += 1;
                track.started_at_unix = Some(now_unix);
            }
            if track.started_at_unix.is_none() {
                // First activation under this runtime process of a workload that
                // had STARTED under the previous one is a re-activation. A
                // seeded workload that never started (stuck Activating) is simply
                // activating for the first time.
                if let Some(seed) = seeded.get(&uid_hex) {
                    if seed.started && track.restart_count == seed.restart_count {
                        track.restart_count += 1;
                    }
                }
                track.started_at_unix = Some(now_unix);
            }
        }
        if any_terminated && track.terminated.is_none() {
            let code = if rec.last_fault_kind == 0 {
                1
            } else {
                rec.last_fault_kind as i32
            };
            track.terminated = Some((
                terminated_reason_for_fault(rec.last_fault_kind),
                code,
                now_unix,
            ));
        }
        if !any_terminated && all_finished && track.terminated.is_none() {
            track.terminated = Some(("Completed", 0, now_unix));
        }

        // §7.2 shape. Reason strings are the fixed vocabulary; nothing else
        // is ever emitted here. A partially-instantiated workload (some planned
        // modules failed to load) waits in ActivationBackOff; a workload whose
        // graph hasn't instantiated at all is plainly Activating.
        let (phase, ready, started, waiting) = match (&track.terminated, fully_loaded) {
            (Some(_), _) => ("Terminated", false, false, None),
            (None, true) => ("Running", rec.modules_recovering == 0, true, None),
            (None, false) => (
                "Activating",
                false,
                false,
                (rec.modules_total > 0).then_some("ActivationBackOff"),
            ),
        };
        // A draining owner stops reporting ready while it is still serving
        // — no new phase value, just the readiness withdrawal the
        // terminating window needs.
        let draining = rec.owner_state == crate::kernel::exec::scheduler::OWNER_STATE_DRAINING;
        let ready = ready && !draining;
        let mut e = String::new();
        let _ = write!(
            e,
            "{{\"owner_uid_hex\":\"{uid_hex}\",\"slot\":{},\"owner_generation\":{},\
             \"runtime\":{{\"phase\":\"{phase}\",\"ready\":{ready},\"started\":{started},\
             \"restart_count\":{}",
            rec.slot, rec.generation, track.restart_count,
        );
        // Bound network endpoints: the raw owner-attributed report. Additive;
        // omitted when the owner has no bound ports, so port-less workloads'
        // output is byte-identical.
        let mut bound_iter = bound_endpoints
            .iter()
            .filter(|(slot, generation, _, _)| *slot == rec.slot && *generation == rec.generation)
            .peekable();
        if bound_iter.peek().is_some() {
            let _ = write!(e, ",\"bound_endpoints\":[");
            for (i, (_, _, proto, port)) in bound_iter.enumerate() {
                let proto_name = if *proto == 2 { "udp" } else { "tcp" };
                if i > 0 {
                    e.push(',');
                }
                let _ = write!(e, "{{\"protocol\":\"{proto_name}\",\"port\":{port}}}");
            }
            e.push(']');
        }
        // New additive fields (old consumers ignore them); emitted only while
        // draining, so non-draining output is byte-identical (rfc §3.7).
        if draining {
            let _ = write!(e, ",\"owner_state\":\"Draining\"");
            if rec.drain_deadline_unix > 0 {
                let _ = write!(
                    e,
                    ",\"drain_deadline_unix\":{},\"drain_remaining_secs\":{}",
                    rec.drain_deadline_unix, rec.drain_remaining_secs
                );
            }
        }
        if let Some(t) = track.started_at_unix {
            let _ = write!(e, ",\"started_at\":\"{}\"", rfc3339_utc(t));
        }
        if let Some((reason, exit_code, finished)) = &track.terminated {
            let _ = write!(
                e,
                ",\"terminated\":{{\"reason\":\"{reason}\",\"exit_code\":{exit_code},\
                 \"signal\":null,\"finished_at\":\"{}\"}}",
                rfc3339_utc(*finished),
            );
        }
        if let Some(w) = waiting {
            let _ = write!(e, ",\"waiting_reason\":\"{w}\"");
        }
        e.push_str("}}");
        entries.push(e);
    }
    // Drop tracks for workloads no longer resident: a removed workload's latches go
    // with it (a re-added workload arrives at a strictly higher owner generation
    // and starts a fresh activation record; the durable per-workload history
    // lives with the orchestrator, not this runtime process).
    tracks.retain(|uid, _| recs.iter().any(|r| r.owner_uid == *uid));
    entries
        .iter()
        .map(|e| format!("\n    {e}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// One workload's carryover from a previous runtime process's status file.
pub struct SeededPod {
    pub restart_count: u32,
    /// The workload had actually started there: its entry carried a
    /// `started_at` stamp, or a terminal state (which counts as prior
    /// activity — a re-run after termination is a restart even in-process).
    pub started: bool,
    /// The previous process persisted a TERMINAL state for this workload. Suppresses
    /// the boot-time drain-timeout-by-restart synthesis: a clean `Completed`
    /// from before the restart is never rewritten by writer seeding.
    pub terminated: bool,
}

/// Recover per-workload carryover from a previous runtime process's status file.
/// This file is only ever written by `OwnerStatusWriter` (atomic replace),
/// so a targeted scan of our own fixed emission order — each workload object
/// opens with `"owner_uid_hex":"…"` and its runtime carries
/// `"restart_count":N` plus optional `started_at`/`terminated` — is
/// reliable without a JSON parser dependency.
pub fn read_seed_restarts(path: &std::path::Path) -> std::collections::HashMap<String, SeededPod> {
    const UID_KEY: &str = "\"owner_uid_hex\":\"";
    let mut seeds = std::collections::HashMap::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return seeds;
    };
    let mut rest = text.as_str();
    while let Some(i) = rest.find(UID_KEY) {
        rest = &rest[i + UID_KEY.len()..];
        let Some(end) = rest.find('"') else { break };
        let uid = rest[..end].to_string();
        rest = &rest[end..];
        // This workload's fields run until the next workload object (or end of file).
        let span = &rest[..rest.find(UID_KEY).unwrap_or(rest.len())];
        let Some(j) = span.find("\"restart_count\":") else {
            break;
        };
        let digits: String = span[j + "\"restart_count\":".len()..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if let Ok(n) = digits.parse::<u32>() {
            let terminated = span.contains("\"terminated\"");
            seeds.insert(
                uid,
                SeededPod {
                    restart_count: n,
                    started: span.contains("\"started_at\"") || terminated,
                    terminated,
                },
            );
        }
        rest = &rest[span.len()..];
    }
    seeds
}

/// Start time of `pid` in clock ticks since boot — field 22 of
/// `/proc/<pid>/stat`, parsed from after the LAST `)` so a comm containing
/// spaces or parens cannot shift the fields. `None` when the process is gone
/// or a zombie (state `Z`: it has exited; anything it wrote is history).
/// Written into the status file so the reader can reject a recycled PID.
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

/// Temp write + fsync + atomic rename + parent fsync — the same durability
/// discipline as the agent's `publish_committed_plan`, so a status file is
/// never observed half-written and a reported write survives power loss.
fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::File::open(&tmp)?.sync_all()?;
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::File::open(parent)?.sync_all()?;
        }
    }
    Ok(())
}

/// RFC 3339 UTC timestamp from unix seconds (Howard Hinnant's
/// civil-from-days), so the status file carries orchestrator-consumable
/// times without a date-time dependency.
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
