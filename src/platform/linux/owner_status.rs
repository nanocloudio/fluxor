// Owner live-status writer (rfc_k8s.md §7.2, §17.2, §18.2) — the runtime
// half of the per-pod status surface.
//
// In node-agent mode (FLUXOR_PLAN set) the runtime consumes the committed
// plan by file + mtime watch; symmetrically it PUBLISHES per-owner live
// status by file: `owner_status.json`, next to the plan, atomically replaced
// whenever the derived state changes. `fluxor agent status --json` joins it
// into the durable per-pod status by Pod UID, so the orchestrator
// (nanocloud) reads one pull-based surface and never learns the
// slot→module mapping — the kernel aggregated modules into owners in
// `scheduler::owner_live_snapshot`, and this file only speaks the §7.2
// vocabulary:
//
//   phase            "Activating" | "Running" | "Terminated"
//   terminated.reason "Completed" | "GraphNodeFault" | "LivenessFailure"
//                    (the reasons this runtime can currently observe; the
//                    full §7.2 set is reserved and enforced by the reader)
//   waiting_reason   "ActivationBackOff" (planned modules only partially
//                    instantiated)
//
// `restart_count` counts AGGREGATE re-activations only: an owner observed
// Terminated (or superseded by a new owner generation) that runs again has
// restarted; an internal module retry (step-guard `Restart` policy) surfaces
// only as transient unreadiness, never as a restart.

/// One pod's tracked lifecycle latches, keyed by Pod UID. The kernel
/// snapshot is instantaneous; phase transitions (activation time, terminal
/// reason, restart count) are latched here across snapshots.
struct PodTrack {
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
struct OwnerStatusWriter {
    path: std::path::PathBuf,
    tracks: std::collections::HashMap<[u8; 16], PodTrack>,
    /// Per-pod carryover recovered from a previous runtime process's status
    /// file: restart count, and whether the pod had actually started there.
    /// A pod that STARTED under the previous process re-activates under this
    /// one — that first activation is a restart. One that never got past
    /// Activating (e.g. ActivationBackOff) hasn't restarted anything.
    seeded: std::collections::HashMap<String, SeededPod>,
    /// This process's start time (clock ticks since boot), written into the
    /// file so the reader can tell this writer from a recycled PID.
    pid_start_ticks: u64,
    /// Last emitted `(plan_generation, pods payload)` — rewrite only on
    /// change. The generation is part of the key: the reader scopes its join
    /// to the committed generation, so a plan reload must rewrite the file
    /// even when the derived pod states are byte-identical.
    last_emit: Option<(u64, String)>,
}

impl OwnerStatusWriter {
    /// `plan_path` is the FLUXOR_PLAN file; the status file lives beside it.
    fn new(plan_path: &std::path::Path) -> Self {
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
    fn seeded_terminated_uids(&self) -> std::collections::HashSet<String> {
        self.seeded
            .iter()
            .filter(|(_, seed)| seed.terminated)
            .map(|(uid, _)| uid.clone())
            .collect()
    }

    /// Snapshot the kernel's per-owner aggregates, roll the lifecycle
    /// latches forward, and atomically replace the status file if the
    /// derived state changed.
    fn tick(&mut self) {
        let mut recs =
            [fluxor::kernel::scheduler::OwnerLiveStatus::EMPTY; fluxor::kernel::owner::MAX_OWNERS];
        let n = fluxor::kernel::scheduler::owner_live_snapshot(&mut recs);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Live drain deadlines live in the drain driver; the kernel snapshot
        // carries only owner_state. Overlay before deriving.
        drain_overlay_for_status(&mut recs[..n], now);
        // Bound network endpoints per owner (rfc_endpoint_lease.md §4.3): the
        // runtime's RAW report — which (protocol, port) pairs are actually
        // listening, owner-attributed. Declarations are the agent's business.
        let bound = linux_net_bound_endpoints()
            .into_iter()
            .map(|(owner, proto, port)| (owner.slot, owner.generation, proto, port))
            .collect::<Vec<_>>();
        let mut pods_json =
            derive_pods_json(&recs[..n], &mut self.tracks, &self.seeded, now, &bound);
        // Drained-and-revoked owners are gone from the live snapshot; their
        // terminal records ride alongside until retention lapses
        // (rfc_owner_drain_and_logs.md §3.7).
        for entry in drain_terminal_pods_json() {
            if !pods_json.is_empty() {
                pods_json.push(',');
            }
            pods_json.push_str("\n    ");
            pods_json.push_str(&entry);
        }
        let plan_generation = fluxor::kernel::owner_plan::last_applied_generation();
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
             \"written_at\": \"{}\",\n  \"pods\": [{}\n  ]\n}}\n",
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
                log::warn!("[owner] status write to {} failed: {e}", self.path.display());
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
    use fluxor::kernel::step_guard::fault_type;
    match kind {
        fault_type::TIMEOUT => "LivenessFailure",
        _ => "GraphNodeFault",
    }
}

/// Roll the per-pod latches forward against the instantaneous kernel
/// snapshot and render the `pods` array body. Pure of I/O and clock —
/// unit-testable.
fn derive_pods_json(
    recs: &[fluxor::kernel::scheduler::OwnerLiveStatus],
    tracks: &mut std::collections::HashMap<[u8; 16], PodTrack>,
    seeded: &std::collections::HashMap<String, SeededPod>,
    now_unix: u64,
    bound_endpoints: &[(u16, u32, u8, u16)], // (slot, generation, protocol, port)
) -> String {
    use std::fmt::Write;
    let mut entries: Vec<String> = Vec::with_capacity(recs.len());
    for rec in recs {
        let uid_hex: String = rec.pod_uid.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        let track = tracks.entry(rec.pod_uid).or_insert_with(|| PodTrack {
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
        // modules_total` is a partially-activated pod, not a healthy one.
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
                // First activation under this runtime process of a pod that
                // had STARTED under the previous one is a re-activation. A
                // seeded pod that never started (stuck Activating) is simply
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
            track.terminated = Some((terminated_reason_for_fault(rec.last_fault_kind), code, now_unix));
        }
        if !any_terminated && all_finished && track.terminated.is_none() {
            track.terminated = Some(("Completed", 0, now_unix));
        }

        // §7.2 shape. Reason strings are the fixed vocabulary; nothing else
        // is ever emitted here. A partially-instantiated pod (some planned
        // modules failed to load) waits in ActivationBackOff; a pod whose
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
        // (rfc_owner_drain_and_logs.md §3.1) — no new phase value, just the
        // readiness withdrawal the terminating window needs.
        let draining =
            rec.owner_state == fluxor::kernel::scheduler::OWNER_STATE_DRAINING;
        let ready = ready && !draining;
        let mut e = String::new();
        let _ = write!(
            e,
            "{{\"pod_uid_hex\":\"{uid_hex}\",\"slot\":{},\"owner_generation\":{},\
             \"runtime\":{{\"phase\":\"{phase}\",\"ready\":{ready},\"started\":{started},\
             \"restart_count\":{}",
            rec.slot, rec.generation, track.restart_count,
        );
        // Bound network endpoints (rfc_endpoint_lease.md §4.3 doc 1): the raw
        // owner-attributed report. Additive; omitted when the owner has no
        // bound ports, so port-less pods' output is byte-identical.
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
    // Drop tracks for pods no longer resident: a removed pod's latches go
    // with it (a re-added pod arrives at a strictly higher owner generation
    // and starts a fresh activation record; the durable per-pod history
    // lives with the orchestrator, not this runtime process).
    tracks.retain(|uid, _| recs.iter().any(|r| r.pod_uid == *uid));
    entries
        .iter()
        .map(|e| format!("\n    {e}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// One pod's carryover from a previous runtime process's status file.
struct SeededPod {
    restart_count: u32,
    /// The pod had actually started there: its entry carried a
    /// `started_at` stamp, or a terminal state (which counts as prior
    /// activity — a re-run after termination is a restart even in-process).
    started: bool,
    /// The previous process persisted a TERMINAL state for this pod. Suppresses
    /// the boot-time drain-timeout-by-restart synthesis: a clean `Completed`
    /// from before the restart is never rewritten
    /// (rfc_owner_drain_and_logs.md §3.6/§3.7 writer seeding).
    terminated: bool,
}

/// Recover per-pod carryover from a previous runtime process's status file.
/// This file is only ever written by `OwnerStatusWriter` (atomic replace),
/// so a targeted scan of our own fixed emission order — each pod object
/// opens with `"pod_uid_hex":"…"` and its runtime carries
/// `"restart_count":N` plus optional `started_at`/`terminated` — is
/// reliable without a JSON parser dependency.
fn read_seed_restarts(path: &std::path::Path) -> std::collections::HashMap<String, SeededPod> {
    const UID_KEY: &str = "\"pod_uid_hex\":\"";
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
        // This pod's fields run until the next pod object (or end of file).
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

#[cfg(test)]
mod owner_status_tests {
    use super::*;
    use fluxor::kernel::scheduler::OwnerLiveStatus;
    use fluxor::kernel::step_guard::fault_type;

    fn uid(n: u8) -> [u8; 16] {
        let mut u = [0u8; 16];
        u[0] = n;
        u
    }

    fn rec(n: u8, slot: u16, generation: u32) -> OwnerLiveStatus {
        OwnerLiveStatus {
            pod_uid: uid(n),
            slot,
            generation,
            modules_total: 2,
            modules_loaded: 2,
            ..OwnerLiveStatus::EMPTY
        }
    }

    #[test]
    fn rfc3339_matches_known_instants() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        // date -u -d @1783275045 → 2026-07-05T18:10:45Z
        assert_eq!(rfc3339_utc(1_783_275_045), "2026-07-05T18:10:45Z");
        assert_eq!(rfc3339_utc(951_827_696), "2000-02-29T12:34:56Z");
    }

    #[test]
    fn seed_distinguishes_terminated_pods_for_by_restart_suppression() {
        // Exactly the writer's own emission shape (read_seed_restarts scans it
        // by substring): pod AA terminated (its outcome is persisted and must
        // not be rewritten as by-restart after a restart), pod BB still running.
        let dir = std::env::temp_dir().join(format!(
            "fluxor-seed-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let plan = dir.join("current.plan");
        let body = concat!(
            "{\n  \"version\": 1,\n  \"pid\": 1,\n  \"pid_start_ticks\": 2,\n",
            "  \"plan_generation\": 3,\n  \"written_at\": \"x\",\n  \"pods\": [\n",
            "    {\"pod_uid_hex\":\"aa000000000000000000000000000000\",\"slot\":1,",
            "\"owner_generation\":1,\"runtime\":{\"phase\":\"Terminated\",",
            "\"ready\":false,\"started\":false,\"restart_count\":0,",
            "\"terminated\":{\"reason\":\"Completed\",\"exit_code\":0,",
            "\"signal\":null,\"finished_at\":\"x\"}}},\n",
            "    {\"pod_uid_hex\":\"bb000000000000000000000000000000\",\"slot\":2,",
            "\"owner_generation\":1,\"runtime\":{\"phase\":\"Running\",",
            "\"ready\":true,\"started\":true,\"restart_count\":0,",
            "\"started_at\":\"x\"}}\n  ]\n}\n",
        );
        std::fs::write(dir.join("owner_status.json"), body).expect("write");

        let writer = OwnerStatusWriter::new(&plan);
        let terminated = writer.seeded_terminated_uids();
        assert!(terminated.contains("aa000000000000000000000000000000"));
        assert!(!terminated.contains("bb000000000000000000000000000000"));
        // The started/restart seed semantics are unchanged by the new flag.
        assert!(writer.seeded["aa000000000000000000000000000000"].started);
        assert!(writer.seeded["bb000000000000000000000000000000"].started);
        assert!(!writer.seeded["bb000000000000000000000000000000"].terminated);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bound_endpoints_are_attributed_to_the_owning_pod_only() {
        let mut tracks = std::collections::HashMap::new();
        let seeds = std::collections::HashMap::new();
        // Pod A (slot 1 gen 7) has a tcp listener + a udp socket; pod B none.
        let bound = [(1u16, 7u32, 1u8, 8080u16), (1, 7, 2, 5353)];
        let j = derive_pods_json(
            &[rec(0xaa, 1, 7), rec(0xbb, 2, 3)],
            &mut tracks,
            &seeds,
            100,
            &bound,
        );
        let (a, b) = j.split_at(j.find("bb000000").unwrap());
        assert!(a.contains(
            "\"bound_endpoints\":[{\"protocol\":\"tcp\",\"port\":8080},{\"protocol\":\"udp\",\"port\":5353}]"
        ));
        assert!(
            !b.contains("bound_endpoints"),
            "port-less pod's output is unchanged"
        );
        // A stale-generation entry (slot reused) never attributes.
        let mut tracks2 = std::collections::HashMap::new();
        let j = derive_pods_json(
            &[rec(0xcc, 1, 8)],
            &mut tracks2,
            &seeds,
            100,
            &[(1, 7, 1, 8080)],
        );
        assert!(!j.contains("bound_endpoints"));
    }

    #[test]
    fn draining_owner_emits_owner_state_and_withdraws_readiness() {
        use fluxor::kernel::scheduler::OWNER_STATE_DRAINING;
        let mut tracks = std::collections::HashMap::new();
        let seeds = std::collections::HashMap::new();

        // A healthy owner that is NOT draining emits no owner_state field and is
        // ready — output stays byte-identical to before this change.
        let healthy = [rec(0xaa, 1, 7)];
        let j = derive_pods_json(&healthy, &mut tracks, &seeds, 100, &[]);
        assert!(!j.contains("owner_state"));
        assert!(j.contains("\"ready\":true"));

        // Flip the same owner to Draining with a deadline: owner_state appears,
        // readiness withdraws (still serving), drain fields present.
        let mut draining = rec(0xbb, 2, 3);
        draining.owner_state = OWNER_STATE_DRAINING;
        draining.drain_deadline_unix = 1_783_275_045;
        draining.drain_remaining_secs = 12;
        let j = derive_pods_json(&[draining], &mut tracks, &seeds, 100, &[]);
        assert!(j.contains("\"owner_state\":\"Draining\""));
        assert!(j.contains("\"drain_deadline_unix\":1783275045"));
        assert!(j.contains("\"drain_remaining_secs\":12"));
        assert!(j.contains("\"ready\":false"));
        // Phase itself stays in the frozen vocabulary.
        assert!(j.contains("\"phase\":\"Running\""));
    }

    #[test]
    fn co_resident_fault_terminates_only_the_owning_pod() {
        let mut tracks = std::collections::HashMap::new();
        let seeds = std::collections::HashMap::new();
        let healthy = [rec(0xaa, 1, 7), rec(0xbb, 2, 3)];
        let j = derive_pods_json(&healthy, &mut tracks, &seeds, 100, &[]);
        assert_eq!(j.matches("\"phase\":\"Running\"").count(), 2);
        assert!(j.contains("\"ready\":true"));

        // Pod A's module terminates (STEP_ERROR); pod B untouched.
        let mut faulted = healthy;
        faulted[0].modules_terminated = 1;
        faulted[0].last_fault_kind = fault_type::STEP_ERROR;
        let j = derive_pods_json(&faulted, &mut tracks, &seeds, 200, &[]);
        let (a, b) = j.split_at(j.find("bb000000").unwrap());
        assert!(a.contains("\"phase\":\"Terminated\""));
        assert!(a.contains("\"reason\":\"GraphNodeFault\""));
        assert!(a.contains("\"exit_code\":2"));
        assert!(a.contains("\"finished_at\":\"1970-01-01T00:03:20Z\""));
        assert!(b.contains("\"phase\":\"Running\"") && b.contains("\"ready\":true"));
    }

    #[test]
    fn internal_retry_is_unready_not_a_restart() {
        let mut tracks = std::collections::HashMap::new();
        let seeds = std::collections::HashMap::new();
        let mut r = [rec(0xaa, 1, 7)];
        derive_pods_json(&r, &mut tracks, &seeds, 100, &[]);

        // Module mid-retry: aggregate stays Running, unready, restart_count 0.
        r[0].modules_recovering = 1;
        let j = derive_pods_json(&r, &mut tracks, &seeds, 200, &[]);
        assert!(j.contains("\"phase\":\"Running\""));
        assert!(j.contains("\"ready\":false"));
        assert!(j.contains("\"restart_count\":0"));

        // Retry succeeded: ready again, still no restart counted.
        r[0].modules_recovering = 0;
        let j = derive_pods_json(&r, &mut tracks, &seeds, 300, &[]);
        assert!(j.contains("\"ready\":true"));
        assert!(j.contains("\"restart_count\":0"));
    }

    #[test]
    fn aggregate_reactivation_increments_restart_count() {
        let mut tracks = std::collections::HashMap::new();
        let seeds = std::collections::HashMap::new();
        let mut r = [rec(0xaa, 1, 7)];
        let j = derive_pods_json(&r, &mut tracks, &seeds, 100, &[]);
        assert!(j.contains("\"restart_count\":0"));
        assert!(j.contains("\"started_at\":\"1970-01-01T00:01:40Z\""));

        // Terminal fault…
        r[0].modules_terminated = 1;
        r[0].last_fault_kind = fault_type::TIMEOUT;
        let j = derive_pods_json(&r, &mut tracks, &seeds, 200, &[]);
        assert!(j.contains("\"phase\":\"Terminated\""));
        assert!(j.contains("\"restart_count\":0"), "termination isn't a restart yet");

        // …graph rebuilt, owner re-activated → ONE aggregate restart.
        r[0].modules_terminated = 0;
        r[0].last_fault_kind = 0;
        let j = derive_pods_json(&r, &mut tracks, &seeds, 300, &[]);
        assert!(j.contains("\"phase\":\"Running\""));
        assert!(j.contains("\"restart_count\":1"));
        assert!(j.contains("\"started_at\":\"1970-01-01T00:05:00Z\""), "re-stamped");
    }

    #[test]
    fn generation_bump_is_a_reactivation() {
        let mut tracks = std::collections::HashMap::new();
        let seeds = std::collections::HashMap::new();
        derive_pods_json(&[rec(0xaa, 1, 7)], &mut tracks, &seeds, 100, &[]);
        let j = derive_pods_json(&[rec(0xaa, 1, 9)], &mut tracks, &seeds, 200, &[]);
        assert!(j.contains("\"owner_generation\":9"));
        assert!(j.contains("\"restart_count\":1"));
    }

    #[test]
    fn clean_completion_is_completed_exit_zero() {
        let mut tracks = std::collections::HashMap::new();
        let seeds = std::collections::HashMap::new();
        let mut r = [rec(0xaa, 1, 7)];
        derive_pods_json(&r, &mut tracks, &seeds, 100, &[]);
        r[0].modules_finished = 2;
        let j = derive_pods_json(&r, &mut tracks, &seeds, 200, &[]);
        assert!(j.contains("\"reason\":\"Completed\""));
        assert!(j.contains("\"exit_code\":0"));
    }

    #[test]
    fn fault_kind_maps_to_the_specific_terminated_reason() {
        let seeds = std::collections::HashMap::new();

        // A step-deadline timeout is the runtime's liveness enforcement.
        let mut tracks = std::collections::HashMap::new();
        let mut r = [rec(0xaa, 1, 7)];
        derive_pods_json(&r, &mut tracks, &seeds, 100, &[]);
        r[0].modules_terminated = 1;
        r[0].last_fault_kind = fault_type::TIMEOUT;
        let j = derive_pods_json(&r, &mut tracks, &seeds, 200, &[]);
        assert!(j.contains("\"reason\":\"LivenessFailure\""), "{j}");

        // A step error (module returned Err) is a graph-node fault.
        let mut tracks = std::collections::HashMap::new();
        let mut r = [rec(0xbb, 2, 3)];
        derive_pods_json(&r, &mut tracks, &seeds, 100, &[]);
        r[0].modules_terminated = 1;
        r[0].last_fault_kind = fault_type::STEP_ERROR;
        let j = derive_pods_json(&r, &mut tracks, &seeds, 200, &[]);
        assert!(j.contains("\"reason\":\"GraphNodeFault\""), "{j}");

        // A hard fault is likewise a graph-node fault.
        let mut tracks = std::collections::HashMap::new();
        let mut r = [rec(0xcc, 3, 1)];
        derive_pods_json(&r, &mut tracks, &seeds, 100, &[]);
        r[0].modules_terminated = 1;
        r[0].last_fault_kind = fault_type::HARD_FAULT;
        let j = derive_pods_json(&r, &mut tracks, &seeds, 200, &[]);
        assert!(j.contains("\"reason\":\"GraphNodeFault\""), "{j}");
    }

    #[test]
    fn seed_roundtrip_survives_runtime_restart() {
        let mut tracks = std::collections::HashMap::new();
        let seeds = std::collections::HashMap::new();
        let mut r = [rec(0xaa, 1, 7)];
        derive_pods_json(&r, &mut tracks, &seeds, 100, &[]);
        r[0].modules_terminated = 1;
        derive_pods_json(&r, &mut tracks, &seeds, 200, &[]);
        r[0].modules_terminated = 0;
        let j = derive_pods_json(&r, &mut tracks, &seeds, 300, &[]);
        assert!(j.contains("\"restart_count\":1"));

        // Write what the runtime would write, re-seed as a fresh process.
        let dir = std::env::temp_dir().join(format!("fluxor-ostat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("owner_status.json");
        std::fs::write(&path, format!("{{\"pods\": [{j}]}}")).unwrap();
        let seeds2 = read_seed_restarts(&path);
        let seed = &seeds2["aa000000000000000000000000000000"];
        assert_eq!(seed.restart_count, 1);
        assert!(seed.started);

        // First activation under the new process = one more restart.
        let mut tracks2 = std::collections::HashMap::new();
        let j2 = derive_pods_json(&[rec(0xaa, 1, 7)], &mut tracks2, &seeds2, 400, &[]);
        assert!(j2.contains("\"restart_count\":2"));
        // A pod unknown to the previous process starts at zero.
        let j3 = derive_pods_json(&[rec(0xbb, 2, 1)], &mut tracks2, &seeds2, 500, &[]);
        assert!(j3.contains("\"restart_count\":0"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn never_started_pod_does_not_restart_across_runtime_restart() {
        // Previous process: the pod was stuck in ActivationBackOff (one of
        // two modules failed to instantiate) — never started.
        let mut tracks = std::collections::HashMap::new();
        let seeds = std::collections::HashMap::new();
        let mut r = [rec(0xaa, 1, 7)];
        r[0].modules_loaded = 1;
        let j = derive_pods_json(&r, &mut tracks, &seeds, 100, &[]);
        assert!(j.contains("\"waiting_reason\":\"ActivationBackOff\""));

        let dir = std::env::temp_dir().join(format!("fluxor-ostat-ns-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("owner_status.json");
        std::fs::write(&path, format!("{{\"pods\": [{j}]}}")).unwrap();
        let seeds2 = read_seed_restarts(&path);
        assert!(!seeds2["aa000000000000000000000000000000"].started);

        // New process: the pod finally loads fully. That is its FIRST
        // activation, not a restart.
        let mut tracks2 = std::collections::HashMap::new();
        r[0].modules_loaded = 2;
        let j2 = derive_pods_json(&r, &mut tracks2, &seeds2, 200, &[]);
        assert!(j2.contains("\"phase\":\"Running\""));
        assert!(j2.contains("\"restart_count\":0"), "{j2}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn uninstantiated_owner_is_activating() {
        let mut tracks = std::collections::HashMap::new();
        let seeds = std::collections::HashMap::new();
        let mut r = [rec(0xaa, 1, 7)];
        r[0].modules_total = 0;
        r[0].modules_loaded = 0;
        let j = derive_pods_json(&r, &mut tracks, &seeds, 100, &[]);
        assert!(j.contains("\"phase\":\"Activating\""));
        assert!(j.contains("\"started\":false"));
        assert!(!j.contains("started_at"), "not started yet");
        assert!(!j.contains("waiting_reason"), "nothing failed — plain Activating");
    }

    #[test]
    fn partial_instantiation_is_activation_backoff_not_running() {
        let mut tracks = std::collections::HashMap::new();
        let seeds = std::collections::HashMap::new();
        // One of two planned modules failed to instantiate.
        let mut r = [rec(0xaa, 1, 7)];
        r[0].modules_loaded = 1;
        let j = derive_pods_json(&r, &mut tracks, &seeds, 100, &[]);
        assert!(j.contains("\"phase\":\"Activating\""), "{j}");
        assert!(j.contains("\"ready\":false"));
        assert!(j.contains("\"waiting_reason\":\"ActivationBackOff\""));
        assert!(!j.contains("started_at"), "never activated");

        // The missing module loads (e.g. rebuild succeeds): Running, ready.
        r[0].modules_loaded = 2;
        let j = derive_pods_json(&r, &mut tracks, &seeds, 200, &[]);
        assert!(j.contains("\"phase\":\"Running\""));
        assert!(j.contains("\"ready\":true"));
        assert!(!j.contains("waiting_reason"));
        assert!(j.contains("\"restart_count\":0"), "activation, not a restart");
    }
}

/// RFC 3339 UTC timestamp from unix seconds (Howard Hinnant's
/// civil-from-days), so the status file carries orchestrator-consumable
/// times without a date-time dependency.
fn rfc3339_utc(unix_secs: u64) -> String {
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
