//! Orchestrator — the single canonical run lifecycle.
//!
//!   claim → build → guard { attach → stage → power → match } → teardown → manifest
//!
//!   1. claim the rig: the lock, and a teardown of whatever an earlier run
//!      left behind if its marker is still there
//!   2. build or resolve artifacts (nothing has touched the rig yet, so a
//!      failure here records `Aborted` and tears nothing down)
//!   3. install the guard: write the teardown marker, set the lock's
//!      expected end, start listening for signals
//!   4. attach observers
//!   5. deploy artifacts
//!   6. apply power/reboot action
//!   7. wait for pass/fail/expectation/timeout
//!   8. tear down: diagnose on a failure, power off always, unstage, drain
//!      the last bytes, detach transports, clear the marker if every step
//!      came out clean
//!   9. write the manifest — on every path, including an error or a
//!      signal — and release the lock
//!
//! The orchestrator knows nothing about specific backends (kasa plugs,
//! journalctl, termios, ...). It resolves capability → backend executable
//! via `rig::backend` and speaks only the subprocess protocol.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};
use crate::rig::backend::{
    attach_with_grace, context_from_plan, invoke_with, resolve as resolve_backend, resolve_relay,
    wire_artifact, wire_binding, ActuatorOutcome, BackendContext, BackendInvocation, BackendRef,
    InvokeOptions, RelayRef, TransportHandle, PHASE_ADHOC, PHASE_RUN, PHASE_TEARDOWN,
};
use crate::rig::events::{DeployEvent, RunEvent};
use crate::rig::lock::{
    acquire as acquire_lock, ensure_state_dir, marker_path_for, now_unix_secs, AcquireOutcome,
    LockGuard, LockOwner, TeardownMarker,
};
use crate::rig::matcher;
use crate::rig::plan::{ArtifactPlan, Plan, DEFAULT_ACTUATOR_TIMEOUT_S};
use crate::rig::profile::{BindingTable, BindingValue, RigProfile};
use crate::rig::record::{
    hash_artifact_bundle, hash_artifact_file, ActuatorRecord, GitIdentity, RunRecord,
    TeardownRecord, Verdict,
};
use crate::rig::vocab::{Capability, Surface};

/// Final outcome of a non-plan `fluxor rig test` invocation.
#[derive(Debug)]
pub struct RunOutcome {
    pub record: RunRecord,
    pub run_dir: PathBuf,
}

pub struct RunOptions {
    /// Skip the build step. Useful when the operator ran `make` themselves.
    pub skip_build: bool,
    /// Force-release any existing lock on the rig.
    pub force_lock: bool,
    /// Actuator subprocess timeout when the binding sets no
    /// `actuator_timeout_s`. Doesn't apply to transports.
    pub actuator_timeout: Duration,
    /// On a verdict other than `Passed`, keep the rig as the run left it
    /// for this long (or until Enter / Ctrl-C) before tearing down.
    pub hold: Option<Duration>,
    /// Run `power diagnose` even when the run was aborted by a signal.
    pub diagnose_on_abort: bool,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            skip_build: false,
            force_lock: false,
            actuator_timeout: Duration::from_secs(DEFAULT_ACTUATOR_TIMEOUT_S),
            hold: None,
            diagnose_on_abort: false,
        }
    }
}

// ── Signals ────────────────────────────────────────────────────────────────

/// Set from the signal handler; read on the main thread between steps.
/// An in-flight actuator is never interrupted (it runs in its own process
/// group, so a terminal's Ctrl-C does not reach it): the step finishes,
/// then the run aborts into its teardown.
static ABORT: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    ABORT.store(true, Ordering::SeqCst);
}

/// Route SIGINT, SIGTERM and SIGHUP into the abort flag. Called once by
/// the CLI before a run; idempotent.
pub fn install_signal_handlers() {
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: the handler only stores to an atomic, which is
        // async-signal-safe; `signal` with a plain function pointer is the
        // documented way to install it.
        unsafe {
            libc::signal(
                sig,
                on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t,
            );
        }
    }
}

/// What a signal would do, for tests and for `--hold`'s end.
pub fn request_abort() {
    ABORT.store(true, Ordering::SeqCst);
}

pub fn abort_requested() -> bool {
    ABORT.load(Ordering::SeqCst)
}

fn clear_abort() {
    ABORT.store(false, Ordering::SeqCst);
}

// ── The run ────────────────────────────────────────────────────────────────

pub fn execute_plan(plan: &Plan, profile: &RigProfile, options: &RunOptions) -> Result<RunOutcome> {
    clear_abort();

    // Step 1 — claim the rig.
    let lock_path = plan
        .lock_path
        .clone()
        .ok_or_else(|| Error::Config("rig run: cannot resolve lock path (no $HOME?)".into()))?;
    let owner = LockOwner::now(
        &plan.rig,
        &format!("scenario:{}", plan.scenario_name),
        plan.effective_timeout_s,
    );
    let lock_guard = claim(&lock_path, &owner, options.force_lock, profile, options)?;
    let state_dir = ensure_state_dir(&lock_path)?;

    // Run dir (used by the backend context AND by the console log writer).
    let run_dir = run_dir_for(plan);
    std::fs::create_dir_all(&run_dir).map_err(|e| {
        Error::Config(format!(
            "rig run: creating run dir {}: {e}",
            run_dir.display()
        ))
    })?;
    let mut record = plan.run_record.clone();
    record.started_at = now_unix_secs();

    // Resolve backends up front so missing-binary errors surface before we
    // touch the rig, and before anything is built.
    let backends = match Backends::resolve(plan, profile) {
        Ok(b) => b,
        Err(e) => return finish_aborted(record, &run_dir, lock_guard, e),
    };

    // Step 2 — build / resolve artifacts. No guard yet: a failed build has
    // touched nothing, so there is nothing to tear down.
    if matches!(plan.artifact, ArtifactPlan::Unresolved { .. }) {
        return finish_aborted(
            record,
            &run_dir,
            lock_guard,
            Error::Config(
                "rig run: artifact is unresolved — add a [build.<target>] recipe to \
                 ~/.config/fluxor/projects/<name>/rig.toml (or an in-tree .fluxor-rig.toml)"
                    .into(),
            ),
        );
    }
    let built = match run_build(plan, profile, options, &run_dir) {
        Ok(b) => b,
        Err(e) => return finish_aborted(record, &run_dir, lock_guard, e),
    };
    record.artifact_git = project_root_of(plan).and_then(GitIdentity::probe);
    record.artifact_sha256 = match &built {
        Some(ArtifactOutput::File(path)) => hash_artifact_file(path).ok(),
        Some(ArtifactOutput::Bundle(root)) => hash_artifact_bundle(root).ok(),
        None => plan.run_record.artifact_sha256.clone(),
    };

    // Step 3 — the guard. From here on every exit path tears down and
    // writes the manifest.
    let marker_path = marker_path_for(&lock_path);
    TeardownMarker::new(&plan.rig, &record.run_id, &run_dir).write(&marker_path)?;
    lock_guard.set_expected_end(now_unix_secs() + plan.lifecycle_budget_s)?;

    let mut session = Session::new(plan, &backends, &run_dir, &state_dir, options);
    let outcome = session.run();
    record.verdict = outcome.verdict.clone();
    record.primary_observation_source = outcome.primary_source;
    record.reason = outcome.reason;

    if record.verdict != Verdict::Passed {
        if let Some(hold) = options.hold {
            session.hold(hold, &lock_guard);
        }
    }
    record.reports = std::mem::take(&mut session.reports);

    // Step 8 — teardown, on every path.
    let diagnose = matches!(record.verdict, Verdict::Failed | Verdict::TimedOut)
        || (record.verdict == Verdict::Aborted && options.diagnose_on_abort);
    let teardown = session.teardown(diagnose);
    if teardown.clean {
        TeardownMarker::clear(&marker_path)?;
    } else {
        let mut marker = TeardownMarker::new(&plan.rig, &record.run_id, &run_dir);
        marker.last_error = Some(teardown_failure_summary(&teardown));
        marker.write(&marker_path)?;
    }
    let clean = teardown.clean;
    record.teardown = Some(teardown);

    // Step 9 — the manifest, then the lock.
    record.finished_at = Some(now_unix_secs());
    write_manifest(&record, &run_dir)?;
    eprintln!(
        "[rig] verdict: {:?}{}  run={}",
        record.verdict,
        if clean {
            ""
        } else {
            "  (TEARDOWN INCOMPLETE — rig marked for teardown)"
        },
        run_dir.display(),
    );
    drop(lock_guard);
    if !clean {
        return Err(Error::Config(format!(
            "rig run: teardown did not complete; the rig stays marked until \
             `fluxor rig teardown --rig {}` succeeds — see {}",
            plan.rig,
            run_dir.join("manifest.json").display()
        )));
    }
    Ok(RunOutcome { record, run_dir })
}

/// Acquire the lock; if the marker says an earlier run never finished its
/// teardown, do that teardown now, holding the lock, before returning.
fn claim(
    lock_path: &Path,
    owner: &LockOwner,
    force: bool,
    profile: &RigProfile,
    options: &RunOptions,
) -> Result<LockGuard> {
    match acquire_lock(lock_path, owner, force)? {
        AcquireOutcome::Acquired(g) => Ok(g),
        AcquireOutcome::Held(conflict) => Err(Error::Config(format!(
            "rig run: {} is already held by pid {} on {} running '{}' since epoch {} \
             (stale={}). Pass --force to take it over.",
            conflict.path.display(),
            conflict.existing.pid,
            conflict.existing.hostname,
            conflict.existing.task,
            conflict.existing.started_at,
            conflict.stale
        ))),
        AcquireOutcome::NeedsTeardown { guard, marker } => {
            eprintln!(
                "[rig] run {} did not finish its teardown ({}); tearing down before anything else",
                marker.run_id,
                marker.last_error.as_deref().unwrap_or("interrupted")
            );
            let record = teardown_rig(profile, lock_path, Some(&marker), options)?;
            if !record.clean {
                return Err(Error::Config(format!(
                    "rig run: the earlier run's teardown still fails ({}); fix that first, \
                     then `fluxor rig teardown --rig {}`",
                    teardown_failure_summary(&record),
                    profile.rig.id
                )));
            }
            Ok(guard)
        }
    }
}

fn finish_aborted(
    mut record: RunRecord,
    run_dir: &Path,
    lock_guard: LockGuard,
    err: Error,
) -> Result<RunOutcome> {
    record.verdict = Verdict::Aborted;
    record.reason = Some(err.to_string());
    record.finished_at = Some(now_unix_secs());
    write_manifest(&record, run_dir)?;
    drop(lock_guard);
    Err(err)
}

fn write_manifest(record: &RunRecord, run_dir: &Path) -> Result<()> {
    let manifest_path = run_dir.join("manifest.json");
    std::fs::write(&manifest_path, record.to_json()).map_err(|e| {
        Error::Config(format!(
            "rig run: writing manifest {}: {e}",
            manifest_path.display()
        ))
    })
}

// ── Backends ───────────────────────────────────────────────────────────────

struct Backends<'a> {
    deploy: (BackendRef, &'a BindingTable),
    consoles: Vec<(Capability, BackendRef, &'a BindingTable)>,
    telemetry: Option<(Capability, BackendRef, &'a BindingTable)>,
    observers: Vec<(Capability, BackendRef, &'a BindingTable)>,
    power: Option<(BackendRef, &'a BindingTable)>,
}

impl<'a> Backends<'a> {
    fn resolve(plan: &Plan, profile: &'a RigProfile) -> Result<Self> {
        let deploy_binding = profile.deploy.get(&plan.deploy.capability).ok_or_else(|| {
            Error::Config(format!(
                "rig run: plan chose {} but profile has no matching [deploy.*] binding",
                plan.deploy.capability.as_str()
            ))
        })?;
        let deploy = (
            resolve_bound(
                Surface::Deploy,
                capability_name(plan.deploy.capability),
                deploy_binding,
                profile,
            )?,
            deploy_binding,
        );
        let mut consoles = Vec::new();
        for c in &plan.consoles {
            let binding = profile.console.get(&c.capability).ok_or_else(|| {
                Error::Config(format!(
                    "rig run: plan chose {} but profile has no [console.*] binding",
                    c.capability.as_str()
                ))
            })?;
            consoles.push((
                c.capability,
                resolve_bound(
                    Surface::Console,
                    capability_name(c.capability),
                    binding,
                    profile,
                )?,
                binding,
            ));
        }
        let telemetry = match &plan.telemetry {
            Some(t) => {
                let binding = profile.telemetry.get(&t.capability).ok_or_else(|| {
                    Error::Config(format!(
                        "rig run: plan chose {} but profile has no [telemetry.*] binding",
                        t.capability.as_str()
                    ))
                })?;
                Some((
                    t.capability,
                    resolve_bound(
                        Surface::Telemetry,
                        capability_name(t.capability),
                        binding,
                        profile,
                    )?,
                    binding,
                ))
            }
            None => None,
        };
        let mut observers = Vec::new();
        for o in &plan.observe_transports {
            let binding = profile.observe.get(&o.capability).ok_or_else(|| {
                Error::Config(format!(
                    "rig run: plan chose {} but profile has no [observe.*] binding",
                    o.capability.as_str()
                ))
            })?;
            observers.push((
                o.capability,
                resolve_bound(
                    Surface::Observe,
                    capability_name(o.capability),
                    binding,
                    profile,
                )?,
                binding,
            ));
        }
        let power = match profile.power.as_ref() {
            Some(binding) => {
                let name = binding.require_string("backend", "power")?;
                Some((
                    resolve_bound(Surface::Power, name, binding, profile)?,
                    binding,
                ))
            }
            None => None,
        };
        if plan.power_required && power.is_none() {
            return Err(Error::Config(format!(
                "rig run: scenario '{}' requires a power backend but the rig profile has \
                 no [power] binding. Either add one or drop the power.* entries from the \
                 scenario's `requires` list.",
                plan.scenario_name,
            )));
        }
        Ok(Self {
            deploy,
            consoles,
            telemetry,
            observers,
            power,
        })
    }
}

/// Resolve a backend for a binding, through the relay the binding names
/// (`relay = "<name>"`) when it names one. The relay's own `[relay.<name>]`
/// binding rides along in every invocation.
pub(crate) fn resolve_bound(
    surface: Surface,
    name: &str,
    binding: &BindingTable,
    profile: &RigProfile,
) -> Result<BackendRef> {
    let backend = resolve_backend(surface, name)?;
    let Some(relay_name) = binding.relay() else {
        return Ok(backend);
    };
    let relay_binding = profile.relay.get(relay_name).ok_or_else(|| {
        Error::Config(format!(
            "rig: {} runs through relay '{relay_name}' but the profile has no \
             [relay.{relay_name}]",
            backend.slug()
        ))
    })?;
    let executable = resolve_relay(relay_name)?;
    Ok(backend.via(RelayRef {
        name: relay_name.to_string(),
        executable,
        binding: wire_binding(relay_binding),
    }))
}

fn invoke_options(
    binding: &BindingTable,
    fallback: Duration,
    run_dir: &Path,
    surface: &str,
    verb: &str,
    phase: &str,
) -> InvokeOptions {
    let suffix = if phase == PHASE_TEARDOWN {
        ".teardown"
    } else {
        ""
    };
    InvokeOptions {
        timeout: binding.actuator_timeout().unwrap_or(fallback),
        grace: binding.shutdown_grace().unwrap_or(Duration::from_secs(2)),
        stderr_log: Some(run_dir.join(format!("{surface}-{verb}{suffix}.stderr.log"))),
    }
}

/// Run one actuator verb and describe it for the manifest. I/O errors
/// (cannot spawn, malformed JSON) become a failed record rather than an
/// `Err`, so a teardown always runs every step.
fn step(
    backend: &BackendRef,
    verb: &str,
    invocation: &BackendInvocation,
    options: &InvokeOptions,
) -> ActuatorRecord {
    eprintln!(
        "[rig] {}.{verb} via {}",
        backend.surface.as_str(),
        backend.slug()
    );
    let mut rec = ActuatorRecord {
        verb: verb.to_string(),
        ..ActuatorRecord::default()
    };
    match invoke_with(backend, verb, invocation, options) {
        Ok(ActuatorOutcome::Ok(report)) => {
            let no_op = report
                .info
                .as_deref()
                .is_some_and(|i| i.trim_start().to_ascii_lowercase().starts_with("no-op"));
            rec.outcome = if no_op { "ok (no-op)" } else { "ok" }.to_string();
            if let Some(info) = report.info.as_deref() {
                eprintln!("[rig] {verb}: {info}");
            }
            rec.info = report.info;
            rec.detail = report.detail;
        }
        Ok(ActuatorOutcome::Unsupported) => {
            rec.outcome = "unsupported".to_string();
        }
        Ok(ActuatorOutcome::Failed {
            reason,
            stderr_tail,
            ..
        }) => {
            eprintln!("[rig] {verb} failed: {reason}");
            rec.outcome = format!("failed: {reason}");
            if !stderr_tail.is_empty() {
                rec.info = Some(stderr_tail);
            }
        }
        Err(e) => {
            eprintln!("[rig] {verb} failed: {e}");
            rec.outcome = format!("failed: {e}");
        }
    }
    rec
}

/// `detail.residue` is what an `off` or `sweep` found still alive. Any
/// non-empty list means the rig is not down, whatever the exit code said.
fn residue_summary(rec: &ActuatorRecord) -> Option<String> {
    let residue = rec.detail.as_ref()?.get("residue")?.as_object()?;
    let mut left = Vec::new();
    for (kind, items) in residue {
        if let Some(arr) = items.as_array() {
            if !arr.is_empty() {
                left.push(format!(
                    "{kind}={}",
                    serde_json::to_string(arr).unwrap_or_default()
                ));
            }
        }
    }
    if left.is_empty() {
        None
    } else {
        Some(left.join(", "))
    }
}

fn teardown_failure_summary(t: &TeardownRecord) -> String {
    let mut parts = Vec::new();
    for (name, rec) in [
        ("diagnose", &t.diagnose),
        ("power", &t.power),
        ("unstage", &t.unstage),
    ] {
        if !rec.is_clean() {
            parts.push(format!("{name}: {}", rec.outcome));
        }
    }
    if parts.is_empty() {
        "not clean".to_string()
    } else {
        parts.join("; ")
    }
}

// ── Session: everything between guard and manifest ─────────────────────────

struct MatchOutcome {
    verdict: Verdict,
    primary_source: Option<String>,
    reason: Option<String>,
}

struct Session<'a> {
    plan: &'a Plan,
    backends: &'a Backends<'a>,
    run_dir: &'a Path,
    state_dir: &'a Path,
    options: &'a RunOptions,
    reports: crate::rig::record::Reports,
    rx: mpsc::Receiver<RunEvent>,
    tx: mpsc::Sender<RunEvent>,
    transports: Vec<TransportHandle>,
    deploy_watch: Option<TransportHandle>,
    byte_logs: BTreeMap<Capability, std::fs::File>,
    /// Visibility of console bytes to the matcher, see `visible`.
    power_started: bool,
    power_done: bool,
    booted: BTreeSet<Capability>,
}

impl<'a> Session<'a> {
    fn new(
        plan: &'a Plan,
        backends: &'a Backends<'a>,
        run_dir: &'a Path,
        state_dir: &'a Path,
        options: &'a RunOptions,
    ) -> Self {
        let (tx, rx) = mpsc::channel::<RunEvent>();
        Self {
            plan,
            backends,
            run_dir,
            state_dir,
            options,
            reports: Default::default(),
            rx,
            tx,
            transports: Vec::new(),
            deploy_watch: None,
            byte_logs: BTreeMap::new(),
            power_started: false,
            // With no power step there is no "previous image talking":
            // everything the transports say is this run's.
            power_done: plan.power_actions.is_empty() || backends.power.is_none(),
            booted: BTreeSet::new(),
        }
    }

    fn context(&self, phase: &str) -> BackendContext {
        context_from_plan(self.plan, self.run_dir, self.state_dir, phase)
    }

    fn invocation(&self, binding: &BindingTable, phase: &str) -> BackendInvocation {
        BackendInvocation {
            binding: wire_binding(binding),
            context: self.context(phase),
            artifact: None,
            args: None,
            relay: None,
        }
    }

    /// Steps 4–7. Never returns `Err`: anything that goes wrong is an
    /// `Aborted` verdict with its reason, so the teardown still runs.
    fn run(&mut self) -> MatchOutcome {
        match self.attach() {
            Ok(()) => {}
            Err(e) => return aborted(format!("attaching transports: {e}")),
        }

        // Step 5 — deploy artifact (actuator).
        let stage_invocation = BackendInvocation {
            binding: wire_binding(self.backends.deploy.1),
            context: self.context(PHASE_RUN),
            artifact: wire_artifact(&self.plan.artifact),
            args: None,
            relay: None,
        };
        let opts = invoke_options(
            self.backends.deploy.1,
            self.options.actuator_timeout,
            self.run_dir,
            "deploy",
            "stage",
            PHASE_RUN,
        );
        let stage = step(&self.backends.deploy.0, "stage", &stage_invocation, &opts);
        let stage_ok = stage.is_ok();
        let stage_outcome = stage.outcome.clone();
        self.reports.stage = Some(stage);
        if !stage_ok {
            return aborted(format!("deploy stage: {stage_outcome}"));
        }
        if abort_requested() {
            return aborted("interrupted by signal".into());
        }

        // Step 6 — power actions. The verbs come from the plan, which
        // maps them from `scenario.requires`: `power.cycle` → `["cycle"]`,
        // otherwise each named verb in list order; `["cycle"]` is the
        // default when a backend is configured but the scenario names no
        // power capability. The markers around them give the matcher a
        // total order: bytes between them are the previous image unless a
        // transport reported a fresh boot in that window.
        if let Some((backend, binding)) = &self.backends.power {
            if !self.plan.power_actions.is_empty() {
                let _ = self.tx.send(RunEvent::PowerStarted);
                let invocation = self.invocation(binding, PHASE_RUN);
                for verb in &self.plan.power_actions {
                    let opts = invoke_options(
                        binding,
                        self.options.actuator_timeout,
                        self.run_dir,
                        "power",
                        verb,
                        PHASE_RUN,
                    );
                    let rec = step(backend, verb, &invocation, &opts);
                    let ok = rec.is_ok();
                    let outcome = rec.outcome.clone();
                    self.reports.power.push(rec);
                    if !ok {
                        let _ = self.tx.send(RunEvent::PowerDone);
                        return aborted(format!("power {verb}: {outcome}"));
                    }
                    if abort_requested() {
                        let _ = self.tx.send(RunEvent::PowerDone);
                        return aborted("interrupted by signal".into());
                    }
                }
                let _ = self.tx.send(RunEvent::PowerDone);
            }
        } else {
            eprintln!(
                "[rig] no power backend configured — scenario does not require one, \
                 assuming DUT is already running"
            );
        }

        // Step 7 — wait for pass/fail/expectation/timeout.
        self.match_loop()
    }

    fn attach(&mut self) -> Result<()> {
        // One log file per byte-stream source the plan attached. File name
        // is `<capability>.log` (e.g. `console.serial.log`,
        // `telemetry.monitor_udp.log`); keeping the streams separate matches
        // the matcher's per-source buffers and avoids interleaved byte
        // streams when multiple sources are wired in the same run.
        let mut caps: Vec<Capability> = self.backends.consoles.iter().map(|c| c.0).collect();
        if let Some(t) = &self.backends.telemetry {
            caps.push(t.0);
        }
        for o in &self.backends.observers {
            caps.push(o.0);
        }
        for cap in caps {
            let path = self.run_dir.join(format!("{}.log", cap.as_str()));
            let f = std::fs::File::create(&path).map_err(|e| {
                Error::Config(format!(
                    "rig run: opening byte-stream log {}: {e}",
                    path.display()
                ))
            })?;
            self.byte_logs.insert(cap, f);
        }

        // Step 4 — attach transports.
        let (deploy_backend, deploy_binding) = &self.backends.deploy;
        let grace = deploy_binding
            .shutdown_grace()
            .unwrap_or(Duration::from_secs(2));
        self.deploy_watch = Some(attach_with_grace(
            deploy_backend.clone(),
            "watch",
            &self.invocation(deploy_binding, PHASE_RUN),
            self.tx.clone(),
            grace,
        )?);

        // Attach every console transport named by a scenario rule (plus the
        // default log-capture console when the scenario names none), the
        // telemetry adapter the board declares, and the transport-style
        // observers. Each transport's bytes are source-tagged so the
        // matcher evaluates rules only against bytes from the capability
        // they declared.
        let mut attachments: Vec<(&str, Capability, &BackendRef, &BindingTable)> = Vec::new();
        for (cap, backend, binding) in &self.backends.consoles {
            attachments.push(("console", *cap, backend, binding));
        }
        if let Some((cap, backend, binding)) = &self.backends.telemetry {
            attachments.push(("telemetry", *cap, backend, binding));
        }
        for (cap, backend, binding) in &self.backends.observers {
            attachments.push(("observer", *cap, backend, binding));
        }
        for (label, _cap, backend, binding) in attachments {
            let grace = binding.shutdown_grace().unwrap_or(Duration::from_secs(2));
            let handle = attach_with_grace(
                backend.clone(),
                "attach",
                &self.invocation(binding, PHASE_RUN),
                self.tx.clone(),
                grace,
            )?;
            eprintln!("[rig] {label} attached: {}", handle.backend().slug());
            self.transports.push(handle);
        }
        Ok(())
    }

    /// Whether console bytes from `source` describe this run's target.
    /// Before the power step they are the previous image talking, unless
    /// the transport reported a fresh boot after the power step started
    /// (a reopened USB console, a cloud machine that did not exist before).
    fn visible(&self, source: Capability) -> bool {
        self.power_done || self.booted.contains(&source)
    }

    /// Write bytes to the capture log, track the power markers, and say
    /// whether the matcher should see the event.
    fn observe_event(&mut self, event: &RunEvent) -> bool {
        match event {
            RunEvent::ConsoleBytes { source, bytes } => {
                if let Some(f) = self.byte_logs.get_mut(source) {
                    let _ = f.write_all(bytes);
                }
                self.visible(*source)
            }
            RunEvent::Boot { source } => {
                if self.power_started {
                    self.booted.insert(*source);
                }
                eprintln!("[rig] {}: fresh boot", source.as_str());
                true
            }
            RunEvent::PowerStarted => {
                self.power_started = true;
                true
            }
            RunEvent::PowerDone => {
                self.power_done = true;
                true
            }
            RunEvent::DeployProgress(DeployEvent::ArtifactFetched {
                filename,
                client_ip,
                ..
            }) => {
                eprintln!(
                    "[rig] deploy fetch: {filename}{}",
                    client_ip
                        .as_deref()
                        .map(|ip| format!(" -> {ip}"))
                        .unwrap_or_default()
                );
                true
            }
            RunEvent::DeployProgress(DeployEvent::Error(msg)) => {
                eprintln!("[rig] deploy error: {msg}");
                true
            }
            RunEvent::DeployProgress(DeployEvent::DhcpActivity) => true,
            RunEvent::TransportClosed { source, reason } => {
                let watch_unsupported = source.surface() == Surface::Deploy
                    && self
                        .deploy_watch
                        .as_mut()
                        .is_some_and(|h| h.exited_unsupported());
                if !watch_unsupported {
                    eprintln!("[rig] transport closed: {}: {reason}", source.as_str());
                }
                true
            }
        }
    }

    fn match_loop(&mut self) -> MatchOutcome {
        let now = Instant::now();
        let mut m = match matcher::Matcher::with_expectations(
            &self.plan.pass_rules,
            &self.plan.fail_rules,
            &self.plan.expect_rules,
            now,
        ) {
            Ok(m) => m,
            Err(e) => return aborted(format!("compiling rules: {e}")),
        };
        // Matching starts now; a `PowerDone` already in the queue moves the
        // anchor to the moment the power step actually finished.
        m.set_anchor(now);
        let deadline = now + Duration::from_secs(self.plan.effective_timeout_s as u64);

        // The matcher reports which rule *actually* fired; we save its source
        // alongside the verdict so the run record can cite the specific rule
        // rather than whichever rule happened to be listed first.
        loop {
            if abort_requested() {
                return aborted("interrupted by signal".into());
            }
            let now = Instant::now();
            let remaining = deadline.saturating_duration_since(now);
            if remaining.is_zero() {
                return from_matcher(m.finalize());
            }
            let wait = remaining.min(Duration::from_secs(1));
            match self.rx.recv_timeout(wait) {
                Ok(event) => {
                    let show = self.observe_event(&event);
                    let now = Instant::now();
                    let outcome = if show {
                        m.observe_at(&event, now)
                    } else {
                        m.tick(now)
                    };
                    if let Some(res) = if_final(outcome) {
                        return res;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Some(res) = if_final(m.tick(Instant::now())) {
                        return res;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return from_matcher(m.finalize());
                }
            }
        }
    }

    /// Pull whatever the transports have said since the last look into the
    /// capture logs. Used between teardown steps and while holding, so the
    /// instance's last words are kept.
    fn drain(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            let _ = self.observe_event(&event);
        }
    }

    /// `--hold`: keep the rig as the run left it until Enter (on a
    /// terminal), a signal, or the time runs out. The power backend's
    /// `hold` verb is told first and may refuse (a cloud deadline it
    /// cannot extend), in which case the hold is skipped.
    fn hold(&mut self, hold: Duration, lock_guard: &LockGuard) {
        let minutes = hold.as_secs().div_ceil(60);
        if let Some((backend, binding)) = &self.backends.power {
            let mut invocation = self.invocation(binding, PHASE_RUN);
            invocation.args = Some(serde_json::json!({ "minutes": minutes }));
            let opts = invoke_options(
                binding,
                self.options.actuator_timeout,
                self.run_dir,
                "power",
                "hold",
                PHASE_RUN,
            );
            let rec = step(backend, "hold", &invocation, &opts);
            if rec.outcome.starts_with("failed") {
                eprintln!("[rig] hold refused ({}); tearing down now", rec.outcome);
                self.reports.power.push(rec);
                return;
            }
            self.reports.power.push(rec);
        }
        if let Err(e) = lock_guard.set_expected_end(now_unix_secs() + hold.as_secs() + 60) {
            eprintln!("[rig] could not extend the lock for the hold: {e}; tearing down now");
            return;
        }
        // SAFETY: isatty only queries fd 0; no memory is touched.
        let interactive = unsafe { libc::isatty(0) } == 1;
        eprintln!(
            "[rig] holding the rig for up to {} min{}; Ctrl-C ends the hold",
            minutes,
            if interactive { " (or press Enter)" } else { "" }
        );
        let (enter_tx, enter_rx) = mpsc::channel::<()>();
        if interactive {
            std::thread::spawn(move || {
                let mut line = String::new();
                let _ = std::io::stdin().read_line(&mut line);
                let _ = enter_tx.send(());
            });
        }
        let deadline = Instant::now() + hold;
        clear_abort();
        while Instant::now() < deadline && !abort_requested() {
            if enter_rx.try_recv().is_ok() {
                break;
            }
            self.drain();
            std::thread::sleep(Duration::from_millis(200));
        }
        clear_abort();
        eprintln!("[rig] hold over; tearing down");
    }

    /// Step 8. Every step runs whatever the earlier ones did; the record
    /// says which succeeded.
    fn teardown(mut self, diagnose: bool) -> TeardownRecord {
        let context = self.context(PHASE_TEARDOWN);
        let backends: &Backends<'a> = self.backends;
        let run_dir: &Path = self.run_dir;
        let fallback = self.options.actuator_timeout;
        let unstage_targets: Vec<(&BackendRef, &BindingTable)> =
            vec![(&backends.deploy.0, backends.deploy.1)];
        let power = backends.power.as_ref().map(|(b, t)| (b, *t));
        let record = run_teardown_steps(
            &context,
            power,
            &unstage_targets,
            diagnose,
            fallback,
            run_dir,
            &mut || self.drain(),
        );
        // Detach transports: SIGTERM, grace, SIGKILL, join readers.
        self.deploy_watch.take();
        self.transports.clear();
        self.drain();
        for f in self.byte_logs.values_mut() {
            let _ = f.flush();
        }
        record
    }
}

/// The teardown's three steps, shared by a run's teardown and by
/// `fluxor rig teardown` (which has no transports to drain). `between`
/// runs after each step.
fn run_teardown_steps(
    context: &BackendContext,
    power: Option<(&BackendRef, &BindingTable)>,
    unstage_targets: &[(&BackendRef, &BindingTable)],
    diagnose: bool,
    fallback_timeout: Duration,
    run_dir: &Path,
    between: &mut dyn FnMut(),
) -> TeardownRecord {
    let mut record = TeardownRecord::default();
    let unsupported = |verb: &str| ActuatorRecord {
        verb: verb.to_string(),
        outcome: "unsupported".to_string(),
        info: None,
        detail: None,
    };

    // 1. diagnose — only on a failure, and only if the backend has it.
    record.diagnose = match (&power, diagnose) {
        (Some((backend, binding)), true) => {
            let invocation = BackendInvocation {
                binding: wire_binding(binding),
                context: context.clone(),
                artifact: None,
                args: None,
                relay: None,
            };
            let opts = invoke_options(
                binding,
                fallback_timeout,
                run_dir,
                "power",
                "diagnose",
                PHASE_TEARDOWN,
            );
            step(backend, "diagnose", &invocation, &opts)
        }
        _ => {
            let mut r = unsupported("diagnose");
            if !diagnose {
                r.outcome = "skipped".to_string();
            }
            r
        }
    };
    between();

    // 2. power off — always. A backend that cannot cut power says so with a
    //    no-op; a profile with no power binding cannot even say that.
    record.power = match &power {
        Some((backend, binding)) => {
            let invocation = BackendInvocation {
                binding: wire_binding(binding),
                context: context.clone(),
                artifact: None,
                args: None,
                relay: None,
            };
            let opts = invoke_options(
                binding,
                fallback_timeout,
                run_dir,
                "power",
                "off",
                PHASE_TEARDOWN,
            );
            let mut rec = step(backend, "off", &invocation, &opts);
            if rec.is_ok() {
                if let Some(left) = residue_summary(&rec) {
                    rec.outcome = format!("failed: residue {left}");
                }
            }
            rec
        }
        None => unsupported("off"),
    };
    between();

    // 3. unstage — whatever was staged for this run.
    let mut unstage: Option<ActuatorRecord> = None;
    for (backend, binding) in unstage_targets {
        let invocation = BackendInvocation {
            binding: wire_binding(binding),
            context: context.clone(),
            artifact: None,
            args: None,
            relay: None,
        };
        let opts = invoke_options(
            binding,
            fallback_timeout,
            run_dir,
            "deploy",
            "unstage",
            PHASE_TEARDOWN,
        );
        let rec = step(backend, "unstage", &invocation, &opts);
        // Several deploy backends: the worst outcome is the one recorded.
        unstage = Some(match unstage.take() {
            Some(prev) if !prev.is_clean() => prev,
            _ => rec,
        });
    }
    record.unstage = unstage.unwrap_or_else(|| unsupported("unstage"));
    between();

    record.clean = (record.diagnose.is_clean() || record.diagnose.outcome == "skipped")
        && record.power.is_clean()
        && record.unstage.is_clean();
    record
}

/// Tear a rig down outside a run: after a crash left the marker, or on
/// `fluxor rig teardown`. Uses every deploy backend the profile binds, and
/// the marker's run dir (so that run's manifest records the teardown) or
/// a fresh ad-hoc run dir.
pub fn teardown_rig(
    profile: &RigProfile,
    lock_path: &Path,
    marker: Option<&TeardownMarker>,
    options: &RunOptions,
) -> Result<TeardownRecord> {
    let lab = lab_of(lock_path);
    let (run_id, run_dir) = match marker {
        Some(m) => (m.run_id.clone(), PathBuf::from(&m.run_dir)),
        None => {
            let (secs, nanos) = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| (d.as_secs(), d.subsec_nanos()))
                .unwrap_or((0, 0));
            let id = format!("{secs:010}-{nanos:09}-{}-teardown", profile.rig.id);
            let dir = lock_path
                .parent()
                .map(|p| p.join("runs").join(&id))
                .unwrap_or_else(|| PathBuf::from(&id));
            (id, dir)
        }
    };
    std::fs::create_dir_all(&run_dir)
        .map_err(|e| Error::Config(format!("rig teardown: creating {}: {e}", run_dir.display())))?;
    let state_dir = ensure_state_dir(lock_path)?;
    let context = BackendContext {
        rig_id: profile.rig.id.clone(),
        lab,
        run_id: run_id.clone(),
        run_dir: run_dir.display().to_string(),
        scenario_name: "teardown".to_string(),
        board: profile.rig.board.clone(),
        effective_timeout_ms: options.actuator_timeout.as_millis() as u64,
        phase: PHASE_TEARDOWN.to_string(),
        state_dir: state_dir.display().to_string(),
    };
    let power_backend = match profile.power.as_ref() {
        Some(binding) => {
            let name = binding.require_string("backend", "power")?;
            Some((
                resolve_bound(Surface::Power, name, binding, profile)?,
                binding,
            ))
        }
        None => None,
    };
    let mut deploy_backends: Vec<(BackendRef, &BindingTable)> = Vec::new();
    for (cap, binding) in &profile.deploy {
        match resolve_bound(Surface::Deploy, capability_name(*cap), binding, profile) {
            Ok(b) => deploy_backends.push((b, binding)),
            Err(e) => eprintln!("[rig] teardown: skipping {}: {e}", cap.as_str()),
        }
    }
    let unstage_targets: Vec<(&BackendRef, &BindingTable)> =
        deploy_backends.iter().map(|(b, t)| (b, *t)).collect();
    let power = power_backend.as_ref().map(|(b, t)| (b, *t));
    let record = run_teardown_steps(
        &context,
        power,
        &unstage_targets,
        false,
        options.actuator_timeout,
        &run_dir,
        &mut || {},
    );

    let marker_path = marker_path_for(lock_path);
    if record.clean {
        TeardownMarker::clear(&marker_path)?;
    } else {
        let mut m = marker
            .cloned()
            .unwrap_or_else(|| TeardownMarker::new(&profile.rig.id, &run_id, &run_dir));
        m.last_error = Some(teardown_failure_summary(&record));
        m.write(&marker_path)?;
    }

    // Record it on the run it belongs to, when that run has a manifest.
    let manifest_path = run_dir.join("manifest.json");
    if let Ok(raw) = std::fs::read_to_string(&manifest_path) {
        if let Ok(mut existing) = serde_json::from_str::<RunRecord>(&raw) {
            existing.teardown = Some(record.clone());
            existing.finished_at = Some(now_unix_secs());
            let _ = std::fs::write(&manifest_path, existing.to_json());
        }
    } else {
        let _ = std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "run_id": run_id,
                "rig": profile.rig.id,
                "kind": "teardown",
                "finished_at": now_unix_secs(),
                "teardown": record,
            }))
            .unwrap_or_default(),
        );
    }
    eprintln!(
        "[rig] teardown {}: {}",
        if record.clean { "clean" } else { "INCOMPLETE" },
        if record.clean {
            "rig is down".to_string()
        } else {
            teardown_failure_summary(&record)
        }
    );
    Ok(record)
}

/// An ad-hoc power verb that leaves the rig running (`on`, `cycle`) on a
/// board whose images leave the host must not be a way to leave a machine
/// behind: it runs under the same guard as a scenario, holds for as long
/// as asked, and tears down.
pub fn adhoc_power_under_guard(
    profile: &RigProfile,
    lock_path: &Path,
    lock_guard: &LockGuard,
    verb: &str,
    hold: Duration,
    options: &RunOptions,
) -> Result<TeardownRecord> {
    clear_abort();
    let state_dir = ensure_state_dir(lock_path)?;
    let (secs, nanos) = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs(), d.subsec_nanos()))
        .unwrap_or((0, 0));
    let run_id = format!("{secs:010}-{nanos:09}-{}-power-{verb}", profile.rig.id);
    let run_dir = lock_path
        .parent()
        .map(|p| p.join("runs").join(&run_id))
        .unwrap_or_else(|| state_dir.join(&run_id));
    std::fs::create_dir_all(&run_dir)
        .map_err(|e| Error::Config(format!("rig power: creating {}: {e}", run_dir.display())))?;
    let binding = profile
        .power
        .as_ref()
        .ok_or_else(|| Error::Config("rig power: profile has no [power] section".into()))?;
    let backend = resolve_bound(
        Surface::Power,
        binding.require_string("backend", "power")?,
        binding,
        profile,
    )?;
    let marker_path = marker_path_for(lock_path);
    TeardownMarker::new(&profile.rig.id, &run_id, &run_dir).write(&marker_path)?;
    let timeout = binding
        .actuator_timeout()
        .unwrap_or(options.actuator_timeout);
    lock_guard.set_expected_end(now_unix_secs() + 3 * timeout.as_secs() + hold.as_secs() + 60)?;

    let context = BackendContext {
        rig_id: profile.rig.id.clone(),
        lab: lab_of(lock_path),
        run_id: run_id.clone(),
        run_dir: run_dir.display().to_string(),
        scenario_name: format!("power:{verb}"),
        board: profile.rig.board.clone(),
        effective_timeout_ms: timeout.as_millis() as u64,
        phase: PHASE_ADHOC.to_string(),
        state_dir: state_dir.display().to_string(),
    };
    let invocation = BackendInvocation {
        binding: wire_binding(binding),
        context: context.clone(),
        artifact: None,
        args: None,
        relay: None,
    };
    let opts = invoke_options(
        binding,
        options.actuator_timeout,
        &run_dir,
        "power",
        verb,
        PHASE_ADHOC,
    );
    let rec = step(&backend, verb, &invocation, &opts);
    if rec.is_ok() {
        let minutes = hold.as_secs().div_ceil(60);
        eprintln!("[rig] holding the rig for up to {minutes} min; Ctrl-C ends the hold");
        let deadline = Instant::now() + hold;
        while Instant::now() < deadline && !abort_requested() {
            std::thread::sleep(Duration::from_millis(200));
        }
        clear_abort();
    }
    teardown_rig(
        profile,
        lock_path,
        TeardownMarker::read(&marker_path)?.as_ref(),
        options,
    )
}

// ── helpers ────────────────────────────────────────────────────────────────

fn aborted(reason: String) -> MatchOutcome {
    MatchOutcome {
        verdict: Verdict::Aborted,
        primary_source: None,
        reason: Some(reason),
    }
}

fn from_matcher(outcome: matcher::MatcherOutcome) -> MatchOutcome {
    match outcome {
        matcher::MatcherOutcome::Passed { primary_source } => MatchOutcome {
            verdict: Verdict::Passed,
            primary_source: Some(primary_source.as_str().to_string()),
            reason: None,
        },
        matcher::MatcherOutcome::Failed {
            primary_source,
            reason,
            ..
        } => MatchOutcome {
            verdict: Verdict::Failed,
            primary_source: Some(primary_source.as_str().to_string()),
            reason: Some(reason),
        },
        matcher::MatcherOutcome::TimedOut | matcher::MatcherOutcome::InProgress => MatchOutcome {
            verdict: Verdict::TimedOut,
            primary_source: None,
            reason: Some("no verdict before the timeout".into()),
        },
    }
}

fn if_final(outcome: matcher::MatcherOutcome) -> Option<MatchOutcome> {
    match outcome {
        matcher::MatcherOutcome::InProgress => None,
        other => Some(from_matcher(other)),
    }
}

enum ArtifactOutput {
    File(PathBuf),
    Bundle(PathBuf),
}

fn project_root_of(plan: &Plan) -> Option<&Path> {
    match &plan.artifact {
        ArtifactPlan::File { project_root, .. } | ArtifactPlan::Bundle { project_root, .. } => {
            Some(project_root)
        }
        ArtifactPlan::Unresolved { .. } => None,
    }
}

fn run_build(
    plan: &Plan,
    profile: &RigProfile,
    options: &RunOptions,
    run_dir: &Path,
) -> Result<Option<ArtifactOutput>> {
    if options.skip_build {
        return Ok(plan_artifact_to_output(plan));
    }
    let (command, project_root, out) = match &plan.artifact {
        ArtifactPlan::File {
            command,
            project_root,
            path,
        } => (command, project_root, ArtifactOutput::File(path.clone())),
        ArtifactPlan::Bundle {
            command,
            project_root,
            root,
        } => (command, project_root, ArtifactOutput::Bundle(root.clone())),
        ArtifactPlan::Unresolved { reason } => {
            return Err(Error::Config(format!(
                "rig run: cannot build — artifact is unresolved: {reason}"
            )))
        }
    };
    if command.is_empty() {
        return Err(Error::Config(
            "rig run: empty build command in project descriptor".into(),
        ));
    }
    eprintln!("[rig] scenario.config: {}", plan.config_path.display());
    eprintln!(
        "[rig] build ({}): {}",
        project_root.display(),
        shell_render(command)
    );
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);
    // Project build commands run with the project root as CWD so
    // relative paths in the recipe resolve against the same anchor as the
    // artifact output.
    cmd.current_dir(project_root);
    // Bench facts the repo cannot carry. A Pico 2 W cannot be built for
    // without the SSID of the network in this room, and no checked-in
    // graph can name it; without a channel for that the build silently
    // produced an image that boots and can never reach a network.
    //
    // Names are used verbatim so the profile says exactly what the build
    // will see. Values are NOT logged here: a profile field written
    // `${env:…}` or `${file:…}` is a secret to the rest of the rig, and
    // printing it at the one place it is consumed would undo that.
    if !profile.build_env.is_empty() {
        let mut names: Vec<&str> = Vec::new();
        for (name, value) in profile.build_env.iter() {
            match value {
                BindingValue::Secret(sec) => {
                    cmd.env(name, sec.expose());
                    names.push(name.as_str());
                }
                other => {
                    return Err(Error::Config(format!(
                        "profile: [build_env].{name} must be a string, got {other:?}"
                    )));
                }
            }
        }
        names.sort_unstable();
        eprintln!("[rig] build env from profile: {}", names.join(", "));
    }
    // Host facts the build reads (`host:…` in a graph), with this rig's
    // `[host]` laid over the operator's file. Written per run, so the run
    // record's directory holds exactly what the build saw.
    if let Some(path) = write_host_config(profile, run_dir)? {
        cmd.env("FLUXOR_HOST_CONFIG", &path);
        eprintln!("[rig] host config for the build: {}", path.display());
    }
    let status = cmd
        .status()
        .map_err(|e| Error::Config(format!("rig run: spawning build `{}`: {e}", &command[0])))?;
    if !status.success() {
        return Err(Error::Config(format!(
            "rig run: build command exited with status {status}"
        )));
    }
    Ok(Some(out))
}

/// `run_dir/host.toml`: the operator's host config with the profile's
/// `[host]` merged over it, table by table. `None` when the profile has
/// no `[host]` — the build then reads the operator's file as usual.
fn write_host_config(profile: &RigProfile, run_dir: &Path) -> Result<Option<PathBuf>> {
    if profile.host.is_empty() {
        return Ok(None);
    }
    let mut merged = match crate::stack_expand::host_config_path() {
        Some(p) if p.is_file() => {
            let raw = std::fs::read_to_string(&p)
                .map_err(|e| Error::Config(format!("rig run: reading {}: {e}", p.display())))?;
            toml::from_str::<toml::Table>(&raw)
                .map_err(|e| Error::Config(format!("rig run: parsing {}: {e}", p.display())))?
        }
        _ => toml::Table::new(),
    };
    merge_tables(&mut merged, &profile.host);
    let path = run_dir.join("host.toml");
    let text = toml::to_string(&merged)
        .map_err(|e| Error::Config(format!("rig run: rendering host config: {e}")))?;
    std::fs::write(&path, text)
        .map_err(|e| Error::Config(format!("rig run: writing {}: {e}", path.display())))?;
    Ok(Some(path))
}

/// Lay `over` on `base`: tables merge, anything else replaces.
fn merge_tables(base: &mut toml::Table, over: &toml::Table) {
    for (k, v) in over {
        match (base.get_mut(k), v) {
            (Some(toml::Value::Table(b)), toml::Value::Table(o)) => merge_tables(b, o),
            _ => {
                base.insert(k.clone(), v.clone());
            }
        }
    }
}

fn plan_artifact_to_output(plan: &Plan) -> Option<ArtifactOutput> {
    match &plan.artifact {
        ArtifactPlan::File { path, .. } => Some(ArtifactOutput::File(path.clone())),
        ArtifactPlan::Bundle { root, .. } => Some(ArtifactOutput::Bundle(root.clone())),
        ArtifactPlan::Unresolved { .. } => None,
    }
}

/// Extract the bare name after the `surface.` prefix — e.g.
/// `deploy.netboot_tftp` → `netboot_tftp`. Used to look up the matching
/// backend executable.
fn capability_name(cap: Capability) -> &'static str {
    let full = cap.as_str();
    full.split_once('.').map(|(_, name)| name).unwrap_or(full)
}

/// `.../labs/<lab>/rigs/<rig>/lock` → `<lab>`.
fn lab_of(lock_path: &Path) -> String {
    lock_path
        .ancestors()
        .nth(3)
        .and_then(|p| p.file_name())
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "default".to_string())
}

fn run_dir_for(plan: &Plan) -> PathBuf {
    // ~/.local/state/fluxor/labs/<lab>/rigs/<rig>/runs/<run_id>
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join(".local")
        .join("state")
        .join("fluxor")
        .join("labs")
        .join(&plan.lab)
        .join("rigs")
        .join(&plan.rig)
        .join("runs")
        .join(&plan.run_record.run_id)
}

fn shell_render(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if a.contains(|c: char| c.is_whitespace() || c == '"' || c == '\'') {
                format!("{a:?}")
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests;
