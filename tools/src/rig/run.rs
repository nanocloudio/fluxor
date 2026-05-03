//! Orchestrator — the single canonical run lifecycle per RFC §10.1.
//!
//!   1. claim the rig
//!   2. resolve scenario + board contract              [done upstream, via Plan]
//!   3. build or resolve artifacts
//!   4. attach observers
//!   5. deploy artifacts
//!   6. apply power/reboot action
//!   7. wait for pass/fail or timeout
//!   8. collect logs and metadata
//!   9. release the rig                                [LockGuard::drop]
//!
//! The orchestrator knows nothing about specific backends (kasa plugs,
//! journalctl, termios, ...). It resolves capability → backend executable
//! via `rig::backend` and speaks only the subprocess protocol.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};
use crate::rig::backend::{
    attach_transport, context_from_plan, invoke_actuator, resolve as resolve_backend,
    wire_artifact, wire_binding, BackendInvocation, BackendRef,
};
use crate::rig::events::{DeployEvent, RunEvent};
use crate::rig::lock::{acquire as acquire_lock, AcquireOutcome, LockGuard, LockOwner};
use crate::rig::matcher;
use crate::rig::plan::{ArtifactPlan, Plan};
use crate::rig::profile::{BindingTable, RigProfile};
use crate::rig::record::{hash_artifact_bundle, hash_artifact_file, RunRecord, Verdict};
use crate::rig::vocab::{Capability, Surface};

/// Final outcome of a non-plan `fluxor rig test` invocation.
pub struct RunOutcome {
    pub record: RunRecord,
    pub run_dir: PathBuf,
}

pub struct RunOptions {
    /// Skip the build step. Useful when the operator ran `make` themselves.
    pub skip_build: bool,
    /// Force-release any existing lock on the rig.
    pub force_lock: bool,
    /// Actuator subprocess soft timeout (protection against a backend
    /// hanging forever). Doesn't apply to transports.
    pub actuator_timeout: Duration,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            skip_build: false,
            force_lock: false,
            actuator_timeout: Duration::from_secs(60),
        }
    }
}

pub fn execute_plan(plan: &Plan, profile: &RigProfile, options: &RunOptions) -> Result<RunOutcome> {
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
    let _lock_guard: LockGuard = match acquire_lock(&lock_path, &owner, options.force_lock)? {
        AcquireOutcome::Acquired(g) => g,
        AcquireOutcome::Held(conflict) => {
            return Err(Error::Config(format!(
                "rig run: {} is already held by pid {} on {} running '{}' since epoch {} \
                 (stale={}). Pass --force to take it over.",
                conflict.path.display(),
                conflict.existing.pid,
                conflict.existing.hostname,
                conflict.existing.task,
                conflict.existing.started_at,
                conflict.stale
            )));
        }
    };

    // Resolve backends up front so missing-binary errors surface before we
    // touch the rig. Deploy is mandatory; consoles are the set of console
    // capabilities the plan decided we need to attach (one per scenario
    // rule source, or one default for log capture); power is mandatory iff
    // the scenario said so, optional otherwise.
    let deploy_backend = resolve_backend(Surface::Deploy, capability_name(plan.deploy.capability))?;
    let console_backends: Vec<(Capability, BackendRef)> = plan
        .consoles
        .iter()
        .map(|c| {
            resolve_backend(Surface::Console, capability_name(c.capability))
                .map(|b| (c.capability, b))
        })
        .collect::<Result<Vec<_>>>()?;
    let power_backend = profile
        .power
        .as_ref()
        .map(|power_binding| -> Result<BackendRef> {
            let backend_name = power_binding.require_string("backend", "power")?;
            resolve_backend(Surface::Power, backend_name)
        })
        .transpose()?;
    if plan.power_required && power_backend.is_none() {
        return Err(Error::Config(format!(
            "rig run: scenario '{}' requires a power backend but the rig profile has \
             no [power] binding. Either add one or drop the power.* entries from the \
             scenario's `requires` list.",
            plan.scenario_name,
        )));
    }

    // Run dir (used by the backend context AND by the console log writer).
    let run_dir = run_dir_for(plan);
    std::fs::create_dir_all(&run_dir).map_err(|e| {
        Error::Config(format!(
            "rig run: creating run dir {}: {e}",
            run_dir.display()
        ))
    })?;

    // Step 3 — build / resolve artifacts.
    let artifact_path_for_record = run_build(plan, options)?;

    // One log file per console source the plan attached. Names are
    // `console.<suffix>.log` (e.g. `console.serial.log`); keeping the
    // streams separate matches the matcher's per-source buffers and
    // avoids interleaved byte streams on multi-console runs.
    let mut console_logs: std::collections::BTreeMap<Capability, std::fs::File> =
        std::collections::BTreeMap::new();
    for sel in &plan.consoles {
        let cap_str = sel.capability.as_str();
        // `console.serial` -> `console.serial.log`
        let path = run_dir.join(format!("{cap_str}.log"));
        let f = std::fs::File::create(&path).map_err(|e| {
            Error::Config(format!(
                "rig run: opening console log {}: {e}",
                path.display()
            ))
        })?;
        console_logs.insert(sel.capability, f);
    }

    // Step 4 — attach transports.
    let (tx, rx) = mpsc::channel::<RunEvent>();

    let deploy_binding = deploy_binding_for(plan, profile)?;
    let deploy_invocation = BackendInvocation {
        binding: wire_binding(deploy_binding),
        context: context_from_plan(plan, &run_dir),
        artifact: None,
    };
    let _deploy_transport = attach_transport(
        deploy_backend.clone(),
        "watch",
        &deploy_invocation,
        tx.clone(),
    )?;

    // Attach every console transport named by a scenario rule (plus the
    // default log-capture console when the scenario names none). Each
    // transport's bytes are source-tagged so the matcher evaluates rules
    // only against bytes from the capability they declared.
    let mut _console_transports: Vec<_> = Vec::with_capacity(console_backends.len());
    for (cap, backend) in console_backends {
        let binding = console_binding_for(profile, cap)?;
        let invocation = BackendInvocation {
            binding: wire_binding(binding),
            context: context_from_plan(plan, &run_dir),
            artifact: None,
        };
        let handle = attach_transport(backend, "attach", &invocation, tx.clone())?;
        eprintln!("[rig] console attached: {}", handle.backend().slug());
        _console_transports.push(handle);
    }

    // Step 5 — deploy artifact (actuator).
    let stage_invocation = BackendInvocation {
        binding: wire_binding(deploy_binding),
        context: context_from_plan(plan, &run_dir),
        artifact: wire_artifact(&plan.artifact),
    };
    if !matches!(plan.artifact, ArtifactPlan::Unresolved { .. }) {
        let report = invoke_actuator(
            &deploy_backend,
            "stage",
            &stage_invocation,
            options.actuator_timeout,
        )?;
        if let Some(info) = report.info.as_deref() {
            eprintln!("[rig] deploy: {info}");
        }
    } else {
        return Err(Error::Config(
            "rig run: artifact is unresolved — add a [build.<target>] recipe to \
             ~/.config/fluxor/projects/<name>/rig.toml (or an in-tree \
             .fluxor-rig.toml)"
                .into(),
        ));
    }

    // Step 6 — power actions. The verbs come from the plan, which
    // maps them from `scenario.requires`: `power.cycle` → `["cycle"]`,
    // otherwise each named verb in list order; `["cycle"]` is the
    // default when a backend is configured but the scenario names no
    // power capability.
    if let Some(backend) = &power_backend {
        let power_binding = profile
            .power
            .as_ref()
            .expect("power backend implies profile.power");
        let invocation = BackendInvocation {
            binding: wire_binding(power_binding),
            context: context_from_plan(plan, &run_dir),
            artifact: None,
        };
        for verb in &plan.power_actions {
            eprintln!("[rig] power.{verb} via {}", backend.slug());
            invoke_actuator(backend, verb, &invocation, options.actuator_timeout)?;
        }
    } else {
        eprintln!(
            "[rig] no power backend configured — scenario does not require one, \
             assuming DUT is already running"
        );
    }

    // Step 7 — wait for pass/fail/timeout.
    let mut m = matcher::Matcher::new(&plan.pass_rules, &plan.fail_rules)?;
    let deadline = Instant::now() + Duration::from_secs(plan.effective_timeout_s as u64);
    let started_at = now_unix_secs();

    // The matcher reports which rule *actually* fired; we save its source
    // alongside the verdict so the run record can cite the specific rule
    // rather than whichever rule happened to be listed first.
    let (verdict, primary_observation_source): (Verdict, Option<String>) = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break verdict_and_source(m.finalize());
        }
        match rx.recv_timeout(remaining) {
            Ok(event) => {
                match &event {
                    RunEvent::ConsoleBytes { source, bytes } => {
                        if let Some(f) = console_logs.get_mut(source) {
                            let _ = f.write_all(bytes);
                        }
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
                    }
                    RunEvent::DeployProgress(DeployEvent::Error(msg)) => {
                        eprintln!("[rig] deploy error: {msg}");
                    }
                    RunEvent::DeployProgress(DeployEvent::DhcpActivity) => {}
                    RunEvent::TransportClosed { source, reason } => {
                        eprintln!("[rig] transport closed: {source}: {reason}");
                    }
                }
                let outcome = m.observe(&event);
                if let Some(res) = verdict_and_source_if_final(&outcome) {
                    break res;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                break verdict_and_source(m.finalize());
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break verdict_and_source(m.finalize());
            }
        }
    };

    for f in console_logs.values_mut() {
        let _ = f.flush();
    }

    // Step 8 — write the run record.
    let artifact_digest = match artifact_path_for_record {
        Some(ArtifactOutput::File(path)) => Some(hash_artifact_file(&path)?),
        Some(ArtifactOutput::Bundle(root)) => Some(hash_artifact_bundle(&root)?),
        None => plan.run_record.artifact_sha256.clone(),
    };

    let mut record = plan.run_record.clone();
    record.started_at = started_at;
    record.finished_at = Some(now_unix_secs());
    record.verdict = verdict.clone();
    record.primary_observation_source = primary_observation_source;
    record.artifact_sha256 = artifact_digest;

    let manifest_path = run_dir.join("manifest.json");
    std::fs::write(&manifest_path, record.to_json()).map_err(|e| {
        Error::Config(format!(
            "rig run: writing manifest {}: {e}",
            manifest_path.display()
        ))
    })?;

    eprintln!("[rig] verdict: {:?}  run={}", verdict, run_dir.display(),);

    // Step 9 — implicit: LockGuard drops on return.
    Ok(RunOutcome { record, run_dir })
}

// ── helpers ────────────────────────────────────────────────────────────────

enum ArtifactOutput {
    File(PathBuf),
    Bundle(PathBuf),
}

fn run_build(plan: &Plan, options: &RunOptions) -> Result<Option<ArtifactOutput>> {
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
    // §15.3: project build commands run with the project root as CWD so
    // relative paths in the recipe resolve against the same anchor as the
    // artifact output.
    cmd.current_dir(project_root);
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

fn plan_artifact_to_output(plan: &Plan) -> Option<ArtifactOutput> {
    match &plan.artifact {
        ArtifactPlan::File { path, .. } => Some(ArtifactOutput::File(path.clone())),
        ArtifactPlan::Bundle { root, .. } => Some(ArtifactOutput::Bundle(root.clone())),
        ArtifactPlan::Unresolved { .. } => None,
    }
}

fn deploy_binding_for<'a>(plan: &'a Plan, profile: &'a RigProfile) -> Result<&'a BindingTable> {
    profile.deploy.get(&plan.deploy.capability).ok_or_else(|| {
        Error::Config(format!(
            "rig run: plan chose {} but profile has no matching [deploy.*] binding",
            plan.deploy.capability.as_str()
        ))
    })
}

fn console_binding_for(profile: &RigProfile, cap: Capability) -> Result<&BindingTable> {
    profile.console.get(&cap).ok_or_else(|| {
        Error::Config(format!(
            "rig run: plan chose {} but profile has no [console.*] binding",
            cap.as_str()
        ))
    })
}

/// Extract the bare name after the `surface.` prefix — e.g.
/// `deploy.netboot_tftp` → `netboot_tftp`. Used to look up the matching
/// backend executable.
fn capability_name(cap: Capability) -> &'static str {
    let full = cap.as_str();
    full.split_once('.').map(|(_, name)| name).unwrap_or(full)
}

/// Convert a terminal outcome into a (verdict, primary_source) pair. The
/// source is the capability of the rule the matcher actually fired —
/// not the first rule in the scenario list. InProgress is treated as
/// TimedOut (finalize-equivalent).
fn verdict_and_source(outcome: matcher::MatcherOutcome) -> (Verdict, Option<String>) {
    match outcome {
        matcher::MatcherOutcome::Passed { primary_source } => {
            (Verdict::Passed, Some(primary_source.as_str().to_string()))
        }
        matcher::MatcherOutcome::Failed { primary_source, .. } => {
            (Verdict::Failed, Some(primary_source.as_str().to_string()))
        }
        matcher::MatcherOutcome::TimedOut => (Verdict::TimedOut, None),
        matcher::MatcherOutcome::InProgress => (Verdict::TimedOut, None),
    }
}

/// Same as [`verdict_and_source`] but returns `None` while the run is
/// still in progress — lets the caller keep reading events.
fn verdict_and_source_if_final(
    outcome: &matcher::MatcherOutcome,
) -> Option<(Verdict, Option<String>)> {
    match outcome {
        matcher::MatcherOutcome::Passed { primary_source } => {
            Some((Verdict::Passed, Some(primary_source.as_str().to_string())))
        }
        matcher::MatcherOutcome::Failed { primary_source, .. } => {
            Some((Verdict::Failed, Some(primary_source.as_str().to_string())))
        }
        matcher::MatcherOutcome::TimedOut => Some((Verdict::TimedOut, None)),
        matcher::MatcherOutcome::InProgress => None,
    }
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

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
