//! `fluxor rig …` subcommand entry points.
//!
//!   * `rig test` — full scenario run (build → stage → power → observe →
//!     verdict → teardown → run record). `--plan` prints the resolved
//!     lifecycle with no side effects; `--hold <min>` keeps a failed run's
//!     rig as it is for a while before the teardown.
//!   * `rig power {on|off|cycle|diagnose|sweep}` — ad-hoc power action.
//!     `on`/`off`/`cycle` are gated by the board's declared `[rig].power`
//!     list; `diagnose` and `sweep` are verbs every backend may offer. All
//!     take the same rig lock the `test` path uses. `--plan` previews the
//!     invocation. `off` on a rig whose backends left state behind becomes
//!     the full teardown.
//!   * `rig teardown` — tear a rig down outside a run: whatever an
//!     interrupted run left, or everything in a lab with `--all`.
//!   * `rig monitor` — the live fault/histogram stream of a running device.

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};

use std::time::Duration;

use crate::error::{Error, Result};
use crate::rig::backend::{
    invoke_with, wire_binding, ActuatorOutcome, BackendContext, BackendInvocation, PHASE_ADHOC,
    PHASE_TEARDOWN,
};
use crate::rig::lock::{
    acquire as acquire_lock, default_lock_path, marker_path_for, now_unix_secs, rig_state_root,
    state_dir_for, AcquireOutcome, LockGuard, LockOwner, TeardownMarker,
};
use crate::rig::plan::DEFAULT_ACTUATOR_TIMEOUT_S;
use crate::rig::record::Verdict;
use crate::rig::run::{
    adhoc_power_under_guard, adhoc_run, execute_plan, install_signal_handlers, invoke_options,
    resolve_bound, teardown_rig, RunOptions,
};
use crate::rig::vocab::Surface;
use crate::rig::{
    build_plan, check_profile_against_board, default_profile_path, enumerate_rigs, load_profile,
    load_scenario, resolve_board_rig, validate_scenario_against_board, validate_tags, BoardRig,
    PlanInputs, ProjectDescriptor, RigProfile,
};

#[derive(Args, Debug)]
pub struct RigArgs {
    #[command(subcommand)]
    pub command: RigCommand,
}

#[derive(Subcommand, Debug)]
pub enum RigCommand {
    /// Run a scenario against a rig.
    Test(TestArgs),
    /// Apply a power action to the rig.
    Power(PowerArgs),
    /// Tear a rig down: power off, unstage, clear its teardown marker.
    Teardown(TeardownArgs),
    /// Stream live fault stats, protection levels, and step timing
    /// histograms from a running Fluxor device (newline-framed
    /// `MON_FAULT` / `MON_HIST` / `MON_STATE` lines; see
    /// `docs/architecture/monitor-protocol.md`).
    ///
    /// The rig profile is OPTIONAL here: with `--rig` (or a single-rig
    /// lab) the serial port and baud default from the profile's
    /// `[console.serial]`; without one, `--port`/`--net` and the
    /// defaults apply.
    Monitor(MonitorArgs),
}

#[derive(Args, Debug)]
pub struct TestArgs {
    /// Path to a scenario TOML (see tests/hardware/).
    #[arg(short, long)]
    pub scenario: PathBuf,
    /// Rig id. Optional when exactly one rig exists in the active lab.
    #[arg(long)]
    pub rig: Option<String>,
    /// Lab namespace. Falls back to $FLUXOR_LAB, then "default".
    #[arg(long)]
    pub lab: Option<String>,
    /// Print the resolved lifecycle without any side effects.
    #[arg(long)]
    pub plan: bool,
    /// Skip the build step (use the artifacts already on disk).
    #[arg(long)]
    pub skip_build: bool,
    /// Take over the rig lock even when its owner is alive. The displaced
    /// owner is named on stderr.
    #[arg(long)]
    pub force: bool,
    /// On a verdict other than pass, keep the rig as the run left it for
    /// this many minutes (Enter or Ctrl-C ends it sooner), then tear down.
    /// A run ended by a signal is not held.
    #[arg(long, value_name = "MIN")]
    pub hold: Option<u64>,
    /// Run the power backend's `diagnose` even when the run was aborted
    /// by a signal (it runs on a failed or timed-out verdict regardless).
    #[arg(long)]
    pub diagnose: bool,
}

#[derive(Args, Debug)]
pub struct PowerArgs {
    /// Power verb. One of: `on`, `off`, `cycle`, `diagnose`, `sweep`.
    pub action: String,
    /// Rig id. Optional when exactly one rig exists in the active lab.
    #[arg(long)]
    pub rig: Option<String>,
    /// Lab namespace. Falls back to $FLUXOR_LAB, then "default".
    #[arg(long)]
    pub lab: Option<String>,
    /// Print the resolved invocation without invoking the backend.
    #[arg(long)]
    pub plan: bool,
    /// Take over the rig lock even when its owner is alive.
    #[arg(long)]
    pub force: bool,
    /// For `on`/`cycle` on a board whose images leave the host: how many
    /// minutes to keep the machine before tearing it down. Required there.
    #[arg(long, value_name = "MIN")]
    pub hold: Option<u64>,
}

#[derive(Args, Debug)]
pub struct TeardownArgs {
    /// Rig id. Optional when exactly one rig exists in the active lab, or
    /// with `--all`.
    #[arg(long)]
    pub rig: Option<String>,
    /// Lab namespace. Falls back to $FLUXOR_LAB, then "default".
    #[arg(long)]
    pub lab: Option<String>,
    /// Every rig profile in the lab, then each power backend's `sweep`.
    #[arg(long)]
    pub all: bool,
    /// Take over the rig lock even when its owner is alive.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct MonitorArgs {
    /// Rig id — optional. When given (or when the lab has exactly one
    /// rig), port/baud default from the profile's [console.serial].
    #[arg(long)]
    pub rig: Option<String>,
    /// Lab namespace. Falls back to $FLUXOR_LAB, then "default".
    #[arg(long)]
    pub lab: Option<String>,
    /// Serial device path (default: the rig profile's console.serial
    /// device, else /dev/ttyACM0).
    #[arg(short = 'p', long)]
    pub port: Option<String>,
    /// Baud rate (default: the rig profile's console.serial baud,
    /// else 115200).
    #[arg(short = 'b', long)]
    pub baud: Option<u32>,
    /// Refresh period in milliseconds.
    #[arg(long, default_value = "500")]
    pub refresh_ms: u64,
    /// Consume MON_* lines from UDP netconsole instead of a serial
    /// port. Pass a bind spec like `:6666` or `0.0.0.0:6666`. When
    /// set, --port is ignored.
    #[arg(long)]
    pub net: Option<String>,
}

pub fn dispatch(args: RigArgs) -> Result<()> {
    match args.command {
        RigCommand::Test(a) => cmd_test(a),
        RigCommand::Power(a) => cmd_power(a),
        RigCommand::Teardown(a) => cmd_teardown(a),
        RigCommand::Monitor(a) => cmd_monitor(a),
    }
}

/// `rig monitor` — the live-telemetry stream. Profile optional: an
/// explicit `--rig` must resolve (hard error otherwise); with no
/// `--rig`, a single-rig lab's profile is consulted best-effort and
/// the classic defaults apply when nothing resolves.
fn cmd_monitor(args: MonitorArgs) -> Result<()> {
    if let Some(net) = args.net.as_deref() {
        return crate::monitor::cmd_monitor_dispatch(
            "",
            args.baud.unwrap_or(115_200),
            args.refresh_ms,
            Some(net),
        );
    }
    let mut port = args.port.clone();
    let mut baud = args.baud;
    if port.is_none() || baud.is_none() {
        match profile_console_serial(args.rig.as_deref(), args.lab.as_deref()) {
            Ok(Some((dev, profile_baud))) => {
                if port.is_none() {
                    port = Some(dev);
                }
                if baud.is_none() {
                    baud = profile_baud;
                }
            }
            Ok(None) => {}
            // Only an explicit --rig propagates resolution errors.
            Err(e) if args.rig.is_some() => return Err(e),
            Err(_) => {}
        }
    }
    crate::monitor::cmd_monitor_dispatch(
        port.as_deref().unwrap_or("/dev/ttyACM0"),
        baud.unwrap_or(115_200),
        args.refresh_ms,
        None,
    )
}

/// Resolve `[console.serial]` (device, baud) from a rig profile.
/// `Ok(None)` when no rig can be determined (no --rig and not exactly
/// one rig in the lab) or the profile has no console.serial binding.
fn profile_console_serial(
    rig: Option<&str>,
    lab: Option<&str>,
) -> Result<Option<(String, Option<u32>)>> {
    let lab = resolve_lab(lab);
    let rig_id = match rig {
        Some(r) => r.to_string(),
        None => {
            let rigs = enumerate_rigs(&lab).unwrap_or_default();
            if rigs.len() == 1 {
                rigs.into_iter().next().unwrap()
            } else {
                return Ok(None);
            }
        }
    };
    let Some(profile_path) = default_profile_path(&lab, &rig_id) else {
        return Err(Error::Config("rig monitor: cannot resolve $HOME".into()));
    };
    if !profile_path.is_file() {
        return Err(Error::Config(format!(
            "rig monitor: profile not found at {}",
            profile_path.display()
        )));
    }
    let profile = load_profile(&profile_path)?;
    let serial = crate::rig::vocab::Capability::parse("console.serial")
        .ok()
        .and_then(|cap| profile.console.get(&cap).cloned());
    let Some(binding) = serial else {
        return Ok(None);
    };
    let Some(device) = binding.optional_string("device").map(str::to_string) else {
        return Ok(None);
    };
    let baud = binding
        .optional_int("baud")
        .and_then(|n| u32::try_from(n).ok());
    Ok(Some((device, baud)))
}

/// `--rig`, or the single rig in the lab.
fn resolve_rig_id(verb: &str, rig: Option<String>, lab: &str) -> Result<String> {
    match rig {
        Some(r) => Ok(r),
        None => {
            let rigs = enumerate_rigs(lab)?;
            match rigs.len() {
                1 => Ok(rigs.into_iter().next().unwrap()),
                0 => Err(Error::Config(format!(
                    "rig {verb}: no rig profiles found in ~/.config/fluxor/labs/{lab}/rigs/ — \
                     create one or pass --rig <id>"
                ))),
                _ => Err(Error::Config(format!(
                    "rig {verb}: multiple rigs in lab '{lab}': {rigs:?} — pass --rig <id>"
                ))),
            }
        }
    }
}

fn load_rig_profile(verb: &str, lab: &str, rig_id: &str) -> Result<RigProfile> {
    let profile_path = default_profile_path(lab, rig_id).ok_or_else(|| {
        Error::Config(format!(
            "rig {verb}: cannot resolve $HOME for profile lookup"
        ))
    })?;
    if !profile_path.is_file() {
        return Err(Error::Config(format!(
            "rig {verb}: profile not found at {} — a rig profile binds this \
             lab's capabilities to one physical bench and is never checked in",
            profile_path.display()
        )));
    }
    load_profile(&profile_path)
}

/// Board descriptor by layered lookup (user override → project-local
/// `targets/boards/` found upward from `anchor` → embedded defaults).
fn load_board(verb: &str, board_id: &str, anchor: Option<&Path>) -> Result<(BoardRig, String)> {
    let project_root_for_boards = anchor.and_then(|a| locate_workspace(a).ok());
    let (rig, source) = resolve_board_rig(board_id, project_root_for_boards.as_deref())?;
    let rig = rig.ok_or_else(|| {
        Error::Config(format!(
            "rig {verb}: board '{board_id}' has no [rig] section ({}); add one or pick \
             a target that does",
            source.display(),
        ))
    })?;
    Ok((rig, source.display()))
}

fn fail_on_errors(verb: &str, what: &str, v: &crate::rig::RigValidation) -> Result<()> {
    for w in &v.warnings {
        eprintln!("warning: {w}");
    }
    if !v.is_ok() {
        for e in &v.errors {
            eprintln!("error: {e}");
        }
        return Err(Error::Config(format!("rig {verb}: {what}")));
    }
    Ok(())
}

fn cmd_test(args: TestArgs) -> Result<()> {
    let lab = resolve_lab(args.lab.as_deref());

    let scenario_path = args.scenario.canonicalize().map_err(|e| {
        Error::Config(format!(
            "rig test: resolving scenario path {}: {e}",
            args.scenario.display()
        ))
    })?;
    let scenario = load_scenario(&scenario_path)?;

    let (board, board_source) = load_board("test", &scenario.target, Some(&scenario_path))?;
    eprintln!("[rig] board descriptor: {board_source}");

    // 1. Validate scenario against board (fail fast at plan time).
    fail_on_errors(
        "test",
        "scenario is not compatible with board contract",
        &validate_scenario_against_board(&scenario, &board),
    )?;

    // 2. Resolve the rig and its profile.
    let rig_id = resolve_rig_id("test", args.rig, &lab)?;
    let profile = load_rig_profile("test", &lab, &rig_id)?;

    // Sanity: profile says board X but scenario targets Y.
    if profile.rig.board != scenario.target {
        return Err(Error::Config(format!(
            "rig test: profile '{}' is for board '{}', but scenario '{}' targets '{}'",
            profile.rig.id, profile.rig.board, scenario.name, scenario.target
        )));
    }
    fail_on_errors(
        "test",
        "profile tags do not satisfy scenario.requires_tags",
        &validate_tags(&scenario, &profile.rig.tags),
    )?;
    fail_on_errors(
        "test",
        "profile does not satisfy the board's build-env rules",
        &check_profile_against_board(&profile, &board),
    )?;

    // 3. Discover the project descriptor, if any: upward from the
    //    scenario's directory, then upward from CWD.
    let project = discover_project_descriptor(&scenario_path)?;

    // 4. Build the plan.
    let plan = build_plan(PlanInputs {
        lab: &lab,
        scenario: &scenario,
        board: &board,
        profile: &profile,
        project: project.as_ref(),
        scenario_path: Some(&scenario_path),
    })?;

    if args.plan {
        println!("{plan}");
        return Ok(());
    }

    // Execute the plan.
    install_signal_handlers();
    let options = RunOptions {
        skip_build: args.skip_build,
        force_lock: args.force,
        hold: args.hold.map(|m| Duration::from_secs(m * 60)),
        diagnose_on_abort: args.diagnose,
        ..RunOptions::default()
    };
    let outcome = execute_plan(&plan, &profile, &options)?;
    match outcome.record.verdict {
        Verdict::Passed => Ok(()),
        Verdict::Failed | Verdict::TimedOut | Verdict::Aborted | Verdict::Planned => {
            Err(Error::Config(format!(
                "rig test: {}{} — see {}",
                match outcome.record.verdict {
                    Verdict::Failed => "FAIL",
                    Verdict::TimedOut => "TIMEOUT",
                    Verdict::Aborted => "ABORTED",
                    _ => "INCOMPLETE",
                },
                outcome
                    .record
                    .reason
                    .as_deref()
                    .map(|r| format!(" ({r})"))
                    .unwrap_or_default(),
                outcome.run_dir.display()
            )))
        }
    }
}

/// Verbs the board contract does not gate: any backend may offer them.
const UNGATED_POWER_VERBS: &[&str] = &["diagnose", "sweep"];

fn cmd_power(args: PowerArgs) -> Result<()> {
    let action = args.action.to_lowercase();
    if !matches!(action.as_str(), "on" | "off" | "cycle")
        && !UNGATED_POWER_VERBS.contains(&action.as_str())
    {
        return Err(Error::Config(format!(
            "rig power: unknown verb '{}' (expected one of: on, off, cycle, diagnose, sweep)",
            args.action
        )));
    }

    let lab = resolve_lab(args.lab.as_deref());
    let rig_id = resolve_rig_id("power", args.rig, &lab)?;
    let profile = load_rig_profile("power", &lab, &rig_id)?;

    let power_binding = profile.power.as_ref().ok_or_else(|| {
        Error::Config(format!(
            "rig power: profile '{}' has no [power] section",
            profile.rig.id
        ))
    })?;
    let backend_name = power_binding.require_string("backend", "power")?;
    let backend = resolve_bound(Surface::Power, backend_name, power_binding, &profile)?;

    // The public board contract enumerates which power verbs a target
    // supports (e.g. picow declares cycle, off, on). `rig power` must
    // honour that contract for the switching verbs — invoking `on` on a
    // board that only declares `cycle` would silently bypass the public
    // surface. No scenario to anchor on, so walk upward from CWD for the
    // optional project layer.
    let cwd = std::env::current_dir().ok();
    let (board, board_source) = load_board("power", &profile.rig.board, cwd.as_deref())?;
    if !UNGATED_POWER_VERBS.contains(&action.as_str()) {
        validate_power_verb_on_board(&board, &action, &profile.rig.board)?;
    }
    fail_on_errors(
        "power",
        "profile does not satisfy the board's build-env rules",
        &check_profile_against_board(&profile, &board),
    )?;

    let lock_path = default_lock_path(&lab, &profile.rig.id)
        .ok_or_else(|| Error::Config("rig power: cannot resolve lock path".into()))?;
    let residue_present = rig_has_residue(&lock_path);
    let timeout = power_binding
        .actuator_timeout()
        .unwrap_or(Duration::from_secs(DEFAULT_ACTUATOR_TIMEOUT_S));
    let options = RunOptions {
        force_lock: args.force,
        ..RunOptions::default()
    };

    if args.plan {
        println!("rig power {action}");
        println!("  lab        {lab}");
        println!("  rig        {}", profile.rig.id);
        println!("  board      {} ({board_source})", profile.rig.board);
        println!(
            "  backend    {} ({})",
            backend.slug(),
            backend.executable.display()
        );
        println!("  timeout    {}s", timeout.as_secs());
        if residue_present && action == "off" {
            println!(
                "  note       backends left state on this rig; `off` becomes the full teardown"
            );
        }
        if board.image_leaves_host && matches!(action.as_str(), "on" | "cycle") {
            println!(
                "  note       board images leave the host; `{action}` runs under a guard and \
                 tears down after --hold"
            );
        }
        print!("  binding   ");
        for (k, v) in power_binding.iter() {
            print!(" {k}=");
            match v {
                crate::rig::profile::BindingValue::Secret(s) => print!("{s}"),
                crate::rig::profile::BindingValue::Int(n) => print!("{n}"),
                crate::rig::profile::BindingValue::Float(f) => print!("{f}"),
                crate::rig::profile::BindingValue::Bool(b) => print!("{b}"),
            }
        }
        println!();
        return Ok(());
    }

    install_signal_handlers();

    // `off` on a rig whose backends left state behind is a teardown, not a
    // bare verb: it also unstages and clears the marker.
    if action == "off" && residue_present {
        eprintln!("[rig] {rig_id} holds backend state; running the full teardown");
        return cmd_teardown(TeardownArgs {
            rig: Some(rig_id),
            lab: Some(lab),
            all: false,
            force: args.force,
        });
    }

    // Lock the rig so an ad-hoc power action can't race an in-progress run.
    let owner = LockOwner::now(&profile.rig.id, &format!("command:power {action}"), 60);
    let guard = match acquire_lock(&lock_path, &owner, args.force)? {
        AcquireOutcome::Acquired(g) => g,
        AcquireOutcome::Held(c) => return Err(held(&c, "power")),
        AcquireOutcome::NeedsTeardown { guard, marker } => {
            if matches!(action.as_str(), "on" | "cycle") {
                drop(guard);
                return Err(Error::Config(format!(
                    "rig power: run {} on this rig never finished its teardown ({}); \
                     `fluxor rig teardown --rig {}` first",
                    marker.run_id,
                    marker.last_error.as_deref().unwrap_or("interrupted"),
                    profile.rig.id
                )));
            }
            guard
        }
    };

    if board.image_leaves_host && matches!(action.as_str(), "on" | "cycle") {
        let Some(minutes) = args.hold else {
            return Err(Error::Config(format!(
                "rig power: board '{}' builds images that leave the host, so `{action}` \
                 would leave a machine running somewhere. Say how long with --hold <min>; \
                 the rig is torn down when it ends.",
                profile.rig.board
            )));
        };
        let record = adhoc_power_under_guard(
            &profile,
            &lock_path,
            &guard,
            &action,
            Duration::from_secs(minutes * 60),
            &options,
        )?;
        drop(guard);
        return if record.clean {
            Ok(())
        } else {
            Err(Error::Config(format!(
                "rig power: teardown after `{action}` did not complete; \
                 `fluxor rig teardown --rig {}` once the cause is fixed",
                profile.rig.id
            )))
        };
    }

    // A bare verb: no scenario, no build, no transports. It still gets its
    // own run directory, for its stderr and whatever the backend keeps.
    guard.set_expected_end(now_unix_secs() + timeout.as_secs() + 30)?;
    let (run_id, run_dir) = adhoc_run(&lock_path, &rig_id, &format!("power-{action}"))?;
    let invocation = BackendInvocation {
        binding: wire_binding(power_binding),
        context: BackendContext {
            rig_id: profile.rig.id.clone(),
            lab: lab.clone(),
            run_id,
            run_dir: run_dir.display().to_string(),
            scenario_name: format!("power:{action}"),
            board: profile.rig.board.clone(),
            effective_timeout_ms: timeout.as_millis() as u64,
            phase: PHASE_ADHOC.to_string(),
            state_dir: state_dir_for(&lock_path).display().to_string(),
        },
        artifact: None,
        args: None,
        relay: None,
    };
    let invoke_options = invoke_options(
        &backend,
        power_binding,
        options.actuator_timeout,
        &run_dir,
        &action,
        PHASE_ADHOC,
    );
    let outcome = invoke_with(&backend, &action, &invocation, &invoke_options)?;
    drop(guard);
    match outcome {
        ActuatorOutcome::Ok(report) => {
            if let Some(info) = report.info.as_deref() {
                eprintln!("[rig] {info}");
            }
            Ok(())
        }
        ActuatorOutcome::Unsupported => Err(Error::Config(format!(
            "rig power: {} does not implement `{action}`",
            backend.slug()
        ))),
        ActuatorOutcome::Failed {
            reason,
            stderr_tail,
            ..
        } => Err(Error::Config(format!(
            "rig power: {reason}{}",
            if stderr_tail.is_empty() {
                String::new()
            } else {
                format!(" — stderr: {stderr_tail}")
            }
        ))),
    }
}

fn held(c: &crate::rig::LockConflict, verb: &str) -> Error {
    Error::Config(format!(
        "rig {verb}: {} is held by pid {} on {} running '{}' (stale={}). \
         Pass --force to take it over.",
        c.path.display(),
        c.existing.pid,
        c.existing.hostname,
        c.existing.task,
        c.stale
    ))
}

fn cmd_teardown(args: TeardownArgs) -> Result<()> {
    let lab = resolve_lab(args.lab.as_deref());
    install_signal_handlers();
    if !args.all {
        let rig_id = resolve_rig_id("teardown", args.rig, &lab)?;
        let profile = load_rig_profile("teardown", &lab, &rig_id)?;
        return teardown_one(&lab, &profile, args.force);
    }

    // Every rig in the lab first, then `sweep` once per distinct power
    // binding — two rigs on one plug, or one cloud account, share a sweep —
    // whatever the rigs' own teardowns came to: the sweep is what finds
    // what they could not stop.
    let mut failed: Vec<String> = Vec::new();
    let mut profiles: Vec<RigProfile> = Vec::new();
    let known = enumerate_rigs(&lab)?;
    for rig_id in &known {
        let profile = match load_rig_profile("teardown", &lab, rig_id) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[rig] teardown {rig_id}: {e}");
                failed.push(rig_id.clone());
                continue;
            }
        };
        if let Err(e) = teardown_one(&lab, &profile, args.force) {
            eprintln!("[rig] teardown {rig_id}: {e}");
            failed.push(rig_id.clone());
        }
        profiles.push(profile);
    }
    let mut swept: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for profile in &profiles {
        let Some(binding) = profile.power.as_ref() else {
            continue;
        };
        if swept.insert(binding_key(binding)) {
            if let Err(e) = sweep(&lab, profile) {
                eprintln!("[rig] sweep for {}: {e}", profile.rig.id);
                failed.push(format!("{} (sweep)", profile.rig.id));
            }
        }
    }

    // A marker whose profile is gone cannot be torn down by name; say so
    // rather than forget it.
    if let Some(root) = rig_state_root(&lab, "") {
        let rigs_dir = root.parent().map(Path::to_path_buf).unwrap_or(root);
        if let Ok(entries) = std::fs::read_dir(&rigs_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let marker = marker_path_for(&entry.path().join("lock"));
                if marker.exists() && !known.contains(&name) {
                    eprintln!(
                        "[rig] {name}: teardown marker at {} but no profile in lab '{lab}' — \
                         restore the profile or clean it up by hand",
                        marker.display()
                    );
                    failed.push(format!("{name} (no profile)"));
                }
            }
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(Error::Config(format!(
            "rig teardown: not clean for {}",
            failed.join(", ")
        )))
    }
}

/// Tear one rig down under its lock.
fn teardown_one(lab: &str, profile: &RigProfile, force: bool) -> Result<()> {
    let rig_id = &profile.rig.id;
    let lock_path = default_lock_path(lab, rig_id)
        .ok_or_else(|| Error::Config("rig teardown: cannot resolve lock path".into()))?;
    let owner = LockOwner::now(rig_id, "command:teardown", 60);
    let (guard, marker): (LockGuard, Option<TeardownMarker>) =
        match acquire_lock(&lock_path, &owner, force)? {
            AcquireOutcome::Acquired(g) => (g, None),
            AcquireOutcome::NeedsTeardown { guard, marker } => (guard, Some(marker)),
            AcquireOutcome::Held(c) => return Err(held(&c, "teardown")),
        };
    let record = teardown_rig(
        profile,
        &lock_path,
        &guard,
        marker.as_ref(),
        &RunOptions::default(),
    )?;
    drop(guard);
    if record.clean {
        Ok(())
    } else {
        Err(Error::Config(format!(
            "rig teardown: {rig_id} is not clean; see its marker at {}",
            marker_path_for(&lock_path).display()
        )))
    }
}

/// Whether anything of an earlier run may still be on the rig: its
/// teardown marker, or state a backend left in the rig's state directory
/// (an image a deploy registered, a machine a power step started), which
/// the matching `unstage` / `off` removes.
fn rig_has_residue(lock_path: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(state_dir_for(lock_path)) else {
        return false;
    };
    entries.flatten().any(|e| {
        let name = e.file_name();
        !name.to_string_lossy().ends_with(".tmp")
    })
}

/// The power backend's `sweep`: everything of the lab's still running
/// anywhere this binding can see. Unsupported is fine.
fn sweep(lab: &str, profile: &RigProfile) -> Result<()> {
    let binding = profile.power.as_ref().expect("caller checked");
    let backend = resolve_bound(
        Surface::Power,
        binding.require_string("backend", "power")?,
        binding,
        profile,
    )?;
    let lock_path = default_lock_path(lab, &profile.rig.id)
        .ok_or_else(|| Error::Config("rig teardown: cannot resolve lock path".into()))?;
    let options = RunOptions::default();
    let (run_id, run_dir) = adhoc_run(&lock_path, &profile.rig.id, "sweep")?;
    let opts = invoke_options(
        &backend,
        binding,
        options.actuator_timeout,
        &run_dir,
        "sweep",
        PHASE_TEARDOWN,
    );
    let invocation = BackendInvocation {
        binding: wire_binding(binding),
        context: BackendContext {
            rig_id: profile.rig.id.clone(),
            lab: lab.to_string(),
            run_id,
            run_dir: run_dir.display().to_string(),
            scenario_name: "teardown:sweep".to_string(),
            board: profile.rig.board.clone(),
            effective_timeout_ms: opts.timeout.as_millis() as u64,
            phase: PHASE_TEARDOWN.to_string(),
            state_dir: state_dir_for(&lock_path).display().to_string(),
        },
        artifact: None,
        args: None,
        relay: None,
    };
    match invoke_with(&backend, "sweep", &invocation, &opts)? {
        ActuatorOutcome::Ok(report) => {
            if let Some(info) = report.info.as_deref() {
                eprintln!("[rig] sweep ({}): {info}", backend.slug());
            }
            let residue = report
                .detail
                .as_ref()
                .and_then(|d| d.get("residue"))
                .and_then(|r| r.as_object())
                .map(|r| {
                    r.iter()
                        .filter(|(_, v)| v.as_array().is_some_and(|a| !a.is_empty()))
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if residue.is_empty() {
                Ok(())
            } else {
                Err(Error::Config(format!(
                    "residue after sweep: {}",
                    residue.join(", ")
                )))
            }
        }
        ActuatorOutcome::Unsupported => Ok(()),
        ActuatorOutcome::Failed { reason, .. } => Err(Error::Config(reason)),
    }
}

/// Identity of a power binding for `--all`'s sweep dedupe: the backend
/// and every field, secrets by sentinel.
fn binding_key(binding: &crate::rig::BindingTable) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (k, v) in binding.iter() {
        let rendered = match v {
            crate::rig::profile::BindingValue::Secret(s) => s.for_hash().to_string(),
            crate::rig::profile::BindingValue::Int(n) => n.to_string(),
            crate::rig::profile::BindingValue::Float(f) => format!("{f:?}"),
            crate::rig::profile::BindingValue::Bool(b) => b.to_string(),
        };
        parts.push(format!("{k}={rendered}"));
    }
    parts.join("\n")
}

/// Confirm the board declares `power.<verb>` in its `[rig].power` list.
/// Called by `cmd_power` to refuse switching verbs the public board
/// contract does not advertise.
fn validate_power_verb_on_board(
    board: &crate::rig::BoardRig,
    verb: &str,
    board_id: &str,
) -> Result<()> {
    let qualified = format!("power.{verb}");
    let cap = crate::rig::vocab::Capability::parse(&qualified)
        .map_err(|e| Error::Config(format!("rig power: deriving capability: {e}")))?;
    if !board.supports(cap) {
        let declared: Vec<&str> = board.power.iter().map(|c| c.as_str()).collect();
        return Err(Error::Config(format!(
            "rig power: board '{board_id}' does not declare '{qualified}' in \
             [rig].power (declares: {declared:?}). Either extend the board \
             contract or pick a supported verb."
        )));
    }
    Ok(())
}

/// Resolve the active lab namespace:
/// `--lab` flag > `FLUXOR_LAB` env > `default`.
fn resolve_lab(flag: Option<&str>) -> String {
    if let Some(l) = flag {
        return l.to_string();
    }
    if let Ok(l) = std::env::var("FLUXOR_LAB") {
        if !l.is_empty() {
            return l;
        }
    }
    "default".to_string()
}

/// Walk upward from `anchor` looking for a directory with a
/// `targets/boards/` subdirectory. Returns `Ok` with that directory when
/// found, `Err` when the walk hits the filesystem root without a match.
/// Used only to discover *optional* project-local board overrides; the
/// harness's baseline board descriptors are embedded in fluxor-tools so
/// callers that don't have their own tree still work.
fn locate_workspace(anchor: &Path) -> Result<PathBuf> {
    let mut cursor = anchor
        .canonicalize()
        .unwrap_or_else(|_| anchor.to_path_buf());
    if cursor.is_file() {
        cursor.pop();
    }
    loop {
        if cursor.join("targets").join("boards").is_dir() {
            return Ok(cursor);
        }
        if !cursor.pop() {
            return Err(Error::Config(format!(
                "no project-local targets/boards/ found upward from {}",
                anchor.display()
            )));
        }
    }
}

fn discover_project_descriptor(scenario_path: &Path) -> Result<Option<ProjectDescriptor>> {
    // Try the scenario's directory first. Fall back to CWD so a scenario
    // checked into one repo can still reference a project build descriptor
    // above the scenario's file tree.
    let parent = scenario_path.parent().unwrap_or(Path::new("."));
    if let Some(p) = ProjectDescriptor::discover(parent)? {
        return Ok(Some(p));
    }
    if let Ok(cwd) = std::env::current_dir() {
        if let Some(p) = ProjectDescriptor::discover(&cwd)? {
            return Ok(Some(p));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::validate_power_verb_on_board;
    use crate::rig::parse_board_rig_str;

    const PI5_RIG: &str = r#"
        [rig]
        artifact = "kernel8_img"
        deploy = ["deploy.netboot_tftp"]
        console = ["console.serial"]
        observe = ["observe.netboot_fetch"]
        power = ["power.cycle"]
    "#;

    const FULL_POWER_RIG: &str = r#"
        [rig]
        artifact = "kernel8_img"
        deploy = ["deploy.netboot_tftp"]
        console = ["console.serial"]
        observe = ["observe.netboot_fetch"]
        power = ["power.cycle", "power.on", "power.off"]
    "#;

    fn load(src: &str) -> crate::rig::BoardRig {
        parse_board_rig_str(src, "t.toml").unwrap().unwrap()
    }

    #[test]
    fn rig_power_accepts_verb_declared_by_board() {
        let board = load(PI5_RIG);
        assert!(validate_power_verb_on_board(&board, "cycle", "pi5").is_ok());
    }

    #[test]
    fn rig_power_rejects_verb_not_in_board_rig_power_list() {
        let board = load(PI5_RIG);

        let err_on = validate_power_verb_on_board(&board, "on", "pi5").unwrap_err();
        let msg = format!("{err_on}");
        assert!(msg.contains("power.on"), "{msg}");
        assert!(msg.contains("power.cycle"), "{msg}");
        assert!(msg.contains("pi5"), "{msg}");

        let err_off = validate_power_verb_on_board(&board, "off", "pi5").unwrap_err();
        assert!(format!("{err_off}").contains("power.off"));
    }

    #[test]
    fn rig_power_allows_all_verbs_when_board_declares_all() {
        let board = load(FULL_POWER_RIG);
        for verb in ["cycle", "on", "off"] {
            assert!(
                validate_power_verb_on_board(&board, verb, "test").is_ok(),
                "board declared {verb} but validator rejected it",
            );
        }
    }

    /// Every embedded board with a rig contract declares `power.off`:
    /// every rig can be told to power down, and a backend that cannot says
    /// so with a no-op.
    #[test]
    fn every_embedded_board_declares_power_off() {
        let mut checked = 0;
        for (id, src) in crate::rig::board::EMBEDDED_BOARDS {
            let Some(rig) = parse_board_rig_str(src, id).unwrap() else {
                continue;
            };
            assert!(
                validate_power_verb_on_board(&rig, "off", id).is_ok(),
                "{id} must declare power.off"
            );
            checked += 1;
        }
        assert!(checked > 0, "no embedded board has a rig contract");
    }
}
