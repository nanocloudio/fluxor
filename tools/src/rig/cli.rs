//! `fluxor rig …` subcommand entry points.
//!
//! Verbs currently implemented end-to-end:
//!   * `rig test` — full scenario run (build → stage → power → observe →
//!     verdict → run record). `--plan` prints the resolved lifecycle
//!     with no side effects.
//!   * `rig power {on|off|cycle}` — ad-hoc power action; gated by the
//!     board's declared `[rig].power` list and by the same rig lock the
//!     `test` path uses. `--plan` previews the invocation.
//!
//! Not yet implemented (dispatcher returns a clear error pointing at
//! the closest working alternative):
//!   * `rig run` — scenario-less one-shot against an arbitrary config.
//!     Use `rig test --scenario <path>` instead for now.
//!   * `rig console` — interactive console attach. The OS-native
//!     `tio <device> -b <baud>` covers this today.

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};
use crate::rig::backend::{
    invoke_actuator, resolve as resolve_backend, wire_binding, BackendContext, BackendInvocation,
};
use crate::rig::lock::{acquire as acquire_lock, default_lock_path, AcquireOutcome, LockOwner};
use crate::rig::record::Verdict;
use crate::rig::run::{execute_plan, RunOptions};
use crate::rig::vocab::Surface;
use crate::rig::{
    build_plan, default_profile_path, enumerate_rigs, load_profile, load_scenario,
    resolve_board_rig, validate_scenario_against_board, validate_tags, PlanInputs,
    ProjectDescriptor,
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
    /// Run an ad-hoc config against a rig (no scenario, no pass/fail rules).
    Run(RunArgs),
    /// Apply a power action to the rig.
    Power(PowerArgs),
    /// Attach to the rig's primary console.
    Console(ConsoleArgs),
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
    /// Skip the build step (use previously built artifacts on disk).
    #[arg(long)]
    pub skip_build: bool,
    /// Force-release any existing rig lock before proceeding. Leaves a
    /// breadcrumb in the run log identifying the displaced owner.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    #[arg(short, long)]
    pub config: PathBuf,
    #[arg(long)]
    pub rig: Option<String>,
    #[arg(long)]
    pub lab: Option<String>,
    #[arg(long)]
    pub plan: bool,
}

#[derive(Args, Debug)]
pub struct PowerArgs {
    /// Power verb. One of: `on`, `off`, `cycle`.
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
    /// Force-release any existing rig lock before proceeding.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct ConsoleArgs {
    #[arg(long)]
    pub rig: Option<String>,
    #[arg(long)]
    pub lab: Option<String>,
}

pub fn dispatch(args: RigArgs) -> Result<()> {
    match args.command {
        RigCommand::Test(a) => cmd_test(a),
        RigCommand::Power(a) => cmd_power(a),
        RigCommand::Run(_) => Err(Error::Config(
            "rig run: not yet implemented — use `rig test --scenario <path>` \
             for scenario-driven runs"
                .into(),
        )),
        RigCommand::Console(_) => Err(Error::Config(
            "rig console: not yet implemented — `tio /dev/ttyUSB0 -b 115200` \
             or equivalent covers this for now"
                .into(),
        )),
    }
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

    // Board descriptor: RFC §15.1 layered lookup. User override wins
    // over a project-local `targets/boards/` (when one exists upward
    // from the scenario), which in turn wins over the defaults embedded
    // in fluxor-tools. This lets the harness run from a sibling project
    // that has no `targets/boards/` tree of its own.
    let project_root_for_boards = locate_workspace(&scenario_path).ok();
    let (board, board_source) = {
        let (rig, source) =
            resolve_board_rig(&scenario.target, project_root_for_boards.as_deref())?;
        let rig = rig.ok_or_else(|| {
            Error::Config(format!(
                "rig test: board '{}' has no [rig] section ({}); add one or pick \
                 a target that does",
                scenario.target,
                source.display(),
            ))
        })?;
        (rig, source)
    };
    eprintln!("[rig] board descriptor: {}", board_source.display());

    // 1. Validate scenario against board (fail fast at plan time per §7.1).
    let v = validate_scenario_against_board(&scenario, &board);
    for w in &v.warnings {
        eprintln!("warning: {w}");
    }
    if !v.is_ok() {
        for e in &v.errors {
            eprintln!("error: {e}");
        }
        return Err(Error::Config(
            "rig test: scenario is not compatible with board contract".into(),
        ));
    }

    // 2. Resolve the rig. If `--rig` isn't given and exactly one rig is
    //    configured in the lab, use that.
    let rig_id = match args.rig {
        Some(r) => r,
        None => {
            let rigs = enumerate_rigs(&lab)?;
            match rigs.len() {
                1 => rigs.into_iter().next().unwrap(),
                0 => {
                    return Err(Error::Config(format!(
                        "rig test: no rig profiles found in ~/.config/fluxor/labs/{lab}/rigs/ — \
                         create one or pass --rig <id>"
                    )))
                }
                _ => {
                    return Err(Error::Config(format!(
                        "rig test: multiple rigs in lab '{lab}': {rigs:?} — pass --rig <id>"
                    )))
                }
            }
        }
    };

    let profile_path = default_profile_path(&lab, &rig_id)
        .ok_or_else(|| Error::Config("rig test: cannot resolve $HOME for profile lookup".into()))?;
    if !profile_path.is_file() {
        return Err(Error::Config(format!(
            "rig test: profile not found at {} — create one per RFC §9 \
             (see .context/rfc_hardware_rig.md)",
            profile_path.display()
        )));
    }
    let profile = load_profile(&profile_path)?;

    // Sanity: profile says board X but scenario targets Y.
    if profile.rig.board != scenario.target {
        return Err(Error::Config(format!(
            "rig test: profile '{}' is for board '{}', but scenario '{}' targets '{}'",
            profile.rig.id, profile.rig.board, scenario.name, scenario.target
        )));
    }

    // Tag match.
    let tv = validate_tags(&scenario, &profile.rig.tags);
    if !tv.is_ok() {
        for e in &tv.errors {
            eprintln!("error: {e}");
        }
        return Err(Error::Config(
            "rig test: profile tags do not satisfy scenario.requires_tags".into(),
        ));
    }

    // 3. Discover project descriptor, if any. Walk up from the scenario's
    //    directory and also from CWD — whichever finds one first.
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
    let options = RunOptions {
        skip_build: args.skip_build,
        force_lock: args.force,
        ..RunOptions::default()
    };
    let outcome = execute_plan(&plan, &profile, &options)?;
    match outcome.record.verdict {
        Verdict::Passed => Ok(()),
        Verdict::Failed
        | Verdict::TimedOut
        | Verdict::Aborted
        | Verdict::Pending
        | Verdict::Planned => Err(Error::Config(format!(
            "rig test: {} — see {}",
            match outcome.record.verdict {
                Verdict::Failed => "FAIL",
                Verdict::TimedOut => "TIMEOUT",
                Verdict::Aborted => "ABORTED",
                _ => "INCOMPLETE",
            },
            outcome.run_dir.display()
        ))),
    }
}

fn cmd_power(args: PowerArgs) -> Result<()> {
    let action = args.action.to_lowercase();
    if !matches!(action.as_str(), "on" | "off" | "cycle") {
        return Err(Error::Config(format!(
            "rig power: unknown verb '{}' (expected one of: on, off, cycle)",
            args.action
        )));
    }

    let lab = resolve_lab(args.lab.as_deref());

    // Resolve rig: explicit --rig, or the single configured rig.
    let rig_id = match args.rig {
        Some(r) => r,
        None => {
            let rigs = enumerate_rigs(&lab)?;
            match rigs.len() {
                1 => rigs.into_iter().next().unwrap(),
                0 => {
                    return Err(Error::Config(format!(
                        "rig power: no rig profiles in ~/.config/fluxor/labs/{lab}/rigs/ — \
                         create one or pass --rig <id>"
                    )))
                }
                _ => {
                    return Err(Error::Config(format!(
                        "rig power: multiple rigs in lab '{lab}': {rigs:?} — pass --rig <id>"
                    )))
                }
            }
        }
    };

    let profile_path = default_profile_path(&lab, &rig_id)
        .ok_or_else(|| Error::Config("rig power: cannot resolve $HOME".into()))?;
    if !profile_path.is_file() {
        return Err(Error::Config(format!(
            "rig power: profile not found at {}",
            profile_path.display()
        )));
    }
    let profile = load_profile(&profile_path)?;

    let power_binding = profile.power.as_ref().ok_or_else(|| {
        Error::Config(format!(
            "rig power: profile '{}' has no [power] section",
            profile.rig.id
        ))
    })?;
    let backend_name = power_binding.require_string("backend", "power")?;
    let backend = resolve_backend(Surface::Power, backend_name)?;

    // The public board contract enumerates which power verbs a target
    // supports (e.g. CM5 declares only power.cycle). `rig power` must
    // honour that contract — invoking `on` / `off` on a board that only
    // declares `cycle` would silently bypass the public surface.
    //
    // Resolve the board via the same layered lookup the scenario path
    // uses so this works under a sibling project: project-local
    // `targets/boards/` → embedded defaults. No scenario to anchor on,
    // so walk upward from CWD for the optional project layer.
    let project_root_for_boards = std::env::current_dir()
        .ok()
        .and_then(|cwd| locate_workspace(&cwd).ok());
    let (board, board_source) = {
        let (rig, source) =
            crate::rig::resolve_board_rig(&profile.rig.board, project_root_for_boards.as_deref())?;
        let rig = rig.ok_or_else(|| {
            Error::Config(format!(
                "rig power: board '{}' has no [rig] section ({})",
                profile.rig.board,
                source.display(),
            ))
        })?;
        (rig, source)
    };
    validate_power_verb_on_board(&board, &action, &profile.rig.board)?;

    // Synthetic context — no scenario, no build, no observers. The backend
    // only needs enough metadata to correlate this invocation in logs.
    // Sub-second precision in the run id keeps fast reruns from colliding.
    let (now_secs, subsec_nanos) = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs(), d.subsec_nanos()))
        .unwrap_or((0, 0));
    let run_id = format!("{now_secs:010}-{subsec_nanos:09}-{rig_id}-power-{action}");
    let run_dir = ad_hoc_run_dir(&lab, &rig_id);

    let invocation = BackendInvocation {
        binding: wire_binding(power_binding),
        context: BackendContext {
            rig_id: profile.rig.id.clone(),
            lab: lab.clone(),
            run_id: run_id.clone(),
            run_dir: run_dir.display().to_string(),
            scenario_name: format!("power:{action}"),
            board: profile.rig.board.clone(),
            effective_timeout_ms: 60_000,
        },
        artifact: None,
    };

    if args.plan {
        println!("rig power {action}");
        println!("  lab        {lab}");
        println!("  rig        {}", profile.rig.id);
        println!(
            "  board      {} ({})",
            profile.rig.board,
            board_source.display()
        );
        println!(
            "  backend    {} ({})",
            backend.slug(),
            backend.executable.display()
        );
        print!("  binding   ");
        for (k, v) in power_binding.iter() {
            print!(" {k}=");
            match v {
                crate::rig::profile::BindingValue::Secret(s) => print!("{s}"),
                crate::rig::profile::BindingValue::Int(n) => print!("{n}"),
                crate::rig::profile::BindingValue::Bool(b) => print!("{b}"),
            }
        }
        println!();
        return Ok(());
    }

    // Lock the rig so an ad-hoc power action can't race an in-progress run.
    let lock_path = default_lock_path(&lab, &profile.rig.id)
        .ok_or_else(|| Error::Config("rig power: cannot resolve lock path".into()))?;
    let owner = LockOwner::now(&profile.rig.id, &format!("command:power {action}"), 60);
    let _guard = match acquire_lock(&lock_path, &owner, args.force)? {
        AcquireOutcome::Acquired(g) => g,
        AcquireOutcome::Held(c) => {
            return Err(Error::Config(format!(
                "rig power: {} is held by pid {} on {} running '{}' (stale={}). \
                 Pass --force to take it over.",
                c.path.display(),
                c.existing.pid,
                c.existing.hostname,
                c.existing.task,
                c.stale
            )));
        }
    };

    let report = invoke_actuator(&backend, &action, &invocation, Duration::from_secs(60))?;
    if let Some(info) = report.info.as_deref() {
        eprintln!("[rig] {info}");
    }
    Ok(())
}

fn ad_hoc_run_dir(lab: &str, rig_id: &str) -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join(".local")
        .join("state")
        .join("fluxor")
        .join("labs")
        .join(lab)
        .join("rigs")
        .join(rig_id)
        .join("ad-hoc")
}

/// Confirm the board declares `power.<verb>` in its `[rig].power` list.
/// Called by `cmd_power` to refuse verbs the public board contract
/// does not advertise.
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

/// Resolve the active lab namespace per RFC §10.2:
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

    const CM5_RIG: &str = r#"
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
        let board = load(CM5_RIG);
        assert!(validate_power_verb_on_board(&board, "cycle", "cm5").is_ok());
    }

    #[test]
    fn rig_power_rejects_verb_not_in_board_rig_power_list() {
        let board = load(CM5_RIG);

        let err_on = validate_power_verb_on_board(&board, "on", "cm5").unwrap_err();
        let msg = format!("{err_on}");
        assert!(msg.contains("power.on"), "{msg}");
        assert!(msg.contains("power.cycle"), "{msg}");
        assert!(msg.contains("cm5"), "{msg}");

        let err_off = validate_power_verb_on_board(&board, "off", "cm5").unwrap_err();
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
}
