//! End-to-end tests of the orchestrator lifecycle against the backend
//! doubles in `tools/src/rig/testdata/`. Each test gets its own `$HOME`
//! (lock, state and run dirs live under it) and its own backend
//! directory on `$FLUXOR_BACKEND_PATH`; both are process-global, so the
//! tests serialise on the shared environment lock.

use super::*;
use crate::rig::board::parse_board_rig_str;
use crate::rig::plan::{build_plan, PlanInputs};
use crate::rig::profile::parse_profile_str;
use crate::rig::project::parse_project_str;
use crate::rig::scenario::parse_scenario_str;
use std::os::unix::fs::PermissionsExt;

const BOARD: &str = r#"
    [rig]
    artifact = "kernel8_img"
    deploy = ["deploy.bootfs_copy"]
    console = ["console.serial"]
    observe = ["observe.netboot_fetch"]
    power = ["power.cycle", "power.off", "power.on"]
    default_timeout_s = 5
"#;

struct Bench {
    _guards: (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ),
    home: crate::rig::test_utils::UniqueTmpDir,
    saved_env: Vec<(String, Option<std::ffi::OsString>)>,
    pub log: PathBuf,
    pub feed: PathBuf,
    pub artifact: PathBuf,
}

impl Bench {
    /// Install the three doubles, point `$FLUXOR_BACKEND_PATH` at them and
    /// `$HOME` at a scratch directory.
    fn new(label: &str) -> Self {
        let env_lock = match crate::project::tests::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let exec_lock = crate::rig::test_utils::lock_exec_spawn();
        let home = crate::rig::test_utils::unique_tmp_dir(&format!("run-{label}"));
        let backends = home.join("backends");
        std::fs::create_dir_all(&backends).unwrap();
        for (name, body) in [
            ("power-recorder", include_str!("../testdata/power-recorder")),
            (
                "deploy-bootfs_copy",
                include_str!("../testdata/deploy-bootfs_copy"),
            ),
            ("console-serial", include_str!("../testdata/console-serial")),
        ] {
            let p = backends.join(name);
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let saved_env = ["HOME", "FLUXOR_BACKEND_PATH"]
            .iter()
            .map(|k| (k.to_string(), std::env::var_os(k)))
            .collect();
        std::env::set_var("HOME", home.path());
        std::env::set_var("FLUXOR_BACKEND_PATH", &backends);
        let artifact = home.join("kernel8.img");
        std::fs::write(&artifact, b"image").unwrap();
        Self {
            _guards: (env_lock, exec_lock),
            log: home.join("recorder.log"),
            feed: home.join("feed.txt"),
            artifact,
            home,
            saved_env,
        }
    }

    fn lock_path(&self) -> PathBuf {
        crate::rig::lock::default_lock_path("default", "rig-a").unwrap()
    }

    fn recorded(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(|l| l.to_string())
            .collect()
    }

    /// Build a plan: `power_extra` and `deploy_extra` are TOML lines added
    /// to the bindings, `scenario_extra` is appended to the scenario.
    fn plan(
        &self,
        power_extra: &str,
        deploy_extra: &str,
        scenario_extra: &str,
    ) -> (Plan, RigProfile) {
        let profile_src = format!(
            r#"
            [rig]
            id = "rig-a"
            board = "stub"

            [power]
            backend = "recorder"
            log = "{log}"
            feed = "{feed}"
            {power_extra}

            [deploy.bootfs_copy]
            log = "{log}"
            feed = "{feed}"
            {deploy_extra}

            [console.serial]
            feed = "{feed}"
            "#,
            log = self.log.display(),
            feed = self.feed.display(),
        );
        let scenario_src = format!(
            r#"
            name = "stub_scenario"
            target = "stub"
            config = "a.yaml"
            requires = ["deploy.bootfs_copy", "power.cycle"]
            timeout_s = 4

            [[pass]]
            source = "console.serial"
            regex = "alive"

            [[fail]]
            source = "console.serial"
            regex = "old image"
            {scenario_extra}
            "#
        );
        let project_src = format!(
            "[build.stub]\ncommand = [\"true\"]\nartifact = \"{}\"\n",
            self.artifact.display()
        );
        let board = parse_board_rig_str(BOARD, "stub.toml").unwrap().unwrap();
        let profile = parse_profile_str(&profile_src, Path::new("/tmp/rig-a.toml")).unwrap();
        let scenario = parse_scenario_str(&scenario_src, self.home.path(), "s.toml").unwrap();
        let project = parse_project_str(&project_src, self.home.path(), "p").unwrap();
        let plan = build_plan(PlanInputs {
            lab: "default",
            scenario: &scenario,
            board: &board,
            profile: &profile,
            project: Some(&project),
            scenario_path: None,
        })
        .unwrap();
        (plan, profile)
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        for (k, v) in self.saved_env.drain(..) {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}

fn manifest(run_dir: &Path) -> RunRecord {
    let raw = std::fs::read_to_string(run_dir.join("manifest.json")).unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn position(log: &[String], entry: &str) -> usize {
    log.iter()
        .position(|l| l == entry)
        .unwrap_or_else(|| panic!("{entry:?} not in {log:?}"))
}

#[test]
fn a_passing_run_powers_off_at_teardown_and_records_everything() {
    let bench = Bench::new("pass");
    let (plan, profile) = bench.plan("", "", "");
    let outcome = execute_plan(&plan, &profile, &RunOptions::default()).unwrap();
    assert_eq!(outcome.record.verdict, Verdict::Passed);

    let log = bench.recorded();
    // stage → cycle → (verdict) → off at teardown → unstage.
    assert!(position(&log, "stage run") < position(&log, "cycle run"));
    assert!(position(&log, "cycle run") < position(&log, "off teardown"));
    assert!(position(&log, "off teardown") < position(&log, "unstage teardown"));
    assert!(
        !log.iter().any(|l| l.starts_with("diagnose")),
        "no diagnose on a pass: {log:?}"
    );

    let m = manifest(&outcome.run_dir);
    assert_eq!(m.verdict, Verdict::Passed);
    let t = m.teardown.expect("teardown recorded");
    assert!(t.clean);
    assert_eq!(t.power.outcome, "ok");
    assert_eq!(t.diagnose.outcome, "skipped");
    assert_eq!(t.unstage.outcome, "ok");
    assert_eq!(
        m.reports.stage.as_ref().unwrap().detail.as_ref().unwrap()["bytes"],
        1234
    );
    assert_eq!(m.reports.power.len(), 1);
    assert_eq!(m.reports.power[0].verb, "cycle");
    assert!(m.artifact_sha256.is_some());
    assert!(
        !marker_path_for(&bench.lock_path()).exists(),
        "marker cleared after a clean teardown"
    );
    assert!(!bench.lock_path().exists(), "lock released");
}

/// The previous image's output (written at stage, before the power step)
/// matches the fail rule; it must stay hidden. The fresh image's output
/// after the reset passes. A boot reported on first open, before the
/// power step, is not a boot.
#[test]
fn bytes_before_the_power_step_are_hidden_unless_a_fresh_boot_follows_power_started() {
    let bench = Bench::new("gating");
    let (plan, profile) = bench.plan("", "", "");
    let outcome = execute_plan(&plan, &profile, &RunOptions::default()).unwrap();
    assert_eq!(
        outcome.record.verdict,
        Verdict::Passed,
        "{:?}",
        outcome.record.reason
    );
    // The hidden bytes still reach the capture log.
    let captured = std::fs::read_to_string(outcome.run_dir.join("console.serial.log")).unwrap();
    assert!(captured.contains("old image alive"), "{captured}");
    assert!(captured.contains("fresh image alive"), "{captured}");
}

#[test]
fn a_boot_on_first_open_does_not_unhide_the_old_image() {
    let bench = Bench::new("boot-first-open");
    let (plan, profile) = bench.plan("", "", "");
    // The console double announces a boot the moment it attaches.
    let mut profile = profile;
    let cap = Capability::parse("console.serial").unwrap();
    let table = profile.console.get_mut(&cap).unwrap();
    *table = parse_profile_str(
        &format!(
            "[rig]\nid = \"rig-a\"\nboard = \"stub\"\n[console.serial]\nfeed = \"{}\"\nboot_on_open = true\n",
            bench.feed.display()
        ),
        Path::new("/tmp/x.toml"),
    )
    .unwrap()
    .console
    .remove(&cap)
    .unwrap();
    let outcome = execute_plan(&plan, &profile, &RunOptions::default()).unwrap();
    assert_eq!(
        outcome.record.verdict,
        Verdict::Passed,
        "{:?}",
        outcome.record.reason
    );
}

#[test]
fn a_failed_stage_aborts_and_still_tears_down() {
    let bench = Bench::new("stage-fails");
    let (plan, profile) = bench.plan("", "fail_stage = true", "");
    let outcome = execute_plan(&plan, &profile, &RunOptions::default()).unwrap();
    assert_eq!(outcome.record.verdict, Verdict::Aborted);
    assert!(outcome
        .record
        .reason
        .as_deref()
        .unwrap()
        .contains("deploy stage"));
    let log = bench.recorded();
    assert!(
        !log.iter().any(|l| l == "cycle run"),
        "no power after a failed stage: {log:?}"
    );
    assert!(log.iter().any(|l| l == "off teardown"), "{log:?}");
    assert!(log.iter().any(|l| l == "unstage teardown"), "{log:?}");
    assert!(manifest(&outcome.run_dir).teardown.unwrap().clean);
}

#[test]
fn a_stage_that_exits_64_is_a_failure_not_an_optional_verb() {
    let bench = Bench::new("stage-64");
    let (plan, profile) = bench.plan("", "stage_64 = true", "");
    let outcome = execute_plan(&plan, &profile, &RunOptions::default()).unwrap();
    assert_eq!(outcome.record.verdict, Verdict::Aborted);
    assert!(
        outcome
            .record
            .reports
            .stage
            .unwrap()
            .outcome
            .contains("unsupported"),
        "stage must be recorded as unsupported and the run aborted"
    );
}

#[test]
fn a_signal_during_an_actuator_lets_it_finish_then_tears_down() {
    let bench = Bench::new("signal");
    // `cycle` takes 800 ms; the abort lands in the middle of it.
    let (plan, profile) = bench.plan("sleep_ms = 800", "", "");
    install_signal_handlers();
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(250));
        // SAFETY: raise delivers SIGINT to this process; the handler only
        // sets an atomic flag.
        unsafe {
            libc::raise(libc::SIGINT);
        }
    });
    let outcome = execute_plan(&plan, &profile, &RunOptions::default()).unwrap();
    assert_eq!(outcome.record.verdict, Verdict::Aborted);
    assert!(outcome.record.reason.as_deref().unwrap().contains("signal"));
    let log = bench.recorded();
    // The in-flight cycle completed (it is in the log and was reported
    // ok), and the teardown still ran.
    assert_eq!(outcome.record.reports.power[0].outcome, "ok");
    assert!(position(&log, "cycle run") < position(&log, "off teardown"));
    assert!(manifest(&outcome.run_dir).teardown.unwrap().clean);
}

#[test]
fn a_failed_power_off_leaves_the_marker_and_the_next_claim_tears_down_first() {
    let bench = Bench::new("marker");
    let (plan, profile) = bench.plan("fail_off = true", "", "");
    let err = execute_plan(&plan, &profile, &RunOptions::default()).unwrap_err();
    assert!(
        format!("{err}").contains("teardown did not complete"),
        "{err}"
    );
    let marker_path = marker_path_for(&bench.lock_path());
    let marker = TeardownMarker::read(&marker_path)
        .unwrap()
        .expect("marker left");
    assert!(
        marker.last_error.as_deref().unwrap().contains("power"),
        "{marker:?}"
    );
    assert!(
        !bench.lock_path().exists(),
        "the lock is released; the marker is what persists"
    );

    // A run dir's manifest records the incomplete teardown.
    let m = manifest(Path::new(&marker.run_dir));
    assert_eq!(m.verdict, Verdict::Passed);
    assert!(!m.teardown.unwrap().clean);

    // The next claim, with a working `off`, tears the old run down before
    // staging anything of its own.
    std::fs::remove_file(&bench.log).unwrap();
    let (plan2, profile2) = bench.plan("", "", "");
    let outcome = execute_plan(&plan2, &profile2, &RunOptions::default()).unwrap();
    assert_eq!(outcome.record.verdict, Verdict::Passed);
    let log = bench.recorded();
    assert!(
        position(&log, "off teardown") < position(&log, "stage run"),
        "{log:?}"
    );
    assert!(!marker_path.exists());
}

#[test]
fn residue_reported_by_off_fails_the_teardown() {
    let bench = Bench::new("residue");
    let (plan, profile) = bench.plan("residue = true", "", "");
    let err = execute_plan(&plan, &profile, &RunOptions::default()).unwrap_err();
    assert!(
        format!("{err}").contains("teardown did not complete"),
        "{err}"
    );
    let marker = TeardownMarker::read(&marker_path_for(&bench.lock_path()))
        .unwrap()
        .unwrap();
    assert!(
        marker.last_error.as_deref().unwrap().contains("residue"),
        "{marker:?}"
    );
    assert!(
        marker.last_error.as_deref().unwrap().contains("i-leftover"),
        "{marker:?}"
    );
}

#[test]
fn diagnose_runs_only_on_failure_and_unsupported_is_tolerated() {
    let bench = Bench::new("diagnose");
    // No "alive" line ever arrives: the fresh image is silent.
    let (plan, profile) = bench.plan("diagnose = true", "", "");
    // Keep `cycle` from writing the fresh image's output.
    let mut profile = profile;
    let table = profile.power.as_mut().unwrap();
    let no_feed = parse_profile_str(
        &format!(
            "[rig]\nid = \"rig-a\"\nboard = \"stub\"\n[power]\nbackend = \"recorder\"\nlog = \"{}\"\ndiagnose = true\n",
            bench.log.display()
        ),
        Path::new("/tmp/x.toml"),
    )
    .unwrap();
    *table = no_feed.power.unwrap();
    let outcome = execute_plan(&plan, &profile, &RunOptions::default()).unwrap();
    assert_eq!(outcome.record.verdict, Verdict::TimedOut);
    let t = manifest(&outcome.run_dir).teardown.unwrap();
    assert_eq!(t.diagnose.outcome, "ok");
    assert_eq!(t.diagnose.detail.unwrap()["registers"], "x0=0");
    assert!(t.clean);
    let log = bench.recorded();
    assert!(position(&log, "diagnose teardown") < position(&log, "off teardown"));

    // Without `diagnose` in the binding the double exits 64: tolerated.
    std::fs::remove_file(&bench.log).unwrap();
    let (plan2, profile2) = bench.plan("", "", "");
    let mut profile2 = profile2;
    *profile2.power.as_mut().unwrap() = parse_profile_str(
        &format!(
            "[rig]\nid = \"rig-a\"\nboard = \"stub\"\n[power]\nbackend = \"recorder\"\nlog = \"{}\"\n",
            bench.log.display()
        ),
        Path::new("/tmp/x.toml"),
    )
    .unwrap()
    .power
    .unwrap();
    let outcome2 = execute_plan(&plan2, &profile2, &RunOptions::default()).unwrap();
    assert_eq!(outcome2.record.verdict, Verdict::TimedOut);
    let t2 = manifest(&outcome2.run_dir).teardown.unwrap();
    assert_eq!(t2.diagnose.outcome, "unsupported");
    assert!(t2.clean);
}

#[test]
fn a_no_op_off_is_recorded_as_such_and_counts_as_clean() {
    let bench = Bench::new("noop");
    let (plan, profile) = bench.plan("no_op_off = true", "", "");
    let outcome = execute_plan(&plan, &profile, &RunOptions::default()).unwrap();
    let t = manifest(&outcome.run_dir).teardown.unwrap();
    assert_eq!(t.power.outcome, "ok (no-op)");
    assert!(t.clean);
}

#[test]
fn a_missed_expectation_fails_by_absence_and_names_itself() {
    let bench = Bench::new("expect");
    let (plan, profile) = bench.plan(
        "",
        "",
        "[[expect]]\nsource = \"console.serial\"\nregex = \"\\\\[boot\\\\] stages=\"\nwithin_s = 1\n",
    );
    let outcome = execute_plan(&plan, &profile, &RunOptions::default()).unwrap();
    assert_eq!(outcome.record.verdict, Verdict::Failed);
    let reason = outcome.record.reason.unwrap();
    assert!(reason.contains("\\[boot\\] stages="), "{reason}");
    assert!(reason.contains("within 1s"), "{reason}");
    assert_eq!(
        outcome.record.primary_observation_source.as_deref(),
        Some("console.serial")
    );
    let log = bench.recorded();
    assert!(log.iter().any(|l| l == "off teardown"));
}

#[test]
fn hold_calls_the_backend_then_tears_down_when_the_time_is_up() {
    let bench = Bench::new("hold");
    let (plan, profile) = bench.plan(
        "",
        "",
        "[[expect]]\nsource = \"console.serial\"\nregex = \"never\"\nwithin_s = 1\n",
    );
    let options = RunOptions {
        hold: Some(Duration::from_millis(400)),
        ..RunOptions::default()
    };
    let start = Instant::now();
    let outcome = execute_plan(&plan, &profile, &options).unwrap();
    assert_eq!(outcome.record.verdict, Verdict::Failed);
    let log = bench.recorded();
    assert!(
        position(&log, "hold run") < position(&log, "off teardown"),
        "{log:?}"
    );
    assert!(start.elapsed() >= Duration::from_millis(400));
    let held = outcome
        .record
        .reports
        .power
        .iter()
        .find(|r| r.verb == "hold")
        .unwrap();
    assert!(
        held.info.as_deref().unwrap().contains("gdb"),
        "the backend's hold info is kept"
    );
}

#[test]
fn no_power_binding_records_off_as_unsupported_and_is_clean() {
    let bench = Bench::new("nopower");
    let (plan, profile) = bench.plan("", "", "");
    let mut profile = profile;
    profile.power = None;
    // The scenario requires power.cycle; drop that requirement so the plan
    // is valid without a backend.
    let mut plan = plan;
    plan.power = None;
    plan.power_required = false;
    plan.power_actions.clear();
    let outcome = execute_plan(&plan, &profile, &RunOptions::default()).unwrap();
    // Without a power step nothing is hidden: the staged image's own
    // "old image alive" line now reaches the matcher and trips the fail
    // rule — which is the right reading when nobody reset the board.
    assert_eq!(outcome.record.verdict, Verdict::Failed);
    let t = manifest(&outcome.run_dir).teardown.unwrap();
    assert_eq!(t.power.outcome, "unsupported");
    assert!(t.clean);
}

#[test]
fn teardown_rig_outside_a_run_uses_every_deploy_binding_and_writes_a_record() {
    let bench = Bench::new("teardown-cmd");
    let (_plan, profile) = bench.plan("", "", "");
    let lock_path = bench.lock_path();
    std::fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
    let record = teardown_rig(&profile, &lock_path, None, &RunOptions::default()).unwrap();
    assert!(record.clean);
    let log = bench.recorded();
    assert_eq!(log, vec!["off teardown", "unstage teardown"]);
}
