//! Plan mode — the no-side-effect resolution of a run per RFC §10.4.
//!
//! Given a scenario, a target board descriptor, a private rig profile, and
//! optionally a project descriptor, produce a [`Plan`] that names every
//! concrete choice the orchestrator would make: which deploy adapter, which
//! power backend, what the artifact looks like, which lock file, which
//! observation rules, and what goes into the run record. Printing the plan
//! shows the operator exactly what a non-plan run would do.

use std::fmt;
use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::rig::board::BoardRig;
use crate::rig::lock::default_lock_path;
use crate::rig::profile::{BindingTable, RigProfile};
use crate::rig::project::{BuildOutput, ProjectDescriptor};
use crate::rig::record::RunRecord;
use crate::rig::scenario::{ObservationRule, Scenario};
use crate::rig::vocab::{Capability, Surface};

/// Fully resolved run intent.
#[derive(Debug, Clone)]
pub struct Plan {
    pub lab: String,
    pub rig: String,
    pub board: String,
    pub tags: Vec<String>,
    pub scenario_name: String,
    pub scenario_path: Option<PathBuf>,
    pub config_path: PathBuf,
    pub effective_timeout_s: u32,
    pub deploy: AdapterSelection,
    /// One attachment per distinct console source named by a rule. Empty
    /// when no rule references a console transport (a summary console for
    /// the run log may still be added by the orchestrator).
    pub consoles: Vec<AdapterSelection>,
    pub telemetry: Option<AdapterSelection>,
    pub power: Option<PowerSelection>,
    /// Power verbs the orchestrator will invoke (in order) against the
    /// power backend. Derived from `scenario.requires`: `power.cycle`
    /// wins if listed (it subsumes on/off), otherwise the specific verbs
    /// named are invoked in list order. Empty when no power backend is
    /// configured AND the scenario doesn't require one. When a backend
    /// *is* configured but the scenario doesn't name any power.*, the
    /// default is a single `cycle`.
    pub power_actions: Vec<&'static str>,
    /// True when the scenario's `requires` list names any `power.*`
    /// capability. In that case the orchestrator must have a power backend
    /// — running without one violates the scenario contract.
    pub power_required: bool,
    pub observers: Vec<ObserverSelection>,
    pub pass_rules: Vec<ObservationRule>,
    pub fail_rules: Vec<ObservationRule>,
    pub artifact: ArtifactPlan,
    pub lock_path: Option<PathBuf>,
    pub run_record: RunRecord,
}

#[derive(Debug, Clone)]
pub struct AdapterSelection {
    pub capability: Capability,
    /// Opaque descriptive string derived from the profile binding. Display
    /// only; adapters read structured fields from the profile directly.
    pub summary: String,
}

#[derive(Debug, Clone)]
pub struct PowerSelection {
    pub backend: String,
    pub summary: String,
}

#[derive(Debug, Clone)]
pub struct ObserverSelection {
    pub rule_kind: RuleKind,
    pub rule: ObservationRule,
    pub bound_to: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    Pass,
    Fail,
}

#[derive(Debug, Clone)]
pub enum ArtifactPlan {
    /// Build-descriptor absent; orchestrator will need to be told how to
    /// produce the artifact. Plan mode still succeeds so operators can
    /// see the rest of the resolved lifecycle.
    Unresolved { reason: String },
    File {
        /// argv of the build command. Per RFC §15.3 it is executed with
        /// `project_root` as the working directory.
        command: Vec<String>,
        project_root: PathBuf,
        path: PathBuf,
    },
    Bundle {
        command: Vec<String>,
        project_root: PathBuf,
        root: PathBuf,
    },
}

pub struct PlanInputs<'a> {
    pub lab: &'a str,
    pub scenario: &'a Scenario,
    pub board: &'a BoardRig,
    pub profile: &'a RigProfile,
    pub project: Option<&'a ProjectDescriptor>,
    pub scenario_path: Option<&'a std::path::Path>,
}

pub fn build_plan(inputs: PlanInputs<'_>) -> Result<Plan> {
    let scenario = inputs.scenario;
    let board = inputs.board;
    let profile = inputs.profile;

    let effective_timeout_s = scenario.timeout_s.or(board.default_timeout_s).unwrap_or(30);

    let deploy = pick_deploy(scenario, board, profile)?;
    let consoles = pick_consoles(scenario, board, profile)?;
    let telemetry = pick_single_surface(
        Surface::Telemetry,
        &board.telemetry,
        board.preferred_telemetry,
        &profile.telemetry,
    );

    let power_required = scenario
        .requires
        .iter()
        .any(|c| c.surface() == Surface::Power);

    let power = profile.power.as_ref().and_then(|t| {
        t.optional_string("backend").map(|backend| PowerSelection {
            backend: backend.to_string(),
            summary: summarise_binding(t),
        })
    });
    if power_required && power.is_none() {
        return Err(Error::Config(format!(
            "rig plan: scenario '{}' requires {:?} but profile '{}' has no [power] \
             section. Either add a power backend binding to the profile or drop the \
             power.* entries from `requires`.",
            scenario.name,
            scenario
                .requires
                .iter()
                .filter(|c| c.surface() == Surface::Power)
                .map(|c| c.as_str())
                .collect::<Vec<_>>(),
            profile.rig.id,
        )));
    }

    let power_actions = derive_power_actions(scenario, power.is_some());

    let observers = observers_from_rules(scenario, board, profile);
    let artifact = pick_artifact(scenario.target.as_str(), board, inputs.project);
    let lock_path = default_lock_path(inputs.lab, &profile.rig.id);

    // Artifact digests require on-disk bytes; the plan stops at the
    // resolved output path rather than triggering a build. The
    // orchestrator fills in the digest after the build runs.
    let artifact_digest: Option<String> = None;
    let run_record = RunRecord::for_plan(inputs.lab, scenario, profile, artifact_digest)?;

    Ok(Plan {
        lab: inputs.lab.to_string(),
        rig: profile.rig.id.clone(),
        board: profile.rig.board.clone(),
        tags: profile.rig.tags.clone(),
        scenario_name: scenario.name.clone(),
        scenario_path: inputs.scenario_path.map(|p| p.to_path_buf()),
        config_path: scenario.config.clone(),
        effective_timeout_s,
        deploy,
        consoles,
        telemetry,
        power,
        power_actions,
        power_required,
        observers,
        pass_rules: scenario.pass.clone(),
        fail_rules: scenario.fail.clone(),
        artifact,
        lock_path,
        run_record,
    })
}

/// Map the scenario's `power.*` requirements to the verbs the
/// orchestrator invokes against the power backend.
///
///   * `power.cycle` → `["cycle"]` (cycle subsumes on+off).
///   * Otherwise each named `power.on` / `power.off` becomes the matching
///     verb in declaration order — e.g. `power.off`, `power.on` →
///     `["off", "on"]`, an explicit cold-start sequence.
///   * No `power.*` named → `["cycle"]` when a backend is configured,
///     else an empty list (skip the power step).
fn derive_power_actions(scenario: &Scenario, have_backend: bool) -> Vec<&'static str> {
    let reqs: Vec<Capability> = scenario
        .requires
        .iter()
        .copied()
        .filter(|c| c.surface() == Surface::Power)
        .collect();

    if reqs.iter().any(|c| c.as_str() == "power.cycle") {
        return vec!["cycle"];
    }

    if !reqs.is_empty() {
        return reqs
            .iter()
            .filter_map(|c| match c.as_str() {
                "power.on" => Some("on"),
                "power.off" => Some("off"),
                // power.cycle handled above; any other capability would have
                // been rejected by the vocabulary parser.
                _ => None,
            })
            .collect();
    }

    if have_backend {
        vec!["cycle"]
    } else {
        Vec::new()
    }
}

fn pick_deploy(
    scenario: &Scenario,
    board: &BoardRig,
    profile: &RigProfile,
) -> Result<AdapterSelection> {
    // A scenario may pin the deploy adapter via `requires`. If it does,
    // that selection wins — the board's preferred_deploy only applies when
    // the scenario hasn't asked for a specific method.
    let required_deploys: Vec<Capability> = scenario
        .requires
        .iter()
        .filter(|c| c.surface() == Surface::Deploy)
        .copied()
        .collect();

    if required_deploys.len() > 1 {
        return Err(Error::Config(format!(
            "rig plan: scenario '{}' lists multiple deploy capabilities in `requires` \
             ({:?}); pin exactly one — the harness only runs a single deploy adapter \
             per run.",
            scenario.name,
            required_deploys
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>(),
        )));
    }

    if let Some(cap) = required_deploys.first().copied() {
        if !board.deploy.contains(&cap) {
            return Err(Error::Config(format!(
                "rig plan: scenario '{}' requires {} but board '{}' does not declare it \
                 (board deploy: {:?})",
                scenario.name,
                cap.as_str(),
                scenario.target,
                board.deploy.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
            )));
        }
        let binding = profile.deploy.get(&cap).ok_or_else(|| {
            Error::Config(format!(
                "rig plan: scenario '{}' requires {} but profile '{}' has no [{}] binding",
                scenario.name,
                cap.as_str(),
                profile.rig.id,
                cap.as_str(),
            ))
        })?;
        return Ok(AdapterSelection {
            capability: cap,
            summary: summarise_binding(binding),
        });
    }

    // No scenario pin — fall back to preferred + first-available.
    if let Some(pref) = board.preferred_deploy {
        if profile.deploy.contains_key(&pref) {
            return Ok(AdapterSelection {
                capability: pref,
                summary: summarise_binding(profile.deploy.get(&pref).unwrap()),
            });
        }
    }
    for cap in &board.deploy {
        if let Some(binding) = profile.deploy.get(cap) {
            return Ok(AdapterSelection {
                capability: *cap,
                summary: summarise_binding(binding),
            });
        }
    }
    Err(Error::Config(format!(
        "rig plan: profile '{}' has no deploy binding matching any capability the board \
         declares (board deploy: {:?}, profile deploy: {:?})",
        profile.rig.id,
        board.deploy.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
        profile
            .deploy
            .keys()
            .map(|c| c.as_str())
            .collect::<Vec<_>>(),
    )))
}

/// Return one adapter selection per distinct console capability the
/// scenario references — via its `requires` list and/or its rule sources.
/// If the scenario names nothing console-specific, fall back to the
/// board's preferred console so the orchestrator can still capture a
/// `console.log` for diagnostics.
fn pick_consoles(
    scenario: &Scenario,
    board: &BoardRig,
    profile: &RigProfile,
) -> Result<Vec<AdapterSelection>> {
    let mut wanted: Vec<Capability> = Vec::new();
    for cap in &scenario.requires {
        if cap.surface() == Surface::Console && !wanted.contains(cap) {
            wanted.push(*cap);
        }
    }
    for rule in scenario.pass.iter().chain(scenario.fail.iter()) {
        if rule.source.surface() == Surface::Console && !wanted.contains(&rule.source) {
            wanted.push(rule.source);
        }
    }

    if !wanted.is_empty() {
        let mut out = Vec::with_capacity(wanted.len());
        for cap in wanted {
            if !board.console.contains(&cap) {
                return Err(Error::Config(format!(
                    "rig plan: scenario '{}' references {} but board '{}' does not \
                     declare it (board console: {:?})",
                    scenario.name,
                    cap.as_str(),
                    scenario.target,
                    board.console.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                )));
            }
            let binding = profile.console.get(&cap).ok_or_else(|| {
                Error::Config(format!(
                    "rig plan: scenario '{}' references {} but profile '{}' has no \
                     [{}] binding",
                    scenario.name,
                    cap.as_str(),
                    profile.rig.id,
                    cap.as_str(),
                ))
            })?;
            out.push(AdapterSelection {
                capability: cap,
                summary: summarise_binding(binding),
            });
        }
        return Ok(out);
    }

    // Scenario is console-agnostic; pick the default for log capture.
    Ok(pick_single_surface(
        Surface::Console,
        &board.console,
        board.preferred_console,
        &profile.console,
    )
    .into_iter()
    .collect())
}

fn pick_single_surface(
    _surface: Surface,
    board_list: &[Capability],
    preferred: Option<Capability>,
    profile_map: &std::collections::BTreeMap<Capability, BindingTable>,
) -> Option<AdapterSelection> {
    // `preferred_*` is authoritative for default selection when the
    // scenario is surface-agnostic; the list is only consulted as a
    // fallback so a profile that doesn't bind the preferred capability
    // still gets a working adapter.
    if let Some(pref) = preferred {
        if let Some(binding) = profile_map.get(&pref) {
            return Some(AdapterSelection {
                capability: pref,
                summary: summarise_binding(binding),
            });
        }
    }
    for cap in board_list {
        if let Some(binding) = profile_map.get(cap) {
            return Some(AdapterSelection {
                capability: *cap,
                summary: summarise_binding(binding),
            });
        }
    }
    None
}

fn observers_from_rules(
    scenario: &Scenario,
    _board: &BoardRig,
    profile: &RigProfile,
) -> Vec<ObserverSelection> {
    let mut out = Vec::new();
    for r in &scenario.pass {
        let bound_to = describe_rule_source(r.source, profile);
        out.push(ObserverSelection {
            rule_kind: RuleKind::Pass,
            rule: r.clone(),
            bound_to,
        });
    }
    for r in &scenario.fail {
        let bound_to = describe_rule_source(r.source, profile);
        out.push(ObserverSelection {
            rule_kind: RuleKind::Fail,
            rule: r.clone(),
            bound_to,
        });
    }
    out
}

fn describe_rule_source(source: Capability, profile: &RigProfile) -> String {
    let map = match source.surface() {
        Surface::Console => &profile.console,
        Surface::Telemetry => &profile.telemetry,
        Surface::Observe => &profile.observe,
        _ => return "(unbound: rule source must be a console/telemetry/observe capability)".into(),
    };
    match map.get(&source) {
        Some(b) => summarise_binding(b),
        None => "(no profile binding — adapter will use defaults)".to_string(),
    }
}

fn pick_artifact(
    board_id: &str,
    board: &BoardRig,
    project: Option<&ProjectDescriptor>,
) -> ArtifactPlan {
    let Some(project) = project else {
        return ArtifactPlan::Unresolved {
            reason: format!(
                "no project descriptor found — add a [build.{board_id}] recipe to \
                 ~/.config/fluxor/projects/<name>/rig.toml (or to an in-tree \
                 .fluxor-rig.toml)"
            ),
        };
    };
    let Some(recipe) = project.recipe(board_id) else {
        return ArtifactPlan::Unresolved {
            reason: format!(
                "project descriptor at {} has no [build.{board_id}] recipe",
                project.project_root.display()
            ),
        };
    };
    match &recipe.output {
        BuildOutput::File(path) => {
            // Single-file artifacts only make sense when the board
            // declares a single-file artifact class.
            if matches!(board.artifact.as_deref(), Some("boot_bundle")) {
                return ArtifactPlan::Unresolved {
                    reason: "board artifact class is 'boot_bundle' but the project \
                             recipe produces a single file — use 'artifact_bundle_dir'"
                        .to_string(),
                };
            }
            ArtifactPlan::File {
                command: recipe.command.clone(),
                project_root: project.project_root.clone(),
                path: path.clone(),
            }
        }
        BuildOutput::Bundle(root) => {
            if matches!(board.artifact.as_deref(), Some("uf2")) {
                return ArtifactPlan::Unresolved {
                    reason: "board artifact class is 'uf2' but the project recipe \
                             produces a bundle — use 'artifact' (single file)"
                        .to_string(),
                };
            }
            ArtifactPlan::Bundle {
                command: recipe.command.clone(),
                project_root: project.project_root.clone(),
                root: root.clone(),
            }
        }
    }
}

/// Compact human-readable summary of a binding. Values go through `Display`
/// so resolved secrets print as `***`.
fn summarise_binding(table: &BindingTable) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (k, v) in table.iter() {
        let rendered = match v {
            crate::rig::profile::BindingValue::Secret(s) => format!("{s}"),
            crate::rig::profile::BindingValue::Int(n) => format!("{n}"),
            crate::rig::profile::BindingValue::Bool(b) => format!("{b}"),
        };
        parts.push(format!("{k}={rendered}"));
    }
    parts.join(", ")
}

// ── Pretty printer ─────────────────────────────────────────────────────────

impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "rig plan ({})", self.scenario_name)?;
        writeln!(f, "  lab               {}", self.lab)?;
        writeln!(f, "  rig               {}", self.rig)?;
        writeln!(f, "  board             {}", self.board)?;
        if !self.tags.is_empty() {
            writeln!(f, "  tags              {:?}", self.tags)?;
        }
        if let Some(sp) = &self.scenario_path {
            writeln!(f, "  scenario          {}", sp.display())?;
        }
        writeln!(f, "  config            {}", self.config_path.display())?;
        writeln!(f, "  effective_timeout {}s", self.effective_timeout_s)?;

        writeln!(
            f,
            "  deploy            {} ({})",
            self.deploy.capability, self.deploy.summary
        )?;
        for c in &self.consoles {
            writeln!(f, "  console           {} ({})", c.capability, c.summary)?;
        }
        if let Some(t) = &self.telemetry {
            writeln!(f, "  telemetry         {} ({})", t.capability, t.summary)?;
        }
        match (&self.power, self.power_required) {
            (Some(p), _) => {
                let verbs = if self.power_actions.is_empty() {
                    "(none)".to_string()
                } else {
                    self.power_actions.join(", ")
                };
                writeln!(
                    f,
                    "  power             {} ({}); verbs: {}",
                    p.backend, p.summary, verbs,
                )?
            }
            (None, true) => writeln!(
                f,
                "  power             REQUIRED by scenario but no profile binding"
            )?,
            (None, false) => writeln!(
                f,
                "  power             (none — scenario does not require power control)"
            )?,
        }

        match &self.artifact {
            ArtifactPlan::File {
                command,
                project_root,
                path,
            } => {
                writeln!(f, "  artifact          file {}", path.display())?;
                writeln!(f, "  build cwd         {}", project_root.display())?;
                writeln!(f, "  build             {}", shell_render(command))?;
            }
            ArtifactPlan::Bundle {
                command,
                project_root,
                root,
            } => {
                writeln!(f, "  artifact          bundle {}", root.display())?;
                writeln!(f, "  build cwd         {}", project_root.display())?;
                writeln!(f, "  build             {}", shell_render(command))?;
            }
            ArtifactPlan::Unresolved { reason } => {
                writeln!(f, "  artifact          UNRESOLVED — {reason}")?;
            }
        }

        if let Some(l) = &self.lock_path {
            writeln!(f, "  lock              {}", l.display())?;
        }

        if !self.pass_rules.is_empty() {
            writeln!(f, "  pass rules:")?;
            for r in &self.pass_rules {
                writeln!(
                    f,
                    "    {} regex={:?}",
                    r.source,
                    r.regex.as_deref().unwrap_or("(none)")
                )?;
            }
        }
        if !self.fail_rules.is_empty() {
            writeln!(f, "  fail rules:")?;
            for r in &self.fail_rules {
                writeln!(
                    f,
                    "    {} regex={:?}",
                    r.source,
                    r.regex.as_deref().unwrap_or("(none)")
                )?;
            }
        }
        writeln!(f, "  run id            {}", self.run_record.run_id)?;
        writeln!(f, "  scenario sha256   {}", self.run_record.scenario_sha256)?;
        writeln!(f, "  profile sha256    {}", self.run_record.profile_sha256)?;
        Ok(())
    }
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
mod tests {
    use super::*;
    use crate::rig::board::parse_board_rig_str;
    use crate::rig::profile::parse_profile_str;
    use crate::rig::project::parse_project_str;
    use crate::rig::scenario::parse_scenario_str;

    const CM5_BOARD: &str = r#"
        [rig]
        artifact = "boot_bundle"
        deploy = ["deploy.netboot_tftp", "deploy.bootfs_copy"]
        preferred_deploy = "deploy.netboot_tftp"
        console = ["console.serial"]
        observe = ["observe.console_regex", "observe.netboot_fetch"]
        power = ["power.cycle"]
        default_timeout_s = 30
    "#;

    const PROFILE: &str = r#"
        [rig]
        id = "pi5-a"
        board = "cm5"
        tags = ["nvme"]

        [power]
        backend = "uhubctl"
        port = 4

        [deploy.netboot_tftp]
        root = "/srv/tftp/pi5-a"
        interface = "enp2s0"

        [console.serial]
        device = "/dev/ttyUSB0"
        baud = 115200

        [observe.netboot_fetch]
        match_serial = "4f3c2a11"
    "#;

    const SCENARIO: &str = r#"
        name = "cm5_boot_banner"
        target = "cm5"
        config = "../examples/cm5/hello.yaml"
        requires = ["deploy.netboot_tftp", "power.cycle"]

        [[pass]]
        source = "console.serial"
        regex = "ok"

        [[fail]]
        source = "console.serial"
        regex = "PANIC"
    "#;

    const PROJECT: &str = r#"
        [build.cm5]
        command = ["make", "firmware", "TARGET=cm5"]
        artifact_bundle_dir = "target/cm5/bundle"
    "#;

    fn load() -> (BoardRig, RigProfile, Scenario, ProjectDescriptor) {
        let board = parse_board_rig_str(CM5_BOARD, "cm5.toml").unwrap().unwrap();
        let profile = parse_profile_str(PROFILE, std::path::Path::new("/tmp/pi5-a.toml")).unwrap();
        let scenario = parse_scenario_str(
            SCENARIO,
            std::path::Path::new("/repo/tests/hardware"),
            "s.toml",
        )
        .unwrap();
        let project = parse_project_str(PROJECT, std::path::Path::new("/repo"), "p").unwrap();
        (board, profile, scenario, project)
    }

    #[test]
    fn builds_plan() {
        let (board, profile, scenario, project) = load();
        let p = build_plan(PlanInputs {
            lab: "default",
            scenario: &scenario,
            board: &board,
            profile: &profile,
            project: Some(&project),
            scenario_path: None,
        })
        .unwrap();
        assert_eq!(p.rig, "pi5-a");
        assert_eq!(p.deploy.capability.as_str(), "deploy.netboot_tftp");
        assert!(matches!(p.artifact, ArtifactPlan::Bundle { .. }));
        assert_eq!(p.effective_timeout_s, 30);
        assert_eq!(p.pass_rules.len(), 1);
        assert_eq!(p.fail_rules.len(), 1);
    }

    #[test]
    fn plan_display_has_no_raw_secrets() {
        std::env::set_var("FLUXOR_PLAN_TEST_PASS", "topsecret-must-not-leak");
        let profile_src = r#"
            [rig]
            id = "pi5-a"
            board = "cm5"

            [power]
            backend = "kasa_local"
            password = "${env:FLUXOR_PLAN_TEST_PASS}"

            [deploy.netboot_tftp]
            root = "/srv/tftp"

            [console.serial]
            device = "/dev/ttyUSB0"
        "#;
        let board = parse_board_rig_str(CM5_BOARD, "cm5.toml").unwrap().unwrap();
        let profile = parse_profile_str(profile_src, std::path::Path::new("/tmp/p.toml")).unwrap();
        let scenario = parse_scenario_str(
            SCENARIO,
            std::path::Path::new("/repo/tests/hardware"),
            "s.toml",
        )
        .unwrap();
        let p = build_plan(PlanInputs {
            lab: "default",
            scenario: &scenario,
            board: &board,
            profile: &profile,
            project: None,
            scenario_path: None,
        })
        .unwrap();
        let rendered = format!("{p}");
        assert!(!rendered.contains("topsecret-must-not-leak"), "{rendered}");
        assert!(rendered.contains("***"), "{rendered}");
        std::env::remove_var("FLUXOR_PLAN_TEST_PASS");
    }

    #[test]
    fn artifact_class_bundle_vs_file_mismatch_unresolved() {
        // Board says uf2 but project recipe is a bundle → unresolved.
        let uf2_board = r#"
            [rig]
            artifact = "uf2"
            deploy = ["deploy.uf2_mount"]
            console = ["console.usb_cdc"]
            observe = ["observe.netboot_fetch"]
            power = ["power.cycle"]
        "#;
        let uf2_profile = r#"
            [rig]
            id = "pico-a"
            board = "pico2w"

            [deploy.uf2_mount]
            mount = "/media/pi/RPI-RP2"

            [console.usb_cdc]
            device = "/dev/ttyACM0"
        "#;
        let board = parse_board_rig_str(uf2_board, "p.toml").unwrap().unwrap();
        let profile = parse_profile_str(uf2_profile, std::path::Path::new("/tmp/p.toml")).unwrap();
        // Scenario uses a deploy rule source so it doesn't matter which
        // consoles the board declares — the artifact-class mismatch is
        // what we're proving here.
        let scenario = parse_scenario_str(
            r#"
                name = "x"
                target = "pico2w"
                config = "a.yaml"
                requires = ["deploy.uf2_mount"]
                [[pass]]
                source = "observe.netboot_fetch"
            "#,
            std::path::Path::new("/repo"),
            "s.toml",
        )
        .unwrap();
        let project = parse_project_str(
            r#"[build.pico2w]
                command = ["make"]
                artifact_bundle_dir = "out"
            "#,
            std::path::Path::new("/repo"),
            "p",
        )
        .unwrap();
        let p = build_plan(PlanInputs {
            lab: "default",
            scenario: &scenario,
            board: &board,
            profile: &profile,
            project: Some(&project),
            scenario_path: None,
        })
        .unwrap();
        assert!(
            matches!(p.artifact, ArtifactPlan::Unresolved { .. }),
            "{:?}",
            p.artifact
        );
    }

    #[test]
    fn scenario_requires_pins_deploy_over_board_preferred() {
        let board_toml = r#"
            [rig]
            artifact = "kernel8_img"
            deploy = ["deploy.netboot_tftp", "deploy.bootfs_copy"]
            preferred_deploy = "deploy.netboot_tftp"
            console = ["console.serial"]
            observe = ["observe.netboot_fetch"]
            power = ["power.cycle"]
        "#;
        let profile_toml = r#"
            [rig]
            id = "pi5-a"
            board = "cm5"

            [power]
            backend = "manual"

            [deploy.netboot_tftp]
            root = "/srv/tftp"
            [deploy.bootfs_copy]
            mount = "/mnt/bootfs"

            [console.serial]
            device = "/dev/ttyUSB0"
        "#;
        let scenario_toml = r#"
            name = "forces_bootfs"
            target = "cm5"
            config = "a.yaml"
            requires = ["deploy.bootfs_copy", "power.cycle", "observe.netboot_fetch"]

            [[pass]]
            source = "observe.netboot_fetch"
        "#;
        let board = parse_board_rig_str(board_toml, "cm5.toml")
            .unwrap()
            .unwrap();
        let profile = parse_profile_str(profile_toml, std::path::Path::new("/tmp/p.toml")).unwrap();
        let scenario =
            parse_scenario_str(scenario_toml, std::path::Path::new("/repo"), "s.toml").unwrap();
        let p = build_plan(PlanInputs {
            lab: "default",
            scenario: &scenario,
            board: &board,
            profile: &profile,
            project: None,
            scenario_path: None,
        })
        .unwrap();
        assert_eq!(
            p.deploy.capability.as_str(),
            "deploy.bootfs_copy",
            "scenario.requires must win over preferred_deploy",
        );
        assert!(p.power_required);
    }

    #[test]
    fn scenario_requires_deploy_that_profile_does_not_bind_fails() {
        let board_toml = r#"
            [rig]
            artifact = "kernel8_img"
            deploy = ["deploy.netboot_tftp", "deploy.bootfs_copy"]
            console = ["console.serial"]
            power = ["power.cycle"]
        "#;
        // Profile only binds netboot_tftp.
        let profile_toml = r#"
            [rig]
            id = "pi5-a"
            board = "cm5"

            [deploy.netboot_tftp]
            root = "/srv/tftp"
        "#;
        let scenario_toml = r#"
            name = "wants_bootfs"
            target = "cm5"
            config = "a.yaml"
            requires = ["deploy.bootfs_copy"]
            [[pass]]
            source = "observe.netboot_fetch"
        "#;
        let board = parse_board_rig_str(board_toml, "cm5.toml")
            .unwrap()
            .unwrap();
        let profile = parse_profile_str(profile_toml, std::path::Path::new("/tmp/p.toml")).unwrap();
        let scenario =
            parse_scenario_str(scenario_toml, std::path::Path::new("/repo"), "s.toml").unwrap();
        let err = build_plan(PlanInputs {
            lab: "default",
            scenario: &scenario,
            board: &board,
            profile: &profile,
            project: None,
            scenario_path: None,
        })
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("deploy.bootfs_copy"), "{msg}");
        assert!(msg.contains("no [deploy.bootfs_copy] binding"), "{msg}");
    }

    #[test]
    fn scenario_requiring_power_with_no_backend_fails_at_plan_time() {
        let board_toml = r#"
            [rig]
            artifact = "kernel8_img"
            deploy = ["deploy.netboot_tftp"]
            console = ["console.serial"]
            observe = ["observe.netboot_fetch"]
            power = ["power.cycle"]
        "#;
        // No [power] section in this profile.
        let profile_toml = r#"
            [rig]
            id = "pi5-a"
            board = "cm5"

            [deploy.netboot_tftp]
            root = "/srv/tftp"

            [console.serial]
            device = "/dev/ttyUSB0"
        "#;
        let scenario_toml = r#"
            name = "needs_power"
            target = "cm5"
            config = "a.yaml"
            requires = ["deploy.netboot_tftp", "power.cycle"]
            [[pass]]
            source = "observe.netboot_fetch"
        "#;
        let board = parse_board_rig_str(board_toml, "cm5.toml")
            .unwrap()
            .unwrap();
        let profile = parse_profile_str(profile_toml, std::path::Path::new("/tmp/p.toml")).unwrap();
        let scenario =
            parse_scenario_str(scenario_toml, std::path::Path::new("/repo"), "s.toml").unwrap();
        let err = build_plan(PlanInputs {
            lab: "default",
            scenario: &scenario,
            board: &board,
            profile: &profile,
            project: None,
            scenario_path: None,
        })
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("power.cycle"), "{msg}");
        assert!(msg.contains("no [power] section"), "{msg}");
    }

    #[test]
    fn console_rule_pins_console_transport_over_board_preferred() {
        let board_toml = r#"
            [rig]
            artifact = "uf2"
            deploy = ["deploy.uf2_mount"]
            console = ["console.usb_cdc", "console.serial"]
            preferred_console = "console.usb_cdc"
            observe = ["observe.usb_enumeration"]
            power = ["power.cycle"]
        "#;
        let profile_toml = r#"
            [rig]
            id = "pico-a"
            board = "pico2w"

            [deploy.uf2_mount]
            mount = "/media/pi/RPI-RP2"

            [console.usb_cdc]
            device = "/dev/ttyACM0"

            [console.serial]
            device = "/dev/ttyUSB0"
        "#;
        let scenario_toml = r#"
            name = "needs_serial"
            target = "pico2w"
            config = "a.yaml"

            [[pass]]
            source = "console.serial"
            regex = "ok"
        "#;
        let board = parse_board_rig_str(board_toml, "pico2w.toml")
            .unwrap()
            .unwrap();
        let profile = parse_profile_str(profile_toml, std::path::Path::new("/tmp/p.toml")).unwrap();
        let scenario =
            parse_scenario_str(scenario_toml, std::path::Path::new("/repo"), "s.toml").unwrap();
        let p = build_plan(PlanInputs {
            lab: "default",
            scenario: &scenario,
            board: &board,
            profile: &profile,
            project: None,
            scenario_path: None,
        })
        .unwrap();
        let caps: Vec<&str> = p.consoles.iter().map(|c| c.capability.as_str()).collect();
        assert!(
            caps.contains(&"console.serial"),
            "plan must attach console.serial when a rule names it (got {caps:?})",
        );
        assert_eq!(
            p.consoles.len(),
            1,
            "plan attached unexpected extras: {caps:?}"
        );
    }

    #[test]
    fn scenario_agnostic_default_honours_preferred_console() {
        // The board lists `console.serial` first but declares
        // `console.usb_cdc` as preferred; default selection must pick
        // the preferred capability, not the first list entry.
        let board_toml = r#"
            [rig]
            artifact = "uf2"
            deploy = ["deploy.uf2_mount"]
            console = ["console.serial", "console.usb_cdc"]
            preferred_console = "console.usb_cdc"
            observe = ["observe.netboot_fetch"]
            power = ["power.cycle"]
        "#;
        let profile_toml = r#"
            [rig]
            id = "pico-a"
            board = "pico2w"

            [deploy.uf2_mount]
            mount = "/mnt/x"

            [console.serial]
            device = "/dev/ttyUSB0"

            [console.usb_cdc]
            device = "/dev/ttyACM0"
        "#;
        // Scenario is console-agnostic — its only rule is an
        // observe.netboot_fetch — so pick_consoles takes the
        // default-selection path.
        let scenario_toml = r#"
            name = "agnostic"
            target = "pico2w"
            config = "a.yaml"
            [[pass]]
            source = "observe.netboot_fetch"
        "#;
        let board = parse_board_rig_str(board_toml, "pico2w.toml")
            .unwrap()
            .unwrap();
        let profile = parse_profile_str(profile_toml, std::path::Path::new("/tmp/p.toml")).unwrap();
        let scenario =
            parse_scenario_str(scenario_toml, std::path::Path::new("/repo"), "s.toml").unwrap();
        let p = build_plan(PlanInputs {
            lab: "default",
            scenario: &scenario,
            board: &board,
            profile: &profile,
            project: None,
            scenario_path: None,
        })
        .unwrap();
        assert_eq!(p.consoles.len(), 1);
        assert_eq!(
            p.consoles[0].capability.as_str(),
            "console.usb_cdc",
            "default selection must honour preferred_console, not list order",
        );
    }

    #[test]
    fn scenario_agnostic_default_honours_preferred_telemetry() {
        // `preferred_telemetry` is authoritative for default selection
        // the same way `preferred_console` is. The vocabulary defines
        // only one telemetry capability today, so this test proves the
        // preferred field is consulted at all.
        let board_toml = r#"
            [rig]
            artifact = "kernel8_img"
            deploy = ["deploy.netboot_tftp"]
            console = ["console.serial"]
            telemetry = ["telemetry.monitor_udp"]
            preferred_telemetry = "telemetry.monitor_udp"
            observe = ["observe.netboot_fetch"]
            power = ["power.cycle"]
        "#;
        let profile_toml = r#"
            [rig]
            id = "pi5-a"
            board = "cm5"

            [deploy.netboot_tftp]
            root = "/srv/tftp"

            [console.serial]
            device = "/dev/ttyUSB0"

            [telemetry.monitor_udp]
            bind = "0.0.0.0:6666"
        "#;
        let scenario_toml = r#"
            name = "agnostic"
            target = "cm5"
            config = "a.yaml"
            [[pass]]
            source = "observe.netboot_fetch"
        "#;
        let board = parse_board_rig_str(board_toml, "cm5.toml")
            .unwrap()
            .unwrap();
        let profile = parse_profile_str(profile_toml, std::path::Path::new("/tmp/p.toml")).unwrap();
        let scenario =
            parse_scenario_str(scenario_toml, std::path::Path::new("/repo"), "s.toml").unwrap();
        let p = build_plan(PlanInputs {
            lab: "default",
            scenario: &scenario,
            board: &board,
            profile: &profile,
            project: None,
            scenario_path: None,
        })
        .unwrap();
        let t = p.telemetry.expect("telemetry selection");
        assert_eq!(t.capability.as_str(), "telemetry.monitor_udp");
    }

    // ── power-verb derivation ─────────────────────────────────────────────

    fn scn_with_requires(requires_literal: &str) -> Scenario {
        let src = format!(
            r#"
                name = "x"
                target = "cm5"
                config = "a.yaml"
                requires = [{requires_literal}]
                [[pass]]
                source = "observe.netboot_fetch"
            "#,
        );
        parse_scenario_str(&src, std::path::Path::new("/repo"), "s.toml").unwrap()
    }

    #[test]
    fn power_verb_defaults_to_cycle_when_backend_present_and_scenario_silent() {
        let s = scn_with_requires(r#""deploy.netboot_tftp""#);
        assert_eq!(derive_power_actions(&s, true), vec!["cycle"]);
    }

    #[test]
    fn power_verb_empty_when_no_backend_and_scenario_silent() {
        let s = scn_with_requires(r#""deploy.netboot_tftp""#);
        assert_eq!(derive_power_actions(&s, false), Vec::<&str>::new());
    }

    #[test]
    fn power_verb_cycle_subsumes_on_and_off() {
        // `power.cycle` subsumes on+off — when it's in `requires`, it's
        // the only verb the orchestrator invokes.
        let s = scn_with_requires(r#""power.cycle", "power.on", "power.off""#);
        assert_eq!(derive_power_actions(&s, true), vec!["cycle"]);
    }

    #[test]
    fn power_verb_on_only_invokes_on_not_cycle() {
        let s = scn_with_requires(r#""power.on""#);
        assert_eq!(derive_power_actions(&s, true), vec!["on"]);
    }

    #[test]
    fn power_verb_off_only_invokes_off_not_cycle() {
        let s = scn_with_requires(r#""power.off""#);
        assert_eq!(derive_power_actions(&s, true), vec!["off"]);
    }

    #[test]
    fn power_verb_on_and_off_in_listed_order() {
        // Explicit cold-start sequence: listing off then on invokes in
        // declared order.
        let s = scn_with_requires(r#""power.off", "power.on""#);
        assert_eq!(derive_power_actions(&s, true), vec!["off", "on"]);
    }

    #[test]
    fn power_verb_plan_surfaces_actions() {
        // End-to-end: a scenario with `power.on` only flows through to
        // `Plan::power_actions`.
        let board_toml = r#"
            [rig]
            artifact = "kernel8_img"
            deploy = ["deploy.netboot_tftp"]
            console = ["console.serial"]
            observe = ["observe.netboot_fetch"]
            power = ["power.on"]
        "#;
        let profile_toml = r#"
            [rig]
            id = "pi5-a"
            board = "cm5"

            [power]
            backend = "manual"

            [deploy.netboot_tftp]
            root = "/srv/tftp"

            [console.serial]
            device = "/dev/ttyUSB0"
        "#;
        let scenario_toml = r#"
            name = "cold_start"
            target = "cm5"
            config = "a.yaml"
            requires = ["deploy.netboot_tftp", "power.on", "observe.netboot_fetch"]
            [[pass]]
            source = "observe.netboot_fetch"
        "#;
        let board = parse_board_rig_str(board_toml, "cm5.toml")
            .unwrap()
            .unwrap();
        let profile = parse_profile_str(profile_toml, std::path::Path::new("/tmp/p.toml")).unwrap();
        let scenario =
            parse_scenario_str(scenario_toml, std::path::Path::new("/repo"), "s.toml").unwrap();
        let p = build_plan(PlanInputs {
            lab: "default",
            scenario: &scenario,
            board: &board,
            profile: &profile,
            project: None,
            scenario_path: None,
        })
        .unwrap();
        assert_eq!(p.power_actions, vec!["on"]);
        assert!(p.power_required);
    }
}
