//! Cross-schema validator: scenario requirements vs. the target board's
//! declared rig capabilities. RFC §7.1 final paragraph — "fail at parse/plan
//! time, not after starting orchestration."

use crate::rig::board::BoardRig;
use crate::rig::matcher::supports_rule_source;
use crate::rig::scenario::{ObservationRule, Scenario};
use crate::rig::vocab::{Capability, Surface};

#[derive(Debug, Default)]
pub struct RigValidation {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl RigValidation {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validate a scenario against the declared capabilities of its target board.
///
/// Returns collected errors rather than short-circuiting — callers typically
/// want to show every issue in one pass so operators don't have to fix,
/// rerun, fix, rerun.
pub fn validate_scenario_against_board(s: &Scenario, board: &BoardRig) -> RigValidation {
    let mut v = RigValidation::default();

    // 1. scenario.target is advisory here — the caller already picked which
    //    board to validate against. We don't re-check the match.

    // 2. Every capability in scenario.requires must be supported by the board.
    for (i, cap) in s.requires.iter().enumerate() {
        if !board.supports(*cap) {
            v.errors.push(format!(
                "scenario '{}': requires[{}] = '{}' — board does not declare this capability \
                 in its [rig] section. Either the scenario is wrong about what this board can do, \
                 or the board descriptor needs to be extended.",
                s.name,
                i,
                cap.as_str()
            ));
        }
    }

    // 3. Every rule source must live on a transport the board declares.
    check_rules("pass", &s.pass, board, s, &mut v);
    check_rules("fail", &s.fail, board, s, &mut v);

    // 4. At least one pass rule is needed to know what success means.
    if s.pass.is_empty() {
        v.warnings.push(format!(
            "scenario '{}': no [[pass]] rules declared — runs can only fail, never pass",
            s.name
        ));
    }

    // 5. Timeout sanity.
    if let Some(t) = s.timeout_s {
        if t == 0 {
            v.errors.push(format!(
                "scenario '{}': timeout_s = 0 would never allow a pass",
                s.name
            ));
        }
    } else if board.default_timeout_s.is_none() {
        v.warnings.push(format!(
            "scenario '{}': no timeout_s and board has no default_timeout_s",
            s.name
        ));
    }

    v
}

/// Cross-check rig tags declared by the scenario against tags declared by a
/// rig profile. RFC §8: "a scenario that asks for ['nvme'] must not silently
/// fall onto a rig that lacks that tag."
///
/// Omitting requires_tags (empty list) means any rig is eligible.
pub fn validate_tags(s: &Scenario, rig_tags: &[String]) -> RigValidation {
    let mut v = RigValidation::default();
    for tag in &s.requires_tags {
        if !rig_tags.iter().any(|t| t == tag) {
            v.errors.push(format!(
                "scenario '{}': requires_tags contains '{}' but selected rig does not carry it \
                 (rig tags: {:?})",
                s.name, tag, rig_tags
            ));
        }
    }
    v
}

fn check_rules(
    kind: &str,
    rules: &[ObservationRule],
    board: &BoardRig,
    s: &Scenario,
    v: &mut RigValidation,
) {
    for (i, r) in rules.iter().enumerate() {
        // Every rule source must be one the matcher can actually evaluate.
        // The vocabulary lists capabilities that are legal to declare on a
        // board but not every one of them has an orchestrator pipeline yet.
        if !supports_rule_source(r.source) {
            v.errors.push(format!(
                "scenario '{}': [[{}]][{}] source = '{}' — this capability is in the \
                 vocabulary but the matcher has no evaluator for it yet. Supported rule \
                 sources: any `console.*` (regex on the console byte stream) and \
                 `observe.netboot_fetch`.",
                s.name,
                kind,
                i,
                r.source.as_str(),
            ));
            continue;
        }
        // Every rule source must correspond to a transport the board
        // actually provides. For observe.* sources the board's observe list
        // is the gate; for console.*/telemetry.* the matching transport list.
        let supported = board.supports(r.source);
        if !supported {
            v.errors.push(format!(
                "scenario '{}': [[{}]][{}] source = '{}' but board does not declare this \
                 capability under its [rig].{} list",
                s.name,
                kind,
                i,
                r.source.as_str(),
                surface_field_name(r.source)
            ));
        }
    }
}

fn surface_field_name(c: Capability) -> &'static str {
    match c.surface() {
        Surface::Power => "power",
        Surface::Deploy => "deploy",
        Surface::Console => "console",
        Surface::Telemetry => "telemetry",
        Surface::Observe => "observe",
        Surface::Rig => "(rig)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rig::board::parse_board_rig_str;
    use crate::rig::scenario::parse_scenario_str;
    use std::path::Path;

    const CM5: &str = r#"
        [rig]
        artifact = "boot_bundle"
        deploy = ["deploy.netboot_tftp"]
        preferred_deploy = "deploy.netboot_tftp"
        console = ["console.serial"]
        telemetry = ["telemetry.monitor_udp"]
        observe = ["observe.console_regex", "observe.netboot_fetch", "observe.monitor_stream"]
        power = ["power.cycle"]
        default_timeout_s = 30
    "#;

    fn load_cm5() -> BoardRig {
        parse_board_rig_str(CM5, "cm5.toml").unwrap().unwrap()
    }

    fn scn(src: &str) -> Scenario {
        parse_scenario_str(src, Path::new("/repo"), "x.toml").unwrap()
    }

    #[test]
    fn matching_scenario_passes() {
        let s = scn(r#"
            name = "ok"
            target = "cm5"
            config = "a.yaml"
            requires = ["deploy.netboot_tftp", "power.cycle"]
            timeout_s = 20

            [[pass]]
            source = "console.serial"
            regex = "ok"
        "#);
        let v = validate_scenario_against_board(&s, &load_cm5());
        assert!(v.is_ok(), "errors: {:?}", v.errors);
    }

    #[test]
    fn missing_capability_fails() {
        let s = scn(r#"
            name = "needs_uf2"
            target = "cm5"
            config = "a.yaml"
            requires = ["deploy.uf2_mount"]

            [[pass]]
            source = "console.serial"
            regex = "ok"
        "#);
        let v = validate_scenario_against_board(&s, &load_cm5());
        assert!(!v.is_ok());
        assert!(v.errors[0].contains("deploy.uf2_mount"));
    }

    #[test]
    fn rule_source_must_be_declared() {
        // Pick a source that is NOT in the cm5 fixture's declarations so
        // this test exercises the board-gate (not the matcher-support
        // gate).
        let s = scn(r#"
            name = "x"
            target = "cm5"
            config = "a.yaml"

            [[pass]]
            source = "console.usb_cdc"
            regex = "."
        "#);
        let v = validate_scenario_against_board(&s, &load_cm5());
        assert!(!v.is_ok());
        assert!(v.errors[0].contains("console.usb_cdc"));
    }

    #[test]
    fn rule_source_unsupported_by_matcher_fails_at_plan_time() {
        // `observe.monitor_stream` is declared by the board but has no
        // matcher evaluator; the scenario must fail at validation.
        let s = scn(r#"
            name = "monitor_stream_scenario"
            target = "cm5"
            config = "a.yaml"

            [[pass]]
            source = "observe.monitor_stream"
            regex = "."
        "#);
        let v = validate_scenario_against_board(&s, &load_cm5());
        assert!(!v.is_ok());
        let msg = &v.errors[0];
        assert!(msg.contains("observe.monitor_stream"), "{msg}");
        assert!(msg.contains("matcher has no evaluator"), "{msg}");
    }

    #[test]
    fn telemetry_rule_source_fails_at_plan_time() {
        // Same gate as the observe.monitor_stream case — telemetry
        // sources aren't evaluated by the matcher.
        let s = scn(r#"
            name = "telemetry_scenario"
            target = "cm5"
            config = "a.yaml"

            [[pass]]
            source = "telemetry.monitor_udp"
            regex = "."
        "#);
        let v = validate_scenario_against_board(&s, &load_cm5());
        assert!(!v.is_ok());
        assert!(v.errors[0].contains("matcher has no evaluator"));
    }

    #[test]
    fn missing_pass_rules_warns() {
        let s = scn(r#"
            name = "x"
            target = "cm5"
            config = "a.yaml"
        "#);
        let v = validate_scenario_against_board(&s, &load_cm5());
        assert!(v.is_ok());
        assert!(v.warnings.iter().any(|w| w.contains("no [[pass]]")));
    }

    #[test]
    fn zero_timeout_fails() {
        let s = scn(r#"
            name = "x"
            target = "cm5"
            config = "a.yaml"
            timeout_s = 0

            [[pass]]
            source = "console.serial"
            regex = "."
        "#);
        let v = validate_scenario_against_board(&s, &load_cm5());
        assert!(!v.is_ok());
    }

    #[test]
    fn tag_mismatch_fails() {
        let s = scn(r#"
            name = "x"
            target = "cm5"
            config = "a.yaml"
            requires_tags = ["nvme"]
        "#);
        let rig_tags: Vec<String> = vec!["basic".into()];
        let v = validate_tags(&s, &rig_tags);
        assert!(!v.is_ok());
    }

    #[test]
    fn empty_tags_match_anything() {
        let s = scn(r#"
            name = "x"
            target = "cm5"
            config = "a.yaml"
        "#);
        let rig_tags: Vec<String> = vec![];
        let v = validate_tags(&s, &rig_tags);
        assert!(v.is_ok());
    }

    /// Guard against the in-tree board descriptor and example scenario
    /// drifting out of sync.
    #[test]
    fn real_cm5_scenario_validates() {
        use crate::rig::{load_scenario, resolve_board_rig};
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let scenario = load_scenario(&workspace.join("tests/hardware/cm5_boot_banner.toml"))
            .expect("load scenario");
        let (board, _source) =
            resolve_board_rig(&scenario.target, Some(workspace)).expect("resolve board");
        let board = board.expect("cm5 should declare [rig]");
        let v = validate_scenario_against_board(&scenario, &board);
        assert!(v.is_ok(), "errors: {:?}", v.errors);
    }
}
