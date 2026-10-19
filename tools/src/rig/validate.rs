//! Cross-schema validators: scenario requirements vs. the target board's
//! declared rig capabilities, and the private profile vs. the board's
//! secret rules. Every failure is raised at parse and plan time, never
//! after orchestration has started.

use crate::rig::board::BoardRig;
use crate::rig::matcher::supports_rule_source;
use crate::rig::profile::{BindingValue, RigProfile};
use crate::rig::scenario::{ExpectRule, ObservationRule, Scenario};
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
    check_expects(&s.expect, board, s, &mut v);

    // 4. At least one pass rule is needed to know what success means.
    if s.pass.is_empty() {
        v.warnings.push(format!(
            "scenario '{}': no [[pass]] rules declared — runs can only fail, never pass",
            s.name
        ));
    }

    // 5. Timeout sanity.
    let effective_timeout = s.timeout_s.or(board.default_timeout_s);
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
    if let Some(t) = effective_timeout {
        for (i, e) in s.expect.iter().enumerate() {
            if let Some(w) = e.within_s {
                if w > t {
                    v.errors.push(format!(
                        "scenario '{}': [[expect]][{i}] within_s = {w} exceeds the run's \
                         timeout ({t}s) — the run would time out before the expectation \
                         could fail by itself",
                        s.name
                    ));
                }
            }
        }
    }

    // 6. The kernel's heartbeat comes every 30 s; a tighter silence bound on
    //    a scenario that waits for it fails a healthy board.
    let waits_for_heartbeat = s
        .pass
        .iter()
        .chain(s.fail.iter())
        .filter_map(|r| r.regex.as_deref())
        .any(|p| p.contains("sched") && p.contains("alive"));
    if waits_for_heartbeat {
        for (i, e) in s.expect.iter().enumerate() {
            if let Some(ms) = e.max_silence_s {
                if ms < 35 {
                    v.warnings.push(format!(
                        "scenario '{}': [[expect]][{i}] max_silence_s = {ms} is shorter than \
                         the 30 s heartbeat the scenario waits for; a quiet but healthy board \
                         would fail it",
                        s.name
                    ));
                }
            }
        }
    }

    v
}

/// Cross-check rig tags declared by the scenario against tags declared by a
/// rig profile: a scenario that asks for `['nvme']` must not silently fall
/// onto a rig that lacks that tag.
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

/// The board's rules for the profile's `[build_env]`:
///
///   * every key in `build_env_required` must be present;
///   * every key in `build_env_secret` must be an indirection, never a
///     literal in the file;
///   * on a board whose image leaves the host (`image_leaves_host`), no
///     secret may enter the build at all — a Wi-Fi PSK must never become
///     a disk image that is uploaded somewhere.
pub fn check_profile_against_board(profile: &RigProfile, board: &BoardRig) -> RigValidation {
    let mut v = RigValidation::default();
    for key in &board.build_env_required {
        if !profile.build_env.contains_key(key) {
            v.errors.push(format!(
                "profile '{}': board '{}' needs [build_env].{key} and the profile does not \
                 set it",
                profile.rig.id, profile.rig.board
            ));
        }
    }
    for key in &board.build_env_secret {
        if let Some(BindingValue::Secret(s)) = profile.build_env.get(key) {
            if !s.is_secret() {
                v.errors.push(format!(
                    "profile '{}': [build_env].{key} is a secret on board '{}' and must be \
                     written as an indirection (`${{file:/abs/path}}` or `${{env:NAME}}`), \
                     not as a literal",
                    profile.rig.id, profile.rig.board
                ));
            }
        }
    }
    if board.image_leaves_host {
        for (key, value) in profile.build_env.iter() {
            let is_secret = board.build_env_secret.contains(key)
                || matches!(value, BindingValue::Secret(s) if s.is_secret());
            if is_secret {
                v.errors.push(format!(
                    "profile '{}': [build_env].{key} is a secret, and board '{}' builds \
                     images that leave this host — a secret must not be built into them",
                    profile.rig.id, profile.rig.board
                ));
            }
        }
    }
    v
}

fn check_source(
    kind: &str,
    i: usize,
    source: Capability,
    board: &BoardRig,
    s: &Scenario,
    v: &mut RigValidation,
) {
    // Every rule source must be one the matcher can actually evaluate.
    // The vocabulary lists capabilities that are legal to declare on a
    // board but not every one of them has an orchestrator pipeline yet.
    if !supports_rule_source(source) {
        v.errors.push(format!(
            "scenario '{}': [[{}]][{}] source = '{}' — this capability is in the \
             vocabulary but the matcher has no evaluator for it yet. Supported rule \
             sources: any `console.*` or `telemetry.*` (regex on the per-source \
             byte stream) and `observe.netboot_fetch`.",
            s.name,
            kind,
            i,
            source.as_str(),
        ));
        return;
    }
    // Every rule source must correspond to a transport the board
    // actually provides. For observe.* sources the board's observe list
    // is the gate; for console.*/telemetry.* the matching transport list.
    if !board.supports(source) {
        v.errors.push(format!(
            "scenario '{}': [[{}]][{}] source = '{}' but board does not declare this \
             capability under its [rig].{} list",
            s.name,
            kind,
            i,
            source.as_str(),
            surface_field_name(source)
        ));
    }
}

fn check_rules(
    kind: &str,
    rules: &[ObservationRule],
    board: &BoardRig,
    s: &Scenario,
    v: &mut RigValidation,
) {
    for (i, r) in rules.iter().enumerate() {
        check_source(kind, i, r.source, board, s, v);
    }
}

fn check_expects(rules: &[ExpectRule], board: &BoardRig, s: &Scenario, v: &mut RigValidation) {
    for (i, r) in rules.iter().enumerate() {
        check_source("expect", i, r.source, board, s, v);
        if r.source.as_str() == "observe.netboot_fetch" && r.max_silence_s.is_some() {
            v.errors.push(format!(
                "scenario '{}': [[expect]][{i}] max_silence_s on observe.netboot_fetch — a \
                 fetch is an event, not a byte stream, so it has no silence",
                s.name
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
    use crate::rig::profile::parse_profile_str;
    use crate::rig::scenario::parse_scenario_str;
    use std::path::Path;

    const PI5: &str = r#"
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

    fn load_pi5() -> BoardRig {
        parse_board_rig_str(PI5, "pi5.toml").unwrap().unwrap()
    }

    fn scn(src: &str) -> Scenario {
        parse_scenario_str(src, Path::new("/repo"), "x.toml").unwrap()
    }

    #[test]
    fn matching_scenario_passes() {
        let s = scn(r#"
            name = "ok"
            target = "pi5"
            config = "a.yaml"
            requires = ["deploy.netboot_tftp", "power.cycle"]
            timeout_s = 20

            [[pass]]
            source = "console.serial"
            regex = "ok"
        "#);
        let v = validate_scenario_against_board(&s, &load_pi5());
        assert!(v.is_ok(), "errors: {:?}", v.errors);
    }

    #[test]
    fn missing_capability_fails() {
        let s = scn(r#"
            name = "needs_uf2"
            target = "pi5"
            config = "a.yaml"
            requires = ["deploy.uf2_mount"]

            [[pass]]
            source = "console.serial"
            regex = "ok"
        "#);
        let v = validate_scenario_against_board(&s, &load_pi5());
        assert!(!v.is_ok());
        assert!(v.errors[0].contains("deploy.uf2_mount"));
    }

    #[test]
    fn rule_source_must_be_declared() {
        // Pick a source that is NOT in the pi5 fixture's declarations so
        // this test exercises the board-gate (not the matcher-support
        // gate).
        let s = scn(r#"
            name = "x"
            target = "pi5"
            config = "a.yaml"

            [[pass]]
            source = "console.usb_cdc"
            regex = "."
        "#);
        let v = validate_scenario_against_board(&s, &load_pi5());
        assert!(!v.is_ok());
        assert!(v.errors[0].contains("console.usb_cdc"));
    }

    #[test]
    fn rule_source_unsupported_by_matcher_fails_at_plan_time() {
        // `observe.monitor_stream` is declared by the board but has no
        // matcher evaluator; the scenario must fail at validation.
        let s = scn(r#"
            name = "monitor_stream_scenario"
            target = "pi5"
            config = "a.yaml"

            [[pass]]
            source = "observe.monitor_stream"
            regex = "."
        "#);
        let v = validate_scenario_against_board(&s, &load_pi5());
        assert!(!v.is_ok());
        let msg = &v.errors[0];
        assert!(msg.contains("observe.monitor_stream"), "{msg}");
        assert!(msg.contains("matcher has no evaluator"), "{msg}");
    }

    #[test]
    fn telemetry_rule_source_is_supported() {
        // `telemetry.*` shares the byte-stream evaluator with `console.*`
        // (the transport tags incoming bytes with the qualified
        // capability). A scenario whose pass rule names a telemetry
        // capability the board declares must validate cleanly.
        let s = scn(r#"
            name = "telemetry_scenario"
            target = "pi5"
            config = "a.yaml"
            requires = ["deploy.netboot_tftp", "power.cycle", "telemetry.monitor_udp"]

            [[pass]]
            source = "telemetry.monitor_udp"
            regex = "."
        "#);
        let v = validate_scenario_against_board(&s, &load_pi5());
        assert!(v.is_ok(), "errors: {:?}", v.errors);
    }

    #[test]
    fn missing_pass_rules_warns() {
        let s = scn(r#"
            name = "x"
            target = "pi5"
            config = "a.yaml"
        "#);
        let v = validate_scenario_against_board(&s, &load_pi5());
        assert!(v.is_ok());
        assert!(v.warnings.iter().any(|w| w.contains("no [[pass]]")));
    }

    #[test]
    fn zero_timeout_fails() {
        let s = scn(r#"
            name = "x"
            target = "pi5"
            config = "a.yaml"
            timeout_s = 0

            [[pass]]
            source = "console.serial"
            regex = "."
        "#);
        let v = validate_scenario_against_board(&s, &load_pi5());
        assert!(!v.is_ok());
    }

    #[test]
    fn expect_rules_are_gated_like_pass_rules_and_bounded_by_the_timeout() {
        let s = scn(r#"
            name = "x"
            target = "pi5"
            config = "a.yaml"
            timeout_s = 20

            [[pass]]
            source = "console.serial"
            regex = "ok"

            [[expect]]
            source = "console.usb_cdc"
            regex = "stage"
            within_s = 5

            [[expect]]
            source = "console.serial"
            regex = "stage"
            within_s = 25
        "#);
        let v = validate_scenario_against_board(&s, &load_pi5());
        assert!(!v.is_ok());
        assert!(
            v.errors
                .iter()
                .any(|e| e.contains("[[expect]][0]") && e.contains("console.usb_cdc")),
            "{:?}",
            v.errors
        );
        assert!(
            v.errors
                .iter()
                .any(|e| e.contains("[[expect]][1]") && e.contains("exceeds the run's timeout")),
            "{:?}",
            v.errors
        );
    }

    #[test]
    fn short_silence_bound_on_a_heartbeat_scenario_warns() {
        let s = scn(r#"
            name = "x"
            target = "pi5"
            config = "a.yaml"
            timeout_s = 120

            [[pass]]
            source = "console.serial"
            regex = "\\[sched\\] alive"

            [[expect]]
            source = "console.serial"
            max_silence_s = 10
        "#);
        let v = validate_scenario_against_board(&s, &load_pi5());
        assert!(v.is_ok(), "{:?}", v.errors);
        assert!(
            v.warnings.iter().any(|w| w.contains("heartbeat")),
            "{:?}",
            v.warnings
        );
    }

    #[test]
    fn tag_mismatch_fails() {
        let s = scn(r#"
            name = "x"
            target = "pi5"
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
            target = "pi5"
            config = "a.yaml"
        "#);
        let rig_tags: Vec<String> = vec![];
        let v = validate_tags(&s, &rig_tags);
        assert!(v.is_ok());
    }

    const PICO_BOARD: &str = r#"
        [rig]
        artifact = "uf2"
        deploy = ["deploy.picotool"]
        console = ["console.usb_cdc"]
        power = ["power.cycle", "power.off"]
        build_env_required = ["WIFI_SSID"]
        build_env_secret = ["WIFI_PASSWORD"]
    "#;

    #[test]
    fn profile_missing_required_build_env_key_fails() {
        let board = parse_board_rig_str(PICO_BOARD, "pico2w.toml")
            .unwrap()
            .unwrap();
        let profile = parse_profile_str(
            r#"
            [rig]
            id = "pico2w-a"
            board = "pico2w"
            "#,
            Path::new("/tmp/p.toml"),
        )
        .unwrap();
        let v = check_profile_against_board(&profile, &board);
        assert!(
            v.errors.iter().any(|e| e.contains("WIFI_SSID")),
            "{:?}",
            v.errors
        );
    }

    #[test]
    fn profile_with_indirected_secret_passes_and_image_leaving_board_refuses_it() {
        std::env::set_var("RIG_VALIDATE_PSK", "x");
        let profile = parse_profile_str(
            r#"
            [rig]
            id = "pico2w-a"
            board = "pico2w"
            [build_env]
            WIFI_SSID = "bench"
            WIFI_PASSWORD = "${env:RIG_VALIDATE_PSK}"
            "#,
            Path::new("/tmp/p.toml"),
        )
        .unwrap();
        let board = parse_board_rig_str(PICO_BOARD, "pico2w.toml")
            .unwrap()
            .unwrap();
        assert!(check_profile_against_board(&profile, &board).is_ok());

        let leaving = parse_board_rig_str(
            &format!("{PICO_BOARD}\n        image_leaves_host = true\n"),
            "ec2.toml",
        )
        .unwrap()
        .unwrap();
        let v = check_profile_against_board(&profile, &leaving);
        assert!(
            v.errors.iter().any(|e| e.contains("leave this host")),
            "{:?}",
            v.errors
        );
        std::env::remove_var("RIG_VALIDATE_PSK");
    }

    /// Guard against the in-tree board descriptor and example scenario
    /// drifting out of sync.
    #[test]
    fn real_pi5_scenario_validates() {
        use crate::rig::{load_scenario, resolve_board_rig};
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let scenario = load_scenario(&workspace.join("tests/hardware/pi5_boot_banner.toml"))
            .expect("load scenario");
        let (board, _source) =
            resolve_board_rig(&scenario.target, Some(workspace)).expect("resolve board");
        let board = board.expect("pi5 should declare [rig]");
        let v = validate_scenario_against_board(&scenario, &board);
        assert!(v.is_ok(), "errors: {:?}", v.errors);
    }
}
