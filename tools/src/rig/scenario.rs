//! Public scenario contract — `tests/hardware/*.toml`.
//!
//! A scenario describes validation intent (what board under test,
//! what config, which capabilities it needs, and the pass/fail rules). Paths
//! inside a scenario are anchored to the scenario file's directory,
//! so scenarios are portable across projects that share the rig harness.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::rig::vocab::{Capability, Surface};

#[derive(Debug, Clone)]
pub struct Scenario {
    pub name: String,
    pub target: String,
    /// Resolved absolute path to the config/example under test.
    pub config: PathBuf,
    pub requires: Vec<Capability>,
    pub requires_tags: Vec<String>,
    pub timeout_s: Option<u32>,
    pub pass: Vec<ObservationRule>,
    pub fail: Vec<ObservationRule>,
    /// Deadlines: what must have appeared by when, and how long a source
    /// may stay silent. A missed expectation fails the run and names
    /// itself, so a timeout says where the boot stopped.
    pub expect: Vec<ExpectRule>,
    /// Directory the scenario was loaded from. Exposed so callers resolving
    /// additional relative paths use the same anchor.
    pub scenario_dir: PathBuf,
    /// Absolute path to the scenario file itself, when the scenario was
    /// loaded from disk: the run record's `scenario_sha256` is the hash of
    /// its bytes. Populated only by [`load_scenario`]; string-based parsing
    /// leaves it `None`.
    pub source_path: Option<PathBuf>,
}

/// Every rule names a transport `source` and a match condition: a regex
/// over the source's byte stream, or, for `observe.netboot_fetch`, over
/// the fetched filename (where a rule without one matches any fetch).
#[derive(Debug, Clone)]
pub struct ObservationRule {
    pub source: Capability,
    pub regex: Option<String>,
}

/// An `[[expect]]` entry. Two shapes, which may be combined:
///
///   * `regex` + `within_s`: the line must appear within `within_s` of the
///     anchor (the end of the power step, or the source's own fresh boot
///     if that is later);
///   * `max_silence_s`: once the source has produced its first byte, it may
///     never go quiet for longer than this.
#[derive(Debug, Clone)]
pub struct ExpectRule {
    pub source: Capability,
    pub regex: Option<String>,
    pub within_s: Option<u32>,
    pub max_silence_s: Option<u32>,
}

// ── TOML deserialization ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ScenarioFile {
    name: String,
    target: String,
    config: String,
    #[serde(default)]
    requires: Vec<String>,
    #[serde(default)]
    requires_tags: Vec<String>,
    timeout_s: Option<u32>,
    #[serde(default)]
    pass: Vec<RuleToml>,
    #[serde(default)]
    fail: Vec<RuleToml>,
    #[serde(default)]
    expect: Vec<ExpectToml>,
}

#[derive(Deserialize)]
struct RuleToml {
    source: String,
    regex: Option<String>,
}

#[derive(Deserialize)]
struct ExpectToml {
    source: String,
    regex: Option<String>,
    within_s: Option<u32>,
    max_silence_s: Option<u32>,
}

pub fn load_scenario(path: &Path) -> Result<Scenario> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("rig: reading scenario {}: {}", path.display(), e)))?;
    let scenario_dir = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let mut scenario = parse_scenario_str(&raw, &scenario_dir, &path.display().to_string())?;
    scenario.source_path = Some(path.to_path_buf());
    Ok(scenario)
}

pub fn parse_scenario_str(raw: &str, scenario_dir: &Path, ctx: &str) -> Result<Scenario> {
    let s: ScenarioFile = toml::from_str(raw)?;

    // Scenario-relative paths are anchored to the scenario file's
    // directory. Absolute paths pass through unchanged.
    let config_path = PathBuf::from(&s.config);
    let config = if config_path.is_absolute() {
        config_path
    } else {
        scenario_dir.join(&config_path)
    };

    let requires = parse_requires(&s.requires, ctx)?;

    let pass = parse_rules(&s.pass, ctx, "pass")?;
    let fail = parse_rules(&s.fail, ctx, "fail")?;
    let expect = parse_expects(&s.expect, ctx)?;

    Ok(Scenario {
        name: s.name,
        target: s.target,
        config,
        requires,
        requires_tags: s.requires_tags,
        timeout_s: s.timeout_s,
        pass,
        fail,
        expect,
        scenario_dir: scenario_dir.to_path_buf(),
        source_path: None,
    })
}

fn parse_requires(values: &[String], ctx: &str) -> Result<Vec<Capability>> {
    let mut out = Vec::with_capacity(values.len());
    for (i, s) in values.iter().enumerate() {
        let cap = Capability::parse(s)
            .map_err(|e| Error::Config(format!("{ctx}: requires[{i}]: {e}")))?;
        out.push(cap);
    }
    Ok(out)
}

fn parse_rule_source(source: &str, ctx: &str, kind: &str, i: usize) -> Result<Capability> {
    let source = Capability::parse(source)
        .map_err(|e| Error::Config(format!("{ctx}: [[{kind}]][{i}].source: {e}")))?;
    // Only transports that can produce observable bytes are valid rule
    // sources. Power and rig-coordination surfaces cannot.
    match source.surface() {
        Surface::Console | Surface::Telemetry | Surface::Observe => Ok(source),
        other => Err(Error::Config(format!(
            "{ctx}: [[{kind}]][{i}].source: '{}' is a '{}' capability; \
             only console/telemetry/observe sources may appear in rules",
            source.as_str(),
            other.as_str()
        ))),
    }
}

fn parse_rules(rules: &[RuleToml], ctx: &str, kind: &str) -> Result<Vec<ObservationRule>> {
    let mut out = Vec::with_capacity(rules.len());
    for (i, r) in rules.iter().enumerate() {
        let source = parse_rule_source(&r.source, ctx, kind, i)?;
        out.push(ObservationRule {
            source,
            regex: r.regex.clone(),
        });
    }
    Ok(out)
}

fn parse_expects(rules: &[ExpectToml], ctx: &str) -> Result<Vec<ExpectRule>> {
    let mut out = Vec::with_capacity(rules.len());
    for (i, r) in rules.iter().enumerate() {
        let source = parse_rule_source(&r.source, ctx, "expect", i)?;
        match (r.regex.is_some(), r.within_s, r.max_silence_s) {
            (false, Some(_), _) => {
                return Err(Error::Config(format!(
                    "{ctx}: [[expect]][{i}]: `within_s` needs a `regex` to wait for"
                )))
            }
            (true, None, _) => {
                return Err(Error::Config(format!(
                    "{ctx}: [[expect]][{i}]: a `regex` needs `within_s` — the deadline is \
                     what makes it an expectation rather than a [[pass]] rule"
                )))
            }
            (false, None, None) => {
                return Err(Error::Config(format!(
                    "{ctx}: [[expect]][{i}]: nothing expected — give `regex` + `within_s`, \
                     `max_silence_s`, or both"
                )))
            }
            _ => {}
        }
        if r.within_s == Some(0) || r.max_silence_s == Some(0) {
            return Err(Error::Config(format!(
                "{ctx}: [[expect]][{i}]: a zero deadline can never be met"
            )));
        }
        out.push(ExpectRule {
            source,
            regex: r.regex.clone(),
            within_s: r.within_s,
            max_silence_s: r.max_silence_s,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PI5_BANNER: &str = r#"
        name = "pi5_boot_banner"
        target = "pi5"
        config = "../../examples/hello/pi5.yaml"
        requires_tags = ["nvme"]
        requires = ["deploy.netboot_tftp", "power.cycle", "observe.console_regex"]
        timeout_s = 30

        [[pass]]
        source = "console.serial"
        regex = "\\[fluxor\\] hw-test: ok"

        [[fail]]
        source = "console.serial"
        regex = "\\[fluxor\\] (PANIC|hw-test: fail)"
    "#;

    #[test]
    fn parses_example() {
        let dir = PathBuf::from("/repo/tests/hardware");
        let s = parse_scenario_str(PI5_BANNER, &dir, "pi5_boot_banner.toml").unwrap();
        assert_eq!(s.name, "pi5_boot_banner");
        assert_eq!(s.target, "pi5");
        assert_eq!(
            s.config,
            PathBuf::from("/repo/tests/hardware/../../examples/hello/pi5.yaml")
        );
        assert_eq!(s.requires.len(), 3);
        assert_eq!(s.requires_tags, vec!["nvme"]);
        assert_eq!(s.pass.len(), 1);
        assert_eq!(s.fail.len(), 1);
        assert!(s.expect.is_empty());
        assert_eq!(s.pass[0].source.as_str(), "console.serial");
    }

    #[test]
    fn absolute_config_path_is_preserved() {
        let src = r#"
            name = "x"
            target = "pi5"
            config = "/absolute/path/to/example.yaml"
        "#;
        let s = parse_scenario_str(src, Path::new("/repo"), "x.toml").unwrap();
        assert_eq!(s.config, PathBuf::from("/absolute/path/to/example.yaml"));
    }

    #[test]
    fn rejects_power_as_rule_source() {
        let src = r#"
            name = "x"
            target = "pi5"
            config = "x.yaml"
            [[pass]]
            source = "power.cycle"
            regex = "ok"
        "#;
        let err = parse_scenario_str(src, Path::new("/repo"), "x.toml").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("only console/telemetry/observe"), "{msg}");
    }

    #[test]
    fn rejects_unknown_capability() {
        let src = r#"
            name = "x"
            target = "pi5"
            config = "x.yaml"
            requires = ["deploy.usb_rocket_launcher"]
        "#;
        assert!(parse_scenario_str(src, Path::new("/repo"), "x.toml").is_err());
    }

    #[test]
    fn empty_requires_tags_is_any_rig() {
        let src = r#"
            name = "x"
            target = "pi5"
            config = "x.yaml"
            requires_tags = []
        "#;
        let s = parse_scenario_str(src, Path::new("/repo"), "x.toml").unwrap();
        assert!(s.requires_tags.is_empty());
    }

    #[test]
    fn parses_expect_rules() {
        let src = r#"
            name = "x"
            target = "pi5"
            config = "x.yaml"
            [[expect]]
            source = "console.serial"
            regex = "\\[boot\\] stages="
            within_s = 30
            [[expect]]
            source = "console.serial"
            max_silence_s = 40
        "#;
        let s = parse_scenario_str(src, Path::new("/repo"), "x.toml").unwrap();
        assert_eq!(s.expect.len(), 2);
        assert_eq!(s.expect[0].within_s, Some(30));
        assert_eq!(s.expect[1].max_silence_s, Some(40));
        assert!(s.expect[1].regex.is_none());
    }

    #[test]
    fn expect_within_needs_regex_and_regex_needs_within() {
        let base = r#"
            name = "x"
            target = "pi5"
            config = "x.yaml"
        "#;
        let no_regex = format!("{base}\n[[expect]]\nsource = \"console.serial\"\nwithin_s = 5\n");
        let err = parse_scenario_str(&no_regex, Path::new("/repo"), "x.toml").unwrap_err();
        assert!(format!("{err}").contains("needs a `regex`"), "{err}");

        let no_within =
            format!("{base}\n[[expect]]\nsource = \"console.serial\"\nregex = \"ok\"\n");
        let err = parse_scenario_str(&no_within, Path::new("/repo"), "x.toml").unwrap_err();
        assert!(format!("{err}").contains("needs `within_s`"), "{err}");

        let empty = format!("{base}\n[[expect]]\nsource = \"console.serial\"\n");
        let err = parse_scenario_str(&empty, Path::new("/repo"), "x.toml").unwrap_err();
        assert!(format!("{err}").contains("nothing expected"), "{err}");

        let zero = format!("{base}\n[[expect]]\nsource = \"console.serial\"\nmax_silence_s = 0\n");
        assert!(parse_scenario_str(&zero, Path::new("/repo"), "x.toml").is_err());
    }
}
