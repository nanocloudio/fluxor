//! Public scenario contract — `tests/hardware/*.toml`.
//!
//! RFC §8. A scenario describes validation intent (what board under test,
//! what config, which capabilities it needs, and the pass/fail rules). Paths
//! inside a scenario are anchored to the scenario file's directory per §15.3,
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
    /// Directory the scenario was loaded from. Exposed so callers resolving
    /// additional relative paths use the same anchor.
    pub scenario_dir: PathBuf,
    /// Absolute path to the scenario file itself, when the scenario was
    /// loaded from disk. Used by the run-record hasher so renaming or
    /// copying a scenario doesn't produce stale `scenario_sha256` values.
    /// Populated only by [`load_scenario`]; string-based parsing leaves it
    /// `None`.
    pub source_path: Option<PathBuf>,
}

/// Per RFC §8.1: every rule names a transport `source` and a match condition.
///
/// V1 supports regex matching. The schema deliberately leaves room for other
/// match kinds (deployment-transport confirmation, USB enumeration) without
/// a breaking change: additional fields are just additional optional keys.
#[derive(Debug, Clone)]
pub struct ObservationRule {
    pub source: Capability,
    pub regex: Option<String>,
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
}

#[derive(Deserialize)]
struct RuleToml {
    source: String,
    regex: Option<String>,
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

    // §15.3: scenario-relative paths are anchored to the scenario file's
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

    Ok(Scenario {
        name: s.name,
        target: s.target,
        config,
        requires,
        requires_tags: s.requires_tags,
        timeout_s: s.timeout_s,
        pass,
        fail,
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

fn parse_rules(rules: &[RuleToml], ctx: &str, kind: &str) -> Result<Vec<ObservationRule>> {
    let mut out = Vec::with_capacity(rules.len());
    for (i, r) in rules.iter().enumerate() {
        let source = Capability::parse(&r.source)
            .map_err(|e| Error::Config(format!("{ctx}: [[{kind}]][{i}].source: {e}")))?;
        // Only transports that can produce observable bytes are valid rule
        // sources. Power and rig-coordination surfaces cannot.
        match source.surface() {
            Surface::Console | Surface::Telemetry | Surface::Observe => {}
            other => {
                return Err(Error::Config(format!(
                    "{ctx}: [[{kind}]][{i}].source: '{}' is a '{}' capability; \
                     only console/telemetry/observe sources may appear in rules",
                    source.as_str(),
                    other.as_str()
                )));
            }
        }
        out.push(ObservationRule {
            source,
            regex: r.regex.clone(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CM5_BANNER: &str = r#"
        name = "cm5_boot_banner"
        target = "cm5"
        config = "../../examples/cm5/hello_uart.yaml"
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
        let s = parse_scenario_str(CM5_BANNER, &dir, "cm5_boot_banner.toml").unwrap();
        assert_eq!(s.name, "cm5_boot_banner");
        assert_eq!(s.target, "cm5");
        assert_eq!(
            s.config,
            PathBuf::from("/repo/tests/hardware/../../examples/cm5/hello_uart.yaml")
        );
        assert_eq!(s.requires.len(), 3);
        assert_eq!(s.requires_tags, vec!["nvme"]);
        assert_eq!(s.pass.len(), 1);
        assert_eq!(s.fail.len(), 1);
        assert_eq!(s.pass[0].source.as_str(), "console.serial");
    }

    #[test]
    fn absolute_config_path_is_preserved() {
        let src = r#"
            name = "x"
            target = "cm5"
            config = "/absolute/path/to/example.yaml"
        "#;
        let s = parse_scenario_str(src, Path::new("/repo"), "x.toml").unwrap();
        assert_eq!(s.config, PathBuf::from("/absolute/path/to/example.yaml"));
    }

    #[test]
    fn rejects_power_as_rule_source() {
        let src = r#"
            name = "x"
            target = "cm5"
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
            target = "cm5"
            config = "x.yaml"
            requires = ["deploy.usb_rocket_launcher"]
        "#;
        assert!(parse_scenario_str(src, Path::new("/repo"), "x.toml").is_err());
    }

    #[test]
    fn empty_requires_tags_is_any_rig() {
        let src = r#"
            name = "x"
            target = "cm5"
            config = "x.yaml"
            requires_tags = []
        "#;
        let s = parse_scenario_str(src, Path::new("/repo"), "x.toml").unwrap();
        assert!(s.requires_tags.is_empty());
    }
}
