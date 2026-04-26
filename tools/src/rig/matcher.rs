//! Observation matcher — RFC §8.1.
//!
//! Consumes [`RunEvent`]s produced by the other adapters and evaluates the
//! scenario's pass/fail rules. Semantics:
//!
//!   * all pass rules must succeed before timeout
//!   * any fail rule causes immediate failure
//!   * fail wins ties
//!   * pass rules are sticky once matched
//!
//! Console rules match against the accumulated tail of console bytes (the
//! buffer is bounded to 16 KiB). Netboot-fetch rules match on the fetched
//! filename; the rule's `regex` field is optional — when absent any fetch
//! satisfies the rule.

use std::collections::{BTreeMap, HashSet};

use regex::Regex;

use crate::error::{Error, Result};
use crate::rig::events::{DeployEvent, RunEvent};
use crate::rig::scenario::ObservationRule;
use crate::rig::vocab::{Capability, Surface};

/// Rule sources the matcher can actually evaluate today. The validator
/// surfaces this list so a scenario whose rule source is merely declared
/// in the vocabulary — but has no matcher path — fails at plan time
/// rather than silently timing out at run time.
///
/// Supported:
///   * any `console.*` capability (matched against the console byte stream)
///   * `observe.netboot_fetch` (satisfied by a DeployEvent::ArtifactFetched)
///
/// Not yet supported (need transport attachment + matcher wiring):
///   * `telemetry.*`
///   * `observe.monitor_stream`
///   * `observe.usb_enumeration`
pub fn supports_rule_source(cap: Capability) -> bool {
    if cap.surface() == Surface::Console {
        return true;
    }
    cap.as_str() == "observe.netboot_fetch"
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    Pass,
    Fail,
}

#[derive(Debug)]
pub struct CompiledRule {
    pub kind: RuleKind,
    pub source: crate::rig::vocab::Capability,
    pub pattern: Option<String>,
    regex: Option<Regex>,
}

#[derive(Debug)]
pub enum MatcherOutcome {
    InProgress,
    /// All pass rules have matched. `primary_source` is the capability of
    /// the rule that completed the pass set (i.e. the last pass rule to
    /// flip from unmatched to matched) — the one whose match finally
    /// produced the verdict, not the one that happened to be listed first.
    Passed {
        primary_source: Capability,
    },
    /// A fail rule fired. `primary_source` is the capability of that
    /// specific rule, not of the first fail rule in the scenario list.
    Failed {
        rule_index: usize,
        primary_source: Capability,
        reason: String,
    },
    TimedOut,
}

pub struct Matcher {
    rules: Vec<CompiledRule>,
    /// Indices of pass rules that have already matched. Sticky per §8.1.
    pass_hits: HashSet<usize>,
    /// Pass-rule indices in the order they first matched. `last()` is the
    /// rule whose match completed the pass set; that's the rule cited in
    /// the Passed outcome.
    pass_order: Vec<usize>,
    pass_total: usize,
    /// First fail rule to match. Reported by `outcome`.
    fail_hit: Option<(usize, String)>,
    /// Rolling tail of console bytes, one buffer per source capability.
    /// Keeping them separate means a rule that names `console.serial` is
    /// only evaluated against `console.serial` bytes — output on another
    /// transport can't satisfy it, even when the board declares several
    /// and the run happens to attach more than one.
    console_bufs: BTreeMap<crate::rig::vocab::Capability, Vec<u8>>,
}

const CONSOLE_BUFFER_MAX: usize = 16 * 1024;
const CONSOLE_BUFFER_TRIM: usize = 8 * 1024;

impl Matcher {
    pub fn new(pass: &[ObservationRule], fail: &[ObservationRule]) -> Result<Self> {
        let mut rules = Vec::with_capacity(pass.len() + fail.len());
        for r in pass {
            rules.push(compile_rule(r, RuleKind::Pass)?);
        }
        for r in fail {
            rules.push(compile_rule(r, RuleKind::Fail)?);
        }
        let pass_total = rules.iter().filter(|r| r.kind == RuleKind::Pass).count();
        Ok(Self {
            rules,
            pass_hits: HashSet::new(),
            pass_order: Vec::new(),
            pass_total,
            fail_hit: None,
            console_bufs: BTreeMap::new(),
        })
    }

    /// Distinct console capabilities named as rule sources. The
    /// orchestrator uses this to decide which console transports to
    /// attach — every one referenced by a rule must be listening.
    pub fn console_sources(&self) -> Vec<Capability> {
        let mut out: Vec<Capability> = Vec::new();
        for r in &self.rules {
            if r.source.surface() == Surface::Console && !out.contains(&r.source) {
                out.push(r.source);
            }
        }
        out
    }

    /// Observe one event and return the current outcome.
    pub fn observe(&mut self, event: &RunEvent) -> MatcherOutcome {
        match event {
            RunEvent::ConsoleBytes { source, bytes } => {
                let buf = self.console_bufs.entry(*source).or_default();
                buf.extend_from_slice(bytes);
                if buf.len() > CONSOLE_BUFFER_MAX {
                    let drop = buf.len() - CONSOLE_BUFFER_TRIM;
                    buf.drain(0..drop);
                }
                self.scan_console(*source);
            }
            RunEvent::DeployProgress(e) => {
                self.scan_deploy(e);
            }
            RunEvent::TransportClosed { .. } => {
                // Transport closure alone is not a fail condition — a
                // disconnected serial line might still be accompanied by
                // a successful TFTP fetch. Orchestrator decides what to
                // do with diagnostics.
            }
        }
        self.current_outcome()
    }

    /// Outcome given no further events (called on timeout).
    pub fn finalize(&self) -> MatcherOutcome {
        match self.current_outcome() {
            MatcherOutcome::InProgress => MatcherOutcome::TimedOut,
            other => other,
        }
    }

    fn current_outcome(&self) -> MatcherOutcome {
        if let Some((idx, reason)) = &self.fail_hit {
            return MatcherOutcome::Failed {
                rule_index: *idx,
                primary_source: self.rules[*idx].source,
                reason: reason.clone(),
            };
        }
        if self.pass_total > 0 && self.pass_hits.len() >= self.pass_total {
            // The pass set became complete when the LAST rule flipped to
            // matched. That rule is the one whose match finished the
            // verdict; cite it in the run record rather than whichever
            // happens to be listed first in the scenario.
            let completing_idx = self
                .pass_order
                .last()
                .copied()
                .expect("pass_total > 0 and pass_hits covers it; pass_order has an entry");
            return MatcherOutcome::Passed {
                primary_source: self.rules[completing_idx].source,
            };
        }
        MatcherOutcome::InProgress
    }

    fn scan_console(&mut self, source: Capability) {
        // Decode lossily — rig consoles are mostly ASCII text with occasional
        // stray bytes from noise. Regex works on UTF-8.
        let Some(buf) = self.console_bufs.get(&source) else {
            return;
        };
        let text = String::from_utf8_lossy(buf);

        // Fail rules first — §8.1 "fail wins". Only rules naming *this*
        // source are considered.
        if self.fail_hit.is_none() {
            for (idx, rule) in self.rules.iter().enumerate() {
                if rule.kind != RuleKind::Fail {
                    continue;
                }
                if rule.source != source {
                    continue;
                }
                if rule_matches_text(rule, &text) {
                    self.fail_hit = Some((
                        idx,
                        format!(
                            "console fail on {}: {:?}",
                            source.as_str(),
                            rule.pattern.as_deref().unwrap_or("<no regex>"),
                        ),
                    ));
                    return;
                }
            }
        }

        for (idx, rule) in self.rules.iter().enumerate() {
            if rule.kind != RuleKind::Pass {
                continue;
            }
            if rule.source != source {
                continue;
            }
            if self.pass_hits.contains(&idx) {
                continue;
            }
            if rule_matches_text(rule, &text) {
                self.pass_hits.insert(idx);
                self.pass_order.push(idx);
            }
        }
    }

    fn scan_deploy(&mut self, event: &DeployEvent) {
        match event {
            DeployEvent::ArtifactFetched { filename, .. } => {
                for (idx, rule) in self.rules.iter().enumerate() {
                    if rule.source.as_str() != "observe.netboot_fetch" {
                        continue;
                    }
                    let matched = match &rule.regex {
                        Some(re) => re.is_match(filename),
                        None => true, // no filter — any fetch satisfies it
                    };
                    if !matched {
                        continue;
                    }
                    match rule.kind {
                        RuleKind::Pass => {
                            if self.pass_hits.insert(idx) {
                                self.pass_order.push(idx);
                            }
                        }
                        RuleKind::Fail => {
                            if self.fail_hit.is_none() {
                                self.fail_hit =
                                    Some((idx, format!("netboot_fetch fail: {filename}")));
                            }
                        }
                    }
                }
            }
            DeployEvent::Error(msg) => {
                // A deploy-side error may flip a fail rule if the scenario
                // asked for it (uncommon — usually runs report these as
                // warnings, not failures).
                for (idx, rule) in self.rules.iter().enumerate() {
                    if rule.kind != RuleKind::Fail {
                        continue;
                    }
                    if rule.source.as_str() != "observe.netboot_fetch" {
                        continue;
                    }
                    // Only treat a deploy error as a fail when the rule's
                    // regex is absent (catch-all) or explicitly matches the
                    // error text.
                    let matched = match &rule.regex {
                        Some(re) => re.is_match(msg),
                        None => false,
                    };
                    if matched && self.fail_hit.is_none() {
                        self.fail_hit = Some((idx, format!("netboot error: {msg}")));
                    }
                }
            }
            DeployEvent::DhcpActivity => {
                // Informational only.
            }
        }
    }
}

fn compile_rule(rule: &ObservationRule, kind: RuleKind) -> Result<CompiledRule> {
    let regex = match &rule.regex {
        Some(p) => Some(
            Regex::new(p)
                .map_err(|e| Error::Config(format!("rig rule: invalid regex {p:?}: {e}")))?,
        ),
        None => None,
    };
    Ok(CompiledRule {
        kind,
        source: rule.source,
        pattern: rule.regex.clone(),
        regex,
    })
}

fn rule_matches_text(rule: &CompiledRule, text: &str) -> bool {
    match &rule.regex {
        Some(re) => re.is_match(text),
        None => false, // console rules must have a regex — nothing to match without one
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rig::vocab::Capability;

    fn console_rule(pattern: &str) -> ObservationRule {
        ObservationRule {
            source: Capability::parse("console.serial").unwrap(),
            regex: Some(pattern.to_string()),
        }
    }

    fn netboot_rule() -> ObservationRule {
        ObservationRule {
            source: Capability::parse("observe.netboot_fetch").unwrap(),
            regex: None,
        }
    }

    fn serial_bytes(bytes: &[u8]) -> RunEvent {
        RunEvent::ConsoleBytes {
            source: Capability::parse("console.serial").unwrap(),
            bytes: bytes.to_vec(),
        }
    }

    fn usb_cdc_bytes(bytes: &[u8]) -> RunEvent {
        RunEvent::ConsoleBytes {
            source: Capability::parse("console.usb_cdc").unwrap(),
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn console_pass_matches() {
        let mut m = Matcher::new(&[console_rule("ok")], &[]).unwrap();
        let r = m.observe(&serial_bytes(b"booted, ok\n"));
        assert!(matches!(r, MatcherOutcome::Passed { .. }));
    }

    #[test]
    fn console_fail_wins_even_when_pass_also_matches() {
        let mut m = Matcher::new(&[console_rule("ok")], &[console_rule("PANIC")]).unwrap();
        let r = m.observe(&serial_bytes(b"ok but also PANIC\n"));
        assert!(matches!(r, MatcherOutcome::Failed { .. }), "{r:?}");
    }

    #[test]
    fn console_pass_is_sticky() {
        let mut m = Matcher::new(&[console_rule("ok")], &[]).unwrap();
        m.observe(&serial_bytes(b"ok"));
        // subsequent noise should not un-pass
        let r = m.observe(&serial_bytes(b"further garbage"));
        assert!(matches!(r, MatcherOutcome::Passed { .. }));
    }

    #[test]
    fn all_pass_rules_required() {
        let mut m = Matcher::new(&[console_rule("stage1"), console_rule("stage2")], &[]).unwrap();
        let r = m.observe(&serial_bytes(b"stage1 done"));
        assert!(matches!(r, MatcherOutcome::InProgress));
        let r = m.observe(&serial_bytes(b"...stage2 done"));
        assert!(matches!(r, MatcherOutcome::Passed { .. }));
    }

    #[test]
    fn console_rules_match_only_their_named_source() {
        let mut m = Matcher::new(&[console_rule("hello")], &[]).unwrap();
        assert!(matches!(
            m.observe(&usb_cdc_bytes(b"hello\n")),
            MatcherOutcome::InProgress,
        ));
        assert!(matches!(
            m.observe(&serial_bytes(b"hello\n")),
            MatcherOutcome::Passed { .. },
        ));
    }

    #[test]
    fn pass_outcome_cites_the_rule_that_completed_the_set() {
        let rule_serial = ObservationRule {
            source: Capability::parse("console.serial").unwrap(),
            regex: Some("stage1".into()),
        };
        let rule_usb = ObservationRule {
            source: Capability::parse("console.usb_cdc").unwrap(),
            regex: Some("stage2".into()),
        };
        let mut m = Matcher::new(&[rule_serial, rule_usb], &[]).unwrap();

        assert!(matches!(
            m.observe(&serial_bytes(b"stage1 done\n")),
            MatcherOutcome::InProgress
        ));
        match m.observe(&usb_cdc_bytes(b"stage2 done\n")) {
            MatcherOutcome::Passed { primary_source } => {
                assert_eq!(primary_source.as_str(), "console.usb_cdc");
            }
            other => panic!("expected Passed with usb_cdc source, got {other:?}"),
        }
    }

    #[test]
    fn fail_outcome_cites_the_rule_that_fired() {
        let fail_usb = ObservationRule {
            source: Capability::parse("console.usb_cdc").unwrap(),
            regex: Some("USB_PANIC".into()),
        };
        let fail_serial = ObservationRule {
            source: Capability::parse("console.serial").unwrap(),
            regex: Some("SER_PANIC".into()),
        };
        let mut m = Matcher::new(&[], &[fail_usb, fail_serial]).unwrap();
        match m.observe(&serial_bytes(b"SER_PANIC\n")) {
            MatcherOutcome::Failed { primary_source, .. } => {
                assert_eq!(primary_source.as_str(), "console.serial");
            }
            other => panic!("expected Failed with console.serial source, got {other:?}"),
        }
    }

    #[test]
    fn fail_outcome_cites_fail_source_even_when_pass_rules_are_present() {
        let pass_rule = ObservationRule {
            source: Capability::parse("console.usb_cdc").unwrap(),
            regex: Some("ok".into()),
        };
        let fail_rule = ObservationRule {
            source: Capability::parse("console.serial").unwrap(),
            regex: Some("PANIC".into()),
        };
        let mut m = Matcher::new(&[pass_rule], &[fail_rule]).unwrap();
        match m.observe(&serial_bytes(b"kernel PANIC\n")) {
            MatcherOutcome::Failed { primary_source, .. } => {
                assert_eq!(primary_source.as_str(), "console.serial");
            }
            other => panic!("expected Failed on console.serial, got {other:?}"),
        }
    }

    #[test]
    fn console_sources_enumerates_distinct_rule_sources() {
        let rule_serial = ObservationRule {
            source: Capability::parse("console.serial").unwrap(),
            regex: Some("a".into()),
        };
        let rule_usb = ObservationRule {
            source: Capability::parse("console.usb_cdc").unwrap(),
            regex: Some("b".into()),
        };
        let m = Matcher::new(&[rule_serial, rule_usb], &[]).unwrap();
        let sources = m.console_sources();
        assert_eq!(sources.len(), 2);
        assert!(sources.iter().any(|c| c.as_str() == "console.serial"));
        assert!(sources.iter().any(|c| c.as_str() == "console.usb_cdc"));
    }

    #[test]
    fn netboot_fetch_without_regex_accepts_any() {
        let mut m = Matcher::new(&[netboot_rule()], &[]).unwrap();
        let r = m.observe(&RunEvent::DeployProgress(DeployEvent::ArtifactFetched {
            filename: "kernel8.img".into(),
            client_ip: None,
            at: std::time::SystemTime::UNIX_EPOCH,
        }));
        assert!(matches!(r, MatcherOutcome::Passed { .. }));
    }

    #[test]
    fn netboot_fetch_regex_filters_by_filename() {
        let mut m = Matcher::new(
            &[ObservationRule {
                source: Capability::parse("observe.netboot_fetch").unwrap(),
                regex: Some("kernel8\\.img$".into()),
            }],
            &[],
        )
        .unwrap();
        let r = m.observe(&RunEvent::DeployProgress(DeployEvent::ArtifactFetched {
            filename: "boot.bin".into(),
            client_ip: None,
            at: std::time::SystemTime::UNIX_EPOCH,
        }));
        assert!(matches!(r, MatcherOutcome::InProgress));
        let r = m.observe(&RunEvent::DeployProgress(DeployEvent::ArtifactFetched {
            filename: "fluxor/kernel8.img".into(),
            client_ip: None,
            at: std::time::SystemTime::UNIX_EPOCH,
        }));
        assert!(matches!(r, MatcherOutcome::Passed { .. }));
    }

    #[test]
    fn timeout_with_partial_match_is_timed_out() {
        let m = Matcher::new(&[console_rule("stage1"), console_rule("stage2")], &[]).unwrap();
        assert!(matches!(m.finalize(), MatcherOutcome::TimedOut));
    }

    #[test]
    fn no_rules_stays_in_progress() {
        let m = Matcher::new(&[], &[]).unwrap();
        assert!(matches!(m.finalize(), MatcherOutcome::TimedOut));
    }
}
