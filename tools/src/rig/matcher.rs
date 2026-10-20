//! Observation matcher.
//!
//! Consumes [`RunEvent`]s produced by the other adapters and evaluates the
//! scenario's pass/fail/expect rules. Semantics:
//!
//!   * all pass rules must succeed before timeout
//!   * any fail rule causes immediate failure
//!   * fail wins ties
//!   * pass rules are sticky once matched
//!   * every `[[expect]]` with a regex must also have been seen, by its
//!     deadline; a missed one fails the run and names itself
//!   * a source with `max_silence_s` must not go quiet for that long once
//!     it has spoken
//!
//! Deadlines are measured from an **anchor**: the moment the power step
//! finished (the orchestrator says so with [`RunEvent::PowerDone`]), or
//! the start of matching (the instant the matcher is built with) when
//! there was no power step. A source that reports a fresh boot after the
//! power step started moves its own expectations' anchor to that boot, so
//! a target that takes a while to come up is not timed against the rig's
//! clock before it exists.
//!
//! Time is an argument: `with_expectations`, `observe_at` and `tick` take
//! `now`, so the deadline logic is tested with a clock the test controls.
//! `new` and `observe` are the wall-clock conveniences.
//!
//! Console rules match against the accumulated tail of console bytes (the
//! buffer is bounded to 16 KiB). Netboot-fetch rules match on the fetched
//! filename; the rule's `regex` field is optional — when absent any fetch
//! satisfies the rule.

use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};

use regex::{Regex, RegexBuilder};

use crate::error::{Error, Result};
use crate::rig::events::{DeployEvent, RunEvent};
use crate::rig::scenario::{ExpectRule, ObservationRule};
use crate::rig::vocab::{Capability, Surface};

/// The observe-surface capabilities a rule may read. Each reaches the
/// matcher as a stream of bytes on its own source — a probe reports its
/// results as NDJSON lines — except `observe.netboot_fetch`, which is the
/// deploy backend's `watch` reporting fetched filenames.
///
///   * `observe.netboot_fetch` — a fetch of the staged artifact
///   * `observe.https_load` — an HTTPS load probe against the rig
///   * `observe.proto_load` — a load probe whose protocol (h1 / h2c / ws /
///     grpc, plaintext or TLS) its binding chooses
///   * `observe.quic_mux` — a transport probe: QUIC streams against an
///     echo, no protocol above them, so a failure is the transport's
///   * `observe.tls_load` — TLS 1.3 handshakes and an echo above them
///   * `observe.udp_capture` — every datagram to a bound port, e.g. a
///     board's `platform.debug.to: net` log
///
/// The other observe capabilities describe what a board offers but carry
/// no stream a regex can read, so a rule on one is refused at plan time
/// rather than left to time out.
pub const OBSERVE_RULE_SOURCES: &[&str] = &[
    "observe.netboot_fetch",
    "observe.https_load",
    "observe.proto_load",
    "observe.quic_mux",
    "observe.tls_load",
    "observe.udp_capture",
];

/// Whether a rule may name `cap` as its source: any console or telemetry
/// capability (regex over its byte stream), or one of
/// [`OBSERVE_RULE_SOURCES`].
pub fn supports_rule_source(cap: Capability) -> bool {
    matches!(cap.surface(), Surface::Console | Surface::Telemetry)
        || OBSERVE_RULE_SOURCES.contains(&cap.as_str())
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
struct CompiledExpect {
    source: Capability,
    pattern: Option<String>,
    regex: Option<Regex>,
    within: Option<Duration>,
    max_silence: Option<Duration>,
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
    /// A fail rule fired, or an expectation was missed. `primary_source`
    /// is the capability of that specific rule, not of the first fail rule
    /// in the scenario list.
    Failed {
        rule_index: usize,
        primary_source: Capability,
        reason: String,
    },
    TimedOut,
}

pub struct Matcher {
    rules: Vec<CompiledRule>,
    expects: Vec<CompiledExpect>,
    /// Indices of pass rules that have already matched. Sticky: a rule that
    /// has matched stays matched.
    pass_hits: HashSet<usize>,
    /// Pass-rule indices in the order they first matched. `last()` is the
    /// rule whose match completed the pass set; that's the rule cited in
    /// the Passed outcome.
    pass_order: Vec<usize>,
    pass_total: usize,
    /// First fail rule to match. Reported by `outcome`.
    fail_hit: Option<(usize, String)>,
    /// Expectations (with a regex) that have been seen.
    expect_hits: HashSet<usize>,
    /// First expectation to be missed: (index into `expects`, reason).
    expect_miss: Option<(usize, String)>,
    /// Rolling tail of console bytes, one buffer per source capability.
    /// Keeping them separate means a rule that names `console.serial` is
    /// only evaluated against `console.serial` bytes — output on another
    /// transport can't satisfy it, even when the board declares several
    /// and the run happens to attach more than one.
    console_bufs: BTreeMap<crate::rig::vocab::Capability, Vec<u8>>,
    /// Deadline anchor: the end of the power step, else matching start.
    anchor: Instant,
    power_started: bool,
    /// A source's own fresh boot after the power step started.
    boot_at: BTreeMap<Capability, Instant>,
    first_byte_at: BTreeMap<Capability, Instant>,
    last_byte_at: BTreeMap<Capability, Instant>,
}

const CONSOLE_BUFFER_MAX: usize = 16 * 1024;
const CONSOLE_BUFFER_TRIM: usize = 8 * 1024;

impl Matcher {
    pub fn new(pass: &[ObservationRule], fail: &[ObservationRule]) -> Result<Self> {
        Self::with_expectations(pass, fail, &[], Instant::now())
    }

    pub fn with_expectations(
        pass: &[ObservationRule],
        fail: &[ObservationRule],
        expect: &[ExpectRule],
        now: Instant,
    ) -> Result<Self> {
        let mut rules = Vec::with_capacity(pass.len() + fail.len());
        for r in pass {
            rules.push(compile_rule(r, RuleKind::Pass)?);
        }
        for r in fail {
            rules.push(compile_rule(r, RuleKind::Fail)?);
        }
        let pass_total = rules.iter().filter(|r| r.kind == RuleKind::Pass).count();
        let expects = expect
            .iter()
            .map(compile_expect)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            rules,
            expects,
            pass_hits: HashSet::new(),
            pass_order: Vec::new(),
            pass_total,
            fail_hit: None,
            expect_hits: HashSet::new(),
            expect_miss: None,
            console_bufs: BTreeMap::new(),
            anchor: now,
            power_started: false,
            boot_at: BTreeMap::new(),
            first_byte_at: BTreeMap::new(),
            last_byte_at: BTreeMap::new(),
        })
    }

    /// Observe one event at the wall clock's "now" and return the current
    /// outcome.
    pub fn observe(&mut self, event: &RunEvent) -> MatcherOutcome {
        self.observe_at(event, Instant::now())
    }

    pub fn observe_at(&mut self, event: &RunEvent, now: Instant) -> MatcherOutcome {
        match event {
            RunEvent::ConsoleBytes { source, bytes } => {
                self.first_byte_at.entry(*source).or_insert(now);
                self.last_byte_at.insert(*source, now);
                let buf = self.console_bufs.entry(*source).or_default();
                buf.extend_from_slice(bytes);
                if buf.len() > CONSOLE_BUFFER_MAX {
                    let drop = buf.len() - CONSOLE_BUFFER_TRIM;
                    buf.drain(0..drop);
                }
                self.scan_console(*source);
            }
            RunEvent::Boot { source } => {
                if self.power_started {
                    self.boot_at.insert(*source, now);
                }
            }
            RunEvent::DeployProgress(e) => {
                self.scan_deploy(e);
            }
            RunEvent::TransportClosed { .. } => {
                // Transport closure alone is not a fail condition — a
                // disconnected serial line might still be accompanied by
                // a successful TFTP fetch. A `max_silence_s` rule sees the
                // closed source go quiet and fails it in due course.
            }
            RunEvent::PowerStarted => {
                self.power_started = true;
            }
            RunEvent::PowerDone => {
                self.anchor = now;
            }
        }
        self.check_deadlines(now);
        self.current_outcome()
    }

    /// Re-evaluate deadlines with no new event. The run loop calls this at
    /// least once a second so an expectation fails when its time is up,
    /// not when the next byte happens to arrive.
    pub fn tick(&mut self, now: Instant) -> MatcherOutcome {
        self.check_deadlines(now);
        self.current_outcome()
    }

    /// Outcome given no further events (called on timeout).
    pub fn finalize(&self) -> MatcherOutcome {
        match self.current_outcome() {
            MatcherOutcome::InProgress => MatcherOutcome::TimedOut,
            other => other,
        }
    }

    fn check_deadlines(&mut self, now: Instant) {
        if self.expect_miss.is_some() || self.fail_hit.is_some() {
            return;
        }
        for (i, e) in self.expects.iter().enumerate() {
            if let Some(within) = e.within {
                if !self.expect_hits.contains(&i) {
                    let start = match self.boot_at.get(&e.source) {
                        Some(boot) if *boot > self.anchor => *boot,
                        _ => self.anchor,
                    };
                    if now.duration_since(start) >= within {
                        self.expect_miss = Some((
                            i,
                            format!(
                                "expected `{}` on {} within {}s; not seen",
                                e.pattern.as_deref().unwrap_or("<no regex>"),
                                e.source.as_str(),
                                within.as_secs()
                            ),
                        ));
                        return;
                    }
                }
            }
            if let Some(max_silence) = e.max_silence {
                if let Some(last) = self.last_byte_at.get(&e.source) {
                    if now.duration_since(*last) >= max_silence {
                        self.expect_miss = Some((
                            i,
                            format!(
                                "{} silent for {}s (max_silence_s)",
                                e.source.as_str(),
                                max_silence.as_secs()
                            ),
                        ));
                        return;
                    }
                }
            }
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
        if let Some((idx, reason)) = &self.expect_miss {
            return MatcherOutcome::Failed {
                rule_index: self.rules.len() + *idx,
                primary_source: self.expects[*idx].source,
                reason: reason.clone(),
            };
        }
        let expects_met = self
            .expects
            .iter()
            .enumerate()
            .filter(|(_, e)| e.regex.is_some())
            .all(|(i, _)| self.expect_hits.contains(&i));
        if self.pass_total > 0 && self.pass_hits.len() >= self.pass_total && expects_met {
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

        // Fail rules first: a fail beats any number of passes. Only rules
        // naming *this* source are considered.
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

        for (i, e) in self.expects.iter().enumerate() {
            if e.source != source || self.expect_hits.contains(&i) {
                continue;
            }
            if let Some(re) = &e.regex {
                if re.is_match(&text) {
                    self.expect_hits.insert(i);
                }
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
                for (i, e) in self.expects.iter().enumerate() {
                    if e.source.as_str() != "observe.netboot_fetch" {
                        continue;
                    }
                    let matched = match &e.regex {
                        Some(re) => re.is_match(filename),
                        None => false,
                    };
                    if matched {
                        self.expect_hits.insert(i);
                    }
                }
            }
            DeployEvent::Error(msg) => {
                // A deploy-side error fails the run only through a
                // netboot_fetch fail rule whose regex matches its text; a
                // rule with no regex filters fetches and never fires on an
                // error.
                for (idx, rule) in self.rules.iter().enumerate() {
                    if rule.kind != RuleKind::Fail {
                        continue;
                    }
                    if rule.source.as_str() != "observe.netboot_fetch" {
                        continue;
                    }
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

fn build_regex(p: &str) -> Result<Regex> {
    // Anchors are per LINE. A console rule matches against the whole
    // accumulated buffer (see `scan_console`), not one line at a time, so
    // without this `$` binds to the end of everything received so far and `^`
    // to the very start — and a rule ending `ERR$` fires only if its line is
    // the last byte in the buffer at the instant of a scan, which for a probe
    // that keeps emitting is never.
    //
    // Per-line is what a scenario author writing `$` means, and `.` still does
    // not cross `\n`, so a pattern stays scoped to one line. Unanchored
    // patterns are unaffected: multi-line only adds match positions for the
    // anchors.
    RegexBuilder::new(p)
        .multi_line(true)
        .build()
        .map_err(|e| Error::Config(format!("rig rule: invalid regex {p:?}: {e}")))
}

fn compile_rule(rule: &ObservationRule, kind: RuleKind) -> Result<CompiledRule> {
    let regex = match &rule.regex {
        Some(p) => Some(build_regex(p)?),
        None => None,
    };
    Ok(CompiledRule {
        kind,
        source: rule.source,
        pattern: rule.regex.clone(),
        regex,
    })
}

fn compile_expect(rule: &ExpectRule) -> Result<CompiledExpect> {
    let regex = match &rule.regex {
        Some(p) => Some(build_regex(p)?),
        None => None,
    };
    Ok(CompiledExpect {
        source: rule.source,
        pattern: rule.regex.clone(),
        regex,
        within: rule.within_s.map(|s| Duration::from_secs(s as u64)),
        max_silence: rule.max_silence_s.map(|s| Duration::from_secs(s as u64)),
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

    fn expect_within(pattern: &str, within_s: u32) -> ExpectRule {
        ExpectRule {
            source: Capability::parse("console.serial").unwrap(),
            regex: Some(pattern.into()),
            within_s: Some(within_s),
            max_silence_s: None,
        }
    }

    fn expect_silence(max_silence_s: u32) -> ExpectRule {
        ExpectRule {
            source: Capability::parse("console.serial").unwrap(),
            regex: None,
            within_s: None,
            max_silence_s: Some(max_silence_s),
        }
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
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

    /// A `$`-anchored rule fires on its line even when more output follows.
    ///
    /// Rules match against the whole accumulated buffer, so without per-line
    /// anchoring `ERR$` binds to the end of everything received and stops
    /// matching the moment the next line arrives — a scenario whose probe
    /// printed its failure would report TIMEOUT instead.
    #[test]
    fn dollar_anchored_fail_rule_fires_when_more_output_follows() {
        let mut m = Matcher::new(&[], &[console_rule("phase=h2c .* ERR$")]).unwrap();
        // The matching line, then more output after it — the real ordering.
        let outcome = m.observe(&serial_bytes(
            b"[proto_load] phase=h2c committed=0 failed=8 ERR\n\
              [proto_load] phase=ws start\n\
              [proto_load] done protocols=h1,h2c,ws any_err=true\n",
        ));
        assert!(
            matches!(outcome, MatcherOutcome::Failed { .. }),
            "a $-anchored fail rule must fire on its own line, got {outcome:?}"
        );
    }

    /// `^` likewise anchors per line, not to the start of the whole stream.
    #[test]
    fn caret_anchored_rule_matches_a_later_line() {
        let mut m = Matcher::new(&[], &[console_rule("^\\[fluxor\\] PANIC")]).unwrap();
        let outcome = m.observe(&serial_bytes(b"boot banner\n[fluxor] PANIC at 0x1234\n"));
        assert!(
            matches!(outcome, MatcherOutcome::Failed { .. }),
            "a ^-anchored rule must match at a line start, got {outcome:?}"
        );
    }

    /// `.` must still not cross a newline, so a pattern stays scoped to one
    /// line rather than silently spanning the buffer.
    #[test]
    fn dot_does_not_span_lines() {
        let mut m = Matcher::new(&[], &[console_rule("phase=h2c.*any_err=true")]).unwrap();
        let outcome = m.observe(&serial_bytes(
            b"[proto_load] phase=h2c OK\n[proto_load] done any_err=true\n",
        ));
        assert!(
            matches!(outcome, MatcherOutcome::InProgress),
            "`.` must not cross a newline, got {outcome:?}"
        );
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

    // ── expectations, on a controlled clock ───────────────────────────────

    #[test]
    fn missed_expectation_fails_by_absence_and_names_the_rule() {
        let t0 = Instant::now();
        let mut m = Matcher::with_expectations(
            &[console_rule("alive")],
            &[],
            &[expect_within("\\[boot\\] stages=", 30)],
            t0,
        )
        .unwrap();
        // Nothing arrives; the clock advances past the deadline.
        assert!(matches!(m.tick(t0 + secs(29)), MatcherOutcome::InProgress));
        match m.tick(t0 + secs(30)) {
            MatcherOutcome::Failed {
                primary_source,
                reason,
                ..
            } => {
                assert_eq!(primary_source.as_str(), "console.serial");
                assert!(reason.contains("\\[boot\\] stages="), "{reason}");
                assert!(reason.contains("within 30s"), "{reason}");
            }
            other => panic!("expected a Failed outcome naming the rule, got {other:?}"),
        }
    }

    #[test]
    fn expectation_seen_in_time_does_not_fail_and_pass_needs_it() {
        let t0 = Instant::now();
        let mut m = Matcher::with_expectations(
            &[console_rule("alive")],
            &[],
            &[expect_within("stages=", 30)],
            t0,
        )
        .unwrap();
        // The pass line alone is not enough while the expectation is unmet.
        assert!(matches!(
            m.observe_at(&serial_bytes(b"[sched] alive\n"), t0 + secs(5)),
            MatcherOutcome::InProgress
        ));
        assert!(matches!(
            m.observe_at(&serial_bytes(b"[boot] stages=a,b\n"), t0 + secs(10)),
            MatcherOutcome::Passed { .. }
        ));
        // Long after the deadline, a met expectation never fails.
        assert!(matches!(
            m.tick(t0 + secs(100)),
            MatcherOutcome::Passed { .. }
        ));
    }

    #[test]
    fn power_done_moves_the_anchor() {
        let t0 = Instant::now();
        let mut m = Matcher::with_expectations(&[], &[], &[expect_within("x", 10)], t0).unwrap();
        // The power step takes 20 s; the deadline counts from its end.
        assert!(matches!(
            m.observe_at(&RunEvent::PowerStarted, t0),
            MatcherOutcome::InProgress
        ));
        assert!(matches!(
            m.observe_at(&RunEvent::PowerDone, t0 + secs(20)),
            MatcherOutcome::InProgress
        ));
        assert!(matches!(m.tick(t0 + secs(29)), MatcherOutcome::InProgress));
        assert!(matches!(
            m.tick(t0 + secs(30)),
            MatcherOutcome::Failed { .. }
        ));
    }

    #[test]
    fn a_fresh_boot_after_power_started_moves_its_sources_anchor_later() {
        let t0 = Instant::now();
        let boot = RunEvent::Boot {
            source: Capability::parse("console.serial").unwrap(),
        };
        let mut m = Matcher::with_expectations(&[], &[], &[expect_within("x", 10)], t0).unwrap();
        // A boot before PowerStarted is the old image: ignored.
        m.observe_at(&boot, t0 + secs(1));
        m.observe_at(&RunEvent::PowerStarted, t0 + secs(2));
        m.observe_at(&RunEvent::PowerDone, t0 + secs(3));
        // The machine only came up 40 s later; the expectation counts from then.
        m.observe_at(&boot, t0 + secs(43));
        assert!(matches!(m.tick(t0 + secs(52)), MatcherOutcome::InProgress));
        assert!(matches!(
            m.tick(t0 + secs(53)),
            MatcherOutcome::Failed { .. }
        ));
    }

    #[test]
    fn max_silence_fails_only_after_the_first_byte_and_resets_on_output() {
        let t0 = Instant::now();
        let mut m =
            Matcher::with_expectations(&[console_rule("done")], &[], &[expect_silence(10)], t0)
                .unwrap();
        // Silence before the first byte is not silence.
        assert!(matches!(m.tick(t0 + secs(60)), MatcherOutcome::InProgress));
        m.observe_at(&serial_bytes(b"hello\n"), t0 + secs(60));
        assert!(matches!(m.tick(t0 + secs(69)), MatcherOutcome::InProgress));
        m.observe_at(&serial_bytes(b"still here\n"), t0 + secs(69));
        assert!(matches!(m.tick(t0 + secs(78)), MatcherOutcome::InProgress));
        match m.tick(t0 + secs(79)) {
            MatcherOutcome::Failed { reason, .. } => {
                assert!(reason.contains("silent for 10s"), "{reason}")
            }
            other => panic!("expected silence failure, got {other:?}"),
        }
    }

    #[test]
    fn fail_rule_beats_a_later_expectation_miss_and_vice_versa_is_first_wins() {
        let t0 = Instant::now();
        let mut m = Matcher::with_expectations(
            &[],
            &[console_rule("PANIC")],
            &[expect_within("ok", 5)],
            t0,
        )
        .unwrap();
        match m.observe_at(&serial_bytes(b"PANIC\n"), t0 + secs(1)) {
            MatcherOutcome::Failed { reason, .. } => assert!(reason.contains("PANIC")),
            other => panic!("{other:?}"),
        }
        // The expectation's deadline passing does not rewrite the reason.
        match m.tick(t0 + secs(10)) {
            MatcherOutcome::Failed { reason, .. } => assert!(reason.contains("PANIC")),
            other => panic!("{other:?}"),
        }
    }
}
