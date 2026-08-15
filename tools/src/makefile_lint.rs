//! `standards/make.md` conformance — the text half of `fluxor ci`'s
//! `makefile` phase.
//!
//! A conforming target *name* says nothing about what the recipe under
//! it does: a `build:` that runs a per-crate shell loop, a `test:` that
//! skips the member crates and a `lint:` that runs rustfmt alone all
//! carry the right names. `standards/cli.md` §1 fixes what a body may
//! be — **one delegation to the CLI verb of the same name** — which
//! makes the body checkable text, and this module checks it.
//!
//! Three rules, all structural:
//!
//!   1. **§2 preamble + target set.** `.DEFAULT_GOAL`, strict `SHELL`,
//!      the seven lifecycle targets, none of the forbidden names.
//!   2. **§1/§2 canonical bodies.** Each lifecycle target is exactly its
//!      delegation, with no prerequisites — `test: build` is how a
//!      lifecycle stage quietly grows a second meaning.
//!   3. **§3 recipe complexity.** No shell loop or conditional in any
//!      recipe, and no file-scope `ifeq`/`ifdef`. Both are the shape
//!      §3 sends into a `fluxor` subcommand or a script under `tools/`.
//!
//! Every violation carries the line it is on, so a failure names
//! `Makefile:<line>` and not just the file.

use std::collections::BTreeSet;

/// One deviation, with the 1-based line it sits on (0 = whole file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub line: usize,
    pub msg: String,
}

impl Violation {
    fn file(msg: impl Into<String>) -> Self {
        Self {
            line: 0,
            msg: msg.into(),
        }
    }
    fn at(line: usize, msg: impl Into<String>) -> Self {
        Self {
            line,
            msg: msg.into(),
        }
    }

    /// `Makefile:12: …` — the form an editor and a human both parse.
    pub fn render(&self, file: &str) -> String {
        if self.line == 0 {
            format!("{file}: {}", self.msg)
        } else {
            format!("{file}:{}: {}", self.line, self.msg)
        }
    }
}

/// The lifecycle targets every project's Makefile must define, each
/// paired with the one command its recipe may contain.
///
/// `help` is `@fluxor help --make` — generated, so the block can never
/// drift from the CLI or fall behind the scripts in the tree.
pub(crate) const LIFECYCLE: &[(&str, &str)] = &[
    ("help", "fluxor help --make"),
    ("build", "fluxor build"),
    ("test", "fluxor test"),
    ("lint", "fluxor lint"),
    ("ci", "fluxor ci"),
    ("publish", "fluxor publish"),
    ("clean", "fluxor clean"),
];

/// Target names `standards/make.md` §1 forbids: each either renames one
/// CLI command or splits a lifecycle stage.
const FORBIDDEN_TARGETS: &[&str] = &[
    "fmt",
    "fmt-check",
    "clippy",
    "check",
    "verify",
    "setup",
    "sync",
    "update",
    "modules",
    "validate",
    "run",
];

/// Shell keywords §3 rules out of a recipe. `then`/`do`/`done`/`fi` are
/// consequences of these, so flagging the opener names the construct
/// once instead of four times.
const SHELL_CONTROL: &[&str] = &["for", "while", "until", "if", "elif", "case"];

/// Make's file-scope conditionals. `else`/`endif` are likewise
/// consequences of an opener already reported.
const MAKE_CONDITIONALS: &[&str] = &["ifeq", "ifneq", "ifdef", "ifndef"];

/// One parsed rule: `name: prereqs…` plus its tab-indented recipe.
#[derive(Debug, Clone)]
pub(crate) struct Target {
    pub(crate) name: String,
    pub(crate) line: usize,
    prereqs: Vec<String>,
    /// `(line, text)` per recipe line, tab and trailing space stripped.
    body: Vec<(usize, String)>,
}

/// Split a Makefile into its rules.
///
/// Deliberately lexical: a real `make` parse would need the variable
/// environment, and every rule here is about the text a contributor
/// reads. Variable assignments (`:=`, `?=`, `+=`, `=`), `.PHONY`-style
/// special targets, and comments are not rules.
pub(crate) fn parse(text: &str) -> Vec<Target> {
    let mut out: Vec<Target> = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let lineno = i + 1;
        if let Some(body) = raw.strip_prefix('\t') {
            let body = body.trim_end();
            if body.is_empty() {
                continue;
            }
            if let Some(t) = out.last_mut() {
                t.body.push((lineno, body.to_string()));
            }
            continue;
        }
        let Some((head, rest)) = split_rule_head(raw) else {
            continue;
        };
        // A rule head ends the previous recipe.
        out.push(Target {
            name: head,
            line: lineno,
            prereqs: rest.split_whitespace().map(str::to_string).collect(),
            body: Vec::new(),
        });
    }
    out
}

/// `name: prereqs` → `(name, prereqs)`, for lines that really are rule
/// heads. Rejects assignments, comments, recipe lines, special targets,
/// and multi-target rules with characters no lifecycle name uses.
fn split_rule_head(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let (name, rest) = line.split_once(':')?;
    // `foo := bar`, `foo ::= bar` — assignments, not rules.
    if rest.starts_with('=') || rest.starts_with(":=") {
        return None;
    }
    let name = name.trim();
    if name.is_empty() || name.starts_with('.') || name.contains('=') {
        return None;
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return None;
    }
    Some((name.to_string(), rest.trim().to_string()))
}

/// Every deviation from `standards/make.md` this text carries.
///
/// `cli_verbs` is the live CLI's top-level command set; an empty set
/// disables the verb check (an unreadable probe must not fail the gate
/// on its own).
pub fn check(text: &str, cli_verbs: &BTreeSet<String>) -> Vec<Violation> {
    let mut v = Vec::new();
    check_preamble(text, &mut v);
    let targets = parse(text);
    check_target_set(&targets, &mut v);
    check_bodies(&targets, &mut v);
    check_recipe_complexity(&targets, &mut v);
    check_file_scope_conditionals(text, &mut v);
    check_verbs(text, cli_verbs, &mut v);
    v.sort_by_key(|x| x.line);
    v
}

fn check_preamble(text: &str, out: &mut Vec<Violation>) {
    // Compared whitespace-insensitively: the skeleton aligns its `:=`
    // columns and real Makefiles do not always follow.
    let squashed: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    for want in [
        ".DEFAULT_GOAL := build",
        "SHELL := /bin/bash",
        ".SHELLFLAGS := -euo pipefail -c",
    ] {
        if !squashed.contains(want) {
            out.push(Violation::file(format!("missing `{want}` (§2)")));
        }
    }
}

fn check_target_set(targets: &[Target], out: &mut Vec<Violation>) {
    let defined: BTreeSet<&str> = targets.iter().map(|t| t.name.as_str()).collect();
    for (want, _) in LIFECYCLE {
        if !defined.contains(want) {
            out.push(Violation::file(format!("no `{want}:` target (§1.1)")));
        }
    }
    for t in targets {
        if FORBIDDEN_TARGETS.contains(&t.name.as_str()) {
            out.push(Violation::at(
                t.line,
                format!(
                    "`{}:` renames a CLI command or splits a lifecycle stage (§1)",
                    t.name
                ),
            ));
        }
    }
}

/// A lifecycle recipe is exactly its delegation — one line, optionally
/// `@`-quiet, nothing else — and takes no prerequisites.
fn check_bodies(targets: &[Target], out: &mut Vec<Violation>) {
    for t in targets {
        let Some((_, canonical)) = LIFECYCLE.iter().find(|(n, _)| *n == t.name) else {
            continue;
        };
        if !t.prereqs.is_empty() {
            out.push(Violation::at(
                t.line,
                format!(
                    "`{}: {}` — a lifecycle target takes no prerequisites; the CLI verb \
                     stages what it needs (cli.md §1)",
                    t.name,
                    t.prereqs.join(" ")
                ),
            ));
        }
        let body: Vec<&(usize, String)> = t.body.iter().collect();
        if body.is_empty() {
            out.push(Violation::at(
                t.line,
                format!("`{}:` has no recipe; it must be `{canonical}` (§2)", t.name),
            ));
            continue;
        }
        for (n, (lineno, cmd)) in body.iter().enumerate() {
            let bare = cmd.trim_start_matches(['@', '-', '+']).trim();
            if n == 0 && bare == *canonical {
                continue;
            }
            out.push(Violation::at(
                *lineno,
                format!(
                    "`{}:` must be exactly `{canonical}` (a leading `@` is allowed) — \
                     found `{cmd}`; per-repo recipe bodies are what drifted, so the body \
                     is now the delegation and the CLI verb reads the project's shape \
                     (cli.md §1)",
                    t.name
                ),
            ));
        }
    }
}

/// §3: a recipe is plain invocations in sequence. A loop or conditional
/// belongs in a `fluxor` subcommand or a script under `tools/`.
fn check_recipe_complexity(targets: &[Target], out: &mut Vec<Violation>) {
    for t in targets {
        for (lineno, cmd) in &t.body {
            // `help`'s `@echo` block is §3's one sanctioned exception,
            // and an `echo` argument is never a control construct.
            let bare = cmd.trim_start_matches(['@', '-', '+']).trim_start();
            if bare.starts_with("echo ") || bare.starts_with("echo\"") {
                continue;
            }
            if let Some(kw) = first_shell_control(cmd) {
                out.push(Violation::at(
                    *lineno,
                    format!(
                        "`{}:` recipe uses shell `{kw}` — §3 allows plain invocations in \
                         sequence only; move it into a `fluxor` subcommand or a script \
                         under `tools/`",
                        t.name
                    ),
                ));
            }
        }
    }
}

/// The first shell control keyword used in *command position* on this
/// line — line start, or after `;`, `&&`, `||`, `|`, `(`. A `for` that
/// is an argument or part of a word (`platform`, `--if-present`) is not
/// a loop.
fn first_shell_control(line: &str) -> Option<&'static str> {
    let mut command_position = true;
    for tok in line.split_whitespace() {
        if command_position {
            if let Some(kw) = SHELL_CONTROL.iter().find(|k| **k == tok) {
                return Some(kw);
            }
        }
        command_position = matches!(tok, ";" | "&&" | "||" | "|" | "(" | "{" | "do" | "then")
            || tok.ends_with(';')
            || tok.ends_with("&&")
            || tok.ends_with('|')
            || tok.ends_with('(');
    }
    None
}

/// §3 again, at file scope: `ifeq`/`ifdef` blocks are per-target
/// dispatch, which is exactly what the CLI's target table already owns.
fn check_file_scope_conditionals(text: &str, out: &mut Vec<Violation>) {
    for (i, raw) in text.lines().enumerate() {
        if raw.starts_with('\t') {
            continue;
        }
        let trimmed = raw.trim_start();
        let Some(word) = trimmed.split_whitespace().next() else {
            continue;
        };
        if MAKE_CONDITIONALS.contains(&word) {
            out.push(Violation::at(
                i + 1,
                format!(
                    "file-scope `{word}` — per-target dispatch is a `fluxor` subcommand or \
                     a script under `tools/`, not a Makefile conditional (§3)"
                ),
            ));
        }
    }
}

/// Every `fluxor <verb>` the file names in command position must resolve
/// against the live CLI, so a renamed or retired verb fails here on the
/// day it moves rather than in a sibling repo weeks later.
fn check_verbs(text: &str, cli_verbs: &BTreeSet<String>, out: &mut Vec<Violation>) {
    if cli_verbs.is_empty() {
        return;
    }
    for (i, line) in text.lines().enumerate() {
        push_unknown_verbs(i + 1, line, cli_verbs, out);
    }
}

/// Report every verb one line names in command position that the CLI
/// does not offer. The one owner of that message: a Makefile line and a
/// shell line differ in how a command is spelled, never in what a
/// retired verb means.
fn push_unknown_verbs(
    lineno: usize,
    line: &str,
    cli_verbs: &BTreeSet<String>,
    out: &mut Vec<Violation>,
) {
    for verb in line.lines().flat_map(command_verbs) {
        if !cli_verbs.contains(&verb) {
            out.push(Violation::at(
                lineno,
                format!(
                    "`fluxor {verb}` is not a CLI command — retired or renamed \
                     (§5: update every in-tree reference in the same change)"
                ),
            ));
        }
    }
}

/// Every retired CLI verb a shell script names.
///
/// §3 sends recipe complexity into `tools/*.sh`, so the scripts are
/// where per-target dispatch and multi-step pipelines now live — and a
/// verb check that stopped at the Makefile would be checking the file
/// the conditionals just left. This is the same check on the other side
/// of that move; only the spelling of a command differs.
///
/// A script calls the CLI through a variable (`FLUXOR=…/fluxor`, then
/// `"$FLUXOR" modules build`), so occurrences of a variable that holds
/// the binary are rewritten to the literal before the shared
/// command-position scan runs.
pub fn check_script(text: &str, cli_verbs: &BTreeSet<String>) -> Vec<Violation> {
    if cli_verbs.is_empty() {
        return Vec::new();
    }
    let vars = cli_vars(text);
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let mut expanded = line.to_string();
        for v in &vars {
            for form in [
                format!("\"${{{v}}}\""),
                format!("\"${v}\""),
                format!("${v}"),
            ] {
                expanded = expanded.replace(&form, "fluxor");
            }
        }
        // A shell line holds several command positions — after `$(`, a
        // pipe, `&&`, `;`. Cutting at each separator turns every one of
        // them into the start of a fragment, which is the position the
        // shared scan already understands.
        for sep in ["$(", "&&", "||", ";", "|", "(", "{"] {
            expanded = expanded.replace(sep, "\n");
        }
        push_unknown_verbs(i + 1, &expanded, cli_verbs, &mut out);
    }
    out
}

/// Shell variables holding the CLI, learned from assignments whose
/// value names the binary — `FLUXOR="${FLUXOR:-target/…/fluxor}"` and
/// the plain `FLUXOR=fluxor` alike. Learned rather than hard-coded to
/// `$FLUXOR`: the name is a script author's choice.
fn cli_vars(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|l| l.trim().split_once('='))
        .filter(|(name, _)| {
            !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        })
        .filter(|(_, value)| {
            let v = value.trim_matches(['"', '}', '\'', ' ']);
            v == "fluxor" || v.ends_with("/fluxor")
        })
        .map(|(name, _)| name.to_string())
        .collect()
}

/// The verbs one Makefile line names in *command position*, which is
/// the only position that has to resolve. A command reference either
/// opens a backtick span or starts the line's payload — after the
/// recipe tab, an `@echo "`, a `#`, and any indent. Everything else on
/// a line is prose ("no fluxor launcher is on PATH", "composed into
/// fluxor graphs"), and a path ending in `/fluxor` is not a command at
/// all. A trailing `:` marks a heading, not an invocation.
fn command_verbs(line: &str) -> Vec<String> {
    let mut spans: Vec<&str> = line.split('`').skip(1).step_by(2).collect();
    let payload = line
        .trim_start()
        .trim_start_matches("@echo \"")
        .trim_start_matches('#')
        .trim_start();
    spans.push(payload);

    spans
        .into_iter()
        .filter_map(|s| s.strip_prefix("fluxor "))
        .filter_map(|rest| {
            let verb: String = rest
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
                .collect();
            let heading = rest[verb.len()..].starts_with(':');
            (!verb.is_empty() && !heading).then_some(verb)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANONICAL: &str = "\
SHELL       := /bin/bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := build

.PHONY: help build test lint ci publish clean

help:
\t@fluxor help --make

build:
\tfluxor build

test:
\tfluxor test

lint:
\tfluxor lint

ci:
\tfluxor ci

publish:
\tfluxor publish

clean:
\tfluxor clean
";

    fn verbs() -> BTreeSet<String> {
        ["help", "build", "test", "lint", "ci", "publish", "clean"]
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    }

    /// §3 sends complexity into `tools/*.sh`, so the scripts carry CLI
    /// calls and must be checked with the Makefile — including the two
    /// spellings a script uses that a recipe does not: the binary behind
    /// a variable, and a command inside `$(…)`.
    #[test]
    fn script_verbs_resolve_through_a_variable_and_inside_substitution() {
        let script = "\
#!/bin/bash
FLUXOR=\"${FLUXOR:-target/release/fluxor}\"
PUBKEY=\"$(\"$FLUXOR\" keygen -k \"$SIGN_KEY\")\"
\"$FLUXOR\" build --check cfg.yaml
\"$FLUXOR\" combine -o out.img fw.bin cfg.yaml
";
        let v = check_script(script, &verbs());
        let lines: Vec<usize> = v.iter().map(|x| x.line).collect();
        assert_eq!(lines, vec![3, 5], "expected keygen and combine, got {v:?}");
        assert!(v[0].msg.contains("`fluxor keygen`"), "{:?}", v[0]);
        assert!(v[1].msg.contains("`fluxor combine`"), "{:?}", v[1]);
    }

    /// A script naming only live verbs is silent, and prose mentioning
    /// the word is not a command reference.
    #[test]
    fn script_with_live_verbs_and_prose_is_clean() {
        let script = "\
#!/bin/bash
# Build one kernel target with the fluxor toolchain.
FLUXOR=\"${FLUXOR:-target/release/fluxor}\"
\"$FLUXOR\" build --check cfg.yaml && \"$FLUXOR\" publish
cp target/release/fluxor /tmp/x
";
        assert!(check_script(script, &verbs()).is_empty());
    }

    /// An unreadable CLI probe disables the check rather than failing
    /// every script in the tree.
    #[test]
    fn script_check_is_disabled_without_a_verb_set() {
        let script = "FLUXOR=./fluxor\n\"$FLUXOR\" nonsense\n";
        assert!(check_script(script, &BTreeSet::new()).is_empty());
    }

    #[test]
    fn the_canonical_skeleton_is_clean() {
        assert_eq!(check(CANONICAL, &verbs()), Vec::new());
    }

    #[test]
    fn a_second_command_in_a_lifecycle_recipe_is_a_violation() {
        let text = CANONICAL.replace("\tfluxor test\n", "\tfluxor test\n\tcargo test --release\n");
        let v = check(&text, &verbs());
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].msg.contains("must be exactly `fluxor test`"), "{v:?}");
        assert!(v[0].msg.contains("cargo test --release"), "{v:?}");
    }

    #[test]
    fn a_lifecycle_prerequisite_is_a_violation() {
        let text = CANONICAL.replace("publish:\n", "publish: build\n");
        let v = check(&text, &verbs());
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].msg.contains("no prerequisites"), "{v:?}");
    }

    #[test]
    fn extra_targets_are_allowed_but_their_recipes_are_not_shell() {
        let ok = format!("{CANONICAL}\nfirmware:\n\t@tools/firmware.sh $(TARGET)\n");
        assert_eq!(check(&ok, &verbs()), Vec::new());

        let looped = format!(
            "{CANONICAL}\nfirmware:\n\tfor t in a b; do build $$t; done\n\te2e && for x in 1; do :; done\n"
        );
        let v = check(&looped, &verbs());
        assert_eq!(v.len(), 2, "{v:?}");
        assert!(v.iter().all(|x| x.msg.contains("shell `for`")), "{v:?}");
    }

    #[test]
    fn a_forbidden_target_name_is_still_caught() {
        let text = format!("{CANONICAL}\nfmt:\n\tcargo fmt --all\n");
        let v = check(&text, &verbs());
        assert!(v.iter().any(|x| x.msg.contains("`fmt:`")), "{v:?}");
    }

    #[test]
    fn file_scope_conditionals_are_caught_with_their_line() {
        let text = format!("{CANONICAL}\nifeq ($(TARGET),pi5)\nRUST_TARGET := x\nendif\n");
        let v = check(&text, &verbs());
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].msg.contains("file-scope `ifeq`"), "{v:?}");
        assert_eq!(v[0].line, CANONICAL.lines().count() + 2);
    }

    #[test]
    fn an_echo_block_and_ordinary_words_are_not_control_constructs() {
        assert_eq!(
            first_shell_control("\t@echo \"if you need help, run …\""),
            None
        );
        assert_eq!(first_shell_control("cargo build --workspace"), None);
        assert_eq!(
            first_shell_control("install -D -m755 $(L) $(B)/fluxor"),
            None
        );
        assert_eq!(
            first_shell_control("for m in *.fmod; do sign $$m; done"),
            Some("for")
        );
        assert_eq!(
            first_shell_control("a && if [ -f x ]; then y; fi"),
            Some("if")
        );
    }

    #[test]
    fn a_retired_verb_fails_where_it_is_written() {
        let text = CANONICAL.replace("\tfluxor ci\n", "\tfluxor verify\n");
        let v = check(&text, &verbs());
        assert!(
            v.iter()
                .any(|x| x.msg.contains("`fluxor verify` is not a CLI command")),
            "{v:?}"
        );
    }

    #[test]
    fn a_missing_preamble_line_names_the_line_it_wants() {
        let text = CANONICAL.replace(".DEFAULT_GOAL := build\n", "");
        let v = check(&text, &verbs());
        assert!(v.iter().any(|x| x.msg.contains(".DEFAULT_GOAL")), "{v:?}");
    }

    /// The verb scan reads command positions only. Prose that happens
    /// to contain the word "fluxor" is not a command reference — the
    /// distinction is the whole reason the phase is usable across
    /// nineteen hand-written Makefiles.
    #[test]
    fn command_verbs_reads_commands_not_prose() {
        assert_eq!(command_verbs("\tfluxor sync"), ["sync"]);
        assert_eq!(
            command_verbs("\t@echo \"  fluxor modules build [--target …]   PIC modules\""),
            ["modules"]
        );
        assert_eq!(
            command_verbs("# the CLI directly (`fluxor build --check …`)"),
            ["build"]
        );
        assert!(command_verbs("\t@echo \"fluxor lifecycle:\"").is_empty());
        assert!(
            command_verbs("\t@echo \"  make check-install  no fluxor launcher on PATH\"")
                .is_empty()
        );
        assert!(command_verbs("\trust-objcopy -O binary target/release/fluxor out.bin").is_empty());
        assert!(command_verbs("# composed into fluxor graphs in `packaging/`").is_empty());
    }

    #[test]
    fn parse_ignores_assignments_and_special_targets() {
        let names: Vec<String> = parse(CANONICAL).into_iter().map(|t| t.name).collect();
        assert_eq!(
            names,
            ["help", "build", "test", "lint", "ci", "publish", "clean"]
        );
    }
}
