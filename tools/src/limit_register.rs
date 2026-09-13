//! The limit-register gate — `fluxor ci`'s `limit-register` phase.
//!
//! A register of the system's deliberate ceilings is worth exactly what its
//! agreement with the code is worth. Fluxor's own register states the rule
//! outright — "an id-shaped ceiling found in source but absent here is a
//! bug" — which is a claim about the code that, unchecked, decays into a
//! claim about the register's last editor's memory.
//!
//! The register is a human document: prose columns carrying the reasoning
//! that makes a ceiling reviewable. Prose is not parseable, so the document
//! also carries a fenced machine-checked block naming, for each ceiling, the
//! `const` and the source file it must still be declared in:
//!
//! ````text
//! ```limit-register
//! MAX_TCP_CONNS | modules/sdk/abi/config.rs | 65536
//! MAX_CHAIN_DEPTH | src/kernel/module/provider.rs | -
//! ```
//! ````
//!
//! `NAME | source path | right-hand side`. The RHS is compared textually
//! after whitespace normalisation, so `2 * MAX_SNAPSHOT` is checked as the
//! expression it is rather than as an evaluated number — the register
//! records what the source says. An RHS of `-` means the constant is
//! per-profile and has no single textual value; its DECLARATION is still
//! required, so deleting or renaming it fails.
//!
//! A constant declared several times behind different `cfg` profiles gets one
//! ROW PER PROFILE, all under the same name:
//!
//! ```text
//! MAX_OPEN_FILES | modules/foundation/fat32/mod.rs | 256
//! MAX_OPEN_FILES | modules/foundation/fat32/mod.rs | 8
//! ```
//!
//! The gate compares the whole set, so a profile added, removed, or retuned
//! is drift. Matching any single declaration instead would pass all three:
//! the profile a register happens to quote stays true while the ones it does
//! not quote drift freely, which is the failure this shape exists to prevent.
//!
//! Two further checks make the block honest rather than decorative:
//!
//! - every name in the block must also appear in the document's prose, so
//!   the machine-checked list and the human-readable table cannot diverge
//!   into two registers;
//! - every ceiling-shaped `const` in a file the register already names is
//!   counted, and those in neither the block nor the exemption block are
//!   REPORTED. A register-named file is one the register vouches for, so a
//!   ceiling appearing there uncovered is exactly the case the stated rule
//!   is about.
//!
//! The coverage half reports rather than fails. Whether a given constant is
//! a policy ceiling or an implementation detail is a question about the
//! subsystem, answerable only by whoever owns it, and a gate that fails
//! until someone invents a hundred rationales gets skipped rather than
//! satisfied. Reporting the count makes the gap a measured number instead of
//! an unenforced sentence; a project whose list is empty promotes the report
//! to a failure with `[ci] limit_register_coverage = "fail"`, after which it
//! cannot grow again.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Default location, overridable with `[ci] limit_register = "..."`.
pub const DEFAULT_REGISTER: &str = "docs/architecture/limit_register.md";

/// One machine-checked row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    pub source: String,
    /// `None` for `-` — declaration required, value unchecked.
    pub rhs: Option<String>,
}

/// What the gate found.
#[derive(Debug, Default)]
pub struct Report {
    /// Distinct constants checked.
    pub checked: usize,
    /// Rows read, which exceeds `checked` by one per extra `cfg` profile.
    pub rows: usize,
    pub failures: Vec<String>,
    /// Ceiling-shaped consts in register-named files that no row covers.
    pub uncovered: Vec<String>,
}

/// Collapse whitespace runs to single spaces and trim — the one
/// normalisation both sides of every RHS comparison pass through, so
/// reformatting a constant is not drift.
fn norm(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Extract the body of the first fenced block with `tag` as its info string.
fn fenced_block<'a>(text: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("```{tag}");
    let mut start = None;
    for (idx, line) in line_offsets(text) {
        let t = line.trim_end();
        match start {
            None => {
                if t == open {
                    start = Some(idx + line.len());
                }
            }
            Some(s) => {
                if t.trim_start().starts_with("```") {
                    return Some(&text[s..idx]);
                }
            }
        }
    }
    None
}

/// `(byte offset, line-with-newline)` pairs.
fn line_offsets(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut pos = 0usize;
    text.split_inclusive('\n').map(move |l| {
        let at = pos;
        pos += l.len();
        (at, l)
    })
}

/// Parse `NAME | source | rhs` rows, skipping blanks and `#` comments.
pub fn parse_rows(block: &str) -> Vec<Row> {
    let mut out = Vec::new();
    for line in block.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(3, '|');
        let (Some(name), Some(source)) = (parts.next(), parts.next()) else {
            continue;
        };
        let rhs = parts.next().map(norm).unwrap_or_default();
        out.push(Row {
            name: name.trim().to_string(),
            source: source.trim().to_string(),
            rhs: if rhs == "-" || rhs.is_empty() {
                None
            } else {
                Some(rhs)
            },
        });
    }
    out
}

/// Every right-hand side `NAME` is declared with in `text`, in order.
///
/// Scans for `const NAME` at a declaration position (preceded by nothing or
/// by `pub`/whitespace, followed by `:` or `=`), then takes the text between
/// the first `=` and the matching `;`. Handles multi-line declarations,
/// which a line-oriented grep cannot.
pub fn declared_rhs(text: &str, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let needle = format!("const {name}");
    let mut from = 0usize;
    while let Some(rel) = text[from..].find(&needle) {
        let at = from + rel;
        from = at + needle.len();
        // The occurrence must be a whole token: `const MAX_A` must not match
        // inside `const MAX_ABC`.
        let after = bytes.get(from).copied().unwrap_or(b' ');
        if after.is_ascii_alphanumeric() || after == b'_' {
            continue;
        }
        // And `const` must start a word.
        if at > 0 {
            let before = bytes[at - 1];
            if before.is_ascii_alphanumeric() || before == b'_' {
                continue;
            }
        }
        let Some(eq_rel) = text[from..].find('=') else {
            continue;
        };
        let eq = from + eq_rel;
        // A `;` before the `=` means this was not a declaration with an
        // initialiser (an associated const in a trait, say).
        if text[from..eq].contains(';') {
            continue;
        }
        let Some(end_rel) = text[eq + 1..].find(';') else {
            continue;
        };
        out.push(norm(&text[eq + 1..eq + 1 + end_rel]));
    }
    out
}

/// Ceiling-shaped constant names declared in `text`.
///
/// Deliberately a NAMING convention rather than a type or value test: a
/// ceiling is recognisable by what it is called, and a convention a reader
/// can apply by eye is one they can also satisfy on purpose.
fn ceiling_consts(text: &str) -> BTreeSet<String> {
    const SUFFIXES: [&str; 7] = [
        "_MAX",
        "_CAP",
        "_CAPACITY",
        "_LIMIT",
        "_BUDGET",
        "_SIZE",
        "_SLOTS",
    ];
    let mut out = BTreeSet::new();
    for (_, line) in line_offsets(text) {
        let Some(rel) = line.find("const ") else {
            continue;
        };
        let rest = &line[rel + "const ".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.len() < 2
            || !name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            continue;
        }
        if name.starts_with("MAX_") || SUFFIXES.iter().any(|s| name.ends_with(s)) {
            out.insert(name);
        }
    }
    out
}

/// Run the gate over one project. `Ok(None)` when the project has no
/// register — a project that has not written one yet is not failing this
/// gate, it is not subject to it.
pub fn check(project_root: &Path, register_rel: &str) -> std::io::Result<Option<Report>> {
    let reg_path = project_root.join(register_rel);
    if !reg_path.is_file() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&reg_path)?;
    let mut report = Report::default();

    let Some(block) = fenced_block(&text, "limit-register") else {
        report.failures.push(format!(
            "{register_rel} has no ```limit-register block — the register states a rule about \
             the source but nothing checks it. Add the fenced block (NAME | source path | RHS)"
        ));
        return Ok(Some(report));
    };
    let rows = parse_rows(block);
    report.rows = rows.len();
    if rows.is_empty() {
        report.failures.push(format!(
            "{register_rel} has an empty ```limit-register block — a gate over nothing reports \
             success over nothing"
        ));
        return Ok(Some(report));
    }
    let exempt: BTreeSet<(String, String)> = fenced_block(&text, "limit-register-exempt")
        .map(parse_rows)
        .unwrap_or_default()
        .into_iter()
        .map(|r| (r.source, r.name))
        .collect();

    // The prose half of the document, for the divergence check: everything
    // outside the machine-checked block.
    let prose = text.replace(block, "");

    let mut by_file: BTreeMap<String, Vec<Row>> = BTreeMap::new();
    for row in rows {
        by_file.entry(row.source.clone()).or_default().push(row);
    }

    for (src, rows) in &by_file {
        let path = project_root.join(src);
        let Ok(body) = std::fs::read_to_string(&path) else {
            for r in rows {
                report.failures.push(format!(
                    "{}: source '{src}' does not exist (register row for {})",
                    register_rel, r.name
                ));
            }
            continue;
        };
        // Rows sharing a name describe one constant's several `cfg`
        // profiles. Grouping them compares the WHOLE profile set: a constant
        // that gains a profile, loses one, or has one profile's value
        // retuned is drift just as much as a single-valued constant
        // changing. Matching any one declaration would pass all three,
        // leaving every profile the register does not happen to quote free
        // to drift.
        let mut grouped: BTreeMap<&str, Vec<&Row>> = BTreeMap::new();
        for r in rows {
            grouped.entry(r.name.as_str()).or_default().push(r);
        }
        for (name, group) in grouped {
            report.checked += 1;
            let found = declared_rhs(&body, name);
            if found.is_empty() {
                report.failures.push(format!(
                    "const {name} is not declared in {src} — it was renamed or removed without \
                     updating {register_rel}"
                ));
                continue;
            }
            // One `-` row anywhere in the group means presence-only.
            if group.iter().all(|r| r.rhs.is_some()) {
                let want: BTreeSet<&str> = group.iter().filter_map(|r| r.rhs.as_deref()).collect();
                let have: BTreeSet<&str> = found.iter().map(String::as_str).collect();
                if want != have {
                    report.failures.push(format!(
                        "const {name} in {src} is declared as [{}], register says [{}]",
                        have.iter().copied().collect::<Vec<_>>().join(", "),
                        want.iter().copied().collect::<Vec<_>>().join(", ")
                    ));
                }
            }
            if !prose.contains(name) {
                report.failures.push(format!(
                    "const {name} is in the machine-checked block of {register_rel} but nowhere \
                     in its prose — the checked list and the readable table have diverged"
                ));
            }
        }

        // Coverage over this file.
        let registered: BTreeSet<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        for c in ceiling_consts(&body) {
            if registered.contains(c.as_str()) || exempt.contains(&(src.clone(), c.clone())) {
                continue;
            }
            report.uncovered.push(format!("{src}::{c}"));
        }
    }
    Ok(Some(report))
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn project(reg: &str, sources: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(DEFAULT_REGISTER);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, reg).unwrap();
        for (rel, body) in sources {
            let f = dir.path().join(rel);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, body).unwrap();
        }
        dir
    }

    fn run(dir: &tempfile::TempDir) -> Report {
        check(dir.path(), DEFAULT_REGISTER).unwrap().unwrap()
    }

    const SRC: &str = "src/a.rs";

    /// A register that agrees with its source passes, and says how much it
    /// checked — a gate that reports "ok" over zero rows is the failure
    /// mode this number exists to rule out.
    #[test]
    fn agreeing_register_passes() {
        let d = project(
            "prose mentions MAX_A\n\n```limit-register\nMAX_A | src/a.rs | 8\n```\n",
            &[(SRC, "pub const MAX_A: usize = 8;\n")],
        );
        let r = run(&d);
        assert!(r.failures.is_empty(), "{:?}", r.failures);
        assert_eq!(r.checked, 1);
    }

    /// The core case: a value edited in source without its row.
    #[test]
    fn value_drift_fails_naming_both_sides() {
        let d = project(
            "prose mentions MAX_A\n\n```limit-register\nMAX_A | src/a.rs | 8\n```\n",
            &[(SRC, "pub const MAX_A: usize = 16;\n")],
        );
        let r = run(&d);
        assert_eq!(r.failures.len(), 1);
        assert!(r.failures[0].contains("[16]"), "{:?}", r.failures);
        assert!(r.failures[0].contains("[8]"), "{:?}", r.failures);
    }

    /// The right-hand side is compared as text, so a constant defined in
    /// terms of another is pinned to that relationship rather than to a
    /// number that would silently stop tracking it.
    #[test]
    fn expression_rhs_is_compared_textually() {
        let d = project(
            "prose mentions MAX_B\n\n```limit-register\nMAX_B | src/a.rs | 2 * MAX_A\n```\n",
            &[(
                SRC,
                "const MAX_A: usize = 8;\npub const MAX_B: usize =  2  *  MAX_A ;\n",
            )],
        );
        assert!(run(&d).failures.is_empty());
    }

    /// Whitespace and line breaks inside a declaration are not drift.
    #[test]
    fn reformatting_is_not_drift() {
        let d = project(
            "prose mentions MAX_A\n\n```limit-register\nMAX_A | src/a.rs | 4 * 1024\n```\n",
            &[(SRC, "pub const MAX_A: usize =\n    4\n    * 1024;\n")],
        );
        assert!(run(&d).failures.is_empty());
    }

    /// One row per profile, and the WHOLE set must match. Matching any
    /// single declaration is what let fluxor's register record 32 for
    /// `MAX_OPEN_FILES` while fat32 said 256 — the 8 row kept passing.
    #[test]
    fn a_changed_profile_fails_even_when_another_still_matches() {
        let src =
            "#[cfg(a)]\npub const MAX_A: usize = 256;\n#[cfg(b)]\npub const MAX_A: usize = 8;\n";
        let agreeing = project(
            "prose mentions MAX_A\n\n```limit-register\nMAX_A | src/a.rs | 256\nMAX_A | src/a.rs | 8\n```\n",
            &[(SRC, src)],
        );
        assert!(run(&agreeing).failures.is_empty());

        let stale = project(
            "prose mentions MAX_A\n\n```limit-register\nMAX_A | src/a.rs | 32\nMAX_A | src/a.rs | 8\n```\n",
            &[(SRC, src)],
        );
        assert_eq!(run(&stale).failures.len(), 1);
    }

    /// A profile added in source without a row is drift too.
    #[test]
    fn an_added_profile_fails() {
        let d = project(
            "prose mentions MAX_A\n\n```limit-register\nMAX_A | src/a.rs | 8\n```\n",
            &[(
                SRC,
                "pub const MAX_A: usize = 8;\n#[cfg(x)]\npub const MAX_A: usize = 4;\n",
            )],
        );
        assert_eq!(run(&d).failures.len(), 1);
    }

    /// `-` requires the declaration but not the value.
    #[test]
    fn dash_checks_presence_only() {
        let present = project(
            "prose mentions MAX_A\n\n```limit-register\nMAX_A | src/a.rs | -\n```\n",
            &[(SRC, "pub const MAX_A: usize = 99;\n")],
        );
        assert!(run(&present).failures.is_empty());

        let renamed = project(
            "prose mentions MAX_A\n\n```limit-register\nMAX_A | src/a.rs | -\n```\n",
            &[(SRC, "pub const MAX_B: usize = 99;\n")],
        );
        assert_eq!(run(&renamed).failures.len(), 1);
    }

    /// A single `-` row makes the whole name presence-only: the register is
    /// then saying it does not check this constant's value, and a partial
    /// profile list would otherwise be read as an exhaustive one.
    #[test]
    fn a_dash_row_makes_the_whole_group_presence_only() {
        let d = project(
            "prose mentions MAX_A\n\n```limit-register\nMAX_A | src/a.rs | 8\nMAX_A | src/a.rs | -\n```\n",
            &[(SRC, "pub const MAX_A: usize = 8;\n#[cfg(x)]\npub const MAX_A: usize = 4;\n")],
        );
        assert!(run(&d).failures.is_empty());
    }

    /// `const MAX_A` must not match inside `const MAX_ABC`.
    #[test]
    fn name_match_is_whole_token() {
        let d = project(
            "prose mentions MAX_A\n\n```limit-register\nMAX_A | src/a.rs | -\n```\n",
            &[(SRC, "pub const MAX_ABC: usize = 1;\n")],
        );
        assert_eq!(run(&d).failures.len(), 1);
    }

    /// The two halves of the document cannot drift into two registers.
    #[test]
    fn a_row_missing_from_the_prose_fails() {
        let d = project(
            "prose mentions nothing\n\n```limit-register\nMAX_A | src/a.rs | 8\n```\n",
            &[(SRC, "pub const MAX_A: usize = 8;\n")],
        );
        let r = run(&d);
        assert_eq!(r.failures.len(), 1);
        assert!(r.failures[0].contains("diverged"), "{:?}", r.failures);
    }

    /// An unregistered ceiling in a register-named file is reported, and
    /// an exemption row retires it.
    #[test]
    fn coverage_reports_then_exemption_retires() {
        let src = "pub const MAX_A: usize = 8;\npub const SCRATCH_SIZE: usize = 4;\n";
        let d = project(
            "prose mentions MAX_A\n\n```limit-register\nMAX_A | src/a.rs | 8\n```\n",
            &[(SRC, src)],
        );
        let r = run(&d);
        assert!(r.failures.is_empty());
        assert_eq!(r.uncovered, vec!["src/a.rs::SCRATCH_SIZE".to_string()]);

        let e = project(
            "prose mentions MAX_A\n\n```limit-register\nMAX_A | src/a.rs | 8\n```\n\n\
             ```limit-register-exempt\nSCRATCH_SIZE | src/a.rs | scratch, not a policy ceiling\n```\n",
            &[(SRC, src)],
        );
        assert!(run(&e).uncovered.is_empty());
    }

    /// A register with no machine-checked block states a rule about the
    /// source that nothing checks — the condition the gate exists to end,
    /// so it is a failure rather than a skip.
    #[test]
    fn a_register_without_a_block_fails() {
        let d = project("just prose\n", &[]);
        let r = run(&d);
        assert_eq!(r.failures.len(), 1);
        assert!(r.failures[0].contains("no ```limit-register block"));
    }

    /// An empty block would otherwise report success over nothing.
    #[test]
    fn an_empty_block_fails() {
        let d = project("prose\n\n```limit-register\n```\n", &[]);
        assert_eq!(run(&d).failures.len(), 1);
    }

    /// A project with no register is not subject to the gate.
    #[test]
    fn a_project_without_a_register_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        assert!(check(dir.path(), DEFAULT_REGISTER).unwrap().is_none());
    }

    /// A row naming a file that does not exist is drift, not a crash.
    #[test]
    fn a_missing_source_file_fails() {
        let d = project(
            "prose mentions MAX_A\n\n```limit-register\nMAX_A | src/gone.rs | 8\n```\n",
            &[],
        );
        let r = run(&d);
        assert_eq!(r.failures.len(), 1);
        assert!(r.failures[0].contains("does not exist"), "{:?}", r.failures);
    }
}
