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
    /// The profile this value belongs to: `+`-joined labels from the
    /// `limit-register-profiles` block, `*` for an unconditional declaration,
    /// or `None` when the row does not say. A group where no row says keeps the
    /// value-set-only comparison; one where any row says is checked pairwise,
    /// so a per-profile register cannot quote one silicon's number against
    /// another's declaration.
    pub profile: Option<String>,
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
    /// Relationships between limits checked from the `limit-constraints`
    /// block.
    pub constraints: usize,
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
        let mut parts = line.splitn(4, '|');
        let (Some(name), Some(source)) = (parts.next(), parts.next()) else {
            continue;
        };
        let rhs = parts.next().map(norm).unwrap_or_default();
        let profile = parts.next().map(norm).filter(|p| !p.is_empty());
        out.push(Row {
            name: name.trim().to_string(),
            source: source.trim().to_string(),
            rhs: if rhs == "-" || rhs.is_empty() {
                None
            } else {
                Some(rhs)
            },
            profile,
        });
    }
    out
}

/// One `const` declaration found in source: the `cfg` predicates it sits
/// behind, and its right-hand side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decl {
    /// Every `cfg(...)` predicate guarding this declaration, innermost last:
    /// its own attribute plus those of every enclosing item. Empty for an
    /// unconditional declaration.
    pub cfgs: Vec<String>,
    pub rhs: String,
}

/// Strip `#[cfg(` … `)]` down to the predicate inside, or `None` if the
/// attribute is not a `cfg`. `cfg_attr` is deliberately not accepted: it
/// conditions an attribute rather than the item's existence, so treating it
/// as a profile guard would invent a profile that does not exist.
fn cfg_predicate(attr: &str) -> Option<String> {
    let t = attr.trim();
    let inner = t.strip_prefix("#[")?.strip_suffix(']')?.trim();
    let pred = inner.strip_prefix("cfg(")?.strip_suffix(')')?;
    Some(norm(pred))
}

/// True for a line that CONSUMES the attributes gathered above it — that is,
/// any line which is not itself an attribute, a comment or blank.
///
/// Deliberately not a list of item keywords. An allowlist of what an item
/// looks like is a list that will be short one entry: `modules/sdk/abi/config.rs`
/// re-exports its three profile modules as three consecutive
/// `#[cfg(...)] pub use profile_*::*;` lines, and a list omitting `use` leaves
/// all three cfgs unconsumed, to accumulate onto the next declaration and
/// report it as `embedded+host+wasm` — a profile that cannot exist. What
/// matters is that attributes bind to the NEXT thing, whatever it is.
fn consumes_attrs(line: &str) -> bool {
    let t = line.trim_start();
    !(t.is_empty() || t.starts_with("//") || t.starts_with("#[") || t.starts_with("#!["))
}

/// Every declaration of `NAME` in `text`, each with the `cfg` predicates that
/// guard it.
///
/// The profile a value belongs to is not a property of the declaration alone:
/// `MAX_TCP_CONNS = 2` is the rp2040 value only because it sits inside
/// `mod profile_embedded` AND behind `cfg(fluxor_silicon = "rp2040")`. So the
/// scan carries a stack of enclosing item `cfg`s alongside the attributes
/// immediately above each declaration, and a declaration's guard set is the
/// join. A gate that read only the nearest attribute would call the embedded
/// and host `MAX_CONNS` the same profile and be unable to say which register
/// row described which silicon — the gap that let a wrong RP2040 memory figure
/// stand unchallenged.
pub fn declared(text: &str, name: &str) -> Vec<Decl> {
    let mut out = Vec::new();
    // Enclosing items: (brace depth the item's body sits at, its cfgs).
    let mut scope: Vec<(usize, Vec<String>)> = Vec::new();
    // Attributes gathered since the last item line.
    let mut pending: Vec<String> = Vec::new();
    // A multi-line attribute in progress, and its bracket balance.
    let mut attr_acc = String::new();
    let mut attr_depth = 0i32;
    let mut depth = 0usize;

    for (off, raw) in line_offsets(text) {
        let line = raw.trim_end();
        let trimmed = line.trim_start();

        // Accumulate an attribute, which may span lines.
        if !attr_acc.is_empty() || trimmed.starts_with("#[") {
            attr_acc.push_str(trimmed);
            attr_depth += trimmed.matches('[').count() as i32;
            attr_depth -= trimmed.matches(']').count() as i32;
            if attr_depth <= 0 {
                if let Some(p) = cfg_predicate(&attr_acc) {
                    pending.push(p);
                }
                attr_acc.clear();
                attr_depth = 0;
            }
            continue;
        }

        let is_item = consumes_attrs(line);
        let mut decl_cfgs: Option<Vec<String>> = None;

        if is_item {
            // This declaration's full guard set, innermost last.
            let mut cfgs: Vec<String> = scope.iter().flat_map(|(_, c)| c.clone()).collect();
            cfgs.extend(pending.iter().cloned());
            decl_cfgs = Some(cfgs);
        }

        // Does this line declare the constant we are after? Reuse the
        // offset-based RHS scan so a multi-line initialiser still reads.
        if is_item {
            if let Some(rhs) = rhs_at(text, off, name) {
                out.push(Decl {
                    cfgs: decl_cfgs.clone().unwrap_or_default(),
                    rhs,
                });
            }
        }

        // Brace bookkeeping, then scope push/pop. An item line that opens a
        // block becomes an enclosing scope for everything inside it.
        let opens = line.matches('{').count();
        let closes = line.matches('}').count();
        let before = depth;
        depth = depth + opens - closes.min(depth + opens);
        if is_item && opens > closes && !pending.is_empty() {
            scope.push((before + 1, std::mem::take(&mut pending)));
        }
        if is_item {
            pending.clear();
        }
        while let Some(&(d, _)) = scope.last() {
            if depth < d {
                scope.pop();
            } else {
                break;
            }
        }
    }
    out
}

/// The right-hand side of a `const NAME` declared on the line starting at
/// `off`, or `None` if that line declares something else.
fn rhs_at(text: &str, off: usize, name: &str) -> Option<String> {
    let line_end = text[off..]
        .find('\n')
        .map(|i| off + i)
        .unwrap_or(text.len());
    let line = &text[off..line_end];
    let needle = format!("const {name}");
    let rel = line.find(&needle)?;
    let at = off + rel;
    let after_idx = at + needle.len();
    // `const MAX_A` must not match inside `const MAX_ABC`.
    let after = text.as_bytes().get(after_idx).copied().unwrap_or(b' ');
    if after.is_ascii_alphanumeric() || after == b'_' {
        return None;
    }
    if at > 0 {
        let before = text.as_bytes()[at - 1];
        if before.is_ascii_alphanumeric() || before == b'_' {
            return None;
        }
    }
    let eq = after_idx + text[after_idx..].find('=')?;
    // A `;` before the `=` means there was no initialiser here.
    if text[after_idx..eq].contains(';') {
        return None;
    }
    let end = eq + 1 + text[eq + 1..].find(';')?;
    Some(norm(&text[eq + 1..end]))
}

/// Every right-hand side `NAME` is declared with in `text`, in order —
/// `declared` without the profile context, for the value-set comparison a
/// register that has not adopted the profile column still gets.
pub fn declared_rhs(text: &str, name: &str) -> Vec<String> {
    declared(text, name).into_iter().map(|d| d.rhs).collect()
}

/// The original byte-oriented scan, kept as a DIFFERENTIAL ORACLE for
/// `declared`.
///
/// `declared` is line-oriented because a declaration's `cfg` guards are found
/// by walking scopes, and a line filter (`opens_item`) is how it decides what a
/// declaration looks like. A filter is exactly the kind of thing that silently
/// stops matching a declaration form nobody thought to try. This function
/// answers the same question without any notion of lines or scopes, and a test
/// runs both over the real per-profile config and asserts they agree — so a
/// declaration the new scanner drops is a test failure rather than a register
/// row that quietly checks nothing.
#[cfg(test)]
fn declared_rhs_by_scan(text: &str, name: &str) -> Vec<String> {
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

// ── Constraints ───────────────────────────────────────────────────────

/// One row of the `limit-constraints` block: a RELATIONSHIP between limits,
/// and where it is enforced.
///
/// Values are only half of a resource envelope. `MAX_SESSIONS` being 512 and
/// `MAX_TCP_CONNS` being 65536 are both true and both checked, and neither says
/// that the first must not exceed the second — so a tuning pass that lowers the
/// connection table below the session table breaks an invariant no row covers.
/// Those couplings are exactly what gets missed when sizes are retuned per
/// silicon, because retuning moves many numbers at once and the constraint
/// between two of them is nobody's edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Constraint {
    /// The relation as it reads in the source assert, or as a `NAME@path`
    /// comparison for a derived one.
    pub relation: String,
    /// The file whose `assert!` enforces it, or `derived` when the relation
    /// holds between two register rows by identical derivation.
    pub enforced_in: String,
}

/// Parse `relation | enforced-in` rows.
pub fn parse_constraints(block: &str) -> Vec<Constraint> {
    let mut out = Vec::new();
    for line in block.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((rel, where_)) = line.rsplit_once('|') else {
            continue;
        };
        out.push(Constraint {
            relation: norm(rel),
            enforced_in: norm(where_),
        });
    }
    out
}

/// The CONDITION of every `assert!` family macro in `text`, whitespace
/// normalised.
///
/// Only the condition, never the message: a coupling stated in an assert's
/// failure text ("cannot exceed") reads convincingly while enforcing nothing,
/// and a gate satisfied by prose inside a string is a gate satisfied by prose.
fn assert_conditions(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    for mac in ["assert!", "assert_eq!", "assert_ne!"] {
        let mut from = 0usize;
        while let Some(rel) = text[from..].find(mac) {
            let at = from + rel;
            from = at + mac.len();
            // `debug_assert!` and `static_assert!` end with the same text; a
            // preceding name character means this is one of those, which is
            // fine — they enforce too — but `xassert!` is not a macro we know,
            // so require the char before to be a non-identifier or `_`.
            let Some(open_rel) = text[from..].find('(') else {
                break;
            };
            let open = from + open_rel;
            if !text[from..open].trim().is_empty() {
                continue;
            }
            let mut depth = 0i32;
            let mut i = open;
            let mut in_str = false;
            let mut esc = false;
            let mut comma = None;
            let mut close = None;
            while i < bytes.len() {
                let c = bytes[i];
                if in_str {
                    if esc {
                        esc = false;
                    } else if c == b'\\' {
                        esc = true;
                    } else if c == b'"' {
                        in_str = false;
                    }
                } else {
                    match c {
                        b'"' => in_str = true,
                        b'(' | b'[' | b'{' => depth += 1,
                        b')' | b']' | b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                close = Some(i);
                                break;
                            }
                        }
                        b',' if depth == 1 && comma.is_none() => comma = Some(i),
                        _ => {}
                    }
                }
                i += 1;
            }
            let Some(close) = close else { break };
            let end = comma.unwrap_or(close);
            out.push(norm(&text[open + 1..end]));
            from = close;
        }
    }
    out
}

/// A `NAME@path` reference in a derived constraint.
fn parse_ref(s: &str) -> Option<(String, String)> {
    let (name, path) = s.split_once('@')?;
    Some((norm(name), norm(path)))
}

/// The profile vocabulary: label → the `cfg` predicate it names.
///
/// Declared in the register rather than built in, because the labels are the
/// project's own deployment classes and a gate that invented them would be
/// asserting a vocabulary nobody agreed to. Parsed from a second fenced block:
///
/// ````text
/// ```limit-register-profiles
/// host     | target_arch = "aarch64"
/// rp2040   | fluxor_silicon = "rp2040"
/// ```
/// ````
pub fn parse_profiles(block: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in block.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((label, pred)) = line.split_once('|') else {
            continue;
        };
        out.insert(norm(label), norm(pred));
    }
    out
}

/// The profile label for one declaration: every guarding `cfg` mapped through
/// the vocabulary, sorted and `+`-joined. `*` for an unguarded declaration.
///
/// `Err` names the predicate that has no label. Failing on an unmapped
/// predicate is the point: a new `cfg` profile added to the source must be
/// NAMED in the register before any row can describe it, so a silicon cannot
/// arrive with its limits undocumented.
fn profile_label(cfgs: &[String], vocab: &BTreeMap<String, String>) -> Result<String, String> {
    if cfgs.is_empty() {
        return Ok("*".to_string());
    }
    let by_pred: BTreeMap<&str, &str> = vocab
        .iter()
        .map(|(l, p)| (p.as_str(), l.as_str()))
        .collect();
    let mut labels = BTreeSet::new();
    for c in cfgs {
        match by_pred.get(c.as_str()) {
            Some(l) => {
                labels.insert(*l);
            }
            None => return Err(c.clone()),
        }
    }
    Ok(labels.into_iter().collect::<Vec<_>>().join("+"))
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
    let profiles = fenced_block(&text, "limit-register-profiles")
        .map(parse_profiles)
        .unwrap_or_default();
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

    // Relationships, checked before values: a coupling that has lost its
    // assert is a defect the value rows cannot show, because every value in it
    // is individually correct.
    if let Some(cblock) = fenced_block(&text, "limit-constraints") {
        let all_rows = parse_rows(block);
        for c in parse_constraints(cblock) {
            report.constraints += 1;
            if c.enforced_in == "derived" {
                // A cross-module relation, where no single compilation sees
                // both sides. Two PIC modules on the same channel cannot assert
                // about each other's constants, so the only checkable form of
                // "these must agree" is that both are DERIVED the same way —
                // which is stronger than an inequality anyway.
                let Some((lhs, rhs)) = c.relation.split_once("==") else {
                    report.failures.push(format!(
                        "{register_rel} constraint '{}' is marked derived but is not an \
                         equality — a derived constraint is checked by both sides having the same \
                         recorded right-hand side, which only `==` states",
                        c.relation
                    ));
                    continue;
                };
                let (Some(a), Some(b)) = (parse_ref(lhs), parse_ref(rhs)) else {
                    report.failures.push(format!(
                        "{register_rel} constraint '{}' must name both sides as NAME@path so each \
                         resolves to a register row",
                        c.relation
                    ));
                    continue;
                };
                let find = |n: &str, f: &str| -> Option<String> {
                    all_rows
                        .iter()
                        .find(|r| r.name == n && r.source == f)
                        .and_then(|r| r.rhs.clone())
                };
                match (find(&a.0, &a.1), find(&b.0, &b.1)) {
                    (Some(x), Some(y)) if x == y => {}
                    (Some(x), Some(y)) => report.failures.push(format!(
                        "{register_rel} constraint '{}' does not hold: {}@{} is '{x}' and {}@{} is \
                         '{y}'. They sit on the same channel carrying the same records, so they \
                         must be derived identically, not merely both be plausible",
                        c.relation, a.0, a.1, b.0, b.1
                    )),
                    _ => report.failures.push(format!(
                        "{register_rel} constraint '{}' names a row that is not in the register \
                         (or has no recorded value): {}@{} / {}@{}",
                        c.relation, a.0, a.1, b.0, b.1
                    )),
                }
                continue;
            }
            let cpath = project_root.join(&c.enforced_in);
            let Ok(cbody) = std::fs::read_to_string(&cpath) else {
                report.failures.push(format!(
                    "{register_rel} constraint '{}' names '{}', which does not exist",
                    c.relation, c.enforced_in
                ));
                continue;
            };
            if !assert_conditions(&cbody)
                .iter()
                .any(|cond| cond.contains(&c.relation))
            {
                report.failures.push(format!(
                    "{register_rel} records the constraint '{}' as enforced in {}, but no \
                     assert! there has it as its condition — the coupling is documented and \
                     unenforced, which is the state the register exists to make impossible",
                    c.relation, c.enforced_in
                ));
            }
        }
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
            let found = declared(&body, name);
            if found.is_empty() {
                report.failures.push(format!(
                    "const {name} is not declared in {src} — it was renamed or removed without \
                     updating {register_rel}"
                ));
                continue;
            }
            // One `-` row anywhere in the group means presence-only.
            if group.iter().all(|r| r.rhs.is_some()) {
                // A group where any row names its profile is checked PAIRWISE:
                // the register then claims which value belongs to which
                // deployment class, and that claim is what a reader sizing a
                // device relies on. Comparing only the value set would let a
                // register say 2 for rp2040 and 8 for rp2350 while the source
                // said the opposite, and pass.
                let labelled = group.iter().any(|r| r.profile.is_some());
                if labelled {
                    let mut unlabelled = group.iter().filter(|r| r.profile.is_none()).peekable();
                    if unlabelled.peek().is_some() {
                        report.failures.push(format!(
                            "const {name} in {src} has {} register row(s) naming a profile and \
                             {} not — a partly-labelled group reads as though the unlabelled rows \
                             applied everywhere. Give every row a profile or none",
                            group.iter().filter(|r| r.profile.is_some()).count(),
                            unlabelled.count()
                        ));
                        continue;
                    }
                    let mut have: BTreeSet<(String, String)> = BTreeSet::new();
                    let mut unmapped = false;
                    for d in &found {
                        match profile_label(&d.cfgs, &profiles) {
                            Ok(l) => {
                                have.insert((l, d.rhs.clone()));
                            }
                            Err(pred) => {
                                report.failures.push(format!(
                                    "const {name} in {src} sits behind cfg({pred}), which no \
                                     label in the ```limit-register-profiles block of \
                                     {register_rel} names — name the profile there, so a row can \
                                     say which deployment class this value is for"
                                ));
                                unmapped = true;
                                break;
                            }
                        }
                    }
                    if unmapped {
                        continue;
                    }
                    let want: BTreeSet<(String, String)> = group
                        .iter()
                        .filter_map(|r| Some((r.profile.clone()?, r.rhs.clone()?)))
                        .collect();
                    if want != have {
                        let fmt = |s: &BTreeSet<(String, String)>| {
                            s.iter()
                                .map(|(p, v)| format!("{p}={v}"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        };
                        report.failures.push(format!(
                            "const {name} in {src} is declared as [{}], register says [{}]",
                            fmt(&have),
                            fmt(&want)
                        ));
                    }
                } else {
                    let want: BTreeSet<&str> =
                        group.iter().filter_map(|r| r.rhs.as_deref()).collect();
                    let have: BTreeSet<&str> = found.iter().map(|d| d.rhs.as_str()).collect();
                    if want != have {
                        report.failures.push(format!(
                            "const {name} in {src} is declared as [{}], register says [{}]",
                            have.iter().copied().collect::<Vec<_>>().join(", "),
                            want.iter().copied().collect::<Vec<_>>().join(", ")
                        ));
                    }
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

    /// The profile column: a group whose rows name profiles is checked
    /// pairwise, so the register's claim about WHICH silicon holds WHICH value
    /// is the claim that gets checked.
    #[test]
    fn profile_rows_are_checked_pairwise() {
        const SRC_BODY: &str = concat!(
            "#[cfg(target_arch = \"aarch64\")]\n",
            "mod profile_host {\n",
            "    pub const MAX_A: usize = 256;\n",
            "}\n",
            "#[cfg(not(target_arch = \"aarch64\"))]\n",
            "mod profile_embedded {\n",
            "    #[cfg(not(fluxor_silicon = \"rp2040\"))]\n",
            "    pub const MAX_A: usize = 8;\n",
            "    #[cfg(fluxor_silicon = \"rp2040\")]\n",
            "    pub const MAX_A: usize = 2;\n",
            "}\n",
        );
        const VOCAB: &str = concat!(
            "```limit-register-profiles\n",
            "host | target_arch = \"aarch64\"\n",
            "embedded | not(target_arch = \"aarch64\")\n",
            "rp2350 | not(fluxor_silicon = \"rp2040\")\n",
            "rp2040 | fluxor_silicon = \"rp2040\"\n",
            "```\n",
        );
        let agreeing = project(
            &format!(
                "prose mentions MAX_A\n\n{VOCAB}\n```limit-register\n\
                 MAX_A | src/a.rs | 256 | host\n\
                 MAX_A | src/a.rs | 8 | embedded+rp2350\n\
                 MAX_A | src/a.rs | 2 | embedded+rp2040\n```\n"
            ),
            &[(SRC, SRC_BODY)],
        );
        let r = run(&agreeing);
        assert!(r.failures.is_empty(), "{:?}", r.failures);

        // The failure the value-set comparison cannot see: the right VALUES
        // attributed to the wrong SILICON. Both sets are {256, 8, 2}.
        let swapped = project(
            &format!(
                "prose mentions MAX_A\n\n{VOCAB}\n```limit-register\n\
                 MAX_A | src/a.rs | 256 | host\n\
                 MAX_A | src/a.rs | 2 | embedded+rp2350\n\
                 MAX_A | src/a.rs | 8 | embedded+rp2040\n```\n"
            ),
            &[(SRC, SRC_BODY)],
        );
        let r = run(&swapped);
        assert_eq!(r.failures.len(), 1, "{:?}", r.failures);
        assert!(r.failures[0].contains("rp2040=2"), "{:?}", r.failures);
    }

    /// Attributes bind to the NEXT thing, whatever it is — including a `use`.
    ///
    /// `config.rs` re-exports its three profile modules as three consecutive
    /// `#[cfg(...)] pub use profile_*::*;` lines. With an item-keyword allowlist
    /// that omitted `use`, none of the three was consumed, all three accumulated,
    /// and the next declaration reported as `embedded+host+wasm` — a profile that
    /// cannot exist. The value-set comparison could not see this; only the
    /// profile column could.
    #[test]
    fn a_use_statement_consumes_the_attributes_above_it() {
        let src = concat!(
            "#[cfg(target_arch = \"aarch64\")]\n",
            "pub use profile_host::*;\n",
            "#[cfg(target_arch = \"wasm32\")]\n",
            "pub use profile_wasm::*;\n",
            "pub const MAX_A: usize = 5;\n",
        );
        let d = project(
            "prose mentions MAX_A\n\n```limit-register-profiles\n\
             host | target_arch = \"aarch64\"\n```\n\
             \n```limit-register\nMAX_A | src/a.rs | 5 | *\n```\n",
            &[(SRC, src)],
        );
        let r = run(&d);
        assert!(
            r.failures.is_empty(),
            "the cfgs on the `use` lines leaked onto MAX_A: {:?}",
            r.failures
        );
    }

    /// A `cfg` profile the register's vocabulary does not name fails, so a new
    /// silicon cannot arrive with its limits undescribed.
    #[test]
    fn an_unnamed_cfg_profile_fails() {
        let d = project(
            "prose mentions MAX_A\n\n```limit-register-profiles\nhost | target_arch = \"aarch64\"\n```\n\
             \n```limit-register\nMAX_A | src/a.rs | 4 | host\n```\n",
            &[(
                SRC,
                "#[cfg(target_arch = \"aarch64\")]\npub const MAX_A: usize = 4;\n\
                 #[cfg(fluxor_silicon = \"rp2040\")]\npub const MAX_A: usize = 1;\n",
            )],
        );
        let r = run(&d);
        assert_eq!(r.failures.len(), 1, "{:?}", r.failures);
        assert!(r.failures[0].contains("rp2040"), "{:?}", r.failures);
        assert!(
            r.failures[0].contains("limit-register-profiles"),
            "{:?}",
            r.failures
        );
    }

    /// Half a group labelled is refused rather than half-checked: an unlabelled
    /// row beside labelled ones reads as "and this one applies everywhere".
    #[test]
    fn a_partly_labelled_group_fails() {
        let d = project(
            "prose mentions MAX_A\n\n```limit-register-profiles\nhost | target_arch = \"aarch64\"\n```\n\
             \n```limit-register\nMAX_A | src/a.rs | 4 | host\nMAX_A | src/a.rs | 1\n```\n",
            &[(
                SRC,
                "#[cfg(target_arch = \"aarch64\")]\npub const MAX_A: usize = 4;\n\
                 pub const MAX_A: usize = 1;\n",
            )],
        );
        let r = run(&d);
        assert_eq!(r.failures.len(), 1, "{:?}", r.failures);
        assert!(r.failures[0].contains("partly-labelled") || r.failures[0].contains("profile"));
    }

    /// An unconditional declaration's profile is `*`, so a register can state
    /// "this one is the same everywhere" and have that checked too.
    #[test]
    fn an_unconditional_declaration_is_star() {
        let d = project(
            "prose mentions MAX_A\n\n```limit-register\nMAX_A | src/a.rs | 7 | *\n```\n",
            &[(SRC, "pub const MAX_A: usize = 7;\n")],
        );
        assert!(run(&d).failures.is_empty());
    }

    /// A constraint the register records as enforced must actually be an
    /// assert's CONDITION in the named file.
    #[test]
    fn a_constraint_must_be_an_assert_condition() {
        let reg = |c: &str| {
            format!(
                "prose mentions MAX_A and MAX_B\n\n```limit-register\n\
                 MAX_A | src/a.rs | 8\nMAX_B | src/a.rs | 4\n```\n\
                 \n```limit-constraints\n{c}\n```\n"
            )
        };
        let enforced = project(
            &reg("MAX_B <= MAX_A | src/a.rs"),
            &[(
                SRC,
                "pub const MAX_A: usize = 8;\npub const MAX_B: usize = 4;\n\
                 const _: () = assert!(MAX_B <= MAX_A, \"B cannot exceed A\");\n",
            )],
        );
        let r = run(&enforced);
        assert!(r.failures.is_empty(), "{:?}", r.failures);
        assert_eq!(r.constraints, 1);

        // The failure this exists for: the coupling is written down and the
        // assert has been deleted.
        let documented_only = project(
            &reg("MAX_B <= MAX_A | src/a.rs"),
            &[(
                SRC,
                "pub const MAX_A: usize = 8;\npub const MAX_B: usize = 4;\n",
            )],
        );
        let r = run(&documented_only);
        assert_eq!(r.failures.len(), 1, "{:?}", r.failures);
        assert!(r.failures[0].contains("unenforced"), "{:?}", r.failures);
    }

    /// A coupling named only in an assert's MESSAGE does not satisfy the gate:
    /// prose inside a string enforces nothing, and reads exactly like enforcement.
    #[test]
    fn a_constraint_in_an_assert_message_does_not_count() {
        let d = project(
            "prose mentions MAX_A and MAX_B\n\n```limit-register\n\
             MAX_A | src/a.rs | 8\nMAX_B | src/a.rs | 4\n```\n\
             \n```limit-constraints\nMAX_B <= MAX_A | src/a.rs\n```\n",
            &[(
                SRC,
                "pub const MAX_A: usize = 8;\npub const MAX_B: usize = 4;\n\
                 const _: () = assert!(true, \"MAX_B <= MAX_A holds, honest\");\n",
            )],
        );
        let r = run(&d);
        assert_eq!(r.failures.len(), 1, "{:?}", r.failures);
        assert!(r.failures[0].contains("unenforced"), "{:?}", r.failures);
    }

    /// A `derived` constraint is the cross-module form: no compilation sees both
    /// sides, so agreement is checked as identical derivation between two rows.
    #[test]
    fn a_derived_constraint_compares_two_rows() {
        let reg = |a: &str, b: &str| {
            format!(
                "prose mentions REC_BUF\n\n```limit-register\n\
                 REC_BUF | src/a.rs | {a}\nREC_BUF | src/b.rs | {b}\n```\n\
                 \n```limit-constraints\n\
                 REC_BUF@src/a.rs == REC_BUF@src/b.rs | derived\n```\n"
            )
        };
        let same = project(
            &reg(
                "if TINY { 512 } else { 4096 }",
                "if TINY { 512 } else { 4096 }",
            ),
            &[
                (
                    SRC,
                    "pub const REC_BUF: usize = if TINY { 512 } else { 4096 };\n",
                ),
                (
                    "src/b.rs",
                    "pub const REC_BUF: usize = if TINY { 512 } else { 4096 };\n",
                ),
            ],
        );
        let r = run(&same);
        assert!(r.failures.is_empty(), "{:?}", r.failures);
        assert_eq!(r.constraints, 1);

        // One side retuned alone — the exact drift the constraint names.
        let drifted = project(
            &reg(
                "if TINY { 256 } else { 4096 }",
                "if TINY { 512 } else { 4096 }",
            ),
            &[
                (
                    SRC,
                    "pub const REC_BUF: usize = if TINY { 256 } else { 4096 };\n",
                ),
                (
                    "src/b.rs",
                    "pub const REC_BUF: usize = if TINY { 512 } else { 4096 };\n",
                ),
            ],
        );
        let r = run(&drifted);
        assert_eq!(r.failures.len(), 1, "{:?}", r.failures);
        assert!(
            r.failures[0].contains("derived identically"),
            "{:?}",
            r.failures
        );
    }

    /// The differential oracle: the line-oriented scanner that finds `cfg`
    /// scopes must find exactly the declarations the scope-blind byte scan
    /// finds. Run over the REAL per-profile config, which is the file whose
    /// shape the scanner exists to read.
    #[test]
    fn the_cfg_scanner_finds_every_declaration_the_flat_scan_does() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let body = std::fs::read_to_string(root.join("modules/sdk/abi/config.rs")).unwrap();
        let names = ceiling_consts(&body);
        assert!(names.len() > 10, "expected the real config to be scanned");
        for name in &names {
            let mut scoped: Vec<String> =
                declared(&body, name).into_iter().map(|d| d.rhs).collect();
            let mut flat = declared_rhs_by_scan(&body, name);
            scoped.sort();
            flat.sort();
            assert_eq!(scoped, flat, "declaration set differs for {name}");
        }
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

#[cfg(test)]
mod profile_probe {
    //! A probe, not a gate: prints every register-named file's per-profile
    //! declarations so the register's profile column can be POPULATED from what
    //! the source says rather than from someone's recollection of it. Ignored by
    //! default; run with `--ignored --nocapture` when editing the register.
    use super::*;
    use std::path::Path;

    /// Runs the real gate over fluxor's OWN register and prints what it found.
    /// `fluxor ci` is the gate; this is the fast loop while editing the document.
    #[test]
    #[ignore = "a reporting probe for editing the register, not a check"]
    fn report_own_register() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let r = check(root, DEFAULT_REGISTER).unwrap().unwrap();
        println!(
            "checked {} ceilings over {} rows, {} couplings, {} uncovered",
            r.checked,
            r.rows,
            r.constraints,
            r.uncovered.len()
        );
        for f in &r.failures {
            println!("FAIL {f}");
        }
        for u in &r.uncovered {
            println!("UNCOVERED {u}");
        }
        assert!(r.failures.is_empty(), "{} failure(s)", r.failures.len());
    }

    #[test]
    #[ignore = "a reporting probe for editing the register, not a check"]
    fn print_declared_profiles() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let text = std::fs::read_to_string(root.join(DEFAULT_REGISTER)).unwrap();
        let block = fenced_block(&text, "limit-register").unwrap();
        let profiles = fenced_block(&text, "limit-register-profiles")
            .map(parse_profiles)
            .unwrap_or_default();
        let mut seen = BTreeSet::new();
        for row in parse_rows(block) {
            if !seen.insert((row.source.clone(), row.name.clone())) {
                continue;
            }
            let Ok(body) = std::fs::read_to_string(root.join(&row.source)) else {
                continue;
            };
            // Every row, including the single unconditional ones: `*` is a
            // claim worth checking too — it says this constant has ONE
            // declaration that applies everywhere, so a `cfg` split added later
            // fails the gate instead of quietly becoming undocumented.
            for d in declared(&body, &row.name) {
                let label = match profile_label(&d.cfgs, &profiles) {
                    Ok(l) => l,
                    Err(p) => format!("UNMAPPED<{p}>"),
                };
                println!("{} | {} | {} | {}", row.name, row.source, d.rhs, label);
            }
        }
    }
}
