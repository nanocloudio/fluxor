//! Hygiene scanner — AST-based lint over the source tree.
//!
//!   1. Parse Rust as AST via `syn`.
//!   2. Per-file checks:
//!      - Inline-test ban for tiers listed in
//!        `fluxor.toml::[ci.hygiene].forbid_inline_tests`. Strict
//!        mode bans every form; permissive mode allows a bottom-of-
//!        file `#[cfg(test)] mod tests { … }` block sized to
//!        `max_inline_lines`.
//!      - `#[allow]` discipline: every `#[allow(...)]` and
//!        `#![allow(...)]` must carry `reason = "..."`.
//!   3. Skip directories named `generated/`, `target/`, `.git/`,
//!      `node_modules/`, `.context/`; skip files starting with
//!      `// @generated` on the first line.
//!   4. Single-pass — emit every violation, exit non-zero at end.
//!   5. Validate exemptions: paths must exist, `expires` must not be
//!      in the past, and the file must still violate the named rule
//!      (otherwise the exemption has silently rotted).

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use syn::visit::Visit;
use syn::{Attribute, ItemMod, Meta};

/// One discrete rule the scanner enforces. Matches the `rule = "..."`
/// discriminator on `[[ci.hygiene.exemption]]` rows in `fluxor.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    InlineTests,
    AllowWithoutReason,
}

impl Rule {
    pub fn as_str(self) -> &'static str {
        match self {
            Rule::InlineTests => "inline-tests",
            Rule::AllowWithoutReason => "allow-without-reason",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "inline-tests" => Some(Rule::InlineTests),
            "allow-without-reason" => Some(Rule::AllowWithoutReason),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Strict,
    Permissive,
}

/// Parsed `[[ci.hygiene.exemption]]` row.
#[derive(Debug, Clone, Deserialize)]
struct ExemptionRaw {
    path: String,
    rule: String,
    #[serde(default)]
    #[allow(dead_code, reason = "field is documentation-only at scan time")]
    reason: String,
    #[serde(default)]
    expires: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct FluxorToml {
    #[serde(default)]
    ci: CiTable,
}

#[derive(Debug, Default, Deserialize)]
struct CiTable {
    #[serde(default)]
    hygiene: HygieneTable,
}

#[derive(Debug, Default, Deserialize)]
struct HygieneTable {
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    forbid_inline_tests: Vec<String>,
    #[serde(default)]
    max_inline_lines: Option<usize>,
    #[serde(default)]
    exemption: Vec<ExemptionRaw>,
}

#[derive(Debug, Clone)]
pub struct Exemption {
    pub path: PathBuf,
    pub rule: Rule,
    pub expires: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub mode: Mode,
    pub forbid_inline_tests: Vec<String>,
    pub max_inline_lines: usize,
    pub exemptions: Vec<Exemption>,
}

impl Default for Config {
    fn default() -> Self {
        // Defaults match the standard text: strict mode, both modules
        // and src under the inline-test ban, 80-line cap for the
        // (unused-by-default) permissive mode.
        Self {
            mode: Mode::Strict,
            forbid_inline_tests: vec!["modules".to_string(), "src".to_string()],
            max_inline_lines: 80,
            exemptions: Vec::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("unknown hygiene mode {0:?}: expected \"strict\" or \"permissive\"")]
    UnknownMode(String),
    #[error("unknown hygiene rule {0:?}: expected \"inline-tests\" or \"allow-without-reason\"")]
    UnknownRule(String),
}

impl Config {
    /// Load `<project_root>/fluxor.toml`. Missing file yields defaults
    /// — projects that haven't adopted the standard yet still get a
    /// meaningful scan against the prescribed baseline.
    pub fn load(project_root: &Path) -> Result<Self, ConfigError> {
        let path = project_root.join("fluxor.toml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| ConfigError::Read {
            path: path.clone(),
            source,
        })?;
        let parsed: FluxorToml = toml::from_str(&raw).map_err(|source| ConfigError::Parse {
            path: path.clone(),
            source,
        })?;
        let h = parsed.ci.hygiene;
        let mode = match h.mode.as_deref() {
            None | Some("strict") => Mode::Strict,
            Some("permissive") => Mode::Permissive,
            Some(other) => return Err(ConfigError::UnknownMode(other.to_string())),
        };
        let mut exemptions = Vec::with_capacity(h.exemption.len());
        for ex in h.exemption {
            let rule =
                Rule::parse(&ex.rule).ok_or_else(|| ConfigError::UnknownRule(ex.rule.clone()))?;
            exemptions.push(Exemption {
                path: PathBuf::from(ex.path),
                rule,
                expires: ex.expires,
            });
        }
        Ok(Self {
            mode,
            forbid_inline_tests: if h.forbid_inline_tests.is_empty() {
                vec!["modules".to_string(), "src".to_string()]
            } else {
                h.forbid_inline_tests
            },
            max_inline_lines: h.max_inline_lines.unwrap_or(80),
            exemptions,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Violation {
    pub path: PathBuf,
    pub line: usize,
    pub rule: Rule,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct StaleExemption {
    pub path: PathBuf,
    pub rule: Rule,
    pub kind: StaleKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleKind {
    PathMissing,
    Expired,
    NoLongerViolates,
}

impl StaleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            StaleKind::PathMissing => "path no longer exists",
            StaleKind::Expired => "expires date is in the past",
            StaleKind::NoLongerViolates => "file no longer violates the rule",
        }
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub violations: Vec<Violation>,
    pub stale_exemptions: Vec<StaleExemption>,
    pub files_scanned: usize,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.violations.is_empty() && self.stale_exemptions.is_empty()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("walking project root {root}: {source}")]
    Walk {
        root: PathBuf,
        source: walkdir::Error,
    },
}

/// Walk `project_root`, parse every `.rs` file as Rust, and apply the
/// hygiene rules in `config`. Returns a one-pass diagnostic set.
pub fn scan(project_root: &Path, config: &Config) -> Result<Report, ScanError> {
    let mut report = Report::default();
    let today = today_yyyy_mm_dd();

    // Pre-check exemptions for `path` missing / `expires` past. Those
    // produce stale diagnostics regardless of whether the scan
    // observes a violation.
    let mut exempt_lookup: HashSet<(PathBuf, Rule)> = HashSet::new();
    let mut already_flagged: HashSet<(PathBuf, Rule)> = HashSet::new();
    for ex in &config.exemptions {
        let abs = project_root.join(&ex.path);
        let key = (ex.path.clone(), ex.rule);
        if !abs.exists() {
            report.stale_exemptions.push(StaleExemption {
                path: ex.path.clone(),
                rule: ex.rule,
                kind: StaleKind::PathMissing,
            });
            already_flagged.insert(key);
            continue;
        }
        if let Some(exp) = &ex.expires {
            if exp.as_str() < today.as_str() {
                report.stale_exemptions.push(StaleExemption {
                    path: ex.path.clone(),
                    rule: ex.rule,
                    kind: StaleKind::Expired,
                });
                already_flagged.insert(key.clone());
            }
        }
        exempt_lookup.insert(key);
    }

    let mut exempt_applied: HashSet<(PathBuf, Rule)> = HashSet::new();

    let walker = walkdir::WalkDir::new(project_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !should_skip(e));

    for entry in walker {
        let entry = entry.map_err(|source| ScanError::Walk {
            root: project_root.to_path_buf(),
            source,
        })?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let rel = match path.strip_prefix(project_root) {
            Ok(r) => r.to_path_buf(),
            Err(_) => continue,
        };
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if is_generated_marker(&content) {
            continue;
        }
        report.files_scanned += 1;

        let tier = classify_tier(&rel);
        let file_violations = scan_file(&rel, &content, tier, config);
        for v in file_violations {
            let key = (rel.clone(), v.rule);
            if exempt_lookup.contains(&key) {
                exempt_applied.insert(key);
                continue;
            }
            report.violations.push(v);
        }
    }

    // Stale check pass 3: exemption rows that match an existing file
    // whose scan produced no violation under the named rule.
    for key in &exempt_lookup {
        if already_flagged.contains(key) {
            continue;
        }
        if !exempt_applied.contains(key) {
            report.stale_exemptions.push(StaleExemption {
                path: key.0.clone(),
                rule: key.1,
                kind: StaleKind::NoLongerViolates,
            });
        }
    }

    report.violations.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(a.line.cmp(&b.line))
            .then_with(|| (a.rule as u8).cmp(&(b.rule as u8)))
    });
    report.stale_exemptions.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then((a.rule as u8).cmp(&(b.rule as u8)))
    });

    Ok(report)
}

fn should_skip(entry: &walkdir::DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    let name = entry.file_name().to_string_lossy();
    matches!(
        name.as_ref(),
        "target" | ".git" | "node_modules" | "generated" | ".context"
    )
}

fn is_generated_marker(content: &str) -> bool {
    content
        .lines()
        .next()
        .is_some_and(|line| line.trim_start() == "// @generated")
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Tier {
    /// `modules/**` — raw `rustc` PIC build; inline tests compile
    /// silently away on the no_std target.
    Modules,
    /// Everything else under any workspace member's source tree.
    Src,
    /// `tests/**`, `benches/**`, `examples/**`, `fuzz/**` — test home
    /// already. No inline-test enforcement, but allow-discipline still
    /// applies.
    Tests,
}

fn classify_tier(rel: &Path) -> Tier {
    // Any directory component named tests/benches/examples/fuzz puts
    // the file in the tests tier — covers root `tests/`, workspace
    // member `tools/tests/`, and nested module test dirs like
    // `modules/foundation/tls/tests/`.
    let comps: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    if comps
        .iter()
        .any(|c| matches!(c.as_str(), "tests" | "benches" | "examples" | "fuzz"))
    {
        return Tier::Tests;
    }
    if comps.first().is_some_and(|c| c == "modules") {
        return Tier::Modules;
    }
    Tier::Src
}

fn tier_forbids_inline_tests(tier: Tier, config: &Config) -> bool {
    match tier {
        Tier::Modules => config.forbid_inline_tests.iter().any(|s| s == "modules"),
        Tier::Src => config.forbid_inline_tests.iter().any(|s| s == "src"),
        Tier::Tests => false,
    }
}

fn scan_file(rel: &Path, src: &str, tier: Tier, config: &Config) -> Vec<Violation> {
    let mut out = Vec::new();
    let parsed = match syn::parse_file(src) {
        Ok(p) => p,
        Err(e) => {
            out.push(Violation {
                path: rel.to_path_buf(),
                line: e.span().start().line,
                // Re-use AllowWithoutReason as a catch-all for now; a
                // dedicated `ParseError` rule can land later.
                rule: Rule::AllowWithoutReason,
                message: format!("syn parse error: {e}"),
            });
            return out;
        }
    };

    // Identify the bottom-of-file `mod tests` block (permissive carve-
    // out). The visitor consults this pointer to suppress inline-test
    // diagnostics on attributes *inside* the permitted block — the
    // outer `#[cfg(test)]` on the block itself is still reported via
    // an explicit size diagnostic at the file root.
    let permitted_trailing_id: Option<*const ItemMod> =
        if tier == Tier::Src && config.mode == Mode::Permissive {
            file_trailing_permitted_mod(&parsed).map(|m| m as *const ItemMod)
        } else {
            None
        };

    let mut visitor = HygieneVisitor {
        rel,
        violations: &mut out,
        inline_test_forbidden: tier_forbids_inline_tests(tier, config),
        permissive_src: tier == Tier::Src && config.mode == Mode::Permissive,
        max_inline_lines: config.max_inline_lines,
        permitted_trailing: permitted_trailing_id,
        in_permitted_depth: 0,
    };
    visitor.visit_file(&parsed);
    out
}

fn file_trailing_permitted_mod(file: &syn::File) -> Option<&ItemMod> {
    let last = file.items.last()?;
    if let syn::Item::Mod(m) = last {
        if is_permitted_trailing_test_mod(m) {
            return Some(m);
        }
    }
    None
}

struct HygieneVisitor<'a> {
    rel: &'a Path,
    violations: &'a mut Vec<Violation>,
    inline_test_forbidden: bool,
    permissive_src: bool,
    max_inline_lines: usize,
    /// Pointer to the trailing `mod tests` that's exempt from the
    /// inline-test ban (permissive mode only). Compared by identity
    /// rather than by content so a duplicate `mod tests` earlier in
    /// the file still gets flagged.
    permitted_trailing: Option<*const ItemMod>,
    /// Recursion depth currently inside the permitted trailing block;
    /// while > 0, inline-test attrs/items are suppressed.
    in_permitted_depth: usize,
}

impl<'a> HygieneVisitor<'a> {
    fn check_allow(&mut self, attr: &Attribute) {
        if !attr_is_allow(attr) {
            return;
        }
        if has_reason_kv(attr) {
            return;
        }
        let line = attr.pound_token.span.start().line;
        let is_inner = matches!(attr.style, syn::AttrStyle::Inner(_));
        self.violations.push(Violation {
            path: self.rel.to_path_buf(),
            line,
            rule: Rule::AllowWithoutReason,
            message: format!(
                "`#{}[allow(...)]` missing `reason = \"...\"`",
                if is_inner { "!" } else { "" }
            ),
        });
    }

    fn check_inline_test_attr(&mut self, attr: &Attribute) {
        if !self.inline_test_forbidden || self.in_permitted_depth > 0 {
            return;
        }
        if let Some(message) = is_inline_test_attr(attr) {
            self.violations.push(Violation {
                path: self.rel.to_path_buf(),
                line: attr.pound_token.span.start().line,
                rule: Rule::InlineTests,
                message,
            });
        }
    }

    fn check_oversize_trailing(&mut self, m: &ItemMod) {
        if let Some(over) = trailing_mod_exceeds(m, self.max_inline_lines) {
            self.violations.push(Violation {
                path: self.rel.to_path_buf(),
                line: m.mod_token.span.start().line,
                rule: Rule::InlineTests,
                message: format!(
                    "trailing `mod {}` is {over} lines — exceeds max_inline_lines cap",
                    m.ident
                ),
            });
        }
    }
}

impl<'a, 'ast> Visit<'ast> for HygieneVisitor<'a> {
    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        // Allow-discipline runs everywhere — including inside the
        // permitted trailing block, where we still want to catch
        // `#[allow(dead_code)]` without a reason.
        self.check_allow(attr);
        self.check_inline_test_attr(attr);
    }

    fn visit_item_mod(&mut self, m: &'ast ItemMod) {
        let is_permitted = self
            .permitted_trailing
            .is_some_and(|ptr| std::ptr::eq(ptr, m));
        if is_permitted {
            self.check_oversize_trailing(m);
        } else if self.inline_test_forbidden
            && self.in_permitted_depth == 0
            && is_test_named_mod(&m.ident)
        {
            self.violations.push(Violation {
                path: self.rel.to_path_buf(),
                line: m.mod_token.span.start().line,
                rule: Rule::InlineTests,
                message: format!("`mod {}` looks like an inline test module", m.ident),
            });
        }
        let _ = self.permissive_src; // referenced via permitted_trailing
        if is_permitted {
            self.in_permitted_depth += 1;
        }
        syn::visit::visit_item_mod(self, m);
        if is_permitted {
            self.in_permitted_depth -= 1;
        }
    }
}

fn attr_is_allow(attr: &Attribute) -> bool {
    attr.path().is_ident("allow")
}

/// Does the attribute carry a `reason = "..."` keyword argument?
/// Tokens-level walk: we don't constrain reason placement — clippy
/// accepts `#[allow(lint, reason = "...")]` and `#[allow(lint_a,
/// lint_b, reason = "...")]` alike.
fn has_reason_kv(attr: &Attribute) -> bool {
    let Meta::List(list) = &attr.meta else {
        return false;
    };
    let tokens = list.tokens.to_string();
    // Cheap textual check: `reason = "..."` substring with a string
    // literal directly after. Avoid false positives on a lint named
    // `reason`: ensure `reason` is followed by `=`.
    let bytes = tokens.as_bytes();
    let needle = b"reason";
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            // Boundary: previous char must not be an identifier char.
            let prev_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            // Next non-space char must be '='.
            let mut j = i + needle.len();
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if prev_ok && j < bytes.len() && bytes[j] == b'=' {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Is this attribute one of the inline-test markers? Returns the
/// diagnostic message when it is, `None` otherwise.
fn is_inline_test_attr(attr: &Attribute) -> Option<String> {
    let path = attr.path();
    let last = path.segments.last()?;
    let last_ident = last.ident.to_string();

    // `#[test]`, `#[tokio::test]`, `#[some_crate::test]` — last
    // segment must equal "test". Bare `#[test]` is the cargo built-in.
    if last_ident == "test" {
        return Some(format!(
            "`#[{}]` is an inline test attribute",
            path_to_string(path)
        ));
    }

    // `#[cfg(test)]` / `#[cfg(any(test, …))]` — meta-list whose
    // *predicate* contains `test` as an identifier (not as a string-
    // literal value inside `feature = "host-test"`, target_os triples
    // that happen to mention test, etc.).
    if last_ident == "cfg" {
        if let Meta::List(list) = &attr.meta {
            if predicate_mentions_test_ident(list.tokens.clone()) {
                return Some("`#[cfg(test)]` selects code only for the test build".to_string());
            }
        }
    }

    // `#[cfg_attr(<predicate>, …)]` — same idea, predicate is the
    // first argument. We still walk the full token tree; the `test`
    // ident only fires inside the predicate (the attribute part is
    // separated by a comma but a stray `test` ident there is also
    // suspicious).
    if last_ident == "cfg_attr" {
        if let Meta::List(list) = &attr.meta {
            if predicate_mentions_test_ident(list.tokens.clone()) {
                return Some(
                    "`#[cfg_attr(test, …)]` conditionally applies attributes only at test time"
                        .to_string(),
                );
            }
        }
    }

    None
}

fn path_to_string(p: &syn::Path) -> String {
    let mut s = String::new();
    if p.leading_colon.is_some() {
        s.push_str("::");
    }
    for (i, seg) in p.segments.iter().enumerate() {
        if i > 0 {
            s.push_str("::");
        }
        s.push_str(&seg.ident.to_string());
    }
    s
}

/// Walk a `cfg`/`cfg_attr` predicate token stream and return true if
/// `test` appears as a bare identifier — not as part of a longer
/// identifier (`test_runner`) and not inside a string literal
/// (`feature = "host-test"`, `target_os = "test_os"`).
fn predicate_mentions_test_ident(tokens: proc_macro2::TokenStream) -> bool {
    use proc_macro2::TokenTree;
    for tt in tokens {
        match tt {
            TokenTree::Ident(i) if i == "test" => return true,
            TokenTree::Group(g) => {
                if predicate_mentions_test_ident(g.stream()) {
                    return true;
                }
            }
            // Idents that are not `test`, punctuation, and literals
            // (string/byte/integer/float) all skipped — only the bare
            // `test` ident in predicate position should fire.
            _ => {}
        }
    }
    false
}

fn is_test_named_mod(ident: &syn::Ident) -> bool {
    let s = ident.to_string();
    s == "tests" || s == "test"
}

/// Permitted trailing block predicate. Standard permissive form:
/// `#[cfg(test)] mod tests { ... }` as the last item in the file.
fn is_permitted_trailing_test_mod(m: &ItemMod) -> bool {
    if !is_test_named_mod(&m.ident) {
        return false;
    }
    // Inline body required — `mod tests;` (file-extension form) is a
    // different shape and doesn't qualify.
    if m.content.is_none() {
        return false;
    }
    // Must carry `#[cfg(test)]` — otherwise the block would compile
    // into production builds, which is never the user's intent.
    m.attrs.iter().any(|a| {
        a.path().is_ident("cfg")
            && matches!(
                &a.meta,
                Meta::List(list) if predicate_mentions_test_ident(list.tokens.clone()),
            )
    })
}

/// Returns `Some(line_count)` if the module body exceeds the cap.
fn trailing_mod_exceeds(m: &ItemMod, cap: usize) -> Option<usize> {
    let (brace, _items) = m.content.as_ref()?;
    let start = brace.span.open().start().line;
    let end = brace.span.close().end().line;
    let span_lines = end.saturating_sub(start);
    if span_lines > cap {
        Some(span_lines)
    } else {
        None
    }
}

/// Today as `YYYY-MM-DD`. Lexicographic ordering is correct for the
/// `expires` field comparison in the staleness check.
fn today_yyyy_mm_dd() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

// Howard Hinnant's date algorithm (civil_from_days). Public domain.
// `z` is days since 1970-01-01 (the unix epoch).
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146_096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_str(src: &str, tier: Tier, config: &Config) -> Vec<Violation> {
        scan_file(Path::new("dummy.rs"), src, tier, config)
    }

    fn strict() -> Config {
        Config {
            mode: Mode::Strict,
            forbid_inline_tests: vec!["modules".into(), "src".into()],
            max_inline_lines: 80,
            exemptions: vec![],
        }
    }

    fn permissive(cap: usize) -> Config {
        Config {
            mode: Mode::Permissive,
            forbid_inline_tests: vec!["modules".into(), "src".into()],
            max_inline_lines: cap,
            exemptions: vec![],
        }
    }

    #[test]
    fn flags_bare_test_attribute() {
        let src = "#[test]\nfn t() {}\n";
        let v = scan_str(src, Tier::Modules, &strict());
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, Rule::InlineTests);
    }

    #[test]
    fn flags_path_qualified_test_attribute() {
        let src = "#[tokio::test]\nasync fn t() {}\n";
        let v = scan_str(src, Tier::Modules, &strict());
        assert!(v.iter().any(|v| v.rule == Rule::InlineTests));
    }

    #[test]
    fn flags_cfg_test() {
        let src = "#[cfg(test)]\nmod tests {}\n";
        let v = scan_str(src, Tier::Modules, &strict());
        assert!(v
            .iter()
            .any(|v| v.rule == Rule::InlineTests && v.message.contains("cfg(test)")));
    }

    #[test]
    fn flags_cfg_attr_test() {
        let src = "#[cfg_attr(test, derive(Debug))]\nstruct S;\n";
        let v = scan_str(src, Tier::Modules, &strict());
        assert!(v.iter().any(|v| v.rule == Rule::InlineTests));
    }

    #[test]
    fn flags_mod_tests_item() {
        let src = "mod tests { fn t() {} }\n";
        let v = scan_str(src, Tier::Modules, &strict());
        assert!(v
            .iter()
            .any(|v| v.rule == Rule::InlineTests && v.message.contains("mod tests")));
    }

    #[test]
    fn tests_tier_skips_inline_test_ban() {
        let src = "#[test]\nfn t() {}\n";
        let v = scan_str(src, Tier::Tests, &strict());
        assert!(v.iter().all(|v| v.rule != Rule::InlineTests));
    }

    #[test]
    fn permissive_allows_trailing_tests_mod() {
        let src = r#"
fn prod() {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn t() {}
}
"#;
        let v = scan_str(src, Tier::Src, &permissive(80));
        assert_eq!(v.len(), 0, "got: {v:?}");
    }

    #[test]
    fn permissive_caps_oversize_trailing_tests_mod() {
        let mut body = String::new();
        for i in 0..200 {
            body.push_str(&format!("    let _x{i} = {i};\n"));
        }
        let src = format!(
            "fn prod() {{}}\n\n#[cfg(test)]\nmod tests {{\n    #[test]\n    fn t() {{\n{body}    }}\n}}\n"
        );
        let v = scan_str(&src, Tier::Src, &permissive(80));
        assert!(
            v.iter()
                .any(|v| v.rule == Rule::InlineTests
                    && v.message.contains("exceeds max_inline_lines"))
        );
    }

    #[test]
    fn permissive_flags_interleaved_inline_test() {
        // `#[cfg(test)] mod tests` not at the bottom — flagged.
        let src = r#"
#[cfg(test)]
mod tests {
    #[test] fn t() {}
}

fn prod_after() {}
"#;
        let v = scan_str(src, Tier::Src, &permissive(80));
        assert!(v.iter().any(|v| v.rule == Rule::InlineTests));
    }

    #[test]
    fn allow_with_reason_passes() {
        let src = r#"
#[allow(dead_code, reason = "needed for ABI")]
fn f() {}
"#;
        let v = scan_str(src, Tier::Tests, &strict());
        assert!(v.iter().all(|v| v.rule != Rule::AllowWithoutReason));
    }

    #[test]
    fn allow_without_reason_is_flagged() {
        let src = "#[allow(dead_code)]\nfn f() {}\n";
        let v = scan_str(src, Tier::Tests, &strict());
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, Rule::AllowWithoutReason);
    }

    #[test]
    fn inner_allow_without_reason_is_flagged() {
        let src = "#![allow(dead_code)]\n";
        let v = scan_str(src, Tier::Tests, &strict());
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, Rule::AllowWithoutReason);
    }

    #[test]
    fn classify_tier_resolves_workspace_member_tests() {
        assert_eq!(
            classify_tier(Path::new("modules/foo/mod.rs")),
            Tier::Modules
        );
        assert_eq!(classify_tier(Path::new("tests/foo.rs")), Tier::Tests);
        assert_eq!(classify_tier(Path::new("tools/tests/foo.rs")), Tier::Tests);
        assert_eq!(classify_tier(Path::new("tools/src/foo.rs")), Tier::Src);
        assert_eq!(classify_tier(Path::new("src/lib.rs")), Tier::Src);
        // Nested test dirs anywhere in the path land in the tests tier —
        // a per-module test suite under `modules/foo/tests/` should not
        // be treated as no_std PIC code.
        assert_eq!(
            classify_tier(Path::new("modules/foundation/tls/tests/crypto_kat.rs")),
            Tier::Tests
        );
        assert_eq!(
            classify_tier(Path::new("modules/app/codec/benches/decode.rs")),
            Tier::Tests
        );
    }

    #[test]
    fn generated_marker_skips_file() {
        let src = "// @generated\n#[allow(dead_code)]\nfn f() {}\n";
        // is_generated_marker is called by the walker before scan_file
        // — emulate that boundary here.
        assert!(is_generated_marker(src));
    }

    #[test]
    fn reason_substring_inside_lint_name_is_not_confused() {
        // Lint named `reasonable_thing` shouldn't satisfy the reason
        // requirement — there's no `=` following the prefix.
        let src = "#[allow(clippy::reasonable_thing)]\nfn f() {}\n";
        let v = scan_str(src, Tier::Tests, &strict());
        assert_eq!(v.len(), 1, "should still be flagged: {v:?}");
        assert_eq!(v[0].rule, Rule::AllowWithoutReason);
    }

    #[test]
    fn feature_string_containing_test_is_not_a_cfg_test() {
        // `#[cfg(feature = "host-test")]` and
        // `#[cfg_attr(not(feature = "host-test"), no_std)]` are the
        // canonical dual-build gates in fluxor. The literal string
        // contains "test" but the predicate doesn't reference the
        // bare `test` cfg.
        let src = r#"
#[cfg(feature = "host-test")]
fn f() {}

#[cfg_attr(not(feature = "host-test"), no_std)]
extern crate alloc;
"#;
        let v = scan_str(src, Tier::Modules, &strict());
        assert!(
            v.iter().all(|v| v.rule != Rule::InlineTests),
            "host-test feature gate should not be flagged: {v:?}"
        );
    }

    #[test]
    fn test_runner_ident_is_not_a_cfg_test() {
        // `#[cfg(test_runner)]` (a custom cfg flag containing the
        // letters `test` as a prefix) must not match the bare `test`
        // ident.
        let src = "#[cfg(test_runner)]\nfn f() {}\n";
        let v = scan_str(src, Tier::Modules, &strict());
        assert!(v.iter().all(|v| v.rule != Rule::InlineTests));
    }
}
