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
//!      - SDK-mount rule: `#[path]`/`include!` mounts must read the
//!        staged, digest-verified `target/fluxor/**` tree, never a
//!        raw `deps/<project>/modules/{sdk,common}/` checkout.
//!   3. Whole-repo checks:
//!      - Module-structure rules over `modules/**`.
//!      - Shadow-guard rules over the shadow-tracked test tiers.
//!      - Repo-file conformance (files a standard mandates at root).
//!   4. Skip directories named `generated/`, `target/`, `.git/`,
//!      `node_modules/`, `.context/`; skip files starting with
//!      `// @generated` on the first line.
//!   5. Single-pass — emit every violation, exit non-zero at end.
//!   6. Validate exemptions: paths must exist, `expires` must not be
//!      in the past, and the file must still violate the named rule
//!      (otherwise the exemption has silently rotted).

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use syn::visit::Visit;
use syn::{Attribute, ItemMod, Meta};

/// One discrete rule the scanner enforces. Matches the `rule = "..."`
/// discriminator carried on every violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    InlineTests,
    AllowWithoutReason,
    ModuleStructure,
    ShadowGuard,
    SdkMount,
    RepoFiles,
}

impl Rule {
    pub fn as_str(self) -> &'static str {
        match self {
            Rule::InlineTests => "inline-tests",
            Rule::AllowWithoutReason => "allow-without-reason",
            Rule::ModuleStructure => "module-structure",
            Rule::ShadowGuard => "shadow-guard",
            Rule::SdkMount => "sdk-mount",
            Rule::RepoFiles => "repo-files",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Strict,
    Permissive,
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
}

#[derive(Debug, Clone)]
pub struct Config {
    pub mode: Mode,
    pub forbid_inline_tests: Vec<String>,
    pub max_inline_lines: usize,
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
        Ok(Self {
            mode,
            forbid_inline_tests: if h.forbid_inline_tests.is_empty() {
                vec!["modules".to_string(), "src".to_string()]
            } else {
                h.forbid_inline_tests
            },
            max_inline_lines: h.max_inline_lines.unwrap_or(80),
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

#[derive(Debug, Default)]
pub struct Report {
    pub violations: Vec<Violation>,
    pub files_scanned: usize,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.violations.is_empty()
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

    // fluxor owns the SDK sources; every other repo consumes them from
    // the staged tree. `modules/sdk/abi_surface.rs` is the same marker
    // the ABI pin test keys off.
    let sdk_owner = project_root.join("modules/sdk/abi_surface.rs").is_file();

    // Files whose inline tests actually run on the host (see
    // `host_compiled_closure`). The inline-tests rule does not apply to
    // them: it exists because a `#[cfg(test)]` block in a `no_std`
    // module compiles away unnoticed, and these blocks do not.
    let host_compiled = host_compiled_closure(project_root);

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
        let tier = if host_compiled.contains(&rel) {
            Tier::Tests // host-compiled: inline tests run, so the rule is moot
        } else {
            tier
        };
        let mut file_violations = scan_file(&rel, &content, tier, config);
        if !sdk_owner {
            file_violations.extend(scan_sdk_mounts(&rel, &content));
        }
        report.violations.extend(file_violations);
    }

    scan_module_structure(project_root, &mut report);
    scan_shadow_guard(project_root, &mut report);
    scan_repo_files(project_root, &mut report);

    report.violations.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(a.line.cmp(&b.line))
            .then_with(|| (a.rule as u8).cmp(&(b.rule as u8)))
    });
    Ok(report)
}

/// Structure rules for the `modules/` tree (standards/fluxor-modules.md
/// §1–§3, §7): a module is a directory, never a crate; tier placement
/// must agree with the manifest; in-module `tests/` must be declared.
/// `modules/sdk/` is the staged-source contract, not a module tree —
/// exempt. All findings report under `Rule::ModuleStructure`.
fn scan_module_structure(project_root: &Path, report: &mut Report) {
    let modules_root = project_root.join("modules");
    if !modules_root.is_dir() {
        return;
    }
    let push = |rel: PathBuf, message: String, report: &mut Report| {
        report.violations.push(Violation {
            path: rel,
            line: 0,
            rule: Rule::ModuleStructure,
            message,
        });
    };

    for entry in walkdir::WalkDir::new(&modules_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            e.file_name() != "sdk" || e.path().parent() != Some(modules_root.as_path())
        })
        .filter_map(std::result::Result::ok)
    {
        let rel = match entry.path().strip_prefix(project_root) {
            Ok(r) => r.to_path_buf(),
            Err(_) => continue,
        };
        let name = entry.file_name().to_string_lossy();

        // Rule: no cargo build system anywhere under modules/**.
        if entry.file_type().is_file() && (name == "Cargo.toml" || name == "Cargo.lock") {
            push(
                rel,
                format!(
                    "{name} under modules/ — a module is a directory, never a crate; \
                     host tests go through `fluxor modules test` ([test] harness), not a shim crate"
                ),
                report,
            );
            continue;
        }
        if entry.file_type().is_dir() && name == "target" {
            push(
                rel,
                "build-output directory under modules/ — stray cargo artefacts; delete it"
                    .to_string(),
                report,
            );
            continue;
        }

        // Module-directory rules key off manifest.toml presence.
        if !(entry.file_type().is_file() && name == "manifest.toml") {
            continue;
        }
        let module_dir = match entry.path().parent() {
            Some(d) => d.to_path_buf(),
            None => continue,
        };
        let module_rel = match module_dir.strip_prefix(project_root) {
            Ok(r) => r.to_path_buf(),
            Err(_) => continue,
        };
        let manifest = fs::read_to_string(entry.path()).unwrap_or_default();

        // Entry file must exist (`entry = "..."` override, default
        // mod.rs) — except for `builtin = true` manifests, which are
        // declarations of kernel-side implementations and carry no
        // module source of their own.
        let is_builtin = manifest
            .lines()
            .map(str::trim)
            .any(|l| l.starts_with("builtin") && l.contains("true"));
        let entry_file = manifest
            .lines()
            .find_map(|l| {
                let l = l.trim();
                l.strip_prefix("entry")
                    .and_then(|r| r.trim().strip_prefix('='))
                    .map(|v| v.trim().trim_matches('"').to_string())
            })
            .unwrap_or_else(|| "mod.rs".to_string());
        if !is_builtin && !module_dir.join(&entry_file).is_file() {
            push(
                module_rel.clone(),
                format!("module entry file `{entry_file}` missing"),
                report,
            );
        }

        // In-module tests/ requires a [test] declaration.
        if module_dir.join("tests").is_dir() && !manifest.contains("[test]") {
            push(
                module_rel.clone(),
                "undeclared tests/ directory — declare `[test] harness = \"tests/...\"` \
                 (run by `fluxor modules test`) or relocate the tests"
                    .to_string(),
                report,
            );
        }

        // Tier placement must agree with hardware_targets.
        let targets_line = manifest
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("hardware_targets"))
            .unwrap_or("")
            .to_string();
        let has = |t: &str| targets_line.contains(&format!("\"{t}\""));
        let linux_only = has("linux") && !has("wasm");
        let wasm_only = has("wasm") && !has("linux");
        let module_rel_str = module_rel.to_string_lossy().replace('\\', "/");
        if module_rel_str.starts_with("modules/platform/linux/") && !linux_only {
            push(
                module_rel.clone(),
                format!(
                    "platform/linux module must declare exactly hardware_targets = [\"linux\"] \
                     (found: {targets_line})"
                ),
                report,
            );
        }
        if module_rel_str.starts_with("modules/platform/wasm/") && !wasm_only {
            push(
                module_rel.clone(),
                format!(
                    "platform/wasm module must declare exactly hardware_targets = [\"wasm\"] \
                     (found: {targets_line})"
                ),
                report,
            );
        }
        if module_rel_str.starts_with("modules/drivers/") && (has("linux") || has("wasm")) {
            push(
                module_rel.clone(),
                format!(
                    "drivers/ modules are silicon-bound; a host platform in hardware_targets \
                     belongs under platform/ (found: {targets_line})"
                ),
                report,
            );
        }
    }
}

/// Record one whole-repo violation (a finding about the repo's shape
/// rather than about one file's contents).
fn push_repo_violation(report: &mut Report, rel: PathBuf, rule: Rule, message: String) {
    report.violations.push(Violation {
        path: rel,
        line: 0,
        rule,
        message,
    });
}

/// The tree tiers [`test-tracking.md §1`] shadow-tracks. `fuzz/` and
/// `fixtures/` are listed by the standard and by the projects that use
/// them; a tier only participates when it exists on disk.
const SHADOW_TIERS: [&str; 5] = ["tests", "benches", "examples", "fixtures", "fuzz"];

/// Shadow-tracking conformance (standards/test-tracking.md §4, §7) —
/// the native replacement for the per-repo `tools/ci-shadow-guard.sh`
/// copies. For every tier that exists on disk:
///
/// - a repo with a shadow repo (`.git-shadow/`) must exclude the tier
///   from the primary repo, un-exclude it in `.git-shadow/info/exclude`,
///   and actually have it committed there (an initialised-but-unborn
///   shadow repo versions nothing);
/// - a repo with no shadow repo must not gitignore the tier — a
///   gitignored-only tier exists on exactly one machine and has no
///   recovery path (§1's explicit failure mode).
fn scan_shadow_guard(project_root: &Path, report: &mut Report) {
    let shadow_dir = project_root.join(".git-shadow");
    let has_shadow = shadow_dir.is_dir();
    let gitignore = fs::read_to_string(project_root.join(".gitignore")).unwrap_or_default();
    let shadow_exclude =
        fs::read_to_string(shadow_dir.join("info").join("exclude")).unwrap_or_default();

    let present: Vec<&str> = SHADOW_TIERS
        .iter()
        .copied()
        .filter(|t| project_root.join(t).is_dir())
        .collect();

    if !has_shadow {
        for tier in present {
            if !ignore_file_lists_tier(&gitignore, tier, false) {
                continue;
            }
            push_repo_violation(
                report,
                PathBuf::from(tier),
                Rule::ShadowGuard,
                format!(
                    "`{tier}/` is gitignored in the primary repo and there is no `.git-shadow/` \
                     — its contents are versioned nowhere and exist only on this machine. \
                     Run the standards/test-tracking.md §4 setup (init `.git-shadow`, invert the \
                     excludes, `git shadow add -A && git shadow commit`), or drop `{tier}/` from \
                     .gitignore and track it in the primary repo"
                ),
            );
        }
        return;
    }

    let born = shadow_repo_is_born(&shadow_dir);
    if !born {
        push_repo_violation(
            report,
            PathBuf::from(".git-shadow"),
            Rule::ShadowGuard,
            "`.git-shadow/` is initialised but has no commits — the shadow-tracked tiers are \
             versioned nowhere, which is compliance shape without compliance. Run \
             `git shadow add -A && git shadow commit -m \"Initial shadow-tracked tests/benches\"` \
             (standards/test-tracking.md §4 step 5)"
                .to_string(),
        );
    }

    for tier in present {
        // A tier with files tracked in the PRIMARY repo is primary-
        // tracked by choice — fluxor's `examples/` is the onboarding
        // catalog the docs link to. Having a shadow repo does not make
        // every tier a shadow tier, and demanding `/examples/` in
        // .gitignore would untrack the catalog to satisfy a rule about
        // where tests live.
        if primary_tracks_tier(project_root, tier) {
            continue;
        }
        if !ignore_file_lists_tier(&gitignore, tier, false) {
            push_repo_violation(
                report,
                PathBuf::from(tier),
                Rule::ShadowGuard,
                format!(
                    "`{tier}/` is a shadow-tracked tier but is not excluded from the primary \
                     repo — add `/{tier}/` to .gitignore, or it reaches the shared remote \
                     (standards/test-tracking.md §4 step 1)"
                ),
            );
        }
        if !ignore_file_lists_tier(&shadow_exclude, tier, true) {
            push_repo_violation(
                report,
                PathBuf::from(tier),
                Rule::ShadowGuard,
                format!(
                    "`{tier}/` is not un-excluded in .git-shadow/info/exclude — the shadow repo \
                     tracks nothing under it, so the tier is versioned nowhere. Add `!/{tier}/` \
                     there (standards/test-tracking.md §4 step 3)"
                ),
            );
            continue;
        }
        if born && shadow_tier_is_empty(&shadow_dir, project_root, tier) {
            push_repo_violation(
                report,
                PathBuf::from(tier),
                Rule::ShadowGuard,
                format!(
                    "`{tier}/` exists on disk and is un-excluded in .git-shadow/info/exclude, but \
                     no file under it is committed in the shadow repo — run \
                     `git shadow add -A {tier} && git shadow commit` \
                     (standards/test-tracking.md §5)"
                ),
            );
        }
    }
}

/// Does an exclude file list `tier`? `negated` selects the shadow
/// repo's inverted form (`!/tests/`) over the primary form (`/tests/`).
/// All four anchoring spellings git accepts are recognised.
fn ignore_file_lists_tier(contents: &str, tier: &str, negated: bool) -> bool {
    contents.lines().any(|line| {
        let line = line.trim();
        let Some(rest) = (if negated {
            line.strip_prefix('!')
        } else if line.starts_with('!') || line.starts_with('#') {
            None
        } else {
            Some(line)
        }) else {
            return false;
        };
        let rest = rest.trim_start_matches('/').trim_end_matches('/');
        rest == tier
    })
}

/// A git repository is "born" once a branch ref exists — loose under
/// `refs/heads/` or in `packed-refs`. Read from the git-dir directly so
/// the check works without invoking git.
/// Does the primary repo track anything under this tier? A non-empty
/// `git ls-files <tier>` is the only signal that settles it, and it is
/// the repo's own answer rather than a list this rule would have to
/// keep.
fn primary_tracks_tier(project_root: &Path, tier: &str) -> bool {
    std::process::Command::new("git")
        .args(["ls-files", "--", tier])
        .current_dir(project_root)
        .output()
        .is_ok_and(|o| !o.stdout.is_empty())
}

fn shadow_repo_is_born(shadow_dir: &Path) -> bool {
    let heads = shadow_dir.join("refs").join("heads");
    let loose = walkdir::WalkDir::new(&heads)
        .follow_links(false)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .any(|e| e.file_type().is_file());
    if loose {
        return true;
    }
    fs::read_to_string(shadow_dir.join("packed-refs"))
        .is_ok_and(|s| s.lines().any(|l| l.contains("refs/heads/")))
}

/// Is `tier` absent from the shadow repo's committed tree? Needs git
/// itself (the tree is packed); if git can't be run the check is
/// skipped rather than guessed at, so it never reports a false
/// violation on a machine without git.
fn shadow_tier_is_empty(shadow_dir: &Path, project_root: &Path, tier: &str) -> bool {
    let out = std::process::Command::new("git")
        .arg("--git-dir")
        .arg(shadow_dir)
        .arg("--work-tree")
        .arg(project_root)
        .args(["ls-tree", "-r", "--name-only", "HEAD", "--", tier])
        .output();
    match out {
        Ok(o) if o.status.success() => o.stdout.is_empty(),
        _ => false,
    }
}

/// SDK-mount rule (standards/dependencies.md): a consuming project
/// mounts fluxor's SDK — and any sibling's shared source tree — from
/// the staged, digest-verified tree `fluxor sync` materialises under
/// `target/fluxor/`, never from a raw `deps/<project>/` checkout. A
/// `deps/` mount has no pin, no digest, and no staleness signal.
fn scan_sdk_mounts(rel: &Path, src: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    for (idx, line) in src.lines().enumerate() {
        let trimmed = line.trim_start();
        if !(trimmed.starts_with("#[path") || trimmed.contains("include!(")) {
            continue;
        }
        let Some(pos) = line.find("deps/") else {
            continue;
        };
        let tail = &line[pos..];
        let staged = if tail.contains("/modules/sdk/") {
            "target/fluxor/fluxor-abi/sdk/"
        } else if tail.contains("/modules/common/") {
            "target/fluxor/<project>-common/"
        } else {
            continue;
        };
        out.push(Violation {
            path: rel.to_path_buf(),
            line: idx + 1,
            rule: Rule::SdkMount,
            message: format!(
                "raw `deps/` source mount — no pin, no digest, no staleness signal. Mount the \
                 staged tree `{staged}...` that `fluxor sync` materialises \
                 (standards/dependencies.md)"
            ),
        });
    }
    out
}

/// Repo-file conformance: files a standard *states* a project carries
/// at its root. Only standard-grounded entries live here — a required
/// file with no standard behind it would be exactly the hand-written
/// variant this rule exists to remove.
///
/// - `clippy.toml` — standards/lints.md §6 ("Workspace-shared
///   `clippy.toml` at repo root"), for the lints that take
///   configuration rather than a level. Checked for Cargo workspaces
///   only; a repo with no workspace root has nothing to share.
///
/// `rustfmt.toml`, `rust-toolchain.toml` and `LICENSE` are deliberately
/// absent: no standard states whether a project carries them, so the
/// spread across the ecosystem is an open owner decision, not a
/// violation. See standards/lints.md §6.1.
fn scan_repo_files(project_root: &Path, report: &mut Report) {
    let root_manifest = project_root.join("Cargo.toml");
    let Ok(manifest) = fs::read_to_string(&root_manifest) else {
        return;
    };
    if !manifest
        .lines()
        .any(|l| l.trim_start().starts_with("[workspace"))
    {
        return;
    }
    if project_root.join("clippy.toml").is_file() {
        return;
    }
    push_repo_violation(
        report,
        PathBuf::from("Cargo.toml"),
        Rule::RepoFiles,
        "workspace root carries no `clippy.toml` — standards/lints.md §6 states the \
         configuration-taking lints (`disallowed-macros`, `disallowed-methods`) are configured \
         in a workspace-shared `clippy.toml` at the repo root; without it those lints are \
         unconfigured and silently enforce nothing"
            .to_string(),
    );
}

fn should_skip(entry: &walkdir::DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    let name = entry.file_name().to_string_lossy();
    matches!(
        name.as_ref(),
        "target" | ".git" | ".git-shadow" | "node_modules" | "generated" | ".context"
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

/// Every file reachable by `#[path]` from a host-compiled root.
///
/// The inline-tests rule bans `#[cfg(test)]` under `modules/` because a
/// `no_std` module compiles the block away and the tests silently never
/// run. That reasoning stops exactly where the file is ALSO pulled into
/// a host build: the same block is compiled and executed there, which is
/// the outcome the rule wants.
///
/// The roots are the three ways a module source becomes host-compiled: a
/// file under `tests/`-like tiers, a file under `src/` (a crate lib that
/// mounts module surfaces), and a `[test] harness` a manifest declares.
/// From each root the mounts are followed transitively — a harness that
/// mounts `../mod.rs` makes that file host-compiled, and anything it
/// mounts in turn.
///
/// Derived, never listed: the alternative is an exemption row per file,
/// which is how thirty of them accumulated saying the same sentence.
fn host_compiled_closure(project_root: &Path) -> HashSet<PathBuf> {
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut queue: Vec<PathBuf> = Vec::new();

    for entry in walkdir::WalkDir::new(project_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !should_skip(e))
        .filter_map(std::result::Result::ok)
    {
        let path = entry.path();
        let Ok(rel) = path.strip_prefix(project_root) else {
            continue;
        };
        match path.extension().and_then(|s| s.to_str()) {
            // A host root: cargo compiles it, so what it mounts is host code.
            Some("rs") if !classify_tier(rel).eq(&Tier::Modules) => {
                queue.push(rel.to_path_buf());
            }
            // A declared module harness is host-compiled by `fluxor test`.
            Some("toml") if path.file_name().is_some_and(|n| n == "manifest.toml") => {
                if let Some(h) = fs::read_to_string(path)
                    .ok()
                    .and_then(|t| toml::from_str::<toml::Value>(&t).ok())
                    .and_then(|d| d.get("test")?.get("harness")?.as_str().map(str::to_string))
                {
                    if let Some(dir) = rel.parent() {
                        queue.push(dir.join(h));
                    }
                }
            }
            _ => {}
        }
    }

    while let Some(rel) = queue.pop() {
        if !seen.insert(rel.clone()) {
            continue;
        }
        let Ok(text) = fs::read_to_string(project_root.join(&rel)) else {
            continue;
        };
        let Some(dir) = rel.parent() else { continue };
        for line in text.lines() {
            if let Some(target) = mount_target(line) {
                queue.push(lexical_join(dir, &target));
            }
        }
    }
    seen
}

/// The file a line mounts, by either mechanism: `#[path = "…"]` on a
/// `mod`, or `include!("…")`. Both splice a source file into the
/// compiling crate, so both carry host-compilation to their target —
/// following only one is how six of these exemptions survived a sweep
/// that removed the rest.
fn mount_target(line: &str) -> Option<String> {
    let t = line.trim();
    let rest = match (t.strip_prefix("#[path"), t.find("include!(")) {
        (Some(after), _) => after.trim_start().strip_prefix('=')?,
        (None, Some(i)) => &t[i + "include!(".len()..],
        (None, None) => return None,
    };
    let q = rest.find('"')?;
    let tail = &rest[q + 1..];
    Some(tail[..tail.find('"')?].to_string())
}

/// Resolve `rel` against `base` textually — `..` pops, `.` is dropped.
fn lexical_join(base: &Path, rel: &str) -> PathBuf {
    let mut out = base.to_path_buf();
    for part in rel.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            p => out.push(p),
        }
    }
    out
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
                // A file that will not parse cannot be checked against
                // any rule, so the rule field is a placeholder — the
                // message is the finding.
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
        }
    }

    fn permissive(cap: usize) -> Config {
        Config {
            mode: Mode::Permissive,
            forbid_inline_tests: vec!["modules".into(), "src".into()],
            max_inline_lines: cap,
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
            classify_tier(Path::new("modules/foundation/http/benches/decode.rs")),
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

    // ---- shadow-guard / sdk-mount / repo-files fixtures ----

    /// Hermetic project root under the process temp dir. Dropped by
    /// the caller via `fs::remove_dir_all` at the end of each test.
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!(
                "fluxor-hygiene-{tag}-{}-{nanos}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).expect("create temp root");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn dir(&self, rel: &str) -> &Self {
            fs::create_dir_all(self.0.join(rel)).expect("create dir");
            self
        }

        fn file(&self, rel: &str, body: &str) -> &Self {
            let p = self.0.join(rel);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).expect("create parent");
            }
            fs::write(p, body).expect("write file");
            self
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn shadow_report(root: &TempRoot, _config: &Config) -> Vec<Violation> {
        let mut report = Report::default();
        scan_shadow_guard(root.path(), &mut report);
        report.violations
    }

    #[test]
    fn shadow_guard_flags_gitignored_tier_with_no_shadow_repo() {
        let root = TempRoot::new("noshadow");
        root.dir("tests").file(".gitignore", "target/\n/tests/\n");
        let v = shadow_report(&root, &strict());
        assert_eq!(v.len(), 1, "got: {v:?}");
        assert_eq!(v[0].rule, Rule::ShadowGuard);
        assert_eq!(v[0].path, Path::new("tests"));
        assert!(v[0].message.contains("versioned nowhere"));
    }

    #[test]
    fn shadow_guard_ignores_primary_tracked_tier() {
        // Not gitignored, no shadow repo: the primary repo tracks it.
        // Converging that state is a separate decision, not this rule's.
        let root = TempRoot::new("tracked");
        root.dir("tests").file(".gitignore", "target/\n");
        assert!(shadow_report(&root, &strict()).is_empty());
    }

    #[test]
    fn shadow_guard_flags_unborn_shadow_repo() {
        let root = TempRoot::new("unborn");
        root.dir("tests")
            .dir(".git-shadow/refs/heads")
            .file(".gitignore", "/tests/\n")
            .file(".git-shadow/info/exclude", "/*\n!/tests/\n");
        let v = shadow_report(&root, &strict());
        assert_eq!(v.len(), 1, "got: {v:?}");
        assert_eq!(v[0].path, Path::new(".git-shadow"));
        assert!(v[0].message.contains("no commits"));
    }

    #[test]
    fn shadow_guard_flags_tier_missing_from_shadow_exclude() {
        // lattice's silent hole: benches/ shadow-tracked in the comment,
        // absent from the exclude file, so the shadow repo tracks none
        // of it.
        let root = TempRoot::new("hole");
        root.dir("tests")
            .dir("benches")
            .file(".git-shadow/refs/heads/main", "0".repeat(40).as_str())
            .file(".gitignore", "/tests/\n/benches/\n")
            .file(".git-shadow/info/exclude", "/*\n!/tests/\n");
        let v = shadow_report(&root, &strict());
        assert_eq!(v.len(), 1, "got: {v:?}");
        assert_eq!(v[0].path, Path::new("benches"));
        assert!(v[0].message.contains("un-excluded"));
    }

    #[test]
    fn shadow_guard_flags_tier_not_excluded_from_primary() {
        let root = TempRoot::new("leak");
        root.dir("examples")
            .file(".git-shadow/refs/heads/main", "0".repeat(40).as_str())
            .file(".gitignore", "target/\n")
            .file(".git-shadow/info/exclude", "/*\n!/examples/\n");
        let v = shadow_report(&root, &strict());
        assert_eq!(v.len(), 1, "got: {v:?}");
        assert!(v[0].message.contains("shared remote"));
    }

    #[test]
    fn shadow_guard_accepts_a_conformant_setup() {
        let root = TempRoot::new("ok");
        root.dir("tests")
            .dir("examples")
            .file(".git-shadow/refs/heads/main", "0".repeat(40).as_str())
            .file(".gitignore", "target/\n/tests/\n/examples/\n")
            .file(
                ".git-shadow/info/exclude",
                "/*\n!/tests/\n!/examples/\n!/.gitignore\n",
            );
        // `shadow_tier_is_empty` needs a real git object store; the
        // fixture has none, so the check declines rather than guesses.
        assert!(shadow_report(&root, &strict()).is_empty());
    }

    #[test]
    fn ignore_spellings_all_match() {
        for spelling in ["/tests/", "/tests", "tests/", "tests"] {
            assert!(
                ignore_file_lists_tier(spelling, "tests", false),
                "{spelling}"
            );
            assert!(
                ignore_file_lists_tier(&format!("!{spelling}"), "tests", true),
                "!{spelling}"
            );
        }
        // A negation is not an exclusion, a comment is not a rule, and
        // a longer path is not the tier.
        assert!(!ignore_file_lists_tier("!/tests/", "tests", false));
        assert!(!ignore_file_lists_tier("#/tests/", "tests", false));
        assert!(!ignore_file_lists_tier("/tests/fixtures/", "tests", false));
    }

    #[test]
    fn shadow_born_detects_packed_refs() {
        let root = TempRoot::new("packed");
        root.file(
            ".git-shadow/packed-refs",
            "# pack-refs with: peeled\nabc123 refs/heads/main\n",
        );
        assert!(shadow_repo_is_born(&root.path().join(".git-shadow")));
        let bare = TempRoot::new("bare");
        bare.dir(".git-shadow/refs/heads");
        assert!(!shadow_repo_is_born(&bare.path().join(".git-shadow")));
    }

    #[test]
    fn sdk_mount_flags_deps_path_and_include() {
        let src = r#"
#[path = "../../../deps/fluxor/modules/sdk/abi.rs"]
mod abi;
include!("../../../deps/fluxor/modules/sdk/runtime.rs");
"#;
        let v = scan_sdk_mounts(Path::new("modules/app/x/mod.rs"), src);
        assert_eq!(v.len(), 2, "got: {v:?}");
        assert!(v.iter().all(|v| v.rule == Rule::SdkMount));
        assert!(v[0].message.contains("target/fluxor/fluxor-abi/sdk/"));
        assert_eq!(v[0].line, 2);
        assert_eq!(v[1].line, 4);
    }

    #[test]
    fn sdk_mount_flags_sibling_common_tree() {
        let src = "#[path = \"../../../deps/clustor/modules/common/kv.rs\"]\nmod kv;\n";
        let v = scan_sdk_mounts(Path::new("modules/app/x/mod.rs"), src);
        assert_eq!(v.len(), 1, "got: {v:?}");
        assert!(v[0].message.contains("<project>-common"));
    }

    #[test]
    fn sdk_mount_accepts_the_staged_tree() {
        let src = r#"
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
"#;
        assert!(scan_sdk_mounts(Path::new("modules/app/x/mod.rs"), src).is_empty());
    }

    #[test]
    fn sdk_mount_ignores_non_sdk_deps_mounts() {
        // A cross-project module mount is a different question; this
        // rule is about the staged source tree only.
        let src = "#[path = \"../../../deps/fluxor/modules/foundation/http/mod.rs\"]\nmod http;\n";
        assert!(scan_sdk_mounts(Path::new("modules/app/x/mod.rs"), src).is_empty());
    }

    fn repo_files_report(root: &TempRoot, _config: &Config) -> Vec<Violation> {
        let mut report = Report::default();
        scan_repo_files(root.path(), &mut report);
        report.violations
    }

    #[test]
    fn repo_files_requires_clippy_toml_in_a_workspace() {
        let root = TempRoot::new("noclippy");
        root.file("Cargo.toml", "[workspace]\nmembers = [\"a\"]\n");
        let v = repo_files_report(&root, &strict());
        assert_eq!(v.len(), 1, "got: {v:?}");
        assert_eq!(v[0].rule, Rule::RepoFiles);
        assert!(v[0].message.contains("clippy.toml"));
    }

    #[test]
    fn repo_files_passes_with_clippy_toml() {
        let root = TempRoot::new("clippy");
        root.file("Cargo.toml", "[workspace]\n")
            .file("clippy.toml", "disallowed-macros = []\n");
        assert!(repo_files_report(&root, &strict()).is_empty());
    }

    #[test]
    fn repo_files_skips_a_non_workspace_repo() {
        let root = TempRoot::new("nows");
        root.file("Cargo.toml", "[package]\nname = \"x\"\n");
        assert!(repo_files_report(&root, &strict()).is_empty());
    }

    #[test]
    fn repo_files_does_not_invent_ungrounded_requirements() {
        // rustfmt.toml / rust-toolchain.toml / LICENSE are absent from
        // this fixture and no standard mandates them, so the rule stays
        // silent about them.
        let root = TempRoot::new("ungrounded");
        root.file("Cargo.toml", "[workspace]\n")
            .file("clippy.toml", "\n");
        assert!(repo_files_report(&root, &strict()).is_empty());
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

    /// A module source pulled into a host build is not what the
    /// inline-tests rule is about: its `#[cfg(test)]` block compiles and
    /// runs there. Both mounting mechanisms carry that, and following
    /// only `#[path]` left every `include!`-mounted core still flagged.
    #[test]
    fn mount_target_reads_both_mounting_mechanisms() {
        assert_eq!(
            mount_target("#[path = \"../../common/ssh_wire.rs\"]").as_deref(),
            Some("../../common/ssh_wire.rs")
        );
        assert_eq!(
            mount_target("include!(\"../../../modules/common/sector_dedup.rs\");").as_deref(),
            Some("../../../modules/common/sector_dedup.rs")
        );
        assert_eq!(mount_target("let p = \"not a mount\";"), None);
    }

    #[test]
    fn lexical_join_resolves_parent_hops() {
        assert_eq!(
            lexical_join(
                std::path::Path::new("tools/cli/tests"),
                "../../../modules/common/x.rs"
            ),
            std::path::PathBuf::from("modules/common/x.rs")
        );
    }
}
