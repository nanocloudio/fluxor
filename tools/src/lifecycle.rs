//! `fluxor build` (no args) / `test` / `lint` / `clean` — the lifecycle
//! verbs, and `fluxor help --make`, the generated `make help` block.
//!
//! A hand-written recipe makes each stage mean whatever its author had
//! in mind, so the same target name diverges repo by repo. The verbs
//! here read the project's shape — root `Cargo.toml`,
//! `[ci.cargo] host_tools_crate`, `modules/` + `[ci].targets`,
//! `[ci.test] scripts`, declared module harnesses, and whether the cargo
//! tree `#[path]`-mounts the staged `target/fluxor` tree — and do what
//! that shape implies. A Makefile recipe becomes one delegation.
//!
//! Every stage the shape does not call for is *omitted*, not skipped: a
//! crate-less project's `build` is the module build alone, and that is
//! the whole recipe, not a recipe with a hole in it.
//!
//! These verbs are the **developer loop**, not the gate. `fluxor ci` is
//! the gate: it runs every phase even after a failure, adds the lint /
//! hygiene / template / lockfile / skew phases, and stamps its green
//! digest. The lifecycle verbs fail fast, exactly like the `set -e`
//! recipe they replace.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::{ci, modules_build};

/// What a checkout's shape implies for the lifecycle verbs.
#[derive(Debug, Clone)]
pub struct Shape {
    pub project_root: PathBuf,
    /// `[project].name`, or the directory basename when unadopted.
    pub name: String,
    /// A root `Cargo.toml` exists.
    pub has_cargo: bool,
    /// `[ci.cargo] host_tools_crate` — or the conventional `tools/`
    /// crate — resolved to a directory that exists. The kernel-rooted
    /// workspaces (fluxor itself) can't build at the root under default
    /// features, so cargo runs here instead; `fluxor ci`'s phase 2 uses
    /// the same resolution.
    pub host_tools: Option<PathBuf>,
    /// `modules/` exists and `[ci].targets` names at least one target,
    /// so `fluxor modules build --all` has something to do.
    pub has_modules: bool,
    /// At least one module manifest declares `[test] harness = "…"`.
    pub has_harnesses: bool,
    /// A cargo-visible source file `#[path]`-mounts something under
    /// `target/fluxor/`, so a wiped `target/` must be re-materialised
    /// before cargo reads the mount.
    pub mounts_staged: bool,
    /// `[ci.test] scripts` globs — the project's runtime gate.
    pub test_scripts: Vec<String>,
}

impl Shape {
    /// Where cargo runs, and with which selector. `--workspace` at the
    /// root; a host-tools sub-crate is one package and takes neither.
    fn cargo_site(&self) -> Option<(PathBuf, bool)> {
        match self.host_tools.as_ref() {
            Some(p) if p != &self.project_root => Some((p.clone(), false)),
            _ if self.has_cargo => Some((self.project_root.clone(), true)),
            _ => None,
        }
    }
}

/// Read the project's shape off disk.
pub fn shape(project_root: &Path) -> Shape {
    let name = crate::project::project_identity(project_root)
        .ok()
        .flatten()
        .map(|i| i.name)
        .or_else(|| {
            project_root
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "project".to_string());

    let host_tools = ci::load_host_tools_crate(project_root)
        .map(|c| project_root.join(c))
        .filter(|p| p.join("Cargo.toml").is_file());

    Shape {
        project_root: project_root.to_path_buf(),
        name,
        has_cargo: project_root.join("Cargo.toml").is_file(),
        host_tools,
        has_modules: project_root.join("modules").is_dir() && !ci_targets(project_root).is_empty(),
        has_harnesses: crate::module_test::resolved_harness_count(project_root) > 0,
        mounts_staged: mounts_staged_tree(project_root),
        test_scripts: ci::load_test_scripts(project_root).unwrap_or_default(),
    }
}

/// `fluxor.toml::[ci].targets`, empty when absent or unreadable.
fn ci_targets(project_root: &Path) -> Vec<String> {
    #[derive(serde::Deserialize)]
    struct Top {
        ci: Option<Ci>,
    }
    #[derive(serde::Deserialize)]
    struct Ci {
        targets: Option<Vec<String>>,
    }
    std::fs::read_to_string(project_root.join("fluxor.toml"))
        .ok()
        .and_then(|raw| toml::from_str::<Top>(&raw).ok())
        .and_then(|t| t.ci)
        .and_then(|c| c.targets)
        .unwrap_or_default()
}

/// Directories that are never part of the cargo tree: build output, the
/// vendored upstream checkout, and `modules/` (PIC sources, built by
/// `fluxor modules build`, which stages the tree itself).
const NON_CARGO_DIRS: &[&str] = &[
    "target",
    ".git",
    ".git-shadow",
    "deps",
    "modules",
    "node_modules",
    ".venv",
    ".context",
];

/// Does a cargo-visible source file `#[path]`-mount the staged tree?
///
/// Detected, never hard-coded: the mount is what makes staging a
/// build-order dependency, and which projects have one changes.
///
/// The test is not "the text mentions `target/fluxor`" — it is that a
/// `#[path]` attribute's own relative path, resolved against the file
/// holding it, lands inside *this* checkout's `target/fluxor`. Prose,
/// runtime path joins, and a fixture string in someone's unit test all
/// mention the directory; none of them make cargo read it.
fn mounts_staged_tree(project_root: &Path) -> bool {
    let staged = project_root.join("target/fluxor");
    for entry in walkdir::WalkDir::new(project_root)
        .into_iter()
        .filter_entry(|e| {
            e.depth() == 0
                || !e.file_type().is_dir()
                || !NON_CARGO_DIRS.contains(&e.file_name().to_string_lossy().as_ref())
        })
        .filter_map(std::result::Result::ok)
    {
        if entry.file_type().is_dir() || entry.path().extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let Some(dir) = entry.path().parent() else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        if text
            .lines()
            .filter_map(path_attr_value)
            .any(|rel| lexical_join(dir, rel).starts_with(&staged))
        {
            return true;
        }
    }
    false
}

/// The literal of a `#[path = "…"]` attribute line, if this is one.
fn path_attr_value(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix("#[path")?;
    let rest = rest.trim_start().strip_prefix('=')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Resolve `rel` against `base` textually — `..` pops, `.` is dropped.
/// Lexical, not filesystem: the staged tree may not exist yet, which is
/// precisely the case staging is for.
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

// ── the verbs ───────────────────────────────────────────────────────────

/// Announce a step before running it: the verbs replace recipes that
/// echoed their commands, so the command must stay visible.
fn step(cmd: &str) {
    println!("\x1b[1;36m+\x1b[0m {cmd}");
}

/// `fluxor build` with no config argument — the lifecycle build.
///
/// Stage (only when the cargo tree mounts `target/fluxor`), build the
/// cargo tree, build the modules. A crate-less project builds modules
/// alone; a module-less project builds cargo alone.
pub fn build(project_root: &Path, verbose: bool) -> Result<()> {
    let s = shape(project_root);
    let mut did_something = false;

    // Staging comes first and stands alone: a wiped `target/` must
    // re-materialise before anything reads the mount, and the reader is
    // not always cargo — wave's standalone harness crates are reached by
    // a `[ci.test]` script, with no workspace in between.
    if s.mounts_staged {
        step("fluxor sync   (the tree mounts target/fluxor)");
        let staged = crate::store_sync::ensure_synced(&s.project_root)?;
        for line in &staged {
            println!("  {line}");
        }
        did_something = true;
    }

    if let Some((dir, workspace)) = s.cargo_site() {
        let args: &[&str] = if workspace {
            &["build", "--workspace", "--all-targets"]
        } else {
            &["build", "--all-targets"]
        };
        step(&cargo_label(&s, &dir, args));
        ci::cargo_in(&dir, args).map_err(Error::Config)?;
        did_something = true;
    }

    if s.has_modules {
        step("fluxor modules build --all");
        run_modules_build(&s, verbose)?;
        did_something = true;
    }

    if !did_something {
        println!("nothing to build: no cargo tree and no modules with `[ci].targets`");
    }
    Ok(())
}

/// `fluxor test` — module harnesses, cargo tests, project e2e scripts.
///
/// The three are the three places a fluxor-native project's tests can
/// live; a project runs whichever it has. The e2e scripts run through
/// `fluxor ci`'s own project-e2e runner, so `make test` and the gate
/// agree on what "the scripts passed" means.
pub fn test(project_root: &Path, verbose: bool) -> Result<()> {
    let s = shape(project_root);
    let mut did_something = false;

    if s.has_harnesses {
        step("fluxor modules test");
        crate::module_test::cmd_test(Some(&s.project_root), None, verbose)?;
        did_something = true;
    }

    if let Some((dir, workspace)) = s.cargo_site() {
        let args: &[&str] = if workspace {
            &["test", "--workspace"]
        } else {
            &["test", "--all-targets", "--all-features"]
        };
        step(&cargo_label(&s, &dir, args));
        ci::cargo_in(&dir, args).map_err(Error::Config)?;
        did_something = true;
    }

    if !s.test_scripts.is_empty() {
        step(&format!("[ci.test] scripts: {}", s.test_scripts.join(", ")));
        ci::run_test_scripts(&s.project_root, &s.test_scripts, true).map_err(Error::Config)?;
        did_something = true;
    }

    if !did_something {
        println!("nothing to test: no module harnesses, no cargo tree, no `[ci.test] scripts`");
    }
    Ok(())
}

/// `fluxor lint` — the precise checks the gate runs, minus the ones that
/// need a build.
///
/// `cargo fmt --all -- --check` and `cargo clippy … -D warnings` where a
/// cargo tree exists, then `fluxor lint hygiene`, always. Module
/// fmt/clippy stay `fluxor ci` phases: they compile PIC sources per
/// target and belong to the gate, not the edit loop.
pub fn lint(project_root: &Path) -> Result<()> {
    let s = shape(project_root);

    if s.has_cargo {
        // fmt parses, it does not build, so it always runs at the root
        // and covers every member — including a kernel workspace's.
        step("cargo fmt --all -- --check");
        ci::cargo_in(&s.project_root, &["fmt", "--all", "--", "--check"]).map_err(Error::Config)?;
    }
    if let Some((dir, workspace)) = s.cargo_site() {
        let args: &[&str] = if workspace {
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ]
        } else {
            &[
                "clippy",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ]
        };
        step(&cargo_label(&s, &dir, args));
        ci::cargo_in(&dir, args).map_err(Error::Config)?;
    }

    step("fluxor lint hygiene");
    ci::run_hygiene(&s.project_root).map_err(Error::Config)?;
    println!("hygiene clean");
    Ok(())
}

/// `fluxor clean` — module artefacts, cargo's target tree, and the
/// generated module-test crates.
pub fn clean(project_root: &Path) -> Result<()> {
    let s = shape(project_root);

    if s.has_modules {
        step("fluxor modules clean");
        let removed = modules_build::clean(&modules_build::BuildOpts {
            project_root: s.project_root.clone(),
            selector: modules_build::TargetSelector::All,
            out_root: s.project_root.join("target/fluxor"),
            strict: false,
            verbose: false,
        })?;
        println!("  removed {removed} artefact file(s)");
    }
    if s.has_cargo {
        step("cargo clean");
        ci::cargo_in(&s.project_root, &["clean"]).map_err(Error::Config)?;
    }

    // `fluxor modules test` generates disposable crates here. `cargo
    // clean` removes them only when it owns `target/`; a crate-less
    // project has no cargo clean at all, so remove them explicitly.
    let moduletests = s.project_root.join("target/fluxor/moduletests");
    if moduletests.exists() {
        step("rm -rf target/fluxor/moduletests");
        std::fs::remove_dir_all(&moduletests)
            .map_err(|e| Error::Config(format!("{}: {e}", moduletests.display())))?;
    }
    Ok(())
}

/// Render a cargo invocation the way it would be typed, including the
/// `cd` when it does not run at the project root.
fn cargo_label(s: &Shape, dir: &Path, args: &[&str]) -> String {
    let cmd = format!("cargo {}", args.join(" "));
    match dir.strip_prefix(&s.project_root) {
        Ok(rel) if rel.as_os_str().is_empty() => cmd,
        Ok(rel) => format!("cd {} && {cmd}", rel.display()),
        Err(_) => format!("cd {} && {cmd}", dir.display()),
    }
}

/// `fluxor modules build --all` with the standard's output root, in the
/// lenient mode the developer loop uses (`--strict` is the gate's).
fn run_modules_build(s: &Shape, verbose: bool) -> Result<()> {
    let report = modules_build::run(&modules_build::BuildOpts {
        project_root: s.project_root.clone(),
        selector: modules_build::TargetSelector::All,
        out_root: s.project_root.join("target/fluxor"),
        strict: false,
        verbose,
    })?;
    for tr in &report.per_target {
        println!(
            "  Modules ({}/{}): built {} of {}, up-to-date {}, skipped {}, failed {}",
            tr.target,
            tr.silicon,
            tr.built.len(),
            tr.built.len() + tr.up_to_date.len() + tr.skipped.len() + tr.failed.len(),
            tr.up_to_date.len(),
            tr.skipped.len(),
            tr.failed.len(),
        );
        for (name, reason) in &tr.failed {
            eprintln!("  FAILED:  {name} — {reason}");
        }
    }
    if report.ok() {
        return Ok(());
    }
    let failed: Vec<String> = report
        .per_target
        .iter()
        .flat_map(|t| t.failed.iter().map(|(n, _)| format!("{}/{n}", t.target)))
        .collect();
    Err(Error::Module(format!(
        "module build failed: {}",
        failed.join(", ")
    )))
}

// ── `fluxor help --make` ────────────────────────────────────────────────

/// Generate the canonical `make help` block for this checkout.
///
/// A Makefile's `help:` target is `@fluxor help --make`, so the text can
/// never drift from the CLI or fall behind the scripts in the tree: the
/// script list is a directory walk, not a hand-kept list, and the
/// lifecycle lines say what the verbs actually do for *this* shape.
pub fn make_help(project_root: &Path) -> String {
    let s = shape(project_root);
    let mut out = String::new();
    let mut line = |t: &str| {
        out.push_str(t);
        out.push('\n');
    };

    line(&format!("{} lifecycle:", s.name));
    line(&format!("  make build     {}", describe_build(&s)));
    line(&format!("  make test      {}", describe_test(&s)));
    line(&format!("  make lint      {}", describe_lint(&s)));
    line("  make ci        fluxor ci — the full gate (lints, hygiene, tests,");
    line("                 strict module build, lockfile checks)");
    line("  make publish   fluxor publish — publish this project's artifacts");
    line("                 into the local OCI store");
    line(&format!("  make clean     {}", describe_clean(&s)));
    if is_fluxor_itself(&s) {
        line("  make install   one-time bootstrap: build the CLI + runtime, publish");
        line("                 them into the store, install the resolving launcher");
    }

    line("");
    line("Not make targets (use the CLI directly):");
    for (cmd, desc) in [
        (
            "fluxor modules build [--target …]",
            "PIC modules for one target",
        ),
        ("fluxor modules list", "module inventory"),
        ("fluxor run <config>", "bring-up"),
        ("fluxor update / fluxor sync", "store consumption"),
        ("fluxor build --check configs/…", "config validation"),
        ("fluxor inspect [subject]", "project / config / store info"),
        ("fluxor store ls", "local OCI store contents"),
    ] {
        line(&column(cmd, desc));
    }
    for applet in applet_manifests(&s.project_root) {
        line(&column(
            &format!("fluxor install {applet}"),
            "register the CLI applet",
        ));
        line(&column(
            &format!("fluxor exec {} -- <cmd>", s.name),
            "run it",
        ));
    }

    let scripts = project_scripts(&s.project_root);
    if !scripts.is_empty() {
        line("");
        line("Project scripts (run directly; `(ci)` = wired into `fluxor ci`):");
        let gated = ci_gated_scripts(&s);
        let width = scripts.iter().map(String::len).max().unwrap_or(0);
        for sc in &scripts {
            let mark = if gated.contains(sc) { "  (ci)" } else { "" };
            line(&format!("  {sc:width$}{mark}"));
        }
    }

    line("");
    line(&format!("One-time setup: {}", setup_line(&s)));
    out
}

/// One "  command    description" line of the not-a-make-target block,
/// on the block's column — never closing up to zero spaces when the
/// command overruns it.
fn column(cmd: &str, desc: &str) -> String {
    const COL: usize = 36;
    // Columns are character counts: `…` and `—` are multi-byte, and
    // `len()` would knock the whole block out of alignment.
    let pad = COL.saturating_sub(cmd.chars().count()).max(1);
    format!("  {cmd}{}{desc}", " ".repeat(pad))
}

/// The fluxor checkout is the one that installs the CLI; everyone else
/// consumes it. The discriminator is the tools crate's own package name
/// in the root workspace's member list.
fn is_fluxor_itself(s: &Shape) -> bool {
    s.project_root.join("tools/src/lifecycle.rs").is_file()
        || std::fs::read_to_string(s.project_root.join("tools/Cargo.toml")).is_ok_and(|t| {
            t.contains("name              = \"fluxor-tools\"")
                || t.contains("name = \"fluxor-tools\"")
        })
}

fn describe_build(s: &Shape) -> String {
    let mut parts = Vec::new();
    if s.mounts_staged {
        parts.push("stage target/fluxor".to_string());
    }
    if s.cargo_site().is_some() {
        parts.push("cargo build --all-targets".to_string());
    }
    if s.has_modules {
        parts.push("PIC modules".to_string());
    }
    if parts.is_empty() {
        parts.push("nothing to build".to_string());
    }
    format!("fluxor build — {}", parts.join(" + "))
}

fn describe_test(s: &Shape) -> String {
    let mut parts = Vec::new();
    if s.has_harnesses {
        parts.push("module harnesses".to_string());
    }
    if s.cargo_site().is_some() {
        parts.push("cargo test".to_string());
    }
    if !s.test_scripts.is_empty() {
        parts.push("e2e scripts".to_string());
    }
    if parts.is_empty() {
        parts.push("nothing to test".to_string());
    }
    format!("fluxor test — {}", parts.join(" + "))
}

fn describe_lint(s: &Shape) -> String {
    if s.has_cargo {
        "fluxor lint — rustfmt --check + clippy -D warnings + hygiene".to_string()
    } else {
        "fluxor lint — hygiene".to_string()
    }
}

fn describe_clean(s: &Shape) -> String {
    let mut parts = Vec::new();
    if s.has_modules {
        parts.push("module artefacts".to_string());
    }
    if s.has_cargo {
        parts.push("cargo clean".to_string());
    }
    parts.push("module-test crates".to_string());
    format!("fluxor clean — {}", parts.join(" + "))
}

/// The one-time bootstrap line: how *this* checkout gets a `fluxor` on
/// PATH. Never `cargo install` — that shadows the launcher.
fn setup_line(s: &Shape) -> String {
    if is_fluxor_itself(s) {
        return "make install   (builds the CLI, publishes it, installs the launcher)".to_string();
    }
    for candidate in ["deps/fluxor", "../fluxor"] {
        if s.project_root.join(candidate).join("Makefile").is_file() {
            return format!("make -C {candidate} install");
        }
    }
    "make -C ../fluxor install".to_string()
}

/// `app.fluxor.toml` / `packaging/cli/workload.toml` — the product-CLI
/// applet manifest, when this project ships one.
fn applet_manifests(project_root: &Path) -> Vec<String> {
    ["packaging/cli/workload.toml", "app.fluxor.toml"]
        .iter()
        .filter(|p| project_root.join(p).is_file())
        .map(|p| (*p).to_string())
        .collect()
}

/// Every shell script under `tools/` and `scripts/`, recursively, as
/// repo-relative paths. A walk, not a list: help text that names six of
/// thirty-eight scripts is how the other thirty-two became invisible.
fn project_scripts(project_root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for top in ["tools", "scripts"] {
        let dir = project_root.join(top);
        if !dir.is_dir() {
            continue;
        }
        for entry in walkdir::WalkDir::new(&dir)
            .into_iter()
            .filter_entry(|e| {
                e.depth() == 0
                    || !e.file_type().is_dir()
                    || !NON_CARGO_DIRS.contains(&e.file_name().to_string_lossy().as_ref())
            })
            .filter_map(std::result::Result::ok)
        {
            if entry.file_type().is_dir() {
                continue;
            }
            let p = entry.path();
            if p.extension().is_some_and(|e| e == "sh" || e == "py") {
                if let Ok(rel) = p.strip_prefix(project_root) {
                    out.push(rel.to_string_lossy().into_owned());
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Which of those scripts `[ci.test] scripts` actually runs — the
/// difference between "in the gate" and "advertised as in the gate".
fn ci_gated_scripts(s: &Shape) -> std::collections::BTreeSet<String> {
    let mut paths = Vec::new();
    for glob in &s.test_scripts {
        ci::expand_glob(&s.project_root, glob, &mut paths);
    }
    paths
        .into_iter()
        .filter_map(|p| {
            p.strip_prefix(&s.project_root)
                .ok()
                .map(|r| r.to_string_lossy().into_owned())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_attr_value_reads_only_real_path_attributes() {
        assert_eq!(
            path_attr_value(r#"    #[path = "../../target/fluxor/x.rs"]"#),
            Some("../../target/fluxor/x.rs")
        );
        // Prose and runtime path joins are not mounts.
        assert_eq!(
            path_attr_value("// The path moves to `../target/fluxor/lib.rs`"),
            None
        );
        assert_eq!(
            path_attr_value(r#"    PathBuf::from(r).join("target/fluxor/x.wasm")"#),
            None
        );
    }

    #[test]
    fn a_mount_counts_only_when_it_lands_in_this_checkouts_staged_tree() {
        let root = Path::new("/p");
        let staged = root.join("target/fluxor");
        // clustor's `tests/wal_scan.rs` shape — one level up into target/.
        assert!(lexical_join(
            &root.join("tests"),
            "../target/fluxor/fluxor-abi/sdk/abi.rs"
        )
        .starts_with(&staged));
        // wave/spectra's `tests/harness/src/lib.rs` shape — three levels up.
        assert!(lexical_join(
            &root.join("tests/harness/src"),
            "../../../target/fluxor/fluxor-abi/sdk/abi.rs"
        )
        .starts_with(&staged));
        // fluxor's own `tools/src/hygiene.rs` carries that exact literal
        // inside a test fixture string; three levels up from `tools/src`
        // escapes the checkout entirely, so it is not a mount here.
        assert!(!lexical_join(
            &root.join("tools/src"),
            "../../../target/fluxor/fluxor-abi/sdk/abi.rs"
        )
        .starts_with(&staged));
    }

    #[test]
    fn cargo_site_prefers_the_host_tools_crate_over_the_root() {
        let root = PathBuf::from("/p");
        let s = Shape {
            project_root: root.clone(),
            name: "p".into(),
            has_cargo: true,
            host_tools: Some(root.join("tools")),
            has_modules: false,
            has_harnesses: false,
            mounts_staged: false,
            test_scripts: Vec::new(),
        };
        assert_eq!(s.cargo_site(), Some((root.join("tools"), false)));
    }

    #[test]
    fn cargo_site_is_the_workspace_root_without_a_host_tools_crate() {
        let root = PathBuf::from("/p");
        let s = Shape {
            project_root: root.clone(),
            name: "p".into(),
            has_cargo: true,
            host_tools: None,
            has_modules: false,
            has_harnesses: false,
            mounts_staged: false,
            test_scripts: Vec::new(),
        };
        assert_eq!(s.cargo_site(), Some((root, true)));
    }

    #[test]
    fn cargo_site_is_absent_for_a_crate_less_project() {
        let s = Shape {
            project_root: PathBuf::from("/p"),
            name: "p".into(),
            has_cargo: false,
            host_tools: None,
            has_modules: true,
            has_harnesses: true,
            mounts_staged: false,
            test_scripts: vec!["tools/e2e/*.sh".into()],
        };
        assert_eq!(s.cargo_site(), None);
        assert_eq!(describe_build(&s), "fluxor build — PIC modules".to_string());
        assert_eq!(
            describe_test(&s),
            "fluxor test — module harnesses + e2e scripts".to_string()
        );
    }

    #[test]
    fn cargo_label_shows_the_cd_only_when_it_leaves_the_root() {
        let root = PathBuf::from("/p");
        let s = Shape {
            project_root: root.clone(),
            name: "p".into(),
            has_cargo: true,
            host_tools: None,
            has_modules: false,
            has_harnesses: false,
            mounts_staged: false,
            test_scripts: Vec::new(),
        };
        assert_eq!(cargo_label(&s, &root, &["test"]), "cargo test");
        assert_eq!(
            cargo_label(&s, &root.join("tools"), &["test"]),
            "cd tools && cargo test"
        );
    }

    #[test]
    fn make_help_uses_store_vocabulary_and_lists_scripts() {
        let dir =
            std::env::temp_dir().join(format!("fluxor-lifecycle-help-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("tools/e2e")).unwrap();
        std::fs::create_dir_all(dir.join("scripts")).unwrap();
        std::fs::write(dir.join("fluxor.toml"), "[project]\nname = \"demo\"\n").unwrap();
        std::fs::write(dir.join("tools/e2e/graph.sh"), "#!/bin/bash\n").unwrap();
        std::fs::write(dir.join("scripts/bringup.sh"), "#!/bin/bash\n").unwrap();

        let text = make_help(&dir);
        assert!(text.starts_with("demo lifecycle:"), "{text}");
        assert!(!text.to_lowercase().contains("registry"), "{text}");
        assert!(text.contains("local OCI store"), "{text}");
        assert!(text.contains("tools/e2e/graph.sh"), "{text}");
        assert!(text.contains("scripts/bringup.sh"), "{text}");
        assert!(text.contains("One-time setup:"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
