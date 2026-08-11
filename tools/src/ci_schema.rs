//! `fluxor.toml` schema — the `fluxor ci` phase that gates the config
//! every other phase reads.
//!
//! `fluxor.toml` is hand-written, and an unchecked key that names
//! nothing does nothing — quietly, forever. Every failure this phase
//! removes is of that shape: a missing `[project]` leaves
//! `ci` with no identity to stamp a green digest under; a `[ci] targets`
//! declared by a repo with no modules (or absent from one that has
//! them) silently builds nothing; a `forbid_inline_tests` naming a
//! directory that does not exist bans nothing, and one naming `src`
//! instead of `modules` permits inline tests exactly where `no_std`
//! compiles them away unnoticed. None of these fail on their own.
//!
//! Three kinds of rule:
//!
//!   1. **Always required** — `[project] name`, `[project] version`.
//!   2. **Conditional** — required or forbidden according to the shape
//!      of the checkout, never according to which repo it is:
//!      `[ci] targets` iff the repo has module manifests under the
//!      standard tiers; `[ci.cargo] host_tools_crate` iff the cargo
//!      phase runs in a sub-crate rather than at the root. The shape is
//!      read through [`crate::lifecycle::shape`], the same reader the
//!      lifecycle verbs use, so the gate and `fluxor build`/`test` can
//!      never disagree about what this project is.
//!   3. **Key sanity** — a key must name something that exists and must
//!      mean one thing. `forbid_inline_tests` entries name real
//!      top-level directories; `[[ci.lints.exemption]] crate` is a
//!      crate *name*; every key under `[ci]` is one the CLI reads.
//!
//! There is no exemption escape here. An exemption is for a rule a
//! project can be right to break; no standard sanctions a `fluxor.toml`
//! key that names nothing, and the fix is always to edit the file the
//! error names.

use std::collections::BTreeSet;
use std::path::Path;

use toml::Value;

/// Every key the CLI reads under `[ci]`, by table path. A key absent
/// from this table is a typo doing nothing — the failure mode the phase
/// exists to end — so the list is the schema, not a hint.
const ALLOWED: &[(&str, &[&str])] = &[
    ("ci", &["targets"]),
    ("ci.cargo", &["host_tools_crate"]),
    (
        "ci.hygiene",
        &[
            "mode",
            "forbid_inline_tests",
            "max_inline_lines",
            "exemption",
        ],
    ),
    (
        "ci.hygiene.exemption",
        &["path", "rule", "reason", "expires"],
    ),
    ("ci.lints", &["exemption"]),
    ("ci.lints.exemption", &["crate", "reason"]),
    ("ci.templates", &["dir", "vars", "template"]),
    ("ci.templates.template", &["file", "vars"]),
    ("ci.test", &["scripts"]),
];

/// Tables under `[ci]` whose *contents* are free-form values rather
/// than schema keys (`vars = { KEY = "…" }` is a substitution map).
const FREEFORM: &[&str] = &["ci.templates.vars", "ci.templates.template.vars"];

/// Run the phase. `Ok(())` when the file conforms; the error lists every
/// problem, one per line, each naming the file, the key, and the fix.
pub fn check(project_root: &Path) -> std::result::Result<(), String> {
    let path = project_root.join("fluxor.toml");
    let Ok(raw) = std::fs::read_to_string(&path) else {
        // No manifest: an unadopted directory, not a broken one. Every
        // other phase treats it the same way.
        return Ok(());
    };
    let doc: Value = toml::from_str(&raw).map_err(|e| format!("fluxor.toml: {e}"))?;

    let mut problems = Vec::new();
    check_project(&doc, &mut problems);
    check_targets(project_root, &doc, &mut problems);
    check_host_tools_crate(project_root, &doc, &mut problems);
    check_inline_test_dirs(project_root, &doc, &mut problems);
    check_lint_exemptions(project_root, &doc, &mut problems);
    check_unknown_keys(&doc, &mut problems);

    if problems.is_empty() {
        return Ok(());
    }
    problems.sort();
    problems.dedup();
    Err(format!(
        "fluxor.toml does not conform to the schema:\n  {}",
        problems.join("\n  ")
    ))
}

// ── always required ─────────────────────────────────────────────────────

fn check_project(doc: &Value, out: &mut Vec<String>) {
    let Some(project) = doc.get("project") else {
        out.push(
            "no `[project]` table — add `[project]` with `name` and `version`; publish scopes \
             every artifact under the project name, and without it `fluxor ci` has no identity \
             to stamp its green digest under"
                .to_string(),
        );
        return;
    };
    for key in ["name", "version"] {
        match project.get(key).and_then(Value::as_str) {
            Some(s) if !s.trim().is_empty() => {}
            Some(_) => out.push(format!(
                "`[project] {key}` is empty — set it to a real value"
            )),
            None => out.push(format!(
                "`[project] {key}` is required — add `{key} = \"…\"` under `[project]`"
            )),
        }
    }
}

// ── conditional on the shape of the checkout ────────────────────────────

/// `manifest.toml` files under the standard tiers, counted the way
/// `fluxor modules build` discovers them.
fn tiered_manifest_count(project_root: &Path) -> usize {
    let mut n = 0;
    for tier in crate::manifest::MODULE_TIERS {
        let root = project_root.join(tier);
        if !root.is_dir() {
            continue;
        }
        n += walkdir::WalkDir::new(&root)
            .min_depth(2)
            .max_depth(3)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name() == "manifest.toml")
            .count();
    }
    n
}

fn ci_targets(doc: &Value) -> Option<&Vec<Value>> {
    doc.get("ci")?.get("targets")?.as_array()
}

fn check_targets(project_root: &Path, doc: &Value, out: &mut Vec<String>) {
    let modules = tiered_manifest_count(project_root);
    let declared = ci_targets(doc);
    match (modules, declared) {
        (0, Some(_)) => out.push(
            "`[ci] targets` declares a module build matrix, but no `manifest.toml` exists under \
             the standard tiers (modules/foundation, modules/drivers, modules/platform/*, \
             modules/fixtures, modules/app, modules/common) — remove the key. A repo whose \
             modules sit in a flat `modules/<name>/` layout is unmigrated: move each module \
             into a tier, and the key becomes required"
                .to_string(),
        ),
        (n, None) if n > 0 => out.push(format!(
            "`[ci] targets` is required: {n} module manifest(s) live under the standard tiers \
             and nothing says which silicon to build them for — add e.g. \
             `[ci]` / `targets = [\"bcm2712\"]`"
        )),
        (n, Some(t)) if n > 0 && t.is_empty() => out.push(
            "`[ci] targets` is empty — `fluxor modules build --all` would build nothing; name \
             at least one silicon/host token"
                .to_string(),
        ),
        _ => {}
    }
}

fn check_host_tools_crate(project_root: &Path, doc: &Value, out: &mut Vec<String>) {
    let declared = doc
        .get("ci")
        .and_then(|c| c.get("cargo"))
        .and_then(|c| c.get("host_tools_crate"))
        .and_then(Value::as_str);

    // The same reader the lifecycle verbs use: whatever `fluxor test`
    // would pick as its cargo site is what the gate must have declared.
    let shape = crate::lifecycle::shape(project_root);
    let sub_crate = shape
        .host_tools
        .as_ref()
        .filter(|p| p.as_path() != project_root);

    match (declared, sub_crate) {
        (None, Some(p)) => {
            let rel = p
                .strip_prefix(project_root)
                .unwrap_or(p)
                .display()
                .to_string();
            out.push(format!(
                "`[ci.cargo] host_tools_crate` is required: this root cannot host the cargo \
                 phase (its default features are not host-buildable), so `fluxor ci` and \
                 `fluxor test` fall back to `{rel}/` by convention — declare it: \
                 `[ci.cargo]` / `host_tools_crate = \"{rel}\"`"
            ));
        }
        (Some(d), _) => {
            let dir = project_root.join(d);
            if !dir.join("Cargo.toml").is_file() {
                out.push(format!(
                    "`[ci.cargo] host_tools_crate = \"{d}\"` names `{d}/`, which has no \
                     Cargo.toml — the cargo phase would report itself skipped and test nothing; \
                     point it at the crate that holds this project's host tests"
                ));
            }
        }
        (None, None) => {}
    }
}

// ── key sanity ──────────────────────────────────────────────────────────

fn check_inline_test_dirs(project_root: &Path, doc: &Value, out: &mut Vec<String>) {
    if doc
        .get("ci")
        .and_then(|c| c.get("forbid_inline_tests"))
        .is_some()
    {
        out.push(
            "`forbid_inline_tests` sits directly under `[ci]`, where nothing reads it — the \
             hygiene scanner reads `[ci.hygiene] forbid_inline_tests`. Move the key under a \
             `[ci.hygiene]` header"
                .to_string(),
        );
    }

    let entries: Vec<String> = doc
        .get("ci")
        .and_then(|c| c.get("hygiene"))
        .and_then(|h| h.get("forbid_inline_tests"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    for e in &entries {
        if e.contains('/') || e.contains('\\') {
            out.push(format!(
                "`[ci.hygiene] forbid_inline_tests` entry {e:?} is a path; entries are top-level \
                 directory names (the scanner bans the whole tier)"
            ));
            continue;
        }
        if !project_root.join(e).is_dir() {
            out.push(format!(
                "`[ci.hygiene] forbid_inline_tests` names {e:?}, which is not a directory in \
                 this repo — a ban over an absent tier enforces nothing; remove it"
            ));
        }
    }

    if tiered_manifest_count(project_root) > 0 && !entries.iter().any(|e| e == "modules") {
        out.push(
            "`[ci.hygiene] forbid_inline_tests` must list \"modules\": every PIC module is \
             `no_std` and an inline `#[cfg(test)]` block there compiles away silently, so the \
             tests read as present and run nowhere"
                .to_string(),
        );
    }
}

/// Workspace members as `(member path, package name)`.
///
/// `[[ci.lints.exemption]] crate` is a package name (below), and the
/// workspace-lint audit enumerates members by path, so the two are
/// joined here — in one place, so they cannot drift apart.
pub fn workspace_members(project_root: &Path) -> Vec<(String, String)> {
    let Ok(raw) = std::fs::read_to_string(project_root.join("Cargo.toml")) else {
        return Vec::new();
    };
    let Ok(doc) = toml::from_str::<Value>(&raw) else {
        return Vec::new();
    };
    let members = doc
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    members
        .into_iter()
        .filter_map(|m| {
            let manifest = project_root.join(&m).join("Cargo.toml");
            let text = std::fs::read_to_string(&manifest).ok()?;
            let parsed: Value = toml::from_str(&text).ok()?;
            let name = parsed
                .get("package")?
                .get("name")?
                .as_str()
                .map(str::to_string)?;
            Some((m, name))
        })
        .collect()
}

/// THE `crate` semantic: a package **name**.
///
/// The key meant a path in one repo and a name in another. A name is
/// what the thing being exempted actually has — `cargo` identifies a
/// package by `[package] name`, a path is one of several spellings of
/// where it happens to sit (`.`, `tools/x`, `./tools/x`), and the audit
/// this exists for reads `[lints]` out of a package. So: names.
fn check_lint_exemptions(project_root: &Path, doc: &Value, out: &mut Vec<String>) {
    let Some(rows) = doc
        .get("ci")
        .and_then(|c| c.get("lints"))
        .and_then(|l| l.get("exemption"))
        .and_then(Value::as_array)
    else {
        return;
    };
    let members = workspace_members(project_root);
    let names: BTreeSet<&str> = members.iter().map(|(_, n)| n.as_str()).collect();
    for row in rows {
        let Some(value) = row.get("crate").and_then(Value::as_str) else {
            out.push(
                "`[[ci.lints.exemption]]` row has no `crate` key — name the package the \
                 exemption is for"
                    .to_string(),
            );
            continue;
        };
        if value.contains('/') || value == "." || value == ".." {
            let suggestion = members
                .iter()
                .find(|(path, _)| path.trim_end_matches('/') == value.trim_end_matches('/'))
                .map(|(_, n)| format!(" — that path is package `{n}`"))
                .unwrap_or_default();
            out.push(format!(
                "`[[ci.lints.exemption]] crate = {value:?}` is a path. This key is a crate \
                 NAME — the `[package] name` cargo resolves, which is the identity the \
                 workspace-lint audit reads a `[lints]` table out of{suggestion}"
            ));
            continue;
        }
        if !names.is_empty() && !names.contains(value) {
            out.push(format!(
                "`[[ci.lints.exemption]] crate = {value:?}` matches no workspace member's \
                 package name ({}) — an exemption for a package that does not exist exempts \
                 nothing",
                members
                    .iter()
                    .map(|(_, n)| n.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
}

fn check_unknown_keys(doc: &Value, out: &mut Vec<String>) {
    let Some(ci) = doc.get("ci") else {
        return;
    };
    walk_table("ci", ci, out);
}

fn walk_table(path: &str, value: &Value, out: &mut Vec<String>) {
    if FREEFORM.contains(&path) {
        return;
    }
    match value {
        Value::Array(rows) => {
            for row in rows {
                walk_table(path, row, out);
            }
        }
        Value::Table(map) => {
            let allowed: &[&str] = ALLOWED
                .iter()
                .find(|(p, _)| *p == path)
                .map(|(_, k)| *k)
                .unwrap_or(&[]);
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                let known_table = ALLOWED.iter().any(|(p, _)| *p == child_path)
                    || FREEFORM.contains(&child_path.as_str());
                if !allowed.contains(&key.as_str()) && !known_table {
                    // A `forbid_inline_tests` directly under `[ci]` has
                    // its own message naming the table it belongs in;
                    // don't also report it as an unknown key.
                    if child_path != "ci.forbid_inline_tests" {
                        out.push(format!(
                            "unknown key `[{path}] {key}` — no phase reads it, so it silently \
                             does nothing. Remove it, or fix the spelling (keys under `[{path}]`: {})",
                            if allowed.is_empty() {
                                "none".to_string()
                            } else {
                                allowed.join(", ")
                            }
                        ));
                    }
                    continue;
                }
                if matches!(child, Value::Table(_) | Value::Array(_)) {
                    walk_table(&child_path, child, out);
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "fluxor-ci-schema-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn write(&self, rel: &str, body: &str) -> &Self {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
            self
        }
        fn dir(&self, rel: &str) -> &Self {
            std::fs::create_dir_all(self.0.join(rel)).unwrap();
            self
        }
        fn err(&self) -> String {
            check(&self.0).unwrap_err()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const MODULE_MANIFEST: &str = "name = \"m\"\ntype = \"Foundation\"\n";

    #[test]
    fn a_module_less_project_is_clean_without_targets() {
        let f = Fixture::new("moduleless");
        f.write(
            "fluxor.toml",
            "[project]\nname = \"cue\"\nversion = \"0.0.1\"\n",
        );
        check(&f.0).unwrap();
    }

    #[test]
    fn project_name_and_version_are_always_required() {
        let f = Fixture::new("noproject");
        f.write("fluxor.toml", "[ci]\n");
        let e = f.err();
        assert!(e.contains("no `[project]` table"), "{e}");
    }

    #[test]
    fn targets_are_required_with_modules_and_forbidden_without() {
        let with = Fixture::new("targets-required");
        with.write(
            "fluxor.toml",
            "[project]\nname = \"p\"\nversion = \"0\"\n[ci.hygiene]\nforbid_inline_tests = [\"modules\"]\n",
        )
        .write("modules/foundation/m/manifest.toml", MODULE_MANIFEST);
        let e = with.err();
        assert!(e.contains("`[ci] targets` is required"), "{e}");
        assert!(e.contains("1 module manifest"), "{e}");

        let without = Fixture::new("targets-forbidden");
        without.write(
            "fluxor.toml",
            "[project]\nname = \"p\"\nversion = \"0\"\n[ci]\ntargets = [\"bcm2712\"]\n",
        );
        let e = without.err();
        assert!(
            e.contains("no `manifest.toml` exists under the standard tiers"),
            "{e}"
        );
        // The flat-layout repo is told what its real problem is.
        assert!(e.contains("flat `modules/<name>/` layout"), "{e}");
    }

    #[test]
    fn a_flat_layout_repo_is_told_to_migrate_not_to_add_targets() {
        let f = Fixture::new("flat");
        f.write(
            "fluxor.toml",
            "[project]\nname = \"zedex\"\nversion = \"0\"\n[ci]\ntargets = [\"bcm2712\"]\n",
        )
        .write("modules/thing/manifest.toml", MODULE_MANIFEST);
        let e = f.err();
        assert!(e.contains("move each module into a tier"), "{e}");
    }

    #[test]
    fn host_tools_crate_is_required_when_the_cargo_site_is_a_sub_crate() {
        let f = Fixture::new("hosttools");
        f.write("fluxor.toml", "[project]\nname = \"p\"\nversion = \"0\"\n")
            .write(
                "Cargo.toml",
                "[package]\nname = \"p\"\nversion = \"0.0.1\"\n",
            )
            .write(
                "tools/Cargo.toml",
                "[package]\nname = \"p-tools\"\nversion = \"0.0.1\"\n",
            );
        let e = f.err();
        assert!(
            e.contains("`[ci.cargo] host_tools_crate` is required"),
            "{e}"
        );
        assert!(e.contains("host_tools_crate = \"tools\""), "{e}");

        // Declared: clean.
        f.write(
            "fluxor.toml",
            "[project]\nname = \"p\"\nversion = \"0\"\n[ci.cargo]\nhost_tools_crate = \"tools\"\n",
        );
        check(&f.0).unwrap();

        // Declared but pointing nowhere: named, with the consequence.
        f.write(
            "fluxor.toml",
            "[project]\nname = \"p\"\nversion = \"0\"\n[ci.cargo]\nhost_tools_crate = \"nope\"\n",
        );
        let e = f.err();
        assert!(e.contains("which has no Cargo.toml"), "{e}");
    }

    #[test]
    fn forbid_inline_tests_must_name_directories_that_exist() {
        let f = Fixture::new("dirs");
        f.write(
            "fluxor.toml",
            "[project]\nname = \"p\"\nversion = \"0\"\n[ci.hygiene]\nforbid_inline_tests = [\"src\"]\n",
        );
        let e = f.err();
        assert!(e.contains("names \"src\", which is not a directory"), "{e}");

        f.dir("src");
        check(&f.0).unwrap();
    }

    #[test]
    fn a_repo_with_modules_must_ban_inline_tests_in_them() {
        let f = Fixture::new("inverted");
        f.dir("src")
            .write(
                "fluxor.toml",
                "[project]\nname = \"zedex\"\nversion = \"0\"\n[ci]\ntargets = [\"bcm2712\"]\n\
                 [ci.hygiene]\nforbid_inline_tests = [\"src\"]\n",
            )
            .write("modules/foundation/m/manifest.toml", MODULE_MANIFEST);
        let e = f.err();
        assert!(e.contains("must list \"modules\""), "{e}");
        assert!(e.contains("compiles away silently"), "{e}");
    }

    #[test]
    fn a_misplaced_forbid_inline_tests_names_the_table_it_belongs_in() {
        let f = Fixture::new("misplaced");
        f.dir("modules").write(
            "fluxor.toml",
            "[project]\nname = \"loam\"\nversion = \"0\"\n[ci]\nforbid_inline_tests = [\"modules\"]\n",
        );
        let e = f.err();
        assert!(
            e.contains("Move the key under a `[ci.hygiene]` header"),
            "{e}"
        );
        // Reported once, as a placement error — not also as a typo.
        assert_eq!(e.matches("forbid_inline_tests").count(), 2, "{e}");
    }

    #[test]
    fn a_lint_exemption_crate_is_a_name_not_a_path() {
        let f = Fixture::new("exempt");
        f.write("Cargo.toml", "[workspace]\nmembers = [\"tools/bench\"]\n")
            .write(
                "tools/bench/Cargo.toml",
                "[package]\nname = \"p-bench\"\nversion = \"0.0.1\"\n",
            )
            .write(
                "fluxor.toml",
                "[project]\nname = \"p\"\nversion = \"0\"\n\
                 [[ci.lints.exemption]]\ncrate = \"tools/bench\"\nreason = \"r\"\n",
            );
        let e = f.err();
        assert!(e.contains("is a path"), "{e}");
        assert!(e.contains("that path is package `p-bench`"), "{e}");

        f.write(
            "fluxor.toml",
            "[project]\nname = \"p\"\nversion = \"0\"\n\
             [[ci.lints.exemption]]\ncrate = \"p-bench\"\nreason = \"r\"\n",
        );
        check(&f.0).unwrap();

        f.write(
            "fluxor.toml",
            "[project]\nname = \"p\"\nversion = \"0\"\n\
             [[ci.lints.exemption]]\ncrate = \"ghost\"\nreason = \"r\"\n",
        );
        let e = f.err();
        assert!(e.contains("matches no workspace member"), "{e}");
    }

    #[test]
    fn an_unknown_key_under_ci_is_an_error_and_freeform_vars_are_not() {
        let f = Fixture::new("unknown");
        f.dir("configs").write(
            "fluxor.toml",
            "[project]\nname = \"p\"\nversion = \"0\"\n\
             [ci.test]\nscript = [\"a.sh\"]\n\
             [ci.templates]\ndir = \"configs\"\nvars = { SELF_ID = \"0\", PORT = \"1\" }\n",
        );
        let e = f.err();
        assert!(e.contains("unknown key `[ci.test] script`"), "{e}");
        assert!(e.contains("keys under `[ci.test]`: scripts"), "{e}");
        assert!(!e.contains("SELF_ID"), "{e}");
    }

    #[test]
    fn exemption_rows_are_schema_checked_row_by_row() {
        let f = Fixture::new("rows");
        f.dir("modules").write(
            "fluxor.toml",
            "[project]\nname = \"p\"\nversion = \"0\"\n\
             [[ci.hygiene.exemption]]\npath = \"modules/x/mod.rs\"\nrule = \"inline-tests\"\n\
             reason = \"r\"\nexpiry = \"2030-01-01\"\n",
        );
        let e = f.err();
        assert!(
            e.contains("unknown key `[ci.hygiene.exemption] expiry`"),
            "{e}"
        );
    }
}
