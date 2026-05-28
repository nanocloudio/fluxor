//! `fluxor.lock` — pinned resolution snapshot.
//!
//! The lockfile sits next to `fluxor.toml`, is committed, and records
//! the exact resolved version of every transitive dependency —
//! source crates and fmods — so a build from a fresh checkout
//! reproduces the same artefacts.
//!
//! This module owns the file format, the read/write path, and a
//! minimal resolver that satisfies each declared `[dependencies]`
//! entry against the local registry's available versions. Cargo-style
//! transitive resolution and ABI unification are not yet implemented;
//! they're planned once the in-registry index makes cross-project
//! lookup cheap.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::hash::file_sha256_prefixed;
use crate::project;
use crate::project_meta;
use crate::registry::{self, ArtefactKind, CrateEntry, FmodEntry, RuntimeEntry};

const LOCKFILE_NAME: &str = "fluxor.lock";
const LOCKFILE_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct LockFile {
    pub lockfile_version: u32,
    pub generated_by: String,
    /// Features that were active when this lockfile was resolved.
    /// `fluxor ci`'s consistency check re-runs the resolver against
    /// this same set, so a feature-gated lockfile stays green across
    /// CI invocations without `--features` having to be remembered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_features: Vec<String>,
    #[serde(default, rename = "crate")]
    pub crates: Vec<LockedCrate>,
    #[serde(default, rename = "fmod")]
    pub fmods: Vec<LockedFmod>,
    #[serde(default, rename = "runtime")]
    pub runtimes: Vec<LockedRuntime>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LockedCrate {
    pub name: String,
    pub version: String,
    pub hash: String,
    /// Path to the artefact in the local registry, relative to the
    /// registry root. Recorded for fast lookup; the canonical
    /// identity is `(name, version, hash)`.
    pub source: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LockedFmod {
    pub project: String,
    pub name: String,
    pub target: String,
    pub version: String,
    pub hash: String,
    pub source: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LockedRuntime {
    pub project: String,
    pub name: String,
    pub host_target: String,
    pub version: String,
    pub hash: String,
    pub source: String,
}

pub fn lockfile_path(project_root: &Path) -> PathBuf {
    project_root.join(LOCKFILE_NAME)
}

pub fn read(project_root: &Path) -> Result<Option<LockFile>> {
    let path = lockfile_path(project_root);
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path)?;
    let parsed: LockFile = toml::from_str(&text)
        .map_err(|e| Error::Config(format!("parse {}: {e}", path.display())))?;
    Ok(Some(parsed))
}

pub fn write(project_root: &Path, lock: &LockFile) -> Result<PathBuf> {
    let path = lockfile_path(project_root);
    let mut body = String::new();
    body.push_str("# fluxor.lock — generated, edit via `fluxor update`\n");
    body.push_str("# Pinned resolution snapshot of every transitive dependency.\n\n");
    let serialised = toml::to_string_pretty(lock)
        .map_err(|e| Error::Config(format!("serialise lockfile: {e}")))?;
    body.push_str(&serialised);
    fs::write(&path, body)?;
    Ok(path)
}

// ── Resolution ────────────────────────────────────────────────────────

/// Resolve `[dependencies]` against the registry's available
/// artefacts, walking transitively via `~/.fluxor/registry/
/// projects/<name>/<version>.toml` meta files. Each project name is
/// resolved once; the first matching version wins. Cargo-style range
/// unification (combining `^1.0` from one edge and `^1.2` from
/// another) is not yet implemented — a conflict is reported via
/// advisory but does not block resolution.
///
/// `active_features` filters this project's optional deps — any
/// `[dependencies.X] optional = true` entry must be referenced by
/// at least one feature in this list to participate. Transitive
/// deps are walked with no features active (default-features only);
/// cargo-style unified-features propagation is pending follow-up.
///
/// Minimal version matching: caret semantics (`"1.0"` matches `1.x.
/// y`). Path / git overrides bypass the registry — they're recorded
/// as `source = "path:..."` so the lockfile still captures intent.
pub fn resolve(project_root: &Path, active_features: &[String]) -> Result<LockFile> {
    let direct_deps =
        project::active_dependencies(project_root, active_features).map_err(Error::Config)?;
    let mut features_sorted: Vec<String> = active_features.to_vec();
    features_sorted.sort();
    features_sorted.dedup();
    let mut lock = LockFile {
        lockfile_version: LOCKFILE_VERSION,
        generated_by: format!("fluxor {}", env!("CARGO_PKG_VERSION")),
        active_features: features_sorted,
        crates: Vec::new(),
        fmods: Vec::new(),
        runtimes: Vec::new(),
    };

    if direct_deps.is_empty() {
        return Ok(lock);
    }

    let root = registry::registry_root()?;
    registry::ensure_layout(&root)?;
    let registry_crates = registry::walk_crates(&root)?;
    let registry_fmods = registry::walk_fmods(&root)?;
    let registry_runtimes = registry::walk_runtimes(&root)?;

    let mut queue: VecDeque<project::DepSpec> = direct_deps.into_iter().collect();
    let mut visited: BTreeMap<String, String> = BTreeMap::new(); // name -> chosen version range

    while let Some(dep) = queue.pop_front() {
        let want = match dep.version.clone().or_else(|| {
            if dep.path.is_some() || dep.git.is_some() {
                Some("*".to_string())
            } else {
                None
            }
        }) {
            Some(v) => v,
            None => {
                return Err(Error::Config(format!(
                    "[dependencies.{}] has neither version, path, nor git",
                    dep.name
                )));
            }
        };

        // Conflict detection: if we've already resolved this name
        // under a different range, surface an advisory but keep the
        // first-seen choice.
        if let Some(prev_range) = visited.get(&dep.name) {
            if prev_range != &want {
                eprintln!(
                    "note: transitive dep {} appears with both `{}` and `{}` — using first-seen range. \
                     Cargo-style range unification is pending a later phase.",
                    dep.name, prev_range, want
                );
            }
            continue;
        }
        visited.insert(dep.name.clone(), want.clone());

        // Resolve this dep's artefacts.
        let chosen_version = resolve_one_dep_artefacts(
            &dep,
            &want,
            &root,
            &registry_crates,
            &registry_fmods,
            &registry_runtimes,
            &mut lock,
        )?;

        // Walk the dep's own [dependencies] via its project-meta file.
        if let Some(chosen) = chosen_version {
            if let Some(meta) = project_meta::read_meta(&root, &dep.name, &chosen)? {
                for (name, meta_dep) in &meta.dependencies {
                    let want_version = meta_dep.version_req().map(String::from);
                    queue.push_back(project::DepSpec {
                        name: name.clone(),
                        version: want_version,
                        path: None,
                        git: None,
                        optional: false,
                    });
                }
            }
        }
    }

    // Stable ordering + cross-edge dedup. Multiple BFS visits to
    // the same `(name, version)` (legitimate via diamonds) coalesce
    // here so the lockfile records one entry each.
    sort_and_finalise(&mut lock);
    Ok(lock)
}

fn sort_and_finalise(lock: &mut LockFile) {
    lock.crates
        .sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
    lock.crates
        .dedup_by(|a, b| a.name == b.name && a.version == b.version);
    lock.fmods.sort_by(|a, b| {
        a.project
            .cmp(&b.project)
            .then(a.target.cmp(&b.target))
            .then(a.name.cmp(&b.name))
    });
    lock.fmods.dedup_by(|a, b| {
        a.project == b.project && a.target == b.target && a.name == b.name && a.version == b.version
    });
    lock.runtimes.sort_by(|a, b| {
        a.project
            .cmp(&b.project)
            .then(a.host_target.cmp(&b.host_target))
            .then(a.name.cmp(&b.name))
    });
    lock.runtimes.dedup_by(|a, b| {
        a.project == b.project
            && a.host_target == b.host_target
            && a.name == b.name
            && a.version == b.version
    });
}

/// Resolve one dep's source crates, fmods, and runtime binaries
/// against the registry, appending to the lockfile. Returns the
/// version actually picked for the source crates (highest matching
/// canonical) so the caller can look up the dep's transitive
/// dependencies via the project-meta file. Returns `None` for path/
/// git overrides where no registry version is consulted.
fn resolve_one_dep_artefacts(
    dep: &project::DepSpec,
    want_version: &str,
    root: &Path,
    registry_crates: &[CrateEntry],
    registry_fmods: &[FmodEntry],
    registry_runtimes: &[RuntimeEntry],
    lock: &mut LockFile,
) -> Result<Option<String>> {
    // Path / git overrides — recorded without consulting registry.
    if let Some(path) = &dep.path {
        lock.crates.push(LockedCrate {
            name: dep.name.clone(),
            version: dep.version.clone().unwrap_or_else(|| "path".to_string()),
            hash: String::new(),
            source: format!("path:{}", path.display()),
        });
        return Ok(None);
    }
    if let Some(git) = &dep.git {
        lock.crates.push(LockedCrate {
            name: dep.name.clone(),
            version: dep.version.clone().unwrap_or_else(|| "git".to_string()),
            hash: String::new(),
            source: format!("git:{git}"),
        });
        return Ok(None);
    }

    // Source crates: every published `<dep.name>-*` crate. Every
    // such crate is published at the same version as `<dep.name>`'s
    // `[project].version` (enforced by `publish_workspace_crate`'s
    // version-mismatch check), so the first picked version is the
    // canonical project version for transitive-meta lookup. The
    // assertion below makes that invariant explicit at the read site
    // so a future change to publish's enforcement wouldn't silently
    // miscompute the meta-file path.
    let prefix = format!("{}-", dep.name);
    let mut owned_crate_names: Vec<&str> = registry_crates
        .iter()
        .filter(|c| c.kind == ArtefactKind::Canonical && c.name.starts_with(&prefix))
        .map(|c| c.name.as_str())
        .collect();
    owned_crate_names.sort();
    owned_crate_names.dedup();
    let mut chosen_project_version: Option<String> = None;
    for crate_name in owned_crate_names {
        if let Some(c) = pick_crate(registry_crates, crate_name, want_version) {
            match &chosen_project_version {
                None => chosen_project_version = Some(c.version.clone()),
                Some(prev) if prev != &c.version => {
                    return Err(Error::Config(format!(
                        "project `{}` has desynced crate versions in the registry: \
                         `{}` at {} but earlier crate at {}. Republish from a clean state — \
                         publish enforces `[package].version == [project].version` going forward.",
                        dep.name, crate_name, c.version, prev
                    )));
                }
                _ => {}
            }
            lock.crates.push(crate_entry_to_locked(root, c)?);
        }
    }

    // fmods: highest canonical per (target, name).
    let mut picked: BTreeMap<(String, String), &FmodEntry> = BTreeMap::new();
    for f in registry_fmods {
        if f.project != dep.name || f.kind != ArtefactKind::Canonical {
            continue;
        }
        let key = (f.target.clone(), f.name.clone());
        picked
            .entry(key)
            .and_modify(|prev| {
                if version_gt(&f.version, &prev.version) {
                    *prev = f;
                }
            })
            .or_insert(f);
    }
    for f in picked.values() {
        lock.fmods.push(fmod_entry_to_locked(root, f)?);
    }

    // Runtime binaries: highest canonical per (host_target, name).
    let mut picked_rt: BTreeMap<(String, String), &RuntimeEntry> = BTreeMap::new();
    for r in registry_runtimes {
        if r.project != dep.name || r.kind != ArtefactKind::Canonical {
            continue;
        }
        let key = (r.host_target.clone(), r.name.clone());
        picked_rt
            .entry(key)
            .and_modify(|prev| {
                if version_gt(&r.version, &prev.version) {
                    *prev = r;
                }
            })
            .or_insert(r);
    }
    for r in picked_rt.values() {
        lock.runtimes.push(runtime_entry_to_locked(root, r)?);
    }

    Ok(chosen_project_version)
}

fn runtime_entry_to_locked(root: &Path, r: &RuntimeEntry) -> Result<LockedRuntime> {
    Ok(LockedRuntime {
        project: r.project.clone(),
        name: r.name.clone(),
        host_target: r.host_target.clone(),
        version: r.version.clone(),
        hash: file_sha256_prefixed(&r.path)?,
        source: relative_source(root, &r.path),
    })
}

fn pick_crate<'a>(
    crates: &'a [CrateEntry],
    name: &str,
    want_version: &str,
) -> Option<&'a CrateEntry> {
    let mut best: Option<&CrateEntry> = None;
    for c in crates {
        if c.name != name {
            continue;
        }
        if c.kind != ArtefactKind::Canonical {
            continue;
        }
        if !version_matches(&c.version, want_version) {
            continue;
        }
        best = match best {
            None => Some(c),
            Some(prev) => {
                if version_gt(&c.version, &prev.version) {
                    Some(c)
                } else {
                    Some(prev)
                }
            }
        };
    }
    best
}

/// Cargo-compatible caret matching, delegated to the `semver` crate.
/// `want` is interpreted as a cargo `VersionReq` (depth-sensitive
/// caret semantics: `"1"` is `>=1.0.0, <2.0.0`, `"0.2"` is `>=0.2.0,
/// <0.3.0`, `"0.0.3"` is exact, etc.). Free-form non-semver strings
/// (e.g. the `"path"` / `"git"` placeholders the override path
/// writes into a lockfile entry's `version` field) fall back to
/// exact-string equality so unconventional values still round-trip
/// through the resolver.
fn version_matches(have: &str, want: &str) -> bool {
    match (
        semver::Version::parse(have),
        semver::VersionReq::parse(want),
    ) {
        (Ok(v), Ok(req)) => req.matches(&v),
        _ => have == want,
    }
}

fn version_gt(a: &str, b: &str) -> bool {
    match (semver::Version::parse(a), semver::Version::parse(b)) {
        (Ok(va), Ok(vb)) => va > vb,
        _ => false,
    }
}

fn relative_source(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.display().to_string())
}

fn crate_entry_to_locked(root: &Path, c: &CrateEntry) -> Result<LockedCrate> {
    Ok(LockedCrate {
        name: c.name.clone(),
        version: c.version.clone(),
        hash: file_sha256_prefixed(&c.path)?,
        source: relative_source(root, &c.path),
    })
}

fn fmod_entry_to_locked(root: &Path, f: &FmodEntry) -> Result<LockedFmod> {
    Ok(LockedFmod {
        project: f.project.clone(),
        name: f.name.clone(),
        target: f.target.clone(),
        version: f.version.clone(),
        hash: file_sha256_prefixed(&f.path)?,
        source: relative_source(root, &f.path),
    })
}

// ── Consistency check ─────────────────────────────────────────────────

/// Compare a stored lockfile against the resolution that would be
/// produced today. Returns `Ok(())` when consistent, or a descriptive
/// error listing the first drift.
pub fn check_consistent(project_root: &Path) -> Result<()> {
    let Some(stored) = read(project_root)? else {
        return Err(Error::Config(format!(
            "{} missing — run `fluxor update` to generate it",
            lockfile_path(project_root).display()
        )));
    };
    // Re-resolve with the same feature set that produced the stored
    // lockfile. Feature gating changes the active dep set; matching
    // the recorded set is what makes a `fluxor update --features X`
    // result stay green under subsequent `fluxor ci` runs.
    let computed = resolve(project_root, &stored.active_features)?;
    if stored.active_features != computed.active_features {
        return Err(Error::Config(format!(
            "lockfile features drift: stored {:?} vs computed {:?}",
            stored.active_features, computed.active_features,
        )));
    }

    if stored.crates.len() != computed.crates.len()
        || stored.fmods.len() != computed.fmods.len()
        || stored.runtimes.len() != computed.runtimes.len()
    {
        return Err(Error::Config(format!(
            "lockfile drift: stored has {} crates + {} fmods + {} runtimes, registry would resolve {} crates + {} fmods + {} runtimes",
            stored.crates.len(),
            stored.fmods.len(),
            stored.runtimes.len(),
            computed.crates.len(),
            computed.fmods.len(),
            computed.runtimes.len(),
        )));
    }
    for (s, c) in stored.crates.iter().zip(computed.crates.iter()) {
        if s.name != c.name || s.version != c.version || s.hash != c.hash {
            return Err(Error::Config(format!(
                "lockfile drift on crate {}: stored ({}, {}) vs computed ({}, {})",
                s.name, s.version, s.hash, c.version, c.hash
            )));
        }
    }
    for (s, c) in stored.fmods.iter().zip(computed.fmods.iter()) {
        if s.project != c.project
            || s.name != c.name
            || s.target != c.target
            || s.version != c.version
            || s.hash != c.hash
        {
            return Err(Error::Config(format!(
                "lockfile drift on fmod {}::{}/{}: stored {} vs computed {}",
                s.project, s.target, s.name, s.version, c.version
            )));
        }
    }
    for (s, c) in stored.runtimes.iter().zip(computed.runtimes.iter()) {
        if s.project != c.project
            || s.name != c.name
            || s.host_target != c.host_target
            || s.version != c.version
            || s.hash != c.hash
        {
            return Err(Error::Config(format!(
                "lockfile drift on runtime {}::{}/{}: stored {} vs computed {}",
                s.project, s.host_target, s.name, s.version, c.version
            )));
        }
    }
    Ok(())
}

// ── CLI surface ───────────────────────────────────────────────────────

pub fn cmd_update(project_root: Option<&Path>, features: &[String]) -> Result<()> {
    let pr = project_root
        .map(PathBuf::from)
        .unwrap_or_else(project::root);
    let lock = resolve(&pr, features)?;

    if lock.crates.is_empty() && lock.fmods.is_empty() && lock.runtimes.is_empty() {
        // Empty lockfile is signal, not an error — but we don't write
        // an empty file. Print the situation so the user knows.
        let deps = project::active_dependencies(&pr, features).map_err(Error::Config)?;
        if deps.is_empty() {
            println!("no [dependencies] active under features {features:?}; nothing to lock.");
            return Ok(());
        }
        println!(
            "[dependencies] declares {} active entry/entries but the local registry has no matching canonical artefacts.",
            deps.len()
        );
        println!("Hint: publish upstream projects (`fluxor publish abi`, etc.) before running `fluxor update`.");
        return Ok(());
    }

    let path = write(&pr, &lock)?;
    println!(
        "wrote {} ({} crate(s), {} fmod(s), {} runtime(s))",
        path.display(),
        lock.crates.len(),
        lock.fmods.len(),
        lock.runtimes.len(),
    );
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_caret_basic() {
        assert!(version_matches("1.0.5", "1.0"));
        assert!(version_matches("1.2.0", "1.0"));
        assert!(version_matches("1.2.5", "1.2.3"));
        assert!(!version_matches("2.0.0", "1.0"));
        assert!(!version_matches("0.9.0", "1.0"));
    }

    #[test]
    fn version_matches_zero_major() {
        assert!(version_matches("0.2.5", "0.2.0"));
        assert!(!version_matches("0.3.0", "0.2.0"));
        assert!(!version_matches("0.2.5", "0.2.6"));
    }

    #[test]
    fn version_matches_zero_zero_x_is_exact() {
        // Cargo's caret rule for `^0.0.x` — only the exact version
        // matches, no minor or patch wiggle room.
        assert!(version_matches("0.0.3", "0.0.3"));
        assert!(!version_matches("0.0.4", "0.0.3"));
        assert!(!version_matches("0.0.2", "0.0.3"));
        assert!(!version_matches("0.1.0", "0.0.3"));
    }

    #[test]
    fn version_gt_basic() {
        assert!(version_gt("1.0.5", "1.0.0"));
        assert!(version_gt("1.1.0", "1.0.5"));
        assert!(!version_gt("1.0.0", "1.0.0"));
    }

    #[test]
    fn version_matches_caret_depth_one() {
        // `^1` means "any 1.x.y" — more permissive than `^1.0`.
        assert!(version_matches("1.5.3", "1"));
        assert!(version_matches("1.0.0", "1"));
        assert!(!version_matches("2.0.0", "1"));
    }

    #[test]
    fn version_matches_falls_back_to_exact_for_non_semver() {
        // The override path writes `"path"` / `"git"` into a
        // lockfile entry's `version` field for path/git deps; the
        // resolver round-trips those via exact-string equality.
        assert!(version_matches("path", "path"));
        assert!(!version_matches("path", "git"));
    }
}
