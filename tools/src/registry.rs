//! `fluxor registry` — local-registry inspection and maintenance.
//!
//! Host-side implementation of the
//! `~/.fluxor/registry/{cargo,fmod,index}/` tree that every publish
//! verb writes into.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;

use crate::error::{Error, Result};

// ── Layout ────────────────────────────────────────────────────────────

/// Subdirectories under the registry root. Created on first publish or
/// on first `registry list` invocation; never deleted by the CLI.
const LAYOUT: &[&str] = &["cargo", "fmod", "index"];

/// Resolve the registry root. `$FLUXOR_REGISTRY` overrides the
/// default `$HOME/.fluxor/registry/`. The override path is used as-is
/// — no `.fluxor/registry/` suffix is appended.
pub fn registry_root() -> Result<PathBuf> {
    if let Some(v) = std::env::var_os("FLUXOR_REGISTRY") {
        return Ok(PathBuf::from(v));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| {
        Error::Config(
            "cannot resolve registry root: neither $HOME nor $FLUXOR_REGISTRY is set".into(),
        )
    })?;
    Ok(PathBuf::from(home).join(".fluxor").join("registry"))
}

/// Idempotent: create `{cargo,fmod,index}/` under the registry root.
pub fn ensure_layout(root: &Path) -> Result<()> {
    for sub in LAYOUT {
        fs::create_dir_all(root.join(sub))?;
    }
    Ok(())
}

// ── Artefact model ────────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ArtefactKind {
    /// `<version>.fmod` / `<name>-<version>.crate`. Never GC'd.
    Canonical,
    /// `<version>-local.<sha>.fmod`. Produced by `fluxor publish --local`.
    Local,
    /// `<version>-live.<sha>.fmod`. Produced on-demand in workspace mode.
    Live,
}

#[derive(Debug, Serialize, Clone)]
pub struct FmodEntry {
    pub project: String,
    pub target: String,
    pub name: String,
    pub version: String,
    pub kind: ArtefactKind,
    /// Content hash for Local / Live; `None` for Canonical.
    pub hash: Option<String>,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub mtime_secs: u64,
}

#[derive(Debug, Serialize, Clone)]
pub struct CrateEntry {
    pub name: String,
    pub version: String,
    pub kind: ArtefactKind,
    pub hash: Option<String>,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub mtime_secs: u64,
}

#[derive(Debug, Serialize, Clone)]
pub struct RuntimeEntry {
    pub project: String,
    pub host_target: String,
    pub name: String,
    pub version: String,
    pub kind: ArtefactKind,
    pub hash: Option<String>,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub mtime_secs: u64,
}

/// Strip `-local.<sha>` or `-live.<sha>` from the trailing edge of a
/// version-like string and return `(bare_version, kind, hash)`.
fn split_version_suffix(s: &str) -> (String, ArtefactKind, Option<String>) {
    if let Some(idx) = s.rfind("-local.") {
        return (
            s[..idx].to_string(),
            ArtefactKind::Local,
            Some(s[idx + "-local.".len()..].to_string()),
        );
    }
    if let Some(idx) = s.rfind("-live.") {
        return (
            s[..idx].to_string(),
            ArtefactKind::Live,
            Some(s[idx + "-live.".len()..].to_string()),
        );
    }
    (s.to_string(), ArtefactKind::Canonical, None)
}

/// Split `<name>-<version-suffix>` where name may contain hyphens
/// and the version begins with an ASCII digit.
fn split_crate_stem(stem: &str) -> Option<(String, String)> {
    let bytes = stem.as_bytes();
    for i in 1..bytes.len() {
        if bytes[i - 1] == b'-' && bytes[i].is_ascii_digit() {
            return Some((stem[..i - 1].to_string(), stem[i..].to_string()));
        }
    }
    None
}

fn mtime_secs(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|m| m.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Enumeration ───────────────────────────────────────────────────────

/// Walk `<root>/fmod/<project>/<target>/<name>/*.fmod` and parse each
/// filename into an `FmodEntry`. Unparseable filenames are skipped
/// silently — the registry is allowed to contain non-fmod files
/// (e.g. `.tmp` during a publish).
pub fn walk_fmods(root: &Path) -> Result<Vec<FmodEntry>> {
    let fmod_root = root.join("fmod");
    if !fmod_root.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for project_entry in read_dirs(&fmod_root)? {
        let project = project_entry.file_name().to_string_lossy().into_owned();
        for target_entry in read_dirs(&project_entry.path())? {
            let target = target_entry.file_name().to_string_lossy().into_owned();
            for name_entry in read_dirs(&target_entry.path())? {
                let name = name_entry.file_name().to_string_lossy().into_owned();
                for file_entry in fs::read_dir(name_entry.path())? {
                    let file_entry = file_entry?;
                    let filename = file_entry.file_name().to_string_lossy().into_owned();
                    let Some(stem) = filename.strip_suffix(".fmod") else {
                        continue;
                    };
                    let (version, kind, hash) = split_version_suffix(stem);
                    let meta = file_entry.metadata()?;
                    out.push(FmodEntry {
                        project: project.clone(),
                        target: target.clone(),
                        name: name.clone(),
                        version,
                        kind,
                        hash,
                        path: file_entry.path(),
                        size_bytes: meta.len(),
                        mtime_secs: mtime_secs(&meta),
                    });
                }
            }
        }
    }
    Ok(out)
}

/// Walk `<root>/cargo/*.crate`.
pub fn walk_crates(root: &Path) -> Result<Vec<CrateEntry>> {
    let crate_root = root.join("cargo");
    if !crate_root.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&crate_root)? {
        let entry = entry?;
        let filename = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = filename.strip_suffix(".crate") else {
            continue;
        };
        let Some((name, version_part)) = split_crate_stem(stem) else {
            continue;
        };
        let (version, kind, hash) = split_version_suffix(&version_part);
        let meta = entry.metadata()?;
        out.push(CrateEntry {
            name,
            version,
            kind,
            hash,
            path: entry.path(),
            size_bytes: meta.len(),
            mtime_secs: mtime_secs(&meta),
        });
    }
    Ok(out)
}

/// Walk `<root>/bin/<project>/<host-target>/<binary>/<version>`.
/// Runtime-binary filenames omit an extension (Linux executables are
/// just named files); `<version>[-local.<hash>]` is the whole name.
pub fn walk_runtimes(root: &Path) -> Result<Vec<RuntimeEntry>> {
    let bin_root = root.join("bin");
    if !bin_root.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for project_entry in read_dirs(&bin_root)? {
        let project = project_entry.file_name().to_string_lossy().into_owned();
        for ht_entry in read_dirs(&project_entry.path())? {
            let host_target = ht_entry.file_name().to_string_lossy().into_owned();
            for name_entry in read_dirs(&ht_entry.path())? {
                let name = name_entry.file_name().to_string_lossy().into_owned();
                for file_entry in fs::read_dir(name_entry.path())? {
                    let file_entry = file_entry?;
                    if !file_entry.file_type()?.is_file() {
                        continue;
                    }
                    let filename = file_entry.file_name().to_string_lossy().into_owned();
                    let (version, kind, hash) = split_version_suffix(&filename);
                    let meta = file_entry.metadata()?;
                    out.push(RuntimeEntry {
                        project: project.clone(),
                        host_target: host_target.clone(),
                        name: name.clone(),
                        version,
                        kind,
                        hash,
                        path: file_entry.path(),
                        size_bytes: meta.len(),
                        mtime_secs: mtime_secs(&meta),
                    });
                }
            }
        }
    }
    Ok(out)
}

fn read_dirs(path: &Path) -> Result<Vec<fs::DirEntry>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            out.push(entry);
        }
    }
    Ok(out)
}

// ── GC policy ─────────────────────────────────────────────────────────

/// Per `(project, target, name)` for fmods or `(name)` for crates,
/// keep the newest N `-local`/`-live` artefacts and trim the rest.
const GC_KEEP_PER_GROUP: usize = 3;

/// Don't touch artefacts younger than this — active iteration
/// sessions shouldn't have their just-published outputs deleted out
/// from under them. 24 hours is conservative; the figure can tighten
/// once usage data exists.
const GC_MIN_AGE_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Serialize, Clone)]
struct GcPlanItem {
    path: PathBuf,
    reason: &'static str,
    size_bytes: u64,
    age_secs: u64,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Compute deletions across fmods and crates. Returns the plan; the
/// caller decides whether to execute or print.
fn build_gc_plan(fmods: &[FmodEntry], crates: &[CrateEntry]) -> Vec<GcPlanItem> {
    let now = now_secs();
    let mut plan = Vec::new();

    use std::collections::BTreeMap;

    // fmods grouped by (project, target, name)
    let mut fmod_groups: BTreeMap<(String, String, String), Vec<&FmodEntry>> = BTreeMap::new();
    for e in fmods {
        if e.kind == ArtefactKind::Canonical {
            continue;
        }
        fmod_groups
            .entry((e.project.clone(), e.target.clone(), e.name.clone()))
            .or_default()
            .push(e);
    }
    for (_key, mut group) in fmod_groups {
        group.sort_by(|a, b| b.mtime_secs.cmp(&a.mtime_secs));
        for victim in group.iter().skip(GC_KEEP_PER_GROUP) {
            let age = now.saturating_sub(victim.mtime_secs);
            if age < GC_MIN_AGE_SECS {
                continue;
            }
            plan.push(GcPlanItem {
                path: victim.path.clone(),
                reason: "fmod: beyond keep-newest-N and older than min-age",
                size_bytes: victim.size_bytes,
                age_secs: age,
            });
        }
    }

    // crates grouped by name
    let mut crate_groups: BTreeMap<String, Vec<&CrateEntry>> = BTreeMap::new();
    for e in crates {
        if e.kind == ArtefactKind::Canonical {
            continue;
        }
        crate_groups.entry(e.name.clone()).or_default().push(e);
    }
    for (_name, mut group) in crate_groups {
        group.sort_by(|a, b| b.mtime_secs.cmp(&a.mtime_secs));
        for victim in group.iter().skip(GC_KEEP_PER_GROUP) {
            let age = now.saturating_sub(victim.mtime_secs);
            if age < GC_MIN_AGE_SECS {
                continue;
            }
            plan.push(GcPlanItem {
                path: victim.path.clone(),
                reason: "crate: beyond keep-newest-N and older than min-age",
                size_bytes: victim.size_bytes,
                age_secs: age,
            });
        }
    }

    plan
}

// ── CLI surface ───────────────────────────────────────────────────────

pub fn cmd_registry_list(json: bool) -> Result<()> {
    let root = registry_root()?;
    ensure_layout(&root)?;
    let fmods = walk_fmods(&root)?;
    let crates = walk_crates(&root)?;
    let runtimes = walk_runtimes(&root)?;

    if json {
        #[derive(Serialize)]
        struct ListOutput<'a> {
            root: &'a Path,
            crates: &'a [CrateEntry],
            fmods: &'a [FmodEntry],
            runtimes: &'a [RuntimeEntry],
        }
        let out = ListOutput {
            root: &root,
            crates: &crates,
            fmods: &fmods,
            runtimes: &runtimes,
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    println!("registry root: {}", root.display());
    println!();

    if crates.is_empty() {
        println!("crates: (none)");
    } else {
        println!("crates ({}):", crates.len());
        let mut sorted = crates.clone();
        sorted.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
        for c in &sorted {
            let kind_tag = match c.kind {
                ArtefactKind::Canonical => "",
                ArtefactKind::Local => "  [local]",
                ArtefactKind::Live => "  [live]",
            };
            println!(
                "  {}-{}{}  ({} bytes)",
                c.name, c.version, kind_tag, c.size_bytes
            );
        }
    }
    println!();

    if fmods.is_empty() {
        println!("fmods: (none)");
    } else {
        println!("fmods ({}):", fmods.len());
        let mut sorted = fmods.clone();
        sorted.sort_by(|a, b| {
            a.project
                .cmp(&b.project)
                .then(a.target.cmp(&b.target))
                .then(a.name.cmp(&b.name))
                .then(a.version.cmp(&b.version))
        });
        let mut last_proj: Option<&str> = None;
        let mut last_target: Option<&str> = None;
        for f in &sorted {
            if last_proj != Some(f.project.as_str()) {
                println!("  {}", f.project);
                last_proj = Some(f.project.as_str());
                last_target = None;
            }
            if last_target != Some(f.target.as_str()) {
                println!("    {}", f.target);
                last_target = Some(f.target.as_str());
            }
            let kind_tag = match f.kind {
                ArtefactKind::Canonical => "",
                ArtefactKind::Local => "  [local]",
                ArtefactKind::Live => "  [live]",
            };
            println!(
                "      {}/{}{}  ({} bytes)",
                f.name, f.version, kind_tag, f.size_bytes
            );
        }
    }
    println!();

    if runtimes.is_empty() {
        println!("runtimes: (none)");
    } else {
        println!("runtimes ({}):", runtimes.len());
        let mut sorted = runtimes.clone();
        sorted.sort_by(|a, b| {
            a.project
                .cmp(&b.project)
                .then(a.host_target.cmp(&b.host_target))
                .then(a.name.cmp(&b.name))
                .then(a.version.cmp(&b.version))
        });
        let mut last_proj: Option<&str> = None;
        let mut last_target: Option<&str> = None;
        for r in &sorted {
            if last_proj != Some(r.project.as_str()) {
                println!("  {}", r.project);
                last_proj = Some(r.project.as_str());
                last_target = None;
            }
            if last_target != Some(r.host_target.as_str()) {
                println!("    {}", r.host_target);
                last_target = Some(r.host_target.as_str());
            }
            let kind_tag = match r.kind {
                ArtefactKind::Canonical => "",
                ArtefactKind::Local => "  [local]",
                ArtefactKind::Live => "  [live]",
            };
            println!(
                "      {}/{}{}  ({} bytes)",
                r.name, r.version, kind_tag, r.size_bytes
            );
        }
    }

    Ok(())
}

pub fn cmd_registry_gc(dry_run: bool) -> Result<()> {
    let root = registry_root()?;
    ensure_layout(&root)?;
    let fmods = walk_fmods(&root)?;
    let crates = walk_crates(&root)?;
    let plan = build_gc_plan(&fmods, &crates);

    println!("registry root: {}", root.display());
    println!(
        "policy: keep newest {} per group; min age {} hours",
        GC_KEEP_PER_GROUP,
        GC_MIN_AGE_SECS / 3600
    );
    println!();

    if plan.is_empty() {
        println!("nothing to collect.");
        return Ok(());
    }

    let total_bytes: u64 = plan.iter().map(|p| p.size_bytes).sum();
    println!(
        "{} {} ({} bytes total):",
        if dry_run { "would remove" } else { "removing" },
        plan.len(),
        total_bytes
    );
    for item in &plan {
        println!(
            "  {}  ({} bytes, {} h old)",
            item.path.display(),
            item.size_bytes,
            item.age_secs / 3600
        );
    }

    if dry_run {
        println!();
        println!("dry-run: no files were deleted. Re-run without --dry-run to apply.");
        return Ok(());
    }

    let mut deleted = 0u64;
    let mut errors: Vec<(PathBuf, io::Error)> = Vec::new();
    for item in &plan {
        match fs::remove_file(&item.path) {
            Ok(()) => deleted += 1,
            Err(e) => errors.push((item.path.clone(), e)),
        }
    }
    println!();
    println!("removed {deleted} files.");
    if !errors.is_empty() {
        eprintln!("warning: {} files could not be removed:", errors.len());
        for (path, e) in &errors {
            eprintln!("  {}: {}", path.display(), e);
        }
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_version_suffix_canonical() {
        let (v, k, h) = split_version_suffix("1.2.0");
        assert_eq!(v, "1.2.0");
        assert_eq!(k, ArtefactKind::Canonical);
        assert!(h.is_none());
    }

    #[test]
    fn split_version_suffix_local() {
        let (v, k, h) = split_version_suffix("1.2.0-local.abc123");
        assert_eq!(v, "1.2.0");
        assert_eq!(k, ArtefactKind::Local);
        assert_eq!(h.as_deref(), Some("abc123"));
    }

    #[test]
    fn split_version_suffix_live() {
        let (v, k, h) = split_version_suffix("0.0.0-live.deadbeef");
        assert_eq!(v, "0.0.0");
        assert_eq!(k, ArtefactKind::Live);
        assert_eq!(h.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn split_crate_stem_simple_name() {
        let (n, v) = split_crate_stem("fluxor-1.0.0").unwrap();
        assert_eq!(n, "fluxor");
        assert_eq!(v, "1.0.0");
    }

    #[test]
    fn split_crate_stem_hyphenated_name() {
        let (n, v) = split_crate_stem("fluxor-sdk-macros-1.0.0").unwrap();
        assert_eq!(n, "fluxor-sdk-macros");
        assert_eq!(v, "1.0.0");
    }

    #[test]
    fn split_crate_stem_hyphenated_name_with_local_suffix() {
        let (n, v) = split_crate_stem("fluxor-sdk-1.0.0-local.abc").unwrap();
        assert_eq!(n, "fluxor-sdk");
        assert_eq!(v, "1.0.0-local.abc");
    }

    #[test]
    fn split_crate_stem_rejects_no_version() {
        assert!(split_crate_stem("no-version-here").is_none());
    }
}
