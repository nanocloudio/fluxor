//! Sync — the one-path materialiser over the OCI store, behind
//! `fluxor sync` / `fluxor workspace publish`. Lib-only (the store
//! engine layering): the bin reaches it via
//! `fluxor_tools::store_sync`.
//!
//! One path: resolve (lockfile, `:latest` write-through for workspace
//! members) → verify blob digest → verify epoch → materialise — with
//! the lockfile written ONCE, after every artifact materialises
//! successfully, under the advisory lock held for the whole run. A
//! failed tree step must never leave a committed pin describing a tree
//! that doesn't exist.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::oci_store::{
    OciStore, ANN_INPUT_DIGEST, ANN_REF_NAME, MT_FLUXOR_RUNTIME, MT_FLUXOR_SOURCE,
};
use crate::store_resolve::{
    read_pinned_blob, read_pinned_manifest, read_store_lock, resolve_dependency, sort_entries,
    write_store_lock, Artifact,
};

/// Stamp file inside an extracted source tree: contains the artifact
/// digest the tree was materialised from. Matching stamp = skip.
const SYNC_STAMP: &str = ".fluxor-sync-stamp";

/// What one `sync_project` run did (or, dry-run, would do).
#[derive(Debug, Default)]
pub struct SyncReport {
    /// The final pin set (written to the lockfile unless dry-run).
    pub entries: Vec<Artifact>,
    /// One line per materialised (or would-be-materialised) artifact.
    pub materialized: Vec<String>,
    /// Per-artifact staleness advisories (already printed; never block).
    pub warnings: Vec<String>,
    /// False on dry-run.
    pub lockfile_written: bool,
}

/// Workspace members as project-name → checkout-path. A member whose
/// `fluxor.toml` is unreadable contributes nothing (a broken dev-local
/// convenience must not fail an otherwise valid build — same policy as
/// `workspace::member_roots`).
fn member_projects() -> Result<BTreeMap<String, PathBuf>> {
    let mut out = BTreeMap::new();
    let Some(ws) = crate::workspace::load_workspace()? else {
        return Ok(out);
    };
    for member in &ws.workspace.members {
        if let Ok(Some(identity)) = crate::project::project_identity(member) {
            out.insert(identity.name, member.clone());
        }
    }
    Ok(out)
}

/// `wave/src/wave-common:0.0.3` → `wave/src/wave-common:latest`.
fn latest_form(reference: &str) -> String {
    match reference.rsplit_once(':') {
        Some((body, _ver)) => format!("{body}:latest"),
        None => format!("{reference}:latest"),
    }
}

/// Prefer recording the canonical (versioned) tag over `:latest` in
/// the lockfile: find another index descriptor holding the same digest
/// under the same tag body. Falls back to the `:latest` ref itself.
fn canonical_ref_for(store: &OciStore, digest: &str, latest_ref: &str) -> String {
    let body = latest_ref.rsplit_once(':').map(|(b, _)| b).unwrap_or("");
    if let Ok(index) = store.read_index() {
        for d in &index.manifests {
            if d.digest != digest {
                continue;
            }
            if let Some(r) = d.annotations.get(ANN_REF_NAME) {
                if !r.ends_with(":latest") && r.rsplit_once(':').map(|(b, _)| b) == Some(body) {
                    return r.clone();
                }
            }
        }
    }
    latest_ref.to_string()
}

/// The whole sync: resolve → epoch check → staleness advisory →
/// materialise → write the lockfile once. `dry_run` performs the
/// resolution and checks but touches neither the tree nor the
/// lockfile.
pub fn sync_project(project_root: &Path, dry_run: bool) -> Result<SyncReport> {
    let store = OciStore::open(crate::oci_store::store_root()?)?;
    let members = member_projects()?;
    // Advisory lock held for the WHOLE run (resolve → materialise →
    // write) so a concurrent update/pin can neither interleave nor be
    // clobbered.
    let _guard = crate::lockfile::lock_lockfile(project_root)?;

    // (b) Start from the lockfile; write-through `:latest` for
    // workspace members, keep everyone else's pins verbatim.
    let existing = read_store_lock(project_root)?
        .map(|l| l.artifacts)
        .unwrap_or_default();
    let mut entries: Vec<Artifact> = Vec::new();
    for e in &existing {
        if let Some(member_path) = members.get(&e.project) {
            let latest = latest_form(&e.reference);
            let desc = store.resolve(&latest).map_err(|_| {
                Error::Config(format!(
                    "'{latest}' not published — run `fluxor publish` in {}",
                    member_path.display()
                ))
            })?;
            let mut ne = e.clone();
            ne.reference = canonical_ref_for(&store, &desc.digest, &latest);
            ne.digest = desc.digest;
            entries.push(ne);
        } else {
            entries.push(e.clone());
        }
    }
    // Missing-entry addition (the declared pinned-means-pinned
    // exception, made safe by the epoch check below): a declared
    // dependency with no entries yet resolves latest and is added.
    let deps = crate::project::dependencies(project_root).map_err(Error::Config)?;
    let pinned_projects: BTreeSet<String> = entries.iter().map(|e| e.project.clone()).collect();
    for dep in &deps {
        if !pinned_projects.contains(&dep.name) {
            entries.extend(resolve_dependency(&store, &dep.name, None)?);
        }
    }
    sort_entries(&mut entries);

    // (c) Epoch rules over the whole resolved set.
    crate::store_resolve::check_epoch(&entries, &store, &members)?;

    // (d) Per-artifact staleness advisory for live members — warn,
    // never block.
    let warnings = staleness_advisories(&store, &entries, &members)?;
    for w in &warnings {
        eprintln!("{w}");
    }

    // (e) Materialise every artifact; (f) only then write the
    // lockfile, still under the guard taken at entry.
    let mut report = SyncReport {
        entries: entries.clone(),
        warnings,
        ..SyncReport::default()
    };
    for e in &entries {
        if dry_run {
            report.materialized.push(format!(
                "would materialise {} '{}' ({})",
                e.kind, e.name, e.digest
            ));
        } else {
            report
                .materialized
                .push(materialize_artifact(&store, project_root, e)?);
        }
    }
    if !dry_run {
        write_store_lock(project_root, &entries)?;
        report.lockfile_written = true;
    }
    Ok(report)
}

/// Compare each live member's current inputs against its published
/// artifacts. Exact on both sides; wording claims only what was
/// measured. Modules and sources compare input digests; runtimes
/// compare the published binary against the member's build output,
/// which is the same question asked directly.
fn staleness_advisories(
    store: &OciStore,
    entries: &[Artifact],
    members: &BTreeMap<String, PathBuf>,
) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    let mut member_digests: BTreeMap<&str, BTreeMap<String, String>> = BTreeMap::new();
    for e in entries {
        let Some(member_path) = members.get(&e.project) else {
            continue;
        };
        if e.kind == "runtime" {
            if runtime_differs_from_build(store, e, member_path)? {
                warnings.push(format!(
                    "warning: runtime '{}' differs from the build on disk ({}) \
                     — run `fluxor publish`",
                    e.name, e.project
                ));
            }
            continue;
        }
        if e.kind != "module" && e.kind != "source" {
            continue;
        }
        let annotations = read_pinned_manifest(store, e)?.annotations;
        let current = match member_digests.entry(e.project.as_str()) {
            std::collections::btree_map::Entry::Occupied(o) => o.into_mut(),
            std::collections::btree_map::Entry::Vacant(v) => {
                v.insert(crate::store_publish::project_input_digests(member_path)?)
            }
        };
        if let (Some(published), Some(now)) =
            (annotations.get(ANN_INPUT_DIGEST), current.get(&e.name))
        {
            if published != now {
                warnings.push(format!(
                    "warning: {} '{}' inputs changed since publish ({})",
                    e.kind, e.name, e.project
                ));
            }
        }
    }
    Ok(warnings)
}

/// True when the member has a built binary for this runtime and its
/// content differs from the published one. Absent build output is not
/// a difference — after `make clean` there is nothing to compare.
fn runtime_differs_from_build(store: &OciStore, e: &Artifact, member: &Path) -> Result<bool> {
    let (Some(triple), Some(published)) = (e.target.as_deref(), runtime_layer_digest(store, e)?)
    else {
        return Ok(false);
    };
    let bin = member
        .join("target")
        .join(triple)
        .join("release")
        .join(&e.name);
    let Ok(bytes) = fs::read(&bin) else {
        return Ok(false);
    };
    Ok(crate::oci_store::sha256_hex_prefixed(&bytes) != published)
}

fn runtime_layer_digest(store: &OciStore, e: &Artifact) -> Result<Option<String>> {
    Ok(read_pinned_manifest(store, e)?
        .layers
        .into_iter()
        .find(|l| l.media_type == MT_FLUXOR_RUNTIME)
        .map(|l| l.digest))
}

// ── Materialisation ───────────────────────────────────────────────────

fn missing_layer_err(e: &Artifact) -> Error {
    Error::Config(format!(
        "artifact '{}' ({}) has no payload layer — corrupt manifest",
        e.name, e.digest
    ))
}

/// Materialise one lockfile entry into the project tree. Every write
/// verifies blob bytes against their digest (via `read_blob`).
fn materialize_artifact(store: &OciStore, project_root: &Path, e: &Artifact) -> Result<String> {
    match e.kind.as_str() {
        "module" => {
            let manifest = read_pinned_manifest(store, e)?;
            let layer = manifest
                .layers
                .iter()
                .find(|l| l.media_type == crate::oci_store::MT_FLUXOR_MODULE)
                .ok_or_else(|| missing_layer_err(e))?;
            let bytes = read_pinned_blob(store, &e.name, &layer.digest)?;
            let target = e
                .target
                .as_deref()
                .ok_or_else(|| Error::Config(format!("module '{}' pin has no target", e.name)))?;
            let dest = project_root
                .join("target/fluxor")
                .join(target)
                .join("modules")
                .join(format!("{}.fmod", e.name));
            if !file_matches(&dest, &bytes) {
                write_file_atomic(&dest, &bytes, false)?;
            }
            Ok(format!("module {} → {}", e.name, dest.display()))
        }
        "source" => {
            let manifest = read_pinned_manifest(store, e)?;
            let layer = manifest
                .layers
                .iter()
                .find(|l| l.media_type == MT_FLUXOR_SOURCE)
                .ok_or_else(|| missing_layer_err(e))?;
            let dest = project_root.join("target/fluxor").join(&e.name);
            let stamp = dest.join(SYNC_STAMP);
            if fs::read_to_string(&stamp).is_ok_and(|s| s.trim() == e.digest) {
                return Ok(format!("source {} up to date ({})", e.name, dest.display()));
            }
            let tar = read_pinned_blob(store, &e.name, &layer.digest)?;
            extract_tree_atomic(&tar, &dest, &e.digest)?;
            Ok(format!("source {} → {}", e.name, dest.display()))
        }
        "runtime" => {
            let manifest = read_pinned_manifest(store, e)?;
            let layer = manifest
                .layers
                .iter()
                .find(|l| l.media_type == MT_FLUXOR_RUNTIME)
                .ok_or_else(|| missing_layer_err(e))?;
            let bytes = read_pinned_blob(store, &e.name, &layer.digest)?;
            let triple = e.target.as_deref().ok_or_else(|| {
                Error::Config(format!("runtime '{}' pin has no host triple", e.name))
            })?;
            let dest = project_root
                .join("target")
                .join(triple)
                .join("release")
                .join(&e.name);
            if !file_matches(&dest, &bytes) {
                write_file_atomic(&dest, &bytes, true)?;
            }
            Ok(format!("runtime {} → {}", e.name, dest.display()))
        }
        // Bundles are install-time artifacts (`fluxor install`); a pin
        // keeps them alive for GC but sync has no tree location for
        // them.
        _ => Ok(format!(
            "{} '{}' pinned (no tree materialisation)",
            e.kind, e.name
        )),
    }
}

fn file_matches(path: &Path, bytes: &[u8]) -> bool {
    fs::read(path)
        .map(|on_disk| on_disk == bytes)
        .unwrap_or(false)
}

fn write_file_atomic(path: &Path, bytes: &[u8], executable: bool) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| Error::Config(format!("no parent dir for {}", path.display())))?;
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".tmp.{}.{}",
        std::process::id(),
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    if executable {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
    }
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err.into());
    }
    Ok(())
}

/// Extract a canonical (plain ustar, uncompressed) tar into `dest`,
/// via temp dir + atomic swap, writing the sync stamp last inside the
/// temp tree so a completed `dest` always carries its digest.
fn extract_tree_atomic(tar: &[u8], dest: &Path, digest: &str) -> Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| Error::Config(format!("no parent dir for {}", dest.display())))?;
    fs::create_dir_all(parent)?;
    let base = dest.file_name().unwrap_or_default().to_string_lossy();
    let tmp = parent.join(format!(".sync-tmp-{}-{}", base, std::process::id()));
    let old = parent.join(format!(".sync-old-{}-{}", base, std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let _ = fs::remove_dir_all(&old);
    fs::create_dir_all(&tmp)?;
    let extracted = extract_ustar(tar, &tmp);
    if let Err(err) = extracted {
        let _ = fs::remove_dir_all(&tmp);
        return Err(err);
    }
    fs::write(tmp.join(SYNC_STAMP), format!("{digest}\n"))?;
    if dest.exists() {
        fs::rename(dest, &old)?;
    }
    if let Err(err) = fs::rename(&tmp, dest) {
        // Best-effort rollback of the displaced tree.
        let _ = fs::rename(&old, dest);
        let _ = fs::remove_dir_all(&tmp);
        return Err(err.into());
    }
    let _ = fs::remove_dir_all(&old);
    Ok(())
}

/// Minimal ustar reader matching `canonical_tar`'s writer: regular
/// files only, clean relative paths, uncompressed. Defensive on the
/// same axes as the legacy `tar -x` flags: absolute paths and `..`
/// traversal are rejected, archive mode/owner bits are ignored.
fn extract_ustar(tar: &[u8], dest: &Path) -> Result<()> {
    let mut off = 0usize;
    while off + 512 <= tar.len() {
        let hdr = &tar[off..off + 512];
        if hdr.iter().all(|&b| b == 0) {
            break; // terminator
        }
        let name = header_str(&hdr[0..100]);
        let prefix = header_str(&hdr[345..500]);
        let size = octal_field(&hdr[124..136])?;
        let typeflag = hdr[156];
        off += 512;
        let data = tar
            .get(off..off + size)
            .ok_or_else(|| Error::Config("truncated tar archive".into()))?;
        off += size + (512 - size % 512) % 512;
        if typeflag != b'0' && typeflag != 0 {
            return Err(Error::Config(format!(
                "tar entry '{name}' is not a regular file (type {typeflag:#x}) — \
                 canonical source tars carry regular files only"
            )));
        }
        let path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        if path.starts_with('/') || path.split('/').any(|c| c == ".." || c.is_empty()) {
            return Err(Error::Config(format!(
                "tar entry has unsafe path {path:?} — refusing"
            )));
        }
        let out = dest.join(&path);
        if let Some(dir) = out.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(&out, data)?;
    }
    Ok(())
}

fn header_str(field: &[u8]) -> &str {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    std::str::from_utf8(&field[..end]).unwrap_or("")
}

fn octal_field(field: &[u8]) -> Result<usize> {
    let s = header_str(field);
    let s = s.trim_matches(|c: char| c == ' ' || c == '\0');
    if s.is_empty() {
        return Ok(0);
    }
    usize::from_str_radix(s, 8).map_err(|e| Error::Config(format!("bad tar size field {s:?}: {e}")))
}

// ── ensure_synced ─────────────────────────────────────────────────────

/// Replay the lockfile digests only — never re-resolving a tag. The
/// pre-flight other commands call before consuming the synced tree.
pub fn ensure_synced(project_root: &Path) -> Result<Vec<String>> {
    let entries = read_store_lock(project_root)?
        .map(|l| l.artifacts)
        .unwrap_or_default();
    let deps = crate::project::dependencies(project_root).map_err(Error::Config)?;
    for dep in &deps {
        if !entries.iter().any(|e| e.project == dep.name) {
            return Err(Error::Config(format!(
                "dependency '{}' has no lockfile entry — run `fluxor sync`",
                dep.name
            )));
        }
    }
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let store = OciStore::open(crate::oci_store::store_root()?)?;
    let mut done = Vec::new();
    for e in &entries {
        done.push(materialize_artifact(&store, project_root, e)?);
    }
    Ok(done)
}

// ── workspace publish ─────────────────────────────────────────────────

/// One member's outcome in a `workspace publish` run.
#[derive(Debug)]
pub enum MemberOutcome {
    /// Published artifacts all match current input digests.
    UpToDate,
    /// Dirty artifacts found; dry-run reported without acting.
    WouldPublish(Vec<String>),
    /// Built (when it owns modules) and published.
    Published(Vec<String>),
}

/// `fluxor workspace publish` (Decision 2): for every workspace member
/// whose input digests differ from its published artifacts, run that
/// member's module build and publish it — topologically ordered by the
/// members' checkout-side `fluxor.toml` dependency declarations. Abort
/// at the first member failure; the already-published topological
/// prefix stands.
///
/// Members are never cargo-built here: runtimes/CLI binaries are
/// published as found (consistent with `publish_project_to_store`'s
/// skip-if-unbuilt behaviour).
pub fn workspace_publish(dry_run: bool) -> Result<Vec<(String, MemberOutcome)>> {
    let Some(ws) = crate::workspace::load_workspace()? else {
        return Err(Error::Config(
            "no workspace (~/.fluxor/workspace.toml) — `workspace publish` needs live members"
                .into(),
        ));
    };
    let mut members: Vec<(String, PathBuf)> = Vec::new();
    for path in &ws.workspace.members {
        // A member without a parseable `[project]` table is a
        // pre-adoption checkout (listed in the workspace ahead of its
        // fluxor.toml). It cannot be named, ordered, or published, so
        // it is skipped with an advisory; the run continues. A member
        // that parses but later fails to build/publish still aborts.
        let identity = match crate::project::project_identity(path) {
            Ok(Some(identity)) => identity,
            Ok(None) | Err(_) => {
                println!(
                    "workspace publish: {} — no fluxor.toml [project] — \
                     pre-adoption member, skipped",
                    path.display()
                );
                continue;
            }
        };
        members.push((identity.name, path.clone()));
    }
    let order = topo_order(&members)?;

    let store = OciStore::open(crate::oci_store::store_root()?)?;
    let current_root = crate::project::root();
    let mut outcomes = Vec::new();
    for (name, path) in order {
        let current = crate::store_publish::project_input_digests(&path)?;
        let published = published_input_digests(&store, &name)?;
        let dirty: Vec<String> = match &published {
            // No published index yet: everything is dirty (first-ever
            // publish).
            None => current.keys().cloned().collect(),
            Some(map) => current
                .iter()
                .filter(|(k, v)| map.get(*k) != Some(v))
                .map(|(k, _)| k.clone())
                .collect(),
        };
        if dirty.is_empty() && published.is_some() {
            outcomes.push((name, MemberOutcome::UpToDate));
            continue;
        }
        if dry_run {
            outcomes.push((name, MemberOutcome::WouldPublish(dirty)));
            continue;
        }
        // Build the member's modules when it owns any. Errors abort
        // the run — the published topological prefix stands.
        if !crate::modules_build::list(&path)?.is_empty() {
            build_member(&name, &path, &current_root)?;
        }
        let tags = crate::store_publish::publish_project_to_store(&path, &[], false)?;
        outcomes.push((name, MemberOutcome::Published(tags)));
    }
    Ok(outcomes)
}

/// Published per-artifact input digests from `<project>/meta:latest`;
/// `None` when the project has never been published.
fn published_input_digests(
    store: &OciStore,
    project: &str,
) -> Result<Option<BTreeMap<String, String>>> {
    let Ok(desc) = store.resolve(&format!("{project}/meta:latest")) else {
        return Ok(None);
    };
    let bytes = store.read_blob(&desc.digest)?;
    let idx: crate::oci_store::ImageIndex = serde_json::from_slice(&bytes)
        .map_err(|e| Error::Config(format!("corrupt project index {}: {e}", desc.digest)))?;
    let mut out = BTreeMap::new();
    for child in &idx.manifests {
        let Some(a) = crate::store_resolve::artifact_from_descriptor(child)? else {
            continue;
        };
        if let Some(d) = child.annotations.get(ANN_INPUT_DIGEST) {
            out.insert(a.name, d.clone());
        }
    }
    Ok(Some(out))
}

// ── ci live-staleness gate ────────────────────────────────────────────

/// The `fluxor ci` live-staleness check — the plan's one declared
/// exception to warn-don't-act: a green gate against a known-stale
/// upstream is a clean build wearing a misleading name.
///
/// For every workspace-member project among this project's declared
/// dependencies — plus the project itself when it is a member — compare
/// the member checkout's current input digests against the published
/// `io.fluxor.input-digest` annotations in `<member>/meta:latest`.
///
/// Returns `Ok(None)` when no workspace file exists (the phase skips
/// cleanly), otherwise `Ok(Some(failures))` — one line per stale or
/// never-published member, each naming `fluxor workspace publish`.
///
/// A published index with no artifact children (a zero-artifact
/// project) is vacuously fresh: nothing is published, so nothing can
/// be stale.
pub fn live_staleness_failures(project_root: &Path) -> Result<Option<Vec<String>>> {
    if crate::workspace::load_workspace()?.is_none() {
        return Ok(None);
    }
    let members = member_projects()?;
    let mut relevant: Vec<(String, PathBuf)> = Vec::new();
    let deps = crate::project::dependencies(project_root).map_err(Error::Config)?;
    for dep in &deps {
        if let Some(path) = members.get(&dep.name) {
            relevant.push((dep.name.clone(), path.clone()));
        }
    }
    if let Ok(Some(identity)) = crate::project::project_identity(project_root) {
        if let Some(path) = members.get(&identity.name) {
            if !relevant.iter().any(|(n, _)| n == &identity.name) {
                relevant.push((identity.name, path.clone()));
            }
        }
    }
    if relevant.is_empty() {
        return Ok(Some(Vec::new()));
    }
    let store = OciStore::open(crate::oci_store::store_root()?)?;
    let mut failures = Vec::new();
    for (name, path) in relevant {
        let current = crate::store_publish::project_input_digests(&path)?;
        match published_input_digests(&store, &name)? {
            None => failures.push(format!(
                "member '{name}' has no published index — run `fluxor workspace publish`"
            )),
            Some(published) => {
                let stale: Vec<&str> = current
                    .iter()
                    .filter(|(k, v)| published.get(*k) != Some(v))
                    .map(|(k, _)| k.as_str())
                    .collect();
                if !stale.is_empty() {
                    failures.push(format!(
                        "member '{name}' inputs changed since publish ({}) — \
                         run `fluxor workspace publish`",
                        stale.join(", ")
                    ));
                }
            }
        }
    }
    Ok(Some(failures))
}

/// Run one member's module build: the current process's own project
/// goes through the lib fns; other checkouts spawn the installed
/// `fluxor` CLI so their build resolves against their own tree.
fn build_member(name: &str, path: &Path, current_root: &Path) -> Result<()> {
    let same = path
        .canonicalize()
        .ok()
        .zip(current_root.canonicalize().ok())
        .is_some_and(|(a, b)| a == b);
    if same {
        let report = crate::modules_build::run(&crate::modules_build::BuildOpts {
            project_root: path.to_path_buf(),
            selector: crate::modules_build::TargetSelector::All,
            out_root: path.join("target/fluxor"),
            strict: false,
            verbose: false,
        })?;
        if !report.ok() {
            return Err(Error::Config(format!(
                "workspace publish: module build failed in member '{name}'"
            )));
        }
        return Ok(());
    }
    let status = std::process::Command::new("fluxor")
        .args(["modules", "build", "--all"])
        .current_dir(path)
        .status()
        .map_err(|e| Error::Config(format!("spawn fluxor in {}: {e}", path.display())))?;
    if !status.success() {
        return Err(Error::Config(format!(
            "workspace publish: `fluxor modules build --all` failed in member '{name}' \
             ({})",
            path.display()
        )));
    }
    Ok(())
}

/// Topological order over the member set by each member's
/// checkout-side `fluxor.toml` `[dependencies]` (dependencies first).
fn topo_order(members: &[(String, PathBuf)]) -> Result<Vec<(String, PathBuf)>> {
    let names: BTreeSet<&str> = members.iter().map(|(n, _)| n.as_str()).collect();
    let mut deps_of: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for (name, path) in members {
        let deps = crate::project::dependencies(path).map_err(Error::Config)?;
        deps_of.insert(
            name,
            deps.into_iter()
                .map(|d| d.name)
                .filter(|d| names.contains(d.as_str()))
                .collect(),
        );
    }
    let mut ordered: Vec<(String, PathBuf)> = Vec::new();
    let mut placed: BTreeSet<String> = BTreeSet::new();
    let mut remaining: Vec<&(String, PathBuf)> = members.iter().collect();
    while !remaining.is_empty() {
        let before = remaining.len();
        remaining.retain(|(name, path)| {
            let ready = deps_of[name.as_str()].iter().all(|d| placed.contains(d));
            if ready {
                ordered.push((name.clone(), path.clone()));
                placed.insert(name.clone());
            }
            !ready
        });
        if remaining.len() == before {
            let cycle: Vec<&str> = remaining.iter().map(|(n, _)| n.as_str()).collect();
            return Err(Error::Config(format!(
                "dependency cycle among workspace members: {}",
                cycle.join(", ")
            )));
        }
    }
    Ok(ordered)
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci_store::ArtifactMeta;

    /// Serialise every FLUXOR_STORE / FLUXOR_WORKSPACE-touching test
    /// (env vars are process-global; cargo runs tests threaded).
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::oci_store::test_env_lock()
    }

    struct EnvScope {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }
    impl EnvScope {
        fn set(pairs: &[(&'static str, &Path)]) -> EnvScope {
            let saved = pairs
                .iter()
                .map(|(k, v)| {
                    let old = std::env::var_os(k);
                    std::env::set_var(k, v);
                    (*k, old)
                })
                .collect();
            EnvScope { saved }
        }
    }
    impl Drop for EnvScope {
        fn drop(&mut self) {
            for (k, old) in self.saved.drain(..) {
                match old {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    fn fake_project(root: &Path, name: &str, deps: &[&str]) {
        std::fs::create_dir_all(root).unwrap();
        let mut toml = format!("[project]\nname = \"{name}\"\nversion = \"0.0.1\"\n");
        if !deps.is_empty() {
            toml.push_str("\n[dependencies]\n");
            for d in deps {
                toml.push_str(&format!("{d} = \"0.0.1\"\n"));
            }
        }
        std::fs::write(root.join("fluxor.toml"), toml).unwrap();
    }

    /// (1) Publish a fake producer's source artifact, then sync a
    /// consumer that depends on it: lockfile written with the pin,
    /// tar extracted, stamp correct.
    #[test]
    fn sync_pins_extracts_and_stamps() {
        let _env = env_lock();
        let scratch = tempfile::tempdir().unwrap();
        let producer = scratch.path().join("producer");
        fake_project(&producer, "producer", &[]);
        std::fs::create_dir_all(producer.join("modules/common")).unwrap();
        std::fs::write(
            producer.join("modules/common/core.rs"),
            "pub fn forty_two() -> u32 { 42 }\n",
        )
        .unwrap();
        let consumer = scratch.path().join("consumer");
        fake_project(&consumer, "consumer", &["producer"]);

        let _scope = EnvScope::set(&[
            ("FLUXOR_STORE", &scratch.path().join("store")),
            // No workspace file: pinned-only mode, no live members.
            (
                "FLUXOR_WORKSPACE",
                &scratch.path().join("no-workspace.toml"),
            ),
        ]);
        crate::store_publish::publish_project_to_store(&producer, &["source"], false).unwrap();

        let report = sync_project(&consumer, false).unwrap();
        assert!(report.lockfile_written);
        assert_eq!(report.entries.len(), 1);
        let entry = &report.entries[0];
        assert_eq!(entry.kind, "source");
        assert_eq!(entry.name, "producer-common");
        assert_eq!(entry.project, "producer");
        assert!(entry.digest.starts_with("sha256:"));

        // Lockfile carries the pin.
        let lock = read_store_lock(&consumer).unwrap().unwrap();
        assert_eq!(lock.artifacts, report.entries);

        // Tree extracted byte-for-byte, stamp = artifact digest.
        let tree = consumer.join("target/fluxor/producer-common");
        assert_eq!(
            std::fs::read_to_string(tree.join("core.rs")).unwrap(),
            "pub fn forty_two() -> u32 { 42 }\n"
        );
        assert_eq!(
            std::fs::read_to_string(tree.join(SYNC_STAMP))
                .unwrap()
                .trim(),
            entry.digest
        );

        // Second sync: stamp short-circuits the extraction.
        let again = sync_project(&consumer, false).unwrap();
        assert!(
            again.materialized[0].contains("up to date"),
            "{:?}",
            again.materialized
        );

        // ensure_synced replays without re-resolving and stays green.
        let replayed = ensure_synced(&consumer).unwrap();
        assert_eq!(replayed.len(), 1);
    }

    /// (2) A mixed-epoch set is the exact hard error naming
    /// `fluxor update`.
    #[test]
    fn mixed_epoch_set_is_a_hard_error() {
        let scratch = tempfile::tempdir().unwrap();
        let store = OciStore::open(scratch.path().join("store")).unwrap();
        for (project, epoch) in [("alpha", "aa11"), ("beta", "bb22")] {
            let txn = store.begin_publish().unwrap();
            let meta = ArtifactMeta {
                project,
                provenance: "local-build",
                source_rev: None,
                abi_surface_hex: epoch,
                input_digest_hex: Some("cafe"),
                ci_digest_hex: None,
            };
            let prepared = store
                .prepare_source(
                    &format!("{project}-common"),
                    "0.0.1",
                    &[("core.rs".to_string(), b"pub fn x() {}\n".to_vec())],
                    &meta,
                )
                .unwrap();
            store
                .commit_publish(&txn, project, "0.0.1", vec![prepared], None)
                .unwrap();
        }
        let mut entries = Vec::new();
        for project in ["alpha", "beta"] {
            let idx_desc = store.resolve(&format!("{project}/meta:latest")).unwrap();
            let idx: crate::oci_store::ImageIndex =
                serde_json::from_slice(&store.read_blob(&idx_desc.digest).unwrap()).unwrap();
            for child in &idx.manifests {
                entries.push(
                    crate::store_resolve::artifact_from_descriptor(child)
                        .unwrap()
                        .unwrap(),
                );
            }
        }
        assert_eq!(entries.len(), 2);
        let err = crate::store_resolve::check_epoch(&entries, &store, &BTreeMap::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("mixed-epoch artifact set"), "{err}");
        assert!(err.contains("run `fluxor update`"), "{err}");
    }

    /// (3) A failed materialisation leaves the lockfile untouched.
    #[test]
    fn sync_failure_leaves_lockfile_untouched() {
        let _env = env_lock();
        let scratch = tempfile::tempdir().unwrap();
        let producer = scratch.path().join("producer");
        fake_project(&producer, "producer", &[]);
        std::fs::create_dir_all(producer.join("modules/common")).unwrap();
        std::fs::write(producer.join("modules/common/core.rs"), "pub fn y() {}\n").unwrap();
        let consumer = scratch.path().join("consumer");
        fake_project(&consumer, "consumer", &["producer"]);

        let _scope = EnvScope::set(&[
            ("FLUXOR_STORE", &scratch.path().join("store")),
            (
                "FLUXOR_WORKSPACE",
                &scratch.path().join("no-workspace.toml"),
            ),
        ]);
        crate::store_publish::publish_project_to_store(&producer, &["source"], false).unwrap();

        // Blow away the tar layer blob so materialisation must fail
        // after resolution succeeds.
        let store = OciStore::open(scratch.path().join("store")).unwrap();
        let desc = store
            .resolve("producer/src/producer-common:latest")
            .unwrap();
        let manifest = store.read_manifest(&desc).unwrap();
        std::fs::remove_file(store.blob_path(&manifest.layers[0].digest).unwrap()).unwrap();

        let err = sync_project(&consumer, false).unwrap_err().to_string();
        assert!(
            err.contains("no longer in store — run `fluxor update`"),
            "{err}"
        );
        assert!(
            !lockfile_path_exists(&consumer),
            "failed materialisation must not commit a pin"
        );
    }

    fn lockfile_path_exists(pr: &Path) -> bool {
        crate::store_resolve::lockfile_path(pr).exists()
    }

    /// The canonical-tar extractor round-trips the writer and rejects
    /// traversal.
    #[test]
    fn ustar_extractor_roundtrip_and_traversal_guard() {
        let files = vec![
            ("a/mod.rs".to_string(), b"pub fn a() {}\n".to_vec()),
            ("b.rs".to_string(), vec![7u8; 513]),
        ];
        let tar = crate::oci_store::canonical_tar(&files).unwrap();
        let dir = tempfile::tempdir().unwrap();
        extract_ustar(&tar, dir.path()).unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("a/mod.rs")).unwrap(),
            b"pub fn a() {}\n"
        );
        assert_eq!(
            std::fs::read(dir.path().join("b.rs")).unwrap(),
            vec![7u8; 513]
        );

        // Hand-craft a traversal entry: reuse a valid header and
        // corrupt the name (checksum is not what protects us here).
        let mut evil = tar.clone();
        evil[0..12].copy_from_slice(b"../evil.rs\0\0");
        assert!(extract_ustar(&evil, dir.path()).is_err());
    }

    /// The ci live-staleness gate: absent workspace file → `None`
    /// (skip); unpublished member → failure naming `workspace
    /// publish`; published + current → clean; edited inputs → failure
    /// listing the artifact.
    #[test]
    fn live_staleness_gate_states() {
        let _env = env_lock();
        let scratch = tempfile::tempdir().unwrap();
        let producer = scratch.path().join("producer");
        fake_project(&producer, "producer", &[]);
        std::fs::create_dir_all(producer.join("modules/common")).unwrap();
        std::fs::write(producer.join("modules/common/core.rs"), "pub fn z() {}\n").unwrap();
        let consumer = scratch.path().join("consumer");
        fake_project(&consumer, "consumer", &["producer"]);

        // (0) No workspace file → skip.
        let no_ws = scratch.path().join("no-workspace.toml");
        let _scope = EnvScope::set(&[
            ("FLUXOR_STORE", &scratch.path().join("store")),
            ("FLUXOR_WORKSPACE", &no_ws),
        ]);
        assert!(live_staleness_failures(&consumer).unwrap().is_none());

        // (1) Member never published → failure naming workspace publish.
        let ws_file = scratch.path().join("workspace.toml");
        std::fs::write(
            &ws_file,
            format!("[workspace]\nmembers = [\"{}\"]\n", producer.display()),
        )
        .unwrap();
        std::env::set_var("FLUXOR_WORKSPACE", &ws_file);
        let failures = live_staleness_failures(&consumer).unwrap().unwrap();
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].contains("no published index"), "{failures:?}");
        assert!(
            failures[0].contains("fluxor workspace publish"),
            "{failures:?}"
        );

        // (2) Published and unchanged → clean.
        crate::store_publish::publish_project_to_store(&producer, &["source"], false).unwrap();
        let failures = live_staleness_failures(&consumer).unwrap().unwrap();
        assert!(failures.is_empty(), "{failures:?}");

        // (3) Inputs edited since publish → failure listing the artifact.
        std::fs::write(
            producer.join("modules/common/core.rs"),
            "pub fn z() -> u32 { 9 }\n",
        )
        .unwrap();
        let failures = live_staleness_failures(&consumer).unwrap().unwrap();
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].contains("producer-common"), "{failures:?}");
        assert!(
            failures[0].contains("fluxor workspace publish"),
            "{failures:?}"
        );
    }

    /// `ensure_synced` on a declared dependency with no pin names
    /// `fluxor sync`.
    #[test]
    fn ensure_synced_requires_entries_for_declared_deps() {
        let scratch = tempfile::tempdir().unwrap();
        let consumer = scratch.path().join("consumer");
        fake_project(&consumer, "consumer", &["producer"]);
        let err = ensure_synced(&consumer).unwrap_err().to_string();
        assert!(
            err.contains("dependency 'producer' has no lockfile entry — run `fluxor sync`"),
            "{err}"
        );
    }

    /// Runtime staleness is measured against the binary itself: equal
    /// bytes are quiet, different bytes warn, and a cleaned tree with
    /// no build output is quiet because nothing was measured.
    #[test]
    fn runtime_staleness_compares_the_binary_not_the_rev() {
        let scratch = tempfile::tempdir().unwrap();
        let store = OciStore::open(scratch.path().join("store")).unwrap();
        let member = scratch.path().join("fluxor");
        let bin = member.join("target/host-triple/release/fluxor");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, b"published build\n").unwrap();

        let txn = store.begin_publish().unwrap();
        let meta = ArtifactMeta {
            project: "fluxor",
            provenance: "local-build",
            source_rev: None,
            abi_surface_hex: "aa11",
            input_digest_hex: None,
            ci_digest_hex: None,
        };
        let prepared = store
            .prepare_runtime(
                "fluxor",
                "0.0.1",
                "host-triple",
                b"published build\n",
                &meta,
            )
            .unwrap();
        let refs = store
            .commit_publish(&txn, "fluxor", "0.0.1", vec![prepared], None)
            .unwrap();
        let entry = Artifact {
            kind: "runtime".into(),
            name: "fluxor".into(),
            project: "fluxor".into(),
            target: Some("host-triple".into()),
            digest: refs[0].digest.clone(),
            reference: "fluxor/run/fluxor-host-triple:0.0.1".into(),
        };

        assert!(!runtime_differs_from_build(&store, &entry, &member).unwrap());
        std::fs::write(&bin, b"rebuilt, not republished\n").unwrap();
        assert!(runtime_differs_from_build(&store, &entry, &member).unwrap());
        std::fs::remove_file(&bin).unwrap();
        assert!(!runtime_differs_from_build(&store, &entry, &member).unwrap());
    }
}
