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
    OciStore, ANN_ABI_SURFACE, ANN_INPUT_DIGEST, ANN_REF_NAME, MT_FLUXOR_RUNTIME, MT_FLUXOR_SOURCE,
};
use crate::store_resolve::{
    read_manifest_layer_blob, read_pinned_manifest, read_store_lock, resolve_dependency,
    sort_entries, write_store_lock, Artifact,
};

/// Stamp file inside an extracted source tree, recording what the tree
/// was materialised from and what it held when it was written:
///
/// ```text
/// sha256:<artifact digest>      // which revision — matches fluxor.lock
/// content:<hex>                 // what the tree held — token-canonical
/// ```
///
/// The two lines answer different questions, and only the second is
/// checkable. `sha256:` names a revision — a claim about where the bytes came
/// from, which an edit inside the tree leaves standing, so on its own it lets
/// a consumer diverge from its own pin with nothing able to notice.
/// `content:` is the bytes themselves, recomputed from the tree on demand by
/// [`crate::store_publish::tree_content_digest`] with no store access and no
/// network, so a consumer can verify itself offline. It is the same
/// token-canonical walk the publisher hashes, so the value also equals the
/// artifact's published input digest.
///
/// A stamp carrying no `content:` line states nothing verifiable about the
/// tree, so the tree is treated as unverified and re-materialised. The reader
/// accepts the shorter shape rather than rejecting it: re-extraction is cheap
/// and leaves the tree correct either way.
const SYNC_STAMP: &str = ".fluxor-sync-stamp";

/// What a sync stamp records. `content` is `None` when the stamp carries no
/// content line, which makes the tree unverifiable rather than wrong.
#[derive(Debug, Clone)]
pub struct SyncStamp {
    pub digest: String,
    pub content: Option<String>,
}

/// Parse a stamp file. Line 1 is the artifact digest; a later `content:<hex>`
/// line carries the tree digest.
pub fn read_sync_stamp(tree: &Path) -> Option<SyncStamp> {
    let text = fs::read_to_string(tree.join(SYNC_STAMP)).ok()?;
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let digest = lines.next()?.to_string();
    let content = lines.find_map(|l| l.strip_prefix("content:").map(str::to_string));
    Some(SyncStamp { digest, content })
}

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
            let bytes = read_manifest_layer_blob(store, &e.name, &e.digest, &layer.digest)?;
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
            // Skip only when the stamp names this revision AND the tree
            // still holds the bytes that revision published. Re-extraction
            // is the one thing that puts an edited tree right, so gating it
            // on the revision alone would make an edited tree permanent:
            // the stamp still names the pinned revision, and every sync
            // after the edit short-circuits on that.
            if let Some(stamp) = read_sync_stamp(&dest) {
                if stamp.digest == e.digest
                    && stamp.content.as_deref()
                        == Some(crate::store_publish::tree_content_digest(&dest)?.as_str())
                {
                    return Ok(format!("source {} up to date ({})", e.name, dest.display()));
                }
            }
            let tar = read_manifest_layer_blob(store, &e.name, &e.digest, &layer.digest)?;
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
            let bytes = read_manifest_layer_blob(store, &e.name, &e.digest, &layer.digest)?;
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
    // Digest the tree before the stamp joins it (dotfiles are skipped by
    // `collect_tree`, so the order is belt-and-braces rather than load-bearing).
    let content = crate::store_publish::tree_content_digest(&tmp)?;
    fs::write(
        tmp.join(SYNC_STAMP),
        format!("{digest}\ncontent:{content}\n"),
    )?;
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
        let published = published_artifacts(&store, &name)?;
        let epoch = current_epoch_hex();
        // Epoch drift counts as dirty here even when sources are
        // untouched: the published artifact carries a stale epoch
        // annotation, and only a rebuild + restage can refresh it.
        let dirty: Vec<String> = stale_artifacts(&current, &epoch, published.as_ref())
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        if dirty.is_empty() && published.is_some() {
            outcomes.push((name, MemberOutcome::UpToDate));
            continue;
        }
        if dry_run {
            outcomes.push((name, MemberOutcome::WouldPublish(dirty)));
            continue;
        }
        // Materialise this member's dependencies BEFORE building it.
        //
        // Without this a surface migration cannot proceed: the member still
        // holds the previous SDK under `target/fluxor/`, compiles against
        // it, and the freshly built module embeds the OLD surface digest —
        // which packaging then rejects with "compiled against a different
        // ABI surface", in a member nobody edited. Topological order is what
        // makes syncing here safe: every dependency has already been
        // published at the current epoch by the time we reach a dependent,
        // so the mixed-epoch guard cannot trip.
        //
        // Best effort by intent, not by accident: a member that cannot
        // resolve (a pre-adoption checkout, or one whose deps this workspace
        // does not own) is left to the build below to succeed or fail on its
        // own terms. Refusing here would make `workspace publish` stricter
        // than the build it is about to run.
        if let Err(e) = sync_project(&path, false) {
            println!("workspace publish: {name} — sync skipped ({e})");
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

/// What one published artifact records about how it was built: the
/// token-canonical digest of its own inputs, and the ABI-surface epoch
/// it was compiled against. The two answer different questions —
/// "must this be rebuilt?" and "is this admissible here?" — so they are
/// carried and compared separately.
#[derive(Debug, Clone, Default)]
struct PublishedArtifact {
    input_digest: Option<String>,
    epoch: Option<String>,
}

/// Published per-artifact build state from `<project>/meta:latest`;
/// `None` when the project has never been published.
fn published_artifacts(
    store: &OciStore,
    project: &str,
) -> Result<Option<BTreeMap<String, PublishedArtifact>>> {
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
        out.insert(
            a.name,
            PublishedArtifact {
                input_digest: child.annotations.get(ANN_INPUT_DIGEST).cloned(),
                epoch: child.annotations.get(ANN_ABI_SURFACE).cloned(),
            },
        );
    }
    Ok(Some(out))
}

/// Why one artifact is not current against what is published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaleReason {
    /// Never published.
    Absent,
    /// The artifact's own sources moved.
    Inputs,
    /// The sources are unchanged, but the artifact was compiled against a
    /// different ABI surface than this checkout presents. It must be
    /// rebuilt and restaged to carry a current epoch, but nothing about
    /// the module itself was edited — worth saying separately, because a
    /// whole project reporting this means one surface edit, not N module
    /// edits.
    Epoch,
}

impl StaleReason {
    const fn label(self) -> &'static str {
        match self {
            Self::Absent => "unpublished",
            Self::Inputs => "sources changed",
            Self::Epoch => "ABI surface moved",
        }
    }
}

/// Compare a checkout's current artifact inputs against what is
/// published, at `epoch`. Returns one entry per artifact that is not
/// current, in artifact-name order.
fn stale_artifacts(
    current: &BTreeMap<String, String>,
    epoch: &str,
    published: Option<&BTreeMap<String, PublishedArtifact>>,
) -> Vec<(String, StaleReason)> {
    let Some(published) = published else {
        // No published index at all: every artifact is a first publish.
        return current
            .keys()
            .map(|k| (k.clone(), StaleReason::Absent))
            .collect();
    };
    let mut out = Vec::new();
    for (name, digest) in current {
        let Some(entry) = published.get(name) else {
            out.push((name.clone(), StaleReason::Absent));
            continue;
        };
        if entry.input_digest.as_deref() != Some(digest.as_str()) {
            out.push((name.clone(), StaleReason::Inputs));
        } else if entry.epoch.as_deref().is_some_and(|e| e != epoch) {
            // Source artifacts carry no epoch; only modules do, so a
            // missing annotation is not drift.
            out.push((name.clone(), StaleReason::Epoch));
        }
    }
    out
}

/// Render a stale set as one human line: artifacts grouped by reason, so
/// "every module, ABI surface moved" reads as the single cause it is
/// rather than as N independent problems.
fn describe_stale(stale: &[(String, StaleReason)]) -> String {
    let mut groups: BTreeMap<&'static str, Vec<&str>> = BTreeMap::new();
    for (name, reason) in stale {
        groups.entry(reason.label()).or_default().push(name);
    }
    groups
        .into_iter()
        .map(|(reason, names)| {
            // Past a handful, the list stops informing and starts hiding
            // the reason, which is the part that tells you what to do.
            if names.len() > 6 {
                format!("{} artifacts: {reason}", names.len())
            } else {
                format!("{}: {reason}", names.join(", "))
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

// ── ci live-staleness gate ────────────────────────────────────────────

/// Current ABI-surface epoch as lower-case hex.
fn current_epoch_hex() -> String {
    crate::hash::abi_surface_digest()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Whether the `fluxor ci` live-staleness phase acts on what it finds.
///
/// It reports on **workspace-member dependencies** only. A project's own
/// publish state is deliberately not checked: nothing builds against its
/// own published artefacts, so comparing the checkout to them says
/// nothing about the build. `fluxor workspace status` is where publish
/// state lives.
///
/// Even for a dependency the finding is informational. A pinned build
/// resolves the *published* artefact, which is what pinning means; an
/// upstream checkout sitting ahead of it means the author has newer work
/// you are not seeing, not that this build is wrong. The conditions that
/// would make it wrong — a module compiled against a different ABI
/// surface, a lockfile that no longer resolves, a skewed CLI — are
/// separate phases that fail on their own account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StalenessScope {
    /// Report and continue. The default.
    #[default]
    Report,
    /// Fail when a member dependency is behind what it published. For a
    /// release gate, where the whole member set must be publishable
    /// together.
    Fail,
}

impl StalenessScope {
    /// Parse the `[ci] live_staleness` key.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "report" => Some(Self::Report),
            "fail" => Some(Self::Fail),
            _ => None,
        }
    }
}

/// The `fluxor ci` live-staleness check.
///
/// For every workspace-member project among this project's declared
/// dependencies, compare the member checkout's current per-artifact
/// input digests against the published `io.fluxor.input-digest`
/// annotations in `<member>/meta:latest`, and the checkout's ABI-surface
/// epoch against each artifact's published `io.fluxor.abi-surface`.
///
/// The two comparisons are reported as distinct causes. An artifact
/// whose sources moved differs from one whose epoch moved: the first
/// changed, the second had the ground move under it. Reading a whole
/// module set as "ABI surface moved" names a single cause, where a bare
/// list of every module names none.
///
/// Returns `Ok(None)` when there is no workspace file, or when this
/// project declares no workspace-member dependencies — the root project
/// of the family declares none, and a phase with nothing to compare
/// skips rather than inventing a comparison against itself.
pub fn live_staleness_report(project_root: &Path) -> Result<Option<Vec<String>>> {
    if crate::workspace::load_workspace()?.is_none() {
        return Ok(None);
    }
    let members = member_projects()?;

    // Declared dependencies that are workspace members. Deliberately not
    // including this project: see `StalenessScope`.
    let mut relevant: Vec<(String, PathBuf)> = Vec::new();
    for dep in crate::project::dependencies(project_root).map_err(Error::Config)? {
        if let Some(path) = members.get(&dep.name) {
            relevant.push((dep.name, path.clone()));
        }
    }
    if relevant.is_empty() {
        return Ok(None);
    }

    let store = OciStore::open(crate::oci_store::store_root()?)?;
    let epoch = current_epoch_hex();
    let mut findings = Vec::new();
    for (name, path) in relevant {
        let current = crate::store_publish::project_input_digests(&path)?;
        match published_artifacts(&store, &name)? {
            None => findings.push(format!(
                "dependency '{name}' has never been published — run \
                 `fluxor publish` in that checkout"
            )),
            Some(published) => {
                let stale = stale_artifacts(&current, &epoch, Some(&published));
                if !stale.is_empty() {
                    findings.push(format!(
                        "dependency '{name}' has unpublished changes ({}); this build \
                         resolves what it published",
                        describe_stale(&stale)
                    ));
                }
            }
        }
    }
    Ok(Some(findings))
}

/// Findings about materialised source trees, split by what is known, because
/// the two states demand different answers.
///
/// `drift` is a tree that disagrees with a recorded fact — known wrong, and a
/// failure. `unverifiable` is a tree whose bytes cannot be checked at all;
/// nothing is known to be wrong, so it is reported rather than failed, but it
/// is reported, because an unverifiable tree is exactly where drift goes
/// unseen.
#[derive(Debug, Default)]
pub struct MaterialisationReport {
    pub drift: Vec<String>,
    pub unverifiable: Vec<String>,
}

impl MaterialisationReport {
    pub fn is_clean(&self) -> bool {
        self.drift.is_empty() && self.unverifiable.is_empty()
    }
}

/// Verify every materialised SOURCE tree against the pin this project itself
/// recorded. `Ok(None)` when the project pins no source artifact.
///
/// Two independent claims are checked, and they fail for different reasons:
///
/// - **stamp vs lockfile** — the tree was materialised from a revision the
///   project does not pin. A hand-edited `fluxor.lock`, or a sync interrupted
///   between extraction and the lockfile write.
/// - **tree vs stamp** — the tree does not hold the bytes it was materialised
///   from. An edit inside `target/fluxor/<artifact>/`, which is generated and
///   is nobody's to edit.
///
/// What this deliberately does NOT ask is whether the pinned revision is the
/// newest one upstream published. That is `live-staleness`'s question, and it
/// is a judgement: building what you pinned while upstream moves on is a
/// defensible state. This question is not a judgement — a project whose disk
/// disagrees with its own lockfile is incoherent whatever upstream is doing —
/// so it can be answered absolutely without that absoluteness reaching
/// upstream. Editing the SDK in the producing project fails no consumer's CI.
/// Half-updating a consumer does.
pub fn materialisation_report(project_root: &Path) -> Result<Option<MaterialisationReport>> {
    let Some(lock) = read_store_lock(project_root)? else {
        return Ok(None);
    };
    let sources: Vec<&Artifact> = lock
        .artifacts
        .iter()
        .filter(|a| a.kind == "source")
        .collect();
    if sources.is_empty() {
        return Ok(None);
    }
    let mut r = MaterialisationReport::default();
    // Every unverifiable tree has the same cause and the same one-command
    // answer, so they are named together on one line. Repeating the sentence
    // per artifact buries the cause — which is the part that says what to do
    // — under its own restatements (same reasoning as `describe_stale`).
    let mut unverifiable: Vec<&str> = Vec::new();
    for e in sources {
        let dest = project_root.join("target/fluxor").join(&e.name);
        if !dest.is_dir() {
            r.drift.push(format!(
                "source '{}' is pinned in fluxor.lock but not materialised at {} — run `fluxor sync`",
                e.name,
                dest.display()
            ));
            continue;
        }
        let Some(stamp) = read_sync_stamp(&dest) else {
            unverifiable.push(&e.name);
            continue;
        };
        if stamp.digest != e.digest {
            r.drift.push(format!(
                "source '{}' was materialised from {} but fluxor.lock pins {} — run `fluxor sync`",
                e.name, stamp.digest, e.digest
            ));
            continue;
        }
        let actual = crate::store_publish::tree_content_digest(&dest)?;
        match stamp.content.as_deref() {
            Some(recorded) if recorded == actual => {}
            // Drift is named one tree at a time: each carries its own two
            // digests, and those are what a reader acts on.
            Some(recorded) => r.drift.push(format!(
                "source '{}' at {} does not hold the bytes it was materialised from: \
                 expected content {recorded}, found {actual}. This tree is generated — \
                 revert the edit in the project that publishes '{}', republish, then run \
                 `fluxor sync`",
                e.name,
                dest.display(),
                e.name
            )),
            None => unverifiable.push(&e.name),
        }
    }
    if !unverifiable.is_empty() {
        r.unverifiable.push(format!(
            "{} source tree(s) under target/fluxor ({}) have no content digest recorded, so \
             their bytes cannot be verified against the revisions fluxor.lock pins — run \
             `fluxor sync` to re-materialise them",
            unverifiable.len(),
            unverifiable.join(", ")
        ));
    }
    Ok(Some(r))
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

    use crate::oci_store::EnvScope;

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

        // Tree extracted byte-for-byte; stamp records BOTH which revision
        // was extracted and what the tree held when it was written.
        let tree = consumer.join("target/fluxor/producer-common");
        assert_eq!(
            std::fs::read_to_string(tree.join("core.rs")).unwrap(),
            "pub fn forty_two() -> u32 { 42 }\n"
        );
        let stamp = read_sync_stamp(&tree).unwrap();
        assert_eq!(stamp.digest, entry.digest);
        assert_eq!(
            stamp.content.as_deref(),
            Some(
                crate::store_publish::tree_content_digest(&tree)
                    .unwrap()
                    .as_str()
            ),
            "the recorded content digest must be recomputable from the tree"
        );

        // Second sync: stamp short-circuits the extraction.
        let again = sync_project(&consumer, false).unwrap();
        assert!(
            again.materialized[0].contains("up to date"),
            "{:?}",
            again.materialized
        );

        // …but only while the tree still holds those bytes. An edit inside
        // a generated tree is the drift this stamp exists to catch: the
        // artifact digest still matches, so a digest-only check would
        // short-circuit on it forever.
        std::fs::write(tree.join("core.rs"), "pub fn forty_two() -> u32 { 43 }\n").unwrap();
        let report = materialisation_report(&consumer).unwrap().unwrap();
        assert_eq!(report.drift.len(), 1, "{report:?}");
        assert!(
            report.drift[0].contains("does not hold the bytes"),
            "{report:?}"
        );
        let healed = sync_project(&consumer, false).unwrap();
        assert!(
            !healed.materialized[0].contains("up to date"),
            "a modified tree must be re-extracted, got {:?}",
            healed.materialized
        );
        assert_eq!(
            std::fs::read_to_string(tree.join("core.rs")).unwrap(),
            "pub fn forty_two() -> u32 { 42 }\n"
        );
        assert!(materialisation_report(&consumer)
            .unwrap()
            .unwrap()
            .is_clean());

        // ensure_synced replays without re-resolving and stays green.
        let replayed = ensure_synced(&consumer).unwrap();
        assert_eq!(replayed.len(), 1);
    }

    /// A producer republish (retag) must never break a workspace
    /// member's existing pin: the member's lockfile pins a manifest
    /// digest, so the retag sweep must keep that manifest's whole
    /// closure — layer blobs included — and the member's next sync
    /// must still materialise.
    #[test]
    fn producer_republish_keeps_member_pin_consumable() {
        let _env = env_lock();
        let scratch = tempfile::tempdir().unwrap();
        let producer = scratch.path().join("producer");
        fake_project(&producer, "producer", &[]);
        std::fs::create_dir_all(producer.join("modules/common")).unwrap();
        std::fs::write(producer.join("modules/common/core.rs"), "pub fn a() {}\n").unwrap();
        let consumer = scratch.path().join("consumer");
        fake_project(&consumer, "consumer", &["producer"]);
        // The consumer is a workspace member, so its lockfile pins are
        // sweep roots.
        let ws_file = scratch.path().join("workspace.toml");
        std::fs::write(
            &ws_file,
            format!(
                "[workspace]\nmembers = [\"{}\"]\n",
                consumer.to_str().unwrap()
            ),
        )
        .unwrap();

        let _scope = EnvScope::set(&[
            ("FLUXOR_STORE", &scratch.path().join("store")),
            ("FLUXOR_WORKSPACE", &ws_file),
        ]);
        crate::store_publish::publish_project_to_store(&producer, &["source"], false).unwrap();
        let report = sync_project(&consumer, false).unwrap();
        let pinned = report.entries[0].digest.clone();

        // Producer republishes changed content: the old manifest is
        // displaced from the index and swept.
        std::fs::write(producer.join("modules/common/core.rs"), "pub fn b() {}\n").unwrap();
        crate::store_publish::publish_project_to_store(&producer, &["source"], false).unwrap();

        // The pinned manifest AND every blob it references survive.
        let store = OciStore::open(scratch.path().join("store")).unwrap();
        let manifest =
            read_pinned_manifest(&store, &report.entries[0]).expect("pinned manifest readable");
        for l in &manifest.layers {
            assert!(
                store.has_blob(&l.digest),
                "layer {} of pinned manifest {pinned} swept — dangling manifest",
                l.digest
            );
        }
        // A cleaned checkout re-materialises from the pinned blobs, so
        // this replay actually reads the layer.
        std::fs::remove_dir_all(consumer.join("target")).unwrap();
        ensure_synced(&consumer).expect("member pin still materialises after producer republish");
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
            err.contains(&format!(
                "manifest {} is present but the layer it references cannot be read",
                desc.digest
            )),
            "{err}"
        );
        // The underlying `read_blob` cause survives, naming the layer
        // and distinguishing absence from corruption.
        assert!(
            err.contains(&format!("blob {} not in store", manifest.layers[0].digest)),
            "{err}"
        );
        // The remedy must be one that terminates: republish alone mints
        // a new manifest and leaves this pin broken.
        assert!(
            err.contains("run `fluxor update` to repin")
                && err.contains("re-run `fluxor store pull`"),
            "{err}"
        );
        assert!(
            !lockfile_path_exists(&consumer),
            "failed materialisation must not commit a pin"
        );
    }

    /// The other half of the pair: the manifest itself is gone, not a
    /// layer under it. That IS "no longer in store", and `fluxor update`
    /// alone repairs it (the tag now names a different manifest), so the
    /// two messages must stay distinct.
    #[test]
    fn missing_pinned_manifest_names_fluxor_update() {
        let _env = env_lock();
        let scratch = tempfile::tempdir().unwrap();
        let producer = scratch.path().join("producer");
        fake_project(&producer, "producer", &[]);
        std::fs::create_dir_all(producer.join("modules/common")).unwrap();
        std::fs::write(producer.join("modules/common/core.rs"), "pub fn w() {}\n").unwrap();
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
        let report = sync_project(&consumer, false).unwrap();
        let pinned = report.entries[0].digest.clone();

        // Delete the pinned manifest blob and force a re-materialisation
        // from the existing lockfile.
        let store = OciStore::open(scratch.path().join("store")).unwrap();
        std::fs::remove_file(store.blob_path(&pinned).unwrap()).unwrap();
        std::fs::remove_dir_all(consumer.join("target")).unwrap();

        let err = ensure_synced(&consumer).unwrap_err().to_string();
        assert!(
            err.contains(&format!(
                "({pinned}) no longer in store — run `fluxor update`"
            )),
            "{err}"
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

    /// The ci live-staleness gate: no workspace file → `None` (skip);
    /// a member dependency that has never published, or has unpublished
    /// work → one finding naming it; published and current → nothing.
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
        assert!(live_staleness_report(&consumer).unwrap().is_none());

        // (1) Dependency never published → one finding naming it.
        let ws_file = scratch.path().join("workspace.toml");
        std::fs::write(
            &ws_file,
            format!("[workspace]\nmembers = [\"{}\"]\n", producer.display()),
        )
        .unwrap();
        std::env::set_var("FLUXOR_WORKSPACE", &ws_file);
        let found = live_staleness_report(&consumer).unwrap().unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("never been published"), "{found:?}");

        // (2) Published and unchanged → nothing.
        crate::store_publish::publish_project_to_store(&producer, &["source"], false).unwrap();
        let found = live_staleness_report(&consumer).unwrap().unwrap();
        assert!(found.is_empty(), "{found:?}");

        // (3) Dependency edited since publish → one finding naming the
        // artifact and the cause.
        std::fs::write(
            producer.join("modules/common/core.rs"),
            "pub fn z() -> u32 { 9 }\n",
        )
        .unwrap();
        let found = live_staleness_report(&consumer).unwrap().unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("producer-common"), "{found:?}");
        assert!(found[0].contains("sources changed"), "{found:?}");
    }

    /// The root project of the family declares no dependencies. The phase
    /// must have nothing to say about it — it must not compare the
    /// checkout against its own published artefacts, which is a
    /// comparison no build depends on.
    #[test]
    fn a_project_with_no_member_dependencies_skips() {
        let _env = env_lock();
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("root");
        fake_project(&root, "root", &[]);
        std::fs::create_dir_all(root.join("modules/common")).unwrap();
        std::fs::write(root.join("modules/common/core.rs"), "pub fn z() {}\n").unwrap();

        // `root` is itself a workspace member, and has never published.
        let ws_file = scratch.path().join("workspace.toml");
        std::fs::write(
            &ws_file,
            format!("[workspace]\nmembers = [\"{}\"]\n", root.display()),
        )
        .unwrap();
        let _scope = EnvScope::set(&[
            ("FLUXOR_STORE", &scratch.path().join("store")),
            ("FLUXOR_WORKSPACE", &ws_file),
        ]);

        assert!(
            live_staleness_report(&root).unwrap().is_none(),
            "a project with no member dependencies has nothing to compare"
        );
    }

    /// An artifact whose sources are untouched but whose published epoch
    /// differs is stale for a DIFFERENT reason, and says so. The two are
    /// separable only because the epoch is its own annotation rather than a
    /// term in the input digest: folded in, an ABI-surface move would be
    /// indistinguishable from an edit, and a whole project's worth of
    /// modules would each report a source change nobody made.
    #[test]
    fn epoch_drift_is_a_distinct_reason_from_an_edit() {
        let published = |input: &str, epoch: &str| {
            let mut m = BTreeMap::new();
            m.insert(
                "mod_a".to_string(),
                PublishedArtifact {
                    input_digest: Some(input.to_string()),
                    epoch: Some(epoch.to_string()),
                },
            );
            m
        };
        let mut current = BTreeMap::new();
        current.insert("mod_a".to_string(), "aaaa".to_string());

        // Same inputs, same epoch → current.
        let map = published("aaaa", "e1");
        assert!(stale_artifacts(&current, "e1", Some(&map)).is_empty());

        // Same inputs, moved epoch → stale, but as a restage not an edit.
        let map = published("aaaa", "e0");
        assert_eq!(
            stale_artifacts(&current, "e1", Some(&map)),
            vec![("mod_a".to_string(), StaleReason::Epoch)]
        );

        // Edited inputs → reported as the edit, not as epoch drift, even
        // when both moved: the edit is the actionable fact.
        let map = published("bbbb", "e0");
        assert_eq!(
            stale_artifacts(&current, "e1", Some(&map)),
            vec![("mod_a".to_string(), StaleReason::Inputs)]
        );

        // A source artifact carries no epoch annotation; a missing one is
        // not drift.
        let mut map = published("aaaa", "e0");
        map.get_mut("mod_a").unwrap().epoch = None;
        assert!(stale_artifacts(&current, "e1", Some(&map)).is_empty());
    }

    /// A whole module set going stale for one reason must read as one
    /// cause, not as a wall of names that hides it.
    #[test]
    fn describe_stale_groups_large_sets_by_reason() {
        let many: Vec<(String, StaleReason)> = (0..40)
            .map(|i| (format!("mod_{i}"), StaleReason::Epoch))
            .collect();
        let line = describe_stale(&many);
        assert_eq!(line, "40 artifacts: ABI surface moved");

        // A small set still names its artifacts, which is what makes the
        // message actionable when it is actionable.
        let few = vec![
            ("fat32".to_string(), StaleReason::Inputs),
            ("nvme".to_string(), StaleReason::Inputs),
        ];
        assert_eq!(describe_stale(&few), "fat32, nvme: sources changed");
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
