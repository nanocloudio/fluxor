//! Resolve + lockfile — the uniform `[[artifact]]` lockfile over the
//! OCI store. Lib-only (the store engine layering): the bin reaches
//! it via `fluxor_tools::store_resolve`.
//!
//! One shape for every project: `[[artifact]]` entries
//! `{kind, name, project, target?, digest, reference}`. The lockfile
//! is always the resolver; `resolve_project` walks the dependencies'
//! project indexes (`<dep>/meta:latest`), `cmd_update` advances the
//! pins (optionally from a snapshot), and `pin_artifact` is the single
//! ad-hoc pin writer. Epoch validation (`check_epoch`) enforces the
//! two sync-time rules: set homogeneity for everyone, currency for
//! live workspace members only.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::oci_store::{
    Descriptor, ImageIndex, ImageManifest, OciStore, ANN_ABI_SURFACE, ANN_KIND, ANN_MODULE_NAME,
    ANN_PROJECT, ANN_REF_NAME, ANN_RUNTIME_TRIPLE, ANN_TARGET,
};

const LOCKFILE_NAME: &str = "fluxor.lock";

// ── Lockfile shape ────────────────────────────────────────────────────

/// One pinned artifact — the uniform lockfile entry for every kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    /// `module` | `source` | `runtime` | `bundle`.
    pub kind: String,
    /// Artifact name (module name, source-tree name, runtime binary
    /// name, bundle name).
    pub name: String,
    /// Publishing project (`io.fluxor.project`).
    pub project: String,
    /// Silicon target for modules, host triple for runtimes; absent
    /// for sources and bundles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Artifact-manifest digest (`sha256:<hex>`) — the identity.
    pub digest: String,
    /// The tag the pin was resolved from — informational.
    pub reference: String,
    /// Content address of what the manifest DELIVERS: a digest over its
    /// layer digests, in order.
    ///
    /// Recorded, never resolved by. The manifest digest stays the
    /// identity, because it is what carries the artifact's target, epoch
    /// and `manifest.toml` metadata, and resolving from a bare layer
    /// would let ports and bytes drift apart. What this field buys is
    /// diagnosis: `fluxor update` can say "77 pins moved, 0 changed"
    /// instead of reporting churn as change, and `fluxor store fsck` can
    /// tell a lost artifact from a renamed one — the difference between
    /// a recoverable pin and a dead one.
    ///
    /// Not the input digest, which is NOT a content address: it hashes a
    /// module's declared sources, not the toolchain or the catalog, and
    /// two artifacts with different bytes can and do share one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

/// Content address of a manifest: a digest over its layer digests in
/// manifest order. Stable across a provenance re-stamp by construction.
pub fn content_digest(manifest: &ImageManifest) -> String {
    let joined = manifest
        .layers
        .iter()
        .map(|l| l.digest.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    crate::oci_store::sha256_hex_prefixed(joined.as_bytes())
}

/// The whole `fluxor.lock`: one `[[artifact]]` list, nothing else.
/// `deny_unknown_fields` is load-bearing — without it any other
/// top-level section deserializes to an empty pin set, and a lockfile
/// that reads as "zero pins" is indistinguishable from a valid empty
/// one.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreLock {
    #[serde(default, rename = "artifact")]
    pub artifacts: Vec<Artifact>,
    /// The catalog (`stacks/` + `targets/`) these pins were resolved
    /// against.
    ///
    /// The catalog is the one input to a build that nothing pinned. It
    /// is read live from the fluxor checkout while the modules it
    /// configures come from the digests above, so the two move
    /// independently: a stack edited in a sibling checkout changes every
    /// downstream build immediately, with no publish, no `update`, and
    /// no record anywhere that anything changed.
    ///
    /// That is not hypothetical. A commit that added parameters to a
    /// module and referenced them from a stack was coherent in its own
    /// tree and broke every consumer's networked build until each
    /// rebuilt that target — and the failure named a parameter the
    /// consumer's config had never mentioned.
    ///
    /// Recording the catalog here does not freeze it; it makes the drift
    /// observable, which is what was missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog: Option<Catalog>,
}

/// The catalog stamp recorded in `fluxor.lock`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    /// Digest over every `stacks/*.toml` and `targets/**/*.toml` in the
    /// install root, by sorted relative path.
    pub digest: String,
    /// Accepted from a lock written before the stamp dropped it, and never
    /// written: it held the install root's absolute path, which is a fact
    /// about one machine in a file every machine commits. Nothing read it —
    /// the drift diagnostic names the root it just digested, which is the
    /// one its reader can actually go and look at.
    #[serde(default, skip_serializing)]
    pub source: Option<String>,
}

/// Digest the catalog at `install_root` — every `stacks/*.toml` and
/// `targets/**/*.toml`, hashed by sorted relative path so the result
/// depends on content and naming and not on directory order.
///
/// Returns `None` when the root holds no catalog to digest.
pub fn catalog_digest(install_root: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};

    fn collect(dir: &Path, base: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect(&path, base, out);
            } else if path.extension().is_some_and(|e| e == "toml") {
                if let (Ok(rel), Ok(bytes)) = (path.strip_prefix(base), fs::read(&path)) {
                    out.push((rel.to_string_lossy().replace('\\', "/"), bytes));
                }
            }
        }
    }

    let mut files = Vec::new();
    collect(&install_root.join("stacks"), install_root, &mut files);
    collect(&install_root.join("targets"), install_root, &mut files);
    if files.is_empty() {
        return None;
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = Sha256::new();
    for (rel, bytes) in &files {
        h.update(rel.as_bytes());
        h.update([0u8]);
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    let out = h.finalize();
    let mut s = String::from("sha256:");
    for b in out {
        s.push_str(&format!("{b:02x}"));
    }
    Some(s)
}

pub fn lockfile_path(project_root: &Path) -> PathBuf {
    project_root.join(LOCKFILE_NAME)
}

/// Read `fluxor.lock`. A missing file is `Ok(None)` — `fluxor update`
/// creates it. Anything present but unreadable is a hard error naming
/// the verb that rewrites it: `deny_unknown_fields` on [`StoreLock`]
/// turns a file of some other shape into a parse failure rather than a
/// silent zero-pin read.
pub fn read_store_lock(project_root: &Path) -> Result<Option<StoreLock>> {
    let path = lockfile_path(project_root);
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path)?;
    let parsed: StoreLock = toml::from_str(&text).map_err(|e| {
        Error::Config(format!(
            "{}: {e}— run `fluxor update` to rewrite it",
            path.display()
        ))
    })?;
    Ok(Some(parsed))
}

/// Stable lockfile order: sort by (kind, project, name, target) and
/// drop duplicate identities (first wins).
pub fn sort_entries(entries: &mut Vec<Artifact>) {
    entries.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| a.project.cmp(&b.project))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.target.cmp(&b.target))
    });
    entries.dedup_by(|a, b| {
        a.kind == b.kind && a.project == b.project && a.name == b.name && a.target == b.target
    });
}

/// Write `fluxor.lock` (sorted, atomic replace). Callers hold the
/// advisory lock (`crate::lockfile::lock_lockfile`) around the whole
/// read-modify-write transaction — this fn never takes it itself, so
/// one guard can span resolve → materialise → write.
pub fn write_store_lock(project_root: &Path, entries: &[Artifact]) -> Result<PathBuf> {
    let mut sorted = entries.to_vec();
    sort_entries(&mut sorted);
    let catalog = crate::project::install_root()
        .and_then(|r| catalog_digest(&r.path))
        .map(|digest| Catalog {
            digest,
            source: None,
        });
    let lock = StoreLock {
        artifacts: sorted,
        catalog,
    };
    let path = lockfile_path(project_root);
    let mut body = String::new();
    body.push_str("# fluxor.lock — generated, edit via `fluxor update`\n");
    body.push_str("# Pinned store artifacts: one [[artifact]] entry per resolved digest.\n\n");
    let serialised = toml::to_string_pretty(&lock)
        .map_err(|e| Error::Config(format!("serialise lockfile: {e}")))?;
    body.push_str(&serialised);
    let tmp = path.with_extension(format!("lock.tmp.{}", std::process::id()));
    fs::write(&tmp, body)?;
    fs::File::open(&tmp)?.sync_all()?;
    if let Err(e) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    register_pins(project_root, &lock.artifacts);
    Ok(path)
}

/// Tell the store which digests this checkout is now holding.
///
/// Every writer of a lockfile comes through here, so a checkout
/// registers itself the first time it resolves anything — no list to
/// maintain, and no way to be a consumer the collector cannot see.
/// Registration never fails the caller: it is a liveness improvement,
/// and a store whose ledger cannot be written is not a reason to fail an
/// update.
pub fn register_pins(project_root: &Path, artifacts: &[Artifact]) {
    // A unit test writing a lockfile in a temp directory must not
    // register that directory in the DEVELOPER's real store: without
    // this, `store_root()` falls back to `~/.local/share/fluxor/store`
    // and every such test leaves a permanent ledger entry naming a
    // tempdir that no longer exists — which `fluxor store fsck` then
    // correctly reports as a dead pin. A test that means to exercise
    // registration opts in by setting `$FLUXOR_STORE`.
    if cfg!(test) && std::env::var_os("FLUXOR_STORE").is_none() {
        return;
    }
    let Ok(store_root) = crate::oci_store::store_root() else {
        return;
    };
    let digests = artifacts.iter().map(|a| a.digest.clone()).collect();
    crate::store_pins::register(&store_root, project_root, &digests);
}

/// Fill in each entry's content address from the manifest it pins.
/// A pin whose manifest cannot be read keeps `None` — unknown is not
/// the same claim as "no layers", and reporting must be able to tell
/// them apart.
fn fill_content(store: &OciStore, entries: &mut [Artifact]) {
    for e in entries.iter_mut() {
        let resolved = store.resolve_pin(&e.digest);
        if let Ok(bytes) = store.read_blob(&resolved) {
            if let Ok(m) = serde_json::from_slice::<ImageManifest>(&bytes) {
                e.content = Some(content_digest(&m));
            }
        }
    }
}

// ── Descriptor → Artifact extraction ──────────────────────────────────

/// Interpret an index child (project-index or snapshot child) as a
/// lockfile artifact. Returns `None` for descriptors that are not
/// pinnable artifacts (nested indexes, unknown kinds).
pub fn artifact_from_descriptor(d: &Descriptor) -> Result<Option<Artifact>> {
    let Some(kind) = d.annotations.get(ANN_KIND) else {
        return Ok(None);
    };
    let reference = d.annotations.get(ANN_REF_NAME).cloned().ok_or_else(|| {
        Error::Config(format!(
            "index child {} carries no ref-name annotation — corrupt project index",
            d.digest
        ))
    })?;
    let project = d.annotations.get(ANN_PROJECT).cloned().unwrap_or_default();
    let tag_body = reference
        .rsplit_once(':')
        .map_or(reference.as_str(), |(body, _ver)| body);
    let last_segment = tag_body.rsplit('/').next().unwrap_or(tag_body).to_string();
    let artifact = match kind.as_str() {
        "module" => Artifact {
            kind: kind.clone(),
            name: d
                .annotations
                .get(ANN_MODULE_NAME)
                .cloned()
                .unwrap_or(last_segment),
            project,
            target: d.annotations.get(ANN_TARGET).cloned(),
            digest: d.digest.clone(),
            reference,
            // Filled by `fill_content` where a store is in hand; this
            // fn reads a descriptor alone.
            content: None,
        },
        "source" => Artifact {
            kind: kind.clone(),
            name: last_segment,
            project,
            target: None,
            digest: d.digest.clone(),
            reference,
            // Filled by `fill_content` where a store is in hand; this
            // fn reads a descriptor alone.
            content: None,
        },
        "runtime" => {
            let triple = d.annotations.get(ANN_RUNTIME_TRIPLE).cloned();
            // Ref shape: `fluxor/run/<name>-<triple>:<ver>`.
            let name = triple
                .as_deref()
                .and_then(|t| last_segment.strip_suffix(&format!("-{t}")))
                .map(str::to_string)
                .unwrap_or(last_segment);
            Artifact {
                kind: kind.clone(),
                name,
                project,
                target: triple,
                digest: d.digest.clone(),
                reference,
                content: None,
            }
        }
        "bundle" => Artifact {
            kind: kind.clone(),
            name: last_segment,
            project,
            target: None,
            digest: d.digest.clone(),
            reference,
            // Filled by `fill_content` where a store is in hand; this
            // fn reads a descriptor alone.
            content: None,
        },
        _ => return Ok(None),
    };
    Ok(Some(artifact))
}

// ── Resolution ────────────────────────────────────────────────────────

/// The silicon set this project builds modules for, from
/// `fluxor.toml::[ci].targets` (each mapped through
/// `resolve_silicon`; unmappable names pass through raw). `None` when
/// the list is absent or empty — the caller then pins every module
/// child rather than guessing.
fn ci_target_silicons(project_root: &Path) -> Result<Option<BTreeSet<String>>> {
    let path = project_root.join("fluxor.toml");
    if !path.exists() {
        return Ok(None);
    }
    #[derive(Deserialize)]
    struct Top {
        ci: Option<Ci>,
    }
    #[derive(Deserialize)]
    struct Ci {
        targets: Option<Vec<String>>,
    }
    let raw = fs::read_to_string(&path)?;
    let parsed: Top = toml::from_str(&raw)
        .map_err(|e| Error::Config(format!("parse {}: {e}", path.display())))?;
    let targets = parsed.ci.and_then(|c| c.targets).unwrap_or_default();
    if targets.is_empty() {
        return Ok(None);
    }
    let mut silicons = BTreeSet::new();
    for t in targets {
        // Target names and silicon ids both appear in [ci].targets
        // downstream; resolve where possible, pass through otherwise
        // (an unresolvable name never silently drops a module pin —
        // both forms stay in the accept set).
        silicons.insert(
            crate::modules_build::resolve_silicon(&t, project_root).unwrap_or_else(|_| t.clone()),
        );
        silicons.insert(t);
    }
    Ok(Some(silicons))
}

fn read_image_index(store: &OciStore, digest: &str) -> Result<ImageIndex> {
    let bytes = store.read_blob(digest)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::Config(format!("corrupt index {digest}: {e}")))
}

/// Resolve one dependency's pinnable artifacts from its project index
/// (`<dep>/meta:latest`): every source and runtime child, plus module
/// children whose target is in `silicons` (all of them when `None`).
pub(crate) fn resolve_dependency(
    store: &OciStore,
    dep: &str,
    silicons: Option<&BTreeSet<String>>,
) -> Result<Vec<Artifact>> {
    let meta_ref = format!("{dep}/meta:latest");
    let desc = store.resolve(&meta_ref).map_err(|_| {
        Error::Config(format!(
            "dependency '{dep}' has no published index ('{meta_ref}' not in store) — \
             run `fluxor publish` in {dep}"
        ))
    })?;
    let idx = read_image_index(store, &desc.digest)?;
    let mut out = Vec::new();
    for child in &idx.manifests {
        let Some(a) = artifact_from_descriptor(child)? else {
            continue;
        };
        match a.kind.as_str() {
            "source" | "runtime" => out.push(a),
            "module" => {
                let wanted = match (silicons, a.target.as_deref()) {
                    (Some(set), Some(t)) => set.contains(t),
                    // No target list, or an untargeted module child:
                    // pin rather than silently drop.
                    _ => true,
                };
                if wanted {
                    out.push(a);
                }
            }
            // Bundles are install-time artifacts (`fluxor install`),
            // not sync pins.
            _ => {}
        }
    }
    fill_content(store, &mut out);
    Ok(out)
}

/// Resolve every declared `[dependencies]` project against the store's
/// project indexes. This is `fluxor update`'s work: pin each dep's
/// sources and runtimes, plus its modules for this project's
/// `[ci].targets`.
pub fn resolve_project(project_root: &Path) -> Result<Vec<Artifact>> {
    let deps = crate::project::dependencies(project_root).map_err(Error::Config)?;
    let store = OciStore::open(crate::oci_store::store_root()?)?;
    let silicons = ci_target_silicons(project_root)?;
    let mut out = Vec::new();
    for dep in deps {
        out.extend(resolve_dependency(&store, &dep.name, silicons.as_ref())?);
    }
    sort_entries(&mut out);
    Ok(out)
}

/// `fluxor update` in the consolidated flow: without `--from`, advance
/// every pin to the deps' latest published state; with
/// `--from snapshot/<name>`, the snapshot's children replace the pins
/// wholesale. Update deliberately does NOT read the existing lockfile
/// — it is the verb that rewrites an unreadable one.
pub fn cmd_update(project_root: &Path, from_snapshot: Option<&str>) -> Result<()> {
    let entries = match from_snapshot {
        None => resolve_project(project_root)?,
        Some(name) => {
            let store = OciStore::open(crate::oci_store::store_root()?)?;
            let reference = if name.starts_with("snapshot/") {
                name.to_string()
            } else {
                format!("snapshot/{name}")
            };
            let desc = store.resolve(&reference)?;
            let idx = read_image_index(&store, &desc.digest)?;
            let mut out = Vec::new();
            for child in &idx.manifests {
                if let Some(a) = artifact_from_descriptor(child)? {
                    out.push(a);
                }
            }
            sort_entries(&mut out);
            fill_content(&store, &mut out);
            out
        }
    };
    let _guard = crate::lockfile::lock_lockfile(project_root)?;
    // Read for REPORTING only. `update` stays the verb that rewrites an
    // unreadable lockfile, so a lock it cannot parse simply yields no
    // comparison rather than an error.
    let before = read_store_lock(project_root)
        .ok()
        .flatten()
        .map(|l| l.artifacts)
        .unwrap_or_default();
    let path = write_store_lock(project_root, &entries)?;
    println!(
        "wrote {} ({} artifact(s): {})",
        path.display(),
        entries.len(),
        describe_update(&before, &entries)
    );
    if let Some(note) = withdrawal_note(project_root, &before, &entries) {
        eprintln!("{note}");
    }
    Ok(())
}

/// How one pin changed across an update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinChange {
    /// Same digest — the pin did not move at all.
    Same,
    /// The digest moved but the artifact did not: identical content
    /// address. The churn this whole design exists to stop, and after
    /// the restamp it should never be reported again.
    Restamped,
    /// The artifact changed.
    Changed,
}

fn classify(old: &Artifact, new: &Artifact) -> PinChange {
    if old.digest == new.digest {
        return PinChange::Same;
    }
    match (&old.content, &new.content) {
        // Same bytes under a new manifest digest. Whether to call that a
        // re-stamp or a rebuild is not knowable from the content alone —
        // both produce identical layers — so the honest label is the one
        // that names the observable: the content did not move.
        (Some(a), Some(b)) if a == b => PinChange::Restamped,
        _ => PinChange::Changed,
    }
}

/// One line describing what an update actually did.
///
/// `wrote fluxor.lock (77 artifact(s))` was true and useless: it could
/// not distinguish 77 modules changing from a publish that changed
/// nothing and merely re-stamped every manifest. Reporting `0 changed`
/// for the second case is the difference between a treadmill and a
/// signal — and a non-zero `re-stamped` count after the migration is the
/// standing regression check that provenance is still outside the
/// manifest.
fn describe_update(before: &[Artifact], after: &[Artifact]) -> String {
    if before.is_empty() {
        return format!("{} new", after.len());
    }
    let key = |a: &Artifact| {
        (
            a.kind.clone(),
            a.project.clone(),
            a.name.clone(),
            a.target.clone(),
        )
    };
    let old: BTreeMap<_, _> = before.iter().map(|a| (key(a), a)).collect();
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for a in after {
        let label = match old.get(&key(a)).map(|o| classify(o, a)) {
            None => "new",
            Some(PinChange::Same) => "unchanged",
            Some(PinChange::Restamped) => "re-stamped",
            Some(PinChange::Changed) => "changed",
        };
        *counts.entry(label).or_default() += 1;
    }
    let retired = before.len()
        - after
            .iter()
            .filter(|a| old.contains_key(&key(a)))
            .count()
            .min(before.len());
    if retired > 0 {
        counts.insert("retired", retired);
    }
    // Always name "changed", even at zero: its absence is the answer
    // most of the time, and an omitted zero reads as an unanswered
    // question.
    counts.entry("changed").or_default();
    counts
        .iter()
        .map(|(k, v)| format!("{v} {k}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Name the digests this update stops holding that somebody else still
/// does — the withdrawal side of the pin ledger.
///
/// A consumer advancing its own pins is correct and unremarkable, and it
/// is also the event that can leave another checkout's pin as the last
/// thing keeping a manifest reachable. The store can see both sides; the
/// checkout doing it could not, until now.
fn withdrawal_note(project_root: &Path, before: &[Artifact], after: &[Artifact]) -> Option<String> {
    let kept: BTreeSet<&str> = after.iter().map(|a| a.digest.as_str()).collect();
    let dropped: Vec<&Artifact> = before
        .iter()
        .filter(|a| !kept.contains(a.digest.as_str()))
        .collect();
    if dropped.is_empty() {
        return None;
    }
    let store_root = crate::oci_store::store_root().ok()?;
    let holders = crate::store_pins::holders(&store_root).ok()?;
    let mut lines = Vec::new();
    for a in dropped {
        let others = holders.others(&a.digest, project_root);
        if others.is_empty() {
            continue;
        }
        lines.push(format!(
            "note: dropping {} {}; {} still pin it",
            a.reference,
            short_hex(a.digest.strip_prefix("sha256:").unwrap_or(&a.digest)),
            others.join(" and ")
        ));
    }
    (!lines.is_empty()).then(|| lines.join("\n"))
}

/// The single ad-hoc pin writer (`fluxor store pin` calls this):
/// upsert one entry under the advisory lock. Keyed by
/// (kind, project, name, target).
pub fn pin_artifact(project_root: &Path, artifact: &Artifact) -> Result<()> {
    let _guard = crate::lockfile::lock_lockfile(project_root)?;
    let mut entries = read_store_lock(project_root)?
        .map(|l| l.artifacts)
        .unwrap_or_default();
    entries.retain(|e| {
        !(e.kind == artifact.kind
            && e.project == artifact.project
            && e.name == artifact.name
            && e.target == artifact.target)
    });
    let mut artifact = artifact.clone();
    if artifact.content.is_none() {
        if let Ok(store) = OciStore::open(crate::oci_store::store_root()?) {
            fill_content(&store, std::slice::from_mut(&mut artifact));
        }
    }
    entries.push(artifact);
    write_store_lock(project_root, &entries)?;
    Ok(())
}

// ── Epoch validation ──────────────────────────────────────────────────

/// Read a blob the lockfile pins, mapping absence onto the one
/// recovery message every pin-follows-a-missing-blob path shares.
pub(crate) fn read_pinned_blob(store: &OciStore, name: &str, digest: &str) -> Result<Vec<u8>> {
    // A pin written before provenance moved out of the manifest names a
    // digest the store may no longer hold; `resolve_pin` follows the
    // restamp alias to the manifest that replaced it — same layers, same
    // target, same epoch. It is a no-op for every other pin.
    let digest = &store.resolve_pin(digest);
    store.read_blob(digest).map_err(|_| {
        Error::Config(format!(
            "artifact '{name}' ({digest}) no longer in store — run `fluxor update`"
        ))
    })
}

/// Read a layer blob a present manifest references. This is NOT
/// "artifact no longer in store" — the manifest is right there; a blob
/// it references is gone or damaged underneath it, which is a store
/// integrity fault. `read_blob`'s own message distinguishes absent from
/// unreadable from failed-integrity, so it is carried through verbatim
/// rather than collapsed.
///
/// Re-publishing alone does not repair the pin: a runtime layer is
/// `sha256(binary)` with no reproducible-build normalisation, so a
/// republish mints a NEW manifest while this pinned one stays broken.
/// The remedies that actually terminate are a republish FOLLOWED BY
/// `fluxor update` (which rewrites the pins), or a re-pull for a store
/// populated from a registry — which is also the only remedy a remote
/// consumer, with no producing repo, can reach.
pub(crate) fn read_manifest_layer_blob(
    store: &OciStore,
    name: &str,
    manifest_digest: &str,
    layer_digest: &str,
) -> Result<Vec<u8>> {
    store.read_blob(layer_digest).map_err(|e| {
        Error::Config(format!(
            "artifact '{name}': manifest {manifest_digest} is present but the layer it \
             references cannot be read ({e}) — the store is inconsistent. Re-publish the \
             artifact in its producing repo and then run `fluxor update` to repin, or \
             re-run `fluxor store pull` if this store was populated from a registry"
        ))
    })
}

/// Read a pinned artifact's manifest by its lockfile digest — the
/// lockfile-side counterpart to `OciStore::read_manifest`, which takes
/// an index descriptor.
pub(crate) fn read_pinned_manifest(store: &OciStore, entry: &Artifact) -> Result<ImageManifest> {
    let bytes = read_pinned_blob(store, &entry.name, &entry.digest)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::Config(format!("corrupt manifest {}: {e}", entry.digest)))
}

/// The current ecosystem epoch (hex). When fluxor itself is a live
/// workspace member, the epoch is computed from the member's TREE
/// (`abi_pin::compute`) — the tree and the compiled-in const diverge
/// exactly during an epoch move, the only moment the check matters.
/// Otherwise the CLI's compiled-in const is authoritative.
pub fn current_epoch_hex(live_projects: &BTreeMap<String, PathBuf>) -> Result<String> {
    for path in live_projects.values() {
        if crate::abi_pin::has_abi_surface(path) {
            return Ok(crate::abi_pin::compute(path)?.digest_hex);
        }
    }
    Ok(crate::hash::abi_surface_digest()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// The two epoch rules over one resolved artifact set
/// (registry_consolidation.md, "Epoch check at sync"):
///
/// 1. **Homogeneity, for everyone**: every artifact must carry the
///    same `io.fluxor.abi-surface`; a mixed set is a hard error naming
///    `fluxor update`. An artifact with NO epoch annotation
///    (pre-cutover publish) is a hard error naming `fluxor publish`
///    in its producer.
/// 2. **Currency, for live members only**: a live member's artifacts
///    must additionally match the current epoch; mismatch is a hard
///    error naming `fluxor workspace publish`.
///
/// `live_projects` maps workspace-member project names to their
/// checkout paths (the fluxor member's tree feeds the current-epoch
/// computation).
pub fn check_epoch(
    entries: &[Artifact],
    store: &OciStore,
    live_projects: &BTreeMap<String, PathBuf>,
) -> Result<()> {
    let mut set_epoch: Option<(String, String)> = None; // (epoch, exemplar)
    let mut live_entries: Vec<(&Artifact, String)> = Vec::new();
    for e in entries {
        let annotations = read_pinned_manifest(store, e)?.annotations;
        let Some(epoch) = annotations.get(ANN_ABI_SURFACE) else {
            return Err(Error::Config(format!(
                "artifact '{}' ({}) carries no epoch annotation (published pre-cutover) — \
                 run `fluxor publish` in {}",
                e.name, e.reference, e.project
            )));
        };
        match &set_epoch {
            None => set_epoch = Some((epoch.clone(), format!("'{}' ({})", e.name, e.project))),
            Some((first, exemplar)) if first != epoch => {
                return Err(Error::Config(format!(
                    "mixed-epoch artifact set: '{}' ({}) is at epoch {} but {exemplar} is at \
                     {} — run `fluxor update` to advance the whole set",
                    e.name,
                    e.project,
                    short_hex(epoch),
                    short_hex(first),
                )));
            }
            Some(_) => {}
        }
        if live_projects.contains_key(&e.project) {
            live_entries.push((e, epoch.clone()));
        }
    }
    if !live_entries.is_empty() {
        let current = current_epoch_hex(live_projects)?;
        for (e, epoch) in live_entries {
            if epoch != current {
                return Err(Error::Config(format!(
                    "artifact '{}' ({}) was published at epoch {} but the current surface \
                     is {} — run `fluxor workspace publish`",
                    e.name,
                    e.project,
                    short_hex(&epoch),
                    short_hex(&current),
                )));
            }
        }
    }
    Ok(())
}

fn short_hex(hex: &str) -> &str {
    &hex[..hex.len().min(12)]
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: &str, project: &str, name: &str, target: Option<&str>) -> Artifact {
        Artifact {
            kind: kind.into(),
            name: name.into(),
            project: project.into(),
            target: target.map(str::to_string),
            digest: format!("sha256:{}", "ab".repeat(32)),
            reference: format!("{project}/{name}:0.0.1"),
            content: None,
        }
    }

    #[test]
    fn lockfile_roundtrip_is_sorted_and_stable() {
        let dir = tempfile::tempdir().unwrap();
        let entries = vec![
            entry("source", "wave", "wave-common", None),
            entry("module", "fluxor", "tls", Some("bcm2712")),
            entry("module", "fluxor", "tls", Some("linux")),
        ];
        write_store_lock(dir.path(), &entries).unwrap();
        let read_back = read_store_lock(dir.path()).unwrap().unwrap();
        assert_eq!(read_back.artifacts.len(), 3);
        // Sorted by (kind, project, name, target): modules first.
        assert_eq!(read_back.artifacts[0].name, "tls");
        assert_eq!(read_back.artifacts[0].target.as_deref(), Some("bcm2712"));
        assert_eq!(read_back.artifacts[2].kind, "source");
        // Byte-stable across a rewrite.
        let one = std::fs::read(lockfile_path(dir.path())).unwrap();
        write_store_lock(dir.path(), &read_back.artifacts).unwrap();
        let two = std::fs::read(lockfile_path(dir.path())).unwrap();
        assert_eq!(one, two);
    }

    #[test]
    fn missing_lockfile_is_none_and_unreadable_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_store_lock(dir.path()).unwrap().is_none());
        std::fs::write(
            dir.path().join("fluxor.lock"),
            "lockfile_version = 1\ngenerated_by = \"fluxor 0.1.0\"\n\n[[crate]]\n\
             name = \"fluxor-abi\"\nversion = \"1.0.0\"\nhash = \"h\"\nsource = \"s\"\n",
        )
        .unwrap();
        let err = read_store_lock(dir.path()).unwrap_err().to_string();
        assert!(err.contains("run `fluxor update`"), "{err}");
    }

    #[test]
    fn pin_artifact_upserts_by_identity() {
        let dir = tempfile::tempdir().unwrap();
        let a = entry("module", "fluxor", "tls", Some("bcm2712"));
        pin_artifact(dir.path(), &a).unwrap();
        let mut b = a.clone();
        b.digest = format!("sha256:{}", "cd".repeat(32));
        pin_artifact(dir.path(), &b).unwrap();
        let lock = read_store_lock(dir.path()).unwrap().unwrap();
        assert_eq!(lock.artifacts.len(), 1, "upsert must replace, not append");
        assert_eq!(lock.artifacts[0].digest, b.digest);
    }

    /// A lock written while the stamp still carried the install root's
    /// path still parses. Every repo holds one, and `deny_unknown_fields`
    /// would otherwise turn dropping the field into a flag day: each lock
    /// unreadable until someone regenerated it, which is the whole point
    /// of keeping the field declared.
    #[test]
    fn a_catalog_stamp_carrying_the_old_source_field_still_parses() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            lockfile_path(dir.path()),
            "artifact = []\n\n[catalog]\ndigest = \"sha256:abc\"\n\
             source = \"/home/someone/checkout\"\n",
        )
        .unwrap();
        let lock = read_store_lock(dir.path()).unwrap().unwrap();
        let catalog = lock.catalog.expect("the stamp parses");
        assert_eq!(catalog.digest, "sha256:abc");
    }

    /// ...and writing it back leaves the path out, so the file stops
    /// carrying one machine's layout into everyone else's tree.
    #[test]
    fn a_written_catalog_stamp_carries_no_source_path() {
        let dir = tempfile::tempdir().unwrap();
        write_store_lock(dir.path(), &[]).unwrap();
        let text = std::fs::read_to_string(lockfile_path(dir.path())).unwrap();
        assert!(!text.contains("source ="), "got:\n{text}");
    }
}
