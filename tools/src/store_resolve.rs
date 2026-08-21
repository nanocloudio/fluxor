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
    let lock = StoreLock { artifacts: sorted };
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
    Ok(path)
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
        },
        "source" => Artifact {
            kind: kind.clone(),
            name: last_segment,
            project,
            target: None,
            digest: d.digest.clone(),
            reference,
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
            }
        }
        "bundle" => Artifact {
            kind: kind.clone(),
            name: last_segment,
            project,
            target: None,
            digest: d.digest.clone(),
            reference,
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
            out
        }
    };
    let _guard = crate::lockfile::lock_lockfile(project_root)?;
    let path = write_store_lock(project_root, &entries)?;
    println!("wrote {} ({} artifact(s))", path.display(), entries.len());
    Ok(())
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
    entries.push(artifact.clone());
    write_store_lock(project_root, &entries)?;
    Ok(())
}

// ── Epoch validation ──────────────────────────────────────────────────

/// Read a blob the lockfile pins, mapping absence onto the one
/// recovery message every pin-follows-a-missing-blob path shares.
pub(crate) fn read_pinned_blob(store: &OciStore, name: &str, digest: &str) -> Result<Vec<u8>> {
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
}
