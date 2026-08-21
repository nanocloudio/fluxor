//! Local OCI image-layout content store for `.fmod` modules and workload
//! bundles (`.context/fmod_registry_plan.md` P1).
//!
//! Layout is the standard OCI image layout: `oci-layout` marker,
//! `blobs/sha256/<hex>` content-addressed blobs, and `index.json` holding one
//! descriptor per tagged artifact. Artifacts are OCI image manifests whose
//! `artifactType` is a fluxor media type (rfc_k8s.md §9); provenance is an
//! annotation (`io.fluxor.provenance = local-build | published`, plus
//! `io.fluxor.source-rev` on local builds), so "just-built sibling repo" vs
//! "published release" is queryable, not guessed.
//!
//! Offline-first invariant: nothing in this module touches the network.
//! Publishing writes only into the local store; consumption (P2) reads only
//! from it. Identical bytes hash to identical digests and are stored once.
//!
//! Determinism: manifest JSON is serialized from field-ordered structs (no
//! timestamps), so re-publishing unchanged content yields byte-identical
//! manifests and therefore identical digests — the P5 promotion property
//! (re-tag, never rebuild) falls out of this.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

// ── Media types (rfc_k8s.md §9) ───────────────────────────────────────

pub const MT_OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const MT_OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const MT_OCI_EMPTY: &str = "application/vnd.oci.empty.v1+json";
pub const MT_FLUXOR_MODULE: &str = "application/vnd.nanocloud.fluxor.module.v1";
pub const MT_FLUXOR_WORKLOAD: &str = "application/vnd.nanocloud.fluxor.workload.v1+json";
pub const MT_FLUXOR_GRAPH: &str = "application/vnd.nanocloud.fluxor.graph.v1+yaml";
pub const MT_FLUXOR_RESOURCES: &str = "application/vnd.nanocloud.fluxor.resources.v1+json";
/// Module manifest.toml metadata carried alongside the `.fmod` layer.
pub const MT_FLUXOR_MODULE_META: &str = "application/vnd.nanocloud.fluxor.module.manifest.v1+toml";
/// A GRAPH IMAGE (`fluxor build --emit=image`): FXSL header + modules
/// blob + config blob — the packaged deployable graph, the sanctioned
/// OTA delivery unit (on RP it is what a flash A/B graph slot holds).
/// The header's own sha256/ABI-pin/epoch travel inside the layer; the
/// annotations mirror target/epoch so admission can happen from the
/// manifest alone, before the layer is fetched.
pub const MT_FLUXOR_IMAGE: &str = "application/vnd.nanocloud.fluxor.image.v1";
/// A complete boot image (e.g. Pi 5 `kernel_2712.img`): kernel +
/// embedded graph, delivered to a staging host (TFTP root, SD writer),
/// never consumed by a running device directly.
pub const MT_FLUXOR_FIRMWARE: &str = "application/vnd.nanocloud.fluxor.firmware.v1";
/// The non-payload prefix of a graph image (FXSL header + module-table
/// header + entry array): the first layer of a LAYERED image manifest.
/// The remaining layers are the raw fmods (`MT_FLUXOR_MODULE`) and the
/// compiled config (`MT_FLUXOR_CONFIG_BIN`), each carrying an
/// `io.fluxor.image.offset` annotation; a consumer reassembles the
/// byte-exact image by placing blobs at their offsets and zero-filling
/// the deterministic alignment gaps (rfc_oci_distribution.md §7.1).
pub const MT_FLUXOR_IMAGE_SKELETON: &str = "application/vnd.nanocloud.fluxor.image.skeleton.v1";
/// Compiled binary graph config (rfc_k8s.md §9).
pub const MT_FLUXOR_CONFIG_BIN: &str = "application/vnd.nanocloud.fluxor.config.v1+bin";
/// Byte offset of a layer within its reassembled graph image (decimal).
pub const ANN_IMAGE_OFFSET: &str = "io.fluxor.image.offset";
/// Staged source tree (canonical uncompressed tar) — the SDK /
/// `<project>-common` trees that consumers `#[path]`/`include!` after
/// `fluxor sync` extraction. Replaces the registry's `.crate` packages.
pub const MT_FLUXOR_SOURCE: &str = "application/vnd.nanocloud.fluxor.source.v1+tar";
/// Host runtime binary (one layer per host triple), `fluxor/run/`
/// namespace only — including the `fluxor` CLI itself.
pub const MT_FLUXOR_RUNTIME: &str = "application/vnd.nanocloud.fluxor.runtime.v1";

// ── Annotation keys ───────────────────────────────────────────────────

pub const ANN_REF_NAME: &str = "org.opencontainers.image.ref.name";
pub const ANN_TITLE: &str = "org.opencontainers.image.title";
pub const ANN_PROVENANCE: &str = "io.fluxor.provenance";
pub const ANN_SOURCE_REV: &str = "io.fluxor.source-rev";
pub const ANN_KIND: &str = "io.fluxor.kind";
pub const ANN_TARGET: &str = "io.fluxor.module.target";
pub const ANN_MODULE_NAME: &str = "io.fluxor.module.name";
/// The ecosystem epoch: the ABI-surface digest the artifact was built
/// against. Sync verifies set homogeneity (everyone) and currency
/// (live members) on this annotation; an artifact without it is not
/// consumable (registry_consolidation.md, epoch rules).
pub const ANN_ABI_SURFACE: &str = "io.fluxor.abi-surface";
/// Token-canonical digest of the artifact's actual inputs, stamped at
/// publish — the per-artifact staleness signal and `workspace publish`
/// work-list key. Runtimes carry `source-rev` + a dirty bit instead.
pub const ANN_INPUT_DIGEST: &str = "io.fluxor.input-digest";
/// The input digest the project's `ci` gate last passed on, when known.
/// Information, never a gate: green-ci is required only at the future
/// promotion-to-`published` re-tag.
pub const ANN_CI_DIGEST: &str = "io.fluxor.ci-digest";
/// Host triple of a runtime artifact's binary layer.
pub const ANN_RUNTIME_TRIPLE: &str = "io.fluxor.runtime.triple";

pub const PROVENANCE_LOCAL: &str = "local-build";
pub const PROVENANCE_PUBLISHED: &str = "published";

/// The canonical OCI empty blob `{}` used as artifact config.
const EMPTY_CONFIG: &[u8] = b"{}";

// ── Wire structs (field order fixed → deterministic JSON) ─────────────

/// Ordered map alias: BTreeMap gives sorted, stable annotation encoding.
pub type Annotations = std::collections::BTreeMap<String, String>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Descriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Annotations::is_empty")]
    pub annotations: Annotations,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "mediaType")]
    pub media_type: String,
    #[serde(rename = "artifactType", skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
    #[serde(default, skip_serializing_if = "Annotations::is_empty")]
    pub annotations: Annotations,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageIndex {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "mediaType")]
    pub media_type: String,
    #[serde(default)]
    pub manifests: Vec<Descriptor>,
}

// ── Store root resolution ─────────────────────────────────────────────

/// Resolve the store root: `$FLUXOR_STORE` override, else
/// `$XDG_DATA_HOME/fluxor/store`, else `$HOME/.local/share/fluxor/store`.
pub fn store_root() -> Result<PathBuf> {
    if let Some(v) = std::env::var_os("FLUXOR_STORE") {
        return Ok(PathBuf::from(v));
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("fluxor").join("store"));
        }
    }
    let home = std::env::var_os("HOME").ok_or_else(|| {
        Error::Config(
            "cannot resolve store root: none of $FLUXOR_STORE, $XDG_DATA_HOME, $HOME set".into(),
        )
    })?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("fluxor")
        .join("store"))
}

// ── Store ─────────────────────────────────────────────────────────────

pub struct OciStore {
    root: PathBuf,
}

impl OciStore {
    /// Open (creating if needed) an OCI image-layout store at `root`.
    /// Rejects a directory that exists but is not an OCI layout.
    pub fn open(root: impl Into<PathBuf>) -> Result<OciStore> {
        let root = root.into();
        let marker = root.join("oci-layout");
        let init_sentinel = root.join(".fluxor-store-init");
        // Pre-lock guard: refuse to touch a non-empty directory that is
        // neither a store (oci-layout) nor OUR interrupted init
        // (.fluxor-store-init) — a Fluxor-specific sentinel, not a generic
        // filename, is what authorizes writing into an existing directory.
        // Done before creating the lock file so a foreign directory is left
        // completely untouched (not even an index.lock).
        if root.is_dir() && !marker.exists() && !init_sentinel.exists() {
            let has_other = fs::read_dir(&root)?
                .filter_map(|e| e.ok())
                .any(|e| e.file_name() != "index.lock");
            if has_other {
                return Err(Error::Config(format!(
                    "{} exists, is not empty, and is not a fluxor store — \
                     refusing to initialize over it",
                    root.display()
                )));
            }
        }
        // Create the root so the lock can live in it, then do ALL
        // initialization under the index lock — first-open, recovery, and
        // every later mutation share one critical section.
        fs::create_dir_all(&root)?;
        let store = OciStore { root };
        let _lock = store.lock_index()?;
        let index = store.root.join("index.json");

        if marker.exists() {
            let text = fs::read_to_string(&marker)?;
            let v: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| Error::Config(format!("corrupt {}: {e}", marker.display())))?;
            if v.get("imageLayoutVersion").and_then(|v| v.as_str()) != Some("1.0.0") {
                return Err(Error::Config(format!(
                    "{}: unsupported imageLayoutVersion (want 1.0.0)",
                    marker.display()
                )));
            }
            // The marker is written LAST during init, so a store carrying it
            // MUST have an index. A missing index here is corruption, not a
            // fresh state — silently recreating an empty one would orphan
            // every blob and lose all tag metadata. Fail loudly instead.
            if !index.exists() {
                return Err(Error::Config(format!(
                    "{}: oci-layout marker present but index.json is missing — \
                     corrupt store (refusing to silently reinitialize and orphan blobs)",
                    store.root.display()
                )));
            }
            return Ok(store);
        }

        // No marker. Recovery (our sentinel present) or fresh init. Re-check
        // foreign-ness under the lock (race-safe), gating recovery on the
        // Fluxor-specific sentinel — generic names like index.json or blobs/
        // are NOT adopted unless the sentinel proves this is our own init.
        let recovering = init_sentinel.exists();
        if !recovering {
            let has_other = fs::read_dir(&store.root)?
                .filter_map(|e| e.ok())
                .any(|e| e.file_name() != "index.lock");
            if has_other {
                return Err(Error::Config(format!(
                    "{} exists, is not empty, and is not a fluxor store — \
                     refusing to initialize over it",
                    store.root.display()
                )));
            }
            // Claim the directory BEFORE writing anything else, so a crash
            // mid-init leaves the sentinel for the next open to recover.
            fs::write(&init_sentinel, b"fluxor-oci-store-init\n")?;
        }
        // Redirection guard: refuse a symlinked blobs/ (could send writes
        // outside the store).
        let blobs = store.root.join("blobs");
        if fs::symlink_metadata(&blobs)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(Error::Config(format!(
                "{}: blobs is a symlink — refusing",
                store.root.display()
            )));
        }
        fs::create_dir_all(blobs.join("sha256"))?;
        if !index.exists() {
            let empty = ImageIndex {
                schema_version: 2,
                media_type: "application/vnd.oci.image.index.v1+json".into(),
                manifests: Vec::new(),
            };
            write_atomic(&index, serde_json::to_string(&empty)?.as_bytes())?;
        }
        // Marker LAST: its presence certifies a fully-formed store.
        fs::write(&marker, b"{\"imageLayoutVersion\":\"1.0.0\"}")?;
        let _ = fs::remove_file(&init_sentinel);
        drop(_lock);
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Path of the blob for `sha256:<hex>` digest (whether or not present).
    pub fn blob_path(&self, digest: &str) -> Result<PathBuf> {
        let hex = digest
            .strip_prefix("sha256:")
            .ok_or_else(|| Error::Config(format!("digest '{digest}' is not sha256:-prefixed")))?;
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Config(format!("malformed digest '{digest}'")));
        }
        Ok(self.root.join("blobs").join("sha256").join(hex))
    }

    pub fn has_blob(&self, digest: &str) -> bool {
        self.blob_path(digest).map(|p| p.exists()).unwrap_or(false)
    }

    /// Store bytes content-addressed; returns `(digest, size)`. Writing an
    /// already-present blob verifies it (content addressing means the path
    /// name promises the bytes); a corrupt existing blob is repaired in
    /// place with the correct content rather than silently trusted.
    pub fn put_blob(&self, bytes: &[u8]) -> Result<(String, u64)> {
        let digest = sha256_hex_prefixed(bytes);
        let path = self.blob_path(&digest)?;
        let healthy = match fs::read(&path) {
            Ok(existing) => sha256_hex_prefixed(&existing) == digest,
            Err(_) => false,
        };
        if !healthy {
            write_atomic(&path, bytes)?;
        }
        Ok((digest, bytes.len() as u64))
    }

    /// Read a blob and verify its bytes hash to the digest that names it —
    /// every consumer gets integrity for free; a substituted or corrupted
    /// file under a content-addressed path is an error, never data.
    ///
    /// The three failure modes are distinct and stay distinct in the
    /// message: absent, present but unreadable (`EACCES`, `EIO`), and
    /// present but failing integrity. Callers word remedies off them —
    /// a corrupt blob is not a missing one.
    pub fn read_blob(&self, digest: &str) -> Result<Vec<u8>> {
        let path = self.blob_path(digest)?;
        let bytes = fs::read(&path).map_err(|e| {
            let what = if e.kind() == std::io::ErrorKind::NotFound {
                "not in store"
            } else {
                "unreadable in store"
            };
            Error::Config(format!("blob {digest} {what} {}: {e}", self.root.display()))
        })?;
        if sha256_hex_prefixed(&bytes) != digest {
            return Err(Error::Config(format!(
                "blob {digest} failed integrity verification in store {}",
                self.root.display()
            )));
        }
        Ok(bytes)
    }

    /// Exclusive advisory lock over index mutations. Concurrent publishers
    /// (e.g. two sibling-repo builds publishing into the shared store)
    /// serialize their read-modify-write of index.json here; blob writes
    /// need no lock (content-addressed, idempotent).
    fn lock_index(&self) -> Result<fs::File> {
        let lock_path = self.root.join("index.lock");
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)?;
        f.lock()
            .map_err(|e| Error::Config(format!("lock {}: {e}", lock_path.display())))?;
        Ok(f)
    }

    pub fn read_index(&self) -> Result<ImageIndex> {
        let text = fs::read_to_string(self.root.join("index.json"))?;
        serde_json::from_str(&text).map_err(|e| Error::Config(format!("corrupt index.json: {e}")))
    }

    fn write_index(&self, index: &ImageIndex) -> Result<()> {
        write_atomic(
            &self.root.join("index.json"),
            serde_json::to_string(index)?.as_bytes(),
        )
    }

    /// Publish an artifact manifest and tag it. Docker-like tag semantics:
    /// a tag is a mutable pointer — re-tagging replaces the descriptor that
    /// previously held the same `ref.name`. The same manifest digest may be
    /// listed under several tags.
    pub fn tag_manifest(&self, manifest: &ImageManifest, ref_name: &str) -> Result<Descriptor> {
        let _index_lock = self.lock_index()?;
        self.tag_manifest_locked(manifest, ref_name)
    }

    /// Body of `tag_manifest` for callers that already hold the index lock
    /// (the publish operations, which must cover their blob writes and the
    /// index update in ONE critical section — otherwise a concurrent
    /// `remove`'s sweep can delete just-written blobs before their
    /// descriptor lands in the index).
    fn tag_manifest_locked(&self, manifest: &ImageManifest, ref_name: &str) -> Result<Descriptor> {
        let bytes = serde_json::to_vec(manifest)?;
        let (digest, size) = self.put_blob(&bytes)?;
        let mut annotations = manifest.annotations.clone();
        annotations.insert(ANN_REF_NAME.into(), ref_name.to_string());
        let desc = Descriptor {
            media_type: MT_OCI_MANIFEST.into(),
            digest,
            size,
            annotations,
        };
        let mut index = self.read_index()?;
        let displaced: Vec<Descriptor> = index
            .manifests
            .iter()
            .filter(|d| {
                d.annotations.get(ANN_REF_NAME).map(String::as_str) == Some(ref_name)
                    && d.digest != desc.digest
            })
            .cloned()
            .collect();
        index
            .manifests
            .retain(|d| d.annotations.get(ANN_REF_NAME).map(String::as_str) != Some(ref_name));
        index.manifests.push(desc.clone());
        self.write_index(&index)?;

        // Retagging is the only way a manifest leaves the index without
        // `remove`; sweep the displaced closure now or its blobs become
        // unreachable through the API forever (unbounded growth under
        // repeated `latest` publishes). A sweep that cannot prove itself safe
        // leaves the blobs in place and warns rather than failing the
        // publish — a bounded leak is preferable to a failed publish.
        if !displaced.is_empty() {
            match self.sweep_with_roots(&index, &displaced) {
                Ok(_removed) => {}
                Err(e) => eprintln!(
                    "warning: retag of '{ref_name}' could not sweep the displaced \
                     artifact ({e}); its blobs remain until a future remove"
                ),
            }
        }
        Ok(desc)
    }

    /// Resolve a reference — a tag (`name:ver`), a full `sha256:<hex>`
    /// digest, or an unambiguous digest-hex prefix — to its descriptor.
    pub fn resolve(&self, reference: &str) -> Result<Descriptor> {
        let index = self.read_index()?;
        if let Some(d) = index
            .manifests
            .iter()
            .find(|d| d.annotations.get(ANN_REF_NAME).map(String::as_str) == Some(reference))
        {
            return Ok(d.clone());
        }
        let hex = reference.strip_prefix("sha256:").unwrap_or(reference);
        if !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            let matches: Vec<&Descriptor> = index
                .manifests
                .iter()
                .filter(|d| {
                    d.digest
                        .strip_prefix("sha256:")
                        .unwrap_or("")
                        .starts_with(hex)
                })
                .collect();
            match matches.len() {
                1 => return Ok(matches[0].clone()),
                n if n > 1 => {
                    return Err(Error::Config(format!(
                        "reference '{reference}' is ambiguous ({n} matches)"
                    )))
                }
                _ => {}
            }
        }
        Err(Error::Config(format!(
            "reference '{reference}' not found in store {}",
            self.root.display()
        )))
    }

    pub fn read_manifest(&self, desc: &Descriptor) -> Result<ImageManifest> {
        let bytes = self.read_blob(&desc.digest)?;
        serde_json::from_str(&String::from_utf8_lossy(&bytes))
            .map_err(|e| Error::Config(format!("corrupt manifest {}: {e}", desc.digest)))
    }

    /// The `.fmod` layer of a module artifact: `(layer digest, blob path)`.
    /// Errors when the manifest is not a module artifact or the blob is
    /// missing from the store.
    pub fn module_fmod_blob(&self, manifest: &ImageManifest) -> Result<(String, PathBuf)> {
        if manifest.artifact_type.as_deref() != Some(MT_FLUXOR_MODULE) {
            return Err(Error::Config(format!(
                "artifact is not a fluxor module (artifactType {:?})",
                manifest.artifact_type
            )));
        }
        let layer = manifest
            .layers
            .iter()
            .find(|l| l.media_type == MT_FLUXOR_MODULE)
            .ok_or_else(|| Error::Config("module artifact has no .fmod layer".into()))?;
        // Content verification, not an existence check: `store pin` relies
        // on this to refuse a pin that would immediately fail at consume
        // time. `read_blob` hashes the bytes against the digest.
        self.read_blob(&layer.digest)?;
        Ok((layer.digest.clone(), self.blob_path(&layer.digest)?))
    }

    /// Return the verified bytes of a module artifact's `manifest.toml`
    /// layer, or `None` if the artifact predates the metadata layer.
    /// The symmetric partner of `module_fmod_blob`: wiring/port
    /// resolution needs the manifest a pinned module ships alongside its
    /// `.fmod`, so a store-only module resolves BOTH layers from the same
    /// content-addressed artifact and its ports can never diverge from its
    /// bytes. `read_blob` hashes the bytes against the layer digest.
    pub fn module_manifest_toml_blob(&self, manifest: &ImageManifest) -> Result<Option<Vec<u8>>> {
        if manifest.artifact_type.as_deref() != Some(MT_FLUXOR_MODULE) {
            return Err(Error::Config(format!(
                "artifact is not a fluxor module (artifactType {:?})",
                manifest.artifact_type
            )));
        }
        let Some(layer) = manifest
            .layers
            .iter()
            .find(|l| l.media_type == MT_FLUXOR_MODULE_META)
        else {
            return Ok(None);
        };
        Ok(Some(self.read_blob(&layer.digest)?))
    }

    /// Remove a reference from the index, then delete every blob no longer
    /// reachable from any remaining indexed manifest. Content shared with
    /// other tags survives (content addressing does the refcounting).
    pub fn remove(&self, reference: &str) -> Result<Vec<String>> {
        let _index_lock = self.lock_index()?;
        let victim = self.resolve(reference)?;
        let mut index = self.read_index()?;
        // Remove by exact descriptor identity: a tag removes one pointer; a
        // digest reference removes every tag of that manifest.
        let by_tag = victim.annotations.get(ANN_REF_NAME).map(String::as_str) == Some(reference);
        let survives = |d: &Descriptor| {
            if by_tag {
                d.annotations.get(ANN_REF_NAME).map(String::as_str) != Some(reference)
            } else {
                d.digest != victim.digest
            }
        };
        // Fail-closed validation FIRST, before any mutation: every manifest
        // that will remain live must be readable (its closure feeds the
        // keep-set) — via `add_closure`, which understands both image
        // manifests and image indexes (project indexes, snapshots). If this
        // errors, the index is untouched and the command is safely
        // retryable.
        let mut probe = BTreeSet::new();
        let mut probe_tiers = BTreeMap::new();
        for d in index.manifests.iter().filter(|d| survives(d)) {
            self.add_closure(d, &mut probe, &mut probe_tiers)
                .map_err(|e| {
                    Error::Config(format!(
                        "refusing to remove: live manifest {} is unreadable ({e})",
                        d.digest
                    ))
                })?;
        }
        index.manifests.retain(survives);
        self.write_index(&index)?;

        // Sweep the victim's now-unreachable closure. Readability of every
        // remaining manifest was proven above, before the index write.
        self.sweep_with_roots(&index, core::slice::from_ref(&victim))
    }
}

// ── Publish operations ────────────────────────────────────────────────

/// Everything needed to publish one built module into the store.
pub struct ModulePublish<'a> {
    pub name: &'a str,
    /// Silicon target the `.fmod` was built for (e.g. `bcm2712`, `linux`).
    pub target: &'a str,
    pub fmod_bytes: &'a [u8],
    /// The module's `manifest.toml` text, carried as a metadata layer.
    pub manifest_toml: Option<&'a str>,
    /// `local-build` or `published`.
    pub provenance: &'a str,
    /// Git revision of the publishing tree (annotated when known).
    pub source_rev: Option<&'a str>,
    /// Tag, e.g. `blinky:1.2.0`.
    pub ref_name: &'a str,
}

/// Publish one `.fmod` as an OCI artifact. Returns the tagged descriptor.
pub fn publish_module(store: &OciStore, m: &ModulePublish<'_>) -> Result<Descriptor> {
    // One critical section over blob writes + index update (see
    // `tag_manifest_locked`).
    let _index_lock = store.lock_index()?;
    let (config_digest, config_size) = store.put_blob(EMPTY_CONFIG)?;
    let (fmod_digest, fmod_size) = store.put_blob(m.fmod_bytes)?;

    let mut layers = vec![Descriptor {
        media_type: MT_FLUXOR_MODULE.into(),
        digest: fmod_digest,
        size: fmod_size,
        annotations: one_annotation(ANN_TITLE, &format!("{}.fmod", m.name)),
    }];
    if let Some(toml_text) = m.manifest_toml {
        let (d, s) = store.put_blob(toml_text.as_bytes())?;
        layers.push(Descriptor {
            media_type: MT_FLUXOR_MODULE_META.into(),
            digest: d,
            size: s,
            annotations: one_annotation(ANN_TITLE, "manifest.toml"),
        });
    }

    let mut annotations = Annotations::new();
    annotations.insert(ANN_KIND.into(), "module".into());
    annotations.insert(ANN_MODULE_NAME.into(), m.name.into());
    annotations.insert(ANN_PROVENANCE.into(), m.provenance.into());
    annotations.insert(ANN_TARGET.into(), m.target.into());
    if let Some(rev) = m.source_rev {
        annotations.insert(ANN_SOURCE_REV.into(), rev.into());
    }

    let manifest = ImageManifest {
        schema_version: 2,
        media_type: MT_OCI_MANIFEST.into(),
        artifact_type: Some(MT_FLUXOR_MODULE.into()),
        config: Descriptor {
            media_type: MT_OCI_EMPTY.into(),
            digest: config_digest,
            size: config_size,
            annotations: Annotations::new(),
        },
        layers,
        annotations,
    };
    store.tag_manifest_locked(&manifest, m.ref_name)
}

/// Everything needed to publish a device artifact (graph image or
/// firmware image) into the store. `epoch` is the image header's epoch
/// (image kind only); `abi_surface_hex` is the surface digest the
/// artifact was built against, mirrored from the image header pin so a
/// consumer can reject an incompatible artifact from the manifest
/// alone.
pub struct DeviceArtifactPublish<'a> {
    /// `"image"` or `"firmware"`.
    pub kind: &'a str,
    pub bytes: &'a [u8],
    pub name: &'a str,
    pub target: &'a str,
    pub epoch: Option<u64>,
    pub abi_surface_hex: Option<&'a str>,
    pub provenance: &'a str,
    pub source_rev: Option<&'a str>,
    pub ref_name: &'a str,
}

/// Image-header epoch annotation (`io.fluxor.image.epoch`, decimal).
pub const ANN_IMAGE_EPOCH: &str = "io.fluxor.image.epoch";

/// One layer of an exploded graph image: the blob plus where it sits in
/// the reassembled image.
pub struct ImageLayer<'a> {
    pub media_type: &'a str,
    pub bytes: &'a [u8],
    pub offset: usize,
    /// Human-facing layer title (module name, "skeleton", "config").
    pub title: &'a str,
}

/// Explode a packed graph image into its layered form: skeleton (all
/// bytes before the first fmod), one layer per fmod, one config layer.
/// Pure function over the FXSL/FXMT formats — returns borrowed slices
/// into `image`. The layers, placed at their offsets with zero-filled
/// gaps, reproduce the hashed regions of `image` byte-for-byte (the
/// modules-to-config alignment gap is outside the hashed regions).
pub fn explode_image(image: &[u8]) -> Result<Vec<ImageLayer<'_>>> {
    const FXSL_MAGIC: u32 = 0x4C53_5846;
    const FXMT_MAGIC: u32 = 0x544D_5846;
    const TABLE_HEADER_SIZE: usize = 16;
    const ENTRY_SIZE: usize = 16;
    if image.len() < 96 || u32::from_le_bytes(image[0..4].try_into().unwrap()) != FXSL_MAGIC {
        return Err(Error::Config("not a graph image (no FXSL header)".into()));
    }
    let modules_offset = u32::from_le_bytes(image[16..20].try_into().unwrap()) as usize;
    let modules_size = u32::from_le_bytes(image[20..24].try_into().unwrap()) as usize;
    let config_offset = u32::from_le_bytes(image[24..28].try_into().unwrap()) as usize;
    let config_size = u32::from_le_bytes(image[28..32].try_into().unwrap()) as usize;
    if modules_offset + modules_size > image.len() || config_offset + config_size > image.len() {
        return Err(Error::Config("image regions out of bounds".into()));
    }
    let table = &image[modules_offset..modules_offset + modules_size];
    if table.len() < TABLE_HEADER_SIZE
        || u32::from_le_bytes(table[0..4].try_into().unwrap()) != FXMT_MAGIC
    {
        return Err(Error::Config("image has no FXMT module table".into()));
    }
    let count = table[5] as usize;
    if TABLE_HEADER_SIZE + count * ENTRY_SIZE > table.len() {
        return Err(Error::Config("module table entries out of bounds".into()));
    }
    let mut layers = Vec::with_capacity(count + 2);
    // Entries are laid out in payload order; the skeleton ends where
    // the first fmod begins.
    let mut fmods: Vec<(usize, usize)> = Vec::with_capacity(count); // (table-rel offset, size)
    for i in 0..count {
        let e = TABLE_HEADER_SIZE + i * ENTRY_SIZE;
        let off = u32::from_le_bytes(table[e + 4..e + 8].try_into().unwrap()) as usize;
        let size = u32::from_le_bytes(table[e + 8..e + 12].try_into().unwrap()) as usize;
        if off + size > table.len() {
            return Err(Error::Config(format!("fmod {i} out of table bounds")));
        }
        fmods.push((off, size));
    }
    let first_fmod = fmods.iter().map(|&(o, _)| o).min().unwrap_or(table.len());
    layers.push(ImageLayer {
        media_type: MT_FLUXOR_IMAGE_SKELETON,
        bytes: &image[0..modules_offset + first_fmod],
        offset: 0,
        title: "skeleton",
    });
    for (i, &(off, size)) in fmods.iter().enumerate() {
        let e = TABLE_HEADER_SIZE + i * ENTRY_SIZE;
        let _name_hash = u32::from_le_bytes(table[e..e + 4].try_into().unwrap());
        layers.push(ImageLayer {
            media_type: MT_FLUXOR_MODULE,
            bytes: &table[off..off + size],
            offset: modules_offset + off,
            title: "fmod",
        });
    }
    layers.push(ImageLayer {
        media_type: MT_FLUXOR_CONFIG_BIN,
        bytes: &image[config_offset..config_offset + config_size],
        offset: config_offset,
        title: "config",
    });
    // Payload order for deterministic manifests and sequential fetch.
    layers.sort_by_key(|l| l.offset);
    Ok(layers)
}

/// Publish a LAYERED graph image: skeleton + per-fmod + config
/// layers, offsets annotated (rfc_oci_distribution.md §7.1). Fmod
/// layer blobs are byte-identical to individually published module
/// artifacts, so the store (and any registry) deduplicates them.
pub fn publish_layered_image(
    store: &OciStore,
    a: &DeviceArtifactPublish<'_>,
) -> Result<Descriptor> {
    let layers_src = explode_image(a.bytes)?;
    let _index_lock = store.lock_index()?;
    let (config_digest, config_size) = store.put_blob(EMPTY_CONFIG)?;
    let mut layers = Vec::with_capacity(layers_src.len());
    for l in &layers_src {
        let (d, sz) = store.put_blob(l.bytes)?;
        let mut ann = one_annotation(ANN_IMAGE_OFFSET, &l.offset.to_string());
        ann.insert(ANN_TITLE.into(), l.title.into());
        layers.push(Descriptor {
            media_type: l.media_type.into(),
            digest: d,
            size: sz,
            annotations: ann,
        });
    }
    let mut annotations = Annotations::new();
    annotations.insert(ANN_KIND.into(), a.kind.into());
    annotations.insert(ANN_MODULE_NAME.into(), a.name.into());
    annotations.insert(ANN_TARGET.into(), a.target.into());
    annotations.insert(ANN_PROVENANCE.into(), a.provenance.into());
    if let Some(e) = a.epoch {
        annotations.insert(ANN_IMAGE_EPOCH.into(), e.to_string());
    }
    if let Some(hex) = a.abi_surface_hex {
        annotations.insert(ANN_ABI_SURFACE.into(), hex.into());
    }
    if let Some(rev) = a.source_rev {
        annotations.insert(ANN_SOURCE_REV.into(), rev.into());
    }
    let manifest = ImageManifest {
        schema_version: 2,
        media_type: MT_OCI_MANIFEST.into(),
        artifact_type: Some(MT_FLUXOR_IMAGE.into()),
        config: Descriptor {
            media_type: MT_OCI_EMPTY.into(),
            digest: config_digest,
            size: config_size,
            annotations: Annotations::new(),
        },
        layers,
        annotations,
    };
    store.tag_manifest_locked(&manifest, a.ref_name)
}

/// Publish a device artifact (graph image / firmware image) as a
/// one-layer OCI artifact. Unlike project artifacts these are
/// *deployment encodings*: they exist so a device (graph image) or a
/// staging host (firmware) can pull them from a registry — the
/// store-side consume paths never read them.
pub fn publish_device_artifact(
    store: &OciStore,
    a: &DeviceArtifactPublish<'_>,
) -> Result<Descriptor> {
    let media_type = match a.kind {
        "image" => MT_FLUXOR_IMAGE,
        "firmware" => MT_FLUXOR_FIRMWARE,
        other => {
            return Err(Error::Config(format!(
                "unknown device artifact kind '{other}' (image|firmware)"
            )))
        }
    };
    let _index_lock = store.lock_index()?;
    let (config_digest, config_size) = store.put_blob(EMPTY_CONFIG)?;
    let (blob_digest, blob_size) = store.put_blob(a.bytes)?;
    let layers = vec![Descriptor {
        media_type: media_type.into(),
        digest: blob_digest,
        size: blob_size,
        annotations: one_annotation(ANN_TITLE, a.name),
    }];
    let mut annotations = Annotations::new();
    annotations.insert(ANN_KIND.into(), a.kind.into());
    annotations.insert(ANN_MODULE_NAME.into(), a.name.into());
    annotations.insert(ANN_TARGET.into(), a.target.into());
    annotations.insert(ANN_PROVENANCE.into(), a.provenance.into());
    if let Some(e) = a.epoch {
        annotations.insert(ANN_IMAGE_EPOCH.into(), e.to_string());
    }
    if let Some(hex) = a.abi_surface_hex {
        annotations.insert(ANN_ABI_SURFACE.into(), hex.into());
    }
    if let Some(rev) = a.source_rev {
        annotations.insert(ANN_SOURCE_REV.into(), rev.into());
    }
    let manifest = ImageManifest {
        schema_version: 2,
        media_type: MT_OCI_MANIFEST.into(),
        artifact_type: Some(media_type.into()),
        config: Descriptor {
            media_type: MT_OCI_EMPTY.into(),
            digest: config_digest,
            size: config_size,
            annotations: Annotations::new(),
        },
        layers,
        annotations,
    };
    store.tag_manifest_locked(&manifest, a.ref_name)
}

/// Everything needed to publish a workload bundle into the store.
pub struct BundlePublish<'a> {
    pub workload_json: &'a str,
    pub resources_json: &'a [u8],
    pub graph_yaml: &'a [u8],
    pub provenance: &'a str,
    pub source_rev: Option<&'a str>,
    pub ref_name: &'a str,
}

/// Publish a workload bundle. The manifest is validated first; every module
/// digest an implementation pins must already be a blob in the store —
/// publishing is where the offline-first closure is established, so a bundle
/// referencing absent modules is rejected with the missing digests listed.
pub fn publish_bundle(store: &OciStore, b: &BundlePublish<'_>) -> Result<Descriptor> {
    // One critical section over blob writes + index update (see
    // `tag_manifest_locked`).
    let _index_lock = store.lock_index()?;
    let manifest = crate::workload::parse_manifest(b.workload_json).map_err(Error::Config)?;
    let report = crate::workload::validate(&manifest);
    if !report.is_ok() {
        return Err(Error::Config(format!(
            "bundle '{}' failed validation: {}",
            manifest.name,
            report.errors.join("; ")
        )));
    }

    // Verify the bundle artifacts against the digests the manifest pins for
    // at least one implementation (each implementation may pin its own graph/
    // resources; all pinned digests that match the provided bytes are fine —
    // what matters is the provided bytes are pinned *somewhere*).
    let resources_digest = sha256_hex_prefixed(b.resources_json);
    let graph_digest = sha256_hex_prefixed(b.graph_yaml);
    let pins_resources = manifest
        .implementations
        .iter()
        .any(|i| i.resources.digest == resources_digest);
    let pins_graph = manifest
        .implementations
        .iter()
        .any(|i| i.graph.digest == graph_digest);
    if !pins_resources {
        return Err(Error::Config(format!(
            "resources.json ({resources_digest}) is not pinned by any implementation"
        )));
    }
    if !pins_graph {
        return Err(Error::Config(format!(
            "graph.yaml ({graph_digest}) is not pinned by any implementation"
        )));
    }

    // Offline-first closure: every referenced module must already be present.
    let mut missing: Vec<String> = Vec::new();
    let mut module_layers: Vec<Descriptor> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for imp in &manifest.implementations {
        for mr in &imp.modules {
            if !seen.insert(mr.digest.clone()) {
                continue;
            }
            // Content verification, not a metadata existence check: the
            // bundle pins these digests, so the bytes behind them must
            // actually hash to them at publish time.
            match store.read_blob(&mr.digest) {
                Ok(bytes) => module_layers.push(Descriptor {
                    media_type: MT_FLUXOR_MODULE.into(),
                    digest: mr.digest.clone(),
                    size: bytes.len() as u64,
                    annotations: one_annotation(ANN_TITLE, &format!("{}.fmod", mr.name)),
                }),
                Err(e) => missing.push(format!("{} ({}): {e}", mr.name, mr.digest)),
            }
        }
    }
    if !missing.is_empty() {
        return Err(Error::Config(format!(
            "bundle '{}' references modules not in the store — publish them first \
             (`fluxor modules publish`): {}",
            manifest.name,
            missing.join(", ")
        )));
    }

    let (config_digest, config_size) = store.put_blob(EMPTY_CONFIG)?;
    let (wl_digest, wl_size) = store.put_blob(b.workload_json.as_bytes())?;
    let (res_digest, res_size) = store.put_blob(b.resources_json)?;
    let (graph_blob_digest, graph_size) = store.put_blob(b.graph_yaml)?;

    let mut layers = vec![
        Descriptor {
            media_type: MT_FLUXOR_WORKLOAD.into(),
            digest: wl_digest,
            size: wl_size,
            annotations: one_annotation(ANN_TITLE, "workload.json"),
        },
        Descriptor {
            media_type: MT_FLUXOR_RESOURCES.into(),
            digest: res_digest,
            size: res_size,
            annotations: one_annotation(ANN_TITLE, "resources.json"),
        },
        Descriptor {
            media_type: MT_FLUXOR_GRAPH.into(),
            digest: graph_blob_digest,
            size: graph_size,
            annotations: one_annotation(ANN_TITLE, "graph.yaml"),
        },
    ];
    layers.extend(module_layers);

    let mut annotations = Annotations::new();
    annotations.insert(ANN_KIND.into(), "bundle".into());
    annotations.insert(ANN_PROVENANCE.into(), b.provenance.into());
    if let Some(rev) = b.source_rev {
        annotations.insert(ANN_SOURCE_REV.into(), rev.into());
    }

    let oci_manifest = ImageManifest {
        schema_version: 2,
        media_type: MT_OCI_MANIFEST.into(),
        artifact_type: Some(MT_FLUXOR_WORKLOAD.into()),
        config: Descriptor {
            media_type: MT_OCI_EMPTY.into(),
            digest: config_digest,
            size: config_size,
            annotations: Annotations::new(),
        },
        layers,
        annotations,
    };
    store.tag_manifest_locked(&oci_manifest, b.ref_name)
}

// ── Source / runtime artifacts + transactional batch publish ─────────
//
// The consolidated publish path (registry_consolidation.md P1): every
// artifact kind is prepared (blobs staged, manifest built) and then a
// whole publish commits in ONE locked index write — partial publish is
// impossible by construction. Each artifact is tagged both `name:ver`
// and `name:latest` (the tag `:latest` IS "most recently published
// digest"; version strings are labels under never-bump).

/// Project-association annotation: which project published an artifact.
/// The project index is derived from it, so ownership never has to be
/// inferred from tag shapes or name prefixes.
pub const ANN_PROJECT: &str = "io.fluxor.project";

/// A staged-but-uncommitted artifact: blobs are in the store, the
/// manifest is built, no tag exists yet. Produced under the caller's
/// batch lock by the `prepare_*` fns; committed by `commit_publish`.
pub struct Prepared {
    pub manifest: ImageManifest,
    /// Canonical tag, e.g. `bcm2712/tls:0.0.1` or `fluxor/src/fluxor-abi:0.0.1`.
    pub ref_name: String,
    /// Moving tag repointed on every publish, e.g. `bcm2712/tls:latest`.
    pub latest_ref: String,
}

/// Common annotation payload every prepared artifact carries.
pub struct ArtifactMeta<'a> {
    pub project: &'a str,
    pub provenance: &'a str,
    pub source_rev: Option<&'a str>,
    /// The ecosystem epoch (hex) the artifact was built against.
    pub abi_surface_hex: &'a str,
    /// Token-canonical input digest (hex); `None` for runtimes, whose
    /// binary layer digest already identifies their inputs.
    pub input_digest_hex: Option<&'a str>,
    /// Input digest the project's ci gate last passed on, when known.
    pub ci_digest_hex: Option<&'a str>,
}

fn base_annotations(kind: &str, meta: &ArtifactMeta<'_>) -> Annotations {
    let mut a = Annotations::new();
    a.insert(ANN_KIND.into(), kind.into());
    a.insert(ANN_PROJECT.into(), meta.project.into());
    a.insert(ANN_PROVENANCE.into(), meta.provenance.into());
    a.insert(ANN_ABI_SURFACE.into(), meta.abi_surface_hex.into());
    if let Some(rev) = meta.source_rev {
        a.insert(ANN_SOURCE_REV.into(), rev.into());
    }
    if let Some(d) = meta.input_digest_hex {
        a.insert(ANN_INPUT_DIGEST.into(), d.into());
    }
    if let Some(d) = meta.ci_digest_hex {
        a.insert(ANN_CI_DIGEST.into(), d.into());
    }
    a
}

/// Held for the duration of one publish transaction: blob staging via
/// the `prepare_*` fns and the final `commit_publish` all happen under
/// this one advisory lock, so a concurrent `remove`'s sweep can never
/// delete staged-but-uncommitted blobs.
pub struct PublishLock(#[allow(dead_code, reason = "held for its Drop")] fs::File);

impl OciStore {
    /// Open a publish transaction (see [`PublishLock`]).
    pub fn begin_publish(&self) -> Result<PublishLock> {
        Ok(PublishLock(self.lock_index()?))
    }

    /// Stage a module artifact for a batch commit — `publish_module`'s
    /// body without the tagging, plus the consolidated annotations.
    pub fn prepare_module(
        &self,
        name: &str,
        target: &str,
        version: &str,
        fmod_bytes: &[u8],
        manifest_toml: Option<&str>,
        meta: &ArtifactMeta<'_>,
    ) -> Result<Prepared> {
        let (config_digest, config_size) = self.put_blob(EMPTY_CONFIG)?;
        let (fmod_digest, fmod_size) = self.put_blob(fmod_bytes)?;
        let mut layers = vec![Descriptor {
            media_type: MT_FLUXOR_MODULE.into(),
            digest: fmod_digest,
            size: fmod_size,
            annotations: one_annotation(ANN_TITLE, &format!("{name}.fmod")),
        }];
        if let Some(toml_text) = manifest_toml {
            let (d, s) = self.put_blob(toml_text.as_bytes())?;
            layers.push(Descriptor {
                media_type: MT_FLUXOR_MODULE_META.into(),
                digest: d,
                size: s,
                annotations: one_annotation(ANN_TITLE, "manifest.toml"),
            });
        }
        let mut annotations = base_annotations("module", meta);
        annotations.insert(ANN_MODULE_NAME.into(), name.into());
        annotations.insert(ANN_TARGET.into(), target.into());
        let manifest = ImageManifest {
            schema_version: 2,
            media_type: MT_OCI_MANIFEST.into(),
            artifact_type: Some(MT_FLUXOR_MODULE.into()),
            config: Descriptor {
                media_type: MT_OCI_EMPTY.into(),
                digest: config_digest,
                size: config_size,
                annotations: Annotations::new(),
            },
            layers,
            annotations,
        };
        Ok(Prepared {
            manifest,
            ref_name: format!("{target}/{name}:{version}"),
            latest_ref: format!("{target}/{name}:latest"),
        })
    }

    /// Stage a source-tree artifact: one canonical-tar layer.
    /// `files` must satisfy `canonical_tar`'s ordering contract.
    pub fn prepare_source(
        &self,
        name: &str,
        version: &str,
        files: &[(String, Vec<u8>)],
        meta: &ArtifactMeta<'_>,
    ) -> Result<Prepared> {
        let tar = canonical_tar(files)?;
        let (config_digest, config_size) = self.put_blob(EMPTY_CONFIG)?;
        let (tar_digest, tar_size) = self.put_blob(&tar)?;
        let manifest = ImageManifest {
            schema_version: 2,
            media_type: MT_OCI_MANIFEST.into(),
            artifact_type: Some(MT_FLUXOR_SOURCE.into()),
            config: Descriptor {
                media_type: MT_OCI_EMPTY.into(),
                digest: config_digest,
                size: config_size,
                annotations: Annotations::new(),
            },
            layers: vec![Descriptor {
                media_type: MT_FLUXOR_SOURCE.into(),
                digest: tar_digest,
                size: tar_size,
                annotations: one_annotation(ANN_TITLE, &format!("{name}.tar")),
            }],
            annotations: base_annotations("source", meta),
        };
        Ok(Prepared {
            manifest,
            ref_name: format!("{}/src/{name}:{version}", meta.project),
            latest_ref: format!("{}/src/{name}:latest", meta.project),
        })
    }

    /// Stage a runtime artifact: one binary layer for one host triple.
    /// Namespace is `fluxor/run/` only — a sibling publishing a runtime
    /// is a design error, enforced here rather than documented around.
    pub fn prepare_runtime(
        &self,
        name: &str,
        version: &str,
        triple: &str,
        binary: &[u8],
        meta: &ArtifactMeta<'_>,
    ) -> Result<Prepared> {
        if meta.project != "fluxor" {
            return Err(Error::Config(format!(
                "runtime artifacts are fluxor's alone (a sibling \"runtime\" is a graph \
                 on fluxor-linux); refusing to publish runtime '{name}' from project '{}'",
                meta.project
            )));
        }
        let (config_digest, config_size) = self.put_blob(EMPTY_CONFIG)?;
        let (bin_digest, bin_size) = self.put_blob(binary)?;
        // Runtime blobs are executed in place: the CLI launcher opens
        // the blob and `fexecve`s the descriptor, and exec requires the
        // x bit on the file itself. Idempotent on re-publish.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                self.blob_path(&bin_digest)?,
                fs::Permissions::from_mode(0o755),
            )?;
        }
        let mut annotations = base_annotations("runtime", meta);
        annotations.insert(ANN_RUNTIME_TRIPLE.into(), triple.into());
        let manifest = ImageManifest {
            schema_version: 2,
            media_type: MT_OCI_MANIFEST.into(),
            artifact_type: Some(MT_FLUXOR_RUNTIME.into()),
            config: Descriptor {
                media_type: MT_OCI_EMPTY.into(),
                digest: config_digest,
                size: config_size,
                annotations: Annotations::new(),
            },
            layers: vec![Descriptor {
                media_type: MT_FLUXOR_RUNTIME.into(),
                digest: bin_digest,
                size: bin_size,
                annotations: one_annotation(ANN_TITLE, name),
            }],
            annotations,
        };
        Ok(Prepared {
            manifest,
            ref_name: format!("fluxor/run/{name}-{triple}:{version}"),
            latest_ref: format!("fluxor/run/{name}-{triple}:latest"),
        })
    }

    /// Commit a whole publish: stage every manifest blob, then repoint
    /// every tag (`name:ver` + `name:latest`) and rewrite the project
    /// index in ONE index write under the lock. Afterwards, sweep
    /// displaced closures with the full liveness root set (tags ∪
    /// snapshot children ∪ workspace-member lockfile digests).
    pub fn commit_publish(
        &self,
        _txn: &PublishLock,
        project: &str,
        version: &str,
        prepared: Vec<Prepared>,
        deps_annotation: Option<&str>,
    ) -> Result<Vec<Descriptor>> {
        let mut index = self.read_index()?;
        let mut new_descs: Vec<Descriptor> = Vec::new();
        let mut repointed: BTreeSet<String> = BTreeSet::new();

        for p in &prepared {
            let bytes = serde_json::to_vec(&p.manifest)?;
            let (digest, size) = self.put_blob(&bytes)?;
            for r in [&p.ref_name, &p.latest_ref] {
                let mut annotations = p.manifest.annotations.clone();
                annotations.insert(ANN_REF_NAME.into(), r.clone());
                new_descs.push(Descriptor {
                    media_type: MT_OCI_MANIFEST.into(),
                    digest: digest.clone(),
                    size,
                    annotations,
                });
                repointed.insert(r.clone());
            }
        }

        // Project index: an OCI image index over every artifact this
        // project currently publishes (the batch, plus prior artifacts
        // of the project whose refs the batch did not repoint).
        let mut children: Vec<Descriptor> = new_descs
            .iter()
            .filter(|d| {
                d.annotations
                    .get(ANN_REF_NAME)
                    .is_some_and(|r| !r.ends_with(":latest"))
            })
            .cloned()
            .collect();
        for d in &index.manifests {
            let same_project = d.annotations.get(ANN_PROJECT).map(String::as_str) == Some(project);
            let is_meta = d
                .annotations
                .get(ANN_REF_NAME)
                .is_some_and(|r| r.starts_with(&format!("{project}/meta:")));
            let displaced_ref = d
                .annotations
                .get(ANN_REF_NAME)
                .is_some_and(|r| repointed.contains(r) || r.ends_with(":latest"));
            if same_project && !is_meta && !displaced_ref {
                children.push(d.clone());
            }
        }
        let mut idx_annotations = Annotations::new();
        idx_annotations.insert(ANN_KIND.into(), "project-index".into());
        idx_annotations.insert(ANN_PROJECT.into(), project.into());
        if let Some(deps) = deps_annotation {
            idx_annotations.insert("io.fluxor.deps".into(), deps.into());
        }
        let project_index = ImageIndex {
            schema_version: 2,
            media_type: MT_OCI_INDEX.into(),
            manifests: children,
        };
        let idx_bytes = serde_json::to_vec(&project_index)?;
        let (idx_digest, idx_size) = self.put_blob(&idx_bytes)?;
        for r in [
            format!("{project}/meta:{version}"),
            format!("{project}/meta:latest"),
        ] {
            let mut annotations = idx_annotations.clone();
            annotations.insert(ANN_REF_NAME.into(), r.clone());
            new_descs.push(Descriptor {
                media_type: MT_OCI_INDEX.into(),
                digest: idx_digest.clone(),
                size: idx_size,
                annotations,
            });
            repointed.insert(r);
        }

        // The single swap: drop every repointed ref, append the batch.
        let displaced: Vec<Descriptor> = index
            .manifests
            .iter()
            .filter(|d| {
                d.annotations
                    .get(ANN_REF_NAME)
                    .is_some_and(|r| repointed.contains(r))
                    && !new_descs.iter().any(|n| n.digest == d.digest)
            })
            .cloned()
            .collect();
        index.manifests.retain(|d| {
            d.annotations
                .get(ANN_REF_NAME)
                .is_none_or(|r| !repointed.contains(r))
        });
        index.manifests.extend(new_descs.clone());
        self.write_index(&index)?;

        if !displaced.is_empty() {
            match self.sweep_with_roots(&index, &displaced) {
                Ok(_removed) => {}
                Err(e) => eprintln!(
                    "warning: publish could not sweep displaced artifacts ({e}); \
                     their blobs remain until a future sweep"
                ),
            }
        }
        Ok(new_descs)
    }

    /// Create (or repoint) a snapshot: one OCI index over `children`,
    /// tagged `snapshot/<name>`. Snapshots are GC roots — everything
    /// reachable from one survives every sweep.
    pub fn create_snapshot(&self, name: &str, children: Vec<Descriptor>) -> Result<Descriptor> {
        let _index_lock = self.lock_index()?;
        let snap = ImageIndex {
            schema_version: 2,
            media_type: MT_OCI_INDEX.into(),
            manifests: children,
        };
        let bytes = serde_json::to_vec(&snap)?;
        let (digest, size) = self.put_blob(&bytes)?;
        let ref_name = format!("snapshot/{name}");
        let mut annotations = Annotations::new();
        annotations.insert(ANN_KIND.into(), "snapshot".into());
        annotations.insert(ANN_REF_NAME.into(), ref_name.clone());
        let desc = Descriptor {
            media_type: MT_OCI_INDEX.into(),
            digest,
            size,
            annotations,
        };
        let mut index = self.read_index()?;
        index
            .manifests
            .retain(|d| d.annotations.get(ANN_REF_NAME) != Some(&ref_name));
        index.manifests.push(desc.clone());
        self.write_index(&index)?;
        Ok(desc)
    }

    /// Closure-add one descriptor's reachable digests into `live`,
    /// traversing both image manifests and image indexes (project
    /// indexes, snapshots). Every digest visited is filed in `tiers` by
    /// its descriptor media type, which is the only place that
    /// classification is available without re-reading the blob.
    fn add_closure(
        &self,
        d: &Descriptor,
        live: &mut BTreeSet<String>,
        tiers: &mut BTreeMap<String, BlobTier>,
    ) -> Result<()> {
        record_tier(
            tiers,
            &d.digest,
            if d.media_type == MT_OCI_INDEX {
                BlobTier::Index
            } else {
                BlobTier::Manifest
            },
        );
        if !live.insert(d.digest.clone()) {
            return Ok(());
        }
        if d.media_type == MT_OCI_INDEX {
            let bytes = self.read_blob(&d.digest)?;
            let idx: ImageIndex = serde_json::from_slice(&bytes)?;
            for child in &idx.manifests {
                self.add_closure(child, live, tiers)?;
            }
            return Ok(());
        }
        let m = self.read_manifest(d)?;
        live.insert(m.config.digest.clone());
        record_tier(tiers, &m.config.digest, tier_of(&m.config.media_type));
        for l in &m.layers {
            live.insert(l.digest.clone());
            record_tier(tiers, &l.digest, tier_of(&l.media_type));
        }
        Ok(())
    }

    /// Closure-add a digest known only by value (a lockfile pin, whose
    /// entry carries no media type). A pinned digest may name a
    /// manifest or an index: everything IT references is live too — a
    /// pinned manifest must keep its config and layer blobs, or the
    /// store is left holding a dangling manifest (JSON present,
    /// referenced blob gone).
    ///
    /// A pin whose blob is ABSENT contributes just itself and is not an
    /// error: a direct layer pin has no closure, and a pin the store
    /// never held cannot be walked. A pin whose blob is PRESENT but
    /// unreadable — failed integrity verification, `EACCES`, `EIO` — is
    /// an error: its closure is unknowable, so the sweep must fail
    /// closed rather than assume the pin references nothing.
    fn add_closure_by_digest(
        &self,
        digest: &str,
        live: &mut BTreeSet<String>,
        tiers: &mut BTreeMap<String, BlobTier>,
    ) -> Result<()> {
        if !live.insert(digest.to_string()) {
            return Ok(());
        }
        if !self.has_blob(digest) {
            return Ok(());
        }
        let bytes = self.read_blob(digest)?;
        // An image manifest requires `config` + `layers`, which an
        // index lacks; `ImageIndex.manifests` defaults, so the index
        // parse must come second and gate on its media type.
        if let Ok(m) = serde_json::from_slice::<ImageManifest>(&bytes) {
            record_tier(tiers, digest, BlobTier::Manifest);
            live.insert(m.config.digest.clone());
            record_tier(tiers, &m.config.digest, tier_of(&m.config.media_type));
            for l in &m.layers {
                live.insert(l.digest.clone());
                record_tier(tiers, &l.digest, tier_of(&l.media_type));
            }
            return Ok(());
        }
        if let Ok(idx) = serde_json::from_slice::<ImageIndex>(&bytes) {
            if idx.media_type == MT_OCI_INDEX {
                record_tier(tiers, digest, BlobTier::Index);
                for child in &idx.manifests {
                    self.add_closure_by_digest(&child.digest, live, tiers)?;
                }
            }
        }
        Ok(())
    }

    /// The store's ONE garbage collector. Sweep `victims`' closures
    /// against the full liveness root set: every index tag (traversed
    /// through indexes — a project-index descriptor is never parsed as
    /// a manifest), plus every `sha256:` digest pinned by a workspace
    /// member's `fluxor.lock` — each pin expanded through ITS closure,
    /// so a pinned manifest keeps every blob it references.
    ///
    /// Every path that can orphan a blob — publish, retag, `remove` —
    /// sweeps through here, so a blob a member lockfile pins is never
    /// evicted regardless of which command triggered the sweep.
    /// An unreadable member lockfile — or a pin whose blob is present
    /// but unreadable — fails CLOSED for the sweep only: warn and
    /// delete nothing; the publish that triggered the sweep has already
    /// succeeded (registry_consolidation.md, GC rules).
    ///
    /// Invariant: no blob referenced by any manifest still present in
    /// the store is ever deleted, and deletion runs strictly in tier
    /// order — indexes, then the manifests they list, then leaves. An
    /// interrupted sweep therefore leaves orphaned bytes, never a
    /// referent-missing index or manifest.
    fn sweep_with_roots(&self, index: &ImageIndex, victims: &[Descriptor]) -> Result<Vec<String>> {
        let mut live: BTreeSet<String> = BTreeSet::new();
        let mut tiers: BTreeMap<String, BlobTier> = BTreeMap::new();
        for d in &index.manifests {
            self.add_closure(d, &mut live, &mut tiers).map_err(|e| {
                Error::Config(format!("live manifest {} is unreadable ({e})", d.digest))
            })?;
        }
        for digest in member_lockfile_digests()? {
            self.add_closure_by_digest(&digest, &mut live, &mut tiers)
                .map_err(|e| Error::Config(format!("pinned blob {digest} is unreadable ({e})")))?;
        }
        let mut candidates: BTreeSet<String> = BTreeSet::new();
        for v in victims {
            candidates.insert(v.digest.clone());
            let mut c = BTreeSet::new();
            if self.add_closure(v, &mut c, &mut tiers).is_ok() {
                candidates.extend(c);
            }
        }
        let mut doomed: Vec<&String> = candidates.difference(&live).collect();
        // Stable by tier: a referent always outlives its referrer.
        doomed.sort_by_key(|d| tiers.get(*d).copied().unwrap_or(BlobTier::Leaf));
        let mut removed = Vec::new();
        for digest in doomed {
            if let Ok(p) = self.blob_path(digest) {
                if fs::remove_file(&p).is_ok() {
                    removed.push(digest.clone());
                }
            }
        }
        Ok(removed)
    }
}

/// Where a blob sits in the reference hierarchy, learned from the
/// descriptor that names it during the closure walk. Ordering is
/// deletion order: an index is deleted before the manifests it lists,
/// a manifest before the leaves it references.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum BlobTier {
    Index,
    Manifest,
    Leaf,
}

fn tier_of(media_type: &str) -> BlobTier {
    match media_type {
        MT_OCI_INDEX => BlobTier::Index,
        MT_OCI_MANIFEST => BlobTier::Manifest,
        _ => BlobTier::Leaf,
    }
}

/// File a digest's tier, keeping the strongest classification seen: one
/// digest may be reached both as a manifest descriptor and as some
/// other manifest's layer, and the referrer tier is what deletion order
/// must respect.
fn record_tier(tiers: &mut BTreeMap<String, BlobTier>, digest: &str, tier: BlobTier) {
    let slot = tiers.entry(digest.to_string()).or_insert(tier);
    *slot = (*slot).min(tier);
}

/// Harvest every `sha256:<hex>` digest from every workspace member's
/// `fluxor.lock` — the third GC root class. A member whose lockfile
/// exists but cannot be read is a hard error (the caller downgrades to
/// warn-and-skip-sweep); a member with no lockfile contributes nothing.
fn member_lockfile_digests() -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    let Ok(Some(ws)) = crate::workspace::load_workspace() else {
        return Ok(out);
    };
    for member in &ws.workspace.members {
        let lock = member.join("fluxor.lock");
        if !lock.exists() {
            continue;
        }
        let text = fs::read_to_string(&lock).map_err(|e| {
            Error::Config(format!(
                "member lockfile {} unreadable ({e}) — sweep skipped (fail-closed)",
                lock.display()
            ))
        })?;
        let mut rest = text.as_str();
        while let Some(pos) = rest.find("sha256:") {
            let hex: String = rest[pos + 7..]
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
            if hex.len() == 64 {
                out.insert(format!("sha256:{hex}"));
            }
            rest = &rest[pos + 7..];
        }
    }
    Ok(out)
}

// ── Canonical tar ─────────────────────────────────────────────────────

/// Build a canonical, uncompressed ustar archive from `(path, bytes)`
/// entries: paths sorted and unique, mtime 0, uid/gid 0 (empty names),
/// mode 0644, no directory entries, two zero blocks at the end.
/// Property: identical file content ⇒ identical archive bytes ⇒
/// identical layer digest — the store's identity for source-tree
/// artifacts (standards/fluxor-modules.md; registry_consolidation.md).
/// No compression: gzip is nondeterministic across implementations and
/// blobs are local.
pub fn canonical_tar(files: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut prev: Option<&str> = None;
    for (path, bytes) in files {
        if path.starts_with('/') || path.split('/').any(|c| c == ".." || c.is_empty()) {
            return Err(Error::Config(format!(
                "canonical tar: path must be clean and relative: {path:?}"
            )));
        }
        if let Some(p) = prev {
            if p >= path.as_str() {
                return Err(Error::Config(format!(
                    "canonical tar: paths must be strictly sorted ({p:?} !< {path:?})"
                )));
            }
        }
        prev = Some(path.as_str());

        // ustar name/prefix split: name ≤ 100 bytes, prefix ≤ 155.
        let (prefix, name) = if path.len() <= 100 {
            ("", path.as_str())
        } else {
            let split = path[..path.len().min(156)]
                .rfind('/')
                .filter(|&i| path.len() - i - 1 <= 100 && i <= 155)
                .ok_or_else(|| {
                    Error::Config(format!("canonical tar: path too long for ustar: {path:?}"))
                })?;
            (&path[..split], &path[split + 1..])
        };

        let mut hdr = [0u8; 512];
        hdr[0..name.len()].copy_from_slice(name.as_bytes());
        hdr[100..108].copy_from_slice(b"0000644\0");
        hdr[108..116].copy_from_slice(b"0000000\0"); // uid
        hdr[116..124].copy_from_slice(b"0000000\0"); // gid
        let size_octal = format!("{:011o}\0", bytes.len());
        hdr[124..136].copy_from_slice(size_octal.as_bytes());
        hdr[136..148].copy_from_slice(b"00000000000\0"); // mtime 0
        hdr[148..156].copy_from_slice(b"        "); // checksum placeholder
        hdr[156] = b'0'; // regular file
        hdr[257..263].copy_from_slice(b"ustar\0");
        hdr[263..265].copy_from_slice(b"00");
        // uname/gname left empty; devmajor/devminor zero.
        hdr[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
        let checksum: u32 = hdr.iter().map(|&b| b as u32).sum();
        let ck = format!("{checksum:06o}\0 ");
        hdr[148..156].copy_from_slice(ck.as_bytes());

        out.extend_from_slice(&hdr);
        out.extend_from_slice(bytes);
        let pad = (512 - bytes.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
    }
    out.extend(std::iter::repeat_n(0u8, 1024));
    Ok(out)
}

#[cfg(test)]
mod canonical_tar_tests {
    use super::canonical_tar;

    #[test]
    fn deterministic_and_extractable_shape() {
        let files = vec![
            ("a/mod.rs".to_string(), b"pub fn a() {}\n".to_vec()),
            ("b.rs".to_string(), vec![0u8; 513]),
        ];
        let one = canonical_tar(&files).unwrap();
        let two = canonical_tar(&files).unwrap();
        assert_eq!(one, two, "identical input must yield identical bytes");
        // 2 headers + 1 block + 2 blocks data + 2 terminator blocks.
        assert_eq!(one.len(), 512 * 7);
        // ustar magic present in each header.
        assert_eq!(&one[257..262], b"ustar");
    }

    #[test]
    fn rejects_unsorted_and_unclean_paths() {
        let unsorted = vec![
            ("b.rs".to_string(), Vec::new()),
            ("a.rs".to_string(), Vec::new()),
        ];
        assert!(canonical_tar(&unsorted).is_err());
        let dotdot = vec![("../x.rs".to_string(), Vec::new())];
        assert!(canonical_tar(&dotdot).is_err());
    }
}

// ── Helpers ───────────────────────────────────────────────────────────

pub fn sha256_hex_prefixed(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

/// Process-wide serialisation for tests that mutate `FLUXOR_STORE` /
/// `FLUXOR_WORKSPACE`: env vars are process-global and cargo runs the
/// lib tests threaded, so every env-touching test holds this guard.
#[cfg(test)]
pub(crate) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static M: std::sync::Mutex<()> = std::sync::Mutex::new(());
    M.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Scoped env override for tests: set on construction, restored to the
/// prior value (or unset) on drop. Restoration must survive a panic
/// between set and unset, or a failing test leaks a path naming a
/// deleted tempdir into every later env-touching test — `test_env_lock`
/// recovers from poisoning, so the leak is not contained by the guard.
#[cfg(test)]
pub(crate) struct EnvScope {
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

#[cfg(test)]
impl EnvScope {
    pub(crate) fn set(pairs: &[(&'static str, &Path)]) -> EnvScope {
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

#[cfg(test)]
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

fn one_annotation(key: &str, value: &str) -> Annotations {
    let mut a = Annotations::new();
    a.insert(key.into(), value.into());
    a
}

/// `git rev-parse HEAD` of `dir`, best effort — a non-repo yields `None`.
pub fn git_source_rev(dir: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let rev = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!rev.is_empty()).then_some(rev)
}

/// Write via temp file + rename so a crash never leaves a torn file where a
/// reader looks. Temp lives in the destination directory (same filesystem)
/// and carries a per-process-unique suffix so concurrent writers of the
/// same destination never collide on the temp name.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = path
        .parent()
        .ok_or_else(|| Error::Config(format!("no parent dir for {}", path.display())))?;
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".tmp.{}.{}.{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed),
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    fs::write(&tmp, bytes)?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal synthetic graph image (FXSL header + FXMT table
    /// with two fmods + config), explode it, and reassemble from the
    /// layers with zero-filled gaps — the hashed regions must be
    /// byte-identical, which is exactly the device-side contract.
    #[test]
    fn explode_image_roundtrips_byte_exact() {
        const HDR: usize = 256;
        let modules_offset = 4096usize;
        // FXMT: header 16 + 2 entries à 16, fmods page-aligned so code
        // (offset + 72) is 4096-aligned, mirroring build_module_table.
        let fmod_a = vec![0xAAu8; 300];
        let fmod_b = vec![0xBBu8; 150];
        let a_off = 4096 - 72; // table-relative; code at 4096
        let b_off = 2 * 4096 - 72;
        let table_len = b_off + fmod_b.len();
        let mut table = vec![0u8; table_len];
        table[0..4].copy_from_slice(&0x544D_5846u32.to_le_bytes());
        table[4] = 1; // version
        table[5] = 2; // count
        for (i, (off, data)) in [(a_off, &fmod_a), (b_off, &fmod_b)].iter().enumerate() {
            let e = 16 + i * 16;
            table[e..e + 4].copy_from_slice(&(0x1111u32 * (i as u32 + 1)).to_le_bytes());
            table[e + 4..e + 8].copy_from_slice(&(*off as u32).to_le_bytes());
            table[e + 8..e + 12].copy_from_slice(&(data.len() as u32).to_le_bytes());
        }
        table[a_off..a_off + fmod_a.len()].copy_from_slice(&fmod_a);
        table[b_off..b_off + fmod_b.len()].copy_from_slice(&fmod_b);
        let config = vec![0xCCu8; 90];
        let config_offset = (modules_offset + table_len).div_ceil(256) * 256;
        let mut image = vec![0xFFu8; config_offset + config.len()];
        image[0..4].copy_from_slice(&0x4C53_5846u32.to_le_bytes());
        image[4] = 1;
        image[16..20].copy_from_slice(&(modules_offset as u32).to_le_bytes());
        image[20..24].copy_from_slice(&(table_len as u32).to_le_bytes());
        image[24..28].copy_from_slice(&(config_offset as u32).to_le_bytes());
        image[28..32].copy_from_slice(&(config.len() as u32).to_le_bytes());
        image[modules_offset..modules_offset + table_len].copy_from_slice(&table);
        image[config_offset..config_offset + config.len()].copy_from_slice(&config);
        let _ = HDR;

        let layers = explode_image(&image).unwrap();
        assert_eq!(layers.len(), 4); // skeleton + 2 fmods + config
        assert_eq!(layers[0].media_type, MT_FLUXOR_IMAGE_SKELETON);
        assert_eq!(layers[0].offset, 0);
        assert_eq!(layers[3].media_type, MT_FLUXOR_CONFIG_BIN);

        // Reassemble: place layers at offsets, zero-fill gaps.
        let mut out = vec![0u8; image.len()];
        for l in &layers {
            out[l.offset..l.offset + l.bytes.len()].copy_from_slice(l.bytes);
        }
        // Hashed regions must match byte-for-byte (the modules→config
        // alignment gap is outside them and may differ: 0xFF vs 0).
        assert_eq!(
            out[modules_offset..modules_offset + table_len],
            image[modules_offset..modules_offset + table_len]
        );
        assert_eq!(
            out[config_offset..config_offset + config.len()],
            image[config_offset..config_offset + config.len()]
        );
        // Fmod layer blobs are the raw fmod bytes (store-dedup contract).
        assert_eq!(layers[1].bytes, &fmod_a[..]);
        assert_eq!(layers[2].bytes, &fmod_b[..]);
    }

    fn temp_store() -> (tempfile::TempDir, OciStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = OciStore::open(dir.path().join("store")).expect("open");
        (dir, store)
    }

    #[test]
    fn open_creates_valid_layout_and_is_idempotent() {
        let (dir, store) = temp_store();
        assert!(store.root().join("oci-layout").exists());
        assert!(store.root().join("index.json").exists());
        assert!(store.root().join("blobs").join("sha256").is_dir());
        // Re-open succeeds.
        OciStore::open(dir.path().join("store")).expect("reopen");
    }

    #[test]
    fn open_rejects_bad_layout_version() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("store");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("oci-layout"), b"{\"imageLayoutVersion\":\"9.9\"}").unwrap();
        assert!(OciStore::open(&root).is_err());
    }

    #[test]
    fn blobs_are_content_addressed_and_deduped() {
        let (_dir, store) = temp_store();
        let (d1, s1) = store.put_blob(b"hello").unwrap();
        let (d2, _) = store.put_blob(b"hello").unwrap();
        assert_eq!(d1, d2);
        assert_eq!(s1, 5);
        assert_eq!(store.read_blob(&d1).unwrap(), b"hello");
        assert_eq!(
            d1,
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    fn publish_test_module(store: &OciStore, name: &str, bytes: &[u8], tag: &str) -> Descriptor {
        publish_module(
            store,
            &ModulePublish {
                name,
                target: "bcm2712",
                fmod_bytes: bytes,
                manifest_toml: Some("version = \"1.0.0\"\n"),
                provenance: PROVENANCE_LOCAL,
                source_rev: Some("deadbeef"),
                ref_name: tag,
            },
        )
        .expect("publish")
    }

    #[test]
    fn module_publish_roundtrip() {
        let (_dir, store) = temp_store();
        let desc = publish_test_module(&store, "blinky", b"FMOD-bytes", "blinky:1.0.0");
        assert_eq!(
            desc.annotations.get(ANN_REF_NAME).map(String::as_str),
            Some("blinky:1.0.0")
        );
        let resolved = store.resolve("blinky:1.0.0").unwrap();
        assert_eq!(resolved.digest, desc.digest);
        let manifest = store.read_manifest(&resolved).unwrap();
        assert_eq!(manifest.artifact_type.as_deref(), Some(MT_FLUXOR_MODULE));
        assert_eq!(
            manifest.annotations.get(ANN_PROVENANCE).map(String::as_str),
            Some(PROVENANCE_LOCAL)
        );
        assert_eq!(
            manifest.annotations.get(ANN_SOURCE_REV).map(String::as_str),
            Some("deadbeef")
        );
        // fmod layer bytes readable and correct.
        let fmod_layer = &manifest.layers[0];
        assert_eq!(fmod_layer.media_type, MT_FLUXOR_MODULE);
        assert_eq!(store.read_blob(&fmod_layer.digest).unwrap(), b"FMOD-bytes");
    }

    #[test]
    fn publishing_is_deterministic() {
        let (_dir, s1) = temp_store();
        let (_dir2, s2) = temp_store();
        let d1 = publish_test_module(&s1, "blinky", b"FMOD-bytes", "blinky:1.0.0");
        let d2 = publish_test_module(&s2, "blinky", b"FMOD-bytes", "blinky:1.0.0");
        assert_eq!(d1.digest, d2.digest, "same inputs → same manifest digest");
    }

    #[test]
    fn retag_replaces_pointer_and_digest_ref_resolves() {
        let (_dir, store) = temp_store();
        let old = publish_test_module(&store, "blinky", b"v1", "blinky:latest");
        let new = publish_test_module(&store, "blinky", b"v2", "blinky:latest");
        assert_ne!(old.digest, new.digest);
        assert_eq!(store.resolve("blinky:latest").unwrap().digest, new.digest);
        // Only one descriptor holds the tag.
        let index = store.read_index().unwrap();
        let holders = index
            .manifests
            .iter()
            .filter(|d| {
                d.annotations.get(ANN_REF_NAME).map(String::as_str) == Some("blinky:latest")
            })
            .count();
        assert_eq!(holders, 1);
        // Digest-prefix resolution still reaches the untagged old manifest? No —
        // retag dropped it from the index entirely; the new one resolves by prefix.
        let hex = new.digest.strip_prefix("sha256:").unwrap();
        assert_eq!(store.resolve(&hex[..12]).unwrap().digest, new.digest);
    }

    #[test]
    fn remove_deletes_unreferenced_blobs_but_keeps_shared_ones() {
        // Sweep liveness includes member lockfiles; point at a file that
        // does not exist so the roots are the index alone.
        let _env = test_env_lock();
        let (_dir, store) = temp_store();
        std::env::set_var("FLUXOR_WORKSPACE", _dir.path().join("no-workspace.toml"));
        // Two tags over the same fmod bytes → shared blob.
        let a = publish_test_module(&store, "blinky", b"shared", "blinky:1.0.0");
        let _b = publish_test_module(&store, "blinky", b"shared", "blinky:1.0.1");
        // Same content + annotations → identical manifests; the tags share
        // everything. Removing one tag must keep all blobs.
        let removed = store.remove("blinky:1.0.0").unwrap();
        assert!(removed.is_empty(), "shared blobs must survive: {removed:?}");
        assert!(store.resolve("blinky:1.0.1").is_ok());
        assert!(store.resolve("blinky:1.0.0").is_err());

        // Remove the last tag → its closure is swept (config blob is shared
        // with nothing now, fmod blob too).
        let manifest = store.read_manifest(&a).unwrap();
        let removed = store.remove("blinky:1.0.1").unwrap();
        std::env::remove_var("FLUXOR_WORKSPACE");
        assert!(removed.contains(&manifest.layers[0].digest));
        assert!(!store.has_blob(&manifest.layers[0].digest));
    }

    /// Every sweep — publish/retag and `store rm` alike — runs the same
    /// liveness root set, so a blob pinned ONLY by a workspace member's
    /// `fluxor.lock` (no tag reaches it) is never evicted. Before the
    /// sweeps were unified, both paths used index-closure liveness only
    /// and evicted the member's pinned blob out from under it.
    #[test]
    fn member_lockfile_pinned_blob_survives_retag_and_remove() {
        let _env = test_env_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let store = OciStore::open(dir.path().join("store")).expect("open");

        // A member checkout whose lockfile pins the fmod bytes' digest.
        let member = dir.path().join("member");
        std::fs::create_dir_all(&member).unwrap();
        let pinned = sha256_hex_prefixed(b"pinned");
        std::fs::write(
            member.join("fluxor.lock"),
            format!("[[artifact]]\nname = \"widget\"\ndigest = \"{pinned}\"\n"),
        )
        .unwrap();
        let ws_file = dir.path().join("workspace.toml");
        std::fs::write(
            &ws_file,
            format!(
                "[workspace]\nmembers = [\"{}\"]\n",
                member.to_str().unwrap()
            ),
        )
        .unwrap();
        let _scope = EnvScope::set(&[("FLUXOR_WORKSPACE", &ws_file)]);

        // (a) A retag that displaces the only manifest reaching the blob.
        publish_test_module(&store, "widget", b"pinned", "widget:latest");
        assert!(store.has_blob(&pinned), "publish stored the fmod blob");
        publish_test_module(&store, "widget", b"changed", "widget:latest");
        assert!(
            store.has_blob(&pinned),
            "retag swept a blob pinned by a member lockfile"
        );

        // (b) A `store rm` of the only tag reaching the blob.
        publish_test_module(&store, "blinky", b"pinned", "blinky:1.0.0");
        let removed = store.remove("blinky:1.0.0").unwrap();
        assert!(
            !removed.contains(&pinned),
            "store rm reported sweeping a member-pinned blob: {removed:?}"
        );
        assert!(
            store.has_blob(&pinned),
            "store rm swept a blob pinned by a member lockfile"
        );
    }

    /// A member lockfile pins a MANIFEST digest — the shape `fluxor.lock`
    /// actually writes. Liveness must cover the pinned manifest's whole
    /// closure: keeping the manifest blob while sweeping its config/layer
    /// blobs leaves a dangling manifest (JSON present, referenced blob
    /// gone), which every consume path then misreports as the artifact
    /// being absent.
    #[test]
    fn member_pinned_manifest_keeps_its_closure_across_retag() {
        let _env = test_env_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let store = OciStore::open(dir.path().join("store")).expect("open");

        let old = publish_test_module(&store, "widget", b"epoch-one", "widget:latest");
        let old_manifest = store.read_manifest(&old).unwrap();

        let member = dir.path().join("member");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(
            member.join("fluxor.lock"),
            format!(
                "[[artifact]]\nname = \"widget\"\ndigest = \"{}\"\n",
                old.digest
            ),
        )
        .unwrap();
        let ws_file = dir.path().join("workspace.toml");
        std::fs::write(
            &ws_file,
            format!(
                "[workspace]\nmembers = [\"{}\"]\n",
                member.to_str().unwrap()
            ),
        )
        .unwrap();
        let _scope = EnvScope::set(&[("FLUXOR_WORKSPACE", &ws_file)]);
        publish_test_module(&store, "widget", b"epoch-two", "widget:latest");

        assert!(
            store.has_blob(&old.digest),
            "pinned manifest blob must survive the retag sweep"
        );
        assert!(
            store.has_blob(&old_manifest.config.digest),
            "pinned manifest's config blob must survive the retag sweep"
        );
        for l in &old_manifest.layers {
            assert!(
                store.has_blob(&l.digest),
                "pinned manifest's layer {} must survive the retag sweep",
                l.digest
            );
        }
    }

    /// A sweep deletes strictly in tier order — index, then the
    /// manifests it lists, then leaves — so an interrupted sweep can
    /// only ever leave orphaned bytes, never a structural blob pointing
    /// at a deleted referent.
    #[test]
    fn sweep_deletes_referrers_before_referents() {
        let _env = test_env_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let store = OciStore::open(dir.path().join("store")).expect("open");
        let ws_file = dir.path().join("no-workspace.toml");
        let _scope = EnvScope::set(&[("FLUXOR_WORKSPACE", &ws_file)]);

        let a = publish_test_module(&store, "alpha", b"alpha-bytes", "alpha:latest");
        let b = publish_test_module(&store, "beta", b"beta-bytes", "beta:latest");
        let snap = store
            .create_snapshot("set", vec![a.clone(), b.clone()])
            .unwrap();
        // Untag both modules: the snapshot alone keeps them reachable.
        store.remove("alpha:latest").unwrap();
        store.remove("beta:latest").unwrap();

        let layers: Vec<String> = [&a, &b]
            .iter()
            .flat_map(|d| store.read_manifest(d).unwrap().layers)
            .map(|l| l.digest)
            .collect();

        let removed = store.remove("snapshot/set").unwrap();
        let pos = |d: &str| removed.iter().position(|r| r == d).expect("swept");
        assert_eq!(pos(&snap.digest), 0, "index must unlink first: {removed:?}");
        let last_manifest = pos(&a.digest).max(pos(&b.digest));
        for l in &layers {
            assert!(
                pos(l) > last_manifest,
                "leaf {l} unlinked before a manifest referencing it: {removed:?}"
            );
        }
    }

    /// A pinned manifest whose blob is PRESENT but corrupt has an
    /// unknowable closure: its config and layers may also sit inside a
    /// displaced victim's closure (content-addressed layers dedupe
    /// across artifacts), so proceeding would sweep them and leave the
    /// pin dangling. The sweep must fail closed — warn, delete nothing.
    #[test]
    fn corrupt_pinned_manifest_aborts_the_sweep() {
        let _env = test_env_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let store = OciStore::open(dir.path().join("store")).expect("open");

        // `widget` is published, pinned by a member, then displaced —
        // reachable only through the pin, exactly the case the pinned
        // closure exists to protect.
        let shared = b"shared-payload";
        let pinned = publish_test_module(&store, "widget", shared, "widget:latest");
        let pinned_manifest = store.read_manifest(&pinned).unwrap();
        let shared_layer = pinned_manifest.layers[0].digest.clone();

        let member = dir.path().join("member");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(
            member.join("fluxor.lock"),
            format!(
                "[[artifact]]\nname = \"widget\"\ndigest = \"{}\"\n",
                pinned.digest
            ),
        )
        .unwrap();
        let ws_file = dir.path().join("workspace.toml");
        std::fs::write(
            &ws_file,
            format!(
                "[workspace]\nmembers = [\"{}\"]\n",
                member.to_str().unwrap()
            ),
        )
        .unwrap();
        let _scope = EnvScope::set(&[("FLUXOR_WORKSPACE", &ws_file)]);
        publish_test_module(&store, "widget", b"widget-two", "widget:latest");

        // `gadget` publishes the SAME payload bytes, so it shares the
        // pinned manifest's layer blob; displacing it makes that shared
        // layer a sweep candidate.
        publish_test_module(&store, "gadget", shared, "gadget:latest");
        std::fs::write(
            store.blob_path(&pinned.digest).unwrap(),
            b"truncated-manifest",
        )
        .unwrap();
        publish_test_module(&store, "gadget", b"gadget-two", "gadget:latest");

        assert!(
            store.has_blob(&shared_layer),
            "sweep deleted the pinned manifest's layer despite being unable to read the pin"
        );
        assert!(
            store.has_blob(&pinned_manifest.config.digest),
            "sweep deleted the pinned manifest's config despite being unable to read the pin"
        );
    }

    fn bundle_fixture(store: &OciStore) -> (String, Vec<u8>, Vec<u8>) {
        let resources = br#"{"modules":1,"edges":0,"stateBytes":1024,"bufferBytes":0}"#.to_vec();
        let graph = b"modules: []\n".to_vec();
        let (fmod_digest, _) = store.put_blob(b"router-fmod").unwrap();
        let cfg = format!("sha256:{}", "ab".repeat(32));
        let workload = format!(
            r#"{{
  "schemaVersion": 1,
  "name": "demo",
  "version": "1.0.0",
  "contract": {{
    "configSchema": {{ "digest": "{cfg}" }},
    "health": {{ "readiness": "r", "liveness": "l" }},
    "update": {{ "drainTimeoutMs": 1000, "statePolicy": "discard" }}
  }},
  "implementations": [ {{
    "target": {{ "family": "linux", "architecture": "aarch64", "fluxorAbi": 1 }},
    "graph": {{ "digest": "{graph_d}" }},
    "modules": [ {{ "name": "router", "digest": "{fmod_digest}" }} ],
    "resources": {{ "digest": "{res_d}" }},
    "bindings": {{ "imports": {{}}, "exports": {{}}, "health": {{ "r": "m.r", "l": "m.l" }} }}
  }} ]
}}"#,
            graph_d = sha256_hex_prefixed(&graph),
            res_d = sha256_hex_prefixed(&resources),
        );
        (workload, resources, graph)
    }

    #[test]
    fn bundle_publish_roundtrip() {
        let (_dir, store) = temp_store();
        let (workload, resources, graph) = bundle_fixture(&store);
        let desc = publish_bundle(
            &store,
            &BundlePublish {
                workload_json: &workload,
                resources_json: &resources,
                graph_yaml: &graph,
                provenance: PROVENANCE_PUBLISHED,
                source_rev: None,
                ref_name: "demo:1.0.0",
            },
        )
        .expect("publish bundle");
        let m = store.read_manifest(&desc).unwrap();
        assert_eq!(m.artifact_type.as_deref(), Some(MT_FLUXOR_WORKLOAD));
        // workload + resources + graph + 1 module layer
        assert_eq!(m.layers.len(), 4);
        assert_eq!(
            m.annotations.get(ANN_PROVENANCE).map(String::as_str),
            Some(PROVENANCE_PUBLISHED)
        );
        assert!(!m.annotations.contains_key(ANN_SOURCE_REV));
    }

    #[test]
    fn bundle_publish_rejects_missing_module_blob() {
        let (_dir, store) = temp_store();
        let (workload, resources, graph) = bundle_fixture(&store);
        // Blow away the module blob the fixture staged.
        let fmod_digest = sha256_hex_prefixed(b"router-fmod");
        std::fs::remove_file(store.blob_path(&fmod_digest).unwrap()).unwrap();
        let err = publish_bundle(
            &store,
            &BundlePublish {
                workload_json: &workload,
                resources_json: &resources,
                graph_yaml: &graph,
                provenance: PROVENANCE_LOCAL,
                source_rev: None,
                ref_name: "demo:1.0.0",
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("not in the store"), "{err}");
    }

    #[test]
    fn bundle_publish_rejects_unpinned_artifacts() {
        let (_dir, store) = temp_store();
        let (workload, resources, _graph) = bundle_fixture(&store);
        let err = publish_bundle(
            &store,
            &BundlePublish {
                workload_json: &workload,
                resources_json: &resources,
                graph_yaml: b"tampered: true\n",
                provenance: PROVENANCE_LOCAL,
                source_rev: None,
                ref_name: "demo:1.0.0",
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("not pinned"), "{err}");
    }

    #[test]
    fn resolve_rejects_ambiguity_and_unknown() {
        let (_dir, store) = temp_store();
        assert!(store.resolve("nope:1").is_err());
        publish_test_module(&store, "a", b"aaa", "a:1");
        publish_test_module(&store, "b", b"bbb", "b:1");
        // Empty-prefix ambiguity is caught by the hexdigit check upstream;
        // a single hex char shared by both digests must error if ambiguous.
        let index = store.read_index().unwrap();
        let d0 = index.manifests[0].digest.strip_prefix("sha256:").unwrap();
        let d1 = index.manifests[1].digest.strip_prefix("sha256:").unwrap();
        let common: String = d0
            .chars()
            .zip(d1.chars())
            .take_while(|(a, b)| a == b)
            .map(|(a, _)| a)
            .collect();
        if !common.is_empty() {
            assert!(store.resolve(&common).is_err());
        }
        // Full unique prefix resolves.
        assert_eq!(store.resolve(d0).unwrap().digest, index.manifests[0].digest);
    }

    #[test]
    fn read_blob_rejects_tampered_and_put_blob_heals() {
        let (_dir, store) = temp_store();
        let (digest, _) = store.put_blob(b"payload").unwrap();
        let path = store.blob_path(&digest).unwrap();
        std::fs::write(&path, b"tampered").unwrap();
        assert!(
            store.read_blob(&digest).is_err(),
            "tampered blob must not read"
        );
        // Re-putting the true content repairs the store.
        store.put_blob(b"payload").unwrap();
        assert_eq!(store.read_blob(&digest).unwrap(), b"payload");
    }

    #[test]
    fn concurrent_publishes_preserve_every_tag() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("store");
        OciStore::open(&root).unwrap();
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let root = root.clone();
                std::thread::spawn(move || {
                    let store = OciStore::open(&root).unwrap();
                    publish_module(
                        &store,
                        &ModulePublish {
                            name: "m",
                            target: "bcm2712",
                            fmod_bytes: format!("bytes-{i}").as_bytes(),
                            manifest_toml: None,
                            provenance: PROVENANCE_LOCAL,
                            source_rev: None,
                            ref_name: &format!("m:{i}"),
                        },
                    )
                    .expect("publish");
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let store = OciStore::open(&root).unwrap();
        for i in 0..8 {
            assert!(
                store.resolve(&format!("m:{i}")).is_ok(),
                "tag m:{i} lost under concurrency"
            );
        }
    }

    #[test]
    fn retag_sweeps_displaced_closure_but_keeps_shared_blobs() {
        let (_dir, store) = temp_store();
        let old = publish_test_module(&store, "blinky", b"v1-bytes", "blinky:latest");
        let old_manifest = store.read_manifest(&old).unwrap();
        let old_fmod = old_manifest.layers[0].digest.clone();
        // The manifest.toml layer bytes are shared between v1 and v2
        // (same fixture text) and must survive the retag sweep.
        let shared_meta = old_manifest.layers[1].digest.clone();

        let new = publish_test_module(&store, "blinky", b"v2-bytes", "blinky:latest");
        assert_ne!(old.digest, new.digest);
        // Displaced closure is gone: old manifest + old fmod blob.
        assert!(!store.has_blob(&old.digest), "old manifest must be swept");
        assert!(!store.has_blob(&old_fmod), "old fmod layer must be swept");
        // Shared + current content survives.
        assert!(store.has_blob(&shared_meta), "shared layer must survive");
        let new_manifest = store.read_manifest(&new).unwrap();
        assert_eq!(
            store.read_blob(&new_manifest.layers[0].digest).unwrap(),
            b"v2-bytes"
        );
    }

    #[test]
    fn open_refuses_arbitrary_nonempty_directory() {
        let dir = tempfile::tempdir().unwrap();
        // Non-empty directory without the layout marker → refused, untouched.
        let victim = dir.path().join("home");
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::write(victim.join("precious.txt"), b"data").unwrap();
        assert!(OciStore::open(&victim).is_err());
        assert!(!victim.join("oci-layout").exists(), "must not initialize");
        assert!(!victim.join("blobs").exists());

        // Empty existing directory → initialized normally.
        let empty = dir.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        OciStore::open(&empty).expect("empty dir initializes");
        // Re-open of a real store still works.
        OciStore::open(&empty).expect("reopen");
    }

    #[test]
    fn open_recovers_sentinel_init_but_refuses_foreign_and_detects_corruption() {
        let tmp = tempfile::tempdir().unwrap();

        // A genuine interrupted init carries OUR sentinel plus half-written
        // artifacts. It must RECOVER into a valid store, not brick.
        let half = tmp.path().join("half");
        std::fs::create_dir_all(half.join("blobs").join("sha256")).unwrap();
        std::fs::write(half.join(".fluxor-store-init"), b"fluxor-oci-store-init\n").unwrap();
        let store = OciStore::open(&half).expect("recover sentinel init");
        assert!(half.join("oci-layout").exists());
        assert!(
            !half.join(".fluxor-store-init").exists(),
            "sentinel cleared"
        );
        publish_test_module(&store, "m", b"bytes", "m:1");
        assert!(store.resolve("m:1").is_ok());

        // An UNRELATED directory that merely happens to contain generic names
        // (index.json, blobs/) but NO sentinel must be refused, and left
        // untouched — no oci-layout, no index.lock, no blobs adoption.
        let unrelated = tmp.path().join("unrelated");
        std::fs::create_dir_all(&unrelated).unwrap();
        std::fs::write(unrelated.join("index.json"), b"{\"not\":\"ours\"}").unwrap();
        assert!(OciStore::open(&unrelated).is_err());
        assert!(!unrelated.join("oci-layout").exists());
        assert!(
            !unrelated.join("index.lock").exists(),
            "foreign dir left untouched"
        );
        assert!(!unrelated.join("blobs").exists());

        // Foreign content with arbitrary files is refused too.
        let foreign = tmp.path().join("foreign");
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::write(foreign.join("passwords.txt"), b"secret").unwrap();
        assert!(OciStore::open(&foreign).is_err());

        // A store whose marker survives but whose index.json was lost is
        // CORRUPTION, not a recoverable/fresh state — reject rather than
        // silently reinitialize and orphan every blob.
        let corrupt = tmp.path().join("corrupt");
        OciStore::open(&corrupt).unwrap(); // make a real store
        std::fs::remove_file(corrupt.join("index.json")).unwrap();
        match OciStore::open(&corrupt) {
            Err(e) => assert!(e.to_string().contains("corrupt store"), "{e}"),
            Ok(_) => panic!("marker-without-index must be rejected as corruption"),
        }

        // A symlinked blobs/ (redirection attempt) under our sentinel is
        // refused.
        let redir = tmp.path().join("redir");
        std::fs::create_dir_all(&redir).unwrap();
        std::fs::write(redir.join(".fluxor-store-init"), b"x\n").unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, redir.join("blobs")).unwrap();
        assert!(OciStore::open(&redir).is_err());
    }
}
