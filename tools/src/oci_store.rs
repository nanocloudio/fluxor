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

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

// ── Media types (rfc_k8s.md §9) ───────────────────────────────────────

pub const MT_OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const MT_OCI_EMPTY: &str = "application/vnd.oci.empty.v1+json";
pub const MT_FLUXOR_MODULE: &str = "application/vnd.nanocloud.fluxor.module.v1";
pub const MT_FLUXOR_WORKLOAD: &str = "application/vnd.nanocloud.fluxor.workload.v1+json";
pub const MT_FLUXOR_GRAPH: &str = "application/vnd.nanocloud.fluxor.graph.v1+yaml";
pub const MT_FLUXOR_RESOURCES: &str = "application/vnd.nanocloud.fluxor.resources.v1+json";
/// Module manifest.toml metadata carried alongside the `.fmod` layer.
pub const MT_FLUXOR_MODULE_META: &str = "application/vnd.nanocloud.fluxor.module.manifest.v1+toml";

// ── Annotation keys ───────────────────────────────────────────────────

pub const ANN_REF_NAME: &str = "org.opencontainers.image.ref.name";
pub const ANN_TITLE: &str = "org.opencontainers.image.title";
pub const ANN_PROVENANCE: &str = "io.fluxor.provenance";
pub const ANN_SOURCE_REV: &str = "io.fluxor.source-rev";
pub const ANN_KIND: &str = "io.fluxor.kind";
pub const ANN_TARGET: &str = "io.fluxor.module.target";
pub const ANN_MODULE_NAME: &str = "io.fluxor.module.name";

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
    pub fn read_blob(&self, digest: &str) -> Result<Vec<u8>> {
        let path = self.blob_path(digest)?;
        let bytes = fs::read(&path).map_err(|e| {
            Error::Config(format!(
                "blob {digest} not in store {}: {e}",
                self.root.display()
            ))
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
            match self.sweep_candidates(&index, &displaced) {
                Ok(_removed) => {}
                Err(e) => eprintln!(
                    "warning: retag of '{ref_name}' could not sweep the displaced \
                     artifact ({e}); its blobs remain until a future remove"
                ),
            }
        }
        Ok(desc)
    }

    /// Delete every blob in `victims`' closures that no manifest in `index`
    /// still reaches. Fails (deleting nothing) if any live manifest is
    /// unreadable — an unknown layer set is never swept around.
    fn sweep_candidates(&self, index: &ImageIndex, victims: &[Descriptor]) -> Result<Vec<String>> {
        let mut live: BTreeSet<String> = BTreeSet::new();
        for d in &index.manifests {
            live.insert(d.digest.clone());
            let m = self.read_manifest(d).map_err(|e| {
                Error::Config(format!("live manifest {} is unreadable ({e})", d.digest))
            })?;
            live.insert(m.config.digest.clone());
            for l in &m.layers {
                live.insert(l.digest.clone());
            }
        }
        let mut candidates: BTreeSet<String> = BTreeSet::new();
        for v in victims {
            candidates.insert(v.digest.clone());
            if let Ok(m) = self.read_manifest(v) {
                candidates.insert(m.config.digest.clone());
                for l in &m.layers {
                    candidates.insert(l.digest.clone());
                }
            }
        }
        let mut removed = Vec::new();
        for digest in candidates {
            if !live.contains(&digest) {
                let path = self.blob_path(&digest)?;
                if path.exists() {
                    fs::remove_file(&path)?;
                    removed.push(digest);
                }
            }
        }
        Ok(removed)
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
        // that will remain live must be readable (its layer set feeds the
        // keep-set). If this errors, the index is untouched and the command
        // is safely retryable.
        for d in index.manifests.iter().filter(|d| survives(d)) {
            self.read_manifest(d).map_err(|e| {
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
        self.sweep_candidates(&index, core::slice::from_ref(&victim))
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

// ── Helpers ───────────────────────────────────────────────────────────

pub fn sha256_hex_prefixed(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
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
        let (_dir, store) = temp_store();
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
        assert!(removed.contains(&manifest.layers[0].digest));
        assert!(!store.has_blob(&manifest.layers[0].digest));
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
