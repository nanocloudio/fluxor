//! Local OCI image-layout content store for `.fmod` modules and workload
//! bundles.
//!
//! Layout is the standard OCI image layout: `oci-layout` marker,
//! `blobs/sha256/<hex>` content-addressed blobs, and `index.json` holding one
//! descriptor per tagged artifact. Artifacts are OCI image manifests whose
//! `artifactType` is a fluxor media type (one per artifact kind, spelled
//! `application/vnd.nanocloud.fluxor.<kind>.v1`).
//!
//! Four sibling directories carry what the manifests deliberately do not:
//!
//! - `provenance/<hex>.toml` — how a manifest came to be published
//!   ([`ProvenanceRow`]): `local-build` vs `published`, the git revision,
//!   the ci digest. Queryable, not guessed, and outside the manifest so
//!   that re-stamping it cannot move the digest everything pins.
//! - `pins/` — the pin ledger (`store_pins`): which checkouts hold which
//!   digests, and therefore what the collector must not touch.
//! - `quarantine/` — blobs a sweep could not prove live. Any read
//!   restores them; only `fluxor store gc` deletes.
//! - `aliases/<old-hex>` — the one-time restamp mapping, so a lockfile
//!   written before provenance moved out still resolves.
//!
//! Offline-first invariant: nothing in this module touches the network.
//! Publishing writes only into the local store; consumption reads only
//! from it. Identical bytes hash to identical digests and are stored once.
//!
//! Determinism, and it is load-bearing rather than decorative: manifest
//! JSON is serialized from field-ordered structs (no timestamps) and
//! carries only facts derived from the artifact, so re-publishing
//! unchanged content yields byte-identical manifests and therefore
//! identical digests. A publish that changed nothing displaces nothing,
//! sweeps nothing and moves no downstream pin; and promotion between
//! environments is a re-tag of an existing digest, never a rebuild.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

// ── Media types ──────────────────────────────────────────────────────
//
// Every fluxor artifact kind has exactly one media type, spelled
// `application/vnd.nanocloud.fluxor.<kind>.v1` plus an optional encoding
// suffix (`+json`, `+yaml`, `+toml`, `+tar`, `+bin`). A manifest's
// `artifactType` is the media type of what it delivers, so a consumer
// can admit or reject an artifact from the manifest alone.

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
/// the deterministic alignment gaps.
pub const MT_FLUXOR_IMAGE_SKELETON: &str = "application/vnd.nanocloud.fluxor.image.skeleton.v1";
/// Compiled binary graph config.
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
/// Provenance annotations, as manifests published BEFORE the provenance
/// side table carried them. Nothing writes these any more; `fluxor store
/// restamp` reads them off old manifests to file the rows they were
/// carrying, and `fluxor store fsck` reports a manifest still wearing
/// one. See [`ProvenanceRow`] for why they moved.
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

/// How one manifest came to be published: facts about the publishing
/// RUN, not about the artifact.
///
/// They live beside the manifest rather than inside it. `source-rev`
/// changes on every commit, so carrying it in the manifest would rewrite
/// the manifest and move its digest while the layers were untouched —
/// and a lockfile pins the manifest digest, so a publish that changed
/// nothing would orphan every pin everywhere and leave the displaced
/// manifest to the garbage collector. One artifact would exist under as
/// many digests as it had commits, differing in nothing but this field.
///
/// Keeping them beside the manifest instead of inside it makes the
/// manifest a pure function of content and identity, so re-publishing
/// unchanged content yields byte-identical bytes, `put_blob` dedupes,
/// nothing is displaced and no sweep runs. It also makes promotion
/// `local-build` → `published` what this module always claimed it was: a
/// re-tag of an existing digest rather than a rewrite.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProvenanceRow {
    /// `local-build` or `published`.
    pub provenance: String,
    /// Git revision of the publishing tree, when known.
    pub source_rev: Option<String>,
    /// Input digest the project's ci gate last passed on, when known.
    pub ci_digest: Option<String>,
}

impl ProvenanceRow {
    pub fn new(provenance: &str) -> ProvenanceRow {
        ProvenanceRow {
            provenance: provenance.to_string(),
            source_rev: None,
            ci_digest: None,
        }
    }

    #[must_use]
    pub fn with_rev(mut self, rev: Option<&str>) -> ProvenanceRow {
        self.source_rev = rev.map(str::to_string);
        self
    }

    #[must_use]
    pub fn with_ci(mut self, ci: Option<&str>) -> ProvenanceRow {
        self.ci_digest = ci.map(str::to_string);
        self
    }

    /// One `[[record]]` block. Rendering is the identity used for
    /// append-dedup, so it must be stable field-for-field.
    fn render(&self) -> String {
        let mut s = format!("[[record]]\nprovenance = \"{}\"\n", self.provenance);
        if let Some(rev) = &self.source_rev {
            s.push_str(&format!("source-rev = \"{rev}\"\n"));
        }
        if let Some(ci) = &self.ci_digest {
            s.push_str(&format!("ci-digest = \"{ci}\"\n"));
        }
        s.push('\n');
        s
    }

    fn parse_all(text: &str) -> Vec<ProvenanceRow> {
        let mut out: Vec<ProvenanceRow> = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line == "[[record]]" {
                out.push(ProvenanceRow::default());
                continue;
            }
            let Some(row) = out.last_mut() else { continue };
            let Some((key, value)) = line.split_once(" = ") else {
                continue;
            };
            let value = value.trim().trim_matches('"').to_string();
            match key {
                "provenance" => row.provenance = value,
                "source-rev" => row.source_rev = Some(value),
                "ci-digest" => row.ci_digest = Some(value),
                _ => {}
            }
        }
        out
    }

    /// `local-build @ 1a2b3c4d5e6f` — the one-line form both `store ls`
    /// and `fluxor inspect` print.
    pub fn summary(&self) -> String {
        match &self.source_rev {
            Some(rev) => format!("{} @ {}", self.provenance, &rev[..rev.len().min(12)]),
            None => self.provenance.clone(),
        }
    }
}

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

    /// Validate a `sha256:<hex>` digest and return its hex body.
    fn digest_hex(digest: &str) -> Result<&str> {
        let hex = digest
            .strip_prefix("sha256:")
            .ok_or_else(|| Error::Config(format!("digest '{digest}' is not sha256:-prefixed")))?;
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Config(format!("malformed digest '{digest}'")));
        }
        Ok(hex)
    }

    /// Where a swept blob waits instead of being deleted (see
    /// [`OciStore::sweep_with_roots`]).
    pub fn quarantine_dir(&self) -> PathBuf {
        self.root.join("quarantine")
    }

    /// Path of the blob for `sha256:<hex>` digest (whether or not
    /// present).
    ///
    /// A blob the sweep quarantined is HEALED here: it is moved back
    /// into `blobs/` and the caller never learns it was ever away. That
    /// is the whole point of quarantining rather than deleting — a
    /// sweep that could not prove a blob unpinned is undone the moment
    /// something proves it wrong by asking for it.
    pub fn blob_path(&self, digest: &str) -> Result<PathBuf> {
        let hex = Self::digest_hex(digest)?;
        let path = self.root.join("blobs").join("sha256").join(hex);
        if !path.exists() {
            let held = self.quarantine_dir().join(hex);
            if held.exists() {
                if let Some(parent) = path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let _ = fs::rename(&held, &path);
            }
        }
        Ok(path)
    }

    /// Whether the store holds these bytes — in `blobs/` or waiting in
    /// quarantine. Quarantine is not absence: any read restores it.
    ///
    /// Unlike [`OciStore::blob_path`] this never moves anything. A query
    /// that healed as a side effect would make the collector's own mark
    /// pass resurrect every candidate it considered.
    pub fn has_blob(&self, digest: &str) -> bool {
        Self::digest_hex(digest)
            .map(|hex| {
                self.root.join("blobs").join("sha256").join(hex).exists()
                    || self.quarantine_dir().join(hex).exists()
            })
            .unwrap_or(false)
    }

    /// Whether `digest` is currently quarantined — `fsck` reports this;
    /// nothing else needs to know, because every read heals.
    pub fn is_quarantined(&self, digest: &str) -> bool {
        Self::digest_hex(digest)
            .map(|hex| {
                !self.root.join("blobs").join("sha256").join(hex).exists()
                    && self.quarantine_dir().join(hex).exists()
            })
            .unwrap_or(false)
    }

    // ── Restamp aliases ───────────────────────────────────────────────
    //
    // `fluxor store restamp` rewrites every manifest once, to move
    // provenance out of it (see `base_annotations`). That is the only
    // event in the store's life that moves a digest without the content
    // moving, and a lockfile written before it would otherwise pin a
    // digest nothing answers to. An alias records old → new so such a
    // pin still resolves, offline, to a manifest with identical layers,
    // target, epoch and input digest.
    //
    // Aliases are consulted ONLY when the pinned digest is not in the
    // store. They are never consulted by `read_blob`, which must keep
    // meaning "these exact bytes" — substituting different bytes under a
    // content-addressed read is the one thing this store cannot do.

    fn alias_dir(&self) -> PathBuf {
        self.root.join("aliases")
    }

    /// Record that `old` was restamped into `new`.
    pub fn record_alias(&self, old: &str, new: &str) -> Result<()> {
        let hex = Self::digest_hex(old)?;
        Self::digest_hex(new)?;
        fs::create_dir_all(self.alias_dir())?;
        write_atomic(&self.alias_dir().join(hex), new.as_bytes())
    }

    /// The digest `old` was restamped into, if any.
    pub fn alias_of(&self, old: &str) -> Option<String> {
        let hex = Self::digest_hex(old).ok()?;
        let text = fs::read_to_string(self.alias_dir().join(hex)).ok()?;
        let target = text.trim().to_string();
        Self::digest_hex(&target).ok()?;
        Some(target)
    }

    /// Resolve a PINNED digest: itself when the store holds it, else the
    /// digest it was restamped into. Pin-resolution paths call this;
    /// integrity paths (`read_blob`) never do.
    pub fn resolve_pin(&self, digest: &str) -> String {
        if self.has_blob(digest) {
            return digest.to_string();
        }
        self.alias_of(digest)
            .filter(|target| self.has_blob(target))
            .unwrap_or_else(|| digest.to_string())
    }

    // ── Provenance side table ─────────────────────────────────────────

    fn provenance_dir(&self) -> PathBuf {
        self.root.join("provenance")
    }

    /// Append one provenance record for `digest`, unless an identical
    /// record is already filed.
    ///
    /// Append rather than replace: one manifest is legitimately
    /// published from several revisions — that is the NORMAL case, since
    /// a rebuild of unchanged sources now yields the same manifest — and
    /// a table that kept only the last row would throw away the history
    /// the annotation used to carry.
    pub fn record_provenance(&self, digest: &str, row: &ProvenanceRow) -> Result<()> {
        let hex = Self::digest_hex(digest)?;
        let path = self.provenance_dir().join(format!("{hex}.toml"));
        let existing = fs::read_to_string(&path).unwrap_or_default();
        let rendered = row.render();
        if existing.contains(&rendered) {
            return Ok(());
        }
        fs::create_dir_all(self.provenance_dir())?;
        let mut body = if existing.is_empty() {
            String::from(
                "# fluxor provenance — how this manifest came to be published.\n\
                 # Append-only; the manifest carries only facts about its content.\n\n",
            )
        } else {
            existing
        };
        body.push_str(&rendered);
        write_atomic(&path, body.as_bytes())
    }

    /// Every provenance record filed for `digest`, oldest first.
    pub fn provenance_of(&self, digest: &str) -> Vec<ProvenanceRow> {
        let Ok(hex) = Self::digest_hex(digest) else {
            return Vec::new();
        };
        let path = self.provenance_dir().join(format!("{hex}.toml"));
        let Ok(text) = fs::read_to_string(path) else {
            return Vec::new();
        };
        ProvenanceRow::parse_all(&text)
    }

    /// The most recent provenance record for `digest`.
    pub fn latest_provenance(&self, digest: &str) -> Option<ProvenanceRow> {
        self.provenance_of(digest).pop()
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
    annotations.insert(ANN_TARGET.into(), m.target.into());

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
    {
        let desc = store.tag_manifest_locked(&manifest, m.ref_name)?;
        store.record_provenance(
            &desc.digest,
            &ProvenanceRow::new(m.provenance).with_rev(m.source_rev),
        )?;
        Ok(desc)
    }
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
/// layers, each layer annotated with its byte offset in the
/// reassembled image so a consumer can rebuild the exact bytes. Fmod
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
    if let Some(e) = a.epoch {
        annotations.insert(ANN_IMAGE_EPOCH.into(), e.to_string());
    }
    if let Some(hex) = a.abi_surface_hex {
        annotations.insert(ANN_ABI_SURFACE.into(), hex.into());
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
    {
        let desc = store.tag_manifest_locked(&manifest, a.ref_name)?;
        store.record_provenance(
            &desc.digest,
            &ProvenanceRow::new(a.provenance).with_rev(a.source_rev),
        )?;
        Ok(desc)
    }
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
    if let Some(e) = a.epoch {
        annotations.insert(ANN_IMAGE_EPOCH.into(), e.to_string());
    }
    if let Some(hex) = a.abi_surface_hex {
        annotations.insert(ANN_ABI_SURFACE.into(), hex.into());
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
    {
        let desc = store.tag_manifest_locked(&manifest, a.ref_name)?;
        store.record_provenance(
            &desc.digest,
            &ProvenanceRow::new(a.provenance).with_rev(a.source_rev),
        )?;
        Ok(desc)
    }
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
    {
        let desc = store.tag_manifest_locked(&oci_manifest, b.ref_name)?;
        store.record_provenance(
            &desc.digest,
            &ProvenanceRow::new(b.provenance).with_rev(b.source_rev),
        )?;
        Ok(desc)
    }
}

// ── Source / runtime artifacts + transactional batch publish ─────────
//
// The consolidated publish path: every
// artifact kind is prepared (blobs staged, manifest built) and then a
// whole publish commits in ONE locked index write — partial publish is
// impossible by construction. Each artifact is tagged both `name:ver`
// and `name:latest` (the tag `:latest` IS "most recently published
// digest"; version strings are labels under never-bump).

/// Project-association annotation: which project published an artifact.
/// The project index is derived from it, so ownership never has to be
/// inferred from tag shapes or name prefixes.
pub const ANN_PROJECT: &str = "io.fluxor.project";

/// What a publish will do to the index, before it does it.
///
/// Produced by [`OciStore::plan_publish`], which writes nothing: the
/// digests here are hashed from the very bytes the commit will store, so
/// `fluxor publish --dry-run` and the publish that follows it cannot
/// disagree.
pub struct PublishPlan {
    /// Descriptors the index will hold after the swap.
    pub new_descs: Vec<Descriptor>,
    /// Tags this publish repoints.
    pub repointed: BTreeSet<String>,
    /// Descriptors the swap drops: manifests that were reachable by tag
    /// and will not be afterwards.
    pub displaced: Vec<Descriptor>,
    /// `(digest, bytes)` for each prepared manifest.
    pub manifest_blobs: Vec<(String, Vec<u8>)>,
    /// `(digest, bytes)` of the project index.
    pub index_blob: (String, Vec<u8>),
}

/// One manifest a publish will displace that somebody else still pins.
#[derive(Debug, Clone)]
pub struct DisplacedPin {
    /// Every tag moving off it — a manifest normally wears both
    /// `name:version` and `name:latest`, and reporting it twice would
    /// say a publish displaces twice as much as it does.
    pub references: Vec<String>,
    pub old_digest: String,
    pub new_digest: String,
    /// Identical layers AND identical input digest: the publish is doing
    /// nothing to this artifact but moving its name.
    pub content_unchanged: bool,
    /// No workspace member pins the old digest. Under the old root set
    /// that meant "about to be deleted"; it now means "held up by the
    /// ledger alone", which is exactly the coupling worth naming.
    pub outside_members: bool,
    /// Workspace-member checkouts still pinning the old digest.
    pub members: Vec<String>,
    /// Non-member checkouts still pinning it.
    pub outsiders: Vec<String>,
}

impl DisplacedPin {
    /// The versioned tag when there is one — `name:latest` names a
    /// moving pointer, and a pin is never resolved from one.
    pub fn reference(&self) -> &str {
        self.references
            .iter()
            .find(|r| !r.ends_with(":latest"))
            .or_else(|| self.references.first())
            .map_or("", String::as_str)
    }

    /// Every holder, members first.
    pub fn holders(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .members
            .iter()
            .map(|m| format!("{m} (member)"))
            .collect();
        out.extend(self.outsiders.iter().cloned());
        out
    }
}

/// Render a displacement report as the block a publish prints. Empty
/// when nothing anybody pins is moving — which, once provenance lives
/// outside the manifest, is the normal case.
pub fn render_displacement(report: &[DisplacedPin]) -> String {
    if report.is_empty() {
        return String::new();
    }
    let short = |d: &str| -> String {
        d.strip_prefix("sha256:")
            .unwrap_or(d)
            .chars()
            .take(12)
            .collect()
    };
    let mut s = format!(
        "\n  {} manifest(s) will be displaced and are pinned elsewhere:\n\n",
        report.len()
    );
    for p in report {
        s.push_str(&format!(
            "    {:<26} {} → {}   content {}\n",
            p.reference(),
            short(&p.old_digest),
            short(&p.new_digest),
            if p.content_unchanged {
                "UNCHANGED"
            } else {
                "changed"
            }
        ));
        s.push_str(&format!("      pinned by  {}", p.holders().join(", ")));
        if p.outside_members {
            s.push_str("   ← no workspace member pins this");
        }
        s.push('\n');
    }
    let unchanged = report.iter().filter(|p| p.content_unchanged).count();
    if unchanged > 0 {
        s.push_str(&format!(
            "\n  {unchanged} of {} are re-stamps: identical layers, identical input-digest.\n",
            report.len()
        ));
    }
    s
}

/// A staged-but-uncommitted artifact: blobs are in the store, the
/// manifest is built, no tag exists yet. Produced under the caller's
/// batch lock by the `prepare_*` fns; committed by `commit_publish`.
pub struct Prepared {
    pub manifest: ImageManifest,
    /// Canonical tag, e.g. `bcm2712/tls:0.0.1` or `fluxor/src/fluxor-abi:0.0.1`.
    pub ref_name: String,
    /// Moving tag repointed on every publish, e.g. `bcm2712/tls:latest`.
    pub latest_ref: String,
    /// How this publishing run produced it — filed beside the manifest
    /// by `commit_publish`, never inside it.
    pub provenance: ProvenanceRow,
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

/// The annotations a manifest carries: facts DERIVED FROM THE ARTIFACT,
/// and nothing else.
///
/// Provenance, source revision and ci digest are facts about the
/// publishing run, and they live in the provenance side table
/// ([`ProvenanceRow`]) precisely so that re-publishing unchanged content
/// cannot move the digest everything downstream pins.
fn base_annotations(kind: &str, meta: &ArtifactMeta<'_>) -> Annotations {
    let mut a = Annotations::new();
    a.insert(ANN_KIND.into(), kind.into());
    a.insert(ANN_PROJECT.into(), meta.project.into());
    a.insert(ANN_ABI_SURFACE.into(), meta.abi_surface_hex.into());
    if let Some(d) = meta.input_digest_hex {
        a.insert(ANN_INPUT_DIGEST.into(), d.into());
    }
    a
}

/// The provenance of one prepared artifact, filed beside its manifest
/// at commit time.
fn base_provenance(meta: &ArtifactMeta<'_>) -> ProvenanceRow {
    ProvenanceRow::new(meta.provenance)
        .with_rev(meta.source_rev)
        .with_ci(meta.ci_digest_hex)
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
            provenance: base_provenance(meta),
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
            provenance: base_provenance(meta),
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
            provenance: base_provenance(meta),
        })
    }

    /// What a publish WOULD do to the index, computed without writing
    /// anything.
    ///
    /// `commit_publish` and `publish_preview` both go through here, so a
    /// dry run cannot describe a different publish from the one that
    /// follows it: the manifest digests are hashed from exactly the
    /// bytes the commit will store.
    pub fn plan_publish(
        &self,
        index: &ImageIndex,
        project: &str,
        version: &str,
        prepared: &[Prepared],
        deps_annotation: Option<&str>,
    ) -> Result<PublishPlan> {
        let mut new_descs: Vec<Descriptor> = Vec::new();
        let mut repointed: BTreeSet<String> = BTreeSet::new();
        let mut manifest_blobs: Vec<(String, Vec<u8>)> = Vec::new();

        for p in prepared {
            let bytes = serde_json::to_vec(&p.manifest)?;
            let digest = sha256_hex_prefixed(&bytes);
            let size = bytes.len() as u64;
            manifest_blobs.push((digest.clone(), bytes));
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
        let idx_digest = sha256_hex_prefixed(&idx_bytes);
        let idx_size = idx_bytes.len() as u64;
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

        Ok(PublishPlan {
            new_descs,
            repointed,
            displaced,
            manifest_blobs,
            index_blob: (idx_digest, idx_bytes),
        })
    }

    /// Everything a publish would displace that some checkout on this
    /// machine is still pinning — computed BEFORE anything is written.
    ///
    /// This is the report that turns an invisible coupling into a
    /// decision. A consumer's pin is protected by the ledger, but a pin
    /// going stale is still that consumer's problem to know about, and
    /// the publisher is the only party who can see it coming.
    pub fn displacement_report(
        &self,
        plan: &PublishPlan,
        publisher: &Path,
    ) -> Result<Vec<DisplacedPin>> {
        let holders = crate::store_pins::holders(&self.root)?;
        // Keyed by the DISPLACED DIGEST, not by tag: one manifest wears
        // `name:version` and `name:latest`, and both move together.
        let mut by_digest: BTreeMap<String, DisplacedPin> = BTreeMap::new();
        for old in &plan.displaced {
            let Some(reference) = old.annotations.get(ANN_REF_NAME) else {
                continue;
            };
            let others = holders.others(&old.digest, publisher);
            if others.is_empty() {
                continue;
            }
            if let Some(existing) = by_digest.get_mut(&old.digest) {
                existing.references.push(reference.clone());
                continue;
            }
            let new_digest = plan
                .new_descs
                .iter()
                .find(|n| n.annotations.get(ANN_REF_NAME) == Some(reference))
                .map(|n| n.digest.clone())
                .unwrap_or_default();
            by_digest.insert(
                old.digest.clone(),
                DisplacedPin {
                    references: vec![reference.clone()],
                    content_unchanged: self.same_content(&old.digest, &new_digest, plan),
                    outside_members: !holders.any_member(&old.digest),
                    members: others
                        .iter()
                        .filter(|h| holders.members.contains(*h))
                        .cloned()
                        .collect(),
                    outsiders: others
                        .iter()
                        .filter(|h| !holders.members.contains(*h))
                        .cloned()
                        .collect(),
                    old_digest: old.digest.clone(),
                    new_digest,
                },
            );
        }
        let mut out: Vec<DisplacedPin> = by_digest.into_values().collect();
        for p in &mut out {
            p.references.sort();
        }
        out.sort_by_key(|p| p.reference().to_string());
        Ok(out)
    }

    /// Whether two manifests deliver the same artifact: identical layer
    /// digests AND identical input digest.
    ///
    /// Both conditions, never one. The input digest is not a content
    /// address: it hashes a module's declared sources and not the
    /// toolchain or the catalog, so two manifests can share one and
    /// still deliver different `.fmod` bytes. The layer list alone would
    /// miss a re-targeting. Together they are the honest claim.
    fn same_content(&self, old: &str, new: &str, plan: &PublishPlan) -> bool {
        let Ok(old_m) = self
            .read_blob(old)
            .and_then(|b| Ok(serde_json::from_slice::<ImageManifest>(&b)?))
        else {
            return false;
        };
        let Some(new_m) = plan
            .manifest_blobs
            .iter()
            .find(|(d, _)| d == new)
            .and_then(|(_, b)| serde_json::from_slice::<ImageManifest>(b).ok())
        else {
            return false;
        };
        let layers = |m: &ImageManifest| -> Vec<String> {
            m.layers.iter().map(|l| l.digest.clone()).collect()
        };
        layers(&old_m) == layers(&new_m)
            && old_m.annotations.get(ANN_INPUT_DIGEST) == new_m.annotations.get(ANN_INPUT_DIGEST)
    }

    /// Commit a whole publish: stage every manifest blob, then repoint
    /// every tag (`name:ver` + `name:latest`) and rewrite the project
    /// index in ONE index write under the lock. Afterwards, sweep
    /// displaced closures with the full liveness root set (tags ∪
    /// snapshot children ∪ every pin in the ledger).
    ///
    /// Returns the committed descriptors and the displacement report,
    /// computed before the index write so the caller can print it
    /// whether or not the sweep then finds anything to do.
    pub fn commit_publish(
        &self,
        _txn: &PublishLock,
        project: &str,
        version: &str,
        prepared: Vec<Prepared>,
        deps_annotation: Option<&str>,
    ) -> Result<Vec<Descriptor>> {
        self.commit_publish_reported(_txn, project, version, prepared, deps_annotation, None)
            .map(|(descs, _)| descs)
    }

    /// `commit_publish` plus the displacement report. `publisher` is the
    /// checkout doing the publishing — its own pins are not somebody
    /// else's problem, so they are excluded from the report.
    pub fn commit_publish_reported(
        &self,
        _txn: &PublishLock,
        project: &str,
        version: &str,
        prepared: Vec<Prepared>,
        deps_annotation: Option<&str>,
        publisher: Option<&Path>,
    ) -> Result<(Vec<Descriptor>, Vec<DisplacedPin>)> {
        let mut index = self.read_index()?;
        let plan = self.plan_publish(&index, project, version, &prepared, deps_annotation)?;

        // Before any mutation, while the displaced manifests are still
        // readable: who else is holding what this publish is about to
        // move off its tag.
        let report = match publisher {
            Some(p) => self.displacement_report(&plan, p).unwrap_or_default(),
            None => Vec::new(),
        };

        for (_digest, bytes) in &plan.manifest_blobs {
            self.put_blob(bytes)?;
        }
        self.put_blob(&plan.index_blob.1)?;

        // Provenance travels beside the manifest, not inside it, so an
        // unchanged artifact re-published from a later commit is the
        // SAME manifest with one more row filed against it.
        for (p, (digest, _)) in prepared.iter().zip(&plan.manifest_blobs) {
            self.record_provenance(digest, &p.provenance)?;
        }

        // The single swap: drop every repointed ref, append the batch.
        index.manifests.retain(|d| {
            d.annotations
                .get(ANN_REF_NAME)
                .is_none_or(|r| !plan.repointed.contains(r))
        });
        index.manifests.extend(plan.new_descs.clone());
        self.write_index(&index)?;

        if !plan.displaced.is_empty() {
            match self.sweep_with_roots(&index, &plan.displaced) {
                Ok(_removed) => {}
                Err(e) => eprintln!(
                    "warning: publish could not sweep displaced artifacts ({e}); \
                     their blobs remain until a future sweep"
                ),
            }
        }
        Ok((plan.new_descs, report))
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
    /// a manifest), plus every `sha256:` digest any checkout on this
    /// machine pins (`store_pins`) — each pin expanded through ITS
    /// closure, so a pinned manifest keeps every blob it references.
    ///
    /// The root class is every checkout, not workspace members alone:
    /// the ledger asks the question that decides the outcome — is anyone
    /// holding this? — rather than whether the holder appears on a
    /// hand-maintained list. A manifest pinned only by a checkout the
    /// sweep cannot see would be deleted, and a rebuild yields a
    /// different digest, so it would be gone rather than re-derivable.
    ///
    /// An unreadable ledger entry or member lockfile — or a pin whose
    /// blob is present but unreadable — fails CLOSED for the sweep only:
    /// warn and quarantine nothing; the publish that triggered the sweep
    /// has already succeeded (registry_consolidation.md, GC rules).
    ///
    /// Nothing here deletes. Doomed blobs are MOVED to `quarantine/`,
    /// from which any read restores them; only `fluxor store gc` unlinks
    /// bytes, and only after they have sat there long enough.
    ///
    /// Invariant: no blob referenced by any manifest still present in
    /// the store is ever quarantined, and quarantining runs strictly in
    /// tier order — indexes, then the manifests they list, then leaves.
    /// An interrupted sweep therefore leaves orphaned bytes, never a
    /// referent-missing index or manifest.
    fn sweep_with_roots(&self, index: &ImageIndex, victims: &[Descriptor]) -> Result<Vec<String>> {
        let mut live: BTreeSet<String> = BTreeSet::new();
        let mut tiers: BTreeMap<String, BlobTier> = BTreeMap::new();
        for d in &index.manifests {
            self.add_closure(d, &mut live, &mut tiers).map_err(|e| {
                Error::Config(format!("live manifest {} is unreadable ({e})", d.digest))
            })?;
        }
        for digest in crate::store_pins::root_digests(&self.root)? {
            // A pin written before the restamp names a manifest the
            // store may no longer hold under that digest; its alias is
            // just as live, and sweeping it would strand the pin for
            // good.
            for d in [digest.clone(), self.resolve_pin(&digest)] {
                self.add_closure_by_digest(&d, &mut live, &mut tiers)
                    .map_err(|e| Error::Config(format!("pinned blob {d} is unreadable ({e})")))?;
            }
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
        let quarantine = self.quarantine_dir();
        if !doomed.is_empty() {
            fs::create_dir_all(&quarantine)?;
        }
        let mut removed = Vec::new();
        for digest in doomed {
            let Ok(hex) = Self::digest_hex(digest) else {
                continue;
            };
            let Ok(p) = self.blob_path(digest) else {
                continue;
            };
            // Move, never unlink. A sweep cannot prove a blob unpinned —
            // it can only prove it did not find a root — and the cost of
            // being wrong is an artifact nobody can rebuild to the same
            // digest. Quarantined bytes come back automatically the next
            // time anything asks for them (`blob_path`), and are deleted
            // only by the explicit `fluxor store gc`.
            if fs::rename(&p, quarantine.join(hex)).is_ok() {
                removed.push(digest.clone());
            }
        }
        Ok(removed)
    }
}

/// What one `fluxor store restamp` did.
#[derive(Debug, Default)]
pub struct RestampReport {
    /// `(old digest, new digest)` for every manifest or index rewritten.
    pub moved: Vec<(String, String)>,
    /// Manifests already carrying no provenance annotations.
    pub already_clean: usize,
    /// Provenance rows recovered from stripped annotations.
    pub rows_filed: usize,
}

/// What one `fluxor store gc` did.
#[derive(Debug, Default)]
pub struct GcReport {
    /// Blobs moved into quarantine by this run.
    pub quarantined: Vec<String>,
    /// Quarantined blobs deleted because they aged out.
    pub deleted: Vec<String>,
    /// Bytes reclaimed by those deletions.
    pub bytes_freed: u64,
    /// Ledger entries dropped (`--forget-missing` only).
    pub forgotten: Vec<PathBuf>,
    /// Quarantined blobs still inside the retention window.
    pub held: usize,
}

impl OciStore {
    /// Every blob reachable from the index, plus every pinned digest's
    /// closure — the full live set, for `gc` and `fsck`.
    ///
    /// Unlike the sweep's internal walk this NEVER errors on a bad
    /// manifest: a report that stops at the first damaged blob cannot
    /// tell you how much damage there is. Unreadable referrers are
    /// returned instead, and the caller decides.
    pub fn live_closure(&self) -> Result<(BTreeSet<String>, Vec<String>)> {
        let index = self.read_index()?;
        let mut live: BTreeSet<String> = BTreeSet::new();
        let mut damaged: Vec<String> = Vec::new();
        let mut stack: Vec<String> = index.manifests.iter().map(|d| d.digest.clone()).collect();
        for digest in crate::store_pins::root_digests(&self.root)? {
            stack.push(self.resolve_pin(&digest));
            stack.push(digest);
        }
        while let Some(digest) = stack.pop() {
            if !live.insert(digest.clone()) {
                continue;
            }
            if !self.has_blob(&digest) {
                continue;
            }
            let Ok(bytes) = self.read_blob(&digest) else {
                damaged.push(digest);
                continue;
            };
            if let Ok(m) = serde_json::from_slice::<ImageManifest>(&bytes) {
                live.insert(m.config.digest.clone());
                live.extend(m.layers.iter().map(|l| l.digest.clone()));
                continue;
            }
            if let Ok(idx) = serde_json::from_slice::<ImageIndex>(&bytes) {
                if idx.media_type == MT_OCI_INDEX {
                    stack.extend(idx.manifests.iter().map(|c| c.digest.clone()));
                }
            }
        }
        Ok((live, damaged))
    }

    /// Full mark-and-sweep plus quarantine expiry — the ONLY verb in the
    /// store that deletes bytes.
    ///
    /// The displacement sweep is triggered by a retag and only ever
    /// considers the victim's own closure, so a blob spared once — it
    /// was pinned at that instant — is never a candidate again and
    /// leaks for good. Unreachable bytes therefore accumulate without
    /// bound, and the sweep's attention stays on the one closure it was
    /// handed, which is where the pinned blobs are. This is the other
    /// half: a deliberate, whole-store pass an operator runs, with a
    /// retention window, rather than a reflex on a hot path.
    pub fn gc(&self, retain_days: u64, forget_missing: bool) -> Result<GcReport> {
        let _lock = self.lock_index()?;
        let mut report = GcReport::default();
        if forget_missing {
            report.forgotten = crate::store_pins::forget_missing(&self.root)?;
        }
        let (live, damaged) = self.live_closure()?;
        if !damaged.is_empty() {
            return Err(Error::Config(format!(
                "refusing to collect: {} referrer(s) are present but unreadable, so what \
                 they keep alive is unknowable (first: {}) — run `fluxor store fsck`",
                damaged.len(),
                damaged[0]
            )));
        }

        let blobs = self.root.join("blobs").join("sha256");
        let quarantine = self.quarantine_dir();
        let mut doomed: Vec<String> = Vec::new();
        if blobs.is_dir() {
            for entry in fs::read_dir(&blobs)? {
                let name = entry?.file_name().to_string_lossy().to_string();
                if name.len() != 64 {
                    continue;
                }
                let digest = format!("sha256:{name}");
                if !live.contains(&digest) {
                    doomed.push(digest);
                }
            }
        }
        doomed.sort();
        if !doomed.is_empty() {
            fs::create_dir_all(&quarantine)?;
        }
        for digest in &doomed {
            let hex = Self::digest_hex(digest)?;
            if fs::rename(blobs.join(hex), quarantine.join(hex)).is_ok() {
                report.quarantined.push(digest.clone());
            }
        }

        // Expiry: quarantined bytes that have sat out the retention
        // window and that nothing has asked for (a read would have
        // healed them straight back into `blobs/`).
        let cutoff = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(retain_days * 86_400));
        if quarantine.is_dir() {
            for entry in fs::read_dir(&quarantine)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().to_string();
                if name.len() != 64 {
                    continue;
                }
                let meta = entry.metadata()?;
                let aged = match (cutoff, meta.modified().ok()) {
                    (Some(cutoff), Some(modified)) => modified < cutoff,
                    // No clock to compare against: keep. Deleting on a
                    // guess is the failure mode this whole path exists
                    // to avoid.
                    _ => false,
                };
                if aged {
                    let size = meta.len();
                    if fs::remove_file(entry.path()).is_ok() {
                        report.deleted.push(format!("sha256:{name}"));
                        report.bytes_freed += size;
                    }
                } else {
                    report.held += 1;
                }
            }
        }
        Ok(report)
    }

    /// Move provenance out of every manifest in the store, once.
    ///
    /// This is the migration for [`ProvenanceRow`]: manifests published
    /// before provenance moved to the side table carry annotations that
    /// change on every publish, so they keep churning until they are
    /// rewritten. Rewriting moves each digest exactly once and never
    /// again.
    ///
    /// No lock is stranded by it. The old manifest blob stays in the
    /// store — a few hundred bytes, and its layers are the same ones —
    /// so a pin written beforehand keeps resolving directly; and if a
    /// later `gc` does eventually collect it, `resolve_pin` follows the
    /// alias recorded here to the rewritten manifest, which carries
    /// identical layers, target, epoch and input digest.
    pub fn restamp(&self) -> Result<RestampReport> {
        let _lock = self.lock_index()?;
        let mut report = RestampReport::default();
        let mut index = self.read_index()?;
        let mut map: BTreeMap<String, Descriptor> = BTreeMap::new();

        // Manifests first, then the indexes that list them, so a
        // rewritten index always points at rewritten children.
        let mut order: Vec<Descriptor> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut stack: Vec<Descriptor> = index.manifests.clone();
        while let Some(d) = stack.pop() {
            if !seen.insert(d.digest.clone()) {
                continue;
            }
            if d.media_type == MT_OCI_INDEX {
                if let Ok(bytes) = self.read_blob(&d.digest) {
                    if let Ok(idx) = serde_json::from_slice::<ImageIndex>(&bytes) {
                        stack.extend(idx.manifests);
                    }
                }
            }
            order.push(d);
        }
        // Leaves (manifests) before their referrers.
        order.sort_by_key(|d| u8::from(d.media_type == MT_OCI_INDEX));

        // One pass suffices for a manifest under an index, but an index
        // listing another index — a snapshot over project indexes — can
        // be visited before its child and would then be rewritten around
        // a digest that moves afterwards. Iterate to a fixpoint rather
        // than reason about the order: rewriting is idempotent, so a
        // second visit either changes nothing or corrects a stale child.
        // Bounded, because a cycle is impossible in a content-addressed
        // graph but a bug that produced one must not hang a migration.
        for _pass in 0..8 {
            let before = map.len();
            self.restamp_pass(&order, &mut map, &mut report)?;
            if map.len() == before {
                break;
            }
        }
        report.moved.sort();
        report.moved.dedup_by_key(|(old, _)| old.clone());

        for d in &mut index.manifests {
            let ref_name = d.annotations.get(ANN_REF_NAME).cloned();
            if let Some(new) = map.get(&d.digest) {
                d.digest = new.digest.clone();
                d.size = new.size;
            }
            d.annotations = strip_provenance(&d.annotations);
            if let Some(r) = ref_name {
                d.annotations.insert(ANN_REF_NAME.into(), r);
            }
        }
        self.write_index(&index)?;
        Ok(report)
    }

    /// One rewriting pass over `order`, accumulating old → new in `map`.
    fn restamp_pass(
        &self,
        order: &[Descriptor],
        map: &mut BTreeMap<String, Descriptor>,
        report: &mut RestampReport,
    ) -> Result<()> {
        for d in order {
            // A manifest's rewrite depends only on its own bytes, so it
            // is settled after one visit. Only an index can be made
            // stale by a later pass, and only an index is revisited.
            if d.media_type != MT_OCI_INDEX && map.contains_key(&d.digest) {
                continue;
            }
            let Ok(bytes) = self.read_blob(&d.digest) else {
                continue;
            };
            let rewritten = if d.media_type == MT_OCI_INDEX {
                let Ok(idx) = serde_json::from_slice::<ImageIndex>(&bytes) else {
                    continue;
                };
                let children: Vec<Descriptor> = idx
                    .manifests
                    .iter()
                    .map(|c| match map.get(&c.digest) {
                        Some(new) => Descriptor {
                            media_type: c.media_type.clone(),
                            digest: new.digest.clone(),
                            size: new.size,
                            annotations: strip_provenance(&c.annotations),
                        },
                        None => Descriptor {
                            annotations: strip_provenance(&c.annotations),
                            ..c.clone()
                        },
                    })
                    .collect();
                serde_json::to_vec(&ImageIndex {
                    manifests: children,
                    ..idx
                })?
            } else {
                let Ok(m) = serde_json::from_slice::<ImageManifest>(&bytes) else {
                    continue;
                };
                report.rows_filed += usize::from(self.file_legacy_provenance(&d.digest, &m)?);
                serde_json::to_vec(&ImageManifest {
                    annotations: strip_provenance(&m.annotations),
                    ..m
                })?
            };
            if rewritten == bytes {
                report.already_clean += 1;
                continue;
            }
            let (new_digest, new_size) = self.put_blob(&rewritten)?;
            self.record_alias(&d.digest, &new_digest)?;
            // Provenance already filed under the OLD digest is filed
            // under the new one too, so `store ls` keeps answering after
            // the rewrite.
            for row in self.provenance_of(&d.digest) {
                self.record_provenance(&new_digest, &row)?;
            }
            report.moved.push((d.digest.clone(), new_digest.clone()));
            map.insert(
                d.digest.clone(),
                Descriptor {
                    media_type: d.media_type.clone(),
                    digest: new_digest,
                    size: new_size,
                    annotations: Annotations::new(),
                },
            );
        }
        Ok(())
    }

    /// File the provenance an old manifest was carrying as annotations.
    /// Returns whether a row was filed.
    fn file_legacy_provenance(&self, digest: &str, m: &ImageManifest) -> Result<bool> {
        let Some(provenance) = m.annotations.get(ANN_PROVENANCE) else {
            return Ok(false);
        };
        let row = ProvenanceRow::new(provenance)
            .with_rev(m.annotations.get(ANN_SOURCE_REV).map(String::as_str))
            .with_ci(m.annotations.get(ANN_CI_DIGEST).map(String::as_str));
        self.record_provenance(digest, &row)?;
        Ok(true)
    }
}

/// Drop the three publishing-run annotations, keeping every annotation
/// that describes the artifact itself.
fn strip_provenance(a: &Annotations) -> Annotations {
    a.iter()
        .filter(|(k, _)| {
            k.as_str() != ANN_PROVENANCE
                && k.as_str() != ANN_SOURCE_REV
                && k.as_str() != ANN_CI_DIGEST
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
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
        // Provenance is filed BESIDE the manifest, never inside it, so a
        // re-publish from a later commit cannot move the digest every
        // downstream lockfile pins.
        assert!(
            !manifest.annotations.contains_key(ANN_PROVENANCE)
                && !manifest.annotations.contains_key(ANN_SOURCE_REV),
            "manifest annotations must describe the artifact, not the publishing run: {:?}",
            manifest.annotations
        );
        let row = store
            .latest_provenance(&desc.digest)
            .expect("provenance row");
        assert_eq!(row.provenance, PROVENANCE_LOCAL);
        assert_eq!(row.source_rev.as_deref(), Some("deadbeef"));
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
        // Swept, not deleted. A sweep can only ever prove it did not FIND
        // a root, and the cost of being wrong is an artifact nobody can
        // rebuild to the same digest — so the bytes wait in quarantine,
        // where any read brings them back, until `fluxor store gc`.
        assert!(store.is_quarantined(&manifest.layers[0].digest));
        assert_eq!(
            store.read_blob(&manifest.layers[0].digest).unwrap(),
            b"shared"
        );
        assert!(
            !store.is_quarantined(&manifest.layers[0].digest),
            "reading a quarantined blob must restore it"
        );
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
        assert!(!m.annotations.contains_key(ANN_PROVENANCE));
        let row = store
            .latest_provenance(&desc.digest)
            .expect("provenance row");
        assert_eq!(row.provenance, PROVENANCE_PUBLISHED);
        assert_eq!(row.source_rev, None);
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
        // Displaced closure is swept — into quarantine, not oblivion.
        assert!(
            store.is_quarantined(&old.digest),
            "old manifest must be swept"
        );
        assert!(
            store.is_quarantined(&old_fmod),
            "old fmod layer must be swept"
        );
        // Shared + current content is never even a candidate.
        assert!(store.has_blob(&shared_meta), "shared layer must survive");
        assert!(!store.is_quarantined(&shared_meta));
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

    // ── Pin stability ────────────────────────────────────────────────
    //
    // A publish that changes nothing must change nothing, and a publish
    // that DOES change something must not destroy the version it
    // displaced. The two rules meet here: provenance sits beside the
    // manifest so an unchanged artifact re-publishes byte-identically,
    // and the sweep treats every checkout's pins as roots so a displaced
    // manifest somebody still holds is not collected.
    //
    // These drive the real batch-publish path (`prepare_module` +
    // `commit_publish`), because that is what `fluxor publish` runs and
    // it is where the displacement sweep is triggered.

    /// A store, one workspace MEMBER that pins nothing, and one
    /// NON-member checkout — the shape in which membership and holding
    /// disagree.
    struct PinFixture {
        _dir: tempfile::TempDir,
        _scope: EnvScope,
        store: OciStore,
        outsider: PathBuf,
    }

    fn pin_fixture() -> PinFixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = OciStore::open(dir.path().join("store")).expect("open");

        let member = dir.path().join("member");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(member.join("fluxor.lock"), "artifact = []\n").unwrap();

        let outsider = dir.path().join("outsider");
        std::fs::create_dir_all(&outsider).unwrap();

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
        PinFixture {
            _dir: dir,
            _scope,
            store,
            outsider,
        }
    }

    /// Publish `rp2350/tls:0.0.1` from `rev`, carrying `fmod`. Input
    /// digest and epoch are fixed: only the git revision and the bytes
    /// vary, which is what separates a re-stamp from a real change.
    fn publish_tls(store: &OciStore, rev: &str, fmod: &[u8]) -> Descriptor {
        const TOML: &str = "version = \"1.0.0\"\n";
        let meta = ArtifactMeta {
            project: "fluxor",
            provenance: PROVENANCE_LOCAL,
            source_rev: Some(rev),
            abi_surface_hex: "3ce0e712ede1",
            input_digest_hex: Some("c9918a03e139"),
            ci_digest_hex: None,
        };
        let txn = store.begin_publish().expect("begin publish");
        let prepared = store
            .prepare_module("tls", "rp2350", "0.0.1", fmod, Some(TOML), &meta)
            .expect("prepare");
        let descs = store
            .commit_publish(&txn, "fluxor", "0.0.1", vec![prepared], None)
            .expect("commit");
        descs
            .into_iter()
            .find(|d| {
                d.annotations.get(ANN_REF_NAME).map(String::as_str) == Some("rp2350/tls:0.0.1")
            })
            .expect("versioned tag in the publish result")
    }

    /// Write the outsider's lockfile and register it with the store, the
    /// way `fluxor update` does.
    fn outsider_pins(fx: &PinFixture, digest: &str) {
        std::fs::write(
            fx.outsider.join("fluxor.lock"),
            format!(
                "[[artifact]]\nkind = \"module\"\nname = \"tls\"\n\
                 project = \"fluxor\"\ntarget = \"rp2350\"\n\
                 digest = \"{digest}\"\nreference = \"rp2350/tls:0.0.1\"\n"
            ),
        )
        .unwrap();
        let n = crate::store_pins::adopt(fx.store.root(), &fx.outsider).expect("adopt");
        assert_eq!(n, 1, "the outsider registered exactly one pin");
    }

    /// CHURN. Re-publishing byte-identical content from a later commit
    /// must leave the manifest digest exactly where it was — no pin
    /// moves, nothing is displaced, no sweep runs.
    #[test]
    fn republishing_unchanged_content_does_not_move_the_manifest_digest() {
        let _env = test_env_lock();
        let fx = pin_fixture();
        const FMOD: &[u8] = b"identical-fmod-bytes";

        let first = publish_tls(&fx.store, "dbec8a4b73e5", FMOD);
        let first_manifest = fx.store.read_manifest(&first).unwrap();

        let second = publish_tls(&fx.store, "abad0790a752", FMOD);
        let second_manifest = fx.store.read_manifest(&second).unwrap();

        assert_eq!(
            first_manifest.layers, second_manifest.layers,
            "fixture error: the two publishes did not carry identical layers"
        );
        assert_eq!(
            first.digest, second.digest,
            "a publish that changed no content moved the manifest digest \
             ({} -> {}), which orphans every pin of this artifact everywhere",
            first.digest, second.digest
        );

        // Both revisions are on record; the manifest carries neither.
        let rows = fx.store.provenance_of(&first.digest);
        assert_eq!(rows.len(), 2, "both publishing runs are recorded: {rows:?}");
        assert_eq!(rows[0].source_rev.as_deref(), Some("dbec8a4b73e5"));
        assert_eq!(rows[1].source_rev.as_deref(), Some("abad0790a752"));
    }

    /// DESTRUCTION. When the content DOES change, the manifest the
    /// publish displaces is still pinned by a checkout that is not a
    /// workspace member. Its pin must keep resolving: membership decides
    /// who is epoch-checked, not who is allowed to hold a digest.
    #[test]
    fn a_publish_does_not_destroy_a_manifest_pinned_only_by_a_non_member() {
        let _env = test_env_lock();
        let fx = pin_fixture();

        let first = publish_tls(&fx.store, "dbec8a4b73e5", b"v1-bytes");
        let first_manifest = fx.store.read_manifest(&first).unwrap();
        outsider_pins(&fx, &first.digest);

        let second = publish_tls(&fx.store, "abad0790a752", b"v2-bytes");
        assert_ne!(first.digest, second.digest, "the content did change");

        assert!(
            fx.store.has_blob(&first.digest),
            "publish destroyed manifest {} — the only checkout pinning it is not a \
             workspace member",
            first.digest
        );
        assert!(
            !fx.store.is_quarantined(&first.digest),
            "a ledger pin is a root"
        );
        for l in &first_manifest.layers {
            assert!(
                fx.store.has_blob(&l.digest),
                "publish destroyed layer {} of a manifest a non-member pins",
                l.digest
            );
        }
        assert_eq!(
            fx.store
                .read_blob(&first_manifest.layers[0].digest)
                .unwrap(),
            b"v1-bytes"
        );
    }

    /// The publisher learns, before it writes anything, whose pins its
    /// publish is about to leave behind — and the dry run describes the
    /// publish that would actually follow it.
    #[test]
    fn the_displacement_report_names_holders_before_the_index_moves() {
        let _env = test_env_lock();
        let fx = pin_fixture();
        let first = publish_tls(&fx.store, "dbec8a4b73e5", b"v1-bytes");
        outsider_pins(&fx, &first.digest);

        let meta = ArtifactMeta {
            project: "fluxor",
            provenance: PROVENANCE_LOCAL,
            source_rev: Some("abad0790a752"),
            abi_surface_hex: "3ce0e712ede1",
            input_digest_hex: Some("c9918a03e139"),
            ci_digest_hex: None,
        };
        let txn = fx.store.begin_publish().unwrap();
        let prepared = fx
            .store
            .prepare_module("tls", "rp2350", "0.0.1", b"v2-bytes", None, &meta)
            .unwrap();
        let index = fx.store.read_index().unwrap();
        let plan = fx
            .store
            .plan_publish(
                &index,
                "fluxor",
                "0.0.1",
                std::slice::from_ref(&prepared),
                None,
            )
            .unwrap();
        // The publisher is a third directory: the outsider's pin is
        // somebody else's problem, which is the whole point.
        let publisher = fx._dir.path().join("publisher");
        std::fs::create_dir_all(&publisher).unwrap();
        let report = fx.store.displacement_report(&plan, &publisher).unwrap();

        assert_eq!(
            report.len(),
            1,
            "one MANIFEST is displaced, though it wears two tags: {report:?}"
        );
        assert_eq!(report[0].reference(), "rp2350/tls:0.0.1");
        assert_eq!(
            report[0].references,
            vec!["rp2350/tls:0.0.1", "rp2350/tls:latest"]
        );
        assert_eq!(report[0].old_digest, first.digest);
        assert!(!report[0].content_unchanged, "the bytes did change");
        assert_eq!(report[0].outsiders, vec!["outsider".to_string()]);
        assert!(
            report[0].outside_members,
            "no workspace member pins it — the line that names the coupling"
        );
        assert!(render_displacement(&report).contains("no workspace member pins this"));

        // Nothing was written: the plan is pure, so the dry run is honest.
        assert_eq!(
            fx.store.resolve("rp2350/tls:0.0.1").unwrap().digest,
            first.digest
        );
        drop(txn);
    }

    /// A manifest nobody pins is still not deleted: it waits in
    /// quarantine, and asking for it brings it back.
    #[test]
    fn an_unpinned_displaced_manifest_is_quarantined_not_deleted() {
        let _env = test_env_lock();
        let fx = pin_fixture();
        let first = publish_tls(&fx.store, "dbec8a4b73e5", b"v1-bytes");
        let layers = fx.store.read_manifest(&first).unwrap().layers;
        publish_tls(&fx.store, "abad0790a752", b"v2-bytes");

        assert!(fx.store.is_quarantined(&first.digest));
        // A read heals it — the sweep proved it did not find a root, not
        // that there was none.
        assert!(fx.store.read_blob(&first.digest).is_ok());
        assert!(!fx.store.is_quarantined(&first.digest));
        assert_eq!(fx.store.read_blob(&layers[0].digest).unwrap(), b"v1-bytes");
    }

    /// The migration: provenance leaves the manifest once, every moved
    /// digest is aliased, and a lockfile written beforehand still
    /// resolves — even after the old manifest is collected.
    #[test]
    fn restamp_moves_each_digest_once_and_strands_no_lock() {
        let _env = test_env_lock();
        let fx = pin_fixture();

        // A manifest in the pre-restamp shape: provenance inside it.
        let legacy = publish_module(
            &fx.store,
            &ModulePublish {
                name: "tls",
                target: "rp2350",
                fmod_bytes: b"v1-bytes",
                manifest_toml: None,
                provenance: PROVENANCE_LOCAL,
                source_rev: Some("dbec8a4b73e5"),
                ref_name: "rp2350/tls:0.0.1",
            },
        )
        .unwrap();
        let mut manifest = fx.store.read_manifest(&legacy).unwrap();
        manifest
            .annotations
            .insert(ANN_SOURCE_REV.into(), "dbec8a4b73e5".into());
        manifest
            .annotations
            .insert(ANN_PROVENANCE.into(), PROVENANCE_LOCAL.into());
        let (old_digest, _) = fx
            .store
            .put_blob(&serde_json::to_vec(&manifest).unwrap())
            .unwrap();
        let tagged = fx
            .store
            .tag_manifest(&manifest, "rp2350/tls:0.0.1")
            .unwrap();
        assert_eq!(tagged.digest, old_digest);
        outsider_pins(&fx, &old_digest);

        let report = fx.store.restamp().unwrap();
        assert!(
            !report.moved.is_empty(),
            "the legacy manifest was rewritten"
        );
        let new_digest = fx.store.resolve("rp2350/tls:0.0.1").unwrap().digest;
        assert_ne!(new_digest, old_digest);

        let restamped = fx.store.read_blob(&new_digest).unwrap();
        let restamped: ImageManifest = serde_json::from_slice(&restamped).unwrap();
        assert!(!restamped.annotations.contains_key(ANN_SOURCE_REV));
        assert_eq!(restamped.layers, manifest.layers, "content did not move");
        assert_eq!(
            fx.store
                .latest_provenance(&new_digest)
                .unwrap()
                .source_rev
                .as_deref(),
            Some("dbec8a4b73e5"),
            "the annotation it was carrying became a provenance row"
        );

        // The old manifest is still there, so the outsider's pin resolves
        // directly. Remove it and the alias takes over — offline, with no
        // re-pin, onto a manifest carrying identical layers.
        assert_eq!(fx.store.resolve_pin(&old_digest), old_digest);
        std::fs::remove_file(fx.store.blob_path(&old_digest).unwrap()).unwrap();
        assert_eq!(fx.store.resolve_pin(&old_digest), new_digest);
    }

    /// The whole-store collector: it reclaims what the displacement
    /// sweep never revisits, and it keeps everything any checkout pins.
    #[test]
    fn gc_collects_the_unreachable_and_keeps_every_pin() {
        let _env = test_env_lock();
        let fx = pin_fixture();
        let first = publish_tls(&fx.store, "dbec8a4b73e5", b"v1-bytes");
        outsider_pins(&fx, &first.digest);
        publish_tls(&fx.store, "abad0790a752", b"v2-bytes");

        // An orphan the displacement sweep will never consider: it is in
        // no victim's closure, so only a whole-store pass finds it.
        let (orphan, _) = fx.store.put_blob(b"nobody references these bytes").unwrap();

        let report = fx.store.gc(30, false).unwrap();
        assert!(
            report.quarantined.contains(&orphan),
            "gc must find orphans the displacement sweep never revisits"
        );
        assert!(report.deleted.is_empty(), "nothing has aged out yet");
        assert!(
            !report.quarantined.contains(&first.digest),
            "a pinned manifest is a root, whoever holds it"
        );
        assert!(fx.store.has_blob(&first.digest));

        // Zero retention: quarantined bytes go for good. This is the only
        // verb in the store that deletes.
        let report = fx.store.gc(0, false).unwrap();
        assert!(report.deleted.contains(&orphan));
        assert!(!fx.store.has_blob(&orphan));
        assert!(fx.store.has_blob(&first.digest), "the pin still holds");
    }

    /// `fsck` names a dead pin, its holder, and the fact that it is a
    /// loss rather than a repair job.
    #[test]
    fn fsck_reports_a_dead_pin_against_the_checkout_holding_it() {
        let _env = test_env_lock();
        let fx = pin_fixture();
        let first = publish_tls(&fx.store, "dbec8a4b73e5", b"v1-bytes");
        outsider_pins(&fx, &first.digest);
        // Simulate the damage the old root set did.
        std::fs::remove_file(fx.store.blob_path(&first.digest).unwrap()).unwrap();

        let report = crate::store_maint::fsck(&fx.store, false).unwrap();
        let outsider = report
            .checkouts
            .iter()
            .find(|c| c.label == "outsider")
            .expect("the outsider is in the ledger");
        assert!(!outsider.member);
        assert_eq!(outsider.sole, 1, "it is the only holder");
        assert_eq!(outsider.unmembered, 1, "no member holds it either");
        assert_eq!(outsider.notable.len(), 1);
        assert!(outsider.notable[0].1.is_fault());
        assert!(crate::store_maint::render(&report).contains("DEAD"));
    }
}
