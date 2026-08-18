//! CLI glue for the local OCI artifact store: `fluxor publish bundle`
//! and `fluxor store ls|rm|snapshot|pin`. (Project artifacts publish
//! through `fluxor publish` — `fluxor_tools::store_publish`; read-only
//! artifact display is `fluxor inspect <ref>` — Decision 5.)
//!
//! The store engine lives in the lib (`fluxor_tools::oci_store`); this module
//! only walks the project tree (bundle dirs) and formats output.
//! Offline-first: none of these verbs touch the network.

use std::fs;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};

use crate::error::{Error, Result};
// Bin-root helper (cli/commands_c.rs, flat `include!` scope).
use crate::resolve_project_root;
use fluxor_tools::oci_store::{
    self, git_source_rev, publish_bundle, sha256_hex_prefixed, BundlePublish, ImageManifest,
    OciStore, ANN_KIND, ANN_PROVENANCE, ANN_REF_NAME, ANN_SOURCE_REV, ANN_TARGET, PROVENANCE_LOCAL,
    PROVENANCE_PUBLISHED,
};
use fluxor_tools::store_remote;
use fluxor_tools::store_resolve;

// ── Args ──────────────────────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct StoreArgs {
    #[command(subcommand)]
    pub command: StoreCommand,
}

#[derive(Subcommand, Debug)]
pub enum StoreCommand {
    /// List artifacts in the local store.
    Ls {
        /// Store directory (default: $XDG_DATA_HOME/fluxor/store,
        /// override with $FLUXOR_STORE).
        #[arg(long)]
        store: Option<PathBuf>,
        /// Only artifacts with this provenance (local-build | published).
        #[arg(long)]
        provenance: Option<String>,
        /// Machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Remove a tag (or, given a digest, every tag of that manifest) and
    /// sweep blobs no longer referenced by any remaining artifact.
    Rm {
        reference: String,
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Name the current cross-project resolved set: writes one OCI
    /// index over every tagged non-snapshot artifact, tagged
    /// `snapshot/<name>`. Snapshots are GC roots; restore pins from
    /// one with `fluxor update --from snapshot/<name>`.
    Snapshot {
        /// Snapshot name (tag becomes `snapshot/<name>`).
        name: String,
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Push a local artifact (and every blob it references) to a remote
    /// OCI registry. The ONE network-write verb: tags stay mutable on
    /// the wire, digests are the identity, and blobs the registry
    /// already holds are skipped.
    Push {
        /// Local store reference (tag, digest, or unambiguous prefix).
        reference: String,
        /// Remote reference:
        /// `[https://]host[:port]/<repo>[:tag]` (e.g.
        /// `registry.nanocloud.io/fluxor/lattice-cdc:latest`).
        remote: String,
        #[arg(long)]
        store: Option<PathBuf>,
        /// Extra CA bundle (PEM) trusted for this registry beyond the
        /// webpki roots (e.g. the nanocloud deployment CA).
        #[arg(long)]
        ca: Option<PathBuf>,
    },
    /// Pull a remote artifact into the local store, digest-verifying
    /// every blob. The ONE network-read verb; every consume path stays
    /// offline against the local store.
    Pull {
        /// Remote reference:
        /// `[https://]host[:port]/<repo>[:tag|@sha256:...]`.
        remote: String,
        /// Local tag to apply (default: `<repo>:<tag>` from the remote).
        #[arg(long = "as")]
        local_as: Option<String>,
        #[arg(long)]
        store: Option<PathBuf>,
        /// Extra CA bundle (PEM) trusted for this registry beyond the
        /// webpki roots (e.g. the nanocloud deployment CA).
        #[arg(long)]
        ca: Option<PathBuf>,
    },
    /// Pin an artifact into `fluxor.lock` (`[[artifact]]`) so
    /// combine/packaging resolve its `.fmod` by digest from the store
    /// when it's absent from `target/fluxor/<target>/modules/`.
    Pin {
        /// Tag (`target/name:ver`), digest, or unambiguous digest prefix
        /// of a store artifact.
        reference: String,
        #[arg(long)]
        store: Option<PathBuf>,
        /// Project root whose fluxor.lock records the pin.
        #[arg(long)]
        project_root: Option<PathBuf>,
    },
}

fn open_store(dir: Option<&Path>) -> Result<OciStore> {
    let root = match dir {
        Some(d) => d.to_path_buf(),
        None => oci_store::store_root().map_err(|e| Error::Config(e.to_string()))?,
    };
    OciStore::open(root).map_err(|e| Error::Config(e.to_string()))
}

fn provenance_flag(published: bool) -> &'static str {
    if published {
        PROVENANCE_PUBLISHED
    } else {
        PROVENANCE_LOCAL
    }
}

// ── fluxor publish bundle ─────────────────────────────────────────────

pub fn cmd_bundle_publish(
    bundle_dir: &Path,
    store_dir: Option<&Path>,
    tag: Option<&str>,
    published: bool,
) -> Result<()> {
    let store = open_store(store_dir)?;
    let read = |name: &str| -> Result<Vec<u8>> {
        fs::read(bundle_dir.join(name))
            .map_err(|e| Error::Config(format!("bundle {}: {name}: {e}", bundle_dir.display())))
    };
    let workload_json = String::from_utf8(read("workload.json")?)
        .map_err(|e| Error::Config(format!("workload.json: {e}")))?;
    let resources_json = read("resources.json")?;
    let graph_yaml = read("graph.yaml")?;

    let ref_name = match tag {
        Some(t) => t.to_string(),
        None => {
            let manifest =
                fluxor_tools::workload::parse_manifest(&workload_json).map_err(Error::Config)?;
            format!("{}:{}", manifest.name, manifest.version)
        }
    };
    let source_rev = git_source_rev(bundle_dir);
    let desc = publish_bundle(
        &store,
        &BundlePublish {
            workload_json: &workload_json,
            resources_json: &resources_json,
            graph_yaml: &graph_yaml,
            provenance: provenance_flag(published),
            source_rev: source_rev.as_deref(),
            ref_name: &ref_name,
        },
    )
    .map_err(|e| Error::Config(e.to_string()))?;
    println!("{ref_name} -> {}", desc.digest);
    Ok(())
}

// ── fluxor publish image|firmware ─────────────────────────────────────

/// Publish a device artifact (graph image / firmware image). For a
/// graph image the FXSL header supplies epoch + ABI pin, mirrored into
/// annotations so a consumer can admit or reject from the manifest
/// alone.
pub fn cmd_device_artifact_publish(
    kind: &str,
    file: &Path,
    name: Option<&str>,
    target: &str,
    tag: Option<&str>,
    store_dir: Option<&Path>,
) -> Result<()> {
    let bytes = fs::read(file).map_err(|e| Error::Config(format!("{}: {e}", file.display())))?;
    let name = name
        .map(str::to_string)
        .or_else(|| {
            file.file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_string)
        })
        .ok_or_else(|| Error::Config("cannot derive a name from the file path".into()))?;

    // Graph images carry their own truth in the FXSL header.
    const FXSL_MAGIC: u32 = 0x4C53_5846;
    let image_kind = kind.starts_with("image");
    let (epoch, abi_hex) = if image_kind {
        if bytes.len() < 96
            || u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) != FXSL_MAGIC
        {
            return Err(Error::Config(format!(
                "{} is not a graph image (missing FXSL header) — build it with `fluxor build <config> --emit=image`",
                file.display()
            )));
        }
        let epoch = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let mut hex = String::with_capacity(64);
        for b in &bytes[64..96] {
            hex.push_str(&format!("{b:02x}"));
        }
        (Some(epoch), Some(hex))
    } else {
        (None, None)
    };

    let store = open_store(store_dir)?;
    let ref_name = tag
        .map(str::to_string)
        .unwrap_or_else(|| format!("{name}:latest"));
    let source_rev = git_source_rev(&resolve_project_root(None));
    let publish = oci_store::DeviceArtifactPublish {
        kind: if image_kind { "image" } else { kind },
        bytes: &bytes,
        name: &name,
        target,
        epoch,
        abi_surface_hex: abi_hex.as_deref(),
        provenance: PROVENANCE_LOCAL,
        source_rev: source_rev.as_deref(),
        ref_name: &ref_name,
    };
    // Layered (exploded) is the default graph-image form;
    // `image-packed` and firmware stay single-blob.
    let desc = if kind == "image" {
        oci_store::publish_layered_image(&store, &publish)
    } else {
        oci_store::publish_device_artifact(&store, &publish)
    }
    .map_err(|e| Error::Config(e.to_string()))?;
    println!("{ref_name} -> {}", desc.digest);
    Ok(())
}

// ── fluxor store ls|inspect|rm ────────────────────────────────────────

pub fn dispatch_store(args: StoreArgs) -> Result<()> {
    match args.command {
        StoreCommand::Ls {
            store,
            provenance,
            json,
        } => cmd_store_ls(store.as_deref(), provenance.as_deref(), json),
        StoreCommand::Rm { reference, store } => cmd_store_rm(&reference, store.as_deref()),
        StoreCommand::Snapshot { name, store } => cmd_store_snapshot(&name, store.as_deref()),
        StoreCommand::Push {
            reference,
            remote,
            store,
            ca,
        } => cmd_store_push(&reference, &remote, store.as_deref(), ca.as_deref()),
        StoreCommand::Pull {
            remote,
            local_as,
            store,
            ca,
        } => cmd_store_pull(
            &remote,
            local_as.as_deref(),
            store.as_deref(),
            ca.as_deref(),
        ),
        StoreCommand::Pin {
            reference,
            store,
            project_root,
        } => cmd_store_pin(&reference, store.as_deref(), project_root.as_deref()),
    }
}

fn cmd_store_push(
    reference: &str,
    remote: &str,
    store_dir: Option<&Path>,
    ca: Option<&Path>,
) -> Result<()> {
    let store = open_store(store_dir)?;
    let remote =
        store_remote::RemoteRef::parse(remote).map_err(|e| Error::Config(e.to_string()))?;
    let client =
        store_remote::RemoteClient::new(&remote, ca).map_err(|e| Error::Config(e.to_string()))?;
    let desc = store_remote::push(&store, reference, &remote, &client)
        .map_err(|e| Error::Config(e.to_string()))?;
    println!(
        "\x1b[1;32mPushed\x1b[0m {reference} → {}/{}:{} ({})",
        remote.host, remote.repo, remote.reference, desc.digest
    );
    Ok(())
}

fn cmd_store_pull(
    remote: &str,
    local_as: Option<&str>,
    store_dir: Option<&Path>,
    ca: Option<&Path>,
) -> Result<()> {
    let store = open_store(store_dir)?;
    let remote =
        store_remote::RemoteRef::parse(remote).map_err(|e| Error::Config(e.to_string()))?;
    let client =
        store_remote::RemoteClient::new(&remote, ca).map_err(|e| Error::Config(e.to_string()))?;
    let desc = store_remote::pull(&store, &remote, &client, local_as)
        .map_err(|e| Error::Config(e.to_string()))?;
    let tag = local_as
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}:{}", remote.repo, remote.reference));
    println!(
        "\x1b[1;32mPulled\x1b[0m {}/{}:{} → {tag} ({})",
        remote.host, remote.repo, remote.reference, desc.digest
    );
    Ok(())
}

fn cmd_store_ls(store_dir: Option<&Path>, provenance: Option<&str>, json: bool) -> Result<()> {
    let store = open_store(store_dir)?;
    let index = store
        .read_index()
        .map_err(|e| Error::Config(e.to_string()))?;
    let ann = |d: &oci_store::Descriptor, key: &str| -> String {
        d.annotations.get(key).cloned().unwrap_or_default()
    };
    let mut entries: Vec<&oci_store::Descriptor> = index
        .manifests
        .iter()
        .filter(|d| {
            provenance
                .is_none_or(|p| d.annotations.get(ANN_PROVENANCE).map(String::as_str) == Some(p))
        })
        .collect();
    entries.sort_by_key(|d| ann(d, ANN_REF_NAME));

    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }
    println!(
        "{:<40} {:<7} {:<10} {:<12} {:<14} DIGEST",
        "REF", "KIND", "TARGET", "PROVENANCE", "SOURCE-REV"
    );
    for d in entries {
        let digest12: String = d
            .digest
            .strip_prefix("sha256:")
            .unwrap_or(&d.digest)
            .chars()
            .take(12)
            .collect();
        let rev: String = ann(d, ANN_SOURCE_REV).chars().take(12).collect();
        println!(
            "{:<40} {:<7} {:<10} {:<12} {:<14} {digest12}",
            ann(d, ANN_REF_NAME),
            ann(d, ANN_KIND),
            ann(d, ANN_TARGET),
            ann(d, ANN_PROVENANCE),
            rev,
        );
    }
    Ok(())
}

fn cmd_store_rm(reference: &str, store_dir: Option<&Path>) -> Result<()> {
    let store = open_store(store_dir)?;
    let removed = store
        .remove(reference)
        .map_err(|e| Error::Config(e.to_string()))?;
    println!("removed '{reference}' ({} blob(s) swept)", removed.len());
    Ok(())
}

// ── fluxor.lock pinning + consume-side resolution ────────────────────

/// Owned form of `modules::StoreFallback` — what `lock_store_resolver`
/// hands to the packaging call sites.
pub type BoxedStoreFallback = Box<dyn Fn(&str) -> crate::modules::StorePin>;

/// Owned resolver from a module name to its pinned `manifest.toml` bytes —
/// the manifest-loader counterpart of `BoxedStoreFallback`.
pub type BoxedManifestResolver = Box<dyn Fn(&str) -> crate::modules::ManifestPin>;

/// One module pin from the `[[artifact]]` lockfile, in the shape the
/// resolvers below key on. A module pin always carries its silicon
/// target (`materialize` errors on one that doesn't; here it simply
/// never matches).
struct ModulePin {
    name: String,
    target: Option<String>,
    digest: String,
    reference: String,
}

/// Read the project's `[[artifact]]` module pins. `Ok(None)` when the
/// lockfile is absent or pins no modules; `Err` when it exists but is
/// unreadable/legacy-shape — which names are pinned is then unknowable,
/// and guessing "none" would let packaging silently consume unpinned
/// bytes.
fn read_module_pins(project_root: &Path) -> Result<Option<Vec<ModulePin>>> {
    let Some(lock) =
        store_resolve::read_store_lock(project_root).map_err(|e| Error::Config(e.to_string()))?
    else {
        return Ok(None);
    };
    let pins: Vec<ModulePin> = lock
        .artifacts
        .into_iter()
        .filter(|a| a.kind == "module")
        .map(|a| ModulePin {
            name: a.name,
            target: a.target,
            digest: a.digest,
            reference: a.reference,
        })
        .collect();
    if pins.is_empty() {
        return Ok(None);
    }
    Ok(Some(pins))
}

fn cmd_store_pin(
    reference: &str,
    store_dir: Option<&Path>,
    project_root: Option<&Path>,
) -> Result<()> {
    let pr = resolve_project_root(project_root);
    let store = open_store(store_dir)?;
    let desc = store
        .resolve(reference)
        .map_err(|e| Error::Config(e.to_string()))?;
    let artifact = store_resolve::artifact_from_descriptor(&desc)
        .map_err(|e| Error::Config(e.to_string()))?
        .ok_or_else(|| {
            Error::Config(format!(
                "'{reference}' is not a pinnable artifact (no kind annotation — \
                 published by an older tool; re-publish it)"
            ))
        })?;
    if artifact.kind == "module" {
        // Fail now, not at consume time, if the .fmod layer is unreadable.
        let manifest = store
            .read_manifest(&desc)
            .map_err(|e| Error::Config(e.to_string()))?;
        store
            .module_fmod_blob(&manifest)
            .map_err(|e| Error::Config(e.to_string()))?;
    }
    store_resolve::pin_artifact(&pr, &artifact).map_err(|e| Error::Config(e.to_string()))?;
    println!(
        "pinned {} ({}) -> {} in {}",
        artifact.name,
        artifact.reference,
        artifact.digest,
        store_resolve::lockfile_path(&pr).display()
    );
    Ok(())
}

/// Build the `fluxor.lock`-pinned OCI-store fallback used by module
/// resolution. `None` when the project has no lockfile,
/// no pins for this target, or the store can't be opened — resolution then
/// behaves exactly as before (on-disk dirs only). The returned closure
/// verifies the `.fmod` bytes against the pinned layer digest before
/// handing the path out; a corrupt blob is skipped with a warning rather
/// than silently packaged.
pub fn lock_store_resolver(
    project_root: &Path,
    target: &str,
    store_dir: Option<&Path>,
) -> Option<BoxedStoreFallback> {
    use crate::modules::StorePin;

    // An unreadable/corrupt lockfile is a hard error for EVERY module
    // resolution: which names are pinned is unknowable, and guessing
    // "none" would let packaging silently consume unpinned bytes.
    let pins = match read_module_pins(project_root) {
        Ok(p) => p?,
        Err(e) => {
            let why = format!("fluxor.lock unreadable: {e}");
            return Some(Box::new(move |_name: &str| StorePin::Failed(why.clone())));
        }
    };
    let pins: Vec<ModulePin> = pins
        .into_iter()
        .filter(|m| m.target.as_deref() == Some(target))
        .collect();
    if pins.is_empty() {
        return None;
    }
    // Pins exist but the store won't open → every pinned name must fail
    // loudly; unpinned names still resolve from disk.
    let store = match open_store(store_dir) {
        Ok(s) => s,
        Err(e) => {
            let why = format!("cannot open OCI store: {e}");
            return Some(Box::new(move |name: &str| {
                if pins.iter().any(|p| p.name == name) {
                    StorePin::Failed(why.clone())
                } else {
                    StorePin::NotPinned
                }
            }));
        }
    };
    Some(Box::new(move |name: &str| {
        let Some(pin) = pins.iter().find(|p| p.name == name) else {
            return StorePin::NotPinned;
        };
        let manifest_bytes = match store.read_blob(&pin.digest) {
            Ok(b) => b,
            Err(e) => return StorePin::Failed(e.to_string()),
        };
        let manifest: ImageManifest = match serde_json::from_slice(&manifest_bytes) {
            Ok(m) => m,
            Err(e) => return StorePin::Failed(format!("corrupt manifest: {e}")),
        };
        match store.module_fmod_blob(&manifest) {
            Ok((digest, path)) => {
                let fmod = match std::fs::read(&path) {
                    Ok(b) => b,
                    Err(e) => return StorePin::Failed(format!("read blob: {e}")),
                };
                if sha256_hex_prefixed(&fmod) != digest {
                    return StorePin::Failed(format!(
                        "store blob {digest} failed integrity verification"
                    ));
                }
                StorePin::Resolved(path)
            }
            Err(e) => StorePin::Failed(e.to_string()),
        }
    }))
}

/// Manifest counterpart of `lock_store_resolver`: resolve a module name to
/// the verified `manifest.toml` text its pinned `[[artifact]]` module
/// entry ships, so wiring/port validation sees the SAME surface the pinned
/// `.fmod` was built with. Returns `None` when the project pins no
/// modules (the common case — zero store I/O).
///
/// Pin selection is silicon-aware. Manifest *content* is largely
/// target-independent, but pin *selection* is not: the same name can be
/// pinned at different digests for two targets, and binding wiring to the
/// wrong one validates a port surface the packaged `.fmod` doesn't have.
///   1. a pin whose target equals `silicon` wins. Pins are tagged with
///      the module-silicon id at publish time, so this is a plain string
///      match;
///   2. otherwise fall back to a name match, but only when it is
///      unambiguous — every pin for that name shares one digest;
///   3. differing digests and no match for a HOST target (`linux`,
///      `wasm`) is `NotPinned`. A pin binds the target it names, and a
///      host graph loads modules built from source into `modules.bin`,
///      never store bytes — so no pin here binds anything, and the
///      on-disk manifest is authoritative;
///   4. differing digests and no match for a SILICON is `Failed`:
///      firmware for that silicon needs the artifact for it, so the
///      right port surface is missing rather than unguessable.
///
/// UTF-8 and integrity are strict. `read_blob` hashes the bytes against the
/// layer digest; non-UTF-8 in a digest-verified artifact is corruption
/// (`Failed`), never lossily repaired.
///
/// An artifact carrying no `manifest.toml` layer yields `NotPinned`, so an
/// on-disk source manifest fills in. A pinned module with neither a
/// manifest layer nor an on-disk source therefore drops out of wiring
/// validation — the standing semantics for a manifest-less module, now
/// reachable through a pin as well.
pub fn lock_store_manifest_resolver(
    project_root: &Path,
    silicon: Option<&str>,
    store_dir: Option<&Path>,
) -> Option<BoxedManifestResolver> {
    use crate::modules::ManifestPin;

    let pins = match read_module_pins(project_root) {
        Ok(p) => p?,
        Err(e) => {
            let why = format!("fluxor.lock unreadable: {e}");
            return Some(Box::new(move |_name: &str| {
                ManifestPin::Failed(why.clone())
            }));
        }
    };
    // Whether the requested target is a host (`linux`, `wasm`) rather than a
    // silicon or board. Resolved through the target descriptor so the set lives
    // in one place (`TargetKind::Host`) instead of being restated here.
    let is_host = silicon
        .is_some_and(|s| crate::target::load_target(s, project_root).is_ok_and(|t| t.is_host()));
    let silicon = silicon.map(|s| s.to_string());
    let store = match open_store(store_dir) {
        Ok(s) => s,
        Err(e) => {
            let why = format!("cannot open OCI store: {e}");
            return Some(Box::new(move |name: &str| {
                if pins.iter().any(|p| p.name == name) {
                    ManifestPin::Failed(why.clone())
                } else {
                    ManifestPin::NotPinned
                }
            }));
        }
    };
    Some(Box::new(move |name: &str| {
        let named: Vec<&ModulePin> = pins.iter().filter(|p| p.name == name).collect();
        if named.is_empty() {
            return ManifestPin::NotPinned;
        }
        let silicon_match = silicon
            .as_deref()
            .and_then(|want| named.iter().find(|p| p.target.as_deref() == Some(want)));
        let unambiguous = named.iter().all(|p| p.digest == named[0].digest);
        let pin = match silicon_match {
            Some(p) => *p,
            // One digest across every target: the artifact is
            // target-agnostic, so any pin is the right pin.
            None if unambiguous => named[0],
            // Nothing for a pin to bind: a host graph loads modules built
            // from source into `modules.bin`, never store bytes. Validating
            // against a silicon pin would check wiring against a surface
            // this run will not load.
            None if is_host => return ManifestPin::NotPinned,
            // A silicon does need the artifact for it, so the right one is
            // missing rather than ambiguous. Falling through would validate
            // against another silicon's surface.
            None => {
                return ManifestPin::Failed(format!(
                    "module '{name}' is pinned for several targets at differing digests \
                     and none matches {}; pin it for this target",
                    silicon.as_deref().unwrap_or("the requested target")
                ))
            }
        };
        let pin_id = format!("pin {} ({})", pin.reference, pin.digest);
        let manifest_bytes = match store.read_blob(&pin.digest) {
            Ok(b) => b,
            Err(e) => return ManifestPin::Failed(format!("{pin_id}: {e}")),
        };
        let manifest: ImageManifest = match serde_json::from_slice(&manifest_bytes) {
            Ok(m) => m,
            Err(e) => return ManifestPin::Failed(format!("{pin_id}: corrupt manifest: {e}")),
        };
        match store.module_manifest_toml_blob(&manifest) {
            Ok(Some(bytes)) => match String::from_utf8(bytes) {
                Ok(text) => ManifestPin::Resolved(text),
                Err(e) => ManifestPin::Failed(format!(
                    "{pin_id}: manifest.toml layer is not valid UTF-8 (corrupt artifact): {e}"
                )),
            },
            // No manifest.toml layer — let an on-disk source manifest resolve it.
            Ok(None) => ManifestPin::NotPinned,
            Err(e) => ManifestPin::Failed(format!("{pin_id}: {e}")),
        }
    }))
}

/// `fluxor store snapshot <name>` — freeze the current resolved set.
fn cmd_store_snapshot(name: &str, store_dir: Option<&Path>) -> Result<()> {
    if name.is_empty() || name.contains('/') || name.contains(':') {
        return Err(Error::Config(format!(
            "snapshot name must be a plain identifier (got {name:?})"
        )));
    }
    let store = open_store(store_dir)?;
    let index = store
        .read_index()
        .map_err(|e| Error::Config(e.to_string()))?;
    let children: Vec<oci_store::Descriptor> = index
        .manifests
        .iter()
        .filter(|d| {
            d.annotations
                .get(oci_store::ANN_REF_NAME)
                .is_none_or(|r| !r.starts_with("snapshot/"))
        })
        .cloned()
        .collect();
    let n = children.len();
    let desc = store
        .create_snapshot(name, children)
        .map_err(|e| Error::Config(e.to_string()))?;
    println!("snapshot/{name}: {} ({n} artifacts)", desc.digest);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxor_tools::oci_store::{publish_module, ModulePublish, PROVENANCE_LOCAL};

    /// Upsert one `[[artifact]]` module pin the way `store pin` does.
    fn pin_module(proj: &Path, name: &str, target: &str, digest: &str, reference: &str) {
        store_resolve::pin_artifact(
            proj,
            &store_resolve::Artifact {
                kind: "module".into(),
                name: name.into(),
                project: "testproj".into(),
                target: Some(target.into()),
                digest: digest.into(),
                reference: reference.into(),
            },
        )
        .expect("pin");
    }

    fn store_with_module(dir: &Path) -> (OciStore, String) {
        let store = OciStore::open(dir.join("store")).expect("open store");
        let desc = publish_module(
            &store,
            &ModulePublish {
                name: "codec",
                target: "bcm2712",
                fmod_bytes: b"fake-fmod-bytes",
                manifest_toml: None,
                provenance: PROVENANCE_LOCAL,
                source_rev: None,
                ref_name: "bcm2712/codec:1.0.0",
            },
        )
        .expect("publish");
        (store, desc.digest)
    }

    #[test]
    fn pin_roundtrip_resolves_fmod_from_store() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        let (_store, digest) = store_with_module(tmp.path());

        pin_module(&proj, "codec", "bcm2712", &digest, "bcm2712/codec:1.0.0");
        // Re-pin with the same key replaces, not duplicates.
        pin_module(&proj, "codec", "bcm2712", &digest, "bcm2712/codec:1.0.0");
        let lock = store_resolve::read_store_lock(&proj).unwrap().unwrap();
        assert_eq!(lock.artifacts.len(), 1);

        let store_dir = tmp.path().join("store");
        let resolver =
            lock_store_resolver(&proj, "bcm2712", Some(&store_dir)).expect("resolver present");
        let crate::modules::StorePin::Resolved(path) = resolver("codec") else {
            panic!("codec must resolve from store");
        };
        assert_eq!(std::fs::read(&path).unwrap(), b"fake-fmod-bytes");
        assert!(matches!(
            resolver("unpinned"),
            crate::modules::StorePin::NotPinned
        ));
        // Wrong target -> no resolver.
        assert!(lock_store_resolver(&proj, "rp2350", Some(&store_dir)).is_none());
    }

    #[test]
    fn corrupt_blob_fails_integrity_and_is_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        let (store, digest) = store_with_module(tmp.path());

        // Corrupt the .fmod blob in place.
        let fmod_digest = sha256_hex_prefixed(b"fake-fmod-bytes");
        std::fs::write(store.blob_path(&fmod_digest).unwrap(), b"tampered").unwrap();

        pin_module(&proj, "codec", "bcm2712", &digest, "bcm2712/codec:1.0.0");
        let store_dir = tmp.path().join("store");
        let resolver = lock_store_resolver(&proj, "bcm2712", Some(&store_dir)).unwrap();
        assert!(
            matches!(resolver("codec"), crate::modules::StorePin::Failed(_)),
            "tampered blob must be a hard failure, not a silent fall-through"
        );
    }

    fn publish_with_manifest(
        store: &OciStore,
        name: &str,
        target: &str,
        fmod: &[u8],
        toml: &str,
    ) -> String {
        publish_module(
            store,
            &ModulePublish {
                name,
                target,
                fmod_bytes: fmod,
                manifest_toml: Some(toml),
                provenance: PROVENANCE_LOCAL,
                source_rev: None,
                ref_name: &format!("{target}/{name}:0.1.0"),
            },
        )
        .expect("publish")
        .digest
    }

    #[test]
    fn pin_resolves_manifest_toml_silicon_aware() {
        use crate::modules::ManifestPin;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        let store = OciStore::open(tmp.path().join("store")).expect("open store");

        let toml = "version = \"0.1.0\"\ntype = \"Protocol\"\nentry = \"mod.rs\"\n";
        let digest = publish_with_manifest(&store, "redis_client", "bcm2712", b"fmodA", toml);
        pin_module(
            &proj,
            "redis_client",
            "bcm2712",
            &digest,
            "bcm2712/redis_client:0.1.0",
        );

        let store_dir = tmp.path().join("store");

        // Exact silicon match resolves the pinned manifest as UTF-8 text.
        let r = lock_store_manifest_resolver(&proj, Some("bcm2712"), Some(&store_dir))
            .expect("resolver present");
        match r("redis_client") {
            ManifestPin::Resolved(text) => assert_eq!(text, toml),
            other => panic!("expected Resolved, got {other:?}"),
        }
        assert!(matches!(r("unpinned"), ManifestPin::NotPinned));

        // Callers pass the module-silicon id (a pi5 graph resolves to
        // `bcm2712` before pin lookup), so the pin matches by string.
        let r_bcm = lock_store_manifest_resolver(&proj, Some("bcm2712"), Some(&store_dir))
            .expect("resolver present");
        match r_bcm("redis_client") {
            ManifestPin::Resolved(text) => assert_eq!(text, toml),
            other => panic!("bcm2712 must match the bcm2712 pin, got {other:?}"),
        }

        // No silicon requested: the lone pin is unambiguous.
        let r_any =
            lock_store_manifest_resolver(&proj, None, Some(&store_dir)).expect("resolver present");
        assert!(matches!(r_any("redis_client"), ManifestPin::Resolved(_)));
    }

    #[test]
    fn silicon_selects_between_same_name_pins_at_different_targets() {
        use crate::modules::ManifestPin;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        let store = OciStore::open(tmp.path().join("store")).expect("open store");

        let bcm = "version = \"0.1.0\"\ntype = \"Protocol\"\nentry = \"mod.rs\"\n\
                   [[ports]]\nname = \"big\"\ndirection = \"out\"\n";
        let rp = "version = \"0.1.0\"\ntype = \"Protocol\"\nentry = \"mod.rs\"\n\
                  [[ports]]\nname = \"small\"\ndirection = \"out\"\n";
        let d_bcm = publish_with_manifest(&store, "mqtt_client", "bcm2712", b"fmodA", bcm);
        let d_rp = publish_with_manifest(&store, "mqtt_client", "rp2350", b"fmodB", rp);
        assert_ne!(d_bcm, d_rp);
        pin_module(
            &proj,
            "mqtt_client",
            "bcm2712",
            &d_bcm,
            "bcm2712/mqtt_client:0.1.0",
        );
        pin_module(
            &proj,
            "mqtt_client",
            "rp2350",
            &d_rp,
            "rp2350/mqtt_client:0.1.0",
        );

        let store_dir = tmp.path().join("store");
        for (silicon, want) in [("rp2350", rp), ("bcm2712", bcm)] {
            let r = lock_store_manifest_resolver(&proj, Some(silicon), Some(&store_dir))
                .expect("resolver present");
            match r("mqtt_client") {
                ManifestPin::Resolved(text) => assert_eq!(text, want, "silicon {silicon}"),
                other => panic!("silicon {silicon}: expected Resolved, got {other:?}"),
            }
        }
    }

    #[test]
    fn corrupt_manifest_layer_is_a_hard_failure() {
        use crate::modules::ManifestPin;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        let store = OciStore::open(tmp.path().join("store")).expect("open store");

        let toml = "version = \"0.1.0\"\ntype = \"Protocol\"\nentry = \"mod.rs\"\n";
        let digest = publish_with_manifest(&store, "redis_client", "bcm2712", b"fmodA", toml);
        pin_module(
            &proj,
            "redis_client",
            "bcm2712",
            &digest,
            "bcm2712/redis_client:0.1.0",
        );

        // Tamper with the manifest.toml blob: the digest no longer matches,
        // and the payload isn't UTF-8 either.
        let toml_digest = sha256_hex_prefixed(toml.as_bytes());
        std::fs::write(store.blob_path(&toml_digest).unwrap(), [0xffu8, 0xfe, 0x00]).unwrap();

        let store_dir = tmp.path().join("store");
        let r = lock_store_manifest_resolver(&proj, Some("bcm2712"), Some(&store_dir))
            .expect("resolver present");
        let why = match r("redis_client") {
            ManifestPin::Failed(why) => why,
            other => panic!("corrupt manifest layer must fail hard, got {other:?}"),
        };
        assert!(
            why.contains("bcm2712/redis_client:0.1.0"),
            "failure must name the pin: {why}"
        );
    }

    #[test]
    fn ambiguous_multi_target_pins_refuse_without_silicon_match() {
        use crate::modules::ManifestPin;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        let store = OciStore::open(tmp.path().join("store")).expect("open store");

        // Same name pinned for two silicons at different digests.
        let d1 = publish_with_manifest(
            &store,
            "amqp_client",
            "bcm2712",
            b"fmodA",
            "version=\"1\"\n",
        );
        let d2 =
            publish_with_manifest(&store, "amqp_client", "rp2350", b"fmodB", "version=\"2\"\n");
        assert_ne!(d1, d2);
        pin_module(
            &proj,
            "amqp_client",
            "bcm2712",
            &d1,
            "bcm2712/amqp_client:0.1.0",
        );
        pin_module(
            &proj,
            "amqp_client",
            "rp2350",
            &d2,
            "rp2350/amqp_client:0.1.0",
        );

        let store_dir = tmp.path().join("store");
        let r = lock_store_manifest_resolver(&proj, Some("bcm2712"), Some(&store_dir)).unwrap();
        // Requested silicon matches one pin -> its manifest.
        match r("amqp_client") {
            ManifestPin::Resolved(text) => assert_eq!(text, "version=\"1\"\n"),
            other => panic!("expected Resolved bcm2712, got {other:?}"),
        }
        // A silicon with NO matching pin and divergent digests -> refuse.
        let r_other = lock_store_manifest_resolver(&proj, Some("stm32"), Some(&store_dir)).unwrap();
        assert!(matches!(r_other("amqp_client"), ManifestPin::Failed(_)));
    }

    /// A HOST target with no matching pin falls through instead of refusing.
    ///
    /// Sibling of `ambiguous_multi_target_pins_refuse_without_silicon_match`,
    /// and the pair is the whole rule: a pin binds the target it names, so a
    /// silicon that should have an artifact and does not is an error, while a
    /// host — whose modules are built from source into `modules.bin` and never
    /// fetched from the store — has nothing for the pin to bind and takes the
    /// on-disk manifest.
    #[test]
    fn ambiguous_multi_target_pins_fall_through_for_a_host_target() {
        use crate::modules::ManifestPin;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        let store = OciStore::open(tmp.path().join("store")).expect("open store");

        let d1 = publish_with_manifest(&store, "tls", "bcm2712", b"fmodA", "version=\"1\"\n");
        let d2 = publish_with_manifest(&store, "tls", "rp2350", b"fmodB", "version=\"2\"\n");
        assert_ne!(d1, d2);
        pin_module(&proj, "tls", "bcm2712", &d1, "bcm2712/tls:0.1.0");
        pin_module(&proj, "tls", "rp2350", &d2, "rp2350/tls:0.1.0");

        let store_dir = tmp.path().join("store");
        let r = lock_store_manifest_resolver(&proj, Some("linux"), Some(&store_dir)).unwrap();
        assert!(
            matches!(r("tls"), ManifestPin::NotPinned),
            "a host target must fall through to the on-disk manifest, not refuse"
        );
    }

    #[test]
    fn pin_without_manifest_layer_falls_through_to_disk() {
        use crate::modules::ManifestPin;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        // Published with manifest_toml: None — no metadata layer.
        let (_store, digest) = store_with_module(tmp.path());
        pin_module(&proj, "codec", "bcm2712", &digest, "bcm2712/codec:1.0.0");
        let store_dir = tmp.path().join("store");
        let resolver = lock_store_manifest_resolver(&proj, Some("bcm2712"), Some(&store_dir))
            .expect("resolver present");
        // No manifest layer => NotPinned so an on-disk source manifest can fill in.
        assert!(matches!(resolver("codec"), ManifestPin::NotPinned));
    }
}
