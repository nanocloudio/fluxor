//! CLI glue for the local OCI artifact store (`.context/fmod_registry_plan.md`
//! P1): `fluxor modules publish`, `fluxor bundle publish`, and
//! `fluxor store ls|inspect|rm`.
//!
//! The store engine lives in the lib (`fluxor_tools::oci_store`); this module
//! only walks the project tree (owned modules, built `.fmod`s, bundle dirs)
//! and formats output. Offline-first: none of these verbs touch the network.

use std::fs;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};

use crate::error::{Error, Result};
use crate::publish::{list_built_targets, list_owned_modules, resolve_project_root};
use fluxor_tools::oci_store::{
    self, git_source_rev, publish_bundle, publish_module, sha256_hex_prefixed, BundlePublish,
    ImageManifest, ModulePublish, OciStore, ANN_KIND, ANN_MODULE_NAME, ANN_PROVENANCE,
    ANN_REF_NAME, ANN_SOURCE_REV, ANN_TARGET, PROVENANCE_LOCAL, PROVENANCE_PUBLISHED,
};

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
    /// Show an artifact's OCI manifest and descriptor.
    Inspect {
        /// Tag (`name:ver`), `sha256:<hex>` digest, or unambiguous
        /// digest prefix.
        reference: String,
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Remove a tag (or, given a digest, every tag of that manifest) and
    /// sweep blobs no longer referenced by any remaining artifact.
    Rm {
        reference: String,
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Pin a module artifact into `fluxor.lock` (`[[oci_module]]`) so
    /// combine/packaging resolve its `.fmod` by digest from the store
    /// when it's absent from `target/fluxor/<target>/modules/`.
    Pin {
        /// Tag (`target/name:ver`), digest, or unambiguous digest prefix
        /// of a module artifact.
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

// ── fluxor modules publish ────────────────────────────────────────────

/// Publish built `.fmod`s into the OCI store. Walks the project's owned
/// modules (same ownership rule as the registry publisher: only modules with
/// a local `manifest.toml` — never re-publish synced upstream artefacts).
#[allow(clippy::too_many_arguments, reason = "CLI surface maps 1:1 to flags")]
pub fn cmd_modules_publish(
    store_dir: Option<&Path>,
    target: Option<&str>,
    module: Option<&str>,
    tag: Option<&str>,
    published: bool,
    pin: bool,
    project_root: Option<&Path>,
) -> Result<()> {
    let pr = resolve_project_root(project_root);
    let store = open_store(store_dir)?;
    let mut owned = list_owned_modules(&pr)?;
    if let Some(m) = module {
        owned.retain(|o| o.name == m);
        if owned.is_empty() {
            return Err(Error::Config(format!(
                "no module manifest at modules/{{foundation,app,drivers}}/{m}/manifest.toml"
            )));
        }
    }
    if owned.is_empty() {
        println!("no owned modules to publish.");
        return Ok(());
    }

    let target_root_under_fluxor = pr.join("target").join("fluxor");
    let target_root_bare = pr.join("target");
    let candidate_roots = [&target_root_under_fluxor, &target_root_bare];
    let targets: Vec<String> = match target {
        Some(t) => vec![t.to_string()],
        None => list_built_targets(&candidate_roots)?,
    };
    if targets.is_empty() {
        return Err(Error::Config(
            "no built fmods under target/fluxor/* or target/* — run `fluxor modules build` first"
                .into(),
        ));
    }

    let source_rev = git_source_rev(&pr);
    let provenance = provenance_flag(published);

    // A --tag override names exactly one artifact; refuse fan-out under it.
    let selected: Vec<(String, &crate::publish::OwnedModule, PathBuf)> = targets
        .iter()
        .flat_map(|t| {
            owned.iter().filter_map(move |o| {
                candidate_roots
                    .iter()
                    .map(|r| r.join(t).join("modules").join(format!("{}.fmod", o.name)))
                    .find(|p| p.exists())
                    .map(|p| (t.clone(), o, p))
            })
        })
        .collect();
    if selected.is_empty() {
        return Err(Error::Config(
            "no built .fmod matched the selection — run `fluxor modules build` first".into(),
        ));
    }
    if tag.is_some() && selected.len() > 1 {
        return Err(Error::Config(format!(
            "--tag names one artifact but {} (target, module) pairs matched — \
             narrow with --target/--module",
            selected.len()
        )));
    }

    let mut pins: Vec<crate::lockfile::LockedOciModule> = Vec::new();
    for (target_name, owned_module, fmod_path) in &selected {
        let fmod_bytes = fs::read(fmod_path)?;
        let manifest_toml = fs::read_to_string(&owned_module.manifest_path)?;
        let ref_name = match tag {
            Some(t) => t.to_string(),
            None => format!(
                "{target_name}/{}:{}",
                owned_module.name, owned_module.version
            ),
        };
        let desc = publish_module(
            &store,
            &ModulePublish {
                name: &owned_module.name,
                target: target_name,
                fmod_bytes: &fmod_bytes,
                manifest_toml: Some(&manifest_toml),
                provenance,
                source_rev: source_rev.as_deref(),
                ref_name: &ref_name,
            },
        )
        .map_err(|e| Error::Config(e.to_string()))?;
        println!("{ref_name} -> {}", desc.digest);
        if pin {
            pins.push(crate::lockfile::LockedOciModule {
                name: owned_module.name.clone(),
                target: target_name.clone(),
                digest: desc.digest.clone(),
                reference: ref_name,
            });
        }
    }
    println!(
        "published {} artifact(s) to {} (provenance={provenance})",
        selected.len(),
        store.root().display()
    );
    if pin {
        let count = pins.len();
        upsert_pins(&pr, pins)?;
        println!(
            "pinned {count} module(s) in {}",
            crate::lockfile::lockfile_path(&pr).display()
        );
    }
    Ok(())
}

// ── fluxor bundle publish ─────────────────────────────────────────────

#[derive(Args, Debug)]
pub struct BundleArgs {
    #[command(subcommand)]
    pub command: BundleCommand,
}

#[derive(Subcommand, Debug)]
pub enum BundleCommand {
    /// Publish a workload bundle directory (workload.json + resources.json +
    /// graph.yaml) into the local OCI store. Every module digest the
    /// manifest pins must already be in the store.
    Publish {
        /// Bundle directory.
        bundle_dir: PathBuf,
        #[arg(long)]
        store: Option<PathBuf>,
        /// Tag override (default: `<name>:<version>` from workload.json).
        #[arg(long)]
        tag: Option<String>,
        /// Annotate provenance=published instead of local-build.
        #[arg(long)]
        published: bool,
    },
}

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

// ── fluxor store ls|inspect|rm ────────────────────────────────────────

pub fn dispatch_store(args: StoreArgs) -> Result<()> {
    match args.command {
        StoreCommand::Ls {
            store,
            provenance,
            json,
        } => cmd_store_ls(store.as_deref(), provenance.as_deref(), json),
        StoreCommand::Inspect { reference, store } => {
            cmd_store_inspect(&reference, store.as_deref())
        }
        StoreCommand::Rm { reference, store } => cmd_store_rm(&reference, store.as_deref()),
        StoreCommand::Pin {
            reference,
            store,
            project_root,
        } => cmd_store_pin(&reference, store.as_deref(), project_root.as_deref()),
    }
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

fn cmd_store_inspect(reference: &str, store_dir: Option<&Path>) -> Result<()> {
    let store = open_store(store_dir)?;
    let desc = store
        .resolve(reference)
        .map_err(|e| Error::Config(e.to_string()))?;
    let manifest = store
        .read_manifest(&desc)
        .map_err(|e| Error::Config(e.to_string()))?;
    let doc = serde_json::json!({ "descriptor": desc, "manifest": manifest });
    println!("{}", serde_json::to_string_pretty(&doc)?);
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

// ── fluxor.lock pinning + consume-side resolution (P2) ──────────────

/// Owned form of `modules::StoreFallback` — what `lock_store_resolver`
/// hands to the packaging call sites.
pub type BoxedStoreFallback = Box<dyn Fn(&str) -> crate::modules::StorePin>;

/// Upsert `[[oci_module]]` pins into the project's `fluxor.lock`,
/// keyed by `(name, target)`. Creates a minimal lockfile when absent.
/// The read-modify-write runs under an exclusive advisory lock so two
/// concurrent publish/pin commands can't discard each other's pins.
fn upsert_pins(project_root: &Path, entries: Vec<crate::lockfile::LockedOciModule>) -> Result<()> {
    let _guard = crate::lockfile::lock_lockfile(project_root)?;
    let mut lock = crate::lockfile::read(project_root)?.unwrap_or_default();
    if lock.lockfile_version == 0 {
        lock.lockfile_version = 1;
        lock.generated_by = format!("fluxor {}", env!("CARGO_PKG_VERSION"));
    }
    for entry in entries {
        match lock
            .oci_modules
            .iter_mut()
            .find(|m| m.name == entry.name && m.target == entry.target)
        {
            Some(existing) => *existing = entry,
            None => lock.oci_modules.push(entry),
        }
    }
    lock.oci_modules
        .sort_by(|a, b| (&a.target, &a.name).cmp(&(&b.target, &b.name)));
    crate::lockfile::write(project_root, &lock)?;
    Ok(())
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
    let manifest = store
        .read_manifest(&desc)
        .map_err(|e| Error::Config(e.to_string()))?;
    let name = manifest
        .annotations
        .get(ANN_MODULE_NAME)
        .cloned()
        .ok_or_else(|| {
            Error::Config(format!(
                "'{reference}' has no {ANN_MODULE_NAME} annotation — not a module \
                 artifact (or published by an older tool; re-publish it)"
            ))
        })?;
    let target = manifest
        .annotations
        .get(ANN_TARGET)
        .cloned()
        .ok_or_else(|| Error::Config(format!("'{reference}' has no {ANN_TARGET} annotation")))?;
    // Fail now, not at consume time, if the .fmod layer is unreadable.
    store
        .module_fmod_blob(&manifest)
        .map_err(|e| Error::Config(e.to_string()))?;
    upsert_pins(
        &pr,
        vec![crate::lockfile::LockedOciModule {
            name: name.clone(),
            target: target.clone(),
            digest: desc.digest.clone(),
            reference: reference.to_string(),
        }],
    )?;
    println!(
        "pinned {target}/{name} -> {} in {}",
        desc.digest,
        crate::lockfile::lockfile_path(&pr).display()
    );
    Ok(())
}

/// Build the `fluxor.lock`-pinned OCI-store fallback used by module
/// resolution (registry plan P2). `None` when the project has no lockfile,
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
    let lock = match crate::lockfile::read(project_root) {
        Ok(l) => l?,
        Err(e) => {
            let why = format!("fluxor.lock unreadable: {e}");
            return Some(Box::new(move |_name: &str| StorePin::Failed(why.clone())));
        }
    };
    let pins: Vec<crate::lockfile::LockedOciModule> = lock
        .oci_modules
        .into_iter()
        .filter(|m| m.target == target)
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

#[cfg(test)]
mod tests {
    use super::*;
    use fluxor_tools::oci_store::PROVENANCE_LOCAL;

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

        upsert_pins(
            &proj,
            vec![crate::lockfile::LockedOciModule {
                name: "codec".into(),
                target: "bcm2712".into(),
                digest: digest.clone(),
                reference: "bcm2712/codec:1.0.0".into(),
            }],
        )
        .expect("upsert");

        // Re-upsert with the same key replaces, not duplicates.
        upsert_pins(
            &proj,
            vec![crate::lockfile::LockedOciModule {
                name: "codec".into(),
                target: "bcm2712".into(),
                digest: digest.clone(),
                reference: "bcm2712/codec:1.0.0".into(),
            }],
        )
        .expect("upsert again");
        let lock = crate::lockfile::read(&proj).unwrap().unwrap();
        assert_eq!(lock.oci_modules.len(), 1);

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

        upsert_pins(
            &proj,
            vec![crate::lockfile::LockedOciModule {
                name: "codec".into(),
                target: "bcm2712".into(),
                digest,
                reference: "bcm2712/codec:1.0.0".into(),
            }],
        )
        .unwrap();
        let store_dir = tmp.path().join("store");
        let resolver = lock_store_resolver(&proj, "bcm2712", Some(&store_dir)).unwrap();
        assert!(
            matches!(resolver("codec"), crate::modules::StorePin::Failed(_)),
            "tampered blob must be a hard failure, not a silent fall-through"
        );
    }
}
