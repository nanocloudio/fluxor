//! CLI glue for the local OCI artifact store: `fluxor publish
//! package|stack|node|firmware|workload` and `fluxor store
//! ls|rm|snapshot|push|pull|adopt|fsck|gc`. Project artifacts
//! publish through `fluxor publish` (`fluxor_tools::store_publish`), and
//! read-only artifact display is `fluxor inspect <ref>`.
//!
//! The store engine lives in the lib (`fluxor_tools::oci_store`, and
//! `fluxor_tools::store_remote` for the registry side); this module walks
//! the project tree and formats output. Offline-first: `store push` and
//! `store pull` are the only verbs that touch the network.

use std::fs;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};

use crate::error::{Error, Result};
// Bin-root helper (cli/commands_c.rs, flat `include!` scope).
use crate::resolve_project_root;
use fluxor_tools::oci_store::{
    self, git_source_rev, sha256_hex_prefixed, ArtifactMeta, OciStore, PackageArtifact,
    StackArtifact, ANN_KIND, ANN_REF_NAME, ANN_TARGET, PROVENANCE_LOCAL, PROVENANCE_PUBLISHED,
};
use fluxor_tools::store_remote;

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
    /// Register a checkout's `fluxor.lock` pins with the store, so its
    /// digests are garbage-collection roots.
    ///
    /// A checkout registers itself whenever it writes its lockfile; this
    /// registers one whose lockfile was written elsewhere — a fresh
    /// clone — and is the answer to "my repo is not in workspace.toml".
    /// Membership is about epoch and currency checking and has nothing
    /// to do with whether somebody is holding a digest.
    Adopt {
        /// Checkouts to register (default: the current project root).
        checkouts: Vec<PathBuf>,
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Check every pin every checkout holds, and the store's own
    /// integrity. Read-only, safe to run while others publish.
    Fsck {
        #[arg(long)]
        store: Option<PathBuf>,
        /// Restore quarantined blobs to `blobs/`. Never deletes.
        #[arg(long)]
        repair: bool,
    },
    /// Collect unreachable blobs: quarantine what no root reaches, then
    /// delete what has sat in quarantine long enough.
    ///
    /// The ONLY verb that deletes bytes. The sweep a publish triggers
    /// only ever looks at the manifest it just displaced, so a blob
    /// spared once is never reconsidered; this is the whole-store pass
    /// that actually reclaims anything.
    Gc {
        #[arg(long)]
        store: Option<PathBuf>,
        /// Days a quarantined blob must sit untouched before deletion.
        #[arg(long, default_value_t = 30)]
        retain_days: u64,
        /// Also drop ledger entries whose checkout is no longer on disk.
        /// Off by default: an unmounted repo looks exactly like a
        /// deleted one.
        #[arg(long)]
        forget_missing: bool,
        /// Report what would be collected and write nothing.
        #[arg(long)]
        dry_run: bool,
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

// ── fluxor publish package | stack ────────────────────────────────────

/// A lib error as the bin's, without a second `Config error:` prefix.
fn lift_error(e: fluxor_tools::error::Error) -> Error {
    match e {
        fluxor_tools::error::Error::Config(m) => Error::Config(m),
        other => Error::Config(other.to_string()),
    }
}

/// One shippable a publish stages: its prepared artefact, the reference it
/// publishes under, and how many module artefacts it carries.
pub struct Staged {
    pub prepared: oci_store::Prepared,
    pub reference: String,
    pub modules: usize,
}

/// The metadata every artefact of the project at `project_root` carries.
fn shippable_meta(
    project_root: &Path,
    published: bool,
) -> Result<(
    crate::project::ProjectIdentity,
    String,
    Option<String>,
    &'static str,
)> {
    let identity = crate::project::project_identity(project_root)
        .map_err(Error::Config)?
        .ok_or_else(|| {
            Error::Config(format!(
                "no [project] table in {}/fluxor.toml — a package or stack is published under \
                 its project",
                project_root.display()
            ))
        })?;
    let epoch_hex: String = crate::hash::abi_surface_digest()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok((
        identity,
        epoch_hex,
        git_source_rev(project_root),
        provenance_flag(published),
    ))
}

/// A package's publish, staged: a source manifest
/// (`packaging/<service|applet>/<name>/workload.toml`) is checked and emitted
/// — its graph built, its module artefacts resolved as the build resolves
/// them — and its documents validated. A package directory given instead
/// (an emitted root, a flat target dir, or a materialised package with its
/// `modules/`) carries its documents, and its module bytes come from its
/// `modules/` or the project's shelf; either way each must hash to the
/// digest `workload.json` pins.
pub fn stage_package(
    package: &Path,
    own: &fluxor_tools::stack::OwnModules,
    store: &OciStore,
    tag: Option<&str>,
    published: bool,
    verbose: bool,
) -> Result<Staged> {
    let (dir, emitted) = if crate::workload_src::is_source_manifest(package) {
        let project_root = crate::project::root_for_config(package);
        fluxor_tools::packaging::check_package(package, &project_root).map_err(Error::Config)?;
        let e = crate::workload_src::emit_package(package, None, verbose)?;
        // A consumer pins a package's modules from where they are
        // published: each of the project's own the package ships must be a
        // published artefact carrying these bytes — staged by this publish,
        // or already in the store.
        let unpublished: Vec<String> = e
            .modules
            .iter()
            .filter(|(name, _)| e.own.contains(name))
            .map(|(name, bytes)| (name, sha256_hex_prefixed(bytes)))
            .filter(|(name, digest)| !own.holds(name, &e.abi, digest))
            .map(|(name, digest)| format!("{name} ({digest})"))
            .collect();
        if !unpublished.is_empty() {
            return Err(Error::Config(format!(
                "package {} ships this project's module(s) {} for {}, which no published \
                 artefact carries: publish its modules with it (`fluxor publish --only fmod \
                 --only package`)",
                package.display(),
                unpublished.join(", "),
                e.abi
            )));
        }
        (e.root, Some(e.modules))
    } else {
        (package.to_path_buf(), None)
    };
    let docs = if dir.join("graph.yaml").is_file() {
        dir.clone()
    } else {
        dir.join("linux")
    };
    let read = |name: &str| -> Result<Vec<u8>> {
        fs::read(docs.join(name))
            .map_err(|e| Error::Config(format!("package {}: {name}: {e}", docs.display())))
    };
    let workload_json = String::from_utf8(read("workload.json")?)
        .map_err(|e| Error::Config(format!("workload.json: {e}")))?;
    let resources_json = read("resources.json")?;
    let graph_yaml = read("graph.yaml")?;
    let manifest = fluxor_tools::workload::parse_manifest(&workload_json).map_err(Error::Config)?;
    let report = fluxor_tools::workload::validate(&manifest);
    if !report.is_ok() {
        return Err(Error::Config(format!(
            "workload package '{}' failed validation: {}",
            manifest.name,
            report.errors.join("; ")
        )));
    }
    let project_root = crate::project::root_for_config(&docs.join("workload.json"));
    let modules = match emitted {
        Some(m) => m,
        None => package_dir_modules(&docs, &project_root, &manifest)?,
    };
    let reference = match tag {
        Some(t) => t.to_string(),
        None => format!("{}:{}", manifest.name, manifest.version),
    };
    let (identity, epoch_hex, source_rev, provenance) = shippable_meta(&project_root, published)?;
    let meta = ArtifactMeta {
        project: &identity.name,
        provenance,
        source_rev: source_rev.as_deref(),
        abi_surface_hex: &epoch_hex,
        input_digest_hex: None,
        ci_digest_hex: None,
    };
    let prepared = store
        .prepare_package(
            &PackageArtifact {
                workload_json: &workload_json,
                resources_json: &resources_json,
                graph_yaml: &graph_yaml,
                modules: &modules,
                ref_name: &reference,
            },
            &meta,
        )
        .map_err(|e| Error::Config(e.to_string()))?;
    Ok(Staged {
        prepared,
        reference,
        modules: modules.len(),
    })
}

/// The module bytes of an already-emitted package directory, by the names
/// its `workload.json` pins: from its `modules/`, else the project's shelf.
/// The pinned digests are checked when the package is prepared, so these
/// are content-addressed reads.
fn package_dir_modules(
    docs: &Path,
    project_root: &Path,
    manifest: &fluxor_tools::workload::WorkloadManifest,
) -> Result<Vec<(String, Vec<u8>)>> {
    let modules_dir = if docs.join("modules").is_dir() {
        docs.join("modules")
    } else {
        crate::modules_build::module_root(
            None,
            project_root,
            &project_root.join("target/fluxor"),
            "linux",
        )?
    };
    let mut modules: Vec<(String, Vec<u8>)> = Vec::new();
    for imp in &manifest.implementations {
        for m in &imp.modules {
            if modules.iter().any(|(n, _)| n == &m.name) {
                continue;
            }
            let path = modules_dir.join(format!("{}.fmod", m.name));
            let bytes = fs::read(&path).map_err(|e| {
                Error::Config(format!(
                    "module '{}' has no built .fmod at {} ({e})",
                    m.name,
                    path.display()
                ))
            })?;
            modules.push((m.name.clone(), bytes));
        }
    }
    Ok(modules)
}

/// A stack's publish, staged: the document checked (the project's
/// `packaging/stack/<name>.yaml`, parsing, versioned, rendering with its
/// defaults and examples), and each module it composes resolved by the
/// publishing project's resolver — its own modules referenced through
/// `own`, its pinned ones through their pins — and recorded beside it, so a
/// consumer that references the stack pins exactly the modules it was
/// composed against.
pub fn stage_stack(
    path: &Path,
    own: &[fluxor_tools::store_resolve::Artifact],
    tag: Option<&str>,
    published: bool,
    store: &OciStore,
) -> Result<Staged> {
    use fluxor_tools::stack;
    let project_root = crate::project::root_for_config(path);
    stack::check_publishable(path, &project_root).map_err(lift_error)?;
    let (doc, bytes) = stack::read_for_publish(path).map_err(lift_error)?;
    let r = fluxor_tools::module_resolver::ModuleResolver::for_project(
        &project_root,
        fluxor_tools::module_resolver::Abi::Unplaced,
        None,
    )
    .map_err(lift_error)?;
    let modules = stack::module_references(&doc, &r, own).map_err(lift_error)?;
    let modules_json = serde_json::to_vec_pretty(&modules)
        .map_err(|e| Error::Config(format!("modules.json: {e}")))?;
    let reference = stack::publish_ref(&doc, tag).map_err(lift_error)?;
    let (identity, epoch_hex, source_rev, provenance) = shippable_meta(&project_root, published)?;
    let meta = ArtifactMeta {
        project: &identity.name,
        provenance,
        source_rev: source_rev.as_deref(),
        abi_surface_hex: &epoch_hex,
        input_digest_hex: None,
        ci_digest_hex: None,
    };
    let prepared = store
        .prepare_stack(
            &StackArtifact {
                stack_yaml: &bytes,
                modules_json: &modules_json,
                ref_name: &reference,
            },
            &meta,
        )
        .map_err(|e| Error::Config(e.to_string()))?;
    Ok(Staged {
        prepared,
        reference,
        modules: modules.len(),
    })
}

/// Commit one staged shippable into its project's index, in one
/// transaction, and say what was published.
fn commit_shippable(
    store: &OciStore,
    project_root: &Path,
    kind: &str,
    staged: Staged,
) -> Result<()> {
    let identity = crate::project::project_identity(project_root)
        .map_err(Error::Config)?
        .ok_or_else(|| {
            Error::Config(format!("no [project] table in {}", project_root.display()))
        })?;
    let deps = crate::project::dependencies(project_root)
        .unwrap_or_default()
        .iter()
        .map(|d| d.name.clone())
        .collect::<Vec<_>>()
        .join(",");
    let deps = (!deps.is_empty()).then_some(deps);
    let txn = store
        .begin_publish()
        .map_err(|e| Error::Config(e.to_string()))?;
    let reference = staged.reference;
    let prepared = vec![staged.prepared];
    let (committed, report) = store
        .read_index()
        .and_then(|index| {
            store.plan_publish(
                &index,
                &identity.name,
                &identity.version,
                &prepared,
                deps.as_deref(),
                &[],
            )
        })
        .and_then(|plan| store.commit_plan(&txn, plan, prepared, Some(project_root)))
        .map_err(|e| Error::Config(e.to_string()))?;
    if !report.is_empty() {
        eprint!(
            "\npublish {kind} {reference} — displacement report{}",
            oci_store::render_displacement(&report)
        );
    }
    let digest = committed
        .iter()
        .find(|d| d.annotations.get(ANN_REF_NAME) == Some(&reference))
        .map(|d| d.digest.clone())
        .unwrap_or_default();
    println!(
        "{reference} -> {digest} ({} module(s), project {})",
        staged.modules, identity.name
    );
    Ok(())
}

/// `fluxor publish package <dir | workload.toml>`.
pub fn cmd_package_publish(
    package: &Path,
    store_dir: Option<&Path>,
    tag: Option<&str>,
    published: bool,
    verbose: bool,
) -> Result<()> {
    let store = open_store(store_dir)?;
    let project_root = crate::project::root_for_config(package);
    let own = match crate::project::project_identity(&project_root).map_err(Error::Config)? {
        Some(id) => fluxor_tools::stack::OwnModules::published(&store, &id.name),
        None => fluxor_tools::stack::OwnModules::default(),
    };
    let staged = stage_package(package, &own, &store, tag, published, verbose)?;
    commit_shippable(&store, &project_root, "package", staged)
}

/// `fluxor publish stack <file>`: its own modules referenced as the project
/// has published them.
pub fn cmd_stack_publish(
    path: &Path,
    store_dir: Option<&Path>,
    tag: Option<&str>,
    published: bool,
) -> Result<()> {
    let store = open_store(store_dir)?;
    let project_root = crate::project::root_for_config(path);
    let identity = crate::project::project_identity(&project_root)
        .map_err(Error::Config)?
        .ok_or_else(|| {
            Error::Config(format!(
                "no [project] table in {}/fluxor.toml — a stack is published under its project",
                project_root.display()
            ))
        })?;
    let own = fluxor_tools::stack::published_modules(&store, &identity.name);
    let staged = stage_stack(path, &own, tag, published, &store)?;
    commit_shippable(&store, &project_root, "stack", staged)
}

// ── fluxor publish node|firmware ──────────────────────────────────────

/// Publish a device artifact (node image / firmware image). For a
/// node image the FXSL header supplies epoch + ABI pin, mirrored into
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

    // Node images carry their own truth in the FXSL header.
    const FXSL_MAGIC: u32 = 0x4C53_5846;
    let image_kind = kind.starts_with("image");
    let (epoch, abi_hex) = if image_kind {
        if bytes.len() < 96
            || u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) != FXSL_MAGIC
        {
            return Err(Error::Config(format!(
                "{} is not a node image (missing FXSL header) — build it with `fluxor build <config> --emit=node`",
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
    // Layered (exploded) is the default node-image form;
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

/// `fluxor publish workload <dir>`: the workload image `--emit=workload`
/// wrote, as an OCI artifact in the local store.
pub fn cmd_workload_image_publish(
    dir: &Path,
    tag: Option<&str>,
    store_dir: Option<&Path>,
) -> Result<()> {
    let read = |p: &Path| fs::read(p).map_err(|e| Error::Config(format!("{}: {e}", p.display())));
    let doc: serde_json::Value = serde_json::from_slice(&read(&dir.join("workload-image.json"))?)
        .map_err(|e| Error::Config(format!("workload-image.json: {e}")))?;
    let field = |k: &str| -> Result<String> {
        match doc.get(k).and_then(|v| v.as_str()) {
            Some(v) if !v.is_empty() => Ok(v.to_string()),
            _ => Err(Error::Config(format!("workload-image.json: no `{k}`"))),
        }
    };
    let name = field("name")?;
    let target = field("target")?;
    let module_abi = field("module_abi")?;
    let abi_surface = field("abi_surface")?;
    let graph = read(&dir.join("graph.flxa"))?;
    // Every module the image lists, read back and checked against the
    // digest the image recorded for it: the layer digest is the pin a node
    // admits the module by, so a module that changed since the image was
    // written must not be published under it.
    let listed = doc
        .get("modules")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if listed.is_empty() {
        return Err(Error::Config("workload-image.json lists no modules".into()));
    }
    let mut modules = Vec::with_capacity(listed.len());
    for m in &listed {
        let mname = m.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let hash = m.get("name_hash").and_then(|v| v.as_u64());
        let sha = m.get("sha256").and_then(|v| v.as_str());
        let (Some(hash), Some(sha), false) = (hash, sha, mname.is_empty()) else {
            return Err(Error::Config(format!(
                "workload-image.json: a module entry lacks name, name_hash or sha256: {m}"
            )));
        };
        let name_hash = u32::try_from(hash).map_err(|_| {
            Error::Config(format!(
                "workload-image.json: {mname}: name_hash {hash} is not a u32"
            ))
        })?;
        // A module name becomes one file name inside the image's
        // `modules/`: it names no directory and leads nowhere else.
        if !fluxor_tools::workload::is_module_name(mname) {
            return Err(Error::Config(format!(
                "workload-image.json: {mname:?} is not a module name (a letter or digit, then \
                 letters, digits, '_' or '-', at most 64 bytes)"
            )));
        }
        let bytes = read(&dir.join("modules").join(format!("{mname}.fmod")))?;
        let actual = sha256_hex_prefixed(&bytes);
        if actual.trim_start_matches("sha256:") != sha {
            return Err(Error::Config(format!(
                "{mname}.fmod is not the module the image recorded (sha256 {sha}, the file is {actual}); rebuild the image"
            )));
        }
        modules.push(oci_store::WorkloadModule {
            name: mname.to_string(),
            name_hash,
            bytes,
        });
    }
    let env = workload_image_env(&doc)?;
    let ref_name = tag
        .map(str::to_string)
        .unwrap_or_else(|| format!("{name}:latest"));
    let store = open_store(store_dir)?;
    let source_rev = git_source_rev(&resolve_project_root(None));
    let desc = oci_store::publish_workload_image(
        &store,
        &oci_store::WorkloadImagePublish {
            name: &name,
            target: &target,
            module_abi: &module_abi,
            abi_surface_hex: &abi_surface,
            graph: &graph,
            modules: &modules,
            env: &env,
            provenance: PROVENANCE_LOCAL,
            source_rev: source_rev.as_deref(),
            ref_name: &ref_name,
        },
    )
    .map_err(|e| Error::Config(e.to_string()))?;
    println!("{ref_name} -> {}", desc.digest);
    Ok(())
}

/// `workload-image.json`'s `env`: every param the image binds to the
/// workload's environment, each `name`, `module`, `param` and `required`.
/// None listed is an image that binds none; an entry missing a field, or
/// with an empty or malformed name, is refused, since the image's config
/// would otherwise tell a puller less than its graph binds.
fn workload_image_env(doc: &serde_json::Value) -> Result<Vec<oci_store::WorkloadEnvBinding>> {
    let Some(listed) = doc.get("env") else {
        return Ok(Vec::new());
    };
    let Some(listed) = listed.as_array() else {
        return Err(Error::Config(
            "workload-image.json: `env` is not a list".into(),
        ));
    };
    let mut out = Vec::with_capacity(listed.len());
    for b in listed {
        let s = |k: &str| b.get(k).and_then(|v| v.as_str()).filter(|v| !v.is_empty());
        let (Some(name), Some(module), Some(param), Some(required)) = (
            s("name"),
            s("module"),
            s("param"),
            b.get("required").and_then(|v| v.as_bool()),
        ) else {
            return Err(Error::Config(format!(
                "workload-image.json: an env entry lacks name, module, param or required: {b}"
            )));
        };
        if name.contains(['=', '\0']) {
            return Err(Error::Config(format!(
                "workload-image.json: env name {name:?} cannot be an environment name"
            )));
        }
        out.push(oci_store::WorkloadEnvBinding {
            name: name.into(),
            module: module.into(),
            param: param.into(),
            required,
        });
    }
    Ok(out)
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
        StoreCommand::Adopt { checkouts, store } => cmd_store_adopt(&checkouts, store.as_deref()),
        StoreCommand::Fsck { store, repair } => cmd_store_fsck(store.as_deref(), repair),
        StoreCommand::Gc {
            store,
            retain_days,
            forget_missing,
            dry_run,
        } => cmd_store_gc(store.as_deref(), retain_days, forget_missing, dry_run),
    }
}

fn cmd_store_adopt(checkouts: &[PathBuf], store_dir: Option<&Path>) -> Result<()> {
    let store = open_store(store_dir)?;
    let targets: Vec<PathBuf> = if checkouts.is_empty() {
        vec![resolve_project_root(None)]
    } else {
        checkouts.to_vec()
    };
    for checkout in targets {
        let n = fluxor_tools::store_pins::adopt(store.root(), &checkout)
            .map_err(|e| Error::Config(e.to_string()))?;
        println!("adopted {} ({n} pin(s) now GC roots)", checkout.display());
    }
    Ok(())
}

fn cmd_store_fsck(store_dir: Option<&Path>, repair: bool) -> Result<()> {
    let store = open_store(store_dir)?;
    let report = fluxor_tools::store_maint::fsck(&store, repair)
        .map_err(|e| Error::Config(e.to_string()))?;
    print!("{}", fluxor_tools::store_maint::render(&report));
    let dead: usize = report
        .checkouts
        .iter()
        .map(|c| c.notable.iter().filter(|(_, h)| h.is_fault()).count())
        .sum();
    if dead > 0 || !report.index_faults.is_empty() {
        return Err(Error::Config(format!(
            "fsck found {dead} unresolvable pin(s) and {} index fault(s)",
            report.index_faults.len()
        )));
    }
    println!("\nfsck: every pin resolves.");
    Ok(())
}

fn cmd_store_gc(
    store_dir: Option<&Path>,
    retain_days: u64,
    forget_missing: bool,
    dry_run: bool,
) -> Result<()> {
    let store = open_store(store_dir)?;
    if dry_run {
        let report = fluxor_tools::store_maint::fsck(&store, false)
            .map_err(|e| Error::Config(e.to_string()))?;
        println!(
            "gc --dry-run: {} of {} blobs are unreachable from any root ({:.1} GiB); \
             {} already quarantined",
            report.blobs_total - report.blobs_live,
            report.blobs_total,
            report.reclaimable as f64 / (1u64 << 30) as f64,
            report.quarantined
        );
        return Ok(());
    }
    let report = store
        .gc(retain_days, forget_missing)
        .map_err(|e| Error::Config(e.to_string()))?;
    println!(
        "gc: {} blob(s) quarantined, {} deleted after {retain_days}d ({:.1} GiB freed), \
         {} still held",
        report.quarantined.len(),
        report.deleted.len(),
        report.bytes_freed as f64 / (1u64 << 30) as f64,
        report.held
    );
    for checkout in &report.forgotten {
        println!("  forgot ledger entry for {}", checkout.display());
    }
    Ok(())
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
        "\x1b[1;32mPushed\x1b[0m {reference} → {}/{} ({})",
        remote.host,
        remote.name(),
        desc.digest
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
        "\x1b[1;32mPulled\x1b[0m {}/{} → {tag} ({})",
        remote.host,
        remote.name(),
        desc.digest
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
    // Provenance lives beside the manifest, not inside it, so that recording
    // it cannot move the digest everything downstream pins.
    // Reading it is one file open per artifact, against a local store.
    let latest = |d: &oci_store::Descriptor| store.latest_provenance(&d.digest);
    let mut entries: Vec<&oci_store::Descriptor> = index
        .manifests
        .iter()
        .filter(|d| provenance.is_none_or(|p| latest(d).is_some_and(|row| row.provenance == p)))
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
        let row = latest(d).unwrap_or_default();
        let rev: String = row
            .source_rev
            .unwrap_or_default()
            .chars()
            .take(12)
            .collect();
        println!(
            "{:<40} {:<7} {:<10} {:<12} {:<14} {digest12}",
            ann(d, ANN_REF_NAME),
            ann(d, ANN_KIND),
            ann(d, ANN_TARGET),
            row.provenance,
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

    /// `workload-image.json`'s `env` becomes the image config's bindings;
    /// none listed is none bound; an entry that would tell a puller less
    /// than the graph binds is refused.
    #[test]
    fn a_workload_image_env_list_is_read_whole_or_refused() {
        let doc = serde_json::json!({"env": [
            {"name": "TOKEN", "module": "probe", "param": "token", "required": true},
            {"name": "PORT", "module": "probe", "param": "port", "required": false},
        ]});
        let env = workload_image_env(&doc).unwrap();
        assert_eq!(env.len(), 2);
        assert_eq!(
            (env[0].name.as_str(), env[0].required, env[1].param.as_str()),
            ("TOKEN", true, "port")
        );
        assert!(workload_image_env(&serde_json::json!({}))
            .unwrap()
            .is_empty());
        for bad in [
            serde_json::json!({"env": "TOKEN"}),
            serde_json::json!({"env": [{"name": "TOKEN", "module": "probe", "param": "token"}]}),
            serde_json::json!({"env": [{"name": "", "module": "m", "param": "p", "required": true}]}),
            serde_json::json!({"env": [{"name": "A=B", "module": "m", "param": "p", "required": true}]}),
        ] {
            assert!(workload_image_env(&bad).is_err(), "{bad}");
        }
    }
}
