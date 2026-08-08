//! Dev-facing bundle source (rfc_system_services.md §10).
//!
//! A thin TOML source manifest — non-derivable fields only — from which
//! `fluxor build <app.fluxor.toml>` emits the EXISTING committed-bundle
//! format the agent consumes (`workload.json` + `resources.json` +
//! `graph.yaml`), plus the per-target `config.bin`/`modules.bin` the run
//! path consumes (§10.3: `build_one` builds them anyway). No new format,
//! no new command, no merge semantic: the manifest REFERENCES whole
//! per-target graph files (§10.1).
//!
//! Layout emitted under `target/fluxor/<name>/`:
//!
//! ```text
//! target/fluxor/<name>/
//!   workload.json                    # all implementations
//!   <target>/{workload.json, graph.yaml, resources.json,   # flat triple —
//!             config.bin, modules.bin}                     # agent-committable
//! ```
//!
//! `workload.json` is duplicated into each target dir so that dir is
//! directly consumable by `fluxor agent commit --bundle` (which expects the
//! flat triple; the agent path is unchanged, §10.4).
//!
//! `linux`-family targets are emitted; other implementations are listed but
//! skipped with a notice.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Error, Result};
use fluxor_tools::workload::{
    validate, Bindings, Contract, DigestRef, Export, Health, Implementation, ModuleRef,
    ResourceProfileDoc, Target, UpdatePolicy, WorkloadManifest,
};

// ============================================================================
// Source manifest (TOML)
// ============================================================================

/// `[workload]` — identity + role (§10.2): `service` implementations carry the
/// health/update contract and the lease/drain machinery; `cli` carries the
/// stdio/exit surface (rfc_cli_execution.md). Named `role`, not `kind` — `kind`
/// means `scenario`.
#[derive(Debug, Deserialize)]
struct WorkloadTable {
    name: String,
    version: String,
    #[serde(default = "default_role")]
    role: String,
}

fn default_role() -> String {
    "service".to_string()
}

/// `[[implementation]]` — one existing per-target graph file, referenced,
/// never merged (§10.1).
#[derive(Debug, Deserialize)]
struct ImplementationTable {
    target: String,
    graph: String,
}

/// `[[export]]` — a declared endpoint plus its graph binding (the binding is
/// not derivable from the graph; `validate()` requires one per export).
#[derive(Debug, Deserialize)]
struct ExportTable {
    name: String,
    protocol: String,
    port: u16,
    binding: String,
}

/// `[resources]` — the non-derivable footprint overrides. Module and edge
/// counts are derived from the graph; these are capacity declarations.
#[derive(Debug, Default, Deserialize)]
struct ResourcesTable {
    state_bytes: Option<u32>,
    buffer_bytes: Option<u32>,
    endpoints: Option<u16>,
    domains: Option<u8>,
}

/// `[health]` — contract signal names bind to graph targets. Defaults:
/// signals `<name>.ready`/`<name>.progress` bound to the first graph
/// module's `ready`/`progress`.
#[derive(Debug, Default, Deserialize)]
struct HealthTable {
    readiness: Option<String>,
    liveness: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SourceManifest {
    workload: WorkloadTable,
    #[serde(default, rename = "implementation")]
    implementations: Vec<ImplementationTable>,
    #[serde(default, rename = "export")]
    exports: Vec<ExportTable>,
    #[serde(default)]
    resources: ResourcesTable,
    #[serde(default)]
    health: HealthTable,
}

fn parse_source_manifest(text: &str) -> Result<SourceManifest> {
    let m: SourceManifest =
        toml::from_str(text).map_err(|e| Error::Config(format!("source manifest: {e}")))?;
    if m.workload.role != "service" && m.workload.role != "cli" {
        return Err(Error::Config(format!(
            "workload.role must be 'service' or 'cli' (got '{}')",
            m.workload.role
        )));
    }
    if m.implementations.is_empty() {
        return Err(Error::Config(
            "source manifest declares no [[implementation]]".into(),
        ));
    }
    Ok(m)
}

// ============================================================================
// Graph facts (derived, never declared)
// ============================================================================

/// The graph facts a bundle derives rather than declares: module types in
/// declaration order and the module/edge counts that seed the resource
/// profile. Platform-stack modules are NOT counted — they are node substrate,
/// not workload footprint (the committed dns bundle counts only its own
/// module, and the plan's `system_modules` policy places ranges past the
/// platform prefix).
struct GraphFacts {
    module_types: Vec<String>,
    modules: u16,
    edges: u16,
}

fn graph_facts(graph_path: &Path) -> Result<GraphFacts> {
    let text = std::fs::read_to_string(graph_path)
        .map_err(|e| Error::Config(format!("read graph {}: {e}", graph_path.display())))?;
    let doc: serde_yaml::Value =
        serde_yaml::from_str(&text).map_err(|e| Error::Config(format!("parse graph: {e}")))?;
    let modules = doc
        .get("modules")
        .and_then(|m| m.as_sequence())
        .cloned()
        .unwrap_or_default();
    let mut module_types = Vec::new();
    for m in &modules {
        // `type:` overrides; `name:` is the fallback (the common single-
        // instance spelling).
        let ty = m
            .get("type")
            .and_then(|v| v.as_str())
            .or_else(|| m.get("name").and_then(|v| v.as_str()))
            .ok_or_else(|| Error::Config("graph module without name/type".into()))?;
        module_types.push(ty.to_string());
    }
    let edges = doc
        .get("wiring")
        .and_then(|w| w.as_sequence())
        .map(|w| w.len())
        .unwrap_or(0);
    Ok(GraphFacts {
        modules: module_types.len() as u16,
        module_types,
        edges: edges as u16,
    })
}

fn sha256_ref(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut s = String::from("sha256:");
    for b in out {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ============================================================================
// Emission
// ============================================================================

/// Emit the committed bundle (+ per-target blobs) from a thin source
/// manifest. Returns the bundle root (`target/fluxor/<name>/`).
pub fn emit_bundle(manifest_path: &Path, verbose: bool) -> Result<PathBuf> {
    let text = std::fs::read_to_string(manifest_path)
        .map_err(|e| Error::Config(format!("read {}: {e}", manifest_path.display())))?;
    let src = parse_source_manifest(&text)?;
    let manifest_dir = manifest_path.parent().unwrap_or(Path::new("."));
    let project_root = crate::project::root_for_config(manifest_path);
    let bundle_root = project_root.join("target/fluxor").join(&src.workload.name);

    let exports: Vec<Export> = src
        .exports
        .iter()
        .map(|e| Export {
            name: e.name.clone(),
            protocol: e.protocol.clone(),
            port: e.port,
        })
        .collect();

    let mut implementations = Vec::new();
    let mut first_module_for_health: Option<String> = None;
    let mut emitted_targets: Vec<(String, PathBuf)> = Vec::new();

    for imp in &src.implementations {
        let graph_path = manifest_dir.join(&imp.graph);
        // linux-family targets only. Others are declared in the source manifest
        // but not emitted — say so rather than silently narrowing the manifest.
        if imp.target != "linux" {
            println!(
                "  skipping [[implementation]] target '{}' (emits linux only)",
                imp.target
            );
            continue;
        }
        let facts = graph_facts(&graph_path)?;
        if first_module_for_health.is_none() {
            first_module_for_health = facts.module_types.first().cloned();
        }

        let target_dir = bundle_root.join(&imp.target);
        std::fs::create_dir_all(&target_dir)?;

        // graph.yaml: copied verbatim — its bytes are the digest the agent
        // verifies at commit.
        let graph_bytes = std::fs::read(&graph_path)?;
        std::fs::write(target_dir.join("graph.yaml"), &graph_bytes)?;

        // resources.json: counts derived from the graph, capacities from the
        // source manifest's [resources] (defaults match the hello bundle's
        // conservative envelope).
        let resources = ResourceProfileDoc {
            modules: facts.modules,
            edges: facts.edges,
            state_bytes: src.resources.state_bytes.unwrap_or(65536),
            buffer_bytes: src.resources.buffer_bytes.unwrap_or(16384),
            endpoints: src.resources.endpoints.unwrap_or(exports.len() as u16),
            domains: src.resources.domains.unwrap_or(1),
            state_schemas: BTreeMap::new(),
        };
        let resources_bytes =
            serde_json::to_vec_pretty(&resources).map_err(|e| Error::Config(e.to_string()))?;
        std::fs::write(target_dir.join("resources.json"), &resources_bytes)?;

        // Per-target blobs: the run path's artifacts, built exactly as
        // `fluxor build <graph>` would (§10.3 — it builds them anyway).
        crate::build_one(&graph_path, Some(&target_dir.join("config.bin")), verbose)?;

        // Module refs pin the REAL built artifacts: read each .fmod from the
        // silicon modules dir build_one just ensured. Linux-family graphs run
        // bcm2712-built modules under the host runtime.
        let modules_dir = project_root.join("target/fluxor/bcm2712/modules");
        let mut module_refs = Vec::new();
        for ty in &facts.module_types {
            // fixtures/ modules are test instruments — never part of a
            // shipped workload bundle (standards/fluxor-modules.md §0.1).
            if project_root
                .join("modules/fixtures")
                .join(ty.as_str())
                .join("manifest.toml")
                .is_file()
            {
                return Err(Error::Config(format!(
                    "module '{ty}' is a fixtures-tier test instrument and cannot be \
                     referenced by a workload bundle"
                )));
            }
            let fmod = modules_dir.join(format!("{ty}.fmod"));
            let bytes = std::fs::read(&fmod).map_err(|e| {
                Error::Config(format!(
                    "module '{ty}' has no built artifact at {} ({e}); run `fluxor modules build --target bcm2712`",
                    fmod.display()
                ))
            })?;
            module_refs.push(ModuleRef {
                name: ty.clone(),
                digest: sha256_ref(&bytes),
            });
        }

        let mut export_bindings = BTreeMap::new();
        for e in &src.exports {
            export_bindings.insert(e.name.clone(), e.binding.clone());
        }

        implementations.push(Implementation {
            target: Target {
                family: "linux".into(),
                architecture: "aarch64".into(),
                fluxor_abi: 1,
            },
            graph: DigestRef {
                digest: sha256_ref(&graph_bytes),
            },
            modules: module_refs,
            resources: DigestRef {
                digest: sha256_ref(&resources_bytes),
            },
            external_nodes: Vec::new(),
            bindings: Bindings {
                imports: BTreeMap::new(),
                exports: export_bindings,
                health: BTreeMap::new(), // filled below (shared contract names)
            },
        });
        emitted_targets.push((imp.target.clone(), target_dir));
    }

    if implementations.is_empty() {
        return Err(Error::Config(
            "no implementation emitted (only target 'linux' is supported)".into(),
        ));
    }

    // Health: contract signal names are workload-scoped; bindings default to
    // the first graph module's ready/progress signals.
    let anchor = first_module_for_health.unwrap_or_else(|| src.workload.name.clone());
    let ready_sig = format!("{}.ready", src.workload.name);
    let live_sig = format!("{}.progress", src.workload.name);
    let ready_target = src
        .health
        .readiness
        .clone()
        .unwrap_or_else(|| format!("{anchor}.ready"));
    let live_target = src
        .health
        .liveness
        .clone()
        .unwrap_or_else(|| format!("{anchor}.progress"));
    for imp in &mut implementations {
        imp.bindings
            .health
            .insert(ready_sig.clone(), ready_target.clone());
        imp.bindings
            .health
            .insert(live_sig.clone(), live_target.clone());
    }

    let manifest = WorkloadManifest {
        schema_version: 1,
        name: src.workload.name.clone(),
        version: src.workload.version.clone(),
        contract: Contract {
            imports: Vec::new(),
            exports,
            // The contract's config identity: the digest of the SOURCE
            // manifest itself — the one document the configuration derives
            // from. (Consumers verify graph/resources digests; this one is
            // an identity, not an artifact pin.)
            config_schema: DigestRef {
                digest: sha256_ref(text.as_bytes()),
            },
            health: Health {
                readiness: ready_sig,
                liveness: live_sig,
            },
            update: UpdatePolicy {
                drain_timeout_ms: 5000,
                state_policy: "discard".into(),
            },
        },
        implementations,
    };

    // The emitted manifest MUST pass the same validation the agent applies
    // at commit — a bundle we emit but the agent would refuse is a bug here,
    // caught now.
    let report = validate(&manifest);
    if !report.is_ok() {
        return Err(Error::Config(format!(
            "emitted workload.json fails validation: {}",
            report.errors.join("; ")
        )));
    }

    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest).map_err(|e| Error::Config(e.to_string()))?;
    std::fs::create_dir_all(&bundle_root)?;
    std::fs::write(bundle_root.join("workload.json"), &manifest_bytes)?;
    // Duplicate into each target dir: the agent consumes a FLAT triple
    // (workload.json beside graph.yaml + resources.json), unchanged (§10.4).
    for (_, dir) in &emitted_targets {
        std::fs::write(dir.join("workload.json"), &manifest_bytes)?;
    }

    println!(
        "Emitted workload bundle '{}' v{} ({} target(s)) -> {}",
        manifest.name,
        manifest.version,
        emitted_targets.len(),
        bundle_root.display()
    );
    Ok(bundle_root)
}

// ============================================================================
// Resolve + run
// ============================================================================

/// Is `path` something the bundle runner understands? A workload source
/// manifest — a `.toml` carrying a `[workload]` table — or a bundle root / target
/// subdir (a dir carrying `workload.json`). Any other `.toml` (stack profiles,
/// module manifests, board configs, `Cargo.toml`) is not a workload manifest and
/// is left to the regular run dispatch, as are graph YAMLs and scenario files.
pub fn is_bundle_path(path: &Path) -> bool {
    if path.is_dir() {
        return path.join("workload.json").is_file();
    }
    is_source_manifest(path)
}

/// Is `path` a workload source manifest — a `.toml` carrying a `[workload]`
/// table? The table is the marker that distinguishes a workload manifest from
/// any other `.toml` (stack profiles, module manifests, board configs,
/// `Cargo.toml`), which must fall through to normal handling.
pub fn is_source_manifest(path: &Path) -> bool {
    path.extension().is_some_and(|e| e == "toml")
        && std::fs::read_to_string(path)
            .ok()
            // `toml::Table`'s FromStr parses a DOCUMENT; `toml::Value`'s
            // parses a single value expression and rejects every real
            // manifest — the sniff must use the document parse.
            .and_then(|t| t.parse::<toml::Table>().ok())
            .is_some_and(|v| v.get("workload").is_some_and(toml::Value::is_table))
}

/// `fluxor run <bundle>` (rfc_system_services.md §10.4): resolve a target
/// from `workload.json` with the SAME resolver the agent uses
/// (`select_implementation`), verify the pinned artifacts, and exec the
/// implementation's built blobs. Accepts a source manifest (emits first —
/// build-and-run), a bundle root, or a target subdir directly.
pub fn run_bundle(path: &Path, verbose: bool) -> Result<()> {
    run_bundle_with_args(path, &[], verbose)
}

/// `run_bundle` with app argv appended after `--` — the `fluxor exec` data
/// path (rfc_cli_execution.md §5.1): the runtime's own parser stops at `--`
/// and the `cli_in` built-in reads the tail from the process argv.
pub fn run_bundle_with_args(path: &Path, app_args: &[String], verbose: bool) -> Result<()> {
    use fluxor_tools::workload::{parse_manifest, select_implementation};

    // A source manifest builds first; running is then resolving the fresh
    // bundle it emitted.
    let dir = if path.extension().is_some_and(|e| e == "toml") {
        emit_bundle(path, verbose)?
    } else {
        path.to_path_buf()
    };

    let manifest_text = std::fs::read_to_string(dir.join("workload.json"))
        .map_err(|e| Error::Config(format!("{}: workload.json: {e}", dir.display())))?;
    let manifest = parse_manifest(&manifest_text).map_err(Error::Config)?;
    let imp = select_implementation(&manifest, "linux", "aarch64", 1).ok_or_else(|| {
        Error::Config(format!(
            "bundle '{}' has no linux/aarch64/abi-1 implementation to run",
            manifest.name
        ))
    })?;

    // The target subdir: the dir itself when given directly (it carries its
    // own workload.json copy), else `<root>/<family>`.
    let target_dir = if dir.join("config.bin").is_file() {
        dir.clone()
    } else {
        dir.join(&imp.target.family)
    };

    // Same artifact discipline as the agent (§10.4: different consumers, one
    // trust model): the graph and resources bytes must hash to the digests
    // the manifest pins.
    for (file, pinned) in [
        ("graph.yaml", &imp.graph.digest),
        ("resources.json", &imp.resources.digest),
    ] {
        let bytes = std::fs::read(target_dir.join(file))
            .map_err(|e| Error::Config(format!("{}: {file}: {e}", target_dir.display())))?;
        let actual = sha256_ref(&bytes);
        if &actual != pinned {
            return Err(Error::Config(format!(
                "bundle {file}: digest mismatch (manifest pins {pinned}, artifact is {actual})"
            )));
        }
    }

    let config_bin = target_dir.join("config.bin");
    let modules_bin = target_dir.join("modules.bin");
    for f in [&config_bin, &modules_bin] {
        if !f.is_file() {
            return Err(Error::Config(format!(
                "{} missing — rebuild the bundle (`fluxor build <app.fluxor.toml>`)",
                f.display()
            )));
        }
    }
    let linux_bin = crate::project::root_for_config(&dir)
        .join("target/aarch64-unknown-linux-gnu/release/fluxor-linux");
    if !linux_bin.exists() {
        return Err(Error::Config(format!(
            "Linux binary not found at {}. Run 'make build' first.",
            linux_bin.display()
        )));
    }

    eprintln!(
        "Running bundle '{}' v{} ({}): {} --config {} --modules {}",
        manifest.name,
        manifest.version,
        imp.target.family,
        linux_bin.display(),
        config_bin.display(),
        modules_bin.display()
    );
    let mut cmd = std::process::Command::new(&linux_bin);
    cmd.arg("--config")
        .arg(&config_bin)
        .arg("--modules")
        .arg(&modules_bin);
    if !app_args.is_empty() {
        cmd.arg("--").args(app_args);
    }
    // Die-with-parent (see `tie_to_parent`): a killed/timeouted `fluxor exec`
    // must not orphan a runtime that never exits on its own.
    let status = crate::tie_to_parent(&mut cmd).status()?;
    // A CLI bundle's exit code IS the deliverable (rfc_cli_execution.md §6):
    // propagate it verbatim rather than wrapping it in a tool error.
    std::process::exit(status.code().unwrap_or(1));
}

// ============================================================================
// Applet registry + exec (rfc_cli_execution.md §5)
// ============================================================================

/// The on-disk applet catalogue: `[applets]` name → absolute bundle path.
/// Deliberately separate from the `cli` stack — the stack is the harness,
/// this is the catalogue (§5.2). Same root discipline as the OCI store:
/// `$FLUXOR_APPLETS` override, else `$XDG_DATA_HOME/fluxor/applets.toml`,
/// else `~/.local/share/fluxor/applets.toml`.
fn registry_path() -> PathBuf {
    if let Some(p) = std::env::var_os("FLUXOR_APPLETS").filter(|v| !v.is_empty()) {
        return PathBuf::from(p);
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(xdg).join("fluxor").join("applets.toml");
    }
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(home).join(".local/share/fluxor/applets.toml");
    }
    PathBuf::from("applets.toml")
}

fn load_registry() -> Result<BTreeMap<String, PathBuf>> {
    let path = registry_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(BTreeMap::new()); // absent → empty catalogue
    };
    let doc: toml::Value = toml::from_str(&text)
        .map_err(|e| Error::Config(format!("applet registry {}: {e}", path.display())))?;
    let mut out = BTreeMap::new();
    if let Some(t) = doc.get("applets").and_then(|v| v.as_table()) {
        for (k, v) in t {
            if let Some(p) = v.as_str() {
                out.insert(k.clone(), PathBuf::from(p));
            }
        }
    }
    Ok(out)
}

fn save_registry(reg: &BTreeMap<String, PathBuf>) -> Result<()> {
    let path = registry_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut text =
        String::from("# fluxor applet registry (rfc_cli_execution.md §5.2)\n[applets]\n");
    for (k, v) in reg {
        text.push_str(&format!("{} = {:?}\n", k, v.display().to_string()));
    }
    std::fs::write(&path, text)?;
    Ok(())
}

/// `fluxor install <bundle>`: register an applet name → cached bundle path.
/// Accepts a source manifest (emits first) or a bundle dir; the name defaults
/// to the bundle's `workload.json` name. `--link <dir>` drops a busybox
/// symlink `<dir>/<name> → fluxor` so `<name> args…` dispatches via argv[0].
pub fn install_applet(
    bundle: &Path,
    name: Option<&str>,
    link: Option<&Path>,
    verbose: bool,
) -> Result<()> {
    let dir = if bundle.extension().is_some_and(|e| e == "toml") {
        emit_bundle(bundle, verbose)?
    } else if !bundle.exists() {
        // Not a path: a store reference (P10 — sibling CLIs are
        // artifacts, not checkouts). Resolve the workload bundle from
        // the OCI store and materialise it into the applet cache.
        materialize_bundle_from_store(&bundle.to_string_lossy(), verbose)?
    } else {
        bundle.to_path_buf()
    };
    let dir = dir
        .canonicalize()
        .map_err(|e| Error::Config(format!("{}: {e}", dir.display())))?;
    let manifest_text = std::fs::read_to_string(dir.join("workload.json"))
        .map_err(|e| Error::Config(format!("{}: workload.json: {e}", dir.display())))?;
    let manifest = fluxor_tools::workload::parse_manifest(&manifest_text).map_err(Error::Config)?;
    let applet = name.unwrap_or(&manifest.name).to_string();

    let mut reg = load_registry()?;
    reg.insert(applet.clone(), dir.clone());
    save_registry(&reg)?;
    println!("installed applet '{applet}' -> {}", dir.display());

    if let Some(bin_dir) = link {
        std::fs::create_dir_all(bin_dir)?;
        let exe =
            std::env::current_exe().map_err(|e| Error::Config(format!("current_exe: {e}")))?;
        let dest = bin_dir.join(&applet);
        let _ = std::fs::remove_file(&dest);
        std::os::unix::fs::symlink(&exe, &dest)
            .map_err(|e| Error::Config(format!("symlink {}: {e}", dest.display())))?;
        println!("linked {} -> {}", dest.display(), exe.display());
    }
    Ok(())
}

/// `fluxor exec <name> [-- args…]` (§5.1): registry exact match → project
/// bundle (`target/fluxor/<name>/`) → error listing known applets. No
/// compilation on the hot path: the cached bundle execs as-is.
pub fn exec_applet(name: &str, args: &[String], verbose: bool) -> Result<()> {
    let reg = load_registry()?;
    if let Some(dir) = reg.get(name) {
        if dir.join("workload.json").is_file() {
            return run_bundle_with_args(dir, args, verbose);
        }
        return Err(Error::Config(format!(
            "applet '{name}' points at {} but no bundle is there — re-run `fluxor install`",
            dir.display()
        )));
    }
    // Project-local fallback: a bundle built in this tree.
    let project = crate::project::root_for_config(Path::new("."))
        .join("target/fluxor")
        .join(name);
    if project.join("workload.json").is_file() {
        return run_bundle_with_args(&project, args, verbose);
    }
    let known: Vec<&str> = reg.keys().map(String::as_str).collect();
    Err(Error::Config(format!(
        "unknown applet '{name}' (known: {})",
        if known.is_empty() {
            "none installed".to_string()
        } else {
            known.join(", ")
        }
    )))
}

/// Resolve a workload-bundle artifact from the local OCI store and
/// materialise it as a runnable bundle dir under the applet cache
/// (`$XDG_DATA_HOME/fluxor/applets/<name>/`). The pinned docs
/// (workload.json / graph.yaml / resources.json) come from the store
/// verbatim — their digests are what the manifest pins — and the
/// per-target blobs (config.bin / modules.bin) are synthesized from
/// the graph exactly as `fluxor build` would produce them.
fn materialize_bundle_from_store(reference: &str, verbose: bool) -> Result<PathBuf> {
    use fluxor_tools::oci_store::{
        self, OciStore, MT_FLUXOR_GRAPH, MT_FLUXOR_RESOURCES, MT_FLUXOR_WORKLOAD,
    };
    let store = OciStore::open(oci_store::store_root().map_err(|e| Error::Config(e.to_string()))?)
        .map_err(|e| Error::Config(e.to_string()))?;
    let full_ref = if reference.contains(':') || reference.starts_with("sha256:") {
        reference.to_string()
    } else {
        format!("{reference}:latest")
    };
    let desc = store.resolve(&full_ref).map_err(|e| {
        Error::Config(format!(
            "'{reference}' is neither a path nor a store bundle ({e}) — \
             publish it first (`fluxor publish bundle <dir>`)"
        ))
    })?;
    let manifest = store
        .read_manifest(&desc)
        .map_err(|e| Error::Config(e.to_string()))?;
    let layer = |mt: &str| -> Result<Vec<u8>> {
        let l = manifest
            .layers
            .iter()
            .find(|l| l.media_type == mt)
            .ok_or_else(|| Error::Config(format!("store artifact {full_ref} has no {mt} layer")))?;
        store
            .read_blob(&l.digest)
            .map_err(|e| Error::Config(e.to_string()))
    };
    let workload_json = layer(MT_FLUXOR_WORKLOAD)?;
    let graph_yaml = layer(MT_FLUXOR_GRAPH)?;
    let resources_json = layer(MT_FLUXOR_RESOURCES)?;

    let parsed = fluxor_tools::workload::parse_manifest(
        std::str::from_utf8(&workload_json)
            .map_err(|e| Error::Config(format!("workload.json not UTF-8: {e}")))?,
    )
    .map_err(Error::Config)?;

    let cache_root = match std::env::var_os("XDG_DATA_HOME") {
        Some(x) if !x.is_empty() => PathBuf::from(x),
        _ => PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share"),
    }
    .join("fluxor/applets")
    .join(&parsed.name);
    std::fs::create_dir_all(&cache_root)?;
    std::fs::write(cache_root.join("workload.json"), &workload_json)?;

    for imp in &parsed.implementations {
        let target_dir = cache_root.join(&imp.target.family);
        std::fs::create_dir_all(&target_dir)?;
        std::fs::write(target_dir.join("workload.json"), &workload_json)?;
        std::fs::write(target_dir.join("graph.yaml"), &graph_yaml)?;
        std::fs::write(target_dir.join("resources.json"), &resources_json)?;
        // Blobs: same synthesis as `fluxor build <graph>` (§10.3).
        crate::build_one(
            &target_dir.join("graph.yaml"),
            Some(&target_dir.join("config.bin")),
            verbose,
        )?;
    }
    if verbose {
        println!(
            "materialised store bundle {full_ref} -> {}",
            cache_root.display()
        );
    }
    Ok(cache_root)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"
[workload]
name = "dns"
version = "1.0.0"
role = "service"

[[implementation]]
target = "linux"
graph = "linux.yaml"

[[export]]
name = "dns"
protocol = "udp"
port = 15353
binding = "dns.net_out"

[resources]
state_bytes = 131072
buffer_bytes = 32768
"#;

    #[test]
    fn source_manifest_parses_thin_fields_only() {
        let m = parse_source_manifest(MANIFEST).unwrap();
        assert_eq!(m.workload.name, "dns");
        assert_eq!(m.workload.role, "service");
        assert_eq!(m.implementations.len(), 1);
        assert_eq!(m.implementations[0].graph, "linux.yaml");
        assert_eq!(m.exports[0].port, 15353);
        assert_eq!(m.exports[0].binding, "dns.net_out");
        assert_eq!(m.resources.state_bytes, Some(131072));
    }

    #[test]
    fn role_is_service_or_cli_and_kind_is_not_accepted() {
        // `role`, not `kind` (§10.2: `kind` means scenario in fluxor).
        let bad = MANIFEST.replace("role = \"service\"", "role = \"daemon\"");
        assert!(parse_source_manifest(&bad).is_err());
        let cli = MANIFEST.replace("role = \"service\"", "role = \"cli\"");
        assert_eq!(parse_source_manifest(&cli).unwrap().workload.role, "cli");
    }

    #[test]
    fn graph_facts_count_own_modules_and_wiring_only() {
        let dir = std::env::temp_dir().join(format!("fluxor-wsrc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let g = dir.join("g.yaml");
        std::fs::write(
            &g,
            "target: linux\nplatform:\n  net: {}\nmodules:\n  - name: dns\n    port: 15353\nwiring:\n  - from: linux_net.net_out\n    to: dns.net_in\n  - from: dns.net_out\n    to: linux_net.net_in\n",
        )
        .unwrap();
        let f = graph_facts(&g).unwrap();
        // The platform stack's linux_net is substrate, not footprint.
        assert_eq!(f.modules, 1);
        assert_eq!(f.module_types, vec!["dns".to_string()]);
        assert_eq!(f.edges, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
