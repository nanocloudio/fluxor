//! Workload bundle source, emission and launch.
//!
//! A thin TOML source manifest — non-derivable fields only — from which
//! `fluxor build <app.fluxor.toml>` emits the bundle format the agent
//! consumes (`workload.json` + `resources.json` + `graph.yaml`), plus the
//! per-target `config.bin`/`modules.bin` the run path consumes. Emitting a
//! bundle calls the same `build_one` a plain `fluxor build <graph>` calls,
//! so a bundle's blobs are byte-for-byte what building the graph directly
//! produces.
//!
//! Bundle-layout rule: the source manifest REFERENCES a whole per-target
//! graph file, one per implementation. It never merges, patches or
//! synthesises graph fragments — a target's graph is exactly the file
//! checked in for it, so what shipped can be read as-is.
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
//! directly consumable by `fluxor agent commit --bundle`, which expects the
//! flat triple in one directory. The bundle pins each artifact by sha256 in
//! `workload.json`, and every consumer re-hashes the files it reads and
//! refuses a mismatch.
//!
//! Only `linux` implementations are emitted; other implementations are
//! skipped with a notice.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Error, Result};
use fluxor_tools::service_params::{self, ParamSpec, ParamValue};
use fluxor_tools::workload::{
    validate, Bindings, Contract, DigestRef, Export, Health, Implementation, ModuleRef,
    ResourceProfileDoc, Target, UpdatePolicy, WorkloadManifest,
};

// ============================================================================
// Source manifest (TOML)
// ============================================================================

/// `[workload]` — identity + role. `service` implementations carry the
/// health/update contract and the lease/drain machinery; `cli` carries the
/// stdio/exit surface (argv after `--`, stdout/stderr, exit code). `role`
/// accepts only `service` or `cli`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadTable {
    name: String,
    version: String,
    #[serde(default = "default_role")]
    role: String,
    /// `store_dir = "state"` — where this workload's control-plane store
    /// lives, relative to the installed bundle unless absolute. Carried
    /// into `workload.json` and set for the runtime at launch, so an
    /// applet's storage does not depend on the environment its caller
    /// exported.
    #[serde(default)]
    store_dir: Option<String>,
}

fn default_role() -> String {
    "service".to_string()
}

/// `[[implementation]]` — one per-target graph file, referenced whole and
/// never merged with anything.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImplementationTable {
    target: String,
    graph: String,
}

/// `[[export]]` — a declared endpoint plus its graph binding (the binding is
/// not derivable from the graph; `validate()` requires one per export).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportTable {
    name: String,
    protocol: String,
    port: u16,
    binding: String,
}

/// `[resources]` — the non-derivable footprint overrides. Module and edge
/// counts are derived from the graph; these are capacity declarations.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
struct HealthTable {
    readiness: Option<String>,
    liveness: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// `[params.<name>]` — a service's run-time parameter schema
    /// ([`fluxor_tools::service_params`]); parsed and checked by
    /// [`parse_source_manifest`].
    #[serde(default)]
    params: toml::Table,
}

/// A parsed source manifest and its checked parameter schema.
struct Source {
    manifest: SourceManifest,
    params: BTreeMap<String, ParamSpec>,
}

fn parse_source_manifest(text: &str) -> Result<Source> {
    let m: SourceManifest =
        toml::from_str(text).map_err(|e| Error::Config(format!("source manifest: {e}")))?;
    if !fluxor_tools::workload::is_workload_name(&m.workload.name) {
        return Err(Error::Config(format!(
            "workload.name '{}' is not a workload name (ASCII letters, digits, '.', '_' or '-', \
             starting with a letter or digit, at most 64 bytes)",
            m.workload.name
        )));
    }
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
    if m.workload.role == "cli" && !m.params.is_empty() {
        return Err(Error::Config(
            "a role = \"cli\" applet declares [params]; an applet takes argv, and parameters \
             belong to services"
                .into(),
        ));
    }
    let params = service_params::parse_source_params(&m.params).map_err(Error::Config)?;
    let errors = service_params::validate_schema(&params);
    if !errors.is_empty() {
        return Err(Error::Config(format!("[params]: {}", errors.join("; "))));
    }
    Ok(Source {
        manifest: m,
        params,
    })
}

// ============================================================================
// Graph facts (derived, never declared)
// ============================================================================

/// The graph facts a bundle derives rather than declares: module types in
/// declaration order and the module/edge counts that seed the resource
/// profile. Platform-stack modules are NOT counted — they are node substrate,
/// not workload footprint.
struct GraphFacts {
    module_types: Vec<String>,
    modules: u16,
    edges: u16,
}

/// Sum the resident state the graph's modules declare in their packed
/// manifests. Returns `(bytes, modules_without_a_figure)`.
///
/// The per-module figure is recorded at pack time from the SDK's
/// `declare_module_state_bytes!` static, in 64-byte units, so it is a
/// measurement of the built artefact rather than an author's estimate. A module
/// with no figure contributes nothing and is COUNTED, so a partial sum is never
/// presented as a total.
fn sum_module_state_bytes(modules_dir: &Path, module_types: &[String]) -> (u64, usize) {
    let mut total = 0u64;
    let mut unknown = 0usize;
    for ty in module_types {
        let fmod = modules_dir.join(format!("{ty}.fmod"));
        match crate::modules::ModuleInfo::from_file(&fmod) {
            Ok(info) if info.manifest.state_bytes_64 > 0 => {
                total += info.manifest.state_bytes_64 as u64 * 64;
            }
            // Unreadable counts as unknown, not as zero: the module loop below
            // reports a missing artefact with a better message than this would.
            _ => unknown += 1,
        }
    }
    (total, unknown)
}

/// The facts of a graph template, read after the environment pass the build
/// applies to it.
fn graph_facts(template: &str) -> Result<GraphFacts> {
    let doc = service_params::parse_graph(template).map_err(Error::Config)?;
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

/// The directory holding the `.fmod` artefacts a linux run of this project
/// loads, by the shared module-root resolution (`explicit` is
/// `--module-root`).
fn linux_module_dir(project_root: &Path, explicit: Option<&Path>) -> Result<PathBuf> {
    crate::modules_build::module_root(
        explicit,
        project_root,
        &project_root.join("target/fluxor"),
        "linux",
    )
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
pub fn emit_bundle(
    manifest_path: &Path,
    module_root: Option<&Path>,
    verbose: bool,
) -> Result<PathBuf> {
    let text = std::fs::read_to_string(manifest_path)
        .map_err(|e| Error::Config(format!("read {}: {e}", manifest_path.display())))?;
    let Source {
        manifest: src,
        params,
    } = parse_source_manifest(&text)?;
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
    let mut referenced: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

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
        // graph.yaml: copied verbatim — its bytes are the digest the agent
        // verifies at commit. For a service with parameters it is the
        // template as written; a run renders it.
        let graph_bytes = std::fs::read(&graph_path)
            .map_err(|e| Error::Config(format!("read graph {}: {e}", graph_path.display())))?;
        let template = String::from_utf8(graph_bytes.clone()).map_err(|e| {
            Error::Config(format!("graph {} is not UTF-8: {e}", graph_path.display()))
        })?;
        let facts = graph_facts(&template)
            .map_err(|e| Error::Config(format!("{}: {e}", graph_path.display())))?;
        if first_module_for_health.is_none() {
            first_module_for_health = facts.module_types.first().cloned();
        }

        let target_dir = bundle_root.join(&imp.target);
        std::fs::create_dir_all(&target_dir)?;

        std::fs::write(target_dir.join("graph.yaml"), &graph_bytes)?;
        let names = service_params::parse_graph(&template)
            .and_then(|doc| service_params::placeholders(&doc))
            .map_err(|e| Error::Config(format!("{}: {e}", graph_path.display())))?;
        referenced.extend(names);

        // State arena demand, derived from the modules the graph names: each
        // `.fmod` records its own resident state (`declare_module_state_bytes!`,
        // read at pack time), so the sum is the footprint the kernel will
        // carve and the composer charges against `NodeCapacity.state_bytes`.
        // An explicit `[resources] state_bytes` overrides the measurement, for
        // a workload that reserves headroom for a module that grows under
        // load. Modules that publish no figure contribute 0 and are counted,
        // so a partial sum is visible as such.
        let (derived_state, unknown_state_modules) = sum_module_state_bytes(
            &linux_module_dir(&project_root, module_root)?,
            &facts.module_types,
        );
        if unknown_state_modules > 0 {
            eprintln!(
                "  note: {unknown_state_modules} of {} module(s) do not publish a state size; \
                 the derived state_bytes ({derived_state}) is a partial sum",
                facts.module_types.len()
            );
        }

        // resources.json: counts derived from the graph, capacities from the
        // source manifest's [resources] where it states them.
        let resources = ResourceProfileDoc {
            modules: facts.modules,
            edges: facts.edges,
            state_bytes: src
                .resources
                .state_bytes
                .unwrap_or_else(|| derived_state.min(u32::MAX as u64) as u32),
            buffer_bytes: src.resources.buffer_bytes.unwrap_or(16384),
            endpoints: src.resources.endpoints.unwrap_or(exports.len() as u16),
            domains: src.resources.domains.unwrap_or(1),
            state_schemas: BTreeMap::new(),
        };
        let resources_bytes =
            serde_json::to_vec_pretty(&resources).map_err(|e| Error::Config(e.to_string()))?;
        std::fs::write(target_dir.join("resources.json"), &resources_bytes)?;

        // Per-target blobs: the run path's artifacts, built by the same
        // `build_one` a plain `fluxor build <graph>` calls, so a bundle's
        // blobs are identical to building the graph on its own.
        //
        // A graph with parameters has no blobs of its own: what it builds
        // depends on the values a run supplies. It is still built here,
        // rendered with its defaults and examples, so a template the
        // builder refuses never becomes a bundle, and any blobs an earlier
        // emit left behind are removed so nothing can launch them.
        if params.is_empty() {
            crate::build_one_from(
                &graph_path,
                Some(&target_dir.join("config.bin")),
                module_root,
                verbose,
            )?;
        } else {
            for stale in ["config.bin", "modules.bin"] {
                let _ = std::fs::remove_file(target_dir.join(stale));
            }
            let check_dir = project_root.join("target/fluxor/run").join(format!(
                "{}-emit-{}",
                src.workload.name,
                std::process::id()
            ));
            let rendered = service_params::render_graph_text(
                &template,
                &service_params::check_values(&params),
            )
            .map_err(|e| Error::Config(format!("{}: {e}", graph_path.display())))?;
            std::fs::create_dir_all(&check_dir)?;
            let check_graph = check_dir.join("graph.yaml");
            std::fs::write(&check_graph, rendered)?;
            let built = crate::build_one_from(
                &check_graph,
                Some(&check_dir.join("config.bin")),
                module_root,
                verbose,
            );
            let _ = std::fs::remove_dir_all(&check_dir);
            built.map_err(|e| {
                Error::Config(format!(
                    "{} rendered with its defaults and examples does not build: {e}",
                    graph_path.display()
                ))
            })?;
        }

        // Module refs pin the built artifacts: each .fmod is read from the
        // modules directory `build_one` loaded them from.
        let modules_dir = linux_module_dir(&project_root, module_root)?;
        let mut module_refs = Vec::new();
        for ty in &facts.module_types {
            // fixtures/ modules are test instruments, never part of a
            // shipped workload bundle.
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
                    "module '{ty}' has no built artifact at {} ({e}); run `fluxor modules build --target linux`",
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
    let reference_errors = service_params::check_references(&params, &referenced);
    if !reference_errors.is_empty() {
        return Err(Error::Config(reference_errors.join("; ")));
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
        role: src.workload.role.clone(),
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
        params,
        store_dir: src.workload.store_dir.clone(),
    };

    // The emitted manifest must pass the same validation the agent applies
    // at commit, so a bundle the agent would refuse fails here.
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
    // (workload.json beside graph.yaml + resources.json) from one directory.
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

/// The parameter values one `fluxor run` was given: `--param name=value`
/// flags and an optional `--params <file.toml>`.
#[derive(Debug, Default)]
pub struct RunParams {
    pub flags: Vec<String>,
    pub file: Option<PathBuf>,
    /// `--module-root`: where a source manifest's build reads `.fmod`s from.
    /// A built bundle's own pinned `modules/` always wins over it.
    pub module_root: Option<PathBuf>,
}

impl RunParams {
    pub fn is_empty(&self) -> bool {
        self.flags.is_empty() && self.file.is_none()
    }

    /// Check the values against `schema` and fill defaults. Every refusal is
    /// reported before anything is built or started.
    fn resolve(
        &self,
        bundle: &str,
        schema: &BTreeMap<String, ParamSpec>,
    ) -> Result<BTreeMap<String, ParamValue>> {
        let file = match &self.file {
            Some(path) => service_params::read_values_file(path).map_err(Error::Config)?,
            None => BTreeMap::new(),
        };
        let flags = self
            .flags
            .iter()
            .map(|raw| service_params::parse_flag(raw))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Error::Config)?;
        service_params::resolve_values(schema, &file, &flags)
            .map_err(|e| Error::Config(format!("bundle '{bundle}' refuses this run:\n{e}")))
    }
}

/// `fluxor run <bundle>`: run a workload bundle, with the operator's
/// `--ca` anchors appended to its client-mode tls/quic instances for this
/// run when given. `<bundle>` is a source manifest, a bundle directory, or
/// the name of a bundle `fluxor.lock` pins (materialised on first use, as
/// `fluxor sync` would). `fluxor exec` is the applet form, see
/// [`exec_applet`].
pub fn run_bundle(path: &Path, params: &RunParams, ca: Option<&Path>, verbose: bool) -> Result<()> {
    launch_bundle(path, &[], None, None, ca, params, verbose)
}

/// The directory of the bundle `fluxor.lock` pins under `name`, or a refusal
/// naming the bundles it does pin. `fluxor run <name>` comes here when
/// `<name>` is not a path.
pub fn pinned_bundle(name: &str) -> Result<PathBuf> {
    let project_root = crate::project::root_for_config(Path::new("."));
    if let Some(dir) = crate::store_sync::ensure_bundle(&project_root, name)
        .map_err(|e| Error::Config(e.to_string()))?
    {
        return Ok(dir);
    }
    let pinned = crate::store_sync::pinned_bundles(&project_root);
    Err(Error::Config(format!(
        "'{name}' is neither a path nor a bundle pinned in {} (pinned bundles: {}) — \
         `fluxor store pin <name>:<version>` pins one",
        fluxor_tools::store_resolve::lockfile_path(&project_root).display(),
        if pinned.is_empty() {
            "none".to_string()
        } else {
            pinned.join(", ")
        }
    )))
}

/// Read a source manifest's parameter schema without building anything, so
/// a run's values are refused before the emit that precedes it.
fn source_params(path: &Path) -> Result<(String, BTreeMap<String, ParamSpec>)> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
    let src = parse_source_manifest(&text)?;
    Ok((src.manifest.workload.name, src.params))
}

/// Write `config_bin` to `out` with the certificates of `pem` appended to
/// every client-mode tls/quic instance, and say what was widened. The
/// operator channel reads PEM only (the build-time `trust` parameter is
/// the one that also takes raw DER), and a block whose base64 does not
/// decode is skipped rather than failing the run. A file that yields no
/// certificate that way, more anchors than an instance holds or one over
/// the DER ceiling, and an instance whose table would overflow, are each
/// an error naming what failed; a graph with no client instance is
/// reported, not an error, since the flag then has nothing to widen.
pub fn write_widened_config(config_bin: &Path, out: &Path, pem: &Path) -> Result<()> {
    let text = std::fs::read_to_string(pem)
        .map_err(|e| Error::Config(format!("--ca: could not read '{}': {e}", pem.display())))?;
    let anchors = crate::trust_anchors::pem_certificates(&text);
    if anchors.is_empty() {
        return Err(Error::Config(format!(
            "--ca: no CERTIFICATE block decodes in '{}'",
            pem.display()
        )));
    }
    let blob = std::fs::read(config_bin)?;
    let (widened, report) = crate::trust_anchors::append_operator_anchors(&blob, &anchors)
        .map_err(|e| Error::Config(format!("--ca: {e}")))?;
    std::fs::write(out, &widened)?;
    if report.instances.is_empty() {
        eprintln!(
            "  --ca: {} anchor(s) in '{}', but the graph has no client-mode tls/quic instance to widen",
            anchors.len(),
            pem.display()
        );
    } else {
        eprintln!(
            "  --ca: {} anchor(s) from '{}' appended to {} client instance(s)",
            anchors.len(),
            pem.display(),
            report.instances.len()
        );
    }
    Ok(())
}

/// Where an applet's runtime binary lives relative to the project that
/// built its bundle. Recorded in the catalogue at install time so `exec`
/// runs the runtime the bundle was built against, wherever it is invoked.
const RUNTIME_RELATIVE: &str = "target/aarch64-unknown-linux-gnu/release/fluxor-linux";

/// A bundle's `workload.json`, parsed and held to the same validation the
/// agent applies at commit.
fn load_manifest(text: &str) -> Result<WorkloadManifest> {
    let manifest = fluxor_tools::workload::parse_manifest(text).map_err(Error::Config)?;
    let report = validate(&manifest);
    if !report.is_ok() {
        return Err(Error::Config(format!(
            "bundle '{}' failed validation: {}",
            manifest.name,
            report.errors.join("; ")
        )));
    }
    Ok(manifest)
}

/// The files one launch writes, in a directory only its owner can enter,
/// removed when the launch ends by any path.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn create(project_root: &Path, name: &str) -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let parent = project_root.join("target/fluxor/run");
        std::fs::create_dir_all(&parent)?;
        let dir = parent.join(format!("{name}-{}", std::process::id()));
        // A directory a crashed launch with this pid left behind.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        Ok(Scratch { dir })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Launch a bundle's linux implementation. `runtime` names the binary to
/// run, else the project's staged one. `applet` marks an applet run: the
/// runtime keeps its own log records out of the program's stderr — fd 2 is
/// the program's alone — and files them under the applet's name instead, so
/// a CLI bundle's output is only what the program itself wrote.
///
/// A bundle with built blobs and no parameters runs them as they are. A
/// bundle that declares parameters, or that carries no blobs (a pinned
/// bundle materialised by sync), is built for this run: its template is
/// rendered with the run's checked values and built against the bundle's
/// own pinned modules — `modules/` when the bundle carries them, else the
/// emitting project's built modules — each verified against the digest
/// `workload.json` pins.
fn launch_bundle(
    path: &Path,
    app_args: &[String],
    runtime: Option<&Path>,
    applet: Option<&str>,
    ca: Option<&Path>,
    params: &RunParams,
    verbose: bool,
) -> Result<()> {
    use fluxor_tools::workload::select_implementation;

    // A source manifest builds first; running is then resolving the fresh
    // bundle it emitted. Its values are checked before that build.
    let dir = if path.extension().is_some_and(|e| e == "toml") {
        let (name, schema) = source_params(path)?;
        params.resolve(&name, &schema)?;
        emit_bundle(path, params.module_root.as_deref(), verbose)?
    } else {
        path.to_path_buf()
    };

    // The documents: a flat dir (materialised bundle or target subdir)
    // carries them itself; an emitted root carries them per target.
    let manifest_dir = if dir.join("workload.json").is_file() {
        dir.clone()
    } else {
        dir.join("linux")
    };
    let manifest_text = std::fs::read_to_string(manifest_dir.join("workload.json"))
        .map_err(|e| Error::Config(format!("{}: workload.json: {e}", dir.display())))?;
    let manifest = load_manifest(&manifest_text)?;
    let imp = select_implementation(&manifest, "linux", "aarch64", 1).ok_or_else(|| {
        Error::Config(format!(
            "bundle '{}' has no linux/aarch64/abi-1 implementation to run",
            manifest.name
        ))
    })?;
    let values = params.resolve(&manifest.name, &manifest.params)?;

    // The target subdir: the dir itself when it carries the graph (a flat
    // dir), else `<root>/<family>`.
    let target_dir = if dir.join("graph.yaml").is_file() {
        dir.clone()
    } else {
        dir.join(&imp.target.family)
    };

    // Same artifact discipline as the agent — different consumers, one trust
    // model: the graph and resources bytes must hash to the digests the
    // manifest pins, and a mismatch refuses the run rather than warning.
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

    let project_root = crate::project::root_for_config(&dir);
    let prebuilt = manifest.params.is_empty() && target_dir.join("config.bin").is_file();
    // Scratch holds what this launch writes: a rendered graph and its blobs,
    // a widened config. Parameter values reach all of them, so the directory
    // is private and goes away on every exit path.
    let scratch = if !prebuilt || ca.is_some() {
        Some(Scratch::create(&project_root, &manifest.name)?)
    } else {
        None
    };
    let (mut config_bin, modules_bin) = match (prebuilt, &scratch) {
        (true, _) | (_, None) => (
            target_dir.join("config.bin"),
            target_dir.join("modules.bin"),
        ),
        (false, Some(scratch)) => {
            let run_dir = &scratch.dir;
            let module_root = if target_dir.join("modules").is_dir() {
                target_dir.join("modules")
            } else {
                linux_module_dir(&project_root, params.module_root.as_deref())?
            };
            for m in &imp.modules {
                let fmod = module_root.join(format!("{}.fmod", m.name));
                let bytes = std::fs::read(&fmod).map_err(|e| {
                    Error::Config(format!(
                        "bundle module '{}': {} ({e})",
                        m.name,
                        fmod.display()
                    ))
                })?;
                let actual = sha256_ref(&bytes);
                if actual != m.digest {
                    return Err(Error::Config(format!(
                        "bundle module '{}': {} is {actual} but the bundle pins {} — \
                         re-emit the bundle or re-sync it",
                        m.name,
                        fmod.display(),
                        m.digest
                    )));
                }
            }
            let template = std::fs::read_to_string(target_dir.join("graph.yaml"))?;
            let rendered =
                service_params::render_graph_text(&template, &values).map_err(Error::Config)?;
            // Only the pinned modules are verified above, so the rendered
            // graph may load nothing else: a value substituted into a module
            // name would otherwise pull in an unverified artefact.
            let facts = graph_facts(&rendered)?;
            if let Some(ty) = facts
                .module_types
                .iter()
                .find(|ty| !imp.modules.iter().any(|m| &m.name == *ty))
            {
                return Err(Error::Config(format!(
                    "the rendered graph loads module '{ty}', which bundle '{}' does not pin",
                    manifest.name
                )));
            }
            let graph = run_dir.join("graph.yaml");
            std::fs::write(&graph, rendered)?;
            crate::build_one_from(
                &graph,
                Some(&run_dir.join("config.bin")),
                Some(&module_root),
                verbose,
            )?;
            (run_dir.join("config.bin"), run_dir.join("modules.bin"))
        }
    };
    for f in [&config_bin, &modules_bin] {
        if !f.is_file() {
            return Err(Error::Config(format!(
                "{} missing — rebuild the bundle (`fluxor build <app.fluxor.toml>`)",
                f.display()
            )));
        }
    }
    // `--ca` widens a copy for this run only; the cached bundle is the
    // publisher's and stays byte-identical.
    if let (Some(pem), Some(scratch)) = (ca, &scratch) {
        let widened = scratch.dir.join("config.operator.bin");
        write_widened_config(&config_bin, &widened, pem)?;
        config_bin = widened;
    }
    // A recorded runtime is the one this bundle's modules were packed
    // against. If it has gone, say so and name it: running the bundle
    // against whatever binary the current directory resolves to would
    // substitute a different ABI, and the mismatch would surface as a
    // module refusing to load rather than as the missing binary.
    let linux_bin = match runtime {
        Some(r) if r.exists() => r.to_path_buf(),
        Some(r) => {
            return Err(Error::Config(format!(
                "the runtime this applet was installed against is gone: {}\n\
                 Reinstall it (`fluxor install`) so it records the \
                 runtime it should run on.",
                r.display()
            )));
        }
        None => project_root.join(RUNTIME_RELATIVE),
    };
    if !linux_bin.exists() {
        return Err(Error::Config(format!(
            "Linux binary not found at {}. Run 'make build' first.",
            linux_bin.display()
        )));
    }

    // A dev run says what it runs; an applet run is the program's, and says
    // nothing of its own unless asked (`-v`).
    if verbose || applet.is_none() {
        eprintln!(
            "Running bundle '{}' v{} ({}): {} --config {} --modules {}",
            manifest.name,
            manifest.version,
            imp.target.family,
            linux_bin.display(),
            config_bin.display(),
            modules_bin.display()
        );
    }
    let mut cmd = std::process::Command::new(&linux_bin);
    cmd.arg("--config")
        .arg(&config_bin)
        .arg("--modules")
        .arg(&modules_bin);
    if !app_args.is_empty() {
        cmd.arg("--").args(app_args);
    }
    if let Some(name) = applet {
        // Exec mode, as the runtime sees it: its log records go to the
        // applet's log directory, and fd 2 stays the program's. `-v` mirrors
        // every record to stderr as well.
        cmd.env("FLUXOR_EXEC", name);
        if verbose {
            cmd.env("FLUXOR_EXEC_LOG_STDERR", "1");
        }
    }
    // A workload that declares where its store lives gets that store,
    // whatever the caller exported, so the same applet run from two shells
    // reaches the same state. Relative paths resolve against the bundle, so
    // a bundle carries its own state with it.
    if let Some(store_dir) = manifest.store_dir.as_deref() {
        let resolved = {
            let p = Path::new(store_dir);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                dir.join(p)
            }
        };
        if verbose {
            eprintln!(
                "[exec] store dir from workload.json: {}",
                resolved.display()
            );
        }
        cmd.env("FLUXOR_STORE_DIR", &resolved);
    }
    // Die-with-parent (see `tie_to_parent`): a killed/timeouted `fluxor exec`
    // must not orphan a runtime that never exits on its own.
    let status = crate::tie_to_parent(&mut cmd).status();
    // `exit` below skips destructors.
    drop(scratch);
    let status = status?;
    // A CLI bundle's exit code IS the deliverable: propagate it verbatim
    // rather than wrapping a non-zero status in a tool error, so a shell
    // sees what the program returned.
    std::process::exit(status.code().unwrap_or(1));
}

// ============================================================================
// Applet registry + exec
// ============================================================================

/// The on-disk applet catalogue: `[applets]` name → absolute bundle path.
/// Deliberately separate from the `cli` stack: the stack is the harness a
/// CLI bundle is built against, the catalogue is the per-user record of
/// which built bundles are installed under which names. Installing or
/// removing an applet must never edit a stack. Same root discipline as the
/// OCI store:
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

/// One catalogue entry: the cached bundle, and the runtime it was built
/// against when the installing project had one staged.
#[derive(Clone, Debug)]
pub struct AppletEntry {
    pub bundle: PathBuf,
    pub runtime: Option<PathBuf>,
}

fn load_registry() -> Result<BTreeMap<String, AppletEntry>> {
    let path = registry_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(BTreeMap::new()); // absent → empty catalogue
    };
    let doc: toml::Value = toml::from_str(&text)
        .map_err(|e| Error::Config(format!("applet registry {}: {e}", path.display())))?;
    let mut out = BTreeMap::new();
    if let Some(t) = doc.get("applets").and_then(|v| v.as_table()) {
        for (k, v) in t {
            if let Some(bundle) = v.get("bundle").and_then(|b| b.as_str()) {
                out.insert(
                    k.clone(),
                    AppletEntry {
                        bundle: PathBuf::from(bundle),
                        runtime: v.get("runtime").and_then(|r| r.as_str()).map(PathBuf::from),
                    },
                );
            }
        }
    }
    Ok(out)
}

fn save_registry(reg: &BTreeMap<String, AppletEntry>) -> Result<()> {
    let path = registry_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut text = String::from("# fluxor applet registry: name -> installed bundle\n[applets]\n");
    for (k, v) in reg {
        match &v.runtime {
            Some(runtime) => text.push_str(&format!(
                "{} = {{ bundle = {:?}, runtime = {:?} }}\n",
                k,
                v.bundle.display().to_string(),
                runtime.display().to_string()
            )),
            None => text.push_str(&format!(
                "{} = {{ bundle = {:?} }}\n",
                k,
                v.bundle.display().to_string()
            )),
        }
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
        emit_bundle(bundle, None, verbose)?
    } else if !bundle.exists() {
        // Not a path: a store reference — a sibling CLI is consumed as a
        // published artifact, never as a checkout. Resolve the bundle from
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
    let manifest = load_manifest(&manifest_text)?;
    if !manifest.params.is_empty() {
        return Err(Error::Config(format!(
            "bundle '{}' is a service with parameters; an applet takes argv — run it with \
             `fluxor run {} --param name=value`",
            manifest.name, manifest.name
        )));
    }
    let applet = name.unwrap_or(&manifest.name).to_string();

    // The runtime the bundle was built against: the installing project's
    // staged binary, recorded so `exec` runs it from any directory. What the
    // lockfile names is materialised first: `fluxor update` rewrites the lock
    // without touching the tree, so the staged binary can otherwise be an
    // older kernel than the project is pinned to.
    let project_root = crate::project::root_for_config(&dir);
    if let Err(e) = crate::store_sync::ensure_synced(&project_root) {
        eprintln!("warning: could not sync the pinned artifacts before install: {e}");
    }
    let runtime = project_root.join(RUNTIME_RELATIVE);
    let runtime = runtime
        .exists()
        .then(|| runtime.canonicalize().unwrap_or(runtime));
    let mut reg = load_registry()?;
    reg.insert(
        applet.clone(),
        AppletEntry {
            bundle: dir.clone(),
            runtime,
        },
    );
    save_registry(&reg)?;
    println!("installed applet '{applet}' -> {}", dir.display());

    if let Some(bin_dir) = link {
        std::fs::create_dir_all(bin_dir)?;
        // Under the launcher this process is the CLI blob of the moment; the
        // link must outlive the epoch, so it points at the launcher itself.
        let exe = match std::env::var_os("FLUXOR_LAUNCHER")
            .map(PathBuf::from)
            .filter(|p| p.is_file())
        {
            Some(launcher) => launcher,
            None => {
                std::env::current_exe().map_err(|e| Error::Config(format!("current_exe: {e}")))?
            }
        };
        let dest = bin_dir.join(&applet);
        let _ = std::fs::remove_file(&dest);
        std::os::unix::fs::symlink(&exe, &dest)
            .map_err(|e| Error::Config(format!("symlink {}: {e}", dest.display())))?;
        println!("linked {} -> {}", dest.display(), exe.display());
    }
    Ok(())
}

/// `fluxor exec <name> [-- args…]`. Resolution order, first match wins:
/// an exact name in the applet registry, then a bundle built in this
/// project (`target/fluxor/<name>/`), else an error listing the applets
/// that ARE known. No compilation on the hot path: the cached bundle
/// execs as-is.
pub fn exec_applet(name: &str, args: &[String], ca: Option<&Path>, verbose: bool) -> Result<()> {
    let reg = load_registry()?;
    if let Some(entry) = reg.get(name) {
        if entry.bundle.join("workload.json").is_file() {
            return launch_bundle(
                &entry.bundle,
                args,
                entry.runtime.as_deref(),
                Some(name),
                ca,
                &RunParams::default(),
                verbose,
            );
        }
        return Err(Error::Config(format!(
            "applet '{name}' points at {} but no bundle is there — re-run `fluxor install`",
            entry.bundle.display()
        )));
    }
    // Project-local fallback: a bundle built in this tree.
    let project = crate::project::root_for_config(Path::new("."))
        .join("target/fluxor")
        .join(name);
    if project.join("workload.json").is_file() {
        return launch_bundle(
            &project,
            args,
            None,
            Some(name),
            ca,
            &RunParams::default(),
            verbose,
        );
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

/// Where the runtime files an applet's log records, kept out of the
/// program's own stderr: `$XDG_STATE_HOME/fluxor/exec/<name>/`, else
/// `~/.local/state/fluxor/exec/<name>/`. The runtime resolves it the same way.
fn exec_logs_dir(name: &str) -> PathBuf {
    let base = if let Some(xdg) = std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
        PathBuf::from(xdg)
    } else if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        PathBuf::from(home).join(".local/state")
    } else {
        PathBuf::from(".")
    };
    base.join("fluxor").join("exec").join(name)
}

/// `fluxor applet logs <name>`: the runtime's records from the applet's
/// latest run — or every kept run with `--all` — the last `tail` lines
/// of each. Runs are files named by their start time and pid.
pub fn applet_logs(name: &str, tail: usize, all: bool) -> Result<()> {
    let dir = exec_logs_dir(name);
    let mut runs: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|e| e == "log"))
                .collect()
        })
        .unwrap_or_default();
    runs.sort();
    if runs.is_empty() {
        return Err(Error::Config(format!(
            "no runs of applet '{name}' recorded under {}",
            dir.display()
        )));
    }
    let chosen: Vec<&PathBuf> = if all {
        runs.iter().collect()
    } else {
        runs.iter().rev().take(1).collect()
    };
    for (index, run) in chosen.iter().enumerate() {
        if all {
            if index > 0 {
                println!();
            }
            println!("== {}", run.display());
        }
        let text = std::fs::read_to_string(run)
            .map_err(|e| Error::Config(format!("{}: {e}", run.display())))?;
        let lines: Vec<&str> = text.lines().collect();
        let skip = if tail == 0 {
            0
        } else {
            lines.len().saturating_sub(tail)
        };
        for line in &lines[skip..] {
            println!("{line}");
        }
    }
    Ok(())
}

/// Resolve a workload-bundle artifact from the local OCI store and
/// materialise it as a runnable bundle dir under the applet cache
/// (`$XDG_DATA_HOME/fluxor/applets/<name>/`): the same digest-verified flat
/// layout `fluxor sync` writes (documents + the bundle's own `modules/`),
/// plus the run blobs (`config.bin` / `modules.bin`) built once from those
/// pinned modules, so `exec` runs without compiling anything.
fn materialize_bundle_from_store(reference: &str, verbose: bool) -> Result<PathBuf> {
    use fluxor_tools::oci_store::{self, OciStore};
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
    let artifact = fluxor_tools::store_resolve::artifact_from_descriptor(&desc)
        .map_err(|e| Error::Config(e.to_string()))?
        .filter(|a| a.kind == "bundle")
        .ok_or_else(|| Error::Config(format!("store artifact {full_ref} is not a bundle")))?;

    let cache_root = match std::env::var_os("XDG_DATA_HOME") {
        Some(x) if !x.is_empty() => PathBuf::from(x),
        _ => PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share"),
    }
    .join("fluxor/applets")
    .join(&artifact.name);
    crate::store_sync::materialize_bundle(&store, &artifact, &cache_root)
        .map_err(|e| Error::Config(e.to_string()))?;
    let manifest_text = std::fs::read_to_string(cache_root.join("workload.json"))?;
    let manifest = load_manifest(&manifest_text)?;
    if !manifest.params.is_empty() {
        return Err(Error::Config(format!(
            "bundle '{}' is a service with parameters; an applet takes argv — pin it with \
             `fluxor store pin {full_ref}` and run it with `fluxor run {} --param name=value`",
            manifest.name, manifest.name
        )));
    }
    crate::build_one_from(
        &cache_root.join("graph.yaml"),
        Some(&cache_root.join("config.bin")),
        Some(&cache_root.join("modules")),
        verbose,
    )?;
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
        let m = parse_source_manifest(MANIFEST).unwrap().manifest;
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
        // `role`, not `kind` — `kind` means scenario in fluxor — and the
        // only accepted roles are `service` and `cli`.
        let bad = MANIFEST.replace("role = \"service\"", "role = \"daemon\"");
        assert!(parse_source_manifest(&bad).is_err());
        let cli = MANIFEST.replace("role = \"service\"", "role = \"cli\"");
        assert_eq!(
            parse_source_manifest(&cli).unwrap().manifest.workload.role,
            "cli"
        );
    }

    #[test]
    fn params_are_parsed_checked_and_refused_on_an_applet() {
        let svc = format!(
            "{MANIFEST}\n[params.port]\ntype = \"integer\"\ndefault = 15353\nmax = 65535\n"
        );
        let src = parse_source_manifest(&svc).unwrap();
        assert_eq!(src.params["port"].default, Some(ParamValue::Integer(15353)));
        let cli = svc.replace("role = \"service\"", "role = \"cli\"");
        let e = parse_source_manifest(&cli).err().unwrap().to_string();
        assert!(e.contains("parameters belong to services"), "{e}");
        let bad = svc.replace("default = 15353", "default = 70000");
        let e = parse_source_manifest(&bad).err().unwrap().to_string();
        assert!(e.contains("above its maximum 65535"), "{e}");
    }

    #[test]
    fn unknown_keys_and_unsafe_names_are_refused() {
        for (from, to, want) in [
            ("[resources]", "[resorces]", "unknown field"),
            (
                "buffer_bytes = 32768",
                "buffer_bytes = 32768\nbogus = 1",
                "unknown field",
            ),
            (
                "name = \"dns\"",
                "name = \"../escape\"",
                "not a workload name",
            ),
            ("name = \"dns\"", "name = \"a/b\"", "not a workload name"),
            ("name = \"dns\"", "name = \"..\"", "not a workload name"),
            ("name = \"dns\"", "name = \"\"", "not a workload name"),
        ] {
            let text = MANIFEST.replacen(from, to, 1);
            let e = parse_source_manifest(&text).err().unwrap().to_string();
            assert!(e.contains(want), "{to}: {e}");
        }
        assert!(parse_source_manifest(&MANIFEST.replacen(
            "name = \"dns\"",
            "name = \"dns-2_a.b\"",
            1
        ))
        .is_ok());
    }

    #[test]
    fn graph_facts_count_own_modules_and_wiring_only() {
        let f = graph_facts(
            "target: linux\nplatform:\n  net: {}\nmodules:\n  - name: dns\n    port: 15353\nwiring:\n  - from: linux_net.net_out\n    to: dns.net_in\n  - from: dns.net_out\n    to: linux_net.net_in\n",
        )
        .unwrap();
        // The platform stack's linux_net is substrate, not footprint.
        assert_eq!(f.modules, 1);
        assert_eq!(f.module_types, vec!["dns".to_string()]);
        assert_eq!(f.edges, 2);
    }
}
