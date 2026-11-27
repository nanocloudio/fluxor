//! Workload package source, emission and launch.
//!
//! A thin TOML source manifest — non-derivable fields only — from which
//! `fluxor build <workload.toml>` emits the package format the agent
//! consumes (`workload.json` + `resources.json` + `graph.yaml`), plus the
//! per-target node image (`node.img`) of this project's own build. Emitting a
//! package calls the same `build_one` a plain `fluxor build <graph>` calls,
//! so a package's blobs are byte-for-byte what building the graph directly
//! produces.
//!
//! Package-layout rule: the source manifest REFERENCES a whole per-target
//! graph file, one per implementation. It never merges, patches or
//! synthesises graphs — a target's graph is the file checked in for it, so
//! what shipped can be read as-is. A graph that includes stacks
//! (`include:`) ships expanded: the includes resolve against the graph's own
//! location when the package is emitted, so the package is whole without the
//! files and pins its source tree held, and everything read from it — its
//! module references, its state sum, a run's module check — sees the
//! stacks' modules. The source manifest is identity only; the package's
//! params are its graph's `params:`, carried in the package's graph and in
//! `workload.json`.
//!
//! Layout emitted under `target/fluxor/<name>/`:
//!
//! ```text
//! target/fluxor/<name>/
//!   workload.json                    # all implementations
//!   <target>/{workload.json, graph.yaml, resources.json,   # flat triple —
//!             node.img,                                   # agent-committable
//!             modules/<artifact>.{fmod,toml}}             # what a launch loads
//! ```
//!
//! `workload.json` is duplicated into each target dir so that dir is
//! directly consumable by `fluxor agent commit --package`, which expects the
//! flat triple in one directory. The package pins each artifact by sha256 in
//! `workload.json`, and every consumer re-hashes the files it reads and
//! refuses a mismatch.
//!
//! Only `linux` implementations are emitted; other implementations are
//! skipped with a notice.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use fluxor_tools::packaging::SourceManifest;
use fluxor_tools::params::{self, ParamSpec, ParamValue};
use fluxor_tools::workload::{
    validate, Bindings, Contract, DigestRef, Export, Health, Implementation, ModuleRef,
    ResourceProfileDoc, Target, UpdatePolicy, WorkloadManifest,
};

/// The package source manifest, read by the one reader `fluxor ci` and the
/// publish sweep check with ([`fluxor_tools::packaging::parse_source_manifest`]).
fn parse_source_manifest(text: &str) -> Result<SourceManifest> {
    fluxor_tools::packaging::parse_source_manifest(text).map_err(Error::Config)
}

// ============================================================================
// Graph facts (derived, never declared)
// ============================================================================

/// The graph facts a package derives rather than declares: its module
/// entries, its first module's type, and the module/edge counts that seed
/// the resource profile. Platform-stack modules are NOT counted — they are
/// node substrate, not workload footprint.
struct GraphFacts {
    entries: Vec<serde_json::Value>,
    first_module: Option<String>,
    modules: u16,
    edges: u16,
}

/// The facts of a package graph. The graph is the expanded one
/// ([`package_graph`]): facts read from a graph that still includes stacks
/// would miss their modules, so one is refused.
fn graph_facts(template: &str) -> Result<GraphFacts> {
    let doc = params::parse_graph(template).map_err(Error::Config)?.doc;
    if includes_stacks(&doc) {
        return Err(Error::Config(
            "the graph still includes stacks; a package carries its graph with every \
             include expanded — emit the package again"
                .into(),
        ));
    }
    let modules = doc
        .get("modules")
        .and_then(|m| m.as_sequence())
        .cloned()
        .unwrap_or_default();
    let entries: Vec<serde_json::Value> = modules
        .iter()
        .map(|m| serde_json::to_value(m).map_err(|e| Error::Config(e.to_string())))
        .collect::<Result<_>>()?;
    let first_module = entries
        .first()
        .map(|e| {
            crate::module_resolver::entry_identity(e)
                .map(|(_, ty, _)| ty.to_string())
                .ok_or_else(|| Error::Config("graph module without name/type".into()))
        })
        .transpose()?;
    let edges = doc
        .get("wiring")
        .and_then(|w| w.as_sequence())
        .map(|w| w.len())
        .unwrap_or(0);
    Ok(GraphFacts {
        modules: modules.len() as u16,
        first_module,
        entries,
        edges: edges as u16,
    })
}

/// What a package pins of its graph's modules.
struct PackageModules {
    /// Each artefact's name and bytes, in declaration order.
    artefacts: Vec<(String, Vec<u8>)>,
    /// Each artefact's name and the `manifest.toml` text it resolved with.
    manifests: Vec<(String, String)>,
    /// The resident state they record, in bytes.
    state: u64,
    /// How many record none.
    unknown: usize,
    /// The artefacts that are the project's own modules.
    own: Vec<String>,
}

/// The module artefacts a package pins for `facts`, each resolved as the
/// build of its graph resolves it: name and bytes, in declaration order, two
/// instances of one artefact once. A native module, which every runtime
/// carries, is pinned by none. Returns the artefacts and the resident state
/// they record (`module_facts!`, read at pack time), with the number that
/// record none.
fn package_modules(
    facts: &GraphFacts,
    r: &crate::module_resolver::ModuleResolver,
) -> Result<PackageModules> {
    let fixtures = r.project_root().join("modules/fixtures");
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    let mut manifests: Vec<(String, String)> = Vec::new();
    let mut own: Vec<String> = Vec::new();
    let (mut state, mut unknown) = (0u64, 0usize);
    for entry in &facts.entries {
        let (name, ty, variant) = crate::module_resolver::entry_identity(entry)
            .ok_or_else(|| Error::Config("graph module without name/type".into()))?;
        let a = r.require(name, ty, variant)?;
        if a.is_native() || out.iter().any(|(n, _)| *n == a.artifact) {
            continue;
        }
        // fixtures/ modules are test instruments, never part of a shipped
        // workload package.
        if a.source_dir().is_some_and(|d| d.starts_with(&fixtures)) {
            return Err(Error::Config(format!(
                "module '{ty}' is a fixtures-layer test instrument and cannot be referenced \
                 by a workload package"
            )));
        }
        let info = a.module_info()?.expect("a PIC module");
        match info.manifest.state_bytes_64 {
            0 => unknown += 1,
            n => state += n as u64 * 64,
        }
        if matches!(a.origin, crate::module_resolver::Origin::Tree { .. }) {
            own.push(a.artifact.clone());
        }
        manifests.push((a.artifact.clone(), r.manifest_text(&a)?));
        out.push((a.artifact.clone(), info.data.clone()));
    }
    Ok(PackageModules {
        artefacts: out,
        manifests,
        state,
        unknown,
        own,
    })
}

/// A package's `modules/`: each module it pins as the `.fmod` and the
/// `manifest.toml` (`<artifact>.toml`) it was packed with, so a launch of
/// the package resolves its modules from the package alone. Whatever an
/// earlier emit left there is replaced.
fn write_package_modules(
    dir: &Path,
    modules: &[(String, Vec<u8>)],
    manifests: &[(String, String)],
) -> Result<()> {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir)?;
    for (name, bytes) in modules {
        std::fs::write(dir.join(format!("{name}.fmod")), bytes)?;
    }
    for (name, text) in manifests {
        std::fs::write(
            dir.join(format!(
                "{name}.{}",
                crate::module_resolver::PACKAGED_MANIFEST_EXT
            )),
            text,
        )?;
    }
    Ok(())
}

/// Does the graph include a stack: an `include:` of its own, or one in any
/// of its `workloads:` entries (each expands in its own scope).
fn includes_stacks(doc: &serde_yaml::Value) -> bool {
    use fluxor_tools::stack::{INCLUDE_KEY, WORKLOADS_KEY};
    doc.get(INCLUDE_KEY).is_some()
        || doc
            .get(WORKLOADS_KEY)
            .and_then(serde_yaml::Value::as_sequence)
            .is_some_and(|w| w.iter().any(|x| x.get(INCLUDE_KEY).is_some()))
}

/// The graph a package carries for the graph file at `graph_path`, whose text
/// is `written`, and the graph's params: the text as written when it
/// includes no stack, else the graph with every include expanded against
/// the graph's own location and `project_root`'s pins, its `params:` kept.
///
/// The expansion reads the graph as the build does, so a package's graph is
/// what building the source graph would have built, and its
/// `${param:<name>}` placeholders — the graph's own, and those it forwards
/// into its includes — stay for a run to render.
fn package_graph(
    graph_path: &Path,
    written: String,
    project_root: &Path,
) -> Result<(String, BTreeMap<String, ParamSpec>)> {
    let at = |e: String| Error::Config(format!("{}: {e}", graph_path.display()));
    let (doc, declared) =
        fluxor_tools::stack::read_expanded(graph_path, project_root, None).map_err(at)?;
    let raw: serde_yaml::Value =
        serde_yaml::from_str(&written).map_err(|e| at(format!("parse graph: {e}")))?;
    if !includes_stacks(&raw) {
        return Ok((written, declared));
    }
    let mut doc = doc;
    // Only a platform stack reads the mark, and a graph without one has
    // nothing to carry it to.
    if doc.get("platform").is_none() {
        fluxor_tools::stack::strip_stack_member_marks(&mut doc);
    }
    if let (Some(obj), false) = (doc.as_object_mut(), declared.is_empty()) {
        let schema = serde_json::to_value(&declared).map_err(|e| at(e.to_string()))?;
        obj.insert(params::PARAMS_KEY.to_string(), schema);
    }
    let expanded = serde_yaml::to_string(&doc).map_err(|e| at(format!("serialise graph: {e}")))?;
    Ok((expanded, declared))
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

/// What an emission is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Emit {
    /// Use on this node: a graph without params is built into the package's
    /// `node.img`, as `fluxor build <graph>` builds it. A launch composes
    /// its own image against the runtime it runs, and never runs this one.
    Run,
    /// A publish: the package's documents and modules are what ships, and
    /// the node that runs it composes its own image. Every graph is built as
    /// a check ([`crate::config::compose_as_check`]) and no `node.img` is
    /// kept.
    Publish,
}

/// An emitted package: its root (`target/fluxor/<name>/`) and the bytes of
/// every module artefact its `workload.json` pins.
pub struct EmittedPackage {
    pub root: PathBuf,
    pub modules: Vec<(String, Vec<u8>)>,
    /// The module artefacts that are the producing project's own, which
    /// its publish must publish beside the package.
    pub own: Vec<String>,
    /// The module ABI the package's modules are built for.
    pub abi: String,
}

/// Emit the committed package (+ per-target blobs) from a thin source
/// manifest.
pub fn emit_package(
    manifest_path: &Path,
    module_root: Option<&Path>,
    purpose: Emit,
    verbose: bool,
) -> Result<EmittedPackage> {
    let text = std::fs::read_to_string(manifest_path)
        .map_err(|e| Error::Config(format!("read {}: {e}", manifest_path.display())))?;
    let src = parse_source_manifest(&text)?;
    let manifest_dir = manifest_path.parent().unwrap_or(Path::new("."));
    let project_root = crate::project::root_for_config(manifest_path);
    let package_root = project_root.join("target/fluxor").join(&src.workload.name);

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
    let mut package_bytes: Vec<(String, Vec<u8>)> = Vec::new();
    let mut package_own: Vec<String> = Vec::new();
    let linux = crate::target::load_target("linux", &project_root)?;

    // graph.yaml: the graph file as written, its includes expanded — its
    // bytes are the digest the agent verifies at commit. For a graph with
    // params it is the template; a run renders it. Everything below reads
    // the expanded graph, so the module references, the state sum and the
    // build all see the modules the includes contribute. Only linux
    // implementations are emitted; the others are named, not silently
    // dropped.
    let mut graphs = Vec::new();
    for imp in &src.implementations {
        if imp.target != "linux" {
            println!(
                "  skipping [[implementation]] target '{}' (emits linux only)",
                imp.target
            );
            continue;
        }
        let graph_path = manifest_dir.join(&imp.graph);
        let written = std::fs::read_to_string(&graph_path)
            .map_err(|e| Error::Config(format!("read graph {}: {e}", graph_path.display())))?;
        let (template, declared) = package_graph(&graph_path, written, &project_root)?;
        graphs.push((imp, graph_path, template, declared));
    }
    let identity = fluxor_tools::packaging::PackageSource {
        name: src.workload.name.clone(),
        role: src.workload.role.clone(),
        implementations: Vec::new(),
    };
    let declared: Vec<_> = graphs.iter().map(|(_, _, _, d)| d.clone()).collect();
    let params = fluxor_tools::packaging::package_params(&identity, &declared)
        .map_err(|e| Error::Config(format!("{}: {e}", manifest_path.display())))?;

    for (imp, graph_path, template, _) in graphs {
        let graph_bytes = template.clone().into_bytes();
        let facts = graph_facts(&template)
            .map_err(|e| Error::Config(format!("{}: {e}", graph_path.display())))?;
        if first_module_for_health.is_none() {
            first_module_for_health = facts.first_module.clone();
        }

        let target_dir = package_root.join(&imp.target);
        std::fs::create_dir_all(&target_dir)?;

        std::fs::write(target_dir.join("graph.yaml"), &graph_bytes)?;
        let r = crate::module_resolver::ModuleResolver::for_graph(
            &serde_json::to_value(params::parse_graph(&template).map_err(Error::Config)?.doc)
                .map_err(|e| Error::Config(e.to_string()))?,
            &graph_path,
            Some(&linux),
            module_root,
        )?;

        // State arena demand, derived from the modules the graph names: each
        // `.fmod` records its own resident state (`module_facts!`,
        // read at pack time), so the sum is the footprint the kernel will
        // carve and the composer charges against `NodeCapacity.state_bytes`.
        // An explicit `[resources] state_bytes` overrides the measurement, for
        // a workload that reserves headroom for a module that grows under
        // load. Modules that publish no figure contribute 0 and are counted,
        // so a partial sum is visible as such.
        let PackageModules {
            artefacts: modules,
            manifests,
            state: derived_state,
            unknown: unknown_state_modules,
            own,
        } = package_modules(&facts, &r)?;
        write_package_modules(&target_dir.join("modules"), &modules, &manifests)?;
        for name in own {
            if !package_own.contains(&name) {
                package_own.push(name);
            }
        }
        if unknown_state_modules > 0 {
            eprintln!(
                "  note: {unknown_state_modules} of {} module(s) do not publish a state size; \
                 the derived state_bytes ({derived_state}) is a partial sum",
                modules.len()
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

        // Per-target blobs: this project's build of the graph, by the same
        // `build_one` a plain `fluxor build <graph>` calls, so a package's
        // blobs are identical to building the graph on its own.
        //
        // A graph with parameters has no blobs of its own: what it builds
        // depends on the values a run supplies. It is still built here,
        // rendered with its defaults and examples, so a template the
        // builder refuses never becomes a package, and any blobs an earlier
        // emit left behind are removed so nothing can launch them. A
        // publish builds every graph that way: what it ships is the
        // documents and the modules. A build whose image is kept nowhere is
        // a check, which binds no host runtime.
        let is_applet = src.workload.role == fluxor_tools::packaging::Kind::Applet.role();
        // An applet's graph is composed as one: the rules that hold only for
        // an applet's graph key on it.
        let as_applet = |build: &dyn Fn() -> Result<()>| {
            if is_applet {
                fluxor_tools::packaging::with_applet(&src.workload.name, build)
            } else {
                build()
            }
        };
        if params.is_empty() && purpose == Emit::Run {
            as_applet(&|| {
                crate::build_one_from(
                    &graph_path,
                    Some(&target_dir.join("node.img")),
                    module_root,
                    verbose,
                )
                .map(|_| ())
            })?;
        } else {
            let _ = std::fs::remove_file(target_dir.join("node.img"));
            let check_dir = project_root.join("target/fluxor/run").join(format!(
                "{}-emit-{}",
                src.workload.name,
                std::process::id()
            ));
            std::fs::create_dir_all(&check_dir)?;
            let check_graph = if params.is_empty() {
                graph_path.clone()
            } else {
                let values =
                    params::check_values(&params, fluxor_tools::stack::graph_dir(&graph_path))
                        .map_err(|e| Error::Config(format!("{}: {e}", graph_path.display())))?;
                let rendered = params::render_graph_text(&template, &values)
                    .map_err(|e| Error::Config(format!("{}: {e}", graph_path.display())))?;
                let at = check_dir.join("graph.yaml");
                std::fs::write(&at, rendered)?;
                at
            };
            let built = crate::config::compose_as_check(|| {
                as_applet(&|| {
                    crate::build_one_from(
                        &check_graph,
                        Some(&check_dir.join("node.img")),
                        module_root,
                        verbose,
                    )
                    .map(|_| ())
                })
            });
            let _ = std::fs::remove_dir_all(&check_dir);
            built.map_err(|e| {
                if params.is_empty() {
                    e
                } else {
                    Error::Config(format!(
                        "{} rendered with its defaults and examples does not build: {e}",
                        graph_path.display()
                    ))
                }
            })?;
        }

        // Module refs pin the artefacts the graph's build resolved.
        let module_refs: Vec<ModuleRef> = modules
            .iter()
            .map(|(name, bytes)| ModuleRef {
                name: name.clone(),
                digest: sha256_ref(bytes),
            })
            .collect();
        for m in modules {
            if !package_bytes.iter().any(|(n, _)| *n == m.0) {
                package_bytes.push(m);
            }
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
    };

    // The emitted manifest must pass the same validation the agent applies
    // at commit, so a package the agent would refuse fails here.
    let report = validate(&manifest);
    if !report.is_ok() {
        return Err(Error::Config(format!(
            "emitted workload.json fails validation: {}",
            report.errors.join("; ")
        )));
    }

    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest).map_err(|e| Error::Config(e.to_string()))?;
    std::fs::create_dir_all(&package_root)?;
    std::fs::write(package_root.join("workload.json"), &manifest_bytes)?;
    // Duplicate into each target dir: the agent consumes a FLAT triple
    // (workload.json beside graph.yaml + resources.json) from one directory.
    for (_, dir) in &emitted_targets {
        std::fs::write(dir.join("workload.json"), &manifest_bytes)?;
    }

    println!(
        "Emitted workload package '{}' v{} ({} target(s)) -> {}",
        manifest.name,
        manifest.version,
        emitted_targets.len(),
        package_root.display()
    );
    Ok(EmittedPackage {
        root: package_root,
        modules: package_bytes,
        own: package_own,
        abi: linux.module_abi().to_string(),
    })
}

// ============================================================================
// Resolve + run
// ============================================================================

/// Is `path` something the package runner understands? A workload source
/// manifest — a `.toml` carrying a `[workload]` table — or a package root / target
/// subdir (a dir carrying `workload.json`). Any other `.toml` (stack profiles,
/// module manifests, board configs, `Cargo.toml`) is not a workload manifest and
/// is left to the regular run dispatch, as are graph YAMLs and scenario files.
pub fn is_package_path(path: &Path) -> bool {
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
    /// A launch runs the modules the built package carries.
    pub module_root: Option<PathBuf>,
}

impl RunParams {
    pub fn is_empty(&self) -> bool {
        self.flags.is_empty() && self.file.is_none()
    }

    /// The values as the params model takes them.
    pub fn values(&self) -> Result<params::Values> {
        let file = match &self.file {
            Some(path) => params::read_values_file(path).map_err(Error::Config)?,
            None => BTreeMap::new(),
        };
        let flags = self
            .flags
            .iter()
            .map(|raw| params::parse_flag(raw))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Error::Config)?;
        Ok(params::Values::Given {
            file,
            file_dir: self
                .file
                .as_deref()
                .and_then(Path::parent)
                .map(Path::to_path_buf),
            flags,
        })
    }

    /// Check the values against `schema` and fill defaults. Every refusal is
    /// reported before anything is built or started.
    fn resolve(
        &self,
        package: &str,
        schema: &BTreeMap<String, ParamSpec>,
    ) -> Result<BTreeMap<String, ParamValue>> {
        self.values()?.resolve(schema, Path::new(".")).map_err(|e| {
            Error::Config(format!(
                "workload package '{package}' refuses this run:\n{e}"
            ))
        })
    }
}

/// `fluxor run <package>`: run a workload package, with the operator's
/// `--ca` anchors appended to its client-mode tls/quic instances for this
/// run when given. `<package>` is a source manifest or a package directory;
/// a name resolves through [`package_by_name`]. `fluxor exec` is the applet form, see
/// [`exec_applet`].
pub fn run_package(
    path: &Path,
    params: &RunParams,
    ca: Option<&Path>,
    verbose: bool,
) -> Result<()> {
    launch_package(
        path,
        &[],
        None,
        None,
        Operator { ca, identity: None },
        params,
        verbose,
    )
}

/// The package `fluxor run <name>` runs: the project's own
/// `packaging/<service|applet>/<name>/workload.toml`, else the package its
/// `fluxor.lock` pins under `name` (materialised as `fluxor sync` would), or
/// a refusal naming both.
pub fn package_by_name(name: &str) -> Result<PathBuf> {
    let project_root = crate::project::root();
    if let Some(own) = fluxor_tools::packaging::package_path(&project_root, name) {
        return Ok(own);
    }
    if let Some(dir) = crate::store_sync::ensure_package(&project_root, name)
        .map_err(|e| Error::Config(e.to_string()))?
    {
        return Ok(dir);
    }
    let pinned = crate::store_sync::pinned_packages(&project_root);
    Err(Error::Config(format!(
        "'{name}' is neither a path, this project's own package (packaging/service/{name}/ or \
         packaging/applet/{name}/), nor a package pinned in {} (pinned packages: {}) — list it \
         in fluxor.toml `[uses] packages` and run `fluxor update` to pin it from the \
         dependency that publishes it",
        fluxor_tools::store_resolve::lockfile_path(&project_root).display(),
        if pinned.is_empty() {
            "none".to_string()
        } else {
            pinned.join(", ")
        }
    )))
}

/// Read a source manifest's parameter schema — its linux graphs' `params:`
/// — without building anything, so a run's values are refused before the
/// emit that precedes it.
fn source_params(path: &Path) -> Result<(String, BTreeMap<String, ParamSpec>)> {
    let src = fluxor_tools::packaging::read_package(path).map_err(Error::Config)?;
    let mut declared = Vec::new();
    for (target, graph) in &src.implementations {
        if target != "linux" {
            continue;
        }
        let text = std::fs::read_to_string(graph)
            .map_err(|e| Error::Config(format!("read {}: {e}", graph.display())))?;
        let g = params::parse_graph(&text)
            .map_err(|e| Error::Config(format!("{}: {e}", graph.display())))?;
        declared.push(g.params);
    }
    let params = fluxor_tools::packaging::package_params(&src, &declared).map_err(Error::Config)?;
    Ok((src.name, params))
}

/// Write the node image `image` to `out` with the certificates of `pem`
/// appended to every client-mode tls/quic instance of its config, re-signed
/// with `seed`, and say what was widened. The
/// operator channel reads PEM only (the build-time `trust` parameter is
/// the one that also takes raw DER), and a block whose base64 does not
/// decode is skipped rather than failing the run. A file that yields no
/// certificate that way, more anchors than an instance holds or one over
/// the DER ceiling, and an instance whose table would overflow, are each
/// an error naming what failed; a graph with no client instance is
/// reported, not an error, since the flag then has nothing to widen.
pub fn write_widened_image(
    image: &Path,
    out: &Path,
    pem: &Path,
    seed: Option<&[u8; 32]>,
) -> Result<()> {
    let text = std::fs::read_to_string(pem)
        .map_err(|e| Error::Config(format!("--ca: could not read '{}': {e}", pem.display())))?;
    let anchors = crate::trust_anchors::pem_certificates(&text);
    if anchors.is_empty() {
        return Err(Error::Config(format!(
            "--ca: no CERTIFICATE block decodes in '{}'",
            pem.display()
        )));
    }
    let img = std::fs::read(image)?;
    let what = image.display().to_string();
    let header = crate::node_image::read(&img, &what)?;
    let (widened, report) =
        crate::trust_anchors::append_operator_anchors(header.config(&img), &anchors)
            .map_err(|e| Error::Config(format!("--ca: {e}")))?;
    std::fs::write(
        out,
        crate::node_image::with_config(&img, &widened, seed, &what)?,
    )?;
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

/// What the operator brings to one run, beside the package: trust anchors to
/// widen client instances with (`--ca`), and a client identity (`--identity`).
#[derive(Clone, Copy)]
struct Operator<'a> {
    ca: Option<&'a Path>,
    identity: Option<&'a (PathBuf, PathBuf)>,
}

/// The operator identity a run of applet `name` brings: `CERT,KEY` when
/// given, else `$HOME/.config/<name>/client.der` + `client.key.der` when
/// both exist, else none.
fn operator_identity(name: &str, given: Option<&str>) -> Result<Option<(PathBuf, PathBuf)>> {
    if let Some(spec) = given {
        let (cert, key) = spec.split_once(',').ok_or_else(|| {
            Error::Config(format!(
                "--identity takes CERT,KEY (DER files), got '{spec}'"
            ))
        })?;
        return Ok(Some((PathBuf::from(cert), PathBuf::from(key))));
    }
    let Some(home) = std::env::var_os("HOME") else {
        return Ok(None);
    };
    let dir = PathBuf::from(home).join(".config").join(name);
    let (cert, key) = (dir.join("client.der"), dir.join("client.key.der"));
    Ok((cert.is_file() && key.is_file()).then_some((cert, key)))
}

/// Write the node image `image` to `out` with the operator's identity given
/// to every client-mode tls instance of its config that names none,
/// re-signed with `seed`, and say so when asked.
fn write_identity_image(
    image: &Path,
    out: &Path,
    cert: &Path,
    key: &Path,
    seed: Option<&[u8; 32]>,
    verbose: bool,
) -> Result<()> {
    let read = |p: &Path| {
        std::fs::read(p).map_err(|e| {
            Error::Config(format!("--identity: could not read '{}': {e}", p.display()))
        })
    };
    let (cert_der, key_der) = (read(cert)?, read(key)?);
    let img = std::fs::read(image)?;
    let what = image.display().to_string();
    let header = crate::node_image::read(&img, &what)?;
    let (given, report) =
        crate::trust_anchors::append_operator_identity(header.config(&img), &cert_der, &key_der)
            .map_err(|e| Error::Config(format!("--identity: {e}")))?;
    write_private(
        out,
        &crate::node_image::with_config(&img, &given, seed, &what)?,
    )?;
    if verbose {
        eprintln!(
            "  --identity: '{}' given to {} client instance(s)",
            cert.display(),
            report.instances.len()
        );
    }
    Ok(())
}

/// The param schema of each module packed in a node image's module table
/// (`fmod::table`), by type-name hash.
fn image_schemas(table: &[u8]) -> std::collections::HashMap<u32, crate::schema::ParamSchema> {
    use fluxor_abi::wire::fmod::{header, table as t};
    let u32_at = |b: &[u8], at: usize| {
        b.get(at..at + 4)
            .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
    };
    let mut out = std::collections::HashMap::new();
    let Some(count) = table
        .get(t::MODULE_COUNT..t::MODULE_COUNT + 2)
        .map(|v| u16::from_le_bytes([v[0], v[1]]) as usize)
    else {
        return out;
    };
    for i in 0..count {
        let e = t::HEADER_SIZE + i * t::ENTRY_SIZE;
        let (Some(hash), Some(off), Some(size)) = (
            u32_at(table, e + t::ENTRY_NAME_HASH),
            u32_at(table, e + t::ENTRY_OFFSET),
            u32_at(table, e + t::ENTRY_SIZE_AT),
        ) else {
            break;
        };
        let Some(fmod) = table.get(off as usize..off as usize + size as usize) else {
            continue;
        };
        let Some(h) = header::Header::read(fmod) else {
            continue;
        };
        let at = header::SIZE
            + h.code_size as usize
            + h.data_size as usize
            + h.export_count as usize * 8;
        let schema = fmod.get(at..at + h.schema_size as usize).unwrap_or(&[]);
        if let Some(ps) = crate::schema::ParamSchema::from_bytes(schema) {
            out.insert(hash, ps);
        }
    }
    out
}

/// The node image `image` with applet `name`'s data directory given where
/// its graph names `${applet:data_dir}`, re-signed with `seed`; `None` when
/// the graph names none, and then no directory is made.
fn data_dir_image(image: &Path, name: &str, seed: Option<&[u8; 32]>) -> Result<Option<Vec<u8>>> {
    use std::os::unix::ffi::OsStrExt;
    let img = std::fs::read(image)?;
    let what = image.display().to_string();
    let header = crate::node_image::read(&img, &what)?;
    let config = header.config(&img);
    let at =
        |e: String| Error::Config(format!("{}: {e}", fluxor_tools::packaging::APPLET_DATA_DIR));
    if !crate::trust_anchors::names_applet_data_dir(config).map_err(at)? {
        return Ok(None);
    }
    let dir = fluxor_tools::packaging::ensure_applet_data_dir(name, |k| std::env::var_os(k))
        .map_err(Error::Config)?;
    let schemas = image_schemas(header.modules(&img));
    let bound = |hash: u32, tag: u8| {
        let p = schemas.get(&hash)?.params.iter().find(|p| p.tag == tag)?;
        Some((p.min, p.max))
    };
    let (given, _) =
        crate::trust_anchors::give_applet_data_dir(config, dir.as_os_str().as_bytes(), &bound)
            .map_err(at)?;
    Ok(Some(crate::node_image::with_config(
        &img, &given, seed, &what,
    )?))
}

/// A package's `workload.json`, parsed and held to the same validation the
/// agent applies at commit.
fn load_manifest(text: &str) -> Result<WorkloadManifest> {
    let manifest = fluxor_tools::workload::parse_manifest(text).map_err(Error::Config)?;
    let report = validate(&manifest);
    if !report.is_ok() {
        return Err(Error::Config(format!(
            "workload package '{}' failed validation: {}",
            manifest.name,
            report.errors.join("; ")
        )));
    }
    Ok(manifest)
}

/// What one launch writes — its rendered graph, the image composed from
/// it, the copies given the applet's data directory, the operator's trust
/// anchors or the operator's key — in a directory only its owner can enter,
/// outside every project tree: under `$XDG_RUNTIME_DIR` (per user, in
/// memory, cleared at logout) when that is set, else under a per-user
/// directory in the system temporary directory. A project tree is backed
/// up, synced and committed, and a package's tree is its producer's: a
/// launch writes into neither. The directory is removed when the launch
/// ends by any path.
struct LaunchScratch {
    dir: PathBuf,
}

impl LaunchScratch {
    fn create(name: &str) -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let root = launch_root()?;
        sweep_dead_launches(&root);
        let dir = root.join(format!("{name}-{}", std::process::id()));
        // A directory a crashed launch with this pid left behind.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        Ok(LaunchScratch { dir })
    }
}

impl Drop for LaunchScratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The per-user root [`LaunchScratch`] directories live under, created
/// `0700` and refused unless it is a real directory this user owns that no
/// one else can enter: in a shared temporary directory another user could
/// have made the name first.
fn launch_root() -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    let uid = unsafe { libc::geteuid() };
    let root = match std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) {
        Some(runtime) => PathBuf::from(runtime).join("fluxor-run"),
        None => std::env::temp_dir().join(format!("fluxor-run-{uid}")),
    };
    match std::fs::DirBuilder::new().mode(0o700).create(&root) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let meta = std::fs::symlink_metadata(&root)?;
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err(Error::Config(format!(
            "{}: not a private directory of this user; refusing to launch from it",
            root.display()
        )));
    }
    Ok(root)
}

/// Remove the directories of launches whose process is gone: a launch
/// killed outright never ran its cleanup.
fn sweep_dead_launches(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|n| n.rsplit_once('-'))
            .and_then(|(_, pid)| pid.parse::<libc::pid_t>().ok())
        else {
            continue;
        };
        // SAFETY: signal 0 only asks whether `pid` exists.
        let gone = pid > 0
            && unsafe { libc::kill(pid, 0) } != 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        if gone {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Write `bytes` to a new file at `path` that only its owner can read.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

/// Launch a package's linux implementation. `installed` is what an applet
/// was installed with: the runtime it runs and the project whose signing
/// key, target definition and Fluxor catalog its image is composed with;
/// without it, the package's own project and its staged runtime. `applet`
/// marks an applet run: the
/// runtime keeps its own log records out of the program's stderr — fd 2 is
/// the program's alone — and files them under the applet's name instead, so
/// a CLI package's output is only what the program itself wrote.
///
/// Every launch composes the image it runs ([`compose_for_launch`]): the
/// package's template is rendered with the run's checked values and
/// composed against the modules the package carries in its `modules/`, each
/// `.fmod` verified against the digest `workload.json` pins and read with
/// the manifest it was packed with, and against the runtime this launch
/// runs. Nothing is resolved from the current directory's project or its
/// `fluxor.lock`. A `node.img` the package's producer built is never what a
/// launch runs.
fn launch_package(
    path: &Path,
    app_args: &[String],
    installed: Option<&AppletEntry>,
    applet: Option<&str>,
    operator: Operator<'_>,
    params: &RunParams,
    verbose: bool,
) -> Result<()> {
    use fluxor_tools::workload::select_implementation;
    let Operator { ca, identity } = operator;

    // A source manifest builds first; running is then resolving the fresh
    // package it emitted. Its values are checked before that build.
    let dir = if path.extension().is_some_and(|e| e == "toml") {
        let (name, schema) = source_params(path)?;
        params.resolve(&name, &schema)?;
        emit_package(path, params.module_root.as_deref(), Emit::Run, verbose)?.root
    } else {
        path.to_path_buf()
    };

    // The documents: a flat dir (materialised package or target subdir)
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
            "workload package '{}' has no linux/aarch64/abi-1 implementation to run",
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
                "package {file}: digest mismatch (manifest pins {pinned}, artifact is {actual})"
            )));
        }
    }

    let project_root = match installed {
        Some(entry) => entry.project()?,
        None => crate::project::root_for_config(&dir),
    };
    let runtime = installed.and_then(|e| e.runtime.as_deref());
    // A recorded runtime is the one this package's modules were packed
    // against. If it has gone, say so and name it: running the package
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
        None => crate::project::linux_runtime(&project_root),
    };
    if !linux_bin.exists() {
        return Err(Error::Config(format!(
            "Linux binary not found at {}. Run 'make build' first.",
            linux_bin.display()
        )));
    }

    // Every launch composes the image it runs, against the runtime it runs:
    // the image pins the providers beside that binary, so an image composed
    // for another runtime, or before this one was rebuilt, is never run.
    // Parameter values, the operator's trust anchors and key reach what the
    // launch writes, so its directory is private and goes away on every exit
    // path.
    let scratch = LaunchScratch::create(&manifest.name)?;
    let module_root = target_dir.join("modules");
    for m in &imp.modules {
        let toml = module_root.join(format!(
            "{}.{}",
            m.name,
            crate::module_resolver::PACKAGED_MANIFEST_EXT
        ));
        if !toml.is_file() {
            return Err(Error::Config(format!(
                "package module '{}': the package carries no manifest for it ({}) — re-emit \
                 the package (`fluxor build <workload.toml>`) or re-sync it",
                m.name,
                toml.display()
            )));
        }
        let fmod = module_root.join(format!("{}.fmod", m.name));
        let bytes = std::fs::read(&fmod).map_err(|e| {
            Error::Config(format!(
                "package module '{}': {} ({e})",
                m.name,
                fmod.display()
            ))
        })?;
        let actual = sha256_ref(&bytes);
        if actual != m.digest {
            return Err(Error::Config(format!(
                "package module '{}': {} is {actual} but the package pins {} — \
                 re-emit the package or re-sync it",
                m.name,
                fmod.display(),
                m.digest
            )));
        }
    }
    let template = std::fs::read_to_string(target_dir.join("graph.yaml"))?;
    let rendered = params::render_graph_text(&template, &values).map_err(Error::Config)?;
    // Only the pinned modules are verified above, so the rendered graph may
    // load nothing else: a value substituted into a module name would
    // otherwise pull in an unverified artefact.
    let facts = graph_facts(&rendered)?;
    let graph = scratch.dir.join("graph.yaml");
    let r = crate::module_resolver::ModuleResolver::for_package(
        &project_root,
        &crate::target::load_target("linux", &project_root)?,
        &module_root,
    )?;
    for entry in &facts.entries {
        let (name, ty, variant) = crate::module_resolver::entry_identity(entry)
            .ok_or_else(|| Error::Config("graph module without name/type".into()))?;
        let a = r.require(name, ty, variant)?;
        if !a.is_native() && !imp.modules.iter().any(|m| m.name == a.artifact) {
            return Err(Error::Config(format!(
                "the rendered graph loads module '{}', which package '{}' does not pin",
                a.artifact, manifest.name
            )));
        }
    }
    std::fs::write(&graph, rendered)?;
    let mut image = scratch.dir.join("node.img");
    let is_applet = manifest.role == fluxor_tools::packaging::Kind::Applet.role();
    compose_for_launch(
        &LaunchComposition {
            graph: &graph,
            output: &image,
            package_modules: &module_root,
            runtime: &linux_bin,
            applet: is_applet.then_some(manifest.name.as_str()),
            project_root: &project_root,
            log: &scratch.dir.join("compose.log"),
        },
        if applet.is_none() {
            ComposeReport::Shown
        } else if verbose {
            ComposeReport::OnStderr
        } else {
            ComposeReport::OnFailure
        },
        verbose,
    )?;
    // A changed config is re-signed with this workspace's key, as the build
    // signed it.
    let seed = crate::signing::seed(None, &project_root)?;
    // The applet's data directory is given to this run's copy, as the
    // operator's identity is below: resolved for the operator running it,
    // and made on first use.
    if let Some(given) = data_dir_image(&image, applet.unwrap_or(&manifest.name), seed.as_ref())? {
        let out = scratch.dir.join("graph.data_dir.img");
        std::fs::write(&out, given)?;
        image = out;
    }
    // `--ca` widens this run's copy only; the package stays byte-identical.
    if let Some(pem) = ca {
        let widened = scratch.dir.join("graph.operator.img");
        write_widened_image(&image, &widened, pem, seed.as_ref())?;
        image = widened;
    }
    // The operator's identity is given the same way, to this run's copy.
    if let Some((cert, key)) = identity {
        let given = scratch.dir.join("graph.identity.img");
        write_identity_image(&image, &given, cert, key, seed.as_ref(), verbose)?;
        image = given;
    }

    // A dev run says what it runs; an applet run is the program's, and says
    // nothing of its own unless asked (`-v`).
    if verbose || applet.is_none() {
        eprintln!(
            "Running package '{}' v{} ({}): {} --image {}",
            manifest.name,
            manifest.version,
            imp.target.family,
            linux_bin.display(),
            image.display()
        );
    }
    let mut cmd = std::process::Command::new(&linux_bin);
    cmd.arg("--image").arg(&image);
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
    // Die-with-parent (see `tie_to_parent`): a killed/timeouted `fluxor exec`
    // must not orphan a runtime that never exits on its own. A stop signal
    // is passed on so the runtime drains first (see `run_tied`).
    let status = crate::run_tied(&mut cmd);
    // `exit` below skips destructors.
    drop(scratch);
    let status = status?;
    crate::exit_if_signalled(&status);
    // A CLI package's exit code IS the deliverable: propagate it verbatim
    // rather than wrapping a non-zero status in a tool error, so a shell
    // sees what the program returned.
    std::process::exit(status.code().unwrap_or(1));
}

/// The image one launch composes: the rendered graph, where the image goes,
/// the package's verified modules, the runtime the launch runs, the applet whose
/// graph it is, the project whose signing key and target definition it
/// takes, and where the composer's report is kept.
struct LaunchComposition<'a> {
    graph: &'a Path,
    output: &'a Path,
    package_modules: &'a Path,
    runtime: &'a Path,
    applet: Option<&'a str>,
    project_root: &'a Path,
    log: &'a Path,
}

/// Where a launch's composer report goes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ComposeReport {
    /// A dev run: on this process's stdout and stderr, as `fluxor build`
    /// reports.
    Shown,
    /// An applet run with `-v`: on stderr, so stdout stays the program's.
    OnStderr,
    /// An applet run: kept in the launch's log, and printed on stderr only
    /// when the composition fails. Both of an applet's streams are the
    /// program's.
    OnFailure,
}

/// Compose a launch's image in a child of this CLI (`compose-launch`), so
/// every line the composer writes, and every process a build step starts,
/// goes where `report` says and nowhere else. The child runs in the
/// launch's directory with the project root named, since the rendered
/// graph lies outside every project tree.
fn compose_for_launch(
    c: &LaunchComposition<'_>,
    report: ComposeReport,
    verbose: bool,
) -> Result<()> {
    let mut cmd = crate::ci::self_invoke();
    cmd.arg("compose-launch")
        .arg(c.graph)
        .arg("--output")
        .arg(c.output)
        .arg("--package-modules")
        .arg(c.package_modules)
        .arg("--runtime")
        .arg(c.runtime);
    if let Some(name) = c.applet {
        cmd.arg("--applet").arg(name);
    }
    if verbose {
        cmd.arg("--verbose");
    }
    cmd.env(crate::project::ENV_PROJECT_ROOT, c.project_root)
        .current_dir(c.graph.parent().unwrap_or(Path::new(".")))
        .stdin(std::process::Stdio::null());
    match report {
        ComposeReport::Shown => {}
        ComposeReport::OnStderr => {
            cmd.stdout(std::io::stderr());
        }
        ComposeReport::OnFailure => {
            let log = std::fs::File::create(c.log)?;
            cmd.stdout(log.try_clone()?).stderr(log);
        }
    }
    let status = cmd
        .status()
        .map_err(|e| Error::Config(format!("compose the launch's image: {e}")))?;
    if status.success() {
        return Ok(());
    }
    if report == ComposeReport::OnFailure {
        if let Ok(text) = std::fs::read_to_string(c.log) {
            eprint!("{text}");
        }
    }
    Err(Error::Config(format!(
        "composing the image this launch runs failed ({status})"
    )))
}

/// `fluxor compose-launch`: compose the image a launch runs
/// ([`compose_for_launch`]) from the package modules in `package_modules`
/// alone, pinning the providers beside `runtime`, as an applet's graph when
/// `applet` names one.
pub fn compose_launch_image(
    graph: &Path,
    output: &Path,
    package_modules: &Path,
    runtime: &Path,
    applet: Option<&str>,
    verbose: bool,
) -> Result<()> {
    let compose = || {
        crate::module_resolver::with_package_modules(package_modules, || {
            crate::config::compose_on_runtime(runtime, || {
                crate::build_one_from(graph, Some(output), Some(package_modules), verbose)
                    .map(|_| ())
            })
        })
    };
    match applet {
        Some(name) => fluxor_tools::packaging::with_applet(name, compose),
        None => compose(),
    }
}

// ============================================================================
// Applet registry + exec
// ============================================================================

/// The on-disk applet catalogue: `[applets]` name → absolute package path.
/// Deliberately separate from the `cli` stack: the stack is the harness a
/// CLI package is built against, the catalogue is the per-user record of
/// which built packages are installed under which names. Installing or
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

/// One catalogue entry: the cached package, the runtime it was built
/// against when the installing project had one staged, and the project it
/// was installed from, whose signing key, target definition and Fluxor
/// catalog its launches compose with.
#[derive(Clone, Debug)]
pub struct AppletEntry {
    pub package: PathBuf,
    pub runtime: Option<PathBuf>,
    pub project: Option<PathBuf>,
}

impl AppletEntry {
    /// The project a launch of this applet composes for: the one recorded
    /// at install, else the project the package lies in. A package outside
    /// every project with none recorded is refused, never composed for
    /// whatever project the current directory is in.
    fn project(&self) -> Result<PathBuf> {
        if let Some(p) = &self.project {
            return Ok(p.clone());
        }
        crate::project::discover_from(&self.package)
            .map(|r| r.path)
            .ok_or_else(|| {
                Error::Config(format!(
                    "applet package {} records no project it was installed from — reinstall \
                     it (`fluxor install`)",
                    self.package.display()
                ))
            })
    }
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
            if let Some(package) = v.get("package").and_then(|b| b.as_str()) {
                out.insert(
                    k.clone(),
                    AppletEntry {
                        package: PathBuf::from(package),
                        runtime: v.get("runtime").and_then(|r| r.as_str()).map(PathBuf::from),
                        project: v.get("project").and_then(|r| r.as_str()).map(PathBuf::from),
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
    let mut text = String::from("# fluxor applet registry: name -> installed package\n[applets]\n");
    for (k, v) in reg {
        let mut fields = vec![format!("package = {:?}", v.package.display().to_string())];
        if let Some(runtime) = &v.runtime {
            fields.push(format!("runtime = {:?}", runtime.display().to_string()));
        }
        if let Some(project) = &v.project {
            fields.push(format!("project = {:?}", project.display().to_string()));
        }
        text.push_str(&format!("{k} = {{ {} }}\n", fields.join(", ")));
    }
    std::fs::write(&path, text)?;
    Ok(())
}

/// `fluxor install <package>`: register an applet name → cached package path.
/// Accepts a source manifest (emits first) or a package dir; the name defaults
/// to the package's `workload.json` name. `--link <dir>` drops a busybox
/// symlink `<dir>/<name> → fluxor` so `<name> args…` dispatches via argv[0].
pub fn install_applet(
    package: &Path,
    name: Option<&str>,
    link: Option<&Path>,
    verbose: bool,
) -> Result<()> {
    let dir = if package.extension().is_some_and(|e| e == "toml") {
        emit_package(package, None, Emit::Run, verbose)?.root
    } else if !package.exists() {
        // Not a path: a name. The project's own package is emitted from its
        // packaging/; a sibling's CLI is consumed as the published artifact
        // this project pins, never as a checkout, materialised into the
        // applet cache.
        let name = package.to_string_lossy();
        match fluxor_tools::packaging::package_path(&crate::project::root(), &name) {
            Some(own) => emit_package(&own, None, Emit::Run, verbose)?.root,
            None => materialize_pinned_package(&name, verbose)?,
        }
    } else {
        package.to_path_buf()
    };
    let dir = dir
        .canonicalize()
        .map_err(|e| Error::Config(format!("{}: {e}", dir.display())))?;
    let manifest_text = std::fs::read_to_string(dir.join("workload.json"))
        .map_err(|e| Error::Config(format!("{}: workload.json: {e}", dir.display())))?;
    let manifest = load_manifest(&manifest_text)?;
    if !manifest.params.is_empty() {
        return Err(Error::Config(format!(
            "workload package '{}' is a service with parameters; an applet takes argv — run it with \
             `fluxor run {} --param name=value`",
            manifest.name, manifest.name
        )));
    }
    let applet = name.unwrap_or(&manifest.name).to_string();

    // The runtime the package was built against: the installing project's
    // staged binary, recorded so `exec` runs it from any directory. What the
    // lockfile names is materialised first: `fluxor update` rewrites the lock
    // without touching the tree, so the staged binary can otherwise be an
    // older kernel than the project is pinned to.
    let project_root = crate::project::root_for_config(&dir);
    if let Err(e) = crate::store_sync::ensure_synced(&project_root) {
        eprintln!("warning: could not sync the pinned artifacts before install: {e}");
    }
    let runtime = crate::project::linux_runtime(&project_root);
    let runtime = runtime
        .exists()
        .then(|| runtime.canonicalize().unwrap_or(runtime));
    let mut reg = load_registry()?;
    reg.insert(
        applet.clone(),
        AppletEntry {
            package: dir.clone(),
            runtime,
            project: Some(project_root.canonicalize().unwrap_or(project_root)),
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
/// an exact name in the applet registry, then a package built in this
/// project (`target/fluxor/<name>/`), else an error listing the applets
/// that ARE known. Nothing is compiled: each launch composes the package's
/// image from its pinned modules, against the runtime it runs, and says
/// nothing of that composition unless it fails or `-v` asks.
pub fn exec_applet(
    name: &str,
    args: &[String],
    ca: Option<&Path>,
    identity: Option<&str>,
    verbose: bool,
) -> Result<()> {
    let identity = operator_identity(name, identity)?;
    let identity = identity.as_ref();
    let reg = load_registry()?;
    if let Some(entry) = reg.get(name) {
        if entry.package.join("workload.json").is_file() {
            return launch_package(
                &entry.package,
                args,
                Some(entry),
                Some(name),
                Operator { ca, identity },
                &RunParams::default(),
                verbose,
            );
        }
        return Err(Error::Config(format!(
            "applet '{name}' points at {} but no package is there — re-run `fluxor install`",
            entry.package.display()
        )));
    }
    // Project-local fallback: a package built in this tree.
    let project = crate::project::root().join("target/fluxor").join(name);
    if project.join("workload.json").is_file() {
        return launch_package(
            &project,
            args,
            None,
            Some(name),
            Operator { ca, identity },
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

/// Materialise the package this project pins under `name` as a runnable
/// package dir under the applet cache (`$XDG_DATA_HOME/fluxor/applets/<name>/`):
/// the same digest-verified flat layout `fluxor sync` writes (documents +
/// the package's own `modules/`). Each `exec` composes its image from them
/// against the runtime it runs.
fn materialize_pinned_package(name: &str, verbose: bool) -> Result<PathBuf> {
    use fluxor_tools::oci_store::{self, OciStore};
    let project_root = crate::project::root();
    let artifact = fluxor_tools::store_resolve::read_store_lock(&project_root)
        .map_err(|e| Error::Config(e.to_string()))?
        .and_then(|l| {
            l.artifacts
                .into_iter()
                .find(|a| a.kind == "package" && a.name == name)
        })
        .ok_or_else(|| {
            Error::Config(format!(
                "'{name}' is neither a path, this project's own package, nor a package pinned in \
                 {} — list it in fluxor.toml `[uses] packages` and run `fluxor update`",
                fluxor_tools::store_resolve::lockfile_path(&project_root).display()
            ))
        })?;
    let store = OciStore::open(oci_store::store_root().map_err(|e| Error::Config(e.to_string()))?)
        .map_err(|e| Error::Config(e.to_string()))?;
    let cache_root = match std::env::var_os("XDG_DATA_HOME") {
        Some(x) if !x.is_empty() => PathBuf::from(x),
        _ => PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share"),
    }
    .join("fluxor/applets")
    .join(&artifact.name);
    crate::store_sync::materialize_package(&store, &artifact, &cache_root)
        .map_err(|e| Error::Config(e.to_string()))?;
    let manifest_text = std::fs::read_to_string(cache_root.join("workload.json"))?;
    let manifest = load_manifest(&manifest_text)?;
    if !manifest.params.is_empty() {
        return Err(Error::Config(format!(
            "workload package '{}' is a service with parameters; an applet takes argv — run it with \
             `fluxor run {} --param name=value`",
            manifest.name, manifest.name
        )));
    }
    if verbose {
        println!(
            "materialised pinned package {} ({}) -> {}",
            artifact.reference,
            artifact.digest,
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
        // `role`, not `kind` — `kind` means scenario in fluxor — and the
        // only accepted roles are `service` and `cli`.
        let bad = MANIFEST.replace("role = \"service\"", "role = \"daemon\"");
        assert!(parse_source_manifest(&bad).is_err());
        let cli = MANIFEST.replace("role = \"service\"", "role = \"cli\"");
        assert_eq!(parse_source_manifest(&cli).unwrap().workload.role, "cli");
    }

    #[test]
    fn params_belong_to_the_graph_not_the_manifest() {
        let svc = format!("{MANIFEST}\n[params.port]\ntype = \"integer\"\ndefault = 15353\n");
        let e = parse_source_manifest(&svc).err().unwrap().to_string();
        assert!(e.contains("`[params]` belongs to the graph"), "{e}");
    }

    #[test]
    fn graph_facts_carry_every_module_entry() {
        let f = graph_facts(
            "target: linux\nmodules:\n  - name: cli_in\n  - name: tool\n  - name: cli_out\n",
        )
        .unwrap();
        assert_eq!(f.modules, 3);
        assert_eq!(f.first_module.as_deref(), Some("cli_in"));
        assert_eq!(f.entries.len(), 3);
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
        assert_eq!(f.entries.len(), 1);
        assert_eq!(f.edges, 2);
    }

    #[test]
    fn graph_facts_refuse_a_graph_whose_includes_are_not_expanded() {
        let e = graph_facts("target: linux\ninclude:\n  - stack: s.yaml\n    as: s\nmodules: []\n")
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("still includes stacks"), "{e}");
        let e = graph_facts(
            "target: linux\nmodules: []\nworkloads:\n  - include:\n      - stack: s.yaml\n        \
             as: s\n",
        )
        .err()
        .unwrap()
        .to_string();
        assert!(
            e.contains("still includes stacks"),
            "a workload's include too: {e}"
        );
    }

    #[test]
    fn a_package_graph_carries_a_workloads_include_expanded() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("s.yaml"),
            "stack: s\nexports:\n  out: a.out\nmodules:\n  - name: a\n    type: echo_worker\n",
        )
        .unwrap();
        let graph = dir.path().join("g.yaml");
        let text =
            "target: linux\nmodules: []\nworkloads:\n  - include:\n      - stack: s.yaml\n        \
                    as: s\n    modules: []\n";
        std::fs::write(&graph, text).unwrap();
        let (carried, _) = package_graph(&graph, text.to_string(), dir.path()).unwrap();
        let doc: serde_yaml::Value = serde_yaml::from_str(&carried).unwrap();
        let w = &doc["workloads"][0];
        assert!(w.get("include").is_none(), "{carried}");
        assert_eq!(w["modules"][0]["name"].as_str(), Some("s_a"), "{carried}");
        assert_eq!(w["modules"][0]["type"].as_str(), Some("echo_worker"));
    }

    /// `fluxor run <name>` looks the name up in the project the command runs
    /// in — its own packaging/ first, then its pins. A project nested inside
    /// another resolves to itself, not to the enclosing one.
    #[test]
    #[allow(
        clippy::undocumented_unsafe_blocks,
        reason = "env mutation serialised by project::tests::ENV_LOCK, as in project.rs"
    )]
    fn a_package_name_resolves_in_the_working_directorys_project() {
        let _g = crate::project::tests::ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let saved = std::env::var_os(crate::project::ENV_PROJECT_ROOT);
        unsafe { std::env::remove_var(crate::project::ENV_PROJECT_ROOT) };
        let tmp = tempfile::tempdir().unwrap();
        let outer = tmp.path().canonicalize().unwrap();
        let inner = outer.join("app");
        std::fs::create_dir(&inner).unwrap();
        std::fs::write(outer.join(".fluxor"), b"").unwrap();
        std::fs::write(inner.join(".fluxor"), b"").unwrap();
        let own = inner.join("packaging/applet/tool/workload.toml");
        std::fs::create_dir_all(own.parent().unwrap()).unwrap();
        std::fs::write(&own, "[workload]\nname = \"tool\"\n").unwrap();
        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&inner).unwrap();
        let refused = package_by_name("absent_package");
        let found = package_by_name("tool");
        std::env::set_current_dir(&cwd).unwrap();
        if let Some(v) = saved {
            unsafe { std::env::set_var(crate::project::ENV_PROJECT_ROOT, v) };
        }
        assert_eq!(
            found.unwrap(),
            own,
            "the project's own package, no pin needed"
        );
        let e = refused.err().unwrap().to_string();
        let lock = inner.join("fluxor.lock");
        assert!(e.contains(&format!("pinned in {} ", lock.display())), "{e}");
    }
}
