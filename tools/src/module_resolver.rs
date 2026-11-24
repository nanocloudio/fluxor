//! The one answer to "which artefact is module type T in variant V, for this
//! project and this module ABI".
//!
//! [`ModuleResolver::resolve`] returns a [`ModuleArtifact`]: its manifest
//! (variant applied), its `.fmod` (when built), its native-ness, its ISR
//! export and its source directory all come from that one value, read from
//! one origin. Nothing else in the tools opens a module's `manifest.toml` or
//! `.fmod` to find a module of a graph, reads `fluxor.lock` module pins, or
//! builds a `<type>-<variant>` name.
//!
//! Precedence, for `(T, V)` with key `K = artifact_name(T, V)`:
//!
//! 1. **Pins, authoritative for the type family.** A pin named `T` or
//!    `T-<v>` for any ABI makes the type pinned: the tree and the catalog are
//!    never consulted for it, and a miss is an error. The pin named `K` for
//!    this ABI answers; when `V` is set and no pin is named `K`, the pin
//!    named `T` answers exactly when `V` is its default variant. A module
//!    the project defines in its own tree and also pins from a dependency is
//!    refused as ambiguous.
//! 2. **The project's tree**: its module layers and the graph's
//!    `module_search_paths`, every one inside the project. A type in two of
//!    these places is refused as ambiguous.
//! 3. **Fluxor's catalog** (the install root), for native modules only.
//!
//! Nothing else is read: no working directory, no sibling checkout.

use crate::error::{Error, Result};
use crate::manifest::{Manifest, MODULE_LAYERS};
use crate::modules::ModuleInfo;
use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// The one name a module build is published, pinned and shelved under:
/// `<type>` for the default variant, `<type>-<variant>` otherwise.
pub fn artifact_name(type_name: &str, variant: Option<&str>) -> String {
    match variant {
        Some(v) => format!("{type_name}-{v}"),
        None => type_name.to_string(),
    }
}

/// Is `name` the artefact of `type_name` or of one of its variants. Sound
/// because a module type name never contains `-` (`modules_build` refuses
/// one), so `T-<v>` can only be a variant of `T`.
fn in_family(name: &str, type_name: &str) -> bool {
    name == type_name
        || name
            .strip_prefix(type_name)
            .and_then(|r| r.strip_prefix('-'))
            .is_some_and(|v| {
                !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
}

/// Which build of a module a resolution is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Abi {
    /// The module ABI a target loads (`TargetDescriptor::module_abi`).
    Module(String),
    /// No ABI: a member placed on another node, or a graph naming no target.
    /// Only manifests are asked, so every pin of an artefact must carry the
    /// same manifest, and no `.fmod` is read.
    Unplaced,
}

impl Abi {
    fn name(&self) -> Option<&str> {
        match self {
            Abi::Module(a) => Some(a),
            Abi::Unplaced => None,
        }
    }
}

/// Where a resolved module comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// A `fluxor.lock` module pin, served by the store.
    Pinned {
        reference: String,
        digest: String,
        project: String,
    },
    /// A module directory in this project's layers or on the graph's
    /// `module_search_paths`.
    Tree { dir: PathBuf },
    /// A native module directory in Fluxor's catalog (the install root).
    Catalog { dir: PathBuf },
}

/// One resolved module: manifest, bytes and facts from one origin.
#[derive(Debug)]
pub struct ModuleArtifact {
    pub type_name: String,
    pub variant: Option<String>,
    /// The artefact that resolved: `artifact_name(type, variant)`, or the
    /// bare type when `variant` is that type's default.
    pub artifact: String,
    pub origin: Origin,
    /// The artefact's manifest with `variant` applied, for the resolver's ABI.
    pub manifest: Manifest,
    fmod: Option<PathBuf>,
    info: OnceCell<ModuleInfo>,
}

impl ModuleArtifact {
    /// Built into the kernel: no `.fmod`, its params schema in its manifest.
    pub fn is_native(&self) -> bool {
        self.manifest.builtin
    }

    /// The module's source directory, for a module of a tree.
    pub fn source_dir(&self) -> Option<&Path> {
        match &self.origin {
            Origin::Tree { dir } | Origin::Catalog { dir } => Some(dir),
            Origin::Pinned { .. } => None,
        }
    }

    /// Whether a `.fmod` of this artefact is at hand.
    pub fn is_built(&self) -> bool {
        self.fmod.is_some()
    }

    /// The packed module, read once. `Ok(None)` for a native module; `Err`
    /// naming the artefact and the remedy when a PIC module has no build.
    pub fn module_info(&self) -> Result<Option<&ModuleInfo>> {
        if self.is_native() {
            return Ok(None);
        }
        if let Some(info) = self.info.get() {
            return Ok(Some(info));
        }
        let Some(path) = &self.fmod else {
            let why = match &self.origin {
                Origin::Tree { .. } => format!(
                    "is not built: run `fluxor modules build` (no {}.fmod on the module shelf)",
                    self.artifact
                ),
                Origin::Pinned { .. } => {
                    "was resolved without a module ABI, so it has no .fmod".to_string()
                }
                Origin::Catalog { .. } => "is a catalog module, which is never packed".to_string(),
            };
            return Err(Error::Module(format!("{} {why}", self.label())));
        };
        let info = ModuleInfo::from_file(path)
            .map_err(|e| Error::Module(format!("{} ({}): {e}", self.label(), self.from())))?;
        Ok(Some(self.info.get_or_init(|| info)))
    }

    /// Raw `define_params!` bytes of a built PIC module.
    pub fn schema_bytes(&self) -> Result<Option<&[u8]>> {
        Ok(self.module_info()?.and_then(|i| i.schema.as_deref()))
    }

    /// Whether the module exports `module_isr_entry`: the built `.fmod`'s
    /// header bit, else a scan of its source. `Err` when neither is at hand.
    pub fn exports_isr_entry(&self) -> Result<bool> {
        if self.fmod.is_some() {
            let info = self.module_info()?.expect("a built module is not native");
            return Ok(fluxor_abi::wire::fmod::header::Header::read(&info.data)
                .is_some_and(|h| h.flags & fluxor_abi::wire::fmod::header::flag::ISR != 0));
        }
        match self.source_dir() {
            Some(dir) => Ok(crate::manifest::check_module_exports_isr_entry(dir).is_ok()),
            None => Err(Error::Module(format!(
                "{} has neither a build nor a source tree, so its `module_isr_entry` export \
                 cannot be verified",
                self.label()
            ))),
        }
    }

    /// `module 'T'` or `module 'T' variant 'V'`, for messages.
    pub fn label(&self) -> String {
        match &self.variant {
            Some(v) => format!("module '{}' variant '{v}'", self.type_name),
            None => format!("module '{}'", self.type_name),
        }
    }

    /// Where it resolved, for messages.
    pub fn from(&self) -> String {
        match &self.origin {
            Origin::Pinned {
                reference, digest, ..
            } => format!("pin {reference} ({digest})"),
            Origin::Tree { dir } | Origin::Catalog { dir } => dir.display().to_string(),
        }
    }
}

/// The places a resolver reads, stated by its caller.
#[derive(Debug, Clone)]
pub struct ResolverSpec {
    /// The project the graph belongs to (`project::root_for_config`).
    pub project_root: PathBuf,
    pub abi: Abi,
    /// Where `fluxor modules build` shelves this project's `.fmod`s.
    pub shelf: Option<PathBuf>,
    /// The graph's `module_search_paths`, absolute; each must lie inside
    /// the project.
    pub search_paths: Vec<PathBuf>,
    /// Fluxor's catalog for this project (`project::install_root`).
    pub install_root: Option<PathBuf>,
    /// The OCI store; `None` is the configured one (`oci_store::store_root`).
    pub store_dir: Option<PathBuf>,
}

/// A `fluxor.lock` module pin.
type Pin = crate::store_resolve::Artifact;

type Answer = std::result::Result<Option<Rc<ModuleArtifact>>, String>;

/// Resolves the modules of one graph (or one project's stacks and packages).
pub struct ModuleResolver {
    spec: ResolverSpec,
    pins: Rc<Vec<Pin>>,
    store: Rc<OnceCell<std::result::Result<crate::oci_store::OciStore, String>>>,
    cache: RefCell<HashMap<(String, Option<String>), Answer>>,
}

impl ModuleResolver {
    /// The resolver for `spec`. Refuses a search path outside the project and
    /// a `fluxor.lock` that cannot be read.
    pub fn new(spec: ResolverSpec) -> Result<Self> {
        let project = spec
            .project_root
            .canonicalize()
            .unwrap_or_else(|_| spec.project_root.clone());
        let mut search_paths = Vec::new();
        for p in &spec.search_paths {
            let canon = p.canonicalize().unwrap_or_else(|_| p.clone());
            if !canon.starts_with(&project) {
                return Err(Error::Config(format!(
                    "module search path {} is outside project {}: a module of another \
                     project resolves from its pin — declare the dependency, run `fluxor \
                     update`, and drop the entry",
                    p.display(),
                    project.display()
                )));
            }
            if !search_paths.contains(&canon) {
                search_paths.push(canon);
            }
        }
        let lock = crate::store_resolve::read_store_lock(&project).map_err(|e| {
            Error::Config(format!(
                "{}/fluxor.lock is unreadable: {e}",
                project.display()
            ))
        })?;
        let mut pins = Vec::new();
        if let Some(lock) = lock {
            crate::store_resolve::check_module_pin_targets(&lock.artifacts)
                .map_err(|e| Error::Config(e.to_string()))?;
            pins.extend(lock.artifacts.into_iter().filter(|a| a.kind == "module"));
        }
        let install_root = spec
            .install_root
            .as_ref()
            .map(|p| p.canonicalize().unwrap_or_else(|_| p.clone()))
            .filter(|p| *p != project);
        Ok(ModuleResolver {
            spec: ResolverSpec {
                project_root: project,
                search_paths,
                install_root,
                ..spec
            },
            pins: Rc::new(pins),
            store: Rc::new(OnceCell::new()),
            cache: RefCell::new(HashMap::new()),
        })
    }

    /// The resolver for one graph: the project anchored at the config, the
    /// ABI of its target (none: [`Abi::Unplaced`]), the shelf `--module-root`
    /// / `$FLUXOR_MODULE_ROOT` / `target/fluxor/<abi>/modules`, the YAML's
    /// `module_search_paths` (config-relative), and the project's catalog.
    pub fn for_graph(
        config: &serde_json::Value,
        config_path: &Path,
        target: Option<&crate::target::TargetDescriptor>,
        module_root: Option<&Path>,
    ) -> Result<Self> {
        let project_root = crate::project::root_for_config(config_path);
        let config_dir = config_path.parent().unwrap_or(Path::new("."));
        let config_dir = if config_dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            config_dir
        };
        let search_paths = config
            .get("module_search_paths")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|e| e.as_str())
                    .map(|s| std::path::absolute(config_dir.join(s)).unwrap_or_default())
                    .collect()
            })
            .unwrap_or_default();
        let (abi, shelf) = match target {
            Some(desc) => (
                Abi::Module(desc.module_abi().to_string()),
                Some(crate::modules_build::select_module_root(
                    module_root,
                    project_root.join(crate::modules_build::modules_dir_for(desc)),
                )?),
            ),
            None => (Abi::Unplaced, None),
        };
        let install_root = crate::project::install_root(&project_root).map(|r| r.path);
        Self::new(ResolverSpec {
            project_root,
            abi,
            shelf,
            search_paths,
            install_root,
            store_dir: None,
        })
    }

    /// The resolver for a project's own stacks and packages: no graph
    /// search paths.
    pub fn for_project(project_root: &Path, abi: Abi, shelf: Option<PathBuf>) -> Result<Self> {
        Self::new(ResolverSpec {
            project_root: project_root.to_path_buf(),
            abi,
            shelf,
            search_paths: Vec::new(),
            install_root: crate::project::install_root(project_root).map(|r| r.path),
            store_dir: None,
        })
    }

    /// The same lock, store and roots with no ABI: for members placed on
    /// another node, whose manifests alone are asked.
    pub fn unplaced(&self) -> Self {
        ModuleResolver {
            spec: ResolverSpec {
                abi: Abi::Unplaced,
                shelf: None,
                ..self.spec.clone()
            },
            pins: Rc::clone(&self.pins),
            store: Rc::clone(&self.store),
            cache: RefCell::new(HashMap::new()),
        }
    }

    /// The places this resolver reads.
    pub fn spec(&self) -> &ResolverSpec {
        &self.spec
    }

    pub fn abi(&self) -> &Abi {
        &self.spec.abi
    }

    pub fn project_root(&self) -> &Path {
        &self.spec.project_root
    }

    /// `(T, V)` resolved: `Ok(None)` when nothing pins the type family and
    /// no root has `T`.
    pub fn resolve(
        &self,
        type_name: &str,
        variant: Option<&str>,
    ) -> Result<Option<Rc<ModuleArtifact>>> {
        let key = (type_name.to_string(), variant.map(str::to_string));
        if let Some(hit) = self.cache.borrow().get(&key) {
            return hit.clone().map_err(Error::Config);
        }
        let answer = self
            .resolve_uncached(type_name, variant)
            .map(|a| a.map(Rc::new))
            .map_err(|e| match e {
                Error::Config(m) | Error::Module(m) => m,
                other => other.to_string(),
            });
        self.cache.borrow_mut().insert(key, answer.clone());
        answer.map_err(Error::Config)
    }

    /// [`resolve`](Self::resolve), with absence an error naming everything
    /// searched. `label` names the instance.
    pub fn require(
        &self,
        label: &str,
        type_name: &str,
        variant: Option<&str>,
    ) -> Result<Rc<ModuleArtifact>> {
        let who = if label == type_name {
            format!("module '{label}'")
        } else {
            format!("module '{label}' (type '{type_name}')")
        };
        match self.resolve(type_name, variant) {
            Ok(Some(a)) => Ok(a),
            Ok(None) => Err(Error::Config(format!(
                "{who} resolves nowhere: {}",
                self.absence(type_name, variant)
            ))),
            Err(e) => Err(Error::Config(format!("{who}: {}", message(e)))),
        }
    }

    /// Why `T` resolved nowhere: every place searched, and the near misses.
    fn absence(&self, type_name: &str, variant: Option<&str>) -> String {
        let mut out = format!(
            "not pinned in fluxor.lock, {} (`fluxor inspect <graph>` shows where a graph's \
             modules resolve from)",
            self.searched().join(", ")
        );
        if let Some(dir) = self.catalog_dir(type_name) {
            out.push_str(&format!(
                "; {} is a module of Fluxor's catalog that is not native, so this project \
                 has no build of it — pin it from fluxor (`fluxor update`)",
                dir.display()
            ));
        }
        if let Some(shelf) = &self.spec.shelf {
            let bare = shelf.join(format!("{}.fmod", artifact_name(type_name, variant)));
            if bare.is_file() {
                out.push_str(&format!(
                    "; found only as a bare .fmod at {}, which carries no manifest to check \
                     its wiring against — pin it, or give its source",
                    bare.display()
                ));
            }
        }
        out
    }

    /// The places searched, in order.
    pub fn searched(&self) -> Vec<String> {
        let layers: Vec<&str> = MODULE_LAYERS
            .iter()
            .map(|l| l.trim_start_matches("modules/"))
            .collect();
        let mut out = vec![format!(
            "not under {}/modules/{{{}}}",
            self.spec.project_root.display(),
            layers.join(",")
        )];
        if !self.spec.search_paths.is_empty() {
            let s: Vec<String> = self
                .spec
                .search_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect();
            out.push(format!("not in module_search_paths [{}]", s.join(", ")));
        }
        match &self.spec.install_root {
            Some(i) => out.push(format!(
                "not a native module of Fluxor's catalog at {}",
                i.display()
            )),
            None => out.push("no Fluxor catalog found".to_string()),
        }
        out
    }

    /// Every module entry resolved strictly: one error listing every
    /// refusal and every absent module. An entry is a type name or a
    /// `{name, type, variant}` map; one image carries one build of a type,
    /// so a type named with two variants is refused.
    pub fn graph_modules(&self, entries: &[serde_json::Value]) -> Result<GraphModules> {
        let mut out = GraphModules {
            project_root: self.spec.project_root.clone(),
            ..GraphModules::default()
        };
        let mut errors = Vec::new();
        let mut variants: HashMap<String, Option<String>> = HashMap::new();
        for entry in entries {
            let Some((name, ty, variant)) = entry_identity(entry) else {
                errors.push(format!("module entry {entry} names no module"));
                continue;
            };
            match variants.get(ty) {
                Some(seen) if seen.as_deref() != variant => {
                    errors.push(format!(
                        "module type '{ty}' is used with conflicting variants ('{}' vs '{}') — \
                         one image carries one build of a module type; align the graph, its \
                         workloads and workload_modules on a single variant",
                        seen.as_deref().unwrap_or("<default>"),
                        variant.unwrap_or("<default>"),
                    ));
                    continue;
                }
                Some(_) => {}
                None => {
                    variants.insert(ty.to_string(), variant.map(str::to_string));
                }
            }
            match self.require(name, ty, variant) {
                Ok(a) => {
                    out.insert(name, a);
                }
                Err(e) => errors.push(message(e)),
            }
        }
        if errors.is_empty() {
            Ok(out)
        } else {
            errors.dedup();
            Err(Error::Config(errors.join("\n")))
        }
    }

    /// Every pin of `artifact` across ABIs, as the lock records them.
    pub fn pins_of(&self, artifact: &str) -> Vec<Pin> {
        self.pins
            .iter()
            .filter(|p| p.name == artifact)
            .cloned()
            .collect()
    }

    fn store(&self) -> Result<&crate::oci_store::OciStore> {
        self.store
            .get_or_init(|| {
                let root = match &self.spec.store_dir {
                    Some(d) => d.clone(),
                    None => crate::oci_store::store_root().map_err(|e| e.to_string())?,
                };
                crate::oci_store::OciStore::open(root).map_err(|e| e.to_string())
            })
            .as_ref()
            .map_err(|e| Error::Config(format!("cannot open the OCI store: {e}")))
    }

    /// The directories of the project's tree holding `T`.
    fn tree_dirs(&self, type_name: &str) -> Vec<PathBuf> {
        let mut found: Vec<PathBuf> = Vec::new();
        let layers = MODULE_LAYERS.iter().map(|l| self.spec.project_root.join(l));
        for root in layers.chain(self.spec.search_paths.iter().cloned()) {
            let dir = root.join(type_name);
            if dir.join("manifest.toml").is_file() {
                let canon = dir.canonicalize().unwrap_or(dir);
                if !found.contains(&canon) {
                    found.push(canon);
                }
            }
        }
        found
    }

    /// `T` in Fluxor's catalog, native or not.
    fn catalog_dir(&self, type_name: &str) -> Option<PathBuf> {
        let install = self.spec.install_root.as_ref()?;
        MODULE_LAYERS
            .iter()
            .map(|l| install.join(l).join(type_name))
            .find(|d| d.join("manifest.toml").is_file())
    }

    fn resolve_uncached(
        &self,
        type_name: &str,
        variant: Option<&str>,
    ) -> Result<Option<ModuleArtifact>> {
        let family: Vec<&Pin> = self
            .pins
            .iter()
            .filter(|p| in_family(&p.name, type_name))
            .collect();
        let tree = self.tree_dirs(type_name);
        if !family.is_empty() {
            if let Some(dir) = tree.first() {
                return Err(Error::Config(format!(
                    "module type '{type_name}' is ambiguous: the project defines it at {} and \
                     its fluxor.lock pins it from project '{}' ({}); rename the project's own \
                     module",
                    dir.display(),
                    family[0].project,
                    family[0].reference
                )));
            }
            return self.resolve_pinned(type_name, variant, &family).map(Some);
        }
        match tree.as_slice() {
            [] => {}
            [dir] => {
                return self
                    .materialise_dir(type_name, variant, dir, false)
                    .map(Some)
            }
            [a, b, ..] => {
                return Err(Error::Config(format!(
                    "module type '{type_name}' is ambiguous: the project has it at {} and at \
                     {}; only one of them can be the module `fluxor modules build` shelves",
                    a.display(),
                    b.display()
                )))
            }
        }
        if let Some(dir) = self.catalog_dir(type_name) {
            let a = self.materialise_dir(type_name, variant, &dir, true)?;
            if a.is_native() {
                return Ok(Some(a));
            }
        }
        Ok(None)
    }

    fn resolve_pinned(
        &self,
        type_name: &str,
        variant: Option<&str>,
        family: &[&Pin],
    ) -> Result<ModuleArtifact> {
        let key = artifact_name(type_name, variant);
        let usable: Vec<&Pin> = match &self.spec.abi {
            Abi::Module(a) => family
                .iter()
                .copied()
                .filter(|p| p.target.as_deref() == Some(a))
                .collect(),
            Abi::Unplaced => family.to_vec(),
        };
        if usable.is_empty() {
            let mut abis: Vec<&str> = family.iter().filter_map(|p| p.target.as_deref()).collect();
            abis.sort_unstable();
            abis.dedup();
            return Err(Error::Config(format!(
                "module '{type_name}' is pinned in fluxor.lock for {}, not {}; pin it for this \
                 target",
                abis.join(", "),
                self.spec.abi.name().unwrap_or("this target")
            )));
        }
        let named =
            |n: &str| -> Vec<&Pin> { usable.iter().copied().filter(|p| p.name == n).collect() };
        let (pins, via_bare) = match named(&key) {
            k if !k.is_empty() => (k, false),
            _ if variant.is_some() => (named(type_name), true),
            _ => (Vec::new(), false),
        };
        if pins.is_empty() {
            let mut names: Vec<&str> = usable.iter().map(|p| p.name.as_str()).collect();
            names.sort_unstable();
            names.dedup();
            return Err(Error::Config(format!(
                "module '{type_name}' is pinned as {}, not as {key}",
                names.join(", ")
            )));
        }
        let artifact = self.materialise_pin(type_name, variant, pins[0])?;
        if self.spec.abi == Abi::Unplaced {
            let text = self.pin_manifest_text(pins[0])?;
            for p in &pins[1..] {
                if self.pin_manifest_text(p)? != text {
                    return Err(Error::Config(format!(
                        "module '{key}' is pinned for several targets with differing manifests; \
                         name the target to resolve it"
                    )));
                }
            }
        }
        if via_bare && default_variant(&artifact.manifest) != variant {
            return Err(Error::Config(format!(
                "module '{type_name}' is pinned as {type_name}, not as {key}"
            )));
        }
        Ok(artifact)
    }

    /// The `manifest.toml` text a pin's artefact carries.
    fn pin_manifest_text(&self, pin: &Pin) -> Result<String> {
        let at = |why: String| {
            Error::Config(format!(
                "module '{}' is pinned in fluxor.lock but pin {} ({}) cannot be served: {why}",
                pin.name, pin.reference, pin.digest
            ))
        };
        let image = self.pin_image(pin).map_err(&at)?;
        let bytes = self
            .store()
            .map_err(|e| at(message(e)))?
            .module_manifest_toml_blob(&image)
            .map_err(|e| at(e.to_string()))?
            .ok_or_else(|| at("its artefact carries no manifest.toml layer".to_string()))?;
        String::from_utf8(bytes)
            .map_err(|e| at(format!("its manifest.toml layer is not UTF-8: {e}")))
    }

    fn pin_image(&self, pin: &Pin) -> std::result::Result<crate::oci_store::ImageManifest, String> {
        let store = self.store().map_err(message)?;
        let bytes = store.read_blob(&pin.digest).map_err(|e| e.to_string())?;
        serde_json::from_slice(&bytes).map_err(|e| format!("corrupt manifest: {e}"))
    }

    /// One pin's artefact: its manifest layer and its `.fmod` layer, from one
    /// image manifest.
    fn materialise_pin(
        &self,
        type_name: &str,
        variant: Option<&str>,
        pin: &Pin,
    ) -> Result<ModuleArtifact> {
        let label = format!("pin {} ({})", pin.reference, pin.digest);
        let text = self.pin_manifest_text(pin)?;
        let manifest = accept(&text, self.spec.abi.name(), variant).map_err(|why| {
            Error::Config(format!(
                "module '{type_name}' is pinned in fluxor.lock but its pinned manifest ({label}) \
                 is rejected: {why}"
            ))
        })?;
        let fmod = match &self.spec.abi {
            Abi::Unplaced => None,
            Abi::Module(_) => {
                let image = self.pin_image(pin).map_err(Error::Config)?;
                let (_, path) = self
                    .store()?
                    .module_fmod_blob(&image)
                    .map_err(|e| Error::Config(format!("{label}: {e}")))?;
                Some(path)
            }
        };
        Ok(ModuleArtifact {
            type_name: type_name.to_string(),
            variant: variant.map(str::to_string),
            artifact: pin.name.clone(),
            origin: Origin::Pinned {
                reference: pin.reference.clone(),
                digest: pin.digest.clone(),
                project: pin.project.clone(),
            },
            manifest,
            fmod,
            info: OnceCell::new(),
        })
    }

    /// A module directory's artefact: its `manifest.toml`, and the shelf's
    /// `.fmod` of the same artefact name.
    fn materialise_dir(
        &self,
        type_name: &str,
        variant: Option<&str>,
        dir: &Path,
        catalog: bool,
    ) -> Result<ModuleArtifact> {
        let path = dir.join("manifest.toml");
        let manifest = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read it: {e}"))
            .and_then(|text| {
                let m = accept(&text, self.spec.abi.name(), None)?;
                if m.builtin {
                    if let Some(v) = variant {
                        return Err(format!(
                            "variant '{v}' requested, but the type is built into the kernel — \
                             native modules have no variants; drop `variant:`"
                        ));
                    }
                    return Ok(m);
                }
                accept(&text, self.spec.abi.name(), variant)
            })
            .map_err(|why| {
                Error::Config(format!(
                    "module '{type_name}' was found at {} but its manifest is rejected: {why}",
                    path.display()
                ))
            })?;
        let artifact = if variant.is_none() || default_variant(&manifest) == variant {
            type_name.to_string()
        } else {
            artifact_name(type_name, variant)
        };
        let fmod = match (&self.spec.shelf, manifest.builtin || catalog) {
            (Some(shelf), false) => {
                Some(shelf.join(format!("{artifact}.fmod"))).filter(|p| p.is_file())
            }
            _ => None,
        };
        let dir = dir.to_path_buf();
        Ok(ModuleArtifact {
            type_name: type_name.to_string(),
            variant: variant.map(str::to_string),
            artifact,
            origin: if catalog {
                Origin::Catalog { dir }
            } else {
                Origin::Tree { dir }
            },
            manifest,
            fmod,
            info: OnceCell::new(),
        })
    }
}

/// The modules of one graph, by instance name.
#[derive(Default)]
pub struct GraphModules {
    by_name: HashMap<String, Rc<ModuleArtifact>>,
    /// Distinct artefacts in first-use order, one per type.
    order: Vec<Rc<ModuleArtifact>>,
    project_root: PathBuf,
}

impl GraphModules {
    fn insert(&mut self, name: &str, a: Rc<ModuleArtifact>) {
        if !self.order.iter().any(|o| o.type_name == a.type_name) {
            self.order.push(Rc::clone(&a));
        }
        self.by_name.insert(name.to_string(), a);
    }

    /// The project the modules were resolved for.
    pub fn project_root(&self) -> &Path {
        &self.project_root
    }

    pub fn get(&self, name: &str) -> Option<&Rc<ModuleArtifact>> {
        self.by_name.get(name)
    }

    /// Instance name → manifest, the map the graph validators read.
    pub fn manifests(&self) -> HashMap<String, Manifest> {
        self.by_name
            .iter()
            .map(|(n, a)| (n.clone(), a.manifest.clone()))
            .collect()
    }

    /// Add the modules of `types` (`tee`, `merge`: the fans a composed graph
    /// runs) not already present.
    pub fn add_types(&mut self, r: &ModuleResolver, types: &[&str]) -> Result<()> {
        for ty in types {
            if self.order.iter().any(|a| a.type_name == *ty) {
                continue;
            }
            let a = r.require(ty, ty, None)?;
            self.insert(ty, a);
        }
        Ok(())
    }

    /// The image's module table: each PIC type's packed module once, built
    /// against the current ABI surface.
    pub fn table(&self) -> Result<Vec<ModuleInfo>> {
        let mut out = Vec::new();
        for a in &self.order {
            let Some(info) = a.module_info()? else {
                continue;
            };
            verify_abi_surface(info, a)?;
            out.push(info.clone());
        }
        Ok(out)
    }

    /// Every distinct artefact, one per type, in first-use order.
    pub fn artifacts(&self) -> &[Rc<ModuleArtifact>] {
        &self.order
    }
}

/// Require a packed module's ABI-surface attestation to equal the current
/// surface: a module built against another surface would be refused by the
/// device at load.
fn verify_abi_surface(info: &ModuleInfo, a: &ModuleArtifact) -> Result<()> {
    let current = crate::hash::abi_surface_digest();
    match info.manifest.abi_surface {
        Some(packed) if packed == current => Ok(()),
        Some(packed) => Err(Error::Module(format!(
            "{} ({}): built against a different ABI surface (module attests {}, current is \
             {}) — rebuild it with `fluxor modules build`. See docs/architecture/abi_surface.md",
            a.label(),
            a.from(),
            crate::hash::hex(&packed[..6]),
            crate::hash::hex(&current[..6]),
        ))),
        None => Err(Error::Module(format!(
            "{} ({}): carries no ABI-surface attestation — rebuild it with `fluxor modules \
             build`. See docs/architecture/abi_surface.md",
            a.label(),
            a.from(),
        ))),
    }
}

/// `(name, type, variant)` of a module entry: a type name, or a map with a
/// `name`, an optional `type` (defaulting to the name) and `variant`.
pub fn entry_identity(entry: &serde_json::Value) -> Option<(&str, &str, Option<&str>)> {
    if let Some(s) = entry.as_str() {
        return Some((s, s, None));
    }
    let name = entry
        .get("name")
        .and_then(|v| v.as_str())
        .or_else(|| entry.get("type").and_then(|v| v.as_str()))?;
    let ty = entry.get("type").and_then(|v| v.as_str()).unwrap_or(name);
    Some((name, ty, entry.get("variant").and_then(|v| v.as_str())))
}

/// Every module entry a node image carries: the graph's `modules:`, each
/// resident workload's modules, and the `workload_modules:` types a workload
/// may be staged with at run time.
pub fn image_entries(config: &serde_json::Value) -> Result<Vec<serde_json::Value>> {
    let mut out: Vec<serde_json::Value> = config
        .get("modules")
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default();
    if let Some(workloads) = config.get("workloads").and_then(|w| w.as_array()) {
        for (pi, w) in workloads.iter().enumerate() {
            for (li, m) in w
                .get("modules")
                .and_then(|m| m.as_array())
                .into_iter()
                .flatten()
                .enumerate()
            {
                let mut m = m.clone();
                if let Some(obj) = m.as_object_mut() {
                    let ty = obj
                        .get("type")
                        .or_else(|| obj.get("name"))
                        .cloned()
                        .unwrap_or_default();
                    obj.insert("type".into(), ty);
                    obj.insert(
                        "name".into(),
                        serde_json::Value::String(format!("__workload{pi}__m{li}")),
                    );
                }
                out.push(m);
            }
        }
    }
    if let Some(list) = config.get("workload_modules").and_then(|l| l.as_array()) {
        for (i, m) in list.iter().enumerate() {
            let (ty, variant) = if let Some(t) = m.as_str() {
                (t, None)
            } else if let Some(t) = m.get("type").and_then(|t| t.as_str()) {
                (t, m.get("variant").cloned())
            } else {
                return Err(Error::Config(format!(
                    "workload_modules entry {m} names no module type: give a type name or \
                     {{type, variant}}"
                )));
            };
            let mut e = serde_json::json!({ "name": format!("__staged{i}"), "type": ty });
            if let Some(v) = variant {
                e["variant"] = v;
            }
            out.push(e);
        }
    }
    Ok(out)
}

/// The variant a manifest's plain `<type>.fmod` carries.
fn default_variant(m: &Manifest) -> Option<&str> {
    m.variants
        .iter()
        .find(|v| v.default)
        .map(|v| v.name.as_str())
}

/// A manifest's text parsed for `abi` with `variant` applied.
fn accept(
    text: &str,
    abi: Option<&str>,
    variant: Option<&str>,
) -> std::result::Result<Manifest, String> {
    let mut m = Manifest::from_toml_str_for_target(text, abi).map_err(message)?;
    if let Some(v) = variant {
        m.apply_variant(v).map_err(message)?;
    }
    Ok(m)
}

/// An error's message without its kind's prefix.
fn message(e: Error) -> String {
    match e {
        Error::Config(m) | Error::Module(m) => m,
        other => other.to_string(),
    }
}
