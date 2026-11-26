//! What a project ships, and only that: everything under `packaging/`.
//!
//! ```text
//! <project>/
//!   packaging/
//!     stack/<name>.yaml             published stacks
//!     service/<name>/workload.toml  service workload packages (graph beside it)
//!     applet/<name>/workload.toml   applet (CLI) workload packages
//! ```
//!
//! [`discover`] is the one discovery: `fluxor publish` publishes exactly
//! what it finds, and `fluxor ci` checks exactly that, the way the publish
//! will read it ([`check_package`], [`crate::stack::check_publishable`]). A
//! directory with its own `fluxor.toml` or `.fluxor` is another project and
//! ships its own. Graphs anywhere else — examples, tests — are never
//! published, though a graph anywhere may include a packaged stack by path.
//!
//! A workload package's `workload.toml` carries identity only: `[workload]` name,
//! version and role, and one `[[implementation]]` per target naming its
//! graph. The package's params are its graph's `params:`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::params::{self, ParamSpec};

/// Where a project's published stacks live.
pub const STACK_DIR: &str = "packaging/stack";
/// Where a project's service workload packages live, one directory each.
pub const SERVICE_DIR: &str = "packaging/service";
/// Where a project's applet (CLI) workload packages live, one directory each.
pub const APPLET_DIR: &str = "packaging/applet";
/// A package's source manifest, in its own directory.
pub const PACKAGE_MANIFEST: &str = "workload.toml";

/// What kind of package a directory holds: the `role` its manifest must
/// declare.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `packaging/service/<name>/`, `role = "service"`.
    Service,
    /// `packaging/applet/<name>/`, `role = "cli"`.
    Applet,
}

impl Kind {
    /// The `role` a manifest of this kind declares.
    pub fn role(self) -> &'static str {
        match self {
            Kind::Service => "service",
            Kind::Applet => "cli",
        }
    }

    fn dir(self) -> &'static str {
        match self {
            Kind::Service => SERVICE_DIR,
            Kind::Applet => APPLET_DIR,
        }
    }
}

/// Everything a project ships, each list sorted.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Shippables {
    /// `packaging/stack/*.yaml`.
    pub stacks: Vec<PathBuf>,
    /// `packaging/{service,applet}/*/workload.toml`, services first.
    pub packages: Vec<(Kind, PathBuf)>,
}

fn entries(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    out.sort();
    out
}

/// The project's shippables: exactly `packaging/stack/*.yaml`,
/// `packaging/service/*/workload.toml` and `packaging/applet/*/workload.toml`,
/// none inside a nested project.
pub fn discover(project_root: &Path) -> Shippables {
    let own = |p: &PathBuf| p.is_file() && crate::project::is_own_file(project_root, p);
    let stacks = entries(&project_root.join(STACK_DIR))
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .filter(own)
        .collect();
    let mut packages = Vec::new();
    for kind in [Kind::Service, Kind::Applet] {
        packages.extend(
            entries(&project_root.join(kind.dir()))
                .into_iter()
                .map(|d| d.join(PACKAGE_MANIFEST))
                .filter(own)
                .map(|p| (kind, p)),
        );
    }
    Shippables { stacks, packages }
}

/// Where the project's own stack `name` lives.
pub fn stack_path(project_root: &Path, name: &str) -> PathBuf {
    project_root.join(STACK_DIR).join(format!("{name}.yaml"))
}

/// The project's own package `name`, service or applet, when it ships one.
pub fn package_path(project_root: &Path, name: &str) -> Option<PathBuf> {
    if !crate::workload::is_workload_name(name) {
        return None;
    }
    [Kind::Service, Kind::Applet]
        .iter()
        .map(|k| project_root.join(k.dir()).join(name).join(PACKAGE_MANIFEST))
        .find(|p| p.is_file() && crate::project::is_own_file(project_root, p))
}

/// `[workload]` — identity + role. `service` implementations carry the
/// health/update contract and the lease/drain machinery; `cli` carries the
/// stdio/exit surface (argv after `--`, stdout/stderr, exit code). `role`
/// accepts only `service` or `cli`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadTable {
    pub name: String,
    pub version: String,
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "service".to_string()
}

/// `[[implementation]]` — one per-target graph file, referenced whole and
/// never merged with anything.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationTable {
    pub target: String,
    pub graph: String,
}

/// `[[export]]` — a declared endpoint plus its graph binding (the binding is
/// not derivable from the graph; `validate()` requires one per export).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportTable {
    pub name: String,
    pub protocol: String,
    pub port: u16,
    pub binding: String,
}

/// `[resources]` — the non-derivable footprint overrides. Module and edge
/// counts are derived from the graph; these are capacity declarations.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcesTable {
    pub state_bytes: Option<u32>,
    pub buffer_bytes: Option<u32>,
    pub endpoints: Option<u16>,
    pub domains: Option<u8>,
}

/// `[health]` — contract signal names bind to graph targets. Defaults:
/// signals `<name>.ready`/`<name>.progress` bound to the first graph
/// module's `ready`/`progress`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthTable {
    pub readiness: Option<String>,
    pub liveness: Option<String>,
}

/// A package's source manifest, `workload.toml`: identity, one
/// `[[implementation]]` per target, and what the graph cannot declare
/// (`[[export]]`, `[resources]`, `[health]`). Unknown keys are refused.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceManifest {
    pub workload: WorkloadTable,
    #[serde(default, rename = "implementation")]
    pub implementations: Vec<ImplementationTable>,
    #[serde(default, rename = "export")]
    pub exports: Vec<ExportTable>,
    #[serde(default)]
    pub resources: ResourcesTable,
    #[serde(default)]
    pub health: HealthTable,
}

/// Parse and check a source manifest: its shape, a workload name, a role of
/// `service` or `cli`, and at least one implementation. A `[params]` table is
/// refused: a package's params are its graph's `params:`. The one reader of
/// `workload.toml`, so what `fluxor ci` and the publish sweep check is what
/// the package emission reads.
pub fn parse_source_manifest(text: &str) -> Result<SourceManifest, String> {
    if toml::from_str::<toml::Table>(text).is_ok_and(|t| t.contains_key("params")) {
        return Err(
            "source manifest: `[params]` belongs to the graph — declare each under `params:` \
             in the graph YAML the `[[implementation]]` names, with the same fields"
                .into(),
        );
    }
    let m: SourceManifest = toml::from_str(text).map_err(|e| format!("source manifest: {e}"))?;
    if !crate::workload::is_workload_name(&m.workload.name) {
        return Err(format!(
            "workload.name '{}' is not a workload name (ASCII letters, digits, '.', '_' or '-', \
             starting with a letter or digit, at most 64 bytes)",
            m.workload.name
        ));
    }
    if m.workload.role != "service" && m.workload.role != "cli" {
        return Err(format!(
            "workload.role must be 'service' or 'cli' (got '{}')",
            m.workload.role
        ));
    }
    if m.implementations.is_empty() {
        return Err("source manifest declares no [[implementation]]".into());
    }
    Ok(m)
}

/// The identity a package's source manifest declares.
#[derive(Clone, Debug)]
pub struct PackageSource {
    pub name: String,
    pub role: String,
    /// `(target, graph path)` per `[[implementation]]`, the path resolved
    /// against the manifest's directory.
    pub implementations: Vec<(String, PathBuf)>,
}

/// Read a package source manifest's identity ([`parse_source_manifest`]),
/// each graph path resolved against the manifest's directory.
pub fn read_package(path: &Path) -> Result<PackageSource, String> {
    let at = |e: String| format!("{}: {e}", path.display());
    let text = std::fs::read_to_string(path).map_err(|e| at(e.to_string()))?;
    let m = parse_source_manifest(&text).map_err(at)?;
    let dir = path.parent().unwrap_or(Path::new("."));
    Ok(PackageSource {
        name: m.workload.name,
        role: m.workload.role,
        implementations: m
            .implementations
            .into_iter()
            .map(|i| (i.target, dir.join(i.graph)))
            .collect(),
    })
}

/// A package's params: its linux graphs' `params:`, which every linux
/// implementation declares alike. An applet's graph declares none: it takes
/// argv.
pub fn package_params(
    src: &PackageSource,
    graphs: &[BTreeMap<String, ParamSpec>],
) -> Result<BTreeMap<String, ParamSpec>, String> {
    let first = graphs.first().cloned().unwrap_or_default();
    if graphs.iter().any(|g| g != &first) {
        return Err(format!(
            "workload package '{}': its linux graphs declare different `params:`; one package has one \
             set of params",
            src.name
        ));
    }
    if src.role == "cli" && !first.is_empty() {
        return Err(format!(
            "workload package '{}' is an applet (role = \"cli\") and its graph declares `params:`; an \
             applet takes argv",
            src.name
        ));
    }
    Ok(first)
}

/// A package source manifest checked the way the publish reads it: its
/// identity, its place (`packaging/<service|applet>/<name>/workload.toml`
/// of `project_root`, with the role its directory names), and each linux
/// graph read with its includes expanded and rendered with its params'
/// defaults and examples. Returns `(graph path, rendered expanded graph)`
/// per linux implementation, for `fluxor build --check`.
pub fn check_package(path: &Path, project_root: &Path) -> Result<Vec<(PathBuf, String)>, String> {
    let src = read_package(path)?;
    let at = |e: String| format!("{}: {e}", path.display());
    if !crate::workload::is_workload_name(&src.name) {
        return Err(at(format!(
            "workload name '{}' is not a workload name",
            src.name
        )));
    }
    let kind = kind_of(path, project_root);
    let expected = project_root
        .join(kind.dir())
        .join(&src.name)
        .join(PACKAGE_MANIFEST);
    if std::path::absolute(&expected).ok() != std::path::absolute(path).ok() {
        return Err(at(format!(
            "workload package '{}' publishes from {} — a package's directory under packaging/service/ or \
             packaging/applet/ is named for it",
            src.name,
            expected.display()
        )));
    }
    if src.role != kind.role() {
        return Err(at(format!(
            "role '{}' under {}; a package there declares role = \"{}\"",
            src.role,
            kind.dir(),
            kind.role()
        )));
    }
    let linux: Vec<&PathBuf> = src
        .implementations
        .iter()
        .filter(|(t, _)| t == "linux")
        .map(|(_, g)| g)
        .collect();
    if linux.is_empty() {
        return Err(at("no linux implementation to check".into()));
    }
    let mut read = Vec::new();
    for graph in &linux {
        let (doc, declared) = crate::stack::read_expanded(graph, project_root, None)
            .map_err(|e| format!("{}: {e}", graph.display()))?;
        read.push((graph, doc, declared));
    }
    let declared: Vec<_> = read.iter().map(|(_, _, p)| p.clone()).collect();
    package_params(&src, &declared).map_err(at)?;
    read.into_iter()
        .map(|(graph, doc, declared)| {
            let values = params::check_values(&declared, crate::stack::graph_dir(graph))?;
            let yaml = serde_yaml::to_value(&doc).map_err(|e| e.to_string())?;
            let rendered = params::render(&yaml, &values)?;
            serde_yaml::to_string(&rendered)
                .map(|t| ((*graph).clone(), t))
                .map_err(|e| e.to_string())
        })
        .collect::<Result<Vec<_>, String>>()
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// The kind of package directory `path` sits in, by its grandparent.
fn kind_of(path: &Path, project_root: &Path) -> Kind {
    let parent = path.parent().and_then(Path::parent);
    if parent.is_some_and(|p| p == project_root.join(APPLET_DIR)) {
        Kind::Applet
    } else {
        Kind::Service
    }
}

// ============================================================================
// Applet builds
// ============================================================================
//
// An applet's graph is checked when its package is emitted, and every
// `fluxor exec` of it composes the image it runs. What differs per
// operator is given to that image at exec: the operator's client identity
// (`--identity`, else `$HOME/.config/<name>/client.der` + `client.key.der`)
// and the applet's own data directory, which the graph names with
// [`APPLET_DATA_DIR`]. The composer learns that the graph it composes is an
// applet's from [`with_applet`], which the package emission and each
// launch's composition wrap around the build: the rules that hold only for
// an applet's graph key on it.

/// The applet's own data directory, as a graph names it: a string param
/// whose value is this placeholder, or begins with it and a `/`, is given
/// the directory [`applet_data_dir`] resolves when `fluxor exec` runs the
/// applet. Only an applet's graph names it.
pub const APPLET_DATA_DIR: &str = "${applet:data_dir}";

/// What every applet placeholder begins with.
const APPLET_PLACEHOLDER: &str = "${applet:";

thread_local! {
    /// The applet whose graph is being built; `None` outside [`with_applet`].
    static APPLET: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Run `f` (the build of applet `name`'s graph) as an applet build.
pub fn with_applet<R>(name: &str, f: impl FnOnce() -> R) -> R {
    let outer = APPLET.with(|a| a.replace(Some(name.to_string())));
    let r = f();
    APPLET.with(|a| a.replace(outer));
    r
}

/// The applet whose graph is being built, inside [`with_applet`].
pub fn applet_being_built() -> Option<String> {
    APPLET.with(|a| a.borrow().clone())
}

/// Refuse an applet placeholder `doc` may not carry: any, outside an applet
/// build; inside one, any but [`APPLET_DATA_DIR`] at the start of a value,
/// alone or followed by a `/`.
pub fn check_applet_placeholders(doc: &serde_json::Value) -> Result<(), String> {
    fn walk(v: &serde_json::Value, applet: Option<&str>) -> Result<(), String> {
        match v {
            serde_json::Value::String(s) => check(s, applet),
            serde_json::Value::Array(a) => a.iter().try_for_each(|x| walk(x, applet)),
            serde_json::Value::Object(o) => o.iter().try_for_each(|(k, x)| {
                if k.contains(APPLET_PLACEHOLDER) {
                    return Err(format!(
                        "`{k}`: an applet placeholder names a value, never a key"
                    ));
                }
                walk(x, applet)
            }),
            _ => Ok(()),
        }
    }
    fn check(s: &str, applet: Option<&str>) -> Result<(), String> {
        if !s.contains(APPLET_PLACEHOLDER) {
            return Ok(());
        }
        if applet.is_none() {
            return Err(format!(
                "\"{s}\": `{APPLET_PLACEHOLDER}…}}` is given by `fluxor exec` to a cli applet, \
                 and this graph is not built as one: only the graph of a `role = \"cli\"` \
                 package, built from its workload.toml (`fluxor build`, `fluxor install` or \
                 `fluxor exec` of the package), may name `{APPLET_DATA_DIR}`"
            ));
        }
        let well_placed = s.strip_prefix(APPLET_DATA_DIR).is_some_and(|rest| {
            (rest.is_empty() || rest.starts_with('/')) && !rest.contains(APPLET_PLACEHOLDER)
        });
        if !well_placed {
            return Err(format!(
                "\"{s}\": the one applet placeholder is `{APPLET_DATA_DIR}`, at the start of a \
                 value: `{APPLET_DATA_DIR}` or `{APPLET_DATA_DIR}/<path>`"
            ));
        }
        Ok(())
    }
    let applet = applet_being_built();
    walk(doc, applet.as_deref())
}

/// The data directory of applet `name`, from the environment `var` reads:
/// `$XDG_DATA_HOME/<name>` when that is an absolute path, else
/// `$HOME/.local/share/<name>`. No trailing separator.
pub fn applet_data_dir(
    name: &str,
    var: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<PathBuf, String> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(format!(
            "applet name '{name}' cannot name a directory of its own"
        ));
    }
    let absolute = |k: &str| {
        var(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    if let Some(xdg) = absolute("XDG_DATA_HOME") {
        return Ok(xdg.join(name));
    }
    match absolute("HOME") {
        Some(home) => Ok(home.join(".local/share").join(name)),
        None => Err(format!(
            "applet '{name}' names `{APPLET_DATA_DIR}`, and neither $XDG_DATA_HOME nor $HOME \
             is an absolute path to put it under"
        )),
    }
}

/// [`applet_data_dir`], made on first use: its parents as the umask has
/// them, the directory itself readable by its owner alone. One that exists
/// is kept as it is.
pub fn ensure_applet_data_dir(
    name: &str,
    var: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<PathBuf, String> {
    use std::os::unix::fs::DirBuilderExt;
    let dir = applet_data_dir(name, var)?;
    if dir.is_dir() {
        return Ok(dir);
    }
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => Ok(dir),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && dir.is_dir() => Ok(dir),
        Err(e) => Err(format!("{}: {e}", dir.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, text: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    const PACKAGE: &str =
        "[workload]\nname = \"N\"\nversion = \"1\"\nrole = \"R\"\n\n[[implementation]]\n\
         target = \"linux\"\ngraph = \"linux.yaml\"\n";

    fn package(root: &Path, dir: &str, name: &str, role: &str) {
        write(
            root,
            &format!("{dir}/{name}/workload.toml"),
            &PACKAGE
                .replace("\"N\"", &format!("\"{name}\""))
                .replace("\"R\"", &format!("\"{role}\"")),
        );
        write(
            root,
            &format!("{dir}/{name}/linux.yaml"),
            "target: linux\nmodules:\n  - name: out\n    type: cli_out\n",
        );
    }

    #[test]
    fn discovery_finds_exactly_the_packaging_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "fluxor.toml", "[project]\nname = \"p\"\n");
        write(root, "packaging/stack/a.yaml", "stack: a\nmodules: [x]\n");
        write(root, "packaging/stack/b.yaml", "stack: b\nmodules: [x]\n");
        package(root, "packaging/service", "svc", "service");
        package(root, "packaging/applet", "tool", "cli");
        // Not shippables: another extension, a nested stack directory, the
        // flat package form, a stack elsewhere, examples, a nested project.
        write(root, "packaging/stack/c.yml", "stack: c\nmodules: [x]\n");
        write(
            root,
            "packaging/stack/deep/d.yaml",
            "stack: d\nmodules: [x]\n",
        );
        write(root, "packaging/service/workload.toml", PACKAGE);
        write(root, "stacks/e.yaml", "stack: e\nmodules: [x]\n");
        package(root, "examples", "demo", "service");
        write(root, "examples/demo/stack.yaml", "stack: s\nmodules: [x]\n");
        package(root, "packaging/service", "inner", "service");
        write(root, "packaging/service/inner/.fluxor", "");
        write(
            root,
            "packaging/applet/nested/fluxor.toml",
            "[project]\nname = \"n\"\n",
        );
        package(root, "packaging/applet", "nested", "cli");

        let s = discover(root);
        assert_eq!(
            s.stacks,
            vec![
                root.join("packaging/stack/a.yaml"),
                root.join("packaging/stack/b.yaml")
            ]
        );
        assert_eq!(
            s.packages,
            vec![
                (
                    Kind::Service,
                    root.join("packaging/service/svc/workload.toml")
                ),
                (
                    Kind::Applet,
                    root.join("packaging/applet/tool/workload.toml")
                ),
            ]
        );
        assert_eq!(
            package_path(root, "tool"),
            Some(root.join("packaging/applet/tool/workload.toml"))
        );
        assert_eq!(package_path(root, "demo"), None);
        assert_eq!(package_path(root, "inner"), None);
    }

    #[test]
    fn a_package_is_checked_at_its_place_with_its_role() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        package(root, "packaging/service", "svc", "service");
        package(root, "packaging/applet", "tool", "cli");
        let checked =
            check_package(&root.join("packaging/service/svc/workload.toml"), root).unwrap();
        assert_eq!(checked.len(), 1);
        check_package(&root.join("packaging/applet/tool/workload.toml"), root).unwrap();

        package(root, "packaging/applet", "wrong", "service");
        let e =
            check_package(&root.join("packaging/applet/wrong/workload.toml"), root).unwrap_err();
        assert!(e.contains("declares role = \"cli\""), "{e}");

        write(
            root,
            "packaging/service/other/workload.toml",
            &PACKAGE
                .replace("\"N\"", "\"svc2\"")
                .replace("\"R\"", "\"service\""),
        );
        let e =
            check_package(&root.join("packaging/service/other/workload.toml"), root).unwrap_err();
        assert!(e.contains("named for it"), "{e}");
    }

    #[test]
    fn workload_params_belong_to_the_graph() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("workload.toml");
        std::fs::write(
            &p,
            format!("{PACKAGE}\n[params.port]\ntype = \"integer\"\ndefault = 1\n"),
        )
        .unwrap();
        let e = read_package(&p).unwrap_err();
        assert!(e.contains("`[params]` belongs to the graph"), "{e}");
    }

    #[test]
    fn an_applet_graph_declares_no_params() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        package(root, "packaging/applet", "tool", "cli");
        write(
            root,
            "packaging/applet/tool/linux.yaml",
            "target: linux\nparams:\n  n: {type: integer, default: 1}\nmodules:\n  - name: out\n    \
             type: cli_out\n    level: ${param:n}\n",
        );
        let e = check_package(&root.join("packaging/applet/tool/workload.toml"), root).unwrap_err();
        assert!(e.contains("an applet takes argv"), "{e}");
    }

    /// `${applet:data_dir}` is `$XDG_DATA_HOME/<name>` when that is
    /// absolute, else `$HOME/.local/share/<name>`; a relative or empty
    /// variable is passed over, and a name that is no single directory
    /// component is refused.
    #[test]
    fn an_applets_data_dir_follows_the_xdg_base_directories() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| std::ffi::OsString::from(v))
            }
        };
        let both = env(&[("XDG_DATA_HOME", "/x/data"), ("HOME", "/home/op")]);
        assert_eq!(
            applet_data_dir("phasor", both).unwrap(),
            PathBuf::from("/x/data/phasor")
        );
        let home = env(&[("HOME", "/home/op")]);
        assert_eq!(
            applet_data_dir("phasor", home).unwrap(),
            PathBuf::from("/home/op/.local/share/phasor")
        );
        let relative = env(&[("XDG_DATA_HOME", "data"), ("HOME", "/home/op")]);
        assert_eq!(
            applet_data_dir("phasor", relative).unwrap(),
            PathBuf::from("/home/op/.local/share/phasor")
        );
        let empty = env(&[("XDG_DATA_HOME", ""), ("HOME", "/home/op")]);
        assert_eq!(
            applet_data_dir("phasor", empty).unwrap(),
            PathBuf::from("/home/op/.local/share/phasor")
        );
        let e = applet_data_dir("phasor", env(&[])).unwrap_err();
        assert!(e.contains("neither $XDG_DATA_HOME nor $HOME"), "{e}");
        for bad in ["", ".", "..", "a/b"] {
            assert!(
                applet_data_dir(bad, env(&[("HOME", "/h")])).is_err(),
                "{bad:?}"
            );
        }
    }

    /// The directory is made on first use, owner-only, and one that exists
    /// is kept as it is.
    #[test]
    fn an_applets_data_dir_is_made_owner_only_on_first_use() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("share").into_os_string();
        let var = move |k: &str| (k == "XDG_DATA_HOME").then(|| base.clone());
        let dir = ensure_applet_data_dir("tool", &var).unwrap();
        assert_eq!(dir, tmp.path().join("share/tool"));
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        std::fs::write(dir.join("kept"), b"x").unwrap();
        assert_eq!(ensure_applet_data_dir("tool", &var).unwrap(), dir);
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o750, "an existing directory is kept as it is");
        assert!(dir.join("kept").is_file());
    }

    /// Outside an applet build any applet placeholder is refused, naming why;
    /// inside one only `${applet:data_dir}` at the start of a value is
    /// taken.
    #[test]
    fn applet_placeholders_are_an_applet_graphs_alone() {
        let graph = |dir: &str| serde_json::json!({"modules": [{"name": "store", "dir": dir, "params": {}}]});
        let e = check_applet_placeholders(&graph("${applet:data_dir}")).unwrap_err();
        assert!(e.contains("this graph is not built as one"), "{e}");
        assert!(check_applet_placeholders(&graph("/var/lib/x")).is_ok());
        with_applet("tool", || {
            assert_eq!(applet_being_built().as_deref(), Some("tool"));
            for ok in ["${applet:data_dir}", "${applet:data_dir}/store", "/plain"] {
                assert!(check_applet_placeholders(&graph(ok)).is_ok(), "{ok}");
            }
            for bad in [
                "${applet:config_dir}",
                "/x/${applet:data_dir}",
                "${applet:data_dir}store",
                "${applet:data_dir}/${applet:data_dir}",
            ] {
                let e = check_applet_placeholders(&graph(bad)).unwrap_err();
                assert!(e.contains("the one applet placeholder"), "{bad}: {e}");
            }
            let key = serde_json::json!({"modules": [{"${applet:data_dir}": 1}]});
            assert!(check_applet_placeholders(&key).is_err());
        });
        assert_eq!(
            applet_being_built(),
            None,
            "the context ends with the build"
        );
    }
}
