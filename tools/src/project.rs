//! Project root discovery for the `fluxor` CLI.
//!
//! Almost every subcommand needs a "project root" to find the
//! `stacks/`, `targets/`, and (by default) `modules/` directories
//! that drive a build. Discovery lives here and nowhere else: a
//! command that reaches for `current_dir()` itself works only when
//! the operator happens to stand in the tree's top directory, and
//! fails silently from a subdirectory, from an external user
//! project, or from a packaged install.
//!
//! ## Resolution order
//!
//! 1. **`$FLUXOR_PROJECT_ROOT` env var**, when set to an existing
//!    directory. Explicit override for tooling that knows where the
//!    tree lives (CI, install scripts, IDE integrations).
//! 2. **Walk up from CWD** looking for a directory that carries a
//!    project marker. Two markers are recognised:
//!    - A `.fluxor` file (user-facing opt-in marker for external
//!      projects).
//!    - Co-located `targets/` and `stacks/` directories (matches the
//!      Fluxor source tree without requiring it to ship a `.fluxor`
//!      file).
//!
//!    The first match wins; the walk stops at the filesystem root.
//! 3. **CWD as a fallback** — for callers that don't care where the
//!    root really is.
//!
//! ## Project-surface discipline
//!
//! The surface this implements, which the rest of the CLI relies on:
//!
//! - A project declares itself on disk. Either the operator opts in
//!   with a `.fluxor` marker file, or the tree is self-evidently a
//!   fluxor project because it carries both `targets/` and `stacks/`.
//!   Nothing is inferred from a name, a parent directory, or an
//!   assumption about where the operator is standing.
//! - The project root and the install root are two different things.
//!   The project root holds what the operator owns and edits; the
//!   install root holds the catalogs shipped with the fluxor
//!   distribution. A resource is resolved against the project root
//!   first and the install root second ([`find_resource`]), so a
//!   project can override any shipped stack or target by placing its
//!   own file at the same relative path without copying the rest.
//! - Every discovery records HOW it resolved ([`DiscoverySource`],
//!   [`InstallDiscoverySource`]) so `fluxor inspect` can tell the
//!   operator which tree a build is actually reading, instead of
//!   leaving a wrong-directory build to fail further downstream.
//! - `fluxor.toml` at the project root carries the project's identity
//!   and its declared dependencies; it is read lazily and its absence
//!   is not an error, because a project root is defined by its
//!   directory layout, not by that file.

use std::path::{Path, PathBuf};

/// Environment variable consulted first for an explicit project root.
pub const ENV_PROJECT_ROOT: &str = "FLUXOR_PROJECT_ROOT";

/// Environment variable consulted first for an explicit install root.
pub const ENV_INSTALL_ROOT: &str = "FLUXOR_INSTALL_ROOT";

/// How [`install_root`] located its returned path. Useful for `inspect`
/// to render *why* the install root was picked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallDiscoverySource {
    /// `$FLUXOR_INSTALL_ROOT` env var pointed at a usable directory.
    EnvVar,
    /// A checkout `~/.fluxor/workspace.toml` names among its
    /// `live_trees` carries `stacks/` + `targets/`. Carries the member's
    /// `[project].name` (from its `fluxor.toml`) for diagnostic rendering.
    LiveTree { project_name: String },
    /// The catalog `fluxor sync` staged from published Fluxor under the
    /// project, `target/fluxor/fluxor-catalog/`: its stacks, targets and
    /// native-module manifests.
    SyncedCatalog,
    /// Found `<exe-prefix>/share/fluxor/{stacks,targets}` from the
    /// running binary's path — matches a `make install`-style layout
    /// where the binary lives at `<prefix>/bin/fluxor`.
    ExePrefixShare,
    /// Found `<exe-prefix>/{stacks,targets}` from the running
    /// binary's path — matches a flat install where stacks/targets
    /// sit next to the binary's prefix dir.
    ExePrefixFlat,
}

/// Resolved install root with provenance — paired with
/// [`ProjectRoot`] in [`Roots`] so `fluxor inspect` can surface both
/// roots and their discovery sources in one block.
#[derive(Debug, Clone)]
pub struct InstallRoot {
    pub path: PathBuf,
    pub source: InstallDiscoverySource,
}

/// Discover the install root for layered resource lookup. The
/// install root is **separate from the project root** — a user
/// running `fluxor` in their own project (with their own
/// `targets/` overrides) still needs the bundled `stacks/` and
/// `targets/` from the fluxor distribution to fall back on.
///
/// Resolution order:
///
/// 1. **`$FLUXOR_INSTALL_ROOT` env var** when set to a directory
///    that has the install markers (`stacks/` + `targets/`).
/// 2. **A `~/.fluxor/workspace.toml` `live_trees` checkout** that
///    carries the install markers: a project building against Fluxor
///    work not yet published names fluxor's checkout there.
/// 3. **The synced catalog**: the `fluxor-catalog` source the current
///    project's `fluxor sync` staged from published Fluxor, at
///    `target/fluxor/fluxor-catalog/`. A workspace member that is not a
///    live tree is used through this, never its working tree.
/// 4. **Walk from `std::env::current_exe()`** looking for
///    - `<prefix>/share/fluxor/{stacks,targets}` (matches the
///      Make / Debian-style install layout where the binary lives
///      at `<prefix>/bin/fluxor`).
///    - `<prefix>/{stacks,targets}` directly (matches a flat
///      install where stacks/targets sit next to the bin dir).
/// 5. **`None`** when nothing matches. In dev mode, the project
///    root walk-up already finds the source tree's
///    `stacks/+targets/`, so the install root being `None` is a
///    no-op fallback.
pub fn install_root() -> Option<InstallRoot> {
    // 1. Env override.
    if let Some(p) = env_var(ENV_INSTALL_ROOT) {
        let path = PathBuf::from(&p);
        if has_install_markers(&path) {
            return Some(InstallRoot {
                path: path.canonicalize().unwrap_or(path),
                source: InstallDiscoverySource::EnvVar,
            });
        }
    }

    // 2. A live tree with install markers: first wins (in practice only
    //    fluxor's own checkout passes). Silent skip on missing /
    //    unparseable workspace.toml — broken user state should never
    //    block the fallbacks.
    if let Ok(Some(ws)) = crate::workspace::load_workspace() {
        for member in &ws.workspace.live_trees {
            if !has_install_markers(member) {
                continue;
            }
            let project_name = project_identity(member)
                .ok()
                .flatten()
                .map(|id| id.name)
                .unwrap_or_else(|| {
                    member
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "<unnamed>".to_string())
                });
            let canon = member.canonicalize().unwrap_or_else(|_| member.clone());
            return Some(InstallRoot {
                path: canon,
                source: InstallDiscoverySource::LiveTree { project_name },
            });
        }
    }

    // 3. The catalog synced from published Fluxor into this project.
    let synced = discover().path.join(SYNCED_CATALOG);
    if has_install_markers(&synced) {
        return Some(InstallRoot {
            path: synced.canonicalize().unwrap_or(synced),
            source: InstallDiscoverySource::SyncedCatalog,
        });
    }

    // 4. Walk from the running binary's path.
    if let Ok(exe) = std::env::current_exe() {
        // `<prefix>/bin/fluxor` → `<prefix>` is `exe.parent().parent()`.
        // Use `.parent()` only when both `bin` and the prefix exist.
        if let Some(prefix) = exe.parent().and_then(|bin| bin.parent()) {
            let share = prefix.join("share").join("fluxor");
            if has_install_markers(&share) {
                return Some(InstallRoot {
                    path: share.canonicalize().unwrap_or(share),
                    source: InstallDiscoverySource::ExePrefixShare,
                });
            }
            if has_install_markers(prefix) {
                return Some(InstallRoot {
                    path: prefix
                        .canonicalize()
                        .unwrap_or_else(|_| prefix.to_path_buf()),
                    source: InstallDiscoverySource::ExePrefixFlat,
                });
            }
        }
    }

    None
}

/// The source artifact Fluxor publishes its `stacks/` and `targets/` as.
macro_rules! catalog_source {
    () => {
        "fluxor-catalog"
    };
}

/// The name of the source artifact Fluxor publishes its `stacks/` and
/// `targets/` as.
#[allow(
    dead_code,
    reason = "read by the library's store modules; the binary compiles this file without them"
)]
pub const CATALOG_SOURCE: &str = catalog_source!();

/// The environment variable `name`, as project and install discovery read it.
pub fn env_var(name: &str) -> Option<std::ffi::OsString> {
    discovery_env::var(name)
}

/// The working directory project discovery starts from.
pub fn current_dir() -> std::io::Result<PathBuf> {
    discovery_env::current_dir()
}

#[cfg(not(test))]
mod discovery_env {
    pub(super) fn var(name: &str) -> Option<std::ffi::OsString> {
        std::env::var_os(name)
    }

    pub(super) fn current_dir() -> std::io::Result<std::path::PathBuf> {
        std::env::current_dir()
    }
}

/// Under test, the thread holding `tests::ENV_LOCK` sees the environment and
/// working directory as it sets them; every other thread sees them as they
/// were when the lock was taken.
#[cfg(test)]
mod discovery_env {
    use std::collections::HashMap;
    use std::ffi::{OsStr, OsString};
    use std::path::PathBuf;
    use std::sync::{Mutex, PoisonError};
    use std::thread::ThreadId;

    struct Snapshot {
        owner: ThreadId,
        vars: HashMap<OsString, OsString>,
        cwd: Option<PathBuf>,
    }

    static HELD: Mutex<Option<Snapshot>> = Mutex::new(None);

    /// The snapshot another thread's lock left, if one is held.
    fn read<R>(f: impl FnOnce(Option<&Snapshot>) -> R) -> R {
        let held = HELD.lock().unwrap_or_else(PoisonError::into_inner);
        let me = std::thread::current().id();
        f(held.as_ref().filter(|s| s.owner != me))
    }

    pub(super) fn var(name: &str) -> Option<OsString> {
        read(|s| match s {
            Some(s) => s.vars.get(OsStr::new(name)).cloned(),
            None => std::env::var_os(name),
        })
    }

    pub(super) fn current_dir() -> std::io::Result<PathBuf> {
        read(|s| match s {
            Some(s) => s
                .cwd
                .clone()
                .ok_or_else(|| std::io::Error::other("no working directory")),
            None => std::env::current_dir(),
        })
    }

    pub(super) fn take() {
        *HELD.lock().unwrap_or_else(PoisonError::into_inner) = Some(Snapshot {
            owner: std::thread::current().id(),
            vars: std::env::vars_os().collect(),
            cwd: std::env::current_dir().ok(),
        });
    }

    pub(super) fn release() {
        *HELD.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

/// Where `fluxor sync` and `fluxor update` stage the published
/// [`CATALOG_SOURCE`], under a project root.
pub const SYNCED_CATALOG: &str = concat!("target/fluxor/", catalog_source!());

fn has_install_markers(path: &Path) -> bool {
    path.is_dir() && path.join("stacks").is_dir() && path.join("targets").is_dir()
}

/// Resolve a resource (e.g. `stacks/audio.toml`,
/// `targets/boards/pi5.toml`) against the project root first, then
/// the install root. Returns the first existing match. Callers that
/// just need "where does this resource live?" without re-doing the
/// project/install discovery should use this helper instead of
/// stitching the lookup themselves.
///
/// `relative` is a path *inside* either root — e.g.
/// `Path::new("stacks/audio.toml")`. Absolute paths are returned
/// as-is when they exist (defensive — callers should pass relative
/// paths, but absolutes pass through cleanly when they happen).
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)] // exercised by inline tests; reserved for future callers (e.g. inspect).
pub fn find_resource(relative: &Path) -> Option<PathBuf> {
    if relative.is_absolute() {
        return relative.is_file().then(|| relative.to_path_buf());
    }
    let project = discover().path;
    let candidate = project.join(relative);
    if candidate.is_file() {
        return Some(candidate);
    }
    if let Some(install) = install_root() {
        let candidate = install.path.join(relative);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// How the resolver located the returned root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoverySource {
    /// `$FLUXOR_PROJECT_ROOT` env var pointed at a usable directory.
    EnvVar,
    /// Walked up from CWD and found a `.fluxor` file.
    DotFluxorMarker,
    /// Walked up from CWD and found `targets/` + `stacks/` together.
    SourceTreeMarker,
    /// No marker found anywhere on the walk; fell back to CWD.
    CwdFallback,
}

/// Resolved project-root path with diagnostic provenance. Returned by
/// [`discover`] for callers that want to surface *why* a particular
/// directory was chosen (notably `fluxor inspect`). Callers that just
/// need the path use [`root`] instead.
#[derive(Debug, Clone)]
pub struct ProjectRoot {
    /// Absolute path to the chosen directory.
    pub path: PathBuf,
    /// Resolution mechanism that picked the path.
    pub source: DiscoverySource,
    /// `$FLUXOR_PROJECT_ROOT` value at resolution time (`None` if
    /// unset; `Some` even when the var didn't ultimately pick the
    /// root, so `inspect` can show "set but ignored because the path
    /// doesn't exist").
    pub env_var_value: Option<String>,
    /// The directory the walk started from. Identical to `path` when
    /// `source == CwdFallback`.
    pub starting_cwd: PathBuf,
}

/// Most-common entry point: discover the project root and return
/// just the path. Equivalent to `discover().path` but more readable
/// at call sites that don't care how the path was found.
pub fn root() -> PathBuf {
    discover().path
}

/// The host runtime a project runs Linux graphs with: the `fluxor-linux`
/// `make build` builds, and `fluxor sync` installs, for this host's triple.
pub fn linux_runtime(project_root: &Path) -> PathBuf {
    project_root.join(format!(
        "target/{}-unknown-linux-gnu/release/fluxor-linux",
        std::env::consts::ARCH
    ))
}

/// Resolve the project root for a command driven by a config file at
/// `config_path` (e.g. `fluxor run <config>`). Resolution order:
///
///   1. `FLUXOR_PROJECT_ROOT` if it names a directory (same override as
///      [`discover`]);
///   2. the marker walk from the config file's OWN location, so the command
///      works from any cwd — a subdirectory of the project, or entirely
///      outside it with an absolute config path;
///   3. cwd-based [`root`] as a last resort.
///
/// Unlike [`root`], step 2 does not depend on the process cwd, which is what
/// lets `fluxor run` resolve modules/binaries the same way no matter where it
/// is invoked from.
pub fn root_for_config(config_path: &Path) -> PathBuf {
    if let Some(value) = env_var(ENV_PROJECT_ROOT) {
        let p = PathBuf::from(&value);
        if p.is_dir() {
            return p.canonicalize().unwrap_or(p);
        }
    }
    let absolute = config_path
        .canonicalize()
        .unwrap_or_else(|_| current_dir().unwrap_or_default().join(config_path));
    if let Some(found) = absolute.parent().and_then(discover_from) {
        return found.path;
    }
    root()
}

/// `[project]` table from `fluxor.toml`. Parsed lazily by the store
/// flow (`store_publish` / `store_sync`) to scope artifacts under the
/// owning project's name.
#[derive(Debug, Clone)]
pub struct ProjectIdentity {
    /// `[project].name` — required for publish to succeed. The CLI
    /// does not fall back to a directory-name heuristic on purpose:
    /// silent identity inference would mean two checkouts with the
    /// same path basename collide in the store.
    pub name: String,
    /// `[project].version` — the human-readable `<ver>` tag label;
    /// defaults to `"0.0.0-dev"` when absent. Resolution never orders
    /// versions — `:latest` is the only tag with semantics.
    pub version: String,
    /// `[project].runtimes` — explicit opt-in list of host runtime
    /// binaries this project owns. The `fluxor publish` runtime sweep
    /// only publishes binaries named here, so binaries synced from
    /// upstream into the consumer's `target/` tree don't get
    /// misclassified as owned and re-published under the consumer's
    /// namespace. Empty when omitted.
    #[allow(
        dead_code,
        reason = "read by the lib-context store flow; this file dual-compiles into the bin, whose paths only read `name`"
    )]
    pub runtimes: Vec<String>,
}

/// Default `[project].version` when the manifest omits it. Canonical
/// publish refuses this value.
pub const DEV_VERSION: &str = "0.0.0-dev";

/// Read `[project]` from `<project_root>/fluxor.toml`. Returns
/// `Ok(None)` when the file is absent (caller decides whether that's
/// an error). Returns an error when the file exists but the
/// `[project]` table is malformed.
pub fn project_identity(project_root: &Path) -> Result<Option<ProjectIdentity>, String> {
    let parsed = read_fluxor_toml(project_root)?;
    Ok(parsed.and_then(|f| f.project).map(|p| ProjectIdentity {
        name: p.name,
        version: p.version.unwrap_or_else(|| DEV_VERSION.to_string()),
        runtimes: p.runtimes.unwrap_or_default(),
    }))
}

/// One entry in `fluxor.toml::[dependencies]`. The wire form is either
/// a bare version string (`fluxor = "1.0"`) or a table
/// (`fluxor = { version = "1.0", path = "../fluxor" }`).
#[derive(Debug, Clone)]
#[allow(
    dead_code,
    reason = "`optional` field is consumed by callers that handle feature-gating; the surface stays exposed"
)]
pub struct DepSpec {
    /// Upstream project name.
    pub name: String,
    /// Version range (e.g. `"1.0"`). `None` for path/git overrides
    /// where the source is authoritative.
    pub version: Option<String>,
    /// Path override — inline form. Resolved relative to the
    /// consuming project's root.
    pub path: Option<PathBuf>,
    /// Git override.
    pub git: Option<String>,
    /// Optional + feature-gated.
    pub optional: bool,
}

/// Parse `[dependencies]` (and `[dependencies.X]` table forms) from
/// `<project_root>/fluxor.toml`. Returns an empty vec when the
/// section is absent. Includes both required and optional entries.
pub fn dependencies(project_root: &Path) -> Result<Vec<DepSpec>, String> {
    let Some(parsed) = read_fluxor_toml(project_root)? else {
        return Ok(Vec::new());
    };
    let Some(deps) = parsed.dependencies else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (name, value) in deps {
        let spec = match value {
            DepValue::Simple(version) => DepSpec {
                name,
                version: Some(version),
                path: None,
                git: None,
                optional: false,
            },
            DepValue::Table(t) => DepSpec {
                name,
                version: t.version,
                path: t.path.map(PathBuf::from),
                git: t.git,
                optional: t.optional.unwrap_or(false),
            },
        };
        out.push(spec);
    }
    Ok(out)
}

#[derive(serde::Deserialize)]
struct FluxorTomlParse {
    #[serde(default)]
    project: Option<ProjectSection>,
    #[serde(default)]
    dependencies: Option<std::collections::BTreeMap<String, DepValue>>,
    #[serde(default)]
    uses: Option<UsesSection>,
}

/// `[uses]`: what this project runs by name that no graph it builds names.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct UsesSection {
    #[serde(default)]
    packages: Vec<String>,
    #[serde(default)]
    stacks: std::collections::BTreeMap<String, String>,
}

/// `fluxor.toml::[uses] packages`: the workload packages this project runs by name
/// (`fluxor run <name>`, `fluxor install <name>`) from scripts, which no
/// graph names. Each is a reference `fluxor update` pins from the
/// dependency that publishes it. Empty when absent.
#[allow(
    dead_code,
    reason = "read by the lib-context store flow; this file dual-compiles into the bin"
)]
pub fn used_packages(project_root: &Path) -> Result<Vec<String>, String> {
    Ok(read_fluxor_toml(project_root)?
        .and_then(|f| f.uses)
        .map(|u| u.packages)
        .unwrap_or_default())
}

/// `fluxor.toml::[uses.stacks]`: each bound name the project's graphs, or
/// a CLI verb composing a graph for it, include as `stack: "@<name>"`,
/// mapped to the stack that fills it. Every value is a reference
/// `fluxor update` pins (other than the project's own packaged stacks);
/// a malformed name or value is refused here, naming the line. Empty when
/// absent.
#[allow(
    dead_code,
    reason = "read by the lib-context store flow; this file dual-compiles into the bin"
)]
pub fn bound_stacks(
    project_root: &Path,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    let bound = read_fluxor_toml(project_root)?
        .and_then(|f| f.uses)
        .map(|u| u.stacks)
        .unwrap_or_default();
    let path = project_root.join("fluxor.toml");
    for (name, stack) in &bound {
        if !crate::stack::is_stack_name(name) {
            return Err(format!(
                "{}: [uses.stacks] key `{name}` is not a bound name ([a-z][a-z0-9_-]*, at most \
                 64 bytes)",
                path.display()
            ));
        }
        if !crate::stack::is_stack_name(stack) {
            return Err(format!(
                "{}: [uses.stacks] `{name} = \"{stack}\"` must name a stack \
                 ([a-z][a-z0-9_-]*, at most 64 bytes)",
                path.display()
            ));
        }
    }
    Ok(bound)
}

#[derive(serde::Deserialize)]
struct ProjectSection {
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    runtimes: Option<Vec<String>>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum DepValue {
    Simple(String),
    Table(DepTable),
}

#[derive(serde::Deserialize)]
struct DepTable {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    git: Option<String>,
    #[serde(default)]
    optional: Option<bool>,
}

fn read_fluxor_toml(project_root: &Path) -> Result<Option<FluxorTomlParse>, String> {
    let path = project_root.join("fluxor.toml");
    if !path.exists() {
        return Ok(None);
    }
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let parsed: FluxorTomlParse =
        toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
    Ok(Some(parsed))
}

/// Discover the project root with provenance. See [`ProjectRoot`].
pub fn discover() -> ProjectRoot {
    let env_var_value = env_var(ENV_PROJECT_ROOT).and_then(|v| v.into_string().ok());
    let starting_cwd = current_dir().unwrap_or_default();

    // 1. Explicit env override.
    if let Some(ref s) = env_var_value {
        let p = PathBuf::from(s);
        if p.is_dir() {
            return ProjectRoot {
                path: p.canonicalize().unwrap_or(p),
                source: DiscoverySource::EnvVar,
                env_var_value,
                starting_cwd,
            };
        }
        // Set but unusable — fall through to the marker walk so
        // `inspect` can show the discrepancy.
    }

    // 2. Walk up from CWD looking for a marker.
    let mut cur = starting_cwd.clone();
    loop {
        if let Some(source) = marker_at(&cur) {
            return ProjectRoot {
                path: cur.canonicalize().unwrap_or(cur),
                source,
                env_var_value,
                starting_cwd,
            };
        }
        if !cur.pop() {
            break;
        }
    }

    // 3. Fallback: CWD.
    ProjectRoot {
        path: starting_cwd.clone(),
        source: DiscoverySource::CwdFallback,
        env_var_value,
        starting_cwd,
    }
}

/// Discover the project root starting from a specific directory
/// rather than the process CWD. Useful for tests and for tools that
/// resolve roots relative to a config file's location.
///
/// Skips the env-var check — callers that want env-var semantics
/// should use [`discover`] / [`root`]. Returns `None` when no marker
/// is found (callers can decide whether to fall back to `start`).
pub fn discover_from(start: &Path) -> Option<ProjectRoot> {
    let starting_cwd = start.to_path_buf();
    let mut cur = starting_cwd.clone();
    loop {
        if let Some(source) = marker_at(&cur) {
            return Some(ProjectRoot {
                path: cur.canonicalize().unwrap_or(cur),
                source,
                env_var_value: None,
                starting_cwd,
            });
        }
        if !cur.pop() {
            return None;
        }
    }
}

/// Whether `path`, a file under `project_root`, belongs to that project
/// rather than to one nested inside it: no directory between the root and
/// the file carries a `fluxor.toml` or a `.fluxor` of its own. A nested
/// project resolves against its own pins and is checked and published by
/// its own CI and its own `fluxor publish`. A path outside the root belongs
/// to another project too.
pub fn is_own_file(project_root: &Path, path: &Path) -> bool {
    let Ok(rel) = path.strip_prefix(project_root) else {
        return false;
    };
    let mut dir = project_root.to_path_buf();
    for component in rel.parent().into_iter().flat_map(Path::components) {
        dir.push(component);
        if dir.join("fluxor.toml").is_file() || dir.join(".fluxor").is_file() {
            return false;
        }
    }
    true
}

/// The files matching `pathspecs` that the project versions, relative to
/// `project_root`, from BOTH of its repositories: the main one and the
/// shadow one (`.git-shadow`) a project may keep its examples and tests in.
/// Enumerating one repository silently leaves out what the other tracks.
/// The shadow repository is the project's own, else the nearest enclosing
/// directory's: a project nested in another's tree may be versioned by that
/// tree's shadow repository, and only its own part of it is listed.
/// Untracked local experiments are not listed, and a tree without git lists
/// nothing.
pub fn tracked_files(
    project_root: &Path,
    pathspecs: &[&str],
) -> std::collections::BTreeSet<String> {
    let mut listing = std::collections::BTreeSet::new();
    let shadow_tree = project_root
        .ancestors()
        .find(|dir| dir.join(".git-shadow").is_dir());
    for work_tree in [None, shadow_tree] {
        let mut cmd = std::process::Command::new("git");
        if let Some(tree) = work_tree {
            cmd.arg("--git-dir")
                .arg(tree.join(".git-shadow"))
                .arg("--work-tree")
                .arg(tree);
        }
        cmd.arg("ls-files")
            .arg("--")
            .args(pathspecs)
            .current_dir(project_root)
            .stderr(std::process::Stdio::null());
        if let Ok(out) = cmd.output() {
            if out.status.success() {
                listing.extend(
                    String::from_utf8_lossy(&out.stdout)
                        .lines()
                        .filter(|l| !l.trim().is_empty())
                        .map(str::to_string),
                );
            }
        }
    }
    listing
}

/// Which marker (if any) identifies `path` as a fluxor project
/// root. Order matters: `.fluxor` (explicit user opt-in) wins over
/// the source-tree heuristic if both somehow co-exist.
fn marker_at(path: &Path) -> Option<DiscoverySource> {
    if path.join(".fluxor").is_file() {
        return Some(DiscoverySource::DotFluxorMarker);
    }
    if path.join("targets").is_dir() && path.join("stacks").is_dir() {
        return Some(DiscoverySource::SourceTreeMarker);
    }
    None
}

#[cfg(test)]
#[allow(
    clippy::undocumented_unsafe_blocks,
    reason = "test scaffolding wraps std::env::{set_var, remove_var} which became `unsafe fn` in Rust 2024; safety is identical at every call site — the tests serialise on the module-level `lock()` mutex, so racing env-mutation across threads is structurally precluded"
)]
pub(crate) mod tests {
    use super::*;
    use std::fs;

    /// The one lock every test that changes the process environment or
    /// working directory holds while it does. Env-var mutations and
    /// `set_current_dir` are process-global; while a test holds the lock,
    /// every other test thread reads them, through [`env_var`] and
    /// [`current_dir`], as they were when the lock was taken.
    pub(crate) struct EnvLock(std::sync::Mutex<()>);

    /// Held while a test may change the environment or working directory.
    pub(crate) struct EnvLockGuard {
        _held: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvLock {
        pub(crate) fn lock(&'static self) -> std::sync::LockResult<EnvLockGuard> {
            let (held, poisoned) = match self.0.lock() {
                Ok(g) => (g, false),
                Err(p) => (p.into_inner(), true),
            };
            super::discovery_env::take();
            let guard = EnvLockGuard { _held: held };
            if poisoned {
                Err(std::sync::PoisonError::new(guard))
            } else {
                Ok(guard)
            }
        }
    }

    impl Drop for EnvLockGuard {
        fn drop(&mut self) {
            super::discovery_env::release();
        }
    }

    pub(crate) static ENV_LOCK: EnvLock = EnvLock(std::sync::Mutex::new(()));

    fn lock() -> EnvLockGuard {
        match ENV_LOCK.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[test]
    fn marker_at_recognises_dot_fluxor_file() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join(".fluxor"), b"").unwrap();
        assert_eq!(
            marker_at(tmp.path()),
            Some(DiscoverySource::DotFluxorMarker)
        );
    }

    #[test]
    fn marker_at_recognises_source_tree_via_targets_and_stacks() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("targets")).unwrap();
        fs::create_dir(tmp.path().join("stacks")).unwrap();
        assert_eq!(
            marker_at(tmp.path()),
            Some(DiscoverySource::SourceTreeMarker)
        );
    }

    #[test]
    fn marker_at_requires_both_targets_and_stacks() {
        // A bare `targets/` directory without `stacks/` is a common
        // shape in unrelated repos — must NOT match. The combination
        // is the heuristic that's specific to fluxor's source tree.
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("targets")).unwrap();
        assert!(marker_at(tmp.path()).is_none());
    }

    #[test]
    fn dot_fluxor_wins_over_source_tree_marker() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("targets")).unwrap();
        fs::create_dir(tmp.path().join("stacks")).unwrap();
        fs::write(tmp.path().join(".fluxor"), b"").unwrap();
        assert_eq!(
            marker_at(tmp.path()),
            Some(DiscoverySource::DotFluxorMarker),
            "explicit user opt-in must take priority over source-tree heuristic"
        );
    }

    #[test]
    fn discover_from_walks_up_to_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let nested = root.join("a/b/c");
        fs::create_dir_all(&nested).unwrap();
        fs::write(root.join(".fluxor"), b"").unwrap();

        let found = discover_from(&nested).expect("walk should find .fluxor");
        assert_eq!(found.source, DiscoverySource::DotFluxorMarker);
        // Compare canonicalised forms — `discover_from` canonicalises
        // its result; `tempdir()` on macOS returns a /var path that
        // canonicalises to /private/var.
        assert_eq!(found.path, root.canonicalize().unwrap());
    }

    #[test]
    fn root_for_config_anchors_to_the_config_location_not_cwd() {
        let _g = lock();
        // SAFETY: env mutation serialised by `ENV_LOCK`. Ensure the override is
        // absent so the config-anchored branch is exercised.
        unsafe {
            std::env::remove_var(ENV_PROJECT_ROOT);
        }
        // A project (marker) with a config nested in a subdirectory.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let config_dir = root.join("examples/hello");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(root.join(".fluxor"), b"").unwrap();
        let config = config_dir.join("linux.yaml");
        fs::write(&config, b"target: linux\n").unwrap();

        // Resolved from the config's own location, independent of the process
        // cwd (the test runs from elsewhere) — this is what makes `fluxor run
        // <config>` work from any directory, including outside the tree.
        assert_eq!(
            root_for_config(&config),
            root.canonicalize().unwrap(),
            "root resolves from the config file, not the caller's cwd"
        );
    }

    #[test]
    fn discover_from_returns_none_when_no_marker_anywhere() {
        // Pick a deep, marker-less subdirectory. Some ancestor of the
        // test working directory may itself have markers (the project
        // we live in), so use an isolated tempdir so the walk really
        // can fail to find a marker — except `/tmp` itself doesn't
        // have one, so the walk reaches the root and returns None.
        let tmp = tempfile::tempdir().unwrap();
        // Don't write any marker.
        let result = discover_from(tmp.path());
        // The walk goes upward toward filesystem root; if the test
        // environment has a marker *above* tmp it would still find
        // one. Don't assert None unconditionally — assert that if
        // Some is returned, it's not the test's own tempdir.
        if let Some(found) = result {
            assert_ne!(
                found.path,
                tmp.path()
                    .canonicalize()
                    .unwrap_or(tmp.path().to_path_buf()),
                "tempdir without a marker must not be reported as the root"
            );
        }
    }

    #[test]
    fn discover_honours_env_var_when_set_to_valid_dir() {
        let _g = lock();
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: env mutation is serialised by `ENV_LOCK`. The
        // remove on the cleanup path runs even if the assertion
        // panics because the guard drop runs first.
        // SAFETY: setting env vars is fine in single-threaded test
        // execution serialised by `ENV_LOCK`. Rust 2024 marks
        // `set_var` unsafe to flag the cross-thread hazard; this
        // call site is protected.
        unsafe {
            std::env::set_var(ENV_PROJECT_ROOT, tmp.path());
        }
        let found = discover();
        unsafe {
            std::env::remove_var(ENV_PROJECT_ROOT);
        }
        assert_eq!(found.source, DiscoverySource::EnvVar);
        assert_eq!(
            found.env_var_value.as_deref(),
            Some(tmp.path().to_str().unwrap())
        );
    }

    // ── install_root ─────────────────────────────────────────────

    /// Point `$FLUXOR_WORKSPACE` at a path that doesn't exist so the
    /// workspace-member resolution branch reads `Ok(None)` and the
    /// test exercises only the env-var / exe-walk branches.
    /// `install_root`'s branches are independent, so neutralising
    /// workspace mode keeps the per-branch tests focused.
    fn neutralise_workspace_env() {
        unsafe {
            std::env::set_var("FLUXOR_WORKSPACE", "/nonexistent/workspace.toml");
        }
    }

    fn restore_workspace_env() {
        unsafe {
            std::env::remove_var("FLUXOR_WORKSPACE");
        }
    }

    #[test]
    fn install_root_env_var_resolves_when_dir_has_markers() {
        let _g = lock();
        neutralise_workspace_env();
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("stacks")).unwrap();
        fs::create_dir(tmp.path().join("targets")).unwrap();
        unsafe {
            std::env::set_var(ENV_INSTALL_ROOT, tmp.path());
        }
        let found = install_root();
        unsafe {
            std::env::remove_var(ENV_INSTALL_ROOT);
        }
        restore_workspace_env();
        let install = found.expect("env var with valid markers must resolve");
        assert_eq!(install.source, InstallDiscoverySource::EnvVar);
    }

    #[test]
    fn install_root_env_var_ignored_when_dir_lacks_markers() {
        // Empty tempdir → no `stacks/` or `targets/`. Even with
        // the env var pointed at it, install_root must reject it
        // (the install layout is what makes the path a fluxor
        // install, not the env var pointing there).
        let _g = lock();
        neutralise_workspace_env();
        let tmp = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var(ENV_INSTALL_ROOT, tmp.path());
        }
        // The env-var path is unusable; install_root should walk
        // past the env-var and workspace branches and reach the
        // current_exe branch. In a test binary current_exe lives
        // under `target/debug/deps/`, where no `share/fluxor` or
        // flat markers exist — so the final result should be None.
        let found = install_root();
        unsafe {
            std::env::remove_var(ENV_INSTALL_ROOT);
        }
        restore_workspace_env();
        assert!(
            found.is_none(),
            "expected no install root when env-var path has no markers, got {found:?}"
        );
    }

    #[test]
    fn install_root_none_when_no_markers_anywhere() {
        let _g = lock();
        neutralise_workspace_env();
        // Ensure no env var sets the install root explicitly.
        unsafe {
            std::env::remove_var(ENV_INSTALL_ROOT);
        }
        // Test binary's current_exe is under target/debug/deps/;
        // walking up doesn't hit a `share/fluxor/` or flat install
        // layout. Result should be None.
        let found = install_root();
        restore_workspace_env();
        assert!(found.is_none());
    }

    /// Synthesise a fake fluxor checkout (stacks/ + targets/ + a
    /// fluxor.toml declaring the project name) and a workspace.toml
    /// listing it. Returns the `TempDir` so the caller controls the
    /// lifetime — drop it after the test finishes.
    fn build_workspace_member(name: &str) -> (tempfile::TempDir, PathBuf) {
        let member = tempfile::tempdir().unwrap();
        fs::create_dir(member.path().join("stacks")).unwrap();
        fs::create_dir(member.path().join("targets")).unwrap();
        fs::write(
            member.path().join("fluxor.toml"),
            format!("[project]\nname = \"{name}\"\nversion = \"0.1.0\"\n"),
        )
        .unwrap();
        let path = member.path().to_path_buf();
        (member, path)
    }

    /// A workspace file listing `members`, of which `live` are live trees.
    fn write_workspace_toml(members: &[&Path], live: &[&Path]) -> tempfile::NamedTempFile {
        let list = |paths: &[&Path]| {
            paths
                .iter()
                .map(|m| format!("  \"{}\",\n", m.display()))
                .collect::<String>()
        };
        let body = format!(
            "[workspace]\nmembers = [\n{}]\nlive_trees = [\n{}]\n",
            list(members),
            list(live)
        );
        let file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        fs::write(file.path(), body).unwrap();
        file
    }

    #[test]
    fn install_root_resolves_to_a_live_tree_when_marker_present() {
        let _g = lock();
        unsafe {
            std::env::remove_var(ENV_INSTALL_ROOT);
        }
        let (_member_guard, member_path) = build_workspace_member("fluxor");
        let ws_file = write_workspace_toml(&[&member_path], &[&member_path]);
        unsafe {
            std::env::set_var("FLUXOR_WORKSPACE", ws_file.path());
        }
        let found = install_root();
        restore_workspace_env();
        let install = found.expect("a live tree with markers must resolve");
        assert_eq!(
            install.path.canonicalize().unwrap(),
            member_path.canonicalize().unwrap(),
        );
        assert_eq!(
            install.source,
            InstallDiscoverySource::LiveTree {
                project_name: "fluxor".into(),
            },
        );
    }

    /// A member that is not a live tree is used through what it
    /// published: its checkout's catalog is never read, and the project's
    /// synced catalog is.
    #[test]
    fn install_root_reads_a_members_catalog_only_from_a_live_tree() {
        let _g = lock();
        unsafe {
            std::env::remove_var(ENV_INSTALL_ROOT);
        }
        let (_member_guard, member_path) = build_workspace_member("fluxor");
        let ws_file = write_workspace_toml(&[&member_path], &[]);
        let project = tempfile::tempdir().unwrap();
        fs::write(project.path().join(".fluxor"), b"").unwrap();
        unsafe {
            std::env::set_var("FLUXOR_WORKSPACE", ws_file.path());
            std::env::set_var(ENV_PROJECT_ROOT, project.path());
        }
        let unsynced = install_root();
        let synced = project.path().join(SYNCED_CATALOG);
        fs::create_dir_all(synced.join("stacks")).unwrap();
        fs::create_dir_all(synced.join("targets")).unwrap();
        let found = install_root();
        unsafe {
            std::env::remove_var(ENV_PROJECT_ROOT);
        }
        restore_workspace_env();
        assert!(
            unsynced
                .as_ref()
                .is_none_or(|r| r.path.canonicalize().ok() != member_path.canonicalize().ok()),
            "a member that is not a live tree must not be the install root, got {unsynced:?}"
        );
        let install = found.expect("the synced catalog resolves");
        assert_eq!(install.source, InstallDiscoverySource::SyncedCatalog);
        assert_eq!(install.path, synced.canonicalize().unwrap());
    }

    #[test]
    fn install_root_env_var_wins_over_workspace_member() {
        // Both branches would resolve; env var must win.
        let _g = lock();
        let (_member_guard, member_path) = build_workspace_member("fluxor");
        let ws_file = write_workspace_toml(&[&member_path], &[&member_path]);
        let env_target = tempfile::tempdir().unwrap();
        fs::create_dir(env_target.path().join("stacks")).unwrap();
        fs::create_dir(env_target.path().join("targets")).unwrap();
        unsafe {
            std::env::set_var(ENV_INSTALL_ROOT, env_target.path());
            std::env::set_var("FLUXOR_WORKSPACE", ws_file.path());
        }
        let found = install_root();
        unsafe {
            std::env::remove_var(ENV_INSTALL_ROOT);
        }
        restore_workspace_env();
        let install = found.expect("env-var path with markers must resolve");
        assert_eq!(install.source, InstallDiscoverySource::EnvVar);
        assert_eq!(
            install.path.canonicalize().unwrap(),
            env_target.path().canonicalize().unwrap(),
        );
    }

    #[test]
    fn install_root_skips_workspace_member_without_markers() {
        // A workspace member that's a downstream project (no
        // stacks/+targets/) must not be picked. install_root should
        // skip it and return None (no env var, no exe-walk match).
        let _g = lock();
        unsafe {
            std::env::remove_var(ENV_INSTALL_ROOT);
        }
        let downstream = tempfile::tempdir().unwrap();
        fs::write(
            downstream.path().join("fluxor.toml"),
            "[project]\nname = \"downstream\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let ws_file = write_workspace_toml(&[downstream.path()], &[downstream.path()]);
        unsafe {
            std::env::set_var("FLUXOR_WORKSPACE", ws_file.path());
        }
        let found = install_root();
        restore_workspace_env();
        assert!(
            found.is_none(),
            "downstream member without markers must not be promoted, got {found:?}"
        );
    }

    // ── find_resource ────────────────────────────────────────────

    #[test]
    fn find_resource_returns_project_root_match_first() {
        let _g = lock();
        let tmp = tempfile::tempdir().unwrap();
        // Synthesise a project root with `.fluxor` marker and a
        // resource. Set FLUXOR_PROJECT_ROOT so the resolver finds
        // the synthesised tree regardless of CWD.
        fs::write(tmp.path().join(".fluxor"), b"").unwrap();
        fs::create_dir_all(tmp.path().join("stacks")).unwrap();
        fs::write(tmp.path().join("stacks/audio.toml"), b"# stub").unwrap();

        unsafe {
            std::env::set_var(ENV_PROJECT_ROOT, tmp.path());
            std::env::remove_var(ENV_INSTALL_ROOT);
        }
        let found = find_resource(Path::new("stacks/audio.toml"));
        unsafe {
            std::env::remove_var(ENV_PROJECT_ROOT);
        }
        let found = found.expect("project-root match must resolve");
        assert!(
            found.ends_with("stacks/audio.toml"),
            "unexpected path: {}",
            found.display()
        );
    }

    #[test]
    fn find_resource_falls_back_to_install_root_when_project_lacks_it() {
        let _g = lock();
        let tmp_project = tempfile::tempdir().unwrap();
        let tmp_install = tempfile::tempdir().unwrap();
        // Project root has the `.fluxor` marker but no stack file.
        fs::write(tmp_project.path().join(".fluxor"), b"").unwrap();
        // Install root has the markers AND the stack file.
        fs::create_dir_all(tmp_install.path().join("stacks")).unwrap();
        fs::create_dir_all(tmp_install.path().join("targets")).unwrap();
        fs::write(
            tmp_install.path().join("stacks/audio.toml"),
            b"# bundled stub",
        )
        .unwrap();

        unsafe {
            std::env::set_var(ENV_PROJECT_ROOT, tmp_project.path());
            std::env::set_var(ENV_INSTALL_ROOT, tmp_install.path());
        }
        let found = find_resource(Path::new("stacks/audio.toml"));
        unsafe {
            std::env::remove_var(ENV_PROJECT_ROOT);
            std::env::remove_var(ENV_INSTALL_ROOT);
        }
        let found = found.expect("install-root fallback must resolve");
        let expected_prefix = tmp_install.path().canonicalize().unwrap();
        assert!(
            found.starts_with(&expected_prefix),
            "expected path under install root {}, got {}",
            expected_prefix.display(),
            found.display()
        );
    }

    #[test]
    fn find_resource_returns_none_when_neither_root_has_it() {
        let _g = lock();
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join(".fluxor"), b"").unwrap();
        unsafe {
            std::env::set_var(ENV_PROJECT_ROOT, tmp.path());
            std::env::remove_var(ENV_INSTALL_ROOT);
        }
        let found = find_resource(Path::new("stacks/nonexistent.toml"));
        unsafe {
            std::env::remove_var(ENV_PROJECT_ROOT);
        }
        assert!(found.is_none(), "expected None for missing resource");
    }

    #[test]
    fn discover_falls_through_when_env_var_points_at_nonexistent_path() {
        let _g = lock();
        unsafe {
            std::env::set_var(ENV_PROJECT_ROOT, "/this/path/does/not/exist");
        }
        let found = discover();
        unsafe {
            std::env::remove_var(ENV_PROJECT_ROOT);
        }
        // env_var_value is still recorded so `inspect` can show "set
        // but ignored" — but the source must NOT be EnvVar.
        assert_ne!(found.source, DiscoverySource::EnvVar);
        assert_eq!(
            found.env_var_value.as_deref(),
            Some("/this/path/does/not/exist")
        );
    }
}
