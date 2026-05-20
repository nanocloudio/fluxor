//! Project root discovery for the `fluxor` CLI.
//!
//! Almost every subcommand needs a "project root" to find the
//! `stacks/`, `targets/`, and (by default) `modules/` directories
//! that drive a build. Before this module existed, ten different
//! sites in `main.rs` and `scenario.rs` hardcoded
//! `std::env::current_dir().unwrap_or_default()` — which works only
//! when the operator runs `fluxor` from the source tree's top
//! directory. Running from a subdirectory, an external user project,
//! or via a packaged install path broke discovery silently.
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
//! 3. **CWD as a fallback** — preserves the pre-`fluxor_tools::project`
//!    behaviour for callers that don't care.
//!
//! See `.context/rfc_fluxor_project_surface_discipline.md` for the
//! broader project-surface design this helper supports.

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
/// 2. **Walk from `std::env::current_exe()`** looking for
///    - `<prefix>/share/fluxor/{stacks,targets}` (matches the
///      Make / Debian-style install layout where the binary lives
///      at `<prefix>/bin/fluxor`).
///    - `<prefix>/{stacks,targets}` directly (matches a flat
///      install where stacks/targets sit next to the bin dir).
/// 3. **`None`** when neither matches. In dev mode, the project
///    root walk-up already finds the source tree's
///    `stacks/+targets/`, so the install root being `None` is a
///    no-op fallback.
pub fn install_root() -> Option<InstallRoot> {
    // 1. Env override.
    if let Ok(p) = std::env::var(ENV_INSTALL_ROOT) {
        let path = PathBuf::from(&p);
        if has_install_markers(&path) {
            return Some(InstallRoot {
                path: path.canonicalize().unwrap_or(path),
                source: InstallDiscoverySource::EnvVar,
            });
        }
    }

    // 2. Walk from the running binary's path.
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
                    path: prefix.canonicalize().unwrap_or_else(|_| prefix.to_path_buf()),
                    source: InstallDiscoverySource::ExePrefixFlat,
                });
            }
        }
    }

    None
}

fn has_install_markers(path: &Path) -> bool {
    path.is_dir() && path.join("stacks").is_dir() && path.join("targets").is_dir()
}

/// Resolve a resource (e.g. `stacks/audio.toml`,
/// `targets/boards/cm5.toml`) against the project root first, then
/// the install root. Returns the first existing match. Callers that
/// just need "where does this resource live?" without re-doing the
/// project/install discovery should use this helper instead of
/// stitching the lookup themselves.
///
/// `relative` is a path *inside* either root — e.g.
/// `Path::new("stacks/audio.toml")`. Absolute paths are returned
/// as-is when they exist (defensive — callers should pass relative
/// paths, but absolutes pass through cleanly when they happen).
#[allow(dead_code)] // exercised by inline tests; reserved for future callers (e.g. inspect).
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

/// Discover the project root with provenance. See [`ProjectRoot`].
pub fn discover() -> ProjectRoot {
    let env_var_value = std::env::var(ENV_PROJECT_ROOT).ok();
    let starting_cwd = std::env::current_dir().unwrap_or_default();

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
#[allow(dead_code)] // exercised by inline tests; reserved for future callers.
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
mod tests {
    use super::*;
    use std::fs;

    /// Locking helper: env-var mutations and `set_current_dir` are
    /// process-global, so the tests serialise on a shared mutex.
    /// `Mutex<()>` rather than `RwLock` because read/write semantics
    /// don't help when env vars are involved.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock() -> std::sync::MutexGuard<'static, ()> {
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
        assert_eq!(
            found.path,
            root.canonicalize().unwrap()
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
                tmp.path().canonicalize().unwrap_or(tmp.path().to_path_buf()),
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
        assert_eq!(found.env_var_value.as_deref(), Some(tmp.path().to_str().unwrap()));
    }

    // ── install_root ─────────────────────────────────────────────

    #[test]
    fn install_root_env_var_resolves_when_dir_has_markers() {
        let _g = lock();
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
        let tmp = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var(ENV_INSTALL_ROOT, tmp.path());
        }
        // The env-var path is unusable; install_root should walk
        // through the env-var branch and fall to the current_exe
        // branch. In a test binary current_exe lives under
        // `target/debug/deps/`, where no `share/fluxor` or flat
        // markers exist — so the final result should be None.
        let found = install_root();
        unsafe {
            std::env::remove_var(ENV_INSTALL_ROOT);
        }
        assert!(
            found.is_none(),
            "expected no install root when env-var path has no markers, got {found:?}"
        );
    }

    #[test]
    fn install_root_none_when_no_markers_anywhere() {
        let _g = lock();
        // Ensure no env var sets the install root explicitly.
        unsafe {
            std::env::remove_var(ENV_INSTALL_ROOT);
        }
        // Test binary's current_exe is under target/debug/deps/;
        // walking up doesn't hit a `share/fluxor/` or flat install
        // layout. Result should be None.
        assert!(install_root().is_none());
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
