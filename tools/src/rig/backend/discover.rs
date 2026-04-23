//! Backend discovery.
//!
//! Lookup precedence:
//!
//!   1. `$FLUXOR_BACKEND_PATH` (colon-separated, `$PATH`-style)
//!   2. `$XDG_DATA_HOME/fluxor/backends/`
//!      (falls back to `$HOME/.local/share/fluxor/backends/`)
//!   3. `$XDG_DATA_DIRS/fluxor/backends/` for each entry
//!      (default: `/usr/local/share/fluxor/backends:/usr/share/fluxor/backends`)
//!
//! A backend is an executable named `<surface>-<name>`, e.g.
//! `power-kasa_local` or `deploy-netboot_tftp`.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::rig::vocab::Surface;

#[derive(Debug, Clone)]
pub struct BackendRef {
    pub surface: Surface,
    pub name: String,
    pub executable: PathBuf,
}

impl BackendRef {
    pub fn slug(&self) -> String {
        format!("{}-{}", self.surface.as_str(), self.name)
    }
}

/// Resolve a backend executable by (surface, name).
///
/// Returns a structured error naming every searched path when nothing
/// matches so the operator can fix their install or env var without
/// guessing.
pub fn resolve(surface: Surface, name: &str) -> Result<BackendRef> {
    let slug = format!("{}-{}", surface.as_str(), name);
    let paths = search_paths();
    for dir in &paths {
        let candidate = dir.join(&slug);
        if is_executable(&candidate) {
            return Ok(BackendRef {
                surface,
                name: name.to_string(),
                executable: candidate,
            });
        }
    }
    let search_list = paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(Error::Config(format!(
        "rig backend '{slug}' not found on any search path: [{search_list}]. \
         Install the fluxor reference backends, provide your own, or set \
         $FLUXOR_BACKEND_PATH to point at them."
    )))
}

/// The full ordered list of directories the resolver will consider. Callers
/// can print this for `--plan` and diagnostic output.
pub fn search_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();

    if let Ok(env) = std::env::var("FLUXOR_BACKEND_PATH") {
        for part in env.split(':') {
            if !part.is_empty() {
                out.push(PathBuf::from(part));
            }
        }
    }

    // XDG data home.
    if let Some(xdg_home) = std::env::var_os("XDG_DATA_HOME").filter(|s| !s.is_empty()) {
        out.push(PathBuf::from(xdg_home).join("fluxor").join("backends"));
    } else if let Some(home) = std::env::var_os("HOME").filter(|s| !s.is_empty()) {
        out.push(
            PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("fluxor")
                .join("backends"),
        );
    }

    // XDG data dirs.
    let data_dirs = std::env::var("XDG_DATA_DIRS")
        .unwrap_or_else(|_| "/usr/local/share:/usr/share".to_string());
    for part in data_dirs.split(':') {
        if part.is_empty() {
            continue;
        }
        out.push(PathBuf::from(part).join("fluxor").join("backends"));
    }

    out
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    // Any execute bit set (owner/group/other) and we consider it runnable.
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_paths_honours_env() {
        let key = "FLUXOR_BACKEND_PATH";
        let prev = std::env::var_os(key);
        std::env::set_var(key, "/opt/one:/opt/two");
        let paths = search_paths();
        assert!(paths.contains(&PathBuf::from("/opt/one")));
        assert!(paths.contains(&PathBuf::from("/opt/two")));
        // XDG defaults still appended.
        assert!(paths.len() >= 3);
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn missing_backend_error_mentions_paths() {
        let key = "FLUXOR_BACKEND_PATH";
        let prev = std::env::var_os(key);
        std::env::set_var(key, "/nope/one");
        let err = resolve(Surface::Power, "does-not-exist").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("power-does-not-exist"), "{msg}");
        assert!(msg.contains("/nope/one"), "{msg}");
        assert!(msg.contains("FLUXOR_BACKEND_PATH"), "{msg}");
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn resolves_real_executable() {
        // Hold the exec-spawn serialisation guard even though this test
        // never exec's the file itself — other tests may be spawning
        // from their own fixtures concurrently, and Linux's ETXTBSY
        // check reacts to write-fds on any executable in the process.
        let _exec_guard = crate::rig::test_utils::lock_exec_spawn();
        let tmp = crate::rig::test_utils::unique_tmp_dir("discover-resolve");

        let exe = tmp.join("power-testbackend");
        std::fs::write(&exe, "#!/bin/sh\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();

        let key = "FLUXOR_BACKEND_PATH";
        let prev = std::env::var_os(key);
        std::env::set_var(key, tmp.display().to_string());
        let found = resolve(Surface::Power, "testbackend").unwrap();
        assert_eq!(found.executable, exe);
        assert_eq!(found.name, "testbackend");
        assert_eq!(found.slug(), "power-testbackend");
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn non_executable_is_skipped() {
        let _exec_guard = crate::rig::test_utils::lock_exec_spawn();
        let tmp = crate::rig::test_utils::unique_tmp_dir("discover-noexec");
        let file = tmp.join("power-noexec");
        std::fs::write(&file, "not an executable").unwrap();
        // Deliberately do NOT chmod +x.

        let key = "FLUXOR_BACKEND_PATH";
        let prev = std::env::var_os(key);
        std::env::set_var(key, tmp.display().to_string());
        assert!(resolve(Surface::Power, "noexec").is_err());
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        std::fs::remove_dir_all(&tmp).ok();
    }
}
