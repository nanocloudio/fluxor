//! Test helpers shared across rig submodules.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use tempfile::TempDir;

/// RAII scratch directory used across rig submodule tests. Replaces
/// the old `unique_tmp_dir(label) -> PathBuf` which leaked to
/// `/tmp/fluxor-test-*` on every run. Backed by [`tempfile::TempDir`]
/// so the directory is removed automatically on drop. Path-style
/// helpers (`.path()`, `.join(...)`) match the previous call-site
/// ergonomics, so the only required change at call sites is "bind
/// the return value for the test's lifetime".
#[derive(Debug)]
pub(crate) struct UniqueTmpDir {
    inner: TempDir,
}

impl UniqueTmpDir {
    #[allow(
        dead_code,
        reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
    )] // not every consumer goes through this accessor
    pub fn path(&self) -> &Path {
        self.inner.path()
    }

    pub fn join<P: AsRef<Path>>(&self, rel: P) -> PathBuf {
        self.inner.path().join(rel)
    }
}

impl AsRef<Path> for UniqueTmpDir {
    fn as_ref(&self) -> &Path {
        self.inner.path()
    }
}

// Deref to Path so test sites that called methods like `.display()`,
// `.to_str()`, or compared paths still compile unchanged. Path methods
// return borrowed data tied to the TempDir's lifetime, so the safety
// argument is the same as for `&Path` derived from any owning struct.
impl std::ops::Deref for UniqueTmpDir {
    type Target = Path;
    fn deref(&self) -> &Self::Target {
        self.inner.path()
    }
}

impl PartialEq<PathBuf> for UniqueTmpDir {
    fn eq(&self, other: &PathBuf) -> bool {
        self.inner.path() == other.as_path()
    }
}

impl PartialEq<UniqueTmpDir> for PathBuf {
    fn eq(&self, other: &UniqueTmpDir) -> bool {
        self.as_path() == other.inner.path()
    }
}

/// Create a fresh scratch directory tagged with `label`. The path
/// goes under the OS temp root (`tempfile`'s default) and the
/// directory is removed when the returned value drops.
pub(crate) fn unique_tmp_dir(label: &str) -> UniqueTmpDir {
    let inner = tempfile::Builder::new()
        .prefix(&format!("fluxor-test-{}-", sanitise(label)))
        .tempdir()
        .expect("creating unique tmp dir");
    UniqueTmpDir { inner }
}

fn sanitise(label: &str) -> String {
    label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Serialises the critical section from "write an executable to disk"
/// through "spawn it". Linux's `execve` reports ETXTBSY if any thread
/// in the process holds a writable fd on the executable's inode, and
/// the check runs before CLOEXEC closure — so a concurrent writer in
/// another test can cause an unrelated spawn to fail. Holding this
/// mutex for the life of each fixture removes the window.
static EXEC_SPAWN_LOCK: Mutex<()> = Mutex::new(());

/// Acquire the process-wide write-then-spawn lock. Poisoning is
/// recovered: if a prior test panicked while holding the guard, the
/// panic surfaces through the test harness and subsequent tests keep
/// their serialisation guarantee.
pub(crate) fn lock_exec_spawn() -> MutexGuard<'static, ()> {
    EXEC_SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}
