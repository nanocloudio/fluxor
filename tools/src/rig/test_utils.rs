//! Test helpers shared across rig submodules.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use tempfile::TempDir;

/// RAII scratch directory used across rig submodule tests, backed by
/// [`tempfile::TempDir`] so the directory is removed on drop. It derefs
/// to [`Path`]; bind it for the test's lifetime.
#[derive(Debug)]
pub(crate) struct UniqueTmpDir {
    inner: TempDir,
}

impl UniqueTmpDir {
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

// Deref to Path, so a test calls `.display()`, `.exists()` and the rest
// on the guard directly.
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
/// through "spawn it". `execve` fails with ETXTBSY while any process
/// holds the file open for writing, and a child another test forks while
/// the file is open inherits that fd until its own exec closes it — so a
/// concurrent spawn elsewhere can make this one fail. Holding this mutex
/// for the life of each fixture removes the window.
static EXEC_SPAWN_LOCK: Mutex<()> = Mutex::new(());

/// Acquire the process-wide write-then-spawn lock. Poisoning is
/// recovered: if a prior test panicked while holding the guard, the
/// panic surfaces through the test harness and subsequent tests keep
/// their serialisation guarantee.
pub(crate) fn lock_exec_spawn() -> MutexGuard<'static, ()> {
    EXEC_SPAWN_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}
