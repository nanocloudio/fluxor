//! Test helpers shared across rig submodules.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Create a fresh tmp directory keyed on (pid, label, nanos, counter).
/// The combination is unique per call so that fixtures which write
/// executables and immediately spawn them never reuse an inode that
/// another test is still holding open for write.
pub(crate) fn unique_tmp_dir(label: &str) -> PathBuf {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "fluxor-test-{}-{}-{}-{}",
        std::process::id(),
        sanitise(label),
        nanos,
        seq,
    ));
    std::fs::create_dir_all(&path).expect("creating unique tmp dir");
    path
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
