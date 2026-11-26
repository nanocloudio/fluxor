//! The runtime's state directory, `FLUXOR_STATE_DIR`: this instance's own,
//! held exclusively for the runtime's life by a lock in it
//! (`instance.lock`), so two runtimes never share one. The OS drops the lock
//! with the process.
//!
//! The instance's name on its host and the host registry runtimes share
//! (tags, claims, tunables, dead-tag collection) are the network provider's
//! (`fluxor-provider-net`); the runtime hands it the same environment
//! (`host_lane::provider_env`).

use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::Mutex;

/// The held lock, for the process's life.
static LOCK: Mutex<Option<File>> = Mutex::new(None);

/// `FLUXOR_STATE_DIR`, when set.
fn state_dir() -> Option<PathBuf> {
    std::env::var("FLUXOR_STATE_DIR")
        .ok()
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
}

/// Runtime start: make `FLUXOR_STATE_DIR` when it is set and lock it. `Err`
/// is fatal: the directory cannot be made, or another runtime holds it.
pub fn lock_from_env() -> Result<(), String> {
    let Some(dir) = state_dir() else {
        return Ok(());
    };
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("FLUXOR_STATE_DIR {}: {e}", dir.display()))?;
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("instance.lock"))
        .map_err(|e| format!("FLUXOR_STATE_DIR {}: {e}", dir.display()))?;
    loop {
        // SAFETY: flock on a descriptor `f` owns for the call.
        let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            break;
        }
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(format!(
            "FLUXOR_STATE_DIR {} is in use by another runtime",
            dir.display()
        ));
    }
    *LOCK.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
    Ok(())
}
