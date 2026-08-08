//! `fluxor.lock` advisory locking.
//!
//! The lockfile format and its read/write/resolve surface live in
//! `store_resolve` (uniform `[[artifact]]` entries over the OCI
//! store). This module owns the one primitive shared by every
//! lockfile writer: the exclusive advisory lock serializing
//! read-modify-write transactions (`fluxor update`, `fluxor sync`,
//! `fluxor store pin`).

use std::fs;
use std::path::Path;

use crate::error::{Error, Result};

/// Take the exclusive advisory lock guarding every `fluxor.lock`
/// read-modify-write. Held for the caller's transaction; released on drop.
/// The guard file (`target/fluxor/.lockfile-guard`) is separate from the
/// lockfile so locking never truncates the data, and lives under `target/`
/// so it is build-output, never repo content. Because anything under
/// `target/` may be deleted at any time (`cargo clean`), the lock is only
/// valid while the path still names the inode we locked — hence the re-stat
/// loop: a guard unlinked between open and lock is abandoned and retried.
pub fn lock_lockfile(project_root: &Path) -> Result<fs::File> {
    let dir = project_root.join("target/fluxor");
    fs::create_dir_all(&dir)?;
    let path = dir.join(".lockfile-guard");
    loop {
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)?;
        f.lock()
            .map_err(|e| Error::Config(format!("lock {}: {e}", path.display())))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            match fs::metadata(&path) {
                Ok(on_disk) if on_disk.ino() == f.metadata()?.ino() => return Ok(f),
                // Guard was deleted (and possibly recreated) while we were
                // acquiring: our lock is on an orphaned inode. Retry.
                _ => {
                    fs::create_dir_all(&dir)?;
                    continue;
                }
            }
        }
        #[cfg(not(unix))]
        return Ok(f);
    }
}
