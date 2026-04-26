//! Rig lockfile — RFC §10.5.
//!
//! A single physical rig is a serialisable resource: only one orchestrated
//! run should touch it at once. V1 uses a local lockfile with atomic
//! create semantics. Lock content identifies the owner (pid, hostname,
//! rig, what it's running, when it started) so a stale lock can be
//! inspected and forcibly released, leaving an audit breadcrumb.
//!
//! Canonical path: `~/.local/state/fluxor/labs/<lab>/rigs/<rig>/lock`.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Identity stored inside the lockfile. All fields are considered
/// non-sensitive and appear in run-log breadcrumbs on forced release.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockOwner {
    pub pid: u32,
    pub hostname: String,
    pub rig: String,
    /// What the owner is running — e.g. `"scenario:cm5_boot_banner"` or
    /// `"command:power cycle"`. Free-form, just has to be useful in logs.
    pub task: String,
    /// Seconds since Unix epoch.
    pub started_at: u64,
    /// Effective timeout governing stale-lock detection per §10.5:
    /// scenario `timeout_s` when present, else board `default_timeout_s`,
    /// else a sensible fallback.
    pub effective_timeout_s: u32,
}

impl LockOwner {
    pub fn now(rig: &str, task: &str, effective_timeout_s: u32) -> Self {
        Self {
            pid: std::process::id(),
            hostname: hostname(),
            rig: rig.to_string(),
            task: task.to_string(),
            started_at: now_unix_secs(),
            effective_timeout_s,
        }
    }

    /// Stale threshold per RFC §10.5: max(2 × effective_timeout_s, 60s).
    pub fn stale_threshold_s(&self) -> u64 {
        std::cmp::max(2 * self.effective_timeout_s as u64, 60)
    }

    pub fn age_s(&self) -> u64 {
        now_unix_secs().saturating_sub(self.started_at)
    }

    pub fn is_stale(&self) -> bool {
        self.age_s() > self.stale_threshold_s()
    }
}

/// Held lock. Drop releases the lock by removing the file iff the file
/// on disk still names us as the owner. If a concurrent `--force` or
/// stale-takeover has installed a different owner, drop is a no-op so
/// the new owner's lock remains intact.
pub struct LockGuard {
    path: PathBuf,
    token: OwnerToken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnerToken {
    pid: u32,
    hostname: String,
    started_at: u64,
}

impl OwnerToken {
    fn matches(&self, owner: &LockOwner) -> bool {
        self.pid == owner.pid
            && self.hostname == owner.hostname
            && self.started_at == owner.started_at
    }
}

impl From<&LockOwner> for OwnerToken {
    fn from(owner: &LockOwner) -> Self {
        Self {
            pid: owner.pid,
            hostname: owner.hostname.clone(),
            started_at: owner.started_at,
        }
    }
}

impl LockGuard {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        // Only unlink when the file on disk still names this guard's
        // owner token. Missing, replaced, or unreadable files are left
        // alone so a takeover holder keeps ownership.
        if let Ok(raw) = std::fs::read_to_string(&self.path) {
            if let Ok(current) = serde_json::from_str::<LockOwner>(&raw) {
                if self.token.matches(&current) {
                    let _ = std::fs::remove_file(&self.path);
                }
            }
        }
    }
}

/// The result of attempting to acquire a lock that was already held.
#[derive(Debug)]
pub struct LockConflict {
    pub path: PathBuf,
    pub existing: LockOwner,
    pub stale: bool,
}

pub enum AcquireOutcome {
    Acquired(LockGuard),
    /// Lock is held by someone else. Caller decides whether to wait,
    /// give up, or retry with `force = true`.
    Held(LockConflict),
}

pub fn acquire(lock_path: &Path, owner: &LockOwner, force: bool) -> Result<AcquireOutcome> {
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Config(format!("rig lock: creating {}: {e}", parent.display())))?;
    }

    // Atomic create-exclusive. If the file exists, we read the existing
    // owner to report it.
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(lock_path)
    {
        Ok(f) => {
            write_owner(&f, owner)?;
            f.sync_all().ok();
            Ok(AcquireOutcome::Acquired(LockGuard {
                path: lock_path.to_path_buf(),
                token: OwnerToken::from(owner),
            }))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_owner(lock_path)?;
            let stale = existing.is_stale();
            if force || stale {
                // Replace the file. We do not assume the previous holder
                // is gone — the caller is taking ownership deliberately.
                std::fs::remove_file(lock_path).map_err(|e| {
                    Error::Config(format!(
                        "rig lock: removing stale/forced {}: {e}",
                        lock_path.display()
                    ))
                })?;
                let f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(lock_path)
                    .map_err(|e| {
                        Error::Config(format!("rig lock: recreating {}: {e}", lock_path.display()))
                    })?;
                write_owner(&f, owner)?;
                f.sync_all().ok();
                Ok(AcquireOutcome::Acquired(LockGuard {
                    path: lock_path.to_path_buf(),
                    token: OwnerToken::from(owner),
                }))
            } else {
                Ok(AcquireOutcome::Held(LockConflict {
                    path: lock_path.to_path_buf(),
                    existing,
                    stale,
                }))
            }
        }
        Err(e) => Err(Error::Config(format!(
            "rig lock: opening {}: {e}",
            lock_path.display()
        ))),
    }
}

/// Canonical lockfile path: `~/.local/state/fluxor/labs/<lab>/rigs/<rig>/lock`.
pub fn default_lock_path(lab: &str, rig: &str) -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    Some(
        home.join(".local")
            .join("state")
            .join("fluxor")
            .join("labs")
            .join(lab)
            .join("rigs")
            .join(rig)
            .join("lock"),
    )
}

fn write_owner(mut f: &std::fs::File, owner: &LockOwner) -> Result<()> {
    let json = serde_json::to_string_pretty(owner)
        .map_err(|e| Error::Config(format!("rig lock: serialising owner: {e}")))?;
    f.write_all(json.as_bytes())
        .map_err(|e| Error::Config(format!("rig lock: writing owner: {e}")))?;
    f.write_all(b"\n").ok();
    Ok(())
}

fn read_owner(path: &Path) -> Result<LockOwner> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        Error::Config(format!(
            "rig lock: reading existing {}: {e}",
            path.display()
        ))
    })?;
    serde_json::from_str(&raw).map_err(|e| {
        Error::Config(format!(
            "rig lock: parsing existing {}: {e} (content: {raw:?})",
            path.display()
        ))
    })
}

fn hostname() -> String {
    // Avoid pulling in a hostname crate. `uname -n` via libc is portable on
    // Unix; fall back to $HOSTNAME, then "unknown".
    if let Ok(buf) = unix_hostname() {
        return buf;
    }
    if let Ok(h) = std::env::var("HOSTNAME") {
        if !h.is_empty() {
            return h;
        }
    }
    "unknown".to_string()
}

fn unix_hostname() -> std::io::Result<String> {
    use std::ffi::CStr;
    let mut buf = [0u8; 256];
    // SAFETY: libc::gethostname takes a writable buffer and nul-terminates
    // within len. We then read up to the first nul via CStr::from_bytes_until_nul.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Ensure nul-termination in case gethostname left the buffer unterminated.
    buf[buf.len() - 1] = 0;
    let cstr = CStr::from_bytes_until_nul(&buf)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "no nul"))?;
    Ok(cstr.to_string_lossy().into_owned())
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        let pid = std::process::id();
        std::env::temp_dir().join(format!("fluxor-rig-lock-{pid}-{name}"))
    }

    #[test]
    fn acquire_and_release() {
        let path = tmp_path("basic.lock");
        let _ = std::fs::remove_file(&path);
        let owner = LockOwner::now("rig-a", "test:x", 30);
        let outcome = acquire(&path, &owner, false).unwrap();
        match outcome {
            AcquireOutcome::Acquired(guard) => {
                assert!(path.exists());
                drop(guard);
                assert!(!path.exists());
            }
            _ => panic!("expected acquired"),
        }
    }

    #[test]
    fn second_acquire_reports_holder() {
        let path = tmp_path("held.lock");
        let _ = std::fs::remove_file(&path);
        let first = LockOwner::now("rig-a", "test:x", 30);
        let _g = match acquire(&path, &first, false).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            _ => panic!("first should succeed"),
        };
        let second = LockOwner::now("rig-a", "test:y", 30);
        match acquire(&path, &second, false).unwrap() {
            AcquireOutcome::Held(c) => {
                assert_eq!(c.existing.task, "test:x");
                assert!(!c.stale);
            }
            _ => panic!("second should be held"),
        }
    }

    #[test]
    fn force_takes_over() {
        let path = tmp_path("force.lock");
        let _ = std::fs::remove_file(&path);
        let first = LockOwner::now("rig-a", "test:x", 30);
        let _g = match acquire(&path, &first, false).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            _ => panic!(),
        };
        let second = LockOwner::now("rig-a", "test:y", 30);
        let outcome = acquire(&path, &second, true).unwrap();
        assert!(matches!(outcome, AcquireOutcome::Acquired(_)));
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("test:y"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn dropping_displaced_guard_leaves_new_owners_lock_intact() {
        let path = tmp_path("takeover.lock");
        let _ = std::fs::remove_file(&path);

        let first = LockOwner::now("rig-a", "test:x", 30);
        let first_guard = match acquire(&path, &first, false).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            _ => panic!("first should acquire"),
        };

        // Simulate a takeover: rewrite the file with a different owner.
        let mut second = LockOwner::now("rig-a", "test:y", 30);
        second.started_at = first.started_at + 1;
        std::fs::write(&path, serde_json::to_string_pretty(&second).unwrap()).unwrap();

        drop(first_guard);

        assert!(
            path.exists(),
            "displaced guard must not unlink the new owner's lockfile"
        );
        let persisted: LockOwner =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(persisted.task, "test:y");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn stale_threshold_formula() {
        let mut o = LockOwner::now("r", "t", 30);
        // max(2 * 30, 60) = 60
        assert_eq!(o.stale_threshold_s(), 60);
        o.effective_timeout_s = 120;
        // max(240, 60) = 240
        assert_eq!(o.stale_threshold_s(), 240);
        o.effective_timeout_s = 5;
        // max(10, 60) = 60
        assert_eq!(o.stale_threshold_s(), 60);
    }

    #[test]
    fn stale_lock_is_taken_over_without_force() {
        let path = tmp_path("stale.lock");
        let _ = std::fs::remove_file(&path);
        // Plant an owner with started_at way in the past.
        let mut ancient = LockOwner::now("rig-a", "test:old", 1);
        ancient.started_at = 0; // 1970; definitely older than 60s threshold
        let json = serde_json::to_string_pretty(&ancient).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).ok();
        std::fs::write(&path, json).unwrap();

        let new_owner = LockOwner::now("rig-a", "test:new", 30);
        match acquire(&path, &new_owner, false).unwrap() {
            AcquireOutcome::Acquired(_) => {
                let content = std::fs::read_to_string(&path).unwrap();
                assert!(content.contains("test:new"));
            }
            _ => panic!("stale lock should be taken over"),
        }
        let _ = std::fs::remove_file(&path);
    }
}
