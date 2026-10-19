//! Rig lockfile and teardown marker.
//!
//! A single physical rig is a serialisable resource: only one orchestrated
//! run should touch it at once. V1 uses a local lockfile with atomic
//! create semantics. Lock content identifies the owner (pid, hostname,
//! rig, what it's running, when it started, when it expects to be done)
//! so a stale lock can be inspected and forcibly released, leaving an
//! audit breadcrumb.
//!
//! Canonical paths under `~/.local/state/fluxor/labs/<lab>/rigs/<rig>/`:
//!
//!   * `lock` — the lockfile;
//!   * `state/needs_teardown.json` — the marker a run writes before it
//!     touches the rig and removes only after a clean teardown. A lock
//!     dies with its process (`kill -9` leaves the file, and the stale
//!     rule clears it); the marker is what records that the rig may
//!     still be running something, so a later claim tears down first.

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
    /// What the owner is running — e.g. `"scenario:pi5_boot_banner"` or
    /// `"command:power cycle"`. Free-form, just has to be useful in logs.
    pub task: String,
    /// Seconds since Unix epoch.
    pub started_at: u64,
    /// Effective timeout governing stale-lock detection:
    /// scenario `timeout_s` when present, else board `default_timeout_s`,
    /// else a sensible fallback.
    pub effective_timeout_s: u32,
    /// Seconds since Unix epoch by which the owner expects to be finished,
    /// every actuator timeout and the teardown allowance included. Read
    /// only from another host, where the pid cannot be probed. Absent in
    /// a lock written by an older core.
    #[serde(default)]
    pub expected_end: Option<u64>,
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
            expected_end: None,
        }
    }

    /// Fallback stale threshold for a lock with no `expected_end`:
    /// max(2 × effective_timeout_s, 60s).
    pub fn stale_threshold_s(&self) -> u64 {
        std::cmp::max(2 * self.effective_timeout_s as u64, 60)
    }

    pub fn age_s(&self) -> u64 {
        now_unix_secs().saturating_sub(self.started_at)
    }

    /// Whether this lock may be taken over without `--force`.
    ///
    /// On the owner's own host the question has an exact answer: a live
    /// pid is never stale, however long it has run (a metal launch can
    /// outlast any scenario timeout many times over), and a dead pid is
    /// stale at once. From another host only time is available: the lock
    /// is stale after `expected_end`, or after the old age formula when
    /// the lock predates that field.
    pub fn is_stale(&self) -> bool {
        if self.hostname == hostname() {
            return !pid_alive(self.pid);
        }
        match self.expected_end {
            Some(end) => now_unix_secs() > end,
            None => self.age_s() > self.stale_threshold_s(),
        }
    }
}

/// True when a process with this pid exists. `kill(pid, 0)` delivers
/// nothing; EPERM means the process exists but belongs to someone else,
/// which still counts as alive.
pub fn pid_alive(pid: u32) -> bool {
    // SAFETY: signal 0 performs the permission and existence checks only;
    // no signal is delivered and no memory is touched.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
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

    /// Rewrite the lock's `expected_end`, keeping every other field. Used
    /// when the guard is installed (the plan's actuator timeouts are known
    /// by then) and again when a `--hold` extends the run.
    pub fn set_expected_end(&self, expected_end: u64) -> Result<()> {
        let mut owner = read_owner(&self.path)?;
        if !self.token.matches(&owner) {
            return Err(Error::Config(format!(
                "rig lock: {} no longer names this process; another run took it over",
                self.path.display()
            )));
        }
        owner.expected_end = Some(expected_end);
        let f = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.path)
            .map_err(|e| {
                Error::Config(format!("rig lock: rewriting {}: {e}", self.path.display()))
            })?;
        write_owner(&f, &owner)?;
        f.sync_all().ok();
        Ok(())
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
    /// The lock is ours, but the rig's teardown marker says an earlier run
    /// never finished tearing down. The caller must run a teardown for the
    /// marker's run (holding this guard) and clear the marker before it
    /// does anything else with the rig.
    NeedsTeardown {
        guard: LockGuard,
        marker: TeardownMarker,
    },
}

pub fn acquire(lock_path: &Path, owner: &LockOwner, force: bool) -> Result<AcquireOutcome> {
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Config(format!("rig lock: creating {}: {e}", parent.display())))?;
    }

    // Atomic create-exclusive. If the file exists, we read the existing
    // owner to report it.
    let guard = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(lock_path)
    {
        Ok(f) => {
            write_owner(&f, owner)?;
            f.sync_all().ok();
            LockGuard {
                path: lock_path.to_path_buf(),
                token: OwnerToken::from(owner),
            }
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
                LockGuard {
                    path: lock_path.to_path_buf(),
                    token: OwnerToken::from(owner),
                }
            } else {
                return Ok(AcquireOutcome::Held(LockConflict {
                    path: lock_path.to_path_buf(),
                    existing,
                    stale,
                }));
            }
        }
        Err(e) => {
            return Err(Error::Config(format!(
                "rig lock: opening {}: {e}",
                lock_path.display()
            )))
        }
    };

    let marker_path = marker_path_for(lock_path);
    match TeardownMarker::read(&marker_path)? {
        Some(marker) => Ok(AcquireOutcome::NeedsTeardown { guard, marker }),
        None => Ok(AcquireOutcome::Acquired(guard)),
    }
}

/// Canonical lockfile path: `~/.local/state/fluxor/labs/<lab>/rigs/<rig>/lock`.
pub fn default_lock_path(lab: &str, rig: &str) -> Option<PathBuf> {
    Some(rig_state_root(lab, rig)?.join("lock"))
}

/// `~/.local/state/fluxor/labs/<lab>/rigs/<rig>/` — the directory the
/// lock, the run records and the state dir all live under.
pub fn rig_state_root(lab: &str, rig: &str) -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    Some(
        home.join(".local")
            .join("state")
            .join("fluxor")
            .join("labs")
            .join(lab)
            .join("rigs")
            .join(rig),
    )
}

/// The rig's persistent state directory, `<root>/state/`, owned by the
/// rig's backends across runs (what is staged, what is live) and by the
/// orchestrator for the teardown marker. Created `0700`: it may hold
/// anything a backend needs to find its own earlier work.
pub fn state_dir_for(lock_path: &Path) -> PathBuf {
    lock_path
        .parent()
        .map(|p| p.join("state"))
        .unwrap_or_else(|| PathBuf::from("state"))
}

pub fn ensure_state_dir(lock_path: &Path) -> Result<PathBuf> {
    let dir = state_dir_for(lock_path);
    std::fs::create_dir_all(&dir)
        .map_err(|e| Error::Config(format!("rig: creating state dir {}: {e}", dir.display())))?;
    let mut perms = std::fs::metadata(&dir)
        .map_err(|e| Error::Config(format!("rig: stat {}: {e}", dir.display())))?
        .permissions();
    use std::os::unix::fs::PermissionsExt;
    if perms.mode() & 0o777 != 0o700 {
        perms.set_mode(0o700);
        std::fs::set_permissions(&dir, perms)
            .map_err(|e| Error::Config(format!("rig: chmod {}: {e}", dir.display())))?;
    }
    Ok(dir)
}

pub fn marker_path_for(lock_path: &Path) -> PathBuf {
    state_dir_for(lock_path).join("needs_teardown.json")
}

/// `state/needs_teardown.json`: written when a run installs its guard,
/// removed only after every teardown step succeeded or was unsupported.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeardownMarker {
    pub schema: u32,
    pub rig: String,
    pub run_id: String,
    pub run_dir: String,
    /// Seconds since Unix epoch when the marker was written.
    pub since: u64,
    /// Why the last teardown attempt did not clear the marker, when one
    /// was made.
    #[serde(default)]
    pub last_error: Option<String>,
}

impl TeardownMarker {
    pub fn new(rig: &str, run_id: &str, run_dir: &Path) -> Self {
        Self {
            schema: 1,
            rig: rig.to_string(),
            run_id: run_id.to_string(),
            run_dir: run_dir.display().to_string(),
            since: now_unix_secs(),
            last_error: None,
        }
    }

    pub fn read(path: &Path) -> Result<Option<Self>> {
        let raw = match std::fs::read_to_string(path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(Error::Config(format!(
                    "rig: reading teardown marker {}: {e}",
                    path.display()
                )))
            }
        };
        serde_json::from_str(&raw).map(Some).map_err(|e| {
            Error::Config(format!(
                "rig: parsing teardown marker {}: {e} (content: {raw:?})",
                path.display()
            ))
        })
    }

    /// Atomic write: temp file + rename, so a reader never sees half a
    /// marker.
    pub fn write(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Config(format!("rig: creating {}: {e}", parent.display())))?;
        }
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| Error::Config(format!("rig: serialising teardown marker: {e}")))?;
        std::fs::write(&tmp, json)
            .map_err(|e| Error::Config(format!("rig: writing {}: {e}", tmp.display())))?;
        std::fs::rename(&tmp, path).map_err(|e| {
            Error::Config(format!(
                "rig: installing teardown marker {}: {e}",
                path.display()
            ))
        })
    }

    pub fn clear(path: &Path) -> Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Config(format!(
                "rig: removing teardown marker {}: {e}",
                path.display()
            ))),
        }
    }
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

pub fn hostname() -> String {
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

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RAII scratch directory + lock-file path. Caller binds both so
    /// the TempDir lives for the test scope; the file inside it is
    /// removed when the dir drops.
    fn tmp_path(name: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::Builder::new()
            .prefix("fluxor-rig-lock-")
            .tempdir()
            .expect("tempdir");
        let path = dir.path().join(name);
        (dir, path)
    }

    fn acquired(outcome: AcquireOutcome) -> LockGuard {
        match outcome {
            AcquireOutcome::Acquired(g) => g,
            AcquireOutcome::NeedsTeardown { .. } => panic!("unexpected teardown marker"),
            AcquireOutcome::Held(c) => panic!("unexpectedly held: {c:?}"),
        }
    }

    #[test]
    fn acquire_and_release() {
        let (_lock_dir, path) = tmp_path("basic.lock");
        let owner = LockOwner::now("rig-a", "test:x", 30);
        let guard = acquired(acquire(&path, &owner, false).unwrap());
        assert!(path.exists());
        drop(guard);
        assert!(!path.exists());
    }

    #[test]
    fn second_acquire_reports_holder() {
        let (_lock_dir, path) = tmp_path("held.lock");
        let first = LockOwner::now("rig-a", "test:x", 30);
        let _g = acquired(acquire(&path, &first, false).unwrap());
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
        let (_lock_dir, path) = tmp_path("force.lock");
        let first = LockOwner::now("rig-a", "test:x", 30);
        let _g = acquired(acquire(&path, &first, false).unwrap());
        let second = LockOwner::now("rig-a", "test:y", 30);
        let outcome = acquire(&path, &second, true).unwrap();
        assert!(matches!(outcome, AcquireOutcome::Acquired(_)));
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("test:y"));
    }

    #[test]
    fn dropping_displaced_guard_leaves_new_owners_lock_intact() {
        let (_lock_dir, path) = tmp_path("takeover.lock");

        let first = LockOwner::now("rig-a", "test:x", 30);
        let first_guard = acquired(acquire(&path, &first, false).unwrap());

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

    /// On the same host a live pid is never stale: a run that has outlived
    /// its scenario timeout many times over (a metal launch) is still a
    /// run, and must not be torn down from under itself.
    #[test]
    fn live_pid_on_this_host_is_never_stale_however_old() {
        let mut ours = LockOwner::now("rig-a", "test:long", 1);
        ours.started_at = 0; // 1970: ancient by any age formula
        ours.expected_end = Some(1); // and long past its expected end
        assert!(
            !ours.is_stale(),
            "our own live pid must never read as stale"
        );
    }

    #[test]
    fn dead_pid_on_this_host_is_stale_at_once() {
        // Spawn a process, let it exit, and reuse its pid: it is dead.
        let child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        let _ = child.wait_with_output();
        let mut dead = LockOwner::now("rig-a", "test:dead", 3600);
        dead.pid = pid;
        // Fresh, with hours of timeout left: only the dead pid makes it stale.
        assert!(dead.is_stale());
    }

    #[test]
    fn other_host_is_stale_only_after_expected_end() {
        let mut remote = LockOwner::now("rig-a", "test:remote", 1);
        remote.hostname = "some-other-host".into();
        remote.started_at = 0;
        remote.expected_end = Some(now_unix_secs() + 3600);
        assert!(!remote.is_stale(), "expected_end in the future: not stale");
        remote.expected_end = Some(now_unix_secs().saturating_sub(1));
        assert!(remote.is_stale(), "expected_end passed: stale");
    }

    #[test]
    fn other_host_without_expected_end_uses_age_formula() {
        let mut remote = LockOwner::now("rig-a", "test:old-core", 1);
        remote.hostname = "some-other-host".into();
        remote.expected_end = None;
        assert!(!remote.is_stale());
        remote.started_at = 0;
        assert!(remote.is_stale());
    }

    #[test]
    fn stale_lock_is_taken_over_without_force() {
        let (_lock_dir, path) = tmp_path("stale.lock");
        // Plant an owner from another host whose expected end has passed.
        let mut ancient = LockOwner::now("rig-a", "test:old", 1);
        ancient.hostname = "elsewhere".into();
        ancient.started_at = 0;
        ancient.expected_end = Some(1);
        let json = serde_json::to_string_pretty(&ancient).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).ok();
        std::fs::write(&path, json).unwrap();

        let new_owner = LockOwner::now("rig-a", "test:new", 30);
        let _g = acquired(acquire(&path, &new_owner, false).unwrap());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("test:new"));
    }

    #[test]
    fn lock_without_expected_end_field_still_parses() {
        let (_lock_dir, path) = tmp_path("old-format.lock");
        let json = r#"{"pid":1,"hostname":"elsewhere","rig":"rig-a","task":"t","started_at":0,"effective_timeout_s":1}"#;
        std::fs::write(&path, json).unwrap();
        let owner = read_owner(&path).unwrap();
        assert_eq!(owner.expected_end, None);
        assert!(owner.is_stale());
    }

    #[test]
    fn set_expected_end_rewrites_only_that_field() {
        let (_lock_dir, path) = tmp_path("extend.lock");
        let owner = LockOwner::now("rig-a", "test:x", 30);
        let guard = acquired(acquire(&path, &owner, false).unwrap());
        guard.set_expected_end(1_900_000_000).unwrap();
        let persisted = read_owner(&path).unwrap();
        assert_eq!(persisted.expected_end, Some(1_900_000_000));
        assert_eq!(persisted.task, "test:x");
        assert_eq!(persisted.started_at, owner.started_at);
    }

    #[test]
    fn marker_makes_acquire_report_needs_teardown_with_the_lock_held() {
        let (_lock_dir, path) = tmp_path("lock");
        let marker_path = marker_path_for(&path);
        TeardownMarker::new("rig-a", "run-1", Path::new("/tmp/run-1"))
            .write(&marker_path)
            .unwrap();
        let owner = LockOwner::now("rig-a", "test:x", 30);
        match acquire(&path, &owner, false).unwrap() {
            AcquireOutcome::NeedsTeardown { guard, marker } => {
                assert_eq!(marker.run_id, "run-1");
                assert!(path.exists(), "the lock is held while tearing down");
                TeardownMarker::clear(&marker_path).unwrap();
                drop(guard);
            }
            _ => panic!("a marker must surface as NeedsTeardown"),
        }
        assert!(!marker_path.exists());
        // With the marker gone the next claim is plain.
        let again = LockOwner::now("rig-a", "test:y", 30);
        let _g = acquired(acquire(&path, &again, false).unwrap());
    }

    #[test]
    fn marker_write_is_atomic_and_clear_is_idempotent() {
        let (_dir, path) = tmp_path("lock");
        let marker_path = marker_path_for(&path);
        let m = TeardownMarker::new("rig-a", "run-9", Path::new("/r"));
        m.write(&marker_path).unwrap();
        assert!(!marker_path.with_extension("json.tmp").exists());
        let back = TeardownMarker::read(&marker_path).unwrap().unwrap();
        assert_eq!(back.run_id, "run-9");
        TeardownMarker::clear(&marker_path).unwrap();
        TeardownMarker::clear(&marker_path).unwrap();
        assert!(TeardownMarker::read(&marker_path).unwrap().is_none());
    }

    #[test]
    fn state_dir_is_created_private() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path) = tmp_path("lock");
        let dir = ensure_state_dir(&path).unwrap();
        assert!(dir.is_dir());
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}
