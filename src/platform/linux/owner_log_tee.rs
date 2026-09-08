// Per-owner log tee — the Linux realization of the owner-scoped log
// surface.
//
// The global `log::Log`. Each record is (1) delegated to an env_logger `Logger`
// for stderr formatting + env-filter behaviour, and (2), when emitted on the
// scheduler (main) thread, owner-attributed and pushed into the kernel
// per-owner ring for `fluxor agent logs`.
//
// Single-writer discipline (rfc §4.2): the kernel rings are written only by the
// scheduler thread. The Linux runtime runs the scheduler single-threaded on the
// main thread, so on-step records push directly. Records emitted off the main
// thread (today only platform/background threads — the graph-integrated
// `proc_executor` worker path has no in-tree callers yet) go to stderr only;
// routing them into the owning ring via a bounded MPSC drained on the tick is
// the documented follow-up for when owner-scoped worker threads land (rfc §4.2).

// NOTE: this file is `include!`d into `linux.rs`, so it shares that module's
// imports (`OnceLock`, `thread`, `std::io::Write`). Other paths are fully
// qualified to avoid colliding with them.

/// The env_logger backend the tee delegates stderr to.
static INNER: OnceLock<env_logger::Logger> = OnceLock::new();
/// Whether the process that writes `path` is still running.
///
/// The pid is the filename's second field (`<ms>-<pid>.log`). A name that
/// does not parse is treated as live — retention declining to act on a file
/// it cannot identify is the safe direction, since the cost is an extra
/// file and the alternative is deleting a running applet's records.
fn writer_is_live(path: &std::path::Path) -> bool {
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return true;
    };
    let Some((_, pid)) = stem.rsplit_once('-') else {
        return true;
    };
    let Ok(pid) = pid.parse::<u32>() else {
        return true;
    };
    std::path::Path::new(&format!("/proc/{pid}")).is_dir()
}

/// Exec mode (`FLUXOR_EXEC=<applet>`, set by `fluxor exec`): the file this
/// run's records go to, so fd 2 stays the program's. `None` outside exec
/// mode, or when the file could not be made.
static EXEC_SINK: OnceLock<Option<std::sync::Mutex<std::fs::File>>> = OnceLock::new();
/// Exec mode: mirror every record to stderr as well (`fluxor exec -v`).
static EXEC_MIRROR: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// The scheduler (main) thread id — only records emitted here reach the rings.
static SCHED_TID: OnceLock<std::thread::ThreadId> = OnceLock::new();
/// Owner attribution consults the scheduler (`current_module_index` → HAL),
/// which is only legal once the runtime is initialized. Until then every
/// record is a platform/boot record → owner 0, no scheduler access. Set by
/// [`enable_owner_log_attribution`] right before the main loop.
static ATTRIBUTION_READY: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

struct TeeLogger;

impl log::Log for TeeLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        INNER.get().map(|l| l.enabled(metadata)).unwrap_or(false)
    }

    fn log(&self, record: &log::Record<'_>) {
        let Some(inner) = INNER.get() else { return };
        match EXEC_SINK.get().and_then(|sink| sink.as_ref()) {
            // An applet run: the record goes to the run's file, and reaches
            // stderr only when it explains a non-zero status — an error —
            // or when the person asked to see everything.
            Some(file) => {
                if !inner.enabled(record.metadata()) {
                    return;
                }
                if let Ok(mut file) = file.lock() {
                    use std::io::Write as _;
                    let _ = writeln!(file, "{}", format_record(record));
                }
                if record.level() <= log::Level::Error
                    || EXEC_MIRROR.load(std::sync::atomic::Ordering::Relaxed)
                {
                    inner.log(record);
                }
            }
            None => {
                inner.log(record);
                if !inner.enabled(record.metadata()) {
                    return;
                }
            }
        }
        // Ring routing is scheduler-thread-only (single writer). Off-thread
        // records are on stderr only; they are not ringed.
        if SCHED_TID.get() != Some(&std::thread::current().id()) {
            return;
        }
        let (uid, slot, generation) =
            if ATTRIBUTION_READY.load(std::sync::atomic::Ordering::Relaxed) {
                on_step_attribution()
            } else {
                // Boot-phase record: the scheduler/HAL is not up yet; this is a
                // platform log → owner 0.
                ([0u8; 16], 0, 0)
            };
        let ts_ms = now_unix_ms();
        let message = format!("{}", record.args());
        // The committed plan generation at emit — the §17.2 join key between a
        // log record and the rollout it ran under. A plain static read on the
        // scheduler thread (we are on it: the SCHED_TID gate above), safe even
        // before HAL init; 0 until the first plan applies.
        let plan_generation = fluxor::kernel::workload::owner_plan::last_applied_generation();
        // `module` is left empty: the message text already carries the module's
        // own "[name] …" convention, and the graph module name is populated from
        // the module-scoped logger (never by parsing), per §4.2.
        fluxor::kernel::workload::owner_log::push_on_slot(
            slot as usize,
            uid,
            generation,
            plan_generation,
            ts_ms,
            &[],
            message.as_bytes(),
        );
    }

    fn flush(&self) {
        if let Some(inner) = INNER.get() {
            inner.flush();
        }
        if let Some(Some(file)) = EXEC_SINK.get() {
            if let Ok(mut file) = file.lock() {
                use std::io::Write as _;
                let _ = file.flush();
            }
        }
    }
}

/// One record as a line: the shape stderr has always had, so a run's file
/// reads the same as a dev run's terminal.
fn format_record(record: &log::Record<'_>) -> String {
    format!(
        "[{} {:<5} {}] {}",
        now_unix_ms(),
        record.level(),
        record.target(),
        record.args()
    )
}

/// Runs an applet keeps: older files under its log directory are removed
/// when a new run starts.
const EXEC_RUNS_KEPT: usize = 10;

/// Open this run's log file under the applet's directory:
/// `$XDG_STATE_HOME/fluxor/exec/<applet>/<start-ms>-<pid>.log`, else the
/// same under `~/.local/state`. `fluxor applet logs` resolves it the same
/// way. Nothing here fails the run: a directory that cannot be made means
/// the records go to stderr as they would outside exec mode.
fn open_exec_sink(applet: &str) -> Option<std::sync::Mutex<std::fs::File>> {
    let base = if let Some(xdg) = std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
        std::path::PathBuf::from(xdg)
    } else if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        std::path::PathBuf::from(home).join(".local/state")
    } else {
        return None;
    };
    // The applet name is a catalogue key, never a path: keep it to one
    // component.
    if applet.is_empty() || applet.contains(['/', '\\']) || applet == "." || applet == ".." {
        return None;
    }
    let dir = base.join("fluxor").join("exec").join(applet);
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .ok()?;
    // Retention only ever reclaims runs that have ENDED. A file names the
    // pid that writes it, and a live writer holds it open: unlinking that
    // one does not free anything — the inode stays until the process exits
    // — and it takes the run's records out of `applet logs` while the run
    // is still producing them. So a still-running pid is skipped, and a
    // long-lived applet cannot be pruned out from under itself by ten short
    // runs beside it.
    let mut runs: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "log"))
        .filter(|p| !writer_is_live(p))
        .collect();
    runs.sort();
    if runs.len() + 1 > EXEC_RUNS_KEPT {
        for old in &runs[..runs.len() + 1 - EXEC_RUNS_KEPT] {
            let _ = std::fs::remove_file(old);
        }
    }
    use std::os::unix::fs::OpenOptionsExt as _;
    let path = dir.join(format!("{:013}-{}.log", now_unix_ms(), std::process::id()));
    // The first line of this file is the run's argv, so it is the invoker's
    // to read and nobody else's: 0600 on the file and 0700 on the directory
    // above it, rather than whatever the umask happens to allow.
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .ok()?;
    let argv: Vec<String> = std::env::args().collect();
    use std::io::Write as _;
    let _ = writeln!(
        file,
        "[{} INFO  fluxor_linux] [exec] applet '{}' pid {} argv {:?}",
        now_unix_ms(),
        applet,
        std::process::id(),
        argv
    );
    Some(std::sync::Mutex::new(file))
}

static TEE: TeeLogger = TeeLogger;

/// Install the tee as the global logger, replacing the direct env_logger init.
/// Must run before the first `log!` call (`log::set_logger` is once-per-process).
fn install_owner_log_tee() {
    // Own the timestamp (unix ms, matching the ring records) so env_logger's
    // `humantime`/jiff timestamp backend isn't needed. Level + module filtering
    // still comes from `env_filter` via `RUST_LOG`.
    let logger = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            use std::io::Write;
            writeln!(buf, "{}", format_record(record))
        })
        .build();
    log::set_max_level(logger.filter());
    let _ = INNER.set(logger);
    // Exec mode: `fluxor exec` names the applet; its records are filed
    // under that name and fd 2 is left to the program.
    let sink = std::env::var("FLUXOR_EXEC")
        .ok()
        .filter(|name| !name.is_empty())
        .and_then(|name| open_exec_sink(&name));
    if std::env::var_os("FLUXOR_EXEC_LOG_STDERR").is_some_and(|v| !v.is_empty()) {
        EXEC_MIRROR.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let _ = EXEC_SINK.set(sink);
    // If another logger was already installed (e.g. a test harness), keep it and
    // fall back to plain stderr formatting rather than panicking.
    let _ = log::set_logger(&TEE);
}

/// Record the calling thread as the scheduler thread (main loop). Called once,
/// on the main thread, before the step loop.
fn register_scheduler_thread() {
    let _ = SCHED_TID.set(std::thread::current().id());
}

/// Enable owner attribution: called once the scheduler and HAL are fully
/// initialized (right before the main loop). Records emitted earlier were
/// attributed to owner 0 without consulting the scheduler.
fn enable_owner_log_attribution() {
    ATTRIBUTION_READY.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// On-step owner attribution: the module the scheduler is currently stepping →
/// its owner `(uid, slot, generation)`, or owner 0 (system) when the current
/// module is system-owned. Valid only on the scheduler thread.
fn on_step_attribution() -> ([u8; 16], u16, u32) {
    let idx = fluxor::kernel::exec::scheduler::current_module_index();
    fluxor::kernel::exec::scheduler::module_owner_attribution(idx).unwrap_or_default()
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Flush every owner's ring to its file under `logs_dir`
/// (`<uid>.<slot>.<generation>.ring`). Called on the scheduler thread on the
/// same ~100 ms tick as the status writer. Only slots with new records since the
/// last flush are rewritten. Scheduler thread only.
fn flush_owner_rings(logs_dir: &std::path::Path) {
    // Per-slot high-water mark of the last flushed record position, keyed by
    // the owner IDENTITY `(uid, generation, next_seq)` — not `next_seq` alone.
    // `install_slot` resets a slot's ring to seq 0 for a new tenant, so a bare
    // seq watermark could alias the new tenant's early records to the previous
    // tenant's flushed ones and skip the new ring file entirely (a low-volume
    // module might never get its file). Main-thread-only, so a plain static is
    // safe.
    static mut LAST_FLUSHED: [([u8; 16], u32, u64); fluxor::kernel::workload::owner::MAX_OWNERS] =
        [([0u8; 16], 0u32, 0u64); fluxor::kernel::workload::owner::MAX_OWNERS];

    let mut created_dir = false;
    for slot in 0..fluxor::kernel::workload::owner::MAX_OWNERS {
        let next = fluxor::kernel::workload::owner_log::next_seq(slot);
        if next == 0 {
            continue; // never written
        }
        let (uid, generation) = fluxor::kernel::workload::owner_log::installed_identity(slot);
        // SAFETY: scheduler-thread-only access to the flush high-water table.
        let already_flushed = unsafe {
            let hw = &raw const LAST_FLUSHED;
            (*hw)[slot] == (uid, generation, next)
        };
        if already_flushed {
            continue; // nothing new since last flush
        }

        let Some((header, buffer)) = fluxor::kernel::workload::owner_log::snapshot_slot_bytes(slot) else {
            continue;
        };

        if !created_dir {
            let _ = std::fs::create_dir_all(logs_dir);
            created_dir = true;
        }
        let mut name = String::with_capacity(32);
        for byte in &uid {
            name.push_str(&format!("{byte:02x}"));
        }
        let path = logs_dir.join(format!("{name}.{slot}.{generation}.ring"));
        // The high-water only advances on a SUCCESSFUL write: a transient
        // failure (full disk, missing dir, permission blip) must leave the
        // slot dirty so the next tick retries — not wait for another record
        // to arrive.
        if write_ring_file(&path, &header, &buffer) {
            // SAFETY: scheduler-thread-only access to the flush high-water table,
            // reached through a raw pointer.
            unsafe {
                let hw = &raw mut LAST_FLUSHED;
                (*hw)[slot] = (uid, generation, next);
            }
        }
    }
}

/// Write a ring file in place: `[header][ring bytes]`. Not tmp+rename — that is
/// wrong for rings (it orphans a follower's fd); a follower tolerates a torn
/// read via the per-record CRC (rfc §4.3). The whole file is rewritten each
/// flush.
/// Returns true only when the full `[header][ring bytes]` image landed —
/// the caller's flush high-water must not advance otherwise.
fn write_ring_file(
    path: &std::path::Path,
    header: &fluxor_contracts::log_ring::RingHeader,
    buffer: &[u8],
) -> bool {
    let mut bytes = Vec::with_capacity(fluxor_contracts::log_ring::HEADER_LEN + buffer.len());
    bytes.extend_from_slice(&header.encode());
    bytes.extend_from_slice(buffer);
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
    else {
        return false;
    };
    use std::io::Seek as _;
    if file.seek(std::io::SeekFrom::Start(0)).is_err() {
        return false;
    }
    if file.write_all(&bytes).is_err() {
        return false;
    }
    file.set_len(bytes.len() as u64).is_ok()
}
