// Per-owner log tee (rfc_owner_drain_and_logs.md Part B) — the Linux
// realization of the owner-scoped log surface.
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
        // Preserve existing stderr behaviour exactly.
        inner.log(record);
        if !inner.enabled(record.metadata()) {
            return;
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
    }
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
            writeln!(
                buf,
                "[{} {:<5} {}] {}",
                now_unix_ms(),
                record.level(),
                record.target(),
                record.args()
            )
        })
        .build();
    log::set_max_level(logger.filter());
    let _ = INNER.set(logger);
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
