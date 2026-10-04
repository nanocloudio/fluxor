// ── Stopping on a signal ────────────────────────────────────────────────────
//
// SIGTERM and SIGINT stop the runtime by draining its graph: every
// drain-capable module is asked to drain, the graph keeps stepping while
// those with work in flight finish it, and the process exits once they have
// or the drain deadline passes. A module holding a lease or staged writes
// gets to commit and release them instead of holding them until they lapse.
// The same sender asking again stops at once. Either way the process ends by
// the signal it was sent, so whoever sent it sees the status it always did.
//
// "The same sender" matters because one request often arrives twice: a
// terminal's Ctrl-C, or a service manager's stop, reaches the `fluxor` CLI
// and this runtime together, and the CLI forwards what it got. Counting the
// forward as a second request would turn every ordinary stop into an
// immediate one.

/// Set by the first SIGTERM / SIGINT; the main loop starts the drain.
static STOP_REQUESTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// The signal that asked.
static STOP_SIGNAL: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
/// Who asked first (`si_pid`; 0 for the kernel, as for a terminal's Ctrl-C).
static STOP_SENDER: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);

/// How long a drain may take before the runtime exits regardless, unless
/// `FLUXOR_DRAIN_MS` says otherwise.
const DEFAULT_DRAIN_MS: u64 = 10_000;

extern "C" fn stop_signal_handler(sig: i32, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    use core::sync::atomic::Ordering;
    // SAFETY: the kernel passes a valid siginfo to an SA_SIGINFO handler.
    let sender = if info.is_null() { 0 } else { unsafe { (*info).si_pid() } };
    if !STOP_REQUESTED.load(Ordering::Acquire) {
        STOP_SIGNAL.store(sig, Ordering::Release);
        STOP_SENDER.store(sender, Ordering::Release);
        STOP_REQUESTED.store(true, Ordering::Release);
        return;
    }
    if sender != STOP_SENDER.load(Ordering::Acquire) {
        // The same request by another route.
        return;
    }
    // Asked twice: stop now, with the default disposition.
    restore_terminal();
    // SAFETY: signal + raise are async-signal-safe libc calls with constant
    // arguments; nothing here touches Rust-managed state.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// Route SIGTERM and SIGINT to a drain.
fn install_stop_signals() {
    // SAFETY: the handler only touches atomics, or restores the terminal and
    // re-raises; its pointer is valid for the process lifetime. The
    // sigaction is zeroed and then filled before use; masking both signals
    // during the handler keeps the first request's fields consistent.
    unsafe {
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = stop_signal_handler as usize;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaddset(&mut sa.sa_mask, libc::SIGINT);
        libc::sigaddset(&mut sa.sa_mask, libc::SIGTERM);
        libc::sigaction(libc::SIGINT, &sa, core::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, core::ptr::null_mut());
    }
}

fn stop_requested() -> bool {
    STOP_REQUESTED.load(core::sync::atomic::Ordering::Acquire)
}

/// End the process by the signal that stopped it.
fn exit_by_stop_signal() -> ! {
    let sig = STOP_SIGNAL.load(core::sync::atomic::Ordering::Acquire);
    restore_terminal();
    // SAFETY: plain libc calls with a signal number the handler recorded.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
    process::exit(128 + sig);
}

/// Publish the final owner status and logs, then end the process by the
/// signal that stopped it.
fn finish_stop(
    owner_status: Option<&mut OwnerStatusWriter>,
    logs_dir: Option<&std::path::Path>,
) -> ! {
    if let Some(w) = owner_status {
        w.tick();
    }
    if let Some(dir) = logs_dir {
        flush_owner_rings(dir);
    }
    exit_by_stop_signal();
}

/// The drain deadline: `FLUXOR_DRAIN_MS`, or [`DEFAULT_DRAIN_MS`].
fn drain_deadline() -> Duration {
    let ms = std::env::var("FLUXOR_DRAIN_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_DRAIN_MS);
    Duration::from_millis(ms)
}

/// A drain under way: the modules it waits for and when it gives up.
struct StopDrain {
    waiting: fluxor::kernel::workload::bitmask::ModuleMask,
    deadline: Instant,
}

impl StopDrain {
    fn begin() -> Self {
        let mut waiting = fluxor::kernel::workload::bitmask::ModuleMask::EMPTY;
        let asked = scheduler::begin_stop_drain(&mut waiting);
        let limit = drain_deadline();
        log::info!(
            "[stop] draining: {asked} module(s) asked, {} finishing work in flight, deadline {} ms",
            waiting.count_ones(),
            limit.as_millis()
        );
        StopDrain {
            waiting,
            deadline: Instant::now() + limit,
        }
    }

    /// Whether the drain is over: every module it waited for finished, or
    /// the deadline passed first.
    fn over(&self) -> bool {
        if scheduler::stop_drain_settled(&self.waiting) {
            log::info!("[stop] drained; exiting");
            return true;
        }
        if Instant::now() < self.deadline {
            return false;
        }
        for i in self.waiting.iter_set() {
            if !scheduler::module_is_finished(i) {
                log::warn!("[stop] module {i} had not finished draining at the deadline");
            }
        }
        true
    }
}
