// cli_in / cli_out built-ins — the host stdio/argv/exit-code surface. Host
// facts stay host-side: argv, stdin, stdout, stderr, and the process exit
// code are owned by these built-ins; app modules remain pure channel-in/out.
//
//   cli_in   args_out  (out 0)  one record: argv after `--`, NUL-separated
//            stdin_out (out 1)  stdin bytes (worker thread → ExtBridge)
//   cli_out  bytes_in  (in 0)   → process stdout (ExtBridge → worker thread)
//            err_in    (in 1)   → process stderr (ditto)
//            exit_in   (in 2)   [code: i32 LE] latches CLI_EXIT_CODE
//
// Blocking I/O lives on worker threads, never in `module_step` — the
// proc_executor discipline. Backpressure is real in both directions:
// stdin pump blocks on a full bridge (`Block` policy), and cli_out stops
// draining a channel whose bridge is full, which backpressures the app
// through ordinary channel fullness.
//
// Completion (the CLI-ness): cli_in returns Done once argv is emitted and
// stdin has hit EOF fully flushed; cli_out returns Done when an exit record
// arrives, or when every upstream producer is finished and its inputs and
// bridges are drained. The plain-run completion branch then exits the
// process with CLI_EXIT_CODE.

use fluxor::kernel::workload::extbridge::{ExtBridge, OverloadPolicy, PushOutcome};
use portable_atomic::AtomicI32;
use std::sync::Arc;
use fluxor::platform::builtin_param_tags::cli_in as cli_in_tags;
use fluxor::platform::builtin_param_tags::cli_out as cli_out_tags;

const CLI_IN_HASH: u32 = 0x39EB09AD; // fnv1a32("cli_in")
const CLI_OUT_HASH: u32 = 0xD0D89096; // fnv1a32("cli_out")

/// Ring capacity per stream. Power of two, > frame header, several channel
/// buffers deep so a slow consumer doesn't immediately stall the pump.
const CLI_BRIDGE_CAP: usize = 8192;
/// One frame ≤ half a default channel buffer, so a popped frame always fits
/// the all-or-nothing channel write in at most a few steps.
const CLI_CHUNK: usize = 1024;

/// The exit code the plain-run completion branch reports (default 0). Set by
/// cli_out's `exit_in`. Node-agent mode never reads it.
pub(crate) static CLI_EXIT_CODE: AtomicI32 = AtomicI32::new(0);

/// Set once the applet latches its exit code (via cli_out's `exit_in`). cli_in
/// keys off this to stop pumping stdin — otherwise a live-TTY stdin (no EOF)
/// would keep the graph from ever completing after the applet is done.
pub(crate) static CLI_EXIT_LATCHED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Set once cli_out itself has retired: the applet is finished and its last
/// bytes are on the fd. A plain run ends there.
///
/// The all-modules-done rule alone is not enough for an applet that wires a
/// platform provider. A provider like `linux_net` serves whoever asks and has
/// no notion of being finished, so it never retires and a graph containing one
/// would run until it was killed. The CLI sink does know: nothing can produce
/// output after it retires, so the run is over whatever else is still willing
/// to be asked.
///
/// Set by a wired sink only. `cli` is a platform stanza, so a graph that names
/// it for its stdin alone still gets a `cli_out`; one that nothing feeds never
/// retires, having no output that could be over.
pub(crate) static CLI_RUN_COMPLETE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

// ── Interactive terminal (raw stdin) ────────────────────────────────────────
//
// When cli_in owns a TTY stdin, disable canonical mode + local echo so an
// interactive applet (`nanocloud exec -it`) gets char-at-a-time input with no
// double echo. We deliberately do NOT touch OPOST/ISIG: output `\n`→`\r\n`
// stays intact (so non-interactive commands print correctly even though stdin
// is always wired), and Ctrl-C still signals. The original termios is saved in
// a signal-safe static and restored on the exit path (and via SIGINT/SIGTERM).
static TERM_RAW_ACTIVE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
static mut TERM_ORIG: core::mem::MaybeUninit<libc::termios> = core::mem::MaybeUninit::uninit();

/// Restore the terminal saved by `enter_raw_stdin` (idempotent; signal-safe —
/// only a static read + `tcsetattr`, both async-signal-safe).
pub(crate) fn restore_terminal() {
    use core::sync::atomic::Ordering;
    if TERM_RAW_ACTIVE.swap(false, Ordering::AcqRel) {
        // SAFETY: the AcqRel swap on TERM_RAW_ACTIVE proves `enter_raw_stdin`
        // Release-published TERM_ORIG before setting the flag, so the static
        // is initialised; tcsetattr only reads it.
        unsafe {
            let t = core::ptr::addr_of!(TERM_ORIG);
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, (*t).as_ptr());
        }
    }
}

extern "C" fn term_signal_handler(sig: i32) {
    restore_terminal();
    // Re-raise with the default disposition so the process dies normally.
    // SAFETY: signal + raise are async-signal-safe libc calls with constant
    // arguments; nothing here touches Rust-managed state.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// Put a TTY stdin into interactive mode (ICANON + ECHO off). No-op if stdin is
/// not a terminal. Installs SIGINT/SIGTERM handlers to restore on interruption.
fn enter_raw_stdin() {
    use core::sync::atomic::Ordering;
    // SAFETY: single-threaded platform init is the only caller, so the
    // TERM_ORIG write cannot race; termios calls operate on a zeroed local
    // filled by tcgetattr before use, and the handler pointers are valid
    // for the process lifetime.
    unsafe {
        if libc::isatty(libc::STDIN_FILENO) != 1 {
            return;
        }
        let mut t: libc::termios = core::mem::zeroed();
        if libc::tcgetattr(libc::STDIN_FILENO, &mut t) != 0 {
            return;
        }
        core::ptr::addr_of_mut!(TERM_ORIG).write(core::mem::MaybeUninit::new(t));
        TERM_RAW_ACTIVE.store(true, Ordering::Release);
        let mut raw = t;
        raw.c_lflag &= !(libc::ICANON | libc::ECHO);
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw);
        libc::signal(libc::SIGINT, term_signal_handler as libc::sighandler_t);
        libc::signal(libc::SIGTERM, term_signal_handler as libc::sighandler_t);
    }
}

/// The process argv after the first `--`, NUL-joined (empty when no `--` or
/// nothing follows it). Host code reads the real env::args — no config baking.
fn argv_record() -> Vec<u8> {
    let mut out = Vec::new();
    let mut seen_sep = false;
    for a in std::env::args() {
        if seen_sep {
            if !out.is_empty() {
                out.push(0);
            }
            out.extend_from_slice(a.as_bytes());
        } else if a == "--" {
            seen_sep = true;
        }
    }
    out
}

// ── cli_in ──────────────────────────────────────────────────────────────────

struct CliInState {
    args_out: i32,
    stdin_out: i32,
    args_sent: bool,
    bridge: Option<Arc<ExtBridge<CLI_BRIDGE_CAP>>>,
    eof: Arc<portable_atomic::AtomicBool>,
    /// Frame bytes accepted from the bridge but not yet written to the
    /// channel (consumer was full). Drained before the next pop.
    pending: Vec<u8>,
    pending_pos: usize,
    /// Steps spent trying to hand argv to a channel that will not take it.
    ///
    /// Bounded because the two reasons a write is refused are
    /// indistinguishable here and only one of them ever resolves: a FIFO
    /// answers `EAGAIN` both when it is momentarily FULL and when the record
    /// is larger than it can EVER hold. Retrying forever is right for the
    /// first and a hang for the second.
    args_retries: u32,
}

/// How long to keep offering argv before calling it undeliverable.
///
/// At the default 100 µs tick this is a few seconds — far longer than a
/// consumer needs to drain a full channel, and short enough that a record
/// which will never fit is reported while someone is still watching. The
/// reader side already bounds its own wait the same way (`ARGV_WAIT` in
/// chronicle_cli); this is the missing half of that pair.
const ARGS_WRITE_RETRIES: u32 = 20_000;

fn cli_in_step(state: *mut u8) -> i32 {
    // SAFETY: kernel-owned arena sized to `CliInState` by the loader.
    let st = unsafe { instance_state::<CliInState>(state) };

    // argv first: one record, retried until the channel takes it whole.
    if !st.args_sent {
        if st.args_out < 0 {
            st.args_sent = true;
        } else {
            let rec = argv_record();
            if rec.is_empty() {
                // A zero-length channel write is meaningless; an absent/empty
                // argv is simply "no record" — apps treat silence as no args.
                st.args_sent = true;
            } else {
                // SAFETY: pointer/length from an owned Vec.
                let w = unsafe { channel::channel_write(st.args_out, rec.as_ptr(), rec.len()) };
                if w == rec.len() as i32 {
                    st.args_sent = true;
                } else {
                    st.args_retries = st.args_retries.saturating_add(1);
                    if st.args_retries < ARGS_WRITE_RETRIES {
                        return 0; // channel full — retry next step, order preserved
                    }
                    // Undeliverable. Almost always the record is bigger than
                    // the channel, in which case no number of retries helps.
                    //
                    // **This used to hang, silently and forever**, and the
                    // symptom was as far from the cause as it gets: a CLI
                    // applet whose argument grew past the channel simply
                    // never started, with nothing in the log and no exit. A
                    // caller sees a command that produces no output and does
                    // not return — indistinguishable from a deadlock in the
                    // applet itself, which is where anyone would look first.
                    //
                    // Reported, then given up on rather than retried: the
                    // graph continues, the applet reads no argv, and an
                    // applet with no arguments prints its help. A visible
                    // wrong answer beats an invisible non-answer.
                    log::error!(
                        "[cli_in] argv record ({} bytes) could not be written to the \
                         args channel after {} attempts — it is most likely larger than \
                         the channel's capacity. The applet will start with NO arguments.",
                        rec.len(),
                        st.args_retries
                    );
                    st.args_sent = true;
                }
            }
        }
    }

    let Some(bridge) = st.bridge.as_ref() else {
        // stdin_out unwired: argv was the whole job.
        return if st.args_sent { 1 } else { 0 };
    };

    // The applet finished (latched its exit) — stop pumping stdin so the graph
    // can complete even when stdin is a live TTY that never sends EOF.
    if st.args_sent && CLI_EXIT_LATCHED.load(Ordering::Acquire) {
        return 1;
    }

    // Flush pending before popping more — byte order under backpressure.
    while st.pending_pos < st.pending.len() {
        // SAFETY: offset/length stay within the owned Vec.
        let w = unsafe {
            channel::channel_write(
                st.stdin_out,
                st.pending.as_ptr().add(st.pending_pos),
                st.pending.len() - st.pending_pos,
            )
        };
        if w > 0 {
            st.pending_pos += w as usize;
        } else {
            return 0;
        }
    }
    st.pending.clear();
    st.pending_pos = 0;

    let mut frame = [0u8; CLI_CHUNK];
    while let Some(n) = bridge.pop_frame(&mut frame) {
        let mut written = 0usize;
        while written < n {
            // SAFETY: `written < n <= frame.len()`.
            let w = unsafe {
                channel::channel_write(st.stdin_out, frame.as_ptr().add(written), n - written)
            };
            if w > 0 {
                written += w as usize;
            } else {
                st.pending.extend_from_slice(&frame[written..n]);
                return 0;
            }
        }
    }

    if st.args_sent && st.eof.load(Ordering::Acquire) && bridge.is_empty() && st.pending.is_empty()
    {
        return 1; // Done: argv out, stdin closed and fully forwarded
    }
    0
}

/// Construct a `cli_in` built-in: read this process's argv/stdin. The stdin
/// pump thread is spawned only when `stdin_out` is wired.
fn build_cli_in(module_idx: usize) -> scheduler::BuiltInModule {
    scheduler::set_current_module(module_idx);
    let args_out = scheduler::module_port(module_idx, cli_in_tags::PORT_ARGS_OUT);
    let stdin_out = scheduler::module_port(module_idx, cli_in_tags::PORT_STDIN_OUT);

    let eof = Arc::new(portable_atomic::AtomicBool::new(false));
    let bridge = if stdin_out >= 0 {
        // An applet may consume stdin interactively (`exec -it`); put a TTY into
        // char-at-a-time, no-echo mode (restored on exit / interrupt).
        enter_raw_stdin();
        let b: Arc<ExtBridge<CLI_BRIDGE_CAP>> = Arc::new(ExtBridge::new(OverloadPolicy::Block));
        let pump = Arc::clone(&b);
        let pump_eof = Arc::clone(&eof);
        std::thread::spawn(move || {
            use std::io::Read;
            let mut stdin = std::io::stdin().lock();
            let mut buf = [0u8; CLI_CHUNK];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        // Block policy: the pump (never module_step) waits out
                        // a full ring — real backpressure to the terminal/pipe.
                        while let PushOutcome::Rejected = pump.push_frame(&buf[..n]) {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    }
                }
            }
            pump_eof.store(true, Ordering::Release);
        });
        Some(b)
    } else {
        eof.store(true, Ordering::Release);
        None
    };

    let mut m = scheduler::BuiltInModule::new("cli_in", cli_in_step);
    install_state(
        &mut m,
        Box::new(CliInState {
            args_out,
            stdin_out,
            args_sent: false,
            bridge,
            eof,
            pending: Vec::new(),
            pending_pos: 0,
            args_retries: 0,
        }),
    );
    log::info!(
        "[inst] module {module_idx} = cli_in (built-in) args_out={args_out} stdin_out={stdin_out}"
    );
    m
}

// ── cli_out ─────────────────────────────────────────────────────────────────

struct CliOutState {
    module_idx: usize,
    bytes_in: i32,
    err_in: i32,
    exit_in: i32,
    stdout_bridge: Option<Arc<ExtBridge<CLI_BRIDGE_CAP>>>,
    stderr_bridge: Option<Arc<ExtBridge<CLI_BRIDGE_CAP>>>,
    exited: bool,
}

/// Drain one input channel into one bridge. Reads a chunk **only when the
/// bridge provably has room for it**, so a full ring leaves the bytes in the
/// channel — backpressure the producing app observes as channel fullness —
/// rather than reading and then dropping them on a rejected push. Stops when
/// the channel is empty or the bridge is full. Returns whether anything moved.
fn drain_to_bridge(chan: i32, bridge: &ExtBridge<CLI_BRIDGE_CAP>) -> bool {
    let mut moved = false;
    let mut buf = [0u8; CLI_CHUNK];
    loop {
        // Prove capacity for a full chunk before consuming any bytes. A read of
        // up to CLI_CHUNK bytes then always pushes losslessly.
        if !bridge.has_room_for(CLI_CHUNK) {
            break;
        }
        // SAFETY: stack buffer of CLI_CHUNK bytes.
        let n = unsafe { channel::channel_read(chan, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            break;
        }
        match bridge.push_frame(&buf[..n as usize]) {
            PushOutcome::Rejected => {
                // Unreachable: we proved room for a full CLI_CHUNK and read at
                // most that many bytes. A rejection means the capacity
                // accounting is wrong; fail loudly in debug rather than spin,
                // and break in release (no bytes were pushed, but none are lost
                // — the read bytes are dropped only in this can't-happen path).
                debug_assert!(false, "cli_out bridge rejected a capacity-proven push");
                break;
            }
            _ => moved = true,
        }
    }
    moved
}

fn cli_out_step(state: *mut u8) -> i32 {
    // SAFETY: kernel-owned arena sized to `CliOutState` by the loader.
    let st = unsafe { instance_state::<CliOutState>(state) };

    let mut moved = false;
    if let (true, Some(b)) = (st.bytes_in >= 0, st.stdout_bridge.as_ref()) {
        // drain_to_bridge proves per-chunk capacity itself, so a full ring
        // leaves bytes in the channel rather than dropping them.
        moved |= drain_to_bridge(st.bytes_in, b);
    }
    if let (true, Some(b)) = (st.err_in >= 0, st.stderr_bridge.as_ref()) {
        moved |= drain_to_bridge(st.err_in, b);
    }

    if st.exit_in >= 0 && !st.exited {
        let mut rec = [0u8; 8];
        // SAFETY: stack buffer.
        let n = unsafe { channel::channel_read(st.exit_in, rec.as_mut_ptr(), rec.len()) };
        if n >= 4 {
            let code = i32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
            CLI_EXIT_CODE.store(code, Ordering::Release);
            CLI_EXIT_LATCHED.store(true, Ordering::Release);
            st.exited = true;
            log::info!("[cli] exit code latched: {code}");
        }
    }

    if moved {
        return 0;
    }

    // Completion: an explicit exit, or every producer that can still feed us is
    // finished with nothing left in flight. This uses the completion-predecessor
    // set (ALL edges, including feedback-cycle back-edges) rather than the
    // forward-only upstream mask — otherwise a sink downstream of the
    // tcp_client/linux_net cycle would retire before its async reply is decoded.
    // Bridges must be empty so the worker threads have written the tail to the fds.
    let upstream_done = scheduler::module_completion_predecessors_finished(st.module_idx);
    let flushed = st.stdout_bridge.as_ref().is_none_or(|b| b.is_empty())
        && st.stderr_bridge.as_ref().is_none_or(|b| b.is_empty());
    // A sink nothing feeds carries no such claim. `cli` is a platform
    // stanza, so a graph that names it for its stdin alone still gets a
    // `cli_out`, and an unwired one has no predecessors at all —
    // `upstream_done` is vacuously true of it. Retiring on that would end
    // the run at its first step, cutting off a graph whose work is outbound
    // rather than printed: one that publishes to a broker would die before
    // its connect completed. Only a fed sink falling quiet means the output
    // is over.
    let wired = st.bytes_in >= 0 || st.err_in >= 0 || st.exit_in >= 0;
    if wired && flushed && (st.exited || upstream_done) {
        CLI_RUN_COMPLETE.store(true, Ordering::Release);
        return 1;
    }
    0
}

/// Spawn a worker that pops bridge frames and writes them to a host stream.
fn spawn_sink_worker<W: std::io::Write + Send + 'static>(
    bridge: Arc<ExtBridge<CLI_BRIDGE_CAP>>,
    mut sink: W,
) {
    std::thread::spawn(move || {
        let mut frame = [0u8; CLI_CHUNK];
        loop {
            match bridge.pop_frame(&mut frame) {
                Some(n) => {
                    if sink.write_all(&frame[..n]).is_err() {
                        return; // consumer hung up (broken pipe)
                    }
                    let _ = sink.flush();
                }
                None => std::thread::sleep(Duration::from_millis(1)),
            }
        }
    });
}

/// Construct a `cli_out` built-in: own stdout/stderr and the exit-code latch.
fn build_cli_out(module_idx: usize) -> scheduler::BuiltInModule {
    scheduler::set_current_module(module_idx);
    let bytes_in = scheduler::module_port(module_idx, cli_out_tags::PORT_BYTES_IN);
    let err_in = scheduler::module_port(module_idx, cli_out_tags::PORT_ERR_IN);
    let exit_in = scheduler::module_port(module_idx, cli_out_tags::PORT_EXIT_IN);

    let stdout_bridge = (bytes_in >= 0).then(|| {
        let b: Arc<ExtBridge<CLI_BRIDGE_CAP>> = Arc::new(ExtBridge::new(OverloadPolicy::Block));
        spawn_sink_worker(Arc::clone(&b), std::io::stdout());
        b
    });
    let stderr_bridge = (err_in >= 0).then(|| {
        let b: Arc<ExtBridge<CLI_BRIDGE_CAP>> = Arc::new(ExtBridge::new(OverloadPolicy::Block));
        spawn_sink_worker(Arc::clone(&b), std::io::stderr());
        b
    });

    let mut m = scheduler::BuiltInModule::new("cli_out", cli_out_step);
    install_state(
        &mut m,
        Box::new(CliOutState {
            module_idx,
            bytes_in,
            err_in,
            exit_in,
            stdout_bridge,
            stderr_bridge,
            exited: false,
        }),
    );
    log::info!(
        "[inst] module {module_idx} = cli_out (built-in) bytes_in={bytes_in} err_in={err_in} exit_in={exit_in}"
    );
    m
}
