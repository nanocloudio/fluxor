//! Transport dispatch — long-running subprocess that streams NDJSON events.
//!
//! Used for `console.*`, `telemetry.*`, `observe.*` and the `watch` side of
//! `deploy.*`. Invocation:
//!
//!   1. Spawn `<executable> <verb>` in its own process group with stdin,
//!      stdout and stderr piped.
//!   2. Write the JSON [`BackendInvocation`] to stdin; close stdin.
//!   3. Spawn a reader thread that parses one NDJSON
//!      [`TransportEvent`](super::protocol::TransportEvent) per line from
//!      stdout and forwards it (translated into a [`RunEvent`]) into the
//!      matcher's channel, and one that copies stderr to the operator's
//!      terminal and, when asked, to a log beside the run.
//!   4. On [`TransportHandle`] drop: SIGTERM to the process group, the
//!      grace period (the binding's `shutdown_grace_s`, default 2 s), then
//!      SIGKILL to whatever of the group is left; then join the readers,
//!      waiting no longer than the grace period again for a pipe some
//!      process outside the group still holds.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crate::error::{Error, Result};
use crate::rig::backend::discover::BackendRef;
use crate::rig::backend::protocol::{BackendInvocation, TransportEvent, EXIT_UNSUPPORTED_VERB};
use crate::rig::backend::{terminate_group, with_relay, DEFAULT_SHUTDOWN_GRACE};
use crate::rig::events::{DeployEvent, RunEvent};
use crate::rig::vocab::Capability;

/// How to run one transport.
#[derive(Debug, Clone)]
pub struct AttachOptions {
    /// Time between SIGTERM and SIGKILL at shutdown.
    pub grace: Duration,
    /// Where to keep the backend's stderr beside the run, in addition to
    /// the operator's terminal.
    pub stderr_log: Option<PathBuf>,
}

impl Default for AttachOptions {
    fn default() -> Self {
        Self {
            grace: DEFAULT_SHUTDOWN_GRACE,
            stderr_log: None,
        }
    }
}

/// Handle to a running transport subprocess. Drop signals shutdown
/// (SIGTERM → grace → SIGKILL to the process group) and joins the readers.
pub struct TransportHandle {
    backend: BackendRef,
    child: Option<Child>,
    /// One message from each reader thread when it finishes.
    readers_done: Receiver<()>,
    readers: usize,
    shutdown: Arc<AtomicBool>,
    /// Set when the backend reports `ready` (its observation is live), or
    /// when its stdout closes — a backend that is gone is not still
    /// getting ready.
    ready: Arc<AtomicBool>,
    grace: Duration,
}

impl TransportHandle {
    pub fn backend(&self) -> &BackendRef {
        &self.backend
    }

    /// Whether the backend has said its observation is live, or exited.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Whether the backend exited saying the verb is unsupported (exit
    /// 64) — a deploy backend with nothing to `watch`. Asked after its
    /// stdout closed, which happens an instant before the process is
    /// reapable, so a short wait for the status is part of the answer.
    pub fn exited_unsupported(&mut self) -> bool {
        let Some(child) = self.child.as_mut() else {
            return false;
        };
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return status.code() == Some(EXIT_UNSUPPORTED_VERB),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => return false,
            }
        }
    }
}

impl Drop for TransportHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(mut child) = self.child.take() {
            // The whole group, so a helper the backend spawned (a
            // `journalctl -f`, a capture process) dies with it rather than
            // holding the stdout pipe open.
            terminate_group(&mut child, self.grace);
        }
        // A reader still blocked at the deadline is on a pipe held by a
        // process outside the group; it ends when that process does.
        let deadline = Instant::now() + self.grace;
        for _ in 0..self.readers {
            let left = deadline.saturating_duration_since(Instant::now());
            if self.readers_done.recv_timeout(left).is_err() {
                break;
            }
        }
    }
}

/// Attach with the default shutdown grace and no stderr log.
pub fn attach(
    backend: BackendRef,
    verb: &str,
    invocation: &BackendInvocation,
    events: Sender<RunEvent>,
) -> Result<TransportHandle> {
    attach_with(backend, verb, invocation, events, &AttachOptions::default())
}

pub fn attach_with(
    backend: BackendRef,
    verb: &str,
    invocation: &BackendInvocation,
    events: Sender<RunEvent>,
    options: &AttachOptions,
) -> Result<TransportHandle> {
    let invocation = with_relay(invocation, &backend);
    let invocation = &invocation;

    // Every transport speaks on behalf of one capability: the qualified
    // `<surface>.<name>` of its backend. Byte events carry it so the
    // matcher routes them to the correct per-source buffer, and a close
    // names the source that went quiet. A probe on the observe surface
    // reports its results as bytes too, so the same byte-buffer/regex
    // pipeline evaluates scenario rules against them.
    let qualified = format!("{}.{}", backend.surface.as_str(), backend.name);
    let source = Capability::parse(&qualified).map_err(|e| {
        Error::Config(format!(
            "transport: cannot identify the capability for backend '{}': {e}",
            backend.slug(),
        ))
    })?;
    let stderr_log = options.stderr_log.clone();

    let mut child = backend
        .command(verb)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Own process group, so shutdown signals the backend and every
        // process it spawned with one `kill(-pgid, …)`, and a terminal's
        // Ctrl-C reaches the orchestrator rather than the backend.
        .process_group(0)
        .spawn()
        .map_err(|e| {
            Error::Config(format!(
                "rig backend: spawning `{}`: {e}",
                backend.describe(verb)
            ))
        })?;

    let json = serde_json::to_string(invocation)
        .map_err(|e| Error::Config(format!("rig backend: serialising invocation: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(json.as_bytes());
        let _ = stdin.write_all(b"\n");
        drop(stdin);
    }

    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        terminate_group(&mut child, options.grace);
        return Err(Error::Config("transport: stdio pipes missing".into()));
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(AtomicBool::new(false));
    let (done_tx, readers_done) = mpsc::channel();

    let spawned = spawn_reader(format!("fluxor-rig/{}", backend.slug()), done_tx.clone(), {
        let (shutdown, ready, slug) = (shutdown.clone(), ready.clone(), backend.slug());
        move || run_reader_loop(stdout, events, source, shutdown, ready, slug)
    })
    .and_then(|()| {
        spawn_reader(
            format!("fluxor-rig/{}/stderr", backend.slug()),
            done_tx,
            move || copy_stderr(stderr, stderr_log),
        )
    });
    if let Err(e) = spawned {
        terminate_group(&mut child, options.grace);
        return Err(e);
    }

    Ok(TransportHandle {
        backend,
        child: Some(child),
        readers_done,
        readers: 2,
        shutdown,
        ready,
        grace: options.grace,
    })
}

fn spawn_reader(
    name: String,
    done: Sender<()>,
    body: impl FnOnce() + Send + 'static,
) -> Result<()> {
    std::thread::Builder::new()
        .name(name)
        .spawn(move || {
            body();
            let _ = done.send(());
        })
        .map(|_| ())
        .map_err(|e| Error::Config(format!("transport: spawning reader thread: {e}")))
}

/// The backend's stderr is its human-readable diagnostics: the operator
/// sees it live, and the run keeps a copy, created when the backend first
/// says something.
fn copy_stderr(mut stderr: impl Read, log_path: Option<PathBuf>) {
    let mut log: Option<std::fs::File> = None;
    let mut chunk = [0u8; 4096];
    loop {
        match stderr.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let _ = std::io::stderr().write_all(&chunk[..n]);
                if log.is_none() {
                    log = log_path
                        .as_ref()
                        .and_then(|p| std::fs::File::create(p).ok());
                }
                if let Some(f) = log.as_mut() {
                    let _ = f.write_all(&chunk[..n]);
                }
            }
        }
    }
}

fn run_reader_loop(
    stdout: ChildStdout,
    events: Sender<RunEvent>,
    source: Capability,
    shutdown: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    slug: String,
) {
    let reader = BufReader::new(stdout);
    for line in reader.lines() {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let event: TransportEvent = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[rig] {slug}: malformed event line (skipped): {e} — raw: {trimmed:?}");
                continue;
            }
        };

        // Everything the backend said before `ready` is already queued, so
        // whoever waits on the flag sees it in order.
        let is_ready = matches!(event, TransportEvent::Ready);
        if let Some(ev) = translate(event, source, &slug) {
            if events.send(ev).is_err() {
                break;
            }
        }
        if is_ready {
            ready.store(true, Ordering::Release);
        }
    }

    ready.store(true, Ordering::Release);
    let _ = events.send(RunEvent::TransportClosed {
        source,
        reason: "transport backend exited".into(),
    });
}

/// Map a wire-format event to the in-process event type the matcher
/// understands. Returns `None` for events that are diagnostics-only.
fn translate(event: TransportEvent, source: Capability, slug: &str) -> Option<RunEvent> {
    match event {
        TransportEvent::Bytes { data } => match crate::b64::decode(&data) {
            Some(bytes) => Some(RunEvent::ConsoleBytes { source, bytes }),
            None => {
                eprintln!("[rig] {slug}: bytes event with malformed base64 (dropped)");
                None
            }
        },
        TransportEvent::Boot => Some(RunEvent::Boot { source }),
        TransportEvent::Fetch {
            filename,
            client_ip,
        } => Some(RunEvent::DeployProgress(DeployEvent::ArtifactFetched {
            filename,
            client_ip,
            at: SystemTime::now(),
        })),
        TransportEvent::Dhcp => Some(RunEvent::DeployProgress(DeployEvent::DhcpActivity)),
        TransportEvent::Error { message } => {
            Some(RunEvent::DeployProgress(DeployEvent::Error(message)))
        }
        TransportEvent::Note { message } => {
            eprintln!("[rig] backend note: {message}");
            None
        }
        TransportEvent::Ready => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rig::backend::protocol::{BackendContext, PHASE_RUN};
    use crate::rig::vocab::Surface;
    use std::collections::BTreeMap;
    use std::sync::mpsc;

    /// Returns (tmp dir, backend ref, exec-spawn lock guard).
    ///
    /// The guard serialises the write-and-spawn window across all tests
    /// in this binary — see `rig::test_utils::EXEC_SPAWN_LOCK` for why
    /// unique paths alone aren't enough to prevent Linux ETXTBSY races.
    /// Callers must keep the guard alive until after their
    /// `Command::spawn` has returned; in practice holding it for the
    /// whole test body is the simplest pattern.
    fn fixture(
        name: &str,
        surface: Surface,
        script: &str,
    ) -> (
        crate::rig::test_utils::UniqueTmpDir,
        BackendRef,
        std::sync::MutexGuard<'static, ()>,
    ) {
        use std::os::unix::fs::PermissionsExt;
        let guard = crate::rig::test_utils::lock_exec_spawn();
        let tmp = crate::rig::test_utils::unique_tmp_dir(&format!("transport-{name}"));
        let slug = format!("{}-{}", surface.as_str(), name);
        let exe = tmp.join(&slug);
        std::fs::write(&exe, script).unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        (
            tmp,
            BackendRef {
                surface,
                name: name.to_string(),
                executable: exe,
                relay: None,
            },
            guard,
        )
    }

    fn sample_invocation() -> BackendInvocation {
        BackendInvocation {
            binding: BTreeMap::new(),
            context: BackendContext {
                rig_id: "pi5-a".into(),
                lab: "default".into(),
                run_id: "test-run".into(),
                run_dir: "/tmp".into(),
                scenario_name: "test".into(),
                board: "pi5".into(),
                effective_timeout_ms: 10_000,
                phase: PHASE_RUN.into(),
                state_dir: "/tmp".into(),
            },
            artifact: None,
            args: None,
            relay: None,
        }
    }

    #[test]
    fn streams_bytes_then_closes_naming_the_source() {
        // Backend emits one bytes event then exits. The matcher channel
        // should receive ConsoleBytes + TransportClosed, both tagged.
        let data = crate::b64::encode(b"hello");
        let script = format!(
            "#!/bin/sh\nread _input\nprintf '{{\"kind\":\"bytes\",\"data\":\"{data}\"}}\\n'\nexit 0\n"
        );
        let (_dir, backend, _exec_guard) = fixture("serial", Surface::Console, &script);
        let (tx, rx) = mpsc::channel::<RunEvent>();
        let handle = attach(backend, "attach", &sample_invocation(), tx).unwrap();

        let first = rx.recv_timeout(Duration::from_secs(2)).expect("bytes");
        match first {
            RunEvent::ConsoleBytes { source, bytes } => {
                assert_eq!(bytes, b"hello");
                assert_eq!(source.as_str(), "console.serial");
            }
            other => panic!("unexpected first event: {other:?}"),
        }
        let second = rx.recv_timeout(Duration::from_secs(2)).expect("closed");
        match second {
            RunEvent::TransportClosed { source, .. } => {
                assert_eq!(source.as_str(), "console.serial");
            }
            other => panic!("unexpected second event: {other:?}"),
        }
        drop(handle);
    }

    #[test]
    fn boot_event_translates_with_its_source() {
        let script = "#!/bin/sh\nread _input\nprintf '{\"kind\":\"boot\"}\\n'\nexit 0\n";
        let (_dir, backend, _exec_guard) = fixture("usb_cdc", Surface::Console, script);
        let (tx, rx) = mpsc::channel::<RunEvent>();
        let _h = attach(backend, "attach", &sample_invocation(), tx).unwrap();
        match rx.recv_timeout(Duration::from_secs(2)).expect("boot") {
            RunEvent::Boot { source } => assert_eq!(source.as_str(), "console.usb_cdc"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn fetch_event_translates_into_deploy_progress() {
        let script = r#"#!/bin/sh
read _input
printf '{"kind":"fetch","filename":"kernel8.img","client_ip":"10.0.0.2"}\n'
exit 0
"#;
        let (_dir, backend, _exec_guard) = fixture("netboot_tftp", Surface::Deploy, script);
        let (tx, rx) = mpsc::channel::<RunEvent>();
        let _handle = attach(backend, "watch", &sample_invocation(), tx).unwrap();

        let ev = rx.recv_timeout(Duration::from_secs(2)).expect("fetch");
        match ev {
            RunEvent::DeployProgress(DeployEvent::ArtifactFetched {
                filename,
                client_ip,
                ..
            }) => {
                assert_eq!(filename, "kernel8.img");
                assert_eq!(client_ip.as_deref(), Some("10.0.0.2"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn malformed_line_is_skipped_not_fatal() {
        let script = r#"#!/bin/sh
read _input
echo 'not json'
printf '{"kind":"dhcp"}\n'
"#;
        let (_dir, backend, _exec_guard) = fixture("netboot_tftp", Surface::Deploy, script);
        let (tx, rx) = mpsc::channel::<RunEvent>();
        let _h = attach(backend, "watch", &sample_invocation(), tx).unwrap();
        let ev = rx.recv_timeout(Duration::from_secs(2)).expect("dhcp");
        assert!(matches!(
            ev,
            RunEvent::DeployProgress(DeployEvent::DhcpActivity)
        ));
    }

    #[test]
    fn deploy_watch_that_exits_64_is_reported_unsupported() {
        let script = "#!/bin/sh\nread _input\nexit 64\n";
        let (_dir, backend, _exec_guard) = fixture("picotool", Surface::Deploy, script);
        let (tx, rx) = mpsc::channel::<RunEvent>();
        let mut h = attach(backend, "watch", &sample_invocation(), tx).unwrap();
        let _closed = rx.recv_timeout(Duration::from_secs(2)).expect("closed");
        assert!(h.exited_unsupported());
    }

    #[test]
    fn drop_sends_sigterm_promptly() {
        // Backend sleeps for "a long time". Drop should terminate it
        // quickly — well under the 2s SIGTERM → SIGKILL grace window.
        //
        // Uses the standard shell pattern for trap-catching-while-waiting:
        // run sleep in the background so the shell's `wait` returns on
        // signal, trap fires, kills the child, exits — closing the stdout
        // pipe so the reader thread sees EOF immediately.
        let script = r#"#!/bin/sh
read _input
sleep 60 &
CHILD=$!
trap "kill $CHILD 2>/dev/null; exit 0" TERM
wait $CHILD
"#;
        // Distinct `name` per test so parallel runs get separate tmp dirs.
        let (_dir, backend, _exec_guard) = fixture("ssh_stage_reboot", Surface::Deploy, script);
        let (tx, _rx) = mpsc::channel::<RunEvent>();
        let handle = attach(backend, "attach", &sample_invocation(), tx).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let start = Instant::now();
        drop(handle);
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "drop took too long: {elapsed:?}"
        );
    }

    /// A backend that exits on SIGTERM but leaves a child that ignores it
    /// (and holds stdout) must not wedge the drop: the group gets SIGKILL
    /// whether or not the backend itself went quietly.
    #[test]
    fn drop_kills_a_child_that_outlives_its_backend() {
        let script = r#"#!/bin/sh
read _input
( trap '' TERM; exec sleep 30 ) &
echo $! > "$STUBBORN_PID"
wait
"#;
        let (dir, backend, _exec_guard) = fixture("stubborn", Surface::Observe, script);
        let pidfile = dir.join("stubborn.pid");
        std::env::set_var("STUBBORN_PID", &pidfile);
        let backend = BackendRef {
            name: "pcap".into(),
            ..backend
        };
        let (tx, _rx) = mpsc::channel::<RunEvent>();
        let handle = attach(backend, "attach", &sample_invocation(), tx).unwrap();
        std::env::remove_var("STUBBORN_PID");
        let deadline = Instant::now() + Duration::from_secs(2);
        while !pidfile.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let start = Instant::now();
        drop(handle);
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(4),
            "drop waited on the stubborn child: {elapsed:?}"
        );
        let pid: u32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !crate::rig::lock::pid_alive(pid),
            "child {pid} survived the group kill"
        );
    }

    /// A transport's stderr is kept beside the run.
    #[test]
    fn stderr_is_kept_in_the_log() {
        let script = "#!/bin/sh\nread _input\necho 'tty opened' >&2\nprintf '{\"kind\":\"ready\"}\\n'\nexit 0\n";
        let (dir, backend, _exec_guard) = fixture("serial", Surface::Console, script);
        let log = dir.join("console-serial-attach.stderr.log");
        let (tx, rx) = mpsc::channel::<RunEvent>();
        let h = attach_with(
            backend,
            "attach",
            &sample_invocation(),
            tx,
            &AttachOptions {
                grace: Duration::from_millis(300),
                stderr_log: Some(log.clone()),
            },
        )
        .unwrap();
        let _closed = rx.recv_timeout(Duration::from_secs(2)).expect("closed");
        drop(h);
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "tty opened\n");
    }

    #[test]
    fn drop_kills_unresponsive_backend_after_grace_window() {
        // Backend refuses SIGTERM entirely. With a short grace, drop
        // should SIGKILL it and return promptly.
        let script = r#"#!/bin/sh
read _input
trap '' TERM
# Use a short sleep so we exit even if SIGKILL somehow misses.
sleep 30
"#;
        let (_dir, backend, _exec_guard) = fixture("bootfs_copy", Surface::Deploy, script);
        let (tx, _rx) = mpsc::channel::<RunEvent>();
        let handle = attach_with(
            backend,
            "attach",
            &sample_invocation(),
            tx,
            &AttachOptions {
                grace: Duration::from_millis(400),
                stderr_log: None,
            },
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let start = Instant::now();
        drop(handle);
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "drop took too long: {elapsed:?}"
        );
    }
}
