//! Transport dispatch — long-running subprocess that streams NDJSON events.
//!
//! Used for `console.*`, `telemetry.*`, `observe.*` and the `watch` side of
//! `deploy.*`. Invocation:
//!
//!   1. Spawn `<executable> <verb>` with stdin/stdout piped.
//!   2. Write the JSON [`BackendInvocation`] to stdin; close stdin.
//!   3. Spawn a reader thread that parses one NDJSON
//!      [`TransportEvent`](super::protocol::TransportEvent) per line from
//!      stdout and forwards it (translated into a [`RunEvent`]) into the
//!      matcher's channel.
//!   4. On [`TransportHandle`] drop: send SIGTERM, wait the grace period
//!      (2 s unless the binding set `shutdown_grace_s`), then SIGKILL.
//!      Join the reader thread.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdout, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use crate::error::{Error, Result};
use crate::rig::backend::discover::BackendRef;
use crate::rig::backend::protocol::{BackendInvocation, TransportEvent, EXIT_UNSUPPORTED_VERB};
use crate::rig::backend::with_relay;
use crate::rig::events::{DeployEvent, RunEvent};
use crate::rig::vocab::Capability;

/// Handle to a running transport subprocess. Drop signals shutdown
/// (SIGTERM → grace → SIGKILL) and joins the reader thread.
pub struct TransportHandle {
    backend: BackendRef,
    child: Option<Child>,
    reader: Option<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
    /// Set when the backend reports `ready` (its observation is live), or
    /// when it exits — a backend that is gone is not still getting ready.
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
            // Backends are spawned in their own process group (see
            // `attach`), so the pgid matches the child's pid. Signal
            // the whole group so grandchildren (e.g. a `journalctl`
            // spawned by the backend script) die too — otherwise they
            // keep the stdout pipe open and wedge the reader thread.
            let pid = child.id() as i32;
            // SAFETY: negative pid signals the whole process group;
            // libc::kill has no memory effects, only signal delivery.
            unsafe {
                libc::kill(-pid, libc::SIGTERM);
            }
            let deadline = Instant::now() + self.grace;
            let exited = loop {
                match child.try_wait() {
                    Ok(Some(_)) => break true,
                    Ok(None) => {
                        if Instant::now() >= deadline {
                            break false;
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => break true,
                }
            };
            if !exited {
                // SAFETY: same group-signal as the SIGTERM above.
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
                let _ = child.wait();
            }
        }

        if let Some(r) = self.reader.take() {
            let _ = r.join();
        }
    }
}

/// Attach with the default 2 s shutdown grace.
pub fn attach(
    backend: BackendRef,
    verb: &str,
    invocation: &BackendInvocation,
    events: Sender<RunEvent>,
) -> Result<TransportHandle> {
    attach_with_grace(backend, verb, invocation, events, Duration::from_secs(2))
}

pub fn attach_with_grace(
    backend: BackendRef,
    verb: &str,
    invocation: &BackendInvocation,
    events: Sender<RunEvent>,
    grace: Duration,
) -> Result<TransportHandle> {
    let invocation = with_relay(invocation, &backend);
    let invocation = &invocation;
    let mut child = backend
        .command(verb)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        // Put the backend in its own process group so shutdown can
        // signal the whole tree (script + any subprocesses it spawned)
        // with one `kill(-pgid, …)`.
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

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Config("transport: stdout missing".into()))?;

    // Every transport speaks on behalf of one capability: the qualified
    // `<surface>.<name>` of its backend. Byte events carry it so the
    // matcher routes them to the correct per-source buffer, and a close
    // names the source that went quiet. Observe-surface backends (e.g.
    // `observe-https_load`) emit synthesised NDJSON bytes summarising
    // probe results so the same byte-buffer/regex pipeline evaluates
    // scenario rules against them; `observe.netboot_fetch` is produced by
    // the deploy backend's `watch` verb, not a transport of its own.
    let qualified = format!("{}.{}", backend.surface.as_str(), backend.name);
    let source = Capability::parse(&qualified).map_err(|e| {
        Error::Config(format!(
            "transport: cannot identify the capability for backend '{}': {e}",
            backend.slug(),
        ))
    })?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_thr = shutdown.clone();
    let ready = Arc::new(AtomicBool::new(false));
    let ready_thr = ready.clone();
    let slug_for_thread = backend.slug();

    let reader = std::thread::Builder::new()
        .name(format!("fluxor-rig/{}", backend.slug()))
        .spawn(move || {
            run_reader_loop(
                stdout,
                events,
                source,
                shutdown_thr,
                ready_thr,
                slug_for_thread,
            );
        })
        .map_err(|e| Error::Config(format!("transport: spawning reader thread: {e}")))?;

    Ok(TransportHandle {
        backend,
        child: Some(child),
        reader: Some(reader),
        shutdown,
        ready,
        grace,
    })
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
        let handle = attach_with_grace(
            backend,
            "attach",
            &sample_invocation(),
            tx,
            Duration::from_millis(400),
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
