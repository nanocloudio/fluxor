//! Transport dispatch — long-running subprocess that streams NDJSON events.
//!
//! Used for `console.*`, `telemetry.*`, and the `watch` side of `deploy.*`.
//! Invocation:
//!
//!   1. Spawn `<executable> <verb>` with stdin/stdout piped.
//!   2. Write the JSON [`BackendInvocation`] to stdin; close stdin.
//!   3. Spawn a reader thread that parses one NDJSON
//!      [`TransportEvent`](super::protocol::TransportEvent) per line from
//!      stdout and forwards it (translated into a [`RunEvent`]) into the
//!      matcher's channel.
//!   4. On [`TransportHandle`] drop: send SIGTERM, wait up to 2s, then
//!      SIGKILL. Join the reader thread.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;

use crate::error::{Error, Result};
use crate::rig::backend::discover::BackendRef;
use crate::rig::backend::protocol::{BackendInvocation, TransportEvent};
use crate::rig::events::{DeployEvent, RunEvent};
use crate::rig::vocab::{Capability, Surface};

/// Handle to a running transport subprocess. Drop signals shutdown
/// (SIGTERM → 2s grace → SIGKILL) and joins the reader thread.
pub struct TransportHandle {
    backend: BackendRef,
    child: Option<Child>,
    reader: Option<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
}

impl TransportHandle {
    pub fn backend(&self) -> &BackendRef {
        &self.backend
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
            unsafe {
                libc::kill(-pid, libc::SIGTERM);
            }
            let deadline = Instant::now() + Duration::from_secs(2);
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

pub fn attach(
    backend: BackendRef,
    verb: &str,
    invocation: &BackendInvocation,
    events: Sender<RunEvent>,
) -> Result<TransportHandle> {
    let mut child = Command::new(&backend.executable)
        .arg(verb)
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
                "rig backend: spawning `{} {verb}`: {e}",
                backend.executable.display()
            ))
        })?;

    let json = serde_json::to_string(invocation).map_err(|e| {
        Error::Config(format!("rig backend: serialising invocation: {e}"))
    })?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(json.as_bytes());
        let _ = stdin.write_all(b"\n");
        drop(stdin);
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Config("transport: stdout missing".into()))?;

    let surface = backend.surface;
    // Static label used in TransportClosed events — owned by the backend.
    let label: &'static str = match surface {
        Surface::Console => "console",
        Surface::Deploy => "deploy",
        Surface::Telemetry => "telemetry",
        Surface::Observe => "observe",
        Surface::Power => "power",
        Surface::Rig => "rig",
    };

    // For transports that emit bytes (console.*, telemetry.*), compute the
    // fully-qualified capability this backend speaks on. Byte events carry
    // this tag so the matcher routes them to the correct per-source buffer
    // and rules that name a specific capability match only their own
    // traffic.
    let byte_source: Option<Capability> = match surface {
        Surface::Console | Surface::Telemetry => {
            let qualified = format!("{}.{}", surface.as_str(), backend.name);
            Some(Capability::parse(&qualified).map_err(|e| {
                Error::Config(format!(
                    "transport: cannot identify byte-source capability for backend '{}': {e}",
                    backend.slug(),
                ))
            })?)
        }
        _ => None,
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_thr = shutdown.clone();
    let slug_for_thread = backend.slug();

    let reader = std::thread::Builder::new()
        .name(format!("fluxor-rig/{}", backend.slug()))
        .spawn(move || {
            run_reader_loop(
                stdout,
                events,
                byte_source,
                label,
                shutdown_thr,
                slug_for_thread,
            );
        })
        .map_err(|e| Error::Config(format!("transport: spawning reader thread: {e}")))?;

    Ok(TransportHandle {
        backend,
        child: Some(child),
        reader: Some(reader),
        shutdown,
    })
}

fn run_reader_loop(
    stdout: ChildStdout,
    events: Sender<RunEvent>,
    byte_source: Option<Capability>,
    label: &'static str,
    shutdown: Arc<AtomicBool>,
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

        if let Some(ev) = translate(event, byte_source, &slug) {
            if events.send(ev).is_err() {
                break;
            }
        }
    }

    let _ = events.send(RunEvent::TransportClosed {
        source: label,
        reason: "transport backend exited".into(),
    });
}

/// Map a wire-format event to the in-process event type the matcher
/// understands. Returns `None` for events that are diagnostics-only or
/// for byte events emitted by backends that have no byte-source
/// capability (non-transport surfaces — the spec forbids these).
fn translate(
    event: TransportEvent,
    byte_source: Option<Capability>,
    slug: &str,
) -> Option<RunEvent> {
    match event {
        TransportEvent::Bytes { data } => match BASE64_STANDARD.decode(data.as_bytes()) {
            Ok(bytes) => {
                let source = match byte_source {
                    Some(s) => s,
                    None => {
                        eprintln!(
                            "[rig] {slug}: backend emitted a bytes event but its surface has \
                             no byte-source mapping; dropped"
                        );
                        return None;
                    }
                };
                Some(RunEvent::ConsoleBytes { source, bytes })
            }
            Err(_) => None, // skip malformed base64 silently; stderr logged by the backend
        },
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
    use crate::rig::backend::protocol::BackendContext;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
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
        PathBuf,
        BackendRef,
        std::sync::MutexGuard<'static, ()>,
    ) {
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
                board: "cm5".into(),
                effective_timeout_ms: 10_000,
            },
            artifact: None,
        }
    }

    #[test]
    fn streams_bytes_then_closes() {
        // Backend emits one bytes event then exits. The matcher channel
        // should receive ConsoleBytes + TransportClosed.
        let data = BASE64_STANDARD.encode(b"hello");
        let script = format!(
            "#!/bin/sh\nread _input\nprintf '{{\"kind\":\"bytes\",\"data\":\"{data}\"}}\\n'\nexit 0\n"
        );
        let (dir, backend, _exec_guard) = fixture("serial", Surface::Console, &script);
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
        assert!(matches!(second, RunEvent::TransportClosed { .. }));
        drop(handle);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn fetch_event_translates_into_deploy_progress() {
        let script = r#"#!/bin/sh
read _input
printf '{"kind":"fetch","filename":"kernel8.img","client_ip":"10.0.0.2"}\n'
exit 0
"#;
        let (dir, backend, _exec_guard) = fixture("netboot_tftp", Surface::Deploy, script);
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
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn malformed_line_is_skipped_not_fatal() {
        let script = r#"#!/bin/sh
read _input
echo 'not json'
printf '{"kind":"dhcp"}\n'
"#;
        let (dir, backend, _exec_guard) = fixture("journal", Surface::Deploy, script);
        let (tx, rx) = mpsc::channel::<RunEvent>();
        let _h = attach(backend, "watch", &sample_invocation(), tx).unwrap();
        let ev = rx.recv_timeout(Duration::from_secs(2)).expect("dhcp");
        assert!(matches!(
            ev,
            RunEvent::DeployProgress(DeployEvent::DhcpActivity)
        ));
        std::fs::remove_dir_all(dir).ok();
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
        // Use the Deploy surface so the byte-source-capability check is
        // skipped — these tests exercise process management, not bytes.
        // Distinct `name` per test so parallel runs get separate tmp dirs.
        let (dir, backend, _exec_guard) = fixture("ssh_stage_reboot", Surface::Deploy, script);
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
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn drop_kills_unresponsive_backend_after_grace_window() {
        // Backend refuses SIGTERM entirely. Drop should SIGKILL it
        // within 2s + a small buffer and still return promptly.
        let script = r#"#!/bin/sh
read _input
trap '' TERM
# Use a short sleep so we exit even if SIGKILL somehow misses.
sleep 30
"#;
        let (dir, backend, _exec_guard) = fixture("bootfs_copy", Surface::Deploy, script);
        let (tx, _rx) = mpsc::channel::<RunEvent>();
        let handle = attach(backend, "attach", &sample_invocation(), tx).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let start = Instant::now();
        drop(handle);
        let elapsed = start.elapsed();
        // SIGKILL fires after the 2s grace; allow some slack for the
        // orphaned sleep's pipe to close. If the reader thread takes
        // too long we'll notice here.
        assert!(
            elapsed < Duration::from_secs(5),
            "drop took too long: {elapsed:?}"
        );
        std::fs::remove_dir_all(dir).ok();
    }
}
