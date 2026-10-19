//! Actuator dispatch — one-shot subprocess invocation.
//!
//! Used for power actions (`cycle`/`on`/`off`/`diagnose`/`hold`/`sweep`)
//! and deploy staging (`stage`/`unstage`). Invocation:
//!
//!   1. Spawn `<executable> <verb>` in its own process group with
//!      stdin/stdout/stderr piped.
//!   2. Write the JSON [`BackendInvocation`] to stdin; close stdin.
//!   3. Drain stdout and stderr on threads while waiting, so a backend
//!      that says a lot on stderr (an `aws` waiter, a traceback) never
//!      fills the pipe and stalls against its own output.
//!   4. Wait for exit, bounded by the caller's timeout. A backend still
//!      running at the deadline gets SIGTERM to its whole process group,
//!      a grace period, then SIGKILL — so a grandchild it spawned cannot
//!      carry on after the orchestrator has reported the step failed.
//!   5. Classify: exit 0 → the [`ActuatorReport`] on stdout (empty stdout
//!      is `{"ok": true}`; `ok: false` is a failure); exit 64 → the verb
//!      is unsupported; anything else → failed.

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::rig::backend::discover::BackendRef;
use crate::rig::backend::protocol::{ActuatorReport, BackendInvocation, EXIT_UNSUPPORTED_VERB};
use crate::rig::backend::with_relay;

/// How to run one actuator call.
#[derive(Debug, Clone)]
pub struct InvokeOptions {
    /// Upper bound on the backend's run time. Well-behaved backends finish
    /// in seconds; a cloud launch may need minutes, which a binding
    /// declares as `actuator_timeout_s`.
    pub timeout: Duration,
    /// Time between SIGTERM and SIGKILL when the timeout fires.
    pub grace: Duration,
    /// Where to keep the backend's stderr, in full, beside the run. The
    /// error message carries only its tail.
    pub stderr_log: Option<PathBuf>,
}

impl Default for InvokeOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            grace: Duration::from_secs(2),
            stderr_log: None,
        }
    }
}

/// What one actuator call came to.
#[derive(Debug)]
pub enum ActuatorOutcome {
    Ok(ActuatorReport),
    /// The backend exited [`EXIT_UNSUPPORTED_VERB`]: it does not implement
    /// this verb. The caller decides whether that is allowed.
    Unsupported,
    Failed {
        /// Exit code, or `None` when the process died of a signal or was
        /// killed at the timeout.
        code: Option<i32>,
        /// Last part of stderr, for the error message and the manifest.
        stderr_tail: String,
        /// Human summary: "exited 7", "did not exit within 60s", …
        reason: String,
    },
}

/// Invoke an actuator backend and classify the result. Only I/O and
/// protocol errors are `Err`; a backend that ran and failed is
/// `Ok(ActuatorOutcome::Failed { .. })`, so the caller can record it and
/// carry on with a teardown.
pub fn invoke_with(
    backend: &BackendRef,
    verb: &str,
    invocation: &BackendInvocation,
    options: &InvokeOptions,
) -> Result<ActuatorOutcome> {
    let invocation = with_relay(invocation, backend);
    let invocation = &invocation;
    let mut child = backend
        .command(verb)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Own process group: a terminal's Ctrl-C reaches the orchestrator
        // and not the backend, so an in-flight launch finishes and gets
        // torn down instead of dying half way; and the timeout can signal
        // the backend together with everything it spawned.
        .process_group(0)
        .spawn()
        .map_err(|e| {
            Error::Config(format!(
                "rig backend: spawning `{}`: {e}",
                backend.describe(verb)
            ))
        })?;
    let pgid = child.id() as libc::pid_t;

    let json = serde_json::to_string(invocation)
        .map_err(|e| Error::Config(format!("rig backend: serialising invocation: {e}")))?;

    // Stdin write + close is best-effort — a backend that ignores stdin
    // and just does its job based on argv is legal.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(json.as_bytes());
        let _ = stdin.write_all(b"\n");
        drop(stdin);
    }

    // Both pipes are drained on their own threads. Reading them only after
    // exit means a backend that writes more than the pipe holds blocks
    // forever on its own stderr, and the timeout then reports a hang that
    // was really a full pipe.
    let stdout_thread = child.stdout.take().map(|mut out| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = out.read_to_end(&mut buf);
            buf
        })
    });
    let stderr_thread = child.stderr.take().map(|mut err| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = err.read_to_end(&mut buf);
            buf
        })
    });

    let deadline = Instant::now() + options.timeout;
    let mut timed_out = false;
    let exit_status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    kill_group(pgid, options.grace, &mut child);
                    break None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                return Err(Error::Config(format!(
                    "rig backend: waiting on `{} {verb}`: {e}",
                    backend.slug()
                )))
            }
        }
    };

    let stdout_buf = stdout_thread
        .and_then(|t| t.join().ok())
        .unwrap_or_default();
    let stderr_buf = stderr_thread
        .and_then(|t| t.join().ok())
        .unwrap_or_default();
    let stderr_text = String::from_utf8_lossy(&stderr_buf).into_owned();
    if let Some(path) = &options.stderr_log {
        if !stderr_buf.is_empty() {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(path, &stderr_buf);
        }
    }

    if timed_out {
        return Ok(ActuatorOutcome::Failed {
            code: None,
            stderr_tail: tail(&stderr_text),
            reason: format!(
                "`{} {verb}` did not exit within {}s (killed with its process group)",
                backend.slug(),
                options.timeout.as_secs()
            ),
        });
    }
    let exit_status = exit_status.expect("either exited or timed out");

    if !exit_status.success() {
        let code = exit_status.code();
        if code == Some(EXIT_UNSUPPORTED_VERB) {
            return Ok(ActuatorOutcome::Unsupported);
        }
        let rendered = code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "<signal>".into());
        return Ok(ActuatorOutcome::Failed {
            code,
            stderr_tail: tail(&stderr_text),
            reason: format!("`{} {verb}` exited {rendered}", backend.slug()),
        });
    }

    let stdout_text = String::from_utf8_lossy(&stdout_buf);
    let trimmed = stdout_text.trim();
    let report = if trimmed.is_empty() {
        ActuatorReport {
            ok: true,
            info: None,
            detail: None,
        }
    } else {
        serde_json::from_str::<ActuatorReport>(trimmed).map_err(|e| {
            Error::Config(format!(
                "rig backend: `{} {verb}` returned malformed JSON on stdout: {e} \
                 (got: {trimmed:?})",
                backend.slug()
            ))
        })?
    };
    if !report.ok {
        return Ok(ActuatorOutcome::Failed {
            code: Some(0),
            stderr_tail: tail(&stderr_text),
            reason: format!(
                "`{} {verb}` reported ok=false{}",
                backend.slug(),
                report
                    .info
                    .as_deref()
                    .map(|i| format!(": {i}"))
                    .unwrap_or_default()
            ),
        });
    }
    Ok(ActuatorOutcome::Ok(report))
}

/// Invoke an actuator and treat anything but a successful report as an
/// error. For callers that need the verb to work (a deploy `stage`, an
/// ad-hoc `power cycle`); the orchestrator's teardown uses
/// [`invoke_with`] directly so it can record a failure and continue.
pub fn invoke(
    backend: &BackendRef,
    verb: &str,
    invocation: &BackendInvocation,
    soft_timeout: Duration,
) -> Result<ActuatorReport> {
    let options = InvokeOptions {
        timeout: soft_timeout,
        ..InvokeOptions::default()
    };
    match invoke_with(backend, verb, invocation, &options)? {
        ActuatorOutcome::Ok(report) => Ok(report),
        ActuatorOutcome::Unsupported => Err(Error::Config(format!(
            "rig backend: `{} {verb}` is not implemented by this backend (exit {})",
            backend.slug(),
            EXIT_UNSUPPORTED_VERB
        ))),
        ActuatorOutcome::Failed {
            reason,
            stderr_tail,
            ..
        } => Err(Error::Config(format!(
            "rig backend: {reason}{}",
            if stderr_tail.is_empty() {
                String::new()
            } else {
                format!(" — stderr: {stderr_tail}")
            }
        ))),
    }
}

/// SIGTERM the group, wait `grace`, SIGKILL whatever is left, reap the
/// child. The reader threads see EOF once every holder of the pipes is
/// gone, which the group kill guarantees.
fn kill_group(pgid: libc::pid_t, grace: Duration, child: &mut std::process::Child) {
    // SAFETY: a negative pid signals the whole process group; libc::kill
    // has no memory effects, only signal delivery.
    unsafe {
        libc::kill(-pgid, libc::SIGTERM);
    }
    let deadline = Instant::now() + grace;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            _ => {
                // SAFETY: same group signal as above.
                unsafe {
                    libc::kill(-pgid, libc::SIGKILL);
                }
                let _ = child.wait();
                break;
            }
        }
    }
    // Grandchildren may outlive the child by a moment after SIGTERM; make
    // sure the group is gone before the reader threads are joined.
    // SAFETY: as above; the group may already be empty, in which case
    // kill reports ESRCH and nothing happens.
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
}

fn tail(s: &str) -> String {
    const MAX: usize = 2000;
    let t = s.trim();
    if t.len() <= MAX {
        return t.to_string();
    }
    let start = t.len() - MAX;
    let start = t
        .char_indices()
        .map(|(i, _)| i)
        .find(|&i| i >= start)
        .unwrap_or(start);
    format!("…{}", &t[start..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rig::backend::protocol::{BackendContext, BindingValue, PHASE_RUN};
    use crate::rig::vocab::Surface;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    /// Returns (tmp dir guard, backend ref, exec-spawn lock guard).
    /// Caller holds the guard until after `invoke_actuator` returns
    /// to serialise the write-and-spawn window across parallel
    /// tests; see `rig::test_utils::lock_exec_spawn` for why. Caller
    /// must also hold the [`UniqueTmpDir`] until the test finishes so
    /// the backing scratch directory doesn't drop early.
    fn fixture_backend(
        name: &str,
        script: &str,
    ) -> (
        crate::rig::test_utils::UniqueTmpDir,
        BackendRef,
        std::sync::MutexGuard<'static, ()>,
    ) {
        let guard = crate::rig::test_utils::lock_exec_spawn();
        let tmp = crate::rig::test_utils::unique_tmp_dir(&format!("actuator-{name}"));
        let exe = tmp.join(format!("power-{name}"));
        std::fs::write(&exe, script).unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        (
            tmp,
            BackendRef {
                surface: Surface::Power,
                name: name.to_string(),
                executable: exe,
                relay: None,
            },
            guard,
        )
    }

    fn sample_invocation() -> BackendInvocation {
        let mut binding = BTreeMap::new();
        binding.insert("backend".into(), BindingValue::String("test".into()));
        BackendInvocation {
            binding,
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

    fn opts(timeout_ms: u64) -> InvokeOptions {
        InvokeOptions {
            timeout: Duration::from_millis(timeout_ms),
            grace: Duration::from_millis(300),
            stderr_log: None,
        }
    }

    #[test]
    fn successful_actuator_returns_report() {
        let (_dir, backend, _exec_guard) = fixture_backend(
            "ok",
            "#!/bin/sh\nread input\nprintf '{\"ok\":true,\"info\":\"did it\"}\\n'\n",
        );
        let r = invoke(
            &backend,
            "cycle",
            &sample_invocation(),
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(r.ok);
        assert_eq!(r.info.as_deref(), Some("did it"));
    }

    #[test]
    fn empty_stdout_is_treated_as_ok() {
        let (_dir, backend, _exec_guard) = fixture_backend("quiet", "#!/bin/sh\nexit 0\n");
        let r = invoke(
            &backend,
            "cycle",
            &sample_invocation(),
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(r.ok);
    }

    #[test]
    fn nonzero_exit_is_error_with_stderr_surfaced() {
        let (_dir, backend, _exec_guard) =
            fixture_backend("fail", "#!/bin/sh\necho 'kasa unreachable' >&2\nexit 7\n");
        let err = invoke(
            &backend,
            "cycle",
            &sample_invocation(),
            Duration::from_secs(5),
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("exited 7"), "{msg}");
        assert!(msg.contains("kasa unreachable"), "{msg}");
    }

    #[test]
    fn malformed_stdout_surfaces_as_error() {
        let (_dir, backend, _exec_guard) =
            fixture_backend("bad_json", "#!/bin/sh\nprintf 'not json'\n");
        let err = invoke(
            &backend,
            "cycle",
            &sample_invocation(),
            Duration::from_secs(5),
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("malformed JSON"), "{msg}");
    }

    #[test]
    fn soft_timeout_kills_hung_backend() {
        let (_dir, backend, _exec_guard) = fixture_backend("hang", "#!/bin/sh\nsleep 30\n");
        let err = invoke(
            &backend,
            "cycle",
            &sample_invocation(),
            Duration::from_millis(300),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("did not exit"));
    }

    #[test]
    fn exit_64_is_unsupported_not_failed() {
        let (_dir, backend, _exec_guard) =
            fixture_backend("noverb", "#!/bin/sh\necho 'no such verb' >&2\nexit 64\n");
        let outcome = invoke_with(&backend, "diagnose", &sample_invocation(), &opts(5000)).unwrap();
        assert!(
            matches!(outcome, ActuatorOutcome::Unsupported),
            "{outcome:?}"
        );
    }

    #[test]
    fn ok_false_on_zero_exit_is_failed() {
        let (_dir, backend, _exec_guard) = fixture_backend(
            "okfalse",
            "#!/bin/sh\nprintf '{\"ok\":false,\"info\":\"plug did not answer\"}\\n'\nexit 0\n",
        );
        match invoke_with(&backend, "off", &sample_invocation(), &opts(5000)).unwrap() {
            ActuatorOutcome::Failed { code, reason, .. } => {
                assert_eq!(code, Some(0));
                assert!(reason.contains("ok=false"), "{reason}");
                assert!(reason.contains("plug did not answer"), "{reason}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    /// A backend that writes more than a pipe buffer holds to stderr must
    /// not wedge: the pipes are drained while it runs.
    #[test]
    fn large_stderr_does_not_hang_and_is_kept_in_the_log() {
        let (dir, backend, _exec_guard) = fixture_backend(
            "chatty",
            "#!/bin/sh\nread input\ni=0\nwhile [ $i -lt 3000 ]; do echo 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' >&2; i=$((i+1)); done\nprintf '{\"ok\":true}\\n'\n",
        );
        let log = dir.join("stage.stderr.log");
        let options = InvokeOptions {
            timeout: Duration::from_secs(10),
            grace: Duration::from_millis(300),
            stderr_log: Some(log.clone()),
        };
        let start = Instant::now();
        let outcome = invoke_with(&backend, "stage", &sample_invocation(), &options).unwrap();
        assert!(matches!(outcome, ActuatorOutcome::Ok(_)), "{outcome:?}");
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "pipe drain stalled"
        );
        let kept = std::fs::metadata(&log).unwrap().len();
        assert!(
            kept > 64 * 1024,
            "stderr log holds the whole output: {kept} bytes"
        );
    }

    /// A timed-out backend's grandchild must die with it: it is signalled
    /// as a process group, and the call returns promptly even though the
    /// grandchild still held the stdout pipe.
    #[test]
    fn timeout_kills_the_backends_process_group() {
        let (dir, backend, _exec_guard) = fixture_backend(
            "grandchild",
            "#!/bin/sh\nread input\nsleep 60 &\necho $! > \"$PIDFILE\"\nwait\n",
        );
        let pidfile = dir.join("grandchild.pid");
        // The script reads the pid file path from its environment; set it
        // for this process so the spawn inherits it.
        std::env::set_var("PIDFILE", &pidfile);
        let start = Instant::now();
        let outcome = invoke_with(&backend, "on", &sample_invocation(), &opts(300)).unwrap();
        let elapsed = start.elapsed();
        std::env::remove_var("PIDFILE");
        assert!(
            matches!(outcome, ActuatorOutcome::Failed { code: None, .. }),
            "{outcome:?}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "the orphaned grandchild held the pipe open: {elapsed:?}"
        );
        let pid: u32 = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // Give the kernel a moment to reap, then the grandchild must be gone.
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !crate::rig::lock::pid_alive(pid),
            "grandchild {pid} survived the group kill"
        );
    }

    #[test]
    fn phase_and_args_reach_the_backend() {
        let (dir, backend, _exec_guard) = fixture_backend(
            "echo",
            "#!/bin/sh\nread input\nprintf '%s' \"$input\" > \"$ECHO_OUT\"\n",
        );
        let out = dir.join("seen.json");
        std::env::set_var("ECHO_OUT", &out);
        let mut inv = sample_invocation();
        inv.context.phase = "teardown".into();
        inv.args = Some(serde_json::json!({"minutes": 15}));
        let _ = invoke_with(&backend, "hold", &inv, &opts(5000)).unwrap();
        std::env::remove_var("ECHO_OUT");
        let seen: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(seen["context"]["phase"], "teardown");
        assert_eq!(seen["args"]["minutes"], 15);
    }
}
