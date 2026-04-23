//! Actuator dispatch — one-shot subprocess invocation.
//!
//! Used for power actions (`cycle`/`on`/`off`) and deploy staging
//! (`stage`). Invocation:
//!
//!   1. Spawn `<executable> <verb>` with stdin/stdout piped.
//!   2. Write the JSON [`BackendInvocation`] to stdin; close stdin.
//!   3. Wait for exit. Nonzero exit = failure (stderr is surfaced in the
//!      error message).
//!   4. On success, parse [`ActuatorReport`] from stdout. If stdout is
//!      empty, treat as `{"ok": true}`.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::rig::backend::discover::BackendRef;
use crate::rig::backend::protocol::{ActuatorReport, BackendInvocation};

/// Invoke an actuator backend with the given verb and serialised config.
/// `soft_timeout` is an upper bound — the caller's effective timeout — that
/// protects against a broken backend hanging forever. Well-behaved backends
/// finish in seconds.
pub fn invoke(
    backend: &BackendRef,
    verb: &str,
    invocation: &BackendInvocation,
    soft_timeout: Duration,
) -> Result<ActuatorReport> {
    let mut child = Command::new(&backend.executable)
        .arg(verb)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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

    // Stdin write + close is best-effort — a backend that ignores stdin
    // and just does its job based on argv is legal.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(json.as_bytes());
        let _ = stdin.write_all(b"\n");
        drop(stdin);
    }

    // Poll wait with a soft timeout.
    let deadline = Instant::now() + soft_timeout;
    let exit_status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(Error::Config(format!(
                        "rig backend: `{} {verb}` did not exit within {}s",
                        backend.slug(),
                        soft_timeout.as_secs()
                    )));
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

    let mut stdout_buf = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut stdout_buf);
    }
    let mut stderr_buf = String::new();
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut stderr_buf);
    }

    if !exit_status.success() {
        let code = exit_status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "<signal>".into());
        let stderr_tail = stderr_buf.trim().to_string();
        return Err(Error::Config(format!(
            "rig backend: `{} {verb}` exited {code}{}",
            backend.slug(),
            if stderr_tail.is_empty() {
                String::new()
            } else {
                format!(" — stderr: {stderr_tail}")
            }
        )));
    }

    let trimmed = stdout_buf.trim();
    if trimmed.is_empty() {
        return Ok(ActuatorReport {
            ok: true,
            info: None,
            detail: None,
        });
    }
    serde_json::from_str::<ActuatorReport>(trimmed).map_err(|e| {
        Error::Config(format!(
            "rig backend: `{} {verb}` returned malformed JSON on stdout: {e} \
             (got: {trimmed:?})",
            backend.slug()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rig::backend::protocol::{BackendContext, BindingValue};
    use crate::rig::vocab::Surface;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// Returns (tmp dir, backend ref, exec-spawn lock guard). Caller
    /// holds the guard until after `invoke_actuator` returns to
    /// serialise the write-and-spawn window across parallel tests; see
    /// `rig::test_utils::lock_exec_spawn` for why.
    fn fixture_backend(
        name: &str,
        script: &str,
    ) -> (
        PathBuf,
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
                board: "cm5".into(),
                effective_timeout_ms: 10_000,
            },
            artifact: None,
        }
    }

    #[test]
    fn successful_actuator_returns_report() {
        let (dir, backend, _exec_guard) = fixture_backend(
            "ok",
            "#!/bin/sh\nread input\nprintf '{\"ok\":true,\"info\":\"did it\"}\\n'\n",
        );
        let r = invoke(&backend, "cycle", &sample_invocation(), Duration::from_secs(5)).unwrap();
        assert!(r.ok);
        assert_eq!(r.info.as_deref(), Some("did it"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn empty_stdout_is_treated_as_ok() {
        let (dir, backend, _exec_guard) = fixture_backend("quiet", "#!/bin/sh\nexit 0\n");
        let r = invoke(&backend, "cycle", &sample_invocation(), Duration::from_secs(5)).unwrap();
        assert!(r.ok);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn nonzero_exit_is_error_with_stderr_surfaced() {
        let (dir, backend, _exec_guard) = fixture_backend(
            "fail",
            "#!/bin/sh\necho 'kasa unreachable' >&2\nexit 7\n",
        );
        let err = invoke(&backend, "cycle", &sample_invocation(), Duration::from_secs(5))
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("exited 7"), "{msg}");
        assert!(msg.contains("kasa unreachable"), "{msg}");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn malformed_stdout_surfaces_as_error() {
        let (dir, backend, _exec_guard) = fixture_backend(
            "bad_json",
            "#!/bin/sh\nprintf 'not json'\n",
        );
        let err = invoke(&backend, "cycle", &sample_invocation(), Duration::from_secs(5))
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("malformed JSON"), "{msg}");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn soft_timeout_kills_hung_backend() {
        let (dir, backend, _exec_guard) = fixture_backend(
            "hang",
            "#!/bin/sh\nsleep 30\n",
        );
        let err = invoke(&backend, "cycle", &sample_invocation(), Duration::from_millis(300))
            .unwrap_err();
        assert!(format!("{err}").contains("did not exit"));
        std::fs::remove_dir_all(dir).ok();
    }
}
