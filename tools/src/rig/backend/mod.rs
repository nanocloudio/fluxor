//! Rig backend subprocess contract.
//!
//! The Rust core treats every concrete mechanism (power-cycling a specific
//! plug model, streaming bytes off a specific tty, tailing a specific
//! netboot log) as an opaque external executable. A mechanism is an
//! executable on the discovery path — no recompile, no trait impl inside
//! this crate.
//!
//! See `docs/architecture/rig-backend-protocol.md` for the normative spec.

pub mod actuator;
pub mod discover;
pub mod protocol;
pub mod transport;

pub use actuator::{invoke as invoke_actuator, invoke_with, ActuatorOutcome, InvokeOptions};
pub use discover::{resolve, resolve_relay, search_paths, BackendRef, RelayRef};
pub use protocol::{
    ActuatorReport, ArtifactRef, BackendContext, BackendInvocation, BindingValue, TransportEvent,
    EXIT_UNSUPPORTED_VERB, PHASE_ADHOC, PHASE_RUN, PHASE_TEARDOWN,
};
pub use transport::{attach as attach_transport, attach_with, AttachOptions, TransportHandle};

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::Child;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Time between SIGTERM and SIGKILL when a binding sets no
/// `shutdown_grace_s`.
pub const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Stop a backend and everything it spawned. Backends run in their own
/// process group, whose id is the backend's pid: SIGTERM goes to the
/// group, the backend gets `grace` to exit, then SIGKILL goes to whatever
/// of the group is left — sent whether or not the backend itself exited,
/// so a helper that ignores SIGTERM cannot outlive it — and the backend
/// is reaped.
pub(crate) fn terminate_group(child: &mut Child, grace: Duration) {
    let pgid = child.id() as libc::pid_t;
    // SAFETY: a negative pid signals the whole process group; kill has no
    // memory effects, only signal delivery.
    unsafe {
        libc::kill(-pgid, libc::SIGTERM);
    }
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            _ => break,
        }
    }
    // SAFETY: as above. An empty group makes kill report ESRCH and
    // nothing happens.
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
    let _ = child.wait();
}

/// A pipe read to EOF on its own thread, so a backend that writes more
/// than a pipe holds never blocks against its own output.
pub(crate) struct PipeDrain {
    buf: Arc<Mutex<Vec<u8>>>,
    done: mpsc::Receiver<()>,
}

impl PipeDrain {
    pub(crate) fn spawn<R: Read + Send + 'static>(mut pipe: R) -> Self {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let (tx, done) = mpsc::channel();
        let sink = buf.clone();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 8192];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => sink
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .extend_from_slice(&chunk[..n]),
                }
            }
            let _ = tx.send(());
        });
        Self { buf, done }
    }

    /// Everything read, once the pipe closes or `deadline` passes. A pipe
    /// still open at the deadline is held by a process the backend left
    /// behind outside its group; what it said so far is returned and the
    /// reader is left to finish on its own.
    pub(crate) fn collect(self, deadline: Instant) -> (Vec<u8>, bool) {
        let closed = self
            .done
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .is_ok();
        let bytes = std::mem::take(&mut *self.buf.lock().unwrap_or_else(|p| p.into_inner()));
        (bytes, closed)
    }
}

use crate::rig::plan::{ArtifactPlan, Plan};
use crate::rig::profile::{BindingTable, BindingValue as ProfileBindingValue};

/// Build a [`BackendContext`] from plan state — every backend call gets
/// the same run-identity header so logs and side-channel outputs can be
/// correlated with the run manifest. `phase` is one of the `PHASE_*`
/// constants.
pub fn context_from_plan(
    plan: &Plan,
    run_dir: &Path,
    state_dir: &Path,
    phase: &str,
) -> BackendContext {
    BackendContext {
        rig_id: plan.rig.clone(),
        lab: plan.lab.clone(),
        run_id: plan.run_record.run_id.clone(),
        run_dir: run_dir.display().to_string(),
        scenario_name: plan.scenario_name.clone(),
        board: plan.board.clone(),
        effective_timeout_ms: (plan.effective_timeout_s as u64) * 1000,
        phase: phase.to_string(),
        state_dir: state_dir.display().to_string(),
    }
}

/// Where a backend's stderr is kept beside the run:
/// `<run_dir>/<surface>-<name>-<verb>.stderr.log`, with `.teardown` before
/// the suffix for a teardown step so it does not overwrite the run's own.
pub fn stderr_log_path(
    run_dir: &Path,
    backend: &BackendRef,
    verb: &str,
    phase: &str,
) -> std::path::PathBuf {
    let teardown = if phase == PHASE_TEARDOWN {
        ".teardown"
    } else {
        ""
    };
    run_dir.join(format!("{}-{verb}{teardown}.stderr.log", backend.slug()))
}

/// The invocation as the process receives it: with the relay's binding
/// when the backend runs through one.
pub(crate) fn with_relay(
    invocation: &BackendInvocation,
    backend: &BackendRef,
) -> BackendInvocation {
    let mut out = invocation.clone();
    out.relay = backend.relay.as_ref().map(|r| r.binding.clone());
    out
}

/// Translate a profile [`BindingTable`] into the wire-format map. Secret
/// values are exposed in plaintext (the backend is the recipient that
/// needs them) but never flow back into logs or plan output.
pub fn wire_binding(table: &BindingTable) -> BTreeMap<String, BindingValue> {
    let mut out = BTreeMap::new();
    for (k, v) in table.iter() {
        let wire = match v {
            ProfileBindingValue::Secret(s) => BindingValue::String(s.expose().to_string()),
            ProfileBindingValue::Int(n) => BindingValue::Int(*n),
            ProfileBindingValue::Float(f) => BindingValue::Float(*f),
            ProfileBindingValue::Bool(b) => BindingValue::Bool(*b),
        };
        out.insert(k.clone(), wire);
    }
    out
}

/// Translate an [`ArtifactPlan`] into a wire-format reference. Returns
/// `None` when the artifact is unresolved — callers shouldn't invoke the
/// deploy `stage` verb in that case.
pub fn wire_artifact(artifact: &ArtifactPlan) -> Option<ArtifactRef> {
    match artifact {
        ArtifactPlan::File { path, .. } => Some(ArtifactRef::File {
            path: path.display().to_string(),
        }),
        ArtifactPlan::Bundle { root, .. } => Some(ArtifactRef::Bundle {
            path: root.display().to_string(),
        }),
        ArtifactPlan::Unresolved { .. } => None,
    }
}
