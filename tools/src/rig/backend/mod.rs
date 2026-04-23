//! Rig backend subprocess contract.
//!
//! The Rust core treats every concrete mechanism (power-cycling a specific
//! plug model, streaming bytes off a specific tty, tailing a specific
//! netboot log) as an opaque external executable. Adding a new mechanism
//! is "drop an executable on `$FLUXOR_BACKEND_PATH`" — no recompile, no
//! trait impl inside this crate.
//!
//! See `docs/architecture/rig-backend-protocol.md` for the normative spec.

pub mod actuator;
pub mod discover;
pub mod protocol;
pub mod transport;

pub use actuator::invoke as invoke_actuator;
pub use discover::{resolve, search_paths, BackendRef};
pub use protocol::{
    ActuatorReport, ArtifactRef, BackendContext, BackendInvocation, BindingValue, TransportEvent,
};
pub use transport::{attach as attach_transport, TransportHandle};

use std::collections::BTreeMap;
use std::path::Path;

use crate::rig::plan::{ArtifactPlan, Plan};
use crate::rig::profile::{BindingTable, BindingValue as ProfileBindingValue};

/// Build a [`BackendContext`] from plan state — every backend call gets
/// the same run-identity header so logs and side-channel outputs can be
/// correlated with the run manifest.
pub fn context_from_plan(plan: &Plan, run_dir: &Path) -> BackendContext {
    BackendContext {
        rig_id: plan.rig.clone(),
        lab: plan.lab.clone(),
        run_id: plan.run_record.run_id.clone(),
        run_dir: run_dir.display().to_string(),
        scenario_name: plan.scenario_name.clone(),
        board: plan.board.clone(),
        effective_timeout_ms: (plan.effective_timeout_s as u64) * 1000,
    }
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
