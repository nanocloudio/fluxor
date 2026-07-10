//! Emit a bounded binary owner plan to a file, for host validation of the
//! kernel staged-plan apply path. The node agent stages plans the same
//! way on a real device.
//!
//! Usage: cargo run -p fluxor-tools --example emit_plan -- <out-path>
//!
//! Composes a single-pod plan that owns module index 0 (matching a 1-module
//! graph like examples/hello/linux.yaml), then writes the encoded plan blob.

#![allow(
    clippy::print_stderr,
    reason = "emit_plan is a host CLI helper that reports status on stderr"
)]

use fluxor_tools::compose::{
    compose, encode_plan, DesiredPhase, DeviceDesiredState, NodeCapacity, OwnerSnapshot,
    PodDesired, ResourceProfile,
};

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: emit_plan <out-path>");

    let mut pod_uid = [0u8; 16];
    pod_uid[0] = 0xaa;
    let pod = PodDesired {
        pod_uid,
        namespace: "default".into(),
        name: "demo".into(),
        workload_digest: [0u8; 32],
        config_generation: 1,
        desired_phase: DesiredPhase::Running,
        profile: ResourceProfile {
            modules: 1,
            edges: 0,
            state_bytes: 0,
            buffer_bytes: 0,
            endpoints: 0,
            domains: 1,
        },
    };
    let ds = DeviceDesiredState {
        generation: 1,
        system_revision: 1,
        pods: vec![pod],
    };
    let cap = NodeCapacity {
        max_owners: 16,
        max_modules: 64,
        max_edges: 128,
        state_bytes: 1 << 20,
        buffer_bytes: 1 << 20,
        max_endpoints: 64,
        max_domains: 4,
    };
    let snap = OwnerSnapshot::empty(16);

    // No revocation graces and a fixed clock: a fresh snapshot has no
    // departing occupants, so no revocation records can be minted and
    // the plan stays byte-deterministic for host validation.
    let plan = compose(&ds, &cap, &snap, &[], 0).expect("compose");
    let bytes = encode_plan(&plan);
    std::fs::write(&out, &bytes).expect("write plan");
    eprintln!(
        "wrote {} ({} bytes): gen={} assignments={} (slot {} owns modules [{}..{}))",
        out,
        bytes.len(),
        plan.generation,
        plan.assignments.len(),
        plan.assignments[0].slot,
        plan.assignments[0].module_base,
        plan.assignments[0].module_base + plan.assignments[0].module_count,
    );
}
