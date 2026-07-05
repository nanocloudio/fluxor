//! End-to-end node-agent delivery driver:
//! reconcile a desired state into a durable FsStorage generation store, then
//! publish the committed plan for the Linux runtime's FLUXOR_PLAN staging.
//!
//! Usage:
//!   cargo run -p fluxor-tools --example agent_publish -- <store-dir> <plan-out>
//!
//! Then boot the graph with the published plan:
//!   FLUXOR_PLAN=<plan-out> fluxor run examples/hello/linux.yaml

#![allow(
    clippy::print_stderr,
    reason = "agent_publish is a host CLI helper that reports status on stderr"
)]

use fluxor_tools::compose::{
    DesiredPhase, DeviceDesiredState, NodeCapacity, OwnerSnapshot, PodDesired, ResourceProfile,
};
use fluxor_tools::genstore::{FsStorage, GenStore};
use fluxor_tools::node_agent::{publish_committed_plan, reconcile_and_commit};

fn main() {
    let mut args = std::env::args().skip(1);
    let store_dir = args
        .next()
        .expect("usage: agent_publish <store-dir> <plan-out>");
    let plan_out = args
        .next()
        .expect("usage: agent_publish <store-dir> <plan-out>");

    let mut pod_uid = [0u8; 16];
    pod_uid[0] = 0xaa;
    let desired = DeviceDesiredState {
        generation: 1,
        system_revision: 1,
        pods: vec![PodDesired {
            pod_uid,
            namespace: "default".into(),
            name: "hello".into(),
            workload_digest: [0u8; 32],
            config_generation: 1,
            desired_phase: DesiredPhase::Running,
            profile: ResourceProfile {
                modules: 1,
                edges: 0,
                state_bytes: 65536,
                buffer_bytes: 16384,
                endpoints: 0,
                domains: 1,
            },
        }],
    };
    let cap = NodeCapacity {
        max_owners: 16,
        max_modules: 128,
        max_edges: 128,
        state_bytes: 1 << 26,
        buffer_bytes: 1 << 23,
        max_endpoints: 64,
        max_domains: 4,
    };

    let mut store = GenStore::new(FsStorage::open(&store_dir).expect("open store"));
    let plan = reconcile_and_commit(&mut store, &desired, &cap, &OwnerSnapshot::empty(16), 1)
        .expect("reconcile");
    let n = publish_committed_plan(&store, std::path::Path::new(&plan_out))
        .expect("publish")
        .expect("committed generation present");
    eprintln!(
        "committed gen 1 to {store_dir}; published {n}-byte plan to {plan_out} \
         (slot {} owns modules [{}..{}), caps state={} buffer={})",
        plan.assignments[0].slot,
        plan.assignments[0].module_base,
        plan.assignments[0].module_base + plan.assignments[0].module_count,
        plan.assignments[0].state_cap,
        plan.assignments[0].buffer_cap,
    );
}
