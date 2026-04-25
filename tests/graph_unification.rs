//! Integration tests for `scheduler::prepare_graph`.
//!
//! Drives the graph compiler directly with synthetic in-memory configs
//! (no .fmod loader, no platform setup) and pins the contract every
//! platform relies on: 1:1 edges share one channel handle on both
//! ports, fan-out groups insert a `_tee`, fan-in groups insert a
//! `_merge`, and distinct ports on the same module never fan.
//!
//! Run with:
//!   cargo test --no-default-features --features host-linux \
//!     --target aarch64-unknown-linux-gnu --test graph_unification

#![cfg(feature = "host-linux")]

use std::sync::Mutex;

use fluxor::kernel::config::{
    Config, ConfigHeader, EdgeClass, GraphEdge, ModuleEntry,
};
use fluxor::kernel::loader;
use fluxor::kernel::scheduler;

/// `STATIC_CONFIG` and `SCHED` are process-wide singletons; serialize
/// the test cases instead of requiring `--test-threads=1` on the CLI.
static GRAPH_LOCK: Mutex<()> = Mutex::new(());

const PRODUCER_HASH: u32 = 0x1111_1111;
const CONSUMER_A_HASH: u32 = 0x2222_2222;
const CONSUMER_B_HASH: u32 = 0x3333_3333;
const CONSUMER_C_HASH: u32 = 0x4444_4444;

fn fresh_config() -> Config {
    let mut cfg = Config::empty();
    cfg.header = ConfigHeader {
        magic: 0,
        version: 1,
        checksum: 0,
        module_count: 0,
        edge_count: 0,
        tick_us: 1000,
        graph_sample_rate: 0,
    };
    cfg
}

fn add_module(cfg: &mut Config, idx: usize, id: u8, name_hash: u32) {
    cfg.modules[idx] = Some(ModuleEntry {
        name_hash,
        id,
        domain_id: 0,
        params_ptr: core::ptr::null(),
        params_len: 0,
    });
    cfg.module_count = cfg.module_count.max(idx as u8 + 1);
}

fn add_edge(
    cfg: &mut Config,
    idx: usize,
    from_id: u8,
    from_port: u8,
    to_id: u8,
    to_port: u8,
) {
    cfg.graph_edges[idx] = Some(GraphEdge {
        from_id,
        to_id,
        to_port: 0,
        from_port_index: from_port,
        to_port_index: to_port,
        buffer_group: 0,
        edge_class: EdgeClass::Local,
    });
    cfg.edge_count = cfg.edge_count.max(idx as u8 + 1);
}

fn install_and_prepare(cfg: Config) -> ([Option<ModuleEntry>; 32], usize) {
    let _guard = GRAPH_LOCK.lock().unwrap();
    loader::reset_state_arena();
    unsafe { scheduler::install_static_config(cfg) };
    let (list, count) = scheduler::prepare_graph().expect("prepare_graph");
    let mut out: [Option<ModuleEntry>; 32] = [None; 32];
    for i in 0..count.min(32) {
        out[i] = list[i];
    }
    (out, count)
}

fn count_internal(modules: &[Option<ModuleEntry>], count: usize, hash: u32) -> usize {
    modules
        .iter()
        .take(count)
        .filter(|m| m.as_ref().map_or(false, |e| e.name_hash == hash))
        .count()
}

#[test]
fn one_to_one_graph_inserts_no_fan_modules() {
    let mut cfg = fresh_config();
    add_module(&mut cfg, 0, 0, PRODUCER_HASH);
    add_module(&mut cfg, 1, 1, CONSUMER_A_HASH);
    add_edge(&mut cfg, 0, 0, 0, 1, 0);

    let (modules, count) = install_and_prepare(cfg);
    assert_eq!(count, 2, "no fan inserts expected for 1:1 graph");
    assert_eq!(count_internal(&modules, count, scheduler::INTERNAL_TEE_HASH), 0);
    assert_eq!(count_internal(&modules, count, scheduler::INTERNAL_MERGE_HASH), 0);
}

#[test]
fn fan_out_inserts_tee_module() {
    let mut cfg = fresh_config();
    add_module(&mut cfg, 0, 0, PRODUCER_HASH);
    add_module(&mut cfg, 1, 1, CONSUMER_A_HASH);
    add_module(&mut cfg, 2, 2, CONSUMER_B_HASH);
    add_module(&mut cfg, 3, 3, CONSUMER_C_HASH);
    // Producer's out[0] fans to three consumers.
    add_edge(&mut cfg, 0, 0, 0, 1, 0);
    add_edge(&mut cfg, 1, 0, 0, 2, 0);
    add_edge(&mut cfg, 2, 0, 0, 3, 0);

    let (modules, count) = install_and_prepare(cfg);
    let tees = count_internal(&modules, count, scheduler::INTERNAL_TEE_HASH);
    assert_eq!(tees, 1, "exactly one tee should be inserted for one fan-out group");
    assert!(count > 4, "module list should grow by the inserted tee");
}

#[test]
fn fan_in_inserts_merge_module() {
    let mut cfg = fresh_config();
    add_module(&mut cfg, 0, 0, PRODUCER_HASH);
    add_module(&mut cfg, 1, 1, CONSUMER_A_HASH);
    add_module(&mut cfg, 2, 2, CONSUMER_B_HASH);
    add_module(&mut cfg, 3, 3, CONSUMER_C_HASH);
    // Three producers fan into consumer C's in[0].
    add_edge(&mut cfg, 0, 0, 0, 3, 0);
    add_edge(&mut cfg, 1, 1, 0, 3, 0);
    add_edge(&mut cfg, 2, 2, 0, 3, 0);

    let (modules, count) = install_and_prepare(cfg);
    let merges = count_internal(&modules, count, scheduler::INTERNAL_MERGE_HASH);
    assert_eq!(merges, 1, "exactly one merge should be inserted for one fan-in group");
}

#[test]
fn distinct_source_ports_do_not_fan() {
    // Two edges from the same module but different output ports — that's
    // not a fan, just a multi-port producer.
    let mut cfg = fresh_config();
    add_module(&mut cfg, 0, 0, PRODUCER_HASH);
    add_module(&mut cfg, 1, 1, CONSUMER_A_HASH);
    add_module(&mut cfg, 2, 2, CONSUMER_B_HASH);
    add_edge(&mut cfg, 0, 0, 0, 1, 0); // producer.out[0] -> A
    add_edge(&mut cfg, 1, 0, 1, 2, 0); // producer.out[1] -> B

    let (modules, count) = install_and_prepare(cfg);
    assert_eq!(count, 3, "no fan inserts when ports are distinct");
    assert_eq!(count_internal(&modules, count, scheduler::INTERNAL_TEE_HASH), 0);
}

/// A direct edge `A.out[p] -> B.in[q]` must resolve to the same
/// channel handle on both module ports, and that handle must equal
/// `edge.channel` set by `open_channels`. Same-domain edges should not
/// have a separate `consumer_channel`.
#[test]
fn direct_edge_shares_handle_on_both_ports() {
    let mut cfg = fresh_config();
    add_module(&mut cfg, 0, 0, PRODUCER_HASH);
    add_module(&mut cfg, 1, 1, CONSUMER_A_HASH);
    // Non-zero ports on both ends so an off-by-port-index regression
    // would surface alongside a stale-channel bug.
    add_edge(&mut cfg, 0, 0, 2, 1, 3);

    let _guard = GRAPH_LOCK.lock().unwrap();
    fluxor::kernel::loader::reset_state_arena();
    unsafe { scheduler::install_static_config(cfg) };
    let _ = scheduler::prepare_graph().expect("prepare_graph");

    let producer_handle = scheduler::get_module_port(0, 1, 2);
    let consumer_handle = scheduler::get_module_port(1, 0, 3);
    let sched = unsafe { scheduler::sched_mut() };
    let wire = sched.edges[0].channel;

    assert!(
        producer_handle >= 0,
        "producer.out[2] not bound (handle={})",
        producer_handle
    );
    assert_eq!(
        producer_handle, wire,
        "producer.out[2] handle does not match edge channel"
    );
    assert_eq!(
        consumer_handle, wire,
        "consumer.in[3] handle does not match edge channel"
    );
    assert_eq!(
        producer_handle, consumer_handle,
        "direct edge handles diverged: producer={} consumer={}",
        producer_handle, consumer_handle
    );
    assert_eq!(
        sched.edges[0].consumer_channel, -1,
        "single-domain direct edge should not have a separate consumer channel",
    );
}
