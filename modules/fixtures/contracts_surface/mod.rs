//! contracts_surface — every alloc-free `fluxor-contracts` entry point a
//! module can call, linked into one module.
//!
//! The build holds what a module's link keeps of the contracts crate to the
//! position-independence rules, so this module building on every module ABI
//! is the proof that none of these functions carries a panic location or a
//! table of pointers. Every input comes through `black_box`, so no call is
//! folded away; every result is folded into one word through `black_box`,
//! so none is discarded.

#![no_std]

use core::ffi::c_void;
use core::hint::black_box;

use abi::SyscallTable;
use fluxor_abi as abi;
use fluxor_contracts as c;
use fluxor_contracts::graph::{self, plan};

use fluxor_rt::*;

/// Bytes the probes read their inputs from.
const INPUT: usize = 256;

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    input: [u8; INPUT],
    out: [u8; INPUT],
    acc: u32,
}

fn fold(acc: &mut u32, v: u64) {
    *acc = acc.wrapping_mul(31).wrapping_add(black_box(v) as u32);
}

fn some<T>(acc: &mut u32, v: Option<T>) {
    fold(acc, u64::from(v.is_some()));
}

fn ok<T, E>(acc: &mut u32, v: Result<T, E>) {
    fold(acc, u64::from(v.is_ok()));
}

/// The integer at `at` of `b`, little-endian, 0 past its end.
fn word(b: &[u8], at: usize) -> u64 {
    let mut v = 0u64;
    for (i, x) in b.iter().skip(at).take(8).enumerate() {
        v |= u64::from(*x) << (8 * i);
    }
    v
}

fn byte(b: &[u8], at: usize) -> u8 {
    b.get(at).copied().unwrap_or(0)
}

fn sizes(acc: &mut u32, b: &[u8]) {
    let n = word(b, 0) as usize;
    let m = word(b, 8) as usize;
    let q = word(b, 16) as usize;
    let r = word(b, 24) as u32;
    use c::{ring_size, state_arena};
    fold(acc, ring_size::record_bytes(r));
    fold(acc, ring_size::buffer_groups(n) as u64);
    fold(acc, u64::from(ring_size::edge_request(r, r >> 3, r >> 7)));
    some(acc, ring_size::sized_ring(r));
    some(acc, ring_size::ring_for(r));
    fold(acc, ring_size::arena_bytes(r));
    some(acc, state_arena::carve_bytes(n));
    fold(acc, state_arena::first_heap_segment(n, m, q) as u64);
    some(acc, state_arena::iso_carve_bytes(n));
    let seat = [r, r >> 1, r >> 2, r >> 3, r >> 4, r >> 5];
    some(acc, state_arena::heap_seat_bytes(&seat, b));
    some(acc, c::rate_class_floor(c::RateClass::Audio, n & 1 == 0));
    let class = if n & 1 == 0 { "audio" } else { "bulk" };
    some(acc, c::RateClass::from_str_opt(black_box(class)));
    fold(acc, u64::from(c::RateClass::Bulk.severity()));
    fold(
        acc,
        u64::from(c::RateClass::Video.exceeds(c::RateClass::Control)),
    );
}

fn cores(acc: &mut u32, b: &[u8]) {
    use c::core_map;
    let map = [byte(b, 0), byte(b, 1), byte(b, 2), byte(b, 3)];
    let d = usize::from(byte(b, 4));
    ok(
        acc,
        core_map::validate(
            b.get(..usize::from(byte(b, 5) & 7)).unwrap_or(&[]),
            byte(b, 6),
        ),
    );
    fold(acc, core_map::core_of(&map, d) as u64);
    fold(acc, u64::from(core_map::domains_of(&map, d)));
    some(acc, core_map::secondary_domain(&map, d));
    fold(acc, u64::from(core_map::has_secondary(&map)));
    fold(
        acc,
        u64::from(core_map::crosses_cores(&map, d, usize::from(byte(b, 7)))),
    );
}

fn params(acc: &mut u32, b: &[u8], out: &mut [u8]) {
    use c::params_tlv;
    let n = usize::from(byte(b, 0));
    some(acc, params_tlv::terminator_at(b, n));
    params_tlv::walk_declared(b, |tag, v| fold(acc, u64::from(tag) + v.len() as u64));
    fold(
        acc,
        params_tlv::merge_room(n, usize::from(byte(b, 1))) as u64,
    );
    let len = usize::from(byte(b, 2));
    let take = usize::from(byte(b, 3) & 31);
    let overrides = [
        (byte(b, 4), b.get(8..8 + take).unwrap_or(&[])),
        (byte(b, 5), b.get(40..40 + take).unwrap_or(&[])),
    ];
    let m = params_tlv::merge_overrides(out, len, overrides.iter().copied());
    fold(acc, m.len as u64 + m.dropped as u64);
}

fn graphs(acc: &mut u32, b: &[u8], out: &mut [u8]) {
    fold(acc, u64::from(graph::name_hash(b)));
    some(acc, graph::FaultPolicy::from_u8(byte(b, 0)));
    let end = graph::Endpoint::from_wire(byte(b, 1), word(b, 2) as u16);
    if let Some(e) = end {
        let (k, i) = e.to_wire();
        fold(acc, u64::from(k) + u64::from(i));
        some(acc, e.new_index());
    }
    ok(acc, graph::header(b));
    if let Ok(g) = graph::decode(b) {
        fold(acc, u64::from(g.header().creator_authority()));
        fold(acc, u64::from(g.module_count()) + u64::from(g.edge_count()));
        for o in g.order() {
            fold(acc, u64::from(o));
        }
        for m in g.modules() {
            fold(acc, u64::from(m.name_hash) + m.params.len() as u64);
        }
        for e in g.edges() {
            fold(acc, u64::from(e.buffer_bytes));
        }
        some(acc, g.edge(usize::from(byte(b, 9))));
    }
    let edge = graph::EdgeRecord {
        from: graph::Endpoint::New(u16::from(byte(b, 10))),
        to: graph::Endpoint::New(u16::from(byte(b, 11))),
        buffer_bytes: word(b, 12) as u32,
        ..graph::EdgeRecord::default()
    };
    let record = graph::ModuleRecord {
        name_hash: word(b, 20) as u32,
        domain: byte(b, 24),
        pre_pass: false,
        step_deadline_us: 0,
        burst_us: 0,
        fault_policy: graph::FaultPolicy::Skip,
        params: b.get(32..32 + usize::from(byte(b, 25) & 63)).unwrap_or(&[]),
    };
    let order = [0u16];
    let modules = [record];
    let edges = [edge];
    let spec = graph::GraphSpec {
        creator_authority: byte(b, 26) & 1 != 0,
        owner_uid: [byte(b, 27); 16],
        state_cap: word(b, 28) as u32,
        buffer_cap: word(b, 30) as u32,
        order: &order,
        modules: &modules,
        edges: &edges,
    };
    fold(acc, graph::encoded_len(&spec) as u64);
    ok(acc, graph::encode_into(&spec, out));
}

fn plans(acc: &mut u32, b: &[u8]) {
    let frame = plan::port_frame(byte(b, 0), byte(b, 1));
    fold(
        acc,
        plan::fan_params(frame, word(b, 2) as u16, word(b, 4) as u32).len() as u64,
    );
    let ports = [plan::PlanPort {
        direction: byte(b, 8) & 1,
        index: byte(b, 9) & 15,
        buffer_size: word(b, 10) as u32,
        max_record: word(b, 14) as u32,
        frame,
    }];
    let module = plan::PlanModule {
        ports: &ports,
        mailbox_safe: byte(b, 18) & 1 != 0,
        multi_inbound: byte(b, 18) & 2 != 0,
        multi_outbound: byte(b, 18) & 4 != 0,
        domain: byte(b, 19) & 3,
    };
    let modules = [module, module];
    let mut edges = [
        graph::EdgeRecord {
            from: graph::Endpoint::New(0),
            to: graph::Endpoint::New(1),
            buffer_bytes: word(b, 20) as u32,
            ..graph::EdgeRecord::default()
        },
        graph::EdgeRecord {
            from: graph::Endpoint::New(0),
            to: graph::Endpoint::New(u16::from(byte(b, 24) & 1)),
            ..graph::EdgeRecord::default()
        },
        graph::EdgeRecord::default(),
        graph::EdgeRecord::default(),
    ];
    let groups = usize::from(byte(b, 25));
    let mut fans = [plan::Fan {
        dir: plan::FanDir::Out,
        of: 0,
        port: 0,
        kind: frame,
        domain: 0,
    }; 2];
    if let Ok(counts) = plan::fan_pass(&modules, &mut edges, 2, &mut fans, groups) {
        fold(acc, core::mem::size_of_val(&counts) as u64);
    }
    for f in &fans {
        fold(
            acc,
            u64::from(f.name_hash()) + f.record(b).params.len() as u64,
        );
    }
    ok(acc, plan::record_mailboxes(&modules, &mut edges, groups));
    let mut out = [0u16; 4];
    let mut indeg = [0u16; 4];
    ok(
        acc,
        plan::order(4, &edges, byte(b, 26) & 1 != 0, &mut out, &mut indeg),
    );
    let platform = plan::RingPlatform {
        buffer_groups: groups,
        domain_cores: [byte(b, 27) & 1, byte(b, 28) & 1, 0, 0],
    };
    fold(acc, u64::from(platform.bridges_cores()));
    fold(
        acc,
        u64::from(platform.crosses_cores(byte(b, 29), byte(b, 30))),
    );
    let rings = plan::rings(&modules, &fans, &edges, 2, platform, |r| {
        fold(acc, core::mem::size_of_val(&r) as u64)
    });
    ok(acc, rings);
}

fn regions(acc: &mut u32, b: &[u8]) {
    use c::isolation;
    some(acc, isolation::Level::from_wire(byte(b, 0)));
    if let Some(l) = isolation::Level::from_wire(byte(b, 0)) {
        fold(acc, u64::from(l.is_gated()));
    }
    let spans = [
        isolation::Span {
            base: word(b, 1),
            len: word(b, 9),
            access: isolation::Access::ReadWrite,
        },
        isolation::Span {
            base: word(b, 17),
            len: word(b, 25),
            access: isolation::Access::ReadExec,
        },
    ];
    let model = match byte(b, 33) & 3 {
        0 => isolation::RegionModel::Pmsav7 {
            regions: byte(b, 34),
        },
        1 => isolation::RegionModel::Pmsav8 {
            regions: byte(b, 34),
        },
        _ => isolation::RegionModel::Pages,
    };
    if let Ok(p) = isolation::region_plan(&spans, model) {
        for r in p.regions() {
            fold(acc, u64::from(r.covers(word(b, 40))));
        }
    }
    fold(acc, isolation::code_region_len(word(b, 48)));
    let (x, y) = isolation::private_region_shape(word(b, 56), model);
    fold(acc, x ^ y);
}

fn boot(acc: &mut u32, b: &[u8]) {
    use c::boot::{MemKind, MemRegion, Range, RegionList};
    let kernel = Range {
        base: word(b, 0) >> 8,
        len: word(b, 8) >> 8,
    };
    fold(acc, kernel.end());
    let mut slots = [MemRegion {
        base: 0,
        len: 0,
        kind: MemKind::Usable,
        reserved: 0,
    }; 4];
    let mut list = RegionList::new(&mut slots, kernel);
    list.add(word(b, 16), word(b, 24), MemKind::Usable);
    list.add(word(b, 32), word(b, 40), MemKind::Reserved);
    fold(acc, list.regions().len() as u64 + list.dropped() as u64);
}

fn configs(acc: &mut u32, b: &[u8]) {
    use c::boot_config;
    some(acc, boot_config::ExecMode::from_u8(byte(b, 0)));
    if let Some(m) = boot_config::ExecMode::from_u8(byte(b, 0)) {
        fold(acc, u64::from(m.is_interrupt()));
    }
    fold(
        acc,
        u64::from(u32::from_le_bytes(
            boot_config::tag_bytes(word(b, 1) as u32),
        )),
    );
    fold(acc, u64::from(boot_config::crc32(b)));
    match boot_config::decode(b) {
        Ok(cfg) => {
            fold(acc, cfg.total_len() as u64 + u64::from(cfg.checksum()));
            some(acc, cfg.hardware());
            if let Some(w) = cfg.workloads() {
                fold(acc, u64::from(w.count()));
                for r in w.iter() {
                    fold(acc, r.blob.len() as u64);
                }
            }
            for entries in [cfg.envelope(), cfg.demand()].into_iter().flatten() {
                fold(acc, entries.len() as u64 + u64::from(entries.is_empty()));
                for e in entries.iter() {
                    fold(acc, u64::from(e.n));
                }
            }
            let g = cfg.graph();
            fold(acc, u64::from(g.domain_count()) + g.params_bytes() as u64);
            for d in g.domains() {
                fold(acc, u64::from(d.tick_us));
            }
            fold(acc, u64::from(g.composed().module_count()));
        }
        Err(e) => {
            let (x, y) = e.detail();
            fold(acc, u64::from(x) + y as u64);
        }
    }
}

fn owners(acc: &mut u32, b: &[u8]) {
    use c::owner_plan;
    let sha = |bytes: &[u8]| [byte(bytes, 0); 32];
    if let Ok(p) = owner_plan::decode(b, usize::from(byte(b, 0)), sha) {
        fold(acc, p.assignments().len() as u64);
        fold(acc, p.revocations().len() as u64);
        fold(acc, p.leases().len() as u64);
    }
}

fn telemetry(acc: &mut u32, b: &[u8]) {
    let severity = if byte(b, 0) & 1 == 0 {
        c::observability::Severity::Info
    } else {
        c::observability::Severity::Debug
    };
    fold(acc, u64::from(black_box(severity).number()));
}

fn probe(s: &mut State) {
    let input = black_box(&s.input[..]);
    let out = black_box(&mut s.out[..]);
    let mut acc = 0u32;
    sizes(&mut acc, input);
    cores(&mut acc, input);
    params(&mut acc, input, out);
    graphs(&mut acc, input, out);
    plans(&mut acc, input);
    regions(&mut acc, input);
    boot(&mut acc, input);
    configs(&mut acc, input);
    owners(&mut acc, input);
    telemetry(&mut acc, input);
    s.acc = black_box(acc);
}

fluxor_rt::module_facts! { state: State }

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[no_mangle]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if state.is_null() || syscalls.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<State>() {
        return -2;
    }
    unsafe {
        core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
    }
    0
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> StepReturn {
    if state.is_null() {
        return StepReturn::error(-1);
    }
    // SAFETY: the loader hands back the block `module_new` initialised.
    let s = unsafe { &mut *(state as *mut State) };
    probe(s);
    StepReturn::Continue
}

fluxor_rt::wasm_entry!();
