//! The composition rules of `fluxor_contracts::graph::plan`: fans, mailbox
//! groups, rings and order.

use fluxor_contracts::graph::plan::{
    self, compose, fan_pass, order, plan, record_mailboxes, Fan, FanDir, FrameKind, PlanError,
    PlanModule, PlanPort, RingNode, RingPlatform, RingRole, DIR_CTRL, DIR_IN, DIR_OUT,
};
use fluxor_contracts::graph::{EdgeClass, EdgeRecord, Endpoint};
use fluxor_contracts::ring_size::{
    arena_bytes, buffer_groups, edge_request, ring_for, DEFAULT_RING_BYTES, MAX_RING_BYTES,
    MIN_RING_BYTES, RECORD_FAN_GROUP_FIRST,
};

const HOST: RingPlatform = RingPlatform {
    buffer_groups: 256,
    split_cross_domain: false,
};

fn port(direction: u8, index: u8, buffer_size: u32, frame: FrameKind) -> PlanPort {
    PlanPort {
        direction,
        index,
        buffer_size,
        max_record: 0,
        frame,
    }
}

fn out(index: u8, buffer_size: u32) -> PlanPort {
    port(DIR_OUT, index, buffer_size, FrameKind::Stream)
}

fn module(ports: &[PlanPort]) -> PlanModule<'_> {
    PlanModule {
        ports,
        ..PlanModule::default()
    }
}

fn edge(from: u16, from_port: u8, to: u16, to_port: u8) -> EdgeRecord {
    EdgeRecord {
        from: Endpoint::New(from),
        from_port,
        to: Endpoint::New(to),
        to_port,
        ..EdgeRecord::default()
    }
}

#[test]
fn a_request_is_the_largest_of_its_three_signals() {
    assert_eq!(edge_request(0, 0, 0), 0);
    assert_eq!(edge_request(4096, 512, 0), 4096);
    assert_eq!(edge_request(512, 4096, 1000), 4096);
    assert_eq!(edge_request(512, 256, 70_000), 70_000);
}

#[test]
fn rings_round_up_to_a_power_of_two_and_refuse_past_the_ceiling() {
    assert_eq!(ring_for(0), Some(DEFAULT_RING_BYTES));
    assert_eq!(ring_for(1), Some(MIN_RING_BYTES));
    assert_eq!(ring_for(4097), Some(8192));
    assert_eq!(ring_for(MAX_RING_BYTES), Some(MAX_RING_BYTES));
    assert_eq!(ring_for(MAX_RING_BYTES + 1), None);
    assert_eq!(arena_bytes(8192), 8192);
    assert_eq!(arena_bytes(65), 128);
}

#[test]
fn a_port_s_frame_kind_follows_its_content_type() {
    let ct = |name: &str| {
        fluxor_contracts::CONTENT_TYPES
            .iter()
            .position(|t| *t == name)
            .unwrap() as u8
    };
    assert_eq!(plan::port_frame(ct("OctetStream"), 0), FrameKind::Stream);
    assert_eq!(
        plan::port_frame(ct("OctetStream"), plan::PORT_FLAG_FRAMED),
        FrameKind::Record
    );
    assert_eq!(plan::port_frame(ct("EthernetFrame"), 0), FrameKind::Eth);
    assert_eq!(plan::port_frame(ct("NetProto"), 0), FrameKind::Net);
    assert_eq!(plan::port_frame(ct("Telemetry"), 0), FrameKind::Telemetry);
    assert_eq!(
        plan::port_frame(ct("ExchangeRequest"), 0),
        FrameKind::Record
    );
}

#[test]
fn a_fan_out_gets_a_tee_and_its_joining_edge_takes_the_producer_s_size() {
    let p0 = [out(0, 32_768)];
    let modules = [module(&p0), module(&[]), module(&[])];
    let edges = [
        edge(0, 0, 1, 0),
        EdgeRecord {
            buffer_bytes: 1000,
            ..edge(0, 0, 2, 0)
        },
    ];
    let c = compose(&modules, &edges, 256, false).unwrap();
    assert_eq!(
        c.fans,
        [Fan {
            dir: FanDir::Out,
            of: 0,
            port: 0,
            kind: FrameKind::Stream,
            domain: 0
        }]
    );
    // The fanned edges leave the tee (node 3) from its ports 0 and 1; the
    // joining edge follows them.
    assert_eq!(c.edges[0].from, Endpoint::New(3));
    assert_eq!(c.edges[1].from, Endpoint::New(3));
    assert_eq!((c.edges[0].from_port, c.edges[1].from_port), (0, 1));
    assert_eq!(c.edges[2], edge(0, 0, 3, 0));
    assert_eq!(c.order, [0, 3, 1, 2]);
    let p = c.rings(&modules, HOST).unwrap();
    let rings: Vec<u32> = p.rings.iter().map(|r| r.ring).collect();
    // tee→1 unsized, tee→2 sized by the graph, producer→tee by the port.
    assert_eq!(rings, vec![8192, 1024, 32_768]);
    assert_eq!(p.total(), 8192 + 1024 + 32_768);
    let tee = RingNode::Tee { of: 0, port: 0 };
    assert_eq!(p.largest_adjacent(tee), 32_768);
    assert_eq!(p.rings[2].ends.role, RingRole::Fan);
    assert_eq!(p.rings[1].ends.role, RingRole::Edge(1));
}

#[test]
fn a_fan_in_on_a_control_input_rejoins_the_control_input() {
    let modules = [module(&[]), module(&[]), module(&[])];
    let ctrl = |from| EdgeRecord {
        to_ctrl: true,
        ..edge(from, 0, 2, 4)
    };
    let c = compose(&modules, &[ctrl(0), ctrl(1)], 256, false).unwrap();
    assert_eq!(c.fans[0].dir, FanDir::In);
    assert_eq!(c.fans[0].port, plan::PORT_KEY_CTRL | 4);
    // Into the merge as data, out of it onto the control input.
    assert!(!c.edges[0].to_ctrl && !c.edges[1].to_ctrl);
    assert_eq!((c.edges[0].to_port, c.edges[1].to_port), (0, 1));
    assert_eq!(
        c.edges[2],
        EdgeRecord {
            to_ctrl: true,
            ..edge(3, 0, 2, 4)
        }
    );
}

#[test]
fn a_group_aliases_onto_its_first_ring_at_the_group_s_largest() {
    let p0 = [out(0, 2048), out(1, 512)];
    let safe = PlanModule {
        mailbox_safe: true,
        ..PlanModule::default()
    };
    let modules = [module(&p0), safe, safe];
    let edges = [
        EdgeRecord {
            buffer_group: 3,
            ..edge(0, 0, 1, 0)
        },
        EdgeRecord {
            buffer_group: 3,
            ..edge(0, 1, 2, 0)
        },
    ];
    let p = plan(&modules, &edges, HOST).unwrap();
    assert_eq!(p.rings.len(), 1);
    assert_eq!(p.aliased, 1);
    assert_eq!(p.total(), 2048);
}

#[test]
fn a_cross_domain_edge_adds_a_default_consumer_ring_where_split() {
    let modules = [
        PlanModule::default(),
        PlanModule {
            domain: 1,
            ..PlanModule::default()
        },
    ];
    let edges = [EdgeRecord {
        buffer_bytes: 65_536,
        ..edge(0, 0, 1, 0)
    }];
    let split = RingPlatform {
        buffer_groups: 256,
        split_cross_domain: true,
    };
    assert_eq!(plan(&modules, &edges, HOST).unwrap().total(), 65_536);
    assert_eq!(
        plan(&modules, &edges, split).unwrap().total(),
        65_536 + u64::from(DEFAULT_RING_BYTES)
    );
    // A cross-core edge is split whatever the domains.
    let same = [PlanModule::default(), PlanModule::default()];
    let cross = [EdgeRecord {
        class: EdgeClass::CrossCore,
        ..edge(0, 0, 1, 0)
    }];
    assert_eq!(plan(&same, &cross, split).unwrap().rings.len(), 2);
}

#[test]
fn an_aliased_edge_that_crosses_domains_still_gets_its_consumer_ring() {
    let safe = PlanModule {
        mailbox_safe: true,
        domain: 1,
        ..PlanModule::default()
    };
    let modules = [PlanModule::default(), safe, safe];
    let edges = [
        EdgeRecord {
            buffer_group: 2,
            ..edge(0, 0, 1, 0)
        },
        EdgeRecord {
            buffer_group: 2,
            ..edge(0, 1, 2, 0)
        },
    ];
    let split = RingPlatform {
        buffer_groups: buffer_groups(1536),
        split_cross_domain: true,
    };
    let p = plan(&modules, &edges, split).unwrap();
    assert_eq!(p.aliased, 1);
    let cross = p
        .rings
        .iter()
        .filter(|r| r.ends.role == RingRole::CrossDomain)
        .count();
    assert_eq!((p.rings.len(), cross), (3, 2));
}

#[test]
fn record_fans_draw_groups_above_the_config_s_until_none_is_left() {
    let record = [port(DIR_OUT, 0, 0, FrameKind::Record)];
    let modules = [module(&record), module(&[]), module(&[])];
    let edges = [edge(0, 0, 1, 0), edge(0, 0, 2, 0)];
    // Three edges around the tee, a group each.
    let room = usize::from(RECORD_FAN_GROUP_FIRST) + 3;
    let c = compose(&modules, &edges, room, false).unwrap();
    let groups: Vec<u8> = c.edges.iter().map(|e| e.buffer_group).collect();
    assert_eq!(groups, [32, 33, 34]);
    assert_eq!(c.fans[0].kind, FrameKind::Record);
    assert_eq!(
        compose(&modules, &edges, room - 1, false).unwrap_err(),
        PlanError::GroupsExhausted
    );
}

#[test]
fn a_stream_fan_clears_the_groups_of_its_edges() {
    let modules = [module(&[]), module(&[]), module(&[])];
    let edges = [
        EdgeRecord {
            buffer_group: 5,
            ..edge(0, 0, 1, 0)
        },
        EdgeRecord {
            buffer_group: 6,
            ..edge(0, 0, 2, 0)
        },
    ];
    let c = compose(&modules, &edges, 256, false).unwrap();
    assert!(c.edges.iter().all(|e| e.buffer_group == 0));
}

#[test]
fn a_fan_s_kind_is_the_kind_its_peers_agree_on() {
    let sink = module(&[]);
    let net = [out(0, 0)].map(|p| PlanPort {
        frame: FrameKind::Net,
        ..p
    });
    let stream = [out(0, 0)];
    let record = [out(0, 0)].map(|p| PlanPort {
        frame: FrameKind::Record,
        ..p
    });
    let kind = |a: &[PlanPort], b: &[PlanPort]| {
        let modules = [module(a), module(b), sink];
        compose(&modules, &[edge(0, 0, 2, 0), edge(1, 0, 2, 0)], 256, false)
            .unwrap()
            .fans[0]
            .kind
    };
    // The fanned input declares nothing: its producers say it.
    assert_eq!(kind(&net, &net), FrameKind::Net);
    // A producer that declares nothing says nothing.
    assert_eq!(kind(&net, &[]), FrameKind::Net);
    // A declared stream is a declaration: disagreement makes a byte fan.
    assert_eq!(kind(&net, &stream), FrameKind::Stream);
    assert_eq!(kind(&record, &net), FrameKind::Stream);
    // The fanned port's own non-stream declaration wins over its peers'.
    let typed_sink = [port(DIR_IN, 0, 0, FrameKind::Eth)];
    let modules = [module(&net), module(&stream), module(&typed_sink)];
    let c = compose(&modules, &[edge(0, 0, 2, 0), edge(1, 0, 2, 0)], 256, false).unwrap();
    assert_eq!(c.fans[0].kind, FrameKind::Eth);
}

#[test]
fn multi_channel_modules_keep_a_channel_per_edge() {
    // 0 serves 1 and 2, which feed it back: no tee, no merge.
    let provider = PlanModule {
        multi_inbound: true,
        multi_outbound: true,
        ..PlanModule::default()
    };
    let modules = [provider, module(&[]), module(&[]), module(&[])];
    let mut edges = vec![
        edge(0, 0, 1, 0),
        edge(0, 0, 2, 0),
        edge(1, 0, 0, 0),
        edge(2, 0, 0, 0),
    ];
    let c = compose(&modules, &edges, 256, true).unwrap();
    assert!(c.fans.is_empty());
    assert_eq!(c.cycle_members, 3);
    // A consumer that does not feed it back: its output keeps the tee, its
    // inputs still no merge.
    edges.push(edge(0, 0, 3, 0));
    let c = compose(&modules, &edges, 256, true).unwrap();
    assert_eq!(c.fans.len(), 1);
    assert_eq!(c.fans[0].dir, FanDir::Out);
    // A control fan-in still merges.
    let ctrl = |from| EdgeRecord {
        to_ctrl: true,
        ..edge(from, 1, 0, 0)
    };
    let c = compose(&modules, &[ctrl(1), ctrl(2)], 256, false).unwrap();
    assert_eq!(c.fans[0].dir, FanDir::In);
}

#[test]
fn an_oversized_request_is_refused_not_clamped() {
    let modules = [PlanModule::default(), PlanModule::default()];
    let edges = [EdgeRecord {
        buffer_bytes: MAX_RING_BYTES + 1,
        ..edge(0, 0, 1, 0)
    }];
    assert!(matches!(
        plan(&modules, &edges, HOST).unwrap_err(),
        PlanError::OverCeiling { request, .. } if request == MAX_RING_BYTES + 1
    ));
}

#[test]
fn an_edge_naming_no_module_is_refused() {
    let modules = [PlanModule::default()];
    assert_eq!(
        compose(&modules, &[edge(0, 0, 1, 0)], 256, false).unwrap_err(),
        PlanError::UnknownModule { edge: 0 }
    );
}

#[test]
fn order_is_breadth_first_in_edge_order() {
    // 0 → 1 and 2 independent: 0 and 2 are sources, 1 is queued behind them.
    let edges = [edge(0, 0, 1, 0)];
    let mut out = [0u16; 3];
    let mut indeg = [0u16; 3];
    assert_eq!(order(3, &edges, false, &mut out, &mut indeg), Ok(0));
    assert_eq!(out, [0, 2, 1]);
    // Successors are queued in edge order.
    let edges = [edge(0, 0, 2, 0), edge(0, 1, 1, 0)];
    order(3, &edges, false, &mut out, &mut indeg).unwrap();
    assert_eq!(out, [0, 2, 1]);
    // An edge to the outside the graph orders nothing.
    let edges = [EdgeRecord {
        to: Endpoint::Net(0),
        ..edge(1, 0, 0, 0)
    }];
    order(3, &edges, false, &mut out, &mut indeg).unwrap();
    assert_eq!(out, [0, 1, 2]);
}

#[test]
fn cycles_are_refused_unless_accepted_then_follow_in_index_order() {
    let edges = [edge(2, 0, 1, 0), edge(1, 0, 2, 0), edge(0, 0, 1, 0)];
    let mut out = [0u16; 4];
    let mut indeg = [0u16; 4];
    assert_eq!(
        order(4, &edges, false, &mut out, &mut indeg),
        Err(PlanError::Cycle { members: 2 })
    );
    assert_eq!(order(4, &edges, true, &mut out, &mut indeg), Ok(2));
    assert_eq!(out, [0, 3, 1, 2]);
    assert_eq!(
        order(4, &edges, true, &mut out[..3], &mut indeg),
        Err(PlanError::OrderCapacity)
    );
}

#[test]
fn the_fan_pass_works_in_the_caller_s_buffers() {
    let modules = [module(&[]), module(&[]), module(&[])];
    let mut edges = [edge(0, 0, 1, 0), edge(0, 0, 2, 0), EdgeRecord::default()];
    let mut fans = [Fan {
        dir: FanDir::Out,
        of: 0,
        port: 0,
        kind: FrameKind::Stream,
        domain: 0,
    }; 1];
    let counts = fan_pass(&modules, &mut edges, 2, &mut fans, 256).unwrap();
    assert_eq!((counts.edges, counts.fans), (3, 1));
    let mut short = [edge(0, 0, 1, 0), edge(0, 0, 2, 0)];
    assert_eq!(
        fan_pass(&modules, &mut short, 2, &mut fans, 256),
        Err(PlanError::EdgeCapacity)
    );
    let mut edges = [edge(0, 0, 1, 0), edge(0, 0, 2, 0), EdgeRecord::default()];
    assert_eq!(
        fan_pass(&modules, &mut edges, 2, &mut [], 256),
        Err(PlanError::FanCapacity)
    );
}

/// A fan has sixteen ports on its many side: a port with sixteen edges
/// fans, one with seventeen is refused, naming the port, rather than
/// numbering a fan port past what an edge carries.
#[test]
fn a_fan_is_at_most_sixteen_wide() {
    let modules: Vec<PlanModule<'_>> = (0..18).map(|_| module(&[])).collect();
    let tee = |n: u16| -> Vec<EdgeRecord> { (1..=n).map(|c| edge(0, 0, c, 0)).collect() };
    let c = compose(&modules, &tee(16), 256, false).unwrap();
    assert_eq!(c.fans.len(), 1);
    assert!(c.edges.iter().all(|e| e.from_port <= 15));
    assert_eq!(
        compose(&modules, &tee(17), 256, false).unwrap_err(),
        PlanError::FanWidth {
            dir: FanDir::Out,
            of: 0,
            port: 0,
            edges: 17
        }
    );
    let merge: Vec<EdgeRecord> = (1..=17).map(|p| edge(p, 0, 0, 0)).collect();
    assert_eq!(
        compose(&modules, &merge, 256, false).unwrap_err(),
        PlanError::FanWidth {
            dir: FanDir::In,
            of: 0,
            port: 0,
            edges: 17
        }
    );
}

#[test]
fn a_point_to_point_record_edge_gets_a_mailbox_of_its_own() {
    let record = [port(DIR_OUT, 0, 0, FrameKind::Record)];
    let record_in = [port(DIR_CTRL, 1, 0, FrameKind::Record)];
    let modules = [module(&record), module(&record_in), module(&[])];
    let mut edges = [
        // Records out of 0.
        edge(0, 0, 2, 0),
        // Records into 1's control input.
        EdgeRecord {
            to_ctrl: true,
            ..edge(2, 0, 1, 1)
        },
        // Neither end carries records.
        edge(2, 0, 2, 0),
        // A net lane carries its own framing.
        EdgeRecord {
            to: Endpoint::Net(1),
            ..edge(0, 0, 0, 0)
        },
        // A group the graph gave is kept.
        EdgeRecord {
            buffer_group: 4,
            ..edge(0, 0, 1, 0)
        },
    ];
    assert_eq!(record_mailboxes(&modules, &mut edges, 256), Ok(2));
    let groups: Vec<u8> = edges.iter().map(|e| e.buffer_group).collect();
    assert_eq!(groups, [32, 33, 0, 0, 4]);
    let mut more = [edge(0, 0, 2, 0)];
    assert_eq!(
        record_mailboxes(&modules, &mut more, usize::from(RECORD_FAN_GROUP_FIRST)),
        Err(PlanError::GroupsExhausted)
    );
}

#[test]
fn a_fan_record_carries_its_params() {
    let fan = Fan {
        dir: FanDir::In,
        of: 3,
        port: 0,
        kind: FrameKind::Telemetry,
        domain: 2,
    };
    let params = plan::fan_params(fan.kind, 32, 8192);
    let r = fan.record(&params);
    assert_eq!(r.name_hash, fluxor_contracts::graph::MERGE_NAME_HASH);
    assert_eq!(r.domain, 2);
    let mut seen = Vec::new();
    fluxor_contracts::params_tlv::walk_declared(&params, |tag, v| seen.push((tag, v.to_vec())));
    assert_eq!(
        seen,
        [
            (plan::fan_param::FRAME_KIND, vec![3]),
            (plan::fan_param::FRAMES_PER_STEP, vec![32, 0]),
            (
                plan::fan_param::SCRATCH_BYTES,
                8192u32.to_le_bytes().to_vec()
            ),
        ]
    );
}
