//! A graph's channel rings: every ring graph preparation opens, and what they
//! take from the buffer arena together.
//!
//! [`plan`] replays graph preparation over a graph's description — the
//! fan-out tees and fan-in merges the kernel inserts, its mailbox aliasing,
//! and the consumer-side ring a multi-domain platform adds for each edge that
//! crosses domains — sizing each ring by the kernel's own rule
//! (`src/kernel/ipc/ring_size.rs`, mounted here by path). The composer sums a
//! graph's rings with it (`ring_demand`); the harness test `ring_demand`
//! mounts this file too, boots graphs through the real `prepare_graph` and
//! pins the arena it leaves used against the plan.

#[path = "../../src/kernel/ipc/ring_size.rs"]
mod ring_size;
pub use ring_size::*;

pub use self::plan::*;

/// What a port carries, as a fan over it sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortFrame {
    /// A byte stream, or records that state their own length and survive
    /// being split: a fan over it moves bytes.
    Stream,
    /// Records that state no length (`Framing::Framed`, or a port's own
    /// `framed` flag): a fan over it gives every edge a mailbox of its own.
    Record,
    /// Ethernet frames, network-protocol records or telemetry: a fan over it
    /// moves whole frames by the length they carry, on byte rings.
    Typed,
}

/// Manifest port flag bit 1: the port carries whole records whatever its
/// content type.
pub const PORT_FLAG_FRAMED: u8 = 0x02;

/// The kind a fan sees for a port of content type `content_type` and
/// manifest flags `flags`.
pub fn port_frame(content_type: u8, flags: u8) -> PortFrame {
    let framed = fluxor_contracts::CONTENT_FRAMING
        .get(content_type as usize)
        .is_some_and(|f| *f == fluxor_contracts::Framing::Framed);
    if framed || flags & PORT_FLAG_FRAMED != 0 {
        return PortFrame::Record;
    }
    match fluxor_contracts::CONTENT_TYPES.get(content_type as usize) {
        Some(&"EthernetFrame") | Some(&"NetProto") | Some(&"Telemetry") => PortFrame::Typed,
        _ => PortFrame::Stream,
    }
}

mod plan {
    use super::*;

    /// Manifest port direction bytes.
    pub const DIR_IN: u8 = 0;
    pub const DIR_OUT: u8 = 1;
    pub const DIR_CTRL: u8 = 2;

    /// One port record of a module's manifest, in manifest order. A lookup
    /// takes the first record matching its direction and index, as the
    /// loader does.
    #[derive(Clone, Copy, Debug)]
    pub struct RingPort {
        pub direction: u8,
        pub index: u8,
        /// The port's declared ring capacity (`buffer_size`); 0 undeclared.
        pub buffer_size: u32,
        /// The largest single write the port issues (`max_record`); 0
        /// undeclared.
        pub max_record: u32,
        pub frame: PortFrame,
    }

    /// A module of the graph, as graph preparation sees it.
    #[derive(Clone, Debug, Default)]
    pub struct RingModule {
        /// Its manifest's port records. Empty for a module the node runs
        /// built in: the loader holds no manifest for it, so none of its
        /// ports is sized.
        pub ports: Vec<RingPort>,
        /// It may consume from an aliased mailbox (`module_mailbox_safe`).
        pub mailbox_safe: bool,
        /// Its data inputs keep one channel per edge rather than a merge
        /// (a platform registers it; `linux_net` on Linux).
        pub multi_inbound: bool,
        /// Its output keeps one channel per edge when every consumer of it
        /// is one of its producers (`linux_net` on Linux).
        pub multi_outbound: bool,
        /// The execution domain it steps in.
        pub domain: u8,
    }

    /// One edge of the graph, as the compiled config carries it.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct RingEdge {
        pub from: usize,
        pub from_port: u8,
        pub to: usize,
        /// The edge lands on a control input.
        pub ctrl: bool,
        pub to_port: u8,
        /// Its mailbox group; 0 for none.
        pub buffer_group: u8,
        /// The graph's `buffer_bytes` for it; 0 for none.
        pub buffer_bytes: u32,
        /// Edge class `cross_core`: bridged across cores whatever the
        /// domains.
        pub cross_core: bool,
    }

    /// What the platform adds to graph preparation.
    #[derive(Clone, Copy, Debug)]
    pub struct RingPlatform {
        /// Mailbox groups the kernel has (`BUFFER_GROUPS`,
        /// [`buffer_groups`] of its graph-edge capacity). A record fan takes
        /// a group of its own for every edge around it, from
        /// [`RECORD_FAN_GROUP_FIRST`] up.
        pub buffer_groups: usize,
        /// Every edge whose ends step in different domains, or whose class
        /// is `cross_core`, is split into a producer-side and a
        /// consumer-side channel joined by a pump, and the consumer side is
        /// a default ring of its own (bcm2712's `bridge_cross_domain_edges`).
        pub split_cross_domain: bool,
    }

    /// A module of the prepared graph: one of the graph's, or a tee or merge
    /// the kernel inserted for a fanned port of one.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum RingNode {
        Module(usize),
        /// The tee on output `port` of module `of`.
        Tee {
            of: usize,
            port: u8,
        },
        /// The merge on input `port` (bit 4 set for a control input) of
        /// module `of`.
        Merge {
            of: usize,
            port: u8,
        },
    }

    /// Why a ring was opened.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum RingRole {
        /// The channel of graph edge `n` (through its fan, when it has one).
        Edge(usize),
        /// The edge joining a fanned port to its tee or merge.
        Fan,
        /// The consumer side of a cross-domain edge.
        CrossDomain,
    }

    /// Where a ring runs: why it was opened, and its two ends.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RingEnds {
        pub role: RingRole,
        pub from: RingNode,
        pub from_port: u8,
        pub to: RingNode,
        pub ctrl: bool,
        pub to_port: u8,
    }

    /// One ring graph preparation opens.
    #[derive(Clone, Copy, Debug)]
    pub struct Ring {
        pub ends: RingEnds,
        /// The producer port's capacity, the consumer port's, and the
        /// edge's `buffer_bytes`.
        pub producer_cap: u32,
        pub consumer_cap: u32,
        pub buffer_bytes: u32,
        /// What was asked: the edge's request, or its mailbox group's
        /// largest; 0 unsized.
        pub request: u32,
        /// The ring granted.
        pub ring: u32,
        /// What it takes from the buffer arena.
        pub arena: u64,
    }

    /// Every ring a graph opens at preparation, in the order it opens them.
    #[derive(Clone, Debug, Default)]
    pub struct RingPlan {
        pub rings: Vec<Ring>,
        /// Edges that share a ring by aliasing into their group's mailbox.
        pub aliased: usize,
    }

    impl RingPlan {
        /// The buffer arena the graph takes.
        pub fn total(&self) -> u64 {
            self.rings.iter().map(|r| r.arena).sum()
        }
    }

    /// A graph graph preparation refuses.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum RingError {
        /// An edge asks for more than [`MAX_RING_BYTES`].
        OverCeiling { ends: RingEnds, request: u32 },
        /// A producer's `max_record` is larger than the ring its edge is
        /// granted, so its writes could never succeed.
        RecordOverRing {
            ends: RingEnds,
            max_record: u32,
            granted: u32,
        },
        /// A record fan needs a mailbox group and none is left.
        GroupsExhausted,
        /// An edge names a module the graph does not have.
        UnknownModule { edge: usize },
    }

    #[derive(Clone, Copy)]
    struct Working {
        from: usize,
        from_port: u8,
        to: usize,
        ctrl: bool,
        to_port: u8,
        group: u16,
        buffer_bytes: u32,
        cross_core: bool,
        role: RingRole,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Dir {
        Out,
        In,
    }

    struct Graph<'a> {
        modules: &'a [RingModule],
        nodes: Vec<RingNode>,
        domains: Vec<u8>,
        edges: Vec<Working>,
    }

    impl Graph<'_> {
        fn ports(&self, node: usize) -> &[RingPort] {
            match self.nodes[node] {
                RingNode::Module(m) => &self.modules[m].ports,
                _ => &[],
            }
        }

        fn port(&self, node: usize, direction: u8, index: u8) -> Option<&RingPort> {
            self.ports(node)
                .iter()
                .find(|p| p.direction == direction && p.index == index)
        }

        fn cap(&self, node: usize, direction: u8, index: u8) -> (u32, u32) {
            self.port(node, direction, index)
                .map(|p| (p.buffer_size, p.max_record))
                .unwrap_or((0, 0))
        }

        fn ends(&self, e: &Working) -> RingEnds {
            RingEnds {
                role: e.role,
                from: self.nodes[e.from],
                from_port: e.from_port,
                to: self.nodes[e.to],
                ctrl: e.ctrl,
                to_port: e.to_port,
            }
        }

        fn module(&self, node: usize) -> Option<&RingModule> {
            match self.nodes[node] {
                RingNode::Module(m) => Some(&self.modules[m]),
                _ => None,
            }
        }

        /// The kind a fan over `node`'s port sees: `None` where the port is
        /// undeclared, or a non-record stream.
        fn frame(&self, node: usize, dir: Dir, key: u8) -> Option<PortFrame> {
            let direction = match dir {
                Dir::Out => DIR_OUT,
                Dir::In if key & 0x10 != 0 => DIR_CTRL,
                Dir::In => DIR_IN,
            };
            match self.port(node, direction, key & 0x0F)?.frame {
                PortFrame::Stream => None,
                f => Some(f),
            }
        }

        fn fresh_group(&self, groups: usize) -> Option<u16> {
            (RECORD_FAN_GROUP_FIRST as usize..groups)
                .map(|g| g as u16)
                .find(|g| !self.edges.iter().any(|e| e.group == *g))
        }

        fn key(e: &Working, dir: Dir) -> u8 {
            match dir {
                Dir::Out => e.from_port,
                Dir::In => (if e.ctrl { 0x10 } else { 0 }) | e.to_port,
            }
        }

        fn touches(e: &Working, m: usize, dir: Dir) -> bool {
            match dir {
                Dir::Out => e.from == m,
                Dir::In => e.to == m,
            }
        }

        /// Whether the out-edges `group` of `m` reach exactly the modules
        /// feeding its data input, each once.
        fn pairs_with_inputs(&self, m: usize, group: &[usize]) -> bool {
            let feeds = |c: usize| {
                self.edges
                    .iter()
                    .any(|e| e.from == c && e.to == m && !e.ctrl)
            };
            for (k, &ei) in group.iter().enumerate() {
                let c = self.edges[ei].to;
                if !feeds(c) || group[..k].iter().any(|&ej| self.edges[ej].to == c) {
                    return false;
                }
            }
            self.edges
                .iter()
                .all(|e| e.to != m || e.ctrl || group.iter().any(|&ei| self.edges[ei].to == e.from))
        }

        /// The kernel's fan pass in one direction.
        fn fan(&mut self, dir: Dir, groups: usize) -> Result<(), RingError> {
            let original = self.nodes.len();
            for m in 0..original {
                let module = match self.nodes[m] {
                    RingNode::Module(i) => i,
                    _ => continue,
                };
                let matching: Vec<usize> = (0..self.edges.len())
                    .filter(|&i| Self::touches(&self.edges[i], m, dir))
                    .collect();
                if matching.len() <= 1 {
                    continue;
                }
                let mut processed = vec![false; matching.len()];
                for start in 0..matching.len() {
                    if processed[start] {
                        continue;
                    }
                    let key = Self::key(&self.edges[matching[start]], dir);
                    let mut group = Vec::new();
                    for j in start..matching.len() {
                        if !processed[j] && Self::key(&self.edges[matching[j]], dir) == key {
                            group.push(matching[j]);
                            processed[j] = true;
                        }
                    }
                    if group.len() <= 1 {
                        continue;
                    }
                    let spec = &self.modules[module];
                    if dir == Dir::Out && spec.multi_outbound && self.pairs_with_inputs(m, &group) {
                        continue;
                    }
                    if dir == Dir::In && key & 0x10 == 0 && spec.multi_inbound {
                        continue;
                    }
                    let mut kind = self.frame(m, dir, key);
                    if kind.is_none() {
                        for &ei in &group {
                            let e = self.edges[ei];
                            let peer = match dir {
                                Dir::Out => self.frame(e.to, Dir::In, Self::key(&e, Dir::In)),
                                Dir::In => self.frame(e.from, Dir::Out, e.from_port),
                            };
                            if peer.is_some() {
                                kind = peer;
                                break;
                            }
                        }
                    }
                    let record = kind == Some(PortFrame::Record);
                    for &ei in &group {
                        if record {
                            let g = self.fresh_group(groups).ok_or(RingError::GroupsExhausted)?;
                            self.edges[ei].group = g;
                        } else {
                            self.edges[ei].group = 0;
                        }
                    }
                    let fan = self.nodes.len();
                    self.nodes.push(match dir {
                        Dir::Out => RingNode::Tee {
                            of: module,
                            port: key,
                        },
                        Dir::In => RingNode::Merge {
                            of: module,
                            port: key,
                        },
                    });
                    self.domains.push(self.domains[m]);
                    let mut join = match dir {
                        Dir::Out => Working {
                            from: m,
                            from_port: key,
                            to: fan,
                            ctrl: false,
                            to_port: 0,
                            group: 0,
                            buffer_bytes: 0,
                            cross_core: false,
                            role: RingRole::Fan,
                        },
                        Dir::In => Working {
                            from: fan,
                            from_port: 0,
                            to: m,
                            ctrl: key & 0x10 != 0,
                            to_port: key & 0x0F,
                            group: 0,
                            buffer_bytes: 0,
                            cross_core: false,
                            role: RingRole::Fan,
                        },
                    };
                    if record {
                        join.group = self.fresh_group(groups).ok_or(RingError::GroupsExhausted)?;
                    }
                    self.edges.push(join);
                    for (k, &ei) in group.iter().enumerate() {
                        let e = &mut self.edges[ei];
                        match dir {
                            Dir::Out => {
                                e.from = fan;
                                e.from_port = k as u8;
                            }
                            Dir::In => {
                                e.to = fan;
                                e.to_port = k as u8;
                                e.ctrl = false;
                            }
                        }
                    }
                }
            }
            Ok(())
        }
    }

    /// The rings graph preparation opens for `edges` between `modules`, in
    /// the order it opens them: every edge's channel, after the fan-out tees
    /// and fan-in merges the kernel inserts and with mailbox groups aliased,
    /// then the consumer side of every cross-domain edge where the platform
    /// splits them.
    pub fn plan(
        modules: &[RingModule],
        edges: &[RingEdge],
        platform: RingPlatform,
    ) -> Result<RingPlan, RingError> {
        let mut g = Graph {
            modules,
            nodes: (0..modules.len()).map(RingNode::Module).collect(),
            domains: modules.iter().map(|m| m.domain).collect(),
            edges: Vec::with_capacity(edges.len()),
        };
        for (i, e) in edges.iter().enumerate() {
            if e.from >= modules.len() || e.to >= modules.len() {
                return Err(RingError::UnknownModule { edge: i });
            }
            g.edges.push(Working {
                from: e.from,
                from_port: e.from_port,
                to: e.to,
                ctrl: e.ctrl,
                to_port: e.to_port,
                group: e.buffer_group as u16,
                buffer_bytes: e.buffer_bytes,
                cross_core: e.cross_core,
                role: RingRole::Edge(i),
            });
        }
        g.fan(Dir::Out, platform.buffer_groups)?;
        g.fan(Dir::In, platform.buffer_groups)?;

        // `open_channels`: an edge's request is the largest of its ports'
        // capacities and its `buffer_bytes`; a group's ring is its largest
        // member's request, opened by its first edge and aliased by every
        // later one whose consumer is mailbox-safe.
        let request = |e: &Working| -> u32 {
            let (from, _) = g.cap(e.from, DIR_OUT, e.from_port);
            let (to, _) = g.cap(e.to, if e.ctrl { DIR_CTRL } else { DIR_IN }, e.to_port);
            edge_request(from, to, e.buffer_bytes)
        };
        let mut group_max: Vec<u32> = vec![0; platform.buffer_groups.max(256)];
        for e in &g.edges {
            if e.group != 0 {
                let r = request(e);
                let slot = &mut group_max[e.group as usize];
                if r > *slot {
                    *slot = r;
                }
            }
        }
        let mut group_open = vec![false; group_max.len()];
        let mut plan = RingPlan::default();
        for e in &g.edges {
            let group = e.group as usize;
            if group != 0 && group_open[group] && g.module(e.to).is_some_and(|m| m.mailbox_safe) {
                plan.aliased += 1;
                continue;
            }
            let asked = if group != 0 && group_max[group] > 0 {
                group_max[group]
            } else {
                request(e)
            };
            let ends = g.ends(e);
            let ring = ring_for(asked).ok_or(RingError::OverCeiling {
                ends,
                request: asked,
            })?;
            let (producer_cap, max_record) = g.cap(e.from, DIR_OUT, e.from_port);
            if max_record > ring {
                return Err(RingError::RecordOverRing {
                    ends,
                    max_record,
                    granted: ring,
                });
            }
            let (consumer_cap, _) = g.cap(e.to, if e.ctrl { DIR_CTRL } else { DIR_IN }, e.to_port);
            plan.rings.push(Ring {
                ends,
                producer_cap,
                consumer_cap,
                buffer_bytes: e.buffer_bytes,
                request: asked,
                ring,
                arena: arena_bytes(ring),
            });
            if group != 0 {
                group_open[group] = true;
            }
        }

        // The platform's cross-domain bridging, after preparation: every
        // edge holds a channel by now, an aliased one its group's, and each
        // that crosses gets a consumer-side ring of its own.
        if platform.split_cross_domain {
            for e in &g.edges {
                if g.domains[e.from] == g.domains[e.to] && !e.cross_core {
                    continue;
                }
                plan.rings.push(Ring {
                    ends: RingEnds {
                        role: RingRole::CrossDomain,
                        ..g.ends(e)
                    },
                    producer_cap: 0,
                    consumer_cap: 0,
                    buffer_bytes: 0,
                    request: 0,
                    ring: DEFAULT_RING_BYTES,
                    arena: arena_bytes(DEFAULT_RING_BYTES),
                });
            }
        }
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    mod planned {
        use super::super::*;

        fn out(index: u8, buffer_size: u32) -> RingPort {
            RingPort {
                direction: DIR_OUT,
                index,
                buffer_size,
                max_record: 0,
                frame: PortFrame::Stream,
            }
        }

        const HOST: RingPlatform = RingPlatform {
            buffer_groups: 256,
            split_cross_domain: false,
        };

        #[test]
        fn a_fan_out_gets_a_tee_and_its_joining_edge_takes_the_producer_s_size() {
            let modules = vec![
                RingModule {
                    ports: vec![out(0, 32_768)],
                    ..Default::default()
                },
                RingModule::default(),
                RingModule::default(),
            ];
            let edges = [
                RingEdge {
                    from: 0,
                    to: 1,
                    ..Default::default()
                },
                RingEdge {
                    from: 0,
                    to: 2,
                    buffer_bytes: 1000,
                    ..Default::default()
                },
            ];
            let p = plan(&modules, &edges, HOST).unwrap();
            let rings: Vec<u32> = p.rings.iter().map(|r| r.ring).collect();
            // tee→1 unsized, tee→2 sized by the graph, producer→tee by the port.
            assert_eq!(rings, vec![8192, 1024, 32_768]);
            assert_eq!(p.total(), 8192 + 1024 + 32_768);
        }

        #[test]
        fn a_group_aliases_onto_its_first_ring_at_the_group_s_largest() {
            let safe = RingModule {
                mailbox_safe: true,
                ..Default::default()
            };
            let modules = vec![
                RingModule {
                    ports: vec![out(0, 2048), out(1, 512)],
                    ..Default::default()
                },
                safe.clone(),
                safe,
            ];
            let edges = [
                RingEdge {
                    from: 0,
                    to: 1,
                    buffer_group: 3,
                    ..Default::default()
                },
                RingEdge {
                    from: 0,
                    from_port: 1,
                    to: 2,
                    buffer_group: 3,
                    ..Default::default()
                },
            ];
            let p = plan(&modules, &edges, HOST).unwrap();
            assert_eq!(p.rings.len(), 1);
            assert_eq!(p.aliased, 1);
            assert_eq!(p.total(), 2048);
        }

        #[test]
        fn a_cross_domain_edge_adds_a_default_consumer_ring_where_split() {
            let modules = vec![
                RingModule::default(),
                RingModule {
                    domain: 1,
                    ..Default::default()
                },
            ];
            let edges = [RingEdge {
                from: 0,
                to: 1,
                buffer_bytes: 65_536,
                ..Default::default()
            }];
            let split = RingPlatform {
                buffer_groups: 256,
                split_cross_domain: true,
            };
            assert_eq!(plan(&modules, &edges, HOST).unwrap().total(), 65_536);
            assert_eq!(
                plan(&modules, &edges, split).unwrap().total(),
                65_536 + DEFAULT_RING_BYTES as u64
            );
        }

        #[test]
        fn an_aliased_edge_that_crosses_domains_still_gets_its_consumer_ring() {
            // The bridging walks every edge holding a channel, and an
            // aliased edge holds its group's.
            let safe = RingModule {
                mailbox_safe: true,
                domain: 1,
                ..Default::default()
            };
            let modules = vec![RingModule::default(), safe.clone(), safe];
            let edges = [
                RingEdge {
                    from: 0,
                    to: 1,
                    buffer_group: 2,
                    ..Default::default()
                },
                RingEdge {
                    from: 0,
                    from_port: 1,
                    to: 2,
                    buffer_group: 2,
                    ..Default::default()
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
            let record = RingPort {
                direction: DIR_OUT,
                index: 0,
                buffer_size: 0,
                max_record: 0,
                frame: PortFrame::Record,
            };
            let modules = vec![
                RingModule {
                    ports: vec![record],
                    ..Default::default()
                },
                RingModule::default(),
                RingModule::default(),
            ];
            let edges = [
                RingEdge {
                    from: 0,
                    to: 1,
                    ..Default::default()
                },
                RingEdge {
                    from: 0,
                    to: 2,
                    ..Default::default()
                },
            ];
            // Three edges around the tee, a group each.
            let room = RingPlatform {
                buffer_groups: RECORD_FAN_GROUP_FIRST as usize + 3,
                split_cross_domain: false,
            };
            assert_eq!(plan(&modules, &edges, room).unwrap().rings.len(), 3);
            let short = RingPlatform {
                buffer_groups: RECORD_FAN_GROUP_FIRST as usize + 2,
                ..room
            };
            assert_eq!(
                plan(&modules, &edges, short).unwrap_err(),
                RingError::GroupsExhausted
            );
        }

        #[test]
        fn the_group_span_follows_the_graph_s_edge_capacity() {
            assert_eq!(buffer_groups(1536), 256);
            assert_eq!(buffer_groups(128), 128);
        }

        #[test]
        fn an_oversized_request_is_refused_not_clamped() {
            let modules = vec![RingModule::default(), RingModule::default()];
            let edges = [RingEdge {
                from: 0,
                to: 1,
                buffer_bytes: MAX_RING_BYTES + 1,
                ..Default::default()
            }];
            assert!(matches!(
                plan(&modules, &edges, HOST).unwrap_err(),
                RingError::OverCeiling { request, .. } if request == MAX_RING_BYTES + 1
            ));
        }
    }
}
