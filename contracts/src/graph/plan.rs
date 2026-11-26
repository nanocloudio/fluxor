//! The composition rules: what turns a declared graph into the composed one
//! the kernel admits.
//!
//! - [`fan_pass`]: a port with more than one edge gets a fan — a tee on an
//!   output, a merge on an input — whose frame kind is the fanned port's
//!   declared kind or, where it declares a stream or nothing, the kind every
//!   peer across the fan agrees on. A lane end is a port of its own: edges
//!   into one lane share a merge, and edges out of it a tee. A record fan gives every edge around it
//!   a mailbox group of its own; any other fan leaves its edges ungrouped. A
//!   multi-inbound module's data inputs, and a multi-outbound module's output
//!   whose consumers are exactly the modules feeding it, stay unfanned.
//! - [`record_mailboxes`]: a point-to-point edge whose producer or consumer
//!   port carries records gets a mailbox group of its own.
//! - [`rings`]: every ring the graph opens, by the sizing rule of
//!   [`crate::ring_size`], with mailbox groups aliased.
//! - [`order`]: the stepping order, Kahn's breadth-first order over the edges
//!   between the graph's modules; cycle members follow in index order when
//!   the caller accepts cycles, and refuse the graph otherwise.
//!
//! Every pass works over caller-provided slices and allocates nothing, so a
//! module with no allocator can compose a graph at runtime. With feature
//! `alloc`, [`compose`] and [`plan`] run them over vectors.
//!
//! A graph's nodes are its declared modules, indices `0..modules.len()`, then
//! its fans in the order the pass inserts them.

use super::{EdgeClass, EdgeRecord, Endpoint, FaultPolicy, ModuleRecord, MAX_PORT_INDEX};
use super::{MERGE_NAME_HASH, TEE_NAME_HASH};
use crate::ring_size::{
    arena_bytes, edge_request, record_bytes, ring_for, DEFAULT_RING_BYTES, RECORD_FAN_GROUP_FIRST,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Manifest port direction bytes.
pub const DIR_IN: u8 = 0;
pub const DIR_OUT: u8 = 1;
pub const DIR_CTRL: u8 = 2;

/// Manifest port flag: the port carries whole records whatever its content
/// type.
pub const PORT_FLAG_FRAMED: u8 = 0x02;

/// A fanned input's port key bit: the input is a control input.
pub const PORT_KEY_CTRL: u8 = 0x10;

/// Whether a port of content type `content_type` and manifest flags `flags`
/// carries mailbox records: its edges, and a fan over it, are mailboxes
/// rather than rings. Every channel keeps write boundaries either way; this
/// only picks the buffer.
#[must_use]
pub fn port_mailbox(content_type: u8, flags: u8) -> bool {
    let framed = crate::CONTENT_FRAMING
        .get(usize::from(content_type))
        .is_some_and(|f| *f == crate::Framing::Framed);
    framed || flags & PORT_FLAG_FRAMED != 0
}

/// One port record of a module's manifest. A lookup takes the first record
/// matching its direction and index, as the loader does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanPort {
    pub direction: u8,
    pub index: u8,
    /// The declared ring capacity (`buffer_size`); 0 undeclared.
    pub buffer_size: u32,
    /// The largest single write the port issues (`max_record`); 0
    /// undeclared.
    pub max_record: u32,
    /// The port carries mailbox records ([`port_mailbox`]).
    pub mailbox: bool,
}

/// A declared module, as composition sees it.
#[derive(Clone, Copy, Debug, Default)]
pub struct PlanModule<'a> {
    /// Its manifest's port records. Empty for a module the node runs built
    /// in, whose ports declare nothing.
    pub ports: &'a [PlanPort],
    /// It may consume from an aliased mailbox (`mailbox_safe`).
    pub mailbox_safe: bool,
    /// Its data inputs keep one channel per edge rather than a merge.
    pub multi_inbound: bool,
    /// Its output keeps one channel per edge when every consumer of it is
    /// one of its producers.
    pub multi_outbound: bool,
    /// The execution domain it steps in.
    pub domain: u8,
}

impl PlanModule<'_> {
    fn port(&self, direction: u8, index: u8) -> Option<&PlanPort> {
        self.ports
            .iter()
            .find(|p| p.direction == direction && p.index == index)
    }
}

/// Which side of a module a fan sits on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FanDir {
    /// A tee on an output.
    Out,
    /// A merge on an input.
    In,
}

/// A fan the pass inserted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fan {
    pub dir: FanDir,
    /// The fanned end: a declared module (`Endpoint::New`), or a lane
    /// (`Endpoint::Lane`), whose commands a merge feeds and whose events a
    /// tee carries out.
    pub of: Endpoint,
    /// The fanned port: an output index, or an input index with
    /// [`PORT_KEY_CTRL`] for a control input; 0 on a lane.
    pub port: u8,
    /// Its edges are mailboxes: the fanned port, or every peer that says,
    /// carries mailbox records.
    pub mailbox: bool,
    /// The domain the fan steps in: the fanned module's, or on a lane the
    /// first peer's across the fan.
    pub domain: u8,
}

impl Fan {
    /// The module the fan runs as.
    #[must_use]
    pub const fn name_hash(&self) -> u32 {
        match self.dir {
            FanDir::Out => TEE_NAME_HASH,
            FanDir::In => MERGE_NAME_HASH,
        }
    }

    /// The node its rings name it by.
    #[must_use]
    pub const fn ring_node(&self) -> RingNode {
        match self.dir {
            FanDir::Out => RingNode::Tee {
                of: self.of,
                port: self.port,
            },
            FanDir::In => RingNode::Merge {
                of: self.of,
                port: self.port,
            },
        }
    }

    /// The fan's module record over `params` (see [`fan_params`]).
    #[must_use]
    pub const fn record<'a>(&self, params: &'a [u8]) -> ModuleRecord<'a> {
        ModuleRecord {
            name_hash: self.name_hash(),
            domain: self.domain,
            pre_pass: false,
            step_deadline_us: 0,
            burst_us: 0,
            fault_policy: FaultPolicy::Skip,
            params,
        }
    }
}

/// The params TLV tags of a fan module.
pub mod fan_param {
    /// `u16`: records moved per step.
    pub const FRAMES_PER_STEP: u8 = 1;
    /// `u32`: bytes of scratch, the largest record the fan moves
    /// ([`super::Composed::fan_scratch`]).
    pub const SCRATCH_BYTES: u8 = 2;
}

/// Records a fan moves per step unless the composer says otherwise.
pub const FRAMES_PER_STEP_DEFAULT: u16 = 64;

/// Bytes of a fan's params TLV.
pub const FAN_PARAMS_LEN: usize = 4 + (2 + 2) + (2 + 4) + 2;

/// A fan's params TLV.
#[must_use]
pub fn fan_params(frames_per_step: u16, scratch_bytes: u32) -> [u8; FAN_PARAMS_LEN] {
    let mut p = [0u8; FAN_PARAMS_LEN];
    p[0] = crate::params_tlv::TLV_MAGIC;
    p[1] = crate::params_tlv::TLV_VERSION;
    // The payload, terminator included: 12 bytes.
    p[2] = (FAN_PARAMS_LEN - 4) as u8;
    p[4] = fan_param::FRAMES_PER_STEP;
    p[5] = 2;
    p[6..8].copy_from_slice(&frames_per_step.to_le_bytes());
    p[8] = fan_param::SCRATCH_BYTES;
    p[9] = 4;
    p[10..14].copy_from_slice(&scratch_bytes.to_le_bytes());
    p[14] = crate::params_tlv::TLV_END;
    p
}

/// A graph composition refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanError {
    /// An edge names a module the graph does not declare.
    UnknownModule { edge: usize },
    /// The caller's edge buffer has no room for a fan's joining edge.
    EdgeCapacity,
    /// The caller's fan buffer has no room for another fan, or the graph's
    /// nodes would pass a `u16` index.
    FanCapacity,
    /// The caller's order or in-degree buffer is shorter than the graph's
    /// nodes.
    OrderCapacity,
    /// A record fan or record edge needs a mailbox group and none is left.
    GroupsExhausted,
    /// A port carries more edges than a fan has ports on its many side
    /// ([`MAX_PORT_INDEX`] + 1): output `port` of end `of` for a tee, or
    /// its input `port` ([`PORT_KEY_CTRL`] set for a control input) for a
    /// merge.
    FanWidth {
        dir: FanDir,
        of: Endpoint,
        port: u8,
        edges: usize,
    },
    /// The graph has cycles and the caller does not accept them.
    Cycle { members: usize },
    /// An edge asks for more than `MAX_RING_BYTES`.
    OverCeiling { ends: RingEnds, request: u32 },
    /// A producer's `max_record`, with its records' length prefixes on a
    /// ring, is larger than the ring its edge is granted.
    RecordOverRing {
        ends: RingEnds,
        max_record: u32,
        granted: u32,
    },
}

// ── Nodes ───────────────────────────────────────────────────────────────────

/// A graph's nodes: its declared modules, then its fans.
#[derive(Clone, Copy)]
struct Nodes<'m, 'f> {
    modules: &'m [PlanModule<'m>],
    fans: &'f [Fan],
}

impl Nodes<'_, '_> {
    fn module(&self, end: Endpoint) -> Option<&PlanModule<'_>> {
        end.new_index().and_then(|i| self.modules.get(i))
    }

    fn fan(&self, end: Endpoint) -> Option<&Fan> {
        end.new_index()
            .and_then(|i| i.checked_sub(self.modules.len()))
            .and_then(|f| self.fans.get(f))
    }

    fn port(&self, end: Endpoint, direction: u8, index: u8) -> Option<&PlanPort> {
        self.module(end)?.port(direction, index)
    }

    /// The `(buffer_size, max_record)` of an end's port: (0, 0) where
    /// undeclared.
    fn cap(&self, end: Endpoint, direction: u8, index: u8) -> (u32, u32) {
        self.port(end, direction, index)
            .map_or((0, 0), |p| (p.buffer_size, p.max_record))
    }

    /// The `(buffer_size, max_record)` an edge's producer end writes with:
    /// a module's port, or for a fan the largest record any of its inbound
    /// producers declares (a fan copies records whole, so it writes what it
    /// reads). 0 where any inbound producer leaves it undeclared.
    fn producer_cap(&self, end: Endpoint, port: u8, edges: &[EdgeRecord]) -> (u32, u32) {
        if self.fan(end).is_none() {
            return self.cap(end, DIR_OUT, port);
        }
        (0, self.fan_inbound_max_record(end, edges, 2))
    }

    /// The largest record an inbound producer of fan `end` declares; 0 when
    /// one declares none. `depth` bounds a fan feeding a fan.
    fn fan_inbound_max_record(&self, end: Endpoint, edges: &[EdgeRecord], depth: u8) -> u32 {
        let mut max = 0u32;
        let mut any = false;
        for e in edges.iter().filter(|e| e.to == end) {
            let m = if self.fan(e.from).is_some() {
                if depth == 0 {
                    0
                } else {
                    self.fan_inbound_max_record(e.from, edges, depth - 1)
                }
            } else {
                self.cap(e.from, DIR_OUT, e.from_port).1
            };
            if m == 0 {
                return 0;
            }
            any = true;
            max = max.max(m);
        }
        if any {
            max
        } else {
            0
        }
    }

    fn domain(&self, end: Endpoint) -> Option<u8> {
        self.module(end)
            .map(|m| m.domain)
            .or_else(|| self.fan(end).map(|f| f.domain))
    }

    fn ring_node(&self, end: Endpoint) -> RingNode {
        if let Some(i) = end.new_index().filter(|&i| i < self.modules.len()) {
            // Node indices fit a u16: `Endpoint::New` carries one.
            return RingNode::Module(i as u16);
        }
        match self.fan(end) {
            Some(f) if f.dir == FanDir::Out => RingNode::Tee {
                of: f.of,
                port: f.port,
            },
            Some(f) => RingNode::Merge {
                of: f.of,
                port: f.port,
            },
            None => RingNode::External(end),
        }
    }
}

const fn in_direction(key: u8) -> u8 {
    if key & PORT_KEY_CTRL != 0 {
        DIR_CTRL
    } else {
        DIR_IN
    }
}

// ── Fan pass ────────────────────────────────────────────────────────────────

/// The port an edge occupies on the side `dir` looks at: its output index,
/// or its input index with [`PORT_KEY_CTRL`] for a control input.
const fn port_key(e: &EdgeRecord, dir: FanDir) -> u8 {
    match dir {
        FanDir::Out => e.from_port,
        FanDir::In if e.to_ctrl => PORT_KEY_CTRL | e.to_port,
        FanDir::In => e.to_port,
    }
}

/// The end of `e` the side `dir` looks at: its producer for a tee, its
/// consumer for a merge.
const fn side(e: &EdgeRecord, dir: FanDir) -> Endpoint {
    match dir {
        FanDir::Out => e.from,
        FanDir::In => e.to,
    }
}

fn touches(e: &EdgeRecord, site: Endpoint, dir: FanDir) -> bool {
    side(e, dir) == site
}

/// What the fan pass inserted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FanCounts {
    /// Edges now in the caller's buffer: the declared ones, then one joining
    /// edge per fan.
    pub edges: usize,
    /// Fans written to the caller's buffer.
    pub fans: usize,
}

struct FanPass<'a, 'm> {
    modules: &'m [PlanModule<'m>],
    edges: &'a mut [EdgeRecord],
    count: usize,
    fans: &'a mut [Fan],
    nfans: usize,
    groups: usize,
}

impl FanPass<'_, '_> {
    /// Whether an end's port carries mailbox records; `None` where the end
    /// is no declared module or the module declares no such port.
    fn declared(&self, end: Endpoint, dir: FanDir, key: u8) -> Option<bool> {
        let module = end.new_index().and_then(|i| self.modules.get(i))?;
        let direction = match dir {
            FanDir::Out => DIR_OUT,
            FanDir::In => in_direction(key),
        };
        module.port(direction, key & 0x0F).map(|p| p.mailbox)
    }

    fn in_group(&self, j: usize, site: Endpoint, dir: FanDir, key: u8) -> bool {
        touches(&self.edges[j], site, dir) && port_key(&self.edges[j], dir) == key
    }

    /// The domain an end steps in: a declared module's, or a fan's the
    /// pass inserted; `None` for an end outside the graph.
    fn domain_of(&self, end: Endpoint) -> Option<u8> {
        let i = end.new_index()?;
        match self.modules.get(i) {
            Some(m) => Some(m.domain),
            None => self.fans[..self.nfans]
                .get(i - self.modules.len())
                .map(|f| f.domain),
        }
    }

    /// The lowest group at or above [`RECORD_FAN_GROUP_FIRST`] no edge uses.
    fn fresh_group(&self) -> Result<u8, PlanError> {
        (usize::from(RECORD_FAN_GROUP_FIRST)..self.groups.min(256))
            .map(|g| g as u8)
            .find(|g| {
                !self.edges[..self.count]
                    .iter()
                    .any(|e| e.buffer_group == *g)
            })
            .ok_or(PlanError::GroupsExhausted)
    }

    /// Whether the out-edges of `m` keyed `key` from `first` on reach
    /// exactly the modules feeding its data input, each once.
    fn pairs_with_inputs(&self, m: usize, first: usize, scan: usize, key: u8) -> bool {
        let me = Endpoint::New(m as u16);
        let edges = &self.edges[..self.count];
        let feeds = |c: Endpoint| {
            edges
                .iter()
                .any(|e| e.from == c && e.to == me && !e.to_ctrl)
        };
        let group = || (first..scan).filter(|&j| self.in_group(j, me, FanDir::Out, key));
        for j in group() {
            let c = edges[j].to;
            if !feeds(c) || group().take_while(|&i| i < j).any(|i| edges[i].to == c) {
                return false;
            }
        }
        edges
            .iter()
            .all(|e| e.to != me || e.to_ctrl || group().any(|j| edges[j].to == e.from))
    }

    /// Whether the fan on `m`'s port `key` moves mailbox records: the port
    /// declares records, or where it declares rings or nothing, every peer
    /// that declares its port agrees on records (rings where they disagree).
    fn record(&self, site: Endpoint, first: usize, scan: usize, dir: FanDir, key: u8) -> bool {
        if self.declared(site, dir, key) == Some(true) {
            return true;
        }
        let mut agreed = None;
        for j in (first..scan).filter(|&j| self.in_group(j, site, dir, key)) {
            let e = &self.edges[j];
            let peer = match dir {
                FanDir::Out => self.declared(e.to, FanDir::In, port_key(e, FanDir::In)),
                FanDir::In => self.declared(e.from, FanDir::Out, e.from_port),
            };
            match (agreed, peer) {
                (_, None) => {}
                (None, Some(k)) => agreed = Some(k),
                (Some(a), Some(k)) if a == k => {}
                (Some(_), Some(_)) => return false,
            }
        }
        agreed.unwrap_or(false)
    }

    fn run(&mut self, dir: FanDir) -> Result<(), PlanError> {
        for m in 0..self.modules.len() {
            self.fan_site(Endpoint::New(m as u16), dir)?;
        }
        // Each lane end the declared edges name, in the order they first
        // name it.
        let scan = self.count;
        for i in 0..scan {
            let end = side(&self.edges[i], dir);
            if matches!(end, Endpoint::Lane { .. })
                && !(0..i).any(|j| side(&self.edges[j], dir) == end)
            {
                self.fan_site(end, dir)?;
            }
        }
        Ok(())
    }

    /// Fan every port of `site` on side `dir` that carries two edges or
    /// more, unless the module keeps one channel per edge there.
    fn fan_site(&mut self, site: Endpoint, dir: FanDir) -> Result<(), PlanError> {
        let scan = self.count;
        for first in 0..scan {
            if !touches(&self.edges[first], site, dir) {
                continue;
            }
            let key = port_key(&self.edges[first], dir);
            // A key is fanned, or left alone, at its first edge.
            if (0..first).any(|j| self.in_group(j, site, dir, key)) {
                continue;
            }
            let size = (first..scan)
                .filter(|&j| self.in_group(j, site, dir, key))
                .count();
            if size < 2 {
                continue;
            }
            if size > usize::from(MAX_PORT_INDEX) + 1 {
                return Err(PlanError::FanWidth {
                    dir,
                    of: site,
                    port: key,
                    edges: size,
                });
            }
            let exempt = match site.new_index() {
                Some(m) if m < self.modules.len() => match dir {
                    FanDir::Out => {
                        self.modules[m].multi_outbound
                            && self.pairs_with_inputs(m, first, scan, key)
                    }
                    FanDir::In => key & PORT_KEY_CTRL == 0 && self.modules[m].multi_inbound,
                },
                _ => false,
            };
            if exempt {
                continue;
            }
            self.insert(site, first, scan, dir, key)?;
        }
        Ok(())
    }

    fn insert(
        &mut self,
        site: Endpoint,
        first: usize,
        scan: usize,
        dir: FanDir,
        key: u8,
    ) -> Result<(), PlanError> {
        if self.count >= self.edges.len() {
            return Err(PlanError::EdgeCapacity);
        }
        let node = self.modules.len() + self.nfans;
        if self.nfans >= self.fans.len() || node > usize::from(u16::MAX) {
            return Err(PlanError::FanCapacity);
        }
        let record = self.record(site, first, scan, dir, key);
        // A lane steps nowhere in the graph: its fan steps with the first
        // peer across it.
        let domain = self.domain_of(site).unwrap_or_else(|| {
            let peer = |e: &EdgeRecord| match dir {
                FanDir::Out => e.to,
                FanDir::In => e.from,
            };
            (first..scan)
                .filter(|&j| self.in_group(j, site, dir, key))
                .find_map(|j| self.domain_of(peer(&self.edges[j])))
                .unwrap_or(0)
        });
        for j in first..scan {
            if self.in_group(j, site, dir, key) {
                self.edges[j].buffer_group = if record { self.fresh_group()? } else { 0 };
            }
        }
        self.fans[self.nfans] = Fan {
            dir,
            of: site,
            port: key,
            mailbox: record,
            domain,
        };
        self.nfans += 1;
        let fan = Endpoint::New(node as u16);
        let here = site;
        let mut join = match dir {
            FanDir::Out => EdgeRecord {
                from: here,
                from_port: key,
                to: fan,
                retains_send: (first..scan)
                    .filter(|&j| self.in_group(j, site, dir, key))
                    .all(|j| self.edges[j].retains_send),
                ..EdgeRecord::default()
            },
            FanDir::In => EdgeRecord {
                from: fan,
                to: here,
                to_port: key & 0x0F,
                to_ctrl: key & PORT_KEY_CTRL != 0,
                ..EdgeRecord::default()
            },
        };
        if record {
            join.buffer_group = self.fresh_group()?;
        }
        self.edges[self.count] = join;
        self.count += 1;
        let mut k = 0u8;
        for j in first..scan {
            if !self.in_group(j, site, dir, key) {
                continue;
            }
            let e = &mut self.edges[j];
            match dir {
                FanDir::Out => {
                    e.from = fan;
                    e.from_port = k;
                }
                FanDir::In => {
                    e.to = fan;
                    e.to_port = k;
                    e.to_ctrl = false;
                }
            }
            k = k.wrapping_add(1);
        }
        Ok(())
    }
}

/// Insert the graph's fans. `edges[..edge_count]` are the declared edges;
/// each fan's joining edge is appended after them, and the fans go to
/// `fans`. `groups` is the kernel's mailbox group span
/// (`ring_size::buffer_groups`), from which a record fan draws a group for
/// every edge around it.
///
/// # Errors
/// An edge naming no declared module, a fanned port with more edges than a
/// fan has ports, a buffer with no room, or no mailbox group left.
pub fn fan_pass(
    modules: &[PlanModule<'_>],
    edges: &mut [EdgeRecord],
    edge_count: usize,
    fans: &mut [Fan],
    groups: usize,
) -> Result<FanCounts, PlanError> {
    for (i, e) in edges[..edge_count].iter().enumerate() {
        for end in [e.from, e.to] {
            if end.new_index().is_some_and(|m| m >= modules.len()) {
                return Err(PlanError::UnknownModule { edge: i });
            }
        }
    }
    let mut pass = FanPass {
        modules,
        edges,
        count: edge_count,
        fans,
        nfans: 0,
        groups,
    };
    pass.run(FanDir::Out)?;
    pass.run(FanDir::In)?;
    Ok(FanCounts {
        edges: pass.count,
        fans: pass.nfans,
    })
}

// ── Record mailboxes ────────────────────────────────────────────────────────

/// Give every ungrouped point-to-point edge whose producer or consumer port
/// carries records a mailbox group of its own, drawn from `groups` as a
/// record fan draws one. Run after [`fan_pass`]: an edge touching a fan
/// already has its fan's decision. A tap and a net lane carry their own
/// framing. Returns how many edges it grouped.
///
/// # Errors
/// No mailbox group left.
pub fn record_mailboxes(
    modules: &[PlanModule<'_>],
    edges: &mut [EdgeRecord],
    groups: usize,
) -> Result<usize, PlanError> {
    let n = modules.len();
    let record = |end: Endpoint, direction: u8, index: u8| {
        end.new_index()
            .and_then(|i| modules.get(i))
            .and_then(|m| m.port(direction, index))
            .is_some_and(|p| p.mailbox)
    };
    let excluded = |end: Endpoint| {
        matches!(end, Endpoint::Tap(_) | Endpoint::Lane { .. })
            || end.new_index().is_some_and(|i| i >= n)
    };
    let mut grouped = 0;
    for i in 0..edges.len() {
        let e = edges[i];
        if e.buffer_group != 0 || excluded(e.from) || excluded(e.to) {
            continue;
        }
        let to_dir = if e.to_ctrl { DIR_CTRL } else { DIR_IN };
        if !record(e.from, DIR_OUT, e.from_port) && !record(e.to, to_dir, e.to_port) {
            continue;
        }
        let g = (usize::from(RECORD_FAN_GROUP_FIRST)..groups.min(256))
            .map(|g| g as u8)
            .find(|g| !edges.iter().any(|x| x.buffer_group == *g))
            .ok_or(PlanError::GroupsExhausted)?;
        edges[i].buffer_group = g;
        grouped += 1;
    }
    Ok(grouped)
}

// ── Order ───────────────────────────────────────────────────────────────────

/// The stepping order of `nodes` nodes joined by `edges`, written to
/// `out[..nodes]`: Kahn's breadth-first order, sources first and each node's
/// successors queued in edge order as their last inbound edge is taken. Only
/// edges between two of the graph's nodes count. Nodes left on a cycle follow
/// in index order when `accept_cycles`. `indeg` is scratch of `nodes`
/// entries. Returns how many nodes sit on cycles.
///
/// # Errors
/// [`PlanError::Cycle`] for a cycle the caller does not accept, or a buffer
/// shorter than `nodes`.
pub fn order(
    nodes: usize,
    edges: &[EdgeRecord],
    accept_cycles: bool,
    out: &mut [u16],
    indeg: &mut [u16],
) -> Result<usize, PlanError> {
    if out.len() < nodes || indeg.len() < nodes || nodes > usize::from(u16::MAX) + 1 {
        return Err(PlanError::OrderCapacity);
    }
    let inner = |e: &EdgeRecord| match (e.from.new_index(), e.to.new_index()) {
        (Some(f), Some(t)) if f < nodes && t < nodes => Some((f, t)),
        _ => None,
    };
    indeg[..nodes].fill(0);
    for (_, t) in edges.iter().filter_map(inner) {
        indeg[t] = indeg[t].saturating_add(1);
    }
    // The queue is the order: a node is stepped in the order it is queued.
    let mut tail = 0;
    for (m, &d) in indeg[..nodes].iter().enumerate() {
        if d == 0 {
            out[tail] = m as u16;
            tail += 1;
        }
    }
    let mut head = 0;
    while head < tail {
        let m = usize::from(out[head]);
        head += 1;
        for (_, t) in edges.iter().filter_map(inner).filter(|&(f, _)| f == m) {
            indeg[t] -= 1;
            if indeg[t] == 0 {
                out[tail] = t as u16;
                tail += 1;
            }
        }
    }
    let members = nodes - tail;
    if members > 0 {
        if !accept_cycles {
            return Err(PlanError::Cycle { members });
        }
        // A node never queued still waits on an edge.
        for (m, &d) in indeg[..nodes].iter().enumerate() {
            if d > 0 {
                out[tail] = m as u16;
                tail += 1;
            }
        }
    }
    Ok(members)
}

// ── Rings ───────────────────────────────────────────────────────────────────

/// What the platform adds to the rings a graph opens.
#[derive(Clone, Copy, Debug)]
pub struct RingPlatform {
    /// Mailbox groups the kernel has (`ring_size::buffer_groups` of its
    /// graph-edge capacity).
    pub buffer_groups: usize,
    /// The core each execution domain steps on, by domain index. Where any
    /// domain steps off core 0 the kernel bridges cores: every edge whose
    /// ends step on different cores, or whose class is `CrossCore`, is
    /// split into a producer-side and a consumer-side channel joined by a
    /// pump, and the consumer side is a default ring of its own. Edges
    /// between domains of one core stay one channel.
    pub domain_cores: [u8; crate::core_map::DOMAINS],
}

impl RingPlatform {
    /// Whether the kernel bridges cores: some domain steps off core 0.
    pub fn bridges_cores(&self) -> bool {
        crate::core_map::has_secondary(&self.domain_cores)
    }

    /// Whether an edge between domains `from` and `to` crosses cores.
    pub fn crosses_cores(&self, from: u8, to: u8) -> bool {
        crate::core_map::crosses_cores(&self.domain_cores, usize::from(from), usize::from(to))
    }
}

/// An end of a ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingNode {
    /// A declared module.
    Module(u16),
    /// The tee on output `port` of `of`: a declared module, or a lane's
    /// events.
    Tee { of: Endpoint, port: u8 },
    /// The merge on input `port` ([`PORT_KEY_CTRL`] set for a control input)
    /// of `of`: a declared module, or a lane's commands.
    Merge { of: Endpoint, port: u8 },
    /// An end outside the graph.
    External(Endpoint),
}

/// Why a ring was opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingRole {
    /// The channel of declared edge `n` (through its fan, when it has one).
    Edge(usize),
    /// The edge joining a fanned port to its fan.
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

/// One ring the graph opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ring {
    pub ends: RingEnds,
    /// The producer port's capacity, the consumer port's, and the edge's
    /// `buffer_bytes`.
    pub producer_cap: u32,
    pub consumer_cap: u32,
    pub buffer_bytes: u32,
    /// What was asked: the edge's request, or its mailbox group's largest;
    /// 0 unsized.
    pub request: u32,
    /// The ring granted.
    pub ring: u32,
    /// What it takes from the buffer arena.
    pub arena: u64,
}

/// What [`rings`] counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RingTotals {
    pub rings: usize,
    /// Edges that share a ring by aliasing into their group's mailbox.
    pub aliased: usize,
    /// The buffer arena the rings take.
    pub arena: u64,
}

/// Every ring a composed graph opens, in the order it opens them, handed to
/// `each`: every edge's channel with mailbox groups aliased, then the
/// consumer side of every cross-domain edge where the platform splits them.
/// `edges` is the composed edge list ([`fan_pass`]'s output), the first
/// `declared_edges` of them the declared ones.
///
/// # Errors
/// A request over the ring ceiling, or a record that cannot fit its ring.
pub fn rings(
    modules: &[PlanModule<'_>],
    fans: &[Fan],
    edges: &[EdgeRecord],
    declared_edges: usize,
    platform: RingPlatform,
    mut each: impl FnMut(Ring),
) -> Result<RingTotals, PlanError> {
    let nodes = Nodes { modules, fans };
    let to_dir = |e: &EdgeRecord| if e.to_ctrl { DIR_CTRL } else { DIR_IN };
    let request = |e: &EdgeRecord| {
        let (from, _) = nodes.cap(e.from, DIR_OUT, e.from_port);
        let (to, _) = nodes.cap(e.to, to_dir(e), e.to_port);
        edge_request(from, to, e.buffer_bytes)
    };
    let ends = |i: usize, e: &EdgeRecord| RingEnds {
        role: if i < declared_edges {
            RingRole::Edge(i)
        } else {
            RingRole::Fan
        },
        from: nodes.ring_node(e.from),
        from_port: e.from_port,
        to: nodes.ring_node(e.to),
        ctrl: e.to_ctrl,
        to_port: e.to_port,
    };
    let mut totals = RingTotals::default();
    for (i, e) in edges.iter().enumerate() {
        let group = e.buffer_group;
        // A group's ring is opened by its first edge and aliased by every
        // later one whose consumer is mailbox-safe.
        let opened = group != 0 && edges[..i].iter().any(|x| x.buffer_group == group);
        if opened && nodes.module(e.to).is_some_and(|m| m.mailbox_safe) {
            totals.aliased += 1;
            continue;
        }
        let group_max = if group == 0 {
            0
        } else {
            edges
                .iter()
                .filter(|x| x.buffer_group == group)
                .map(request)
                .max()
                .unwrap_or(0)
        };
        let asked = if group_max > 0 { group_max } else { request(e) };
        let ends = ends(i, e);
        let ring = ring_for(asked).ok_or(PlanError::OverCeiling {
            ends,
            request: asked,
        })?;
        // A ring keeps each record's length beside it; a mailbox's record is
        // its whole buffer.
        let (producer_cap, max_record) = nodes.producer_cap(e.from, e.from_port, edges);
        let footprint = if group != 0 {
            u64::from(max_record)
        } else {
            record_bytes(max_record)
        };
        if footprint > u64::from(ring) {
            return Err(PlanError::RecordOverRing {
                ends,
                max_record,
                granted: ring,
            });
        }
        let (consumer_cap, _) = nodes.cap(e.to, to_dir(e), e.to_port);
        let r = Ring {
            ends,
            producer_cap,
            consumer_cap,
            buffer_bytes: e.buffer_bytes,
            request: asked,
            ring,
            arena: arena_bytes(ring),
        };
        totals.rings += 1;
        totals.arena += r.arena;
        each(r);
    }
    if platform.bridges_cores() {
        for (i, e) in edges.iter().enumerate() {
            let crosses = match (nodes.domain(e.from), nodes.domain(e.to)) {
                (Some(a), Some(b)) => platform.crosses_cores(a, b),
                _ => false,
            };
            if !crosses && e.class != EdgeClass::CrossCore {
                continue;
            }
            let r = Ring {
                ends: RingEnds {
                    role: RingRole::CrossDomain,
                    ..ends(i, e)
                },
                producer_cap: 0,
                consumer_cap: 0,
                buffer_bytes: 0,
                request: 0,
                ring: DEFAULT_RING_BYTES,
                arena: arena_bytes(DEFAULT_RING_BYTES),
            };
            totals.rings += 1;
            totals.arena += r.arena;
            each(r);
        }
    }
    Ok(totals)
}

// ── Over vectors ────────────────────────────────────────────────────────────

/// A declared graph composed: its fans inserted, mailbox groups assigned and
/// order computed.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Default)]
pub struct Composed {
    /// Declared modules; node `declared_modules + i` is `fans[i]`.
    pub declared_modules: usize,
    /// Declared edges; the edges after them join fans to fanned ports.
    pub declared_edges: usize,
    pub fans: Vec<Fan>,
    pub edges: Vec<EdgeRecord>,
    /// Node indices, the first to step first.
    pub order: Vec<u16>,
    /// Nodes on cycles, stepped after the rest in index order.
    pub cycle_members: usize,
}

#[cfg(feature = "alloc")]
impl Composed {
    /// Declared modules and fans.
    #[must_use]
    pub fn nodes(&self) -> usize {
        self.declared_modules + self.fans.len()
    }

    /// The rings the composed graph opens.
    ///
    /// # Errors
    /// As [`rings`].
    pub fn rings(
        &self,
        modules: &[PlanModule<'_>],
        platform: RingPlatform,
    ) -> Result<RingPlan, PlanError> {
        let mut plan = RingPlan::default();
        let totals = rings(
            modules,
            &self.fans,
            &self.edges,
            self.declared_edges,
            platform,
            |r| plan.rings.push(r),
        )?;
        plan.aliased = totals.aliased;
        Ok(plan)
    }

    /// The scratch fan `k` (of [`Self::fans`]) is given: the largest record
    /// it can be handed — what every producer feeding it declares as its
    /// `max_record` — or, where one declares none, the largest ring beside
    /// it in `rings`, which no record outgrows.
    #[must_use]
    pub fn fan_scratch(&self, k: usize, modules: &[PlanModule<'_>], rings: &RingPlan) -> u32 {
        let Some(fan) = self.fans.get(k) else {
            return 0;
        };
        let nodes = Nodes {
            modules,
            fans: &self.fans,
        };
        let end = Endpoint::New((self.declared_modules + k) as u16);
        match nodes.fan_inbound_max_record(end, &self.edges, 2) {
            0 => rings.largest_adjacent(fan.ring_node()),
            m => m,
        }
    }
}

/// A fan moves each record whole, so every edge a fan writes asks for a ring
/// that holds the largest record the fan can be handed: what its producers
/// declare as their `max_record`, or, where one declares none, the largest
/// request among the edges into it. The floor rides in the edge's
/// `buffer_bytes`, which every consumer of the composed graph sizes its ring
/// by. Edges of a mailbox group keep the group's buffer.
pub fn size_fan_writes(modules: &[PlanModule<'_>], fans: &[Fan], edges: &mut [EdgeRecord]) {
    let nodes = Nodes { modules, fans };
    for i in 0..edges.len() {
        let from = edges[i].from;
        if edges[i].buffer_group != 0 || nodes.fan(from).is_none() {
            continue;
        }
        let floor = match nodes.fan_inbound_max_record(from, edges, 2) {
            0 => edges
                .iter()
                .filter(|x| x.to == from)
                .map(|x| {
                    let (producer, _) = nodes.cap(x.from, DIR_OUT, x.from_port);
                    let to_dir = if x.to_ctrl { DIR_CTRL } else { DIR_IN };
                    let (consumer, _) = nodes.cap(x.to, to_dir, x.to_port);
                    edge_request(producer, consumer, x.buffer_bytes)
                })
                .max()
                .unwrap_or(0),
            m => u32::try_from(record_bytes(m)).unwrap_or(u32::MAX),
        };
        if floor > edges[i].buffer_bytes {
            edges[i].buffer_bytes = floor;
        }
    }
}

/// Compose `edges` between `modules`: [`fan_pass`] then [`order`].
///
/// # Errors
/// As [`fan_pass`] and [`order`].
#[cfg(feature = "alloc")]
pub fn compose(
    modules: &[PlanModule<'_>],
    edges: &[EdgeRecord],
    groups: usize,
    accept_cycles: bool,
) -> Result<Composed, PlanError> {
    // A fan takes two edges or more of one port and adds one edge: each
    // declared edge is fanned at most once on each side.
    let mut buf = Vec::with_capacity(2 * edges.len());
    buf.extend_from_slice(edges);
    buf.resize(2 * edges.len(), EdgeRecord::default());
    let mut fans = alloc::vec![
        Fan {
            dir: FanDir::Out,
            of: Endpoint::New(0),
            port: 0,
            mailbox: false,
            domain: 0,
        };
        edges.len()
    ];
    let counts = fan_pass(modules, &mut buf, edges.len(), &mut fans, groups)?;
    buf.truncate(counts.edges);
    fans.truncate(counts.fans);
    size_fan_writes(modules, &fans, &mut buf);
    let nodes = modules.len() + fans.len();
    let mut out = alloc::vec![0u16; nodes];
    let mut indeg = alloc::vec![0u16; nodes];
    let cycle_members = order(nodes, &buf, accept_cycles, &mut out, &mut indeg)?;
    Ok(Composed {
        declared_modules: modules.len(),
        declared_edges: edges.len(),
        fans,
        edges: buf,
        order: out,
        cycle_members,
    })
}

/// Every ring a graph opens, in the order it opens them.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Default)]
pub struct RingPlan {
    pub rings: Vec<Ring>,
    /// Edges that share a ring by aliasing into their group's mailbox.
    pub aliased: usize,
}

#[cfg(feature = "alloc")]
impl RingPlan {
    /// The buffer arena the graph takes.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.rings.iter().map(|r| r.arena).sum()
    }

    /// The largest ring with `node` at either end: a fan's scratch.
    #[must_use]
    pub fn largest_adjacent(&self, node: RingNode) -> u32 {
        self.rings
            .iter()
            .filter(|r| r.ends.from == node || r.ends.to == node)
            .map(|r| r.ring)
            .max()
            .unwrap_or(0)
    }
}

/// The rings `edges` between `modules` open: [`fan_pass`] then [`rings`].
///
/// # Errors
/// As [`fan_pass`] and [`rings`].
#[cfg(feature = "alloc")]
pub fn plan(
    modules: &[PlanModule<'_>],
    edges: &[EdgeRecord],
    platform: RingPlatform,
) -> Result<RingPlan, PlanError> {
    compose(modules, edges, platform.buffer_groups, true)?.rings(modules, platform)
}
