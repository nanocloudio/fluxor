//! The composer's last step, shared by every graph the tools emit: a
//! declared graph — its modules, what their manifests say of their ports,
//! and the edges between them — composed by the rules every producer links
//! (`fluxor_contracts::graph::plan`: fans, mailbox groups, rings, stepping
//! order) and encoded by the one composed-graph codec
//! (`fluxor_contracts::graph`). A boot config's graph section, each of its
//! resident workloads (`WKLD`), a workload image's graph and a workload
//! `CREATE` carry what this produces.
//!
//! The composer refuses what the kernel would refuse of the composed graph:
//! more pre-pass modules in one domain than
//! [`graph::MAX_PRE_PASS_PER_DOMAIN`], a cycle the graph does not accept, a
//! ring past the ceiling, and for a workload more modules or edges than one
//! live add admits.
//!
//! A RESIDENT WORKLOAD is a workload-owned subgraph declared in a graph YAML's
//! `workloads:` section and admitted by the kernel at boot, alongside the node
//! graph rather than inside it. Each workload gets its own owner handle, its
//! own state/buffer caps, and is scheduled as an independent resident graph.
//! Workloads are self-contained: edges between the workload's own modules
//! (`New → New`), in one domain, and lanes to the node's network (`Net`).
//! Module params are the inline TLV `schema::build_params_from_schema`
//! produces; a workload module cannot reference a `data:`-section blob.
//!
//! A workload composed here is its own authority: its header's
//! creator-authority flag is never set. That flag is honoured only from the
//! `APPLY_ADD` of a module acting with the node's authority, and refused on
//! both paths a graph composed here takes: a node graph's resident workloads
//! and a workload `CREATE`.
//!
//! Every module record carries its step budget: the YAML
//! `step_deadline_us`, `step_deadline_burst_us` and `fault_policy` (`0`
//! deadline = the node's default, `0` burst = `deadline ×
//! BURST_MULTIPLIER`). The kernel takes a module's budget from its record
//! alone, and admits a workload module's only within the node's ceiling and
//! with a policy confined to the module (see
//! `config::builder::workload_step_budget`, which refuses at build time what
//! the kernel would refuse at admission).

use fluxor_contracts::graph::plan::{
    self, Fan, FanDir, PlanError, PlanModule, PlanPort, RingNode, RingPlatform,
};
use fluxor_contracts::graph::{self, EdgeRecord, Endpoint, GraphSpec, ModuleRecord};

pub use fluxor_contracts::graph::FaultPolicy;

use crate::manifest::Manifest;

/// Whether a params TLV tag is a node tag — mirrors the kernel's
/// `scheduler::is_node_param_tag`: 0xF0–0xF7 (the restart settings 0xF2 and
/// 0xF3, the trust class (0xF4), protection level 0xF5, quarantine partner 0xF7),
/// ISR budget (0xFB), IRQ (0xFC) and device window (0xFD). Only the node's
/// own graph grants them; a node refuses a workload module whose params carry
/// one. The heap flags 0xF8–0xFA and the heap cap 0xEF act on the module's
/// own heap and are not node tags.
pub const fn is_node_param_tag(tag: u8) -> bool {
    matches!(tag, 0xF0..=0xF7 | 0xFB..=0xFD)
}

/// The first node tag in a params TLV, walked as the kernel walks it
/// (`scheduler::params_node_tag`): after the `0xFE` header when present, up
/// to the `0xFF` end marker; extended entries after the marker are not read.
pub fn params_node_tag(params: &[u8]) -> Option<u8> {
    if params.len() < 4 {
        return None;
    }
    let mut pos = if params[0] == 0xFE { 4 } else { 0 };
    while pos + 2 <= params.len() {
        let tag = params[pos];
        let len = params[pos + 1] as usize;
        pos += 2;
        if tag == 0xFF {
            break;
        }
        if pos + len > params.len() {
            break;
        }
        if is_node_param_tag(tag) {
            return Some(tag);
        }
        pos += len;
    }
    None
}

/// Burst multiplier — mirrors `kernel::step_guard::BURST_MULTIPLIER`.
const BURST_MULTIPLIER: u32 = 8;
/// Default step deadline — mirrors
/// `kernel::step_guard::DEFAULT_STEP_DEADLINE_US` (hardware figure).
const DEFAULT_STEP_DEADLINE_US: u32 = 2000;

/// A module's step budget, as its record carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct StepBudget {
    /// `step_deadline_us`; `0` = the node's default.
    pub deadline_us: u32,
    /// `step_deadline_burst_us`; `0` = `deadline × BURST_MULTIPLIER`.
    pub burst_us: u32,
    pub fault_policy: FaultPolicy,
}

impl StepBudget {
    /// Whether a deadline of either kind is declared. An undeclared budget
    /// runs on the node's defaults and is not measured against a ceiling.
    pub fn declares_deadline(&self) -> bool {
        self.deadline_us != 0 || self.burst_us != 0
    }

    /// The burst deadline the kernel runs the module under: the declared
    /// burst, else the declared (or default) deadline × `BURST_MULTIPLIER`.
    pub fn effective_burst_us(&self) -> u32 {
        if self.burst_us != 0 {
            return self.burst_us;
        }
        let d = if self.deadline_us != 0 {
            self.deadline_us
        } else {
            DEFAULT_STEP_DEADLINE_US
        };
        d.saturating_mul(BURST_MULTIPLIER)
    }
}

/// Largest graph one `apply_add` admits, fans included — mirrors
/// `kernel::exec::scheduler::live::MAX_ADD_MODULES`.
pub const MAX_ADD_MODULES: usize = 64;
/// Largest edge count one `apply_add` admits, fans' edges included — mirrors
/// `kernel::exec::scheduler::live::MAX_ADD_EDGES`.
pub const MAX_ADD_EDGES: usize = 192;

/// The ports `manifest` declares, as composition reads them.
pub fn plan_ports(manifest: &Manifest) -> Vec<PlanPort> {
    manifest
        .ports
        .iter()
        .map(|p| PlanPort {
            direction: p.direction,
            index: p.index,
            buffer_size: p.buffer_size,
            max_record: p.max_record,
            frame: plan::port_frame(p.content_type, p.flags),
        })
        .collect()
}

/// A declared module: what its record carries and what composition reads of
/// its manifest.
#[derive(Clone, Debug, Default)]
pub struct GraphModule {
    /// Its instance name, for refusals.
    pub name: String,
    /// FNV-1a of its type, the `.fmod` (or native module) it runs as.
    pub name_hash: u32,
    pub domain: u8,
    /// It runs in its domain's pre-pass (`pre_pass` in its manifest).
    pub pre_pass: bool,
    pub budget: StepBudget,
    /// Its params TLV.
    pub params: Vec<u8>,
    /// Its manifest's ports; empty for a module the node runs built in.
    pub ports: Vec<PlanPort>,
    /// It may consume from an aliased mailbox.
    pub mailbox_safe: bool,
    /// The node keeps one channel per edge on its inputs and outputs rather
    /// than a fan (the Linux network provider).
    pub multi_channel: bool,
}

impl GraphModule {
    fn plan(&self) -> PlanModule<'_> {
        PlanModule {
            ports: &self.ports,
            mailbox_safe: self.mailbox_safe,
            multi_inbound: self.multi_channel,
            multi_outbound: self.multi_channel,
            domain: self.domain,
        }
    }
}

/// A module of a composed graph: a declared module or a fan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ComposedModule {
    pub name_hash: u32,
    pub domain: u8,
    pub pre_pass: bool,
    pub budget: StepBudget,
    pub params: Vec<u8>,
}

/// A declared graph composed: its declared modules (indices `0..n`), then
/// one module per fan; every edge, the fans' joining edges after the
/// declared ones; and the stepping order.
#[derive(Clone, Debug, Default)]
pub struct Composition {
    pub modules: Vec<ComposedModule>,
    pub edges: Vec<EdgeRecord>,
    pub order: Vec<u16>,
    pub fans: Vec<Fan>,
}

impl Composition {
    /// The module records, in index order.
    pub fn records(&self) -> Vec<ModuleRecord<'_>> {
        self.modules
            .iter()
            .map(|m| ModuleRecord {
                name_hash: m.name_hash,
                domain: m.domain,
                pre_pass: m.pre_pass,
                step_deadline_us: m.budget.deadline_us,
                burst_us: m.budget.burst_us,
                fault_policy: m.budget.fault_policy,
                params: &m.params,
            })
            .collect()
    }

    /// The graph over `records` ([`Self::records`]), owned by the system: no
    /// owner, no caps, no authority flag.
    pub fn spec<'a>(&'a self, records: &'a [ModuleRecord<'a>]) -> GraphSpec<'a> {
        GraphSpec {
            creator_authority: false,
            owner_uid: [0; 16],
            state_cap: 0,
            buffer_cap: 0,
            order: &self.order,
            modules: records,
            edges: &self.edges,
        }
    }

    /// The fan module types the graph runs (`tee`, `merge`), which its
    /// image's module table must carry.
    pub fn fan_types(&self) -> Vec<&'static str> {
        fan_types(self.fans.iter().map(|f| f.dir))
    }
}

/// `tee` when `dirs` has a fan-out, `merge` when it has a fan-in.
pub fn fan_types(dirs: impl IntoIterator<Item = FanDir>) -> Vec<&'static str> {
    let (mut tee, mut merge) = (false, false);
    for d in dirs {
        match d {
            FanDir::Out => tee = true,
            FanDir::In => merge = true,
        }
    }
    let mut out = Vec::new();
    if tee {
        out.push("tee");
    }
    if merge {
        out.push("merge");
    }
    out
}

/// What a graph is composed for.
#[derive(Clone, Copy, Debug)]
pub struct Placement<'a> {
    /// The kernel's mailbox groups and domain bridging (`ring_demand::platform`).
    pub platform: RingPlatform,
    /// The graph steps its cycles' members in declaration order rather than
    /// being refused (`scheduler: accept_cycles`).
    pub accept_cycles: bool,
    /// The execution domains' names, by id, for refusals.
    pub domain_names: &'a [String],
}

/// A fan's params TLV for its scratch bytes (see [`Composer::fan_params`]).
pub type FanParams<'a> = dyn Fn(&Fan, u32) -> Result<Vec<u8>, String> + 'a;

/// What [`compose`] asks of its caller.
pub struct Composer<'a> {
    /// A refusal of the plan, said in the graph's own names.
    pub describe: &'a dyn Fn(PlanError) -> String,
    /// A fan's params TLV for `scratch` bytes of scratch: the frame kind,
    /// frames per step and scratch (`plan::fan_params`), with the heap the
    /// fan's module type derives for that scratch.
    pub fan_params: &'a FanParams<'a>,
}

/// Compose `edges` between `modules`: refuse a domain whose pre-pass is over
/// capacity, insert the fans, give record edges their mailboxes, order the
/// nodes, and size each fan's scratch to the largest ring beside it.
pub fn compose(
    modules: &[GraphModule],
    edges: &[EdgeRecord],
    placement: Placement<'_>,
    composer: &Composer<'_>,
) -> Result<Composition, String> {
    check_pre_pass(modules, placement.domain_names)?;
    let plan_modules: Vec<PlanModule<'_>> = modules.iter().map(GraphModule::plan).collect();
    let groups = placement.platform.buffer_groups;
    let mut composed = match plan::compose(&plan_modules, edges, groups, placement.accept_cycles) {
        Err(PlanError::Cycle { .. }) => {
            return Err(cycle_refusal(modules, &plan_modules, edges, groups))
        }
        r => r.map_err(composer.describe)?,
    };
    plan::record_mailboxes(&plan_modules, &mut composed.edges, groups)
        .map_err(composer.describe)?;
    let rings = composed
        .rings(&plan_modules, placement.platform)
        .map_err(composer.describe)?;
    let mut out: Vec<ComposedModule> = modules
        .iter()
        .map(|m| ComposedModule {
            name_hash: m.name_hash,
            domain: m.domain,
            pre_pass: m.pre_pass,
            budget: m.budget,
            params: m.params.clone(),
        })
        .collect();
    for fan in &composed.fans {
        let node = match fan.dir {
            FanDir::Out => RingNode::Tee {
                of: fan.of,
                port: fan.port,
            },
            FanDir::In => RingNode::Merge {
                of: fan.of,
                port: fan.port,
            },
        };
        let params = (composer.fan_params)(fan, rings.largest_adjacent(node))?;
        let r = fan.record(&params);
        out.push(ComposedModule {
            name_hash: r.name_hash,
            domain: r.domain,
            pre_pass: r.pre_pass,
            budget: StepBudget::default(),
            params,
        });
    }
    Ok(Composition {
        modules: out,
        edges: composed.edges,
        order: composed.order,
        fans: composed.fans,
    })
}

/// Refuse a domain with more pre-pass modules than its pre-pass holds,
/// naming the domain and its pre-pass modules.
fn check_pre_pass(modules: &[GraphModule], domain_names: &[String]) -> Result<(), String> {
    let mut domains: Vec<u8> = modules
        .iter()
        .filter(|m| m.pre_pass)
        .map(|m| m.domain)
        .collect();
    domains.sort_unstable();
    domains.dedup();
    for d in domains {
        let names: Vec<&str> = modules
            .iter()
            .filter(|m| m.pre_pass && m.domain == d)
            .map(|m| m.name.as_str())
            .collect();
        if names.len() <= graph::MAX_PRE_PASS_PER_DOMAIN {
            continue;
        }
        let domain = domain_names
            .get(usize::from(d))
            .map_or_else(|| format!("domain {d}"), |n| format!("domain '{n}'"));
        let over = &names[graph::MAX_PRE_PASS_PER_DOMAIN..];
        return Err(format!(
            "{domain} has {} pre_pass modules ({}), and a domain's pre-pass runs at most {} \
             (MAX_PRE_PASS_PER_DOMAIN): place {} in another `tick` domain, or use a module \
             that is not pre_pass",
            names.len(),
            names.join(", "),
            graph::MAX_PRE_PASS_PER_DOMAIN,
            over.join(", "),
        ));
    }
    Ok(())
}

/// The refusal of a graph with a cycle it does not accept, naming the nodes
/// on the cycle.
fn cycle_refusal(
    modules: &[GraphModule],
    plan_modules: &[PlanModule<'_>],
    edges: &[EdgeRecord],
    groups: usize,
) -> String {
    let members = match plan::compose(plan_modules, edges, groups, true) {
        Ok(c) => {
            let names: Vec<String> = c.order[c.order.len() - c.cycle_members..]
                .iter()
                .map(|&n| node_name(modules, &c.fans, usize::from(n)))
                .collect();
            names.join(", ")
        }
        Err(e) => format!("{e:?}"),
    };
    format!(
        "the graph has a cycle through {members}: each waits on another's edge, and the \
         kernel steps a cycle only in a graph that accepts one. Declare \
         `scheduler: {{ accept_cycles: true }}` to step its members in declaration order, \
         or break the cycle"
    )
}

/// A node's name: a declared module's, or its fan's.
fn node_name(modules: &[GraphModule], fans: &[Fan], node: usize) -> String {
    if let Some(m) = modules.get(node) {
        return m.name.clone();
    }
    match fans.get(node - modules.len()) {
        Some(f) => {
            let of = modules
                .get(usize::from(f.of))
                .map_or("?", |m| m.name.as_str());
            match f.dir {
                FanDir::Out => format!("tee({of}.out{})", f.port),
                FanDir::In if f.port & plan::PORT_KEY_CTRL != 0 => {
                    format!("merge({of}.ctrl{})", f.port & 0x0F)
                }
                FanDir::In => format!("merge({of}.in{})", f.port),
            }
        }
        None => format!("node {node}"),
    }
}

/// The kernel's lane rule (`net_keys_paired`): every net key names exactly
/// one edge into the network (from a workload module) and one out of it (to
/// a workload module); a lane joined to another lane is refused.
pub fn check_net_lanes(edges: &[EdgeRecord]) -> Result<(), String> {
    for e in edges {
        let key = match (e.from, e.to) {
            (Endpoint::Net(_), Endpoint::Net(_)) => {
                return Err(
                    "a net lane connects to a module of the workload, not to another lane".into(),
                )
            }
            (Endpoint::Net(k), _) | (_, Endpoint::Net(k)) => k,
            _ => continue,
        };
        let into = edges.iter().filter(|x| x.to == Endpoint::Net(key)).count();
        let out = edges
            .iter()
            .filter(|x| x.from == Endpoint::Net(key))
            .count();
        if into != 1 || out != 1 {
            return Err(format!(
                "net lane {key} has {into} edge(s) into it and {out} out of it; a lane is exactly one of each \
                 (a module's commands in, its events out)"
            ));
        }
    }
    Ok(())
}

/// One resident workload (a workload-owner subgraph admitted via `apply_add`).
#[derive(Clone, Debug, Default)]
pub struct Workload {
    pub owner_uid: [u8; 16],
    pub state_cap: u32,
    pub buffer_cap: u32,
    /// The workload's graph, composed.
    pub graph: Composition,
    /// Idle-safe attestation (graph YAML `idle_safe: true` on the workload): the
    /// operator asserts every module in this workload is demand-driven — it makes
    /// progress only when an event or its own periodic schedule wakes it, and
    /// never relies on being stepped to notice anything. Carried in the
    /// workload record's flags (`WorkloadRecord::idle_safe`). The scheduler ANDs the attestation across every
    /// module the owner holds and parks the whole graph when idle only if all
    /// of them attest; an UNATTESTED workload is fail-closed — never parked, only
    /// relaxed to a liveness step every `tick_max`.
    pub idle_safe: bool,
}

/// Encode one workload as the composed graph the kernel admits: owned by the
/// workload, under its caps, with its own authority.
pub fn encode_workload(workload: &Workload) -> Result<Vec<u8>, String> {
    let g = &workload.graph;
    if g.modules.len() > MAX_ADD_MODULES {
        return Err(format!(
            "workload has {} modules ({} of them fans), exceeds MAX_ADD_MODULES ({MAX_ADD_MODULES})",
            g.modules.len(),
            g.fans.len()
        ));
    }
    if g.edges.len() > MAX_ADD_EDGES {
        return Err(format!(
            "workload has {} edges ({} of them joining fans), exceeds MAX_ADD_EDGES ({MAX_ADD_EDGES})",
            g.edges.len(),
            g.fans.len()
        ));
    }
    let records = g.records();
    graph::encode(&GraphSpec {
        creator_authority: false,
        owner_uid: workload.owner_uid,
        state_cap: workload.state_cap,
        buffer_cap: workload.buffer_cap,
        ..g.spec(&records)
    })
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxor_contracts::graph::plan::{fan_params, FrameKind, FRAMES_PER_STEP_DEFAULT};
    use fluxor_contracts::graph::{MERGE_NAME_HASH, TEE_NAME_HASH};

    const PLATFORM: RingPlatform = RingPlatform {
        buffer_groups: 64,
        domain_cores: [0, 0, 0, 0],
    };

    fn module(name: &str, hash: u32) -> GraphModule {
        GraphModule {
            name: name.into(),
            name_hash: hash,
            ..GraphModule::default()
        }
    }

    fn edge(from: Endpoint, from_port: u8, to: Endpoint, to_port: u8) -> EdgeRecord {
        EdgeRecord {
            from,
            from_port,
            to,
            to_port,
            ..EdgeRecord::default()
        }
    }

    fn fan_tlv(f: &Fan, scratch: u32) -> Result<Vec<u8>, String> {
        Ok(fan_params(f.kind, FRAMES_PER_STEP_DEFAULT, scratch).to_vec())
    }

    fn describe(e: PlanError) -> String {
        format!("{e:?}")
    }

    fn composed(
        modules: &[GraphModule],
        edges: &[EdgeRecord],
        accept: bool,
    ) -> Result<Composition, String> {
        compose(
            modules,
            edges,
            Placement {
                platform: PLATFORM,
                accept_cycles: accept,
                domain_names: &[],
            },
            &Composer {
                describe: &describe,
                fan_params: &fan_tlv,
            },
        )
    }

    fn workload(modules: Vec<GraphModule>, edges: Vec<EdgeRecord>) -> Workload {
        Workload {
            owner_uid: [7u8; 16],
            state_cap: 4096,
            buffer_cap: 8192,
            graph: composed(&modules, &edges, true).expect("composes"),
            idle_safe: false,
        }
    }

    #[test]
    fn a_workload_encodes_as_a_composed_graph_it_owns() {
        let mut m = module("a", 0xAABB_CCDD);
        m.domain = 1;
        m.budget = StepBudget {
            deadline_us: 12_000,
            burst_us: 16_000,
            fault_policy: FaultPolicy::Tolerate,
        };
        m.params = vec![0xFE, 0x01];
        let b = encode_workload(&workload(vec![m], vec![])).unwrap();
        let g = graph::decode(&b).expect("the codec takes it");
        let h = g.header();
        assert_eq!(h.owner_uid, [7u8; 16]);
        assert_eq!((h.state_cap, h.buffer_cap), (4096, 8192));
        assert!(!h.creator_authority());
        assert_eq!((g.module_count(), g.edge_count()), (1, 0));
        let r = g.modules().next().unwrap();
        assert_eq!((r.name_hash, r.domain), (0xAABB_CCDD, 1));
        assert_eq!((r.step_deadline_us, r.burst_us), (12_000, 16_000));
        assert_eq!(r.fault_policy, FaultPolicy::Tolerate);
        assert_eq!(r.params, &[0xFE, 0x01]);
        assert_eq!(g.order().collect::<Vec<_>>(), [0]);
    }

    #[test]
    fn net_lane_edges_encode_as_net_endpoints() {
        let edges = vec![
            edge(Endpoint::Net(2), 0, Endpoint::New(0), 0),
            EdgeRecord {
                buffer_bytes: 4096,
                ..edge(Endpoint::New(0), 0, Endpoint::Net(2), 0)
            },
        ];
        assert!(check_net_lanes(&edges).is_ok());
        let b = encode_workload(&workload(vec![module("a", 1)], edges)).unwrap();
        let g = graph::decode(&b).unwrap();
        let e: Vec<_> = g.edges().collect();
        assert_eq!((e[0].from, e[0].to), (Endpoint::Net(2), Endpoint::New(0)));
        assert_eq!((e[1].from, e[1].to), (Endpoint::New(0), Endpoint::Net(2)));
        assert_eq!(e[1].buffer_bytes, 4096);
    }

    #[test]
    fn a_fanned_output_gets_a_tee_module_and_its_scratch() {
        // a.out0 -> b, a.out0 -> c: one tee, joined from a.
        let modules = vec![module("a", 1), module("b", 2), module("c", 3)];
        let edges = vec![
            edge(Endpoint::New(0), 0, Endpoint::New(1), 0),
            EdgeRecord {
                buffer_bytes: 32 * 1024,
                ..edge(Endpoint::New(0), 0, Endpoint::New(2), 0)
            },
        ];
        let c = composed(&modules, &edges, false).unwrap();
        assert_eq!(c.modules.len(), 4);
        assert_eq!(c.fan_types(), ["tee"]);
        let tee = &c.modules[3];
        assert_eq!(tee.name_hash, TEE_NAME_HASH);
        assert_eq!(
            tee.params,
            fan_params(FrameKind::Stream, FRAMES_PER_STEP_DEFAULT, 32 * 1024)
        );
        assert_eq!(c.edges.len(), 3);
        assert_eq!(c.edges[2].from, Endpoint::New(0));
        assert_eq!(c.edges[2].to, Endpoint::New(3));
        assert_eq!(c.order, [0, 3, 1, 2]);
    }

    #[test]
    fn a_fanned_input_gets_a_merge_module() {
        let modules = vec![module("a", 1), module("b", 2), module("c", 3)];
        let edges = vec![
            edge(Endpoint::New(0), 0, Endpoint::New(2), 0),
            edge(Endpoint::New(1), 0, Endpoint::New(2), 0),
        ];
        let c = composed(&modules, &edges, false).unwrap();
        assert_eq!(c.fan_types(), ["merge"]);
        assert_eq!(c.modules[3].name_hash, MERGE_NAME_HASH);
    }

    #[test]
    fn a_fifth_pre_pass_module_in_a_domain_is_refused_by_name() {
        let modules: Vec<GraphModule> = (0..5)
            .map(|i| GraphModule {
                pre_pass: true,
                ..module(&format!("drain{i}"), 1)
            })
            .collect();
        assert!(composed(&modules[..4], &[], false).is_ok());
        let e = compose(
            &modules,
            &[],
            Placement {
                platform: PLATFORM,
                accept_cycles: false,
                domain_names: &["fast".to_string()],
            },
            &Composer {
                describe: &describe,
                fan_params: &fan_tlv,
            },
        )
        .unwrap_err();
        assert!(e.contains("domain 'fast'") && e.contains("drain4"), "{e}");
        assert!(e.contains("pre_pass"), "{e}");
    }

    #[test]
    fn a_cycle_is_refused_unless_accepted() {
        let modules = vec![module("a", 1), module("b", 2), module("src", 3)];
        let edges = vec![
            edge(Endpoint::New(2), 0, Endpoint::New(0), 0),
            edge(Endpoint::New(0), 0, Endpoint::New(1), 0),
            edge(Endpoint::New(1), 0, Endpoint::New(0), 1),
        ];
        let e = composed(&modules, &edges, false).unwrap_err();
        assert!(e.contains("cycle through a, b"), "{e}");
        assert!(e.contains("accept_cycles"), "{e}");
        let c = composed(&modules, &edges, true).unwrap();
        assert_eq!(c.order, [2, 0, 1]);
    }

    #[test]
    fn node_tags_are_found_where_the_kernel_reads_them() {
        let tlv = |entries: &[u8], ext: &[u8]| {
            let mut b = vec![0xFE, 0x01, 0, 0];
            b.extend_from_slice(entries);
            b.extend_from_slice(&[0xFF, 0x00]);
            b.extend_from_slice(ext);
            b
        };
        // Schema params, heap flags and the heap cap only.
        assert_eq!(
            params_node_tag(&tlv(
                &[1, 1, 7, 12, 2, 0, 0, 0xF8, 1, 1, 0xEF, 4, 0, 1, 0, 0],
                &[]
            )),
            None
        );
        // Each node tag, behind an ordinary entry.
        for tag in [0xF2, 0xF3, 0xF4, 0xF5, 0xF7, 0xFB, 0xFC, 0xFD] {
            assert_eq!(params_node_tag(&tlv(&[1, 1, 0, tag, 1, 0], &[])), Some(tag));
        }
        // A wrong length still counts.
        assert_eq!(params_node_tag(&tlv(&[0xFD, 1, 0], &[])), Some(0xFD));
        // Extended entries past the end marker are not node tags, whatever
        // their tag byte (tls's credentials use [tag][0][len BE]).
        assert_eq!(params_node_tag(&tlv(&[1, 1, 0], &[0xFD, 0, 0, 1, 9])), None);
        // A node tag's value bytes are skipped, not read as tags.
        assert_eq!(params_node_tag(&tlv(&[3, 2, 0xF5, 0xFD], &[])), None);
    }

    #[test]
    fn effective_burst_follows_the_kernel_rule() {
        let none = StepBudget::default();
        assert!(!none.declares_deadline());
        assert_eq!(
            none.effective_burst_us(),
            DEFAULT_STEP_DEADLINE_US * BURST_MULTIPLIER
        );
        let d = StepBudget {
            deadline_us: 1_500,
            ..StepBudget::default()
        };
        assert_eq!(d.effective_burst_us(), 12_000);
        let b = StepBudget {
            deadline_us: 1_500,
            burst_us: 4_000,
            ..StepBudget::default()
        };
        assert_eq!(b.effective_burst_us(), 4_000);
    }

    #[test]
    fn net_lanes_are_refused_unless_paired() {
        let e = |from, to| edge(from, 0, to, 0);
        let (l, n) = (Endpoint::New, Endpoint::Net);
        // Commands in, no events out.
        let one_way = [e(l(0), n(1))];
        assert!(check_net_lanes(&one_way)
            .unwrap_err()
            .contains("net lane 1"));
        // Two command edges into one lane.
        let doubled = [e(l(0), n(1)), e(l(1), n(1)), e(n(1), l(0))];
        assert!(check_net_lanes(&doubled).is_err());
        // A lane into a lane.
        assert!(check_net_lanes(&[e(n(1), n(2))]).is_err());
        // Two lanes, each paired.
        let two = [e(l(0), n(1)), e(n(1), l(0)), e(l(1), n(2)), e(n(2), l(1))];
        assert!(check_net_lanes(&two).is_ok());
    }

    #[test]
    fn too_many_modules_rejected() {
        let modules: Vec<GraphModule> = (0..=MAX_ADD_MODULES).map(|_| module("m", 0)).collect();
        let e = encode_workload(&workload(modules, vec![])).unwrap_err();
        assert!(e.contains("exceeds MAX_ADD_MODULES"), "{e}");
    }
}
