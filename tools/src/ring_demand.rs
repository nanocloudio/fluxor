//! A graph's channel rings against the target's buffer arena, at build.
//!
//! Every edge is a channel and every channel's ring comes from the kernel's
//! buffer arena. The kernel refuses arena exhaustion as a channel opens —
//! correct, but late: it presents at boot as `[buf] arena full` and a graph
//! that never starts. This adds the rings up from the compiled config, by the
//! rule the kernel opens them by (`fluxor_contracts::graph::plan`), and refuses an image whose
//! rings do not fit, naming the edges that take the most.
//!
//! The sum is over what graph preparation opens: every edge's ring at the
//! largest of its producer port's capacity, its consumer port's and its
//! `buffer_bytes` (the default ring where none sizes it), the edges of the
//! tees and merges the composer put on fanned ports, mailbox groups aliased
//! onto one ring, and on bcm2712 the consumer-side ring of every edge
//! crossing domains. The config is the compiled one, so platform-injected
//! modules, the fans and the composer's mailbox groups are in it. The limit is the kernel profile's
//! arena, or the graph's `capacity: { buffer_arena }` envelope — its size on
//! RP, which places the arena per graph, and a lower figure only elsewhere,
//! where the arena is fixed. The rings are also counted against the channel
//! table the kernel's boot plan sizes: the graph's edges and fans plus the
//! `channels` reserve (`capacity::plan_pool`). Workload subgraphs a node
//! admits later, and channels modules open for themselves, draw on the same
//! arena and are not part of the sum.

use std::collections::HashMap;

use fluxor_contracts::graph::plan::{
    self as rings, Fan, FanDir, FrameKind, PlanError, PlanModule, PlanPort, RingNode, RingPlatform,
};
use fluxor_contracts::graph::{
    ComposedGraph, EdgeClass, EdgeRecord, Endpoint, MERGE_NAME_HASH, TEE_NAME_HASH,
};
use fluxor_contracts::ring_size;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::hash::fnv1a_hash;
use crate::manifest::Manifest;
use crate::target::TargetDescriptor;

/// How many of the largest rings the table lists.
const TABLE_ROWS: usize = 10;

/// How many of the largest rings a refusal names.
const REFUSAL_EDGES: usize = 5;

/// What the loader will hold for one module type, keyed by its name hash:
/// its manifest's ports, and whether it consumes from an aliased mailbox.
/// A module type absent here is one the kernel runs built in, which the
/// loader holds no manifest for.
pub struct ModuleFacts<'a> {
    pub manifest: &'a Manifest,
    pub mailbox_safe: bool,
}

/// The buffer arena of the kernel `target` runs, in bytes, where it is known.
pub fn buffer_arena_bytes(target: &TargetDescriptor) -> Option<u64> {
    crate::capacity::kernel_buffer_arena(target.runtime())
        .or_else(|| target.buffer_arena_kb.map(|kb| kb as u64 * 1024))
}

/// What the platform `target` runs adds to graph preparation.
pub fn platform(target: &TargetDescriptor) -> RingPlatform {
    platform_of(target.runtime())
}

/// What the kernel of `runtime` adds to graph preparation: its mailbox
/// groups, and whether it bridges domains.
pub fn platform_of(runtime: &str) -> RingPlatform {
    RingPlatform {
        buffer_groups: ring_size::buffer_groups(crate::capacity::kernel_max_edges(runtime)),
        split_cross_domain: crate::capacity::kernel_bridges_domains(runtime),
    }
}

/// The module types a platform keeps one channel per edge for, in and out,
/// by name hash: the hosted network provider on the Linux runtime, which
/// drains one inbound lane per wired edge and keeps one events channel per
/// consumer that is also its producer.
pub fn multi_channel(runtime: &str, name_hash: u32) -> bool {
    runtime == "linux" && name_hash == fnv1a_hash(b"linux_net")
}

/// A refusal of the plan, said in the graph's names: `names` are the
/// declared modules' instance names by index, `manifests` their manifests
/// by name (for port names), `runtime` the kernel the graph is for.
pub fn refusal(
    e: PlanError,
    names: &[String],
    manifests: &HashMap<String, Manifest>,
    runtime: &str,
) -> String {
    let namer = Namer { names, manifests };
    match e {
        PlanError::OverCeiling { ends, request } => format!(
            "{} asks for a {request} B ring, over the {} B ceiling of one channel: lower \
             the request or split the stream",
            namer.edge(&ends),
            ring_size::MAX_RING_BYTES
        ),
        PlanError::RecordOverRing {
            ends,
            max_record,
            granted,
        } => format!(
            "{}: its producer writes records of up to {max_record} B ({} B of ring with \
             their length prefix) but the ring is {granted} B, so a record that size could \
             never be written; raise the edge's buffer_bytes or the port's buffer_size",
            namer.edge(&ends),
            ring_size::record_bytes(max_record)
        ),
        PlanError::GroupsExhausted => format!(
            "the graph's record edges and fans need more mailbox groups than the {runtime} \
             kernel has"
        ),
        PlanError::FanWidth {
            dir,
            of,
            port,
            edges,
        } => {
            let (node, direction) = match dir {
                FanDir::Out => (RingNode::Module(of), rings::DIR_OUT),
                FanDir::In if port & rings::PORT_KEY_CTRL != 0 => {
                    (RingNode::Module(of), rings::DIR_CTRL)
                }
                FanDir::In => (RingNode::Module(of), rings::DIR_IN),
            };
            format!(
                "{} is wired to {edges} ports, and the fan that joins them has {}: \
                 fan the port in stages through a module of its own, or wire fewer",
                namer.end(node, port & 0x0F, direction),
                usize::from(fluxor_contracts::graph::MAX_PORT_INDEX) + 1
            )
        }
        PlanError::UnknownModule { edge } => format!("edge {edge} names no module"),
        PlanError::EdgeCapacity
        | PlanError::FanCapacity
        | PlanError::OrderCapacity
        | PlanError::Cycle { .. } => format!("the graph does not compose: {e:?}"),
    }
}

/// The figure a pool is held to: the kernel's own, or the graph's capacity
/// envelope. Where the kernel places its arenas per graph (RP) the entry is
/// the arena's size, larger or smaller; elsewhere the arena is fixed and an
/// entry only lowers what an allocation is admitted against.
struct Limit {
    value: u64,
    /// Whether the envelope set it.
    envelope: bool,
}

fn limit(config: &Value, pool: &str, kernel: u64, runtime: &str) -> Limit {
    match config
        .get("capacity")
        .and_then(|c| c.get(pool))
        .and_then(|v| v.as_u64())
    {
        Some(n) if n < kernel || crate::capacity::kernel_places_arenas(runtime) => Limit {
            value: n,
            envelope: true,
        },
        _ => Limit {
            value: kernel,
            envelope: false,
        },
    }
}

/// A declared module of the composed graph, as the ring plan sees it.
struct ModuleSpec {
    ports: Vec<PlanPort>,
    mailbox_safe: bool,
    domain: u8,
}

/// The composed graph's rings as `rings::rings` sees them: its declared
/// modules, its fans, and every edge, the fans' joining edges last.
struct Graph {
    names: Vec<String>,
    modules: Vec<ModuleSpec>,
    fans: Vec<Fan>,
    edges: Vec<EdgeRecord>,
    declared_edges: usize,
}

impl Graph {
    fn plan(&self, platform: RingPlatform) -> std::result::Result<rings::RingPlan, PlanError> {
        let modules: Vec<PlanModule<'_>> = self
            .modules
            .iter()
            .map(|m| PlanModule {
                ports: &m.ports,
                mailbox_safe: m.mailbox_safe,
                domain: m.domain,
                ..PlanModule::default()
            })
            .collect();
        let mut plan = rings::RingPlan::default();
        let totals = rings::rings(
            &modules,
            &self.fans,
            &self.edges,
            self.declared_edges,
            platform,
            |r| plan.rings.push(r),
        )?;
        plan.aliased = totals.aliased;
        Ok(plan)
    }
}

/// The frame kind a fan's params name (tag 1), a stream where they name
/// none.
fn fan_kind(params: &[u8]) -> FrameKind {
    let mut kind = FrameKind::Stream;
    fluxor_contracts::params_tlv::walk_declared(params, |tag, value| {
        if tag == rings::fan_param::FRAME_KIND {
            kind = match value.first() {
                Some(1) => FrameKind::Eth,
                Some(2) => FrameKind::Net,
                Some(3) => FrameKind::Telemetry,
                Some(4) => FrameKind::Record,
                _ => FrameKind::Stream,
            };
        }
    });
    kind
}

/// The graph `composed` (a compiled config's graph section) holds, with
/// each declared module's facts. Its declared modules are those before its
/// fans: the composer appends one `tee` or `merge` module per fan, and one
/// joining edge per fan after the declared edges.
fn decode(
    config: &Value,
    composed: &ComposedGraph<'_>,
    facts: &HashMap<u32, ModuleFacts<'_>>,
) -> Result<Graph> {
    let records: Vec<_> = composed.modules().collect();
    let is_fan = |h: u32| h == TEE_NAME_HASH || h == MERGE_NAME_HASH;
    let declared = records
        .iter()
        .rposition(|m| !is_fan(m.name_hash))
        .map_or(0, |i| i + 1);
    let decl: Vec<&Value> = config
        .get("modules")
        .and_then(|m| m.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let mut names = Vec::with_capacity(declared);
    let mut modules = Vec::with_capacity(declared);
    for (i, record) in records[..declared].iter().enumerate() {
        let name = decl
            .get(i)
            .and_then(|d| d.get("name").and_then(|n| n.as_str()))
            .map(String::from)
            .unwrap_or_else(|| format!("module{i}"));
        let fact = facts.get(&record.name_hash);
        modules.push(ModuleSpec {
            ports: fact
                .map(|f| crate::add_subgraph::plan_ports(f.manifest))
                .unwrap_or_default(),
            mailbox_safe: fact.is_some_and(|f| f.mailbox_safe),
            domain: record.domain,
        });
        names.push(name);
    }
    let edges: Vec<EdgeRecord> = composed.edges().collect();
    let mut fans = Vec::with_capacity(records.len() - declared);
    for (k, record) in records[declared..].iter().enumerate() {
        let node = Endpoint::New((declared + k) as u16);
        let (dir, join) = if record.name_hash == TEE_NAME_HASH {
            (FanDir::Out, edges.iter().find(|e| e.to == node))
        } else {
            (FanDir::In, edges.iter().find(|e| e.from == node))
        };
        let joined = |e: &EdgeRecord| match dir {
            FanDir::Out => e.from.new_index().map(|of| (of, e.from_port)),
            FanDir::In => e.to.new_index().map(|of| {
                let ctrl = if e.to_ctrl { rings::PORT_KEY_CTRL } else { 0 };
                (of, e.to_port | ctrl)
            }),
        };
        let Some((of, port)) = join.and_then(joined).filter(|&(of, _)| of < declared) else {
            return Err(Error::Config(format!(
                "compiled fan {} joins no declared module",
                declared + k
            )));
        };
        fans.push(Fan {
            dir,
            of: of as u16,
            port,
            kind: fan_kind(record.params),
            domain: record.domain,
        });
    }
    let declared_edges = edges.len().saturating_sub(fans.len());
    Ok(Graph {
        names,
        modules,
        fans,
        edges,
        declared_edges,
    })
}

/// What sized a ring: its producer port's capacity, its consumer port's, the
/// edge's `buffer_bytes`, the request they make and the ring granted — what
/// to look at when a port over-declares.
fn asks(r: &rings::Ring) -> String {
    match r.ends.role {
        rings::RingRole::CrossDomain => format!("cross-domain consumer ring {}", r.ring),
        _ => format!(
            "producer {}, consumer {}, buffer_bytes {}: asks {}, ring {}",
            r.producer_cap, r.consumer_cap, r.buffer_bytes, r.request, r.ring
        ),
    }
}

/// Names a ring's ends by module and port, as the wiring does.
struct Namer<'a> {
    names: &'a [String],
    manifests: &'a HashMap<String, Manifest>,
}

impl Namer<'_> {
    fn port(&self, module: usize, direction: u8, index: u8) -> String {
        let name = &self.names[module];
        self.manifests
            .get(name)
            .and_then(|m| m.find_port_spec(direction, index))
            .and_then(|p| p.name.clone())
            .unwrap_or_else(|| {
                let dir = match direction {
                    rings::DIR_OUT => "out",
                    rings::DIR_CTRL => "ctrl",
                    _ => "in",
                };
                format!("{dir}{index}")
            })
    }

    fn end(&self, node: RingNode, port: u8, direction: u8) -> String {
        match node {
            RingNode::Module(m) => {
                let m = usize::from(m);
                format!("{}.{}", self.names[m], self.port(m, direction, port))
            }
            RingNode::Tee { of, port: p } => {
                let of = usize::from(of);
                format!(
                    "tee({}.{})",
                    self.names[of],
                    self.port(of, rings::DIR_OUT, p)
                )
            }
            RingNode::Merge { of, port: p } => {
                let of = usize::from(of);
                let dir = if p & rings::PORT_KEY_CTRL != 0 {
                    rings::DIR_CTRL
                } else {
                    rings::DIR_IN
                };
                format!("merge({}.{})", self.names[of], self.port(of, dir, p & 0x0F))
            }
            RingNode::External(end) => format!("{end:?}"),
        }
    }

    fn edge(&self, ends: &rings::RingEnds) -> String {
        let to_dir = if ends.ctrl {
            rings::DIR_CTRL
        } else {
            rings::DIR_IN
        };
        let label = format!(
            "{} -> {}",
            self.end(ends.from, ends.from_port, rings::DIR_OUT),
            self.end(ends.to, ends.to_port, to_dir)
        );
        match ends.role {
            rings::RingRole::CrossDomain => format!("{label} (cross-domain)"),
            _ => label,
        }
    }
}

/// Add up a compiled graph's rings and refuse it when they are over the
/// target's buffer arena or its channel slots. `config` is the expanded graph
/// the blob was built from, `facts` what the loader holds per module type,
/// and `manifests` the source manifests by instance name, for port names. A
/// target whose kernel arena is not known here (no graph-running kernel
/// profile) is not checked.
pub fn check(
    config: &Value,
    blob: &[u8],
    facts: &HashMap<u32, ModuleFacts<'_>>,
    manifests: &HashMap<String, Manifest>,
    target: &TargetDescriptor,
) -> Result<()> {
    let Some(arena) = buffer_arena_bytes(target) else {
        return Ok(());
    };
    let cfg = fluxor_contracts::boot_config::decode(blob)
        .map_err(|e| Error::Config(format!("boot config refused: {e}")))?;
    check_composed(
        config,
        &cfg.graph().composed(),
        facts,
        manifests,
        target,
        arena,
    )
}

fn check_composed(
    config: &Value,
    composed: &ComposedGraph<'_>,
    facts: &HashMap<u32, ModuleFacts<'_>>,
    manifests: &HashMap<String, Manifest>,
    target: &TargetDescriptor,
    kernel_arena: u64,
) -> Result<()> {
    let graph = decode(config, composed, facts)?;
    if graph.edges.is_empty() {
        return Ok(());
    }
    let namer = Namer {
        names: &graph.names,
        manifests,
    };
    let plan = graph
        .plan(platform(target))
        .map_err(|e| Error::Config(refusal(e, &graph.names, manifests, target.runtime())))?;
    let total = plan.total();
    let arena = limit(config, "buffer_arena", kernel_arena, target.runtime());
    // Every ring takes a slot of the channel table, which the kernel sizes to
    // its boot plan: the graph's edges, its fans' modules and edges (and on
    // bcm2712 the consumer side of each cross-domain edge) plus the
    // `channels` reserve (the envelope's entry, else the profile's default).
    // Resident workloads add their own share to the plan and are not in this
    // sum.
    let compiled: Vec<(u16, u16, u8, u8, u8)> = graph
        .edges
        .iter()
        .map(|e| {
            let node = |end: Endpoint| end.new_index().map_or(u16::MAX, |i| i as u16);
            (
                node(e.from),
                node(e.to),
                u8::from(e.to_ctrl),
                e.from_port,
                e.to_port,
            )
        })
        .collect();
    let domain = |end: Endpoint| {
        let i = end.new_index()?;
        graph
            .modules
            .get(i)
            .map(|m| m.domain)
            .or_else(|| graph.fans.get(i - graph.modules.len()).map(|f| f.domain))
    };
    let shape = crate::capacity::GraphShape {
        modules: (graph.modules.len() + graph.fans.len()) as u64,
        edges: compiled.len() as u64,
        fans: crate::capacity::fan_count(&compiled),
        crossings: crate::capacity::crossing_count(graph.edges.iter().map(|e| {
            (
                domain(e.from),
                domain(e.to),
                e.class == EdgeClass::CrossCore,
            )
        })),
        ..Default::default()
    };
    let entries: Vec<(String, u64)> = config
        .get("capacity")
        .and_then(|c| c.get("channels"))
        .and_then(Value::as_u64)
        .map(|n| ("channels".to_string(), n))
        .into_iter()
        .collect();
    let channel_plan =
        crate::capacity::plan_pool(target.runtime(), "channels", &shape, &[], &entries);
    let slots = Limit {
        value: channel_plan.ceiling(),
        envelope: channel_plan.from_envelope,
    };
    let by = |l: &Limit| {
        if l.envelope {
            " (its capacity envelope)"
        } else {
            ""
        }
    };

    let mut rows: Vec<&rings::Ring> = plan.rings.iter().collect();
    rows.sort_by(|a, b| b.arena.cmp(&a.arena));
    println!(
        "Buffer arena ({}{}): {} B, {} ring(s) for {} edge(s)",
        target.id,
        if arena.envelope {
            ", capacity envelope"
        } else {
            ""
        },
        arena.value,
        plan.rings.len(),
        graph.edges.len()
    );
    for r in rows.iter().take(TABLE_ROWS) {
        println!("  {:>9}  {}  [{}]", r.arena, namer.edge(&r.ends), asks(r));
    }
    if rows.len() > TABLE_ROWS {
        let rest: u64 = rows[TABLE_ROWS..].iter().map(|r| r.arena).sum();
        println!("  {rest:>9}  ({} more ring(s))", rows.len() - TABLE_ROWS);
    }
    if plan.rings.len() as u64 > slots.value {
        return Err(Error::Config(format!(
            "graph preparation opens {} channel(s) but {}'s kernel sizes its channel table to {} \
             (derived {} + reserve {}{}): every ring is a channel slot, the edges joining \
             fanned ports to their tees and merges and the consumer side of a cross-domain \
             edge included — over by {}. Raise `capacity: {{ channels }}`, fan \
             fewer ports, or split the graph.",
            plan.rings.len(),
            target.id,
            slots.value,
            channel_plan.derived,
            channel_plan.reserve,
            by(&slots),
            plan.rings.len() as u64 - slots.value
        )));
    }
    if total > arena.value {
        println!("  {total:>9}  total, OVER by {}", total - arena.value);
        let largest: Vec<String> = rows
            .iter()
            .take(REFUSAL_EDGES)
            .map(|r| format!("{} ({} B: {})", namer.edge(&r.ends), r.arena, asks(r)))
            .collect();
        return Err(Error::Config(format!(
            "graph's channel rings need {total} B but {}'s buffer arena is {} B{} — over by \
             {} B. The largest: {}. Size each ring to the records its edge carries (the \
             port's buffer_size, the edge's buffer_bytes), or drop modules from the graph.",
            target.id,
            arena.value,
            by(&arena),
            total - arena.value,
            largest.join(", ")
        )));
    }
    println!(
        "  {total:>9}  total, {}% of {}, slack {}",
        total * 100 / arena.value,
        arena.value,
        arena.value - total
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::PortSpec;
    use fluxor_contracts::graph::{GraphSpec, ModuleRecord};

    fn port(direction: u8, index: u8, buffer_size: u32) -> PortSpec {
        PortSpec {
            direction,
            content_type: 0,
            flags: 0,
            name: Some(format!("p{direction}_{index}")),
            index,
            buffer_size,
            max_record: 0,
            rate_class_max: None,
            rate_class_default: None,
            requires_capability: None,
            contract: None,
            serves: None,
            contract_optional: false,
            facts: Default::default(),
            gates_readiness: true,
            accepts_record: 0,
            retains_send: false,
            datagram_only: false,
            send_buffer_param: None,
            send_pool_param: None,
            send_pool_lanes_param: None,
        }
    }

    fn root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("repo root")
            .to_path_buf()
    }

    fn linux() -> TargetDescriptor {
        crate::target::load_target("linux", &root()).expect("linux target")
    }

    /// `n` producer→consumer pairs, each edge asking for `ring` bytes
    /// through its producer's port: the expanded graph, its composed graph's
    /// bytes, and the two module types' manifests.
    fn graph(n: usize, ring: u32) -> (Value, Vec<u8>, Manifest, Manifest) {
        graph_in(n, ring, |_| 0)
    }

    /// [`graph`], each module in the domain `domain` gives its index.
    fn graph_in(
        n: usize,
        ring: u32,
        domain: impl Fn(usize) -> u8,
    ) -> (Value, Vec<u8>, Manifest, Manifest) {
        let mut modules = Vec::new();
        let mut records = Vec::new();
        let mut edges = Vec::new();
        for i in 0..n {
            modules.push(serde_json::json!({"name": format!("src{i}"), "type": "ring_src"}));
            modules.push(serde_json::json!({"name": format!("dst{i}"), "type": "ring_dst"}));
            for (k, ty) in [(2 * i, "ring_src"), (2 * i + 1, "ring_dst")] {
                records.push(ModuleRecord {
                    name_hash: fnv1a_hash(ty.as_bytes()),
                    domain: domain(k),
                    ..ModuleRecord::default()
                });
            }
            edges.push(EdgeRecord {
                from: Endpoint::New(2 * i as u16),
                to: Endpoint::New(2 * i as u16 + 1),
                ..EdgeRecord::default()
            });
        }
        let order: Vec<u16> = (0..records.len() as u16).collect();
        let blob = fluxor_contracts::graph::encode(&GraphSpec {
            order: &order,
            modules: &records,
            edges: &edges,
            ..GraphSpec::default()
        })
        .unwrap();
        let config = serde_json::json!({ "modules": modules });
        let src = Manifest {
            ports: vec![port(rings::DIR_OUT, 0, ring)],
            ..Default::default()
        };
        let dst = Manifest {
            ports: vec![port(rings::DIR_IN, 0, 0)],
            ..Default::default()
        };
        (config, blob, src, dst)
    }

    fn facts<'a>(src: &'a Manifest, dst: &'a Manifest) -> HashMap<u32, ModuleFacts<'a>> {
        HashMap::from([
            (
                fnv1a_hash(b"ring_src"),
                ModuleFacts {
                    manifest: src,
                    mailbox_safe: false,
                },
            ),
            (
                fnv1a_hash(b"ring_dst"),
                ModuleFacts {
                    manifest: dst,
                    mailbox_safe: false,
                },
            ),
        ])
    }

    fn run(
        config: &Value,
        blob: &[u8],
        facts: &HashMap<u32, ModuleFacts<'_>>,
        manifests: &HashMap<String, Manifest>,
    ) -> Result<()> {
        let target = linux();
        let arena = buffer_arena_bytes(&target).unwrap();
        let composed = fluxor_contracts::graph::decode(blob).unwrap();
        check_composed(config, &composed, facts, manifests, &target, arena)
    }

    #[test]
    fn a_graph_under_the_arena_passes() {
        // Eight 1 MiB rings: half the host arena.
        let (config, blob, src, dst) = graph(8, 1 << 20);
        run(&config, &blob, &facts(&src, &dst), &HashMap::new()).unwrap();
    }

    #[test]
    fn a_graph_over_the_arena_is_refused_naming_its_largest_edges() {
        // Seventeen rings that each round up to 1 MiB: one over the host's
        // 16 MiB.
        let (config, blob, src, dst) = graph(17, (1 << 20) - 100);
        let e = run(&config, &blob, &facts(&src, &dst), &HashMap::new())
            .unwrap_err()
            .to_string();
        assert!(e.contains("need 17825792 B"), "{e}");
        assert!(e.contains("over by 1048576 B"), "{e}");
        assert!(
            e.contains(
                "src0.out0 -> dst0.in0 (1048576 B: producer 1048476, consumer 0, buffer_bytes 0: \
                 asks 1048476, ring 1048576)"
            ),
            "{e}"
        );
    }

    #[test]
    fn port_names_come_from_the_source_manifests() {
        let (config, blob, src, dst) = graph(17, 1 << 20);
        let manifests = HashMap::from([
            ("src0".to_string(), src.clone()),
            ("dst0".to_string(), dst.clone()),
        ]);
        let e = run(&config, &blob, &facts(&src, &dst), &manifests)
            .unwrap_err()
            .to_string();
        assert!(e.contains("src0.p1_0 -> dst0.p0_0"), "{e}");
    }

    #[test]
    fn a_built_in_module_s_ports_are_unsized() {
        // No facts for either type: the kernel holds no manifest for a
        // built-in, so every edge takes the default ring.
        let (config, blob, _, _) = graph(3, 1 << 20);
        let composed = fluxor_contracts::graph::decode(&blob).unwrap();
        let graph = decode(&config, &composed, &HashMap::new()).unwrap();
        let plan = graph.plan(platform(&linux())).unwrap();
        assert_eq!(plan.total(), 3 * ring_size::DEFAULT_RING_BYTES as u64);
    }

    #[test]
    fn a_capacity_envelope_below_the_kernel_arena_is_the_limit() {
        // Eight 1 MiB rings fit the host's 16 MiB, not a 4 MiB envelope.
        let (mut config, blob, src, dst) = graph(8, 1 << 20);
        config["capacity"] = serde_json::json!({"buffer_arena": 4 << 20});
        let e = run(&config, &blob, &facts(&src, &dst), &HashMap::new())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("buffer arena is 4194304 B (its capacity envelope) — over by 4194304 B"),
            "{e}"
        );
        // Linux's arena is a fixed array: an envelope above it raises nothing,
        // and the arena itself binds.
        config["capacity"] = serde_json::json!({"buffer_arena": 1u64 << 40});
        run(&config, &blob, &facts(&src, &dst), &HashMap::new()).unwrap();
    }

    /// A `channels:` envelope entry is a live-add reserve on top of what the
    /// graph derives, never a lower ceiling: Linux sizes its channel table to
    /// the graph's edges and fans plus the reserve, so a zero reserve still
    /// seats every ring this graph opens.
    #[test]
    fn a_channels_reserve_is_not_a_ceiling() {
        let (mut config, blob, src, dst) = graph(3, 1024);
        config["capacity"] = serde_json::json!({"channels": 0});
        run(&config, &blob, &facts(&src, &dst), &HashMap::new()).unwrap();
    }

    /// On bcm2712 an edge between domains opens a consumer-side channel of
    /// its own, which the boot plan derives (`cross_domain_edges`): three
    /// crossing edges plan six channels before any reserve, so even a zero
    /// `channels` reserve seats every ring.
    #[test]
    fn cross_domain_rings_are_derived_on_bcm2712() {
        let (mut config, blob, src, dst) = graph_in(3, 1024, |k| (k % 2) as u8);
        let composed = fluxor_contracts::graph::decode(&blob).unwrap();
        let pi5 = crate::target::load_target("pi5", &root()).expect("pi5 target");
        let arena = buffer_arena_bytes(&pi5).unwrap();
        let check = |config: &Value| {
            check_composed(
                config,
                &composed,
                &facts(&src, &dst),
                &HashMap::new(),
                &pi5,
                arena,
            )
        };
        check(&config).expect("the default reserve");
        config["capacity"] = serde_json::json!({"channels": 0});
        check(&config).expect("the crossings are derived, not reserved");
        let shape = crate::capacity::GraphShape {
            modules: 6,
            edges: 3,
            crossings: 3,
            ..Default::default()
        };
        let entries = vec![("channels".to_string(), 0)];
        let plan = crate::capacity::plan_pool("pi5", "channels", &shape, &[], &entries);
        assert_eq!(plan.ceiling(), 6);
        let linux = crate::capacity::plan_pool("linux", "channels", &shape, &[], &entries);
        assert_eq!(linux.ceiling(), 3, "Linux bridges no domains");
    }

    /// RP places its buffer arena per graph at the plan's figure, so an entry
    /// above the silicon default is the arena's size there, where on Linux it
    /// raises nothing.
    #[test]
    fn an_rp_buffer_arena_entry_is_its_size() {
        let (mut config, blob, src, dst) = graph(1, 128 * 1024);
        let composed = fluxor_contracts::graph::decode(&blob).unwrap();
        let pico2w = crate::target::load_target("pico2w", &root()).expect("pico2w target");
        let arena = buffer_arena_bytes(&pico2w).unwrap();
        let check = |config: &Value| {
            check_composed(
                config,
                &composed,
                &facts(&src, &dst),
                &HashMap::new(),
                &pico2w,
                arena,
            )
        };
        let e = check(&config).unwrap_err().to_string();
        assert!(e.contains("buffer arena is 65536 B"), "{e}");
        config["capacity"] = serde_json::json!({"buffer_arena": 256 * 1024});
        check(&config).expect("the entry places a 256 KiB arena");
    }

    #[test]
    fn the_hosted_network_provider_keeps_a_channel_per_edge_on_linux_only() {
        // `linux_net` (1) feeds two consumers (2, 3) that both feed it back:
        // composed for Linux it keeps an edge each, with no tee or merge.
        let hash = fnv1a_hash(b"linux_net");
        let edge = |f: u16, t: u16| EdgeRecord {
            from: Endpoint::New(f),
            to: Endpoint::New(t),
            ..EdgeRecord::default()
        };
        let edges = [edge(1, 2), edge(1, 3), edge(2, 1), edge(3, 1)];
        // The expanded graph names no types: the hash alone decides.
        let config = serde_json::json!({ "modules": [] });
        let rings_on = |runtime: &str, target: &TargetDescriptor| {
            let modules: Vec<crate::add_subgraph::GraphModule> = (0..4u32)
                .map(|i| {
                    let h = if i == 1 { hash } else { 0x1000 + i };
                    crate::add_subgraph::GraphModule {
                        name: format!("m{i}"),
                        name_hash: h,
                        multi_channel: multi_channel(runtime, h),
                        ..Default::default()
                    }
                })
                .collect();
            let composition = crate::add_subgraph::compose(
                &modules,
                &edges,
                crate::add_subgraph::Placement {
                    platform: platform(target),
                    accept_cycles: true,
                    domain_names: &[],
                },
                &crate::add_subgraph::Composer {
                    describe: &|e| format!("{e:?}"),
                    fan_params: &|f, scratch| {
                        Ok(
                            rings::fan_params(f.kind, rings::FRAMES_PER_STEP_DEFAULT, scratch)
                                .to_vec(),
                        )
                    },
                },
            )
            .unwrap();
            let records = composition.records();
            let blob = fluxor_contracts::graph::encode(&composition.spec(&records)).unwrap();
            let composed = fluxor_contracts::graph::decode(&blob).unwrap();
            let graph = decode(&config, &composed, &HashMap::new()).unwrap();
            (
                graph.fans.len(),
                graph.plan(platform(target)).unwrap().rings.len(),
            )
        };
        let pi5 = crate::target::load_target("pi5", &root()).unwrap();
        assert_eq!(rings_on("linux", &linux()), (0, 4));
        // Elsewhere: a tee and a merge, each with its joining edge.
        assert_eq!(rings_on("bcm2712", &pi5), (2, 6));
    }

    #[test]
    fn the_rp_arenas_come_from_the_silicon() {
        let rp2040 = crate::target::load_target("rp2040", &root()).unwrap();
        let pico2w = crate::target::load_target("pico2w", &root()).unwrap();
        assert_eq!(buffer_arena_bytes(&rp2040), Some(16 * 1024));
        assert_eq!(buffer_arena_bytes(&pico2w), Some(64 * 1024));
        assert_eq!(
            buffer_arena_bytes(&linux()),
            crate::capacity::kernel_buffer_arena("linux")
        );
    }
}
