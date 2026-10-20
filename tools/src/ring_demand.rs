//! A graph's channel rings against the target's buffer arena, at build.
//!
//! Every edge is a channel and every channel's ring comes from the kernel's
//! buffer arena. The kernel refuses arena exhaustion as a channel opens —
//! correct, but late: it presents at boot as `[buf] arena full` and a graph
//! that never starts. This adds the rings up from the compiled config, by the
//! rule the kernel opens them by (`ring_plan`), and refuses an image whose
//! rings do not fit, naming the edges that take the most.
//!
//! The sum is over what graph preparation opens: every edge's ring at the
//! largest of its producer port's capacity, its consumer port's and its
//! `buffer_bytes` (the default ring where none sizes it), the tees and merges
//! the kernel inserts on fanned ports, mailbox groups aliased onto one ring,
//! and on bcm2712 the consumer-side ring of every edge crossing domains. The
//! config is the compiled one, so platform-injected modules and the
//! composer's mailbox groups are in it. The limit is the kernel profile's
//! arena, or the graph's `capacity: { buffer_arena }` envelope where that is
//! lower, and the rings are also counted against the channel slots
//! (`MAX_CHANNELS`, or `capacity: { channels }`). Workload subgraphs a node
//! admits later, and channels modules open for themselves, draw on the same
//! arena and are not part of the sum.

use std::collections::HashMap;

use crate::ring_plan::{self as rings, RingEdge, RingError, RingModule, RingNode, RingPlatform};
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
    RingPlatform {
        buffer_groups: rings::buffer_groups(crate::capacity::kernel_max_edges(target.runtime())),
        split_cross_domain: target.runtime() == "bcm2712",
    }
}

/// The module types a platform keeps one channel per edge for, in and out,
/// by the name hash the kernel registers them under: the hosted network
/// provider on the Linux runtime (`register_multi_inbound` and
/// `register_multi_outbound` of `LINUX_NET_HASH`).
fn multi_channel(runtime: &str, name_hash: u32) -> bool {
    runtime == "linux" && name_hash == fnv1a_hash(b"linux_net")
}

/// The figure a pool is held to: the kernel's own, or the graph's capacity
/// envelope where that is lower (the kernel enforces the envelope as it
/// allocates).
struct Limit {
    value: u64,
    /// Whether the envelope set it.
    envelope: bool,
}

fn limit(config: &Value, pool: &str, kernel: u64) -> Limit {
    match config
        .get("capacity")
        .and_then(|c| c.get(pool))
        .and_then(|v| v.as_u64())
    {
        Some(n) if n < kernel => Limit {
            value: n,
            envelope: true,
        },
        _ => Limit {
            value: kernel,
            envelope: false,
        },
    }
}

/// The graph's rings as `rings::plan` sees them, from a compiled config.
struct Graph {
    names: Vec<String>,
    modules: Vec<RingModule>,
    edges: Vec<RingEdge>,
}

/// The graph `decoded` (a compiled config, as `config::decode_config` reads
/// it) holds, with each module's facts.
fn decode(
    config: &Value,
    decoded: &Value,
    facts: &HashMap<u32, ModuleFacts<'_>>,
    runtime: &str,
) -> Result<Graph> {
    let declared: Vec<&Value> = config
        .get("modules")
        .and_then(|m| m.as_array())
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let entries = decoded["modules"].as_array().cloned().unwrap_or_default();
    let mut names = Vec::with_capacity(entries.len());
    let mut modules = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let decl = declared.get(i);
        let name = decl
            .and_then(|d| d.get("name").and_then(|n| n.as_str()))
            .map(String::from)
            .unwrap_or_else(|| format!("module{i}"));
        let type_name = decl
            .and_then(|d| d.get("type").and_then(|t| t.as_str()))
            .unwrap_or(&name)
            .to_string();
        let hash = entry["name_hash"]
            .as_str()
            .and_then(|h| u32::from_str_radix(h.trim_start_matches("0x"), 16).ok())
            .unwrap_or_else(|| fnv1a_hash(type_name.as_bytes()));
        let fact = facts.get(&hash);
        let multi = multi_channel(runtime, hash);
        modules.push(RingModule {
            ports: fact
                .map(|f| {
                    f.manifest
                        .ports
                        .iter()
                        .map(|p| rings::RingPort {
                            direction: p.direction,
                            index: p.index,
                            buffer_size: p.buffer_size,
                            max_record: p.max_record,
                            frame: rings::port_frame(p.content_type, p.flags),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            mailbox_safe: fact.is_some_and(|f| f.mailbox_safe),
            multi_inbound: multi,
            multi_outbound: multi,
            domain: entry["domain_id"].as_u64().unwrap_or(0) as u8,
        });
        names.push(name);
    }
    let id_to_index: HashMap<u64, usize> = entries
        .iter()
        .enumerate()
        .filter_map(|(i, e)| e["id"].as_u64().map(|id| (id, i)))
        .collect();
    let mut edges = Vec::new();
    for (i, e) in decoded["graph"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        let end = |key: &str| -> Result<usize> {
            e[key]
                .as_u64()
                .and_then(|id| id_to_index.get(&id).copied())
                .ok_or_else(|| Error::Config(format!("compiled edge {i} names no module")))
        };
        edges.push(RingEdge {
            from: end("from_id")?,
            from_port: e["from_port_index"].as_u64().unwrap_or(0) as u8,
            to: end("to_id")?,
            ctrl: e["to_port"].as_str() == Some("ctrl"),
            to_port: e["to_port_index"].as_u64().unwrap_or(0) as u8,
            buffer_group: e["buffer_group"].as_u64().unwrap_or(0) as u8,
            buffer_bytes: e["buffer_bytes"].as_u64().unwrap_or(0) as u32,
            cross_core: e["edge_class"].as_str() == Some("cross_core"),
        });
    }
    Ok(Graph {
        names,
        modules,
        edges,
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
            RingNode::Module(m) => format!("{}.{}", self.names[m], self.port(m, direction, port)),
            RingNode::Tee { of, port: p } => {
                format!(
                    "tee({}.{})",
                    self.names[of],
                    self.port(of, rings::DIR_OUT, p)
                )
            }
            RingNode::Merge { of, port: p } => {
                let dir = if p & 0x10 != 0 {
                    rings::DIR_CTRL
                } else {
                    rings::DIR_IN
                };
                format!("merge({}.{})", self.names[of], self.port(of, dir, p & 0x0F))
            }
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
    let decoded = crate::config::decode_config(blob)?;
    check_decoded(config, &decoded, facts, manifests, target, arena)
}

fn check_decoded(
    config: &Value,
    decoded: &Value,
    facts: &HashMap<u32, ModuleFacts<'_>>,
    manifests: &HashMap<String, Manifest>,
    target: &TargetDescriptor,
    kernel_arena: u64,
) -> Result<()> {
    let graph = decode(config, decoded, facts, target.runtime())?;
    if graph.edges.is_empty() {
        return Ok(());
    }
    let namer = Namer {
        names: &graph.names,
        manifests,
    };
    let plan = rings::plan(&graph.modules, &graph.edges, platform(target)).map_err(|e| {
        Error::Config(match e {
            RingError::OverCeiling { ends, request } => format!(
                "{} asks for a {request} B ring, over the {} B ceiling of one channel: lower \
                 the request or split the stream",
                namer.edge(&ends),
                rings::MAX_RING_BYTES
            ),
            RingError::RecordOverRing {
                ends,
                max_record,
                granted,
            } => format!(
                "{}: its producer writes records of up to {max_record} B but the ring is \
                 {granted} B, so a record that size could never be written; raise the edge's \
                 buffer_bytes or the port's buffer_size",
                namer.edge(&ends)
            ),
            RingError::GroupsExhausted => format!(
                "the graph's record fans need more mailbox groups than {}'s kernel has",
                target.id
            ),
            RingError::UnknownModule { edge } => format!("compiled edge {edge} names no module"),
        })
    })?;
    let total = plan.total();
    let arena = limit(config, "buffer_arena", kernel_arena);
    let slots = limit(
        config,
        "channels",
        crate::capacity::kernel_max_edges(target.runtime()) as u64,
    );
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
            "graph preparation opens {} channel(s) but {} has {} channel slot(s){}: every ring is a \
             channel slot, the edges joining fanned ports to their tees and merges and the \
             consumer side of a cross-domain edge included. Fan fewer ports, or split the \
             graph.",
            plan.rings.len(),
            target.id,
            slots.value,
            by(&slots)
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
            facts: Default::default(),
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
    /// through its producer's port: the expanded graph, its compiled form as
    /// `decode_config` reads it, and the two module types' manifests.
    fn graph(n: usize, ring: u32) -> (Value, Value, Manifest, Manifest) {
        let mut modules = Vec::new();
        let mut entries = Vec::new();
        let mut edges = Vec::new();
        for i in 0..n {
            modules.push(serde_json::json!({"name": format!("src{i}"), "type": "ring_src"}));
            modules.push(serde_json::json!({"name": format!("dst{i}"), "type": "ring_dst"}));
            for (k, ty) in [(2 * i, "ring_src"), (2 * i + 1, "ring_dst")] {
                entries.push(serde_json::json!({
                    "id": k,
                    "name_hash": format!("0x{:08x}", fnv1a_hash(ty.as_bytes())),
                    "domain_id": 0,
                }));
            }
            edges.push(serde_json::json!({"from_id": 2 * i, "to_id": 2 * i + 1, "to_port": "in"}));
        }
        let config = serde_json::json!({ "modules": modules });
        let decoded = serde_json::json!({ "modules": entries, "graph": edges });
        let src = Manifest {
            ports: vec![port(rings::DIR_OUT, 0, ring)],
            ..Default::default()
        };
        let dst = Manifest {
            ports: vec![port(rings::DIR_IN, 0, 0)],
            ..Default::default()
        };
        (config, decoded, src, dst)
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
        decoded: &Value,
        facts: &HashMap<u32, ModuleFacts<'_>>,
        manifests: &HashMap<String, Manifest>,
    ) -> Result<()> {
        let target = linux();
        let arena = buffer_arena_bytes(&target).unwrap();
        check_decoded(config, decoded, facts, manifests, &target, arena)
    }

    #[test]
    fn a_graph_under_the_arena_passes() {
        // Eight 1 MiB rings: half the host arena.
        let (config, decoded, src, dst) = graph(8, 1 << 20);
        run(&config, &decoded, &facts(&src, &dst), &HashMap::new()).unwrap();
    }

    #[test]
    fn a_graph_over_the_arena_is_refused_naming_its_largest_edges() {
        // Seventeen rings that each round up to 1 MiB: one over the host's
        // 16 MiB.
        let (config, decoded, src, dst) = graph(17, (1 << 20) - 100);
        let e = run(&config, &decoded, &facts(&src, &dst), &HashMap::new())
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
        let (config, decoded, src, dst) = graph(17, 1 << 20);
        let manifests = HashMap::from([
            ("src0".to_string(), src.clone()),
            ("dst0".to_string(), dst.clone()),
        ]);
        let e = run(&config, &decoded, &facts(&src, &dst), &manifests)
            .unwrap_err()
            .to_string();
        assert!(e.contains("src0.p1_0 -> dst0.p0_0"), "{e}");
    }

    #[test]
    fn a_built_in_module_s_ports_are_unsized() {
        // No facts for either type: the kernel holds no manifest for a
        // built-in, so every edge takes the default ring.
        let (config, decoded, _, _) = graph(3, 1 << 20);
        let graph = decode(&config, &decoded, &HashMap::new(), "linux").unwrap();
        let plan = rings::plan(&graph.modules, &graph.edges, platform(&linux())).unwrap();
        assert_eq!(plan.total(), 3 * rings::DEFAULT_RING_BYTES as u64);
    }

    #[test]
    fn a_capacity_envelope_below_the_kernel_arena_is_the_limit() {
        // Eight 1 MiB rings fit the host's 16 MiB, not a 4 MiB envelope.
        let (mut config, decoded, src, dst) = graph(8, 1 << 20);
        config["capacity"] = serde_json::json!({"buffer_arena": 4 << 20});
        let e = run(&config, &decoded, &facts(&src, &dst), &HashMap::new())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("buffer arena is 4194304 B (its capacity envelope) — over by 4194304 B"),
            "{e}"
        );
        // An envelope above the kernel's arena is the kernel's to clamp.
        config["capacity"] = serde_json::json!({"buffer_arena": 1u64 << 40});
        run(&config, &decoded, &facts(&src, &dst), &HashMap::new()).unwrap();
    }

    #[test]
    fn every_ring_takes_a_channel_slot() {
        let (mut config, decoded, src, dst) = graph(3, 1024);
        config["capacity"] = serde_json::json!({"channels": 2});
        let e = run(&config, &decoded, &facts(&src, &dst), &HashMap::new())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains(
                "opens 3 channel(s) but linux has 2 channel slot(s) (its capacity envelope)"
            ),
            "{e}"
        );
        config["capacity"] = serde_json::json!({"channels": 3});
        run(&config, &decoded, &facts(&src, &dst), &HashMap::new()).unwrap();
    }

    #[test]
    fn the_hosted_network_provider_keeps_a_channel_per_edge_on_linux_only() {
        // `linux_net` (1) feeds two consumers (2, 3) that both feed it back:
        // on Linux the kernel keeps an edge each, with no tee or merge.
        let hash = fnv1a_hash(b"linux_net");
        let entries: Vec<Value> = (0..4)
            .map(|i| {
                let h = if i == 1 { hash } else { 0x1000 + i };
                serde_json::json!({"id": i, "name_hash": format!("0x{h:08x}"), "domain_id": 0})
            })
            .collect();
        let edge = |f: u32, t: u32| serde_json::json!({"from_id": f, "to_id": t, "to_port": "in"});
        let decoded = serde_json::json!({
            "modules": entries,
            "graph": [edge(1, 2), edge(1, 3), edge(2, 1), edge(3, 1)],
        });
        // The expanded graph names no types: the hash alone decides.
        let config = serde_json::json!({ "modules": [] });
        let rings_on = |runtime: &str, target: &TargetDescriptor| {
            let graph = decode(&config, &decoded, &HashMap::new(), runtime).unwrap();
            rings::plan(&graph.modules, &graph.edges, platform(target))
                .unwrap()
                .rings
                .len()
        };
        let pi5 = crate::target::load_target("pi5", &root()).unwrap();
        assert_eq!(rings_on("linux", &linux()), 4);
        // Elsewhere: a tee and a merge, each with its joining edge.
        assert_eq!(rings_on("bcm2712", &pi5), 6);
    }

    #[test]
    fn the_rp_arenas_come_from_the_silicon() {
        let rp2040 = crate::target::load_target("rp2040", &root()).unwrap();
        let pico2w = crate::target::load_target("pico2w", &root()).unwrap();
        assert_eq!(buffer_arena_bytes(&rp2040), Some(16 * 1024));
        assert_eq!(buffer_arena_bytes(&pico2w), Some(64 * 1024));
        assert_eq!(
            buffer_arena_bytes(&linux()),
            Some(crate::capacity::HOST_BUFFER_ARENA)
        );
    }
}
